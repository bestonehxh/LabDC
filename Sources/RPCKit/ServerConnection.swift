import Foundation
import AuthKit

/// Drives one DCERPC connection over a single `RPCTransport`: negotiates binds, reassembles
/// request fragments, dispatches to the registered interface for the request's presentation
/// context, and fragments the response. Swift errors from a dispatch become fault PDUs.
///
/// One connection = one transport = one serial request loop (no security-context multiplexing),
/// matching what we advertise in bind-time feature negotiation.
public final class RPCServerConnection: @unchecked Sendable {
    /// Server-advertised maximum transmit / receive fragment sizes (MS-RPCE default 4280 / 5840).
    public static let defaultMaxXmit: UInt16 = 4280
    public static let defaultMaxRecv: UInt16 = 5840

    private let transport: RPCTransport
    private let identity: AuthenticatedIdentity
    private let sessionKey: [UInt8]
    private var authProvider: any RPCAuthProvider
    private let handles = RPCHandleTable()

    private var interfaces: [(uuid: DCEUUID, major: UInt16, iface: any RPCInterface)] = []
    private var boundContexts: [UInt16: any RPCInterface] = [:]
    private var negotiatedOutboundFrag = 4280
    private var recvSequence: UInt32 = 0
    private var sendSequence: UInt32 = 0
    /// WP-AF: the `auth_context_id` the client chose in its bind (or alter_context) sec_trailer.
    /// MS-RPCE §2.2.2.11: the server must echo it in every PDU of that security context — bind_ack,
    /// alter_context_resp and each protected response. Samba's client uses 1 and rejects anything
    /// else ("Auth context id 0 mismatch expected 1"); impacket and Windows use 0. We run one
    /// security context per connection (no sec-context multiplexing), so one value suffices.
    private var authContextID: UInt32 = 0

    private var accumulator: [UInt8] = []

    public init(transport: RPCTransport,
                identity: AuthenticatedIdentity = .anonymous,
                sessionKey: [UInt8] = [],
                authProvider: any RPCAuthProvider = NoAuthProvider()) {
        self.transport = transport
        self.identity = identity
        self.sessionKey = sessionKey
        self.authProvider = authProvider
    }

    /// Registers an interface. Binds are matched by UUID and major version.
    public func register(_ iface: any RPCInterface) {
        interfaces.append((iface.interfaceUUID, iface.interfaceVersion.0, iface))
    }

    // MARK: PDU framing over a byte stream

    /// Returns the next complete PDU's bytes, reading from the transport as needed. Returns nil
    /// on a clean close.
    private func nextPDU() async throws -> [UInt8]? {
        while true {
            if accumulator.count >= 16 {
                let fragLen = Int(UInt16(accumulator[8]) | (UInt16(accumulator[9]) << 8))
                // A frag_length below the 16-byte common header can never be consumed: the stream
                // would buffer every later byte forever (memory DoS). Drop the connection instead.
                guard fragLen >= 16 else {
                    accumulator.removeAll()
                    throw RPCError.malformedPDU("frag_length \(fragLen) is shorter than the PDU header")
                }
                if accumulator.count >= fragLen {
                    let pdu = Array(accumulator[0..<fragLen])
                    accumulator.removeFirst(fragLen)
                    return pdu
                }
            }
            let chunk = try await transport.receive()
            if chunk.isEmpty {
                return accumulator.isEmpty ? nil : nil   // partial trailing data is dropped on close
            }
            accumulator.append(contentsOf: chunk)
        }
    }

    /// Runs the connection until the transport closes.
    public func run() async throws {
        while let pduBytes = try await nextPDU() {
            let (parsed, _) = try PDUCodec.parse(pduBytes)
            switch parsed.header.type {
            case .bind, .alterContext:
                // WP-AJ: a bind is always answered. If it cannot be accepted (unsupported auth type,
                // a provider that throws — e.g. schannel for a computer with no secure-channel state)
                // it gets a `bind_nak` at once and the connection stays usable for another bind; a
                // failed alter_context gets a fault and the connection is closed (MS-RPCE §3.3.1.5.x;
                // what Samba's dcesrv does). Before this the error ended `run()` silently and the
                // client waited for its own timeout.
                do {
                    try await handleBind(parsed, alter: parsed.header.type == .alterContext)
                } catch {
                    if parsed.header.type == .bind {
                        try await send(PDUCodec.encodeBindNak(callID: parsed.header.callID,
                                                              reason: Self.bindNakReason(for: error)))
                    } else {
                        try await send(PDUCodec.encodeFault(callID: parsed.header.callID, contextID: 0,
                                                            status: .accessDenied))
                        return
                    }
                }
            case .request:
                try await handleRequest(parsed, raw: pduBytes)
            case .auth3:
                // Final leg of a 3-leg auth (NTLM AUTHENTICATE / DCE-style Kerberos); consume its
                // verifier to establish the security context and continue. No response PDU follows.
                if let v = parsed.verifier {
                    _ = try await authProvider.bind(authType: RPCAuthType(rawValue: v.type) ?? .none,
                                                    authData: v.data, authLevel: RPCAuthLevel(rawValue: v.level) ?? .none)
                }
            case .shutdown:
                return
            default:
                try await send(PDUCodec.encodeFault(callID: parsed.header.callID, contextID: 0, status: .protoError))
            }
        }
    }

    private func send(_ bytes: [UInt8]) async throws { try await transport.send(bytes) }

    /// WP-AJ: the `bind_nak` reject reason for a bind that failed with `error` (MS-RPCE §2.2.2.5).
    static func bindNakReason(for error: Error) -> RPCBindNakReason {
        if case RPCError.bindRejected(let r) = error { return r }
        return .reasonNotSpecified
    }

    // MARK: bind

    private func handleBind(_ parsed: PDUCodec.Parsed, alter: Bool) async throws {
        let bind = try PDUCodec.decodeBind(parsed)
        // Negotiate the auth verifier, if any. WP-AI: on an `alter_context` this is the next leg of a
        // multi-leg bind — the SPNEGO-Kerberos client AP-REP (+ mechListMIC) or the SPNEGO/raw NTLM
        // AUTHENTICATE when the client chose alter_context over auth3 (MS-RPCE §3.3.1.5.2.2). The
        // provider's reply token (the final SPNEGO negTokenResp) goes in the alter_context_resp
        // trailer with the same auth type/level/context id; a leg with no reply token (raw NTLM /
        // raw Kerberos) gets no trailer, as in Samba's `api_pipe_alter_context`.
        var responseAuth: [UInt8]? = nil
        if let v = parsed.verifier, v.type != RPCAuthType.none.rawValue {
            if alter, authProvider.isEstablished, authProvider is RPCAuthenticator {
                // An alter_context that only adds a presentation context to an established
                // ncacn_ip_tcp security context: no auth leg is left to run, but it must name the
                // bound context.
                try checkBoundSecurityContext(v, provider: authProvider)
            } else {
                authContextID = v.contextID
                do {
                    responseAuth = try await authProvider.bind(authType: RPCAuthType(rawValue: v.type) ?? .none,
                                                               authData: v.data,
                                                               authLevel: RPCAuthLevel(rawValue: v.level) ?? .none)
                } catch {
                    // A failed alter_context leg is answered with a fault (as Samba and Windows do)
                    // before the connection is dropped, so the client reports access denied rather
                    // than a reset. `run()` sends that fault (WP-AJ) and ends the connection.
                    throw error
                }
            }
        }

        var results = [ContextResult]()
        for ctx in bind.contexts {
            results.append(negotiate(ctx))
        }

        negotiatedOutboundFrag = min(Int(Self.defaultMaxXmit), Int(bind.maxRecv == 0 ? Self.defaultMaxXmit : bind.maxRecv))
        let maxXmit = min(Self.defaultMaxXmit, bind.maxXmit == 0 ? Self.defaultMaxXmit : bind.maxXmit)
        let maxRecv = min(Self.defaultMaxRecv, bind.maxRecv == 0 ? Self.defaultMaxRecv : bind.maxRecv)

        var verifier: AuthVerifier?
        if let data = responseAuth, !data.isEmpty {
            verifier = AuthVerifier(type: authProvider.authType.rawValue,
                                    level: authProvider.authLevel.rawValue,
                                    padLength: 0, contextID: authContextID, data: data)
        }
        let ack = PDUCodec.encodeBindAck(callID: parsed.header.callID, maxXmit: maxXmit, maxRecv: maxRecv,
                                         assocGroup: alter ? 0 : 0x1234, secondaryAddress: "",
                                         results: results, alter: alter, verifier: verifier)
        try await send(ack)
    }

    /// Decides the result for one proposed presentation context, and records the binding.
    private func negotiate(_ ctx: PresentationContext) -> ContextResult {
        // Bind-time feature negotiation context: its transfer syntax UUID starts with the
        // 6cb71c2c-9812-4540 prefix; answer negotiate_ack with no multiplexing / no keep-orphan.
        for ts in ctx.transferSyntaxes where ts.uuid.description.hasPrefix(RPCTransferSyntax.bindTimeFeatureNegotiationPrefix) {
            return ContextResult(result: .negotiateAck, reason: 0,
                                 transferSyntax: RPCSyntaxID(uuid: DCEUUID(bytes: [UInt8](repeating: 0, count: 16)), versionMajor: 0, versionMinor: 0))
        }
        // Does the client offer NDR32?
        let hasNDR32 = ctx.transferSyntaxes.contains { $0.uuid == RPCTransferSyntax.ndr32.uuid }
        guard let iface = interfaces.first(where: { $0.uuid == ctx.abstractSyntax.uuid && $0.major == ctx.abstractSyntax.versionMajor })?.iface else {
            return ContextResult(result: .providerRejection, reason: RPCContextReason.abstractSyntaxNotSupported.rawValue,
                                 transferSyntax: zeroSyntax)
        }
        guard hasNDR32 else {
            // Only NDR64 (or other) offered → reject this context; the client falls back.
            return ContextResult(result: .providerRejection,
                                 reason: RPCContextReason.proposedTransferSyntaxesNotSupported.rawValue,
                                 transferSyntax: zeroSyntax)
        }
        boundContexts[ctx.id] = iface
        return ContextResult(result: .acceptance, reason: 0, transferSyntax: RPCTransferSyntax.ndr32)
    }

    private var zeroSyntax: RPCSyntaxID {
        RPCSyntaxID(uuid: DCEUUID(bytes: [UInt8](repeating: 0, count: 16)), versionMajor: 0, versionMinor: 0)
    }

    // MARK: request / response

    private func handleRequest(_ first: PDUCodec.Parsed, raw firstRaw: [UInt8]) async throws {
        // Reassemble stub across fragments sharing this call id.
        let callID = first.header.callID
        var req = try PDUCodec.decodeRequest(first)
        var stub = req.stub
        let contextID = req.contextID
        let opnum = req.opnum
        var lastFlags = first.header.flags
        var provider = authProvider

        // Verify/unseal the first fragment's body if protected. A trailer that names a different
        // security context (auth_context_id / auth_type, WP-AF) is an auth error that drops the
        // connection, for every provider. A failed signature check or unseal then becomes
        // nca_s_fault_access_denied for the whole-PDU providers (NTLM/SPNEGO/Kerberos on
        // ncacn_ip_tcp, WP-AE — what impacket/Windows expect), and drops the connection for the
        // stub-only path (Netlogon schannel), as Samba's server does (WP-AG).
        let faultsOnAuthError = (provider.authLevel == .pktIntegrity || provider.authLevel == .pktPrivacy)
            && provider is RPCWholePDUAuthenticator
        try checkBoundSecurityContext(first, provider: provider)
        do {
            stub = try openIncoming(parsed: first, raw: firstRaw, currentStub: stub, provider: provider)
        } catch {
            guard faultsOnAuthError else { throw error }
            try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: .accessDenied))
            return
        }

        while !lastFlags.contains(.lastFrag) {
            guard let more = try await nextPDU() else { throw RPCError.reassembly("stream closed mid-request") }
            let (p, _) = try PDUCodec.parse(more)
            guard p.header.type == .request, p.header.callID == callID else {
                throw RPCError.reassembly("interleaved PDU during reassembly")
            }
            let r = try PDUCodec.decodeRequest(p)
            let chunk: [UInt8]
            try checkBoundSecurityContext(p, provider: provider)
            do {
                chunk = try openIncoming(parsed: p, raw: more, currentStub: r.stub, provider: provider)
            } catch {
                guard faultsOnAuthError else { throw error }
                try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: .accessDenied))
                return
            }
            stub.append(contentsOf: chunk)
            lastFlags = p.header.flags
            if stub.count > 16 * 1024 * 1024 { throw RPCError.reassembly("request exceeds 16 MiB") }
        }
        req.stub = stub

        // Dispatch.
        guard let iface = boundContexts[contextID] else {
            try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: .contextMismatch))
            return
        }
        // On ncacn_ip_tcp the identity and session key come from the RPC auth provider once it has a
        // security context; otherwise they are the connection's (SMB session, or anonymous).
        var effIdentity = identity
        var effSessionKey = sessionKey
        if let idp = provider as? RPCConnectionIdentity, let est = idp.establishedIdentity {
            effIdentity = est
            if let k = idp.establishedSessionKey { effSessionKey = k }
        }
        let ctx = RPCCallContext(identity: effIdentity, sessionKey: effSessionKey,
                                 clientAddress: transport.remoteAddress, handles: handles, contextID: contextID,
                                 authLevel: provider.authLevel,
                                 authType: provider.isEstablished ? provider.authType : .none,
                                 authPrincipal: provider.isEstablished ? provider.boundPrincipal : nil)
        let reader = NDRReader(stub)
        let responseStub: [UInt8]
        do {
            let writer = try await iface.dispatch(opnum: opnum, input: reader, context: ctx)
            responseStub = writer.bytes
        } catch let e as RPCError {
            try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: e.faultStatus))
            authProvider = provider
            return
        } catch let e as NDRError {
            _ = e
            try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: .ndr))
            authProvider = provider
            return
        } catch {
            try await send(PDUCodec.encodeFault(callID: callID, contextID: contextID, status: .cantPerform))
            authProvider = provider
            return
        }

        try await sendResponse(callID: callID, contextID: contextID, stub: responseStub, provider: &provider)
        authProvider = provider
    }

    /// Recovers the plaintext stub of one incoming request fragment, choosing the whole-PDU path
    /// (NTLM/SPNEGO on ncacn_ip_tcp, which verifies over the entire PDU) or the stub-only path
    /// (Netlogon schannel) by the provider's capabilities.
    private func openIncoming(parsed p: PDUCodec.Parsed, raw: [UInt8], currentStub: [UInt8],
                              provider: any RPCAuthProvider) throws -> [UInt8] {
        // Netlogon schannel proves key possession only through per-PDU signatures, so a schannel
        // context below packet integrity never runs a request (CVE-2022-38023 class; the provider
        // already refuses such a bind — this is the belt to that).
        if provider.authType == .schannel, provider.isEstablished,
           provider.authLevel != .pktIntegrity, provider.authLevel != .pktPrivacy {
            throw RPCError.auth("schannel below packet integrity")
        }
        if provider.authLevel == .pktIntegrity || provider.authLevel == .pktPrivacy,
           let whole = provider as? RPCWholePDUAuthenticator, p.verifier != nil {
            let stubOffset = 16 + 8 + (p.header.flags.contains(.objectUUID) ? 16 : 0)
            return try whole.openRequestPDU(raw, stubOffset: stubOffset)
        }
        if let v = p.verifier, provider.authLevel != .none {
            return try applyIncomingProtection(stub: currentStub, pad: p.authPad, verifier: v, provider: provider)
        }
        // WP-AJ: once a connection is bound at integrity/privacy every request must carry the auth
        // trailer (Samba's `dcesrv_auth_pkt_pull` rejects one without); otherwise an injected
        // plaintext request would run under the established identity.
        if p.verifier == nil, provider.isEstablished,
           provider.authLevel == .pktIntegrity || provider.authLevel == .pktPrivacy {
            throw RPCError.auth("unprotected request on a \(provider.authLevel) connection")
        }
        return currentStub
    }

    /// WP-AF: every protected PDU must belong to the bound security context (Samba's server enforces
    /// the same in `dcerpc_ncacn_pull_pkt_auth`). A mismatch is an auth error that the caller lets
    /// propagate, dropping the connection. Applies to the whole-PDU (NTLM/SPNEGO) and stub-only
    /// (schannel) paths alike; unprotected connections are unaffected.
    private func checkBoundSecurityContext(_ p: PDUCodec.Parsed, provider: any RPCAuthProvider) throws {
        guard let v = p.verifier, provider.authLevel != .none else { return }
        try checkBoundSecurityContext(v, provider: provider)
    }

    private func checkBoundSecurityContext(_ verifier: AuthVerifier, provider: any RPCAuthProvider) throws {
        if verifier.contextID != authContextID {
            throw RPCError.auth("auth_context_id \(verifier.contextID) does not match bound \(authContextID)")
        }
        if verifier.type != provider.authType.rawValue {
            throw RPCError.auth("auth_type \(verifier.type) does not match bound \(provider.authType.rawValue)")
        }
    }

    private func applyIncomingProtection(stub: [UInt8], pad: [UInt8], verifier: AuthVerifier,
                                         provider: any RPCAuthProvider) throws -> [UInt8] {
        try checkBoundSecurityContext(verifier, provider: provider)
        // The auth provider's covered range is the padded stub (`stub + pad`, MS-NRPC §3.3.4.2);
        // after verify/unseal we drop the pad to recover the NDR stub.
        let covered = stub + pad
        func stripPad(_ b: [UInt8]) -> [UInt8] {
            pad.isEmpty ? b : Array(b.dropLast(pad.count))
        }
        switch provider.authLevel {
        case .pktPrivacy:
            let out = try provider.unseal(body: covered, auth: verifier.data, sequence: recvSequence)
            recvSequence &+= 1
            return stripPad(out)
        case .pktIntegrity, .pkt, .call, .connect:
            try provider.verify(body: covered, auth: verifier.data, sequence: recvSequence)
            recvSequence &+= 1
            return stub
        case .none:
            return stub
        }
    }

    private func sendResponse(callID: UInt32, contextID: UInt16, stub: [UInt8], provider: inout any RPCAuthProvider) async throws {
        let total = stub.count
        // Reserve overhead for header + response fields (+ trailer for protected levels).
        // WP-AF: a protected fragment adds up to 3 pad bytes, the 8-byte sec_trailer and the auth
        // value (56 bytes for a sealed schannel NL_AUTH_SHA2_SIGNATURE; Kerberos/NTLM are within
        // 96), so reserve that and keep the stub a multiple of 16 like Samba's dcerpc_guess_sizes —
        // otherwise a full fragment overshot the client's max_recv_frag by up to ~40 bytes.
        let protected = provider.authLevel == .pktIntegrity || provider.authLevel == .pktPrivacy
        let overhead = 24 + (protected ? 8 + 96 : 0)
        var maxStub = max(16, negotiatedOutboundFrag - overhead)
        if protected { maxStub -= maxStub % 16 }
        var offset = 0
        if total == 0 {
            try await emitResponseFragment(callID: callID, contextID: contextID, allocHint: 0,
                                           stub: [], first: true, last: true, provider: &provider)
            return
        }
        while offset < total {
            let end = min(offset + maxStub, total)
            let chunk = Array(stub[offset..<end])
            let isFirst = offset == 0
            let isLast = end == total
            try await emitResponseFragment(callID: callID, contextID: contextID,
                                           allocHint: UInt32(total - offset),
                                           stub: chunk, first: isFirst, last: isLast, provider: &provider)
            offset = end
        }
    }

    private func emitResponseFragment(callID: UInt32, contextID: UInt16, allocHint: UInt32,
                                      stub: [UInt8], first: Bool, last: Bool, provider: inout any RPCAuthProvider) async throws {
        var flags = PFCFlags()
        if first { flags.insert(.firstFrag) }
        if last { flags.insert(.lastFrag) }
        // Whole-PDU protected providers (NTLM/SPNEGO on ncacn_ip_tcp) own the entire fragment layout
        // because the signature covers the header and sec_trailer, so they build the PDU themselves.
        if provider.authLevel == .pktIntegrity || provider.authLevel == .pktPrivacy,
           let whole = provider as? RPCWholePDUAuthenticator {
            let pdu = try whole.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint,
                                                 contextID: contextID, stub: stub)
            try await send(pdu)
            return
        }
        var outStub = stub
        var verifier: AuthVerifier?
        // WP-Z: at integrity/privacy the auth pad goes *inside* the protected region (the response
        // header is 24 bytes, so padding the stub to 4 aligns the sec_trailer), and is signed and
        // sealed with the stub — what Samba's client verifies. Previously the pad was appended in
        // the clear after sealing, which only clients that skip the response check (impacket) took.
        let pad = (4 - stub.count % 4) % 4
        let padded = stub + [UInt8](repeating: 0, count: pad)
        switch provider.authLevel {
        case .pktPrivacy:
            let (sealed, auth) = try provider.seal(body: padded, sequence: sendSequence)
            outStub = sealed
            verifier = AuthVerifier(type: provider.authType.rawValue, level: provider.authLevel.rawValue,
                                    padLength: UInt8(pad), contextID: authContextID, data: auth)
            sendSequence &+= 1
        case .pktIntegrity:
            let auth = try provider.sign(body: padded, sequence: sendSequence)
            outStub = padded
            verifier = AuthVerifier(type: provider.authType.rawValue, level: provider.authLevel.rawValue,
                                    padLength: UInt8(pad), contextID: authContextID, data: auth)
            sendSequence &+= 1
        default:
            break
        }
        let pdu = PDUCodec.encodeResponse(callID: callID, flags: flags, allocHint: allocHint,
                                          contextID: contextID, stub: outStub, verifier: verifier)
        try await send(pdu)
    }
}
