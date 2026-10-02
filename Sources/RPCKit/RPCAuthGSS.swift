import Foundation
import AuthKit

/// Whole-PDU protection for connection-oriented DCERPC authenticated with Kerberos (RFC 4121 IOV,
/// MS-RPCE §2.2.2.12), shared by the raw-Kerberos provider (`auth_type` 16) and the SPNEGO provider
/// (`auth_type` 9) once it selects Kerberos. At PDU privacy the stub is sealed and the RFC 4121 wrap
/// token goes in the auth trailer; at PDU integrity the stub travels in the clear with a MIC token in
/// the trailer. The RPC PDU header is not covered — we decline `PFC_SUPPORT_HEADER_SIGN`.
///
/// The alignment pad (impacket's `\xBB` fill) goes *inside* the wrapped/signed region and its length
/// is recorded in the `sec_trailer` `auth_pad_length`, exactly as impacket and Samba place it.
final class KerberosRPCProtector: @unchecked Sendable {
    private let lock = NSLock()
    let context: KerberosSecurityContext
    let level: RPCAuthLevel
    let authType: RPCAuthType
    private var clientAuthContextId: UInt32 = 0

    init(context: KerberosSecurityContext, level: RPCAuthLevel, authType: RPCAuthType) {
        self.context = context
        self.level = level
        self.authType = authType
    }

    func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                          contextID: UInt16, stub: [UInt8]) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        let confidential = level == .pktPrivacy
        let padLen = (4 - stub.count % 4) % 4
        let padded = stub + [UInt8](repeating: 0, count: padLen)
        let wrapped = try context.wrapRPC(stub: padded, confidential: confidential)
        let respPrefix = LEBytes.u32(allocHint) + LEBytes.u16(contextID) + [0, 0]   // alloc_hint | ctx | cancel | rsvd
        let outBody = respPrefix + wrapped.data
        let authValue = wrapped.trailer
        let authLen = authValue.count
        let secTrailer: [UInt8] = [authType.rawValue, level.rawValue, UInt8(padLen), 0] + LEBytes.u32(clientAuthContextId)
        let fragLen = 16 + outBody.count + 8 + authLen
        var header: [UInt8] = [0x05, 0x00, PDUType.response.rawValue, flags.rawValue]
        header += RPCHeader.drep
        header += LEBytes.u16(UInt16(fragLen))
        header += LEBytes.u16(UInt16(authLen))
        header += LEBytes.u32(callID)
        return header + outBody + secTrailer + authValue
    }

    func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        guard pdu.count >= 24 else { throw RPCError.auth("short protected PDU") }
        let fragLen = Int(LEBytes.readU16(pdu, 8))
        let authLen = Int(LEBytes.readU16(pdu, 10))
        guard authLen > 0, fragLen <= pdu.count, fragLen >= stubOffset + 8 + authLen else {
            throw RPCError.auth("bad Kerberos auth trailer geometry")
        }
        let sigStart = fragLen - authLen
        let trailerStart = sigStart - 8
        guard trailerStart >= stubOffset else { throw RPCError.auth("auth trailer underflows stub") }
        let secTrailer = Array(pdu[trailerStart..<sigStart])
        let padLen = Int(secTrailer[2])
        clientAuthContextId = LEBytes.readU32(pdu, trailerStart + 4)
        let authValue = Array(pdu[sigStart..<fragLen])
        let dataRegion = Array(pdu[stubOffset..<trailerStart])
        let confidential = level == .pktPrivacy
        let plain: [UInt8]
        do { plain = try context.unwrapRPC(data: dataRegion, trailer: authValue, confidential: confidential) }
        catch { throw RPCError.auth("Kerberos IOV unwrap: \(error)") }
        guard padLen <= plain.count else { throw RPCError.auth("auth_pad_length past stub") }
        return Array(plain.dropLast(padLen))
    }
}

/// RPC authentication provider for `RPC_C_AUTHN_GSS_KERBEROS` (auth type 16): raw GSS Kerberos with
/// `GSS_C_DCE_STYLE` (MS-KILE §3.4.5). AP-REQ in the bind → AP-REP in the bind_ack → the client's
/// AP-REP in the alter_context leg, then RFC 4121 IOV per PDU. Tokens are GSS-framed (`60 … 01 00`
/// AP-REQ, `02 00` AP-REP).
public final class KerberosRPCAuthProvider: RPCAuthenticator, @unchecked Sendable {
    private let acceptor: KerberosAcceptor
    private var level: RPCAuthLevel = .none
    private var pending: KerberosAcceptResult?
    private var protector: KerberosRPCProtector?
    private var identity: AuthenticatedIdentity?
    private var sessionKeyBytes: [UInt8] = []
    private let framedAuthType: RPCAuthType

    public init(acceptor: KerberosAcceptor) { self.acceptor = acceptor; self.framedAuthType = .kerberos }

    public var authType: RPCAuthType { framedAuthType }
    public var authLevel: RPCAuthLevel { level }
    public var isEstablished: Bool { protector != nil }
    public var establishedIdentity: AuthenticatedIdentity? { protector != nil ? identity : nil }
    public var establishedSessionKey: [UInt8]? { protector != nil ? sessionKeyBytes : nil }

    private func establish(_ r: KerberosAcceptResult) {
        protector = KerberosRPCProtector(context: r.context, level: level, authType: framedAuthType)
        identity = r.identity
        sessionKeyBytes = r.context.tokenKey.bytes
    }

    public func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        if pending == nil && protector == nil {
            level = authLevel
            let r: KerberosAcceptResult
            do { r = try await acceptor.accept(authData, dceStyle: true) }
            catch { throw RPCError.auth("Kerberos AP-REQ: \(error)") }
            if r.dceTicketSessionKey == nil {          // non-DCE mutual: done in one leg
                establish(r)
            } else {
                pending = r
            }
            return r.outputToken
        }
        guard let r = pending else { throw RPCError.auth("unexpected Kerberos auth leg") }
        do { try acceptor.completeDCEStyle(r, clientAPRep: authData) }
        catch { throw RPCError.auth("Kerberos third-leg AP-REP: \(error)") }
        r.rebaseDCESequence()
        establish(r)
        pending = nil
        // Raw GSS Kerberos has no fourth token: the acceptor's output after the client's AP-REP is
        // empty, so whether the leg came in `auth3` or `alter_context` there is no auth trailer to
        // return (Samba's `api_pipe_alter_context` adds one only when the mech produced bytes).
        return nil
    }

    public func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                 contextID: UInt16, stub: [UInt8]) throws -> [UInt8] {
        guard let p = protector else { throw RPCError.auth("Kerberos context not established") }
        return try p.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint, contextID: contextID, stub: stub)
    }
    public func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        guard let p = protector else { throw RPCError.auth("Kerberos context not established") }
        return try p.openRequestPDU(pdu, stubOffset: stubOffset)
    }
    public func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("Kerberos RPC uses whole-PDU protection") }
    public func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { throw RPCError.auth("Kerberos RPC uses whole-PDU protection") }
    public func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws { throw RPCError.auth("Kerberos RPC uses whole-PDU protection") }
    public func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("Kerberos RPC uses whole-PDU protection") }
}

/// RPC authentication provider for `RPC_C_AUTHN_GSS_NEGOTIATE` (auth type 9): SPNEGO.
///
/// The first bind verifier is a SPNEGO `NegTokenInit`. When it selects Kerberos (what impacket's
/// `set_kerberos(True)` and Windows send for RPC), this drives the same `GSS_C_DCE_STYLE` three-leg
/// handshake as raw Kerberos but with SPNEGO framing: the acceptor's AP-REP is returned as the bare
/// `NegTokenResp.responseToken`, the client's third-leg AP-REP arrives the same way on the
/// alter_context leg (with Windows' mechListMIC), and is answered with the final `NegTokenResp
/// { accept-completed, mechListMIC }` in the alter_context_resp trailer (WP-AI). Per-PDU protection is
/// the RFC 4121 IOV wrap (`sec_trailer` auth_type 9) on RFC 4121 sequence numbers.
/// When it selects NTLM, the negotiated `NTLMSecurityContext` drives the whole-PDU NTLM protection
/// (auth_type 9), via `SPNEGOAcceptor`.
public final class SPNEGORPCAuthProvider: RPCAuthenticator, @unchecked Sendable {
    private let makeNTLM: (@Sendable () -> NTLMServer)?
    private let makeKerberos: (@Sendable () -> KerberosAcceptor)?

    // NTLM branch
    private var spnego: SPNEGOAcceptor?
    private var ntlmProtector: NTLMWholePDUProtector?
    // Kerberos branch
    private var kerberos: KerberosAcceptor?
    private var pendingKerb: KerberosAcceptResult?
    private var kerbProtector: KerberosRPCProtector?
    /// The client's MechTypeList DER as received, which both mechListMICs cover (RFC 4178 §5).
    private var mechTypesDER: [UInt8] = []

    private var level: RPCAuthLevel = .none
    private var identity: AuthenticatedIdentity?
    private var sessionKeyBytes: [UInt8] = []
    private enum Branch { case undecided, ntlm, kerberos }
    private var branch: Branch = .undecided

    public init(makeNTLM: (@Sendable () -> NTLMServer)?, makeKerberos: (@Sendable () -> KerberosAcceptor)?) {
        self.makeNTLM = makeNTLM
        self.makeKerberos = makeKerberos
    }

    public var authType: RPCAuthType { .spnego }
    public var authLevel: RPCAuthLevel { level }
    public var isEstablished: Bool { ntlmProtector != nil || kerbProtector != nil }
    public var establishedIdentity: AuthenticatedIdentity? { isEstablished ? identity : nil }
    public var establishedSessionKey: [UInt8]? { isEstablished ? sessionKeyBytes : nil }

    public func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        if branch == .undecided {
            level = authLevel
            let token: SPNEGOToken
            do { token = try SPNEGOToken(bytes: authData) }
            catch { throw RPCError.auth("SPNEGO bind token: \(error)") }
            guard case .initial(let initial) = token else { throw RPCError.auth("SPNEGO: first token is not NegTokenInit") }
            // The optimistic mechToken belongs to the client's *first* mechanism, so the DCE-style
            // Kerberos path applies only when that is Kerberos (Windows lists MS-KRB5 first).
            let picksKerberos = initial.mechTypes.first?.isKerberos == true && makeKerberos != nil
            if picksKerberos, let mechToken = initial.mechToken {
                branch = .kerberos
                mechTypesDER = initial.mechTypesDER
                let acc = makeKerberos!()
                kerberos = acc
                let r: KerberosAcceptResult
                do { r = try await acc.accept(mechToken, dceStyle: true) }
                catch { throw RPCError.auth("SPNEGO-Kerberos AP-REQ: \(error)") }
                guard let bareAPRep = r.dceBareAPRep else { throw RPCError.auth("SPNEGO-Kerberos: no AP-REP produced") }
                pendingKerb = r
                let pick = initial.mechTypes.first { $0.isKerberos }
                let resp = SPNEGOToken.NegTokenResp(negState: .acceptIncomplete, supportedMech: pick,
                                                    responseToken: bareAPRep)
                return SPNEGOToken.response(resp).encode()
            }
            // NTLM branch (SPNEGO selecting NTLMSSP).
            branch = .ntlm
            let acc = SPNEGOAcceptor(kerberos: nil, ntlm: makeNTLM?())
            spnego = acc
            return try await ntlmStep(authData)
        }
        switch branch {
        case .kerberos:
            // Third leg (WP-AI): the client's AP-REP (and, from Windows, its mechListMIC) inside a
            // NegTokenResp, on the alter_context (or auth3) leg. The reply is the final SPNEGO
            // negTokenResp — accept-completed plus our mechListMIC — which MS-RPCE §3.3.1.5.2.2
            // requires in the alter_context_resp auth trailer; without it Windows drops the
            // connection (the WP-AI capture). Over auth3 the connection discards it.
            guard let r = pendingKerb, let acc = kerberos else { throw RPCError.auth("no pending Kerberos context") }
            let reply = try Self.spnegoKerberosFinalLeg(authData, context: r.context, mechTypesDER: mechTypesDER) { apRep in
                do { try acc.completeDCEStyle(r, clientAPRep: apRep) }
                catch { throw RPCError.auth("SPNEGO-Kerberos third leg: \(error)") }
                r.rebaseDCESequence()
            }
            kerbProtector = KerberosRPCProtector(context: r.context, level: level, authType: .spnego)
            identity = r.identity
            sessionKeyBytes = r.context.tokenKey.bytes
            pendingKerb = nil
            return reply
        case .ntlm:
            return try await ntlmStep(authData)
        case .undecided:
            throw RPCError.auth("SPNEGO: inconsistent state")
        }
    }

    /// The final SPNEGO leg of a `GSS_C_DCE_STYLE` Kerberos bind (MS-SPNG §3.2.5.2, RFC 4178 §5),
    /// separated from the provider so the captured Windows tokens can drive it directly.
    ///
    /// `authData` is the client's `NegTokenResp { accept-incomplete, responseToken = its AP-REP,
    /// [mechListMIC] }`. `completeMech` validates the AP-REP (and re-bases the context's sequence
    /// numbers). A client mechListMIC — Windows always sends one, a CFX GetMIC over the MechTypeList
    /// with the AcceptorSubkey flag — must verify, and is answered with ours ("if we got a MIC, we
    /// must send a MIC"); a client that sends none (impacket) gets none. Returns the encoded
    /// `NegTokenResp { accept-completed, [mechListMIC] }` for the alter_context_resp trailer.
    static func spnegoKerberosFinalLeg(_ authData: [UInt8], context: KerberosSecurityContext, mechTypesDER: [UInt8],
                                       completeMech: ([UInt8]) throws -> Void) throws -> [UInt8] {
        let token: SPNEGOToken
        do { token = try SPNEGOToken(bytes: authData) } catch { throw RPCError.auth("SPNEGO third-leg: \(error)") }
        guard case .response(let resp) = token else {
            throw RPCError.auth("SPNEGO third-leg is not a NegTokenResp")
        }
        if resp.negState == .reject { throw RPCError.auth("SPNEGO: client rejected the context") }
        guard let apRep = resp.responseToken else {
            throw RPCError.auth("SPNEGO third-leg NegTokenResp has no responseToken (client AP-REP)")
        }
        try completeMech(apRep)
        var ourMIC: [UInt8]?
        if let clientMIC = resp.mechListMIC {
            do { try context.verifyMIC(mechTypesDER, token: clientMIC) }
            catch { throw RPCError.auth("SPNEGO mechListMIC does not verify: \(error)") }
            do { ourMIC = try context.getMIC(mechTypesDER) }
            catch { throw RPCError.auth("SPNEGO mechListMIC: \(error)") }
        }
        return SPNEGOToken.response(.init(negState: .acceptCompleted, mechListMIC: ourMIC)).encode()
    }

    private func ntlmStep(_ authData: [UInt8]) async throws -> [UInt8]? {
        guard var acc = spnego else { throw RPCError.auth("SPNEGO acceptor missing") }
        let step: SPNEGOAcceptor.Step
        do { step = try await acc.step(authData) } catch { throw RPCError.auth("SPNEGO: \(error)") }
        spnego = acc
        switch step {
        case .continue(let token):
            return token
        case .complete(let output, let id, let context):
            identity = id
            if let ntlm = context as? NTLMSecurityContext {
                ntlmProtector = NTLMWholePDUProtector(exportedSessionKey: ntlm.exportedSessionKey,
                                                      flags: ntlm.negotiatedFlags, level: level, authType: .spnego)
                sessionKeyBytes = ntlm.exportedSessionKey
                return output
            }
            throw RPCError.auth("SPNEGO selected a mechanism unsupported for ncacn_ip_tcp per-PDU protection")
        }
    }

    public func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                 contextID: UInt16, stub: [UInt8]) throws -> [UInt8] {
        if let p = kerbProtector {
            return try p.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint, contextID: contextID, stub: stub)
        }
        if let p = ntlmProtector {
            return p.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint, contextID: contextID, stub: stub)
        }
        throw RPCError.auth("SPNEGO context not established")
    }
    public func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        if let p = kerbProtector { return try p.openRequestPDU(pdu, stubOffset: stubOffset) }
        if let p = ntlmProtector { return try p.openRequestPDU(pdu, stubOffset: stubOffset) }
        throw RPCError.auth("SPNEGO context not established")
    }
    public func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("SPNEGO RPC uses whole-PDU protection") }
    public func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { throw RPCError.auth("SPNEGO RPC uses whole-PDU protection") }
    public func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws { throw RPCError.auth("SPNEGO RPC uses whole-PDU protection") }
    public func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("SPNEGO RPC uses whole-PDU protection") }
}

/// How a `ncacn_ip_tcp` connection builds its per-connection auth providers. The closures are called
/// per connection so each gets a fresh `NTLMServer`/`KerberosAcceptor` (challenge and replay state).
public struct RPCServerAuthConfig: Sendable {
    public var makeNTLMServer: (@Sendable () -> NTLMServer)?
    public var makeKerberosAcceptor: (@Sendable () -> KerberosAcceptor)?
    /// WP-AJ: builds the Netlogon schannel provider (auth type 68) for a connection — in production
    /// a `NetlogonSchannelProvider` over the DC's shared `NetlogonStateStore`, so a secure channel
    /// established over the netlogon pipe is usable over TCP and vice versa. Nil = type 68 is refused
    /// with a `bind_nak` (authentication_type_not_recognized).
    public var makeSchannel: (@Sendable () -> any RPCAuthProvider)?

    public init(makeNTLMServer: (@Sendable () -> NTLMServer)? = nil,
                makeKerberosAcceptor: (@Sendable () -> KerberosAcceptor)? = nil,
                makeSchannel: (@Sendable () -> any RPCAuthProvider)? = nil) {
        self.makeNTLMServer = makeNTLMServer
        self.makeKerberosAcceptor = makeKerberosAcceptor
        self.makeSchannel = makeSchannel
    }
}

/// The auth provider a `ncacn_ip_tcp` connection presents before the client picks an auth service.
/// The first bind verifier selects the concrete provider by `auth_type` (10 NTLM, 9 SPNEGO,
/// 16 Kerberos, 68 Netlogon schannel — WP-AJ); everything afterwards is delegated to it. A bind with
/// no verifier leaves the connection unauthenticated (anonymous), which is how `rpcdump`/EPM lookups
/// connect. An auth type we do not serve throws `RPCError.bindRejected(.authenticationTypeNotRecognized)`
/// (the connection answers `bind_nak`); a provider that fails its first leg is dropped again, so a
/// retried bind on the same connection starts clean.
public final class RPCServerAuthNegotiator: RPCAuthenticator, @unchecked Sendable {
    private let config: RPCServerAuthConfig
    private var chosen: (any RPCAuthenticator)?

    public init(config: RPCServerAuthConfig) { self.config = config }

    public var authType: RPCAuthType { chosen?.authType ?? .none }
    public var authLevel: RPCAuthLevel { chosen?.authLevel ?? .none }
    public var isEstablished: Bool { chosen?.isEstablished ?? false }
    public var boundPrincipal: String? { chosen?.boundPrincipal }
    public var establishedIdentity: AuthenticatedIdentity? { chosen?.establishedIdentity }
    public var establishedSessionKey: [UInt8]? { chosen?.establishedSessionKey }

    public func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        if chosen == nil {
            switch authType {
            case .ntlm:
                guard let make = config.makeNTLMServer else { throw RPCError.bindRejected(.authenticationTypeNotRecognized) }
                chosen = NTLMRPCAuthProvider(server: make())
            case .spnego:
                chosen = SPNEGORPCAuthProvider(makeNTLM: config.makeNTLMServer, makeKerberos: config.makeKerberosAcceptor)
            case .kerberos:
                guard let make = config.makeKerberosAcceptor else { throw RPCError.bindRejected(.authenticationTypeNotRecognized) }
                chosen = KerberosRPCAuthProvider(acceptor: make())
            case .schannel:
                guard let make = config.makeSchannel else { throw RPCError.bindRejected(.authenticationTypeNotRecognized) }
                chosen = StubProtectedRPCAuthenticator(make())
            default:
                throw RPCError.bindRejected(.authenticationTypeNotRecognized)
            }
            do {
                return try await chosen!.bind(authType: authType, authData: authData, authLevel: authLevel)
            } catch {
                chosen = nil
                throw error
            }
        }
        return try await chosen!.bind(authType: authType, authData: authData, authLevel: authLevel)
    }

    public func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                 contextID: UInt16, stub: [UInt8]) throws -> [UInt8] {
        guard let c = chosen else { throw RPCError.auth("no auth context") }
        return try c.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint, contextID: contextID, stub: stub)
    }

    public func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        guard let c = chosen else { throw RPCError.auth("no auth context") }
        return try c.openRequestPDU(pdu, stubOffset: stubOffset)
    }

    public func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("use whole-PDU path") }
    public func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { throw RPCError.auth("use whole-PDU path") }
    public func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws { throw RPCError.auth("use whole-PDU path") }
    public func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("use whole-PDU path") }
}

extension KerberosAcceptResult {
    /// WP-AI: once a DCE-style handshake completes, protect with RFC 4121 sequence numbers — send
    /// from our AP-REP seq-number, receive from the initiator's Authenticator seq-number — instead of
    /// the base 0 the acceptor started the context with. Windows' alter_context mechListMIC carries
    /// its Authenticator seq-number (588035807 in the WP-AI capture, not 0) and it asks for
    /// GSS_C_SEQUENCE_FLAG; impacket's Authenticator seq-number is 0, so it is unaffected.
    func rebaseDCESequence() {
        guard let ours = dceAcceptorSeq else { return }
        context.resetSequenceNumbers(send: UInt64(ours), recv: UInt64(dceInitiatorSeq ?? 0))
    }
}

/// WP-AJ: presents a stub-only provider (Netlogon schannel, whose `NL_AUTH_SHA2_SIGNATURE` covers
/// just the padded stub, MS-NRPC §3.3.4.2) through the whole-PDU interface the `ncacn_ip_tcp`
/// negotiator exposes. It lays the fragment out exactly as `RPCServerConnection` does for a
/// stub-only provider on a pipe: the auth pad goes *inside* the protected region and is recorded in
/// `auth_pad_length`, the stub is sealed (privacy) or signed (integrity), and the `sec_trailer`
/// echoes the client's `auth_context_id`. Incoming fragments are verified/unsealed over
/// `stub ‖ auth pad` and the pad is stripped.
final class StubProtectedRPCAuthenticator: RPCAuthenticator, @unchecked Sendable {
    private let lock = NSLock()
    private var inner: any RPCAuthProvider
    private var contextID: UInt32 = 0
    private var recvSequence: UInt32 = 0
    private var sendSequence: UInt32 = 0

    init(_ inner: any RPCAuthProvider) { self.inner = inner }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    var authType: RPCAuthType { locked { inner.authType } }
    var authLevel: RPCAuthLevel { locked { inner.authLevel } }
    var isEstablished: Bool { locked { inner.isEstablished } }
    var boundPrincipal: String? { locked { inner.boundPrincipal } }
    var establishedIdentity: AuthenticatedIdentity? { locked { (inner as? RPCConnectionIdentity)?.establishedIdentity } }
    var establishedSessionKey: [UInt8]? { locked { (inner as? RPCConnectionIdentity)?.establishedSessionKey } }

    func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        // The connection drives one PDU at a time, so the provider is not shared across this await.
        var p = locked { inner }
        let out = try await p.bind(authType: authType, authData: authData, authLevel: authLevel)
        locked { inner = p; recvSequence = 0; sendSequence = 0 }
        return out
    }

    func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                          contextID ctx: UInt16, stub: [UInt8]) throws -> [UInt8] {
        try locked {
            let pad = (4 - stub.count % 4) % 4
            let padded = stub + [UInt8](repeating: 0, count: pad)
            let out: [UInt8]
            let auth: [UInt8]
            switch inner.authLevel {
            case .pktPrivacy:
                (out, auth) = try inner.seal(body: padded, sequence: sendSequence)
            case .pktIntegrity:
                out = padded
                auth = try inner.sign(body: padded, sequence: sendSequence)
            default:
                throw RPCError.auth("stub-protected provider at level \(inner.authLevel)")
            }
            sendSequence &+= 1
            let v = AuthVerifier(type: inner.authType.rawValue, level: inner.authLevel.rawValue,
                                 padLength: UInt8(pad), contextID: contextID, data: auth)
            return PDUCodec.encodeResponse(callID: callID, flags: flags, allocHint: allocHint,
                                           contextID: ctx, stub: out, verifier: v)
        }
    }

    func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        try locked {
            let (p, _) = try PDUCodec.parse(pdu)
            guard let v = p.verifier else { throw RPCError.auth("protected request without auth trailer") }
            guard stubOffset >= 16, p.body.count >= stubOffset - 16 else { throw RPCError.auth("short protected request") }
            contextID = v.contextID
            let stub = Array(p.body[(stubOffset - 16)...])
            let covered = stub + p.authPad
            switch inner.authLevel {
            case .pktPrivacy:
                let plain = try inner.unseal(body: covered, auth: v.data, sequence: recvSequence)
                recvSequence &+= 1
                return p.authPad.isEmpty ? plain : Array(plain.dropLast(p.authPad.count))
            case .pktIntegrity:
                try inner.verify(body: covered, auth: v.data, sequence: recvSequence)
                recvSequence &+= 1
                return stub
            default:
                throw RPCError.auth("stub-protected provider at level \(inner.authLevel)")
            }
        }
    }

    func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { try locked { try inner.sign(body: body, sequence: sequence) } }
    func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { try locked { try inner.seal(body: body, sequence: sequence) } }
    func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws { try locked { try inner.verify(body: body, auth: auth, sequence: sequence) } }
    func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { try locked { try inner.unseal(body: body, auth: auth, sequence: sequence) } }
}
