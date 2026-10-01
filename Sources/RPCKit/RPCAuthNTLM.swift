import Foundation
import AuthKit
import SheepCrypto

/// The MS-NLMP §3.4.4 per-PDU protection NTLMSSP applies to connection-oriented DCERPC, shared by
/// the raw-NTLM (`RPC_C_AUTHN_WINNT`, type 10) provider and the SPNEGO provider when it selects
/// NTLM. At PDU integrity the 16-byte NTLM MAC signs the **whole PDU** (header + stub + auth pad +
/// `sec_trailer` header); at PDU privacy the stub (with pad) is additionally RC4-sealed while the MAC
/// still covers the whole plaintext PDU — exactly what impacket's `ntlm.SIGN`/`ntlm.SEAL` produce
/// from `rpc_packet.get_packet()[:-16]`.
///
/// One continuous RC4 handle and one sequence number per direction are advanced across every
/// protected PDU (and, with key exchange, across the 8-byte MAC checksum) to stay byte-synchronised
/// with the peer. All access is serial (one `RPCServerConnection`), guarded by `lock` for safety.
final class NTLMWholePDUProtector: @unchecked Sendable {
    private let lock = NSLock()
    let level: RPCAuthLevel
    let authType: RPCAuthType
    private let keyExch: Bool
    private let clientSignKey: [UInt8]
    private let serverSignKey: [UInt8]
    private var clientSeal: RPCRC4Stream
    private var serverSeal: RPCRC4Stream
    private var recvSeq: UInt32 = 0
    private var sendSeq: UInt32 = 0
    private var clientAuthContextId: UInt32 = 0

    init(exportedSessionKey esk: [UInt8], flags: NTLMFlags, level: RPCAuthLevel, authType: RPCAuthType) {
        self.level = level
        self.authType = authType
        self.keyExch = flags.contains(.keyExchange)
        self.clientSignKey = NTLMCrypto.signKey(esk, clientToServer: true)
        self.serverSignKey = NTLMCrypto.signKey(esk, clientToServer: false)
        self.clientSeal = RPCRC4Stream(key: NTLMCrypto.sealKey(esk, flags: flags, clientToServer: true))
        self.serverSeal = RPCRC4Stream(key: NTLMCrypto.sealKey(esk, flags: flags, clientToServer: false))
    }

    /// The 16-byte NTLM2 signature: Version(0x00000001) ‖ checksum(8) ‖ SeqNum(4 LE), where
    /// checksum = RC4(HMAC_MD5(SignKey, SeqNum ‖ message)[0..8]) when key exchange is negotiated.
    private func mac(signKey: [UInt8], seal: inout RPCRC4Stream, seq: UInt32, message: [UInt8]) -> [UInt8] {
        var checksum = Array(HMACMD5.authenticate(key: signKey, LEBytes.u32(seq) + message).prefix(8))
        if keyExch { checksum = seal.process(checksum) }
        return [0x01, 0x00, 0x00, 0x00] + checksum + LEBytes.u32(seq)
    }

    func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                          contextID: UInt16, stub: [UInt8]) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        let padLen = (4 - stub.count % 4) % 4
        let pad = [UInt8](repeating: 0, count: padLen)
        let sigLen = 16
        let respPrefix = LEBytes.u32(allocHint) + LEBytes.u16(contextID) + [0, 0]   // alloc_hint | ctx | cancel | rsvd
        let bodyPlain = respPrefix + stub + pad
        let fragLen = 16 + bodyPlain.count + 8 + sigLen
        var header: [UInt8] = [0x05, 0x00, PDUType.response.rawValue, flags.rawValue]
        header += RPCHeader.drep
        header += LEBytes.u16(UInt16(fragLen))
        header += LEBytes.u16(UInt16(sigLen))
        header += LEBytes.u32(callID)
        let secTrailer: [UInt8] = [authType.rawValue, level.rawValue, UInt8(padLen), 0] + LEBytes.u32(clientAuthContextId)

        let outBody: [UInt8]
        let sig: [UInt8]
        if level == .pktPrivacy {
            let sealed = serverSeal.process(stub + pad)             // seal only the stub (+pad)
            let signedRegion = header + bodyPlain + secTrailer      // MAC over the whole plaintext PDU
            sig = mac(signKey: serverSignKey, seal: &serverSeal, seq: sendSeq, message: signedRegion)
            outBody = respPrefix + sealed
        } else {
            let signedRegion = header + bodyPlain + secTrailer
            sig = mac(signKey: serverSignKey, seal: &serverSeal, seq: sendSeq, message: signedRegion)
            outBody = bodyPlain
        }
        sendSeq &+= 1
        return header + outBody + secTrailer + sig
    }

    func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        guard pdu.count >= 24 else { throw RPCError.auth("short protected PDU") }
        let fragLen = Int(LEBytes.readU16(pdu, 8))
        let authLen = Int(LEBytes.readU16(pdu, 10))
        guard authLen == 16, fragLen <= pdu.count, fragLen >= stubOffset + 8 + authLen else {
            throw RPCError.auth("bad NTLM auth trailer geometry")
        }
        let sigStart = fragLen - authLen
        let trailerStart = sigStart - 8
        guard trailerStart >= stubOffset else { throw RPCError.auth("auth pad underflows stub") }
        let secTrailer = Array(pdu[trailerStart..<sigStart])
        let padLen = Int(secTrailer[2])
        clientAuthContextId = LEBytes.readU32(pdu, trailerStart + 4)
        let authValue = Array(pdu[sigStart..<fragLen])
        let sealedRegion = Array(pdu[stubOffset..<trailerStart])    // stub + pad
        guard padLen <= sealedRegion.count else { throw RPCError.auth("auth_pad_length past stub") }

        let plainStubPad: [UInt8]
        let signedRegion: [UInt8]
        if level == .pktPrivacy {
            plainStubPad = clientSeal.process(sealedRegion)
            signedRegion = Array(pdu[0..<stubOffset]) + plainStubPad + secTrailer
        } else {
            plainStubPad = sealedRegion
            signedRegion = Array(pdu[0..<sigStart])                 // header + body + pad + sec_trailer (plaintext)
        }
        let expected = mac(signKey: clientSignKey, seal: &clientSeal, seq: recvSeq, message: signedRegion)
        guard ConstantTime.equal(expected, authValue) else { throw RPCError.auth("NTLM signature mismatch") }
        recvSeq &+= 1
        return Array(plainStubPad.dropLast(padLen))
    }
}

/// RPC authentication provider for `RPC_C_AUTHN_WINNT` (auth type 10): NTLMSSP over
/// connection-oriented DCERPC.
///
/// Handshake: the bind verifier carries an NTLMSSP NEGOTIATE, answered with a CHALLENGE in the
/// bind_ack; the client returns an AUTHENTICATE in the `auth3` PDU, which establishes the context.
/// Thereafter every request/response is protected by `NTLMWholePDUProtector`.
public final class NTLMRPCAuthProvider: RPCAuthenticator, @unchecked Sendable {
    private var ntlmServer: NTLMServer
    private var challenged = false
    private var level: RPCAuthLevel = .none
    private var protector: NTLMWholePDUProtector?
    private var identity: AuthenticatedIdentity?
    private var sessionKeyBytes: [UInt8] = []

    public init(server: NTLMServer) { self.ntlmServer = server }

    public var authType: RPCAuthType { .ntlm }
    public var authLevel: RPCAuthLevel { level }
    public var isEstablished: Bool { protector != nil }
    public var establishedIdentity: AuthenticatedIdentity? { protector != nil ? identity : nil }
    public var establishedSessionKey: [UInt8]? { protector != nil ? sessionKeyBytes : nil }

    public func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        if !challenged {
            level = authLevel
            let challenge: [UInt8]
            do { challenge = try ntlmServer.challenge(for: authData) }
            catch { throw RPCError.auth("NTLM negotiate: \(error)") }
            challenged = true
            return challenge
        }
        let result: NTLMServer.Result
        do { result = try await ntlmServer.authenticate(authData) }
        catch { throw RPCError.auth("NTLM authenticate: \(error)") }
        guard let ctx = result.context else { throw RPCError.auth("anonymous NTLM not permitted on ncacn_ip_tcp") }
        protector = NTLMWholePDUProtector(exportedSessionKey: result.exportedSessionKey,
                                          flags: ctx.negotiatedFlags, level: level, authType: .ntlm)
        identity = result.identity
        sessionKeyBytes = result.exportedSessionKey
        return nil
    }

    public func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                 contextID: UInt16, stub: [UInt8]) throws -> [UInt8] {
        guard let p = protector else { throw RPCError.auth("NTLM context not established") }
        return p.buildResponsePDU(callID: callID, flags: flags, allocHint: allocHint, contextID: contextID, stub: stub)
    }

    public func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8] {
        guard let p = protector else { throw RPCError.auth("NTLM context not established") }
        return try p.openRequestPDU(pdu, stubOffset: stubOffset)
    }

    // Unused stub-only requirements (whole-PDU path is used instead).
    public func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("NTLM RPC uses whole-PDU protection") }
    public func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { throw RPCError.auth("NTLM RPC uses whole-PDU protection") }
    public func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws { throw RPCError.auth("NTLM RPC uses whole-PDU protection") }
    public func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { throw RPCError.auth("NTLM RPC uses whole-PDU protection") }
}
