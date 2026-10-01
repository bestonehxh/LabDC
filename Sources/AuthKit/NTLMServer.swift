import Foundation
import SheepCrypto
import Synchronization
import os

/// NTLM session security with extended session security (MS-NLMP §3.4.2–3.4.4): separate
/// client-to-server / server-to-client sign and seal keys, one continuous RC4 handle and one
/// sequence number per direction, version-1 NTLMSSP_MESSAGE_SIGNATURE
/// `01 00 00 00 | checksum (8) | SeqNum (4, LE)` where
/// checksum = HMAC_MD5(SignKey, SeqNum | message)[0..8], RC4-encrypted with the direction's
/// sealing handle when KEY_EXCH was negotiated.
///
/// GSS_Wrap output is `signature (16) | message` (sealed with the same handle first when
/// SEAL was negotiated), which is what Windows LDAP and Samba put in a SASL buffer.
public final class NTLMSecurityContext: GSSSecurityContext {
    public let mechanism: GSSMechanism = .ntlm
    public let negotiatedFlags: NTLMFlags
    public let isServer: Bool
    /// The 16-byte exported session key (MS-NLMP §3.1.5.1.2), the GSS session key SMB2 uses
    /// (MS-SMB2 §3.3.5.5.3). Never log it.
    public let exportedSessionKey: [UInt8]

    private struct Direction: Sendable {
        var signKey: [UInt8]
        var sealKey: [UInt8]
        var handle: RC4Stream
        var seq: UInt32 = 0
    }

    private struct State: Sendable {
        var send: Direction
        var recv: Direction
    }

    private let state: Mutex<State>

    /// - Parameter exportedSessionKey: the 16-byte key from the AUTHENTICATE exchange.
    public init(exportedSessionKey: [UInt8], flags: NTLMFlags, isServer: Bool) {
        negotiatedFlags = flags
        self.isServer = isServer
        self.exportedSessionKey = exportedSessionKey
        func direction(clientToServer: Bool) -> Direction {
            let seal = NTLMCrypto.sealKey(exportedSessionKey, flags: flags, clientToServer: clientToServer)
            return Direction(signKey: NTLMCrypto.signKey(exportedSessionKey, clientToServer: clientToServer),
                             sealKey: seal, handle: RC4Stream(key: seal))
        }
        state = Mutex(State(send: direction(clientToServer: !isServer), recv: direction(clientToServer: isServer)))
    }

    public var flags: GSSContextFlags {
        var f: GSSContextFlags = []
        if negotiatedFlags.contains(.sign) { f.insert(.integrity) }
        if negotiatedFlags.contains(.seal) { f.insert([.confidentiality, .integrity]) }
        return f
    }

    private var ess: Bool { negotiatedFlags.contains(.extendedSessionSecurity) }

    private func checkESS() throws {
        guard ess else { throw AuthKitError.unsupported("NTLM signing without extended session security") }
    }

    private static func signature(_ d: inout Direction, _ message: [UInt8], keyExchange: Bool) -> [UInt8] {
        var seq: [UInt8] = []
        seq.appendLE32(d.seq)
        var checksum = Array(HMACMD5.authenticate(key: d.signKey, seq + message).prefix(8))
        if keyExchange { checksum = d.handle.process(checksum) }
        d.seq &+= 1
        return [1, 0, 0, 0] + checksum + seq
    }

    public func wrap(_ message: [UInt8], confidential: Bool) throws -> [UInt8] {
        try checkESS()
        let kx = negotiatedFlags.contains(.keyExchange)
        return state.withLock { s in
            if confidential {
                let sealed = s.send.handle.process(message)
                return Self.signature(&s.send, message, keyExchange: kx) + sealed
            }
            return Self.signature(&s.send, message, keyExchange: kx) + message
        }
    }

    /// NTLM tokens do not say whether they are sealed: they are when SEAL was negotiated.
    public func unwrap(_ token: [UInt8]) throws -> (message: [UInt8], confidential: Bool) {
        try checkESS()
        guard token.count >= 16 else { throw AuthKitError.malformed(what: "NTLM wrap token", reason: "shorter than a signature") }
        let sealed = negotiatedFlags.contains(.seal)
        let kx = negotiatedFlags.contains(.keyExchange)
        return try state.withLock { s in
            var body = Array(token[16...])
            if sealed { body = s.recv.handle.process(body) }
            let expectedSeq = s.recv.seq
            let expected = Self.signature(&s.recv, body, keyExchange: kx)
            guard ConstantTime.equal(expected, Array(token[..<16])) else {
                let got = token.le32(12)
                if got != expectedSeq { throw AuthKitError.sequenceError(expected: UInt64(expectedSeq), got: UInt64(got)) }
                throw AuthKitError.integrityCheckFailed("NTLM signature")
            }
            return (body, sealed)
        }
    }

    public func getMIC(_ message: [UInt8]) throws -> [UInt8] {
        try checkESS()
        let kx = negotiatedFlags.contains(.keyExchange)
        return state.withLock { Self.signature(&$0.send, message, keyExchange: kx) }
    }

    public func verifyMIC(_ message: [UInt8], token: [UInt8]) throws {
        try checkESS()
        let kx = negotiatedFlags.contains(.keyExchange)
        try state.withLock { s in
            let expected = Self.signature(&s.recv, message, keyExchange: kx)
            guard token.count == 16, ConstantTime.equal(expected, token) else {
                throw AuthKitError.integrityCheckFailed("NTLM MIC")
            }
        }
    }

    /// MS-SPNG §3.3.5.1: the SPNEGO mechListMIC must not advance the RC4 state, so the first
    /// application message sees the same key stream. The caller saves and restores around it.
    /// Sequence numbers are *not* restored (Samba's `ntlmssp_sign_reset(…, false)`).
    public func withPreservedCipherState<T>(_ body: () throws -> T) rethrows -> T {
        let saved = state.withLock { ($0.send.handle, $0.recv.handle) }
        defer { state.withLock { $0.send.handle = saved.0; $0.recv.handle = saved.1 } }
        return try body()
    }
}

/// NTLMSSP server (MS-NLMP §3.2.5): NEGOTIATE -> CHALLENGE -> AUTHENTICATE, NTLMv2 only.
public struct NTLMServer: Sendable {
    public let source: any AuthSecretSource
    public var allowAnonymous: Bool
    public let clock: @Sendable () -> Date
    public let rng: RandomBytes
    /// Fixed server challenge (tests only).
    public var fixedChallenge: [UInt8]?

    private(set) var negotiate: NTLMNegotiateMessage?
    private(set) var challengeBytes: [UInt8]?
    private(set) var challenge: NTLMChallengeMessage?

    static let logger = Logger(subsystem: "dev.labdc.app", category: "AuthKit")

    public init(source: any AuthSecretSource, allowAnonymous: Bool = true, clock: @escaping @Sendable () -> Date = { Date() },
                rng: RandomBytes = RandomBytes(), fixedChallenge: [UInt8]? = nil) {
        self.source = source
        self.allowAnonymous = allowAnonymous
        self.clock = clock
        self.rng = rng
        self.fixedChallenge = fixedChallenge
    }

    /// The flags we answer with: what the client asked for among what we support, plus the
    /// ones a server always sets.
    static func responseFlags(_ client: NTLMFlags) -> NTLMFlags {
        var f: NTLMFlags = [.ntlm, .alwaysSign, .targetTypeDomain, .targetInfo, .version, .requestTarget]
        f.insert(client.contains(.unicode) ? .unicode : .oem)
        let echoed: NTLMFlags = [.sign, .seal, .keyExchange, .negotiate128, .negotiate56, .extendedSessionSecurity, .identify]
        f.formUnion(client.intersection(echoed))
        return f
    }

    /// Handles NEGOTIATE_MESSAGE and returns CHALLENGE_MESSAGE.
    public mutating func challenge(for negotiateBytes: [UInt8]) throws -> [UInt8] {
        guard challengeBytes == nil else { throw AuthKitError.invalidState("NTLM NEGOTIATE received twice") }
        let neg = try NTLMNegotiateMessage(negotiateBytes)
        let dnsComputer = source.dcDNSName
        let info: [NTLMAVPair] = [
            .string(NTLMAVPair.nbDomainName, source.netbiosDomain.uppercased()),
            .string(NTLMAVPair.nbComputerName, source.dcName.uppercased()),
            .string(NTLMAVPair.dnsDomainName, source.dnsDomain.lowercased()),
            .string(NTLMAVPair.dnsComputerName, dnsComputer),
            .string(NTLMAVPair.dnsTreeName, source.dnsDomain.lowercased()),
            NTLMAVPair(id: NTLMAVPair.timestamp, value: {
                var b: [UInt8] = []
                b.appendLE64(NTLMCrypto.fileTime(clock()))
                return b
            }()),
        ]
        let msg = NTLMChallengeMessage(flags: Self.responseFlags(neg.flags), targetName: source.netbiosDomain.uppercased(),
                                       serverChallenge: fixedChallenge ?? rng.next(8), targetInfo: info)
        let bytes = msg.encode()
        negotiate = neg
        challenge = msg
        challengeBytes = bytes
        return bytes
    }

    /// Result of a successful AUTHENTICATE.
    public struct Result: Sendable {
        public var identity: AuthenticatedIdentity
        /// `nil` for anonymous logons (no session key, no signing).
        public var context: NTLMSecurityContext?
        /// The AUTHENTICATE carried a MIC (MsvAvFlags 0x2) and it verified: the client is
        /// "new SPNEGO" and expects a mechListMIC.
        public var micVerified: Bool
        public var exportedSessionKey: [UInt8]
    }

    /// Verifies AUTHENTICATE_MESSAGE.
    public func authenticate(_ bytes: [UInt8]) async throws -> Result {
        guard let challenge, let challengeBytes, let negotiate else {
            throw AuthKitError.invalidState("NTLM AUTHENTICATE before CHALLENGE")
        }
        let auth = try NTLMAuthenticateMessage(bytes)
        let flags = challenge.flags.intersection(auth.flags.union([.ntlm, .unicode, .oem, .targetInfo, .version, .alwaysSign,
                                                                    .targetTypeDomain, .requestTarget]))

        // Anonymous (MS-NLMP §3.2.5.1.2): empty user and NT response, LM empty or Z(1).
        if auth.user.isEmpty && auth.ntResponse.isEmpty && (auth.lmResponse.isEmpty || auth.lmResponse == [0]) {
            guard allowAnonymous else {
                throw AuthKitError.ntlm(status: AuthKitError.NTStatus.accessDenied, reason: "anonymous logon refused")
            }
            Self.logger.info("NTLM: anonymous logon")
            return Result(identity: .anonymous, context: nil, micVerified: false, exportedSessionKey: [UInt8](repeating: 0, count: 16))
        }
        guard auth.ntResponse.count > 24 else {
            throw AuthKitError.ntlm(status: AuthKitError.NTStatus.ntlmBlocked,
                                    reason: auth.ntResponse.count == 24 ? "NTLMv1 is not accepted" : "LM-only response")
        }
        guard let account = await source.ntHash(forSAM: auth.user) else {
            throw AuthKitError.ntlm(status: AuthKitError.NTStatus.logonFailure, reason: "unknown user \(auth.user)")
        }
        let proof = Array(auth.ntResponse[0..<16])
        let temp = Array(auth.ntResponse[16...])
        guard temp.count >= 28, temp[0] == 1, temp[1] == 1 else {
            throw AuthKitError.ntlm(status: AuthKitError.NTStatus.invalidParameter, reason: "bad NTLMv2 blob")
        }
        // Clients hash the domain they sent; some send "" or the other name form (Samba tries these too).
        var domains = [auth.domain]
        for d in ["", source.netbiosDomain.uppercased(), source.dnsDomain] where !domains.contains(d) { domains.append(d) }
        var responseKey: [UInt8]?
        for d in domains {
            let k = NTLMCrypto.ntowfv2(ntHash: account.hash, user: auth.user, domain: d)
            if ConstantTime.equal(NTLMCrypto.ntProofStr(responseKeyNT: k, serverChallenge: challenge.serverChallenge, temp: temp), proof) {
                responseKey = k
                break
            }
        }
        guard let responseKey else {
            throw AuthKitError.ntlm(status: AuthKitError.NTStatus.logonFailure, reason: "wrong password for \(auth.user)")
        }
        let sessionBaseKey = NTLMCrypto.sessionBaseKey(responseKeyNT: responseKey, ntProofStr: proof)
        var exported = sessionBaseKey          // KeyExchangeKey = SessionBaseKey for NTLMv2
        if flags.contains(.keyExchange) {
            guard auth.encryptedRandomSessionKey.count == 16 else {
                throw AuthKitError.ntlm(status: AuthKitError.NTStatus.invalidParameter, reason: "KEY_EXCH without a 16-byte key")
            }
            exported = RC4.apply(key: sessionBaseKey, auth.encryptedRandomSessionKey)
        }

        // MIC (MS-NLMP §3.2.5.1.2) when MsvAvFlags says it is there.
        let clientPairs = try NTLMAVPair.decode(Array(temp[28...]))
        let avFlags = clientPairs.first { $0.id == NTLMAVPair.flags }.map { $0.value.count >= 4 ? $0.value.le32(0) : 0 } ?? 0
        var micVerified = false
        if avFlags & NTLMAVPair.flagMICPresent != 0 {
            guard let at = auth.micOffset else {
                throw AuthKitError.ntlm(status: AuthKitError.NTStatus.invalidParameter, reason: "MIC flagged but no MIC field")
            }
            let got = Array(auth.raw[at..<(at + 16)])
            var zeroed = auth.raw
            for i in at..<(at + 16) { zeroed[i] = 0 }
            let expected = NTLMCrypto.mic(exportedSessionKey: exported, negotiate: negotiate.raw, challenge: challengeBytes,
                                          authenticate: zeroed)
            guard ConstantTime.equal(expected, got) else {
                throw AuthKitError.ntlm(status: AuthKitError.NTStatus.logonFailure, reason: "MIC does not verify")
            }
            micVerified = true
        }
        Self.logger.info("NTLM: authenticated \(auth.domain, privacy: .public)\\\(auth.user, privacy: .public)")
        return Result(identity: account.identity,
                      context: NTLMSecurityContext(exportedSessionKey: exported, flags: flags, isServer: true),
                      micVerified: micVerified, exportedSessionKey: exported)
    }
}
