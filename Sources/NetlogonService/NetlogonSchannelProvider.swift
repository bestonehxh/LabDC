import AuthKit
import Foundation
import RPCKit
import SheepCrypto
import Store

/// RPC authentication provider for `RPC_C_AUTHN_NETLOGON` (auth type 68), the schannel used for
/// NETLOGON calls after the secure channel is established (MS-NRPC §3.3.4). At bind it parses the
/// client's `NL_AUTH_MESSAGE`, resolves the computer's secure-channel session key from the shared
/// state, and replies with an `NL_AUTH_MESSAGE` response; per PDU it applies the AES
/// `NL_AUTH_SHA2_SIGNATURE` (integrity, auth level 5) or seals with AES-CFB8 (privacy, level 6).
/// The RC4 `NL_AUTH_SIGNATURE` legacy path is left off (`allowRC4` reserved for a lab flag).
///
/// WP-AJ: a bind that names a computer with no secure-channel state here (the DC restarted since
/// the client's `NetrServerAuthenticate3`, or the client never authenticated) or that is not a
/// type-68 bind at all throws `RPCError.bindRejected`, which the connection answers with a
/// `bind_nak` at once. Samba's client maps any bind_nak on a schannel bind to
/// `NT_STATUS_NETWORK_ACCESS_DENIED`, deletes its cached Netlogon credentials and re-runs
/// `NetrServerReqChallenge`/`NetrServerAuthenticate3` — previously it got no answer and timed out.
///
/// On `ncacn_ip_tcp` there is no SMB session to carry the caller's identity, so the TCP endpoint
/// builds the provider with `identityDirectory`: once bound, `establishedIdentity` is the secure
/// channel's computer account (what the SMB session of a winbind/Windows member is on the pipe).
/// On the pipes it stays nil, so the SMB session identity is kept exactly as before.
public struct NetlogonSchannelProvider: RPCAuthProvider, RPCConnectionIdentity {
    // NL_AUTH_MESSAGE
    static let messageResponse: UInt32 = 1
    static let flagNetbiosDomain: UInt32 = 0x1
    static let flagNetbiosHost: UInt32 = 0x2
    // Signature/seal algorithm ids (MS-NRPC §2.2.1.3.2/3).
    static let sigHMACSHA256: UInt16 = 0x0013
    static let sealAES128: UInt16 = 0x001A
    static let sealNotEncrypted: UInt16 = 0xFFFF

    private let store: NetlogonStateStore
    private let rng: RandomBytes
    private let identityDirectory: DirectoryStore?
    private var identity: AuthenticatedIdentity?
    private var computerName: String?
    private var level: RPCAuthLevel = .none
    private var sessionKey: [UInt8] = []
    private var aes = true
    private var established = false
    /// The schannel sequence number (MS-NRPC §3.3.4.2). WP-Z: it is ONE counter for the whole
    /// association, advanced on every protected PDU in either direction (Samba `netsec_do_seq_num`
    /// increments it on send and on receive; impacket does the same). Request n therefore carries
    /// 2n and its response 2n+1 — not RPCKit's per-direction counters, which gave response 0 for
    /// request 0 and made Samba's winbindd fail the response check with ACCESS_DENIED.
    private var sequence = SequenceCounter()

    /// A per-association counter shared by the non-mutating sign/seal/verify/unseal calls.
    final class SequenceCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var value: UInt64 = 0
        func next() -> UInt64 {
            lock.lock(); defer { lock.unlock() }
            let v = value
            value &+= 1
            return v
        }
    }

    /// - Parameter identityDirectory: when set (the `ncacn_ip_tcp` endpoint), the bound channel's
    ///   computer account becomes the connection identity (`RPCConnectionIdentity`).
    public init(store: NetlogonStateStore, rng: RandomBytes = RandomBytes(), identityDirectory: DirectoryStore? = nil) {
        self.store = store
        self.rng = rng
        self.identityDirectory = identityDirectory
    }

    public var authType: RPCAuthType { .schannel }
    public var authLevel: RPCAuthLevel { level }
    public var isEstablished: Bool { established }
    public var establishedIdentity: AuthenticatedIdentity? { established ? identity : nil }
    public var establishedSessionKey: [UInt8]? { nil }
    /// The computer whose secure channel this binding uses (every request is signed with its key).
    public var boundPrincipal: String? { established ? computerName : nil }

    public mutating func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? {
        guard authType == .schannel else {
            throw RPCError.bindRejected(.authenticationTypeNotRecognized)
        }
        guard authData.count >= 8, authData.prefix(4).allSatisfy({ $0 == 0 }) else {   // NL_AUTH_MESSAGE, type 0 (negotiate)
            throw RPCError.bindRejected(.reasonNotSpecified)
        }
        // CVE-2022-38023 class: the NL_AUTH_MESSAGE proves nothing by itself — possession of the
        // session key is shown only by the per-PDU NL_AUTH_SHA2_SIGNATURE. A bind below packet
        // integrity (connect/call/pkt) would let unsigned requests run as the secure channel, so it
        // is refused (Windows' RequireSignOrSeal, Samba's `server schannel require seal`).
        guard authLevel == .pktIntegrity || authLevel == .pktPrivacy else {
            throw RPCError.bindRejected(.reasonNotSpecified)
        }
        // The message must name the computer, and that computer must have live secure-channel
        // state (there is no "most recent channel" fallback).
        guard let computer = Self.computerName(fromNLAuth: authData), !computer.isEmpty,
              let channel = store.channel(computer: computer) else {
            throw RPCError.bindRejected(.reasonNotSpecified)
        }
        if let dir = identityDirectory {
            identity = await Self.identity(of: channel, in: dir)
        }
        self.computerName = channel.computerName
        self.sessionKey = channel.sessionKey
        self.aes = channel.usesAES
        self.level = authLevel
        self.established = true
        self.sequence = SequenceCounter()
        // NL_AUTH_MESSAGE response: MessageType = 1, Flags = 0, a 4-byte buffer.
        var out = [UInt8]()
        out.appendLE32(Self.messageResponse)
        out.appendLE32(0)
        out.append(contentsOf: [0, 0, 0, 0])
        return out
    }

    /// The computer account behind a secure channel, as an `AuthenticatedIdentity` (SID, groups).
    static func identity(of channel: NetlogonChannel, in dir: DirectoryStore) async -> AuthenticatedIdentity? {
        let name = channel.accountName.hasSuffix("$") ? channel.accountName : channel.computerName + "$"
        guard let entry = try? await dir.read(sam: name), let sid = entry.sid,
              let info = try? await dir.domainInfo() else { return nil }
        let groups = (try? await dir.groupSIDs(of: entry.id)) ?? []
        return AuthenticatedIdentity(sid: sid, sam: entry.samAccountName ?? name, domain: info.netbiosDomain,
                                     groups: groups)
    }

    /// Parses the `NL_AUTH_MESSAGE` and returns the NetBIOS host name (bit 0x2) when present.
    static func computerName(fromNLAuth data: [UInt8]) -> String? {
        guard data.count >= 8 else { return nil }
        let flags = UInt32(data[4]) | (UInt32(data[5]) << 8) | (UInt32(data[6]) << 16) | (UInt32(data[7]) << 24)
        var i = 8
        func cstr() -> String? {
            guard i < data.count else { return nil }
            var bytes = [UInt8]()
            while i < data.count, data[i] != 0 { bytes.append(data[i]); i += 1 }
            if i < data.count { i += 1 }  // skip NUL
            return String(decoding: bytes, as: UTF8.self)
        }
        if flags & flagNetbiosDomain != 0 { _ = cstr() }
        if flags & flagNetbiosHost != 0 { return cstr() }
        return nil
    }

    // MARK: per-PDU protection (§3.3.4.2)

    /// The 8-byte fixed head of an `NL_AUTH_SHA2_SIGNATURE`.
    private func sigHead(sealed: Bool) -> [UInt8] {
        var h = [UInt8]()
        h.appendLE16(Self.sigHMACSHA256)
        h.appendLE16(sealed ? Self.sealAES128 : Self.sealNotEncrypted)
        h.appendLE16(0xFFFF)          // Pad
        h.appendLE16(0)               // Flags
        return h
    }

    public func sign(body: [UInt8], sequence _: UInt32) throws -> [UInt8] {
        let head = sigHead(sealed: false)
        let checksum = NetlogonCrypto.signatureChecksum(sessionKey: sessionKey, sigHeader8: head,
                                                        confounder: [], message: body)
        let derived = NetlogonCrypto.deriveSequenceNumber(sequence.next(), initiator: false)
        let seqEnc = NetlogonCrypto.sealSequenceNumberAES(sessionKey: sessionKey, checksum: checksum, derived)
        return head + seqEnc + checksum + [UInt8](repeating: 0, count: 24)   // 48-byte integrity signature
    }

    public func seal(body: [UInt8], sequence _: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) {
        let head = sigHead(sealed: true)
        let confounder = rng.next(8)
        let checksum = NetlogonCrypto.signatureChecksum(sessionKey: sessionKey, sigHeader8: head,
                                                        confounder: confounder, message: body)
        let derived = NetlogonCrypto.deriveSequenceNumber(sequence.next(), initiator: false)
        let seqEnc = NetlogonCrypto.sealSequenceNumberAES(sessionKey: sessionKey, checksum: checksum, derived)
        let sealKey = NetlogonCrypto.sealKeyAES(sessionKey)
        let iv = derived + derived
        let stream = NetlogonCrypto.aesCFB8(key: sealKey, iv: iv, confounder + body, encrypt: true)
        let confounderEnc = Array(stream.prefix(8))
        let sealedBody = Array(stream.dropFirst(8))
        let auth = head + seqEnc + checksum + confounderEnc + [UInt8](repeating: 0, count: 24)  // 56 bytes
        return (sealedBody, auth)
    }

    public func verify(body: [UInt8], auth: [UInt8], sequence _: UInt32) throws {
        guard auth.count >= 24 else { throw RPCError.auth("short NL_AUTH signature") }
        let expected = NetlogonCrypto.deriveSequenceNumber(sequence.next(), initiator: true)
        let head = Array(auth[0..<8])
        let checksumRecv = Array(auth[16..<24])
        let checksum = NetlogonCrypto.signatureChecksum(sessionKey: sessionKey, sigHeader8: head,
                                                        confounder: [], message: body)
        guard ConstantTime.equal(checksum, checksumRecv) else { throw RPCError.auth("NL_AUTH checksum mismatch") }
        try checkSequence(auth: auth, checksum: checksum, expected: expected)
    }

    public func unseal(body: [UInt8], auth: [UInt8], sequence _: UInt32) throws -> [UInt8] {
        guard auth.count >= 32 else { throw RPCError.auth("short NL_AUTH seal trailer") }
        let expected = NetlogonCrypto.deriveSequenceNumber(sequence.next(), initiator: true)
        let checksumRecv = Array(auth[16..<24])
        let confounderEnc = Array(auth[24..<32])
        // Seal IV = the expected (plain) sequence number twice (Samba decrypts with its own counter,
        // not the wire value); then the checksum covers header ‖ plain confounder ‖ plain stub.
        let sealKey = NetlogonCrypto.sealKeyAES(sessionKey)
        let plain = NetlogonCrypto.aesCFB8(key: sealKey, iv: expected + expected, confounderEnc + body, encrypt: false)
        let checksum = NetlogonCrypto.signatureChecksum(sessionKey: sessionKey, sigHeader8: Array(auth[0..<8]),
                                                        confounder: Array(plain.prefix(8)), message: Array(plain.dropFirst(8)))
        guard ConstantTime.equal(checksum, checksumRecv) else { throw RPCError.auth("NL_AUTH checksum mismatch (sealed)") }
        try checkSequence(auth: auth, checksum: checksum, expected: expected)
        return Array(plain.dropFirst(8))
    }

    /// The wire SequenceNumber must decrypt to the expected counter value with the initiator bit.
    private func checkSequence(auth: [UInt8], checksum: [UInt8], expected: [UInt8]) throws {
        let wire = NetlogonCrypto.sealSequenceNumberAES(sessionKey: sessionKey, checksum: checksum, expected)
        guard ConstantTime.equal(wire, Array(auth[8..<16])) else {
            throw RPCError.auth("NL_AUTH sequence number mismatch")
        }
    }
}

extension Array where Element == UInt8 {
    mutating func appendLE16(_ v: UInt16) { append(UInt8(truncatingIfNeeded: v)); append(UInt8(truncatingIfNeeded: v >> 8)) }
    mutating func appendLE32(_ v: UInt32) { for s in stride(from: 0, to: 32, by: 8) { append(UInt8(truncatingIfNeeded: v >> s)) } }
}
