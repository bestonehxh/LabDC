import CryptoKit
import Foundation

/// Returns the NTOWFv1 (NT hash, 16 bytes) of the account with relative ID `rid`, current
/// password or (`previous`) the one before it; nil when there is no such machine account.
/// WP-X wires this to the Store (`read(sid:)` + `secrets(id:).ntHash`).
public typealias SNTPKeyProvider = @Sendable (_ rid: UInt32, _ previous: Bool) async -> [UInt8]?

/// The MS-SNTP trailer of a request (MS-SNTP §2.2.1, §2.2.3).
public enum MSSNTPAuthenticator: Sendable, Hashable {
    /// 68-byte request: little-endian Key Identifier (RID in the low 31 bits, key selector in the
    /// top bit) + 16-byte checksum (zero from Windows clients, ignored).
    case classic(keyID: UInt32)
    /// 120-byte request: Key Identifier (all 32 bits are the RID), Reserved, Flags
    /// (`USE_OLDKEY_VERSION` 0x01), ClientHashIDHints (`NTLM_PWD_HASH` 0x01), SignatureHashID,
    /// 64-byte checksum.
    case extended(keyID: UInt32, flags: UInt8, clientHashIDHints: UInt8)

    public static let classicLength = 68
    public static let extendedLength = 120

    /// Parses the trailer of a 68- or 120-byte request; nil for any other length.
    public init?(request: [UInt8]) {
        switch request.count {
        case Self.classicLength:
            self = .classic(keyID: rdLE32(request, 48))
        case Self.extendedLength:
            self = .extended(keyID: rdLE32(request, 48), flags: request[53], clientHashIDHints: request[54])
        default:
            return nil
        }
    }

    /// The account RID and key selector the request names.
    public var account: (rid: UInt32, previous: Bool) {
        switch self {
        case .classic(let id): (id & 0x7FFF_FFFF, id & 0x8000_0000 != 0)
        case .extended(let id, let flags, _): (id, flags & 0x01 != 0)
        }
    }

    /// Classic checksum (MS-SNTP §3.2.5.1.1 via MS-NRPC §3.5.4.8.2 `NetrLogonComputeServerDigest`):
    /// `MD5(NT hash || response[0..<48])`.
    public static func classicChecksum(ntHash: [UInt8], response header: [UInt8]) -> [UInt8] {
        var md5 = Insecure.MD5()
        md5.update(data: ntHash)
        md5.update(data: header.prefix(NTPPacket.headerLength))
        return Array(md5.finalize())
    }

    /// Extended checksum (MS-SNTP §3.1.5.5): `HMAC-SHA512(K, response[0..<48])` with
    /// `K = SP800-108 counter-mode KDF(NT hash, "sntp-ms", Key Identifier)`.
    ///
    /// UNVERIFIED: the spec leaves the KDF's PRF and encodings open and no open implementation
    /// does this format. This uses the conventional SP800-108 §5.1 form Microsoft uses elsewhere:
    /// PRF HMAC-SHA512, `[i=1]BE32 || "sntp-ms" || 0x00 || KeyIdentifier(LE, as sent) || [L=512]BE32`.
    /// A wrong guess only makes a Windows client ignore the reply (as with an unsigned one).
    public static func extendedChecksum(ntHash: [UInt8], keyID: UInt32, response header: [UInt8]) -> [UInt8] {
        let kdfInput = be32(1) + Array("sntp-ms".utf8) + [0] + le32(keyID) + be32(512)
        let k = Array(HMAC<SHA512>.authenticationCode(for: kdfInput, using: SymmetricKey(data: ntHash)))
        return Array(HMAC<SHA512>.authenticationCode(for: Array(header.prefix(NTPPacket.headerLength)),
                                                     using: SymmetricKey(data: k)))
    }
}

/// Builds SNTP replies (RFC 4330 §5, server side) plus MS-SNTP authenticated replies.
///
/// - 48-byte client (mode 3) request -> mode 4 reply; symmetric active (mode 1) -> mode 2.
///   Version copied from the request (1–4; others dropped), LI 0, `Poll` echoed, `Precision` -20,
///   `Originate` = the request's `Transmit`, `Receive`/`Transmit` from the clock, `Reference` =
///   the receive time with the fraction cleared.
/// - 68/120-byte MS-SNTP requests: signed with the key provider when it knows the RID (the
///   reply echoes the Key Identifier, MS-SNTP note <4>); otherwise answered with a plain
///   48-byte reply when `answerUnauthenticated`, else dropped (MS-SNTP §3.2.5.1.1 SHOULD).
/// - Other modes, short packets and other lengths' trailers: mode 3/1 with a non-MS trailer
///   (RFC 5905 MAC / extension fields) get a plain reply; everything else is dropped.
public struct SNTPResponder: Sendable {
    public var stratum: UInt8
    public var referenceID: [UInt8]
    public var precision: Int8 = -20
    /// 1/1024 s in NTP short format.
    public var rootDelay: UInt32 = 0x0000_0040
    /// ~10 ms in NTP short format.
    public var rootDispersion: UInt32 = 0x0000_028F
    public var answerUnauthenticated: Bool
    public var keyProvider: SNTPKeyProvider?
    public let clock: @Sendable () -> Date

    public init(stratum: UInt8 = 2, referenceID: String = "LOCL", answerUnauthenticated: Bool = true,
                keyProvider: SNTPKeyProvider? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.stratum = stratum
        self.referenceID = Array((Array(referenceID.utf8) + [0, 0, 0, 0]).prefix(4))
        self.answerUnauthenticated = answerUnauthenticated
        self.keyProvider = keyProvider
        self.clock = clock
    }

    /// The reply datagram for `request` received at `receivedAt`, or nil to stay silent.
    public func reply(to request: [UInt8], receivedAt: Date) async -> [UInt8]? {
        guard let req = try? NTPPacket(bytes: request), (1...4).contains(req.version) else { return nil }
        let replyMode: NTPPacket.Mode
        switch req.mode {
        case .client: replyMode = .server
        case .symmetricActive: replyMode = .symmetricPassive
        default: return nil
        }
        var out = NTPPacket()
        out.leapIndicator = 0
        out.version = req.version
        out.mode = replyMode
        out.stratum = stratum
        out.poll = req.poll
        out.precision = precision
        out.rootDelay = rootDelay
        out.rootDispersion = rootDispersion
        out.referenceID = referenceID
        let received = NTPTimestamp(date: receivedAt)
        out.referenceTimestamp = NTPTimestamp(seconds: received.seconds, fraction: 0)
        out.originateTimestamp = req.transmitTimestamp
        out.receiveTimestamp = received
        guard let auth = MSSNTPAuthenticator(request: request) else {
            out.transmitTimestamp = NTPTimestamp(date: clock())
            return out.encode()
        }

        let (rid, previous) = auth.account
        var key: [UInt8]?
        if case .extended(_, _, let hints) = auth, hints & 0x01 == 0 {
            key = nil  // §3.2.5.1.1: no NTLM_PWD_HASH hint -> ignore
        } else if let keyProvider {
            key = await keyProvider(rid, previous)
        }
        out.transmitTimestamp = NTPTimestamp(date: clock())
        let header = out.encode()
        guard let key, key.count == 16 else { return answerUnauthenticated ? header : nil }
        switch auth {
        case .classic(let keyID):
            return header + le32(keyID) + MSSNTPAuthenticator.classicChecksum(ntHash: key, response: header)
        case .extended(let keyID, let flags, _):
            // Key Identifier, Reserved 0, Flags echoed, ClientHashIDHints 0, SignatureHashID NTLM_PWD_HASH.
            return header + le32(keyID) + [0, flags & 0x01, 0, 0x01]
                + MSSNTPAuthenticator.extendedChecksum(ntHash: key, keyID: keyID, response: header)
        }
    }
}

func rdLE32(_ b: [UInt8], _ i: Int) -> UInt32 {
    UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
}
