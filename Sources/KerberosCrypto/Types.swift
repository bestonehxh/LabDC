/// Kerberos encryption types implemented in phase 0 (RFC 3961 §8 / IANA numbers).
public enum EncryptionType: Int32, Sendable, CaseIterable, CustomStringConvertible {
    /// `aes256-cts-hmac-sha1-96` (RFC 3962).
    case aes256CtsHmacSha1 = 18
    /// `aes128-cts-hmac-sha1-96` (RFC 3962).
    case aes128CtsHmacSha1 = 17
    /// `arcfour-hmac` / `rc4-hmac` (RFC 4757).
    case rc4Hmac = 23

    /// Length of the protocol key (and of the random-to-key input) in bytes.
    public var keyLength: Int {
        switch self {
        case .aes256CtsHmacSha1: 32
        case .aes128CtsHmacSha1: 16
        case .rc4Hmac: 16
        }
    }

    /// Bytes `encrypt` adds to a plaintext: confounder plus integrity tag.
    public var overhead: Int {
        switch self {
        case .aes256CtsHmacSha1, .aes128CtsHmacSha1: AESProfile.confounderLength + AESProfile.macLength
        case .rc4Hmac: RC4HMAC.confounderLength + RC4HMAC.macLength
        }
    }

    public var description: String {
        switch self {
        case .aes256CtsHmacSha1: "aes256-cts-hmac-sha1-96"
        case .aes128CtsHmacSha1: "aes128-cts-hmac-sha1-96"
        case .rc4Hmac: "arcfour-hmac"
        }
    }
}

/// Keyed checksum types implemented in phase 0.
public enum ChecksumType: Int32, Sendable, CaseIterable, CustomStringConvertible {
    /// `hmac-sha1-96-aes256` (RFC 3962), 12 bytes.
    case hmacSha1Aes256 = 16
    /// `hmac-sha1-96-aes128` (RFC 3962), 12 bytes.
    case hmacSha1Aes128 = 15
    /// `hmac-md5` / `KERB_CHECKSUM_HMAC_MD5` (RFC 4757 §4, MS-PAC), 16 bytes, RC4 keys only.
    case hmacMd5 = -138

    /// Length of the checksum value in bytes.
    public var length: Int {
        switch self {
        case .hmacSha1Aes256, .hmacSha1Aes128: AESProfile.macLength
        case .hmacMd5: 16
        }
    }

    /// The only encryption type whose keys this checksum accepts.
    public var keyType: EncryptionType {
        switch self {
        case .hmacSha1Aes256: .aes256CtsHmacSha1
        case .hmacSha1Aes128: .aes128CtsHmacSha1
        case .hmacMd5: .rc4Hmac
        }
    }

    public var description: String {
        switch self {
        case .hmacSha1Aes256: "hmac-sha1-96-aes256"
        case .hmacSha1Aes128: "hmac-sha1-96-aes128"
        case .hmacMd5: "hmac-md5"
        }
    }
}

/// A Kerberos protocol key (RFC 3961 "protocol key"): the enctype plus the raw key bytes.
///
/// `description` never prints the key bytes, so a key can be interpolated into log lines.
public struct KerberosKey: Sendable, Equatable, CustomStringConvertible {
    public let type: EncryptionType
    public let bytes: [UInt8]

    /// - Throws: `KerberosCryptoError.invalidKeyLength` when `bytes.count != type.keyLength`.
    public init(type: EncryptionType, bytes: [UInt8]) throws {
        guard bytes.count == type.keyLength else {
            throw KerberosCryptoError.invalidKeyLength(type: type, expected: type.keyLength, actual: bytes.count)
        }
        self.type = type
        self.bytes = bytes
    }

    /// For internal callers that already guarantee the length.
    init(uncheckedType type: EncryptionType, bytes: [UInt8]) {
        precondition(bytes.count == type.keyLength)
        self.type = type
        self.bytes = bytes
    }

    public var description: String { "KerberosKey(\(type), \(bytes.count * 8) bits)" }
}

/// Key usage numbers (RFC 4120 §7.5.1, MS-KILE, MS-PAC). Modelled as named `Int32`
/// constants rather than an enum so any number can be passed through.
public enum KeyUsage {
    /// AS-REQ PA-ENC-TIMESTAMP, client key.
    public static let asReqPaEncTimestamp: Int32 = 1
    /// Ticket enc-part (AS-REP and TGS-REP), service key.
    public static let kdcRepTicket: Int32 = 2
    /// AS-REP enc-part, client key (RC4 maps this to 8).
    public static let asRepEncPart: Int32 = 3
    /// TGS-REQ authorization-data, TGS session key.
    public static let tgsReqAuthDataSessionKey: Int32 = 4
    /// TGS-REQ authorization-data, authenticator subkey.
    public static let tgsReqAuthDataSubkey: Int32 = 5
    /// TGS-REQ PA-TGS-REQ authenticator `cksum` over req-body, TGS session key.
    public static let tgsReqAuthenticatorChecksum: Int32 = 6
    /// TGS-REQ PA-TGS-REQ authenticator, TGS session key.
    public static let tgsReqAuthenticatorSessionKey: Int32 = 7
    /// TGS-REP enc-part, TGS session key.
    public static let tgsRepEncPartSessionKey: Int32 = 8
    /// TGS-REP enc-part, authenticator subkey (RC4 keeps T = 9, like MIT and Heimdal).
    public static let tgsRepEncPartSubkey: Int32 = 9
    /// AP-REQ authenticator `cksum`, application session key.
    public static let apReqAuthenticatorChecksum: Int32 = 10
    /// AP-REQ authenticator, application session key.
    public static let apReqAuthenticator: Int32 = 11
    /// AP-REP enc-part, application session key.
    public static let apRepEncPart: Int32 = 12
    /// KRB-PRIV enc-part.
    public static let krbPrivEncPart: Int32 = 13
    /// KRB-CRED enc-part.
    public static let krbCredEncPart: Int32 = 14
    /// KRB-SAFE checksum.
    public static let krbSafeChecksum: Int32 = 15
    /// `KERB_NON_KERB_CKSUM_SALT` (MS-PAC §2.8): PAC server, KDC and ticket signatures.
    public static let pacChecksum: Int32 = 17
    /// Usage 23, the RFC 4757 "sign wrap token" that RC4 remaps to T = 13. Not used in phase 0.
    public static let gssSignWrapToken: Int32 = 23
}
