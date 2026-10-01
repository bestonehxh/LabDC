import SheepCrypto

/// GSS-API mechanism OIDs used by AuthKit, in DER content form (without tag and length).
public enum GSSMechanism: Sendable, Hashable, CustomStringConvertible {
    /// Kerberos V5, 1.2.840.113554.1.2.2 (RFC 1964 / RFC 4121).
    case kerberos
    /// Microsoft's mistyped Kerberos OID, 1.2.840.48018.1.2.2 (MS-KILE §3.1.5.11); it means Kerberos.
    case msKerberos
    /// NTLMSSP, 1.3.6.1.4.1.311.2.2.10 (MS-NLMP).
    case ntlm
    /// SPNEGO, 1.3.6.1.5.5.2 (RFC 4178).
    case spnego
    /// Anything else, as DER content bytes.
    case other([UInt8])

    public static let kerberosOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02]
    public static let msKerberosOID: [UInt8] = [0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02]
    public static let ntlmOID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A]
    public static let spnegoOID: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]

    public init(oidContent bytes: [UInt8]) {
        switch bytes {
        case Self.kerberosOID: self = .kerberos
        case Self.msKerberosOID: self = .msKerberos
        case Self.ntlmOID: self = .ntlm
        case Self.spnegoOID: self = .spnego
        default: self = .other(bytes)
        }
    }

    /// DER content bytes of the OID.
    public var oidContent: [UInt8] {
        switch self {
        case .kerberos: Self.kerberosOID
        case .msKerberos: Self.msKerberosOID
        case .ntlm: Self.ntlmOID
        case .spnego: Self.spnegoOID
        case .other(let b): b
        }
    }

    /// Full DER TLV (`06 len content`).
    public var oidDER: [UInt8] { [0x06] + DERLength.encode(oidContent.count) + oidContent }

    /// Kerberos under either OID.
    public var isKerberos: Bool { self == .kerberos || self == .msKerberos }

    public var description: String {
        switch self {
        case .kerberos: "krb5"
        case .msKerberos: "ms-krb5"
        case .ntlm: "ntlmssp"
        case .spnego: "spnego"
        case .other(let b): "oid(\(b.hex))"
        }
    }
}

/// DER definite lengths.
enum DERLength {
    static func encode(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    /// Reads a definite length at `index`, advancing it. Accepts non-minimal forms (BER).
    static func decode(_ b: [UInt8], _ index: inout Int) throws -> Int {
        guard index < b.count else { throw AuthKitError.malformed(what: "length", reason: "truncated") }
        let first = b[index]; index += 1
        if first < 0x80 { return Int(first) }
        let n = Int(first & 0x7F)
        guard n > 0, n <= 4, index + n <= b.count else {
            throw AuthKitError.malformed(what: "length", reason: "indefinite or oversized length")
        }
        var v = 0
        for _ in 0..<n { v = (v << 8) | Int(b[index]); index += 1 }
        return v
    }
}

/// The RFC 2743 §3.1 InitialContextToken framing:
/// `60 len 06 len <mech OID> <inner token>` (APPLICATION 0 IMPLICIT, constructed).
public enum GSSFraming {
    /// Wraps `inner` with the framing for `mech`.
    public static func wrap(mech: GSSMechanism, _ inner: [UInt8]) -> [UInt8] {
        let body = mech.oidDER + inner
        return [0x60] + DERLength.encode(body.count) + body
    }

    /// Splits a framed token into its mechanism and inner bytes. The length must cover the
    /// whole input exactly (Heimdal and Windows both frame the entire token).
    public static func unwrap(_ token: [UInt8]) throws -> (mech: GSSMechanism, inner: [UInt8]) {
        guard token.first == 0x60 else { throw AuthKitError.malformed(what: "GSS token", reason: "no 0x60 framing") }
        var i = 1
        let len = try DERLength.decode(token, &i)
        guard i + len == token.count else {
            throw AuthKitError.malformed(what: "GSS token", reason: "framing length \(len) does not match \(token.count - i) bytes")
        }
        guard i < token.count, token[i] == 0x06 else { throw AuthKitError.malformed(what: "GSS token", reason: "no mech OID") }
        i += 1
        let olen = try DERLength.decode(token, &i)
        guard i + olen <= token.count else { throw AuthKitError.malformed(what: "GSS token", reason: "OID truncated") }
        let oid = Array(token[i..<(i + olen)])
        return (GSSMechanism(oidContent: oid), Array(token[(i + olen)...]))
    }
}

// MARK: - Byte helpers

extension Array where Element == UInt8 {
    mutating func appendBE16(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xFF)) }
    mutating func appendBE32(_ v: UInt32) { for s in stride(from: 24, through: 0, by: -8) { append(UInt8((v >> UInt32(s)) & 0xFF)) } }
    mutating func appendBE64(_ v: UInt64) { for s in stride(from: 56, through: 0, by: -8) { append(UInt8((v >> UInt64(s)) & 0xFF)) } }
    mutating func appendLE16(_ v: UInt16) { append(UInt8(v & 0xFF)); append(UInt8(v >> 8)) }
    mutating func appendLE32(_ v: UInt32) { for s in stride(from: 0, through: 24, by: 8) { append(UInt8((v >> UInt32(s)) & 0xFF)) } }
    mutating func appendLE64(_ v: UInt64) { for s in stride(from: 0, through: 56, by: 8) { append(UInt8((v >> UInt64(s)) & 0xFF)) } }

    func be16(_ at: Int) -> UInt16 { UInt16(self[at]) << 8 | UInt16(self[at + 1]) }
    func be32(_ at: Int) -> UInt32 { (0..<4).reduce(0) { $0 << 8 | UInt32(self[at + $1]) } }
    func be64(_ at: Int) -> UInt64 { (0..<8).reduce(0) { $0 << 8 | UInt64(self[at + $1]) } }
    func le16(_ at: Int) -> UInt16 { UInt16(self[at]) | UInt16(self[at + 1]) << 8 }
    func le32(_ at: Int) -> UInt32 { (0..<4).reduce(0) { $0 | UInt32(self[at + $1]) << (8 * UInt32($1)) } }
    func le64(_ at: Int) -> UInt64 { (0..<8).reduce(0) { $0 | UInt64(self[at + $1]) << (8 * UInt64($1)) } }
}

extension String {
    /// UTF-16LE bytes, no terminator.
    var utf16LE: [UInt8] { utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] } }

    init(utf16LE bytes: ArraySlice<UInt8>) {
        let b = Array(bytes)
        var units: [UInt16] = []
        var i = 0
        while i + 1 < b.count { units.append(UInt16(b[i]) | UInt16(b[i + 1]) << 8); i += 2 }
        self = String(decoding: units, as: UTF16.self)
    }
}
