import Foundation
import Crypto

/// Vendor-Specific (type 26, RFC 2865 §5.26): vendor id (4) + sub-attributes (type, length ≥ 2,
/// value). Parsed with every length checked — a malformed VSA is nil, never a crash.
public struct VendorSpecific: Sendable, Equatable {
    public var vendor: UInt32
    public var subAttributes: [SubAttribute]

    public struct SubAttribute: Sendable, Equatable {
        public var type: UInt8
        public var value: [UInt8]
        public init(type: UInt8, value: [UInt8]) { self.type = type; self.value = value }
    }

    /// Microsoft (RFC 2548).
    public static let microsoft: UInt32 = 311

    /// MS VSA types (RFC 2548 §2).
    public enum MS: UInt8, Sendable {
        case chapError = 2, chapNTEncPW = 6, mppeEncryptionPolicy = 7, mppeEncryptionTypes = 8, chapChallenge = 11
        case mppeSendKey = 16, mppeRecvKey = 17, chap2Response = 25, chap2Success = 26, chap2CPW = 27
    }

    public init(vendor: UInt32, subAttributes: [SubAttribute]) {
        self.vendor = vendor
        self.subAttributes = subAttributes
    }

    /// Parses the value of one Vendor-Specific attribute; nil when a sub-attribute's length is
    /// below 2 or runs past the end.
    public init?(_ value: [UInt8]) {
        guard value.count >= 4 else { return nil }
        vendor = value.prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
        subAttributes = []
        var i = 4
        while i < value.count {
            guard i + 2 <= value.count else { return nil }
            let type = value[i], len = Int(value[i + 1])
            guard len >= 2, i + len <= value.count else { return nil }
            subAttributes.append(SubAttribute(type: type, value: Array(value[(i + 2)..<(i + len)])))
            i += len
        }
    }

    /// One Vendor-Specific attribute carrying one sub-attribute; nil when the value is too long.
    public static func attribute(vendor: UInt32, type: UInt8, value: [UInt8]) -> RADIUSPacket.Attribute? {
        guard value.count + 2 <= 255 - 2 - 4 else { return nil }
        let payload: [UInt8] = [UInt8(vendor >> 24 & 0xff), UInt8(vendor >> 16 & 0xff),
                                UInt8(vendor >> 8 & 0xff), UInt8(vendor & 0xff),
                                type, UInt8(value.count + 2)] + value
        return .init(.vendorSpecific, payload)
    }
}

extension RADIUSPacket {
    /// The value of the first vendor sub-attribute `type` of `vendor`, across every
    /// (well-formed) Vendor-Specific attribute.
    public func vendorAttribute(vendor: UInt32, type: UInt8) -> [UInt8]? {
        for attr in all(.vendorSpecific) {
            guard let vsa = VendorSpecific(attr.value), vsa.vendor == vendor else { continue }
            if let sub = vsa.subAttributes.first(where: { $0.type == type }) { return sub.value }
        }
        return nil
    }

    public func microsoft(_ type: VendorSpecific.MS) -> [UInt8]? {
        vendorAttribute(vendor: VendorSpecific.microsoft, type: type.rawValue)
    }

    /// A 4-byte big-endian integer attribute.
    public static func integer(_ type: AttrType, _ value: UInt32) -> Attribute {
        .init(type, bigEndian(value))
    }

    /// RFC 2868 §3.1/§3.2: a tagged integer — tag byte + the low 3 bytes of the value
    /// (Tunnel-Type, Tunnel-Medium-Type). Tag 0 means "no tunnel grouping", the widely used form.
    public static func taggedInteger(_ type: AttrType, tag: UInt8 = 0, _ value: UInt32) -> Attribute {
        .init(type, [tag, UInt8(value >> 16 & 0xff), UInt8(value >> 8 & 0xff), UInt8(value & 0xff)])
    }

    /// RFC 2868 §3.6: a tagged string — a tag byte (0x01…0x1F) before the text; tag 0 sends the
    /// text alone (the tag field is optional for strings, and a first byte ≥ 0x20 is text).
    public static func taggedString(_ type: AttrType, tag: UInt8 = 0, _ value: String) -> Attribute {
        (1...0x1F).contains(tag) ? .init(type, [tag] + Array(value.utf8)) : .init(type, Array(value.utf8))
    }

    static func bigEndian(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
    }
}

/// RFC 2548 §2.4.2/§2.4.3: MS-MPPE-Send-Key / MS-MPPE-Recv-Key values. Salt (2 bytes, high bit
/// set, unique per key in a reply) + the encrypted string: P = key length (1) + key + zero pad to
/// 16-byte blocks; b(1) = MD5(secret + Request-Authenticator + salt), c(i) = p(i) ⊕ b(i),
/// b(i) = MD5(secret + c(i-1)).
public enum MPPEKeyAttribute {
    public static func encrypt(key: [UInt8], secret: [UInt8], requestAuthenticator: [UInt8], salt: [UInt8]) -> [UInt8] {
        var s = Array(salt.prefix(2))
        while s.count < 2 { s.append(0) }
        s[0] |= 0x80
        var plain = [UInt8(key.count)] + key
        if plain.count % 16 != 0 { plain += [UInt8](repeating: 0, count: 16 - plain.count % 16) }
        var out = s
        var chain = requestAuthenticator + s
        for block in stride(from: 0, to: plain.count, by: 16) {
            let b = Array(Insecure.MD5.hash(data: secret + chain))
            let c = zip(plain[block..<block + 16], b).map { $0 ^ $1 }
            out += c
            chain = c
        }
        return out
    }

    /// The reverse (a NAS's view; the tests use it for the round trip). nil when malformed.
    public static func decrypt(_ value: [UInt8], secret: [UInt8], requestAuthenticator: [UInt8]) -> [UInt8]? {
        guard value.count >= 18, (value.count - 2) % 16 == 0, value[0] & 0x80 != 0 else { return nil }
        let salt = Array(value[0..<2])
        var plain: [UInt8] = []
        var chain = requestAuthenticator + salt
        for block in stride(from: 2, to: value.count, by: 16) {
            let c = Array(value[block..<block + 16])
            let b = Array(Insecure.MD5.hash(data: secret + chain))
            plain += zip(c, b).map { $0 ^ $1 }
            chain = c
        }
        let len = Int(plain[0])
        guard len + 1 <= plain.count else { return nil }
        return Array(plain[1..<(1 + len)])
    }
}

/// Names for the few enumerated values the policy engine shows (RFC 2865 §5.6, RFC 3748 §5).
public enum RADIUSNames {
    public static let serviceTypes: [UInt32: String] = [
        1: "Login-User", 2: "Framed-User", 3: "Callback-Login-User", 4: "Callback-Framed-User",
        5: "Outbound-User", 6: "Administrative-User", 7: "NAS-Prompt-User", 8: "Authenticate-Only",
        9: "Callback-NAS-Prompt", 10: "Call-Check", 11: "Callback-Administrative",
    ]

    public static func serviceType(_ value: UInt32) -> String { serviceTypes[value] ?? String(value) }

    public static let eapTypes: [UInt8: String] = [
        1: "Identity", 4: "MD5-Challenge", 6: "GTC", 13: "EAP-TLS", 21: "EAP-TTLS", 25: "PEAP",
        26: "EAP-MSCHAPv2", 43: "EAP-FAST",
    ]

    public static func eapType(_ value: UInt8) -> String { eapTypes[value] ?? "EAP type \(value)" }

    /// Acct-Status-Type (RFC 2866 §5.1).
    public static func acctStatusType(_ value: UInt32) -> String {
        switch value {
        case 1: "Start"
        case 2: "Stop"
        case 3: "Interim-Update"
        case 7: "Accounting-On"
        case 8: "Accounting-Off"
        default: "status \(value)"
        }
    }
}
