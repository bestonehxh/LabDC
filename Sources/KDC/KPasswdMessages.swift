import Foundation
import KerberosASN1
import SwiftASN1

/// RFC 3244 §2 result codes (and the Microsoft additions 6 and 7).
public enum KPasswdResult: UInt16, Sendable, CustomStringConvertible {
    case success = 0
    case malformed = 1
    case hardError = 2
    case authError = 3
    case softError = 4
    case accessDenied = 5
    case badVersion = 6
    case initialFlagNeeded = 7

    public var description: String {
        switch self {
        case .success: "SUCCESS"
        case .malformed: "MALFORMED"
        case .hardError: "HARDERROR"
        case .authError: "AUTHERROR"
        case .softError: "SOFTERROR"
        case .accessDenied: "ACCESSDENIED"
        case .badVersion: "BAD_VERSION"
        case .initialFlagNeeded: "INITIAL_FLAG_NEEDED"
        }
    }
}

/// A kpasswd request or reply (RFC 3244 §2, the RFC 3244 / Microsoft framing):
/// ```
/// message length (2, BE, whole message) | version (2, BE) | AP length (2, BE) | AP-REQ or AP-REP | KRB-PRIV or KRB-ERROR
/// ```
/// Request versions: 0x0001 = change password (the KRB-PRIV user-data is the new password),
/// 0xFF80 = Microsoft set password (user-data is `ChangePasswdData`). Replies always carry
/// version 0x0001; an error before the AP exchange has AP length 0 and a KRB-ERROR whose
/// `e-data` is the result code and string. Over TCP the whole message is additionally
/// preceded by the 4-byte Kerberos TCP length.
public struct KPasswdMessage: Sendable, Hashable {
    public static let changePasswordVersion: UInt16 = 0x0001
    public static let setPasswordVersion: UInt16 = 0xFF80
    public static let replyVersion: UInt16 = 0x0001

    public var version: UInt16
    /// AP-REQ (request) or AP-REP (reply); empty in an error reply.
    public var apData: [UInt8]
    /// KRB-PRIV, or KRB-ERROR in an error reply.
    public var body: [UInt8]

    public init(version: UInt16, apData: [UInt8], body: [UInt8]) {
        self.version = version
        self.apData = apData
        self.body = body
    }

    public enum ParseError: Error, Equatable { case tooShort, lengthMismatch(declared: Int, actual: Int), apTooLong }

    public init(bytes: [UInt8]) throws {
        guard bytes.count >= 6 else { throw ParseError.tooShort }
        let length = Int(bytes[0]) << 8 | Int(bytes[1])
        guard length == bytes.count else { throw ParseError.lengthMismatch(declared: length, actual: bytes.count) }
        version = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        let apLength = Int(bytes[4]) << 8 | Int(bytes[5])
        guard 6 + apLength <= bytes.count else { throw ParseError.apTooLong }
        apData = Array(bytes[6..<(6 + apLength)])
        body = Array(bytes[(6 + apLength)...])
    }

    public func encode() -> [UInt8] {
        let total = 6 + apData.count + body.count
        precondition(total <= 0xFFFF, "kpasswd message too long")
        return [UInt8(total >> 8), UInt8(total & 0xFF), UInt8(version >> 8), UInt8(version & 0xFF),
                UInt8(apData.count >> 8), UInt8(apData.count & 0xFF)] + apData + body
    }

    /// The reply user-data: result code (2, BE) followed by the result string.
    public static func resultData(_ result: KPasswdResult, _ text: String) -> [UInt8] {
        [UInt8(result.rawValue >> 8), UInt8(result.rawValue & 0xFF)] + Array(text.utf8)
    }

    /// Splits reply user-data (or KRB-ERROR e-data) into code and string.
    public static func parseResult(_ data: [UInt8]) -> (code: UInt16, text: String)? {
        guard data.count >= 2 else { return nil }
        return (UInt16(data[0]) << 8 | UInt16(data[1]), String(decoding: data[2...], as: UTF8.self))
    }
}

/// The Microsoft set-password request (RFC 3244 §2):
/// ```
/// ChangePasswdData ::= SEQUENCE {
///     newpasswd  [0] OCTET STRING,
///     targname   [1] PrincipalName OPTIONAL,
///     targrealm  [2] Realm OPTIONAL
/// }
/// ```
public struct ChangePasswdData: Sendable, Hashable {
    public var newPassword: [UInt8]
    public var targetName: PrincipalName?
    public var targetRealm: String?

    public init(newPassword: [UInt8], targetName: PrincipalName? = nil, targetRealm: String? = nil) {
        self.newPassword = newPassword
        self.targetName = targetName
        self.targetRealm = targetRealm
    }

    public init(derBytes: [UInt8]) throws {
        let root = try DER.parse(derBytes)
        self = try DER.sequence(root, identifier: .sequence) { nodes in
            let pw = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                Array(try ASN1OctetString(derEncoded: $0).bytes)
            }
            let name = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                try PrincipalName(derEncoded: $0)
            }
            let realm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                try KerberosString(derEncoded: $0).value
            }
            return ChangePasswdData(newPassword: pw, targetName: name, targetRealm: realm)
        }
    }

    public func encode() -> [UInt8] {
        var s = DER.Serializer()
        do {
            try s.appendConstructedNode(identifier: .sequence) { c in
                try c.serialize(ASN1OctetString(contentBytes: newPassword[...]), explicitlyTaggedWithTagNumber: 0,
                                tagClass: .contextSpecific)
                if let targetName { try c.serialize(targetName, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific) }
                if let targetRealm {
                    try c.serialize(KerberosString(targetRealm), explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
                }
            }
        } catch {
            preconditionFailure("ChangePasswdData serialization failed: \(error)")
        }
        return s.serializedBytes
    }
}

/// ```
/// AP-REP ::= [APPLICATION 15] SEQUENCE {
///     pvno     [0] INTEGER (5),
///     msg-type [1] INTEGER (15),
///     enc-part [2] EncryptedData -- EncAPRepPart
/// }
/// ```
/// (KerberosASN1 has no AP-REP; AuthKit has its own. Kept internal here so the two never
/// collide in a module that imports both.)
struct KPasswdAPRep: Sendable, Hashable {
    var encPart: EncryptedData

    func encode() -> [UInt8] {
        var s = DER.Serializer()
        do {
            try s.serialize(explicitlyTaggedWithTagNumber: 15, tagClass: .application) { c in
                try c.appendConstructedNode(identifier: .sequence) { c in
                    try c.serialize(Int64(5), explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
                    try c.serialize(Int64(15), explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
                    try c.serialize(encPart, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
                }
            }
        } catch {
            preconditionFailure("AP-REP serialization failed: \(error)")
        }
        return s.serializedBytes
    }

    init(encPart: EncryptedData) { self.encPart = encPart }

    init(derBytes: [UInt8]) throws {
        let root = try DER.parse(derBytes)
        self = try DER.explicitlyTagged(root, tagNumber: 15, tagClass: .application) { inner in
            try DER.sequence(inner, identifier: .sequence) { nodes in
                _ = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { try Int64(derEncoded: $0) }
                _ = try DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { try Int64(derEncoded: $0) }
                return KPasswdAPRep(encPart: try DER.explicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                    try EncryptedData(derEncoded: $0)
                })
            }
        }
    }
}

/// ```
/// EncAPRepPart ::= [APPLICATION 27] SEQUENCE {
///     ctime      [0] KerberosTime,
///     cusec      [1] Microseconds,
///     subkey     [2] EncryptionKey OPTIONAL,
///     seq-number [3] UInt32 OPTIONAL
/// }
/// ```
struct KPasswdEncAPRepPart: Sendable, Hashable {
    var ctime: KerberosTime
    var cusec: Int32
    var seqNumber: UInt32?

    func encode() -> [UInt8] {
        var s = DER.Serializer()
        do {
            try s.serialize(explicitlyTaggedWithTagNumber: 27, tagClass: .application) { c in
                try c.appendConstructedNode(identifier: .sequence) { c in
                    try c.serialize(ctime, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
                    try c.serialize(Int64(cusec), explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
                    if let seqNumber {
                        try c.serialize(Int64(seqNumber), explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific)
                    }
                }
            }
        } catch {
            preconditionFailure("EncAPRepPart serialization failed: \(error)")
        }
        return s.serializedBytes
    }

    init(ctime: KerberosTime, cusec: Int32, seqNumber: UInt32?) {
        self.ctime = ctime
        self.cusec = cusec
        self.seqNumber = seqNumber
    }

    init(derBytes: [UInt8]) throws {
        let root = try DER.parse(derBytes)
        self = try DER.explicitlyTagged(root, tagNumber: 27, tagClass: .application) { inner in
            try DER.sequence(inner, identifier: .sequence) { nodes in
                let ctime = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { try KerberosTime(derEncoded: $0) }
                let cusec = try DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { try Int32(derEncoded: $0) }
                _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) { try EncryptionKey(derEncoded: $0) }
                let seq = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                    UInt32(truncatingIfNeeded: try Int64(derEncoded: $0))
                }
                return KPasswdEncAPRepPart(ctime: ctime, cusec: cusec, seqNumber: seq)
            }
        }
    }
}
