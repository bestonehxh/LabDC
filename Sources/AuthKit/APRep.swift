import KerberosASN1
import SwiftASN1

/// ```
/// AP-REP ::= [APPLICATION 15] SEQUENCE {
///     pvno     [0] INTEGER (5),
///     msg-type [1] INTEGER (15),
///     enc-part [2] EncryptedData -- EncAPRepPart
/// }
/// ```
/// (KerberosASN1 deferred AP-REP; it lives here because only the GSS acceptor needs it.)
public struct APRep: Sendable, Hashable {
    public var encPart: EncryptedData

    public init(encPart: EncryptedData) { self.encPart = encPart }

    public func encode() -> [UInt8] {
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

    public init(derBytes: [UInt8]) throws {
        do {
            let root = try DER.parse(derBytes)
            guard root.identifier.tagClass == .application, root.identifier.tagNumber == 15 else {
                throw AuthKitError.malformed(what: "AP-REP", reason: "not [APPLICATION 15]")
            }
            self = try DER.explicitlyTagged(root, tagNumber: 15, tagClass: .application) { inner in
                try DER.sequence(inner, identifier: .sequence) { nodes in
                    let pvno = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { try Int64(derEncoded: $0) }
                    let type = try DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { try Int64(derEncoded: $0) }
                    guard pvno == 5, type == 15 else { throw AuthKitError.malformed(what: "AP-REP", reason: "pvno/msg-type") }
                    return APRep(encPart: try DER.explicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                        try EncryptedData(derEncoded: $0)
                    })
                }
            }
        } catch let e as AuthKitError {
            throw e
        } catch {
            throw AuthKitError.malformed(what: "AP-REP", reason: "\(error)")
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
public struct EncAPRepPart: Sendable, Hashable {
    public var ctime: KerberosTime
    public var cusec: Int32
    public var subkey: EncryptionKey?
    public var seqNumber: UInt32?

    public init(ctime: KerberosTime, cusec: Int32, subkey: EncryptionKey? = nil, seqNumber: UInt32? = nil) {
        self.ctime = ctime
        self.cusec = cusec
        self.subkey = subkey
        self.seqNumber = seqNumber
    }

    public func encode() -> [UInt8] {
        var s = DER.Serializer()
        do {
            try s.serialize(explicitlyTaggedWithTagNumber: 27, tagClass: .application) { c in
                try c.appendConstructedNode(identifier: .sequence) { c in
                    try c.serialize(ctime, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
                    try c.serialize(Int64(cusec), explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
                    if let subkey { try c.serialize(subkey, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific) }
                    if let seqNumber { try c.serialize(Int64(seqNumber), explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific) }
                }
            }
        } catch {
            preconditionFailure("EncAPRepPart serialization failed: \(error)")
        }
        return s.serializedBytes
    }

    public init(derBytes: [UInt8]) throws {
        do {
            let root = try DER.parse(derBytes)
            guard root.identifier.tagClass == .application, root.identifier.tagNumber == 27 else {
                throw AuthKitError.malformed(what: "EncAPRepPart", reason: "not [APPLICATION 27]")
            }
            self = try DER.explicitlyTagged(root, tagNumber: 27, tagClass: .application) { inner in
                try DER.sequence(inner, identifier: .sequence) { nodes in
                    let ctime = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { try KerberosTime(derEncoded: $0) }
                    let cusec = try DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { try Int32(derEncoded: $0) }
                    let subkey = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                        try EncryptionKey(derEncoded: $0)
                    }
                    // seq-number: accept the signed 4-byte form some encoders emit.
                    let seq = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                        UInt32(truncatingIfNeeded: try Int64(derEncoded: $0))
                    }
                    return EncAPRepPart(ctime: ctime, cusec: cusec, subkey: subkey, seqNumber: seq)
                }
            }
        } catch let e as AuthKitError {
            throw e
        } catch {
            throw AuthKitError.malformed(what: "EncAPRepPart", reason: "\(error)")
        }
    }
}
