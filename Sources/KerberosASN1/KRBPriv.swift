import SwiftASN1

// MARK: - KRB-PRIV (RFC 4120 §5.7), used by kpasswd (RFC 3244)

/// ```
/// KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (21),
///                         -- NOTE: there is no [2] tag
///         enc-part        [3] EncryptedData -- EncKrbPrivPart
/// }
/// ```
public struct KRBPriv: KerberosApplicationMessage {
    public static var applicationTag: UInt { 21 }

    public var encPart: EncryptedData

    public init(encPart: EncryptedData) { self.encPart = encPart }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            try Field.required(&nodes, 1) { try Field.messageType($0, expected: MessageType.krbPriv) }
            return KRBPriv(encPart: try Field.required(&nodes, 3) { try EncryptedData(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, MessageType.krbPriv)
            try coder.field(3, encPart)
        }
    }
}

/// ```
/// EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
///         user-data       [0] OCTET STRING,
///         timestamp       [1] KerberosTime OPTIONAL,
///         usec            [2] Microseconds OPTIONAL,
///         seq-number      [3] UInt32 OPTIONAL,
///         s-address       [4] HostAddress -- sender's addr --,
///         r-address       [5] HostAddress OPTIONAL -- recip's addr
/// }
/// ```
/// `s-address` is mandatory in RFC 4120 but optional in Heimdal's and MIT's decoders; it is
/// decoded leniently (nil when absent) and emitted whenever it is set.
public struct EncKrbPrivPart: KerberosApplicationMessage {
    public static var applicationTag: UInt { 28 }

    public var userData: [UInt8]
    public var timestamp: KerberosTime?
    public var usec: Microseconds?
    public var seqNumber: UInt32?
    public var sAddress: HostAddress?
    public var rAddress: HostAddress?

    public init(userData: [UInt8], timestamp: KerberosTime? = nil, usec: Microseconds? = nil, seqNumber: UInt32? = nil,
                sAddress: HostAddress?, rAddress: HostAddress? = nil) {
        self.userData = userData
        self.timestamp = timestamp
        self.usec = usec
        self.seqNumber = seqNumber
        self.sAddress = sAddress
        self.rAddress = rAddress
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            EncKrbPrivPart(
                userData: try Field.required(&nodes, 0, Field.octets),
                timestamp: try Field.optional(&nodes, 1) { try KerberosTime(derEncoded: $0) },
                usec: try Field.optional(&nodes, 2, Field.microseconds),
                seqNumber: try Field.optional(&nodes, 3, Field.uint32),
                sAddress: try Field.optional(&nodes, 4) { try HostAddress(derEncoded: $0) },
                rAddress: try Field.optional(&nodes, 5) { try HostAddress(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, ASN1OctetString(contentBytes: userData[...]))
            try coder.optionalField(1, timestamp)
            try coder.optionalField(2, usec)
            try coder.optionalField(3, seqNumber)
            try coder.optionalField(4, sAddress)
            try coder.optionalField(5, rAddress)
        }
    }
}
