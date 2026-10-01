import SwiftASN1

// MARK: - AP-REQ

/// ```
/// AP-REQ ::= [APPLICATION 14] SEQUENCE {
///     pvno            [0] INTEGER (5),
///     msg-type        [1] INTEGER (14),
///     ap-options      [2] APOptions,
///     ticket          [3] Ticket,
///     authenticator   [4] EncryptedData -- Authenticator
/// }
/// ```
/// `ticket.rawDER` holds the ticket bytes as received.
public struct APReq: KerberosApplicationMessage {
    public static var applicationTag: UInt { 14 }

    public var apOptions: APOptions
    public var ticket: Ticket
    public var authenticator: EncryptedData

    public init(apOptions: APOptions = APOptions(), ticket: Ticket, authenticator: EncryptedData) {
        self.apOptions = apOptions
        self.ticket = ticket
        self.authenticator = authenticator
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            try Field.required(&nodes, 1) { try Field.messageType($0, expected: MessageType.apReq) }
            return APReq(
                apOptions: try Field.required(&nodes, 2) { try KerberosFlags(derEncoded: $0) },
                ticket: try Field.required(&nodes, 3) { try Ticket(derEncoded: $0) },
                authenticator: try Field.required(&nodes, 4) { try EncryptedData(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, MessageType.apReq)
            try coder.field(2, apOptions)
            try coder.field(3, ticket)
            try coder.field(4, authenticator)
        }
    }
}

// MARK: - Authenticator

/// ```
/// Authenticator ::= [APPLICATION 2] SEQUENCE  {
///     authenticator-vno       [0] INTEGER (5),
///     crealm                  [1] Realm,
///     cname                   [2] PrincipalName,
///     cksum                   [3] Checksum OPTIONAL,
///     cusec                   [4] Microseconds,
///     ctime                   [5] KerberosTime,
///     subkey                  [6] EncryptionKey OPTIONAL,
///     seq-number              [7] UInt32 OPTIONAL,
///     authorization-data      [8] AuthorizationData OPTIONAL
/// }
/// ```
/// `rawDER` holds the decrypted bytes as received. Empty `authorizationData` means absent.
public struct Authenticator: KerberosApplicationMessage {
    public static var applicationTag: UInt { 2 }

    public var crealm: String
    public var cname: PrincipalName
    public var cksum: Checksum?
    public var cusec: Microseconds
    public var ctime: KerberosTime
    public var subkey: EncryptionKey?
    public var seqNumber: UInt32?
    public var authorizationData: AuthorizationData
    public internal(set) var received: ReceivedDER = ReceivedDER()
    public var rawDER: [UInt8]? { received.bytes }

    public init(
        crealm: String,
        cname: PrincipalName,
        cksum: Checksum? = nil,
        cusec: Microseconds,
        ctime: KerberosTime,
        subkey: EncryptionKey? = nil,
        seqNumber: UInt32? = nil,
        authorizationData: AuthorizationData = []
    ) {
        self.crealm = crealm
        self.cname = cname
        self.cksum = cksum
        self.cusec = cusec
        self.ctime = ctime
        self.subkey = subkey
        self.seqNumber = seqNumber
        self.authorizationData = authorizationData
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            return Authenticator(
                crealm: try Field.required(&nodes, 1) { try KerberosString(derEncoded: $0).value },
                cname: try Field.required(&nodes, 2) { try PrincipalName(derEncoded: $0) },
                cksum: try Field.optional(&nodes, 3) { try Checksum(derEncoded: $0) },
                cusec: try Field.required(&nodes, 4, Field.microseconds),
                ctime: try Field.required(&nodes, 5) { try KerberosTime(derEncoded: $0) },
                subkey: try Field.optional(&nodes, 6) { try EncryptionKey(derEncoded: $0) },
                seqNumber: try Field.optional(&nodes, 7, Field.uint32),
                authorizationData: try Field.optional(&nodes, 8) { try AuthorizationData(derEncoded: $0) } ?? [])
        }
        self.received = ReceivedDER(Array(node.encodedBytes))
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, KerberosString(crealm))
            try coder.field(2, cname)
            try coder.optionalField(3, cksum)
            try coder.field(4, cusec)
            try coder.field(5, ctime)
            try coder.optionalField(6, subkey)
            try coder.optionalField(7, seqNumber)
            if !authorizationData.isEmpty { try coder.field(8, authorizationData) }
        }
    }
}
