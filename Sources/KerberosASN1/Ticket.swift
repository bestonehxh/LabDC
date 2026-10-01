import SwiftASN1

/// The exact bytes a value was decoded from. Excluded from `==`/`hash` so that a decoded value
/// equals the same value built by hand.
public struct ReceivedDER: Hashable, Sendable {
    public var bytes: [UInt8]?

    public init(_ bytes: [UInt8]? = nil) { self.bytes = bytes }

    public static func == (lhs: ReceivedDER, rhs: ReceivedDER) -> Bool { true }
    public func hash(into hasher: inout Hasher) {}
}

// MARK: - Ticket

/// ```
/// Ticket ::= [APPLICATION 1] SEQUENCE {
///     tkt-vno         [0] INTEGER (5),
///     realm           [1] Realm,
///     sname           [2] PrincipalName,
///     enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ```
public struct Ticket: KerberosApplicationMessage {
    public static var applicationTag: UInt { 1 }

    public var realm: String
    public var sname: PrincipalName
    public var encPart: EncryptedData
    /// The DER this ticket was decoded from (`nil` when built locally). Not updated on mutation;
    /// `encode()` always re-serializes the fields.
    public internal(set) var received: ReceivedDER = ReceivedDER()
    /// Shorthand for `received.bytes`.
    public var rawDER: [UInt8]? { received.bytes }

    public init(realm: String, sname: PrincipalName, encPart: EncryptedData) {
        self.realm = realm
        self.sname = sname
        self.encPart = encPart
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            return Ticket(
                realm: try Field.required(&nodes, 1) { try KerberosString(derEncoded: $0).value },
                sname: try Field.required(&nodes, 2) { try PrincipalName(derEncoded: $0) },
                encPart: try Field.required(&nodes, 3) { try EncryptedData(derEncoded: $0) })
        }
        self.received = ReceivedDER(Array(node.encodedBytes))
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, KerberosString(realm))
            try coder.field(2, sname)
            try coder.field(3, encPart)
        }
    }
}

// MARK: - EncTicketPart

/// ```
/// EncTicketPart ::= [APPLICATION 3] SEQUENCE {
///     flags                   [0] TicketFlags,
///     key                     [1] EncryptionKey,
///     crealm                  [2] Realm,
///     cname                   [3] PrincipalName,
///     transited               [4] TransitedEncoding,
///     authtime                [5] KerberosTime,
///     starttime               [6] KerberosTime OPTIONAL,
///     endtime                 [7] KerberosTime,
///     renew-till              [8] KerberosTime OPTIONAL,
///     caddr                   [9] HostAddresses OPTIONAL,
///     authorization-data      [10] AuthorizationData OPTIONAL
/// }
/// ```
/// Empty `caddr` / `authorizationData` are treated as absent.
public struct EncTicketPart: KerberosApplicationMessage {
    public static var applicationTag: UInt { 3 }

    public var flags: TicketFlags
    public var key: EncryptionKey
    public var crealm: String
    public var cname: PrincipalName
    public var transited: TransitedEncoding
    public var authtime: KerberosTime
    public var starttime: KerberosTime?
    public var endtime: KerberosTime
    public var renewTill: KerberosTime?
    public var caddr: HostAddresses
    public var authorizationData: AuthorizationData

    public init(
        flags: TicketFlags,
        key: EncryptionKey,
        crealm: String,
        cname: PrincipalName,
        transited: TransitedEncoding = .empty,
        authtime: KerberosTime,
        starttime: KerberosTime? = nil,
        endtime: KerberosTime,
        renewTill: KerberosTime? = nil,
        caddr: HostAddresses = [],
        authorizationData: AuthorizationData = []
    ) {
        self.flags = flags
        self.key = key
        self.crealm = crealm
        self.cname = cname
        self.transited = transited
        self.authtime = authtime
        self.starttime = starttime
        self.endtime = endtime
        self.renewTill = renewTill
        self.caddr = caddr
        self.authorizationData = authorizationData
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            EncTicketPart(
                flags: try Field.required(&nodes, 0) { try KerberosFlags(derEncoded: $0) },
                key: try Field.required(&nodes, 1) { try EncryptionKey(derEncoded: $0) },
                crealm: try Field.required(&nodes, 2) { try KerberosString(derEncoded: $0).value },
                cname: try Field.required(&nodes, 3) { try PrincipalName(derEncoded: $0) },
                transited: try Field.required(&nodes, 4) { try TransitedEncoding(derEncoded: $0) },
                authtime: try Field.required(&nodes, 5) { try KerberosTime(derEncoded: $0) },
                starttime: try Field.optional(&nodes, 6) { try KerberosTime(derEncoded: $0) },
                endtime: try Field.required(&nodes, 7) { try KerberosTime(derEncoded: $0) },
                renewTill: try Field.optional(&nodes, 8) { try KerberosTime(derEncoded: $0) },
                caddr: try Field.optional(&nodes, 9) { try HostAddresses(derEncoded: $0) } ?? [],
                authorizationData: try Field.optional(&nodes, 10) { try AuthorizationData(derEncoded: $0) } ?? [])
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, flags)
            try coder.field(1, key)
            try coder.field(2, KerberosString(crealm))
            try coder.field(3, cname)
            try coder.field(4, transited)
            try coder.field(5, authtime)
            try coder.optionalField(6, starttime)
            try coder.field(7, endtime)
            try coder.optionalField(8, renewTill)
            if !caddr.isEmpty { try coder.field(9, caddr) }
            if !authorizationData.isEmpty { try coder.field(10, authorizationData) }
        }
    }
}
