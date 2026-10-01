import SwiftASN1

// MARK: - KDC-REP (AS-REP / TGS-REP)

/// Shared shape of AS-REP and TGS-REP:
/// ```
/// KDC-REP ::= SEQUENCE {
///     pvno            [0] INTEGER (5),
///     msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///     padata          [2] SEQUENCE OF PA-DATA OPTIONAL,
///     crealm          [3] Realm,
///     cname           [4] PrincipalName,
///     ticket          [5] Ticket,
///     enc-part        [6] EncryptedData -- EncASRepPart or EncTGSRepPart
/// }
/// ```
/// `padata` empty means absent.
public protocol KDCRepMessage: KerberosApplicationMessage {
    var padata: [PAData] { get set }
    var crealm: String { get set }
    var cname: PrincipalName { get set }
    var ticket: Ticket { get set }
    var encPart: EncryptedData { get set }
    init(padata: [PAData], crealm: String, cname: PrincipalName, ticket: Ticket, encPart: EncryptedData)
}

extension KDCRepMessage {
    public init(derEncoded node: ASN1Node) throws {
        let tag = Self.applicationTag
        self = try Field.applicationSequence(node, tag: tag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            try Field.required(&nodes, 1) { try Field.messageType($0, expected: Int32(tag)) }
            return Self(
                padata: try Field.optional(&nodes, 2) { try Field.sequenceOf($0) as [PAData] } ?? [],
                crealm: try Field.required(&nodes, 3) { try KerberosString(derEncoded: $0).value },
                cname: try Field.required(&nodes, 4) { try PrincipalName(derEncoded: $0) },
                ticket: try Field.required(&nodes, 5) { try Ticket(derEncoded: $0) },
                encPart: try Field.required(&nodes, 6) { try EncryptedData(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, Int32(Self.applicationTag))
            try coder.optionalSequenceField(2, padata)
            try coder.field(3, KerberosString(crealm))
            try coder.field(4, cname)
            try coder.field(5, ticket)
            try coder.field(6, encPart)
        }
    }
}

/// `AS-REP ::= [APPLICATION 11] KDC-REP`
public struct ASRep: KDCRepMessage {
    public static var applicationTag: UInt { 11 }

    public var padata: [PAData]
    public var crealm: String
    public var cname: PrincipalName
    public var ticket: Ticket
    public var encPart: EncryptedData

    public init(padata: [PAData] = [], crealm: String, cname: PrincipalName, ticket: Ticket, encPart: EncryptedData) {
        self.padata = padata
        self.crealm = crealm
        self.cname = cname
        self.ticket = ticket
        self.encPart = encPart
    }
}

/// `TGS-REP ::= [APPLICATION 13] KDC-REP`
public struct TGSRep: KDCRepMessage {
    public static var applicationTag: UInt { 13 }

    public var padata: [PAData]
    public var crealm: String
    public var cname: PrincipalName
    public var ticket: Ticket
    public var encPart: EncryptedData

    public init(padata: [PAData] = [], crealm: String, cname: PrincipalName, ticket: Ticket, encPart: EncryptedData) {
        self.padata = padata
        self.crealm = crealm
        self.cname = cname
        self.ticket = ticket
        self.encPart = encPart
    }
}

// MARK: - EncKDCRepPart

/// ```
/// EncKDCRepPart ::= SEQUENCE {
///     key             [0] EncryptionKey,
///     last-req        [1] LastReq,
///     nonce           [2] UInt32,
///     key-expiration  [3] KerberosTime OPTIONAL,
///     flags           [4] TicketFlags,
///     authtime        [5] KerberosTime,
///     starttime       [6] KerberosTime OPTIONAL,
///     endtime         [7] KerberosTime,
///     renew-till      [8] KerberosTime OPTIONAL,
///     srealm          [9] Realm,
///     sname           [10] PrincipalName,
///     caddr           [11] HostAddresses OPTIONAL,
///     encrypted-pa-data [12] METHOD-DATA OPTIONAL   -- RFC 6806 §11 (Heimdal/Windows)
/// }
/// ```
/// Empty `caddr` / `encryptedPAData` are treated as absent. `nonce` is encoded exactly like
/// `KDCReqBody.nonce` (signed 4-byte form), so echoing the request's value reproduces its bytes.
public struct EncKDCRepPart: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var key: EncryptionKey
    public var lastReq: LastReq
    public var nonce: UInt32
    public var keyExpiration: KerberosTime?
    public var flags: TicketFlags
    public var authtime: KerberosTime
    public var starttime: KerberosTime?
    public var endtime: KerberosTime
    public var renewTill: KerberosTime?
    public var srealm: String
    public var sname: PrincipalName
    public var caddr: HostAddresses
    public var encryptedPAData: [PAData]

    public init(
        key: EncryptionKey,
        lastReq: LastReq,
        nonce: UInt32,
        keyExpiration: KerberosTime? = nil,
        flags: TicketFlags,
        authtime: KerberosTime,
        starttime: KerberosTime? = nil,
        endtime: KerberosTime,
        renewTill: KerberosTime? = nil,
        srealm: String,
        sname: PrincipalName,
        caddr: HostAddresses = [],
        encryptedPAData: [PAData] = []
    ) {
        self.key = key
        self.lastReq = lastReq
        self.nonce = nonce
        self.keyExpiration = keyExpiration
        self.flags = flags
        self.authtime = authtime
        self.starttime = starttime
        self.endtime = endtime
        self.renewTill = renewTill
        self.srealm = srealm
        self.sname = sname
        self.caddr = caddr
        self.encryptedPAData = encryptedPAData
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            EncKDCRepPart(
                key: try Field.required(&nodes, 0) { try EncryptionKey(derEncoded: $0) },
                lastReq: try Field.required(&nodes, 1) { try LastReq(derEncoded: $0) },
                nonce: try Field.required(&nodes, 2, Field.uint32),
                keyExpiration: try Field.optional(&nodes, 3) { try KerberosTime(derEncoded: $0) },
                flags: try Field.required(&nodes, 4) { try KerberosFlags(derEncoded: $0) },
                authtime: try Field.required(&nodes, 5) { try KerberosTime(derEncoded: $0) },
                starttime: try Field.optional(&nodes, 6) { try KerberosTime(derEncoded: $0) },
                endtime: try Field.required(&nodes, 7) { try KerberosTime(derEncoded: $0) },
                renewTill: try Field.optional(&nodes, 8) { try KerberosTime(derEncoded: $0) },
                srealm: try Field.required(&nodes, 9) { try KerberosString(derEncoded: $0).value },
                sname: try Field.required(&nodes, 10) { try PrincipalName(derEncoded: $0) },
                caddr: try Field.optional(&nodes, 11) { try HostAddresses(derEncoded: $0) } ?? [],
                encryptedPAData: try Field.optional(&nodes, 12) { try Field.sequenceOf($0) as [PAData] } ?? [])
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, key)
            try coder.field(1, lastReq)
            try coder.field(2, Field.nonceWireValue(nonce))
            try coder.optionalField(3, keyExpiration)
            try coder.field(4, flags)
            try coder.field(5, authtime)
            try coder.optionalField(6, starttime)
            try coder.field(7, endtime)
            try coder.optionalField(8, renewTill)
            try coder.field(9, KerberosString(srealm))
            try coder.field(10, sname)
            if !caddr.isEmpty { try coder.field(11, caddr) }
            try coder.optionalSequenceField(12, encryptedPAData)
        }
    }
}

/// `EncASRepPart ::= [APPLICATION 25] EncKDCRepPart`. Fields are reachable directly
/// (`encASRepPart.nonce`) through dynamic member lookup on `part`.
@dynamicMemberLookup
public struct EncASRepPart: KerberosApplicationMessage {
    public static var applicationTag: UInt { 25 }

    public var part: EncKDCRepPart

    public init(_ part: EncKDCRepPart) { self.part = part }

    public subscript<T>(dynamicMember keyPath: WritableKeyPath<EncKDCRepPart, T>) -> T {
        get { part[keyPath: keyPath] }
        set { part[keyPath: keyPath] = newValue }
    }

    public init(derEncoded node: ASN1Node) throws {
        self.part = try DER.explicitlyTagged(node, tagNumber: Self.applicationTag, tagClass: .application) {
            try EncKDCRepPart(derEncoded: $0)
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.serialize(part, explicitlyTaggedWithTagNumber: Self.applicationTag, tagClass: .application)
    }
}

/// `EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart`. Fields reachable via dynamic member lookup.
@dynamicMemberLookup
public struct EncTGSRepPart: KerberosApplicationMessage {
    public static var applicationTag: UInt { 26 }

    public var part: EncKDCRepPart

    public init(_ part: EncKDCRepPart) { self.part = part }

    public subscript<T>(dynamicMember keyPath: WritableKeyPath<EncKDCRepPart, T>) -> T {
        get { part[keyPath: keyPath] }
        set { part[keyPath: keyPath] = newValue }
    }

    public init(derEncoded node: ASN1Node) throws {
        self.part = try DER.explicitlyTagged(node, tagNumber: Self.applicationTag, tagClass: .application) {
            try EncKDCRepPart(derEncoded: $0)
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.serialize(part, explicitlyTaggedWithTagNumber: Self.applicationTag, tagClass: .application)
    }
}

extension EncKDCRepPart {
    /// Decodes a decrypted KDC-REP enc-part that may carry either tag: some KDCs (old MIT) put
    /// `[APPLICATION 26]` inside an AS-REP, and clients accept both.
    public init(eitherApplicationTag bytes: [UInt8]) throws {
        do {
            let node = try DER.parse(bytes)
            guard node.identifier.tagClass == .application,
                node.identifier.tagNumber == EncASRepPart.applicationTag
                    || node.identifier.tagNumber == EncTGSRepPart.applicationTag
            else {
                throw KerberosASN1Error.unexpectedApplicationTag(
                    expected: EncASRepPart.applicationTag,
                    got: node.identifier.tagClass == .application ? node.identifier.tagNumber : nil)
            }
            self = try DER.explicitlyTagged(node, tagNumber: node.identifier.tagNumber, tagClass: .application) {
                try EncKDCRepPart(derEncoded: $0)
            }
        } catch {
            throw KerberosASN1Error.wrap(error)
        }
    }
}
