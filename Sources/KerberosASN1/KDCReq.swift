import SwiftASN1

// MARK: - KDC-REQ-BODY

/// ```
/// KDC-REQ-BODY ::= SEQUENCE {
///     kdc-options             [0] KDCOptions,
///     cname                   [1] PrincipalName OPTIONAL -- Used only in AS-REQ --,
///     realm                   [2] Realm,
///     sname                   [3] PrincipalName OPTIONAL,
///     from                    [4] KerberosTime OPTIONAL,
///     till                    [5] KerberosTime,
///     rtime                   [6] KerberosTime OPTIONAL,
///     nonce                   [7] UInt32,
///     etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --,
///     addresses               [9] HostAddresses OPTIONAL,
///     enc-authorization-data  [10] EncryptedData OPTIONAL -- AuthorizationData --,
///     additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
/// }
/// ```
/// - `etype` keeps the client's preference order.
/// - `nonce` is a `UInt32`. Decoding accepts both the signed 4-byte form (what Heimdal and MIT
///   send: their ASN.1 declares nonce as a signed int32, so e.g. `0xBB128A52` arrives as
///   `02 04 BB 12 8A 52`) and the unsigned 5-byte form (`02 05 00 BB 12 8A 52`). Encoding always
///   uses the signed 4-byte form, so a nonce echoed into EncKDCRepPart is byte-identical to what
///   Heimdal sent and decodes on Heimdal/MIT (which reject a 5-byte value for an int32).
/// - Empty `addresses` / `additionalTickets` are treated as absent.
/// - `rawDER` holds the bytes as received: the TGS-REQ authenticator checksum covers exactly them.
public struct KDCReqBody: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var kdcOptions: KDCOptions
    public var cname: PrincipalName?
    public var realm: String
    public var sname: PrincipalName?
    public var from: KerberosTime?
    public var till: KerberosTime
    public var rtime: KerberosTime?
    public var nonce: UInt32
    public var etype: [Int32]
    public var addresses: HostAddresses
    public var encAuthorizationData: EncryptedData?
    public var additionalTickets: [Ticket]
    /// Bytes this body was decoded from (the SEQUENCE TLV, without the `[4]` wrapper).
    public internal(set) var received: ReceivedDER = ReceivedDER()
    public var rawDER: [UInt8]? { received.bytes }

    public init(
        kdcOptions: KDCOptions = KDCOptions(),
        cname: PrincipalName? = nil,
        realm: String,
        sname: PrincipalName? = nil,
        from: KerberosTime? = nil,
        till: KerberosTime,
        rtime: KerberosTime? = nil,
        nonce: UInt32,
        etype: [Int32],
        addresses: HostAddresses = [],
        encAuthorizationData: EncryptedData? = nil,
        additionalTickets: [Ticket] = []
    ) {
        self.kdcOptions = kdcOptions
        self.cname = cname
        self.realm = realm
        self.sname = sname
        self.from = from
        self.till = till
        self.rtime = rtime
        self.nonce = nonce
        self.etype = etype
        self.addresses = addresses
        self.encAuthorizationData = encAuthorizationData
        self.additionalTickets = additionalTickets
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            KDCReqBody(
                kdcOptions: try Field.required(&nodes, 0) { try KerberosFlags(derEncoded: $0) },
                cname: try Field.optional(&nodes, 1) { try PrincipalName(derEncoded: $0) },
                realm: try Field.required(&nodes, 2) { try KerberosString(derEncoded: $0).value },
                sname: try Field.optional(&nodes, 3) { try PrincipalName(derEncoded: $0) },
                from: try Field.optional(&nodes, 4) { try KerberosTime(derEncoded: $0) },
                till: try Field.required(&nodes, 5) { try KerberosTime(derEncoded: $0) },
                rtime: try Field.optional(&nodes, 6) { try KerberosTime(derEncoded: $0) },
                nonce: try Field.required(&nodes, 7, Field.uint32),
                etype: try Field.required(&nodes, 8) { try Field.sequenceOf($0) as [Int32] },
                addresses: try Field.optional(&nodes, 9) { try HostAddresses(derEncoded: $0) } ?? [],
                encAuthorizationData: try Field.optional(&nodes, 10) { try EncryptedData(derEncoded: $0) },
                additionalTickets: try Field.optional(&nodes, 11) { try Field.sequenceOf($0) as [Ticket] } ?? [])
        }
        self.received = ReceivedDER(Array(node.encodedBytes))
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, kdcOptions)
            try coder.optionalField(1, cname)
            try coder.field(2, KerberosString(realm))
            try coder.optionalField(3, sname)
            try coder.optionalField(4, from)
            try coder.field(5, till)
            try coder.optionalField(6, rtime)
            try coder.field(7, Field.nonceWireValue(nonce))
            try coder.sequenceField(8, etype)
            if !addresses.isEmpty { try coder.field(9, addresses) }
            try coder.optionalField(10, encAuthorizationData)
            try coder.optionalSequenceField(11, additionalTickets)
        }
    }
}

// MARK: - KDC-REQ (AS-REQ / TGS-REQ)

/// Shared shape of AS-REQ and TGS-REQ:
/// ```
/// KDC-REQ ::= SEQUENCE {
///     -- NOTE: first tag is [1], not [0]
///     pvno            [1] INTEGER (5) ,
///     msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///     padata          [3] SEQUENCE OF PA-DATA OPTIONAL,
///     req-body        [4] KDC-REQ-BODY
/// }
/// ```
/// `padata` empty means absent: an empty SEQUENCE OF PA-DATA is never emitted.
public protocol KDCReqMessage: KerberosApplicationMessage {
    var padata: [PAData] { get set }
    var reqBody: KDCReqBody { get set }
    init(padata: [PAData], reqBody: KDCReqBody)
}

extension KDCReqMessage {
    public init(derEncoded node: ASN1Node) throws {
        let tag = Self.applicationTag
        self = try Field.applicationSequence(node, tag: tag) { nodes in
            _ = try Field.required(&nodes, 1, Field.version)
            try Field.required(&nodes, 2) { try Field.messageType($0, expected: Int32(tag)) }
            let padata = try Field.optional(&nodes, 3) { try Field.sequenceOf($0) as [PAData] } ?? []
            let body = try Field.required(&nodes, 4) { try KDCReqBody(derEncoded: $0) }
            return Self(padata: padata, reqBody: body)
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(1, 5)
            try coder.field(2, Int32(Self.applicationTag))
            try coder.optionalSequenceField(3, padata)
            try coder.field(4, reqBody)
        }
    }
}

/// `AS-REQ ::= [APPLICATION 10] KDC-REQ`
public struct ASReq: KDCReqMessage {
    public static var applicationTag: UInt { 10 }

    public var padata: [PAData]
    public var reqBody: KDCReqBody

    public init(padata: [PAData] = [], reqBody: KDCReqBody) {
        self.padata = padata
        self.reqBody = reqBody
    }
}

/// `TGS-REQ ::= [APPLICATION 12] KDC-REQ`
public struct TGSReq: KDCReqMessage {
    public static var applicationTag: UInt { 12 }

    public var padata: [PAData]
    public var reqBody: KDCReqBody

    public init(padata: [PAData] = [], reqBody: KDCReqBody) {
        self.padata = padata
        self.reqBody = reqBody
    }

    /// Decodes the AP-REQ carried in PA-TGS-REQ, if present.
    public func tgsAPReq() throws -> APReq? {
        guard let pa = padata.first(ofType: PADataType.tgsReq) else { return nil }
        return try APReq(derBytes: pa.value)
    }
}
