import SwiftASN1

// MARK: - PrincipalName

/// ```
/// PrincipalName ::= SEQUENCE {
///     name-type       [0] Int32,
///     name-string     [1] SEQUENCE OF KerberosString
/// }
/// ```
public struct PrincipalName: KerberosASN1Type, DERImplicitlyTaggable, CustomStringConvertible {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var nameType: Int32
    public var nameString: [String]

    public init(nameType: Int32, nameString: [String]) {
        self.nameType = nameType
        self.nameString = nameString
    }

    /// `krbtgt/REALM` with NT-SRV-INST.
    public static func krbtgt(realm: String) -> PrincipalName {
        PrincipalName(nameType: NameType.srvInst, nameString: ["krbtgt", realm])
    }

    /// Components joined with `/` (no realm, no escaping).
    public var description: String { nameString.joined(separator: "/") }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            let type = try Field.required(&nodes, 0) { try Int32(derEncoded: $0) }
            let names: [KerberosString] = try Field.required(&nodes, 1) { try Field.sequenceOf($0) }
            return PrincipalName(nameType: type, nameString: names.map(\.value))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, nameType)
            try coder.sequenceField(1, nameString.map { KerberosString($0) })
        }
    }
}

// MARK: - HostAddress / HostAddresses

/// ```
/// HostAddress ::= SEQUENCE {
///     addr-type       [0] Int32,
///     address         [1] OCTET STRING
/// }
/// ```
public struct HostAddress: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var addrType: Int32
    public var address: [UInt8]

    public init(addrType: Int32, address: [UInt8]) {
        self.addrType = addrType
        self.address = address
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            HostAddress(
                addrType: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                address: try Field.required(&nodes, 1, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, addrType)
            try coder.field(1, ASN1OctetString(contentBytes: address[...]))
        }
    }
}

/// `HostAddresses ::= SEQUENCE OF HostAddress`. As an OPTIONAL field, empty means absent.
public struct HostAddresses: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByArrayLiteral {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var elements: [HostAddress]

    public init(_ elements: [HostAddress] = []) { self.elements = elements }
    public init(arrayLiteral elements: HostAddress...) { self.elements = elements }

    public var isEmpty: Bool { elements.isEmpty }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.elements = try DER.sequence(of: HostAddress.self, identifier: identifier, rootNode: node)
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(elements, identifier: identifier)
    }
}

// MARK: - AuthorizationData

/// One element of `AuthorizationData`: `SEQUENCE { ad-type [0] Int32, ad-data [1] OCTET STRING }`.
public struct AuthorizationDataElement: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var adType: Int32
    public var adData: [UInt8]

    public init(adType: Int32, adData: [UInt8]) {
        self.adType = adType
        self.adData = adData
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            AuthorizationDataElement(
                adType: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                adData: try Field.required(&nodes, 1, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, adType)
            try coder.field(1, ASN1OctetString(contentBytes: adData[...]))
        }
    }
}

/// ```
/// AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type [0] Int32, ad-data [1] OCTET STRING }
/// AD-IF-RELEVANT    ::= AuthorizationData
/// ```
/// As an OPTIONAL field, empty means absent.
public struct AuthorizationData: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByArrayLiteral {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var elements: [AuthorizationDataElement]

    public init(_ elements: [AuthorizationDataElement] = []) { self.elements = elements }
    public init(arrayLiteral elements: AuthorizationDataElement...) { self.elements = elements }

    public var isEmpty: Bool { elements.isEmpty }

    /// `AD-IF-RELEVANT { AD-WIN2K-PAC pac }`: the single element a KDC puts in a ticket.
    public static func ifRelevantPAC(_ pac: [UInt8]) -> AuthorizationData {
        let inner = AuthorizationData([AuthorizationDataElement(adType: AuthorizationDataType.win2kPAC, adData: pac)])
        return AuthorizationData([
            AuthorizationDataElement(adType: AuthorizationDataType.ifRelevant, adData: inner.encode())
        ])
    }

    /// Finds the AD-WIN2K-PAC blob, looking inside AD-IF-RELEVANT containers (one level, as Windows does).
    public func findPAC() throws -> [UInt8]? {
        for e in elements {
            if e.adType == AuthorizationDataType.win2kPAC { return e.adData }
            if e.adType == AuthorizationDataType.ifRelevant {
                let inner = try AuthorizationData(derBytes: e.adData)
                if let pac = inner.elements.first(where: { $0.adType == AuthorizationDataType.win2kPAC }) {
                    return pac.adData
                }
            }
        }
        return nil
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.elements = try DER.sequence(of: AuthorizationDataElement.self, identifier: identifier, rootNode: node)
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(elements, identifier: identifier)
    }
}

// MARK: - PA-DATA / METHOD-DATA

/// ```
/// PA-DATA ::= SEQUENCE {
///     -- NOTE: first tag is [1], not [0]
///     padata-type     [1] Int32,
///     padata-value    [2] OCTET STRING
/// }
/// ```
public struct PAData: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var type: Int32
    public var value: [UInt8]

    public init(type: Int32, value: [UInt8]) {
        self.type = type
        self.value = value
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            PAData(
                type: try Field.required(&nodes, 1) { try Int32(derEncoded: $0) },
                value: try Field.required(&nodes, 2, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(1, type)
            try coder.field(2, ASN1OctetString(contentBytes: value[...]))
        }
    }
}

extension Array where Element == PAData {
    /// First PA-DATA of the given type.
    public func first(ofType type: Int32) -> PAData? { first { $0.type == type } }
}

/// `METHOD-DATA ::= SEQUENCE OF PA-DATA` — the `e-data` of KDC_ERR_PREAUTH_REQUIRED.
public struct MethodData: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByArrayLiteral {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var elements: [PAData]

    public init(_ elements: [PAData] = []) { self.elements = elements }
    public init(arrayLiteral elements: PAData...) { self.elements = elements }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.elements = try DER.sequence(of: PAData.self, identifier: identifier, rootNode: node)
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(elements, identifier: identifier)
    }
}

// MARK: - KerberosFlags

/// `KerberosFlags ::= BIT STRING (SIZE (32..MAX))`, used for KDCOptions, TicketFlags, APOptions
/// and PA-PAC-OPTIONS.
///
/// Bit 0 is the most significant bit of the first octet (ASN.1 BIT STRING numbering).
/// Always serialized as exactly 32 bits: `03 05 00 b0 b1 b2 b3` (0 unused bits), even when
/// trailing bits are zero. On decode, bit strings shorter than 32 bits are zero-extended and
/// bits beyond 31 are ignored.
public struct KerberosFlags: KerberosASN1Type, DERImplicitlyTaggable, CustomStringConvertible {
    public static var defaultIdentifier: ASN1Identifier { .bitString }

    /// Big-endian image of bits 0...31 (bit 0 = `0x8000_0000`).
    public var rawValue: UInt32

    public init(rawValue: UInt32 = 0) { self.rawValue = rawValue }

    /// Sets the given bit numbers.
    public init(bits: [Int]) {
        self.rawValue = 0
        for b in bits { self[b] = true }
    }

    /// Bit `n` (0...31) in ASN.1 numbering.
    public subscript(bit: Int) -> Bool {
        get {
            precondition((0..<32).contains(bit), "KerberosFlags bit out of range")
            return rawValue & (UInt32(0x8000_0000) >> UInt32(bit)) != 0
        }
        set {
            precondition((0..<32).contains(bit), "KerberosFlags bit out of range")
            let mask = UInt32(0x8000_0000) >> UInt32(bit)
            rawValue = newValue ? (rawValue | mask) : (rawValue & ~mask)
        }
    }

    /// Set bit numbers, ascending.
    public var setBits: [Int] { (0..<32).filter { self[$0] } }

    public var description: String { "KerberosFlags(bits: \(setBits))" }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        let bits = try ASN1BitString(derEncoded: node, withIdentifier: identifier)
        var value: UInt32 = 0
        for (i, byte) in bits.bytes.prefix(4).enumerated() {
            value |= UInt32(byte) << UInt32(24 - 8 * i)
        }
        self.rawValue = value
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            bytes.append(0)  // unused bits in the last octet
            bytes.append(UInt8(truncatingIfNeeded: rawValue >> 24))
            bytes.append(UInt8(truncatingIfNeeded: rawValue >> 16))
            bytes.append(UInt8(truncatingIfNeeded: rawValue >> 8))
            bytes.append(UInt8(truncatingIfNeeded: rawValue))
        }
    }

    /// Bit numbers from RFC 4120 §5.3 (TicketFlags), §5.4.1 (KDCOptions), §5.5.1 (APOptions),
    /// RFC 6806 / MS-KILE / MS-SFU. The same position has different meanings in different flag sets.
    public enum Bit {
        // TicketFlags / KDCOptions (shared positions)
        public static let reserved = 0
        public static let forwardable = 1
        public static let forwarded = 2
        public static let proxiable = 3
        public static let proxy = 4
        /// TicketFlags `may-postdate`, KDCOptions `allow-postdate`.
        public static let mayPostdate = 5
        public static let postdated = 6
        /// TicketFlags only.
        public static let invalid = 7
        public static let renewable = 8
        // TicketFlags only
        public static let initial = 9
        public static let preAuthent = 10
        public static let hwAuthent = 11
        public static let transitedPolicyChecked = 12
        public static let okAsDelegate = 13
        /// TicketFlags `enc-pa-rep` (RFC 6806).
        public static let encPARep = 15
        // KDCOptions only
        /// KDCOptions `opt-hardware-auth`.
        public static let optHardwareAuth = 11
        /// KDCOptions `cname-in-addl-tkt` (MS-SFU constrained delegation).
        public static let cnameInAddlTkt = 14
        /// KDCOptions `canonicalize` (RFC 6806).
        public static let canonicalize = 15
        public static let requestAnonymous = 16
        public static let disableTransitedCheck = 26
        public static let renewableOK = 27
        public static let encTktInSkey = 28
        public static let renew = 30
        public static let validate = 31
        // APOptions
        public static let useSessionKey = 1
        public static let mutualRequired = 2
    }

    // Typed accessors (TicketFlags / KDCOptions / APOptions share this type).
    public var forwardable: Bool { get { self[Bit.forwardable] } set { self[Bit.forwardable] = newValue } }
    public var forwarded: Bool { get { self[Bit.forwarded] } set { self[Bit.forwarded] = newValue } }
    public var proxiable: Bool { get { self[Bit.proxiable] } set { self[Bit.proxiable] = newValue } }
    public var proxy: Bool { get { self[Bit.proxy] } set { self[Bit.proxy] = newValue } }
    public var mayPostdate: Bool { get { self[Bit.mayPostdate] } set { self[Bit.mayPostdate] = newValue } }
    public var postdated: Bool { get { self[Bit.postdated] } set { self[Bit.postdated] = newValue } }
    public var invalid: Bool { get { self[Bit.invalid] } set { self[Bit.invalid] = newValue } }
    public var renewable: Bool { get { self[Bit.renewable] } set { self[Bit.renewable] = newValue } }
    /// TicketFlags `initial`.
    public var initial: Bool { get { self[Bit.initial] } set { self[Bit.initial] = newValue } }
    /// TicketFlags `pre-authent`.
    public var preAuthent: Bool { get { self[Bit.preAuthent] } set { self[Bit.preAuthent] = newValue } }
    public var hwAuthent: Bool { get { self[Bit.hwAuthent] } set { self[Bit.hwAuthent] = newValue } }
    public var transitedPolicyChecked: Bool {
        get { self[Bit.transitedPolicyChecked] } set { self[Bit.transitedPolicyChecked] = newValue }
    }
    /// TicketFlags `ok-as-delegate`.
    public var okAsDelegate: Bool { get { self[Bit.okAsDelegate] } set { self[Bit.okAsDelegate] = newValue } }
    /// TicketFlags `enc-pa-rep` (same bit as KDCOptions `canonicalize`).
    public var encPARep: Bool { get { self[Bit.encPARep] } set { self[Bit.encPARep] = newValue } }
    /// KDCOptions `cname-in-addl-tkt`.
    public var cnameInAddlTkt: Bool { get { self[Bit.cnameInAddlTkt] } set { self[Bit.cnameInAddlTkt] = newValue } }
    /// KDCOptions `canonicalize`.
    public var canonicalize: Bool { get { self[Bit.canonicalize] } set { self[Bit.canonicalize] = newValue } }
    public var requestAnonymous: Bool { get { self[Bit.requestAnonymous] } set { self[Bit.requestAnonymous] = newValue } }
    /// KDCOptions `disable-transited-check`.
    public var disableTransitedCheck: Bool {
        get { self[Bit.disableTransitedCheck] } set { self[Bit.disableTransitedCheck] = newValue }
    }
    /// KDCOptions `renewable-ok`.
    public var renewableOK: Bool { get { self[Bit.renewableOK] } set { self[Bit.renewableOK] = newValue } }
    /// KDCOptions `enc-tkt-in-skey`.
    public var encTktInSkey: Bool { get { self[Bit.encTktInSkey] } set { self[Bit.encTktInSkey] = newValue } }
    /// KDCOptions `renew`.
    public var renew: Bool { get { self[Bit.renew] } set { self[Bit.renew] = newValue } }
    /// KDCOptions `validate`.
    public var validate: Bool { get { self[Bit.validate] } set { self[Bit.validate] = newValue } }
    /// APOptions `use-session-key`.
    public var useSessionKey: Bool { get { self[Bit.useSessionKey] } set { self[Bit.useSessionKey] = newValue } }
    /// APOptions `mutual-required`.
    public var mutualRequired: Bool { get { self[Bit.mutualRequired] } set { self[Bit.mutualRequired] = newValue } }
}

public typealias KDCOptions = KerberosFlags
public typealias TicketFlags = KerberosFlags
public typealias APOptions = KerberosFlags

// MARK: - EncryptedData / EncryptionKey / Checksum

/// ```
/// EncryptedData ::= SEQUENCE {
///     etype   [0] Int32 -- EncryptionType --,
///     kvno    [1] UInt32 OPTIONAL,
///     cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```
/// `PA-ENC-TIMESTAMP ::= EncryptedData` — its padata-value is this type's encoding.
public struct EncryptedData: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var etype: Int32
    public var kvno: UInt32?
    public var cipher: [UInt8]

    public init(etype: Int32, kvno: UInt32? = nil, cipher: [UInt8]) {
        self.etype = etype
        self.kvno = kvno
        self.cipher = cipher
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            EncryptedData(
                etype: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                kvno: try Field.optional(&nodes, 1, Field.uint32),
                cipher: try Field.required(&nodes, 2, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, etype)
            try coder.optionalField(1, kvno)
            try coder.field(2, ASN1OctetString(contentBytes: cipher[...]))
        }
    }
}

/// ```
/// EncryptionKey ::= SEQUENCE {
///     keytype     [0] Int32,
///     keyvalue    [1] OCTET STRING
/// }
/// ```
public struct EncryptionKey: KerberosASN1Type, DERImplicitlyTaggable, CustomStringConvertible {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var keytype: Int32
    public var keyvalue: [UInt8]

    public init(keytype: Int32, keyvalue: [UInt8]) {
        self.keytype = keytype
        self.keyvalue = keyvalue
    }

    /// Never prints key material.
    public var description: String { "EncryptionKey(keytype: \(keytype), \(keyvalue.count) bytes)" }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            EncryptionKey(
                keytype: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                keyvalue: try Field.required(&nodes, 1, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, keytype)
            try coder.field(1, ASN1OctetString(contentBytes: keyvalue[...]))
        }
    }
}

/// ```
/// Checksum ::= SEQUENCE {
///     cksumtype   [0] Int32,
///     checksum    [1] OCTET STRING
/// }
/// ```
public struct Checksum: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var cksumtype: Int32
    public var checksum: [UInt8]

    public init(cksumtype: Int32, checksum: [UInt8]) {
        self.cksumtype = cksumtype
        self.checksum = checksum
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            Checksum(
                cksumtype: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                checksum: try Field.required(&nodes, 1, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, cksumtype)
            try coder.field(1, ASN1OctetString(contentBytes: checksum[...]))
        }
    }
}

// MARK: - TransitedEncoding

/// ```
/// TransitedEncoding ::= SEQUENCE {
///     tr-type     [0] Int32 -- must be registered --,
///     contents    [1] OCTET STRING
/// }
/// ```
public struct TransitedEncoding: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var trType: Int32
    public var contents: [UInt8]

    public init(trType: Int32 = TransitedType.domainX500Compress, contents: [UInt8] = []) {
        self.trType = trType
        self.contents = contents
    }

    /// No realms transited (`tr-type 1`, empty contents).
    public static let empty = TransitedEncoding()

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            TransitedEncoding(
                trType: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                contents: try Field.required(&nodes, 1, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, trType)
            try coder.field(1, ASN1OctetString(contentBytes: contents[...]))
        }
    }
}

// MARK: - LastReq

/// One LastReq element: `SEQUENCE { lr-type [0] Int32, lr-value [1] KerberosTime }`.
public struct LastReqEntry: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var lrType: Int32
    public var lrValue: KerberosTime

    public init(lrType: Int32, lrValue: KerberosTime) {
        self.lrType = lrType
        self.lrValue = lrValue
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            LastReqEntry(
                lrType: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                lrValue: try Field.required(&nodes, 1) { try KerberosTime(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, lrType)
            try coder.field(1, lrValue)
        }
    }
}

/// `LastReq ::= SEQUENCE OF SEQUENCE { lr-type [0] Int32, lr-value [1] KerberosTime }`.
/// A mandatory field: emitted even when empty.
public struct LastReq: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByArrayLiteral {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var elements: [LastReqEntry]

    public init(_ elements: [LastReqEntry] = []) { self.elements = elements }
    public init(arrayLiteral elements: LastReqEntry...) { self.elements = elements }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.elements = try DER.sequence(of: LastReqEntry.self, identifier: identifier, rootNode: node)
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(elements, identifier: identifier)
    }
}
