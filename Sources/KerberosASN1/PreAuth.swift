import SwiftASN1

// MARK: - PA-ENC-TS-ENC

/// ```
/// PA-ENC-TS-ENC ::= SEQUENCE {
///     patimestamp     [0] KerberosTime -- client's time --,
///     pausec          [1] Microseconds OPTIONAL
/// }
/// ```
/// The plaintext of PA-ENC-TIMESTAMP (whose padata-value is an `EncryptedData`).
public struct PAEncTSEnc: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var patimestamp: KerberosTime
    public var pausec: Microseconds?

    public init(patimestamp: KerberosTime, pausec: Microseconds? = nil) {
        self.patimestamp = patimestamp
        self.pausec = pausec
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            PAEncTSEnc(
                patimestamp: try Field.required(&nodes, 0) { try KerberosTime(derEncoded: $0) },
                pausec: try Field.optional(&nodes, 1, Field.microseconds))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, patimestamp)
            try coder.optionalField(1, pausec)
        }
    }
}

// MARK: - ETYPE-INFO2

/// ```
/// ETYPE-INFO2-ENTRY ::= SEQUENCE {
///     etype           [0] Int32,
///     salt            [1] KerberosString OPTIONAL,
///     s2kparams       [2] OCTET STRING OPTIONAL
/// }
/// ```
public struct ETypeInfo2Entry: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var etype: Int32
    public var salt: String?
    public var s2kparams: [UInt8]?

    public init(etype: Int32, salt: String? = nil, s2kparams: [UInt8]? = nil) {
        self.etype = etype
        self.salt = salt
        self.s2kparams = s2kparams
    }

    /// AES `s2kparams`: the PBKDF2 iteration count as a 4-byte big-endian integer (RFC 3962 §4).
    public static func aesIterations(_ count: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16),
         UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            ETypeInfo2Entry(
                etype: try Field.required(&nodes, 0) { try Int32(derEncoded: $0) },
                salt: try Field.optional(&nodes, 1) { try KerberosString(derEncoded: $0).value },
                s2kparams: try Field.optional(&nodes, 2, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, etype)
            try coder.optionalField(1, salt.map { KerberosString($0) })
            try coder.optionalField(2, s2kparams.map { ASN1OctetString(contentBytes: $0[...]) })
        }
    }
}

/// `ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY` (entries in KDC preference order).
public struct ETypeInfo2: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByArrayLiteral {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var entries: [ETypeInfo2Entry]

    public init(_ entries: [ETypeInfo2Entry]) { self.entries = entries }
    public init(arrayLiteral entries: ETypeInfo2Entry...) { self.entries = entries }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.entries = try DER.sequence(of: ETypeInfo2Entry.self, identifier: identifier, rootNode: node)
        guard !entries.isEmpty else {
            throw KerberosASN1Error.invalidField(name: "ETYPE-INFO2", reason: "SIZE (1..MAX): empty")
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(entries, identifier: identifier)
    }

    /// The PA-DATA (type 19) carrying this ETYPE-INFO2.
    public var paData: PAData { PAData(type: PADataType.etypeInfo2, value: encode()) }
}

// MARK: - MS-KILE PA-PAC-REQUEST / PA-PAC-OPTIONS

/// MS-KILE KERB-PA-PAC-REQUEST (padata-type 128):
/// ```
/// KERB-PA-PAC-REQUEST ::= SEQUENCE {
///     include-pac     [0] BOOLEAN -- if TRUE, and no PAC present, include PAC.
///                                 -- if FALSE, and PAC present, remove PAC
/// }
/// ```
/// Decoding accepts any non-zero BOOLEAN octet as TRUE (DER requires 0xFF; not every client
/// obeys); encoding always writes 0xFF / 0x00.
public struct PAPacRequest: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var includePAC: Bool

    public init(includePAC: Bool) { self.includePAC = includePAC }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            PAPacRequest(includePAC: try Field.required(&nodes, 0) { n in
                guard n.identifier == .boolean, case .primitive(let b) = n.content, b.count == 1 else {
                    throw KerberosASN1Error.invalidField(name: "include-pac", reason: "not a BOOLEAN")
                }
                return b.first! != 0
            })
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, includePAC)
        }
    }

    /// The PA-DATA (type 128) carrying this request.
    public var paData: PAData { PAData(type: PADataType.pacRequest, value: encode()) }
}

/// MS-KILE PA-PAC-OPTIONS (padata-type 167):
/// ```
/// PA-PAC-OPTIONS ::= SEQUENCE {
///     flags   [0] PAC-OPTIONS-FLAGS   -- KerberosFlags
///     -- Claims (0), Branch Aware (1), Forward to Full DC (2),
///     -- Resource-based Constrained Delegation (3)
/// }
/// ```
/// (MS-KILE prints the member untagged; Windows, Heimdal, Samba and Wireshark all use `[0]`.)
public struct PAPacOptions: KerberosASN1Type, DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }

    public var flags: KerberosFlags

    public init(flags: KerberosFlags = KerberosFlags()) { self.flags = flags }

    public enum Bit {
        public static let claims = 0
        public static let branchAware = 1
        public static let forwardToFullDC = 2
        public static let resourceBasedConstrainedDelegation = 3
    }

    public var claims: Bool { get { flags[Bit.claims] } set { flags[Bit.claims] = newValue } }
    public var branchAware: Bool { get { flags[Bit.branchAware] } set { flags[Bit.branchAware] = newValue } }
    public var forwardToFullDC: Bool {
        get { flags[Bit.forwardToFullDC] } set { flags[Bit.forwardToFullDC] = newValue }
    }
    public var resourceBasedConstrainedDelegation: Bool {
        get { flags[Bit.resourceBasedConstrainedDelegation] }
        set { flags[Bit.resourceBasedConstrainedDelegation] = newValue }
    }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            PAPacOptions(flags: try Field.required(&nodes, 0) { try KerberosFlags(derEncoded: $0) })
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.field(0, flags)
        }
    }

    /// The PA-DATA (type 167) carrying these options.
    public var paData: PAData { PAData(type: PADataType.pacOptions, value: encode()) }
}

/// The spec's name for the PA-PAC-OPTIONS flag set.
public typealias KERBPAPacOptions = PAPacOptions
