import SwiftASN1

/// ```
/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
///     pvno            [0] INTEGER (5),
///     msg-type        [1] INTEGER (30),
///     ctime           [2] KerberosTime OPTIONAL,
///     cusec           [3] Microseconds OPTIONAL,
///     stime           [4] KerberosTime,
///     susec           [5] Microseconds,
///     error-code      [6] Int32,
///     crealm          [7] Realm OPTIONAL,
///     cname           [8] PrincipalName OPTIONAL,
///     realm           [9] Realm -- service realm --,
///     sname           [10] PrincipalName -- service name --,
///     e-text          [11] KerberosString OPTIONAL,
///     e-data          [12] OCTET STRING OPTIONAL
/// }
/// ```
/// For `KDC_ERR_PREAUTH_REQUIRED`, `e-data` is a DER `METHOD-DATA` (see `init(..., methodData:)`
/// and `methodData()`).
public struct KRBError: KerberosApplicationMessage {
    public static var applicationTag: UInt { 30 }

    public var ctime: KerberosTime?
    public var cusec: Microseconds?
    public var stime: KerberosTime
    public var susec: Microseconds
    public var errorCode: Int32
    public var crealm: String?
    public var cname: PrincipalName?
    public var realm: String
    public var sname: PrincipalName
    public var eText: String?
    public var eData: [UInt8]?

    public init(
        ctime: KerberosTime? = nil,
        cusec: Microseconds? = nil,
        stime: KerberosTime,
        susec: Microseconds = 0,
        errorCode: Int32,
        crealm: String? = nil,
        cname: PrincipalName? = nil,
        realm: String,
        sname: PrincipalName,
        eText: String? = nil,
        eData: [UInt8]? = nil
    ) {
        self.ctime = ctime
        self.cusec = cusec
        self.stime = stime
        self.susec = susec
        self.errorCode = errorCode
        self.crealm = crealm
        self.cname = cname
        self.realm = realm
        self.sname = sname
        self.eText = eText
        self.eData = eData
    }

    /// Convenience: `e-data` = DER of the given METHOD-DATA (e.g. PA-ETYPE-INFO2 + empty PA-ENC-TIMESTAMP).
    public init(
        stime: KerberosTime,
        susec: Microseconds = 0,
        errorCode: Int32,
        crealm: String? = nil,
        cname: PrincipalName? = nil,
        realm: String,
        sname: PrincipalName,
        eText: String? = nil,
        methodData: MethodData
    ) {
        self.init(
            stime: stime, susec: susec, errorCode: errorCode, crealm: crealm, cname: cname,
            realm: realm, sname: sname, eText: eText, eData: methodData.encode())
    }

    /// Decodes `e-data` as METHOD-DATA; `nil` when there is no e-data.
    public func methodData() throws -> MethodData? {
        guard let eData else { return nil }
        return try MethodData(derBytes: eData)
    }

    public init(derEncoded node: ASN1Node) throws {
        self = try Field.applicationSequence(node, tag: Self.applicationTag) { nodes in
            _ = try Field.required(&nodes, 0, Field.version)
            try Field.required(&nodes, 1) { try Field.messageType($0, expected: MessageType.krbError) }
            return KRBError(
                ctime: try Field.optional(&nodes, 2) { try KerberosTime(derEncoded: $0) },
                cusec: try Field.optional(&nodes, 3, Field.microseconds),
                stime: try Field.required(&nodes, 4) { try KerberosTime(derEncoded: $0) },
                susec: try Field.required(&nodes, 5, Field.microseconds),
                errorCode: try Field.required(&nodes, 6) { try Int32(derEncoded: $0) },
                crealm: try Field.optional(&nodes, 7) { try KerberosString(derEncoded: $0).value },
                cname: try Field.optional(&nodes, 8) { try PrincipalName(derEncoded: $0) },
                realm: try Field.required(&nodes, 9) { try KerberosString(derEncoded: $0).value },
                sname: try Field.required(&nodes, 10) { try PrincipalName(derEncoded: $0) },
                eText: try Field.optional(&nodes, 11) { try KerberosString(derEncoded: $0).value },
                eData: try Field.optional(&nodes, 12, Field.octets))
        }
    }

    public func serialize(into coder: inout DER.Serializer) throws {
        try coder.applicationSequence(Self.applicationTag) { coder in
            try coder.field(0, 5)
            try coder.field(1, MessageType.krbError)
            try coder.optionalField(2, ctime)
            try coder.optionalField(3, cusec)
            try coder.field(4, stime)
            try coder.field(5, susec)
            try coder.field(6, errorCode)
            try coder.optionalField(7, crealm.map { KerberosString($0) })
            try coder.optionalField(8, cname)
            try coder.field(9, KerberosString(realm))
            try coder.field(10, sname)
            try coder.optionalField(11, eText.map { KerberosString($0) })
            try coder.optionalField(12, eData.map { ASN1OctetString(contentBytes: $0[...]) })
        }
    }
}
