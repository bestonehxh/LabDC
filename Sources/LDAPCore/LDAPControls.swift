/// Control OIDs this package knows (RFC 2696, MS-ADTS §3.1.1.3.4.1).
public enum LDAPControlOID {
    /// `LDAP_PAGED_RESULT_OID_STRING` (RFC 2696).
    public static let pagedResults = "1.2.840.113556.1.4.319"
    /// `LDAP_SERVER_SD_FLAGS_OID`.
    public static let sdFlags = "1.2.840.113556.1.4.801"
    /// `LDAP_SERVER_SHOW_DELETED_OID`.
    public static let showDeleted = "1.2.840.113556.1.4.417"
    /// `LDAP_SERVER_SHOW_RECYCLED_OID`.
    public static let showRecycled = "1.2.840.113556.1.4.2064"
    /// `LDAP_SERVER_SORT_OID` (RFC 2891 request).
    public static let serverSort = "1.2.840.113556.1.4.473"
    /// `LDAP_SERVER_RESP_SORT_OID` (RFC 2891 response).
    public static let sortResponse = "1.2.840.113556.1.4.474"
    /// `LDAP_SERVER_PERMISSIVE_MODIFY_OID`.
    public static let permissiveModify = "1.2.840.113556.1.4.1413"
    /// `LDAP_SERVER_TREE_DELETE_OID`.
    public static let treeDelete = "1.2.840.113556.1.4.805"
    /// `LDAP_SERVER_DOMAIN_SCOPE_OID`: no referrals (we never generate any).
    public static let domainScope = "1.2.840.113556.1.4.1339"
    /// `LDAP_SERVER_NOTIFICATION_OID` (not supported).
    public static let notification = "1.2.840.113556.1.4.528"
    /// `LDAP_SERVER_EXTENDED_DN_OID` (not supported).
    public static let extendedDN = "1.2.840.113556.1.4.529"
    /// `LDAP_SERVER_LAZY_COMMIT_OID`: commits are synchronous anyway.
    public static let lazyCommit = "1.2.840.113556.1.4.619"
    /// ManageDsaIT (RFC 3296): we have no referral objects, so it is a no-op.
    public static let manageDsaIT = "2.16.840.1.113730.3.4.2"
}

/// Extended operation OIDs.
public enum LDAPExtendedOID {
    /// StartTLS (RFC 4511 §4.14).
    public static let startTLS = "1.3.6.1.4.1.1466.20037"
    /// "Who am I?" (RFC 4532).
    public static let whoAmI = "1.3.6.1.4.1.4203.1.11.3"
    /// Password Modify (RFC 3062).
    public static let passwordModify = "1.3.6.1.4.1.4203.1.11.1"
    /// Notice of Disconnection (RFC 4511 §4.4.1), unsolicited.
    public static let noticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
}

/// `realSearchControlValue ::= SEQUENCE { size INTEGER, cookie OCTET STRING }` (RFC 2696).
public struct PagedResultsValue: Sendable, Hashable {
    /// Requested page size (request) or the estimated total (response; 0 = unknown).
    public var size: Int32
    /// Empty on the first request and on the last response.
    public var cookie: [UInt8]

    public init(size: Int32, cookie: [UInt8] = []) {
        self.size = size
        self.cookie = cookie
    }

    public init(controlValue: [UInt8]) throws {
        var f = try BERFields(try BERElement(bytes: controlValue).expect(.sequence, "pagedResults"), "pagedResults")
        size = try f.next(.integer, "size").int32()
        cookie = try f.next(.octetString, "cookie").octets()
    }

    public var controlValue: [UInt8] { BERElement.sequence([.integer(Int64(size)), .octetString(cookie)]).encoded() }

    public func control(critical: Bool = false) -> LDAPControl {
        LDAPControl(oid: LDAPControlOID.pagedResults, critical: critical, value: controlValue)
    }
}

/// `SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }` (MS-ADTS §3.1.1.3.4.1.11).
public struct SDFlagsValue: Sendable, Hashable {
    public static let owner: UInt32 = 0x1, group: UInt32 = 0x2, dacl: UInt32 = 0x4, sacl: UInt32 = 0x8

    public var flags: UInt32

    public init(flags: UInt32) { self.flags = flags }

    public init(controlValue: [UInt8]) throws {
        var f = try BERFields(try BERElement(bytes: controlValue).expect(.sequence, "sdFlags"), "sdFlags")
        flags = UInt32(truncatingIfNeeded: try f.next(.integer, "Flags").integer())
    }

    public var controlValue: [UInt8] { BERElement.sequence([.integer(Int64(flags))]).encoded() }
}

/// RFC 2891 `SortKeyList` (decoded only so that the request can be refused precisely).
public struct SortRequestValue: Sendable, Hashable {
    public struct Key: Sendable, Hashable {
        public var attribute: String
        public var orderingRule: String?
        public var reverse: Bool
    }

    public var keys: [Key]

    public init(controlValue: [UInt8]) throws {
        let list = try BERElement(bytes: controlValue).expect(.sequence, "SortKeyList")
        keys = try list.children().map { k in
            var f = try BERFields(try k.expect(.sequence, "SortKey"), "SortKey")
            let attr = try f.next(.octetString, "attributeType").string()
            let rule = try f.optional(.context(0)).map { try $0.string() }
            let reverse = try f.optional(.context(1)).map { try $0.boolean() } ?? false
            return Key(attribute: attr, orderingRule: rule, reverse: reverse)
        }
    }
}

/// RFC 2891 `SortResult ::= SEQUENCE { sortResult ENUMERATED, attributeType [0] OPTIONAL }`.
public struct SortResponseValue: Sendable, Hashable {
    public var result: LDAPResultCode
    public var attribute: String?

    public init(result: LDAPResultCode, attribute: String? = nil) {
        self.result = result
        self.attribute = attribute
    }

    public var controlValue: [UInt8] {
        var items: [BERElement] = [.enumerated(Int64(result.rawValue))]
        if let attribute { items.append(.octetString(attribute, tag: .context(0))) }
        return BERElement.sequence(items).encoded()
    }

    public var control: LDAPControl { LDAPControl(oid: LDAPControlOID.sortResponse, value: controlValue) }
}

/// RFC 3062 `PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0], oldPasswd [1], newPasswd [2] }`,
/// all OPTIONAL. The request value itself may be absent.
public struct PasswordModifyRequestValue: Sendable, Hashable {
    public var userIdentity: [UInt8]?
    public var oldPassword: [UInt8]?
    public var newPassword: [UInt8]?

    public init(userIdentity: [UInt8]? = nil, oldPassword: [UInt8]? = nil, newPassword: [UInt8]? = nil) {
        self.userIdentity = userIdentity
        self.oldPassword = oldPassword
        self.newPassword = newPassword
    }

    public init(requestValue: [UInt8]?) throws {
        guard let requestValue else { return }
        var f = try BERFields(try BERElement(bytes: requestValue).expect(.sequence, "PasswdModifyRequestValue"),
                              "PasswdModifyRequestValue")
        userIdentity = try f.optional(.context(0)).map { try $0.octets() }
        oldPassword = try f.optional(.context(1)).map { try $0.octets() }
        newPassword = try f.optional(.context(2)).map { try $0.octets() }
    }

    public var requestValue: [UInt8] {
        var items: [BERElement] = []
        if let userIdentity { items.append(.octetString(userIdentity, tag: .context(0))) }
        if let oldPassword { items.append(.octetString(oldPassword, tag: .context(1))) }
        if let newPassword { items.append(.octetString(newPassword, tag: .context(2))) }
        return BERElement.sequence(items).encoded()
    }
}

/// RFC 3062 `PasswdModifyResponseValue ::= SEQUENCE { genPasswd [0] OPTIONAL }`.
public struct PasswordModifyResponseValue: Sendable, Hashable {
    public var generatedPassword: [UInt8]?

    public init(generatedPassword: [UInt8]? = nil) { self.generatedPassword = generatedPassword }

    public var responseValue: [UInt8] {
        BERElement.sequence(generatedPassword.map { [.octetString($0, tag: .context(0))] } ?? []).encoded()
    }
}
