/// Attribute syntaxes (MS-ADTS §3.1.1.2.2.2). Only what matching and the subschema need.
public enum AttributeSyntax: String, Sendable, CaseIterable {
    case dn, oid, caseIgnoreString, printableString, numericString, boolean, integer, octetString,
         generalizedTime, unicodeString, securityDescriptor, largeInteger, sid, dnBinary

    /// `attributeSyntax` value.
    public var attributeSyntaxOID: String {
        switch self {
        case .dn: "2.5.5.1"
        case .oid: "2.5.5.2"
        case .caseIgnoreString: "2.5.5.4"
        case .printableString: "2.5.5.5"
        case .numericString: "2.5.5.6"
        case .dnBinary: "2.5.5.7"
        case .boolean: "2.5.5.8"
        case .integer: "2.5.5.9"
        case .octetString: "2.5.5.10"
        case .generalizedTime: "2.5.5.11"
        case .unicodeString: "2.5.5.12"
        case .securityDescriptor: "2.5.5.15"
        case .largeInteger: "2.5.5.16"
        case .sid: "2.5.5.17"
        }
    }

    /// `oMSyntax` value.
    public var oMSyntax: Int {
        switch self {
        case .dn, .dnBinary: 127
        case .oid: 6
        case .caseIgnoreString: 20
        case .printableString: 19
        case .numericString: 18
        case .boolean: 1
        case .integer: 2
        case .octetString, .sid: 4
        case .generalizedTime: 24
        case .unicodeString: 64
        case .securityDescriptor: 66
        case .largeInteger: 65
        }
    }

    /// LDAP syntax OID for the subschema entry (RFC 4517 / MS-ADTS §3.1.1.2.2.2).
    public var ldapSyntaxOID: String {
        switch self {
        case .dn: "1.3.6.1.4.1.1466.115.121.1.12"
        case .oid: "1.3.6.1.4.1.1466.115.121.1.38"
        case .caseIgnoreString: "1.3.6.1.4.1.1466.115.121.1.44"
        case .printableString: "1.3.6.1.4.1.1466.115.121.1.44"
        case .numericString: "1.3.6.1.4.1.1466.115.121.1.36"
        case .boolean: "1.3.6.1.4.1.1466.115.121.1.7"
        case .integer: "1.3.6.1.4.1.1466.115.121.1.27"
        case .octetString, .sid: "1.3.6.1.4.1.1466.115.121.1.40"
        case .generalizedTime: "1.3.6.1.4.1.1466.115.121.1.24"
        case .unicodeString: "1.3.6.1.4.1.1466.115.121.1.15"
        case .securityDescriptor: "1.2.840.113556.1.4.907"
        case .largeInteger: "1.2.840.113556.1.4.906"
        case .dnBinary: "1.2.840.113556.1.4.903"
        }
    }

    /// Values compared as bytes (no case folding).
    public var isBinary: Bool { self == .octetString || self == .sid || self == .securityDescriptor }
    /// Values compared as signed 64-bit integers.
    public var isInteger: Bool { self == .integer || self == .largeInteger }
}

/// An `attributeSchema` entry of the built-in catalog.
public struct AttributeDefinition: Sendable, Hashable {
    public var name: String
    public var cn: String
    public var oid: String
    public var syntax: AttributeSyntax
    public var singleValued: Bool
    /// Even for forward links, odd (forward + 1) for back links.
    public var linkID: Int?
}

/// A `classSchema` entry of the built-in catalog.
public struct ClassDefinition: Sendable, Hashable {
    public enum Kind: Int, Sendable { case structural = 1, abstract = 2, auxiliary = 3 }
    public var name: String
    public var cn: String
    public var oid: String
    public var superior: String?
    public var kind: Kind
    /// The class whose `CN=` in the schema NC is `objectCategory` (`person` for `user`).
    public var category: String
}

/// The built-in schema: syntaxes for matching, class chains for `objectClass`, linked-attribute
/// pairs, and the objects written into the Schema NC. OIDs follow MS-ADA1..3 / MS-ADSC.
public enum DirectorySchema {
    private static func a(_ name: String, _ cn: String, _ oid: String, _ syntax: AttributeSyntax,
                          single: Bool = true, link: Int? = nil) -> AttributeDefinition {
        AttributeDefinition(name: name, cn: cn, oid: oid, syntax: syntax, singleValued: single, linkID: link)
    }

    public static let attributes: [AttributeDefinition] = [
        a("accountExpires", "Account-Expires", "1.2.840.113556.1.4.159", .largeInteger),
        a("adminCount", "Admin-Count", "1.2.840.113556.1.4.150", .integer),
        a("badPwdCount", "Bad-Pwd-Count", "1.2.840.113556.1.4.12", .integer),
        a("cn", "Common-Name", "2.5.4.3", .unicodeString),
        a("dc", "Domain-Component", "0.9.2342.19200300.100.1.25", .unicodeString),
        a("defaultObjectCategory", "Default-Object-Category", "1.2.840.113556.1.4.783", .dn),
        a("description", "Description", "2.5.4.13", .unicodeString, single: false),
        a("directReports", "Reports", "1.2.840.113556.1.2.436", .dn, single: false, link: 43),
        a("displayName", "Display-Name", "1.2.840.113556.1.2.13", .unicodeString),
        a("distinguishedName", "Obj-Dist-Name", "2.5.4.49", .dn),
        a("dNSHostName", "DNS-Host-Name", "1.2.840.113556.1.4.619", .unicodeString),
        a("dnsRoot", "Dns-Root", "1.2.840.113556.1.4.28", .unicodeString, single: false),
        a("givenName", "Given-Name", "2.5.4.42", .unicodeString),
        a("governsID", "Governs-ID", "1.2.840.113556.1.2.22", .oid),
        a("groupType", "Group-Type", "1.2.840.113556.1.4.750", .integer),
        a("instanceType", "Instance-Type", "1.2.840.113556.1.2.1", .integer),
        a("isCriticalSystemObject", "Is-Critical-System-Object", "1.2.840.113556.1.4.868", .boolean),
        a("isDeleted", "Is-Deleted", "1.2.840.113556.1.2.48", .boolean),
        a("lastKnownParent", "Last-Known-Parent", "1.2.840.113556.1.4.781", .dn),
        a("lastLogon", "Last-Logon", "1.2.840.113556.1.4.52", .largeInteger),
        a("lastLogonTimestamp", "Last-Logon-Timestamp", "1.2.840.113556.1.4.1696", .largeInteger),
        a("lDAPDisplayName", "LDAP-Display-Name", "1.2.840.113556.1.2.460", .unicodeString),
        a("linkID", "Link-ID", "1.2.840.113556.1.2.50", .integer),
        a("logonCount", "Logon-Count", "1.2.840.113556.1.4.169", .integer),
        a("mail", "E-mail-Addresses", "0.9.2342.19200300.100.1.3", .unicodeString),
        a("managedBy", "Managed-By", "1.2.840.113556.1.4.653", .dn, link: 72),
        a("managedObjects", "Managed-Objects", "1.2.840.113556.1.4.654", .dn, single: false, link: 73),
        a("manager", "Manager", "0.9.2342.19200300.100.1.10", .dn, link: 42),
        a("member", "Member", "2.5.4.31", .dn, single: false, link: 2),
        a("memberOf", "Is-Member-Of-DL", "1.2.840.113556.1.2.102", .dn, single: false, link: 3),
        a("minPwdLength", "Min-Pwd-Length", "1.2.840.113556.1.4.78", .integer),
        a("msDS-Behavior-Version", "ms-DS-Behavior-Version", "1.2.840.113556.1.4.1459", .integer),
        a("msDS-SupportedEncryptionTypes", "ms-DS-Supported-Encryption-Types", "1.2.840.113556.1.4.1963", .integer),
        a("mS-DS-CreatorSID", "ms-DS-Creator-SID", "1.2.840.113556.1.4.1861", .sid),
        a("ms-DS-MachineAccountQuota", "MS-DS-Machine-Account-Quota", "1.2.840.113556.1.4.1411", .integer),
        a("name", "RDN", "1.2.840.113556.1.4.1", .unicodeString),
        a("nCName", "NC-Name", "1.2.840.113556.1.2.16", .dn),
        a("nETBIOSName", "NETBIOS-Name", "1.2.840.113556.1.4.87", .unicodeString),
        a("nTSecurityDescriptor", "NT-Security-Descriptor", "1.2.840.113556.1.2.281", .securityDescriptor),
        a("objectCategory", "Object-Category", "1.2.840.113556.1.4.782", .dn),
        a("objectClass", "Object-Class", "2.5.4.0", .oid, single: false),
        a("objectClassCategory", "Object-Class-Category", "1.2.840.113556.1.2.370", .integer),
        a("objectGUID", "Object-Guid", "1.2.840.113556.1.4.2", .octetString),
        a("objectSid", "Object-Sid", "1.2.840.113556.1.4.146", .sid),
        a("operatingSystem", "Operating-System", "1.2.840.113556.1.4.363", .unicodeString),
        a("primaryGroupID", "Primary-Group-ID", "1.2.840.113556.1.4.98", .integer),
        a("pwdHistoryLength", "Pwd-History-Length", "1.2.840.113556.1.4.95", .integer),
        a("pwdLastSet", "Pwd-Last-Set", "1.2.840.113556.1.4.96", .largeInteger),
        a("pwdProperties", "Pwd-Properties", "1.2.840.113556.1.4.93", .integer),
        a("rIDAvailablePool", "RID-Available-Pool", "1.2.840.113556.1.4.370", .largeInteger),
        a("sAMAccountName", "SAM-Account-Name", "1.2.840.113556.1.4.221", .unicodeString),
        a("sAMAccountType", "SAM-Account-Type", "1.2.840.113556.1.4.302", .integer),
        a("serverReference", "Server-Reference", "1.2.840.113556.1.4.515", .dn, link: 94),
        a("serverReferenceBL", "Server-Reference-BL", "1.2.840.113556.1.4.516", .dn, single: false, link: 95),
        a("servicePrincipalName", "Service-Principal-Name", "1.2.840.113556.1.4.771", .unicodeString, single: false),
        a("sn", "Surname", "2.5.4.4", .unicodeString),
        a("subClassOf", "Sub-Class-Of", "1.2.840.113556.1.2.21", .oid),
        a("systemFlags", "System-Flags", "1.2.840.113556.1.4.375", .integer),
        a("tombstoneLifetime", "Tombstone-Lifetime", "1.2.840.113556.1.2.54", .integer),
        a("unicodePwd", "Unicode-Pwd", "1.2.840.113556.1.4.90", .octetString),
        a("userAccountControl", "User-Account-Control", "1.2.840.113556.1.4.8", .integer),
        a("userPrincipalName", "User-Principal-Name", "1.2.840.113556.1.4.656", .unicodeString),
        a("uSNChanged", "USN-Changed", "1.2.840.113556.1.2.120", .largeInteger),
        a("uSNCreated", "USN-Created", "1.2.840.113556.1.2.19", .largeInteger),
        a("wellKnownObjects", "Well-Known-Objects", "1.2.840.113556.1.4.618", .dnBinary, single: false),
        a("otherWellKnownObjects", "Other-Well-Known-Objects", "1.2.840.113556.1.4.1359", .dnBinary, single: false),
        a("whenChanged", "When-Changed", "1.2.840.113556.1.2.3", .generalizedTime),
        a("whenCreated", "When-Created", "1.2.840.113556.1.2.2", .generalizedTime),
        // PK-4: Group Policy containers and links (MS-ADA1..3) — integers so `versionNumber>=`
        // and `flags:1.2.840.113556.1.4.803:=` compare numerically.
        a("flags", "Flags", "1.2.840.113556.1.4.38", .integer),
        a("versionNumber", "Version-Number", "1.2.840.113556.1.4.141", .integer),
        a("gPCFunctionalityVersion", "GPC-Functionality-Version", "1.2.840.113556.1.4.893", .integer),
        a("gPCFileSysPath", "GPC-File-Sys-Path", "1.2.840.113556.1.4.894", .unicodeString),
        a("gPCMachineExtensionNames", "GPC-Machine-Extension-Names", "1.2.840.113556.1.4.1348", .unicodeString),
        a("gPCUserExtensionNames", "GPC-User-Extension-Names", "1.2.840.113556.1.4.1349", .unicodeString),
        a("gPCWQLFilter", "GPC-WQL-Filter", "1.2.840.113556.1.4.1694", .unicodeString),
        a("gPLink", "GP-Link", "1.2.840.113556.1.4.891", .unicodeString),
        a("gPOptions", "GP-Options", "1.2.840.113556.1.4.892", .integer),
        // [MS-GPWL]: the 802.11 / 802.3 policy objects under a GPO's CN=Machine (MS-ADA2).
        a("ms-net-ieee-80211-GP-PolicyGUID", "ms-net-ieee-80211-GP-PolicyGUID", "1.2.840.113556.1.4.1951", .unicodeString),
        a("ms-net-ieee-80211-GP-PolicyData", "ms-net-ieee-80211-GP-PolicyData", "1.2.840.113556.1.4.1952", .unicodeString),
        a("ms-net-ieee-80211-GP-PolicyReserved", "ms-net-ieee-80211-GP-PolicyReserved", "1.2.840.113556.1.4.1953", .octetString),
        a("ms-net-ieee-8023-GP-PolicyGUID", "ms-net-ieee-8023-GP-PolicyGUID", "1.2.840.113556.1.4.1954", .unicodeString),
        a("ms-net-ieee-8023-GP-PolicyData", "ms-net-ieee-8023-GP-PolicyData", "1.2.840.113556.1.4.1955", .unicodeString),
        a("ms-net-ieee-8023-GP-PolicyReserved", "ms-net-ieee-8023-GP-PolicyReserved", "1.2.840.113556.1.4.1956", .octetString),
        // PK-4: certificationAuthority objects (Configuration NC, Public Key Services).
        a("cACertificate", "CA-Certificate", "2.5.4.37", .octetString, single: false),
        // PK-6: certificates issued for an account (CT_FLAG_PUBLISH_TO_DS templates).
        a("userCertificate", "X509-Cert", "2.5.4.36", .octetString, single: false),
        a("authorityRevocationList", "Authority-Revocation-List", "2.5.4.38", .octetString, single: false),
        a("certificateRevocationList", "Certificate-Revocation-List", "2.5.4.39", .octetString, single: false),
        a("cACertificateDN", "CA-Certificate-DN", "1.2.840.113556.1.4.697", .unicodeString),
        // PK-5: enrollment services, certificate templates, enterprise OIDs, CDP objects
        // (attributeId / syntax / single-valuedness from MS-ADA1..3, as Samba's
        // MS-AD_Schema_2K8_R2_Attributes.txt lists them).
        a("crossCertificatePair", "Cross-Certificate-Pair", "2.5.4.40", .octetString, single: false),
        a("deltaRevocationList", "Delta-Revocation-List", "2.5.4.53", .octetString, single: false),
        a("certificateTemplates", "Certificate-Templates", "1.2.840.113556.1.4.823", .unicodeString, single: false),
        a("msPKI-Enrollment-Servers", "ms-PKI-Enrollment-Servers", "1.2.840.113556.1.4.2076", .unicodeString, single: false),
        a("msPKI-Site-Name", "ms-PKI-Site-Name", "1.2.840.113556.1.4.2077", .unicodeString),
        a("revision", "Revision", "1.2.840.113556.1.4.145", .integer),
        a("pKIDefaultKeySpec", "PKI-Default-Key-Spec", "1.2.840.113556.1.4.1327", .integer),
        a("pKIKeyUsage", "PKI-Key-Usage", "1.2.840.113556.1.4.1328", .octetString),
        a("pKIMaxIssuingDepth", "PKI-Max-Issuing-Depth", "1.2.840.113556.1.4.1329", .integer),
        a("pKICriticalExtensions", "PKI-Critical-Extensions", "1.2.840.113556.1.4.1330", .unicodeString, single: false),
        a("pKIExpirationPeriod", "PKI-Expiration-Period", "1.2.840.113556.1.4.1331", .octetString),
        a("pKIOverlapPeriod", "PKI-Overlap-Period", "1.2.840.113556.1.4.1332", .octetString),
        a("pKIExtendedKeyUsage", "PKI-Extended-Key-Usage", "1.2.840.113556.1.4.1333", .unicodeString, single: false),
        a("pKIDefaultCSPs", "PKI-Default-CSPs", "1.2.840.113556.1.4.1334", .unicodeString, single: false),
        a("msPKI-RA-Signature", "ms-PKI-RA-Signature", "1.2.840.113556.1.4.1429", .integer),
        a("msPKI-Enrollment-Flag", "ms-PKI-Enrollment-Flag", "1.2.840.113556.1.4.1430", .integer),
        a("msPKI-Private-Key-Flag", "ms-PKI-Private-Key-Flag", "1.2.840.113556.1.4.1431", .integer),
        a("msPKI-Certificate-Name-Flag", "ms-PKI-Certificate-Name-Flag", "1.2.840.113556.1.4.1432", .integer),
        a("msPKI-Minimal-Key-Size", "ms-PKI-Minimal-Key-Size", "1.2.840.113556.1.4.1433", .integer),
        a("msPKI-Template-Schema-Version", "ms-PKI-Template-Schema-Version", "1.2.840.113556.1.4.1434", .integer),
        a("msPKI-Template-Minor-Revision", "ms-PKI-Template-Minor-Revision", "1.2.840.113556.1.4.1435", .integer),
        a("msPKI-Cert-Template-OID", "ms-PKI-Cert-Template-OID", "1.2.840.113556.1.4.1436", .unicodeString),
        a("msPKI-Supersede-Templates", "ms-PKI-Supersede-Templates", "1.2.840.113556.1.4.1437", .unicodeString, single: false),
        a("msPKI-RA-Policies", "ms-PKI-RA-Policies", "1.2.840.113556.1.4.1438", .unicodeString, single: false),
        a("msPKI-Certificate-Policy", "ms-PKI-Certificate-Policy", "1.2.840.113556.1.4.1439", .unicodeString, single: false),
        a("msPKI-Certificate-Application-Policy", "ms-PKI-Certificate-Application-Policy", "1.2.840.113556.1.4.1674",
          .unicodeString, single: false),
        a("msPKI-RA-Application-Policies", "ms-PKI-RA-Application-Policies", "1.2.840.113556.1.4.1675",
          .unicodeString, single: false),
        a("msPKI-OIDLocalizedName", "ms-PKI-OID-LocalizedName", "1.2.840.113556.1.4.1712", .unicodeString, single: false),
    ]

    private static func c(_ name: String, _ cn: String, _ oid: String, _ sup: String?,
                          _ kind: ClassDefinition.Kind = .structural, category: String? = nil) -> ClassDefinition {
        ClassDefinition(name: name, cn: cn, oid: oid, superior: sup, kind: kind, category: category ?? name)
    }

    public static let classes: [ClassDefinition] = [
        c("top", "Top", "2.5.6.0", nil, .abstract),
        c("person", "Person", "2.5.6.6", "top"),
        c("organizationalPerson", "Organizational-Person", "2.5.6.7", "person", category: "person"),
        c("user", "User", "1.2.840.113556.1.5.9", "organizationalPerson", category: "person"),
        c("computer", "Computer", "1.2.840.113556.1.3.30", "user"),
        c("group", "Group", "1.2.840.113556.1.5.8", "top"),
        c("organizationalUnit", "Organizational-Unit", "2.5.6.5", "top"),
        c("container", "Container", "1.2.840.113556.1.3.23", "top"),
        c("domain", "Domain", "1.2.840.113556.1.5.66", "top", .abstract),
        c("domainDNS", "Domain-DNS", "1.2.840.113556.1.5.67", "domain"),
        c("builtinDomain", "Builtin-Domain", "1.2.840.113556.1.5.4", "top"),
        c("foreignSecurityPrincipal", "Foreign-Security-Principal", "1.2.840.113556.1.5.76", "top"),
        c("configuration", "Configuration", "1.2.840.113556.1.5.12", "top"),
        c("dMD", "DMD", "1.2.840.113556.1.3.9", "top"),
        c("classSchema", "Class-Schema", "1.2.840.113556.1.3.13", "top"),
        c("attributeSchema", "Attribute-Schema", "1.2.840.113556.1.3.14", "top"),
        c("subSchema", "SubSchema", "2.5.20.1", "top"),
        c("rIDManager", "RID-Manager", "1.2.840.113556.1.5.83", "top"),
        c("lostAndFound", "Lost-And-Found", "1.2.840.113556.1.5.139", "top"),
        c("infrastructureUpdate", "Infrastructure-Update", "1.2.840.113556.1.5.175", "top"),
        c("msDS-QuotaContainer", "ms-DS-Quota-Container", "1.2.840.113556.1.5.242", "top"),
        c("msDS-PasswordSettingsContainer", "ms-DS-Password-Settings-Container", "1.2.840.113556.1.5.256", "top"),
        c("crossRefContainer", "Cross-Ref-Container", "1.2.840.113556.1.5.7000.53", "top"),
        c("crossRef", "Cross-Ref", "1.2.840.113556.1.3.11", "top"),
        c("sitesContainer", "Sites-Container", "1.2.840.113556.1.5.107", "top"),
        c("site", "Site", "1.2.840.113556.1.5.31", "top"),
        c("serversContainer", "Servers-Container", "1.2.840.113556.1.5.7000.48", "top"),
        c("server", "Server", "1.2.840.113556.1.5.17", "top"),
        c("nTDSDSA", "NTDS-DSA", "1.2.840.113556.1.5.7000.47", "top"),
        c("nTDSSiteSettings", "NTDS-Site-Settings", "1.2.840.113556.1.5.69", "top"),
        c("subnetContainer", "Subnet-Container", "1.2.840.113556.1.5.95", "top"),
        c("nTDSService", "NTDS-Service", "1.2.840.113556.1.5.72", "top"),
        c("groupPolicyContainer", "Group-Policy-Container", "1.2.840.113556.1.5.157", "container"),
        c("ms-net-ieee-80211-GroupPolicy", "ms-net-ieee-80211-GroupPolicy", "1.2.840.113556.1.5.251", "top"),
        c("ms-net-ieee-8023-GroupPolicy", "ms-net-ieee-8023-GroupPolicy", "1.2.840.113556.1.5.252", "top"),
        c("certificationAuthority", "Certification-Authority", "2.5.6.16", "top"),
        // PK-5 (MS-ADSC; governsId from Samba's MS-AD_Schema_2K8_R2_Classes.txt).
        c("pKIEnrollmentService", "PKI-Enrollment-Service", "1.2.840.113556.1.5.178", "top"),
        c("pKICertificateTemplate", "PKI-Certificate-Template", "1.2.840.113556.1.5.177", "top"),
        c("msPKI-Enterprise-Oid", "ms-PKI-Enterprise-Oid", "1.2.840.113556.1.5.196", "top"),
        c("cRLDistributionPoint", "CRL-Distribution-Point", "2.5.6.19", "top"),
    ]

    private static let attributeIndex: [String: AttributeDefinition] =
        Dictionary(uniqueKeysWithValues: attributes.map { ($0.name.lowercased(), $0) })
    private static let classIndex: [String: ClassDefinition] =
        Dictionary(uniqueKeysWithValues: classes.map { ($0.name.lowercased(), $0) })

    public static func attribute(_ name: String) -> AttributeDefinition? { attributeIndex[name.lowercased()] }
    public static func objectClass(_ name: String) -> ClassDefinition? { classIndex[name.lowercased()] }

    /// Unknown attributes are treated as case-insensitive strings.
    public static func syntax(of name: String) -> AttributeSyntax {
        attributeIndex[name.lowercased()]?.syntax ?? .unicodeString
    }

    public static func isSingleValued(_ name: String) -> Bool { attributeIndex[name.lowercased()]?.singleValued ?? false }

    /// `objectClass` values from `top` down to `cls` (`top, person, organizationalPerson, user`).
    /// Unknown classes give `[top, cls]`.
    public static func classChain(_ cls: String) -> [String] {
        guard var def = objectClass(cls) else { return ["top", cls] }
        var chain = [def.name]
        while let sup = def.superior, let next = objectClass(sup) {
            chain.insert(next.name, at: 0)
            def = next
        }
        return chain
    }

    /// Canonical spelling of a known class (`USER` -> `user`).
    public static func canonicalClassName(_ cls: String) -> String { objectClass(cls)?.name ?? cls }

    /// Every known class whose chain contains `cls` (used to narrow `objectClass=` in SQL).
    static func subclasses(of cls: String) -> [String] {
        classes.filter { classChain($0.name).contains { $0.caseInsensitiveCompare(cls) == .orderedSame } }.map(\.name)
    }

    /// Forward link name -> back link name.
    public static let linkPairs: [String: String] = [
        "member": "memberOf", "manager": "directReports", "managedBy": "managedObjects",
        "serverReference": "serverReferenceBL",
    ]

    /// Canonical forward-link name for `name`, if it is one.
    public static func forwardLink(_ name: String) -> String? {
        linkPairs.keys.first { $0.caseInsensitiveCompare(name) == .orderedSame }
    }

    /// Canonical back-link name for `name`, if it is one.
    public static func backLink(_ name: String) -> String? {
        linkPairs.values.first { $0.caseInsensitiveCompare(name) == .orderedSame }
    }

    // MARK: - Matching keys

    /// The comparison key of a value under `syntax`: lower-cased text for strings, the
    /// normalised DN for DNs, canonical decimal for integers, `TRUE`/`FALSE` for booleans,
    /// the bytes themselves for binary syntaxes. nil when the value is invalid for the syntax.
    public static func matchKey(_ value: [UInt8], syntax: AttributeSyntax) -> [UInt8]? {
        if syntax.isBinary { return value }
        guard let s = String(validating: value, as: UTF8.self) else { return nil }
        switch syntax {
        case .integer, .largeInteger:
            guard let v = Int64(s.trimmingSpaces) else { return nil }
            return Array(String(v).utf8)
        case .boolean:
            let u = s.uppercased()
            guard u == "TRUE" || u == "FALSE" else { return nil }
            return Array(u.utf8)
        case .dn:
            if let dn = try? DN(string: s) { return Array(dn.normalized.utf8) }
            return Array(s.lowercased().utf8)
        case .generalizedTime:
            return Array(s.utf8)
        default:
            return Array(s.lowercased().utf8)
        }
    }

    /// The `value_norm` column: the match key as text, nil for binary syntaxes.
    static func storedNorm(_ value: [UInt8], name: String) -> String? {
        let syntax = syntax(of: name)
        guard !syntax.isBinary, let key = matchKey(value, syntax: syntax) else { return nil }
        return String(decoding: key, as: UTF8.self)
    }
}

extension String {
    var trimmingSpaces: String {
        var s = Substring(self)
        while s.first == " " { s = s.dropFirst() }
        while s.last == " " { s = s.dropLast() }
        return String(s)
    }
}
