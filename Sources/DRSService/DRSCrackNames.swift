import Foundation
import RPCKit
import Store
import MSPAC

/// `DS_NAME_FORMAT` (MS-DRSR §4.1.4.1.3) plus the extended values MS-DRSR §4.1.4.2.1 (`CrackNames`)
/// accepts as `formatOffered` / `formatDesired`. The numeric values of the extended formats are those
/// of Samba's `librpc/idl/drsuapi.idl` (`drsuapi_DsNameFormat`), which match `ntdsapi.h`.
public enum DSNameFormat: UInt32, Sendable, CaseIterable {
    case unknown = 0
    case fqdn1779 = 1          // distinguished name
    case nt4Account = 2        // DOMAIN\sam (DOMAIN\ = the domain itself)
    case display = 3
    case uniqueID = 6          // objectGUID, "{...}"
    case canonical = 7         // domain/ou/cn (domain/ = the domain itself)
    case userPrincipal = 8     // user@realm
    case canonicalEx = 9       // domain/ou\ncn
    case servicePrincipal = 10
    case sidOrSidHistory = 11
    case dnsDomain = 12

    // Extended formats (Samba drsuapi.idl / ntdsapi.h `DS_*`).
    case upnAndAltSecID = 0xFFFF_FFEF             // DS_USER_PRINCIPAL_NAME_AND_ALTSECID
    case nt4AccountSansDomainEx = 0xFFFF_FFF0     // DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX
    case listGlobalCatalogServers = 0xFFFF_FFF1   // DS_LIST_GLOBAL_CATALOG_SERVERS
    case upnForLogon = 0xFFFF_FFF2                // DS_USER_PRINCIPAL_NAME_FOR_LOGON
    case listServersWithDCsInSite = 0xFFFF_FFF3   // DS_LIST_SERVERS_WITH_DCS_IN_SITE
    case stringSID = 0xFFFF_FFF4                  // DS_STRING_SID_NAME
    case altSecurityIdentities = 0xFFFF_FFF5      // DS_ALT_SECURITY_IDENTITIES_NAME
    case listNCs = 0xFFFF_FFF6                    // DS_LIST_NCS
    case listDomains = 0xFFFF_FFF7                // DS_LIST_DOMAINS
    case mapSchemaGUID = 0xFFFF_FFF8              // DS_MAP_SCHEMA_GUID
    case nt4AccountSansDomain = 0xFFFF_FFF9       // DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
    case listRoles = 0xFFFF_FFFA                  // DS_LIST_ROLES
    case listInfoForServer = 0xFFFF_FFFB          // DS_LIST_INFO_FOR_SERVER
    case listServersForDomainInSite = 0xFFFF_FFFC // DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE
    case listDomainsInSite = 0xFFFF_FFFD          // DS_LIST_DOMAINS_IN_SITE
    case listServersInSite = 0xFFFF_FFFE          // DS_LIST_SERVERS_IN_SITE
    case listSites = 0xFFFF_FFFF                  // DS_LIST_SITES

    /// The short name used in the operational log (`NT4_ACCOUNT`, `LIST_SITES`, ...).
    var logName: String {
        switch self {
        case .unknown: "UNKNOWN"
        case .fqdn1779: "FQDN_1779"
        case .nt4Account: "NT4_ACCOUNT"
        case .display: "DISPLAY"
        case .uniqueID: "GUID"
        case .canonical: "CANONICAL"
        case .userPrincipal: "UPN"
        case .canonicalEx: "CANONICAL_EX"
        case .servicePrincipal: "SPN"
        case .sidOrSidHistory: "SID_OR_SID_HISTORY"
        case .dnsDomain: "DNS_DOMAIN"
        case .upnAndAltSecID: "UPN_AND_ALTSECID"
        case .nt4AccountSansDomainEx: "NT4_ACCOUNT_SANS_DOMAIN_EX"
        case .listGlobalCatalogServers: "LIST_GLOBAL_CATALOG_SERVERS"
        case .upnForLogon: "UPN_FOR_LOGON"
        case .listServersWithDCsInSite: "LIST_SERVERS_WITH_DCS_IN_SITE"
        case .stringSID: "STRING_SID"
        case .altSecurityIdentities: "ALT_SECURITY_IDENTITIES"
        case .listNCs: "LIST_NCS"
        case .listDomains: "LIST_DOMAINS"
        case .mapSchemaGUID: "MAP_SCHEMA_GUID"
        case .nt4AccountSansDomain: "NT4_ACCOUNT_SANS_DOMAIN"
        case .listRoles: "LIST_ROLES"
        case .listInfoForServer: "LIST_INFO_FOR_SERVER"
        case .listServersForDomainInSite: "LIST_SERVERS_FOR_DOMAIN_IN_SITE"
        case .listDomainsInSite: "LIST_DOMAINS_IN_SITE"
        case .listServersInSite: "LIST_SERVERS_IN_SITE"
        case .listSites: "LIST_SITES"
        }
    }

    /// `1(FQDN_1779)`, `0xFFFFFFF0(NT4_ACCOUNT_SANS_DOMAIN_EX)`, `0x0000000D` for an unknown value.
    static func describe(_ raw: UInt32) -> String {
        let number = raw > 0xFF ? String(format: "0x%08X", raw) : String(raw)
        guard let f = DSNameFormat(rawValue: raw) else { return number + "(?)" }
        return "\(number)(\(f.logName))"
    }
}

/// `DS_NAME_ERROR` (MS-DRSR §4.1.4.1.x `DS_NAME_ERROR`, the `status` of a `DS_NAME_RESULT_ITEMW`).
enum DSNameError: UInt32 {
    case ok = 0, resolving = 1, notFound = 2, notUnique = 3, noMapping = 4, domainOnly = 5,
         noSyntacticalMapping = 6, trustReferral = 7
    // "Private" statuses for DS_STRING_SID_NAME and DS_MAP_SCHEMA_GUID.
    case isSidHistoryUnknown = 0xFFFF_FFF2, isSidHistoryAlias = 0xFFFF_FFF3,
         isSidHistoryGroup = 0xFFFF_FFF4, isSidHistoryUser = 0xFFFF_FFF5
    case isSidUnknown = 0xFFFF_FFF6, isSidAlias = 0xFFFF_FFF7, isSidGroup = 0xFFFF_FFF8,
         isSidUser = 0xFFFF_FFF9
    case schemaGuidControlRight = 0xFFFF_FFFA, schemaGuidClass = 0xFFFF_FFFB,
         schemaGuidAttrSet = 0xFFFF_FFFC, schemaGuidAttr = 0xFFFF_FFFD,
         schemaGuidNotFound = 0xFFFF_FFFE, isFPO = 0xFFFF_FFFF

    /// The log spelling: `OK`, `notFound`, `IS_SID_USER`, or hex.
    static func describe(_ raw: UInt32) -> String {
        switch DSNameError(rawValue: raw) {
        case .ok: "OK"
        case .resolving: "resolving"
        case .notFound: "notFound"
        case .notUnique: "notUnique"
        case .noMapping: "noMapping"
        case .domainOnly: "domainOnly"
        case .noSyntacticalMapping: "noSyntacticalMapping"
        case .trustReferral: "trustReferral"
        case .isSidUser: "IS_SID_USER"
        case .isSidGroup: "IS_SID_GROUP"
        case .isSidAlias: "IS_SID_ALIAS"
        case .isSidUnknown: "IS_SID_UNKNOWN"
        case .schemaGuidNotFound: "SCHEMA_GUID_NOT_FOUND"
        default: String(format: "0x%08X", raw)
        }
    }
}

/// One `DS_NAME_RESULT_ITEMW`.
struct CrackItem: Equatable {
    var status: UInt32
    var domain: String?
    var name: String?

    init(_ status: DSNameError, domain: String? = nil, name: String? = nil) {
        self.status = status.rawValue
        self.domain = domain
        self.name = name
    }

    init(status: UInt32, domain: String?, name: String?) {
        self.status = status
        self.domain = domain
        self.name = name
    }
}

/// The outcome of looking up one offered name.
private enum Lookup {
    case found(DirectoryEntry)
    case failed(DSNameError)
}

/// `userAccountControl` ADS_UF_TEMP_DUPLICATE_ACCOUNT (MS-ADTS §2.2.16), not in `UserAccountControl`.
private let adsUFTempDuplicateAccount: UInt32 = 0x100

extension DRSService {
    // MARK: IDL_DRSCrackNames (opnum 12)

    func dsCrackNames(_ r: NDRReader, _ context: RPCCallContext) async throws -> NDRWriter {
        // ([in] DRS_HANDLE hDrs, [in] DWORD dwInVersion, [in] DRS_MSG_CRACKREQ* pmsgIn,
        //  [out] DWORD* pdwOutVersion, [out] DRS_MSG_CRACKREPLY* pmsgOut)
        _ = try r.contextHandle()
        _ = try r.u32()                       // dwInVersion
        _ = try r.u32()                       // union tag (V1)
        _ = try r.u32()                       // CodePage
        _ = try r.u32()                       // LocaleId
        let flags = try r.u32()               // dwFlags
        let offeredRaw = try r.u32()
        let desiredRaw = try r.u32()
        let cNames = Int(try r.u32())
        var names = [String]()
        if try r.pointer() != nil {           // rpNames: PLPWSTR_ARRAY
            let arrayCount = Int(try r.u32())
            var present = [Bool]()
            for _ in 0..<arrayCount { present.append(try r.pointer() != nil) }
            for p in present {
                if p { r.align(4); names.append(try r.varyingWCharBody(stripNUL: true)) }
            }
        }
        _ = cNames
        names = names.map { $0.hasSuffix("\0") ? String($0.dropLast()) : $0 }

        let info = try await store.domainInfo()
        // nil = "unsupported operation": Samba's dcesrv_drsuapi_DsCrackNames answers WERR_OK with
        // an empty (NULL) ctr1 for the extended formats it does not implement.
        let results: [CrackItem]?
        switch DSNameFormat(rawValue: offeredRaw) {
        case .listSites: results = try await listSites(info)
        case .listServersInSite: results = try await listServersInSite(names, info)
        case .listDomains: results = try await listNCs(info, domainsOnly: true)
        case .listNCs: results = try await listNCs(info, domainsOnly: false)
        case .listDomainsInSite: results = try await listDomainsInSite(names, info)
        case .listServersForDomainInSite: results = try await listServersForDomainInSite(names, info)
        case .listServersWithDCsInSite: results = try await listServersWithDCsInSite(names, info)
        case .listInfoForServer: results = try await listInfoForServer(names, info)
        case .listRoles: results = try await listRoles(info)
        case .listGlobalCatalogServers: results = try await listGlobalCatalogServers(info)
        case .mapSchemaGUID:
            // MS-DRSR CrackNames: every name starts as SCHEMA_GUID_NOT_FOUND; our schema objects do
            // not carry schemaIDGUID / rightsGuid, so none is ever mapped.
            results = names.map { _ in CrackItem(.schemaGuidNotFound) }
        case .upnForLogon:
            // Output-only format; as an input it is not a "regular name lookup" in MS-DRSR and
            // Samba answers it as unsupported.
            results = nil
        default:
            var items = [CrackItem]()
            for name in names {
                items.append(try await crack(name, offeredRaw: offeredRaw, desiredRaw: desiredRaw, info: info))
            }
            results = items
        }

        logCrackNames(offeredRaw: offeredRaw, desiredRaw: desiredRaw, flags: flags, names: names,
                      results: results, context: context)

        let w = NDRWriter()
        w.u32(1)                              // pdwOutVersion = 1
        w.u32(1)                              // pmsgOut tag = V1
        if let results {
            _ = w.uniquePointer(true)         // pResult
            w.deferPointee {
                w.u32(UInt32(results.count))  // DS_NAME_RESULTW.cItems
                _ = w.uniquePointer(true)     // rItems
                w.deferPointee {
                    w.u32(UInt32(results.count))  // conformant array max_count
                    for item in results {
                        w.u32(item.status)
                        Self.drsStringPointer(w, item.domain)
                        Self.drsStringPointer(w, item.name)
                    }
                }
            }
            w.flushDeferred()
            w.align(4)                        // 4-align the trailing DWORD after the WCHAR arrays
        } else {
            _ = w.uniquePointer(false)        // pResult = NULL
        }
        w.u32(0)                              // ErrorCode = 0
        return w
    }

    // MARK: Regular name lookup (MS-DRSR §4.1.4.2.10 LookupName)

    /// Resolves one name in `offered` format to an object and formats it as `desired`.
    func crack(_ name: String, offeredRaw: UInt32, desiredRaw: UInt32, info: DomainInfo) async throws -> CrackItem {
        let offered = DSNameFormat(rawValue: offeredRaw)
        let desired = DSNameFormat(rawValue: desiredRaw)
        // DNS domain name is a whole-domain query, answered without an object (WP-AG behaviour).
        if desired == .dnsDomain {
            return CrackItem(.ok, domain: info.dnsDomain, name: info.dnsDomain)
        }
        let entry: DirectoryEntry
        switch try await lookup(name, offered: offered, info: info) {
        case .failed(let status): return CrackItem(status, domain: info.dnsDomain)
        case .found(let e): entry = e
        }
        guard let desired, desired.isOutputFormat else {
            // MS-DRSR LookupName: a desired format outside the output set is DS_NAME_ERROR_RESOLVING;
            // unknown values in the base range keep WP-AG's NO_MAPPING.
            return CrackItem(desiredRaw >= DSNameFormat.upnAndAltSecID.rawValue ? .resolving : .noMapping,
                             domain: info.dnsDomain)
        }
        guard let formatted = format(entry, desired: desired, info: info) else {
            return CrackItem(.noMapping, domain: info.dnsDomain)
        }
        let status: DSNameError = offered == .stringSID ? Self.sidTypeStatus(entry) : .ok
        return CrackItem(status, domain: info.dnsDomain, name: formatted)
    }

    /// Maps an offered name to a directory entry.
    private func lookup(_ name: String, offered: DSNameFormat?, info: DomainInfo) async throws -> Lookup {
        guard let offered else { return .failed(.notFound) }   // Samba: default -> NOT_FOUND
        switch offered {
        case .unknown:
            // MS-DRSR LookupUnknownName / Samba cracknames.c DsCrackNameOneName (UNKNOWN): try the
            // formats in Samba's order and keep the first one that finds the object.
            for f in [DSNameFormat.fqdn1779, .userPrincipal, .nt4Account, .canonical, .uniqueID,
                      .display, .servicePrincipal, .sidOrSidHistory, .canonicalEx] {
                if case .found(let e) = try await lookup(name, offered: f, info: info) { return .found(e) }
            }
            return .failed(.notFound)
        case .nt4Account:
            // DOMAIN\sam or just sam. "DOMAIN\" (nothing after the backslash) is the domain itself
            // (MS-DRSR DS_NT4_ACCOUNT_NAME: "the domain-only name is in the format domain\"; Samba
            // cracknames.c: no account -> only the crossRef domain_filter -> the NC head).
            if let slash = name.firstIndex(of: "\\") {
                let domain = String(name[..<slash])
                let account = String(name[name.index(after: slash)...])
                if account.isEmpty {
                    guard Self.isOurDomain(domain, info) else { return .failed(.notFound) }
                    return try await entryOrNotFound(store.read(dn: info.domainDN))
                }
                return try await entryOrNotFound(store.read(sam: account))
            }
            return try await entryOrNotFound(store.read(sam: name))
        case .userPrincipal:
            // user@realm: try UPN, then the local part as sAMAccountName.
            if let e = try await firstBy(attribute: "userPrincipalName", equals: name, info: info) { return .found(e) }
            let local = String(name.split(separator: "@").first ?? "")
            return try await entryOrNotFound(store.read(sam: local))
        case .servicePrincipal:
            return entryOrNotFound(try await firstBy(attribute: "servicePrincipalName", equals: name, info: info))
        case .fqdn1779:
            guard let dn = try? DN(string: name) else { return .failed(.notFound) }
            return try await entryOrNotFound(store.read(dn: dn))
        case .sidOrSidHistory, .stringSID:
            guard let sid = try? SID(string: name) else { return .failed(.notFound) }
            return try await entryOrNotFound(store.read(sid: sid))
        case .uniqueID:
            let hex = name.trimmingCharacters(in: CharacterSet(charactersIn: "{}"))
            guard let guid = GUID(string: hex) else { return .failed(.notFound) }
            return try await entryOrNotFound(store.read(guid: guid))
        case .canonical:
            return try await resolveCanonical(name, info: info)
        case .canonicalEx:
            // Samba: replace the last '\n' with '/', then as DS_CANONICAL_NAME.
            guard let nl = name.lastIndex(of: "\n") else { return .failed(.resolving) }
            var canonical = name
            canonical.replaceSubrange(nl...nl, with: "/")
            return try await resolveCanonical(canonical, info: info)
        case .display:
            if let e = try await firstBy(attribute: "displayName", equals: name, info: info) { return .found(e) }
            return try await entryOrNotFound(store.read(sam: name))
        case .nt4AccountSansDomain, .nt4AccountSansDomainEx:
            // MS-DRSR LookupName: rt := LookupAttr(flags, sAMAccountName, name) — the name exactly
            // as given (no "$" is appended). Samba does not implement these formats.
            let hit = try await lookupAttr("sAMAccountName", name, info: info)
            if offered == .nt4AccountSansDomainEx, case .found(let e) = hit {
                // "Check that the account is valid": disabled / temp-duplicate -> NOT_FOUND.
                let uac = UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0)
                if uac & (UserAccountControl.accountDisable | adsUFTempDuplicateAccount) != 0 {
                    return .failed(.notFound)
                }
            }
            return hit
        case .altSecurityIdentities:
            return try await lookupAttr("altSecurityIdentities", name, info: info)
        case .upnAndAltSecID:
            // MS-DRSR LookupUPNAndAltSecID(IncludingAltSecID = true): UPN + altSecurityIdentities,
            // then sAMAccountName = the part before '@'.
            let hits = try await entries(attribute: "userPrincipalName", equals: name, info: info)
                + entries(attribute: "altSecurityIdentities", equals: name, info: info)
            if hits.count == 1 { return .found(hits[0]) }
            if hits.count > 1 { return .failed(.notUnique) }
            guard let at = name.lastIndex(of: "@"), at != name.startIndex else { return .failed(.notFound) }
            return try await lookupAttr("sAMAccountName", String(name[..<at]), info: info)
        default:
            return .failed(.notFound)
        }
    }

    private func entryOrNotFound(_ e: DirectoryEntry?) -> Lookup {
        e.map { .found($0) } ?? .failed(.notFound)
    }

    /// MS-DRSR §4.1.4.2.11 LookupAttr over the default NC: none -> NOT_FOUND, several -> NOT_UNIQUE.
    private func lookupAttr(_ attribute: String, _ value: String, info: DomainInfo) async throws -> Lookup {
        guard !value.isEmpty else { return .failed(.notFound) }
        let hits = try await entries(attribute: attribute, equals: value, info: info)
        switch hits.count {
        case 0: return .failed(.notFound)
        case 1: return .found(hits[0])
        default: return .failed(.notUnique)
        }
    }

    private func entries(attribute: String, equals value: String, info: DomainInfo) async throws -> [DirectoryEntry] {
        try await store.search(base: info.domainDN, scope: .subtree,
                               filter: .equality(attribute: attribute, value: Array(value.utf8)), attrs: nil)
    }

    private func firstBy(attribute: String, equals value: String, info: DomainInfo) async throws -> DirectoryEntry? {
        try await entries(attribute: attribute, equals: value, info: info).first
    }

    /// DS_CANONICAL_NAME -> object, as Samba cracknames.c does it: the text before the first '/'
    /// must be our DNS domain (crossRef dnsRoot) and there must be at least one '/' (else
    /// RESOLVE_ERROR); nothing after it ("lab.sheep/") is the domain NC head itself; otherwise each
    /// '/'-separated component is matched by RDN value one level down from the previous object
    /// (get_format_functional_filtering_param: onelevel "name=<component>").
    private func resolveCanonical(_ canonical: String, info: DomainInfo) async throws -> Lookup {
        guard !canonical.isEmpty else { return .failed(.resolving) }
        guard let slash = canonical.firstIndex(of: "/") else { return .failed(.resolving) }
        let domain = String(canonical[..<slash])
        guard domain.caseInsensitiveCompare(info.dnsDomain) == .orderedSame else { return .failed(.notFound) }
        let rest = String(canonical[canonical.index(after: slash)...])
        guard let head = try await store.read(dn: info.domainDN) else { return .failed(.notFound) }
        if rest.isEmpty { return .found(head) }

        let components = rest.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var current = head
        var walked = true
        for component in components {
            let matches = try await store.children(of: current.id).filter {
                $0.dn.rdn?.value.caseInsensitiveCompare(component) == .orderedSame
            }
            if matches.count > 1 { return .failed(.notUnique) }
            guard let next = matches.first else { walked = false; break }
            current = next
        }
        if walked { return .found(current) }

        // WP-AG fallback, kept so earlier answers do not change: the leaf as a sAMAccountName, then
        // the path as CN= containers.
        guard let leaf = components.last, !leaf.isEmpty else { return .failed(.notFound) }
        if let e = try await store.read(sam: leaf) { return .found(e) }
        var rdns = components.reversed().map { RDN("CN", $0) }
        rdns += info.domainDN.rdns
        return try await entryOrNotFound(store.read(dn: DN(rdns: rdns)))
    }

    /// MS-DRSR LookupName for DS_STRING_SID_NAME: the object type goes in the status.
    static func sidTypeStatus(_ e: DirectoryEntry) -> DSNameError {
        let t = UInt32(truncatingIfNeeded: e.int("sAMAccountType") ?? 0)
        switch t {
        case SAMAccountType.userObject, SAMAccountType.machineAccount, SAMAccountType.trustAccount: return .isSidUser
        case SAMAccountType.groupObject, SAMAccountType.nonSecurityGroupObject: return .isSidGroup
        case SAMAccountType.aliasObject, SAMAccountType.nonSecurityAliasObject: return .isSidAlias
        default: return .isSidUnknown
        }
    }

    static func isOurDomain(_ domain: String, _ info: DomainInfo) -> Bool {
        domain.caseInsensitiveCompare(info.netbiosDomain) == .orderedSame
            || domain.caseInsensitiveCompare(info.dnsDomain) == .orderedSame
    }

    // MARK: Output (MS-DRSR §4.1.4.2.24 ConstructOutput)

    /// Formats an entry in the desired format. Returns nil when the object has no such name.
    private func format(_ e: DirectoryEntry, desired: DSNameFormat, info: DomainInfo) -> String? {
        let isDomainHead = e.dn == info.domainDN
        switch desired {
        case .fqdn1779: return e.dn.description
        case .nt4Account:
            // Samba cracknames.c: a domain object -> "<nETBIOSName>\" (ConstructOutput IsDomainOnly);
            // a BUILTIN SID -> "BUILTIN\<sam>"; otherwise "<NETBIOS>\<sam>".
            if isDomainHead { return "\(info.netbiosDomain)\\" }
            guard let sam = e.samAccountName else { return nil }
            if let sid = e.sid, sid.identifierAuthority == 5, sid.subAuthorities.first == 32 {
                return "BUILTIN\\\(sam)"
            }
            return "\(info.netbiosDomain)\\\(sam)"
        case .userPrincipal:
            return e.string("userPrincipalName") ?? e.samAccountName.map { "\($0)@\(info.dnsDomain)" }
        case .upnForLogon:
            return e.string("userPrincipalName") ?? e.samAccountName.map { "\($0)@\(info.dnsDomain)" }
        case .display: return e.string("displayName") ?? e.samAccountName
        case .canonical: return canonicalName(e.dn, info: info)
        case .canonicalEx:
            // DS_CANONICAL_NAME_EX: the rightmost '/' becomes '\n' (MS-DRSR §4.1.4.1.3).
            var s = canonicalName(e.dn, info: info)
            if let slash = s.lastIndex(of: "/") { s.replaceSubrange(slash...slash, with: "\n") }
            return s
        case .sidOrSidHistory, .stringSID: return e.sid?.description
        case .uniqueID: return "{\(e.guid.description)}"
        case .servicePrincipal: return e.strings("servicePrincipalName").first
        case .dnsDomain: return info.dnsDomain
        default: return nil
        }
    }

    /// Canonical name: `dnsDomain/` then the non-DC RDNs, root-most first, joined by `/`; the
    /// domain NC head itself is `dnsDomain/` (ldb_dn_canonical_string, AD `canonicalName`).
    func canonicalName(_ dn: DN, info: DomainInfo) -> String {
        let path = dn.rdns.filter { $0.type.caseInsensitiveCompare("DC") != .orderedSame }
            .reversed().map(\.value)
        if path.isEmpty { return info.dnsDomain + "/" }
        return ([info.dnsDomain] + path).joined(separator: "/")
    }

    /// A `[string,unique] wchar_t*` with the 4-byte alignment DRSUAPI's LPWSTR arrays use before the
    /// conformant size prefix (impacket aligns each conformant array to 4).
    static func drsStringPointer(_ w: NDRWriter, _ s: String?) {
        guard let s else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.deferPointee { w.align(4); w.varyingWCharBody(s, includeNUL: true) }
    }
}

extension DSNameFormat {
    /// The desired formats ConstructOutput can produce (MS-DRSR LookupName's output set, plus the
    /// base formats WP-AG already answered).
    var isOutputFormat: Bool {
        switch self {
        case .fqdn1779, .nt4Account, .display, .uniqueID, .canonical, .canonicalEx, .userPrincipal,
             .servicePrincipal, .sidOrSidHistory, .dnsDomain, .stringSID, .upnForLogon:
            return true
        default:
            return false
        }
    }
}
