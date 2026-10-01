import AuthKit
import Foundation
import LDAPCore
import MSPAC
import NIOCore
import Store

extension LDAPConnection {
    // MARK: RootDSE (MS-ADTS §3.1.1.3.2)

    static let supportedCapabilities = [
        "1.2.840.113556.1.4.800",   // LDAP_CAP_ACTIVE_DIRECTORY_OID
        "1.2.840.113556.1.4.1670",  // LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
        "1.2.840.113556.1.4.1791",  // LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
        "1.2.840.113556.1.4.1935",  // LDAP_CAP_ACTIVE_DIRECTORY_V61_OID
        "1.2.840.113556.1.4.2080",  // LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID
        "1.2.840.113556.1.4.2237",  // LDAP_CAP_ACTIVE_DIRECTORY_W8_OID
    ]

    static let supportedControls = [
        LDAPControlOID.pagedResults, LDAPControlOID.sdFlags, LDAPControlOID.showDeleted, LDAPControlOID.showRecycled,
        LDAPControlOID.treeDelete, LDAPControlOID.permissiveModify, LDAPControlOID.domainScope, LDAPControlOID.lazyCommit,
    ]

    static let supportedExtensions = [LDAPExtendedOID.startTLS, LDAPExtendedOID.whoAmI, LDAPExtendedOID.passwordModify]

    static let supportedLDAPPolicies = [
        "MaxPoolThreads", "MaxPercentDirSyncRequests", "MaxDatagramRecv", "MaxReceiveBuffer", "InitRecvTimeout",
        "MaxConnections", "MaxConnIdleTime", "MaxPageSize", "MaxBatchReturnMessages", "MaxQueryDuration",
        "MaxDirSyncDuration", "MaxTempTableSize", "MaxResultSetSize", "MinResultSets", "MaxResultSetsPerConn",
        "MaxNotificationPerConn", "MaxValRange", "MaxValRangeTransitive", "ThreadMemoryLimit", "SystemMemoryLimitPercent",
    ]

    /// The RootDSE attributes, in the order AD lists them.
    func rootDSEAttributes() async throws -> [LDAPAttribute] {
        try await Self.rootDSEAttributes(store: store, info: info, now: config.clock(), vendorVersion: config.vendorVersion)
    }

    /// The RootDSE attributes, in the order AD lists them (shared with the CLDAP responder).
    static func rootDSEAttributes(store: DirectoryStore, info i: DomainInfo, now: Date,
                                  vendorVersion: String) async throws -> [LDAPAttribute] {
        let usn = try await store.highestCommittedUSN()
        func a(_ name: String, _ values: [String]) -> LDAPAttribute { LDAPAttribute(name, strings: values) }
        return [
            a("configurationNamingContext", [i.configurationDN.description]),
            a("currentTime", [GeneralizedTime.string(now)]),
            a("defaultNamingContext", [i.domainDN.description]),
            a("dnsHostName", [i.dcDNSName]),
            a("domainControllerFunctionality", ["7"]),
            a("domainFunctionality", ["7"]),
            a("dsServiceName", [i.dsServiceDN.description]),
            a("forestFunctionality", ["7"]),
            a("highestCommittedUSN", [String(usn)]),
            a("isGlobalCatalogReady", ["TRUE"]),
            a("isSynchronized", ["TRUE"]),
            a("ldapServiceName", ["\(i.dnsDomain.lowercased()):\(i.dcName.lowercased())$@\(i.realm)"]),
            a("namingContexts", [i.domainDN.description, i.configurationDN.description, i.schemaDN.description]),
            a("rootDomainNamingContext", [i.domainDN.description]),
            a("schemaNamingContext", [i.schemaDN.description]),
            a("serverName", [i.serverDN.description]),
            a("subschemaSubentry", [i.subschemaDN.description]),
            a("supportedCapabilities", Self.supportedCapabilities),
            a("supportedControl", Self.supportedControls),
            a("supportedExtension", Self.supportedExtensions),
            a("supportedLDAPPolicies", Self.supportedLDAPPolicies),
            a("supportedLDAPVersion", ["3", "2"]),
            a("supportedSASLMechanisms", Self.saslMechanisms),
            a("vendorName", ["Sheep"]),
            a("vendorVersion", [vendorVersion]),
        ]
    }

    // MARK: Search

    func search(_ message: LDAPMessage, _ request: SearchRequest) async throws {
        let id = message.messageID
        let selection = AttributeSelection(request.attributes)

        // LDAP ping over TCP (MS-ADTS §6.3.3): the same answer as over CLDAP.
        if request.baseObject.isEmpty, request.scope == .base,
           request.attributes.contains(where: { $0.caseInsensitiveCompare("Netlogon") == .orderedSame }) {
            let responder = NetlogonResponder(store: store, info: info, flags: config.netlogonFlags)
            let ip = NetlogonAddress.select(configured: config.advertisedIPv4, arrivedOn: channel.localAddress?.ipAddress)
            let entry = await responder.entry(for: request.filter, serverIPv4: ip)
            send(LDAPMessage(messageID: id, .searchResultEntry(entry)), flush: false)
            send(LDAPMessage(messageID: id, .searchResultDone(.success)))
            return
        }

        // RootDSE: readable by anyone, whatever the filter.
        if request.baseObject.isEmpty, request.scope == .base {
            var attrs = try await rootDSEAttributes()
            if !selection.allUser, !selection.allOperational {
                attrs = attrs.filter { selection.wants($0.type) }
            }
            if request.typesOnly { attrs = attrs.map { LDAPAttribute(type: $0.type, values: []) } }
            send(LDAPMessage(messageID: id, .searchResultEntry(SearchResultEntry(objectName: "", attributes: attrs))), flush: false)
            send(LDAPMessage(messageID: id, .searchResultDone(.success)))
            return
        }
        _ = try requireBound()

        let includeDeleted = message.control(LDAPControlOID.showDeleted) != nil || message.control(LDAPControlOID.showRecycled) != nil
        var sdFlags: UInt32?
        if let c = message.control(LDAPControlOID.sdFlags), let v = c.value {
            sdFlags = (try? SDFlagsValue(controlValue: v).flags) ?? nil
            if sdFlags == nil, c.critical { throw LDAPFailure(.protocolError, ADDiagnostic.criticalControl) }
        }
        // The store narrows equality on sAMAccountName/UPN through columns that tombstones
        // no longer fill; a double negation keeps the filter's meaning (three-valued logic)
        // but makes the store evaluate it on every candidate, so tombstones match.
        var request = request
        if includeDeleted { request.filter = .not(.not(request.filter)) }
        let render = RenderOptions(selection: selection, typesOnly: request.typesOnly, sdFlags: sdFlags,
                                   maxValRange: config.maxValRange)

        // Base "" with a subtree/one-level scope: every naming context (AD's GC behaviour).
        let bases: [DN]
        if request.baseObject.isEmpty {
            bases = [info.domainDN, info.configurationDN, info.schemaDN]
        } else {
            let base = try await resolveBaseDN(request.baseObject)
            guard try await store.read(dn: base, includeDeleted: includeDeleted) != nil else { throw await noSuchObject(base) }
            bases = [base]
        }
        let scope = request.baseObject.isEmpty && request.scope == .oneLevel ? SearchScope.base : request.scope

        if let pagedControl = message.control(LDAPControlOID.pagedResults), bases.count == 1 {
            let paged: PagedResultsValue
            do { paged = try PagedResultsValue(controlValue: pagedControl.value ?? []) } catch {
                throw LDAPFailure(.protocolError, ADDiagnostic.criticalControl)
            }
            try await pagedSearch(id: id, base: bases[0], scope: scope, request: request, paged: paged,
                                  includeDeleted: includeDeleted, render: render)
            return
        }

        let serverLimit = config.maxPageSize
        let limit = request.sizeLimit > 0 ? min(Int(request.sizeLimit), serverLimit) : serverLimit
        var sent = 0
        var exceeded = false
        for base in bases {
            let remaining = limit - sent
            let entries = try await store.search(base: base, scope: scope, filter: request.filter, includeDeleted: includeDeleted,
                                                 sizeLimit: remaining + 1)
            for e in entries.prefix(remaining) {
                send(LDAPMessage(messageID: id, .searchResultEntry(try await self.render(e, render))), flush: false)
            }
            sent += min(entries.count, remaining)
            if entries.count > remaining {
                exceeded = true
                break
            }
        }
        let done: LDAPResult = exceeded
            ? LDAPResult(.sizeLimitExceeded, diagnosticMessage: request.sizeLimit > 0 && Int(request.sizeLimit) <= serverLimit
                ? "" : "0000212A: LdapErr: DSID-0C0909E1, comment: size limit (MaxPageSize \(serverLimit)) exceeded, data 0, \(ADDiagnostic.version)")
            : .success
        send(LDAPMessage(messageID: id, .searchResultDone(done)))
    }

    /// RFC 2696 paging: the cookie names the last object id sent for this exact search.
    private func pagedSearch(id: Int32, base: DN, scope: SearchScope, request: SearchRequest, paged: PagedResultsValue,
                             includeDeleted: Bool, render: RenderOptions) async throws {
        let key = "\(base.normalized)|\(scope.rawValue)|\(request.filter.ldapString)|\(includeDeleted)"
        var after: ObjectID?
        if !paged.cookie.isEmpty {
            guard let state = pagedSearches.removeValue(forKey: paged.cookie), state.key == key else {
                throw LDAPFailure(.unwillingToPerform, "00002024: LdapErr: DSID-0C090AFF, comment: invalid paged results cookie, data 0, \(ADDiagnostic.version)")
            }
            after = state.lastID
        }
        func done(cookie: [UInt8]) {
            send(LDAPMessage(messageID: id, .searchResultDone(.success),
                             controls: [PagedResultsValue(size: 0, cookie: cookie).control()]))
        }
        // Size 0 abandons the paged search (RFC 2696 §3).
        guard paged.size > 0 else { return done(cookie: []) }
        let pageSize = min(Int(paged.size), config.maxPageSize)
        let entries = try await store.search(base: base, scope: scope, filter: request.filter, includeDeleted: includeDeleted,
                                             sizeLimit: pageSize + 1, after: after)
        let page = entries.prefix(pageSize)
        for e in page {
            send(LDAPMessage(messageID: id, .searchResultEntry(try await self.render(e, render))), flush: false)
        }
        if entries.count > pageSize, let last = page.last {
            var cookie = [UInt8](repeating: 0, count: 12)
            for i in cookie.indices { cookie[i] = UInt8.random(in: 0...255) }
            pagedSearches[cookie] = PagedSearch(key: key, lastID: last.id)
            if pagedSearches.count > 64, let stale = pagedSearches.keys.first(where: { $0 != cookie }) {
                pagedSearches.removeValue(forKey: stale)
            }
            done(cookie: cookie)
        } else {
            done(cookie: [])
        }
    }

    // MARK: Extended DN forms (MS-ADTS §3.1.1.3.1.2.4)

    /// A search base, accepting AD's `<WKGUID=guid,dn>`, `<GUID=guid>` and `<SID=sid>` forms besides a
    /// plain DN. WP-Z: Samba's `net ads join` finds the Computers container with
    /// `<WKGUID=AA312825768811D1ADED00C04FD8D5CD,dc=…>` (`ads_default_ou_string`).
    func resolveBaseDN(_ text: String) async throws -> DN {
        guard text.hasPrefix("<"), let close = text.firstIndex(of: ">") else { return try parseDN(text) }
        let inner = String(text[text.index(after: text.startIndex)..<close])
        guard let eq = inner.firstIndex(of: "=") else { return try parseDN(text) }
        let kind = inner[..<eq].uppercased()
        let value = String(inner[inner.index(after: eq)...])
        let invalid = LDAPFailure(.invalidDNSyntax, ADDiagnostic.invalidDN(text))
        switch kind {
        case "WKGUID":
            guard let comma = value.firstIndex(of: ",") else { throw invalid }
            let guid = value[..<comma].uppercased()
            let container = try parseDN(String(value[value.index(after: comma)...]))
            let entry = try await requireEntry(container)
            for v in entry.strings("wellKnownObjects") {
                // DN-Binary: B:32:<hex GUID>:<DN>
                let parts = v.split(separator: ":", maxSplits: 3).map(String.init)
                if parts.count == 4, parts[2].uppercased() == guid { return try parseDN(parts[3]) }
            }
            throw await noSuchObject(container)
        case "GUID":
            let g = value.count == 32 && !value.contains("-") ? Self.dashedGUID(fromHex: value) : value
            guard let guid = GUID(string: g) else { throw invalid }
            guard let e = try await store.read(guid: guid) else { throw LDAPFailure(.noSuchObject, ADDiagnostic.noSuchObject(bestMatch: "")) }
            return e.dn
        case "SID":
            guard let sid = (try? SID(string: value)) ?? Self.hexBytes(value).flatMap({ try? SID(bytes: $0) }) else { throw invalid }
            guard let e = try await store.read(sid: sid) else { throw LDAPFailure(.noSuchObject, ADDiagnostic.noSuchObject(bestMatch: "")) }
            return e.dn
        default:
            return try parseDN(text)
        }
    }

    /// `<GUID=hex32>` is the objectGUID's bytes in wire order: the first three fields are little-endian.
    static func dashedGUID(fromHex h: String) -> String {
        guard let b = hexBytes(h), b.count == 16 else { return h }
        func x(_ r: [UInt8]) -> String { r.map { String(format: "%02x", $0) }.joined() }
        return "\(x(b[0..<4].reversed()))-\(x(b[4..<6].reversed()))-\(x(b[6..<8].reversed()))-\(x(Array(b[8..<10])))-\(x(Array(b[10..<16])))"
    }

    static func hexBytes(_ h: String) -> [UInt8]? {
        let c = Array(h.utf8)
        guard c.count % 2 == 0, !c.isEmpty else { return nil }
        var out = [UInt8]()
        for i in stride(from: 0, to: c.count, by: 2) {
            guard let b = UInt8(String(decoding: c[i...i + 1], as: UTF8.self), radix: 16) else { return nil }
            out.append(b)
        }
        return out
    }

    // MARK: Compare

    func compare(_ message: LDAPMessage, _ request: CompareRequest) async throws {
        _ = try requireBound()
        let dn = try parseDN(request.entry)
        let entry = try await requireEntry(dn)
        let name = AttributeSelection.baseName(request.attribute)
        guard entry.has(name) else { throw LDAPFailure(.noSuchAttribute, ADDiagnostic.noSuchAttribute) }
        let match = FilterAST.equality(attribute: name, value: request.assertionValue).matches(entry, schemaDN: info.schemaDN)
        send(LDAPMessage(messageID: message.messageID, .compareResponse(LDAPResult(match ? .compareTrue : .compareFalse))))
    }

    // MARK: Rendering entries

    struct RenderOptions {
        var selection: AttributeSelection
        var typesOnly: Bool
        var sdFlags: UInt32?
        var maxValRange: Int
    }

    /// Attributes never returned (secrets and write-only attributes).
    static let hiddenAttributes: Set<String> = [
        "unicodepwd", "userpassword", "dbcspwd", "ntpwdhistory", "lmpwdhistory", "supplementalcredentials",
    ]

    func render(_ entry: DirectoryEntry, _ options: RenderOptions) async throws -> SearchResultEntry {
        let sel = options.selection
        var attrs: [LDAPAttribute] = []
        if !sel.none {
            var source = entry.attributes.filter { !Self.hiddenAttributes.contains($0.name.lowercased()) }
            if !sel.allUser { source = source.filter { sel.wants($0.name) } }
            // Constructed attributes, returned only when asked for by name (or `+`).
            for name in AttributeSelection.constructed where sel.wantsConstructed(name) {
                if let a = try await constructed(name, entry) { source.append(a) }
            }
            for a in source {
                var values = a.values
                if a.name.caseInsensitiveCompare("nTSecurityDescriptor") == .orderedSame, let flags = options.sdFlags {
                    values = values.map { Self.maskSecurityDescriptor($0, flags: flags) }
                }
                let range = sel.range(for: a.name)
                if range != nil || values.count > options.maxValRange {
                    let (slice, label) = Self.rangeSlice(values, range: range ?? (0, nil), maxValRange: options.maxValRange)
                    attrs.append(LDAPAttribute(type: "\(a.name);range=\(label)", values: options.typesOnly ? [] : slice))
                } else {
                    attrs.append(LDAPAttribute(type: a.name, values: options.typesOnly ? [] : values))
                }
            }
        }
        return SearchResultEntry(objectName: entry.dn.description, attributes: attrs)
    }

    /// Values `low…high` (AD `MaxValRange` caps a page), labelled `low-high` or `low-*` for the last.
    static func rangeSlice(_ values: [[UInt8]], range: (low: Int, high: Int?), maxValRange: Int) -> ([[UInt8]], String) {
        let low = range.low
        guard low < values.count else { return ([], "\(low)-*") }
        var high = min(range.high ?? Int.max, low + maxValRange - 1)
        high = min(high, values.count - 1)
        let slice = Array(values[low...high])
        return (slice, high == values.count - 1 ? "\(low)-*" : "\(low)-\(high)")
    }

    /// SD flags: drop the owner, group, DACL or SACL the client did not ask for by clearing
    /// their offsets (and the DACL/SACL present bits) in the self-relative descriptor.
    static func maskSecurityDescriptor(_ sd: [UInt8], flags: UInt32) -> [UInt8] {
        guard sd.count >= 20 else { return sd }
        var out = sd
        var control = UInt16(out[2]) | UInt16(out[3]) << 8
        func clear(_ offset: Int) { for i in offset..<(offset + 4) { out[i] = 0 } }
        if flags & SDFlagsValue.owner == 0 { clear(4) }
        if flags & SDFlagsValue.group == 0 { clear(8) }
        if flags & SDFlagsValue.sacl == 0 {
            clear(12)
            control &= ~0x0010
        }
        if flags & SDFlagsValue.dacl == 0 {
            clear(16)
            control &= ~0x0004
        }
        out[2] = UInt8(control & 0xFF)
        out[3] = UInt8(control >> 8)
        return out
    }

    /// Constructed (operational) attributes AD computes on request.
    func constructed(_ name: String, _ entry: DirectoryEntry) async throws -> Attribute? {
        switch name {
        case "createTimeStamp":
            return entry.values("whenCreated").isEmpty ? nil : Attribute(name: name, values: entry.values("whenCreated"))
        case "modifyTimeStamp":
            return entry.values("whenChanged").isEmpty ? nil : Attribute(name: name, values: entry.values("whenChanged"))
        case "subSchemaSubEntry":
            return Attribute(name, strings: [info.subschemaDN.description])
        case "canonicalName":
            return Attribute(name, strings: [Self.canonicalName(entry.dn)])
        case "tokenGroups":
            guard entry.sid != nil else { return nil }
            let sids = try await store.groupSIDs(of: entry.id)
            return sids.isEmpty ? nil : Attribute(name: name, values: sids.map(\.bytes))
        case "msDS-KeyVersionNumber":
            // WP-Z: Samba's keytab sync (`pw2kt_get_dc_info`) needs it after `net ads join`.
            guard let secrets = try await store.secrets(id: entry.id) else { return nil }
            return Attribute(name, strings: [String(secrets.kvno)])
        case "msDS-User-Account-Control-Computed":
            guard entry.has("userAccountControl") else { return nil }
            var bits: UInt32 = 0
            let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
            if entry.int("pwdLastSet") == 0, uac & UserAccountControl.dontExpirePassword == 0 { bits |= UserAccountControl.passwordExpired }
            return Attribute(name, strings: [String(bits)])
        default:
            return nil
        }
    }

    /// `lab.sheep/Users/alice` (MS-ADTS canonical name).
    static func canonicalName(_ dn: DN) -> String {
        let domainParts = dn.rdns.reversed().prefix { $0.type.caseInsensitiveCompare("DC") == .orderedSame }
        let domain = domainParts.reversed().map(\.value).joined(separator: ".")
        let rest = dn.rdns.reversed().dropFirst(domainParts.count).map(\.value)
        return ([domain] + rest).joined(separator: "/") + (rest.isEmpty ? "/" : "")
    }
}

/// The requested attribute list (RFC 4511 §4.5.1.8 plus AD ranges).
struct AttributeSelection {
    /// `*` or an empty list.
    var allUser: Bool
    /// `+`.
    var allOperational: Bool
    /// `1.1` alone.
    var none: Bool
    /// Lower-cased base names asked for.
    var names: Set<String>
    /// Ranges asked for (`member;range=0-1499`), by lower-cased base name.
    var ranges: [String: (low: Int, high: Int?)]

    static let constructed = ["createTimeStamp", "modifyTimeStamp", "subSchemaSubEntry", "canonicalName", "tokenGroups",
                              "msDS-User-Account-Control-Computed", "msDS-KeyVersionNumber"]

    init(_ requested: [String]) {
        var names = Set<String>()
        var ranges: [String: (Int, Int?)] = [:]
        allUser = requested.isEmpty || requested.contains("*")
        allOperational = requested.contains("+")
        none = requested == ["1.1"]
        for r in requested where r != "*" && r != "+" && r != "1.1" {
            let parts = r.split(separator: ";").map(String.init)
            guard let base = parts.first else { continue }
            names.insert(base.lowercased())
            for option in parts.dropFirst() where option.lowercased().hasPrefix("range=") {
                let spec = option.dropFirst(6).split(separator: "-", maxSplits: 1).map(String.init)
                if spec.count == 2, let low = Int(spec[0]), low >= 0 {
                    ranges[base.lowercased()] = (low, spec[1] == "*" ? nil : Int(spec[1]))
                }
            }
        }
        self.names = names
        self.ranges = ranges
    }

    /// `name` without options (`member;range=0-9` → `member`, `userCertificate;binary`).
    static func baseName(_ name: String) -> String { String(name.split(separator: ";").first ?? Substring(name)) }

    func wants(_ name: String) -> Bool { allUser || names.contains(name.lowercased()) }

    func wantsConstructed(_ name: String) -> Bool { allOperational || names.contains(name.lowercased()) }

    func range(for name: String) -> (low: Int, high: Int?)? { ranges[name.lowercased()] }
}
