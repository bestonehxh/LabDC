import Foundation
import MSPAC
import Store

/// UI-2: the Users page's read model — folders (OU tree), people, groups and computers of the
/// domain partition, derived from store entries. Pure values: `DirectoryEditor.snapshot()` builds
/// one after every change; the page filters, searches and sorts it.
public struct DirectorySnapshot: Sendable, Equatable {
    public var domainDN: DN
    public var dnsDomain: String
    /// The tree's root: the domain itself, with `Builtin`, `Computers`, `Users`, the OUs.
    public var root: DirectoryFolder
    public var people: [DirectoryPerson]
    public var groups: [DirectoryGroup]
    public var computers: [DirectoryComputer]
    /// Every folder by id (the root included).
    public var folders: [ObjectID: DirectoryFolder]

    public init(domainDN: DN, dnsDomain: String, root: DirectoryFolder, people: [DirectoryPerson] = [],
                groups: [DirectoryGroup] = [], computers: [DirectoryComputer] = []) {
        self.domainDN = domainDN
        self.dnsDomain = dnsDomain
        self.root = root
        self.people = people
        self.groups = groups
        self.computers = computers
        var index: [ObjectID: DirectoryFolder] = [:]
        func walk(_ f: DirectoryFolder) {
            index[f.id] = f
            for c in f.children ?? [] { walk(c) }
        }
        walk(root)
        folders = index
    }

    public static let empty = DirectorySnapshot(domainDN: DN.root, dnsDomain: "",
                                                root: DirectoryFolder(id: 0, dn: DN.root, name: "Domain", kind: .domain))

    public var isEmpty: Bool { folders.count <= 1 && people.isEmpty && groups.isEmpty && computers.isEmpty }

    // MARK: Lookups

    public func folder(_ id: ObjectID?) -> DirectoryFolder? { id.flatMap { folders[$0] } }

    public func folder(dn: DN) -> DirectoryFolder? { folders.values.first { $0.dn == dn } }

    /// `Staff / IT` for an object whose parent is `parentID` (the DNS domain at the root).
    public func folderPath(_ parentID: ObjectID?) -> String {
        folder(parentID)?.path ?? "—"
    }

    /// Every folder in tree order (for pickers), with its depth.
    public var folderList: [(folder: DirectoryFolder, depth: Int)] {
        var out: [(DirectoryFolder, Int)] = []
        func walk(_ f: DirectoryFolder, _ depth: Int) {
            out.append((f, depth))
            for c in f.children ?? [] { walk(c, depth + 1) }
        }
        walk(root, 0)
        return out
    }

    public func person(_ id: ObjectID) -> DirectoryPerson? { people.first { $0.id == id } }
    public func group(_ id: ObjectID) -> DirectoryGroup? { groups.first { $0.id == id } }
    public func computer(_ id: ObjectID) -> DirectoryComputer? { computers.first { $0.id == id } }

    /// Any person/group/computer by DN (member lists).
    public func member(dn: DN) -> DirectoryMember? {
        if let p = people.first(where: { $0.dn == dn }) { return DirectoryMember(p) }
        if let c = computers.first(where: { $0.dn == dn }) { return DirectoryMember(c) }
        if let g = groups.first(where: { $0.dn == dn }) { return DirectoryMember(g) }
        return nil
    }

    /// Any person/group/computer by id.
    public func member(id: ObjectID) -> DirectoryMember? {
        if let p = person(id) { return DirectoryMember(p) }
        if let c = computer(id) { return DirectoryMember(c) }
        if let g = group(id) { return DirectoryMember(g) }
        return nil
    }

    /// The DN of any listed object or folder.
    public func dn(of id: ObjectID) -> DN? {
        person(id)?.dn ?? computer(id)?.dn ?? group(id)?.dn ?? folders[id]?.dn
    }

    /// The folder an object is in.
    public func parentID(of id: ObjectID) -> ObjectID? {
        person(id)?.parentID ?? computer(id)?.parentID ?? group(id)?.parentID ?? folders[id]?.parentID
    }

    /// True when the folder holds nothing (no sub-folders, no objects listed or not). The store
    /// refuses to delete a non-empty one anyway; the page greys the menu item.
    public func isEmpty(folder id: ObjectID) -> Bool {
        guard let f = folders[id] else { return false }
        if !(f.children ?? []).isEmpty || f.otherChildren > 0 { return false }
        return !people.contains { $0.parentID == id } && !groups.contains { $0.parentID == id }
            && !computers.contains { $0.parentID == id }
    }

    /// `id` and every folder below it.
    public func folderAndDescendants(_ id: ObjectID) -> Set<ObjectID> {
        guard let f = folders[id] else { return [] }
        var out: Set<ObjectID> = [id]
        for c in f.children ?? [] { out.formUnion(folderAndDescendants(c.id)) }
        return out
    }

    // MARK: Build

    /// Object classes the page reads (one subtree search).
    public static let classes = ["user", "group", "organizationalUnit", "container", "builtinDomain", "domainDNS"]

    /// Builds the snapshot from the entries of a subtree search of the domain partition.
    ///
    /// Folders: the domain, `CN=Builtin`, the top-level `CN=Users` and `CN=Computers` containers,
    /// every `organizationalUnit` and the containers inside OUs. Everything else (System,
    /// Program Data, ForeignSecurityPrincipals, …) stays out of the tree and its contents out of
    /// the tables.
    public static func build(entries: [DirectoryEntry], domainDN: DN, dnsDomain: String) -> DirectorySnapshot {
        guard let domain = entries.first(where: { $0.dn == domainDN }) else { return .empty }
        let rootID = domain.id
        let byID = Dictionary(entries.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        func classes(_ e: DirectoryEntry) -> Set<String> { Set(e.strings("objectClass").map { $0.lowercased() }) }

        func folderKind(_ e: DirectoryEntry) -> DirectoryFolder.Kind? {
            if e.id == rootID { return .domain }
            let cls = classes(e)
            if cls.contains("organizationalunit") { return .organizationalUnit }
            if cls.contains("builtindomain"), e.parentID == rootID { return .builtin }
            if e.objectClass.lowercased() == "container", let p = e.parentID {
                if p == rootID, let n = e.dn.rdn?.value.lowercased(), n == "users" || n == "computers" { return .container }
                if let parent = byID[p], classes(parent).contains("organizationalunit") { return .container }
            }
            return nil
        }
        var folderEntries: [ObjectID: (entry: DirectoryEntry, kind: DirectoryFolder.Kind)] = [:]
        for e in entries { if let k = folderKind(e) { folderEntries[e.id] = (e, k) } }
        // A folder counts only when its chain up to the root is made of folders.
        func reachable(_ id: ObjectID) -> Bool {
            var cursor: ObjectID? = id
            for _ in 0..<64 {
                guard let c = cursor else { return false }
                if c == rootID { return true }
                guard let f = folderEntries[c] else { return false }
                cursor = f.entry.parentID
            }
            return false
        }
        let folderIDs = Set(folderEntries.keys.filter(reachable))
        var childrenOf: [ObjectID: [ObjectID]] = [:]
        for id in folderIDs where id != rootID {
            if let p = folderEntries[id]?.entry.parentID { childrenOf[p, default: []].append(id) }
        }

        var people: [DirectoryPerson] = []
        var groups: [DirectoryGroup] = []
        var computers: [DirectoryComputer] = []
        var otherChildren: [ObjectID: Int] = [:]
        var sidNames: [String: String] = [:]
        for e in entries { if let sid = e.sid { sidNames[sid.description] = e.samAccountName ?? e.dn.rdn?.value ?? "" } }
        var groupsByDN: [String: DirectoryEntry] = [:]
        for e in entries where classes(e).contains("group") { groupsByDN[e.dn.normalized] = e }

        for e in entries where !folderIDs.contains(e.id) {
            guard let parent = e.parentID, folderIDs.contains(parent) else { continue }
            let cls = classes(e)
            if cls.contains("computer") {
                computers.append(DirectoryComputer(e, sidNames: sidNames))
            } else if cls.contains("user") {
                people.append(DirectoryPerson(e, groupsByDN: groupsByDN))
            } else if cls.contains("group") {
                groups.append(DirectoryGroup(e))
            } else {
                otherChildren[parent, default: 0] += 1
            }
        }
        // Children that were not in the search (other classes) keep a folder "not empty".
        for e in entries where !folderIDs.contains(e.id) {
            if let p = e.parentID, folderIDs.contains(p), folderKind(e) != nil { otherChildren[p, default: 0] += 1 }
        }

        func makeFolder(_ id: ObjectID, path: [String]) -> DirectoryFolder {
            let (e, kind) = folderEntries[id] ?? (domain, .domain)
            let name = kind == .domain ? dnsDomain : (e.dn.rdn?.value ?? "?")
            let here = kind == .domain ? [] : path + [name]
            let kids = (childrenOf[id] ?? []).map { makeFolder($0, path: here) }.sorted(by: DirectoryFolder.treeOrder)
            var f = DirectoryFolder(id: id, dn: e.dn, name: name, kind: kind, parentID: kind == .domain ? nil : e.parentID,
                                    children: kids.isEmpty ? nil : kids,
                                    isCritical: e.string("isCriticalSystemObject")?.uppercased() == "TRUE",
                                    description: e.string("description"))
            f.path = kind == .domain ? dnsDomain : here.joined(separator: " / ")
            f.otherChildren = otherChildren[id] ?? 0
            return f
        }
        let root = makeFolder(rootID, path: [])
        return DirectorySnapshot(domainDN: domainDN, dnsDomain: dnsDomain, root: root, people: people, groups: groups,
                                 computers: computers)
    }
}

/// A node of the folder (OU) tree.
public struct DirectoryFolder: Identifiable, Hashable, Sendable {
    public enum Kind: String, Sendable, Hashable {
        /// The domain itself (the tree's root: "everything").
        case domain
        /// `CN=Builtin`.
        case builtin
        /// `CN=Users`, `CN=Computers` (and containers inside OUs).
        case container
        /// An OU: the owner's folders. Only these are renamed and deleted.
        case organizationalUnit
    }

    public var id: ObjectID
    public var dn: DN
    public var name: String
    public var kind: Kind
    public var parentID: ObjectID?
    /// nil for a leaf (the shape `List(_:children:)` expects).
    public var children: [DirectoryFolder]?
    public var isCritical = false
    public var description: String?
    /// `Staff / IT`; the DNS domain name for the root.
    public var path = ""
    /// Objects inside that the page does not list (so the folder is not empty).
    public var otherChildren = 0

    public init(id: ObjectID, dn: DN, name: String, kind: Kind, parentID: ObjectID? = nil,
                children: [DirectoryFolder]? = nil, isCritical: Bool = false, description: String? = nil) {
        self.id = id
        self.dn = dn
        self.name = name
        self.kind = kind
        self.parentID = parentID
        self.children = children
        self.isCritical = isCritical
        self.description = description
        self.path = name
    }

    /// OUs can be renamed and deleted; the default containers cannot.
    public var isEditable: Bool { kind == .organizationalUnit && !isCritical }

    /// New folders go below the domain or an OU (an OU's possible superiors in AD).
    public var canHoldFolders: Bool { kind == .domain || kind == .organizationalUnit }

    /// Whether the folder can hold the objects of a People/Groups/Computers tab (AD's
    /// possibleSuperiors: Users and OUs take users and groups, Computers and Domain Controllers
    /// take machines only, Builtin holds the domain's own groups).
    public func accepts(tab: String) -> Bool {
        switch kind {
        case .domain, .organizationalUnit: return true
        case .container:
            switch name.lowercased() {
            case "computers", "domain controllers": return tab == "computers"
            default: return tab != "computers"
            }
        case .builtin: return tab != "computers"
        }
    }

    public var symbol: String {
        switch kind {
        case .domain: "globe"
        case .builtin: "lock.shield"
        case .container: "folder"
        case .organizationalUnit: "folder.fill"
        }
    }

    /// Default containers first (Builtin, Computers, Users…), then OUs, each by name.
    static func treeOrder(_ a: DirectoryFolder, _ b: DirectoryFolder) -> Bool {
        let ra = a.kind == .organizationalUnit ? 1 : 0, rb = b.kind == .organizationalUnit ? 1 : 0
        if ra != rb { return ra < rb }
        return a.name.localizedStandardCompare(b.name) == .orderedAscending
    }
}

/// A person/computer/group in a member list.
public struct DirectoryMember: Identifiable, Hashable, Sendable {
    public enum Kind: String, Sendable, Hashable { case person, group, computer }
    public var id: ObjectID
    public var kind: Kind
    public var name: String
    public var detail: String

    init(_ p: DirectoryPerson) { self.init(id: p.id, kind: .person, name: p.displayName, detail: p.username) }
    init(_ c: DirectoryComputer) { self.init(id: c.id, kind: .computer, name: c.name, detail: c.dnsName ?? c.samAccountName) }
    init(_ g: DirectoryGroup) { self.init(id: g.id, kind: .group, name: g.name, detail: g.scope.title) }

    public init(id: ObjectID, kind: Kind, name: String, detail: String) {
        self.id = id
        self.kind = kind
        self.name = name
        self.detail = detail
    }

    public var symbol: String {
        switch kind {
        case .person: "person"
        case .group: "person.2"
        case .computer: "desktopcomputer"
        }
    }
}

// MARK: - People

public struct DirectoryPerson: Identifiable, Hashable, Sendable {
    public var id: ObjectID
    public var dn: DN
    public var parentID: ObjectID?
    /// `displayName`, else the RDN value.
    public var displayName: String
    /// `sAMAccountName`.
    public var username: String
    public var upn: String?
    public var enabled: Bool
    /// Direct groups (`memberOf`) by name; the primary group (Domain Users) is implicit and not listed.
    public var groupIDs: [ObjectID]
    public var groupNames: [String]
    public var mail: String?
    public var phone: String?
    public var title: String?
    public var department: String?
    public var description: String?
    /// `pwdLastSet` = 0 on a password that can expire (what sign-in actually enforces).
    public var mustChangePassword: Bool
    /// `userAccountControl` DONT_EXPIRE_PASSWORD.
    public var passwordNeverExpires = false
    /// `accountExpires`; nil = never.
    public var accountExpires: Date?
    public var passwordLastSet: Date?
    public var lastLogon: Date?
    public var created: Date?
    public var sid: String?
    public var isCritical: Bool

    public enum Status: String, Sendable, Hashable, Comparable {
        case enabled = "Enabled", disabled = "Disabled", expired = "Expired"
        public static func < (a: Status, b: Status) -> Bool { a.rawValue < b.rawValue }
    }

    public func status(now: Date = Date()) -> Status {
        if !enabled { return .disabled }
        if let e = accountExpires, e < now { return .expired }
        return .enabled
    }

    /// The Groups column: `NetAdmins, Staff`.
    public var groupsText: String { groupNames.joined(separator: ", ") }

    public init(id: ObjectID, dn: DN, parentID: ObjectID?, displayName: String, username: String, upn: String? = nil,
                enabled: Bool = true, groupIDs: [ObjectID] = [], groupNames: [String] = []) {
        self.id = id
        self.dn = dn
        self.parentID = parentID
        self.displayName = displayName
        self.username = username
        self.upn = upn
        self.enabled = enabled
        self.groupIDs = groupIDs
        self.groupNames = groupNames
        mustChangePassword = false
        isCritical = false
    }

    init(_ e: DirectoryEntry, groupsByDN: [String: DirectoryEntry]) {
        let username = e.samAccountName ?? e.dn.rdn?.value ?? ""
        let display = e.string("displayName").flatMap { $0.isEmpty ? nil : $0 } ?? e.dn.rdn?.value ?? username
        var groups: [(ObjectID, String)] = []
        for text in e.strings("memberOf") {
            guard let norm = try? DN(string: text).normalized, let g = groupsByDN[norm] else { continue }
            groups.append((g.id, g.dn.rdn?.value ?? g.samAccountName ?? "?"))
        }
        groups.sort { $0.1.localizedStandardCompare($1.1) == .orderedAscending }
        let uac = UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0)
        self.init(id: e.id, dn: e.dn, parentID: e.parentID, displayName: display, username: username,
                  upn: e.string("userPrincipalName"), enabled: uac & UserAccountControl.accountDisable == 0,
                  groupIDs: groups.map(\.0), groupNames: groups.map(\.1))
        mail = e.string("mail")
        phone = e.string("telephoneNumber")
        title = e.string("title")
        department = e.string("department")
        description = e.string("description")
        let pls = e.int("pwdLastSet") ?? 0
        passwordNeverExpires = uac & UserAccountControl.dontExpirePassword != 0
        // pwdLastSet 0 or UF_PASSWORD_EXPIRED, unless never-expires — what the KDC, LDAP bind,
        // Netlogon and `DirectoryStore.passwordMustChange` enforce.
        mustChangePassword = (pls == 0 || uac & UserAccountControl.passwordExpired != 0) && !passwordNeverExpires
        passwordLastSet = FileTimeDate.date(pls)
        accountExpires = FileTimeDate.date(e.int("accountExpires") ?? 0)
        lastLogon = FileTimeDate.latest(e.int("lastLogon"), e.int("lastLogonTimestamp"))
        created = e.string("whenCreated").flatMap(GeneralizedTime.date)
        sid = e.sid?.description
        isCritical = e.string("isCriticalSystemObject")?.uppercased() == "TRUE"
    }

    /// Search: sAMAccountName, display name, UPN, mail.
    public func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return true }
        return [username, displayName, upn ?? "", mail ?? ""].contains { $0.localizedCaseInsensitiveContains(q) }
    }
}

// MARK: - Groups

public enum GroupScope: String, Sendable, Hashable, CaseIterable, Comparable {
    case global, universal, domainLocal, builtinLocal

    public var title: String {
        switch self {
        case .global: "Global"
        case .universal: "Universal"
        case .domainLocal: "Domain local"
        case .builtinLocal: "Built-in local"
        }
    }

    /// The scopes the inspector offers.
    public static let editable: [GroupScope] = [.global, .universal, .domainLocal]

    public init(groupType: Int64) {
        let t = Int32(truncatingIfNeeded: groupType)
        if t & GroupType.builtinLocal != 0 { self = .builtinLocal }
        else if t & GroupType.universalGroup != 0 { self = .universal }
        else if t & GroupType.resourceGroup != 0 { self = .domainLocal }
        else { self = .global }
    }

    /// `groupType` for this scope (security or distribution).
    public func groupType(security: Bool) -> Int32 {
        let bits: Int32 = switch self {
        case .global: GroupType.accountGroup
        case .universal: GroupType.universalGroup
        case .domainLocal: GroupType.resourceGroup
        case .builtinLocal: GroupType.resourceGroup | GroupType.builtinLocal
        }
        return security ? bits | GroupType.security : bits
    }

    public static func < (a: GroupScope, b: GroupScope) -> Bool { a.title < b.title }
}

public struct DirectoryGroup: Identifiable, Hashable, Sendable {
    public var id: ObjectID
    public var dn: DN
    public var parentID: ObjectID?
    /// The RDN value (`NetAdmins`).
    public var name: String
    public var samAccountName: String
    public var scope: GroupScope
    public var isSecurity: Bool
    public var memberDNs: [DN]
    public var description: String?
    public var isCritical: Bool
    public var sid: String?

    public var memberCount: Int { memberDNs.count }

    public init(id: ObjectID, dn: DN, parentID: ObjectID?, name: String, scope: GroupScope = .global,
                memberDNs: [DN] = [], description: String? = nil) {
        self.id = id
        self.dn = dn
        self.parentID = parentID
        self.name = name
        samAccountName = name
        self.scope = scope
        isSecurity = true
        self.memberDNs = memberDNs
        self.description = description
        isCritical = false
    }

    init(_ e: DirectoryEntry) {
        let type = e.int("groupType") ?? Int64(GroupType.globalSecurity)
        self.init(id: e.id, dn: e.dn, parentID: e.parentID, name: e.dn.rdn?.value ?? e.samAccountName ?? "?",
                  scope: GroupScope(groupType: type), memberDNs: e.strings("member").compactMap { try? DN(string: $0) },
                  description: e.string("description"))
        samAccountName = e.samAccountName ?? name
        isSecurity = Int32(truncatingIfNeeded: type) & GroupType.security != 0
        isCritical = e.string("isCriticalSystemObject")?.uppercased() == "TRUE"
        sid = e.sid?.description
    }

    /// Search: name, sAMAccountName, description.
    public func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return true }
        return [name, samAccountName, description ?? ""].contains { $0.localizedCaseInsensitiveContains(q) }
    }
}

// MARK: - Computers

public struct DirectoryComputer: Identifiable, Hashable, Sendable {
    public var id: ObjectID
    public var dn: DN
    public var parentID: ObjectID?
    /// The RDN value (`PC01`).
    public var name: String
    /// `PC01$`.
    public var samAccountName: String
    public var dnsName: String?
    public var operatingSystem: String?
    public var operatingSystemVersion: String?
    public var lastLogon: Date?
    /// `whenCreated` (when it joined).
    public var joined: Date?
    /// `mS-DS-CreatorSID` resolved to an account name, when the store has it.
    public var joinedBy: String?
    public var spns: [String]
    public var enabled: Bool
    public var isDomainController: Bool
    public var isCritical: Bool
    public var sid: String?

    /// The OS column: `Windows 11 Pro 10.0 (26100)`.
    public var osText: String {
        [operatingSystem, operatingSystemVersion].compactMap { $0 }.joined(separator: " ")
    }

    public init(id: ObjectID, dn: DN, parentID: ObjectID?, name: String, dnsName: String? = nil,
                operatingSystem: String? = nil, lastLogon: Date? = nil, joined: Date? = nil) {
        self.id = id
        self.dn = dn
        self.parentID = parentID
        self.name = name
        samAccountName = name.uppercased() + "$"
        self.dnsName = dnsName
        self.operatingSystem = operatingSystem
        self.lastLogon = lastLogon
        self.joined = joined
        spns = []
        enabled = true
        isDomainController = false
        isCritical = false
    }

    init(_ e: DirectoryEntry, sidNames: [String: String]) {
        self.init(id: e.id, dn: e.dn, parentID: e.parentID, name: e.dn.rdn?.value ?? e.samAccountName ?? "?",
                  dnsName: e.string("dNSHostName"), operatingSystem: e.string("operatingSystem"),
                  lastLogon: FileTimeDate.latest(e.int("lastLogon"), e.int("lastLogonTimestamp")),
                  joined: e.string("whenCreated").flatMap(GeneralizedTime.date))
        samAccountName = e.samAccountName ?? name + "$"
        operatingSystemVersion = e.string("operatingSystemVersion")
        if let creator = e.values("mS-DS-CreatorSID").first, let sid = try? SID(bytes: creator) {
            joinedBy = sidNames[sid.description] ?? sid.description
        }
        spns = e.strings("servicePrincipalName").sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        let uac = UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0)
        enabled = uac & UserAccountControl.accountDisable == 0
        isDomainController = uac & UserAccountControl.serverTrustAccount != 0
        isCritical = e.string("isCriticalSystemObject")?.uppercased() == "TRUE"
        sid = e.sid?.description
    }

    /// Search: name, sAMAccountName, DNS name, OS.
    public func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return true }
        return [name, samAccountName, dnsName ?? "", operatingSystem ?? ""].contains { $0.localizedCaseInsensitiveContains(q) }
    }
}

// MARK: - FILETIME

/// `accountExpires`, `lastLogon`, `pwdLastSet`: 100 ns since 1601-01-01 UTC; 0 and Int64.max
/// mean "never".
public enum FileTimeDate {
    static let epochDelta: Int64 = 11_644_473_600

    public static func date(_ value: Int64) -> Date? {
        guard value > 0, value != Int64.max else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(value / 10_000_000 - epochDelta)
                    + TimeInterval(value % 10_000_000) / 10_000_000)
    }

    public static func value(_ date: Date) -> Int64 {
        Int64(((date.timeIntervalSince1970 + TimeInterval(epochDelta)) * 10_000_000).rounded())
    }

    static func latest(_ a: Int64?, _ b: Int64?) -> Date? {
        [a, b].compactMap { $0.flatMap(date) }.max()
    }
}
