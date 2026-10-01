import Foundation
import MSPAC
import Store

/// A domain as it appears in an `LSAPR_REFERENCED_DOMAIN_LIST` entry (`LSAPR_TRUST_INFORMATION`).
public struct ReferencedDomain: Sendable, Hashable, CustomStringConvertible {
    public var name: String
    public var sid: SID

    public init(name: String, sid: SID) {
        self.name = name
        self.sid = sid
    }

    public var description: String { "\(name.isEmpty ? "\"\"" : name) (\(sid))" }
}

/// One translated name or SID: the account SID, its unqualified name, its `SID_NAME_USE`, and the
/// referenced domain it is reported under (with the RID relative to that domain).
public struct ResolvedAccount: Sendable, Hashable, CustomStringConvertible {
    public var sid: SID
    /// Unqualified name: `alice`, `Administrators`, `Everyone`, `LABSHEEP` (for a domain).
    public var name: String
    public var use: SIDNameUse
    public var domain: ReferencedDomain
    /// `sid` relative to `domain.sid`: the last sub-authority, or `0xFFFFFFFF` for a domain itself.
    public var relativeID: UInt32

    public init(sid: SID, name: String, use: SIDNameUse, domain: ReferencedDomain, relativeID: UInt32) {
        self.sid = sid
        self.name = name
        self.use = use
        self.domain = domain
        self.relativeID = relativeID
    }

    public var description: String { "\(domain.name)\\\(name) \(sid) \(use)" }
}

/// Well-known SIDs outside the account and BUILTIN domains (MS-DTYP §2.4.2.4): the null/world/
/// local/creator authorities (reported under a domain with an empty name, as Windows does) and
/// the single-sub-authority `NT AUTHORITY` principals.
public enum WellKnownSIDs {
    public struct Entry: Sendable, Hashable {
        public let sid: String
        public let name: String
        public let domainName: String
        public let domainSID: String
    }

    public static let ntAuthority = ReferencedDomain(name: "NT AUTHORITY", sid: try! SID(string: "S-1-5"))
    public static let builtin = ReferencedDomain(name: "BUILTIN", sid: try! SID(string: "S-1-5-32"))

    public static let entries: [Entry] = {
        var e: [Entry] = [
            Entry(sid: "S-1-0-0", name: "NULL SID", domainName: "", domainSID: "S-1-0"),
            Entry(sid: "S-1-1-0", name: "Everyone", domainName: "", domainSID: "S-1-1"),
            Entry(sid: "S-1-2-0", name: "LOCAL", domainName: "", domainSID: "S-1-2"),
            Entry(sid: "S-1-2-1", name: "CONSOLE LOGON", domainName: "", domainSID: "S-1-2"),
            Entry(sid: "S-1-3-0", name: "CREATOR OWNER", domainName: "", domainSID: "S-1-3"),
            Entry(sid: "S-1-3-1", name: "CREATOR GROUP", domainName: "", domainSID: "S-1-3"),
            Entry(sid: "S-1-3-2", name: "CREATOR OWNER SERVER", domainName: "", domainSID: "S-1-3"),
            Entry(sid: "S-1-3-3", name: "CREATOR GROUP SERVER", domainName: "", domainSID: "S-1-3"),
            Entry(sid: "S-1-3-4", name: "OWNER RIGHTS", domainName: "", domainSID: "S-1-3"),
        ]
        let nt: [(UInt32, String)] = [
            (1, "DIALUP"), (2, "NETWORK"), (3, "BATCH"), (4, "INTERACTIVE"), (6, "SERVICE"), (7, "ANONYMOUS LOGON"),
            (8, "PROXY"), (9, "ENTERPRISE DOMAIN CONTROLLERS"), (10, "SELF"), (11, "Authenticated Users"),
            (12, "RESTRICTED"), (13, "TERMINAL SERVER USER"), (14, "REMOTE INTERACTIVE LOGON"),
            (15, "This Organization"), (17, "IUSR"), (18, "SYSTEM"), (19, "LOCAL SERVICE"), (20, "NETWORK SERVICE"),
            (1000, "Other Organization"),
        ]
        for (rid, name) in nt {
            e.append(Entry(sid: "S-1-5-\(rid)", name: name, domainName: "NT AUTHORITY", domainSID: "S-1-5"))
        }
        return e
    }()

    static let bySID: [SID: Entry] = Dictionary(uniqueKeysWithValues: entries.map { (try! SID(string: $0.sid), $0) })

    static func resolved(_ e: Entry) -> ResolvedAccount {
        let sid = try! SID(string: e.sid)
        return ResolvedAccount(sid: sid, name: e.name, use: .wellKnownGroup,
                               domain: ReferencedDomain(name: e.domainName, sid: try! SID(string: e.domainSID)),
                               relativeID: sid.rid ?? 0)
    }
}

/// Translates names and SIDs the way a Windows DC's LSA does (MS-LSAT §3.1.4.5, §3.1.4.9), from
/// three sources: the well-known table above, the BUILTIN domain (`S-1-5-32-*`, the Store's
/// builtin groups), and the account domain (users, groups and computers in the Store).
///
/// Name forms: `DOMAIN\name` (NetBIOS name, DNS name or realm; `BUILTIN`, `NT AUTHORITY`, or empty
/// for the world/creator authorities), `name@dns` (explicit UPN, else the implicit
/// `sam@dnsDomain`/`sam@REALM`), and a bare name (well-known, then domain names, then BUILTIN and
/// account-domain sAMAccountNames).
public struct AccountResolver: Sendable {
    public let store: DirectoryStore

    public init(store: DirectoryStore) { self.store = store }

    static let attrs = ["objectSid", "sAMAccountName", "sAMAccountType"]

    /// The account domain (`LABSHEEP`, domain SID).
    public func accountDomain() async throws -> ReferencedDomain {
        let info = try await store.domainInfo()
        return ReferencedDomain(name: info.netbiosDomain, sid: info.domainSID)
    }

    // MARK: SIDs

    public func resolve(sid: SID) async throws -> ResolvedAccount? {
        let info = try await store.domainInfo()
        let account = ReferencedDomain(name: info.netbiosDomain, sid: info.domainSID)
        if sid == account.sid {
            return ResolvedAccount(sid: sid, name: account.name, use: .domain, domain: account, relativeID: 0xFFFF_FFFF)
        }
        if sid == WellKnownSIDs.builtin.sid {
            return ResolvedAccount(sid: sid, name: "BUILTIN", use: .domain, domain: WellKnownSIDs.builtin,
                                   relativeID: 0xFFFF_FFFF)
        }
        if sid == WellKnownSIDs.ntAuthority.sid {
            return ResolvedAccount(sid: sid, name: "NT AUTHORITY", use: .domain, domain: WellKnownSIDs.ntAuthority,
                                   relativeID: 0xFFFF_FFFF)
        }
        if let e = WellKnownSIDs.bySID[sid] { return WellKnownSIDs.resolved(e) }
        guard let parent = sid.domain, parent == account.sid || parent == WellKnownSIDs.builtin.sid else { return nil }
        guard let entry = try await store.read(sid: sid, attrs: Self.attrs),
              let use = Self.use(of: entry), let sam = entry.samAccountName else { return nil }
        return ResolvedAccount(sid: sid, name: sam, use: use,
                               domain: parent == account.sid ? account : WellKnownSIDs.builtin,
                               relativeID: sid.rid ?? 0)
    }

    /// The domain an unmapped SID would be reported under (so `DomainIndex` can still point at
    /// it), or nil if the SID's authority is not one this DC knows.
    public func authority(of sid: SID) async throws -> ReferencedDomain? {
        let account = try await accountDomain()
        guard let parent = sid.domain else { return nil }
        if parent == account.sid { return account }
        if parent == WellKnownSIDs.builtin.sid { return WellKnownSIDs.builtin }
        if parent == WellKnownSIDs.ntAuthority.sid { return WellKnownSIDs.ntAuthority }
        return nil
    }

    // MARK: names

    public func resolve(name raw: String) async throws -> ResolvedAccount? {
        let info = try await store.domainInfo()
        let account = ReferencedDomain(name: info.netbiosDomain, sid: info.domainSID)
        let name = raw.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return nil }

        func isAccountDomainName(_ s: String) -> Bool {
            [info.netbiosDomain, info.dnsDomain, info.realm].contains { $0.caseInsensitiveCompare(s) == .orderedSame }
        }
        func eq(_ a: String, _ b: String) -> Bool { a.caseInsensitiveCompare(b) == .orderedSame }
        func domainResult(_ d: ReferencedDomain) -> ResolvedAccount {
            ResolvedAccount(sid: d.sid, name: d.name, use: .domain, domain: d, relativeID: 0xFFFF_FFFF)
        }

        if let slash = name.firstIndex(of: "\\") {
            let domainPart = String(name[..<slash])
            let accountPart = String(name[name.index(after: slash)...])
            if eq(domainPart, "NT AUTHORITY") {
                if accountPart.isEmpty { return domainResult(WellKnownSIDs.ntAuthority) }
                return WellKnownSIDs.entries.first { $0.domainName == "NT AUTHORITY" && eq($0.name, accountPart) }
                    .map(WellKnownSIDs.resolved)
            }
            if domainPart.isEmpty {
                return WellKnownSIDs.entries.first { $0.domainName.isEmpty && eq($0.name, accountPart) }
                    .map(WellKnownSIDs.resolved)
            }
            if eq(domainPart, "BUILTIN") {
                if accountPart.isEmpty { return domainResult(WellKnownSIDs.builtin) }
                return try await sam(accountPart, in: WellKnownSIDs.builtin)
            }
            if isAccountDomainName(domainPart) {
                if accountPart.isEmpty { return domainResult(account) }
                return try await sam(accountPart, in: account)
            }
            return nil
        }

        if let at = name.lastIndex(of: "@"), at != name.startIndex {
            let user = String(name[..<at]), suffix = String(name[name.index(after: at)...])
            if let entry = try await store.read(upn: name, attrs: Self.attrs),
               let sid = entry.sid, sid.domain == account.sid, let use = Self.use(of: entry),
               let sam = entry.samAccountName {
                return ResolvedAccount(sid: sid, name: sam, use: use, domain: account, relativeID: sid.rid ?? 0)
            }
            if isAccountDomainName(suffix) { return try await sam(user, in: account) }
            return nil
        }

        if let e = WellKnownSIDs.entries.first(where: { eq($0.name, name) }) { return WellKnownSIDs.resolved(e) }
        if eq(name, "NT AUTHORITY") { return domainResult(WellKnownSIDs.ntAuthority) }
        if eq(name, "BUILTIN") { return domainResult(WellKnownSIDs.builtin) }
        if isAccountDomainName(name) { return domainResult(account) }
        if let r = try await sam(name, in: WellKnownSIDs.builtin) { return r }
        return try await sam(name, in: account)
    }

    /// A sAMAccountName lookup restricted to one domain (BUILTIN or the account domain).
    private func sam(_ sam: String, in domain: ReferencedDomain) async throws -> ResolvedAccount? {
        guard !sam.isEmpty,
              let entry = try await store.read(sam: sam, attrs: Self.attrs),
              let sid = entry.sid, sid.domain == domain.sid, let use = Self.use(of: entry),
              let stored = entry.samAccountName else { return nil }
        return ResolvedAccount(sid: sid, name: stored, use: use, domain: domain, relativeID: sid.rid ?? 0)
    }

    /// `SID_NAME_USE` from `sAMAccountType` (MS-SAMR §2.2.1.9): users, computers and trust
    /// accounts are `SidTypeUser` (what a Windows DC reports for `PC$`), global/universal groups
    /// `SidTypeGroup`, domain-local and builtin groups `SidTypeAlias`.
    static func use(of entry: DirectoryEntry) -> SIDNameUse? {
        guard let t = entry.int("sAMAccountType") else { return nil }
        switch UInt32(truncatingIfNeeded: t) >> 28 {
        case 1: return .group
        case 2: return .alias
        case 3: return .user
        default: return nil
        }
    }
}
