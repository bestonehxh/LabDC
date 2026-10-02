import Foundation

/// What the AD zone generator needs to know about the domain and this DC.
public struct DNSDomainInfo: Hashable, Sendable {
    /// The AD DNS domain, e.g. `lab.sheep` (also the forest root in phase 1).
    public var dnsDomain: DNSName
    /// The DC's fully qualified host name, e.g. `dc1.lab.sheep`.
    public var dcHostName: DNSName
    /// The domain's `objectGUID` (used in `_ldap._tcp.<guid>.domains._msdcs`).
    public var domainGUID: UUID
    /// The DC's NTDS Settings `objectGUID` (the DSA GUID, used in `<guid>._msdcs CNAME`).
    /// MS-ADTS §6.3.2.3 uses the DSA GUID there; nil falls back to `domainGUID`.
    public var dsaGUID: UUID?
    /// The DC's site, e.g. `Default-First-Site-Name`.
    public var site: String
    /// The DC's addresses: A records for IPv4, AAAA for IPv6.
    public var addresses: [DNSAddress]
    /// The DC's names before a domain rename (`dc.lab.sheep` after lab.sheep became
    /// corp.example): each is answered with the DC's addresses, so certificates issued before
    /// the rename — whose CRL and AIA URLs name the old host — still reach this DC.
    public var formerHostNames: [DNSName]
    /// Phase 5: reverse zones for the DHCP scopes (`0.20.10.in-addr.arpa`): SOA + NS generated,
    /// PTR records stored by the DHCP server. Not open to RFC 2136 updates.
    public var reverseZones: [DNSName]

    public init(dnsDomain: DNSName, dcHostName: DNSName, domainGUID: UUID, dsaGUID: UUID? = nil,
                site: String = "Default-First-Site-Name", addresses: [DNSAddress], formerHostNames: [DNSName] = [],
                reverseZones: [DNSName] = []) {
        self.dnsDomain = dnsDomain
        self.dcHostName = dcHostName
        self.domainGUID = domainGUID
        self.dsaGUID = dsaGUID
        self.site = site
        self.addresses = addresses
        self.formerHostNames = formerHostNames
        self.reverseZones = reverseZones
    }

    /// The zones this server is authoritative for (and takes dynamic updates in): the domain and
    /// `_msdcs.<domain>`.
    public var zones: [DNSName] { [dnsDomain, dnsDomain.prepending("_msdcs")] }

    /// The former DC names not already inside `zones` (nor the current DC name), each once.
    public var formerHostZones: [DNSName] {
        var seen = Set<DNSName>()
        return formerHostNames.filter { name in
            name != dcHostName && !zones.contains { name.isSubdomain(of: $0) } && seen.insert(name).inserted
        }
    }

    /// Everything queries are answered for: `zones`, plus a single-name zone per former DC name
    /// (SOA, NS and the DC's A/AAAA; no dynamic updates).
    public var servedZones: [DNSName] {
        let fixed = zones + formerHostZones
        return fixed + reverseZones.filter { !fixed.contains($0) }
    }
}

/// Where the DNS server gets its domain facts and stored records.
///
/// WP-P adapts `DirectoryStore` (its `domain` and `dns_records` tables) to this protocol.
/// `records(zone:)` returns every stored record of the zone (static and dynamic); the
/// server adds the generated AD records (`ADZoneGenerator`) on top. Dynamic update calls
/// `addDynamic`/`removeDynamic`, which must persist with `dynamic = 1`.
public protocol DNSZoneSource: Sendable {
    /// Stored records whose owner lies in `zone` (the most specific zone the server serves).
    func records(zone: DNSName) async -> [DNSRecord]
    /// Domain facts for the generated records. Called per query; keep it cheap.
    func domainInfo() async -> DNSDomainInfo
    /// Stores `record` in `zone`. An existing record with the same data gets the new TTL.
    func addDynamic(_ record: DNSRecord, zone: DNSName) async throws
    /// Removes the stored record with the same owner, type, class and RDATA (TTL ignored).
    func removeDynamic(_ record: DNSRecord, zone: DNSName) async throws
    /// Whether `name` has a record an administrator created (not a dynamic update or the DHCP
    /// server). Static names are never changed by an unsigned update, and a blocked name
    /// (`DNSBlockList`) is answered only when it has one. Default: false.
    func hasStaticRecords(name: DNSName, zone: DNSName) async -> Bool
    /// The client that registered `name` by an unsigned dynamic update, and when it last did.
    /// Default: nil (no tracking; the server then goes by the addresses in the name's A/AAAA).
    func dynamicOwner(name: DNSName, zone: DNSName) async -> DNSRecordOwner?
    /// Records (or with nil forgets) the owner of `name`. Default: does nothing.
    func setDynamicOwner(_ owner: DNSRecordOwner.Holder?, name: DNSName, zone: DNSName) async throws
}

/// Who registered a name by a dynamic update — the sender's address for an unsigned update, the
/// authenticated account for a secure (GSS-TSIG) one — and when it last refreshed it. Only the
/// owner may change or delete the name's records with an unsigned update.
public struct DNSRecordOwner: Hashable, Sendable {
    public enum Holder: Hashable, Sendable, CustomStringConvertible {
        case address(DNSAddress)
        /// An account (its SID text and sAMAccountName) that registered by a secure update.
        case account(sid: String, name: String)

        /// The stored form (`dns_owners.owner`): the address text, or `account:<SID>:<sam>`.
        public var storageText: String {
            switch self {
            case .address(let a): a.description
            case let .account(sid, name): "account:\(sid):\(name)"
            }
        }

        public init?(storageText text: String) {
            if text.hasPrefix("account:") {
                let parts = text.dropFirst("account:".count).split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2, !parts[0].isEmpty else { return nil }
                self = .account(sid: String(parts[0]), name: String(parts[1]))
            } else if let a = DNSAddress(text) {
                self = .address(a)
            } else {
                return nil
            }
        }

        public var description: String {
            switch self {
            case .address(let a): a.description
            case .account(_, let name): name
            }
        }
    }

    public var holder: Holder
    public var updated: Date

    public init(holder: Holder, updated: Date) {
        self.holder = holder
        self.updated = updated
    }

    public init(address: DNSAddress, updated: Date) {
        self.init(holder: .address(address), updated: updated)
    }

    /// The owner's address when an unsigned update registered the name.
    public var address: DNSAddress? {
        if case .address(let a) = holder { return a }
        return nil
    }
}

extension DNSZoneSource {
    public func hasStaticRecords(name: DNSName, zone: DNSName) async -> Bool { false }
    public func dynamicOwner(name: DNSName, zone: DNSName) async -> DNSRecordOwner? { nil }
    public func setDynamicOwner(_ owner: DNSRecordOwner.Holder?, name: DNSName, zone: DNSName) async throws {}
}

/// An in-memory `DNSZoneSource` for tests and for running DNS without a Store. Records given to
/// `init` (or `addStatic`) are static, those from `addDynamic` dynamic.
public actor InMemoryZoneSource: DNSZoneSource {
    private var info: DNSDomainInfo
    private var stored: [DNSName: [(record: DNSRecord, dynamic: Bool)]]
    private var owners: [DNSName: [DNSName: DNSRecordOwner]] = [:]

    public init(info: DNSDomainInfo, records: [DNSName: [DNSRecord]] = [:]) {
        self.info = info
        self.stored = records.mapValues { $0.map { ($0, false) } }
    }

    public func records(zone: DNSName) -> [DNSRecord] { (stored[zone] ?? []).map(\.record) }

    public func domainInfo() -> DNSDomainInfo { info }

    public func setDomainInfo(_ info: DNSDomainInfo) { self.info = info }

    public func addDynamic(_ record: DNSRecord, zone: DNSName) { add(record, zone: zone, dynamic: true) }

    /// An administrator's record.
    public func addStatic(_ record: DNSRecord, zone: DNSName) { add(record, zone: zone, dynamic: false) }

    private func add(_ record: DNSRecord, zone: DNSName, dynamic: Bool) {
        var list = stored[zone] ?? []
        if let i = list.firstIndex(where: { $0.record.sameData(as: record) }) {
            list[i].record = record
        } else {
            list.append((record, dynamic))
        }
        stored[zone] = list
    }

    public func removeDynamic(_ record: DNSRecord, zone: DNSName) {
        stored[zone]?.removeAll { $0.record.sameData(as: record) }
    }

    public func hasStaticRecords(name: DNSName, zone: DNSName) async -> Bool {
        (stored[zone] ?? []).contains { !$0.dynamic && $0.record.name == name }
    }

    public func dynamicOwner(name: DNSName, zone: DNSName) async -> DNSRecordOwner? { owners[zone]?[name] }

    public func setDynamicOwner(_ owner: DNSRecordOwner.Holder?, name: DNSName, zone: DNSName) async throws {
        owners[zone, default: [:]][name] = owner.map { DNSRecordOwner(holder: $0, updated: Date()) }
    }

    /// Tests: an owner with a given age.
    public func setOwnerRecord(_ owner: DNSRecordOwner?, name: DNSName, zone: DNSName) {
        owners[zone, default: [:]][name] = owner
    }
}
