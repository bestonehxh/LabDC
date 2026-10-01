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

    public init(dnsDomain: DNSName, dcHostName: DNSName, domainGUID: UUID, dsaGUID: UUID? = nil,
                site: String = "Default-First-Site-Name", addresses: [DNSAddress], formerHostNames: [DNSName] = []) {
        self.dnsDomain = dnsDomain
        self.dcHostName = dcHostName
        self.domainGUID = domainGUID
        self.dsaGUID = dsaGUID
        self.site = site
        self.addresses = addresses
        self.formerHostNames = formerHostNames
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
    public var servedZones: [DNSName] { zones + formerHostZones }
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
}

/// An in-memory `DNSZoneSource` for tests and for running DNS without a Store.
public actor InMemoryZoneSource: DNSZoneSource {
    private var info: DNSDomainInfo
    private var stored: [DNSName: [DNSRecord]]

    public init(info: DNSDomainInfo, records: [DNSName: [DNSRecord]] = [:]) {
        self.info = info
        self.stored = records
    }

    public func records(zone: DNSName) -> [DNSRecord] { stored[zone] ?? [] }

    public func domainInfo() -> DNSDomainInfo { info }

    public func setDomainInfo(_ info: DNSDomainInfo) { self.info = info }

    public func addDynamic(_ record: DNSRecord, zone: DNSName) {
        var list = stored[zone] ?? []
        if let i = list.firstIndex(where: { $0.sameData(as: record) }) {
            list[i] = record
        } else {
            list.append(record)
        }
        stored[zone] = list
    }

    public func removeDynamic(_ record: DNSRecord, zone: DNSName) {
        stored[zone]?.removeAll { $0.sameData(as: record) }
    }
}
