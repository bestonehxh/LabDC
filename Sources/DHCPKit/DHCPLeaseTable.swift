import Foundation

/// Everything the server engines need besides the packet: the configuration snapshot.
public struct DHCPConfig: Sendable {
    public var scopes: [DHCPScope]
    public var reservations: [DHCPReservation]
    public var settings: DHCPSettings
    /// The AD DNS domain (default domain name, the zone A/AAAA records go into).
    public var domain: String
    /// The DC's IPv4 handed out as DNS/NTP server when a scope names none.
    public var dcIPv4: String?
    /// The DC's IPv6 addresses (global/ULA) for v6 DNS/NTP defaults.
    public var dcIPv6: [String]
    /// The server DUID (DUID-LLT, persisted).
    public var serverDUID: [UInt8]

    public init(scopes: [DHCPScope] = [], reservations: [DHCPReservation] = [], settings: DHCPSettings = DHCPSettings(),
                domain: String = "", dcIPv4: String? = nil, dcIPv6: [String] = [], serverDUID: [UInt8] = []) {
        self.scopes = scopes; self.reservations = reservations; self.settings = settings; self.domain = domain
        self.dcIPv4 = dcIPv4; self.dcIPv6 = dcIPv6; self.serverDUID = serverDUID
    }

    public func scope(id: Int64) -> DHCPScope? { scopes.first { $0.id == id } }

    /// Enabled scopes of `family`.
    public func active(_ family: DHCPFamily) -> [DHCPScope] { scopes.filter { $0.enabled && $0.family == family } }

    /// Whether a relayed v4 packet may use this server. With an allowed-relays list, the
    /// datagram source or giaddr must match it. Without one, the giaddr must lie inside an
    /// enabled v4 scope subnet (the relay's interface on the client VLAN) or be loopback (a
    /// relay agent on this Mac): replies go to giaddr, so an arbitrary giaddr would make LabDC
    /// reflect replies at any host, and a forged relay from anywhere could feed device profiles.
    /// A relay whose giaddr sits outside the scopes (option 82 link selection, a loopback
    /// interface on the switch) has to be listed.
    public func admitsRelay(source: IPv4Address, giaddr: IPv4Address) -> Bool {
        if !settings.allowedRelays.isEmpty { return settings.allowsRelay([source.description, giaddr.description]) }
        if giaddr.value >> 24 == 127 { return true }
        return active(.v4).contains { $0.subnetV4?.contains(giaddr) ?? false }
    }

    /// The v6 counterpart: with an allowed-relays list, the source or a link-address must match
    /// it; without one, a non-:: link-address or the relay's source must lie inside an enabled v6
    /// scope (or be loopback) — replies go back to the relay, so an arbitrary one would make
    /// LabDC reflect replies anywhere.
    public func admitsRelay(source: IPv6Address, linkAddresses: [IPv6Address]) -> Bool {
        let links = linkAddresses.filter { !$0.isZero }
        if !settings.allowedRelays.isEmpty { return settings.allowsRelay([source.description] + links.map(\.description)) }
        if source == IPv6Address("::1") { return true }
        let v6 = active(.v6)
        return ([source] + links).contains { a in v6.contains { $0.subnetV6?.contains(a) ?? false } }
    }

    /// The scope whose subnet contains `link`, plus every scope sharing its network.
    public func scopes(forLink link: IPv4Address) -> [DHCPScope] {
        let v4 = active(.v4)
        guard let first = v4.first(where: { $0.subnetV4?.contains(link) ?? false }) else { return [] }
        guard let shared = first.sharedNetwork?.trimmingCharacters(in: .whitespaces), !shared.isEmpty else { return [first] }
        return [first] + v4.filter { $0.id != first.id && $0.sharedNetwork?.trimmingCharacters(in: .whitespaces) == shared }
    }

    public func scopes(forLink link: IPv6Address) -> [DHCPScope] {
        let v6 = active(.v6)
        guard let first = v6.first(where: { $0.subnetV6?.contains(link) ?? false }) else { return [] }
        guard let shared = first.sharedNetwork?.trimmingCharacters(in: .whitespaces), !shared.isEmpty else { return [first] }
        return [first] + v6.filter { $0.id != first.id && $0.sharedNetwork?.trimmingCharacters(in: .whitespaces) == shared }
    }
}

/// The in-memory lease map (one entry per address, history included) with a client index and a
/// dirty set for the write-behind to the store.
///
/// The allocator never scans a pool address by address: the table keeps the v4 addresses that
/// have a row (sorted, so the first never-used address of a range is a binary search), each
/// scope's v4 rows ordered by when they became free (the longest-free address is the head), and
/// per-relay / circuit / MAC / DUID indexes for the caps.
public struct DHCPLeaseTable: Sendable {
    public private(set) var leases: [String: DHCPLease] = [:]
    private var byClient: [String: Set<String>] = [:]
    /// Lease ids changed since the last `takeDirty()`.
    public private(set) var dirty: Set<String> = []
    /// Lease ids removed since the last `takeDirty()`.
    public private(set) var removed: Set<String> = []

    /// One row in a scope's free-age order: when the address became (or becomes) free.
    struct AgeEntry: Comparable, Sendable {
        var at: Double
        var address: UInt32
        static func < (a: AgeEntry, b: AgeEntry) -> Bool { a.at != b.at ? a.at < b.at : a.address < b.address }
    }

    /// v4 addresses with a row, ascending.
    private var v4Used: [UInt32] = []
    /// Per scope id: its v4 rows by `freeSince`, oldest first.
    private var v4ByAge: [Int64: [AgeEntry]] = [:]
    /// Secondary indexes (`family/key` → lease ids).
    private var byRelay: [String: Set<String>] = [:]
    private var byCircuit: [String: Set<String>] = [:]
    private var byMAC: [String: Set<String>] = [:]
    private var byDUID: [String: Set<String>] = [:]
    /// Rows in state `foreign`, per scope id.
    private var foreignRows: [Int64: Int] = [:]

    public init(_ leases: [DHCPLease] = []) {
        for l in leases {
            if let old = self.leases[l.id] { unindex(old, bulk: true) }
            self.leases[l.id] = l
            index(l, bulk: true)
        }
        v4Used.sort()
        for k in v4ByAge.keys { v4ByAge[k]!.sort() }
        dirty = []
    }

    /// When the lease's address is (or will be) free: the expiry for holding states, else the
    /// last change.
    static func freeSince(_ l: DHCPLease) -> Double {
        (l.state.holdsAddress ? l.expires : l.updated).timeIntervalSinceReferenceDate
    }

    private static func lowerBound<T: Comparable>(_ a: [T], _ v: T) -> Int {
        var lo = 0, hi = a.count
        while lo < hi { let mid = (lo + hi) / 2; if a[mid] < v { lo = mid + 1 } else { hi = mid } }
        return lo
    }

    private static func sortedInsert<T: Comparable>(_ a: inout [T], _ v: T) {
        let i = lowerBound(a, v)
        if i < a.count, a[i] == v { return }
        a.insert(v, at: i)
    }

    private static func sortedRemove<T: Comparable>(_ a: inout [T], _ v: T) {
        let i = lowerBound(a, v)
        if i < a.count, a[i] == v { a.remove(at: i) }
    }

    private static func add(_ d: inout [String: Set<String>], _ key: String?, _ id: String) {
        guard let key else { return }
        d[key, default: []].insert(id)
    }

    private static func drop(_ d: inout [String: Set<String>], _ key: String?, _ id: String) {
        guard let key else { return }
        d[key]?.remove(id)
        if d[key]?.isEmpty == true { d[key] = nil }
    }

    private static func k(_ family: DHCPFamily, _ v: String?) -> String? {
        guard let v, !v.isEmpty else { return nil }
        return "\(family.rawValue)/\(v.lowercased())"
    }

    private mutating func index(_ l: DHCPLease, bulk: Bool) {
        byClient[l.clientKey, default: []].insert(l.id)
        Self.add(&byRelay, Self.k(l.family, l.relay), l.id)
        Self.add(&byCircuit, Self.k(l.family, l.circuitID), l.id)
        Self.add(&byMAC, Self.k(l.family, l.mac), l.id)
        Self.add(&byDUID, Self.k(l.family, l.duid), l.id)
        if l.state == .foreign { foreignRows[l.scopeID, default: 0] += 1 }
        guard l.family == .v4, let a = IPv4Address(l.address)?.value else { return }
        let e = AgeEntry(at: Self.freeSince(l), address: a)
        if bulk {
            v4Used.append(a)
            v4ByAge[l.scopeID, default: []].append(e)
        } else {
            Self.sortedInsert(&v4Used, a)
            Self.sortedInsert(&v4ByAge[l.scopeID, default: []], e)
        }
    }

    private mutating func unindex(_ l: DHCPLease, bulk: Bool = false) {
        Self.drop(&byClient, l.clientKey, l.id)
        Self.drop(&byRelay, Self.k(l.family, l.relay), l.id)
        Self.drop(&byCircuit, Self.k(l.family, l.circuitID), l.id)
        Self.drop(&byMAC, Self.k(l.family, l.mac), l.id)
        Self.drop(&byDUID, Self.k(l.family, l.duid), l.id)
        if l.state == .foreign {
            let n = (foreignRows[l.scopeID] ?? 0) - 1
            foreignRows[l.scopeID] = n > 0 ? n : nil
        }
        guard l.family == .v4, let a = IPv4Address(l.address)?.value else { return }
        let e = AgeEntry(at: Self.freeSince(l), address: a)
        if bulk {
            // A duplicate id in the bulk load: the arrays are still unsorted.
            if let i = v4Used.lastIndex(of: a) { v4Used.remove(at: i) }
            if let i = v4ByAge[l.scopeID]?.lastIndex(of: e) { v4ByAge[l.scopeID]!.remove(at: i) }
            return
        }
        Self.sortedRemove(&v4Used, a)
        if v4ByAge[l.scopeID] != nil {
            Self.sortedRemove(&v4ByAge[l.scopeID]!, e)
            if v4ByAge[l.scopeID]!.isEmpty { v4ByAge[l.scopeID] = nil }
        }
    }

    private mutating func insert(_ lease: DHCPLease) {
        if let old = leases[lease.id] { unindex(old) }
        leases[lease.id] = lease
        index(lease, bulk: false)
    }

    public static func key(_ family: DHCPFamily, _ address: String) -> String { "\(family.rawValue)/\(address)" }

    public func lease(_ family: DHCPFamily, _ address: String) -> DHCPLease? { leases[Self.key(family, address)] }

    public func leases(client: String) -> [DHCPLease] {
        (byClient[client] ?? []).compactMap { leases[$0] }.sorted { $0.updated > $1.updated }
    }

    public var all: [DHCPLease] { Array(leases.values) }

    // MARK: Allocation indexes

    /// The first v4 address in `lo`…`hi` that has no row at all (never used): a binary search
    /// over the sorted used addresses.
    public func firstUnusedV4(from lo: UInt32, through hi: UInt32) -> UInt32? {
        guard lo <= hi else { return nil }
        let a = Self.lowerBound(v4Used, lo)
        var b = Self.lowerBound(v4Used, hi)
        if b < v4Used.count, v4Used[b] == hi { b += 1 }
        // In [a, b) the values are strictly increasing inside lo…hi, so "v4Used[a+i] > lo+i" is
        // monotonic in i and its first true i is the first gap.
        var l = 0, h = b - a
        while l < h {
            let mid = (l + h) / 2
            if UInt64(v4Used[a + mid]) > UInt64(lo) + UInt64(mid) { h = mid } else { l = mid + 1 }
        }
        let cand = UInt64(lo) + UInt64(l)
        return cand <= UInt64(hi) ? UInt32(cand) : nil
    }

    /// Scope `scope`'s v4 rows that are free at `now`, longest-free first, at most `limit`.
    public func freeV4ByAge(scope: Int64, now: Date, limit: Int) -> [(address: UInt32, since: Date)] {
        guard let list = v4ByAge[scope] else { return [] }
        let t = now.timeIntervalSinceReferenceDate
        var out: [(address: UInt32, since: Date)] = []
        // A row still holding its address sorts at its expiry, after every free one.
        for e in list {
            if e.at > t || out.count >= limit { break }
            out.append((e.address, Date(timeIntervalSinceReferenceDate: e.at)))
        }
        return out
    }

    /// Scope ids that have v4 rows (orphans of deleted scopes included).
    public var v4ScopeIDs: [Int64] { Array(v4ByAge.keys) }

    /// Rows in state `foreign` for `scope` (until the sweeper ends them).
    public func foreignCount(scope: Int64) -> Int { foreignRows[scope] ?? 0 }

    private func rows(_ d: [String: Set<String>], _ family: DHCPFamily, _ key: String?) -> [DHCPLease] {
        guard let k = Self.k(family, key), let ids = d[k] else { return [] }
        return ids.compactMap { leases[$0] }
    }

    public func leases(relay: String, family: DHCPFamily) -> [DHCPLease] { rows(byRelay, family, relay) }
    public func leases(circuit: String, family: DHCPFamily) -> [DHCPLease] { rows(byCircuit, family, circuit) }
    public func leases(mac: String, family: DHCPFamily) -> [DHCPLease] { rows(byMAC, family, mac) }
    public func leases(duid: String) -> [DHCPLease] { rows(byDUID, .v6, duid) }

    /// How many of `rows` hold their address at `now`, counted up to `limit` (a cap only needs
    /// to know whether it is reached).
    public static func holding(_ rows: [DHCPLease], now: Date, limit: Int, includeForeign: Bool,
                               excludingClient: String? = nil) -> Int {
        var n = 0
        for l in rows where l.holds(at: now) && (includeForeign || l.state != .foreign) && l.clientKey != excludingClient {
            n += 1
            if n >= limit { break }
        }
        return n
    }

    /// Stores (or replaces) a lease and marks it for the write-behind (offers are kept in memory only).
    public mutating func put(_ lease: DHCPLease) {
        insert(lease)
        removed.remove(lease.id)
        dirty.insert(lease.id)
    }

    public mutating func remove(_ id: String) {
        guard let old = leases.removeValue(forKey: id) else { return }
        unindex(old)
        dirty.remove(id)
        removed.insert(id)
    }

    /// The changed leases (offers excluded — they live a minute and are never persisted) and the
    /// removed ids; clears both sets.
    public mutating func takeDirty() -> (changed: [DHCPLease], removed: [String]) {
        let changed = dirty.compactMap { leases[$0] }.filter { $0.state != .offered }
        let gone = Array(removed)
        dirty = []
        removed = []
        return (changed, gone)
    }

    /// A write-behind that failed: its ids become dirty again, so the next flush writes the
    /// leases as they are then — never the snapshot that failed, which a packet handled during
    /// the failed save may already have superseded. An id changed since is dirty anyway; one
    /// removed since stays removed (and vice versa).
    public mutating func requeue(changed: [String], removed gone: [String]) {
        for id in changed where leases[id] != nil && !removed.contains(id) { dirty.insert(id) }
        for id in gone where leases[id] == nil { removed.insert(id) }
    }

    /// Whether `address` is held by someone other than `client` at `now`.
    public func heldByOther(_ family: DHCPFamily, _ address: String, client: String, now: Date) -> Bool {
        guard let l = lease(family, address) else { return false }
        return l.holds(at: now) && (l.clientKey != client || l.state == .foreign || l.state == .declined || l.state == .abandoned)
    }

    /// Ages leases: lapsed offers and active leases past expiry become `expired`, quarantines
    /// end. Returns the leases that just expired from `active` (their DNS records go).
    public mutating func sweep(now: Date) -> [DHCPLease] {
        var expired: [DHCPLease] = []
        for l in leases.values where l.expires <= now {
            switch l.state {
            case .offered:
                var e = l; e.state = .expired; e.updated = now
                put(e)
            case .active:
                var e = l; e.state = .expired; e.updated = now
                put(e)
                expired.append(e)
            case .declined, .abandoned, .foreign:
                // The quarantine / foreign hold ended: the row stays as history only.
                var e = l; e.state = .expired; e.updated = now
                put(e)
            case .released, .expired:
                continue
            }
        }
        return expired
    }

    /// Drops history rows (released/expired) last touched before `cutoff`.
    public mutating func prune(before cutoff: Date) -> Int {
        let old = leases.values.filter { ($0.state == .released || $0.state == .expired) && $0.updated < cutoff }.map(\.id)
        for id in old { remove(id) }
        return old.count
    }

    /// Active leases per scope (utilisation).
    public func activeCount(scope: Int64, now: Date) -> Int {
        leases.values.filter { $0.scopeID == scope && $0.state == .active && $0.expires > now }.count
    }
}

/// Counter names the engines bump (applied by the server to its per-scope counters).
public enum DHCPCounterKey: Sendable, Equatable {
    case discover, offer, request, ack, nak, decline, release, inform
    case solicit, advertise, reply, renew
    case ignoredLocal, droppedRelay, foreignSeen, noScope, capped

    public func apply(_ c: inout DHCPCounters) {
        switch self {
        case .discover: c.discover += 1
        case .offer: c.offer += 1
        case .request: c.request += 1
        case .ack: c.ack += 1
        case .nak: c.nak += 1
        case .decline: c.decline += 1
        case .release: c.release += 1
        case .inform: c.inform += 1
        case .solicit: c.solicit += 1
        case .advertise: c.advertise += 1
        case .reply: c.reply += 1
        case .renew: c.renew += 1
        case .ignoredLocal: c.ignoredLocal += 1
        case .droppedRelay: c.droppedRelay += 1
        case .foreignSeen: c.foreignSeen += 1
        case .noScope: c.noScope += 1
        case .capped: c.capped += 1
        }
    }
}

/// A DNS change the server should make for a lease (it runs after the reply is sent).
public struct DHCPDNSAction: Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case register, unregister }

    public var kind: Kind
    public var lease: DHCPLease
    /// The FQDN to register (register only).
    public var fqdn: String?
    /// Write A/AAAA (+DHCID); false = PTR only (the client does its own A).
    public var forward: Bool
    public var ptr: Bool
    public var identifierType: DHCPDNS.IdentifierType
    public var identifier: [UInt8]

    public init(kind: Kind, lease: DHCPLease, fqdn: String?, forward: Bool, ptr: Bool,
                identifierType: DHCPDNS.IdentifierType, identifier: [UInt8]) {
        self.kind = kind; self.lease = lease; self.fqdn = fqdn; self.forward = forward; self.ptr = ptr
        self.identifierType = identifierType; self.identifier = identifier
    }
}

/// What a client message did, for the server to act on.
public struct DHCPCommonOutcome: Sendable {
    /// One Activity line (the exchanges people care about: ACK, NAK, DECLINE, RELEASE, …).
    public var line: String?
    /// A diagnostic that floods could repeat (drops, ignored locals): logged rate-limited by key.
    public var quiet: (key: String, text: String)?
    public var events: [DHCPEvent] = []
    public var dns: [DHCPDNSAction] = []
    public var counters: [DHCPCounterKey] = []
    /// The scope the counters belong to (nil = server-wide).
    public var scopeID: Int64?
    /// The client's fingerprint and the profile it gives (MAC-keyed device profile).
    public var profile: (mac: String, fingerprint: DHCPFingerprint, result: DeviceClassifier.Result, hostname: String?)?
    /// Copy the client message to the profilers.
    public var forwardToProfilers = false
    /// Wait before sending (per-scope offer delay).
    public var delayMs = 0
    /// Ping this address before the offer goes out (ping-before-offer).
    public var pingAddress: String?

    public init() {}
}
