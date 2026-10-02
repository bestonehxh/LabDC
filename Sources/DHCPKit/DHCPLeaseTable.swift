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
public struct DHCPLeaseTable: Sendable {
    public private(set) var leases: [String: DHCPLease] = [:]
    private var byClient: [String: Set<String>] = [:]
    /// Lease ids changed since the last `takeDirty()`.
    public private(set) var dirty: Set<String> = []
    /// Lease ids removed since the last `takeDirty()`.
    public private(set) var removed: Set<String> = []

    public init(_ leases: [DHCPLease] = []) {
        for l in leases { insert(l) }
        dirty = []
    }

    private mutating func insert(_ lease: DHCPLease) {
        if let old = leases[lease.id], old.clientKey != lease.clientKey {
            byClient[old.clientKey]?.remove(lease.id)
            if byClient[old.clientKey]?.isEmpty == true { byClient[old.clientKey] = nil }
        }
        leases[lease.id] = lease
        byClient[lease.clientKey, default: []].insert(lease.id)
    }

    public static func key(_ family: DHCPFamily, _ address: String) -> String { "\(family.rawValue)/\(address)" }

    public func lease(_ family: DHCPFamily, _ address: String) -> DHCPLease? { leases[Self.key(family, address)] }

    public func leases(client: String) -> [DHCPLease] {
        (byClient[client] ?? []).compactMap { leases[$0] }.sorted { $0.updated > $1.updated }
    }

    public var all: [DHCPLease] { Array(leases.values) }

    /// Stores (or replaces) a lease and marks it for the write-behind (offers are kept in memory only).
    public mutating func put(_ lease: DHCPLease) {
        insert(lease)
        removed.remove(lease.id)
        dirty.insert(lease.id)
    }

    public mutating func remove(_ id: String) {
        guard let old = leases.removeValue(forKey: id) else { return }
        byClient[old.clientKey]?.remove(id)
        if byClient[old.clientKey]?.isEmpty == true { byClient[old.clientKey] = nil }
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
