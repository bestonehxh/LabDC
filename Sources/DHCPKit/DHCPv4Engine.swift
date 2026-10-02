import Foundation

/// How a v4 datagram reached the server (from `recvmsg`).
public struct DHCPv4Arrival: Sendable {
    public var source: IPv4Address
    public var sourcePort: UInt16
    /// The destination address (`IP_RECVDSTADDR`); nil when unknown.
    public var destination: IPv4Address?
    /// The receiving interface (`IP_RECVIF`) and this Mac's address/subnet on it.
    public var interfaceName: String?
    public var interfaceAddress: IPv4Address?
    public var interfaceSubnet: IPv4Subnet?
    /// The server identifier to hand out: the settings' address, else this Mac's address toward
    /// the relay (or on the interface).
    public var serverAddress: IPv4Address
    /// Every IPv4 address of this Mac (option 54 "is it us?").
    public var localAddresses: Set<IPv4Address>

    public init(source: IPv4Address, sourcePort: UInt16 = 67, destination: IPv4Address? = nil, interfaceName: String? = nil,
                interfaceAddress: IPv4Address? = nil, interfaceSubnet: IPv4Subnet? = nil, serverAddress: IPv4Address,
                localAddresses: Set<IPv4Address> = []) {
        self.source = source; self.sourcePort = sourcePort; self.destination = destination
        self.interfaceName = interfaceName; self.interfaceAddress = interfaceAddress; self.interfaceSubnet = interfaceSubnet
        self.serverAddress = serverAddress; self.localAddresses = localAddresses
    }

    /// Arrived as a broadcast (limited or the interface's directed broadcast). An unknown
    /// destination counts as broadcast: never answer what might be a local broadcast.
    public var isBroadcast: Bool {
        guard let d = destination else { return true }
        return d == .broadcast || d == interfaceSubnet?.broadcast || d.value >> 28 == 0xE
    }
}

public struct DHCPv4Outcome: Sendable {
    public enum Destination: Sendable, Equatable {
        case none
        /// Relay agent: `giaddr`, port 67 or (RFC 8357) the port the relay sent from.
        case relay(IPv4Address, UInt16)
        /// 255.255.255.255:68 out of the named interface (direct mode, `ciaddr` = 0).
        case broadcast(String?)
        /// A client that has an address: `ciaddr`:68.
        case unicast(IPv4Address, UInt16)
    }

    public var reply: DHCPv4Packet?
    public var destination: Destination = .none
    public var common = DHCPCommonOutcome()

    public init() {}
}

/// The DHCPv4 server state machine (RFC 2131 §4.3), pure: packet + arrival + config + lease
/// table in, reply + effects out. Coexists with a production server: relay-only unless the
/// interface is opted in, never NAKs a client it knows nothing about, marks addresses a client
/// requested from another server as foreign.
public enum DHCPv4Engine {
    public static func handle(_ p: DHCPv4Packet, arrival: DHCPv4Arrival, config: DHCPConfig,
                              leases: inout DHCPLeaseTable, now: Date) -> DHCPv4Outcome {
        var out = DHCPv4Outcome()
        guard p.op == 1, let type = p.messageType else {
            out.common.quiet = ("not-request \(arrival.source)", "DHCP datagram from \(arrival.source) is not a client request, dropped")
            return out
        }
        guard [.discover, .request, .decline, .release, .inform].contains(type) else {
            out.common.quiet = ("server-msg \(arrival.source)", "DHCP \(type) from \(arrival.source) (a server message on the server port), dropped")
            return out
        }
        let relayed = !p.giaddr.isZero
        let agent = p.relayAgentInformation
        let settings = config.settings
        let who = p.mac ?? DHCPHex.string(p.hardwareAddress)

        // 1. How it arrived: relayed, direct broadcast on an opted-in interface, or unicast from a lease holder.
        var scopes: [DHCPScope] = []
        var linkText = ""
        let clientKey = Self.clientKey(p)
        if relayed {
            guard config.admitsRelay(source: arrival.source, giaddr: p.giaddr) else {
                out.common.counters = [.droppedRelay]
                let why = settings.allowedRelays.isEmpty
                    ? "giaddr outside every scope subnet (list the relay under allowed relays)" : "not an allowed relay"
                out.common.quiet = ("relay \(arrival.source)", "DHCP \(type) via relay \(arrival.source) (giaddr \(p.giaddr)) dropped: \(why)")
                return out
            }
            guard p.hops <= 16 else {
                out.common.quiet = ("hops \(arrival.source)", "DHCP \(type) via \(arrival.source) dropped: \(p.hops) relay hops")
                return out
            }
            // RFC 3527 / Cisco 150 link selection → RFC 3011 option 118 → giaddr.
            let link = agent?.linkSelectionAddress ?? p.address(DHCPv4OptionCode.subnetSelection) ?? p.giaddr
            scopes = config.scopes(forLink: link)
            linkText = link == p.giaddr ? "giaddr \(link)" : "link \(link)"
        } else if arrival.isBroadcast {
            guard let ifname = arrival.interfaceName, settings.directInterfaces.contains(ifname), let ifaddr = arrival.interfaceAddress else {
                out.common.counters = [.ignoredLocal]
                out.common.quiet = ("local", "DHCP \(type) from \(who) on the local segment ignored (relay-only)")
                return out
            }
            scopes = config.scopes(forLink: ifaddr)
            linkText = "direct on \(ifname)"
        } else {
            // Unicast from a client: only RENEW/RELEASE/INFORM/DECLINE from one of our lease holders.
            let addr = p.ciaddr.isZero ? arrival.source : p.ciaddr
            if let l = leases.lease(.v4, addr.description), l.clientKey == clientKey,
               [.active, .expired, .released, .offered].contains(l.state), let s = config.scope(id: l.scopeID), s.enabled {
                scopes = [s]
                linkText = "unicast from \(addr)"
            } else {
                out.common.counters = [.ignoredLocal]
                out.common.quiet = ("unicast \(addr)", "DHCP \(type) unicast from \(addr) (\(who)) ignored: no lease here")
                return out
            }
        }
        guard let primary = scopes.first else {
            out.common.counters = [.noScope]
            out.common.quiet = ("noscope \(linkText)", "DHCP \(type) from \(who) (\(linkText)) dropped: no scope for that link")
            return out
        }
        out.common.scopeID = primary.id
        if relayed, type != .release, type != .decline { out.common.forwardToProfilers = true }
        if !relayed, arrival.isBroadcast, [.discover, .request, .inform].contains(type) { out.common.forwardToProfilers = true }

        // Server identifier: RFC 5107 override from the relay, else ours.
        let serverID = agent?.serverIDOverride ?? arrival.serverAddress
        var ours = arrival.localAddresses
        ours.insert(arrival.serverAddress)
        ours.insert(serverID)
        if let s = settings.serverAddress.flatMap(IPv4Address.init) { ours.insert(s) }

        // Fingerprint + profile on every client message that carries one.
        if [.discover, .request, .inform].contains(type), let mac = p.mac {
            let fp = DHCPFingerprint(v4: p)
            out.common.profile = (mac, fp, DeviceClassifier.classify(fp), p.hostName ?? p.clientFQDN?.name)
        }

        let ctx = Context(p: p, arrival: arrival, config: config, scopes: scopes, linkText: linkText, clientKey: clientKey,
                          serverID: serverID, ours: ours, now: now, relayed: relayed)
        switch type {
        case .discover: discover(ctx, &leases, &out)
        case .request: request(ctx, &leases, &out)
        case .decline: decline(ctx, &leases, &out)
        case .release: release(ctx, &leases, &out)
        case .inform: inform(ctx, &leases, &out)
        default: break
        }
        return out
    }

    /// Identity = client-id (61) else htype + chaddr (spec rev 2).
    public static func clientKey(_ p: DHCPv4Packet) -> String {
        if let id = p.clientIdentifier { return "id:" + DHCPHex.string(id) }
        return "hw:\(p.htype):" + DHCPHex.string(p.hardwareAddress)
    }

    struct Context {
        let p: DHCPv4Packet
        let arrival: DHCPv4Arrival
        let config: DHCPConfig
        let scopes: [DHCPScope]
        let linkText: String
        let clientKey: String
        let serverID: IPv4Address
        let ours: Set<IPv4Address>
        let now: Date
        let relayed: Bool

        var who: String {
            let id = p.mac ?? DHCPHex.string(p.hardwareAddress)
            let name = p.hostName ?? p.clientFQDN?.name
            return name.map { "\(id) (\($0))" } ?? id
        }

        var via: String { relayed ? "via relay \(arrival.source)" : linkText }

        func scope(containing a: IPv4Address) -> DHCPScope? { scopes.first { $0.subnetV4?.contains(a) ?? false } }

        func reservation() -> DHCPReservation? {
            let ids = Set(scopes.map(\.id))
            let agent = p.relayAgentInformation
            let mac = p.mac
            let cid = p.clientIdentifier.map(DHCPHex.string)
            return config.reservations.first { r in
                guard r.enabled, ids.contains(r.scopeID) else { return false }
                if let m = r.mac, let mac, m == mac { return true }
                if let c = r.clientID, let cid, c.lowercased() == cid { return true }
                if let c = r.circuitID, let circuit = agent?.circuit, CircuitIDDecoder.matches(c, circuit) { return true }
                if let rid = r.remoteID, let remote = agent?.remote, CircuitIDDecoder.matches(rid, remote) { return true }
                return false
            }
        }

        func policy(in scope: DHCPScope) -> DHCPClassPolicy? {
            scope.classPolicies.first { $0.matches(vendorClass: p.vendorClass, userClass: p.userClass) }
        }
    }

    // MARK: DISCOVER

    static func discover(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        out.common.counters.append(.discover)
        guard let picked = allocate(c, &leases, out: &out) else { return }
        let (address, scope, reservation, _) = picked
        var lease = leases.lease(.v4, address.description)
        let fresh = lease?.clientKey != c.clientKey || lease.map { !$0.holds(at: c.now) && $0.state != .released && $0.state != .expired } ?? true
        if lease == nil || lease?.clientKey != c.clientKey {
            lease = DHCPLease(family: .v4, address: address.description, scopeID: scope.id, state: .offered, clientKey: c.clientKey,
                              start: c.now, expires: c.now)
        }
        guard var l = lease else { return }
        let wasActive = l.state == .active && l.expires > c.now
        if !wasActive {
            l.state = .offered
            l.expires = c.now.addingTimeInterval(TimeInterval(c.config.settings.offerHoldSeconds))
        }
        fill(&l, c, scope: scope, reservation: reservation)
        leases.put(l)
        var reply = baseReply(c, type: .offer, yiaddr: address)
        addLeaseOptions(&reply, c, scope: scope, reservation: reservation, leaseSeconds: leaseSeconds(c, scope))
        addConfigOptions(&reply, c, scope: scope, reservation: reservation)
        addFQDNReply(&reply, c, scope: scope)
        fit(&reply, c)
        out.reply = reply
        out.destination = destination(c, nak: false)
        out.common.counters.append(.offer)
        out.common.delayMs = scope.offerDelayMs
        if scope.pingBeforeOffer, reservation == nil, !wasActive, fresh { out.common.pingAddress = address.description }
    }

    /// Picks an address: reservation → the client's own lease → option 50 → the first never-used
    /// address → the longest-free one. Nil (with a quiet line) when nothing fits.
    static func allocate(_ c: Context, _ leases: inout DHCPLeaseTable, out: inout DHCPv4Outcome)
        -> (IPv4Address, DHCPScope, DHCPReservation?, String)? {
        if let r = c.reservation(), let a = IPv4Address(r.address), let scope = c.config.scope(id: r.scopeID) {
            if leases.heldByOther(.v4, r.address, client: c.clientKey, now: c.now) {
                let other = leases.lease(.v4, r.address)
                out.common.quiet = ("resv-held \(r.address)", "DHCP reservation \(r.name) (\(r.address)) is held by "
                                    + "\(other?.state == .foreign ? "another server's client" : other?.whoText ?? "another client"); no offer to \(c.who)")
                return nil
            }
            return (a, scope, r, "reservation")
        }
        guard !c.scopes.allSatisfy(\.knownClientsOnly) else {
            out.common.quiet = ("unknown \(c.clientKey)", "DHCP DISCOVER from \(c.who) \(c.via): known clients only, no reservation, no offer")
            return nil
        }
        let open = c.scopes.filter { !$0.knownClientsOnly }
        let reserved = Set(c.config.reservations.filter { $0.enabled }.map(\.address))

        // The client's own current or recent lease.
        for l in leases.leases(client: c.clientKey) where l.family == .v4 && l.state != .foreign && l.state != .declined && l.state != .abandoned {
            guard let a = IPv4Address(l.address), let s = open.first(where: { $0.id == l.scopeID || $0.subnetV4?.contains(a) == true }),
                  s.isAssignable(l.address), !reserved.contains(l.address),
                  !leases.heldByOther(.v4, l.address, client: c.clientKey, now: c.now) else { continue }
            if let pol = c.policy(in: s), !pol.ranges.isEmpty, !pol.ranges.contains(where: { $0.v4?.contains(a) ?? false }) { continue }
            return (a, s, nil, "own lease")
        }

        // New allocations are capped per relay and per circuit, and client-id churn per MAC.
        if let why = capReason(c, leases, includeForeign: false) {
            out.common.counters.append(.capped)
            out.common.quiet = (why.key, "\(why.text); no offer to \(c.who)")
            return nil
        }

        // Each open scope parsed once: subnet, ranges (policy ranges where they apply),
        // exclusions and routers as integers.
        let pools = open.compactMap { Pool($0, policy: c.policy(in: $0)) }
        let reservedV4 = Set(reserved.compactMap { IPv4Address($0)?.value })
        func free(_ v: UInt32, _ pool: Pool) -> Bool {
            pool.allows(v) && !reservedV4.contains(v)
                && !(leases.lease(.v4, IPv4Address(v).description).map { $0.holds(at: c.now) } ?? false)
        }

        // Option 50, when it is free in one of our ranges.
        if let req = c.p.requestedAddress, let pool = pools.first(where: { $0.subnet.contains(req) }), free(req.value, pool) {
            return (req, pool.scope, nil, "requested")
        }

        // Never-used first: a binary search per range for the first address without a row,
        // skipping exclusions, routers, reservations and network/broadcast.
        for pool in pools {
            for span in pool.search {
                var v = span.lowerBound
                var probes = 0
                while probes < Self.maxProbes, let u = leases.firstUnusedV4(from: v, through: span.upperBound) {
                    if pool.allows(u), !reservedV4.contains(u) { return (IPv4Address(u), pool.scope, nil, "new") }
                    probes += 1
                    guard let next = pool.next(after: u), next <= span.upperBound else { break }
                    v = next
                }
            }
        }

        // Else the address free the longest: the head of each scope's free-age order (orphan
        // rows of deleted scopes too), a bounded number of candidates per scope.
        var oldest: (IPv4Address, DHCPScope, Date)?
        let known = Set(c.config.scopes.map(\.id))
        let orphans = leases.v4ScopeIDs.filter { !known.contains($0) }
        for pool in pools {
            for sid in [pool.scope.id] + orphans {
                for (v, since) in leases.freeV4ByAge(scope: sid, now: c.now, limit: Self.maxProbes) {
                    if let o = oldest, o.2 <= since { break }
                    if pool.subnet.contains(IPv4Address(v)), free(v, pool) {
                        oldest = (IPv4Address(v), pool.scope, since)
                        break
                    }
                }
            }
        }
        if let oldest { return (oldest.0, oldest.1, nil, "reused") }
        out.common.quiet = ("full \(c.scopes.first?.id ?? 0)", "DHCP: no free address in \(c.scopes.map(\.name).joined(separator: ", ")) for \(c.who)")
        return nil
    }

    /// Candidates the allocator looks at per range / scope before giving up.
    static let maxProbes = 1024

    /// A scope's pool as integers, parsed once per message.
    struct Pool {
        let scope: DHCPScope
        let subnet: IPv4Subnet
        /// The scope's ranges.
        let ranges: [ClosedRange<UInt32>]
        /// Where to look: the class policy's ranges when it has any, else the scope's.
        let search: [ClosedRange<UInt32>]
        let exclusions: [ClosedRange<UInt32>]
        let routers: Set<UInt32>

        init?(_ scope: DHCPScope, policy: DHCPClassPolicy?) {
            guard let subnet = scope.subnetV4 else { return nil }
            self.scope = scope
            self.subnet = subnet
            func ints(_ r: [DHCPRange]) -> [ClosedRange<UInt32>] {
                r.compactMap { $0.v4.map { $0.lowerBound.value...$0.upperBound.value } }.sorted { $0.lowerBound < $1.lowerBound }
            }
            ranges = ints(scope.ranges)
            let pr = ints(policy?.ranges ?? [])
            search = pr.isEmpty ? ranges : pr
            exclusions = ints(scope.exclusions)
            routers = Set(scope.routers.compactMap { IPv4Address($0)?.value })
        }

        /// `DHCPScope.isAssignable` plus the policy's ranges, without parsing strings.
        func allows(_ v: UInt32) -> Bool {
            let a = IPv4Address(v)
            guard subnet.isHost(a), !routers.contains(v) else { return false }
            guard ranges.contains(where: { $0.contains(v) }), search.contains(where: { $0.contains(v) }) else { return false }
            return !exclusions.contains { $0.contains(v) }
        }

        /// The next address worth trying after `v`: past an exclusion that holds it, else into
        /// the next scope range when `v` is outside them, else `v + 1`.
        func next(after v: UInt32) -> UInt32? {
            if let ex = exclusions.first(where: { $0.contains(v) }) {
                return ex.upperBound == .max ? nil : ex.upperBound + 1
            }
            if !ranges.contains(where: { $0.contains(v) }) {
                return ranges.first(where: { $0.lowerBound > v })?.lowerBound
            }
            return v == .max ? nil : v + 1
        }
    }

    /// The per-relay / per-circuit / client-id churn caps, nil when none is reached. Offers and
    /// leases count; `includeForeign` counts rows marked from other servers' REQUESTs too.
    static func capReason(_ c: Context, _ leases: DHCPLeaseTable, includeForeign: Bool) -> (key: String, text: String)? {
        let settings = c.config.settings
        if settings.maxLeasesPerRelay > 0, c.relayed {
            let rows = leases.leases(relay: c.arrival.source.description, family: .v4)
            let n = DHCPLeaseTable.holding(rows, now: c.now, limit: settings.maxLeasesPerRelay, includeForeign: includeForeign)
            if n >= settings.maxLeasesPerRelay {
                return ("cap relay \(c.arrival.source)", "DHCP: relay \(c.arrival.source) has \(n) leases (cap \(settings.maxLeasesPerRelay))")
            }
        }
        if settings.maxLeasesPerCircuit > 0, let circuit = c.p.relayAgentInformation?.circuit {
            let hex = DHCPHex.string(circuit)
            let n = DHCPLeaseTable.holding(leases.leases(circuit: hex, family: .v4), now: c.now, limit: settings.maxLeasesPerCircuit,
                                           includeForeign: includeForeign)
            if n >= settings.maxLeasesPerCircuit {
                return ("cap circuit \(hex)", "DHCP: circuit \(CircuitIDDecoder.describe(circuit)) has \(n) leases (cap \(settings.maxLeasesPerCircuit))")
            }
        }
        if settings.clientIDChurnLimit > 0, let mac = c.p.mac {
            let hourAgo = c.now.addingTimeInterval(-3600)
            let keys = Set(leases.leases(mac: mac, family: .v4).filter { $0.updated > hourAgo }.map(\.clientKey) + [c.clientKey])
            if keys.count > settings.clientIDChurnLimit {
                return ("churn \(mac)", "DHCP: \(mac) used \(keys.count) client identifiers in an hour (cap \(settings.clientIDChurnLimit))")
            }
        }
        return nil
    }

    // MARK: REQUEST

    static func request(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        out.common.counters.append(.request)
        let p = c.p
        if let sid = p.serverIdentifier {
            // SELECTING.
            guard c.ours.contains(sid) else {
                foreignRequest(c, sid, &leases, &out)
                return
            }
            guard let req = p.requestedAddress, var l = leases.lease(.v4, req.description), l.clientKey == c.clientKey,
                  l.state == .offered || (l.state == .active && l.expires > c.now) else {
                nak(c, "the address it asks for (\(p.requestedAddress?.description ?? "none")) was not offered to it", &out)
                return
            }
            ack(c, &l, &leases, &out)
            return
        }
        if p.ciaddr.isZero {
            // INIT-REBOOT: option 50 must be the client's own lease on this link.
            guard let req = p.requestedAddress else {
                out.common.quiet = ("badreq \(c.clientKey)", "DHCP REQUEST from \(c.who) without server id, ciaddr or option 50, dropped")
                return
            }
            guard let scope = c.scope(containing: req) else {
                if c.scopes.contains(where: \.authoritative) { nak(c, "\(req) is not on this link", &out) }
                else { out.common.quiet = ("reboot-wrong \(c.clientKey)", "DHCP REQUEST from \(c.who) for \(req) (not on \(c.linkText)), not ours to answer") }
                return
            }
            if var l = leases.lease(.v4, req.description), l.clientKey == c.clientKey, l.state != .foreign,
               l.state != .declined, l.state != .abandoned, scope.contains(req.description) {
                if l.state == .active || l.state == .offered || !leases.heldByOther(.v4, req.description, client: c.clientKey, now: c.now) {
                    ack(c, &l, &leases, &out)
                    return
                }
            }
            if leases.heldByOther(.v4, req.description, client: c.clientKey, now: c.now), scope.authoritative {
                nak(c, "\(req) belongs to another client", &out)
                return
            }
            out.common.quiet = ("reboot-unknown \(c.clientKey)", "DHCP REQUEST (init-reboot) from \(c.who) for \(req): no lease here, silent")
            return
        }
        // RENEWING / REBINDING: only for an address on the client's link (an enabled scope
        // there); a REBINDING broadcast from another link must not extend it.
        let addr = p.ciaddr
        out.common.counters.append(.renew)
        guard c.scope(containing: addr) != nil else {
            if c.scopes.contains(where: \.authoritative) { nak(c, "\(addr) is not on this link", &out) }
            else { out.common.quiet = ("renew-wrong \(c.clientKey)", "DHCP REQUEST (renew) from \(c.who) for \(addr) (not on \(c.linkText)), not ours to answer") }
            return
        }
        if var l = leases.lease(.v4, addr.description), l.clientKey == c.clientKey,
           l.state == .active || ((l.state == .expired || l.state == .released) && !leases.heldByOther(.v4, addr.description, client: c.clientKey, now: c.now)) {
            ack(c, &l, &leases, &out)
            return
        }
        if leases.heldByOther(.v4, addr.description, client: c.clientKey, now: c.now), c.scopes.contains(where: \.authoritative) {
            nak(c, "\(addr) belongs to another client", &out)
            return
        }
        out.common.quiet = ("renew-unknown \(c.clientKey)", "DHCP REQUEST (renew) from \(c.who) for \(addr): no lease here, silent")
    }

    /// A REQUEST to another server: our offer to this client lapses; option 50 / ciaddr is that
    /// server's for a lease time (passive foreign-lease detection).
    static func foreignRequest(_ c: Context, _ other: IPv4Address, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        for var l in leases.leases(client: c.clientKey) where l.family == .v4 && l.state == .offered {
            l.state = .expired; l.expires = c.now; l.updated = c.now
            leases.put(l)
        }
        guard let req = c.p.requestedAddress ?? (c.p.ciaddr.isZero ? nil : c.p.ciaddr), let scope = c.scope(containing: req) else {
            out.common.quiet = ("foreign \(other)", "DHCP REQUEST from \(c.who) to server \(other) (not us)")
            return
        }
        let existing = leases.lease(.v4, req.description)
        if let l = existing, l.state == .active, l.expires > c.now, l.clientKey != c.clientKey {
            out.common.quiet = ("foreign-conflict \(req)", "DHCP: server \(other) handed \(req) to \(c.who) while it is leased here to \(l.whoText)")
            return
        }
        // An offer to another client, a DECLINE quarantine or an abandoned address stays as it
        // is: a forged REQUEST must not turn them into something else.
        if let l = existing, l.holds(at: c.now), [.offered, .declined, .abandoned].contains(l.state) {
            out.common.quiet = ("foreign-kept \(req)", "DHCP REQUEST from \(c.who) to server \(other) for \(req), which is \(l.state.title.lowercased()) here: not marked")
            return
        }
        let ownActive = existing.map { $0.state == .active && $0.clientKey == c.clientKey && $0.expires > c.now } ?? false
        let refresh = existing.map { $0.state == .foreign && $0.clientKey == c.clientKey && $0.holds(at: c.now) } ?? false
        if !ownActive, !refresh {
            // A new foreign hold: the relay / circuit / churn caps apply (foreign rows count), and
            // foreign rows may take at most half of a scope's pool, so forged REQUESTs naming
            // another server cannot mark the whole pool taken.
            let share = max(1, Int(min(scope.poolSize / 2, UInt64(Int.max))))
            var why = capReason(c, leases, includeForeign: true)
            if why == nil, leases.foreignCount(scope: scope.id) >= share {
                why = ("cap foreign \(scope.id)", "DHCP: \(leases.foreignCount(scope: scope.id)) addresses of \(scope.name) are already marked as other servers' (cap \(share))")
            }
            if let why {
                out.common.counters.append(.capped)
                out.common.quiet = (why.key, "\(why.text); \(req) from \(c.who)'s REQUEST to server \(other) not marked")
                return
            }
            // One foreign hold per client: the address it asked another server for before lapses.
            for var old in leases.leases(client: c.clientKey) where old.family == .v4 && old.state == .foreign && old.address != req.description {
                old.state = .expired; old.expires = c.now; old.updated = c.now
                leases.put(old)
            }
        }
        var f = existing ?? DHCPLease(family: .v4, address: req.description, scopeID: scope.id, state: .foreign,
                                      clientKey: c.clientKey, start: c.now, expires: c.now)
        if ownActive {
            // Our own client moving to the other server: our lease ends.
            out.common.dns.append(unregister(f))
        }
        f.clientKey = c.clientKey
        f.state = .foreign
        f.scopeID = scope.id
        f.otherServer = other.description
        f.mac = c.p.mac
        f.hostname = c.p.hostName ?? f.hostname
        f.start = c.now; f.updated = c.now
        f.expires = c.now.addingTimeInterval(TimeInterval(min(scope.leaseSeconds, Self.foreignHoldSeconds)))
        f.relay = c.relayed ? c.arrival.source.description : nil
        f.circuitID = c.p.relayAgentInformation?.circuit.map(DHCPHex.string)
        leases.put(f)
        out.common.counters.append(.foreignSeen)
        out.common.events.append(DHCPEvent(date: c.now, family: .v4, address: req.description, mac: c.p.mac, clientKey: c.clientKey,
                                           kind: "FOREIGN", detail: "requested from server \(other) \(c.via)"))
        out.common.quiet = ("foreign \(req)", "DHCP: \(req) is leased by server \(other) to \(c.who) (seen in its REQUEST)")
    }

    /// How long an address seen in a REQUEST to another server stays marked (at most the
    /// scope's lease time): short, since forged REQUESTs can create such rows.
    static let foreignHoldSeconds = 1800

    static func ack(_ c: Context, _ l: inout DHCPLease, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        // The lease's scope must be one of this link's enabled scopes and hold the address.
        guard let a = IPv4Address(l.address),
              let scope = c.scopes.first(where: { $0.id == l.scopeID && $0.contains(l.address) }) ?? c.scope(containing: a) else {
            if c.scopes.contains(where: \.authoritative) { nak(c, "\(l.address) is not on this link", &out) }
            else { out.common.quiet = ("ack-wrong \(c.clientKey)", "DHCP REQUEST from \(c.who) for \(l.address): not in an enabled scope on \(c.linkText), silent") }
            return
        }
        let reservation = c.reservation().flatMap { $0.address == l.address ? $0 : nil }
        let seconds = leaseSeconds(c, scope)
        let wasActive = l.state == .active && l.expires > c.now
        if !wasActive { l.start = c.now }
        l.state = .active
        l.expires = c.now.addingTimeInterval(TimeInterval(seconds))
        l.scopeID = scope.id
        fill(&l, c, scope: scope, reservation: reservation)
        var reply = baseReply(c, type: .ack, yiaddr: a)
        addLeaseOptions(&reply, c, scope: scope, reservation: reservation, leaseSeconds: seconds)
        addConfigOptions(&reply, c, scope: scope, reservation: reservation)
        let dns = dnsPlan(c, scope: scope, reservation: reservation, lease: l)
        if let fqdn = c.p.clientFQDN {
            var r = ClientFQDN(s: dns.forward, o: dns.forward && !fqdn.s, e: fqdn.e, n: !dns.forward && !dns.ptr && fqdn.n,
                               name: dns.fqdn ?? fqdn.name, fullyQualified: dns.fqdn != nil || fqdn.fullyQualified)
            if fqdn.n { r.s = false }
            reply[DHCPv4OptionCode.clientFQDN] = r.encodeV4()
        }
        fit(&reply, c)
        leases.put(l)
        out.reply = reply
        out.destination = destination(c, nak: false)
        out.common.counters.append(.ack)
        if let fqdn = dns.fqdn, dns.forward || dns.ptr {
            out.common.dns.append(DHCPDNSAction(kind: .register, lease: l, fqdn: fqdn, forward: dns.forward, ptr: dns.ptr,
                                                identifierType: c.p.clientIdentifier == nil ? .hardware : .clientID,
                                                identifier: c.p.clientIdentifier ?? ([c.p.htype] + c.p.hardwareAddress)))
        }
        let what = wasActive ? "renewed" : "new"
        out.common.events.append(DHCPEvent(date: c.now, family: .v4, address: l.address, mac: l.mac, clientKey: l.clientKey,
                                           kind: "ACK", detail: "\(what), \(seconds) s \(c.via) · scope \(scope.name)"))
        out.common.line = "DHCP ACK \(l.address) to \(c.who) \(c.via) · scope \(scope.name)" + (wasActive ? " (renew)" : "")
    }

    static func nak(_ c: Context, _ why: String, _ out: inout DHCPv4Outcome) {
        var reply = baseReply(c, type: .nak, yiaddr: .zero)
        reply.options = [DHCPv4Option(DHCPv4OptionCode.messageType, [DHCPv4MessageType.nak.rawValue]),
                         DHCPv4Option(DHCPv4OptionCode.serverIdentifier, c.serverID.bytes),
                         DHCPv4Option(DHCPv4OptionCode.message, Array(why.prefix(200).utf8))]
        if let cid = c.p.clientIdentifier { reply[DHCPv4OptionCode.clientIdentifier] = cid }
        if let agent = c.p[DHCPv4OptionCode.relayAgentInformation], c.p.relayAgentInformation != nil {
            reply[DHCPv4OptionCode.relayAgentInformation] = agent
        }
        if c.relayed { reply.flags |= DHCPv4Packet.broadcastFlag }
        out.reply = reply
        out.destination = destination(c, nak: true)
        out.common.counters.append(.nak)
        out.common.events.append(DHCPEvent(date: c.now, family: .v4, address: c.p.requestedAddress?.description ?? c.p.ciaddr.description,
                                           mac: c.p.mac, clientKey: c.clientKey, kind: "NAK", detail: why))
        out.common.line = "DHCP NAK to \(c.who) \(c.via): \(why)"
    }

    // MARK: DECLINE / RELEASE / INFORM

    static func decline(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        out.common.counters.append(.decline)
        if let sid = c.p.serverIdentifier, !c.ours.contains(sid) { return }
        guard let req = c.p.requestedAddress, var l = leases.lease(.v4, req.description), l.clientKey == c.clientKey else {
            out.common.quiet = ("decline \(c.clientKey)", "DHCP DECLINE from \(c.who) for an address it does not hold here")
            return
        }
        if l.dnsName != nil || l.dnsPTR != nil { out.common.dns.append(unregister(l)) }
        let quarantine = c.config.settings.declineQuarantineSeconds
        l.state = .declined
        l.updated = c.now
        l.expires = c.now.addingTimeInterval(TimeInterval(quarantine))
        leases.put(l)
        out.common.events.append(DHCPEvent(date: c.now, family: .v4, address: l.address, mac: l.mac, clientKey: l.clientKey,
                                           kind: "DECLINE", detail: "address in use on the network; quarantined \(quarantine / 60) min"))
        out.common.line = "DHCP DECLINE \(l.address) from \(c.who) \(c.via): address in use, quarantined \(quarantine / 60) min"
    }

    static func release(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        out.common.counters.append(.release)
        if let sid = c.p.serverIdentifier, !c.ours.contains(sid) { return }
        guard var l = leases.lease(.v4, c.p.ciaddr.description), l.clientKey == c.clientKey, l.state == .active else {
            out.common.quiet = ("release \(c.clientKey)", "DHCP RELEASE from \(c.who) for \(c.p.ciaddr): no active lease here")
            return
        }
        if l.dnsName != nil || l.dnsPTR != nil { out.common.dns.append(unregister(l)) }
        l.state = .released
        l.expires = c.now
        l.updated = c.now
        leases.put(l)
        out.common.events.append(DHCPEvent(date: c.now, family: .v4, address: l.address, mac: l.mac, clientKey: l.clientKey,
                                           kind: "RELEASE", detail: "released by the client \(c.via)"))
        out.common.line = "DHCP RELEASE \(l.address) from \(c.who) \(c.via)"
    }

    static func inform(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv4Outcome) {
        out.common.counters.append(.inform)
        let addr = c.p.ciaddr.isZero ? c.arrival.source : c.p.ciaddr
        guard let scope = c.scope(containing: addr) ?? c.scopes.first else { return }
        var reply = baseReply(c, type: .ack, yiaddr: .zero)
        reply.ciaddr = c.p.ciaddr
        addConfigOptions(&reply, c, scope: scope, reservation: nil)
        fit(&reply, c)
        out.reply = reply
        out.destination = c.relayed ? relayDestination(c) : (c.p.ciaddr.isZero ? .broadcast(c.arrival.interfaceName) : .unicast(c.p.ciaddr, 68))
        out.common.counters.append(.ack)
        out.common.line = "DHCP INFORM from \(addr) \(c.who) \(c.via) · scope \(scope.name)"
        _ = leases
    }

    // MARK: Replies

    static func baseReply(_ c: Context, type: DHCPv4MessageType, yiaddr: IPv4Address) -> DHCPv4Packet {
        var r = DHCPv4Packet(op: 2, htype: c.p.htype, hlen: c.p.hlen, hops: c.p.hops, xid: c.p.xid, secs: 0, flags: c.p.flags,
                             ciaddr: .zero, yiaddr: yiaddr, siaddr: .zero, giaddr: c.p.giaddr, chaddr: c.p.chaddr)
        r.options = [DHCPv4Option(DHCPv4OptionCode.messageType, [type.rawValue]),
                     DHCPv4Option(DHCPv4OptionCode.serverIdentifier, c.serverID.bytes)]
        // RFC 6842: echo the client identifier.
        if let cid = c.p.clientIdentifier { r.options.append(DHCPv4Option(DHCPv4OptionCode.clientIdentifier, cid)) }
        return r
    }

    static func leaseSeconds(_ c: Context, _ scope: DHCPScope) -> Int {
        let max = scope.leaseSeconds
        guard let want = c.p.requestedLeaseTime, want > 0 else { return max }
        return Swift.max(60, Swift.min(max, Int(want)))
    }

    static func addLeaseOptions(_ r: inout DHCPv4Packet, _ c: Context, scope: DHCPScope, reservation: DHCPReservation?, leaseSeconds: Int) {
        r[DHCPv4OptionCode.leaseTime] = DHCPOptionBuilder.uint32(UInt32(leaseSeconds))
        r[DHCPv4OptionCode.renewalTime] = DHCPOptionBuilder.uint32(UInt32(leaseSeconds / 2))
        r[DHCPv4OptionCode.rebindingTime] = DHCPOptionBuilder.uint32(UInt32(leaseSeconds * 7 / 8))
    }

    /// The scope's configuration, filtered by option 55 for the optional ones (always: mask,
    /// routers, DNS, domain; option 43 whenever the vendor class matches).
    static func addConfigOptions(_ r: inout DHCPv4Packet, _ c: Context, scope: DHCPScope, reservation: DHCPReservation?) {
        let prl = Set(c.p.parameterRequestList)
        func wanted(_ code: UInt8) -> Bool { prl.isEmpty || prl.contains(code) }
        if let s = scope.subnetV4 { r[DHCPv4OptionCode.subnetMask] = s.mask.bytes }
        if !scope.routers.isEmpty, let b = try? DHCPOptionBuilder.ipv4List(scope.routers) { r[DHCPv4OptionCode.router] = b }
        let dns = scope.dnsServers.isEmpty ? [c.config.dcIPv4].compactMap { $0 } : scope.dnsServers
        if !dns.isEmpty, let b = try? DHCPOptionBuilder.ipv4List(dns) { r[DHCPv4OptionCode.dnsServers] = b }
        let domain = scope.domainName ?? c.config.domain
        if !domain.isEmpty { r[DHCPv4OptionCode.domainName] = Array(domain.utf8) }
        if let mtu = scope.mtu, wanted(DHCPv4OptionCode.interfaceMTU) { r[DHCPv4OptionCode.interfaceMTU] = DHCPOptionBuilder.uint16(UInt16(mtu)) }
        if let s = scope.subnetV4, wanted(DHCPv4OptionCode.broadcastAddress), !prl.isEmpty { r[DHCPv4OptionCode.broadcastAddress] = s.broadcast.bytes }
        let ntp = scope.ntpServers.isEmpty ? [c.config.dcIPv4].compactMap { $0 } : scope.ntpServers
        if !ntp.isEmpty, wanted(DHCPv4OptionCode.ntpServers), let b = try? DHCPOptionBuilder.ipv4List(ntp) { r[DHCPv4OptionCode.ntpServers] = b }
        let search = scope.searchList.isEmpty ? (domain.isEmpty ? [] : [domain]) : scope.searchList
        if !search.isEmpty, prl.contains(DHCPv4OptionCode.domainSearch), let b = try? DHCPOptionBuilder.domainSearch(search) {
            r[DHCPv4OptionCode.domainSearch] = b
        }
        if !scope.staticRoutes.isEmpty, let b = try? DHCPOptionBuilder.classlessRoutes(scope.staticRoutes) {
            if wanted(DHCPv4OptionCode.classlessStaticRoute) { r[DHCPv4OptionCode.classlessStaticRoute] = b }
            if prl.contains(DHCPv4OptionCode.msClasslessStaticRoute) { r[DHCPv4OptionCode.msClasslessStaticRoute] = b }
        }
        if !scope.capwap.isEmpty, wanted(DHCPv4OptionCode.capwapAC), let b = try? DHCPOptionBuilder.capwap(scope.capwap) {
            r[DHCPv4OptionCode.capwapAC] = b
        }
        if let t = scope.tftpServer, !t.isEmpty, wanted(DHCPv4OptionCode.tftpServerName) { r[DHCPv4OptionCode.tftpServerName] = Array(t.utf8) }
        if let b = scope.bootfile, !b.isEmpty, wanted(DHCPv4OptionCode.bootfileName) { r[DHCPv4OptionCode.bootfileName] = Array(b.utf8) }
        if !scope.tftpServers150.isEmpty, wanted(DHCPv4OptionCode.tftpServerAddress), let b = try? DHCPOptionBuilder.ipv4List(scope.tftpServers150) {
            r[DHCPv4OptionCode.tftpServerAddress] = b
        }
        let policy = c.policy(in: scope)
        // Option 43: reservation → class policy → scope, sent when the vendor class matches.
        for candidate in [reservation?.option43, policy?.option43, scope.option43] {
            guard let o = candidate else { continue }
            if o.applies(to: c.p.vendorClass), let b = try? o.encode() {
                r[DHCPv4OptionCode.vendorSpecific] = b
                break
            }
        }
        // Options the server sets itself are never overridden (rows saved before validation refused them).
        for o in scope.customOptions + (policy?.options ?? []) + (reservation?.options ?? [])
        where o.code <= 254 && DHCPCustomOption.serverManagedV4[o.code] == nil {
            let code = UInt8(o.code)
            guard wanted(code), let b = try? o.encode() else { continue }
            r[code] = b
        }
        if let sel = c.p[DHCPv4OptionCode.subnetSelection], sel.count == 4 { r[DHCPv4OptionCode.subnetSelection] = sel }
        if c.p.relayAgentInformation != nil, let agent = c.p[DHCPv4OptionCode.relayAgentInformation] {
            r[DHCPv4OptionCode.relayAgentInformation] = agent
        }
    }

    static func addFQDNReply(_ r: inout DHCPv4Packet, _ c: Context, scope: DHCPScope) {
        guard let fqdn = c.p.clientFQDN else { return }
        let plan = dnsPlan(c, scope: scope, reservation: nil, lease: nil)
        r[DHCPv4OptionCode.clientFQDN] = ClientFQDN(s: plan.forward, o: plan.forward && !fqdn.s, e: fqdn.e, n: fqdn.n && !plan.forward,
                                                    name: plan.fqdn ?? fqdn.name, fullyQualified: plan.fqdn != nil || fqdn.fullyQualified).encodeV4()
    }

    /// Drops optional options until the reply fits the client's maximum message size (57) or 576.
    static func fit(_ r: inout DHCPv4Packet, _ c: Context) {
        let limit = (c.p.maxMessageSize ?? 576) - 28  // IP + UDP headers
        let optional: [UInt8] = [DHCPv4OptionCode.msClasslessStaticRoute, DHCPv4OptionCode.domainSearch,
                                 DHCPv4OptionCode.broadcastAddress, DHCPv4OptionCode.tftpServerAddress, DHCPv4OptionCode.bootfileName,
                                 DHCPv4OptionCode.tftpServerName, DHCPv4OptionCode.capwapAC, DHCPv4OptionCode.interfaceMTU,
                                 DHCPv4OptionCode.ntpServers, DHCPv4OptionCode.classlessStaticRoute, DHCPv4OptionCode.vendorSpecific]
        let core: Set<UInt8> = [1, 3, 6, 15, 51, 53, 54, 58, 59, 61, 81, 82, 118]
        var i = 0
        while r.encode(minimumSize: 0).count > limit {
            if i < optional.count { r[optional[i]] = nil; i += 1; continue }
            // Custom options last.
            guard let victim = r.options.last(where: { !core.contains($0.code) }) else { break }
            r[victim.code] = nil
        }
    }

    static func relayDestination(_ c: Context) -> DHCPv4Outcome.Destination {
        // RFC 8357: a relay that sent 82/19 listens on the port it sent from.
        let port: UInt16 = c.p.relayAgentInformation?.hasRelaySourcePort == true ? c.arrival.sourcePort : 67
        return .relay(c.p.giaddr, port)
    }

    /// RFC 2131 §4.1: relay → giaddr; a client with an address → ciaddr; else broadcast.
    static func destination(_ c: Context, nak: Bool) -> DHCPv4Outcome.Destination {
        if c.relayed { return relayDestination(c) }
        if !nak, !c.p.ciaddr.isZero { return .unicast(c.p.ciaddr, 68) }
        return .broadcast(c.arrival.interfaceName)
    }

    // MARK: Lease details and DNS

    static func fill(_ l: inout DHCPLease, _ c: Context, scope: DHCPScope, reservation: DHCPReservation?) {
        let p = c.p
        l.updated = c.now
        l.mac = p.mac
        l.clientID = p.clientIdentifier.map(DHCPHex.string)
        if let h = reservation?.hostname ?? p.hostName ?? p.clientFQDN?.name { l.hostname = h }
        l.relay = c.relayed ? c.arrival.source.description : nil
        l.link = c.relayed ? p.giaddr.description : c.arrival.interfaceName
        let agent = p.relayAgentInformation
        if let circuit = agent?.circuit { l.circuitID = DHCPHex.string(circuit) }
        if let remote = agent?.remote { l.remoteID = DHCPHex.string(remote) }
        if let vss = agent?.sub(RelayAgentInformation.vss) { l.vss = DHCPHex.string(vss) }
        if let vc = p.vendorClass { l.vendorClass = vc }
        if let uc = p.userClass { l.userClass = uc }
        if [.discover, .request, .inform].contains(p.messageType) {
            let fp = DHCPFingerprint(v4: p)
            l.fingerprint = fp
            let profile = DeviceClassifier.classify(fp)
            l.deviceCategory = profile.category.rawValue
            l.deviceOS = profile.os
        }
        l.reservationID = reservation?.id
        l.otherServer = nil
    }

    struct DNSPlan { var fqdn: String?; var forward: Bool; var ptr: Bool }

    /// Windows semantics (spec rev 2): client S=0 → PTR only; S=1 or a plain host name → A+PTR;
    /// N=1 → nothing. "Always" overrides S=0.
    static func dnsPlan(_ c: Context, scope: DHCPScope, reservation: DHCPReservation?, lease: DHCPLease?) -> DNSPlan {
        let mode = c.config.settings.ddns
        let fqdnOption = c.p.clientFQDN
        let raw = reservation?.hostname ?? fqdnOption?.name ?? c.p.hostName ?? lease?.hostname
        guard scope.dnsUpdates, mode != .never, let raw, let label = DHCPDNS.sanitizeLabel(raw) else {
            return DNSPlan(fqdn: nil, forward: false, ptr: false)
        }
        let domain = scope.domainName ?? c.config.domain
        let fqdn = DHCPDNS.fqdn(label: label, domain: domain)
        if let f = fqdnOption {
            if f.n { return DNSPlan(fqdn: fqdn, forward: false, ptr: false) }
            if !f.s, mode == .windows { return DNSPlan(fqdn: fqdn, forward: false, ptr: true) }
        }
        return DNSPlan(fqdn: fqdn, forward: true, ptr: true)
    }

    static func unregister(_ l: DHCPLease) -> DHCPDNSAction {
        DHCPDNSAction(kind: .unregister, lease: l, fqdn: l.dnsName, forward: l.dnsForward, ptr: l.dnsPTR != nil,
                      identifierType: .hardware, identifier: [])
    }

    /// An unregister action for a lease that expired or was released by the admin.
    public static func unregisterAction(_ l: DHCPLease) -> DHCPDNSAction { unregister(l) }
}
