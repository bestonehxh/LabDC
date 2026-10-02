import DHCPKit
import DNSKit
import Foundation
import RADIUSKit
import Store
import Synchronization

/// What the Services row and the DHCP page show about the running server.
public struct DHCPRuntimeStatus: Sendable, Equatable {
    public var running: Bool
    public var modeText: String
    public var scopes: Int
    public var activeLeases: Int
    public var counters: DHCPCounters
    public var perScope: [Int64: DHCPCounters]
    /// Active leases per scope (utilisation).
    public var activePerScope: [Int64: Int]
    /// Datagrams dropped because too many were already in flight (backpressure), both families.
    public var droppedBusy: Int

    public init(running: Bool = false, modeText: String = "relay-only", scopes: Int = 0, activeLeases: Int = 0,
                counters: DHCPCounters = DHCPCounters(), perScope: [Int64: DHCPCounters] = [:], activePerScope: [Int64: Int] = [:],
                droppedBusy: Int = 0) {
        self.running = running; self.modeText = modeText; self.scopes = scopes; self.activeLeases = activeLeases
        self.counters = counters; self.perScope = perScope; self.activePerScope = activePerScope; self.droppedBusy = droppedBusy
    }

    /// `relay-only · 4 scopes · 123 leases`.
    public var summary: String {
        "\(modeText) · \(scopes) scope\(scopes == 1 ? "" : "s") · \(activeLeases) lease\(activeLeases == 1 ? "" : "s")"
    }
}

/// Phase 5: the DHCP server (docs/specs/phase5-dhcp.md). udp 67 (v4) and udp 547 (v6) on BSD
/// sockets; relay-first beside the production server; leases in memory with a write-behind to
/// the store every second; dynamic DNS in the DC's zones; device profiles for RADIUS; relay
/// copies to ClearPass/ISE profilers. Packet handling is serialised in `DHCPCore` (an actor);
/// the sockets only receive and send.
public final class DHCPServer: @unchecked Sendable {
    public struct Options: Sendable {
        public var v4Port: UInt16
        public var v6Port: UInt16
        /// v4 and v6 are independent listeners: either may be left out (its port is busy, or no
        /// scope of that family exists).
        public var enableV4: Bool
        public var enableV6: Bool
        public var flushInterval: Duration
        public var sweepInterval: Duration
        /// Datagrams per family handed to the core and not finished yet; above it a datagram is
        /// dropped on the socket queue (counted, logged once a flush interval) instead of
        /// queueing an unbounded number of tasks during a flood.
        public var maxInFlight: Int

        public init(v4Port: UInt16 = 67, v6Port: UInt16 = 547, enableV4: Bool = true, enableV6: Bool = true,
                    flushInterval: Duration = .seconds(1), sweepInterval: Duration = .seconds(15), maxInFlight: Int = 256) {
            self.v4Port = v4Port; self.v6Port = v6Port; self.enableV4 = enableV4; self.enableV6 = enableV6
            self.flushInterval = flushInterval; self.sweepInterval = sweepInterval; self.maxInFlight = maxInFlight
        }
    }

    let core: DHCPCore
    private let queue = DispatchQueue(label: "dev.labdc.app.dhcp")
    private var v4: DHCPUDPSocket?
    private var v6: DHCPUDPSocket?
    private var loops: [Task<Void, Never>] = []
    public private(set) var v4Port: UInt16 = 0
    public private(set) var v6Port: UInt16 = 0
    let options: Options
    let gate4: DHCPInFlightGate
    let gate6: DHCPInFlightGate

    /// - Parameters:
    ///   - advertised: the DC's IPv4 handed out as DNS/NTP when a scope names none.
    ///   - log: Activity lines (`DHCP ACK …`); `warn` for problems.
    public init(store: DirectoryStore, options: Options = Options(), clock: @escaping @Sendable () -> Date = { Date() },
                advertised: @escaping @Sendable () -> String? = { ServeAddresses.current().first },
                log: @escaping @Sendable (String) -> Void, warn: @escaping @Sendable (String) -> Void = { _ in }) {
        self.options = options
        gate4 = DHCPInFlightGate(limit: options.maxInFlight)
        gate6 = DHCPInFlightGate(limit: options.maxInFlight)
        core = DHCPCore(store: store, clock: clock, advertised: advertised, log: log, warn: warn)
    }

    /// Loads config and leases, binds the sockets (port 0 = ephemeral, tests). Errors name the
    /// listener (`DHCP udp 67: …`, `DHCPv6 udp 547: …`) for the Services row.
    public func start() async throws {
        try await core.load()
        let core = self.core
        let gate4 = self.gate4, gate6 = self.gate6
        var s4: DHCPUDPSocket?
        if options.enableV4 {
            do {
                s4 = try DHCPUDPSocket(family: .v4, port: options.v4Port, queue: queue) { d in
                    guard gate4.enter() else { return }
                    Task { await core.receive4(d); gate4.leave() }
                }
            } catch {
                throw CLIError.failure("DHCP udp \(options.v4Port): \(error)")
            }
        }
        var s6: DHCPUDPSocket?
        if options.enableV6 {
            do {
                s6 = try DHCPUDPSocket(family: .v6, port: options.v6Port, queue: queue) { d in
                    guard gate6.enter() else { return }
                    Task { await core.receive6(d); gate6.leave() }
                }
            } catch {
                s4?.cancel()
                throw CLIError.failure("DHCPv6 udp \(options.v6Port): \(error)")
            }
        }
        v4 = s4
        v6 = s6
        v4Port = s4?.port ?? 0
        v6Port = s6?.port ?? 0
        await core.attach(v4: s4, v6: s6)
        let flush = options.flushInterval, sweep = options.sweepInterval
        let limit = options.maxInFlight
        loops.append(Task { [core] in
            while !Task.isCancelled {
                try? await Task.sleep(for: flush)
                await core.flush()
                for (gate, name) in [(gate4, "DHCP"), (gate6, "DHCPv6")] {
                    let n = gate.takeUnreported()
                    if n > 0 { await core.reportBusy("\(name): \(n) datagram\(n == 1 ? "" : "s") dropped (over \(limit) in flight)") }
                }
            }
        })
        loops.append(Task { [core] in
            while !Task.isCancelled {
                try? await Task.sleep(for: sweep)
                if Task.isCancelled { return }
                await core.sweep()
            }
        })
        await core.logStart(v4Port: v4Port, v6Port: v6Port)
    }

    /// Stops the listeners and writes every pending lease change.
    public func stop() async {
        for t in loops { t.cancel() }
        loops = []
        v4?.cancel(); v6?.cancel()
        v4 = nil; v6 = nil
        await core.detach()
        await core.flush()
        v4Port = 0; v6Port = 0
    }

    /// A scope, reservation or setting changed: reload now.
    public func configChanged() async { await core.reload() }

    public func status() async -> DHCPRuntimeStatus {
        var s = await core.status(running: v4 != nil || v6 != nil)
        s.droppedBusy = gate4.dropped + gate6.dropped
        return s
    }

    /// Leases (memory, so offers and unsaved changes show too).
    public func leases() async -> [DHCPLease] { await core.allLeases() }

    /// Admin "Release": the lease ends now and its DNS records go.
    public func release(family: DHCPFamily, address: String) async throws { try await core.adminRelease(family: family, address: address) }

    public func flush() async { await core.flush() }
}

/// Backpressure for one family: how many datagrams are being handled; past `limit` new ones
/// are dropped and counted. Called on the socket queue (`enter`) and from the handling task
/// (`leave`).
final class DHCPInFlightGate: Sendable {
    let limit: Int
    private let state = Mutex<(busy: Int, dropped: Int, reported: Int)>((0, 0, 0))

    init(limit: Int) { self.limit = max(1, limit) }

    func enter() -> Bool {
        state.withLock { s in
            guard s.busy < limit else { s.dropped += 1; return false }
            s.busy += 1
            return true
        }
    }

    func leave() { state.withLock { $0.busy -= 1 } }

    var busy: Int { state.withLock { $0.busy } }
    var dropped: Int { state.withLock { $0.dropped } }

    /// Drops since the last call (for one log line per flush interval).
    func takeUnreported() -> Int {
        state.withLock { s in
            let n = s.dropped - s.reported
            s.reported = s.dropped
            return n
        }
    }
}

/// The serialised state: config snapshot, lease table, counters, rate limiters.
actor DHCPCore {
    let store: DirectoryStore
    let clock: @Sendable () -> Date
    let advertised: @Sendable () -> String?
    let log: @Sendable (String) -> Void
    let warn: @Sendable (String) -> Void
    let dns: DHCPDNSUpdater

    var config = DHCPConfig()
    var loadedAt = Date.distantPast
    var table = DHCPLeaseTable()
    var counters: [Int64: DHCPCounters] = [:]
    var global = DHCPCounters()
    var limiter = RADIUSLogLimiter(interval: 60)
    var pendingEvents: [DHCPEvent] = []
    var interfaces: (at: Date, info: DHCPInterfaceInfo)?
    var toward: [IPv4Address: (at: Date, address: IPv4Address)] = [:]
    var buckets: [String: (tokens: Double, at: Date)] = [:]
    var joined: Set<UInt32> = []
    weak var v4: DHCPUDPSocket?
    weak var v6: DHCPUDPSocket?
    /// The last profile written per MAC (what it said, when): an unchanged profile is not
    /// written again until `profileRefresh` passes (last-seen moves then).
    var profileCache: [String: (key: ProfileKey, at: Date)] = [:]
    var lastProfilePurge = Date.distantPast
    /// Tests: replaces the store write of the write-behind.
    var saveLeases: (@Sendable ([DHCPLease], [String]) async throws -> Void)?
    static let configTTL: TimeInterval = 30
    static let historyDays: TimeInterval = 30
    static let profileRefresh: TimeInterval = 3600
    static let profileCacheLimit = 50_000
    /// Ping-before-offer blocks for up to 0.3 s per try: off the cooperative pool.
    static let pingQueue = DispatchQueue(label: "dev.labdc.app.dhcp.ping", qos: .utility, attributes: .concurrent)

    struct ProfileKey: Equatable {
        var vendorClass: String?
        var hostname: String?
        var category: String
        var os: String
        var confidence: Int
    }

    init(store: DirectoryStore, clock: @escaping @Sendable () -> Date, advertised: @escaping @Sendable () -> String?,
         log: @escaping @Sendable (String) -> Void, warn: @escaping @Sendable (String) -> Void) {
        self.store = store; self.clock = clock; self.advertised = advertised; self.log = log; self.warn = warn
        dns = DHCPDNSUpdater(store: store, log: log)
    }

    func load() async throws {
        table = DHCPLeaseTable(try await store.dhcpLeases())
        try await reloadConfig()
    }

    func attach(v4: DHCPUDPSocket?, v6: DHCPUDPSocket?) {
        self.v4 = v4
        self.v6 = v6
        joined = []
        joinDirectInterfaces()
    }

    func detach() { v4 = nil; v6 = nil }

    func logStart(v4Port: UInt16, v6Port: UInt16) {
        let scopes = config.scopes.filter(\.enabled)
        let ports = (v4Port != 0 ? ["udp \(v4Port)"] : []) + (v6Port != 0 ? ["udp \(v6Port) (v6)"] : [])
        log(ports.joined(separator: " + ") + ": listening, \(config.settings.modeText), "
            + "\(scopes.count) scope\(scopes.count == 1 ? "" : "s"), \(table.all.filter { $0.state == .active }.count) active leases")
    }

    func reload() async {
        do { try await reloadConfig() } catch { warn("config: \(error) — keeping the last one") }
    }

    private func reloadConfig() async throws {
        let scopes = try await store.dhcpScopes()
        let reservations = try await store.dhcpReservations()
        let settings = try await store.dhcpSettings()
        let domain = (try? await store.domainInfo().dnsDomain) ?? ""
        let info = currentInterfaces(force: true)
        let duid = try await store.dhcpServerDUID(mac: info.firstMAC ?? [], now: clock())
        let dc4 = advertised()
        var dc6: [String] = []
        if let dc4, let a = IPv4Address(dc4), let owner = info.interfaces.first(where: { $0.ipv4.contains { $0.0 == a } }) {
            dc6 = owner.ipv6.map(\.description)
        }
        if dc6.isEmpty { dc6 = info.interfaces.filter { !$0.name.hasPrefix("utun") }.flatMap(\.ipv6).prefix(2).map(\.description) }
        config = DHCPConfig(scopes: scopes, reservations: reservations, settings: settings, domain: domain, dcIPv4: dc4,
                            dcIPv6: dc6, serverDUID: duid)
        loadedAt = clock()
        joinDirectInterfaces()
    }

    private func currentConfig() async -> DHCPConfig {
        if clock().timeIntervalSince(loadedAt) > Self.configTTL { await reload() }
        return config
    }

    private func joinDirectInterfaces() {
        guard let v6 else { return }
        let info = currentInterfaces()
        for name in config.settings.directInterfaces {
            guard let i = info.interface(named: name), !joined.contains(i.index) else { continue }
            if let e = v6.joinAllDHCPAgents(interface: i.index), e != EADDRINUSE {
                warn("cannot join ff02::1:2 on \(name): \(String(cString: strerror(e)))")
            } else {
                joined.insert(i.index)
            }
        }
    }

    private func currentInterfaces(force: Bool = false) -> DHCPInterfaceInfo {
        let now = Date()
        if !force, let cached = interfaces, now.timeIntervalSince(cached.at) < 10 { return cached.info }
        let info = DHCPInterfaceInfo.current()
        interfaces = (now, info)
        return info
    }

    /// The server identifier toward a relay (cached a minute per giaddr).
    private func serverAddress(toward giaddr: IPv4Address) -> IPv4Address? {
        let now = Date()
        if let c = toward[giaddr], now.timeIntervalSince(c.at) < 60 { return c.address }
        guard let a = DHCPInterfaceInfo.localAddress(toward: giaddr) else { return nil }
        toward[giaddr] = (now, a)
        return a
    }

    private func limited(_ key: String, _ text: String) {
        guard let held = limiter.admit(key, now: clock()) else { return }
        log(held > 0 ? "\(text) (\(held) more since the last line)" : text)
    }

    private func count(_ keys: [DHCPCounterKey], scope: Int64?) {
        for k in keys {
            k.apply(&global)
            if let scope { k.apply(&counters[scope, default: DHCPCounters()]) }
        }
    }

    // MARK: v4

    func receive4(_ d: DHCPDatagram) async {
        guard let source = d.sourceV4 else { return }
        let packet: DHCPv4Packet
        do { packet = try DHCPv4Packet(bytes: d.bytes) } catch {
            limited("malformed \(source)", "malformed DHCP datagram from \(source) dropped (\(error))")
            return
        }
        guard packet.op == 1 else { return }   // our own replies on a loop, other servers' answers
        let config = await currentConfig()
        let info = currentInterfaces()
        let iface = d.interfaceIndex.flatMap { info.interface(index: $0) }
        let ifaddr = iface?.ipv4.first { $0.1.contains(source) } ?? iface?.ipv4.first
        var server = config.settings.serverAddress.flatMap(IPv4Address.init)
        if server == nil, !packet.giaddr.isZero { server = serverAddress(toward: packet.giaddr) }
        if server == nil { server = ifaddr?.0 ?? config.dcIPv4.flatMap(IPv4Address.init) }
        let arrival = DHCPv4Arrival(source: source, sourcePort: d.sourcePort, destination: d.destinationV4, interfaceName: iface?.name,
                                    interfaceAddress: ifaddr?.0, interfaceSubnet: ifaddr?.1, serverAddress: server ?? .zero,
                                    localAddresses: info.allIPv4)
        var now = clock()
        var out = DHCPv4Engine.handle(packet, arrival: arrival, config: config, leases: &table, now: now)
        // Ping-before-offer: an address that answers is abandoned and the DISCOVER runs again.
        var attempts = 0
        while let candidate = out.common.pingAddress, attempts < 3, let a = IPv4Address(candidate) {
            attempts += 1
            let inUse = await Self.ping(a)
            guard inUse else { break }
            now = clock()
            if var l = table.lease(.v4, candidate) {
                l.state = .abandoned
                l.updated = now
                l.expires = now.addingTimeInterval(TimeInterval(config.settings.declineQuarantineSeconds))
                table.put(l)
            }
            pendingEvents.append(DHCPEvent(date: now, family: .v4, address: candidate, mac: packet.mac, clientKey: nil,
                                           kind: "ABANDONED", detail: "answered a ping before the offer"))
            log("DHCP \(candidate) answers ping: abandoned for \(config.settings.declineQuarantineSeconds / 60) min, offering another address")
            out = DHCPv4Engine.handle(packet, arrival: arrival, config: config, leases: &table, now: now)
        }
        count(out.common.counters, scope: out.common.scopeID)
        if out.common.forwardToProfilers { forward4(d.bytes, packet: packet, interfaceAddress: ifaddr?.0, config: config) }
        if let reply = out.reply {
            let bytes = reply.encode()
            let delay = out.common.delayMs
            let destination = out.destination
            let index = iface?.index
            if delay > 0 {
                Task { [weak self] in
                    try? await Task.sleep(for: .milliseconds(delay))
                    await self?.send4(bytes, destination, interface: index)
                }
            } else {
                send4(bytes, destination, interface: index)
            }
            if config.settings.forwardReplies { forwardReply4(bytes, config: config) }
        }
        let addressed = out.reply.map { [.offer, .ack].contains($0.messageType) && !$0.yiaddr.isZero } ?? false
        await finish(out.common, family: .v4, addressed: addressed,
                     relay: packet.giaddr.isZero ? [] : [source.description, packet.giaddr.description])
    }

    /// Ping-before-offer on `pingQueue` (a blocking ICMP wait), like `RadiusCoAClient`.
    static func ping(_ a: IPv4Address) async -> Bool {
        await withCheckedContinuation { (done: CheckedContinuation<Bool, Never>) in
            pingQueue.async { done.resume(returning: DHCPPing.isInUse(a)) }
        }
    }

    func reportBusy(_ text: String) { warn(text) }

    func send4(_ bytes: [UInt8], _ destination: DHCPv4Outcome.Destination, interface: UInt32?) {
        guard let v4 else { return }
        let e: Int32?
        switch destination {
        case .none: return
        case .relay(let a, let port): e = v4.send(bytes, v4: a, port: port)
        case .unicast(let a, let port): e = v4.send(bytes, v4: a, port: port)
        case .broadcast: e = v4.send(bytes, v4: .broadcast, port: 68, interface: interface)
        }
        if let e { limited("send \(destination)", "DHCP reply to \(destination) not sent: \(String(cString: strerror(e)))") }
    }

    /// A relay copy of a client message to each profiler (udp 67): byte-identical except
    /// `giaddr`, which is filled in when the packet came direct.
    private func forward4(_ original: [UInt8], packet: DHCPv4Packet, interfaceAddress: IPv4Address?, config: DHCPConfig) {
        let targets = config.settings.v4Profilers
        guard !targets.isEmpty, let v4, original.count >= 28 else { return }
        var bytes = original
        if packet.giaddr.isZero, let a = interfaceAddress {
            bytes.replaceSubrange(24..<28, with: a.bytes)
        }
        for (t, port) in targets where admitForward(t.description) {
            if let e = v4.send(bytes, v4: t, port: port) {
                limited("profiler \(t)", "DHCP copy to profiler \(t) not sent: \(String(cString: strerror(e)))")
            }
        }
    }

    private func forwardReply4(_ bytes: [UInt8], config: DHCPConfig) {
        guard let v4 else { return }
        for (t, port) in config.settings.v4Profilers where admitForward(t.description) {
            _ = v4.send(bytes, v4: t, port: port)
        }
    }

    /// Token bucket per profiler: 200 packets burst, 100/s sustained.
    private func admitForward(_ key: String) -> Bool {
        let now = Date()
        var b = buckets[key] ?? (200, now)
        b.tokens = min(200, b.tokens + now.timeIntervalSince(b.at) * 100)
        b.at = now
        guard b.tokens >= 1 else {
            buckets[key] = b
            limited("profiler-rate \(key)", "DHCP copies to profiler \(key) rate-limited (over 100/s)")
            return false
        }
        b.tokens -= 1
        buckets[key] = b
        return true
    }

    // MARK: v6

    func receive6(_ d: DHCPDatagram) async {
        guard let source = d.sourceV6 else { return }
        let config = await currentConfig()
        let info = currentInterfaces()
        let iface = d.interfaceIndex.flatMap { info.interface(index: $0) }
        let arrival = DHCPv6Arrival(source: source, sourcePort: d.sourcePort, destination: d.destinationV6, interfaceName: iface?.name,
                                    interfaceGlobal: iface?.ipv6.first)
        let out = DHCPv6Engine.handle(d.bytes, arrival: arrival, config: config, leases: &table, now: clock())
        count(out.common.counters, scope: out.common.scopeID)
        if out.common.forwardToProfilers { forward6(d.bytes, arrival: arrival, config: config) }
        if let wire = out.wire {
            let delay = out.common.delayMs
            let destination = out.destination
            let index = iface?.index ?? d.interfaceIndex
            if delay > 0 {
                Task { [weak self] in
                    try? await Task.sleep(for: .milliseconds(delay))
                    await self?.send6(wire, destination, interface: index)
                }
            } else {
                send6(wire, destination, interface: index)
            }
            if config.settings.forwardReplies, config.settings.forwardV6 {
                for (t, port) in config.settings.v6Profilers where admitForward(t.description) {
                    _ = v6?.send(wire, v6: t, port: port)
                }
            }
        }
        let addressed = out.reply.map { [.advertise, .reply].contains($0.type) && $0.iaNAs.contains { !$0.addresses.isEmpty } } ?? false
        let relayed = d.bytes.first == DHCPv6MessageType.relayForward.rawValue
        await finish(out.common, family: .v6, addressed: addressed, relay: relayed ? [source.description] : [])
    }

    func send6(_ bytes: [UInt8], _ destination: DHCPv6Outcome.Destination, interface: UInt32?) {
        guard let v6 else { return }
        let e: Int32?
        switch destination {
        case .none: return
        case .relay(let a, let port): e = v6.send(bytes, v6: a, port: port, interface: interface)
        case .client(let a, _): e = v6.send(bytes, v6: a, port: 546, interface: interface)
        }
        if let e { limited("send6 \(destination)", "DHCPv6 reply to \(destination) not sent: \(String(cString: strerror(e)))") }
    }

    /// v6 relay copies (off by default): a Relay-forward as received, or one LabDC wraps around
    /// a message that came direct.
    private func forward6(_ original: [UInt8], arrival: DHCPv6Arrival, config: DHCPConfig) {
        let targets = config.settings.v6Profilers
        guard !targets.isEmpty, let v6 else { return }
        var bytes = original
        if original.first != DHCPv6MessageType.relayForward.rawValue {
            bytes = DHCPv6RelayMessage(type: .relayForward, hopCount: 0, linkAddress: arrival.interfaceGlobal ?? .zero,
                                       peerAddress: arrival.source,
                                       options: [DHCPv6Option(DHCPv6OptionCode.relayMessage, original)]).encode()
        }
        for (t, port) in targets where admitForward(t.description) { _ = v6.send(bytes, v6: t, port: port) }
    }

    // MARK: Effects

    /// Logs, events, device profiles and DNS after the reply went out. `addressed`: the reply
    /// offered or acknowledged an address — only then is the device profile written (a flood of
    /// DISCOVERs with random MACs that never get an address does not grow the table).
    /// `relay`: the relay's source and giaddr (v4) or source (v6); empty when direct.
    private func finish(_ common: DHCPCommonOutcome, family: DHCPFamily, addressed: Bool, relay: [String]) async {
        if let line = common.line { log(line) }
        if let q = common.quiet { limited(q.key, q.text) }
        pendingEvents += common.events
        if let p = common.profile, addressed { await recordProfile(p, family: family, scopeID: common.scopeID, relay: relay) }
        for action in common.dns { await applyDNS(action) }
    }

    private func recordProfile(_ p: (mac: String, fingerprint: DHCPFingerprint, result: DeviceClassifier.Result, hostname: String?),
                               family: DHCPFamily, scopeID: Int64?, relay: [String]) async {
        let now = clock()
        let key = ProfileKey(vendorClass: p.fingerprint.vendorClass, hostname: p.hostname, category: p.result.category.rawValue, os: p.result.os,
                             confidence: p.result.confidence)
        if let last = profileCache[p.mac], last.key == key, now.timeIntervalSince(last.at) < Self.profileRefresh { return }
        let category = DeviceCategory(rawValue: p.result.category.rawValue) ?? .unknown
        let profile = DeviceProfile(mac: p.mac, firstSeen: now, lastSeen: now, source: family == .v4 ? .dhcp4 : .dhcp6,
                                    category: category, os: p.result.os, vendorClass: p.fingerprint.vendorClass,
                                    hostname: p.hostname, confidence: p.result.confidence)
        let guarded = await categoryGuard(mac: p.mac, scopeID: scopeID, relay: relay)
        do {
            if try await store.upsertDeviceProfile(profile, guard: guarded), category != .unknown {
                log("DHCP device \(p.mac)\(p.hostname.map { " (\($0))" } ?? "") is \(p.result.category.title) — \(p.result.os) (\(p.result.reason))")
            }
            if profileCache.count >= Self.profileCacheLimit { profileCache = [:] }
            profileCache[p.mac] = (key, now)
        } catch {
            limited("profile", "device profile for \(p.mac) not saved: \(error)")
        }
    }

    /// Anti-poisoning (docs/notes/dhcp.md, "Profile trust"): a MAC with an open RADIUS session
    /// that authenticated by 802.1X (User-Name is not the MAC itself, i.e. not MAB) keeps its
    /// category unless the DHCP packet came from that session's NAS — the relay address is the
    /// NAS address, or the NAS address lies in the packet's scope — and the new guess is
    /// strictly more confident. MAB-only devices are profiled as before.
    private func categoryGuard(mac: String, scopeID: Int64?, relay: [String]) async -> DirectoryStore.CategoryGuard {
        guard let sessions = try? await store.activeRadiusSessions(mac: mac) else { return .open }
        let dot1x = sessions.filter { s in
            guard let user = s.userName, !user.isEmpty else { return false }
            return RADIUSMAC.normalize(user) != s.mac
        }
        guard !dot1x.isEmpty else { return .open }
        let scope = scopeID.flatMap { config.scope(id: $0) }
        let sameNAS = dot1x.contains { s in
            [s.nasIP, s.nasSource].compactMap { $0 }.contains { nas in relay.contains(nas) || (scope?.contains(nas) ?? false) }
        }
        return sameNAS ? .strictlyHigher : .frozen
    }

    private func applyDNS(_ action: DHCPDNSAction) async {
        let updated = await dns.apply(action, domain: config.domain)
        guard var current = table.lease(updated.family, updated.address), current.clientKey == updated.clientKey else { return }
        current.dnsName = updated.dnsName
        current.dnsPTR = updated.dnsPTR
        current.dnsForward = updated.dnsForward
        current.dnsDHCID = updated.dnsDHCID
        table.put(current)
    }

    /// The write-behind: changed leases and new events in one store transaction each.
    func flush() async {
        let (changed, removed) = table.takeDirty()
        let events = pendingEvents
        pendingEvents = []
        if !changed.isEmpty || !removed.isEmpty {
            do {
                if let saveLeases { try await saveLeases(changed, removed) } else { try await store.saveDHCPLeases(changed, removed: removed) }
            } catch {
                // Mark the ids dirty again: the next flush writes the leases as they are then.
                // Re-putting `changed` would overwrite what packets handled during this await did.
                table.requeue(changed: changed.map(\.id), removed: removed)
                limited("flush", "DHCP: leases not saved yet (\(error)); retrying")
            }
        }
        if !events.isEmpty {
            do { try await store.addDHCPEvents(events) } catch { limited("events", "DHCP: audit rows not saved (\(error))") }
        }
    }

    /// Expiry: active leases past their time end (DNS removed), offers lapse, quarantines end;
    /// history older than 30 days goes.
    func sweep() async {
        let now = clock()
        if now.timeIntervalSince(loadedAt) > Self.configTTL { await reload() }
        for l in table.sweep(now: now) {
            let scope = config.scope(id: l.scopeID)?.name ?? "#\(l.scopeID)"
            log("DHCP\(l.family == .v6 ? "v6" : "") lease \(l.address) of \(l.whoText) expired · scope \(scope)")
            pendingEvents.append(DHCPEvent(date: now, family: l.family, address: l.address, mac: l.mac, clientKey: l.clientKey,
                                           kind: "EXPIRED", detail: "lease time ran out"))
            if l.dnsName != nil || l.dnsPTR != nil { await applyDNS(DHCPv4Engine.unregisterAction(l)) }
        }
        _ = table.prune(before: now.addingTimeInterval(-Self.historyDays * 86_400))
        await flush()
        if now.timeIntervalSince(lastProfilePurge) >= Self.profileRefresh { await purgeProfiles(now: now) }
    }

    /// Hourly: `unknown`, non-manual device profiles unseen for 30 days go; cache entries older
    /// than the refresh interval are forgotten.
    func purgeProfiles(now: Date) async {
        lastProfilePurge = now
        profileCache = profileCache.filter { now.timeIntervalSince($0.value.at) < Self.profileRefresh }
        do {
            let n = try await store.purgeUnknownDeviceProfiles(lastSeenBefore: now.addingTimeInterval(-Self.historyDays * 86_400))
            if n > 0 { log("DHCP: \(n) unknown device profile\(n == 1 ? "" : "s") unseen for 30 days removed") }
        } catch {
            limited("profile-purge", "DHCP: device profile purge failed (\(error))")
        }
    }

    // Tests.
    func setSaveLeases(_ f: (@Sendable ([DHCPLease], [String]) async throws -> Void)?) { saveLeases = f }
    func putLease(_ l: DHCPLease) { table.put(l) }

    func adminRelease(family: DHCPFamily, address: String) async throws {
        guard var l = table.lease(family, address) else { throw CLIError.failure("no lease for \(address)") }
        let now = clock()
        if l.dnsName != nil || l.dnsPTR != nil { await applyDNS(DHCPv4Engine.unregisterAction(l)) }
        l = table.lease(family, address) ?? l
        l.state = .released
        l.expires = now
        l.updated = now
        l.dnsName = nil; l.dnsPTR = nil; l.dnsForward = false; l.dnsDHCID = nil
        table.put(l)
        pendingEvents.append(DHCPEvent(date: now, family: family, address: address, mac: l.mac, clientKey: l.clientKey,
                                       kind: "RELEASE", detail: "released in LabDC"))
        log("DHCP\(family == .v6 ? "v6" : "") lease \(address) of \(l.whoText) released (app)")
        await flush()
    }

    func allLeases() -> [DHCPLease] { table.all }

    func status(running: Bool) -> DHCPRuntimeStatus {
        let now = clock()
        var active: [Int64: Int] = [:]
        for l in table.all where l.state == .active && l.expires > now { active[l.scopeID, default: 0] += 1 }
        return DHCPRuntimeStatus(running: running, modeText: config.settings.modeText, scopes: config.scopes.filter(\.enabled).count,
                                 activeLeases: active.values.reduce(0, +), counters: global, perScope: counters, activePerScope: active)
    }
}
