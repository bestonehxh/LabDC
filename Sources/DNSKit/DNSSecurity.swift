import Darwin
import Foundation

// Hardening of the DNS server (CVE audit, 1 Oct 2026): Windows' global query block list,
// who may recurse, response rate limiting, and the address helpers they share.

/// Windows' global query block list (`dnscmd /config /globalqueryblocklist`): names whose first
/// label is `wpad` or `isatap` are never registered by a dynamic update or the DHCP server, and
/// never answered — a member that registered `wpad` would become every browser's proxy
/// (WPAD hijack), `isatap` every host's IPv6 router. An administrator who really serves one
/// creates a static record; only then is it answered.
public enum DNSBlockList {
    /// The leftmost labels Windows blocks by default (lower case).
    public static let names: Set<String> = ["wpad", "isatap"]

    /// Whether `name`'s first label is on the list (`wpad.lab.sheep`, `WPAD`, `isatap.corp.example`).
    /// `DNSResponder.reservedNameReason` includes it, so the DHCP server's dynamic DNS (which
    /// asks that) never registers a blocked name either.
    public static func isBlocked(_ name: DNSName) -> Bool {
        guard let first = name.canonicalLabels.first else { return false }
        return names.contains(String(decoding: first, as: UTF8.self))
    }
}

extension DNSAddress {
    /// The address a listener reports for `from` (`192.0.2.7`, `fe80::1%en0`, `::ffff:192.0.2.7`):
    /// the `%scope` dropped and an IPv4-mapped IPv6 address folded to IPv4. nil for anything that
    /// is not an address.
    public static func sender(_ text: String) -> DNSAddress? {
        let host = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        return DNSAddress(host)?.unmapped
    }

    /// `::ffff:a.b.c.d` as `a.b.c.d`; anything else unchanged.
    public var unmapped: DNSAddress {
        guard bytes.count == 16, bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF else { return self }
        return DNSAddress(bytes: Array(bytes[12..<16]))
    }

    /// The first `prefix` bits, the rest zero.
    func masked(_ prefix: Int) -> DNSAddress {
        var out = bytes
        for i in 0..<out.count {
            let bits = max(0, min(8, prefix - i * 8))
            out[i] &= bits == 8 ? 0xFF : UInt8(truncatingIfNeeded: 0xFF00 >> bits)
        }
        return DNSAddress(bytes: out)
    }
}

/// An IPv4 or IPv6 network (`10.20.0.0/24`, `fd00::/64`); a bare address is a host route.
public struct DNSNetwork: Hashable, Sendable, CustomStringConvertible {
    public let network: DNSAddress
    public let prefix: Int

    public init(address: DNSAddress, prefix: Int) {
        let p = max(0, min(address.bytes.count * 8, prefix))
        self.prefix = p
        self.network = address.masked(p)
    }

    /// `a.b.c.d/n`, `x::/n` or a bare address; nil when it is neither.
    public init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), let address = DNSAddress.sender(String(parts[0])) else { return nil }
        let bits = address.bytes.count * 8
        var prefix = bits
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...bits).contains(p) else { return nil }
            prefix = p
        }
        self.init(address: address, prefix: prefix)
    }

    public func contains(_ address: DNSAddress) -> Bool {
        let a = address.unmapped
        return a.bytes.count == network.bytes.count && a.masked(prefix) == network
    }

    public var description: String { "\(network)/\(prefix)" }
}

/// Who may use this server as a resolver (names outside our zones are forwarded only for them).
/// Answers for our own zones are given to anyone — a member must find the DC — but an open
/// resolver is a reflection/amplification tool and a cache-poisoning target.
public enum DNSRecursionPolicy: Sendable {
    /// Anyone (tests, a resolver deliberately offered to everyone).
    case any
    /// Only clients for which the check is true; loopback and the DC's own addresses always pass.
    case allowed(@Sendable (DNSAddress) async -> Bool)

    /// The networks of this Mac's interfaces (re-read every 10 s), the default.
    public static var connectedNetworks: DNSRecursionPolicy {
        let cache = DNSConnectedNetworksCache()
        return .allowed { address in cache.current().contains { $0.contains(address) } }
    }
}

/// The networks of the up interfaces of this Mac (IPv4 and IPv6, with their prefix lengths).
public enum DNSClientNetworks {
    public static func connected() -> [DNSNetwork] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [DNSNetwork] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, let sa = entry.pointee.ifa_addr, let mask = entry.pointee.ifa_netmask else { continue }
            let family = Int32(sa.pointee.sa_family)
            let address: [UInt8], netmask: [UInt8]
            if family == AF_INET {
                address = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin_addr) { Array($0) } }
                netmask = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin_addr) { Array($0) } }
            } else if family == AF_INET6 {
                address = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin6_addr) { Array($0) } }
                netmask = mask.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin6_addr) { Array($0) } }
            } else {
                continue
            }
            guard address.count == netmask.count else { continue }
            let prefix = netmask.reduce(0) { $0 + $1.nonzeroBitCount }
            let network = DNSNetwork(address: DNSAddress(bytes: address), prefix: prefix)
            if !out.contains(network) { out.append(network) }
        }
        return out
    }
}

/// `DNSClientNetworks.connected()`, re-read at most every `lifetime` seconds.
final class DNSConnectedNetworksCache: @unchecked Sendable {
    private let lock = NSLock()
    private var cached: (at: TimeInterval, list: [DNSNetwork])?
    private let lifetime: TimeInterval

    init(lifetime: TimeInterval = 10) { self.lifetime = lifetime }

    func current() -> [DNSNetwork] {
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock(); defer { lock.unlock() }
        if let cached, now - cached.at < lifetime { return cached.list }
        let list = DNSClientNetworks.connected()
        cached = (now, list)
        return list
    }
}

/// Response rate limiting (RRL, as in BIND/Knot) for UDP: a token bucket per client network
/// (/24 for IPv4, /56 for IPv6) and one per (client network, query name). A client over its rate
/// gets every `slip`-th answer as an empty truncated reply (a real client retries over TCP,
/// which is not limited and cannot be spoofed) and nothing otherwise, so the server is useless
/// as a reflector and a spoofed flood cannot hammer one name. Loopback is never limited.
public struct DNSRateLimit: Sendable, Equatable {
    /// Responses per second (and burst) to one client network.
    public var clientRate: Double = 100
    public var clientBurst: Double = 200
    /// Responses per second (and burst) to one client network for one name.
    public var nameRate: Double = 20
    public var nameBurst: Double = 40
    /// Every `slip`-th limited response is sent truncated (0: drop them all).
    public var slip: Int = 2
    public var ipv4Prefix = 24
    public var ipv6Prefix = 56

    public init() {}
}

/// The RRL state: two fixed-size tables of token buckets (client networks, and client network ×
/// query name), as in BIND. A key is hashed (with the process's random seed, so a client cannot
/// aim at another one's slot) to a set of `ways` adjacent slots; an unknown key takes an empty
/// or else the stalest slot of its set. Memory is fixed whatever a flood of random names or
/// random /56s sends, and a check is O(1) — no growing dictionary, no sweep (CVE audit 2 Oct 2026).
struct DNSRateLimiter {
    enum Verdict: Equatable { case answer, slip, drop }

    private struct Slot {
        /// The key's hash; 0: empty.
        var key: Int = 0
        var tokens: Double = 0
        var last: TimeInterval = 0
        var limited = 0
    }

    /// `count` slots in sets of `ways`, allocated on first use.
    private struct Table {
        static let ways = 4
        private var slots: [Slot] = []
        let count: Int

        init(count: Int) { self.count = max(1, count / Self.ways) * Self.ways }

        /// The index of `key`'s slot; a new key gets a full bucket.
        mutating func slot(_ key: Int, burst: Double, now: TimeInterval) -> Int {
            if slots.isEmpty { slots = Array(repeating: Slot(), count: count) }
            let key = key == 0 ? 1 : key
            let base = Int(UInt(bitPattern: key) % UInt(count / Self.ways)) * Self.ways
            var victim = base
            for i in base..<base + Self.ways {
                if slots[i].key == key { return i }
                if slots[victim].key == 0 { continue }
                if slots[i].key == 0 || slots[i].last < slots[victim].last { victim = i }
            }
            slots[victim] = Slot(key: key, tokens: burst, last: now)
            return victim
        }

        /// Refills slot `i` and takes one token; false (and the miss counted) when it is empty.
        mutating func take(_ i: Int, rate: Double, burst: Double, now: TimeInterval) -> Bool {
            slots[i].tokens = min(burst, slots[i].tokens + max(0, now - slots[i].last) * rate)
            slots[i].last = now
            guard slots[i].tokens >= 1 else {
                slots[i].limited += 1
                return false
            }
            slots[i].tokens -= 1
            return true
        }

        func limited(_ i: Int) -> Int { slots[i].limited }

        var occupied: Int { slots.reduce(0) { $0 + ($1.key == 0 ? 0 : 1) } }
    }

    let limit: DNSRateLimit
    private var clients: Table
    private var names: Table

    init(_ limit: DNSRateLimit, clientSlots: Int = 8192, nameSlots: Int = 32768) {
        self.limit = limit
        clients = Table(count: clientSlots)
        names = Table(count: nameSlots)
    }

    /// Slots in use and slots in all, per table (tests).
    var occupied: (clients: Int, names: Int) { (clients.occupied, names.occupied) }
    var capacity: (clients: Int, names: Int) { (clients.count, names.count) }

    /// Whether a response to `client` for `name` at `now` (seconds, monotonic) may go out. A
    /// client network over its rate is limited before its name is looked at, so a flood of
    /// random names from one network takes no name slots.
    mutating func check(client: DNSAddress, name: DNSName, now: TimeInterval) -> Verdict {
        let a = client.unmapped
        let net = a.masked(a.isIPv4 ? limit.ipv4Prefix : limit.ipv6Prefix)
        var hc = Hasher()
        hc.combine(net)
        let c = clients.slot(hc.finalize(), burst: limit.clientBurst, now: now)
        guard clients.take(c, rate: limit.clientRate, burst: limit.clientBurst, now: now) else {
            return verdict(clients.limited(c))
        }
        var hn = Hasher()
        hn.combine(net)
        hn.combine(name)            // DNSName hashes case-insensitively
        let n = names.slot(hn.finalize(), burst: limit.nameBurst, now: now)
        guard names.take(n, rate: limit.nameRate, burst: limit.nameBurst, now: now) else {
            return verdict(names.limited(n))
        }
        return .answer
    }

    private func verdict(_ count: Int) -> Verdict {
        limit.slip > 0 && count % limit.slip == 0 ? .slip : .drop
    }
}
