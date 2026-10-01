import Foundation

/// NAS addresses (30 Sep 2026): IPv4 and IPv6, with or without a `%en0` scope, IPv4-mapped IPv6
/// folded to IPv4; a client entry is an address, a CIDR (`10.0.0.0/24`, `fd00::/64`) or a range
/// (`10.0.0.10-10.0.0.20`).
public enum RADIUSAddress {
    /// Canonical text of an address (`fe80::1%en0` → `fe80::1`, `::ffff:10.0.0.5` → `10.0.0.5`,
    /// `[2001:db8::1]` → `2001:db8::1`); nil when it is not an IP address.
    public static func normalize(_ text: String) -> String? {
        bytes(text).map(format)
    }

    /// 4 bytes (IPv4) or 16 (IPv6).
    public static func bytes(_ text: String) -> [UInt8]? {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") { s = String(s[s.index(after: s.startIndex)..<close]) }
        if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, s, &v6) == 1 else { return nil }
        let b = withUnsafeBytes(of: &v6) { Array($0) }
        if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff { return Array(b[12..<16]) }
        return b
    }

    public static func format(_ b: [UInt8]) -> String {
        if b.count == 4 { return b.map(String.init).joined(separator: ".") }
        var v6 = in6_addr()
        withUnsafeMutableBytes(of: &v6) { dst in for (i, x) in b.prefix(16).enumerated() { dst[i] = x } }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &buf, socklen_t(buf.count)) != nil else { return "?" }
        return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// Whether `address` falls in `pattern` (address, CIDR or range; same family only).
    public static func matches(pattern: String, address: String) -> Bool {
        guard let source = bytes(address) else { return false }
        let p = pattern.trimmingCharacters(in: .whitespaces)
        if let slash = p.lastIndex(of: "/") {
            guard let base = bytes(String(p[..<slash])), base.count == source.count,
                  let bits = Int(p[p.index(after: slash)...]), (0...(base.count * 8)).contains(bits) else { return false }
            for i in 0..<base.count {
                let take = max(0, min(8, bits - i * 8))
                let mask: UInt8 = take == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - take))
                if base[i] & mask != source[i] & mask { return false }
            }
            return true
        }
        if let dash = p.firstIndex(of: "-"), let from = bytes(String(p[..<dash])),
           let to = bytes(String(p[p.index(after: dash)...])), from.count == source.count, to.count == source.count {
            return !source.lexicographicallyPrecedes(from) && !to.lexicographicallyPrecedes(source)
        }
        return bytes(p) == source
    }

    /// Whether `pattern` is something `matches` understands (the client editor validates with it).
    public static func isValidPattern(_ pattern: String) -> Bool {
        let p = pattern.trimmingCharacters(in: .whitespaces)
        if let slash = p.lastIndex(of: "/") {
            guard let base = bytes(String(p[..<slash])), let bits = Int(p[p.index(after: slash)...]) else { return false }
            return (0...(base.count * 8)).contains(bits)
        }
        if let dash = p.firstIndex(of: "-") {
            guard let a = bytes(String(p[..<dash])), let b = bytes(String(p[p.index(after: dash)...])) else { return false }
            return a.count == b.count
        }
        return bytes(p) != nil
    }
}

/// RFC 5080 §2.2.2: a retransmitted request (same source, port, Identifier and Request
/// Authenticator) gets the cached reply again — never a second evaluation (which would count a
/// second bad password or give a different MS-CHAPv2 answer). Entries live 30 s (a NAS retries for up to ~30 s).
public struct RADIUSDuplicateCache: Sendable {
    public struct Key: Hashable, Sendable {
        public var source: String
        public var port: UInt16
        public var id: UInt8
        public var authenticator: [UInt8]
        public init(source: String, port: UInt16, id: UInt8, authenticator: [UInt8]) {
            self.source = source; self.port = port; self.id = id; self.authenticator = authenticator
        }
    }

    public enum Lookup: Equatable, Sendable {
        /// First sight: handle it, then `finish`.
        case new
        /// The first copy is still being handled: drop this one.
        case inProgress
        /// Already answered: send these bytes again.
        case replay([UInt8])
        /// Already dropped (no reply): drop again.
        case dropped
    }

    private enum Entry { case pending, reply([UInt8]?) }
    private var entries: [Key: (entry: Entry, at: Date)] = [:]
    public let lifetime: TimeInterval
    public let capacity: Int

    public init(lifetime: TimeInterval = 30, capacity: Int = 4096) {
        self.lifetime = lifetime
        self.capacity = capacity
    }

    public var count: Int { entries.count }

    public mutating func begin(_ key: Key, now: Date) -> Lookup {
        if let hit = entries[key], now.timeIntervalSince(hit.at) < lifetime {
            switch hit.entry {
            case .pending: return .inProgress
            case .reply(let bytes?): return .replay(bytes)
            case .reply(nil): return .dropped
            }
        }
        if entries.count >= capacity { prune(now: now) }
        if entries.count >= capacity {
            // Still full of live entries: forget the oldest rather than grow without bound.
            if let oldest = entries.min(by: { $0.value.at < $1.value.at })?.key { entries[oldest] = nil }
        }
        entries[key] = (.pending, now)
        return .new
    }

    public mutating func finish(_ key: Key, reply: [UInt8]?, now: Date) {
        entries[key] = (.reply(reply), now)
    }

    public mutating func prune(now: Date) {
        entries = entries.filter { now.timeIntervalSince($0.value.at) < lifetime }
    }
}

/// One log line per key per interval; the next admitted line says how many were held back
/// ("unknown NAS 10.0.0.9 dropped (37 more)") — a scanning host must not flood Activity.
public struct RADIUSLogLimiter: Sendable {
    private var last: [String: (at: Date, suppressed: Int)] = [:]
    public let interval: TimeInterval
    public let capacity: Int

    public init(interval: TimeInterval = 60, capacity: Int = 1024) {
        self.interval = interval
        self.capacity = capacity
    }

    /// nil = hold this line back; otherwise the number of lines held back since the last one.
    public mutating func admit(_ key: String, now: Date) -> Int? {
        if let seen = last[key], now.timeIntervalSince(seen.at) < interval {
            last[key] = (seen.at, seen.suppressed + 1)
            return nil
        }
        let suppressed = last[key]?.suppressed ?? 0
        if last.count >= capacity { last = last.filter { now.timeIntervalSince($0.value.at) < interval } }
        if last.count >= capacity { last.removeAll() }
        last[key] = (now, 0)
        return suppressed
    }
}
