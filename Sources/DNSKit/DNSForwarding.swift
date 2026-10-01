import Foundation
import SystemConfiguration

/// Where the DNS server sends names outside its zones (owner, 27 Sep 2026: Windows PCs and
/// ClearPass point their DNS at the Mac to join, and must still resolve everything else).
public enum DNSForwarding: Hashable, Sendable {
    /// This Mac's resolvers as macOS uses them, followed as the network changes (`DNSSystemResolvers`).
    case system
    /// The servers from Settings ▸ Directory ▸ Other names (`--forwarders`).
    case servers([DNSUpstream])

    /// The plan for this moment. Upstreams that are this DNS server itself (a loopback or one of
    /// `ownAddresses`, on `ownPort`) are dropped: forwarding to ourselves only loops until it
    /// times out. The Mac's DNS with nothing left falls back to 1.1.1.1.
    public func plan(ownAddresses: Set<DNSAddress>, ownPort: UInt16,
                     system: () -> DNSSystemResolvers.Snapshot = { DNSSystemResolvers.current() }) -> DNSResolverPlan {
        func isSelf(_ u: DNSUpstream) -> Bool {
            guard u.port == ownPort, let a = u.address else { return false }
            return a.isLoopback || ownAddresses.contains(a)
        }
        var plan: DNSResolverPlan
        switch self {
        case .system:
            let snapshot = system()
            plan = DNSResolverPlan(defaults: snapshot.defaults, scoped: snapshot.scoped, origin: .system)
        case .servers(let list):
            plan = DNSResolverPlan(defaults: list, origin: .configured)
        }
        plan.skipped = (plan.defaults + plan.scoped.flatMap(\.servers)).filter(isSelf)
        plan.defaults.removeAll(where: isSelf)
        plan.scoped = plan.scoped.compactMap { s in
            let servers = s.servers.filter { !isSelf($0) }
            return servers.isEmpty ? nil : DNSScopedUpstreams(domain: s.domain, servers: servers)
        }
        if plan.defaults.isEmpty, self == .system {
            plan.defaults = [.cloudflare]
            plan.origin = .fallback
        }
        return plan
    }
}

/// Servers for one domain and below (a VPN's split DNS, an `/etc/resolver/<domain>` file).
public struct DNSScopedUpstreams: Hashable, Sendable {
    public var domain: DNSName
    public var servers: [DNSUpstream]

    public init(domain: DNSName, servers: [DNSUpstream]) {
        self.domain = domain
        self.servers = servers
    }
}

/// Which upstreams a forwarded name goes to.
public struct DNSResolverPlan: Hashable, Sendable {
    public enum Origin: String, Hashable, Sendable {
        /// This Mac's DNS.
        case system
        /// The servers in Settings / `--forwarders`.
        case configured
        /// The Mac had no usable DNS server: 1.1.1.1.
        case fallback
    }

    public var defaults: [DNSUpstream]
    public var scoped: [DNSScopedUpstreams]
    public var origin: Origin
    /// Entries left out because they are this DNS server itself.
    public var skipped: [DNSUpstream]

    public init(defaults: [DNSUpstream], scoped: [DNSScopedUpstreams] = [], origin: Origin = .configured,
                skipped: [DNSUpstream] = []) {
        self.defaults = defaults
        self.scoped = scoped
        self.origin = origin
        self.skipped = skipped
    }

    /// The servers for `name`: the longest matching scoped domain, else the defaults.
    public func upstreams(for name: DNSName) -> [DNSUpstream] {
        scoped.filter { name.isSubdomain(of: $0.domain) }
            .max { $0.domain.labels.count < $1.domain.labels.count }?.servers ?? defaults
    }

    /// "192.168.1.1, 8.8.8.8 · corp.example → 10.0.0.53"
    public var summary: String {
        var parts = [defaults.isEmpty ? "no server" : defaults.map(\.settingsText).joined(separator: ", ")]
        parts += scoped.map { "\($0.domain) → " + $0.servers.map(\.settingsText).joined(separator: ", ") }
        return parts.joined(separator: " · ")
    }
}

extension DNSUpstream {
    /// `10.0.0.53`, `10.0.0.53:5353`, `2001:db8::53`, `[2001:db8::53]:5353`, `fe80::1%en0`.
    /// Addresses only: a host name would need DNS to find the DNS server.
    public static func parse(_ text: String) throws -> DNSUpstream {
        let t = text.trimmingCharacters(in: .whitespaces)
        var host = t
        var port: UInt16 = 53
        func portValue(_ s: Substring) throws -> UInt16 {
            guard let p = UInt16(s), p > 0 else { throw DNSKitError.invalidText("\(text): the port is a number from 1 to 65535") }
            return p
        }
        if t.hasPrefix("["), let close = t.firstIndex(of: "]") {
            host = String(t[t.index(after: t.startIndex)..<close])
            let rest = t[t.index(after: close)...]
            if !rest.isEmpty {
                guard rest.hasPrefix(":") else { throw DNSKitError.invalidText("\(text): write [address]:port") }
                port = try portValue(rest.dropFirst())
            }
        } else if t.filter({ $0 == ":" }).count == 1 {
            let parts = t.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            host = String(parts[0])
            port = try portValue(parts[1])
        }
        let upstream = DNSUpstream(host: host, port: port)
        guard upstream.address != nil else {
            throw DNSKitError.invalidText("\(t.isEmpty ? "an empty entry" : t) is not an IP address (for example 10.0.0.53, 8.8.8.8 or 10.0.0.53:5353)")
        }
        return upstream
    }

    /// A list separated by commas, spaces, semicolons or new lines.
    public static func parseList(_ text: String) throws -> [DNSUpstream] {
        var out: [DNSUpstream] = []
        for item in text.split(whereSeparator: { $0 == "," || $0 == ";" || $0 == " " || $0.isNewline }) {
            let u = try parse(String(item))
            if !out.contains(u) { out.append(u) }
        }
        return out
    }

    /// `10.0.0.53`, or with the port when it is not 53 (`10.0.0.53:5353`, `[2001:db8::53]:5353`).
    public var settingsText: String { port == 53 ? host : description }

    /// The address without an IPv6 scope; nil for a name.
    public var address: DNSAddress? {
        DNSAddress(host.split(separator: "%", maxSplits: 1).first.map(String.init) ?? host)
    }
}

extension DNSAddress {
    /// 127.0.0.0/8 or ::1.
    public var isLoopback: Bool {
        isIPv4 ? bytes[0] == 127 : bytes == [UInt8](repeating: 0, count: 15) + [1]
    }
}

/// This Mac's resolvers, read the way macOS itself uses them (what `scutil --dns` shows).
public enum DNSSystemResolvers {
    public struct Snapshot: Hashable, Sendable {
        /// The primary network service's DNS servers.
        public var defaults: [DNSUpstream]
        /// Per-domain servers: VPN split DNS (`SupplementalMatchDomains`) and `/etc/resolver` files.
        public var scoped: [DNSScopedUpstreams]

        public init(defaults: [DNSUpstream], scoped: [DNSScopedUpstreams] = []) {
            self.defaults = defaults
            self.scoped = scoped
        }
    }

    /// Reads the dynamic store (`State:/Network/Global/DNS`, `State:/Network/Service/*/DNS`) and
    /// `/etc/resolver`; `/etc/resolv.conf` when the store has no default servers.
    public static func current(resolverDirectory: String = "/etc/resolver",
                               resolvConf: String = "/etc/resolv.conf") -> Snapshot {
        var defaults: [DNSUpstream] = []
        var scoped: [DNSScopedUpstreams] = []
        if let store = SCDynamicStoreCreate(nil, "LabDC DNS" as CFString, nil, nil) {
            if let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
                defaults = addresses(global["ServerAddresses"])
            }
            let pattern = ["State:/Network/Service/[^/]+/DNS"] as CFArray
            if let services = SCDynamicStoreCopyMultiple(store, nil, pattern) as? [String: Any] {
                for key in services.keys.sorted() {
                    guard let dns = services[key] as? [String: Any],
                          let domains = dns["SupplementalMatchDomains"] as? [String] else { continue }
                    let servers = addresses(dns["ServerAddresses"])
                    guard !servers.isEmpty else { continue }
                    for domain in domains where !domain.isEmpty {
                        if let name = try? DNSName(parsing: domain) { scoped.append(DNSScopedUpstreams(domain: name, servers: servers)) }
                    }
                }
            }
        }
        scoped += resolverFiles(resolverDirectory)
        if defaults.isEmpty {
            defaults = DNSUpstream.parseResolvConf((try? String(contentsOfFile: resolvConf, encoding: .utf8)) ?? "")
        }
        return Snapshot(defaults: defaults, scoped: scoped)
    }

    /// `/etc/resolver/<domain>` files (`nameserver` lines and an optional `port`).
    static func resolverFiles(_ directory: String) -> [DNSScopedUpstreams] {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return [] }
        var out: [DNSScopedUpstreams] = []
        for file in files.sorted() where !file.hasPrefix(".") {
            let text = (try? String(contentsOfFile: directory + "/" + file, encoding: .utf8)) ?? ""
            out += resolverFile(domain: file, text: text).map { [$0] } ?? []
        }
        return out
    }

    static func resolverFile(domain: String, text: String) -> DNSScopedUpstreams? {
        var port: UInt16 = 53
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            if fields.count >= 2, fields[0] == "port", let p = UInt16(fields[1]) { port = p }
        }
        let servers = DNSUpstream.parseResolvConf(text).map { DNSUpstream(host: $0.host, port: port) }
        guard !servers.isEmpty, let name = try? DNSName(parsing: domain) else { return nil }
        return DNSScopedUpstreams(domain: name, servers: servers)
    }

    private static func addresses(_ value: Any?) -> [DNSUpstream] {
        ((value as? [String]) ?? []).map { DNSUpstream(host: $0) }.filter { $0.address != nil }
    }
}
