import DHCPKit
import DNSKit
import Foundation
import Store
import Synchronization

/// Who may use the DC's DNS as a resolver (names outside the domain are forwarded only for them,
/// CVE audit 1 Oct 2026): the networks of this Mac's interfaces, the DHCP scopes' subnets and the
/// networks added in Settings (`dnsAllowedClients` / `--dns-allow`). Loopback and the DC's own
/// addresses always pass (DNSResponder). Re-read at most every `lifetime` seconds.
final class DNSRecursionACL: Sendable {
    private struct State {
        var extra: [DNSNetwork]
        var cached: (at: Date, list: [DNSNetwork])?
    }
    private let store: DirectoryStore
    private let connected: @Sendable () -> [DNSNetwork]
    private let lifetime: TimeInterval
    private let state: Mutex<State>

    init(store: DirectoryStore, extra: [DNSNetwork], lifetime: TimeInterval = 10,
         connected: @escaping @Sendable () -> [DNSNetwork] = { DNSClientNetworks.connected() }) {
        self.store = store
        self.lifetime = lifetime
        self.connected = connected
        self.state = Mutex(State(extra: extra, cached: nil))
    }

    /// Settings changed: the next query re-reads everything.
    func setExtra(_ networks: [DNSNetwork]) {
        state.withLock { $0 = State(extra: networks, cached: nil) }
    }

    var policy: DNSRecursionPolicy { .allowed { [self] address in await allows(address) } }

    func allows(_ address: DNSAddress) async -> Bool {
        await networks().contains { $0.contains(address) }
    }

    func networks() async -> [DNSNetwork] {
        let now = Date()
        let (fresh, extra): ([DNSNetwork]?, [DNSNetwork]) = state.withLock { s in
            if let cached = s.cached, now.timeIntervalSince(cached.at) < lifetime { return (cached.list, s.extra) }
            return (nil, s.extra)
        }
        if let fresh { return fresh }
        let scopes = ((try? await store.dhcpScopes()) ?? []).filter(\.enabled).compactMap { DNSNetwork($0.subnet) }
        var list: [DNSNetwork] = []
        for n in connected() + scopes + extra where !list.contains(n) { list.append(n) }
        state.withLock { $0.cached = (now, list) }
        return list
    }
}

extension DNSNetwork {
    /// `10.0.0.0/8, fd00::/64` (commas, spaces or new lines between) → networks; throws on the
    /// first entry that is not an address or a CIDR.
    public static func parseList(_ text: String) throws -> [DNSNetwork] {
        try text.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map { item in
            guard let n = DNSNetwork(String(item)) else { throw CLIError.usage("\(item) is not an address or CIDR") }
            return n
        }
    }
}
