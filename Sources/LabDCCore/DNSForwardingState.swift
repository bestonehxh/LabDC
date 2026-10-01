import DNSKit
import Foundation

/// What the DNS forwarder's plan is built from: the setting, the port DNS bound and the advertised
/// address (with this Mac's addresses, read on every refresh, they are what "ourselves" means).
final class DNSForwardingState: @unchecked Sendable {
    private let lock = NSLock()
    private var forwarding: DNSForwarding = .system
    private var boundPort: UInt16 = 53
    private var advertise: String?

    func update(forwarding: DNSForwarding, port: UInt16, advertise: String?) {
        lock.lock(); defer { lock.unlock() }
        self.forwarding = forwarding
        if port != 0 { boundPort = port }
        self.advertise = advertise
    }

    var port: UInt16 { lock.lock(); defer { lock.unlock() }; return boundPort }

    func plan() -> DNSResolverPlan {
        lock.lock()
        let (forwarding, port, advertise) = (self.forwarding, boundPort, self.advertise)
        lock.unlock()
        let own = Set((ServeAddresses.current() + [advertise].compactMap { $0 }).compactMap(DNSAddress.init))
        return forwarding.plan(ownAddresses: own, ownPort: port)
    }
}

extension DNSResolverPlan {
    /// "this Mac's DNS" / "set in Settings" / the fallback explained.
    public var originText: String {
        switch origin {
        case .system: "this Mac's DNS"
        case .configured: "set in Settings"
        case .fallback: "this Mac has no DNS server of its own, so 1.1.1.1"
        }
    }
}

extension DNSForwarding {
    /// Settings ▸ Directory ▸ Other names: `[]` = this Mac's DNS, else the servers as typed.
    public init(settingsList: [String]) {
        let servers = settingsList.compactMap { try? DNSUpstream.parse($0) }
        self = servers.isEmpty ? .system : .servers(servers)
    }

    /// `--forwarders` / the settings field: "system" (or empty) = this Mac's DNS, else a list.
    public init(parsing text: String) throws {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty || t.lowercased() == "system" { self = .system; return }
        let servers = try DNSUpstream.parseList(t)
        self = servers.isEmpty ? .system : .servers(servers)
    }

    public var settingsList: [String] {
        if case .servers(let list) = self { return list.map(\.settingsText) }
        return []
    }
}

/// The Services page's line about forwarding (plain strings, so the app need not import DNSKit).
public struct DNSForwardingInfo: Equatable, Sendable {
    /// "192.168.1.1, 8.8.8.8 · corp.example → 10.0.0.53"
    public var servers: String
    /// "this Mac's DNS" / "set in Settings" / the fallback explained.
    public var origin: String
    public var isFallback: Bool
    /// Entries left out because they are this Mac.
    public var skipped: [String]

    public init(servers: String, origin: String, isFallback: Bool = false, skipped: [String] = []) {
        self.servers = servers
        self.origin = origin
        self.isFallback = isFallback
        self.skipped = skipped
    }

    init(_ plan: DNSResolverPlan) {
        self.init(servers: plan.summary, origin: plan.originText, isFallback: plan.origin == .fallback,
                  skipped: plan.skipped.map(\.settingsText))
    }
}

public struct DNSForwardingTestResult: Equatable, Sendable {
    public var ok: Bool
    public var text: String
}
