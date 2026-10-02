import Foundation
import Observation
import Store

/// One listener as the app shows it.
public struct ListenerStatus: Identifiable, Hashable, Sendable {
    public enum State: Hashable, Sendable {
        case starting
        case running
        /// Turned off in Settings (for example "Let devices join the domain").
        case off
        /// Not running because the server is stopped.
        case stopped
        case failed(String)
    }

    public var listener: ServeListener
    public var id: ServeListener { listener }
    /// The bound port while running.
    public var port: Int?
    /// The port from the settings.
    public var configuredPort: UInt16
    public var state: State

    public init(listener: ServeListener, port: Int?, configuredPort: UInt16, state: State) {
        self.listener = listener
        self.port = port
        self.configuredPort = configuredPort
        self.state = state
    }

    /// `LDAPS 636`, `RPC 49664`.
    public var chipLabel: String {
        let p = port.map(String.init) ?? (configuredPort == 0 ? "auto" : String(configuredPort))
        return "\(listener.shortName) \(p)"
    }
}

/// The embedded server as the sidebar and Overview see it. Updated by `ServerController` on the
/// main actor; views observe it.
@MainActor @Observable
public final class ServerStatus {
    public enum Phase: String, Sendable {
        case notSetUp, stopped, starting, stopping, running, problem
        /// Restart All, a settings restart or a domain rename: between the stop and the start.
        case restarting
    }

    /// Starting, stopping or restarting: nothing may replace the controller or move its folder.
    public var isBusy: Bool { [.starting, .stopping, .restarting].contains(phase) }

    public var phase: Phase = .stopped
    public var listeners: [ListenerStatus] = []
    /// What DNS/CLDAP/EPM hand out (`--advertise` or the first interface address).
    public var advertisedIPv4: String?
    public var addresses: [String] = []
    public var advertisePinned = false
    /// The runtime has reported the interface list at least once (so a nil address means none).
    public var addressesReported = false
    /// UI-1c: this Mac's IPv4 interfaces (`Wi-Fi 192.168.1.155`, `Tailscale 100.64.0.10`).
    public var interfaces: [NetworkInterfaceChoice] = []
    /// UI-1c: the interface that owns `advertisedIPv4` (`Wi-Fi`), nil when none does.
    public var advertisedInterfaceName: String? {
        NetworkInterfaces.choice(for: advertisedIPv4, in: interfaces)?.displayName
    }
    /// The address devices are told is not on this Mac any more (owner, 1 Oct 2026): the pinned
    /// interface went offline, or the Mac has no IPv4 address at all. Nil while not running.
    public var networkProblem: String? {
        guard phase == .running || phase == .problem else { return nil }
        guard addressesReported else { return nil }
        guard let ip = advertisedIPv4 else {
            return "This Mac has no network address; devices cannot reach the domain."
        }
        if advertisePinned, !interfaces.isEmpty, !interfaces.contains(where: { $0.ipv4 == ip }) {
            return "\(ip) (chosen in Settings) is offline; devices cannot reach the domain. Reconnect it or pick another address in Settings ▸ System."
        }
        return nil
    }
    /// `Wi-Fi 192.168.1.155` / `192.168.1.155` (sidebar header, Overview).
    public var advertisedLabel: String? {
        guard let ip = advertisedIPv4 else { return nil }
        return advertisedInterfaceName.map { "\($0) \(ip)" } ?? ip
    }
    public var realm: String?
    public var dnsDomain: String?
    public var netbiosDomain: String?
    public var dcName: String?
    public var dcDNSName: String?
    public var baseDN: String?
    public var startedAt: Date?
    /// Why the server is not running (start failed), or the last failed port change.
    public var lastError: String?
    /// UI-1b: services whose Restart is in progress.
    public var restarting: Set<ServeService> = []
    /// UI-1b: the result of each service's last Restart.
    public var lastRestart: [ServeService: RestartOutcome] = [:]
    /// Phase 5: `relay-only · 4 scopes · 123 leases` while DHCP runs.
    public var dhcpSummary: String?
    /// Phase 5: DHCP was stopped with Services ▸ Stop. Its listeners read as off (DHCP is off
    /// until a scope exists), so the row says Stopped (and offers Start) from this instead.
    public var dhcpStopped = false

    public init() {}

    /// Sidebar: "Running" / "Starting…" / "Problem".
    public var headline: String {
        switch phase {
        case .running: "Running"
        case .starting: "Starting…"
        case .stopping: "Stopping…"
        case .restarting: "Restarting…"
        case .problem: "Problem"
        case .stopped: "Stopped"
        case .notSetUp: "Not set up"
        }
    }

    /// UI-1b: one row per service (DNS · Kerberos · Directory · File & RPC · Time · Web/PKI),
    /// each with a single state; the Overview, the sidebar tooltip and Settings use it.
    public var services: [ServiceStatus] {
        Self.services(listeners: listeners, restarting: restarting, lastRestart: lastRestart).map { s in
            var s = s
            if s.service == .dhcp, s.state == .running { s.detail = dhcpSummary }
            if s.service == .dhcp, s.state == .off, dhcpStopped { s.state = .stopped }
            return s
        }
    }

    public nonisolated static func services(listeners: [ListenerStatus], restarting: Set<ServeService> = [],
                                            lastRestart: [ServeService: RestartOutcome] = [:]) -> [ServiceStatus] {
        ServeService.allCases.map {
            ServiceStatus.make($0, listeners: listeners, restarting: restarting.contains($0), lastRestart: lastRestart[$0])
        }
    }

    /// Titles of the services that are running, in Overview order.
    public var runningServices: [String] {
        services.filter { $0.state == .running || $0.state == .restarting }.map(\.service.title)
    }

    /// The sidebar header tooltip: one line per service (`Directory: Running — LDAP 389 · …`).
    public var servicesTooltip: String {
        services.map { s in
            "\(s.service.title): \(s.stateLabel)" + (s.state == .off ? "" : " — \(s.portsText)")
                + (s.problemMessage.map { " (\($0))" } ?? "")
        }.joined(separator: "\n")
    }

    /// "Everything is running" / "Starting…" / "2 problems".
    public var statusTitle: String {
        switch phase {
        case .running: problems.isEmpty ? "Everything is running" : "Running, with \(problems.count) problem\(problems.count == 1 ? "" : "s")"
        case .starting: "Starting…"
        case .stopping: "Stopping…"
        case .restarting: "Restarting…"
        // A listener problem while the rest runs is not "Not running" (owner, 1 Oct 2026: a busy
        // DHCP port read as "Not running" above a list of the services that were running).
        case .problem: runningServices.isEmpty ? "Not running"
            : "Running, with \(max(problems.count, 1)) problem\(problems.count > 1 ? "s" : "")"
        case .stopped: "Stopped"
        case .notSetUp: "Not set up yet"
        }
    }

    /// "DNS, Kerberos, LDAP, SMB, RPC, HTTP" while everything runs; with a problem, only what is
    /// not running ("Not running: DHCPv6").
    public var statusSubtitle: String {
        if runningServices.isEmpty { return "No service is listening." }
        if phase == .problem || !problems.isEmpty, !notRunningServices.isEmpty {
            return "Not running: " + notRunningServices.joined(separator: ", ")
        }
        return runningServices.joined(separator: ", ")
    }

    /// What is not running although it should (a problem or a Stop; off in Settings does not
    /// count), in Overview order. A service that runs in part names its failed listeners
    /// (`DHCPv6`, `LDAPS`).
    public var notRunningServices: [String] {
        services.flatMap { s -> [String] in
            switch s.state {
            case .problem, .stopped:
                let failed = s.listeners.filter { if case .failed = $0.state { true } else { false } }
                if !failed.isEmpty, s.listeners.contains(where: { $0.state == .running }) {
                    return failed.map(\.listener.displayName)
                }
                return [s.service.title]
            default:
                return []
            }
        }
    }

    /// Every problem, one sentence each: the start error and each service in trouble.
    public var problems: [String] {
        var out: [String] = []
        if let lastError { out.append(lastError) }
        for s in services {
            if let why = s.problemMessage, why != lastError { out.append("\(s.service.title): \(why)") }
        }
        return out
    }

    /// Problems no service row shows (a start failure outside any listener, like the store).
    public var generalProblems: [String] {
        var out: [String] = []
        if let networkProblem { out.append(networkProblem) }
        guard let lastError else { return out }
        return services.contains { $0.problemMessage == lastError } ? out : out + [lastError]
    }

    /// Fills the realm/domain/DC names.
    public func apply(_ info: DomainInfo) {
        realm = info.realm
        dnsDomain = info.dnsDomain
        netbiosDomain = info.netbiosDomain
        dcName = info.dcName
        dcDNSName = info.dcDNSName
        baseDN = info.domainDN.description
    }

    /// Rebuilds `listeners` from the options and what is bound.
    public func applyListeners(options: ServeOptions, bound: ServeBoundPorts?, failures: [ServeListener: String],
                               starting: Bool = false) {
        listeners = Self.listenerStatuses(options: options, bound: bound, failures: failures, starting: starting)
    }

    /// The listener rows: failures first win, then off (disabled), then running (bound),
    /// starting, or stopped.
    public nonisolated static func listenerStatuses(options: ServeOptions, bound: ServeBoundPorts?, failures: [ServeListener: String],
                                                    starting: Bool = false) -> [ListenerStatus] {
        ServeListener.allCases.map { l in
            let configured = options.ports[l]
            let port = bound.flatMap { l.bound(in: $0) }
            let state: ListenerStatus.State
            if let why = failures[l] {
                state = .failed(why)
            } else if !l.isEnabled(in: options) {
                state = .off
            } else if l == .dhcp || l == .dhcpv6, port == nil, bound != nil, !starting {
                // Phase 5: DHCP runs only once a scope exists: off (not a problem) before that.
                state = .off
            } else if l == .nbns, port == nil, bound != nil, !starting {
                // The runtime skips NBNS (with a log line) when macOS's netbiosd holds udp 137:
                // off, not a problem.
                state = .off
            } else if port != nil {
                state = .running
            } else if starting {
                state = .starting
            } else {
                state = .stopped
            }
            return ListenerStatus(listener: l, port: port, configuredPort: configured, state: state)
        }
    }
}

extension ServeListener {
    /// The listener a start-up error names (`CLIError` messages start with `DNS udp+tcp 53: …`,
    /// `LDAP tcp 389/636/…`, `EPM tcp 135`, …).
    public static func named(inError message: String) -> ServeListener? {
        let prefixes: [(String, ServeListener)] = [
            ("DNS ", .dns), ("KDC ", .kdc), ("kpasswd ", .kpasswd), ("LDAP ", .ldap), ("CLDAP ", .cldap),
            ("SMB ", .smb), ("SYSVOL ", .smb), ("SNTP ", .sntp), ("EPM ", .epm), ("RPC ", .rpc), ("HTTP ", .http),
            ("SCEP ", .http), ("EST ", .est), ("HTTPS ", .https), ("RADIUS ", .radius), ("DHCPv6 ", .dhcpv6), ("DHCP ", .dhcp),
        ]
        return prefixes.first { message.hasPrefix($0.0) }?.1
    }
}
