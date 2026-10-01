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
    /// UI-1c: this Mac's IPv4 interfaces (`Wi-Fi 192.168.1.155`, `Tailscale 100.64.0.10`).
    public var interfaces: [NetworkInterfaceChoice] = []
    /// UI-1c: the interface that owns `advertisedIPv4` (`Wi-Fi`), nil when none does.
    public var advertisedInterfaceName: String? {
        NetworkInterfaces.choice(for: advertisedIPv4, in: interfaces)?.displayName
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
        Self.services(listeners: listeners, restarting: restarting, lastRestart: lastRestart)
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
        case .problem: "Not running"
        case .stopped: "Stopped"
        case .notSetUp: "Not set up yet"
        }
    }

    /// "DNS, Kerberos, LDAP, SMB, RPC, HTTP".
    public var statusSubtitle: String {
        runningServices.isEmpty ? "No service is listening." : runningServices.joined(separator: ", ")
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
        guard let lastError else { return [] }
        return services.contains { $0.problemMessage == lastError } ? [] : [lastError]
    }

    /// Worth knowing but not a problem: several addresses without a pinned one.
    public var notes: [String] {
        guard !advertisePinned, addresses.count > 1, phase == .running else { return [] }
        return ["This Mac has \(addresses.count) addresses (\(addresses.joined(separator: ", "))); devices are told \(advertisedIPv4 ?? "?"). "
                + "Choose the one devices use in Settings ▸ Directory ▸ Network."]
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
            ("SCEP ", .http), ("EST ", .est), ("HTTPS ", .https), ("RADIUS ", .radius),
        ]
        return prefixes.first { message.hasPrefix($0.0) }?.1
    }
}
