import Foundation

/// What the owner sees instead of ports (owner decision 26 Sep 2026): the Overview status, the
/// sidebar tooltip and Settings ▸ Directory group the listeners by service.
public enum ServeService: String, CaseIterable, Identifiable, Sendable, Hashable {
    case dns, kerberos, directory, fileAndRPC, time, webPKI, radius, dhcp

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .dns: "DNS"
        case .kerberos: "Kerberos"
        case .directory: "Directory"
        case .fileAndRPC: "File & RPC"
        case .time: "Time"
        case .webPKI: "Web/PKI"
        case .radius: "RADIUS"
        case .dhcp: "DHCP"
        }
    }

    /// One sentence under the title (plain words; the technical names are in the ports line).
    public var summary: String {
        switch self {
        case .dns: "Devices find the domain and this Mac by name."
        case .kerberos: "Sign-in tickets and password changes."
        case .directory: "Users, groups and computers over LDAP."
        case .fileAndRPC: "Domain join, Group Policy files and NAC password checks."
        case .time: "Keeps joined computers' clocks in step."
        case .webPKI: "CA download, CRL and certificate enrollment."
        case .radius: "802.1X: the NAS asks, the policy answers with VLANs."
        case .dhcp: "Addresses for test VLANs, through the switches' DHCP relay."
        }
    }

    public var symbol: String {
        switch self {
        case .dns: "signpost.right"
        case .kerberos: "key"
        case .directory: "person.2.badge.key"
        case .fileAndRPC: "folder.badge.gearshape"
        case .time: "clock"
        case .webPKI: "globe.badge.chevron.backward"
        case .radius: "dot.radiowaves.right"
        case .dhcp: "network"
        }
    }

    /// The listeners behind the service, in display order (NetBIOS 139/137 sit with SMB).
    public var listeners: [ServeListener] {
        switch self {
        case .dns: [.dns]
        case .kerberos: [.kdc, .kpasswd]
        case .directory: [.ldap, .ldaps, .gc, .gcs, .cldap]
        case .fileAndRPC: [.smb, .nbss, .nbns, .epm, .rpc]
        case .time: [.sntp]
        case .webPKI: [.http, .https, .est]
        case .radius: [.radius, .radacct]
        case .dhcp: [.dhcp, .dhcpv6]
        }
    }

    /// The service a listener belongs to.
    public static func of(_ listener: ServeListener) -> ServeService {
        allCases.first { $0.listeners.contains(listener) } ?? .webPKI
    }

    /// Other services a Restart also bounces because they share a server object with this one
    /// (SMB and SNTP are started together).
    public var restartAlsoAffects: [ServeService] {
        switch self {
        case .fileAndRPC: [.time]
        case .time: [.fileAndRPC]
        default: []
        }
    }
}

/// One service row: a single state for all its listeners, the ports as secondary text.
public struct ServiceStatus: Identifiable, Hashable, Sendable {
    public enum State: Hashable, Sendable {
        case running
        case starting
        case restarting
        /// At least one listener failed; the message is the first failure.
        case problem(String)
        /// Every listener is turned off in Settings (for example "Let devices join the domain").
        case off
        case stopped
    }

    public var service: ServeService
    public var id: ServeService { service }
    public var state: State
    /// The service's listeners (off ones included, with state `.off`).
    public var listeners: [ListenerStatus]
    /// The result of the last Restart of this row (`Restarted 14:02:11` / the error), until the next one.
    public var lastRestart: RestartOutcome?
    /// A one-line runtime summary (DHCP: `relay-only · 4 scopes · 123 leases`).
    public var detail: String?

    public init(service: ServeService, state: State, listeners: [ListenerStatus], lastRestart: RestartOutcome? = nil) {
        self.service = service
        self.state = state
        self.listeners = listeners
        self.lastRestart = lastRestart
    }

    /// `Running` / `Starting…` / `Restarting…` / `Problem` / `Off` / `Stopped`.
    public var stateLabel: String {
        switch state {
        case .running: "Running"
        case .starting: "Starting…"
        case .restarting: "Restarting…"
        case .problem: "Problem"
        case .off: service == .dhcp ? "Off until a scope exists" : "Off in Settings"
        case .stopped: "Stopped"
        }
    }

    public var problemMessage: String? {
        if case .problem(let m) = state { return m }
        return nil
    }

    /// `LDAP 389 · LDAPS 636 · GC 3268 · GC-TLS 3269 · CLDAP udp 389`: every listener that is on,
    /// with the bound port when running, else the configured one.
    /// NetBIOS shows as one token, `NetBIOS 137/139` (`NetBIOS 139` when macOS's netbiosd holds 137).
    public var portsText: String {
        func port(_ l: ListenerStatus) -> String {
            l.port.map(String.init) ?? (l.configuredPort == 0 ? "auto" : String(l.configuredPort))
        }
        var tokens: [String] = []
        let on = listeners.filter { $0.state != .off }
        for l in on {
            switch l.listener {
            case .nbns:
                continue
            case .nbss:
                if let ns = on.first(where: { $0.listener == .nbns }) {
                    tokens.append("NetBIOS \(port(ns))/\(port(l))")
                } else {
                    tokens.append("NetBIOS \(port(l))")
                }
            // The row already says RADIUS: "Auth udp 1812 · Accounting udp 1813" (owner, 2 Oct 2026).
            case .radius:
                tokens.append("Auth udp \(port(l))")
            case .radacct:
                tokens.append("Accounting udp \(port(l))")
            default:
                let proto = l.listener.transport == "udp" ? "udp " : ""
                tokens.append("\(l.listener.shortName) \(proto)\(port(l))")
            }
        }
        return tokens.joined(separator: " · ")
    }

    /// A listener that is off although the service runs, in plain words (NetBIOS name service
    /// when macOS holds udp 137), shown under the ports.
    public var note: String? {
        guard state == .running || problemMessage != nil,
              listeners.contains(where: { $0.listener == .nbns && $0.state == .off }),
              listeners.contains(where: { $0.listener == .nbss && $0.state != .off }) else { return nil }
        return "NetBIOS name service is off: macOS's own netbiosd holds udp 137 (names still resolve through DNS)."
    }

    /// Restart makes sense only while the server runs and the service is not off or mid-restart;
    /// on a row stopped with Stop it starts the service again.
    public var canRestart: Bool {
        switch state {
        case .running, .problem, .stopped: true
        default: false
        }
    }

    /// Services ▸ Stop: a running (or failing) service can be stopped on its own.
    public var canStop: Bool {
        switch state {
        case .running, .problem: true
        default: false
        }
    }

    /// What else a Stop takes down because it shares the server ("Time", "File & RPC").
    public var stopAlsoAffects: [ServeService] { service.restartAlsoAffects }

    /// Folds the listener states into one: problem wins, then restarting, starting, running, off, stopped.
    public static func make(_ service: ServeService, listeners all: [ListenerStatus], restarting: Bool,
                            lastRestart: RestartOutcome? = nil) -> ServiceStatus {
        let mine = service.listeners.compactMap { l in all.first { $0.listener == l } }
        let state: State
        if let failed = mine.first(where: { if case .failed = $0.state { true } else { false } }),
           case .failed(let why) = failed.state {
            state = restarting ? .restarting : .problem(service == .dhcp ? dhcpProblem(mine) ?? why : why)
        } else if restarting {
            state = .restarting
        } else if mine.contains(where: { $0.state == .starting }) {
            state = .starting
        } else if mine.contains(where: { $0.state == .running }) {
            state = .running
        } else if !mine.isEmpty, mine.allSatisfy({ $0.state == .off }) {
            state = .off
        } else {
            state = .stopped
        }
        return ServiceStatus(service: service, state: state, listeners: mine, lastRestart: lastRestart)
    }

    /// DHCPv4 and DHCPv6 are independent: `Running (IPv4) · IPv6: udp 547 in use by …` when one
    /// runs and the other failed; `IPv4: … · IPv6: …` when both failed. nil when none failed.
    static func dhcpProblem(_ listeners: [ListenerStatus]) -> String? {
        func family(_ l: ServeListener) -> String { l == .dhcpv6 ? "IPv6" : "IPv4" }
        func reason(_ l: ListenerStatus, _ why: String) -> String {
            let port = l.port ?? Int(l.configuredPort)
            if let holder = PortProbe.holderName(in: why) {
                return holder.hasPrefix("not visible")
                    ? "udp \(port) in use (\(holder))"
                    : "udp \(port) in use by \(holder)"
            }
            // `DHCPv6 udp 547: …` → `…`.
            if let colon = why.range(of: ": "), why.hasPrefix(l.listener.shortName + " ") {
                return String(why[colon.upperBound...])
            }
            return why
        }
        var running: [String] = []
        var failed: [String] = []
        for l in listeners {
            switch l.state {
            case .running: running.append(family(l.listener))
            case .failed(let why): failed.append("\(family(l.listener)): \(reason(l, why))")
            default: break
            }
        }
        guard !failed.isEmpty else { return nil }
        let head = running.isEmpty ? [] : ["Running (\(running.joined(separator: ", ")))"]
        return (head + failed).joined(separator: " · ")
    }
}

/// What the last Restart of a service did.
public struct RestartOutcome: Hashable, Sendable {
    public var date: Date
    /// nil when it worked.
    public var error: String?

    public init(date: Date, error: String? = nil) {
        self.date = date
        self.error = error
    }

    public var succeeded: Bool { error == nil }
}
