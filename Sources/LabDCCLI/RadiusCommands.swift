import Foundation
import RADIUSKit
import LabDCCore
import Store

/// `labdc radius …` (phase 4a, 30 Sep 2026): NAS clients, the policy list and a dry-run
/// `test` that evaluates `Name=value` attributes exactly as the server does (directory facts
/// merged, first match wins, default action). Works on the store file; a running server picks
/// the change up within 30 s (its config cache).
public enum RadiusCommand: Equatable, Sendable {
    case clients
    /// `secret` nil = generate one (printed once — the NAS needs it).
    case clientAdd(name: String, ip: String, secret: String?)
    case clientRemove(String)
    /// The NAS's RFC 5176 CoA port and flavour.
    case clientSet(name: String, coaPort: UInt16?, coaVendor: CoAVendor?)
    /// Accounting sessions (`all`: ended ones of the last 30 days too).
    case sessions(all: Bool)
    /// Reauthenticate / Disconnect a session: its row id (`#12` or `12`), MAC or Acct-Session-Id.
    case coa(CoAAction, target: String)
    /// Registered devices (the MAB allow-list).
    case devices
    case deviceAdd(mac: String, description: String?, group: String?)
    case deviceRemove(String)
    case policies
    /// The action when no rule matches.
    case defaultAction(RADIUSDefaultAction)
    case test([String])
}

extension CLIParser {
    static let radiusUsage = """
          labdc radius clients [--data <dir>]
          labdc radius client add <name> --ip <address|cidr|range> [--secret <secret>] [--data <dir>]
          labdc radius client remove <name> [--data <dir>]
          labdc radius client set <name> [--coa-port <port>] [--coa-vendor generic|cisco|arubaBounce|arubaDisconnect] [--data <dir>]
          labdc radius sessions [--all] [--data <dir>]   (accounting: open sessions; --all: ended ones too)
          labdc radius reauth|disconnect <session #id|mac|Acct-Session-Id> [--data <dir>]   (RFC 5176 CoA)
          labdc radius devices [--data <dir>]   (registered devices for MAB)
          labdc radius device add <mac> [--description <text>] [--group <group>] [--data <dir>]
          labdc radius device remove <mac> [--data <dir>]
          labdc radius policies [--data <dir>]
          labdc radius default accept|reject [--data <dir>]   (when no rule matches)
          labdc radius test <Name=value>... [--data <dir>]   e.g. User-Name=alice Called-Station-Id=aa-bb:Staff
        """

    static func parseRadius(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("radius needs clients, client, policies, sessions, reauth, disconnect, devices, device, default or test") }
        var args = Array(rest.dropFirst())
        switch sub {
        case "clients":
            let o = try Options(args, valued: ["--data"])
            return .radius(data: o.data(defaultData), .clients)
        case "client":
            guard let verb = args.first else { throw CLIError.usage("radius client needs add or remove") }
            args.removeFirst()
            switch verb {
            case "add":
                let o = try Options(args, valued: ["--data", "--ip", "--secret"], positionals: 1)
                let ip = try o.required("--ip")
                guard RADIUSAddress.isValidPattern(ip) else { throw CLIError.usage("--ip \(ip) is not an address, CIDR or range") }
                return .radius(data: o.data(defaultData), .clientAdd(name: o.positionals[0], ip: ip, secret: o.values["--secret"]))
            case "remove", "delete":
                let o = try Options(args, valued: ["--data"], positionals: 1)
                return .radius(data: o.data(defaultData), .clientRemove(o.positionals[0]))
            case "set":
                let o = try Options(args, valued: ["--data", "--coa-port", "--coa-vendor"], positionals: 1)
                var port: UInt16?
                if let text = o.values["--coa-port"] {
                    guard let p = UInt16(text), p != 0 else { throw CLIError.usage("--coa-port takes 1…65535, not \(text)") }
                    port = p
                }
                var vendor: CoAVendor?
                if let text = o.values["--coa-vendor"] {
                    guard let v = CoAVendor.allCases.first(where: { $0.rawValue.lowercased() == text.lowercased() }) else {
                        throw CLIError.usage("--coa-vendor takes \(CoAVendor.allCases.map(\.rawValue).joined(separator: ", ")), not \(text)")
                    }
                    vendor = v
                }
                guard port != nil || vendor != nil else { throw CLIError.usage("radius client set needs --coa-port or --coa-vendor") }
                return .radius(data: o.data(defaultData), .clientSet(name: o.positionals[0], coaPort: port, coaVendor: vendor))
            default:
                throw CLIError.usage("unknown radius client command \(verb)")
            }
        case "sessions":
            let all = args.contains("--all")
            let o = try Options(args.filter { $0 != "--all" }, valued: ["--data"])
            return .radius(data: o.data(defaultData), .sessions(all: all))
        case "reauth", "reauthenticate", "disconnect":
            let o = try Options(args, valued: ["--data"], positionals: 1)
            return .radius(data: o.data(defaultData), .coa(sub == "disconnect" ? .disconnect : .reauthenticate, target: o.positionals[0]))
        case "devices":
            let o = try Options(args, valued: ["--data"])
            return .radius(data: o.data(defaultData), .devices)
        case "device":
            guard let verb = args.first else { throw CLIError.usage("radius device needs add or remove") }
            args.removeFirst()
            switch verb {
            case "add":
                let o = try Options(args, valued: ["--data", "--description", "--group"], positionals: 1)
                guard RADIUSMAC.normalize(o.positionals[0]) != nil else { throw CLIError.usage("\(o.positionals[0]) is not a MAC address") }
                return .radius(data: o.data(defaultData), .deviceAdd(mac: o.positionals[0], description: o.values["--description"],
                                                                      group: o.values["--group"]))
            case "remove", "delete":
                let o = try Options(args, valued: ["--data"], positionals: 1)
                return .radius(data: o.data(defaultData), .deviceRemove(o.positionals[0]))
            default:
                throw CLIError.usage("unknown radius device command \(verb)")
            }
        case "policies":
            let o = try Options(args, valued: ["--data"])
            return .radius(data: o.data(defaultData), .policies)
        case "default":
            let o = try Options(args, valued: ["--data"], positionals: 1)
            guard let action = RADIUSDefaultAction(rawValue: o.positionals[0].lowercased()) else {
                throw CLIError.usage("radius default takes accept or reject, not \(o.positionals[0])")
            }
            return .radius(data: o.data(defaultData), .defaultAction(action))
        case "test":
            // Every argument that is not --data <dir> is one `Name=value`.
            var pairs: [String] = []
            var data = defaultData
            var i = 0
            while i < args.count {
                if args[i] == "--data" {
                    guard i + 1 < args.count else { throw CLIError.usage("--data needs a value") }
                    data = expand(args[i + 1]); i += 2; continue
                }
                guard args[i].contains("=") else { throw CLIError.usage("radius test takes Name=value pairs, not \(args[i])") }
                pairs.append(args[i]); i += 1
            }
            guard !pairs.isEmpty else { throw CLIError.usage("radius test needs at least one Name=value (e.g. User-Name=alice)") }
            return .radius(data: data, .test(pairs))
        default:
            throw CLIError.usage("unknown radius command \(sub)")
        }
    }
}

public enum RadiusCommands {
    public static func run(data url: URL, _ command: RadiusCommand, out: (String) -> Void) async throws {
        let store = try DataDirectory(url).openExistingStore()
        switch command {
        case .clients:
            let clients = try await store.listNAS()
            if clients.isEmpty { out("no RADIUS clients") }
            for c in clients { out("\(c.name)\t\(c.ip)\t\(c.enabled ? "enabled" : "disabled")") }
        case let .clientAdd(name, ip, secret):
            guard try await store.listNAS().allSatisfy({ $0.name.caseInsensitiveCompare(name) != .orderedSame }) else {
                throw CLIError.failure("a RADIUS client named \(name) already exists")
            }
            let chosen = secret ?? generateSecret()
            do { try await store.addNAS(.init(name: name, ip: ip, secret: chosen)) } catch {
                throw CLIError.failure("\(error)")
            }
            out("added RADIUS client \(name) (\(ip))")
            if secret == nil { out("shared secret (shown once): \(chosen)") }
        case .clientRemove(let name):
            guard let c = try await store.listNAS().first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
                throw CLIError.failure("no RADIUS client named \(name)")
            }
            try await store.deleteNAS(id: c.id)
            out("removed RADIUS client \(c.name)")
        case let .clientSet(name, port, vendor):
            guard var c = try await store.listNAS().first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
                throw CLIError.failure("no RADIUS client named \(name)")
            }
            if let vendor { c.coaVendor = vendor }
            if let port { c.coaPort = port }
            try await store.updateNAS(c)
            out("\(c.name): CoA \(c.coaVendor.title), udp \(c.coaPort)")
        case .sessions(let all):
            let sessions = try await store.radiusSessions(activeOnly: !all)
            if sessions.isEmpty { out(all ? "no accounting sessions" : "no active sessions") }
            for s in sessions { out(describe(s)) }
        case let .coa(action, target):
            let session = try await findSession(store, target)
            let config = await RadiusConfig.load(store)
            guard let nas = config.nas(for: session.nasSource) else {
                throw CLIError.failure("no enabled RADIUS client for \(session.nasSource)")
            }
            let result = await RadiusCoAClient.send(action, session: session, nas: nas)
            out("\(result.request) \(session.mac ?? session.userName ?? session.sessionId) on \(nas.name) "
                + "(\(session.nasSource):\(nas.coaPort)) → \(result.text)")
            if !result.ok { throw CLIError.failure("\(result.request) not acknowledged") }
        case .devices:
            let devices = try await store.registeredDevices()
            if devices.isEmpty { out("no registered devices") }
            for d in devices { out("\(d.mac)\t\(d.group ?? "-")\t\(d.description)") }
        case let .deviceAdd(mac, description, group):
            let device = DirectoryStore.RegisteredDevice(mac: mac, description: description ?? "", group: group)
            do { try await store.saveRegisteredDevice(device) } catch { throw CLIError.failure("\(error)") }
            out("registered \(device.mac)\(device.group.map { " (\($0))" } ?? "")")
        case .deviceRemove(let mac):
            guard try await store.deleteRegisteredDevice(mac: mac) else { throw CLIError.failure("no registered device \(mac)") }
            out("removed \(RADIUSMAC.normalize(mac) ?? mac)")
        case .policies:
            let policies = try await store.listRadiusPolicies()
            for p in policies.sorted(by: { $0.position < $1.position }) {
                let action = p.action == .acceptVLAN ? "Accept, VLAN \(p.vlan ?? "?")" : p.action.title
                out("\(p.position + 1). \(p.name)\t\(action)\t\(p.rows.count) row\(p.rows.count == 1 ? "" : "s")\(p.enabled ? "" : "\tdisabled")")
            }
            out("no match: \(try await store.radiusDefaultAction().title)")
        case .defaultAction(let action):
            try await store.setRadiusDefaultAction(action)
            out("no match: \(action.title)")
        case .test(let pairs):
            let (request, unknown) = RequestContext.parse(pairs.joined(separator: "\n"))
            let result = await ServerController.radiusTest(store: store, request: request, unknown: unknown)
            for line in result.text.split(separator: "\n", omittingEmptySubsequences: false) { out(String(line)) }
        }
    }

    /// `#12  alice  aa:bb:…  AP-3F port 7  since 2026-10-01 09:30  active  1.2 MB in / 300 kB out`
    static func describe(_ s: DirectoryStore.RadiusSession) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        let state = s.active ? "active" : "ended \(f.string(from: s.stoppedAt ?? s.updatedAt))"
            + (s.terminateCause.map { " (\(RADIUSNames.terminateCause($0)))" } ?? "")
        let bytes = ByteCountFormatter()
        let port = s.nasPortId ?? s.nasPort.map(String.init)
        return ["#\(s.id)", s.userName ?? "-", s.mac ?? s.callingStationId ?? "-",
                (s.nasName ?? s.nasSource) + (port.map { " port \($0)" } ?? ""),
                s.framedIP ?? "-", "since \(f.string(from: s.startedAt))", state,
                "\(bytes.string(fromByteCount: Int64(clamping: s.inputOctets))) in / \(bytes.string(fromByteCount: Int64(clamping: s.outputOctets))) out",
                "session \(s.sessionId)"].joined(separator: "\t")
    }

    /// `#12` / `12` (row id), a MAC (its newest open session) or an Acct-Session-Id.
    static func findSession(_ store: DirectoryStore, _ target: String) async throws -> DirectoryStore.RadiusSession {
        let t = target.hasPrefix("#") ? String(target.dropFirst()) : target
        if let id = Int64(t), let s = try await store.radiusSession(id: id) { return s }
        if RADIUSMAC.normalize(target) != nil, let s = try await store.activeRadiusSessions(mac: target).first { return s }
        if let s = try await store.radiusSessions(activeOnly: false, limit: 5000).first(where: { $0.sessionId == target }) { return s }
        throw CLIError.failure("no session \(target) (try `labdc radius sessions`)")
    }

    /// 24 characters from an unambiguous alphabet (what the app's Generate button gives).
    static func generateSecret() -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
        var bytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }
}
