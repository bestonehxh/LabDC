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
          labdc radius policies [--data <dir>]
          labdc radius default accept|reject [--data <dir>]   (when no rule matches)
          labdc radius test <Name=value>... [--data <dir>]   e.g. User-Name=alice Called-Station-Id=aa-bb:Staff
        """

    static func parseRadius(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("radius needs clients, client, policies or test") }
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
            default:
                throw CLIError.usage("unknown radius client command \(verb)")
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

    /// 24 characters from an unambiguous alphabet (what the app's Generate button gives).
    static func generateSecret() -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
        var bytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }
}
