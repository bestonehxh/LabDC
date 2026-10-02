import DHCPKit
import Foundation
import LabDCCore
import Store

/// `labdc dhcp …` (phase 5): scopes, reservations, leases, settings, the direct-mode probe, a
/// dry-run `test` (a relayed DISCOVER/SOLICIT through the real engine, nothing sent or saved),
/// `simulate` (a real relay exchange over UDP, for Scripts/dhcp-check.sh), export/import.
/// Works on the store file; a running server picks config changes up within 30 s.
public enum DHCPCommand: Equatable, Sendable {
    case scopes(json: Bool)
    /// `flags`: --subnet --range --vlan --router --lease --dns --domain --ntp --search --exclude
    /// --option43 --capwap --tftp --bootfile --tftp150 --shared --offer-delay --mtu --route
    /// --preferred; booleans --authoritative --known-only --ping --no-dns-update --no-rapid-commit
    /// --disabled.
    case scopeAdd(name: String, flags: [String: String])
    case scopeRemove(String)
    case scopeEnable(String, Bool)
    case reservations(scope: String?)
    /// `flags`: --scope --address --mac --client-id --duid --circuit-id --remote-id --hostname --option43.
    case reservationAdd(name: String, flags: [String: String])
    case reservationRemove(String)
    case leases(search: String?, format: LeaseFormat, all: Bool, watch: Bool)
    case leaseRelease(String)
    case history(String)
    case devices
    /// Empty = show the settings.
    case settings([String: String])
    case direct(interface: String, on: Bool)
    case test([String: String])
    case simulate([String: String])
    case export(out: String?)
    case importConfig(String)

    public enum LeaseFormat: String, Equatable, Sendable { case text, json, csv }
}

extension CLIParser {
    static let dhcpUsage = """
          labdc dhcp scopes [--json] [--data <dir>]
          labdc dhcp scope add <name> --subnet <cidr> --range <a-b>[,<a-b>] [--vlan N] [--router <ip>] [--lease 8h]
                          [--dns <ips>] [--domain <d>] [--ntp <ips>] [--search <d,…>] [--exclude <a-b>] [--route <cidr>@<gw>,…]
                          [--option43 cisco|aruba|huawei|huawei-binary|unifi|ruckus-sz|ruckus-zd:<ip,…> | raw:<hex>] [--capwap <ips>]
                          [--tftp <name>] [--bootfile <f>] [--tftp150 <ips>] [--shared <name>] [--offer-delay <ms>] [--mtu N]
                          [--authoritative] [--known-only] [--ping] [--no-dns-update] [--no-rapid-commit] [--disabled]
          labdc dhcp scope remove|enable|disable <name>
          labdc dhcp reservations [--scope <name>]
          labdc dhcp reservation add <name> --scope <scope> --address <ip> [--mac <m>] [--client-id <hex>] [--duid <hex>]
                          [--circuit-id <text|hex>] [--remote-id <text|hex>] [--hostname <h>] [--option43 …]
          labdc dhcp reservation remove <name>
          labdc dhcp leases [--search <text>] [--json|--csv] [--all] [--watch]
          labdc dhcp lease release <address>        (with the server stopped; use the app while it runs)
          labdc dhcp history <address|mac>
          labdc dhcp devices
          labdc dhcp settings [--allowed-relays <list>|none] [--profilers <list>|none] [--forward-replies on|off]
                          [--forward-v6 on|off] [--dhcpv6 on|off] [--ddns windows|always|never] [--quarantine <s>] [--server-address <ip>|auto]
                          [--cap-relay N] [--cap-circuit N] [--churn N]
          labdc dhcp direct <interface> | labdc dhcp direct --off <interface>   (probes first; refused if a DHCP server answers)
          labdc dhcp test --giaddr <ip> --mac <mac> [--vendor-class <t>] [--hostname <h>] [--circuit-id <x>] [--remote-id <x>]
                          [--link-selection <ip>] [--user-class <u>]
          labdc dhcp test --v6 --link-address <ip6> [--duid <hex>] [--mac <m>] [--vendor-class <t>] [--hostname <h>]
          labdc dhcp simulate --port <server port> --link <ip|ip6> --mac <mac> [--v6] [--hostname <h>] [--vendor-class <t>] [--release]
          labdc dhcp export [--out <file>] | labdc dhcp import <file>
        """

    /// `--name value` pairs (and bare `--flag`s as "true") plus positionals.
    static func flagArgs(_ args: [String], booleans: Set<String>) throws -> (flags: [String: String], positionals: [String], data: URL?) {
        var flags: [String: String] = [:]
        var positionals: [String] = []
        var data: URL?
        var i = 0
        while i < args.count {
            let a = args[i]
            if a == "--data" {
                guard i + 1 < args.count else { throw CLIError.usage("--data needs a value") }
                data = expand(args[i + 1]); i += 2; continue
            }
            if a.hasPrefix("--") {
                if booleans.contains(a) { flags[a] = "true"; i += 1; continue }
                guard i + 1 < args.count else { throw CLIError.usage("\(a) needs a value") }
                flags[a] = args[i + 1]; i += 2; continue
            }
            positionals.append(a); i += 1
        }
        return (flags, positionals, data)
    }

    static func parseDHCP(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("dhcp needs scopes, scope, reservations, reservation, leases, settings, test …") }
        let args = Array(rest.dropFirst())
        let booleans: Set<String> = ["--json", "--csv", "--all", "--watch", "--authoritative", "--known-only", "--ping", "--no-dns-update",
                                     "--no-rapid-commit", "--disabled", "--v6", "--release", "--off"]
        let (flags, pos, data) = try flagArgs(args, booleans: booleans)
        let dir = data ?? defaultData
        func one(_ what: String) throws -> String {
            guard pos.count == 2 else { throw CLIError.usage("dhcp \(sub) \(what) needs one name") }
            return pos[1]
        }
        switch sub {
        case "scopes":
            return .dhcp(data: dir, .scopes(json: flags["--json"] != nil))
        case "scope":
            switch pos.first {
            case "add":
                let name = try one("add")
                guard flags["--subnet"] != nil, flags["--range"] != nil else { throw CLIError.usage("dhcp scope add needs --subnet and --range") }
                return .dhcp(data: dir, .scopeAdd(name: name, flags: flags))
            case "remove", "delete": return .dhcp(data: dir, .scopeRemove(try one("remove")))
            case "enable": return .dhcp(data: dir, .scopeEnable(try one("enable"), true))
            case "disable": return .dhcp(data: dir, .scopeEnable(try one("disable"), false))
            default: throw CLIError.usage("dhcp scope needs add, remove, enable or disable")
            }
        case "reservations":
            return .dhcp(data: dir, .reservations(scope: flags["--scope"]))
        case "reservation":
            switch pos.first {
            case "add":
                let name = try one("add")
                guard flags["--scope"] != nil, flags["--address"] != nil else { throw CLIError.usage("dhcp reservation add needs --scope and --address") }
                return .dhcp(data: dir, .reservationAdd(name: name, flags: flags))
            case "remove", "delete": return .dhcp(data: dir, .reservationRemove(try one("remove")))
            default: throw CLIError.usage("dhcp reservation needs add or remove")
            }
        case "leases":
            let format: DHCPCommand.LeaseFormat = flags["--json"] != nil ? .json : flags["--csv"] != nil ? .csv : .text
            return .dhcp(data: dir, .leases(search: flags["--search"], format: format, all: flags["--all"] != nil, watch: flags["--watch"] != nil))
        case "lease":
            guard pos.first == "release", pos.count == 2 else { throw CLIError.usage("dhcp lease release <address>") }
            return .dhcp(data: dir, .leaseRelease(pos[1]))
        case "history":
            guard pos.count == 1 else { throw CLIError.usage("dhcp history <address|mac>") }
            return .dhcp(data: dir, .history(pos[0]))
        case "devices":
            return .dhcp(data: dir, .devices)
        case "settings":
            return .dhcp(data: dir, .settings(flags))
        case "direct":
            if let iface = flags["--off"] == "true" ? pos.first : nil { return .dhcp(data: dir, .direct(interface: iface, on: false)) }
            guard pos.count == 1 else { throw CLIError.usage("dhcp direct <interface> (or --off <interface>)") }
            return .dhcp(data: dir, .direct(interface: pos[0], on: true))
        case "test":
            if flags["--v6"] != nil {
                guard flags["--link-address"] != nil else { throw CLIError.usage("dhcp test --v6 needs --link-address") }
            } else {
                guard flags["--giaddr"] != nil, flags["--mac"] != nil else { throw CLIError.usage("dhcp test needs --giaddr and --mac") }
            }
            return .dhcp(data: dir, .test(flags))
        case "simulate":
            guard flags["--port"] != nil, flags["--link"] != nil, flags["--mac"] != nil else {
                throw CLIError.usage("dhcp simulate needs --port, --link and --mac")
            }
            return .dhcp(data: dir, .simulate(flags))
        case "export":
            return .dhcp(data: dir, .export(out: flags["--out"]))
        case "import":
            guard pos.count == 1 else { throw CLIError.usage("dhcp import <file>") }
            return .dhcp(data: dir, .importConfig(pos[0]))
        default:
            throw CLIError.usage("unknown dhcp command \(sub)")
        }
    }
}

public enum DHCPCommands {
    public static func run(data url: URL, _ command: DHCPCommand, out: (String) -> Void) async throws {
        if case .simulate(let flags) = command {
            try simulate(flags, out: out)
            return
        }
        let store = try DataDirectory(url).openExistingStore()
        switch command {
        case .scopes(let json):
            let scopes = try await store.dhcpScopes()
            if json {
                let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
                out(String(decoding: try e.encode(scopes), as: UTF8.self))
                return
            }
            if scopes.isEmpty { out("no DHCP scopes (DHCP stays off until one exists)") }
            for s in scopes {
                out("\(s.name)\t\(s.family.title)\t\(s.subnet)\t\(s.ranges.map(\.text).joined(separator: ","))"
                    + (s.vlan.map { "\tVLAN \($0)" } ?? "") + (s.enabled ? "" : "\tdisabled"))
            }
        case let .scopeAdd(name, flags):
            let scope = try scopeFrom(name: name, flags)
            do { try await store.addDHCPScope(scope) } catch { throw CLIError.failure("\(error)") }
            out("added scope \(name) (\(scope.subnet), \(scope.ranges.map(\.text).joined(separator: ", ")))")
        case .scopeRemove(let name):
            let s = try await scope(named: name, store)
            try await store.deleteDHCPScope(id: s.id)
            out("removed scope \(s.name) with its reservations and leases")
        case let .scopeEnable(name, on):
            var s = try await scope(named: name, store)
            s.enabled = on
            try await store.updateDHCPScope(s)
            out("scope \(s.name) \(on ? "enabled" : "disabled")")
        case .reservations(let scopeName):
            let scopes = try await store.dhcpScopes()
            var filter: Int64?
            if let scopeName { filter = try await scope(named: scopeName, store).id }
            let list = try await store.dhcpReservations(scope: filter)
            if list.isEmpty { out("no reservations") }
            for r in list {
                out("\(r.name)\t\(r.address)\t\(r.identifierText)\t\(scopes.first { $0.id == r.scopeID }?.name ?? "?")" + (r.enabled ? "" : "\tdisabled"))
            }
        case let .reservationAdd(name, flags):
            let s = try await scope(named: flags["--scope"] ?? "", store)
            let r = DHCPReservation(scopeID: s.id, name: name, mac: flags["--mac"], clientID: flags["--client-id"], duid: flags["--duid"],
                                    circuitID: flags["--circuit-id"], remoteID: flags["--remote-id"], address: flags["--address"] ?? "",
                                    hostname: flags["--hostname"], option43: try flags["--option43"].map(option43))
            do { try await store.addDHCPReservation(r) } catch { throw CLIError.failure("\(error)") }
            out("reserved \(r.address) for \(name) (\(r.identifierText)) in \(s.name)")
        case .reservationRemove(let name):
            guard let r = try await store.dhcpReservations().first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
                throw CLIError.failure("no reservation named \(name)")
            }
            try await store.deleteDHCPReservation(id: r.id)
            out("removed reservation \(r.name) (\(r.address))")
        case let .leases(search, format, all, watch):
            try await leases(store, search: search, format: format, all: all, watch: watch, out: out)
        case .leaseRelease(let address):
            let family: DHCPFamily = IPv6Address(address) != nil ? .v6 : .v4
            guard var l = try await store.dhcpLease(family: family, address: address) else { throw CLIError.failure("no lease for \(address)") }
            l.state = .released
            l.expires = Date(); l.updated = Date()
            try await store.saveDHCPLeases([l])
            try await store.addDHCPEvents([DHCPEvent(date: Date(), family: family, address: address, mac: l.mac, clientKey: l.clientKey,
                                                     kind: "RELEASE", detail: "released with labdc dhcp")])
            out("released \(address) (\(l.whoText)); DNS records go when the server next sees the lease end")
        case .history(let key):
            let events: [DHCPEvent]
            if DirectoryStore.canonicalMAC(key) != nil, IPv4Address(key) == nil, IPv6Address(key) == nil {
                events = try await store.dhcpEvents(mac: key)
            } else {
                events = try await store.dhcpEvents(family: IPv6Address(key) != nil ? .v6 : .v4, address: key)
            }
            if events.isEmpty { out("no history for \(key)") }
            for e in events { out("\(timestamp(e.date))\t\(e.kind)\t\(e.address ?? "-")\t\(e.mac ?? "-")\t\(e.detail)") }
        case .devices:
            let list = try await store.deviceProfiles()
            if list.isEmpty { out("no devices profiled yet") }
            for p in list {
                out("\(p.mac)\t\(p.category.title)\t\(p.os ?? "-")\t\(p.hostname ?? "-")\t\(p.vendorClass ?? "-")\t\(p.confidence)%"
                    + (p.manualOverride ? "\tmanual" : ""))
            }
        case .settings(let flags):
            var s = try await store.dhcpSettings()
            if !flags.isEmpty {
                try apply(flags, to: &s)
                do { try await store.setDHCPSettings(s) } catch { throw CLIError.failure("\(error)") }
            }
            out("mode: \(s.modeText)")
            out("allowed relays: \(s.allowedRelays.isEmpty ? "any whose giaddr is inside a scope (listing them is recommended)" : s.allowedRelays.joined(separator: ", "))")
            out("profilers: \(s.profilers.isEmpty ? "none" : s.profilers.joined(separator: ", "))"
                + " (replies \(s.forwardReplies ? "on" : "off"), v6 \(s.forwardV6 ? "on" : "off"))")
            out("dynamic DNS: \(s.ddns.title)")
            out("decline quarantine: \(s.declineQuarantineSeconds) s · server address: \(s.serverAddress ?? "automatic")")
            out("caps: per relay \(s.maxLeasesPerRelay == 0 ? "none" : String(s.maxLeasesPerRelay)), per circuit "
                + "\(s.maxLeasesPerCircuit == 0 ? "none" : String(s.maxLeasesPerCircuit)), client-ids per MAC per hour \(s.clientIDChurnLimit)")
        case let .direct(interface, on):
            var s = try await store.dhcpSettings()
            if on {
                out("probing \(interface) for other DHCP servers (3 s)…")
                let result = DHCPProbe.run(interface: interface)
                if let problem = result.problem { throw CLIError.failure("direct mode stays off: \(problem)") }
                guard result.servers.isEmpty else {
                    throw CLIError.failure("direct mode stays off: DHCP server \(result.servers.joined(separator: ", ")) answers on \(interface)")
                }
                if !s.directInterfaces.contains(interface) { s.directInterfaces.append(interface) }
                out("no other DHCP server answered; LabDC answers DHCP broadcasts on \(interface)")
            } else {
                s.directInterfaces.removeAll { $0 == interface }
                out("relay-only on \(interface)")
            }
            try await store.setDHCPSettings(s)
        case .test(let flags):
            let advertised = ServeAddresses.current().first
            let result: (ok: Bool, lines: [String])
            if flags["--v6"] != nil {
                result = try await DHCPDryRun.advertise(store: store, DHCPDryRun.V6(
                    linkAddress: flags["--link-address"] ?? "", duid: flags["--duid"], mac: flags["--mac"],
                    vendorClass: flags["--vendor-class"], hostname: flags["--hostname"]), advertised: advertised)
            } else {
                result = try await DHCPDryRun.offer(store: store, DHCPDryRun.V4(
                    giaddr: flags["--giaddr"] ?? "", mac: flags["--mac"] ?? "", vendorClass: flags["--vendor-class"],
                    hostname: flags["--hostname"], circuitID: flags["--circuit-id"], remoteID: flags["--remote-id"],
                    linkSelection: flags["--link-selection"], userClass: flags["--user-class"]), advertised: advertised)
            }
            for l in result.lines { out(l) }
            if !result.ok { throw CLIError.failure("no offer") }
        case .export(let path):
            let data = try await store.exportDHCPConfig()
            if let path {
                try data.write(to: URL(fileURLWithPath: (path as NSString).expandingTildeInPath), options: .atomic)
                out("wrote DHCP scopes, reservations and settings to \(path)")
            } else {
                out(String(decoding: data, as: UTF8.self))
            }
        case .importConfig(let path):
            let data = try Data(contentsOf: URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
            let r: (scopes: Int, reservations: Int, ignoredDirect: [String])
            do { r = try await store.importDHCPConfig(data) } catch { throw CLIError.failure("import failed: \(error)") }
            out("imported \(r.scopes) scopes and \(r.reservations) reservations")
            out(DHCPCommands.directNote(ignored: r.ignoredDirect))
        case .simulate:
            break
        }
    }

    // MARK: Helpers

    static func scope(named name: String, _ store: DirectoryStore) async throws -> DHCPScope {
        guard let s = try await store.dhcpScopes().first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
            throw CLIError.failure("no DHCP scope named \(name)")
        }
        return s
    }

    /// What an import did with the file's direct interfaces (kept as they were: direct mode
    /// needs the probe in `dhcp direct <interface>`).
    public static func directNote(ignored: [String]) -> String {
        guard !ignored.isEmpty else { return "direct interfaces unchanged (an import never switches direct mode on)" }
        return "direct interfaces in the file (\(ignored.joined(separator: ", "))) ignored: an import never switches direct mode on; "
            + "use `labdc dhcp direct <interface>` (it probes for another server first)"
    }

    static func list(_ text: String?) -> [String] {
        (text ?? "").split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init).filter { !$0.isEmpty }
    }

    /// `8h`, `30m`, `2d`, `3600`.
    static func seconds(_ text: String) throws -> Int {
        let t = text.lowercased()
        let mult: Int = t.hasSuffix("d") ? 86_400 : t.hasSuffix("h") ? 3600 : t.hasSuffix("m") ? 60 : 1
        guard let n = Int(t.trimmingCharacters(in: CharacterSet(charactersIn: "dhms"))), n > 0 else {
            throw CLIError.usage("\(text) is not a duration (8h, 30m, 3600)")
        }
        return n * mult
    }

    /// `cisco:10.0.0.9,10.0.0.10`, `unifi:10.0.0.2`, `raw:f104…`.
    static func option43(_ text: String) throws -> VendorOption43 {
        let parts = text.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { throw CLIError.usage("--option43 takes vendor:addresses or raw:hex") }
        let vendors: [String: VendorOption43.Vendor] = ["cisco": .cisco, "aruba": .aruba, "huawei": .huawei, "huawei-binary": .huaweiBinary,
                                                        "unifi": .unifi, "ruckus-sz": .ruckusSmartZone, "ruckus-zd": .ruckusZoneDirector, "raw": .raw]
        guard let vendor = vendors[parts[0].lowercased()] else { throw CLIError.usage("unknown option 43 vendor \(parts[0])") }
        let o = vendor == .raw ? VendorOption43(vendor: .raw, rawHex: parts[1]) : VendorOption43(vendor: vendor, controllers: list(parts[1]))
        do { _ = try o.encode() } catch { throw CLIError.usage("--option43: \(error)") }
        return o
    }

    static func scopeFrom(name: String, _ f: [String: String]) throws -> DHCPScope {
        let subnet = f["--subnet"] ?? ""
        let v6 = IPv6Subnet(subnet) != nil
        let ranges = try list(f["--range"]).map { t -> DHCPRange in
            guard let r = DHCPRange(text: t) else { throw CLIError.usage("bad range \(t)") }
            return r
        }
        let exclusions = list(f["--exclude"]).compactMap { DHCPRange(text: $0) }
        let routes = try list(f["--route"]).map { t -> DHCPOptionBuilder.StaticRoute in
            let p = t.split(separator: "@").map(String.init)
            guard p.count == 2 else { throw CLIError.usage("--route takes <cidr>@<gateway>") }
            return .init(destination: p[0], gateway: p[1])
        }
        var s = DHCPScope(name: name, family: v6 ? .v6 : .v4, enabled: f["--disabled"] == nil, vlan: f["--vlan"].flatMap { Int($0) },
                          subnet: subnet, ranges: ranges, exclusions: exclusions, sharedNetwork: f["--shared"],
                          routers: list(f["--router"]), leaseSeconds: try f["--lease"].map(seconds),
                          preferredSeconds: try f["--preferred"].map(seconds) ?? 0, dnsServers: list(f["--dns"]),
                          domainName: f["--domain"], ntpServers: list(f["--ntp"]), searchList: list(f["--search"]),
                          mtu: f["--mtu"].flatMap { Int($0) }, staticRoutes: routes, capwap: list(f["--capwap"]),
                          tftpServer: f["--tftp"], bootfile: f["--bootfile"], tftpServers150: list(f["--tftp150"]),
                          option43: try f["--option43"].map(option43),
                          authoritative: f["--authoritative"] != nil, knownClientsOnly: f["--known-only"] != nil,
                          offerDelayMs: f["--offer-delay"].flatMap { Int($0) } ?? 0, pingBeforeOffer: f["--ping"] != nil,
                          dnsUpdates: f["--no-dns-update"] == nil, rapidCommit: f["--no-rapid-commit"] == nil)
        if let vlan = f["--vlan"], Int(vlan) == nil { throw CLIError.usage("--vlan \(vlan) is not a number") }
        s.id = 0
        do { try s.validate() } catch { throw CLIError.usage("\(error)") }
        return s
    }

    static func apply(_ f: [String: String], to s: inout DHCPSettings) throws {
        func onOff(_ key: String) throws -> Bool? {
            guard let v = f[key] else { return nil }
            switch v.lowercased() {
            case "on", "yes", "true": return true
            case "off", "no", "false": return false
            default: throw CLIError.usage("\(key) takes on or off")
            }
        }
        for key in f.keys where !["--allowed-relays", "--profilers", "--forward-replies", "--forward-v6", "--dhcpv6", "--ddns", "--quarantine",
                                 "--server-address", "--cap-relay", "--cap-circuit", "--churn"].contains(key) {
            throw CLIError.usage("unknown dhcp settings option \(key)")
        }
        if let v = f["--allowed-relays"] { s.allowedRelays = v == "none" ? [] : list(v) }
        if let v = f["--profilers"] { s.profilers = v == "none" ? [] : list(v) }
        if let v = try onOff("--forward-replies") { s.forwardReplies = v }
        if let v = try onOff("--forward-v6") { s.forwardV6 = v }
        if let v = try onOff("--dhcpv6") { s.enableV6 = v }
        if let v = f["--ddns"] {
            guard let m = DHCPSettings.DDNSMode(rawValue: v.lowercased()) else { throw CLIError.usage("--ddns takes windows, always or never") }
            s.ddns = m
        }
        if let v = f["--quarantine"] { s.declineQuarantineSeconds = try seconds(v) }
        if let v = f["--server-address"] { s.serverAddress = v == "auto" ? nil : v }
        if let v = f["--cap-relay"] { s.maxLeasesPerRelay = Int(v) ?? -1 }
        if let v = f["--cap-circuit"] { s.maxLeasesPerCircuit = Int(v) ?? -1 }
        if let v = f["--churn"] { s.clientIDChurnLimit = Int(v) ?? -1 }
    }

    static func timestamp(_ d: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: d)
    }

    static func leases(_ store: DirectoryStore, search: String?, format: DHCPCommand.LeaseFormat, all: Bool, watch: Bool,
                       out: (String) -> Void, rounds: Int? = nil) async throws {
        let scopes = try await store.dhcpScopes()
        func select(_ list: [DHCPLease]) -> [DHCPLease] {
            let now = Date()
            return list.filter { all || ($0.state == .active && $0.expires > now) || $0.state == .declined || $0.state == .foreign }
                .filter { l in
                    guard let q = search?.lowercased(), !q.isEmpty else { return true }
                    return [l.address, l.mac ?? "", l.hostname ?? "", l.clientKey, l.vendorClass ?? "", l.deviceCategory ?? "", l.deviceOS ?? ""]
                        .contains { $0.lowercased().contains(q) }
                }
                .sorted { ($0.family.rawValue, $0.address.count, $0.address) < ($1.family.rawValue, $1.address.count, $1.address) }
        }
        func row(_ l: DHCPLease) -> String {
            let scope = scopes.first { $0.id == l.scopeID }?.name ?? "#\(l.scopeID)"
            let device = l.deviceCategory.flatMap { DeviceClassifier.Category(rawValue: $0)?.title } ?? "-"
            return "\(l.address)\t\(l.state.title)\t\(l.mac ?? l.duid ?? "-")\t\(l.hostname ?? "-")\t\(device)\t\(l.deviceOS ?? "-")\t"
                + "\(scope)\tuntil \(timestamp(l.expires))"
        }
        func print(_ list: [DHCPLease]) throws {
            switch format {
            case .json:
                let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .iso8601
                out(String(decoding: try e.encode(list), as: UTF8.self))
            case .csv:
                out("address,state,mac,hostname,category,os,vendor_class,scope,expires,relay,circuit_id,option55")
                for l in list {
                    let scope = scopes.first { $0.id == l.scopeID }?.name ?? ""
                    let fields = [l.address, l.state.rawValue, l.mac ?? l.duid ?? "", l.hostname ?? "", l.deviceCategory ?? "", l.deviceOS ?? "",
                                  l.vendorClass ?? "", scope, timestamp(l.expires), l.relay ?? "", l.circuitID ?? "",
                                  l.fingerprint?.parameterListText ?? ""]
                    out(fields.map { $0.contains(",") || $0.contains("\"") ? "\"" + $0.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : $0 }
                        .joined(separator: ","))
                }
            case .text:
                if list.isEmpty { out("no leases") }
                for l in list {
                    out(row(l))
                    if let fp = l.fingerprint { out("    " + fp.lines.joined(separator: " · ")) }
                }
            }
        }
        let first = select(try await store.dhcpLeases())
        try print(first)
        guard watch else { return }
        var seen = Dictionary(first.map { ($0.id, $0.updated) }, uniquingKeysWith: { a, _ in a })
        var round = 0
        while rounds.map({ round < $0 }) ?? true {
            round += 1
            try await Task.sleep(for: .seconds(2))
            let changed = select(try await store.dhcpLeases()).filter { seen[$0.id] != $0.updated }
            for l in changed { seen[l.id] = l.updated }
            if !changed.isEmpty { try print(changed) }
        }
    }

    /// A real relay exchange against a server on this Mac (loopback): DORA or SOLICIT/REQUEST.
    static func simulate(_ f: [String: String], out: (String) -> Void) throws {
        guard let port = f["--port"].flatMap({ UInt16($0) }) else { throw CLIError.usage("--port needs a port number") }
        guard let mac = f["--mac"].flatMap(DHCPMAC.bytes) else { throw CLIError.usage("--mac needs a MAC address") }
        if f["--v6"] != nil {
            guard let link = f["--link"].flatMap(IPv6Address.init) else { throw CLIError.usage("--link needs an IPv6 address with --v6") }
            let relay = try DHCPTestRelay(v6: true)
            let (adv, reply) = try relay.solicitRequest(serverPort: port, duid: [0, 3, 0, 1] + mac, link: link, mac: mac, fqdn: f["--hostname"])
            guard let adv else { throw CLIError.failure("no ADVERTISE from [::1]:\(port)") }
            out("ADVERTISE " + (adv.iaNAs.first?.addresses.first.map { $0.address.description } ?? "no address"))
            for l in DHCPDescribe.v6(adv) { out("  " + l) }
            guard let reply, let address = reply.iaNAs.first?.addresses.first?.address else { throw CLIError.failure("no REPLY with an address") }
            out("REPLY \(address)")
            for l in DHCPDescribe.v6(reply) { out("  " + l) }
            if f["--release"] != nil, let sid = reply.serverDUID {
                let rel = DHCPv6Message(type: .release, transactionID: 77, options: [
                    DHCPv6Option(DHCPv6OptionCode.clientID, [0, 3, 0, 1] + mac), DHCPv6Option(DHCPv6OptionCode.serverID, sid),
                    DHCPv6IANA(iaid: 7, addresses: [.init(address: address, preferred: 0, valid: 0)]).option,
                ])
                let r = relay.exchange(DHCPTestRelay.relayForward(rel, link: link, mac: mac), serverPort: port).flatMap { try? DHCPTestRelay.unwrap($0).message }
                out("RELEASE \(address): \(r?.type.description ?? "no reply")")
            }
            return
        }
        guard let link = f["--link"].flatMap(IPv4Address.init) else { throw CLIError.usage("--link needs an IPv4 address") }
        let relay = try DHCPTestRelay()
        let (offer, ack) = try relay.dora(serverPort: port, mac: mac, link: link, hostname: f["--hostname"], vendorClass: f["--vendor-class"])
        guard let offer, offer.messageType == .offer else { throw CLIError.failure("no OFFER from 127.0.0.1:\(port)") }
        out("OFFER \(offer.yiaddr)")
        for l in DHCPDescribe.v4(offer) { out("  " + l) }
        guard let ack, ack.messageType == .ack else { throw CLIError.failure("no ACK (\(ack?.messageType?.description ?? "nothing"))") }
        out("ACK \(ack.yiaddr)")
        if f["--release"] != nil, let sid = ack.serverIdentifier {
            var rel = DHCPv4Packet(op: 1, hops: 1, xid: 77, ciaddr: ack.yiaddr, giaddr: IPv4Address("127.0.0.1")!, chaddr: mac,
                                   options: [DHCPv4Option(53, [DHCPv4MessageType.release.rawValue]), DHCPv4Option(54, sid.bytes)])
            rel[DHCPv4OptionCode.relayAgentInformation] = DHCPTestRelay.agentInfo(link: link)
            _ = relay.exchange(rel.encode(), serverPort: port, expectReply: false)
            out("RELEASE \(ack.yiaddr) sent")
        }
    }
}
