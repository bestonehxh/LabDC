import CertConvert
import Foundation
import PKIKit
import Store
import SYSVOL
import X509

/// `labdc gpo …` (PK-4): the default GPOs, Trusted Root distribution and autoenrollment
/// policy in the Default Domain Policy.
public enum GPOCommand: Equatable, Sendable {
    case initialize
    case show
    /// `file`: PEM / DER / P7B with one or more certificates; `pick` which of them (nil: the
    /// self-signed ones, else the server's certificate).
    case trustedRootAdd(file: String, name: String?, pick: Dot1XTrustCertificate.Pick? = nil)
    /// A LabDC CA (`nil` = the current one).
    case trustedRootAddCA(ca: String?, name: String?)
    case trustedRootRemove(thumbprint: String)
    case trustedRootList
    case autoEnrollShow
    case autoEnrollEnable(cepURL: String?, policyID: String?)
    case autoEnrollDisable
    /// Group Policy ▸ Wi-Fi profiles (1 Oct 2026). Everything but `list` publishes at once.
    case wifiList
    /// `name`: the profile's name (its SSID too unless `--ssid` says otherwise).
    case wifiAdd(name: String, WiFiOptions)
    case wifiSet(name: String, WiFiOptions)
    case wifiRemove(name: String)
    /// The wireless policy's name / description.
    case wifiPolicy(name: String?, description: String?)
    /// Group Policy ▸ Wired (802.1X on Ethernet).
    case wiredShow
    case wiredSet(WiredOptions)
    case wiredOff
    /// A publishing `wifi`/`wired` command with `--include-draft`: the app's unpublished Group
    /// Policy ▸ Wi-Fi / Wired changes are published along with it (refused without the flag).
    indirect case includingDraft(GPOCommand)

    /// The `wifi`/`wired` commands that publish the 802.1X profiles.
    public var publishesDot1X: Bool {
        switch self {
        case .wifiAdd, .wifiSet, .wifiRemove, .wifiPolicy, .wiredSet, .wiredOff, .includingDraft: true
        default: false
        }
    }
}

/// `--server labdc` / `--server-names a;b --trusted-root <sha1|file>`: which RADIUS server a
/// profile's clients validate (owner, 1 Oct 2026).
public enum RadiusServerOption: Equatable, Sendable {
    /// This DC (LabDC RADIUS).
    case labDC
    /// Another server (e.g. ClearPass). nil keeps the profile's current value; names nil with a
    /// certificate file takes the names from the file; `pick`: which certificates of that file.
    case other(serverNames: [String]?, trustedRoot: String?, pick: Dot1XTrustCertificate.Pick? = nil)
}

/// The options of `labdc gpo wifi add|set` (GPMC's profile properties); nil keeps the current
/// value (add: the default).
public struct WiFiOptions: Equatable, Sendable {
    public var ssids: [String]?
    public var rename: String?
    public var security: Dot1XPolicy.Security?
    public var method: Dot1XPolicy.Method?
    public var signInAs: Dot1XPolicy.AuthMode?
    public var autoConnect: Bool?
    public var hidden: Bool?
    public var autoSwitch: Bool?
    public var singleSignOn: Bool?
    public var cacheUserData: Bool?
    /// 1-based position in the preference order.
    public var order: Int?
    public var server: RadiusServerOption?
    /// `--verify-server on|off` (PerformServerValidation).
    public var verifyServer: Bool?
    /// `--prompt-user on|off`: ask the user when the server can't be verified.
    public var promptUser: Bool?

    public init(ssids: [String]? = nil, rename: String? = nil, security: Dot1XPolicy.Security? = nil,
                method: Dot1XPolicy.Method? = nil, signInAs: Dot1XPolicy.AuthMode? = nil, autoConnect: Bool? = nil,
                hidden: Bool? = nil, autoSwitch: Bool? = nil, singleSignOn: Bool? = nil, cacheUserData: Bool? = nil,
                order: Int? = nil, server: RadiusServerOption? = nil, verifyServer: Bool? = nil, promptUser: Bool? = nil) {
        self.ssids = ssids; self.rename = rename; self.security = security; self.method = method
        self.signInAs = signInAs; self.autoConnect = autoConnect; self.hidden = hidden; self.autoSwitch = autoSwitch
        self.singleSignOn = singleSignOn; self.cacheUserData = cacheUserData; self.order = order
        self.server = server; self.verifyServer = verifyServer; self.promptUser = promptUser
    }

    func applied(to profile: Dot1XProfileSet.Wireless) -> Dot1XProfileSet.Wireless {
        var p = profile
        if let ssids { p.ssids = ssids }
        if let rename { p.name = rename }
        if let security { p.security = security }
        if let method { p.method = method }
        if let signInAs { p.signInAs = signInAs }
        if let autoConnect { p.connectAutomatically = autoConnect }
        if let hidden { p.connectHidden = hidden }
        if let autoSwitch { p.autoSwitch = autoSwitch }
        if let singleSignOn { p.singleSignOn = singleSignOn }
        if let cacheUserData { p.cacheUserData = cacheUserData }
        if let verifyServer { p.validation.verify = verifyServer }
        if let promptUser { p.validation.promptUser = promptUser }
        // 192-bit is EAP-TLS only: choosing it without a method picks EAP-TLS.
        if security == .wpa3Suite192, method == nil { p.method = .tls }
        return p
    }
}

/// The options of `labdc gpo wired set`.
public struct WiredOptions: Equatable, Sendable {
    public var method: Dot1XPolicy.Method?
    public var signInAs: Dot1XPolicy.AuthMode?
    public var name: String?
    public var description: String?
    public var server: RadiusServerOption?
    public var verifyServer: Bool?
    public var promptUser: Bool?

    public init(method: Dot1XPolicy.Method? = nil, signInAs: Dot1XPolicy.AuthMode? = nil, name: String? = nil,
                description: String? = nil, server: RadiusServerOption? = nil, verifyServer: Bool? = nil,
                promptUser: Bool? = nil) {
        self.method = method; self.signInAs = signInAs; self.name = name; self.description = description
        self.server = server; self.verifyServer = verifyServer; self.promptUser = promptUser
    }
}

extension CLIParser {
    static let gpoUsage = """
          labdc gpo init | show [--data <dir>]
          labdc gpo trusted-root add <cert.pem|cert.der|chain.p7b> [--name <friendly name>]
                [--pick leaf|root|all | --thumbprint <sha1>[,<sha1>…]] [--data <dir>]
            (any certificate, as GPMC; a file with several: the self-signed root(s) unless --pick / --thumbprint)
          labdc gpo trusted-root add-ca [<LabDC CA name>] [--name <friendly name>] [--data <dir>]
          labdc gpo trusted-root remove <sha1 thumbprint> | list [--data <dir>]
          labdc gpo autoenroll [--enable [--cep-url <url>] [--policy-id <{GUID}>] | --disable] [--data <dir>]
          labdc gpo wifi list [--data <dir>]
          labdc gpo wifi add <profile name> [--ssid <SSID>[,<SSID>…]] [--security wpa2|wpa3|wpa3-192]
                [--method tls|peap] [--sign-in computer-or-user|computer|user] [--auto-connect on|off]
                [--hidden on|off] [--auto-switch on|off] [--sso on|off] [--cache on|off] [--order <n>] [--data <dir>]
          labdc gpo wifi set <profile name> [--rename <new name>] [same options as add] [--data <dir>]
            RADIUS server (add/set, wired set): --server labdc (this DC, the default)
                | --server-names '<name>[;<name>…]' --trusted-root <sha1 thumbprint|cert file>
                  [--pick leaf|root|all | --thumbprint <sha1>[,<sha1>…]]
                  (another server, e.g. ClearPass; the file's chosen certificate(s) join the trusted roots,
                   by default its self-signed root, else the server's own certificate)
            Server validation (add/set, wired set): --verify-server on|off (default on)
                --prompt-user on|off (default off; on while testing: Windows shows the certificate the server sent)
          labdc gpo wifi remove <profile name> [--data <dir>]
          labdc gpo wifi policy [--name <policy name>] [--description <text>] [--data <dir>]
          labdc gpo wired [show] | set [--method tls|peap] [--sign-in …] [--name …] [--description …] [RADIUS server] | off [--data <dir>]
            (wifi add/set/remove/policy and wired set/off publish to the Default Domain Policy at once;
             the SSID defaults to the profile name; renaming a profile removes the old-named one from PCs)
            --include-draft (wifi add/set/remove/policy, wired set/off): when the app's Group Policy page has
              changes not published yet, publish them together with this one (without it the command refuses)
        """

    static func parseSecurity(_ s: String) throws -> Dot1XPolicy.Security {
        switch s.lowercased() {
        case "wpa2", "wpa2-enterprise": return .wpa2
        case "wpa3", "wpa3-enterprise": return .wpa3
        case "wpa3-192", "wpa3-enterprise-192", "192", "suite-b": return .wpa3Suite192
        default: throw CLIError.usage("--security is wpa2, wpa3 or wpa3-192, not \(s)")
        }
    }

    static func parseMethod(_ s: String) throws -> Dot1XPolicy.Method {
        switch s.lowercased() {
        case "tls", "eap-tls": return .tls
        case "peap", "peap-mschapv2": return .peapMSCHAPv2
        default: throw CLIError.usage("--method is tls or peap, not \(s)")
        }
    }

    static func parseSignIn(_ s: String) throws -> Dot1XPolicy.AuthMode {
        switch s.lowercased() {
        case "computer-or-user", "machineoruser": return .machineOrUser
        case "computer", "machine": return .machine
        case "user": return .user
        default: throw CLIError.usage("--sign-in is computer-or-user, computer or user, not \(s)")
        }
    }

    static func parseOnOff(_ flag: String, _ s: String) throws -> Bool {
        switch s.lowercased() {
        case "on", "yes", "true", "1": return true
        case "off", "no", "false", "0": return false
        default: throw CLIError.usage("\(flag) is on or off, not \(s)")
        }
    }

    /// `--pick leaf|root|all` / `--thumbprint <sha1>[,<sha1>…]`: which certificates of a file.
    static func parsePick(_ o: Options) throws -> Dot1XTrustCertificate.Pick? {
        let pick = o.values["--pick"], thumbprints = o.values["--thumbprint"]
        if pick != nil && thumbprints != nil { throw CLIError.usage("--pick and --thumbprint exclude each other") }
        if let pick { return try Dot1XTrustCertificate.Pick.parse(pick) }
        guard let thumbprints else { return nil }
        let list = thumbprints.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard !list.isEmpty else { throw CLIError.usage("--thumbprint needs a SHA-1 thumbprint") }
        for t in list where TrustedRoot.normalizedThumbprint(t) == nil {
            throw CLIError.usage("--thumbprint \(t) is not a 40-digit hex SHA-1 thumbprint")
        }
        return .thumbprints(list)
    }

    /// `--server labdc` / `--server-names` / `--trusted-root` [`--pick` / `--thumbprint`].
    static func parseServer(_ o: Options) throws -> RadiusServerOption? {
        let names = o.values["--server-names"].map(Dot1XProfileSet.RadiusServer.names)
        let root = o.values["--trusted-root"]
        let pick = try parsePick(o)
        if pick != nil {
            guard let root else { throw CLIError.usage("--pick / --thumbprint go with --trusted-root <cert file>") }
            if TrustedRoot.normalizedThumbprint(root) != nil {
                throw CLIError.usage("--pick / --thumbprint choose from a certificate file, not from --trusted-root \(root)")
            }
        }
        if let server = o.values["--server"] {
            guard server.lowercased() == "labdc" || server.lowercased() == "this-dc" else {
                throw CLIError.usage("--server is labdc (this DC); for another server give --server-names and --trusted-root")
            }
            if names != nil || root != nil { throw CLIError.usage("--server labdc takes no --server-names or --trusted-root") }
            return .labDC
        }
        if let names, names.isEmpty { throw CLIError.usage("--server-names needs at least one name") }
        return names == nil && root == nil ? nil : .other(serverNames: names, trustedRoot: root, pick: pick)
    }

    static let serverFlags: Set<String> = ["--server", "--server-names", "--trusted-root", "--pick", "--thumbprint",
                                           "--verify-server", "--prompt-user"]

    /// `--verify-server` / `--prompt-user`.
    static func parseValidation(_ o: Options) throws -> (verify: Bool?, prompt: Bool?) {
        (try o.values["--verify-server"].map { try parseOnOff("--verify-server", $0) },
         try o.values["--prompt-user"].map { try parseOnOff("--prompt-user", $0) })
    }

    /// `--include-draft` taken out of `args`; the publishing command parsed from the rest is
    /// wrapped in `.includingDraft`.
    static func parseIncludingDraft(_ args: [String], _ parse: ([String]) throws -> CLICommand) throws -> CLICommand {
        let rest = args.filter { $0 != "--include-draft" }
        let command = try parse(rest)
        guard rest.count != args.count else { return command }
        guard case let .gpo(data, sub) = command, sub.publishesDot1X else {
            throw CLIError.usage("--include-draft goes with a command that publishes (wifi add/set/remove/policy, wired set/off)")
        }
        return .gpo(data: data, .includingDraft(sub))
    }

    /// `labdc gpo wifi …`
    static func parseWiFi(_ args: [String], defaultData: URL) throws -> CLICommand {
        try parseIncludingDraft(args) { try parseWiFiCommand($0, defaultData: defaultData) }
    }

    static func parseWiFiCommand(_ args: [String], defaultData: URL) throws -> CLICommand {
        guard let verb = args.first else { throw CLIError.usage("gpo wifi needs list, add, set, remove or policy") }
        let rest = Array(args.dropFirst())
        switch verb {
        case "list":
            let o = try Options(rest, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .wifiList)
        case "add", "set":
            var valued = Set(["--data", "--ssid", "--security", "--method", "--sign-in", "--auto-connect",
                              "--hidden", "--auto-switch", "--sso", "--cache", "--order"]).union(serverFlags)
            if verb == "set" { valued.insert("--rename") }
            let o = try Options(rest, valued: valued, positionals: 1)
            func flag(_ name: String) throws -> Bool? { try o.values[name].map { try parseOnOff(name, $0) } }
            let ssids = o.values["--ssid"].map { $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
            let order = try o.values["--order"].map { s -> Int in
                guard let n = Int(s), n >= 1 else { throw CLIError.usage("--order is a position from 1, not \(s)") }
                return n
            }
            let options = WiFiOptions(ssids: ssids, rename: o.values["--rename"],
                                      security: try o.values["--security"].map(parseSecurity),
                                      method: try o.values["--method"].map(parseMethod),
                                      signInAs: try o.values["--sign-in"].map(parseSignIn),
                                      autoConnect: try flag("--auto-connect"), hidden: try flag("--hidden"),
                                      autoSwitch: try flag("--auto-switch"), singleSignOn: try flag("--sso"),
                                      cacheUserData: try flag("--cache"), order: order, server: try parseServer(o),
                                      verifyServer: try flag("--verify-server"), promptUser: try flag("--prompt-user"))
            if options.security == .wpa3Suite192, let m = options.method, m != .tls {
                throw CLIError.usage("WPA3-Enterprise 192-bit works with EAP-TLS only")
            }
            let name = o.positionals[0]
            if let rename = options.rename, rename.trimmingCharacters(in: .whitespaces).isEmpty {
                throw CLIError.usage("--rename needs a name")
            }
            do {
                try Dot1XPolicy.validate(ssids: ssids ?? (verb == "add" ? [name] : ["x"]), security: .wpa2, method: .tls)
            } catch {
                throw CLIError.usage("\(error)")
            }
            return .gpo(data: o.data(defaultData), verb == "add" ? .wifiAdd(name: name, options) : .wifiSet(name: name, options))
        case "remove":
            let o = try Options(rest, valued: ["--data"], positionals: 1)
            return .gpo(data: o.data(defaultData), .wifiRemove(name: o.positionals[0]))
        case "policy":
            let o = try Options(rest, valued: ["--data", "--name", "--description"])
            if let n = o.values["--name"], n.trimmingCharacters(in: .whitespaces).isEmpty {
                throw CLIError.usage("--name needs a name")
            }
            return .gpo(data: o.data(defaultData), .wifiPolicy(name: o.values["--name"], description: o.values["--description"]))
        default:
            throw CLIError.usage("unknown gpo wifi command \(verb)")
        }
    }

    /// `labdc gpo wired …`
    static func parseWired(_ args: [String], defaultData: URL) throws -> CLICommand {
        try parseIncludingDraft(args) { try parseWiredCommand($0, defaultData: defaultData) }
    }

    static func parseWiredCommand(_ args: [String], defaultData: URL) throws -> CLICommand {
        let verb = args.first.flatMap { $0.hasPrefix("--") ? nil : $0 } ?? "show"
        let rest = args.first == verb ? Array(args.dropFirst()) : args
        switch verb {
        case "show":
            let o = try Options(rest, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .wiredShow)
        case "set":
            let o = try Options(rest, valued: Set(["--data", "--method", "--sign-in", "--name", "--description"]).union(serverFlags))
            let validation = try parseValidation(o)
            return .gpo(data: o.data(defaultData), .wiredSet(WiredOptions(method: try o.values["--method"].map(parseMethod),
                                                                          signInAs: try o.values["--sign-in"].map(parseSignIn),
                                                                          name: o.values["--name"],
                                                                          description: o.values["--description"],
                                                                          server: try parseServer(o),
                                                                          verifyServer: validation.verify,
                                                                          promptUser: validation.prompt)))
        case "off":
            let o = try Options(rest, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .wiredOff)
        default:
            throw CLIError.usage("unknown gpo wired command \(verb)")
        }
    }

    static func parseGPO(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("gpo needs init, show, trusted-root, autoenroll, wifi or wired") }
        var args = Array(rest.dropFirst())
        switch sub {
        case "init":
            let o = try Options(args, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .initialize)
        case "show":
            let o = try Options(args, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .show)
        case "trusted-root", "trusted-roots":
            guard let verb = args.first else { throw CLIError.usage("gpo trusted-root needs add, add-ca, remove or list") }
            args.removeFirst()
            switch verb {
            case "add":
                let o = try Options(args, valued: ["--data", "--name", "--pick", "--thumbprint"], positionals: 1)
                return .gpo(data: o.data(defaultData), .trustedRootAdd(file: o.positionals[0], name: o.values["--name"],
                                                                       pick: try parsePick(o)))
            case "add-ca":
                // Optional CA name: count the positionals first.
                var positionals = 0, i = 0
                while i < args.count {
                    if args[i] == "--data" || args[i] == "--name" { i += 2; continue }
                    if !args[i].hasPrefix("--") { positionals += 1 }
                    i += 1
                }
                guard positionals <= 1 else { throw CLIError.usage("gpo trusted-root add-ca takes at most one CA name") }
                let o = try Options(args, valued: ["--data", "--name"], positionals: positionals)
                return .gpo(data: o.data(defaultData), .trustedRootAddCA(ca: o.positionals.first, name: o.values["--name"]))
            case "remove":
                let o = try Options(args, valued: ["--data"], positionals: 1)
                return .gpo(data: o.data(defaultData), .trustedRootRemove(thumbprint: o.positionals[0]))
            case "list":
                let o = try Options(args, valued: ["--data"])
                return .gpo(data: o.data(defaultData), .trustedRootList)
            default:
                throw CLIError.usage("unknown gpo trusted-root command \(verb)")
            }
        case "autoenroll", "auto-enroll":
            let enable = args.contains("--enable"), disable = args.contains("--disable")
            args.removeAll { $0 == "--enable" || $0 == "--disable" }
            let o = try Options(args, valued: ["--data", "--cep-url", "--policy-id"])
            if enable && disable { throw CLIError.usage("--enable and --disable exclude each other") }
            if !enable && (o.values["--cep-url"] != nil || o.values["--policy-id"] != nil) {
                throw CLIError.usage("--cep-url / --policy-id go with --enable")
            }
            if let url = o.values["--cep-url"] {
                guard let u = URL(string: url), u.scheme?.lowercased() == "https", u.host != nil else {
                    throw CLIError.usage("--cep-url must be an https:// URL, not \(url)")
                }
            }
            if let id = o.values["--policy-id"], !(id.hasPrefix("{") && id.hasSuffix("}") && GUID(string: id) != nil) {
                throw CLIError.usage("--policy-id must be a braced GUID like {3F2504E0-4F89-11D3-9A0C-0305E82C3301}, not \(id)")
            }
            let command: GPOCommand = enable ? .autoEnrollEnable(cepURL: o.values["--cep-url"], policyID: o.values["--policy-id"])
                : disable ? .autoEnrollDisable : .autoEnrollShow
            return .gpo(data: o.data(defaultData), command)
        case "wifi", "wi-fi", "wlan":
            return try parseWiFi(args, defaultData: defaultData)
        case "wired", "lan":
            return try parseWired(args, defaultData: defaultData)
        default:
            throw CLIError.usage("unknown gpo command \(sub)")
        }
    }
}

public enum GPOCommands {
    public static func run(data url: URL, _ command: GPOCommand, out: (String) -> Void) async throws {
        let dir = DataDirectory(url)
        let store = try dir.openExistingStore()
        let info = try await store.requireInfo()
        let editor = GroupPolicyEditor(root: dir.sysvolURL, store: store)
        do {
            try await run(command, editor: editor, info: info, dir: dir, out: out)
        } catch let e as CLIError {
            throw e
        } catch {
            throw CLIError.failure("\(error)")
        }
    }

    static func run(_ command: GPOCommand, editor: GroupPolicyEditor, info: DomainInfo, dir: DataDirectory,
                    includeDraft: Bool = false, out: (String) -> Void) async throws {
        switch command {
        case .includingDraft(let inner):
            try await run(inner, editor: editor, info: info, dir: dir, includeDraft: true, out: out)

        case .initialize:
            let result = try await editor.ensureDefaultGPOs()
            for gpo in result.createdGPOs { out("created \(gpo.displayName) \(gpo.guid)") }
            if result.isNoOp { out("default GPOs already present") }
            for gpo in DefaultGPO.all { out(try await summary(editor, gpo)) }

        case .show:
            for gpo in DefaultGPO.all {
                out(try await summary(editor, gpo))
                let state = try await editor.state(gpo)
                out("  gPCFileSysPath \(state.fileSysPath)")
                out("  machine extensions \(state.machineExtensions.description.isEmpty ? "-" : state.machineExtensions.description)")
                for scope in GPOScope.allCases {
                    let pol = try await editor.registryPolicy(gpo, scope: scope)
                    for e in pol.entries { out("  \(scope.rawValue)/Registry.pol \(e)") }
                }
            }

        case let .trustedRootAdd(file, name, pick):
            // Any certificate, as GPMC's Trusted Root import (1 Oct 2026); several in the file:
            // --pick / --thumbprint choose, else the self-signed root(s).
            let url = URL(fileURLWithPath: (file as NSString).expandingTildeInPath)
            guard let bytes = try? Data(contentsOf: url) else { throw CLIError.failure("cannot read \(file)") }
            let candidates = try Dot1XTrustCertificate.candidates(Array(bytes), fileName: url.lastPathComponent).certificates
            let chosen = try Dot1XTrustCertificate.pick(pick, from: candidates, fileName: url.lastPathComponent)
            for c in candidates where !chosen.contains(where: { $0.thumbprint == c.thumbprint }) {
                out("left out \(c.thumbprint) \(c.subject) (\(c.role)); --pick all or --thumbprint \(c.thumbprint) adds it")
            }
            for c in chosen {
                let item = try CertificateItem(der: c.der)
                try await add(item, name: chosen.count == 1 ? name : name.map { "\($0) (\(commonName(item.certificate.subject) ?? "certificate"))" },
                              editor: editor, out: out)
            }

        case let .trustedRootAddCA(caName, name):
            let pki: LabPKI
            do { pki = try await LabPKI.open(directory: dir.pkiURL) } catch { throw CLIError.failure("PKI in \(dir.pkiURL.path): \(error)") }
            let ca: CertificateAuthority
            do {
                if let caName { ca = try await pki.authority(named: caName) } else { ca = try await pki.currentAuthority() }
            } catch {
                throw CLIError.failure("\(error)")
            }
            try await add(try CertificateItem(der: ca.der()),
                          name: name ?? commonName(ca.certificate.subject) ?? ca.certificate.subject.description,
                          editor: editor, out: out)

        case .trustedRootRemove(let thumbprint):
            try await GroupPolicyDot1X.checkRootUnused(thumbprint, data: dir, editor: editor)
            let change = try await editor.removeTrustedRoot(thumbprint: thumbprint)
            out("removed \(change.thumbprint) from Default Domain Policy" + (change.edit.changed ? " (version \(change.edit.version.raw))" : " (was not in it)"))
            for dn in change.directoryObjects { out("removed from \(dn)") }

        case .trustedRootList:
            let roots = try await editor.trustedRoots()
            let published = Set(try await CertificationAuthorityDirectory.published(store: editor.store).map { CertificateBlob.thumbprint($0.der) })
            if roots.isEmpty { out("no trusted roots in Default Domain Policy") }
            for r in roots {
                let subject = (try? Certificate(derEncoded: r.der)).map { "\($0.subject)\tuntil \(day($0.notValidAfter))" } ?? "?"
                out([r.thumbprint, subject, r.friendlyName.map { "name \"\($0)\"" } ?? "-",
                     published.contains(r.thumbprint) ? "published in Configuration" : "GPO only"].joined(separator: "\t"))
            }

        case .autoEnrollShow:
            out(describe(try await editor.autoEnrollment()))
            out("  users: " + describe(try await editor.autoEnrollment(scope: .user)).dropFirst("autoenrollment: ".count))

        case let .autoEnrollEnable(cepURL, policyID):
            var id = policyID
            if id == nil { id = try await AutoEnrollmentSettings.defaultPolicyID(store: editor.store) }
            let settings = AutoEnrollmentSettings(
                cepURL: cepURL ?? AutoEnrollmentSettings.defaultCEPURL(dcDNSName: info.dcDNSName),
                policyID: (id ?? "").uppercased())
            let edit = try await editor.enableAutoEnrollment(settings)
            out("autoenrollment enabled in Default Domain Policy (AEPolicy 7, CEP \(settings.cepURL), Kerberos, policy ID \(settings.policyID))"
                + (edit.changed ? ", version \(edit.previous.raw) -> \(edit.version.raw)" : ", unchanged"))
            // PK-6: the user side too, so users get their User certificate at logon.
            let user = try await editor.enableAutoEnrollment(settings, scope: .user)
            out("  users: same policy in User Configuration"
                + (user.changed ? ", version \(user.previous.raw) -> \(user.version.raw)" : ", unchanged"))

        case .autoEnrollDisable:
            let edit = try await editor.disableAutoEnrollment()
            out("autoenrollment disabled in Default Domain Policy (AEPolicy 0x8000)"
                + (edit.changed ? ", version \(edit.previous.raw) -> \(edit.version.raw)" : ", unchanged"))
            let user = try await editor.disableAutoEnrollment(scope: .user)
            out("  users: disabled in User Configuration"
                + (user.changed ? ", version \(user.previous.raw) -> \(user.version.raw)" : ", unchanged"))

        case .wifiList:
            let draft = try await GroupPolicyDot1X.draft(dir, editor: editor)
            let published = try await editor.publishedDot1XProfiles().set
            out("policy \"\(draft.name)\"" + (draft.description.isEmpty ? "" : ": \(draft.description)"))
            if draft.wireless.isEmpty { out("no Wi-Fi profiles") }
            for (i, w) in draft.wireless.enumerated() { out("\(i + 1)\t" + describe(w)) }
            out(publishState(draft: draft, published: published))

        case let .wifiAdd(name, options):
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                if set.wireless(named: name) != nil { throw CLIError.failure("there is already a Wi-Fi profile named \(name); use gpo wifi set") }
                var profile = options.applied(to: Dot1XProfileSet.Wireless(name: name))
                profile.name = name
                profile.server = try resolve(options.server, current: nil, in: &set)
                try set.save(profile)
                if let order = options.order { set.move(named: name, to: order - 1) }
                return "added \(name)"
            }

        case let .wifiSet(name, options):
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                guard let current = set.wireless(named: name) else { throw CLIError.failure("no Wi-Fi profile named \(name)") }
                var changed = options.applied(to: current)
                changed.server = try resolve(options.server, current: current.server, in: &set)
                try set.save(changed, replacing: name)
                if let order = options.order { set.move(named: changed.name, to: order - 1) }
                return "changed \(name)" + (changed.name != name
                    ? " (now \(changed.name); PCs drop the profile named \(name) at their next gpupdate)" : "")
            }

        case .wifiRemove(let name):
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                guard set.remove(named: name) else { throw CLIError.failure("no Wi-Fi profile named \(name)") }
                return "removed \(name)"
            }

        case let .wifiPolicy(name, description):
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                if let name { set.name = name.trimmingCharacters(in: .whitespaces) }
                if let description { set.description = description.trimmingCharacters(in: .whitespacesAndNewlines) }
                return "wireless policy \"\(set.name)\"" + (set.description.isEmpty ? "" : ": \(set.description)")
            }

        case .wiredShow:
            let draft = try await GroupPolicyDot1X.draft(dir, editor: editor)
            let published = try await editor.publishedDot1XProfiles().set
            if let w = draft.wired {
                out("wired 802.1X on\tpolicy \"\(w.name)\"\t\(w.method.shortTitle)\tsign in as \(w.signInAs.title)\tWired AutoConfig Automatic"
                    + describe(w.server) + describe(w.validation))
            } else {
                out("wired 802.1X off")
            }
            out(publishState(draft: draft, published: published))

        case let .wiredSet(options):
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                var w = set.wired ?? Dot1XProfileSet.Wired()
                if let m = options.method { w.method = m }
                if let s = options.signInAs { w.signInAs = s }
                if let n = options.name, !n.trimmingCharacters(in: .whitespaces).isEmpty { w.name = n }
                if let d = options.description { w.description = d }
                if let v = options.verifyServer { w.validation.verify = v }
                if let p = options.promptUser { w.validation.promptUser = p }
                w.server = try resolve(options.server, current: w.server, in: &set)
                set.wired = w
                return "wired 802.1X on (\(w.method.shortTitle), sign in as \(w.signInAs.title))"
            }

        case .wiredOff:
            try await editDot1X(dir: dir, editor: editor, includeDraft: includeDraft, out: out) { set in
                set.wired = nil
                return "wired 802.1X off"
            }
        }
    }

    /// Edits the 802.1X profiles (the same list as the app's Group Policy page), publishes them
    /// to the Default Domain Policy and keeps them as the page's list.
    ///
    /// The page's list may hold edits the owner has not published yet. A CLI change starts from
    /// what is published and refuses while such edits exist (it would publish them too, unseen);
    /// `includeDraft` (`--include-draft`) starts from the page's list and publishes everything.
    static func editDot1X(dir: DataDirectory, editor: GroupPolicyEditor, includeDraft: Bool = false,
                          out: (String) -> Void, _ edit: (inout Dot1XProfileSet) throws -> String) async throws {
        let published = try await editor.publishedDot1XProfiles().set
        var set = published
        if let saved = GroupPolicyDot1X.savedDraft(dir) {
            if saved != published, !includeDraft {
                out("warning: the app's Group Policy ▸ Wi-Fi / Wired list has changes not published yet")
                throw CLIError.failure("refused: this change would publish those unpublished changes too. Publish or undo them "
                                       + "in the app first, or pass --include-draft to publish them together with this change")
            }
            if saved != published { out("note: publishing the app's unpublished Group Policy changes too (--include-draft)") }
            set = saved
        }
        let what: String
        do { what = try edit(&set) } catch let e as Dot1XPolicy.Invalid { throw CLIError.failure("\(e)") }
        let pki: LabPKI
        do { pki = try await LabPKI.open(directory: dir.pkiURL) } catch { throw CLIError.failure("PKI in \(dir.pkiURL.path): \(error)") }
        let report = try await GroupPolicyDot1X.publish(set, store: editor.store, pki: pki, editor: editor)
        set = report.set
        set.pendingRoots = []  // trusted roots now
        try GroupPolicyDot1X.saveDraft(set, dir)
        out(what)
        for e in report.events { out(e) }
        out("published: \(report.summary); Windows applies at gpupdate /force")
    }

    /// The profile's RADIUS server after `option`: a certificate file's chosen certificate(s)
    /// become pending trusted roots of `set` (added in the same publish), the profile trusting
    /// all of them.
    static func resolve(_ option: RadiusServerOption?, current: Dot1XProfileSet.RadiusServer?,
                        in set: inout Dot1XProfileSet) throws -> Dot1XProfileSet.RadiusServer? {
        guard let option else { return current }
        guard case let .other(names, root, pick) = option else { return nil }
        var thumbprint = current?.trustedRoot
        var also = current?.alsoTrusted ?? []
        var fileNames: [String]?
        if let root {
            if let t = TrustedRoot.normalizedThumbprint(root) {
                thumbprint = t
                also = []
            } else {
                let url = URL(fileURLWithPath: (root as NSString).expandingTildeInPath)
                guard let bytes = try? Data(contentsOf: url) else {
                    throw CLIError.failure("--trusted-root \(root) is neither a SHA-1 thumbprint nor a readable certificate file")
                }
                let loaded = try Dot1XTrustCertificate.load(Array(bytes), fileName: url.lastPathComponent, pick: pick)
                for c in [loaded.certificate] + loaded.others {
                    set.addPendingRoot(Dot1XProfileSet.PendingRoot(der: c.der, name: c.name))
                }
                thumbprint = loaded.certificate.thumbprint
                also = loaded.others.map(\.thumbprint)
                fileNames = loaded.serverNames
            }
        }
        guard let thumbprint else { throw CLIError.failure("another RADIUS server needs --trusted-root <sha1 thumbprint|cert file>") }
        guard let serverNames = names ?? (current?.trustedRoot == thumbprint ? current?.serverNames : nil) ?? fileNames ?? current?.serverNames,
              !serverNames.isEmpty else {
            throw CLIError.failure("another RADIUS server needs --server-names (the names in its certificate)")
        }
        return Dot1XProfileSet.RadiusServer(serverNames: serverNames, trustedRoot: thumbprint, alsoTrusted: also)
    }

    /// "\tserver cppm.lab.sheep, trusts 1A2B…" for another RADIUS server; "" for this DC.
    static func describe(_ server: Dot1XProfileSet.RadiusServer?) -> String {
        guard let server else { return "" }
        return "\tserver \(server.serverNames.joined(separator: ";")), trusts \(server.allTrusted.joined(separator: ", "))"
    }

    /// "\tno server check" / "\tasks the user" when not the standard (verify, never ask).
    static func describe(_ v: Dot1XProfileSet.ServerValidation) -> String {
        (v.verify ? "" : "\tserver NOT verified") + (v.promptUser ? "\tasks the user when the server can't be verified" : "")
    }

    static func describe(_ w: Dot1XProfileSet.Wireless) -> String {
        var flags = [w.connectAutomatically ? "auto-connect" : "manual"]
        if w.connectHidden { flags.append("hidden") }
        if w.connectAutomatically && w.autoSwitch { flags.append("auto-switch") }
        if w.singleSignOn { flags.append("SSO") }
        if !w.cacheUserData { flags.append("no cache") }
        return [w.name, "SSID " + w.ssids.joined(separator: ", "), w.security.title, w.method.shortTitle,
                "sign in as \(w.signInAs.title)", flags.joined(separator: ", ")].joined(separator: "\t") + describe(w.server)
            + describe(w.validation)
    }

    static func publishState(draft: Dot1XProfileSet, published: Dot1XProfileSet) -> String {
        if draft == published { return published.isEmpty ? "not published" : "published" }
        return "changes not published yet (the app's Group Policy ▸ Publish changes, or any gpo wifi/wired change, publishes them)"
    }

    static func add(_ c: CertificateItem, name: String?, editor: GroupPolicyEditor, out: (String) -> Void) async throws {
        let info = CACertificateInfo(der: c.der, commonName: commonName(c.certificate.subject), subject: c.certificate.subject.description)
        if !c.isCA { out("note: \(c.certificate.subject) is not a CA certificate; Windows trusts it as it is (as GPMC does)") }
        let change = try await editor.addTrustedRoot(info, friendlyName: name)
        out("trusted root \(change.thumbprint) \(c.certificate.subject) in Default Domain Policy"
            + (change.edit.changed ? " (version \(change.edit.previous.raw) -> \(change.edit.version.raw))" : " (already there)"))
        for dn in change.directoryObjects { out("published in \(dn)") }
    }

    static func summary(_ editor: GroupPolicyEditor, _ gpo: DefaultGPO) async throws -> String {
        let s = try await editor.state(gpo)
        let links = s.linkedOn.map(\.description).joined(separator: "; ")
        return "\(s.displayName) \(gpo.guid) version \(s.containerVersion.raw) (user \(s.containerVersion.user), machine \(s.containerVersion.machine))"
            + (s.versionsMatch ? "" : " GPT.INI \(s.fileVersion.raw) MISMATCH")
            + " linked on \(links.isEmpty ? "-" : links)"
    }

    static func describe(_ state: AutoEnrollmentState) -> String {
        switch state {
        case .notConfigured: "autoenrollment: not configured"
        case .disabled: "autoenrollment: disabled"
        case let .enabled(ae, urls): "autoenrollment: enabled (AEPolicy \(ae)), enrollment policy servers: \(urls.isEmpty ? "-" : urls.joined(separator: ", "))"
        }
    }

    /// The last (most specific) CN of a name.
    static func commonName(_ name: DistinguishedName) -> String? {
        var cn: String?
        for rdn in name { for ava in rdn where ava.type == .RDNAttributeType.commonName { cn = String(describing: ava.value) } }
        return cn
    }

    static func day(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle().year().month().day())
    }
}
