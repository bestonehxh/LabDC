import DNSKit
import Foundation
import NetlogonService

public struct UserAddOptions: Equatable, Sendable {
    public var sam: String
    public var password: String
    public var upn: String?
    public var ou: String?
    public var groups: [String]

    public init(sam: String, password: String, upn: String? = nil, ou: String? = nil, groups: [String] = []) {
        self.sam = sam
        self.password = password
        self.upn = upn
        self.ou = ou
        self.groups = groups
    }
}

public enum CAExportFormat: String, Equatable, Sendable {
    case pem, der
}

/// A parsed `labdc` command line. Every command takes `--data <dir>`.
public enum CLICommand: Equatable, Sendable {
    case serve(ServeOptions)
    case userAdd(data: URL, UserAddOptions)
    case userPasswd(data: URL, sam: String, password: String)
    case userList(data: URL)
    case computerList(data: URL)
    case computerAddSPN(data: URL, account: String, spn: String)
    case dnsList(data: URL)
    case exportKeytab(data: URL, out: String)
    /// `labdc ca …` (PK-1; `ca export` is `.ca(data:, .export(...))`).
    case ca(data: URL, CACommand)
    case status(data: URL)
    /// `labdc cert …`: the certificate converter (PK-3); works on files only.
    case cert(CertCommand)
    /// `labdc gpo …` (PK-4).
    case gpo(data: URL, GPOCommand)
    /// `labdc pki …` (PK-5).
    case pki(data: URL, PKICommand)
    /// `labdc scep …` / `labdc est …` (PK-7): enrollment challenges, device settings.
    case enrollment(data: URL, protocolName: String, EnrollmentCommand)
    /// `labdc radius …` (phase 4a): NAS clients, policies, dry-run test.
    case radius(data: URL, RadiusCommand)
    /// `labdc dhcp …` (phase 5): scopes, reservations, leases, settings, test, simulate.
    case dhcp(data: URL, DHCPCommand)
    case help
}

public enum CLIParser {
    public static let usage = """
        usage:
          labdc serve [--data <dir>] [--provision realm=LAB.SHEEP dns=lab.sheep netbios=LABSHEEP dc=dc1 admin-password=<pw>]
                          [--ports dns=53,kdc=88,kpasswd=464,ldap=389,ldaps=636,gc=3268,gcs=3269,cldap=389,smb=445,sntp=123,epm=135,rpc=0,http=80,est=8443,https=443,nbns=137,nbss=139]
                          [--no-dns] [--no-smb] [--no-sntp] [--no-rpc-tcp] [--no-http] [--no-est] [--no-https] [--netbios] [--no-radius]
                          [--no-dhcp] [--no-dhcpv6]
                          [--advertise <ipv4>] [--forwarders system|<ip>[:port],…] [--dns-allow <cidr>,…]
                          [--dns-updates secure|nonsecure|off] [--verbose]
                          [--ntlm-auth ntlmv2-only|mschapv2-and-ntlmv2-only|yes]
          labdc user add <sam> --password <pw> [--upn <upn>] [--ou <dn>] [--groups g1,g2] [--data <dir>]
          labdc user passwd <sam> --password <pw> [--data <dir>]
          labdc user list [--data <dir>]
          labdc computer list [--data <dir>]
          labdc computer add-spn <account> <spn> [--data <dir>]
          labdc dns list [--data <dir>]
          labdc export-keytab --out <file> [--data <dir>]
        \(CLIParser.caUsage)
          labdc status [--data <dir>]
        \(CLIParser.gpoUsage)
        \(CLIParser.pkiUsage)
        \(CLIParser.enrollmentUsage)
        \(CLIParser.radiusUsage)
        \(CLIParser.dhcpUsage)
        \(CertCLIParser.usage)

        --data defaults to ~/Library/Application Support/LabDC (lab.sqlite and pki/ live there).
        Everything except serve works on the store file directly and may run while serve runs.
        serve leaves NetBIOS (nbns udp 137, nbss tcp 139) off unless --netbios is given (--no-netbios
        is still accepted and changes nothing); RADIUS (udp 1812/1813) always runs unless --no-radius; DHCP
        (udp 67 + 547, ports dhcp= / dhcpv6=) runs once a scope exists unless --no-dhcp (--no-dhcpv6: v4 only).
        """

    /// `~/Library/Application Support/LabDC`.
    public static var defaultDataDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/LabDC", isDirectory: true)
    }

    /// Parses the arguments after the program name.
    public static func parse(_ arguments: [String], defaultData: URL = CLIParser.defaultDataDirectory) throws -> CLICommand {
        guard let command = arguments.first else { throw CLIError.usage("missing command") }
        let rest = Array(arguments.dropFirst())
        switch command {
        case "-h", "--help", "help":
            return .help
        case "serve":
            return try parseServe(rest, defaultData: defaultData)
        case "user":
            guard let sub = rest.first else { throw CLIError.usage("user needs add, passwd or list") }
            let args = Array(rest.dropFirst())
            switch sub {
            case "add":
                let o = try Options(args, valued: ["--data", "--password", "--upn", "--ou", "--groups"], positionals: 1)
                let groups = o.values["--groups"].map {
                    $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                } ?? []
                return .userAdd(data: o.data(defaultData), UserAddOptions(
                    sam: o.positionals[0], password: try o.required("--password"), upn: o.values["--upn"],
                    ou: o.values["--ou"], groups: groups))
            case "passwd":
                let o = try Options(args, valued: ["--data", "--password"], positionals: 1)
                return .userPasswd(data: o.data(defaultData), sam: o.positionals[0], password: try o.required("--password"))
            case "list":
                let o = try Options(args, valued: ["--data"])
                return .userList(data: o.data(defaultData))
            default:
                throw CLIError.usage("unknown user command \(sub)")
            }
        case "computer":
            guard let sub = rest.first else { throw CLIError.usage("computer needs list or add-spn") }
            let args = Array(rest.dropFirst())
            switch sub {
            case "list":
                let o = try Options(args, valued: ["--data"])
                return .computerList(data: o.data(defaultData))
            case "add-spn":
                let o = try Options(args, valued: ["--data"], positionals: 2)
                return .computerAddSPN(data: o.data(defaultData), account: o.positionals[0], spn: o.positionals[1])
            default:
                throw CLIError.usage("unknown computer command \(sub)")
            }
        case "dns":
            guard rest.first == "list" else { throw CLIError.usage("dns needs list") }
            let o = try Options(Array(rest.dropFirst()), valued: ["--data"])
            return .dnsList(data: o.data(defaultData))
        case "export-keytab":
            let o = try Options(rest, valued: ["--data", "--out"])
            return .exportKeytab(data: o.data(defaultData), out: try o.required("--out"))
        case "ca":
            return try parseCA(rest, defaultData: defaultData)
        case "status":
            let o = try Options(rest, valued: ["--data"])
            return .status(data: o.data(defaultData))
        case "cert":
            return .cert(try CertCLIParser.parse(rest))
        case "gpo":
            return try parseGPO(rest, defaultData: defaultData)
        case "pki":
            return try parsePKI(rest, defaultData: defaultData)
        case "scep", "est":
            return try parseEnrollment(rest, protocolName: command, defaultData: defaultData)
        case "radius":
            return try parseRadius(rest, defaultData: defaultData)
        case "dhcp":
            return try parseDHCP(rest, defaultData: defaultData)
        default:
            throw CLIError.usage("unknown command \(command)")
        }
    }

    static func parseServe(_ args: [String], defaultData: URL) throws -> CLICommand {
        var options = ServeOptions(dataDirectory: defaultData)
        var i = 0
        func value(_ name: String) throws -> String {
            i += 1
            guard i < args.count, !args[i].hasPrefix("--") else { throw CLIError.usage("\(name) needs a value") }
            return args[i]
        }
        while i < args.count {
            let arg = args[i]
            switch arg {
            case "--data":
                options.dataDirectory = expand(try value(arg))
            case "--provision":
                var tokens: [String] = []
                while i + 1 < args.count, !args[i + 1].hasPrefix("--") {
                    i += 1
                    tokens.append(args[i])
                }
                guard !tokens.isEmpty else { throw CLIError.usage("--provision needs key=value items") }
                options.provision = try ProvisionSpec.parse(tokens)
            case "--ports":
                try options.ports.apply(try value(arg))
            case "--no-dns":
                options.dnsEnabled = false
            case "--no-smb":
                options.smbEnabled = false
            case "--no-sntp":
                options.sntpEnabled = false
            case "--no-rpc-tcp":
                options.rpcTcpEnabled = false
            case "--no-http":
                options.httpEnabled = false
            case "--no-est":
                options.estEnabled = false
            case "--no-https":
                options.httpsEnabled = false
            case "--no-radius", "--radius":
                // RADIUS is on by default with the directory; --no-radius is for tests/scripts
                // (--radius stays accepted for older scripts).
                options.radiusEnabled = arg == "--radius"
            case "--no-dhcp":
                options.dhcpEnabled = false
            case "--no-dhcpv6":
                options.dhcpV6Enabled = false
            case "--netbios", "--no-netbios":
                // Off by default (macOS's netbiosd owns 137 and nothing in the join needs it);
                // --no-netbios stays for older scripts.
                options.netbiosEnabled = arg == "--netbios"
            case "--forwarders":
                // Where DNS sends names outside the domain: "system" (this Mac's DNS, the default)
                // or addresses, e.g. --forwarders 10.0.0.53,8.8.8.8.
                let text = try value(arg)
                do { options.dnsForwarding = try DNSForwarding(parsing: text) } catch {
                    throw CLIError.usage("--forwarders: \(error)")
                }
            case "--dns-allow":
                // Networks besides this Mac's own and the DHCP scopes that may resolve names
                // outside the domain through this DNS, e.g. --dns-allow 10.8.0.0/16,fd00::/64.
                let text = try value(arg)
                do { options.dnsAllowedClients = try DNSNetwork.parseList(text) } catch {
                    throw CLIError.usage("--dns-allow: \(error)")
                }
            case "--dns-updates":
                // Dynamic DNS updates: nonsecure (GSS-TSIG plus unsigned own-address updates, the
                // default), secure (GSS-TSIG only; unsigned ones are REFUSED) or off.
                let v = try value(arg)
                guard let mode = DNSDynamicUpdateMode(argument: v) else {
                    throw CLIError.usage("--dns-updates takes secure, nonsecure or off, not \(v)")
                }
                options.dnsUpdateMode = mode
            case "--advertise":
                let address = try value(arg)
                guard isIPv4(address) else { throw CLIError.usage("--advertise needs a dotted IPv4 address, not \(address)") }
                options.advertise = address
            case "--ntlm-auth":
                let v = try value(arg)
                guard let policy = NTLMAuthPolicy(rawValue: v) else {
                    throw CLIError.usage("--ntlm-auth takes ntlmv2-only, mschapv2-and-ntlmv2-only or yes, not \(v)")
                }
                options.ntlmAuth = policy
            case "--verbose", "-v":
                options.verbose = true
            case "-h", "--help":
                return .help
            default:
                throw CLIError.usage("unknown argument \(arg)")
            }
            i += 1
        }
        return .serve(options)
    }

    static func expand(_ path: String) -> URL {
        URL(fileURLWithPath: (path as NSString).expandingTildeInPath, isDirectory: true).standardizedFileURL
    }

    public static func isIPv4(_ text: String) -> Bool {
        var a = in_addr()
        return inet_pton(AF_INET, text, &a) == 1
    }

    /// `--name value` options plus a fixed number of positional arguments.
    struct Options {
        var values: [String: String] = [:]
        var positionals: [String] = []

        init(_ args: [String], valued: Set<String>, positionals count: Int = 0) throws {
            var i = 0
            while i < args.count {
                let arg = args[i]
                if valued.contains(arg) {
                    guard i + 1 < args.count else { throw CLIError.usage("\(arg) needs a value") }
                    values[arg] = args[i + 1]
                    i += 2
                    continue
                }
                if arg.hasPrefix("--") { throw CLIError.usage("unknown argument \(arg)") }
                positionals.append(arg)
                i += 1
            }
            guard positionals.count == count else {
                throw CLIError.usage(count == 0 ? "unexpected argument \(positionals[0])"
                                     : "expected \(count) argument\(count == 1 ? "" : "s"), got \(positionals.count)")
            }
        }

        func required(_ name: String) throws -> String {
            guard let v = values[name] else { throw CLIError.usage("missing \(name)") }
            return v
        }

        func data(_ fallback: URL) -> URL { values["--data"].map(CLIParser.expand) ?? fallback }
    }
}
