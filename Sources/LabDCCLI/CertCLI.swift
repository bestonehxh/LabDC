import CertConvert
import Foundation

/// Where a password comes from. Passwords are never printed.
public enum CertPasswordSource: Equatable, Sendable {
    case none
    case value(String)
    /// One line of standard input (`--password-stdin`, then `--out-password-stdin`).
    case stdin
}

/// Input-side options shared by the `cert` subcommands.
public struct CertInputOptions: Equatable, Sendable {
    public var password: CertPasswordSource = .none
    /// JKS key-entry password when it differs from the store password.
    public var keyPassword: String?
    /// Only this PKCS#12 friendlyName / JKS alias.
    public var alias: String?

    public init(password: CertPasswordSource = .none, keyPassword: String? = nil, alias: String? = nil) {
        self.password = password
        self.keyPassword = keyPassword
        self.alias = alias
    }
}

public struct CertConvertCLIOptions: Equatable, Sendable {
    public var input: String
    public var format: OutputFormat
    public var out: String
    public var keys: [String] = []
    public var chain: [String] = []
    public var inputOptions = CertInputOptions()
    public var outPassword: CertPasswordSource = .none
    public var legacy = false
    public var friendlyName: String?
    public var noChain = false
    /// pem/der: one file per certificate (`<out stem>-N.<ext>`).
    public var split = false

    public init(input: String, format: OutputFormat, out: String) {
        self.input = input
        self.format = format
        self.out = out
    }
}

public struct CertExportCLIOptions: Equatable, Sendable {
    public var preset: ExportPreset
    public var input: String
    public var outDirectory: String
    public var baseName: String?
    public var keys: [String] = []
    public var chain: [String] = []
    public var inputOptions = CertInputOptions()
    public var outPassword: CertPasswordSource = .none
    public var legacy = false
    public var friendlyName: String?

    public init(preset: ExportPreset, input: String, outDirectory: String) {
        self.preset = preset
        self.input = input
        self.outDirectory = outDirectory
    }
}

/// `labdc cert …` (PK-3). Offline, file-to-file; no data directory involved.
public enum CertCommand: Equatable, Sendable {
    case inspect(files: [String], CertInputOptions)
    case convert(CertConvertCLIOptions)
    case verify(cert: String, ca: [String], chain: [String], CertInputOptions)
    case match(cert: String, key: String, CertInputOptions)
    case exportFor(CertExportCLIOptions)
}

enum CertCLIParser {
    static let usage = """
          labdc cert inspect <file>… [--password <pw> | --password-stdin] [--key-password <pw>] [--alias <name>]
          labdc cert convert <in> --to pem|der|p7b|p12|key-pkcs8|key-pkcs1|combined --out <file>
                                 [--key <file>] [--chain <file>]… [--password <pw> | --password-stdin]
                                 [--out-password <pw> | --out-password-stdin] [--legacy] [--name <friendlyName>]
                                 [--no-chain] [--split] [--alias <name>] [--key-password <pw>]
          labdc cert verify <cert> --ca <ca-file> [--ca <file>]… [--chain <file>]… [--password <pw> | --password-stdin]
          labdc cert match <cert> <key> [--password <pw> | --password-stdin]
          labdc cert export-for clearpass|imaster|switch|windows|macos <in> --out-dir <dir> [--name <base>]
                                 [--key <file>] [--chain <file>]… [--password …] [--out-password …] [--legacy]
        """

    /// `--name value` (repeatable) options, flags and positionals.
    struct Args {
        var values: [String: [String]] = [:]
        var flags: Set<String> = []
        var positionals: [String] = []

        init(_ args: [String], valued: Set<String>, flags known: Set<String>) throws {
            var i = 0
            while i < args.count {
                let a = args[i]
                if valued.contains(a) {
                    guard i + 1 < args.count else { throw CLIError.usage("\(a) needs a value") }
                    values[a, default: []].append(args[i + 1])
                    i += 2
                } else if known.contains(a) {
                    flags.insert(a)
                    i += 1
                } else if a.hasPrefix("--") {
                    throw CLIError.usage("unknown argument \(a)")
                } else {
                    positionals.append(a)
                    i += 1
                }
            }
        }

        func one(_ name: String) throws -> String? {
            guard let v = values[name] else { return nil }
            guard v.count == 1 else { throw CLIError.usage("\(name) given more than once") }
            return v[0]
        }

        func required(_ name: String) throws -> String {
            guard let v = try one(name) else { throw CLIError.usage("missing \(name)") }
            return v
        }

        func password(_ value: String, _ stdinFlag: String) throws -> CertPasswordSource {
            let v = try one(value)
            if v != nil, flags.contains(stdinFlag) { throw CLIError.usage("use \(value) or \(stdinFlag), not both") }
            if let v { return .value(v) }
            return flags.contains(stdinFlag) ? .stdin : .none
        }

        func inputOptions() throws -> CertInputOptions {
            CertInputOptions(password: try password("--password", "--password-stdin"),
                             keyPassword: try one("--key-password"), alias: try one("--alias"))
        }
    }

    static let inputValued: Set<String> = ["--password", "--key-password", "--alias"]
    static let inputFlags: Set<String> = ["--password-stdin"]

    static func parse(_ rest: [String]) throws -> CertCommand {
        guard let sub = rest.first else { throw CLIError.usage("cert needs inspect, convert, verify, match or export-for") }
        let args = Array(rest.dropFirst())
        switch sub {
        case "inspect", "show", "decode":
            let a = try Args(args, valued: inputValued, flags: inputFlags)
            guard !a.positionals.isEmpty else { throw CLIError.usage("cert inspect needs a file") }
            return .inspect(files: a.positionals, try a.inputOptions())
        case "convert":
            let a = try Args(args, valued: inputValued.union(["--to", "--out", "--key", "--chain", "--out-password", "--name"]),
                             flags: inputFlags.union(["--out-password-stdin", "--legacy", "--no-chain", "--split"]))
            guard a.positionals.count == 1 else { throw CLIError.usage("cert convert needs exactly one input file") }
            let toText = try a.required("--to")
            guard let format = OutputFormat(argument: toText) else {
                throw CLIError.usage("--to is pem, der, p7b, p12, key-pkcs8, key-pkcs1 or combined, not \(toText)")
            }
            var o = CertConvertCLIOptions(input: a.positionals[0], format: format, out: try a.required("--out"))
            o.keys = a.values["--key"] ?? []
            o.chain = a.values["--chain"] ?? []
            o.inputOptions = try a.inputOptions()
            o.outPassword = try a.password("--out-password", "--out-password-stdin")
            o.legacy = a.flags.contains("--legacy")
            o.friendlyName = try a.one("--name")
            o.noChain = a.flags.contains("--no-chain")
            o.split = a.flags.contains("--split")
            if o.split, format != .pem, format != .der { throw CLIError.usage("--split works with --to pem or der") }
            return .convert(o)
        case "verify":
            let a = try Args(args, valued: inputValued.union(["--ca", "--chain"]), flags: inputFlags)
            guard a.positionals.count == 1 else { throw CLIError.usage("cert verify needs exactly one certificate file") }
            guard let ca = a.values["--ca"], !ca.isEmpty else { throw CLIError.usage("cert verify needs --ca <file>") }
            return .verify(cert: a.positionals[0], ca: ca, chain: a.values["--chain"] ?? [], try a.inputOptions())
        case "match":
            let a = try Args(args, valued: inputValued, flags: inputFlags)
            guard a.positionals.count == 2 else { throw CLIError.usage("cert match needs <cert> <key>") }
            return .match(cert: a.positionals[0], key: a.positionals[1], try a.inputOptions())
        case "export-for", "export":
            let a = try Args(args, valued: inputValued.union(["--out-dir", "--name", "--key", "--chain", "--out-password", "--friendly-name"]),
                             flags: inputFlags.union(["--out-password-stdin", "--legacy"]))
            guard a.positionals.count == 2 else {
                throw CLIError.usage("cert export-for needs <preset> <input> (presets: \(ExportPreset.allCases.map(\.rawValue).joined(separator: ", ")))")
            }
            guard let preset = ExportPreset(rawValue: a.positionals[0].lowercased()) else {
                throw CLIError.usage("unknown preset \(a.positionals[0]) (presets: \(ExportPreset.allCases.map(\.rawValue).joined(separator: ", ")))")
            }
            var o = CertExportCLIOptions(preset: preset, input: a.positionals[1], outDirectory: try a.required("--out-dir"))
            o.baseName = try a.one("--name")
            o.keys = a.values["--key"] ?? []
            o.chain = a.values["--chain"] ?? []
            o.inputOptions = try a.inputOptions()
            o.outPassword = try a.password("--out-password", "--out-password-stdin")
            o.legacy = a.flags.contains("--legacy")
            o.friendlyName = try a.one("--friendly-name")
            return .exportFor(o)
        default:
            throw CLIError.usage("unknown cert command \(sub)")
        }
    }
}

/// Runs `cert` commands.
public enum CertCLI {
    /// Reads a password when one is needed but was not given; the default prompts on the
    /// terminal without echo (`readpassphrase`), and returns nil when there is no terminal.
    public typealias PasswordPrompt = @Sendable (String) -> String?

    public static let terminalPrompt: PasswordPrompt = { prompt in
        var buf = [CChar](repeating: 0, count: 1024)
        guard let p = readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) else { return nil }
        return String(cString: p)
    }

    /// Lines of standard input, read lazily (for `--password-stdin` / `--out-password-stdin`).
    final class StdinLines: @unchecked Sendable {
        private let read: () -> String?
        init(_ read: @escaping () -> String? = { Swift.readLine(strippingNewline: true) }) { self.read = read }
        func next(_ flag: String) throws -> String {
            guard let line = read() else { throw CLIError.failure("\(flag): no line on standard input") }
            return line
        }
    }

    public static func run(_ command: CertCommand, out: (String) -> Void,
                           prompt: @escaping PasswordPrompt = terminalPrompt,
                           stdin: @escaping () -> String? = { Swift.readLine(strippingNewline: true) }) async throws {
        let lines = StdinLines(stdin)
        do {
            try await dispatch(command, out: out, prompt: prompt, stdin: lines)
        } catch let e as CertConvertError {
            throw CLIError.failure(e.description)
        }
    }

    private static func dispatch(_ command: CertCommand, out: (String) -> Void, prompt: @escaping PasswordPrompt,
                                 stdin: StdinLines) async throws {
        switch command {
        case let .inspect(files, options):
            var loader = try Loader(options, prompt: prompt, stdin: stdin)
            for (i, file) in files.enumerated() {
                if i > 0 { out("") }
                var bundle = try loader.load(file)
                if let alias = options.alias { bundle = try bundle.selecting(alias: alias) }
                for line in CertConvert.report(bundle) { out(line) }
            }

        case .convert(let o):
            var loader = try Loader(o.inputOptions, prompt: prompt, stdin: stdin)
            let bundle = try loader.loadAll(main: o.input, keys: o.keys, chain: o.chain, alias: o.inputOptions.alias)
            let outPassword = try resolve(o.outPassword, "--out-password-stdin", stdin: stdin)
            var options = OutputOptions(legacy: o.legacy, friendlyName: o.friendlyName, includeChain: !o.noChain)
            switch o.format {
            case .p12:
                options.password = outPassword ?? loader.password
                if options.password == nil {
                    options.password = prompt("Password for the new PKCS#12 file: ")
                    guard options.password != nil else { throw CLIError.failure("PKCS#12 output needs --out-password or --password") }
                }
            case .keyPKCS8, .keyPKCS1, .combined:
                options.password = outPassword // keys stay unencrypted unless --out-password is given
            default:
                break
            }
            let outURL = URL(fileURLWithPath: o.out)
            if o.split {
                let stem = outURL.deletingPathExtension().lastPathComponent
                let files = CertConvert.splitCertificates(bundle, pem: o.format == .pem, baseName: stem)
                guard !files.isEmpty else { throw CLIError.failure("no certificate to write") }
                for f in files {
                    let url = outURL.deletingLastPathComponent().appendingPathComponent(f.name)
                    try write(f, to: url)
                    out("wrote \(f.summary) to \(url.path)")
                }
            } else {
                let file = try CertConvert.convert(bundle, to: o.format, options: options,
                                                   baseName: outURL.deletingPathExtension().lastPathComponent)
                try write(file, to: outURL)
                out("wrote \(file.summary) to \(o.out)\(file.containsPrivateKey ? " (mode 0600)" : "")")
                if o.format == .der, bundle.certificates.count > 1 {
                    out("note: DER holds one certificate; \(bundle.certificates.count - 1) other(s) not written (use --split, --to pem or --to p7b)")
                }
            }

        case let .verify(certFile, caFiles, chainFiles, options):
            var loader = try Loader(options, prompt: prompt, stdin: stdin)
            let certBundle = try loader.load(certFile)
            guard let leaf = certBundle.leaf else { throw CLIError.failure("\(certFile) holds no certificate") }
            var roots: [CertificateItem] = []
            for f in caFiles { roots += try loader.load(f).certificates }
            guard !roots.isEmpty else { throw CLIError.failure("no CA certificate in \(caFiles.joined(separator: ", "))") }
            var intermediates = certBundle.certificates.filter { $0.der != leaf.der }
            for f in chainFiles { intermediates += try loader.load(f).certificates }
            let result = await CertConvert.verify(leaf, intermediates: intermediates, roots: roots)
            for line in result.lines() { out(line) }
            if !result.valid { throw CLIError.failure("verification failed") }

        case let .match(certFile, keyFile, options):
            var loader = try Loader(options, prompt: prompt, stdin: stdin)
            let certs = try loader.load(certFile).certificates
            let keyBundle = try loader.load(keyFile)
            guard let key = keyBundle.primaryKey else { throw CLIError.failure("\(keyFile) holds no private key") }
            guard !certs.isEmpty else { throw CLIError.failure("\(certFile) holds no certificate") }
            if let hit = certs.first(where: { key.matches($0) }) {
                out("MATCH: the \(key.algorithm) key in \(keyFile) belongs to \(hit.certificate.subject)")
                out("  public key SHA-256 \(key.publicKeyFingerprint ?? "?")")
            } else {
                out("NO MATCH: the \(key.algorithm) key in \(keyFile) belongs to none of the \(certs.count) certificate(s) in \(certFile)")
                throw CLIError.failure("key and certificate do not match")
            }

        case .exportFor(let o):
            var loader = try Loader(o.inputOptions, prompt: prompt, stdin: stdin)
            let bundle = try loader.loadAll(main: o.input, keys: o.keys, chain: o.chain, alias: o.inputOptions.alias)
            let outPassword = try resolve(o.outPassword, "--out-password-stdin", stdin: stdin)
            var options = OutputOptions(legacy: o.legacy, friendlyName: o.friendlyName)
            let needsPFX = bundle.primaryKey != nil && [.clearpass, .windows, .macos].contains(o.preset)
            switch o.preset {
            case .clearpass, .windows, .macos, .imaster:
                // PFX password / iMaster key password: --out-password, else the input password.
                options.password = outPassword ?? loader.password
            case .switch:
                options.password = outPassword
            }
            if needsPFX, options.password == nil {
                options.password = prompt("Password for the new \(o.preset.title) PFX: ")
                guard options.password != nil else { throw CLIError.failure("the PFX needs --out-password or --password") }
            }
            let base = o.baseName ?? URL(fileURLWithPath: o.input).deletingPathExtension().lastPathComponent
            let dir = URL(fileURLWithPath: (o.outDirectory as NSString).expandingTildeInPath, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let files = try CertConvert.export(bundle, for: o.preset, options: options, baseName: base)
            out("\(o.preset.title) export:")
            for f in files {
                let url = dir.appendingPathComponent(f.name)
                try write(f, to: url)
                out("  \(url.path)  \(f.summary)\(f.containsPrivateKey ? " (mode 0600)" : "")")
            }
        }
    }

    private static func resolve(_ source: CertPasswordSource, _ flag: String, stdin: StdinLines) throws -> String? {
        switch source {
        case .none: nil
        case .value(let v): v
        case .stdin: try stdin.next(flag)
        }
    }

    /// Loads files, asking for the password once when the first encrypted input needs one.
    struct Loader {
        var password: String?
        let keyPassword: String?
        let prompt: PasswordPrompt

        init(_ options: CertInputOptions, prompt: @escaping PasswordPrompt, stdin: StdinLines) throws {
            self.password = try CertCLI.resolve(options.password, "--password-stdin", stdin: stdin)
            self.keyPassword = options.keyPassword
            self.prompt = prompt
        }

        mutating func load(_ path: String) throws -> CertBundle {
            let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
            do {
                return try CertConvert.load(contentsOf: url, password: password, keyPassword: keyPassword)
            } catch CertConvertError.passwordRequired(let why) where password == nil {
                guard let pw = prompt("Password for \(url.lastPathComponent): ") else {
                    throw CLIError.failure("\(why); give --password or --password-stdin")
                }
                password = pw
                return try CertConvert.load(contentsOf: url, password: pw, keyPassword: keyPassword)
            }
        }

        mutating func loadAll(main: String, keys: [String], chain: [String], alias: String?) throws -> CertBundle {
            var bundle = try load(main)
            if let alias { bundle = try bundle.selecting(alias: alias) }
            for f in keys + chain { bundle.add(try load(f)) }
            return bundle
        }
    }

    /// Writes `file`; private-key files are created 0600, others 0644.
    static func write(_ file: OutputFile, to url: URL) throws {
        let mode: Int = file.containsPrivateKey ? 0o600 : 0o644
        let fm = FileManager.default
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        guard fm.createFile(atPath: tmp.path, contents: Data(file.data), attributes: [.posixPermissions: mode]) else {
            throw CLIError.failure("cannot write \(url.path)")
        }
        do {
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: tmp.path)
            if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
            try fm.moveItem(at: tmp, to: url)
        } catch {
            try? fm.removeItem(at: tmp)
            throw CLIError.failure("cannot write \(url.path): \(error.localizedDescription)")
        }
    }
}
