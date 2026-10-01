// labdc-kdc: command-line front end of the phase-0 KDC.
//
//   labdc-kdc serve         --principals Scripts/principals.json [--port 88] [--bind 0.0.0.0] [--verbose]
//   labdc-kdc export-keytab --principals Scripts/principals.json --out lab.keytab
//   labdc-kdc show          --principals Scripts/principals.json
//
// Arguments are parsed by hand (no ArgumentParser in phase 0). Keys are never printed.
import Foundation
import KDC

setvbuf(stdout, nil, _IOLBF, 0)

/// SIGINT/SIGTERM handlers of `serve`; global so they live as long as the process
/// (a local array is released early in release builds, and the signals are then ignored).
var signalSources: [any DispatchSourceSignal] = []

let usage = """
    usage:
      labdc-kdc serve         --principals <file> [--port 88] [--bind 0.0.0.0] [--verbose]
      labdc-kdc export-keytab --principals <file> --out <keytab>
      labdc-kdc show          --principals <file>
    """

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("labdc-kdc: \(message)\n".utf8))
    exit(code)
}

func usageError(_ message: String) -> Never {
    FileHandle.standardError.write(Data("labdc-kdc: \(message)\n\(usage)\n".utf8))
    exit(64)
}

/// `--name value` options and bare `--flag`s.
struct Options {
    var values: [String: String] = [:]
    var flags: Set<String> = []

    init(_ args: ArraySlice<String>, valued: Set<String>, flags allowed: Set<String>) {
        var it = args.makeIterator()
        while let arg = it.next() {
            if valued.contains(arg) {
                guard let v = it.next() else { usageError("\(arg) needs a value") }
                values[arg] = v
            } else if allowed.contains(arg) {
                flags.insert(arg)
            } else if arg == "-h" || arg == "--help" {
                print(usage)
                exit(0)
            } else {
                usageError("unknown argument \(arg)")
            }
        }
    }

    func required(_ name: String) -> String {
        guard let v = values[name] else { usageError("missing \(name)") }
        return v
    }
}

func loadStore(_ path: String) -> JSONPrincipalStore {
    do {
        let store = try JSONPrincipalStore(contentsOf: URL(fileURLWithPath: path))
        if store.generatedKeys { print("generated new krbtgt keys and saved them to \(path)") }
        return store
    } catch {
        fail("\(error)")
    }
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else { usageError("missing command") }
let rest = arguments.dropFirst(2)

switch arguments[1] {
case "serve":
    let opts = Options(rest, valued: ["--principals", "--port", "--bind"], flags: ["--verbose"])
    let store = loadStore(opts.required("--principals"))
    guard let port = UInt16(opts.values["--port"] ?? "88") else { usageError("bad --port") }
    let bind = opts.values["--bind"] ?? "0.0.0.0"
    let verbose = opts.flags.contains("--verbose")
    let kdc = KDC(store: store, onExchange: { record in
        var line = record.description
        if verbose {
            line += " [\(record.replySize) bytes]"
            if let reason = record.reason { line += " (\(reason))" }
        }
        print(line)
    })
    let server = KDCServer(kdc: kdc, port: port, bindAddress: bind)
    do { try await server.start() } catch { fail("cannot listen on \(bind):\(port): \(error)") }
    print("labdc-kdc serving realm \(store.realm) on udp+tcp \(bind):\(server.port)")

    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    signalSources = [SIGINT, SIGTERM].map { sig in
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        source.setEventHandler {
            server.stop()
            print("labdc-kdc stopped")
            exit(0)
        }
        source.resume()
        return source
    }
    while true { try await Task.sleep(for: .seconds(3600)) }

case "export-keytab":
    let opts = Options(rest, valued: ["--principals", "--out"], flags: [])
    let store = loadStore(opts.required("--principals"))
    let out = opts.required("--out")
    do {
        let principals = try await store.allPrincipals()
        let entries = Keytab.entries(for: principals)
        try Keytab.write(entries, to: URL(fileURLWithPath: out))
        print("wrote \(entries.count) keys of \(principals.count) principals to \(out)")
    } catch {
        fail("\(error)")
    }

case "show":
    let opts = Options(rest, valued: ["--principals"], flags: [])
    let store = loadStore(opts.required("--principals"))
    print("realm \(store.realm)  domain SID \(store.domainSID)  NetBIOS \(store.netbiosDomain)  DC \(store.dcName)  DNS \(store.dnsDomain)")
    do {
        for p in try await store.allPrincipals() {
            var line = "\(p.displayName)  \(p.kind.label)  kvno=\(p.kvno)  etypes=\(p.enctypes.map { String($0.rawValue) }.joined(separator: ","))"
            switch p.kind {
            case let .user(sid, upn, _, groups):
                line += "  sid=\(sid)  upn=\(upn)  groups=\(groups.map(String.init).joined(separator: ","))"
            case let .computer(sid, _, groups):
                line += "  sid=\(sid)  groups=\(groups.map(String.init).joined(separator: ","))"
            case .service, .krbtgt:
                break
            }
            if !p.enabled { line += "  DISABLED" }
            print(line)
        }
    } catch {
        fail("\(error)")
    }

case "-h", "--help", "help":
    print(usage)

default:
    usageError("unknown command \(arguments[1])")
}
