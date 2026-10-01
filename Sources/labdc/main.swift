// labdc: the phase-1 domain controller in one process, plus offline admin commands.
// See `CLIParser.usage` (and README.md). Arguments are parsed by hand.
import Foundation
import LabDCCLI

setvbuf(stdout, nil, _IOLBF, 0)

/// SIGINT/SIGTERM sources of `serve`. Global so they live as long as the process: a local
/// is released early in release builds and the signals are then ignored (wp-e.md).
var signalSources: [any DispatchSourceSignal] = []

func fail(_ error: Error) -> Never {
    if let e = error as? CLIError {
        FileHandle.standardError.write(Data("labdc: \(e.description)\n".utf8))
        if case .usage = e { FileHandle.standardError.write(Data((CLIParser.usage + "\n").utf8)) }
        exit(e.exitCode)
    }
    FileHandle.standardError.write(Data("labdc: \(error)\n".utf8))
    exit(1)
}

// First run after the rename (1 Oct 2026): ~/Library/Application Support/SheepAuth and its
// profiles/backups become LabDC's (LegacyMigration). An explicit --data names its own folder.
let arguments = Array(CommandLine.arguments.dropFirst())
if !arguments.contains("--data"), !["help", "-h", "--help"].contains(arguments.first ?? "help") {
    let report = LegacyMigration.run()
    for line in report.lines { FileHandle.standardError.write(Data("labdc: migration: \(line)\n".utf8)) }
    if report.blocked != nil { exit(1) }
}

let command: CLICommand
do { command = try CLIParser.parse(Array(CommandLine.arguments.dropFirst())) } catch { fail(error) }

switch command {
case .help:
    print(CLIParser.usage)

case .serve(let options):
    // UI-1: also appended to <data>/logs/serve-YYYY-MM-DD.log (the app's Activity page reads it).
    let log = ServeLog(echo: true, file: ServeLogFile(directory: DataDirectory(options.dataDirectory).logsURL))
    let runtime = ServeRuntime(options: options, log: log)
    // Handlers first, so a signal during start-up also stops cleanly.
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let stopping = StopFlag()
    signalSources = [SIGINT, SIGTERM].map { sig in
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        source.setEventHandler {
            guard stopping.begin() else {
                log.event("serve", "second signal: exiting now")
                exit(1)
            }
            log.event("serve", "\(sig == SIGINT ? "SIGINT" : "SIGTERM"): stopping")
            Task {
                await runtime.stop()
                log.event("serve", "stopped")
                exit(0)
            }
        }
        source.resume()
        return source
    }
    do {
        try await runtime.start()
    } catch {
        fail(error)
    }
    log.banner(await runtime.banner())
    let addresses = ServeAddresses.current()
    if options.advertise == nil, addresses.count > 1 {
        log.warning("serve", ServeRuntime.multipleAddressWarning(addresses))
    }
    log.event("serve", "ready")
    while true { try await Task.sleep(for: .seconds(3600)) }

default:
    do {
        try await CLICommands.run(command) { print($0) }
    } catch {
        fail(error)
    }
}

/// Set once by the first signal.
final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var started = false
    func begin() -> Bool {
        lock.withLock {
            if started { return false }
            started = true
            return true
        }
    }
}
