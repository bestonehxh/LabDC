import DirectoryKit
import DNSKit
import RADIUSKit
import Foundation
import Observation
import PKIKit
import SYSVOL
import Store
import X509

/// The embedded server of the app: the same `ServeRuntime` as `labdc serve`, in-process, with
/// the settings from `<data>/settings.json`, an observable `ServerStatus`, the log as a `LogHub`
/// (plus the daily file) and the Overview's derived data (directory summary, recent activity).
///
/// UI-2/3/4 use `store` / `pki` / `runtime` for their pages (the same Store/PKI/GPO APIs the CLI
/// uses) and `logs.stream()` for live updates; call `refreshSummary()` after a mutation.
@MainActor @Observable
public final class ServerController {
    public let data: DataDirectory
    public let status = ServerStatus()
    @ObservationIgnored public let logs: LogHub
    @ObservationIgnored public let logFile: ServeLogFile
    public private(set) var settings: ServerSettings
    public private(set) var summary = DirectorySummary()
    /// Last 20 sign-in outcomes, newest first.
    public private(set) var recentActivity: [ActivityEvent] = []
    /// Bumped after every settings save (the "Saved" pill watches it).
    public private(set) var savedGeneration = 0

    public private(set) var runtime: ServeRuntime?
    public private(set) var store: DirectoryStore?
    public private(set) var pki: LabPKI?
    @ObservationIgnored public let serveLog: ServeLog
    @ObservationIgnored private let portOverride: PortSet?
    @ObservationIgnored private var failures: [ServeListener: String] = [:]
    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    @ObservationIgnored private var summaryTask: Task<Void, Never>?
    @ObservationIgnored private var lastOptions: ServeOptions?
    /// The start in flight (`start()` joins it, `stop()` cancels and waits for it).
    @ObservationIgnored private var startTask: Task<Void, Never>?
    /// Ports a restart keeps for listeners configured as 0 (ephemeral in tests, the dynamic RPC
    /// port in production), so Restart All does not move them.
    @ObservationIgnored private var sessionPins: [ServeListener: UInt16] = [:]
    /// A restart or domain rename is between its stop and its start (`.restarting`).
    @ObservationIgnored private var restartWindow = false
    /// `stop()` / `retire()` came during that window: its pending start must not happen.
    @ObservationIgnored private var restartCancelled = false
    /// `stop()` calls waiting for the restart window to close.
    @ObservationIgnored private var restartWaiters: [CheckedContinuation<Void, Never>] = []
    /// Set by `retire()`: this controller is being replaced and never starts again.
    @ObservationIgnored public private(set) var isRetired = false
    /// Services the owner stopped with Services ▸ Stop. Every start of this controller (a
    /// restart to apply a setting, a domain rename, a CA switch, a backup import) keeps them
    /// stopped; their row's Start, or Start for the whole server, clears them.
    ///
    /// Kept for the life of this controller only, not in `settings.json`: quitting and reopening
    /// the app (or switching profiles) starts everything, as the Stop confirmation says (owner,
    /// 1 Oct 2026) — a service stopped for a test must not stay off unnoticed after a relaunch.
    public private(set) var ownerStopped: Set<ServeService> = []
    /// The runtime of the start in flight (`performStart`): a stop that cancels that start reads
    /// the ports it had bound from here.
    @ObservationIgnored private var startingRuntime: ServeRuntime?
    /// Ports released by the last stop(s), not yet waited for (`stopAndWaitForPorts`).
    @ObservationIgnored private var releasedPorts: [ServeHeldPort] = []

    /// - Parameters:
    ///   - dataDirectory: the `--data` folder (`~/Library/Application Support/LabDC`).
    ///   - portOverride: base ports instead of the standard ones (tests, `--ports`); the settings'
    ///     own port changes still apply on top.
    ///   - echo: also print the log to stdout (like `labdc serve`).
    public init(dataDirectory: URL, portOverride: PortSet? = nil, echo: Bool = false) {
        let data = DataDirectory(dataDirectory)
        self.data = data
        self.portOverride = portOverride
        let hub = LogHub()
        let file = ServeLogFile(directory: data.logsURL)
        logs = hub
        logFile = file
        let (events, continuation) = AsyncStream.makeStream(of: ServeRuntimeEvent.self)
        serveLog = ServeLog(echo: echo, file: file, lines: { hub.append($0) }, onRuntimeEvent: { continuation.yield($0) })
        settings = ServerSettings.load(data.settingsURL)
        status.phase = data.hasStore ? .stopped : .notSetUp
        status.addresses = ServeAddresses.current().sorted()
        status.advertisePinned = settings.advertise != nil
        status.advertisedIPv4 = settings.advertise ?? ServeAddresses.current().first
        status.interfaces = NetworkInterfaces.current()
        // Earlier runs of today, so the Activity page and "Recent activity" survive a relaunch.
        hub.preload(file.todaysLines())
        recentActivity = ActivityEvent.recent(hub.history())

        tasks.append(Task { [weak self] in
            for await event in events { self?.handle(event) }
        })
        let lines = hub.stream()
        tasks.append(Task { [weak self] in
            for await line in lines { self?.handle(line) }
        })
    }

    public var isSetUp: Bool { data.hasStore }
    public var isRunning: Bool { runtime != nil }

    /// The options the server runs with (settings + override).
    public func serveOptions(provision: ProvisionSpec? = nil) -> ServeOptions {
        var ports = configuredPorts()
        for (l, port) in sessionPins where ports[l] == 0 { ports[l] = port }
        var options = settings.serveOptions(data: data.url, portOverride: ports, provision: provision)
        options.ownerStopped = ownerStopped
        return options
    }

    /// The ports from the override and the settings, before this session's pins.
    private func configuredPorts() -> PortSet {
        var ports = portOverride ?? .standard
        for (name, port) in settings.ports { if let l = ServeListener(rawValue: name) { ports[l] = port } }
        return ports
    }

    // MARK: Start / stop

    /// Starts every service (the `labdc serve` path); `provision` first creates the domain.
    /// Failures end in `.problem` with `lastError`, never throw. A start already in flight is
    /// joined, not repeated; `stop()` cancels it.
    public func start(provision: ProvisionSpec? = nil) async {
        // A restart in progress starts by itself; a retired controller never starts again.
        guard !isRetired, !restartWindow else { return }
        // Start for the whole server brings every service back, including any the owner stopped.
        if runtime == nil, startTask == nil { ownerStopped = [] }
        await startNow(provision: provision)
    }

    private func startNow(provision: ProvisionSpec? = nil) async {
        guard !isRetired else { return }
        if let pending = startTask {
            await pending.value
            return
        }
        guard runtime == nil, status.phase != .stopping else { return }
        let task = Task { await self.performStart(provision: provision) }
        startTask = task
        await task.value
        if startTask == task { startTask = nil }
    }

    private func performStart(provision: ProvisionSpec?) async {
        guard !Task.isCancelled else { return }
        let options = serveOptions(provision: provision)
        failures = [:]
        status.lastError = nil
        status.phase = .starting
        status.applyListeners(options: options, bound: nil, failures: [:], starting: true)
        let rt = ServeRuntime(options: options, log: serveLog)
        startingRuntime = rt
        // Whoever stopped the previous runtime waited for its ports already (a restart, or
        // `stopAndWaitForPorts`); they belong to this start now.
        releasedPorts = []
        do {
            try await rt.start()
        } catch {
            if Task.isCancelled {
                await rt.stop()
                serveLog.event("serve", "start cancelled")
                return
            }
            let message = "\(error)"
            if let l = ServeListener.named(inError: message) { failures[l] = message }
            status.lastError = message
            status.applyListeners(options: options, bound: nil, failures: failures)
            status.phase = data.hasStore ? .problem : .notSetUp
            serveLog.warning("serve", "start failed: \(message)")
            return
        }
        lastOptions = options
        if Task.isCancelled {
            // stop() came while the listeners were binding: this runtime never becomes current.
            await rt.stop()
            serveLog.event("serve", "start cancelled; stopped")
            return
        }
        runtime = rt
        startingRuntime = nil
        if let why = await rt.radiusStartFailure { failures[.radius] = why }
        await syncDHCPFailures(rt)
        store = await rt.store
        pki = await rt.pki
        if let info = try? await store?.domainInfo() { status.apply(info) }
        serveLog.banner(await rt.banner())
        let addresses = ServeAddresses.current()
        if options.advertise == nil, addresses.count > 1 {
            serveLog.warning("serve", ServeRuntime.multipleAddressWarning(addresses, app: true))
        }
        serveLog.event("serve", "ready (LabDC app)")
        status.startedAt = Date()
        status.addresses = addresses.sorted()
        status.addressesReported = true
        status.advertisePinned = options.advertise != nil
        status.advertisedIPv4 = await rt.advertisedIPv4
        status.interfaces = NetworkInterfaces.current()
        await refreshListeners()
        // The lab CA is trusted domain-wide by itself, once per CA (30 Sep 2026): a new or
        // never-published current CA goes into the Default Domain Policy at start and is
        // remembered, so a trusted root the owner removed stays removed across restarts.
        if pki != nil {
            do { try await publishCAIfNew() } catch {
                serveLog.warning("GPO", "auto-publish of the CA failed: \(error)")
            }
        }
        await refreshSummary()
    }

    /// The `domain` table key holding the thumbprint of the last CA published (by hand or at start).
    static let publishedCAKey = "app.publishedCAThumbprint"

    /// Publishes the current CA unless it was published before.
    func publishCAIfNew() async throws {
        guard let store, let pki else { return }
        let thumbprint = CertificateBlob.thumbprint(try await pki.currentAuthority().der())
        guard try await store.domainValue(forKey: Self.publishedCAKey) != thumbprint else { return }
        try await publishCA(refresh: false)
    }

    /// Settings ▸ Domain ▸ "Rename domain…": in-place rename of the DNS domain/realm/base DN —
    /// every DN, DN-valued attribute, DNS record, SPN/UPN and GPO path is rewritten, the SYSVOL
    /// domain folder moves with its GPOs and scripts, and the DC certificate reissues for the new
    /// name at start. Keys and kvnos stay (the stored salt keeps being announced), but joined
    /// devices must rejoin: their DNS suffix, realm and machine SPNs name the old domain.
    /// A failure rolls the store and the folder back and starts the server again (30 Sep 2026).
    /// - Returns: what changed, for the confirmation text.
    @discardableResult
    public func renameDomain(to newDNS: String) async throws -> DomainRenameResult {
        let setup: DomainSetup
        switch DomainSetup.derive(newDNS) {
        case .success(let s): setup = s
        case .failure(let problem): throw CLIError.failure(problem.description)
        }
        let clean = setup.dnsDomain
        guard let store else { throw CLIError.failure("the server is not running") }
        let old = try await store.domainInfo().dnsDomain.lowercased()
        guard old != clean else { throw CLIError.failure("The domain is already \(clean).") }
        let sysvol = data.sysvolURL
        return try await withServicesStopped { () async throws -> DomainRenameResult in
            var result: DomainRenameResult
            do {
                // File work runs off the main actor (a large SYSVOL must not freeze the window).
                let moved = try await Task.detached { try SysvolRename.moveDomainFolder(root: sysvol, from: old, to: clean) }.value
                do {
                    result = try await store.renameDomain(newDNS: clean)
                } catch {
                    if moved {
                        _ = try? await Task.detached { try SysvolRename.moveDomainFolder(root: sysvol, from: clean, to: old) }.value
                    }
                    throw error
                }
            } catch {
                serveLog.warning("serve", "domain rename to \(clean) failed: \(error); starting again as \(old)")
                throw CLIError.failure("Renaming to \(clean) failed: \(error)")
            }
            // The store is committed: from here on problems are warnings in the result, not a rollback.
            let rewriter = DomainNameRewriter(old: old, new: clean)
            let report = await Task.detached { SysvolRename.rewriteAll(root: sysvol, rewriter: rewriter) }.value
            if !report.changed.isEmpty { serveLog.event("SYSVOL", "domain name rewritten in \(report.changed.joined(separator: ", "))") }
            if !report.failed.isEmpty {
                for (path, why) in report.failed.sorted(by: { $0.key < $1.key }) {
                    serveLog.warning("SYSVOL", "could not rewrite \(path) for \(clean): \(why)")
                }
                let n = report.failed.count
                result.warnings.append("\(n) SYSVOL file\(n == 1 ? "" : "s") still name\(n == 1 ? "s" : "") \(old) "
                                       + "(\(report.failed.keys.sorted().joined(separator: ", "))); see the log.")
            }
            do {
                result.gposUpdated = try await SysvolRename.bumpGPOVersions(root: sysvol, store: store).count
            } catch {
                serveLog.warning("GPO", "raising GPO versions after the rename: \(error)")
                result.warnings.append("GPO versions could not be raised (\(error)); members may keep the old policy until the next edit.")
            }
            if let former = result.formerDCName {
                serveLog.event("DNS", "\(former) keeps answering with this DC's address (CRL/AIA URLs in older certificates)")
            }
            serveLog.event("serve", "\(result.summary) Services restart with reissued certificates (app)")
            return result
        }
    }

    /// Settings ▸ Domain ▸ "Start over": stops the server, moves the whole data folder (store,
    /// CA, SYSVOL, settings) to a timestamped backup beside it and starts from an empty folder —
    /// the next screen is the Setup wizard. Everything old stays in the backup; devices must
    /// join the new domain again.
    /// - Returns: the backup folder name (for the confirmation text), or throws.
    public func startOverWithNewDomain() async throws -> String {
        let dataURL = data.url
        let stamp = Self.backupStamp(Date())
        let backup = dataURL.deletingLastPathComponent().appendingPathComponent("LabDC-backup-\(stamp)", isDirectory: true)
        // Busy (`.restarting`) from the stop to the end of the move, which runs off the main
        // actor; nothing starts afterwards unless the move failed (the old domain starts again).
        try await withServicesStopped(startAfter: false) {
            try await Task.detached { try Self.moveAside(dataURL, to: backup) }.value
        }
        settings = ServerSettings()
        try saveSettings()
        status.phase = data.hasStore ? .stopped : .notSetUp
        status.startedAt = nil
        summary = DirectorySummary()
        recentActivity = []
        failures = [:]
        lastOptions = nil
        sessionPins = [:]
        serveLog.event("serve", "data moved to \(backup.lastPathComponent); ready for a new domain (app)")
        return backup.lastPathComponent
    }

    /// Moves the data folder to `backup` and leaves an empty folder in its place (Start over);
    /// a failure after the move puts the folder back.
    nonisolated static func moveAside(_ dataURL: URL, to backup: URL) throws {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: dataURL.path, isDirectory: &isDir), isDir.boolValue else { return }
        try fm.moveItem(at: dataURL, to: backup)
        do {
            try fm.createDirectory(at: dataURL, withIntermediateDirectories: true)
        } catch {
            try? fm.moveItem(at: backup, to: dataURL)
            throw error
        }
    }

    static func backupStamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")   // keep the year Gregorian (a Thai device gives 2569)
        f.dateFormat = "yyyy-MM-dd-HHmmss"
        return f.string(from: date)
    }

    /// Stops every service (reverse order, like SIGTERM on `labdc serve`). A start still in
    /// flight is cancelled and waited for first, so no runtime binds ports after this returns
    /// (switching or moving the data folder right after is safe).
    public func stop() async {
        if restartWindow {
            // Mid-restart (or rename): the pending start is refused; wait for the window to close.
            restartCancelled = true
            await withCheckedContinuation { restartWaiters.append($0) }
        }
        await stopRuntime()
    }

    /// Called before this controller is replaced (profile switch, rename, wizard Cancel): stops,
    /// and refuses every later start, including one a restart or rename still has pending.
    public func retire() async {
        isRetired = true
        await stop()
    }

    /// `stop()`, then waits until every port the stopped runtime (or a start it cancelled) had
    /// bound is free again — AppModel calls it before the next profile's controller starts on
    /// the same ports, so that start never collides with sockets still closing.
    public func stopAndWaitForPorts() async {
        await stop()
        let held = releasedPorts
        releasedPorts = []
        await ServeHeldPort.waitUntilFree(held)
    }

    /// Stops the runtime (or cancels the start in flight) and returns the ports it had actually
    /// bound — not `status.listeners`, whose ports are nil while a start is still binding.
    @discardableResult
    private func stopRuntime() async -> [ServeHeldPort] {
        var held: [ServeHeldPort] = []
        if let pending = startTask {
            status.phase = .stopping
            pending.cancel()
            await pending.value
            if startTask == pending { startTask = nil }
        }
        // A start that was cancelled (or failed) stopped its runtime itself: its ports.
        if let starting = startingRuntime, starting !== runtime {
            startingRuntime = nil
            held += await starting.releasedPorts
        }
        guard let rt = runtime else {
            if [.stopping, .starting, .restarting].contains(status.phase) { settleStopped() }
            releasedPorts += held
            return held
        }
        status.phase = .stopping
        await rt.stop()
        held += await rt.releasedPorts
        serveLog.event("serve", "stopped")
        runtime = nil
        store = nil
        pki = nil
        settleStopped()
        releasedPorts += held
        return held
    }

    private func settleStopped() {
        status.startedAt = nil
        status.dhcpStopped = ownerStopped.contains(.dhcp)
        status.phase = restartWindow ? .restarting : data.hasStore ? .stopped : .notSetUp
        if let lastOptions { status.applyListeners(options: lastOptions, bound: nil, failures: [:]) }
    }

    /// Stops, returning every port the runtime had bound (ports configured as 0 are pinned for
    /// this session, so the next start binds the same ones). Pair with `startWhenReleased`.
    private func stopHoldingPorts() async -> [ServeHeldPort] {
        let held = await stopRuntime()
        let configured = configuredPorts()
        for h in held where configured[h.listener] == 0 { sessionPins[h.listener] = h.port }
        return held
    }

    /// Opens the restart window: the phase stays `.restarting` from the stop until the start, so
    /// nothing sees an idle controller in between. False when one is open already.
    private func beginRestartWindow() -> Bool {
        guard !restartWindow, !isRetired else { return false }
        restartWindow = true
        restartCancelled = false
        status.phase = .restarting
        return true
    }

    private func endRestartWindow() {
        restartWindow = false
        if status.phase == .restarting { settleStopped() }
        let waiters = restartWaiters
        restartWaiters = []
        for w in waiters { w.resume() }
    }

    /// Waits until the stopped listeners have released their ports (Network.framework frees
    /// UDP/TCP a moment after `cancel()`), then starts, so nothing collides with itself.
    /// A `stop()` or `retire()` during the wait cancels the start.
    private func startWhenReleased(_ held: [ServeHeldPort]) async {
        for h in held where !restartCancelled && !isRetired {
            await ServeRuntime.waitUntilFree(h.port, h.protos)
        }
        guard !restartCancelled, !isRetired else {
            serveLog.event("serve", "restart cancelled; staying stopped")
            return
        }
        await startNow()
    }

    /// Stops and starts again with the current settings, on the same ports. The phase is
    /// `.restarting` throughout; a restart already in progress is joined.
    public func restart() async {
        guard beginRestartWindow() else {
            if restartWindow { await withCheckedContinuation { restartWaiters.append($0) } }
            return
        }
        defer { endRestartWindow() }
        await startWhenReleased(await stopHoldingPorts())
    }

    /// Restart after a change the running services must pick up (settings, NetBIOS name, a new
    /// current CA). A restart already in progress may have started before the change, so this
    /// waits for it and then restarts again; nothing happens when the server is stopped (or was
    /// stopped meanwhile) or the controller is retired.
    public func restartToApply() async {
        while restartWindow { await withCheckedContinuation { restartWaiters.append($0) } }
        guard runtime != nil || startTask != nil, !isRetired else { return }
        await restart()
    }

    /// The busy-phase path for work that needs the services down (domain rename, backup import,
    /// Start over): opens the restart window (`.restarting` throughout), stops holding the ports,
    /// runs `work`, then waits for the ports and starts again. When `work` throws (it undoes its
    /// own changes), the server starts again only if it was running, so it ends as it was before.
    /// `startAfter: false` stays stopped on success.
    /// A `stop()`/`retire()` meanwhile waits for `work` to finish and cancels the start.
    private func withServicesStopped<T>(startAfter: Bool = true, _ work: () async throws -> T) async throws -> T {
        guard beginRestartWindow() else {
            throw CLIError.failure(isRetired ? "This domain is closing." : "The services are already restarting; try again in a moment.")
        }
        defer { endRestartWindow() }
        let wasRunning = runtime != nil || startTask != nil
        let held = await stopHoldingPorts()
        let result: T
        do {
            result = try await work()
        } catch {
            if wasRunning { await startWhenReleased(held) }
            throw error
        }
        if startAfter { await startWhenReleased(held) }
        return result
    }

    nonisolated static func protos(_ l: ServeListener) -> [PortProbe.Proto] { ServeHeldPort.protos(l) }

    /// UI-1b, Domain ▸ Restart All Services / ⌘R on Overview: every service stops and starts again
    /// (the same as quitting and relaunching, without leaving the app).
    public func restartAllServices() async {
        serveLog.event("serve", "restart all services (app)")
        let all = Set(ServeService.allCases)
        status.restarting = all
        defer { status.restarting = [] }
        await restart()
        let outcome = RestartOutcome(date: Date(), error: status.phase == .running ? nil : status.lastError ?? "not running")
        for s in all { status.lastRestart[s] = outcome }
    }

    /// UI-1b, Overview ▸ Restart on a service row: that service's listeners stop and start on the
    /// same ports while the others keep running (`ServeRuntime.restartInPlace`). When the server is
    /// not running at all (a start failure), this retries the whole start. Returns the outcome,
    /// which the row also shows.
    @discardableResult
    public func restartService(_ service: ServeService) async -> RestartOutcome {
        guard !status.restarting.contains(service) else {
            return status.lastRestart[service] ?? RestartOutcome(date: Date())
        }
        status.restarting.insert(service)
        // Whatever happens (a throw, a busy port), the row leaves "Restarting…" with an outcome.
        var outcome = RestartOutcome(date: Date(), error: "the restart did not finish")
        defer {
            status.restarting.remove(service)
            status.lastRestart[service] = outcome
        }
        if let rt = runtime {
            do {
                if ownerStopped.remove(service) != nil {
                    // Start on a row the owner stopped: the stop is forgotten.
                    try await rt.startInPlace(service.listeners, name: service.title)
                } else {
                    try await rt.restartInPlace(service.listeners, name: service.title)
                }
                for l in service.listeners { failures[l] = nil }
                for other in service.restartAlsoAffects { for l in other.listeners { failures[l] = nil } }
                if let e = status.lastError, service.listeners.contains(where: { ServeListener.named(inError: e) == $0 }) {
                    status.lastError = nil
                }
                outcome = RestartOutcome(date: Date())
            } catch {
                let message = "\(error)"
                let failed = ServeListener.named(inError: message).flatMap { service.listeners.contains($0) ? $0 : nil }
                    ?? service.listeners.first!
                failures[failed] = message
                outcome = RestartOutcome(date: Date(), error: message)
            }
            if service == .dhcp {
                // v4 and v6 are separate listeners: one may run while the other's port is busy.
                await syncDHCPFailures(rt)
                if outcome.succeeded, let why = failures[.dhcpv6] ?? failures[.dhcp] {
                    outcome = RestartOutcome(date: Date(), error: why)
                }
            }
            await refreshListeners()
        } else {
            serveLog.event("serve", "restart \(service.title): the server is not running; starting every service")
            await start()
            outcome = RestartOutcome(date: Date(), error: status.phase == .running ? nil : status.lastError ?? "not running")
        }
        return outcome
    }

    /// Phase 5: a DHCP scope, reservation or setting changed — the runtime reloads (the first
    /// scope starts DHCP), the Services row and its summary follow.
    func dhcpChanged() async {
        guard let rt = runtime else { return }
        await rt.dhcpConfigChanged()
        await syncDHCPFailures(rt)
        await refreshListeners()
    }

    /// DHCPv4 and DHCPv6 are independent listeners, each with its own problem.
    private func syncDHCPFailures(_ rt: ServeRuntime) async {
        failures[.dhcp] = await rt.dhcpStartFailure
        failures[.dhcpv6] = await rt.dhcpv6StartFailure
    }

    /// The runtime restarted listeners by itself (LDAP/EST/HTTPS after a certificate reissue):
    /// a listener that did not come back is a problem on its row, one that did is clear again.
    func listenersChangedByRuntime(_ messages: [String]) async {
        guard runtime != nil, !status.isBusy else { return }
        let restarted: [ServeListener] = [.ldap, .ldaps, .gc, .gcs, .est, .https]
        for l in restarted { failures[l] = nil }
        if let e = status.lastError, let l = ServeListener.named(inError: e), restarted.contains(l) { status.lastError = nil }
        for message in messages {
            failures[ServeListener.named(inError: message) ?? .ldap] = message
        }
        if let message = messages.first { status.lastError = message }
        await refreshListeners()
    }

    /// The runtime's background retry bound a DHCP port that was busy.
    private func dhcpChangedByRuntime() async {
        guard let rt = runtime, !status.isBusy, !status.restarting.contains(.dhcp) else { return }
        await syncDHCPFailures(rt)
        await refreshListeners()
    }

    /// Services ▸ Stop (owner, 1 Oct 2026): stops one service; the others keep running. Restart
    /// (shown as Start on a stopped row) brings it back; quitting and reopening starts everything.
    public func stopService(_ service: ServeService) async {
        guard let rt = runtime, !status.isBusy, !status.restarting.contains(service) else { return }
        ownerStopped.insert(service)
        await rt.stopInPlace(service.listeners, name: service.title)
        for l in service.listeners { failures[l] = nil }
        if let e = status.lastError, service.listeners.contains(where: { ServeListener.named(inError: e) == $0 }) {
            status.lastError = nil
        }
        status.lastRestart[service] = nil
        await refreshListeners()
    }

    private func refreshListeners() async {
        guard let rt = runtime else { return }
        let options = await rt.options
        let bound = await rt.bound
        status.dhcpSummary = await rt.dhcp?.status().summary
        status.dhcpStopped = await rt.dhcpStoppedByOwner
        lastOptions = options
        status.applyListeners(options: options, bound: bound, failures: failures)
        let failed = !failures.isEmpty
        status.phase = failed ? .problem : .running
    }

    // MARK: Settings (applied immediately; no Apply)

    /// Moves one listener: saved, then restarted in place while everything else keeps running.
    /// On failure the old port stays (and is kept in the settings) and the error is thrown.
    public func setPort(_ listener: ServeListener, _ port: UInt16) async throws {
        let previous = settings
        guard serveOptions().ports[listener] != port else { return }
        for l in listener.restartsWith { sessionPins[l] = nil }
        settings.setPort(listener, port)
        try saveSettings()
        guard let rt = runtime else {
            // Not running (for example a busy port stopped the start): try again with the new port.
            if status.phase == .problem { await start() }
            return
        }
        do {
            try await rt.restart(listener, port: port)
            for l in listener.restartsWith { failures[l] = nil }
            status.lastError = nil
        } catch {
            settings = previous
            try? saveSettings()
            await refreshListeners()
            throw error
        }
        await refreshListeners()
    }

    /// Changes a non-port setting; the server restarts when its options change.
    public func updateSettings(_ change: (inout ServerSettings) -> Void) async throws {
        var s = settings
        change(&s)
        guard s != settings else { return }
        let before = serveOptions()
        settings = s
        try saveSettings()
        status.advertisePinned = s.advertise != nil
        // Also while a start (or a restart) is in flight: it read the old settings.
        if serveOptions() != before, runtime != nil || startTask != nil || restartWindow {
            serveLog.event("serve", "settings changed; restarting the services")
            await restartToApply()
        }
    }

    /// Settings ▸ Directory ▸ Other names: "" = this Mac's DNS, else IP addresses (comma or space
    /// separated, `:port` optional). Saved, then applied live: DNS keeps running.
    public func setDNSForwarders(_ text: String) async throws {
        let forwarding = try DNSForwarding(parsing: text)
        let list = forwarding.settingsList
        guard list != settings.dnsForwarders else { return }
        settings.dnsForwarders = list
        try saveSettings()
        if let rt = runtime {
            await rt.setDNSForwarding(forwarding)
            await refreshListeners()
        }
    }

    /// Settings: networks (CIDRs, comma or space separated) besides this Mac's own and the DHCP
    /// scopes that may resolve names outside the domain through this DNS. Saved, applied live.
    public func setDNSAllowedClients(_ text: String) async throws {
        let networks = try DNSNetwork.parseList(text)
        let list = networks.map(\.description)
        guard list != settings.dnsAllowedClients else { return }
        settings.dnsAllowedClients = list
        try saveSettings()
        await runtime?.setDNSAllowedClients(networks)
    }

    /// Settings ▸ DNS "Dynamic updates": secure and nonsecure / secure only / off. Saved, applied
    /// live (DNS keeps running).
    public func setDNSDynamicUpdates(_ mode: DNSDynamicUpdateMode) async throws {
        guard mode != settings.dnsDynamicUpdates else { return }
        settings.dnsDynamicUpdates = mode
        try saveSettings()
        await runtime?.setDNSUpdateMode(mode)
    }

    /// Where DNS sends names outside the domain right now (Services); nil while DNS is not running.
    public func dnsForwardingInfo() async -> DNSForwardingInfo? {
        guard let plan = await runtime?.dnsForwardingPlan() else { return nil }
        return DNSForwardingInfo(plan)
    }

    /// The domain's password policy (Settings ▸ Directory ▸ Password policy); nil while off.
    public func passwordPolicy() async -> PasswordPolicy? {
        guard let store else { return nil }
        return try? await store.passwordPolicy()
    }

    /// Settings ▸ Directory ▸ Password policy: applies to every later password set or changed
    /// (the app, kpasswd, SAMR and LDAP). `relaxed` accepts anything, for a lab.
    public func setPasswordPolicy(_ policy: PasswordPolicy) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.setPasswordPolicy(policy)
        serveLog.event("Store", "password policy: min \(policy.minLength), complexity \(policy.complexity), "
                       + "history \(policy.historyLength)\(policy.relaxed ? ", relaxed (any password)" : "") (app)")
    }

    // MARK: RADIUS (phase 4a)

    public func radiusNAS() async -> [DirectoryStore.NASClient] {
        guard let store else { return [] }
        return (try? await store.listNAS()) ?? []
    }

    public func addRadiusNAS(_ client: DirectoryStore.NASClient) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.addNAS(client)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "NAS \(client.name) (\(client.ip)) added (app)")
    }

    public func updateRadiusNAS(_ client: DirectoryStore.NASClient) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.updateNAS(client)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "NAS \(client.name) (\(client.ip)) updated (app)")
    }

    public func deleteRadiusNAS(id: Int64) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.deleteNAS(id: id)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "NAS deleted (app)")
    }

    public func radiusPolicies() async -> [RADIUSPolicy] {
        guard let store else { return [] }
        return (try? await store.listRadiusPolicies()) ?? []
    }

    public func saveRadiusPolicy(_ policy: RADIUSPolicy) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.saveRadiusPolicy(policy)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "policy \(policy.name) saved (\(policy.action.title), position \(policy.position + 1)) (app)")
    }

    public func deleteRadiusPolicy(id: UUID) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.deleteRadiusPolicy(id: id)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "policy deleted (app)")
    }

    /// What happens when no rule matches (Reject by default).
    /// RADIUS ▸ 802.1X ▸ "Require PEAP crypto binding" (default off).
    public func radiusRequirePEAPCryptoBinding() async -> Bool {
        guard let store else { return false }
        return (try? await store.radiusRequirePEAPCryptoBinding()) ?? false
    }

    public func setRadiusRequirePEAPCryptoBinding(_ on: Bool) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.setRadiusRequirePEAPCryptoBinding(on)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "require PEAP crypto binding: \(on ? "on" : "off") (app)")
    }

    public func radiusDefaultAction() async -> RADIUSDefaultAction {
        guard let store else { return .reject }
        return (try? await store.radiusDefaultAction()) ?? .reject
    }

    public func setRadiusDefaultAction(_ action: RADIUSDefaultAction) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.setRadiusDefaultAction(action)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "default action when no rule matches: \(action.title) (app)")
    }

    // MARK: RADIUS sessions, CoA, registered devices (phase 4c / 5)

    /// RADIUS ▸ Sessions: newest first; `activeOnly` = no Stop and updated within a day (`radiusSessionStaleAfter`).
    public func radiusSessions(activeOnly: Bool) async -> [DirectoryStore.RadiusSession] {
        guard let store else { return [] }
        return (try? await store.radiusSessions(activeOnly: activeOnly, now: Date())) ?? []
    }

    /// Reauthenticate / Disconnect a session through its NAS (RFC 5176); the Activity line is
    /// written by the RADIUS server.
    public func radiusCoA(_ action: CoAAction, session: DirectoryStore.RadiusSession) async -> CoAResult {
        guard let runtime else {
            return CoAResult(request: action.title, outcome: nil, problem: "the server is not running", attempts: 0)
        }
        return await runtime.radiusCoA(action, session: session)
    }

    public func registeredDevices() async -> [DirectoryStore.RegisteredDevice] {
        guard let store else { return [] }
        return (try? await store.registeredDevices()) ?? []
    }

    public func saveRegisteredDevice(_ device: DirectoryStore.RegisteredDevice) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.saveRegisteredDevice(device)
        serveLog.event("RADIUS", "registered device \(device.mac)\(device.group.map { " (\($0))" } ?? "") saved (app)")
    }

    public func deleteRegisteredDevice(mac: String) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.deleteRegisteredDevice(mac: mac)
        serveLog.event("RADIUS", "registered device \(mac) removed (app)")
    }

    /// Group Policy page: the draft, what is published, the GPO version, the trust and the other
    /// things the Default Domain Policy carries (trusted roots, password policy). nil when the
    /// server is not running.
    public func groupPolicySnapshot() async -> GroupPolicySnapshot? {
        guard let store, let editor = gpoEditor() else { return nil }
        do {
            let published = try await editor.publishedDot1XProfiles().set
            let draft = GroupPolicyDot1X.savedDraft(data) ?? published
            let state = try? await editor.state(.defaultDomainPolicy)
            var trust: GroupPolicyDot1X.Trust?
            if let pki { trust = try? await GroupPolicyDot1X.trust(store: store, pki: pki) }
            let roots = ((try? await editor.trustedRoots()) ?? []).map { root -> String in
                let cert = try? Certificate(derEncoded: root.der)
                return root.friendlyName ?? cert.flatMap { Self.commonName($0.subject) } ?? root.thumbprint
            }
            var certificates = ((try? await editor.trustedRoots()) ?? []).compactMap {
                try? Dot1XTrustCertificate(der: $0.der, friendlyName: $0.friendlyName)
            }
            // The LabDC CA is trusted by every member through AD (Certification Authorities), and
            // Publish adds it when another server's certificate was issued by it: list it so such
            // a profile still opens and saves, and it can be chosen directly.
            if let pki, let ca = try? await pki.currentAuthority(), let der = try? ca.der(),
               let c = try? Dot1XTrustCertificate(der: der),
               !certificates.contains(where: { $0.thumbprint == c.thumbprint }) {
                certificates.append(c)
            }
            return GroupPolicySnapshot(draft: draft, published: published,
                                       version: state.map { Int(GPOVersion.newest($0.containerVersion, $0.fileVersion).machine) } ?? 0,
                                       trust: trust, trustedRoots: roots, passwordPolicy: try? await store.passwordPolicy(),
                                       certificates: certificates)
        } catch {
            return nil
        }
    }

    /// Group Policy page: keeps the edited profiles (`<data>/group-policy-8021x.json`); nothing
    /// reaches Windows until `publishDot1X`.
    public func saveDot1XDraft(_ set: Dot1XProfileSet) throws {
        try set.validate()
        try GroupPolicyDot1X.saveDraft(set, data)
    }

    /// Group Policy ▸ Discard (owner, 2 Oct 2026): forgets the unpublished edits — the draft
    /// file goes, so the page shows what is published again (pending certificates included).
    public func discardDot1XDraft() throws {
        let url = GroupPolicyDot1X.draftURL(data)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do { try FileManager.default.removeItem(at: url) } catch {
            throw CLIError.failure("cannot remove \(url.path): \(error.localizedDescription)")
        }
        serveLog.event("GPO", "802.1X unpublished changes discarded (app)")
    }

    /// Group Policy ▸ Publish changes: the draft into the Default Domain Policy (one version bump).
    @discardableResult
    public func publishDot1X() async throws -> GroupPolicyDot1X.PublishReport {
        guard let store, let pki, let editor = gpoEditor() else { throw CLIError.failure("the server is not running") }
        let set = try await GroupPolicyDot1X.draft(data, editor: editor)
        let report = try await GroupPolicyDot1X.publish(set, store: store, pki: pki, editor: editor)
        var saved = report.set
        saved.pendingRoots = []  // trusted roots now
        if saved != set { try GroupPolicyDot1X.saveDraft(saved, data) }
        for e in report.events { serveLog.event("PKI", "\(e) (app)") }
        serveLog.event("GPO", "802.1X profiles published: \(report.summary) (app)")
        return report
    }

    /// Group Policy ▸ Remove all from Group Policy: the wireless and wired policy objects leave
    /// the Default Domain Policy (the version is bumped so PCs drop them). The list stays as a
    /// draft that can be published again.
    public func removeDot1XFromGroupPolicy() async throws {
        guard let editor = gpoEditor() else { throw CLIError.failure("the server is not running") }
        let published = try await editor.publishedDot1XProfiles().set
        if GroupPolicyDot1X.savedDraft(data) == nil { try GroupPolicyDot1X.saveDraft(published, data) }
        try await editor.remove80211Policies()
        serveLog.event("GPO", "802.1X profiles removed from the Default Domain Policy (app)")
    }

    /// RADIUS ▸ "Allow RSA-only devices" (default off).
    public func rsaOnlyDevicesAllowed() async -> Bool {
        guard let pki, let store else { return false }
        return await CAService(pki: pki, store: store).rsaCompatibilityEnabled()
    }

    /// RADIUS ▸ "Allow RSA-only devices": on creates the RSA compatibility root (RSA-3072,
    /// SHA-256) on first use with its RSA RADIUS certificate, enables the Computer-RSA / User-RSA
    /// templates (SCEP/EST) and puts the root into the Default Domain Policy's trusted roots and
    /// NTAuth; the RADIUS server then serves the RSA chain to clients that cannot use ECDSA and
    /// accepts client certificates from that root. Off reverses all of it (the root and its key
    /// stay). The 802.1X profiles keep pointing at the main root: Windows never needs RSA.
    public func setRSAOnlyDevicesAllowed(_ on: Bool) async throws {
        guard let pki, let store, let editor = gpoEditor() else { throw CLIError.failure("the server is not running") }
        let service = try await CAService.open(pki: pki, store: store)
        let created = try await service.setRSACompatibility(on)
        if created { serveLog.event("PKI", "RSA compatibility CA (RSA-3072) created (app)") }
        guard let ca = try? await pki.authority(named: LabPKI.rsaCompatCAName) else {
            serveLog.event("RADIUS", "RSA-only devices not allowed (app)")
            return
        }
        let der = try ca.der()
        if on {
            let dc = try await store.domainInfo().dcDNSName
            if try await pki.ensureRSAServerCertificate(hostname: dc) == .issued {
                serveLog.event("PKI", "RSA RADIUS certificate issued for \(dc) (app)")
            }
            let cn = Self.commonName(ca.certificate.subject)
            let change = try await editor.addTrustedRoot(CACertificateInfo(der: der, commonName: cn, subject: ca.certificate.subject.description),
                                                         friendlyName: cn)
            serveLog.event("GPO", "trusted root \(change.thumbprint) \(ca.certificate.subject) in Default Domain Policy (app)")
        } else {
            do {
                let change = try await editor.removeTrustedRoot(thumbprint: CertificateBlob.thumbprint(der))
                serveLog.event("GPO", "trusted root \(change.thumbprint) removed from Default Domain Policy (app)")
            } catch GroupPolicyError.unknownThumbprint {}
        }
        serveLog.event("RADIUS", "RSA-only devices \(on ? "allowed: RSA chain for clients without ECDSA, Computer-RSA / User-RSA templates on" : "not allowed") (app)")
    }

    /// The RSA compatibility root's certificate (DER) for old devices to install, nil before it exists.
    public func rsaCompatibilityRoot() async -> (der: [UInt8], thumbprint: String)? {
        guard let pki, let ca = try? await pki.authority(named: LabPKI.rsaCompatCAName), let der = try? ca.der() else { return nil }
        return (der, CertificateBlob.thumbprint(der))
    }

    /// The 802.1X 192-bit (P-384) root's SHA-1 thumbprint (WPA3-Enterprise 192-bit profiles).
    public func suiteBThumbprint() async -> String? {
        guard let pki, let ca = (try? await pki.suiteBAuthority()) ?? nil, let der = try? ca.der() else { return nil }
        return CertificateBlob.thumbprint(der)
    }

    /// Writes the policy order in one store transaction (RADIUS ▸ Policies ▸ Move up/down).
    public func reorderRadiusPolicies(_ ids: [UUID]) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        try await store.reorderRadiusPolicies(ids)
        await runtime?.radiusConfigChanged()
        serveLog.event("RADIUS", "policy order changed (app)")
    }

    /// The lab CA's SHA-1 thumbprint (the 802.1X client trusts it in EAP-TLS).
    public func caThumbprint() async -> String? {
        guard let pki, let ca = try? await pki.currentAuthority(), let der = try? ca.der() else { return nil }
        return CertificateBlob.thumbprint(der)
    }

    private func gpoEditor() -> GroupPolicyEditor? {
        guard let store else { return nil }
        return GroupPolicyEditor(root: data.sysvolURL, store: store)
    }

    /// The Test box: `Name = value` lines become a request context, the account's directory
    /// facts are merged in and the policies run — the same `RadiusServer.decide` a live request
    /// goes through. No password is checked and nothing is sent.
    public func testRadius(attributes text: String) async -> RadiusTestResult {
        guard let store else { return RadiusTestResult(ok: false, text: "The server is not running.") }
        let (parsed, unknown) = RequestContext.parse(text)
        let profiles = await runtime?.deviceProfiles ?? NoDeviceProfiles()
        return await Self.radiusTest(store: store, request: parsed, unknown: unknown, profiles: profiles)
    }

    /// Shared by the Test box and `labdc radius test`.
    public nonisolated static func radiusTest(store: DirectoryStore, request parsed: RequestContext, unknown: [String],
                                              profiles: DeviceProfileSource = NoDeviceProfiles()) async -> RadiusTestResult {
        var request = parsed
        let config = await RadiusConfig.load(store)
        var notes: [String] = []
        var facts: DirectoryFacts?
        let mab = request.authMethod == "mab"
        // Device facts by Calling-Station-Id (MAB: the MAC in User-Name); lines given stay.
        let mac = request.callingStationId.flatMap(RADIUSMAC.normalize)
            ?? (mab ? request.userName.flatMap(RADIUSMAC.normalize) : nil)
        if let mac { request.merge(await RadiusDeviceFacts.lookup(mac: mac, store: store, profiles: profiles)) }
        if mab {
            notes.append("MAB: no directory account is looked up; only rules that allow MAB are tried.")
        } else if let user = request.userName, !user.isEmpty {
            facts = try? await store.radiusFacts(name: user)
            if facts == nil {
                notes.append("No account named \(user): a live request is rejected before the policies run."
                             + (RADIUSMAC.normalize(user) != nil ? " For MAC Authentication Bypass add auth_method = mab." : ""))
            }
        } else {
            notes.append("No User-Name: only the RADIUS attributes are tested.")
        }
        let decision = RadiusServer.decide(request: &request, facts: facts, config: config)
        let none = mab ? "no MAB rule matched" : "no rule matched, default action"
        var lines = ["\(decision.accept ? "Accept" : "Reject") — \(decision.rule.map { "rule \($0)" } ?? none)"]
        lines += decision.attributes.map { "    " + RADIUSEvaluator.describe($0) }
        if let facts {
            lines.append("Facts: groups \(facts.groups.isEmpty ? "none" : facts.groups.joined(separator: ", "))"
                         + "; OU \(facts.ou ?? "none"); \(facts.isMachine ? "machine" : "user") account"
                         + (facts.accountFlags.isEmpty ? "" : "; \(facts.accountFlags.joined(separator: ", "))"))
        }
        lines.append("Device: \(request.deviceCategory ?? "unknown")"
                     + (request.deviceOS.map { ", \($0)" } ?? "")
                     + (request.dhcpVendorClass.map { ", vendor class \($0)" } ?? "")
                     + (request.dhcpHostname.map { ", hostname \($0)" } ?? "")
                     + (request.registeredDevice ? ", registered" + (request.deviceGroup.map { " (\($0))" } ?? "") : ""))
        lines.append("Request: \(request.timeOfDay) \(request.weekday)"
                     + (request.nasIP.map { ", NAS-IP-Address \($0)" } ?? "")
                     + (request.calledStationId.map { ", Called-Station-Id \($0)" } ?? ""))
        lines += notes
        if !unknown.isEmpty { lines.append("Not understood: " + unknown.joined(separator: "; ")) }
        return RadiusTestResult(ok: decision.accept, text: lines.joined(separator: "\n"))
    }

    /// Settings ▸ Directory ▸ NetBIOS name: renames the domain's NetBIOS name in the store and
    /// restarts, so CLDAP/Netlogon answer with the new one. Devices already joined keep the old
    /// name until they rejoin or their config is updated — the caller says so.
    public func setNetbiosDomain(_ name: String) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        guard let netbios = DomainSetup.validNetbios(name) else {
            throw CLIError.failure(DomainSetup.netbiosRule)
        }
        guard netbios != status.netbiosDomain else { return }
        try await store.setDomainValue(netbios, forKey: "netbios")
        serveLog.event("Store", "NetBIOS domain name changed to \(netbios) (app)")
        await restartToApply()
    }

    /// Services ▸ Test: asks LabDC's own DNS (on this Mac) for `name`, the way a PC that
    /// uses this Mac for DNS would, so the answer has gone through the forwarder.
    public func testDNSForwarding(name: String = "apple.com") async -> DNSForwardingTestResult {
        guard let port = status.listeners.first(where: { $0.listener == .dns })?.port, port > 0 else {
            return DNSForwardingTestResult(ok: false, text: "DNS is not running.")
        }
        let upstreams = (await runtime?.dnsForwardingPlan())?.summary ?? "the DNS servers"
        let probe = DNSForwarder(upstreams: [DNSUpstream(host: "127.0.0.1", port: UInt16(truncatingIfNeeded: port))],
                                 timeout: .seconds(8), cacheCapacity: 0)
        let started = ContinuousClock.now
        do {
            let qname = try DNSName(parsing: name)
            let reply = try await probe.resolve(.query(id: UInt16.random(in: 0...UInt16.max), name: qname, type: .a))
            let ms = Int((ContinuousClock.now - started) / .milliseconds(1))
            let addresses = reply.answers.compactMap { r -> String? in
                if case .a(let a) = r.rdata { return a.description }
                return nil
            }
            switch reply.rcode {
            case .noError where !addresses.isEmpty:
                return DNSForwardingTestResult(ok: true, text: "\(name) → \(addresses.prefix(2).joined(separator: ", ")) in \(ms) ms, through \(upstreams).")
            case .nxDomain:
                return DNSForwardingTestResult(ok: false, text: "\(upstreams) answered that \(name) does not exist. Those servers may only know internal names; add a public DNS server such as 8.8.8.8.")
            case .servFail, .refused:
                return DNSForwardingTestResult(ok: false, text: "No answer for \(name) from \(upstreams). Check that this Mac can reach them, or enter other servers in Settings ▸ System.")
            default:
                return DNSForwardingTestResult(ok: false, text: "\(name): \(reply.rcode), no address in the answer.")
            }
        } catch {
            return DNSForwardingTestResult(ok: false, text: "LabDC's DNS on port \(port) did not answer: \(error)")
        }
    }

    /// UI-1c, the interface picker (Setup wizard, Settings ▸ Directory): nil = automatic (the first
    /// address), else one of this Mac's IPv4 addresses. Saved as `advertise` in settings.json and
    /// applied live (`ServeRuntime.setAdvertise`: the listeners that hand out the address restart
    /// in place, with a log line); without a running server it is only saved.
    public func setAdvertisedAddress(_ ipv4: String?) async throws {
        status.interfaces = NetworkInterfaces.current()
        guard ipv4 != settings.advertise else { return }
        let previous = settings
        settings.advertise = ipv4
        try saveSettings()
        status.advertisePinned = ipv4 != nil
        let label = NetworkInterfaces.choice(for: ipv4 ?? ServeAddresses.current().first, in: status.interfaces)?.displayName
        if let rt = runtime {
            do {
                try await rt.setAdvertise(ipv4, label: label)
            } catch {
                settings = previous
                try? saveSettings()
                try? await rt.setAdvertise(previous.advertise)
                await refreshListeners()
                throw error
            }
            status.advertisedIPv4 = await rt.advertisedIPv4
            await refreshListeners()
        } else {
            status.advertisedIPv4 = ipv4 ?? ServeAddresses.current().first
            serveLog.event("serve", "devices will be told \(status.advertisedLabel ?? "127.0.0.1")"
                           + (ipv4 == nil ? " (automatic, first address)" : " (pinned)") + " when the services start")
        }
    }

    private func saveSettings() throws {
        try data.prepare()
        try settings.save(data.settingsURL)
        savedGeneration += 1
    }

    // MARK: Account and CA actions

    /// Settings ▸ General: the Administrator password (domain policy enforced by the store).
    public func changeAdministratorPassword(_ password: String) async throws {
        guard let store else { throw CLIError.failure("the server is not running") }
        guard let admin = try await store.read(sam: "Administrator") else { throw CLIError.failure("no Administrator account") }
        try await store.setPassword(id: admin.id, password: password)
        serveLog.event("Store", "Administrator password changed (app)")
        savedGeneration += 1
    }

    /// Overview ▸ "Publish CA": the current CA into the Default Domain Policy's trusted roots and
    /// the Configuration NC (what `labdc gpo trusted-root add-ca` does).
    public func publishCA(refresh: Bool = true) async throws {
        guard let store, let pki else { throw CLIError.failure("the server is not running") }
        let ca = try await pki.currentAuthority()
        let cn = Self.commonName(ca.certificate.subject)
        let der = try ca.der()
        let info = CACertificateInfo(der: der, commonName: cn, subject: ca.certificate.subject.description)
        let change = try await GroupPolicyEditor(root: data.sysvolURL, store: store).addTrustedRoot(info, friendlyName: cn)
        try await store.setDomainValue(CertificateBlob.thumbprint(der), forKey: Self.publishedCAKey)
        serveLog.event("GPO", "trusted root \(change.thumbprint) \(ca.certificate.subject) in Default Domain Policy"
                       + (change.edit.changed ? " (version \(change.edit.version.raw))" : " (already there)"))
        if refresh { await refreshSummary() }
    }

    /// The current CA certificate as PEM (`.pem`) or DER (`.cer`).
    public func caCertificate(der: Bool) async throws -> Data {
        let pki: LabPKI
        if let p = self.pki { pki = p } else { pki = try await LabPKI.open(directory: data.pkiURL) }
        let ca = try await pki.currentAuthority()
        return der ? Data(try ca.der()) : Data(try ca.pem().utf8)
    }

    /// Re-reads users/computers/trusted roots (after a mutation; also runs on directory log lines).
    public func refreshSummary() async {
        guard let store else { return }
        summary = await DirectorySummary.load(store: store, pki: pki, data: data)
    }

    /// The "Fill in on the device" values.
    public var deviceFields: DeviceFields {
        let ldaps = status.listeners.first { $0.listener == .ldaps }
        let http = status.listeners.first { $0.listener == .http }
        return DeviceFields.make(address: status.advertisedIPv4, dcDNSName: status.dcDNSName, baseDN: status.baseDN,
                                 ldapsPort: ldaps?.port ?? ldaps.map { Int($0.configuredPort) } ?? 636,
                                 httpPort: http?.port ?? http.map { Int($0.configuredPort) } ?? 80,
                                 caName: summary.caName)
    }

    // MARK: Backup

    /// The files of the data folder a backup carries besides the store, `pki/` and `sysvol/`:
    /// the settings and the Group Policy ▸ Wi-Fi / Wired list being edited (its unpublished draft).
    nonisolated static let backupFiles = ["settings.json", "group-policy-8021x.json"]

    /// Settings ▸ Backup ▸ Export: `<folder>/LabDC backup <date>/` (`… <date> 2/`, `3/`… when
    /// that folder exists already, e.g. two exports in the same second) with `store.json` (the
    /// store's JSON export: every table, key material included — see `StoreExportV2`), `pki/`,
    /// `sysvol/`, `settings.json` and the 802.1X draft `group-policy-8021x.json`.
    @discardableResult
    public func exportBackup(into folder: URL, now: Date = Date()) async throws -> URL {
        let fm = FileManager.default
        let stamp = now.formatted(Date.ISO8601FormatStyle().year().month().day().time(includingFractionalSeconds: false)
            .dateTimeSeparator(.space).timeSeparator(.omitted))
        let target = try Self.makeUniqueFolder(in: folder, named: "LabDC backup \(stamp)")
        let store: DirectoryStore
        if let s = self.store { store = s } else { store = try data.openExistingStore() }
        let json = try await store.exportJSON()
        try json.write(to: target.appendingPathComponent("store.json"), options: .atomic)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.appendingPathComponent("store.json").path)
        for sub in ["pki", "sysvol"] where fm.fileExists(atPath: data.url.appendingPathComponent(sub).path) {
            try fm.copyItem(at: data.url.appendingPathComponent(sub), to: target.appendingPathComponent(sub))
        }
        for name in Self.backupFiles where fm.fileExists(atPath: data.url.appendingPathComponent(name).path) {
            try fm.copyItem(at: data.url.appendingPathComponent(name), to: target.appendingPathComponent(name))
        }
        serveLog.event("serve", "backup exported to \(target.path)")
        return target
    }

    /// Creates `<folder>/<name>` (0700), or `<name> 2`, `<name> 3`… when it exists: never an
    /// existing folder (an export into it would fail half-way or mix two backups).
    nonisolated static func makeUniqueFolder(in folder: URL, named name: String) throws -> URL {
        let fm = FileManager.default
        try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        for n in 1...1000 {
            let candidate = folder.appendingPathComponent(n == 1 ? name : "\(name) \(n)", isDirectory: true)
            // mkdir fails when the name exists: the check and the create are one step.
            if mkdir(candidate.path, 0o700) == 0 { return candidate }
            guard errno == EEXIST else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: candidate.path,
                                                               NSLocalizedDescriptionKey: "cannot create \(candidate.path): \(String(cString: strerror(errno)))"])
            }
        }
        throw CocoaError(.fileWriteFileExists, userInfo: [NSFilePathErrorKey: folder.appendingPathComponent(name).path])
    }

    /// Settings ▸ Backup ▸ Import: stops the server, moves the current data folder aside
    /// (`<data> before import <date>`), builds a new one from the backup and starts again. The
    /// phase is `.restarting` throughout and the file work runs off the main actor; a failure
    /// puts the previous folder back and starts it again.
    public func importBackup(from backup: URL, now: Date = Date()) async throws {
        let json = try await Task.detached { try Data(contentsOf: backup.appendingPathComponent("store.json")) }.value
        let stamp = now.formatted(Date.ISO8601FormatStyle().year().month().day().time(includingFractionalSeconds: false)
            .dateTimeSeparator(.space).timeSeparator(.omitted))
        let data = self.data
        let aside = data.url.deletingLastPathComponent().appendingPathComponent("\(data.url.lastPathComponent) before import \(stamp)")
        try await withServicesStopped {
            do {
                try await Self.buildFromBackup(backup, json: json, data: data, aside: aside)
            } catch {
                serveLog.warning("serve", "backup import from \(backup.path) failed: \(error); previous data restored")
                throw error
            }
            settings = ServerSettings.load(data.settingsURL)
            status.advertisePinned = settings.advertise != nil
            sessionPins = [:]
            serveLog.event("serve", "backup imported from \(backup.path); previous data kept in \(aside.path)")
        }
    }

    /// The file side of `importBackup` (off the main actor): the current folder aside, a new one
    /// built from the backup; on failure the half-built folder goes and the old one comes back.
    nonisolated static func buildFromBackup(_ backup: URL, json: Data, data: DataDirectory, aside: URL) async throws {
        let fm = FileManager.default
        let hadFolder = fm.fileExists(atPath: data.url.path)
        if hadFolder { try fm.moveItem(at: data.url, to: aside) }
        do {
            try data.prepare()
            let store = try DirectoryStore(path: data.storeURL.path)
            try await store.importJSON(json)
            for sub in ["pki", "sysvol"] where fm.fileExists(atPath: backup.appendingPathComponent(sub).path) {
                try fm.copyItem(at: backup.appendingPathComponent(sub), to: data.url.appendingPathComponent(sub))
            }
            for name in backupFiles where fm.fileExists(atPath: backup.appendingPathComponent(name).path) {
                try fm.copyItem(at: backup.appendingPathComponent(name), to: data.url.appendingPathComponent(name))
            }
        } catch {
            // The half-built folder always goes, so a failed import into a fresh install is
            // "not set up" again rather than a broken domain.
            try? fm.removeItem(at: data.url)
            if hadFolder { try? fm.moveItem(at: aside, to: data.url) }
            throw error
        }
    }

    // MARK: Events

    private func handle(_ event: ServeRuntimeEvent) {
        switch event {
        case let .addressesChanged(advertised, addresses, pinned):
            status.addresses = addresses
            status.addressesReported = true
            status.advertisePinned = pinned
            status.advertisedIPv4 = advertised
            status.interfaces = NetworkInterfaces.current()
        case .dhcpChanged:
            Task { await dhcpChangedByRuntime() }
        case .listenersChanged(let failures):
            Task { await listenersChangedByRuntime(failures) }
        }
    }

    private func handle(_ line: LogLine) {
        if let e = ActivityEvent.parse(line) {
            recentActivity.insert(e, at: 0)
            if recentActivity.count > 20 { recentActivity.removeLast(recentActivity.count - 20) }
        }
        if Self.touchesDirectory(line) { scheduleSummaryRefresh() }
    }

    /// Lines after which the Overview counts may have changed (a computer joined, an object
    /// added over LDAP/SAMR, a GPO or PKI change).
    nonisolated static func touchesDirectory(_ line: LogLine) -> Bool {
        switch line.component {
        case "NETLOGON": line.text.hasPrefix("Authenticate") || line.text.hasPrefix("ServerPasswordSet")
        case "SAMR", "GPO", "Store": true
        case "PKI": line.text.contains("trusted root") || line.text.contains("directory objects")
        case "LDAP": !line.text.hasPrefix("bind ")
        default: false
        }
    }

    private func scheduleSummaryRefresh() {
        guard summaryTask == nil else { return }
        summaryTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1))
            await self?.refreshSummary()
            self?.summaryTask = nil
        }
    }

    /// The last (most specific) CN of a name.
    nonisolated static func commonName(_ name: DistinguishedName) -> String? {
        var cn: String?
        for rdn in name { for ava in rdn where ava.type == .RDNAttributeType.commonName { cn = String(describing: ava.value) } }
        return cn
    }
}

/// Overview ▸ "Fill in on the device".
public struct DeviceFields: Equatable, Sendable {
    /// The DC's address devices use (the advertised IPv4).
    public var dcAddress: String
    /// `ldaps://192.168.1.36:636`
    public var ldapURL: String
    /// `DC=lab,DC=sheep`
    public var baseDN: String
    /// `CN=Administrator,CN=Users,DC=lab,DC=sheep`
    public var lookupAccountDN: String
    /// `http://192.168.1.36/pki/lab.crt`
    public var caDownloadURL: String

    public static func make(address: String?, dcDNSName: String?, baseDN: String?, ldapsPort: Int, httpPort: Int,
                            caName: String?) -> DeviceFields {
        let host = address ?? dcDNSName ?? "127.0.0.1"
        let base = baseDN ?? ""
        let ca = CAService.caCertificatePath(caName: caName ?? LabPKI.labCAName)
        return DeviceFields(dcAddress: host,
                            ldapURL: "ldaps://\(host)" + (ldapsPort == 636 ? ":636" : ":\(ldapsPort)"),
                            baseDN: base,
                            lookupAccountDN: base.isEmpty ? "CN=Administrator,CN=Users" : "CN=Administrator,CN=Users,\(base)",
                            caDownloadURL: "http://\(host)\(httpPort == 80 ? "" : ":\(httpPort)")\(ca)")
    }
}

/// The Test box's outcome: which rule matched and what would be returned.
public struct RadiusTestResult: Sendable, Equatable {
    public var ok: Bool
    public var text: String

    public init(ok: Bool, text: String) { self.ok = ok; self.text = text }
}
