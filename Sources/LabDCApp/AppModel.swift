import AppKit
import Observation
import LabDCCore
import SwiftUI
import UniformTypeIdentifiers

/// Command-line options of the app (for tests, the smoke run and a second lab on other ports):
/// `--data <dir>`, `--ports dns=5353,…` (same syntax as `labdc serve`), `--ephemeral-ports`,
/// `--echo` (log to stdout), `--smoke [<png folder>]`.
struct LaunchOptions: Equatable {
    /// nil = the active profile's folder (AppProfile); `--data` overrides profiles entirely.
    var data: URL?
    var ports: PortSet?
    var echo = false
    var smokeOutput: URL?

    static func parse(_ arguments: [String]) -> LaunchOptions {
        var o = LaunchOptions()
        var i = 1
        let args = arguments
        func next() -> String? {
            guard i + 1 < args.count, !args[i + 1].hasPrefix("-") else { return nil }
            i += 1
            return args[i]
        }
        while i < args.count {
            switch args[i] {
            case "--data":
                if let v = next() { o.data = URL(fileURLWithPath: (v as NSString).expandingTildeInPath, isDirectory: true).standardizedFileURL }
            case "--ports":
                if let v = next() {
                    var p = o.ports ?? .standard
                    if (try? p.apply(v)) != nil { o.ports = p }
                }
            case "--ephemeral-ports":
                o.ports = .ephemeral
            case "--echo":
                o.echo = true
            case "--smoke":
                o.smokeOutput = next().map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath, isDirectory: true) }
                    ?? URL(fileURLWithPath: "docs/design/screens", isDirectory: true)
            default:
                break  // -NSDocumentRevisionsDebugMode and friends from Xcode/Finder
            }
            i += 1
        }
        return o
    }
}

/// `~/Library/Application Support/LabDC` (the CLI's default too).
enum CLIDefaults {
    static var dataDirectory: URL { AppProfile.legacyURL }
}

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case overview, services, users, radius, certificates, activity, connect

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .services: "Services"
        case .users: "Directory"
        case .radius: "RADIUS"
        case .certificates: "Certificates"
        case .activity: "Activity"
        case .connect: "Connect"
        }
    }
}

/// The app's state: which screen, which page, the embedded server and the log view's model.
@MainActor @Observable
final class AppModel {
    enum Screen: Equatable { case loading, setup, main }

    var screen: Screen = .loading
    var selection: SidebarItem? = .overview
    /// Settings ▸ General ▸ "Try": a greeting picture to play once on the Overview.
    var greetingPreview: GreetingPreviewRequest?
    private(set) var controller: ServerController
    /// Goes up every time `controller` is replaced (a profile switch, rename or wizard Cancel),
    /// so views can reload what they read from the previous one. Never reused, unlike an
    /// ObjectIdentifier of a freed controller.
    private(set) var controllerGeneration = 0
    let launch: LaunchOptions
    let logModel = LogViewModel()
    /// UI-2: the Users page (kept across page switches).
    let usersModel = UsersModel()
    /// UI-3: the Certificates page (kept across page switches).
    let certificates = CertificatesModel()
    /// UI-5: Activity ▸ Authentications (+ its tab and the Test login sheet).
    let authentications = AuthenticationsViewModel()
    /// Shown as an alert (Export CA failures and the like).
    var alert: String?
    /// The profile the Setup wizard's Cancel returns to: the one active before the wizard opened.
    /// nil = the most recent provisioned profile, or quit (owner review, 30 Sep 2026).
    private(set) var wizardReturnProfile: String?
    /// After Start over: the backup holding the active profile's old data, which the wizard's
    /// Cancel puts back so the profile is exactly as it was (owner, 30 Sep 2026).
    private(set) var startOverBackup: String?
    /// `--data` names one folder: profiles do not apply, Settings says so instead of listing them.
    var profilesApply: Bool { launch.data == nil }
    @ObservationIgnored private var bootstrapped = false

    init(launch: LaunchOptions) {
        self.launch = launch
        let data = launch.data ?? AppProfile.activeURL()
        controller = ServerController(dataDirectory: data, portOverride: launch.ports, echo: launch.echo)
        logModel.attach(controller.logs)
        authentications.attach(controller)
    }

    /// First launch → start the active profile; when it has no domain, the wizard opens for it
    /// (never a silent jump to another profile) and Cancel returns to the profile used before.
    func bootstrap() async {
        guard !bootstrapped else { return }
        bootstrapped = true
        if await controller.data.isProvisioned() {
            screen = .main
            await controller.start()
            return
        }
        wizardReturnProfile = profilesApply ? AppProfile.previousName : nil
        screen = .setup
    }

    /// Settings ▸ Profiles: stops everything, points the app at another profile's folder and
    /// starts it (or the Setup wizard when that profile has no domain yet, whose Cancel comes back
    /// to the profile active now).
    func switchToProfile(_ name: String) async {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let previous = AppProfile.activeName
        screen = .loading
        await controller.retire()
        await open(clean, returnTo: previous == clean ? wizardReturnProfile : previous)
    }

    /// Settings ▸ Profiles ▸ Rename: the active profile's services stop before its folder moves,
    /// then start again under the new name (owner review, 30 Sep 2026).
    func renameProfile(_ name: String, to newName: String) async throws {
        guard name == AppProfile.activeName, profilesApply else {
            try AppProfile.rename(from: name, to: newName)
            return
        }
        // A name that cannot be used is refused before anything stops.
        guard name != AppProfile.legacyName else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey:
                "The Default profile keeps its original folder (it predates profiles)."])
        }
        // Listing and moving profile folders is file work: off the main actor.
        let existing = await Task.detached { AppProfile.all().map(\.name) }.value
        _ = try AppProfile.validatedNewName(newName, existing: existing.filter { $0 != name })
        screen = .loading
        await controller.retire()
        do {
            let clean = try await Task.detached { try AppProfile.rename(from: name, to: newName) }.value
            await open(clean, returnTo: wizardReturnProfile)
        } catch {
            await open(name, returnTo: wizardReturnProfile)
            throw error
        }
    }

    /// Settings ▸ Start over: the old domain now lives in `backup`; the wizard's Cancel restores it.
    func beginSetupAfterStartOver(backup: String) {
        startOverBackup = backup
        screen = .setup
    }

    /// Points the app at `name` (already stopped) and starts it, or opens the wizard.
    private func open(_ name: String, returnTo previous: String?) async {
        startOverBackup = nil
        if profilesApply { AppProfile.setActive(name) }
        let data = launch.data ?? (AppProfile.named(name)?.url ?? AppProfile.url(for: name))
        // The old controller must never start again (a restart or rename it still has pending).
        await controller.retire()
        controller = ServerController(dataDirectory: data, portOverride: launch.ports, echo: launch.echo)
        controllerGeneration += 1
        logModel.attach(controller.logs)
        authentications.attach(controller)
        selection = .overview
        if await controller.data.isProvisioned() {
            wizardReturnProfile = nil
            screen = .main
            await controller.start()
        } else {
            wizardReturnProfile = previous
            screen = .setup
        }
    }

    /// Wizard ▸ Cancel: return to the profile that was active before the wizard (or the most
    /// recent provisioned one), or quit the app when there is nothing to go back to (a first
    /// launch with no domain anywhere, or `--data` on an empty folder).
    func cancelWizard() async {
        if let backup = startOverBackup {
            screen = .loading
            await controller.retire()
            do {
                try AppProfile.restoreStartOver(dataURL: controller.data.url, backup: backup)
            } catch {
                alert = "The previous domain could not be put back: \(error.localizedDescription)"
            }
            await open(profilesApply ? AppProfile.activeName : "", returnTo: wizardReturnProfile)
            return
        }
        guard profilesApply else {
            NSApp.terminate(nil)
            return
        }
        let active = AppProfile.activeName
        let candidates = AppProfile.all().filter { $0.provisioned && $0.name != active }
        let target = candidates.first { $0.name == wizardReturnProfile }
            ?? candidates.first { $0.name == AppProfile.legacyName } ?? candidates.first
        if let target {
            await switchToProfile(target.name)
        } else {
            NSApp.terminate(nil)
        }
    }

    /// The profiles for the Settings list, active first.
    var profiles: [AppProfile] {
        let all = AppProfile.all()
        let active = AppProfile.activeName
        return all.sorted { ($0.name == active ? 0 : 1, $0.name) < ($1.name == active ? 0 : 1, $1.name) }
    }

    /// Wizard ▸ Create: provisions like `serve --provision`, starts, opens Overview. Returns the
    /// error when the domain could not be created (the wizard stays open then).
    /// - Parameter advertise: the wizard's interface choice (nil = automatic, the first address).
    func finishSetup(_ setup: DomainSetup, password: String, advertise: String? = nil) async -> String? {
        do { try await controller.setAdvertisedAddress(advertise) } catch {
            return "The address could not be saved: \(error)"
        }
        await controller.start(provision: setup.provisionSpec(adminPassword: password))
        guard await controller.data.isProvisioned() else {
            return controller.status.lastError ?? "The domain could not be created."
        }
        startOverBackup = nil
        selection = .overview
        screen = .main
        return nil
    }

    /// UI-1c: the Overview dashboard's numbers (directory summary + today's sign-ins).
    var dashboardStats: DashboardStats {
        DashboardStats.make(summary: controller.summary, events: authentications.feed.events)
    }

    // MARK: Files

    func openDataFolder() {
        try? controller.data.prepare()
        NSWorkspace.shared.open(controller.data.url)
    }

    func openLogFolder() {
        try? FileManager.default.createDirectory(at: controller.data.logsURL, withIntermediateDirectories: true)
        NSWorkspace.shared.open(controller.data.logsURL)
    }

    /// Domain ▸ Export CA… / Overview ▸ Save CA…: `.pem` or `.cer` (DER) by the chosen extension.
    func exportCA() {
        let panel = NSSavePanel()
        panel.title = "Export CA certificate"
        panel.nameFieldStringValue = "\(controller.status.netbiosDomain ?? "LabDC") CA.pem"
        panel.allowedContentTypes = [UTType(filenameExtension: "pem") ?? .data, UTType(filenameExtension: "cer") ?? .data]
        panel.allowsOtherFileTypes = true
        panel.message = "Save as .pem for most devices, .cer for Windows."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do {
                let data = try await controller.caCertificate(der: url.pathExtension.lowercased() == "cer" || url.pathExtension.lowercased() == "der")
                try data.write(to: url, options: .atomic)
            } catch {
                alert = "The CA certificate could not be saved: \(error)"
            }
        }
    }
}
