import AppKit
import LabDCCore
import SwiftUI

/// Entry point: `--smoke` renders every page into PNGs and exits; anything else is the app.
@main
enum Main {
    @MainActor static func main() {
        if CommandLine.arguments.contains("--smoke") {
            Smoke.main()
        } else {
            migrateFromSheepAuth()
            LabDCApp.main()
        }
    }

    /// First launch after the rename (1 Oct 2026): SheepAuth's folders and preferences become
    /// LabDC's before anything reads them. `--data` names its own folder, so nothing moves then.
    /// While SheepAuth still runs nothing moves: say so and quit rather than open an empty
    /// LabDC folder (whose Setup wizard would offer a second domain).
    @MainActor static func migrateFromSheepAuth() {
        guard LaunchOptions.parse(CommandLine.arguments).data == nil else { return }
        let report = LegacyMigration.run()
        if !report.isEmpty {
            let log = ServeLog(echo: false, file: ServeLogFile(directory: DataDirectory(AppProfile.legacyURL).logsURL))
            for line in report.lines { log.event("migration", line) }
        }
        guard let blocked = report.blocked else { return }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.activate()
        let alert = NSAlert()
        alert.messageText = "Quit SheepAuth first"
        alert.informativeText = "SheepAuth is now LabDC. \(blocked)"
        alert.addButton(withTitle: "Quit LabDC")
        alert.runModal()
        exit(0)
    }
}

struct LabDCApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model: AppModel

    init() {
        let model = AppModel(launch: LaunchOptions.parse(CommandLine.arguments))
        _model = State(initialValue: model)
        AppDelegate.model = model
    }

    var body: some Scene {
        Window("LabDC", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 1260, minHeight: 600)
        }
        .defaultSize(width: 1300, height: 720)
        // Owner, 28 Sep 2026: no title bar ("Overview" covered the page); the window buttons sit
        // over the sidebar and every page starts at the top.
        .windowStyle(.hiddenTitleBar)
        // The window never gets narrower than the pages (1260 × 600: the Directory tables keep
        // every column at the minimum); a saved smaller frame grows.
        .windowResizability(.contentMinSize)
        .commands { AppCommands(model: model) }

        Settings {
            SettingsView()
                .environment(model)
        }
    }
}

/// Keeps the server running when the window closes and stops it cleanly on Quit.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    static var model: AppModel?
    private var stopping = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// UI-3: certificate/key files dropped on the Dock icon (or opened with LabDC) go to the
    /// Certificate Converter window.
    func application(_ application: NSApplication, open urls: [URL]) {
        ConverterWindowController.shared.show(files: urls.filter(\.isFileURL))
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !stopping, let model = Self.model, model.controller.isRunning else { return .terminateNow }
        stopping = true
        Task { @MainActor in
            await model.controller.stop()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

/// Menu bar: Domain ▸ Open Data Folder, Export CA…; Help ▸ Join Guides.
struct AppCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandMenu("Domain") {
            Button("Open Data Folder") { model.openDataFolder() }
                .keyboardShortcut("o", modifiers: [.command, .shift])
            Button("Open Log Folder") { model.openLogFolder() }
            Divider()
            Button("Export CA…") { model.exportCA() }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(!model.controller.isSetUp)
            Divider()
            // UI-1b: a maintenance action, not an on/off switch (⌘R on Overview does the same).
            Button("Restart All Services") {
                Task { await model.controller.restartAllServices() }
            }
            .disabled(!model.controller.isSetUp || model.controller.status.isBusy)
        }
        // UI-3: Window ▸ Certificate Converter.
        CommandGroup(before: .windowArrangement) {
            Button("Certificate Converter") { ConverterWindowController.shared.show() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
            Divider()
        }
        CommandGroup(replacing: .help) {
            Button("Join Guides") {
                openWindow(id: "main")
                model.selection = .connect
            }
            Button("Activity Log") {
                openWindow(id: "main")
                model.selection = .activity
                model.authentications.tab = .log
            }
        }
    }
}

/// Setup wizard until the domain exists, then the main window.
struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            switch model.screen {
            case .loading:
                ProgressView("Opening…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .setup:
                SetupWizardView()
            case .main:
                MainView()
            }
        }
        .task { await model.bootstrap() }
    }
}
