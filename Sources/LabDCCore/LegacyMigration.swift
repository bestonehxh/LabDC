import CoreFoundation
import Darwin
import Foundation
import os

/// SheepAuth → LabDC (owner, 1 Oct 2026). The first LabDC launch (app or `labdc` CLI) moves the
/// SheepAuth data where LabDC looks for it, once, and copies the old app's preferences:
///
/// - `Application Support/SheepAuth` → `Application Support/LabDC` (the Default profile, the
///   CLI's `--data` default);
/// - `Application Support/SheepAuth Profiles` → `LabDC Profiles`;
/// - every `SheepAuth-backup-<stamp>` folder (Start over's backups, beside Default and inside the
///   profiles folder) → `LabDC-backup-<stamp>`;
/// - the `dev.sheep.auth` preferences (active profile, greeting picture, window frames, …) into
///   `dev.labdc.app`, key prefix `dev.sheep.auth.` → `dev.labdc.app.`, an active/previous
///   profile that named a renamed backup folder following it.
///
/// Never overwrites: a step whose target already exists is skipped (both folders stay, the log
/// says so). While SheepAuth still runs (its process holds the ports and the store) nothing moves
/// and the caller shows `Report.blocked`. Nothing on the wire changes — the data is moved, not
/// rewritten: domain, realm, CA keys, SPNs, GPO GUIDs and RADIUS secrets are the same files.
public enum LegacyMigration {
    public static let oldBundleID = "dev.sheep.auth"
    public static let newBundleID = "dev.labdc.app"
    static let oldFolder = "SheepAuth", newFolder = "LabDC"
    static let oldProfiles = "SheepAuth Profiles", newProfiles = "LabDC Profiles"
    public static let oldBackupPrefix = "SheepAuth-backup-", newBackupPrefix = "LabDC-backup-"
    /// Set in the new domain once the old preferences were copied (or there were none).
    static let defaultsDoneKey = "dev.labdc.app.migratedFromSheepAuth"
    /// Executable names of the old app and CLI (`SheepAuthApp` is an unbundled `swift run`).
    static let oldProcessNames: Set<String> = ["SheepAuth", "SheepAuthApp", "sheepauth"]

    private static let logger = Logger(subsystem: newBundleID, category: "migration")

    public struct Report: Sendable, Equatable {
        /// "old → new", one per folder moved.
        public var moved: [String] = []
        /// Steps skipped because the LabDC folder already exists (both stay).
        public var kept: [String] = []
        /// Moves that failed (the old folder stays where it was).
        public var failed: [String] = []
        /// Preference keys copied into the LabDC domain.
        public var defaultsCopied: [String] = []
        /// Set when SheepAuth still runs: nothing was moved or copied.
        public var blocked: String?

        public var isEmpty: Bool {
            moved.isEmpty && kept.isEmpty && failed.isEmpty && defaultsCopied.isEmpty && blocked == nil
        }

        /// One line per fact, for the log.
        public var lines: [String] {
            var out = moved.map { "moved \($0)" }
            out += kept.map { "kept both (the LabDC one exists): \($0)" }
            out += failed.map { "could not move \($0)" }
            if !defaultsCopied.isEmpty {
                out.append("copied \(defaultsCopied.count) SheepAuth preference(s): \(defaultsCopied.sorted().joined(separator: ", "))")
            }
            if let blocked { out.append(blocked) }
            return out
        }
    }

    // MARK: - Entry point

    /// Everything, for the app and the CLI: folders, then (unless blocked) the preferences.
    /// - Parameters:
    ///   - home: the home folder (tests pass a temporary one).
    ///   - defaults: the LabDC preferences (`.standard` in the app, the `dev.labdc.app` suite in the CLI).
    ///   - oldDefaults: the SheepAuth preferences (`dev.sheep.auth`); nil reads them with CFPreferences.
    ///   - runningOldApp: why moving is unsafe now (SheepAuth runs), nil when it is safe.
    public static func run(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                           defaults: UserDefaults? = nil,
                           oldDefaults: [String: Any]? = nil,
                           runningOldApp: () -> String? = LegacyMigration.runningOldApp) -> Report {
        var report = migrateFolders(home: home, runningOldApp: runningOldApp)
        if report.blocked == nil, let target = defaults ?? newDomainDefaults() {
            report.defaultsCopied = copyDefaults(from: oldDefaults ?? readOldDefaults(), to: target, home: home)
        }
        for line in report.lines { logger.notice("\(line, privacy: .public)") }
        return report
    }

    /// The LabDC preferences as seen from this process: `.standard` inside LabDC.app, the
    /// `dev.labdc.app` suite elsewhere (the CLI, an unbundled `swift run`).
    public static func newDomainDefaults() -> UserDefaults? {
        Bundle.main.bundleIdentifier == newBundleID ? .standard : UserDefaults(suiteName: newBundleID)
    }

    // MARK: - Folders

    static func support(_ home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support", isDirectory: true)
    }

    /// Moves the SheepAuth folders to their LabDC names (see the type's comment).
    public static func migrateFolders(home: URL, runningOldApp: () -> String?) -> Report {
        let fm = FileManager.default
        let support = support(home)
        let steps: [(URL, URL)] = [
            (support.appendingPathComponent(oldFolder, isDirectory: true), support.appendingPathComponent(newFolder, isDirectory: true)),
            (support.appendingPathComponent(oldProfiles, isDirectory: true), support.appendingPathComponent(newProfiles, isDirectory: true)),
        ]
        var report = Report()
        let pendingTop = steps.filter { fm.fileExists(atPath: $0.0.path) }
        let backupParents = [support, support.appendingPathComponent(newProfiles, isDirectory: true),
                             support.appendingPathComponent(oldProfiles, isDirectory: true)]
        guard !pendingTop.isEmpty || backupParents.contains(where: { !oldBackups(in: $0).isEmpty }) else { return report }
        if let why = runningOldApp() {
            report.blocked = "SheepAuth is still running (\(why)); nothing was moved. Quit SheepAuth, then open LabDC again: "
                + "its data in ~/Library/Application Support/SheepAuth moves to LabDC on that launch."
            return report
        }
        for (old, new) in pendingTop { move(old, to: new, report: &report) }
        // Backups beside Default and inside the profiles folder (wherever it is now).
        for parent in [support, support.appendingPathComponent(newProfiles, isDirectory: true),
                       support.appendingPathComponent(oldProfiles, isDirectory: true)] {
            for backup in oldBackups(in: parent) {
                let suffix = String(backup.lastPathComponent.dropFirst(oldBackupPrefix.count))
                move(backup, to: parent.appendingPathComponent(newBackupPrefix + suffix, isDirectory: true), report: &report)
            }
        }
        return report
    }

    static func oldBackups(in parent: URL) -> [URL] {
        let children = (try? FileManager.default.contentsOfDirectory(at: parent, includingPropertiesForKeys: [.isDirectoryKey])) ?? []
        return children
            .filter { $0.lastPathComponent.hasPrefix(oldBackupPrefix) }
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private static func move(_ old: URL, to new: URL, report: inout Report) {
        let what = "\(display(old)) → \(display(new))"
        guard !FileManager.default.fileExists(atPath: new.path) else {
            report.kept.append(what)
            return
        }
        do {
            try FileManager.default.moveItem(at: old, to: new)
            report.moved.append(what)
        } catch {
            report.failed.append("\(what): \(error.localizedDescription)")
        }
    }

    /// The path from `Application Support/` on (the log never needs the home folder).
    private static func display(_ url: URL) -> String {
        let parts = url.pathComponents
        if let i = parts.lastIndex(of: "Application Support") { return parts[i...].joined(separator: "/") }
        return url.path
    }

    // MARK: - Preferences

    /// The SheepAuth app's own preferences (only its domain, not the global ones).
    public static func readOldDefaults() -> [String: Any] {
        let keys = CFPreferencesCopyKeyList(oldBundleID as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        guard let keys, let values = CFPreferencesCopyMultiple(keys, oldBundleID as CFString,
                                                               kCFPreferencesCurrentUser, kCFPreferencesAnyHost) as? [String: Any]
        else { return [:] }
        return values
    }

    /// Copies `old` into `defaults` once: keys renamed (`dev.sheep.auth.` → `dev.labdc.app.`), a
    /// key LabDC already has left alone, the active/previous profile mapped to its renamed backup
    /// folder. Returns the LabDC keys written.
    public static func copyDefaults(from old: [String: Any], to defaults: UserDefaults, home: URL) -> [String] {
        guard !defaults.bool(forKey: defaultsDoneKey) else { return [] }
        var written: [String] = []
        let profileKeys: Set<String> = ["\(newBundleID).activeProfile", "\(newBundleID).previousProfile"]
        for (key, value) in old {
            let newKey = key.hasPrefix(oldBundleID + ".") ? newBundleID + key.dropFirst(oldBundleID.count) : key
            guard defaults.object(forKey: newKey) == nil else { continue }
            var value = value
            if profileKeys.contains(newKey), let name = value as? String {
                value = mappedProfileName(name, home: home)
            }
            defaults.set(value, forKey: newKey)
            written.append(newKey)
        }
        defaults.set(true, forKey: defaultsDoneKey)
        return written
    }

    /// A profile name that was a `SheepAuth-backup-…` folder, as renamed (when the LabDC-named
    /// folder exists beside Default or among the profiles); any other name as it is.
    public static func mappedProfileName(_ name: String, home: URL) -> String {
        guard name.hasPrefix(oldBackupPrefix) else { return name }
        let renamed = newBackupPrefix + name.dropFirst(oldBackupPrefix.count)
        let support = support(home)
        let exists = [support, support.appendingPathComponent(newProfiles, isDirectory: true)].contains {
            FileManager.default.fileExists(atPath: $0.appendingPathComponent(renamed).path)
        }
        return exists ? renamed : name
    }

    // MARK: - Is SheepAuth still running?

    /// "SheepAuth (pid 123)" when the old app or `sheepauth` CLI runs as this user, else nil.
    public static func runningOldApp() -> String? {
        let me = getpid()
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return nil }
        var pids = [pid_t](repeating: 0, count: Int(count) + 32)
        let filled = pids.withUnsafeMutableBufferPointer {
            proc_listallpids($0.baseAddress, Int32($0.count * MemoryLayout<pid_t>.size))
        }
        guard filled > 0 else { return nil }
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        for pid in pids.prefix(Int(filled)) where pid > 0 && pid != me {
            let n = proc_pidpath(pid, &path, UInt32(path.count))
            guard n > 0 else { continue }
            let bytes = path.prefix(Int(n)).map { UInt8(bitPattern: $0) }
            let name = URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self)).lastPathComponent
            if oldProcessNames.contains(name) { return "\(name) pid \(pid)" }
        }
        return nil
    }
}
