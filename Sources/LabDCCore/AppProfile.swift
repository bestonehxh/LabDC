import Foundation

/// Named data folders ("profiles"): every profile is one domain with its own store, CA, SYSVOL
/// and settings. The pre-profiles location (`~/Library/Application Support/LabDC`) stays the
/// "Default" profile so existing installs keep working; the others live beside it under
/// `LabDC Profiles/<name>`. `--data` overrides everything (the CLI's explicit folder).
public struct AppProfile: Sendable, Equatable, Identifiable {
    public static let legacyName = "Default"
    static let defaultsKey = "dev.labdc.app.activeProfile"
    static let previousKey = "dev.labdc.app.previousProfile"
    /// The pre-profiles location (`~/Library/Application Support/LabDC`).
    public static let legacyURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/LabDC", isDirectory: true)

    public var name: String
    public var url: URL
    public var provisioned: Bool

    public var id: String { name }
    public var isLegacy: Bool { name == Self.legacyName }

    /// Beside the Default folder, not inside it, so Start over on Default never moves the others.
    /// Profiles made while the app was called "Pasture" move here once (1 Oct 2026).
    static var root: URL {
        let support = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support", isDirectory: true)
        let url = support.appendingPathComponent("LabDC Profiles", isDirectory: true)
        let old = support.appendingPathComponent("Pasture/Profiles", isDirectory: true)
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path), fm.fileExists(atPath: old.path) {
            try? fm.moveItem(at: old, to: url)
        }
        return url
    }

    /// The folder of the active profile — the same as the CLI default for "Default". Resolved
    /// like `AppModel.open` does (through `named`), so a Start-over backup that Settings switched
    /// to (`Application Support/LabDC-backup-…`) is still found after a relaunch.
    public static func activeURL() -> URL {
        guard let name = UserDefaults.standard.string(forKey: defaultsKey), name != legacyName else {
            return legacyURL
        }
        return resolvedURL(for: name, among: all())
    }

    /// `name`'s folder among `profiles` (a backup folder included), else where a named profile lives.
    static func resolvedURL(for name: String, among profiles: [AppProfile]) -> URL {
        profiles.first { $0.name == name }?.url ?? url(for: name)
    }

    /// The actual profile entry by name (Default, a LabDC Profiles/ folder, or a backup folder).
    public static func named(_ name: String) -> AppProfile? {
        all().first { $0.name == name }
    }

    public static func url(for name: String) -> URL {
        name == legacyName ? legacyURL : root.appendingPathComponent(name, isDirectory: true)
    }

    /// Makes `name` active and remembers the one it replaces (`previousName`).
    public static func setActive(_ name: String) {
        let current = activeName
        if current != name { UserDefaults.standard.set(current, forKey: previousKey) }
        UserDefaults.standard.set(name, forKey: defaultsKey)
    }

    /// The profile that was active before the current one (the wizard's Cancel returns to it).
    public static var previousName: String? {
        UserDefaults.standard.string(forKey: previousKey)
    }

    public static var activeName: String {
        UserDefaults.standard.string(forKey: defaultsKey) ?? legacyName
    }

    /// Every profile: the legacy folder first, the named profiles under `LabDC Profiles/`, then the
    /// `LabDC-backup-…` folders that "Start over" created (newest first) — a backup holds a
    /// whole domain, so Cancel after a start-over finds its way back to it.
    public static func all() -> [AppProfile] {
        let fm = FileManager.default
        var out = [AppProfile(name: legacyName, url: legacyURL,
                              provisioned: fm.fileExists(
                                  atPath: legacyURL.appendingPathComponent("lab.sqlite").path))]
        if let children = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey]) {
            for url in children where (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true {
                let provisioned = fm.fileExists(atPath: url.appendingPathComponent("lab.sqlite").path)
                out.append(AppProfile(name: url.lastPathComponent, url: url, provisioned: provisioned))
            }
        }
        let support = legacyURL.deletingLastPathComponent()
        if let siblings = try? fm.contentsOfDirectory(at: support, includingPropertiesForKeys: [.isDirectoryKey]) {
            let backups = siblings
                .filter { $0.lastPathComponent.hasPrefix("LabDC-backup-") }
                .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true }
                .sorted { $0.lastPathComponent > $1.lastPathComponent }
            for url in backups {
                let provisioned = fm.fileExists(atPath: url.appendingPathComponent("lab.sqlite").path)
                out.append(AppProfile(name: url.lastPathComponent, url: url, provisioned: provisioned))
            }
        }
        return out
    }

    /// A profile name as typed, trimmed; throws when it cannot be a folder name under `LabDC Profiles/`:
    /// empty, "." or "..", a leading dot (hidden), "/" or ":" (path separators), or "Default"
    /// (owner review, 30 Sep 2026).
    public static func validatedName(_ name: String) throws -> String {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        func refuse(_ why: String) -> CocoaError {
            CocoaError(.fileWriteInvalidFileName, userInfo: [NSLocalizedDescriptionKey: why])
        }
        if clean.isEmpty { throw refuse("Type a name for the profile.") }
        if clean.hasPrefix(".") { throw refuse("A profile name cannot start with a dot.") }
        if clean.contains("/") || clean.contains(":") { throw refuse("A profile name cannot contain / or :.") }
        if clean.caseInsensitiveCompare(legacyName) == .orderedSame { throw refuse("\(legacyName) is the original profile's name.") }
        return clean
    }

    /// `validatedName`, and not the name of a profile that already exists (case-insensitively,
    /// as the Mac's file system compares folder names).
    public static func validatedNewName(_ name: String, existing: [String]) throws -> String {
        let clean = try validatedName(name)
        if existing.contains(where: { $0.caseInsensitiveCompare(clean) == .orderedSame }) {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey:
                "A profile named \(clean) already exists."])
        }
        return clean
    }

    /// Creates an empty profile folder (the app then switches to it, which remembers the profile
    /// it leaves). A name already in use is an error, never a silent switch to that profile.
    public static func create(name: String) throws -> AppProfile {
        let clean = try validatedNewName(name, existing: all().map(\.name))
        let target = url(for: clean)
        if FileManager.default.fileExists(atPath: target.path) {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey:
                "A profile named \(clean) already exists."])
        }
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        return AppProfile(name: clean, url: target, provisioned: false)
    }
}

extension AppProfile {
    /// Renames a profile's folder (never the legacy Default — that path predates profiles).
    /// When the renamed profile is the active one, the caller must stop its services first and
    /// restart them under the new name. Returns the trimmed new name.
    @discardableResult
    public static func rename(from name: String, to newName: String) throws -> String {
        let clean = try validatedNewName(newName, existing: all().map(\.name).filter { $0 != name })
        guard name != legacyName else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey:
                "The Default profile keeps its original folder (it predates profiles)."])
        }
        guard let source = named(name) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey:
                "No profile named \(name)."])
        }
        let target = root.appendingPathComponent(clean, isDirectory: true)
        if FileManager.default.fileExists(atPath: target.path) {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey:
                "A profile named \(clean) already exists."])
        }
        try FileManager.default.moveItem(at: source.url, to: target)
        // The same profile under a new name: not a switch, so `previousName` stays (renamed too).
        if activeName == name { UserDefaults.standard.set(clean, forKey: defaultsKey) }
        if previousName == name { UserDefaults.standard.set(clean, forKey: previousKey) }
        return clean
    }

    /// True when the folder holds nothing but empty folders (and Finder's `.DS_Store`).
    public static func isEffectivelyEmpty(_ url: URL) -> Bool {
        let fm = FileManager.default
        guard let children = try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isDirectoryKey]) else {
            return false
        }
        return children.allSatisfy { child in
            if child.lastPathComponent == ".DS_Store" { return true }
            guard (try? child.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else { return false }
            return isEffectivelyEmpty(child)
        }
    }

    /// What a profile folder holds, in words for the delete alert ("a directory database",
    /// "certificates", "logs", …); empty when `isEffectivelyEmpty`.
    public static func contents(of url: URL) -> [String] {
        let fm = FileManager.default
        func has(_ path: String) -> Bool {
            let child = url.appendingPathComponent(path)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: child.path, isDirectory: &isDir) else { return false }
            return !isDir.boolValue || !isEffectivelyEmpty(child)
        }
        let known: [(String, String)] = [("lab.sqlite", "a directory database"), ("pki", "certificates"),
                                         ("sysvol", "SYSVOL policies"), ("settings.json", "settings"), ("logs", "logs")]
        var out = known.filter { has($0.0) }.map(\.1)
        let names = Set(known.map(\.0) + [".DS_Store", "lab.sqlite-wal", "lab.sqlite-shm"])
        let others = ((try? fm.contentsOfDirectory(atPath: url.path)) ?? []).filter { !names.contains($0) && has($0) }
        if !others.isEmpty { out.append("other files") }
        return out
    }

    /// Moves a profile folder to the Trash, whatever it holds (the app asks first and names
    /// what is inside). Never the profile in use, and never Default, the CLI's own folder
    /// (owner, 30 Sep 2026).
    public static func moveToTrash(name: String) throws {
        guard name != legacyName else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey:
                "The Default profile cannot be deleted."])
        }
        guard activeName != name else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey:
                "\(name) is in use — switch to another profile first."])
        }
        guard let profile = named(name) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey: "No profile named \(name)."])
        }
        try FileManager.default.trashItem(at: profile.url, resultingItemURL: nil)
    }

    /// Wizard ▸ Cancel after Start over: puts the backup `startOverWithNewDomain` made back at
    /// `dataURL`, so the profile is exactly as before. The fresh folder the wizard used (settings
    /// and logs of the aborted setup at most) goes to the Trash, as the Start-over dialog promises;
    /// one that already holds a new domain is
    /// never touched (owner, 30 Sep 2026). The server must be stopped.
    public static func restoreStartOver(dataURL: URL, backup: String) throws {
        let fm = FileManager.default
        let source = dataURL.deletingLastPathComponent().appendingPathComponent(backup, isDirectory: true)
        guard backup.hasPrefix("LabDC-backup-"), fm.fileExists(atPath: source.path) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey:
                "The backup \(backup) is no longer there."])
        }
        if fm.fileExists(atPath: dataURL.path) {
            guard !fm.fileExists(atPath: dataURL.appendingPathComponent("lab.sqlite").path) else {
                throw CocoaError(.fileWriteFileExists, userInfo: [NSLocalizedDescriptionKey:
                    "A new domain was already created; the backup stays in \(backup)."])
            }
            try fm.trashItem(at: dataURL, resultingItemURL: nil)
        }
        try fm.moveItem(at: source, to: dataURL)
    }
}
