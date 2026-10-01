import Foundation
import Synchronization

/// The on-disk serve log: `<data>/logs/serve-YYYY-MM-DD.log` (local calendar day), one file per
/// day, appended line by line; a new file starts with the first line of a new day, and files
/// older than `keepDays` are removed then.
public final class ServeLogFile: Sendable {
    public let directory: URL
    public let keepDays: Int
    private let calendar: Calendar
    private struct State {
        var day: String?
        var handle: FileHandle?
    }
    private let state = Mutex(State())

    /// - Parameter calendar: defaults to the Gregorian calendar in the local time zone (never the
    ///   user's calendar: a Buddhist-calendar Mac would otherwise write `serve-2569-…`).
    public init(directory: URL, keepDays: Int = 30, calendar: Calendar = ServeLogFile.localGregorian) {
        self.directory = directory
        self.keepDays = keepDays
        self.calendar = calendar
    }

    deinit {
        state.withLock { try? $0.handle?.close() }
    }

    public static var localGregorian: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = .current
        return c
    }

    /// `serve-2026-09-26.log`.
    public static func fileName(for date: Date, calendar: Calendar = ServeLogFile.localGregorian) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "serve-%04d-%02d-%02d.log", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    public func url(for date: Date) -> URL {
        directory.appendingPathComponent(Self.fileName(for: date, calendar: calendar))
    }

    public func write(_ line: String, at date: Date = Date()) {
        let name = Self.fileName(for: date, calendar: calendar)
        let data = Data((line + "\n").utf8)
        state.withLock { s in
            if s.day != name || s.handle == nil {
                try? s.handle?.close()
                s.handle = open(name)
                s.day = name
                prune(now: date)
            }
            if let h = s.handle {
                do {
                    try h.seekToEnd()
                    try h.write(contentsOf: data)
                } catch {
                    s.handle = nil
                }
            }
        }
    }

    /// The day files present, oldest first.
    public func files() -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.filter { $0.hasPrefix("serve-") && $0.hasSuffix(".log") }.sorted()
            .map { directory.appendingPathComponent($0) }
    }

    /// The lines of today's file (for the app's Activity page after a relaunch).
    public func todaysLines(now: Date = Date()) -> [String] {
        guard let text = try? String(contentsOf: url(for: now), encoding: .utf8) else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    private func open(_ name: String) -> FileHandle? {
        let fm = FileManager.default
        try? fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent(name)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        return try? FileHandle(forWritingTo: url)
    }

    private func prune(now: Date) {
        guard keepDays > 0, let cutoff = calendar.date(byAdding: .day, value: -keepDays, to: now) else { return }
        let oldest = Self.fileName(for: cutoff, calendar: calendar)
        for url in files() where url.lastPathComponent < oldest {
            try? FileManager.default.removeItem(at: url)
        }
    }
}
