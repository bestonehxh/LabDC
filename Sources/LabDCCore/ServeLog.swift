import Foundation
import os

/// One line per event: to `os.Logger` (subsystem `dev.labdc.app`, category `serve`) and, when
/// `echo` is set, to stdout with a UTC timestamp and the component name.
///
/// The servers log their own per-request detail to the unified log under their categories
/// (`DNS`, `LDAP`, `CLDAP`, `KDC`, `kpasswd`, `Store`, `PKI`); watch everything with
/// `log stream --level info --predicate 'subsystem == "dev.labdc.app"'`.
///
/// UI-1: every line can also go to a daily file (`<data>/logs/serve-YYYY-MM-DD.log`,
/// `ServeLogFile`) and, parsed, to `lines` (the app's `LogHub`); runtime events that are not log
/// lines (the advertised address changed) go to `onRuntimeEvent`.
public final class ServeLog: Sendable {
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "serve")
    private let echo: Bool
    private let sink: (@Sendable (String) -> Void)?
    private let file: ServeLogFile?
    private let lines: (@Sendable (LogLine) -> Void)?
    private let onRuntimeEvent: (@Sendable (ServeRuntimeEvent) -> Void)?

    /// - Parameters:
    ///   - echo: also print to stdout.
    ///   - sink: receives every line as well (tests).
    ///   - file: appends every line to the day's log file.
    ///   - lines: receives every line as a `LogLine` (the app).
    ///   - onRuntimeEvent: receives `ServeRuntimeEvent`s.
    public init(echo: Bool = true, sink: (@Sendable (String) -> Void)? = nil, file: ServeLogFile? = nil,
                lines: (@Sendable (LogLine) -> Void)? = nil, onRuntimeEvent: (@Sendable (ServeRuntimeEvent) -> Void)? = nil) {
        self.echo = echo
        self.sink = sink
        self.file = file
        self.lines = lines
        self.onRuntimeEvent = onRuntimeEvent
    }

    public func event(_ component: String, _ text: String) {
        Self.logger.notice("\(component, privacy: .public) \(text, privacy: .public)")
        let now = Date()
        let line = "\(Self.timestamp(now)) \(component) \(text)"
        emit(line, LogLine(date: now, component: component, text: text, level: .info, raw: line))
    }

    public func warning(_ component: String, _ text: String) {
        Self.logger.warning("\(component, privacy: .public) \(text, privacy: .public)")
        let now = Date()
        let line = "\(Self.timestamp(now)) \(component) WARNING \(text)"
        emit(line, LogLine(date: now, component: component, text: text, level: .warning, raw: line))
    }

    /// Plain text (banner) without timestamp; also logged.
    public func banner(_ text: String) {
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            Self.logger.notice("\(String(line), privacy: .public)")
        }
        if echo { Self.write(text) }
        sink?(text)
        let now = Date()
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            file?.write(String(line), at: now)
            lines?(LogLine(date: now, component: "serve", text: String(line), level: .banner, raw: String(line)))
        }
    }

    /// Hands a runtime event to the observer (no log line).
    public func runtimeEvent(_ event: ServeRuntimeEvent) {
        onRuntimeEvent?(event)
    }

    private func emit(_ line: String, _ parsed: LogLine) {
        if echo { Self.write(line) }
        sink?(line)
        file?.write(line, at: parsed.date)
        lines?(parsed)
    }

    private static func write(_ line: String) {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }

    static func timestamp(_ date: Date = Date()) -> String {
        var t = time_t(date.timeIntervalSince1970)
        var tm = tm()
        gmtime_r(&t, &tm)
        return String(format: "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

/// Something the runtime reports that is state rather than a log line.
public enum ServeRuntimeEvent: Sendable, Equatable {
    /// The interface IPv4 list changed; `advertised` is what DNS/CLDAP/EPM now hand out.
    case addressesChanged(advertised: String?, addresses: [String], pinned: Bool)
}
