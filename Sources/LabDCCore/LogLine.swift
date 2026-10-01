import Foundation

/// One line of the serve log: `2026-09-26T08:55:24Z KDC AS alice@LABSHEEP from … -> OK …`.
public struct LogLine: Sendable, Hashable, Identifiable {
    public enum Level: String, Sendable, Hashable {
        case info, warning
        /// The start-up banner (no timestamp, no component).
        case banner
    }

    /// Position in the `LogHub` (assigned when the line enters it; 0 before).
    public var seq: Int = 0
    public var id: Int { seq }
    public var date: Date
    /// `KDC`, `NETLOGON`, `LDAP`, `DRSUAPI`, `SCEP`, `serve`, …
    public var component: String
    /// The text after the component (and after `WARNING`).
    public var text: String
    public var level: Level
    /// The line exactly as printed on stdout / written to the file.
    public var raw: String

    public init(seq: Int = 0, date: Date, component: String, text: String, level: Level = .info, raw: String) {
        self.seq = seq
        self.date = date
        self.component = component
        self.text = text
        self.level = level
        self.raw = raw
    }

    /// Parses a stdout / file line. Lines without the leading UTC timestamp are banner lines
    /// (dated `fallbackDate`).
    public static func parse(_ raw: String, fallbackDate: Date = Date()) -> LogLine {
        let parts = raw.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        if parts.count >= 2, let date = parseTimestamp(String(parts[0])) {
            let component = String(parts[1])
            var text = parts.count > 2 ? String(parts[2]) : ""
            var level = Level.info
            if text.hasPrefix("WARNING ") {
                level = .warning
                text = String(text.dropFirst("WARNING ".count))
            }
            return LogLine(date: date, component: component, text: text, level: level, raw: raw)
        }
        return LogLine(date: fallbackDate, component: "serve", text: raw, level: .banner, raw: raw)
    }

    /// `2026-09-26T08:55:24Z` (what `ServeLog` prints).
    public static func parseTimestamp(_ s: String) -> Date? {
        let u = Array(s.utf8)
        guard u.count == 20, u[4] == 0x2D, u[7] == 0x2D, u[10] == 0x54, u[13] == 0x3A, u[16] == 0x3A, u[19] == 0x5A else { return nil }
        func num(_ r: Range<Int>) -> Int? {
            var v = 0
            for i in r {
                guard u[i] >= 0x30, u[i] <= 0x39 else { return nil }
                v = v * 10 + Int(u[i] - 0x30)
            }
            return v
        }
        guard let y = num(0..<4), let mo = num(5..<7), let d = num(8..<10), let h = num(11..<13), let mi = num(14..<16),
              let se = num(17..<19) else { return nil }
        var c = DateComponents()
        c.year = y; c.month = mo; c.day = d; c.hour = h; c.minute = mi; c.second = se
        c.timeZone = TimeZone(identifier: "UTC")
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: c)
    }
}
