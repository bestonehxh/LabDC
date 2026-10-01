import Foundation

/// A Windows FILETIME (MS-DTYP §2.3.3): 100-nanosecond intervals since 1601-01-01T00:00:00Z,
/// transmitted as two little-endian UInt32 (`dwLowDateTime`, `dwHighDateTime`), which is the
/// same byte sequence as one little-endian UInt64.
///
/// `0x7FFFFFFF_FFFFFFFF` means "never" (e.g. `PasswordMustChange` of a non-expiring password)
/// and 0 means "not set".
public struct FileTime: RawRepresentable, Hashable, Comparable, Sendable, CustomStringConvertible {
    public var rawValue: UInt64

    public init(rawValue: UInt64) { self.rawValue = rawValue }

    public init(low: UInt32, high: UInt32) { rawValue = UInt64(high) << 32 | UInt64(low) }

    public static let never = FileTime(rawValue: 0x7FFF_FFFF_FFFF_FFFF)
    public static let zero = FileTime(rawValue: 0)

    public static let ticksPerSecond: UInt64 = 10_000_000

    /// 1601-01-01T00:00:00Z, built with the Gregorian calendar in UTC (never `Calendar.current`,
    /// which may be Buddhist or Japanese on the owner's machine).
    public static let epoch: Date = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let components = DateComponents(year: 1601, month: 1, day: 1, hour: 0, minute: 0, second: 0)
        return calendar.date(from: components)!
    }()

    /// Whole seconds from 1601-01-01 to 1970-01-01 (11644473600), derived from `epoch`.
    public static let unixEpochOffsetSeconds: Int64 = Int64((-epoch.timeIntervalSince1970).rounded())

    /// Converts a date; dates before 1601 clamp to 0 and dates at or beyond "never" clamp to
    /// `never`. Sub-tick precision is rounded to the nearest 100 ns.
    public init(_ date: Date) {
        let t = date.timeIntervalSince1970
        let whole = t.rounded(.down)
        let fraction = t - whole
        guard whole.isFinite, whole > -Double(Int64.max / 2), whole < Double(Int64.max / 2) else {
            rawValue = whole > 0 ? FileTime.never.rawValue : 0
            return
        }
        let seconds = Int64(whole) + FileTime.unixEpochOffsetSeconds
        let fracTicks = Int64((fraction * Double(FileTime.ticksPerSecond)).rounded())
        guard seconds >= 0 else { rawValue = 0; return }
        let (mul, o1) = seconds.multipliedReportingOverflow(by: Int64(FileTime.ticksPerSecond))
        let (sum, o2) = mul.addingReportingOverflow(fracTicks)
        if o1 || o2 || sum >= Int64(FileTime.never.rawValue) {
            rawValue = FileTime.never.rawValue
        } else {
            rawValue = UInt64(max(0, sum))
        }
    }

    public var isNever: Bool { rawValue == FileTime.never.rawValue }

    /// The instant, or nil for "never" (and for values above it, which are not valid times).
    public var date: Date? {
        guard rawValue < FileTime.never.rawValue else { return nil }
        let seconds = Int64(rawValue / FileTime.ticksPerSecond) - FileTime.unixEpochOffsetSeconds
        let fraction = Double(rawValue % FileTime.ticksPerSecond) / Double(FileTime.ticksPerSecond)
        return Date(timeIntervalSince1970: Double(seconds) + fraction)
    }

    public var low: UInt32 { UInt32(truncatingIfNeeded: rawValue) }
    public var high: UInt32 { UInt32(truncatingIfNeeded: rawValue >> 32) }

    public static func < (a: FileTime, b: FileTime) -> Bool { a.rawValue < b.rawValue }

    public var description: String {
        if isNever { return "never" }
        return "FILETIME(0x\(String(rawValue, radix: 16)))"
    }
}
