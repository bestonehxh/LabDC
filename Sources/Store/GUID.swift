import Foundation
import SheepCrypto

/// A Windows GUID in its binary (`objectGUID`) layout: Data1 (UInt32), Data2 and Data3
/// (UInt16) little-endian, then Data4 as 8 bytes (MS-DTYP §2.3.4.2).
public struct GUID: Sendable, Hashable, CustomStringConvertible {
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) throws {
        guard bytes.count == 16 else { throw StoreError.constraintViolation("a GUID is 16 bytes, got \(bytes.count)") }
        self.bytes = bytes
    }

    /// Parses `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, with or without braces.
    public init?(string: String) {
        var s = string
        if s.hasPrefix("{") && s.hasSuffix("}") { s = String(s.dropFirst().dropLast()) }
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 5, parts.map(\.count) == [8, 4, 4, 4, 12],
              parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isHexDigit } }) else { return nil }
        let d1 = [UInt8](hex: String(parts[0])), d2 = [UInt8](hex: String(parts[1])), d3 = [UInt8](hex: String(parts[2]))
        bytes = d1.reversed() + d2.reversed() + d3.reversed() + [UInt8](hex: String(parts[3])) + [UInt8](hex: String(parts[4]))
    }

    /// A random version-4 GUID.
    public static func random(_ rng: RandomBytes) -> GUID {
        var b = rng.next(16)
        b[7] = (b[7] & 0x0F) | 0x40  // version nibble is the high nibble of Data3 (little-endian byte 7)
        b[8] = (b[8] & 0x3F) | 0x80  // RFC 4122 variant
        return GUID(unchecked: b)
    }

    init(unchecked bytes: [UInt8]) { self.bytes = bytes }

    /// Lower-case `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, as AD prints it (and as DNS
    /// `<guid>._msdcs` names use it).
    public var description: String {
        let d1 = Array(bytes[0..<4].reversed()).hex, d2 = Array(bytes[4..<6].reversed()).hex
        let d3 = Array(bytes[6..<8].reversed()).hex
        return "\(d1)-\(d2)-\(d3)-\(Array(bytes[8..<10]).hex)-\(Array(bytes[10..<16]).hex)"
    }
}

/// LDAP GeneralizedTime as AD writes it: `20260925120000.0Z`.
public enum GeneralizedTime {
    public static func string(_ date: Date) -> String {
        var t = time_t(date.timeIntervalSince1970.rounded(.down))
        var tm = tm()
        gmtime_r(&t, &tm)
        func pad(_ v: Int32, _ n: Int) -> String {
            let s = String(v)
            return String(repeating: "0", count: max(0, n - s.count)) + s
        }
        return pad(tm.tm_year + 1900, 4) + pad(tm.tm_mon + 1, 2) + pad(tm.tm_mday, 2)
            + pad(tm.tm_hour, 2) + pad(tm.tm_min, 2) + pad(tm.tm_sec, 2) + ".0Z"
    }

    /// Parses `YYYYMMDDHHMMSS[.f]Z`.
    public static func date(_ s: String) -> Date? {
        let digits = Array(s.prefix(14))
        guard digits.count == 14, digits.allSatisfy(\.isASCIIDigit) else { return nil }
        func num(_ r: Range<Int>) -> Int32 { Int32(String(digits[r]))! }
        var tm = tm()
        tm.tm_year = num(0..<4) - 1900
        tm.tm_mon = num(4..<6) - 1
        tm.tm_mday = num(6..<8)
        tm.tm_hour = num(8..<10)
        tm.tm_min = num(10..<12)
        tm.tm_sec = num(12..<14)
        return Date(timeIntervalSince1970: TimeInterval(timegm(&tm)))
    }
}

extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
