import Foundation

/// Why a datagram or a configuration value was refused. Every parser in DHCPKit throws one of
/// these instead of trapping: a malformed packet from the network is a log line, never a crash.
public enum DHCPError: Error, Equatable, Sendable, CustomStringConvertible {
    /// The bytes end before a field or option does.
    case truncated(String)
    /// The bytes are there but make no sense (bad magic cookie, a length that is not allowed).
    case malformed(String)
    /// A configuration value (address, range, option text) is not usable.
    case invalid(String)

    public var description: String {
        switch self {
        case .truncated(let s): "truncated: \(s)"
        case .malformed(let s): "malformed: \(s)"
        case .invalid(let s): s
        }
    }
}

/// A bounds-checked cursor over a byte array. Every read checks the remaining length first.
public struct DHCPReader: Sendable {
    public let bytes: [UInt8]
    public private(set) var offset: Int
    let end: Int

    public init(_ bytes: [UInt8], offset: Int = 0, end: Int? = nil) {
        self.bytes = bytes
        self.offset = max(0, min(offset, bytes.count))
        self.end = max(self.offset, min(end ?? bytes.count, bytes.count))
    }

    public var remaining: Int { end - offset }
    public var isAtEnd: Bool { offset >= end }

    public mutating func u8(_ what: @autoclosure () -> String = "byte") throws -> UInt8 {
        guard remaining >= 1 else { throw DHCPError.truncated(what()) }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func u16(_ what: @autoclosure () -> String = "16-bit field") throws -> UInt16 {
        guard remaining >= 2 else { throw DHCPError.truncated(what()) }
        defer { offset += 2 }
        return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    public mutating func u32(_ what: @autoclosure () -> String = "32-bit field") throws -> UInt32 {
        guard remaining >= 4 else { throw DHCPError.truncated(what()) }
        defer { offset += 4 }
        return bytes[offset..<offset + 4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }

    public mutating func take(_ count: Int, _ what: @autoclosure () -> String = "field") throws -> [UInt8] {
        guard count >= 0, remaining >= count else { throw DHCPError.truncated(what()) }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    public mutating func rest() -> [UInt8] {
        defer { offset = end }
        return Array(bytes[offset..<end])
    }
}

/// Big-endian appends.
extension Array where Element == UInt8 {
    mutating func appendU16(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xFF)) }
    mutating func appendU32(_ v: UInt32) {
        append(UInt8(v >> 24)); append(UInt8(v >> 16 & 0xFF)); append(UInt8(v >> 8 & 0xFF)); append(UInt8(v & 0xFF))
    }
}

public enum DHCPHex {
    /// `0a1b2c` (lower case, no separators).
    public static func string(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Accepts `0a1b2c`, `0a:1b:2c`, `0a-1b-2c`, `0a 1b 2c`, `0x0a1b2c` and `0a1b.2c3d` (Cisco).
    public static func bytes(_ text: String) -> [UInt8]? {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if t.hasPrefix("0x") { t.removeFirst(2) }
        let digits = t.filter { !":-. ".contains($0) }
        guard digits.count % 2 == 0, digits.allSatisfy(\.isHexDigit) else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(digits.count / 2)
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            guard let b = UInt8(digits[index..<next], radix: 16) else { return nil }
            out.append(b)
            index = next
        }
        return out
    }

    /// Printable ASCII as text, anything else as hex (`circuit "Gi1/0/3"` vs `000400140105`).
    public static func printable(_ bytes: [UInt8]) -> String {
        if !bytes.isEmpty, bytes.allSatisfy({ (0x20...0x7E).contains($0) }) {
            return String(decoding: bytes, as: UTF8.self)
        }
        return string(bytes)
    }
}

/// MAC addresses as the rest of LabDC writes them: lower case `aa:bb:cc:dd:ee:ff`.
public enum DHCPMAC {
    public static func string(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// Any common spelling (`AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`, `aabbccddeeff`) → canonical,
    /// nil unless it is 6 bytes.
    public static func normalize(_ text: String) -> String? {
        guard let b = DHCPHex.bytes(text), b.count == 6 else { return nil }
        return string(b)
    }

    public static func bytes(_ text: String) -> [UInt8]? {
        guard let b = DHCPHex.bytes(text), b.count == 6 else { return nil }
        return b
    }
}

/// DNS names in RFC 1035 wire form (no compression) for options 81, 119, 24 and 39.
public enum DHCPDNSWire {
    /// `lab.sheep` → 03 6c 61 62 05 73 68 65 65 70 00. Fails on an empty label or one over 63.
    public static func encode(_ name: String, terminate: Bool = true) throws -> [UInt8] {
        var out: [UInt8] = []
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        if !trimmed.isEmpty {
            for label in trimmed.split(separator: ".", omittingEmptySubsequences: false) {
                let bytes = Array(label.utf8)
                guard !bytes.isEmpty, bytes.count <= 63 else { throw DHCPError.invalid("bad DNS name \(name)") }
                out.append(UInt8(bytes.count))
                out += bytes
            }
        }
        if terminate { out.append(0) }
        guard out.count <= 255 else { throw DHCPError.invalid("DNS name too long: \(name)") }
        return out
    }

    /// Several names one after another (option 119 / 24).
    public static func encodeList(_ names: [String]) throws -> [UInt8] {
        try names.flatMap { try encode($0) }
    }

    /// Decodes a sequence of names; compression pointers (option 119, RFC 3397) are followed
    /// within `bytes` with a loop limit. A trailing name without the root label (option 81/39
    /// partial names) is returned as is.
    public static func decodeList(_ bytes: [UInt8]) throws -> [String] {
        var names: [String] = []
        var offset = 0
        while offset < bytes.count {
            let (name, next) = try decode(bytes, at: offset)
            names.append(name)
            guard next > offset else { break }
            offset = next
        }
        return names
    }

    /// One name at `offset`: the text and where the next name starts.
    public static func decode(_ bytes: [UInt8], at start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var offset = start
        var next: Int?
        var jumps = 0
        while true {
            guard offset < bytes.count else {
                // A partial name (no root label): what was read so far.
                return (labels.joined(separator: "."), next ?? offset)
            }
            let len = Int(bytes[offset])
            if len == 0 {
                return (labels.joined(separator: "."), next ?? offset + 1)
            }
            if len & 0xC0 == 0xC0 {
                guard offset + 1 < bytes.count else { throw DHCPError.truncated("compression pointer") }
                let target = (len & 0x3F) << 8 | Int(bytes[offset + 1])
                if next == nil { next = offset + 2 }
                jumps += 1
                guard jumps < 64, target < bytes.count else { throw DHCPError.malformed("compression loop") }
                offset = target
                continue
            }
            guard len <= 63 else { throw DHCPError.malformed("label length \(len)") }
            guard offset + 1 + len <= bytes.count else { throw DHCPError.truncated("DNS label") }
            labels.append(String(decoding: bytes[offset + 1..<offset + 1 + len], as: UTF8.self))
            guard labels.count < 128 else { throw DHCPError.malformed("too many labels") }
            offset += 1 + len
        }
    }
}
