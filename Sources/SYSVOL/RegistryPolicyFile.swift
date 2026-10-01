import Foundation

/// Registry value types a `Registry.pol` instruction can carry (WinNT.h `REG_*`; MS-GPREG §2.2.1).
public enum RegistryValueType: UInt32, Sendable, Hashable, CustomStringConvertible {
    /// Used for key-only instructions ("create the key"): empty value name, no data.
    case none = 0
    case sz = 1
    case expandSz = 2
    case binary = 3
    case dword = 4
    case dwordBigEndian = 5
    case link = 6
    case multiSz = 7
    case qword = 11

    public var description: String {
        switch self {
        case .none: "REG_NONE"
        case .sz: "REG_SZ"
        case .expandSz: "REG_EXPAND_SZ"
        case .binary: "REG_BINARY"
        case .dword: "REG_DWORD"
        case .dwordBigEndian: "REG_DWORD_BIG_ENDIAN"
        case .link: "REG_LINK"
        case .multiSz: "REG_MULTI_SZ"
        case .qword: "REG_QWORD"
        }
    }
}

/// One `[key;value;type;size;data]` instruction of a Registry Policy file (MS-GPREG §2.2.1).
///
/// `key` is relative to HKLM (`Machine/Registry.pol`) or HKCU (`User/Registry.pol`) and never
/// includes the hive. Key and value names compare case-insensitively, as the registry does.
public struct RegistryPolicyEntry: Sendable, Hashable, CustomStringConvertible {
    public var key: String
    public var valueName: String
    /// The raw `Type` field (a `RegistryValueType` for every file we write; kept raw so an
    /// unknown type read from a foreign file round-trips unchanged).
    public var typeCode: UInt32
    public var data: [UInt8]

    public init(key: String, valueName: String, typeCode: UInt32, data: [UInt8]) {
        self.key = key
        self.valueName = valueName
        self.typeCode = typeCode
        self.data = data
    }

    public init(key: String, valueName: String, type: RegistryValueType, data: [UInt8]) {
        self.init(key: key, valueName: valueName, typeCode: type.rawValue, data: data)
    }

    public var type: RegistryValueType? { RegistryValueType(rawValue: typeCode) }

    /// `REG_DWORD`, little-endian.
    public static func dword(_ key: String, _ name: String, _ value: UInt32) -> RegistryPolicyEntry {
        RegistryPolicyEntry(key: key, valueName: name, type: .dword, data: RegistryPolicyFile.le32(value))
    }

    /// `REG_SZ`: UTF-16LE with the terminating NUL (the size counts it, as Windows writes it).
    public static func string(_ key: String, _ name: String, _ value: String) -> RegistryPolicyEntry {
        RegistryPolicyEntry(key: key, valueName: name, type: .sz, data: RegistryPolicyFile.utf16z(value))
    }

    /// `REG_BINARY`.
    public static func binary(_ key: String, _ name: String, _ value: [UInt8]) -> RegistryPolicyEntry {
        RegistryPolicyEntry(key: key, valueName: name, type: .binary, data: value)
    }

    /// `REG_MULTI_SZ`: each string NUL-terminated, then one more NUL.
    public static func multiString(_ key: String, _ name: String, _ values: [String]) -> RegistryPolicyEntry {
        var data: [UInt8] = []
        for v in values { data += RegistryPolicyFile.utf16z(v) }
        data += [0, 0]
        return RegistryPolicyEntry(key: key, valueName: name, type: .multiSz, data: data)
    }

    /// `REG_QWORD`, little-endian.
    public static func qword(_ key: String, _ name: String, _ value: UInt64) -> RegistryPolicyEntry {
        RegistryPolicyEntry(key: key, valueName: name, type: .qword,
                            data: (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * UInt64($0))) })
    }

    /// A key-only instruction: the client creates `key` and sets nothing ("If value, type, size,
    /// or data are missing or zero, only the registry key is created"; LGPO shows it as
    /// `CREATEKEY`). Encoded as an empty value name, type `REG_NONE`, size 0.
    public static func createKey(_ key: String) -> RegistryPolicyEntry {
        RegistryPolicyEntry(key: key, valueName: "", type: .none, data: [])
    }

    /// `**DeleteKeys` (REG_SZ, `;`-separated list of keys to delete before the values that follow).
    public static func deleteKeys(_ key: String, _ keys: [String]) -> RegistryPolicyEntry {
        string(key, "**DeleteKeys", keys.joined(separator: ";"))
    }

    /// The data as a little-endian DWORD, when the entry is a 4-byte `REG_DWORD`.
    public var dwordValue: UInt32? {
        guard typeCode == RegistryValueType.dword.rawValue, data.count == 4 else { return nil }
        return UInt32(data[0]) | UInt32(data[1]) << 8 | UInt32(data[2]) << 16 | UInt32(data[3]) << 24
    }

    /// The data as a string, for `REG_SZ` / `REG_EXPAND_SZ` (trailing NULs dropped).
    public var stringValue: String? {
        guard typeCode == RegistryValueType.sz.rawValue || typeCode == RegistryValueType.expandSz.rawValue else { return nil }
        return RegistryPolicyFile.decodeUTF16(data)
    }

    /// Whether this is a key-only instruction.
    public var isKeyOnly: Bool { valueName.isEmpty && typeCode == RegistryValueType.none.rawValue && data.isEmpty }

    /// Same key and value name (case-insensitive).
    public func addresses(key k: String, valueName v: String) -> Bool {
        key.caseInsensitiveCompare(k) == .orderedSame && valueName.caseInsensitiveCompare(v) == .orderedSame
    }

    public var description: String {
        let t = type?.description ?? "type \(typeCode)"
        let shown: String
        if let d = dwordValue { shown = "\(d) (0x\(String(d, radix: 16)))" }
        else if let s = stringValue { shown = "\"\(s)\"" }
        else { shown = "\(data.count) bytes" }
        return "[\(key);\(valueName.isEmpty ? "(key)" : valueName);\(t);\(shown)]"
    }
}

/// Errors reading a `Registry.pol`.
public enum RegistryPolicyError: Error, Equatable, CustomStringConvertible, Sendable {
    case badSignature
    case unsupportedVersion(UInt32)
    case truncated(offset: Int)
    case malformed(offset: Int, String)
    /// A value is larger than the 65535 bytes the Size field allows (MS-GPREG §2.2.1).
    case valueTooLarge(key: String, valueName: String, size: Int)

    public var description: String {
        switch self {
        case .badSignature: "Registry.pol: not a PReg file"
        case .unsupportedVersion(let v): "Registry.pol: version \(v) (only 1 is defined)"
        case .truncated(let o): "Registry.pol: truncated at offset \(o)"
        case let .malformed(o, s): "Registry.pol: \(s) at offset \(o)"
        case let .valueTooLarge(k, v, n): "Registry.pol: \(k)\\\(v) is \(n) bytes, more than the 65535 a policy value may hold"
        }
    }
}

/// A Registry Policy file (`Machine/Registry.pol`, `User/Registry.pol`), MS-GPREG §2.2.1:
///
///     "PReg" (50 52 65 67) | version 1 (LE32) | instructions...
///     instruction = "[" key NUL ";" value NUL ";" type(LE32) ";" size(LE32) ";" data "]"
///
/// Every character (`[`, `;`, `]`, names, NULs) is UTF-16LE, so each delimiter is two bytes
/// (`5B 00`, `3B 00`, `5D 00`); `type` and `size` are raw 32-bit little-endian integers. Order is
/// significant (instructions are applied in file order), so `set` replaces in place and appends
/// new values at the end.
public struct RegistryPolicyFile: Sendable, Hashable {
    public static let signature: [UInt8] = [0x50, 0x52, 0x65, 0x67]   // "PReg"
    public static let version: UInt32 = 1
    /// MS-GPREG §2.2.1: Size "MUST be in the range 0 to 65535".
    public static let maxDataSize = 65535

    public var entries: [RegistryPolicyEntry]

    public init(entries: [RegistryPolicyEntry] = []) { self.entries = entries }

    /// Parses a file. A zero-length file reads as empty (a missing file is also treated as
    /// empty by `GroupPolicyEditor`).
    public init(bytes: [UInt8]) throws {
        entries = []
        guard !bytes.isEmpty else { return }
        guard bytes.count >= 8 else { throw RegistryPolicyError.truncated(offset: bytes.count) }
        guard Array(bytes[0..<4]) == Self.signature else { throw RegistryPolicyError.badSignature }
        let version = Self.readLE32(bytes, 4)
        guard version == Self.version else { throw RegistryPolicyError.unsupportedVersion(version) }
        var p = 8
        func char(_ c: UInt8, _ what: String) throws {
            guard p + 2 <= bytes.count else { throw RegistryPolicyError.truncated(offset: p) }
            guard bytes[p] == c, bytes[p + 1] == 0 else { throw RegistryPolicyError.malformed(offset: p, "expected '\(what)'") }
            p += 2
        }
        func string() throws -> String {
            var units: [UInt16] = []
            while true {
                guard p + 2 <= bytes.count else { throw RegistryPolicyError.truncated(offset: p) }
                let u = UInt16(bytes[p]) | UInt16(bytes[p + 1]) << 8
                p += 2
                if u == 0 { break }
                units.append(u)
            }
            return String(decoding: units, as: UTF16.self)
        }
        func u32() throws -> UInt32 {
            guard p + 4 <= bytes.count else { throw RegistryPolicyError.truncated(offset: p) }
            defer { p += 4 }
            return Self.readLE32(bytes, p)
        }
        while p < bytes.count {
            try char(0x5B, "[")
            let key = try string()
            try char(0x3B, ";")
            let value = try string()
            try char(0x3B, ";")
            let type = try u32()
            try char(0x3B, ";")
            let size = Int(try u32())
            try char(0x3B, ";")
            guard p + size <= bytes.count else { throw RegistryPolicyError.truncated(offset: p) }
            let data = Array(bytes[p..<(p + size)])
            p += size
            try char(0x5D, "]")
            entries.append(RegistryPolicyEntry(key: key, valueName: value, typeCode: type, data: data))
        }
    }

    /// The file bytes. Throws when a value exceeds the 65535-byte Size limit.
    public func encoded() throws -> [UInt8] {
        var out = Self.signature + Self.le32(Self.version)
        let open: [UInt8] = [0x5B, 0], semi: [UInt8] = [0x3B, 0], close: [UInt8] = [0x5D, 0]
        for e in entries {
            guard e.data.count <= Self.maxDataSize else {
                throw RegistryPolicyError.valueTooLarge(key: e.key, valueName: e.valueName, size: e.data.count)
            }
            out += open + Self.utf16z(e.key) + semi + Self.utf16z(e.valueName) + semi
            out += Self.le32(e.typeCode) + semi + Self.le32(UInt32(e.data.count)) + semi
            out += e.data + close
        }
        return out
    }

    // MARK: Editing

    /// The instruction for `key` / `valueName`, if any (the last one wins, as on the client).
    public func entry(key: String, valueName: String) -> RegistryPolicyEntry? {
        entries.last { $0.addresses(key: key, valueName: valueName) }
    }

    /// Sets a value: replaces the first instruction with the same key and value name in place
    /// (dropping later duplicates) or appends. Returns whether the file changed.
    @discardableResult
    public mutating func set(_ entry: RegistryPolicyEntry) -> Bool {
        guard let first = entries.firstIndex(where: { $0.addresses(key: entry.key, valueName: entry.valueName) }) else {
            entries.append(entry)
            return true
        }
        let before = entries
        entries[first] = entry
        var i = entries.count - 1
        while i > first {
            if entries[i].addresses(key: entry.key, valueName: entry.valueName) { entries.remove(at: i) }
            i -= 1
        }
        return entries != before
    }

    /// Removes every instruction for `key` / `valueName`. Returns whether any was removed.
    @discardableResult
    public mutating func remove(key: String, valueName: String) -> Bool {
        let n = entries.count
        entries.removeAll { $0.addresses(key: key, valueName: valueName) }
        return entries.count != n
    }

    /// Removes every instruction on `key` and (with `subkeys`) below it. Returns how many.
    @discardableResult
    public mutating func removeKey(_ key: String, subkeys: Bool = true) -> Int {
        let n = entries.count
        entries.removeAll { Self.isKey($0.key, atOrBelow: key, subkeys: subkeys) }
        return n - entries.count
    }

    /// Instructions on `key` and (with `subkeys`) below it, in file order.
    public func entries(under key: String, subkeys: Bool = true) -> [RegistryPolicyEntry] {
        entries.filter { Self.isKey($0.key, atOrBelow: key, subkeys: subkeys) }
    }

    static func isKey(_ k: String, atOrBelow base: String, subkeys: Bool) -> Bool {
        let a = k.lowercased(), b = base.lowercased()
        return a == b || (subkeys && a.hasPrefix(b + "\\"))
    }

    // MARK: Encoding helpers

    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]
    }

    static func readLE32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
    }

    /// UTF-16LE with a terminating NUL.
    static func utf16z(_ s: String) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(s.utf16.count * 2 + 2)
        for u in s.utf16 { out += [UInt8(u & 0xFF), UInt8(u >> 8)] }
        return out + [0, 0]
    }

    /// UTF-16LE to String, stopping at the first NUL.
    static func decodeUTF16(_ b: [UInt8]) -> String {
        var units: [UInt16] = []
        var i = 0
        while i + 1 < b.count {
            let u = UInt16(b[i]) | UInt16(b[i + 1]) << 8
            if u == 0 { break }
            units.append(u)
            i += 2
        }
        return String(decoding: units, as: UTF16.self)
    }
}
