import Foundation

/// Little-endian byte reader over `[UInt8]` with bounds checking (every SMB2 field is LE).
public struct SMBReader: Sendable {
    public let bytes: [UInt8]
    public var offset: Int

    public init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    public var remaining: Int { bytes.count - offset }

    public mutating func u8() throws -> UInt8 {
        guard offset >= 0, offset + 1 <= bytes.count else { throw SMBKitError.malformed("truncated at \(offset)") }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func u16() throws -> UInt16 {
        guard offset >= 0, offset + 2 <= bytes.count else { throw SMBKitError.malformed("truncated at \(offset)") }
        defer { offset += 2 }
        return bytes.le16(offset)
    }

    public mutating func u32() throws -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.count else { throw SMBKitError.malformed("truncated at \(offset)") }
        defer { offset += 4 }
        return bytes.le32(offset)
    }

    public mutating func u64() throws -> UInt64 {
        guard offset >= 0, offset + 8 <= bytes.count else { throw SMBKitError.malformed("truncated at \(offset)") }
        defer { offset += 8 }
        return bytes.le64(offset)
    }

    public mutating func take(_ n: Int) throws -> [UInt8] {
        guard n >= 0, offset >= 0, n <= bytes.count - offset else {
            throw SMBKitError.malformed("need \(n) bytes at \(offset)")
        }
        defer { offset += n }
        return Array(bytes[offset..<(offset + n)])
    }

    public mutating func skip(_ n: Int) throws { _ = try take(n) }
}

extension Array where Element == UInt8 {
    @inline(__always) func le16(_ at: Int) -> UInt16 { UInt16(self[at]) | UInt16(self[at + 1]) << 8 }
    @inline(__always) func le32(_ at: Int) -> UInt32 {
        UInt32(self[at]) | UInt32(self[at + 1]) << 8 | UInt32(self[at + 2]) << 16 | UInt32(self[at + 3]) << 24
    }
    @inline(__always) func le64(_ at: Int) -> UInt64 { UInt64(le32(at)) | UInt64(le32(at + 4)) << 32 }

    /// `count` bytes at `offset`, or nil when out of range (offsets come from the wire).
    func slice(_ offset: Int, _ count: Int) -> [UInt8]? {
        guard offset >= 0, count >= 0, offset <= self.count, count <= self.count - offset else { return nil }
        return Array(self[offset..<(offset + count)])
    }

    mutating func put16(_ v: UInt16) { append(UInt8(v & 0xFF)); append(UInt8(v >> 8)) }
    mutating func put32(_ v: UInt32) { for s in stride(from: 0, through: 24, by: 8) { append(UInt8((v >> UInt32(s)) & 0xFF)) } }
    mutating func put64(_ v: UInt64) { put32(UInt32(truncatingIfNeeded: v)); put32(UInt32(truncatingIfNeeded: v >> 32)) }
    mutating func zeros(_ n: Int) { if n > 0 { append(contentsOf: repeatElement(0, count: n)) } }
    /// Pads with zeros to a multiple of `alignment`.
    mutating func pad(to alignment: Int) { zeros((alignment - count % alignment) % alignment) }

    mutating func set16(_ v: UInt16, at i: Int) { self[i] = UInt8(v & 0xFF); self[i + 1] = UInt8(v >> 8) }
    mutating func set32(_ v: UInt32, at i: Int) { for k in 0..<4 { self[i + k] = UInt8((v >> UInt32(8 * k)) & 0xFF) } }
    mutating func set64(_ v: UInt64, at i: Int) {
        set32(UInt32(truncatingIfNeeded: v), at: i)
        set32(UInt32(truncatingIfNeeded: v >> 32), at: i + 4)
    }
}

/// UTF-16LE, the string encoding of every SMB2 name field.
public enum UTF16LE {
    public static func encode(_ s: String) -> [UInt8] { s.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] } }

    public static func decode(_ b: [UInt8]) -> String {
        var units: [UInt16] = []
        units.reserveCapacity(b.count / 2)
        var i = 0
        while i + 1 < b.count {
            units.append(UInt16(b[i]) | UInt16(b[i + 1]) << 8)
            i += 2
        }
        while units.last == 0 { units.removeLast() }
        return String(decoding: units, as: UTF16.self)
    }
}

/// Windows FILETIME: 100 ns intervals since 1601-01-01.
public enum FileTime {
    public static func from(_ date: Date) -> UInt64 {
        let t = (date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000
        return t <= 0 ? 0 : UInt64(t)
    }
}
