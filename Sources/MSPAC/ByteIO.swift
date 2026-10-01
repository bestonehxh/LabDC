// Little-endian byte writer/reader shared by the PAC and NDR codecs. Internal.

struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    var count: Int { bytes.count }

    mutating func u8(_ v: UInt8) { bytes.append(v) }

    mutating func u16(_ v: UInt16) {
        bytes.append(UInt8(truncatingIfNeeded: v))
        bytes.append(UInt8(truncatingIfNeeded: v >> 8))
    }

    mutating func u32(_ v: UInt32) {
        for shift in stride(from: 0, to: 32, by: 8) { bytes.append(UInt8(truncatingIfNeeded: v >> UInt32(shift))) }
    }

    mutating func u64(_ v: UInt64) {
        for shift in stride(from: 0, to: 64, by: 8) { bytes.append(UInt8(truncatingIfNeeded: v >> UInt64(shift))) }
    }

    mutating func append(_ b: [UInt8]) { bytes.append(contentsOf: b) }

    mutating func zeros(_ n: Int) { bytes.append(contentsOf: repeatElement(0, count: n)) }

    /// Pads with zero bytes until `count` is a multiple of `alignment` (relative to `base`).
    mutating func align(_ alignment: Int, base: Int = 0) {
        let rel = bytes.count - base
        let pad = (alignment - rel % alignment) % alignment
        zeros(pad)
    }

    mutating func patchU32(_ v: UInt32, at offset: Int) {
        for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: v >> UInt32(8 * i)) }
    }
}

struct ByteReader {
    let bytes: [UInt8]
    private(set) var position: Int
    let end: Int
    let context: String

    init(_ bytes: [UInt8], range: Range<Int>? = nil, context: String) {
        self.bytes = bytes
        let r = range ?? 0..<bytes.count
        position = r.lowerBound
        end = r.upperBound
        self.context = context
    }

    var remaining: Int { end - position }

    mutating func need(_ n: Int, _ what: String) throws {
        guard n >= 0, n <= remaining else { throw MSPACError.truncated(context: "\(context) \(what)") }
    }

    mutating func u8(_ what: String) throws -> UInt8 {
        try need(1, what)
        defer { position += 1 }
        return bytes[position]
    }

    mutating func u16(_ what: String) throws -> UInt16 {
        try need(2, what)
        defer { position += 2 }
        return UInt16(bytes[position]) | UInt16(bytes[position + 1]) << 8
    }

    mutating func u32(_ what: String) throws -> UInt32 {
        try need(4, what)
        var v: UInt32 = 0
        for i in 0..<4 { v |= UInt32(bytes[position + i]) << UInt32(8 * i) }
        position += 4
        return v
    }

    mutating func u64(_ what: String) throws -> UInt64 {
        try need(8, what)
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(bytes[position + i]) << UInt64(8 * i) }
        position += 8
        return v
    }

    mutating func take(_ n: Int, _ what: String) throws -> [UInt8] {
        try need(n, what)
        defer { position += n }
        return Array(bytes[position..<(position + n)])
    }

    /// Skips padding so that `position - base` is a multiple of `alignment`.
    mutating func align(_ alignment: Int, base: Int, _ what: String) throws {
        let rel = position - base
        let pad = (alignment - rel % alignment) % alignment
        try need(pad, what)
        position += pad
    }
}

func readU32LE(_ b: [UInt8], _ offset: Int) -> UInt32 {
    var v: UInt32 = 0
    for i in 0..<4 { v |= UInt32(b[offset + i]) << UInt32(8 * i) }
    return v
}

extension String {
    /// UTF-16LE code units as bytes, no terminator.
    var utf16LEBytes: [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(utf16.count * 2)
        for u in utf16 {
            out.append(UInt8(truncatingIfNeeded: u))
            out.append(UInt8(truncatingIfNeeded: u >> 8))
        }
        return out
    }

    /// Decodes UTF-16LE bytes (even count assumed). Invalid surrogates become U+FFFD.
    init(utf16LE bytes: [UInt8]) {
        var units = [UInt16]()
        units.reserveCapacity(bytes.count / 2)
        var i = 0
        while i + 1 < bytes.count {
            units.append(UInt16(bytes[i]) | UInt16(bytes[i + 1]) << 8)
            i += 2
        }
        self = String(decoding: units, as: UTF16.self)
    }
}
