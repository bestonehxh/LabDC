// Minimal NDR (DCE 1.1 / MS-RPCE) machinery for the PAC: little-endian, NDR20, type
// serialization version 1 (MS-RPCE §2.2.6). Internal; only KERB_VALIDATION_INFO uses it.
//
// Rules implemented:
// - Primitive types are aligned to their size (u16 -> 2, u32 -> 4) relative to the start of the
//   serialized body (the byte after the 16 header bytes, itself 8-aligned in the PAC).
// - Embedded [unique] pointers are a 4-byte referent id in the flat part; non-null referents
//   are numbered 0x00020000, 0x00020004, ... in the order they are marshalled (Windows style;
//   receivers only test for zero). Pointee bodies are deferred: after the containing
//   structure, in pointer order; pointers inside a pointee are deferred to just after it.
// - A conformant array body starts with MaximumCount (u32); a conformant varying array (the
//   WCHAR buffer of RPC_UNICODE_STRING) with MaximumCount, Offset, ActualCount.

enum NDR {
    /// Common type header (MS-RPCE §2.2.6.1): version 1, little-endian (0x10), header length 8,
    /// filler 0xCCCCCCCC.
    static let commonHeader: [UInt8] = [0x01, 0x10, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC]

    static let firstReferent: UInt32 = 0x0002_0000

    /// Wraps a serialized top-level body in the common and private headers. The private header
    /// (§2.2.6.2) holds ObjectBufferLength (body length padded to a multiple of 8) and a zero
    /// filler; the body is padded with zeros to that length.
    static func typeSerialize(_ body: [UInt8]) -> [UInt8] {
        var w = ByteWriter()
        w.append(commonHeader)
        let padded = (body.count + 7) & ~7
        w.u32(UInt32(padded))
        w.u32(0)
        w.append(body)
        w.zeros(padded - body.count)
        return w.bytes
    }

    /// Validates the two headers and returns the byte range of the serialized body.
    static func typeDeserialize(_ bytes: [UInt8], context: String) throws -> Range<Int> {
        guard bytes.count >= 16 else { throw MSPACError.ndr(context: context, reason: "shorter than the 16-byte headers") }
        guard bytes[0] == 0x01 else { throw MSPACError.ndr(context: context, reason: "type serialization version \(bytes[0]) is not 1") }
        guard bytes[1] == 0x10 else {
            throw MSPACError.ndr(context: context, reason: "endianness 0x\(String(bytes[1], radix: 16)) is not little-endian (0x10)")
        }
        guard bytes[2] == 0x08, bytes[3] == 0x00 else { throw MSPACError.ndr(context: context, reason: "common header length is not 8") }
        let length = Int(readU32LE(bytes, 8))
        guard length <= bytes.count - 16 else {
            throw MSPACError.ndr(context: context, reason: "ObjectBufferLength \(length) exceeds the \(bytes.count - 16) available bytes")
        }
        return 16..<(16 + length)
    }
}

struct NDRWriter {
    private(set) var out = ByteWriter()
    private var nextReferent = NDR.firstReferent

    var bytes: [UInt8] { out.bytes }

    mutating func u8(_ v: UInt8) { out.u8(v) }

    mutating func u16(_ v: UInt16) {
        out.align(2)
        out.u16(v)
    }

    mutating func u32(_ v: UInt32) {
        out.align(4)
        out.u32(v)
    }

    mutating func fileTime(_ t: FileTime) {
        u32(t.low)
        u32(t.high)
    }

    mutating func raw(_ b: [UInt8]) { out.append(b) }

    /// Writes a [unique] pointer: a fresh referent id when present, else 0.
    mutating func pointer(_ present: Bool) {
        if present {
            u32(nextReferent)
            nextReferent &+= 4
        } else {
            u32(0)
        }
    }
}

struct NDRReader {
    private var r: ByteReader
    private let base: Int
    let context: String

    init(_ bytes: [UInt8], range: Range<Int>, context: String) {
        r = ByteReader(bytes, range: range, context: context)
        base = range.lowerBound
        self.context = context
    }

    var remaining: Int { r.remaining }

    mutating func u8(_ what: String) throws -> UInt8 { try r.u8(what) }

    mutating func u16(_ what: String) throws -> UInt16 {
        try r.align(2, base: base, what)
        return try r.u16(what)
    }

    mutating func u32(_ what: String) throws -> UInt32 {
        try r.align(4, base: base, what)
        return try r.u32(what)
    }

    mutating func fileTime(_ what: String) throws -> FileTime {
        let low = try u32(what)
        let high = try u32(what)
        return FileTime(low: low, high: high)
    }

    mutating func take(_ n: Int, _ what: String) throws -> [UInt8] { try r.take(n, what) }

    /// Reads a [unique] pointer; true when the referent id is non-zero.
    mutating func pointer(_ what: String) throws -> Bool { try u32(what) != 0 }

    /// Reads a conformant array's MaximumCount and checks it against the size_is value and
    /// against the bytes left (`elementSize` per element), so hostile counts cannot allocate.
    mutating func conformance(_ what: String, expected: UInt32, elementSize: Int) throws {
        let max = try u32("\(what) MaximumCount")
        guard max == expected else { throw fail("\(what) MaximumCount \(max) does not match its count \(expected)") }
        guard Int(max) <= remaining / elementSize else { throw MSPACError.truncated(context: "\(context) \(what) elements") }
    }

    func fail(_ reason: String) -> MSPACError { .ndr(context: context, reason: reason) }
}
