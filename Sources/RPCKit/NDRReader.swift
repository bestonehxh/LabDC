import Foundation
import MSPAC

/// NDR32 little-endian unmarshaller, the mirror of `NDRWriter`. Alignment is relative to the
/// stub start (`base`). Every read is bounds-checked and throws `NDRError` with the offset
/// (relative to `base`) on underrun or a broken invariant.
public final class NDRReader: @unchecked Sendable {
    private let bytes: [UInt8]
    private var pos: Int
    private let base: Int
    private var deferred: [() throws -> Void] = []

    /// Reads `bytes[range]` as a stub whose alignment origin is `range.lowerBound`.
    public init(_ bytes: [UInt8], range: Range<Int>? = nil) {
        self.bytes = bytes
        let r = range ?? (0..<bytes.count)
        self.pos = r.lowerBound
        self.base = r.lowerBound
    }

    /// Bytes not yet consumed.
    public var remaining: Int { bytes.count - pos }
    /// Current offset relative to the stub start.
    public var offset: Int { pos - base }

    private func need(_ n: Int) throws {
        if pos + n > bytes.count {
            throw NDRError(offset: pos - base, reason: "need \(n) bytes, \(bytes.count - pos) left")
        }
    }

    // MARK: alignment

    public func align(_ alignment: Int) {
        let rel = pos - base
        pos += (alignment - rel % alignment) % alignment
    }

    /// Aligns to a constructed type's alignment (its largest member) before its first field.
    public func alignStruct(_ largestMember: Int) { align(largestMember) }

    /// Reads a 16-bit union discriminant and aligns to the union's alignment, where the selected
    /// arm begins. Mirror of `NDRWriter.unionDiscriminant16`.
    public func unionDiscriminant16(unionAlignment: Int = 4) throws -> UInt16 {
        let tag = try u16()
        align(unionAlignment)
        return tag
    }

    /// Reads a 32-bit union discriminant and aligns to the union's alignment.
    public func unionDiscriminant32(unionAlignment: Int = 4) throws -> UInt32 {
        let tag = try u32()
        align(unionAlignment)
        return tag
    }

    // MARK: primitives

    public func u8() throws -> UInt8 { try need(1); defer { pos += 1 }; return bytes[pos] }
    public func i8() throws -> Int8 { Int8(bitPattern: try u8()) }

    public func u16() throws -> UInt16 {
        align(2); try need(2); defer { pos += 2 }
        return UInt16(bytes[pos]) | (UInt16(bytes[pos + 1]) << 8)
    }
    public func i16() throws -> Int16 { Int16(bitPattern: try u16()) }

    public func u32() throws -> UInt32 {
        align(4); try need(4); defer { pos += 4 }
        var v: UInt32 = 0
        for i in 0..<4 { v |= UInt32(bytes[pos + i]) << (8 * i) }
        return v
    }
    public func i32() throws -> Int32 { Int32(bitPattern: try u32()) }

    public func u64() throws -> UInt64 {
        align(8); try need(8); defer { pos += 8 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(bytes[pos + i]) << (8 * i) }
        return v
    }
    public func i64() throws -> Int64 { Int64(bitPattern: try u64()) }

    public func enum16() throws -> UInt16 { try u16() }
    public func enum32() throws -> UInt32 { try u32() }

    /// Reads `n` raw bytes with no alignment.
    public func take(_ n: Int) throws -> [UInt8] {
        try need(n); defer { pos += n }
        return Array(bytes[pos..<pos + n])
    }

    // MARK: pointers

    /// Reads a unique pointer referent id; returns nil for NULL (id 0), otherwise the id.
    public func pointer() throws -> UInt32? {
        let id = try u32()
        return id == 0 ? nil : id
    }

    public func deferPointee(_ body: @escaping () throws -> Void) { deferred.append(body) }

    public func flushDeferred() throws {
        var i = 0
        while i < deferred.count {
            let job = deferred[i]
            i += 1
            try job()
        }
        deferred.removeAll(keepingCapacity: false)
    }

    // MARK: well-known constructed types

    public func guid() throws -> DCEUUID {
        align(4)
        return DCEUUID(bytes: try take(16))
    }

    public func fileTime() throws -> FileTime {
        let low = try u32(); let high = try u32()
        return FileTime(low: low, high: high)
    }

    public func oldLargeInteger() throws -> Int64 {
        let low = try u32(); let high = try u32()
        return Int64(bitPattern: UInt64(low) | (UInt64(high) << 32))
    }

    /// Reads a conformant array of UInt32 with a bound on the element count.
    public func conformantUInt32Array(maxElements: Int = 1 << 20) throws -> [UInt32] {
        let n = Int(try u32())
        guard n <= maxElements, n <= remaining / 4 else {
            throw NDRError(offset: offset, reason: "conformant u32 array count \(n) too large")
        }
        var out = [UInt32](); out.reserveCapacity(n)
        for _ in 0..<n { out.append(try u32()) }
        return out
    }

    /// Reads a conformant array of bytes (MaximumCount then bytes).
    public func conformantByteArray(maxBytes: Int = 1 << 24) throws -> [UInt8] {
        let n = Int(try u32())
        guard n <= maxBytes, n <= remaining else {
            throw NDRError(offset: offset, reason: "conformant byte array count \(n) too large")
        }
        return try take(n)
    }

    /// Reads an RPC_SID (hoisted conformance, then the fixed header and subauthorities).
    public func sid() throws -> SID {
        let maxCount = Int(try u32())
        let revision = try u8()
        guard revision == 1 else { throw NDRError(offset: offset, reason: "SID revision \(revision) is not 1") }
        let subCount = Int(try u8())
        guard subCount == maxCount else {
            throw NDRError(offset: offset, reason: "SID subauthority count \(subCount) != conformance \(maxCount)")
        }
        guard subCount <= SID.maxSubAuthorities else {
            throw NDRError(offset: offset, reason: "SID has \(subCount) subauthorities")
        }
        var authority: UInt64 = 0
        for _ in 0..<6 { authority = (authority << 8) | UInt64(try u8()) }
        var subs = [UInt32](); subs.reserveCapacity(subCount)
        for _ in 0..<subCount { subs.append(try u32()) }
        do {
            return try SID(identifierAuthority: authority, subAuthorities: subs)
        } catch {
            throw NDRError(offset: offset, reason: "invalid SID: \(error)")
        }
    }

    /// Reads a conformant+varying WCHAR array body and returns the string. `stripNUL` drops a
    /// single trailing NUL (for `[string]` bodies).
    public func varyingWCharBody(stripNUL: Bool) throws -> String {
        let maxCount = Int(try u32())
        let offsetField = Int(try u32())
        let actual = Int(try u32())
        guard offsetField == 0 else { throw NDRError(offset: offset, reason: "varying array Offset \(offsetField) != 0") }
        guard actual <= maxCount, actual <= remaining / 2 else {
            throw NDRError(offset: offset, reason: "varying WCHAR count \(actual) too large")
        }
        var units = [UInt16](); units.reserveCapacity(actual)
        for _ in 0..<actual {
            let lo = try u8(); let hi = try u8()
            units.append(UInt16(lo) | (UInt16(hi) << 8))
        }
        if stripNUL, units.last == 0 { units.removeLast() }
        return String(decoding: units, as: UTF16.self)
    }

    /// Reads the flat part of an RPC_UNICODE_STRING: Length, MaximumLength and the buffer
    /// pointer. The struct is 4-aligned (it holds a pointer), so this aligns to 4 first, which
    /// matters after a 16-bit field. The deferred buffer is read later with
    /// `unicodeStringBody(byteLength:present:)`, where NDR places the pointees.
    public func unicodeStringHeader() throws -> (byteLength: UInt16, present: Bool) {
        alignStruct(4)
        let len = try u16()
        let maxLen = try u16()
        guard len <= maxLen else {
            throw NDRError(offset: offset, reason: "RPC_UNICODE_STRING Length \(len) > MaximumLength \(maxLen)")
        }
        let present = try pointer() != nil
        return (len, present)
    }

    /// Reads the deferred WCHAR buffer of an RPC_UNICODE_STRING (nil when its pointer was NULL),
    /// trimmed to `byteLength` bytes.
    public func unicodeStringBody(byteLength: UInt16, present: Bool) throws -> String? {
        guard present else { return nil }
        let s = try varyingWCharBody(stripNUL: false)
        let units = Array(s.utf16)
        return String(decoding: units.prefix(Int(byteLength) / 2), as: UTF16.self)
    }

    /// An RPC_UNICODE_STRING whose buffer immediately follows its header (a top-level parameter,
    /// or the last pointer of a flat part being read in place).
    public func unicodeString() throws -> String? {
        let h = try unicodeStringHeader()
        return try unicodeStringBody(byteLength: h.byteLength, present: h.present)
    }
}
