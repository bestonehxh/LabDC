import Foundation
import RPCKit
import MSPAC

/// NDR (NDR32) read/write helpers for the MS-NRPC wire types, layered on RPCKit's `NDRReader`/
/// `NDRWriter`. Verified byte-for-byte against impacket's `impacket.dcerpc.v5.nrpc` marshalling.
///
/// Conventions confirmed against impacket:
/// - `NDRENUM` (e.g. `NETLOGON_SECURE_CHANNEL_TYPE`, the info-class discriminants) is **16-bit**.
/// - `RPC_UNICODE_STRING` is 4-aligned (a struct with a pointer); we align(4) before each header
///   because RPCKit's `unicodeString` only aligns to 2. Empty strings still carry a non-null buffer.
/// - `LPWSTR`/`WSTR` bodies are NUL-terminated (`ActualCount` counts the NUL); `RPC_UNICODE_STRING`
///   bodies are counted (no NUL).
/// - Top-level pointer parameters (and top-level union-arm pointers) place their pointee **inline**
///   right after the referent; pointers embedded in a struct **defer** their bodies to after the
///   enclosing construction, in field order (RPCKit's FIFO deferral reproduces this).
enum NLNDR {

    // MARK: readers

    /// A conformant+varying wide-string body: MaximumCount, Offset(0), ActualCount, then the units.
    /// `stripNUL` drops a single trailing NUL (LPWSTR/WSTR bodies carry one; counted strings do not).
    static func readWCharBody(_ r: NDRReader, stripNUL: Bool) throws -> String {
        let maxCount = Int(try r.u32())
        _ = try r.u32()                        // Offset
        let actual = Int(try r.u32())
        guard actual <= maxCount, actual <= r.remaining / 2 + 1 else {
            throw NDRError(offset: r.offset, reason: "wchar body count \(actual) too large")
        }
        var units = [UInt16](); units.reserveCapacity(actual)
        for _ in 0..<actual {
            let lo = try r.u8(); let hi = try r.u8()
            units.append(UInt16(lo) | (UInt16(hi) << 8))
        }
        if stripNUL, units.last == 0 { units.removeLast() }
        return String(decoding: units, as: UTF16.self)
    }

    /// The raw bytes of a conformant+varying WCHAR body, for `RPC_UNICODE_STRING`s that carry a
    /// binary blob instead of text (`NETLOGON_WORKSTATION_INFO.OsVersion` = an `OSVERSIONINFOEXW`).
    static func readWCharBodyBytes(_ r: NDRReader) throws -> [UInt8] {
        let maxCount = Int(try r.u32())
        _ = try r.u32()                        // Offset
        let actual = Int(try r.u32())
        guard actual <= maxCount, actual * 2 <= r.remaining else {
            throw NDRError(offset: r.offset, reason: "wchar body count \(actual) too large")
        }
        return try r.take(actual * 2)
    }

    /// A conformant+varying byte body (the RPC ANSI `STRING`/`STR` buffer).
    static func readByteBody(_ r: NDRReader) throws -> [UInt8] {
        let maxCount = Int(try r.u32())
        _ = try r.u32()                        // Offset
        let actual = Int(try r.u32())
        guard actual <= maxCount, actual <= r.remaining else {
            throw NDRError(offset: r.offset, reason: "byte body count \(actual) too large")
        }
        return try r.take(actual)
    }

    /// An embedded WSTR handle (no pointer): the conformant+varying NUL-terminated body inline.
    static func readInlineWSTR(_ r: NDRReader) throws -> String {
        try readWCharBody(r, stripNUL: true)
    }

    /// A top-level `LPWSTR` parameter: referent id then, if non-null, the WSTR body inline.
    static func readTopLevelString(_ r: NDRReader) throws -> String? {
        let ref = try r.u32()
        if ref == 0 { return nil }
        return try readWCharBody(r, stripNUL: true)
    }

    /// A top-level `PGUID`: referent then, if non-null, the 16-byte GUID inline.
    static func readTopLevelGUID(_ r: NDRReader) throws -> DCEUUID? {
        let ref = try r.u32()
        if ref == 0 { return nil }
        return try r.guid()
    }

    /// An `RPC_UNICODE_STRING`/RPC ANSI `STRING` header: two u16 length words and a referent.
    /// Returns whether the buffer pointer is present (non-null). 4-aligned.
    static func readStringHeader(_ r: NDRReader) throws -> Bool {
        r.align(4)
        _ = try r.u16()                        // Length (or MaximumLength for ANSI STRING; equal here)
        _ = try r.u16()                        // MaximumLength (or Length)
        return try r.u32() != 0
    }

    // MARK: writers

    /// Writes a top-level (or union-arm) non-null referent id.
    static func writeReferent(_ w: NDRWriter) { _ = w.uniquePointer(true) }

    /// Writes an `RPC_UNICODE_STRING` (4-aligned). `nil` → NULL buffer; "" → non-null empty buffer.
    static func writeUnicodeString(_ w: NDRWriter, _ s: String?) {
        w.align(4)
        w.unicodeString(s)
    }

    /// Writes an `RPC_UNICODE_STRING` header whose buffer body is **appended to `bodies`** instead of
    /// RPCKit's writer-wide deferral queue. Used for structs inside a deferred conformant array
    /// (`NETLOGON_DOMAIN_INFO.TrustedDomains`): NDR emits the pointees embedded in an array right
    /// after that array, before the enclosing struct's next deferred pointee, while the writer's
    /// FIFO would push them behind every pointee already queued (breadth-first).
    ///
    /// `large` reproduces Samba's `lsa_StringLarge` (what `NETLOGON_ONE_DOMAIN_INFO` and
    /// `NETLOGON_DOMAIN_INFO` use): MaximumLength = Length + 2 and the body's MaximumCount = the
    /// character count + 1 (room for a terminator that is not sent: ActualCount = the characters).
    /// A nil string is Length 0, MaximumLength 0 and a NULL buffer in both forms.
    static func writeUnicodeString(_ w: NDRWriter, _ s: String?, large: Bool = false, bodies: inout [() -> Void]) {
        w.align(4)
        guard let s else { w.u16(0); w.u16(0); w.u32(0); return }
        let units = Array(s.utf16)
        let byteLen = UInt16(units.count * 2)
        w.u16(byteLen); w.u16(large ? byteLen + 2 : byteLen)
        _ = w.uniquePointer(true)
        bodies.append {
            w.u32(UInt32(units.count + (large ? 1 : 0)))   // MaximumCount
            w.u32(0)                                        // Offset
            w.u32(UInt32(units.count))                      // ActualCount
            var bytes = [UInt8](); bytes.reserveCapacity(units.count * 2)
            for u in units { bytes.append(UInt8(truncatingIfNeeded: u)); bytes.append(UInt8(truncatingIfNeeded: u >> 8)) }
            w.raw(bytes)
        }
    }

    /// An `RPC_UNICODE_STRING` that carries a binary blob (`TrustExtension`): Length =
    /// MaximumLength = the byte count, body = MaximumCount/Offset/ActualCount in WCHARs + the bytes.
    /// `nil` → Length 0, MaximumLength 0, NULL buffer. The blob length must be even.
    static func writeBlobUnicodeString(_ w: NDRWriter, _ blob: [UInt8]?, bodies: inout [() -> Void]) {
        w.align(4)
        guard let blob else { w.u16(0); w.u16(0); w.u32(0); return }
        precondition(blob.count % 2 == 0, "a UNICODE_STRING blob is a whole number of WCHARs")
        w.u16(UInt16(blob.count)); w.u16(UInt16(blob.count))
        _ = w.uniquePointer(true)
        bodies.append {
            let units = UInt32(blob.count / 2)
            w.u32(units); w.u32(0); w.u32(units)
            w.raw(blob)
        }
    }
}
