import Foundation
import MSPAC
import RPCKit

// Small NDR32 building blocks shared by the three interfaces.
//
// Conventions used throughout this module:
// - `encode(_ w:)` writes a construct's flat part and *defers* its pointees on the writer's FIFO
//   queue. The caller flushes after each top-level parameter, which is where NDR places a
//   parameter's pointees. Every structure here has at most one pointer chain per nesting level,
//   so FIFO order equals NDR's depth-first order.
// - `decode(_ r:)` reads sequentially; decoders read a construct's flat part and then its
//   pointees in NDR order, so they are only called where the construct's pointees come next
//   (top-level parameters and whole arrays).

/// The flat part of an `RPC_UNICODE_STRING`: byte length and whether the buffer pointer is set.
struct UnicodeStringHeader {
    var byteLength: UInt16
    var present: Bool
}

extension NDRReader {
    /// `RPC_UNICODE_STRING` is 4-aligned (it holds a pointer). RPCKit's `unicodeStringHeader`
    /// now aligns to 4 itself; the explicit `align(4)` here is redundant and harmless.
    func unicodeStringFlat() throws -> UnicodeStringHeader {
        align(4)
        let h = try unicodeStringHeader()
        return UnicodeStringHeader(byteLength: h.byteLength, present: h.present)
    }

    /// Reads the deferred buffer of an `RPC_UNICODE_STRING` (nil when the pointer was NULL),
    /// trimmed to `Length` bytes.
    func unicodeStringBody(_ h: UnicodeStringHeader) throws -> String? {
        guard h.present else { return nil }
        let s = try varyingWCharBody(stripNUL: false)
        let units = Array(s.utf16)
        let n = min(units.count, Int(h.byteLength) / 2)
        return String(decoding: units[0..<n], as: UTF16.self)
    }

    /// A complete `RPC_UNICODE_STRING` whose buffer immediately follows (top-level use).
    func unicodeStringInline() throws -> String? {
        try unicodeStringBody(try unicodeStringFlat())
    }

    /// A `[string, unique] wchar_t*` whose body immediately follows (NUL stripped).
    func stringPointerInline() throws -> String? {
        guard try pointer() != nil else { return nil }
        return try varyingWCharBody(stripNUL: true)
    }

    /// A `[string] wchar_t*` reference (never NULL; no referent id) body.
    func refStringInline() throws -> String {
        try varyingWCharBody(stripNUL: true)
    }

    /// A unique pointer to an `RPC_SID` whose body immediately follows.
    func sidPointerInline() throws -> SID? {
        guard try pointer() != nil else { return nil }
        return try sid()
    }

    /// A conformant-array count with a sanity bound (NDR `[range]` or a resource guard).
    func boundedCount(max: Int) throws -> Int {
        let n = Int(try u32())
        guard n <= max else { throw NDRError(offset: offset, reason: "count \(n) exceeds \(max)") }
        return n
    }
}

extension NDRWriter {
    /// `RPC_UNICODE_STRING` at its natural 4-byte alignment. RPCKit's `unicodeString` now aligns
    /// to 4 itself (it used to pad only to 2, misplacing it after `SID_NAME_USE` or a union tag);
    /// the explicit `align(4)` here is redundant and harmless.
    func rpcUnicodeString(_ s: String?) {
        align(4)
        unicodeString(s)
    }

    /// A unique pointer to an `RPC_SID`, body deferred.
    func sidPointer(_ sid: SID?) {
        guard let sid else { u32(0); return }
        _ = uniquePointer(true)
        deferPointee { [weak self] in self?.sid(sid) }
    }
}
