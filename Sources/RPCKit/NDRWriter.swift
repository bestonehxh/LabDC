import Foundation
import MSPAC

/// NDR32 (DCE 1.1 / MS-RPCE transfer syntax `8a885d04…` v2.0) little-endian marshaller.
///
/// Alignment is measured **relative to the start of the stub** (the first byte this writer
/// produces), as MS-RPCE requires; a `NDRWriter` therefore always begins at a natural
/// 8-byte boundary in the enclosing PDU.
///
/// Pointers are two-phase. In the *flat* pass the referent id (or 0 for NULL) is written in
/// place; the pointee *body* is enqueued and emitted later, in pointer order, by
/// `flushDeferred()`. A pointee that itself contains pointers enqueues its own pointees,
/// which follow it — the FIFO queue reproduces NDR's "deferred referents in order" rule.
/// Referent ids are the Windows sequence `0x00020000, 0x00020004, …`; receivers only test
/// for zero, so the exact ids never matter for interoperability but match Windows byte for byte.
public final class NDRWriter: @unchecked Sendable {
    private var buf: [UInt8] = []
    private var nextReferent: UInt32 = 0x0002_0000
    private var deferred: [() -> Void] = []

    public init() {}

    /// The marshalled bytes. Call `flushDeferred()` first if any pointers were written.
    public var bytes: [UInt8] { buf }

    /// Current length, i.e. the offset (relative to the stub start) of the next byte.
    public var count: Int { buf.count }

    // MARK: alignment

    /// Pads with zero bytes until the length is a multiple of `alignment`.
    public func align(_ alignment: Int) {
        let pad = (alignment - buf.count % alignment) % alignment
        if pad > 0 { buf.append(contentsOf: repeatElement(0, count: pad)) }
    }

    /// Aligns to a constructed type's alignment before its first field. NDR aligns a structure
    /// (and a union arm) to its **largest member**: 4 for anything holding a pointer, a u32, an
    /// enum32 or a conformance count; 8 for a u64/hyper member; 2 for u16-only structs.
    public func alignStruct(_ largestMember: Int) { align(largestMember) }

    /// A non-encapsulated union's 16-bit discriminant (`[switch_type(unsigned short)]`, e.g. an
    /// enum16 info level) followed by alignment to the union's alignment, where the selected
    /// arm begins. The discriminant itself aligns only to 2; the arm aligns to `unionAlignment`,
    /// the largest alignment among **all** arms (4 whenever any arm has a pointer or u32), so a
    /// lone u16 arm still starts 4-aligned. Confirmed against impacket's `NDRUNION`.
    public func unionDiscriminant16(_ tag: UInt16, unionAlignment: Int = 4) {
        u16(tag)
        align(unionAlignment)
    }

    /// A 32-bit discriminant (`[switch_type(unsigned long)]` / enum32) followed by alignment to
    /// the union's alignment.
    public func unionDiscriminant32(_ tag: UInt32, unionAlignment: Int = 4) {
        u32(tag)
        align(unionAlignment)
    }

    // MARK: primitives

    public func u8(_ v: UInt8) { buf.append(v) }
    public func i8(_ v: Int8) { buf.append(UInt8(bitPattern: v)) }

    public func u16(_ v: UInt16) {
        align(2)
        buf.append(UInt8(truncatingIfNeeded: v))
        buf.append(UInt8(truncatingIfNeeded: v >> 8))
    }
    public func i16(_ v: Int16) { u16(UInt16(bitPattern: v)) }

    public func u32(_ v: UInt32) {
        align(4)
        for s in stride(from: 0, to: 32, by: 8) { buf.append(UInt8(truncatingIfNeeded: v >> s)) }
    }
    public func i32(_ v: Int32) { u32(UInt32(bitPattern: v)) }

    public func u64(_ v: UInt64) {
        align(8)
        for s in stride(from: 0, to: 64, by: 8) { buf.append(UInt8(truncatingIfNeeded: v >> s)) }
    }
    public func i64(_ v: Int64) { u64(UInt64(bitPattern: v)) }

    /// A 16-bit NDR enum.
    public func enum16(_ v: UInt16) { u16(v) }
    /// A 32-bit ("v1") NDR enum.
    public func enum32(_ v: UInt32) { u32(v) }

    /// Raw, already-aligned bytes (no alignment applied).
    public func raw(_ b: [UInt8]) { buf.append(contentsOf: b) }

    /// A fixed-size array of bytes (no conformance/varying header, natural alignment 1).
    public func fixedBytes(_ b: [UInt8]) { buf.append(contentsOf: b) }

    // MARK: pointers

    /// Allocates the next referent id.
    public func newReferent() -> UInt32 {
        defer { nextReferent &+= 4 }
        return nextReferent
    }

    /// Writes a top-level or embedded unique/`[unique]` pointer: a fresh referent id when
    /// `present`, otherwise 0. Use `deferPointee` to enqueue its body.
    @discardableResult
    public func uniquePointer(_ present: Bool) -> Bool {
        u32(present ? newReferent() : 0)
        return present
    }

    /// Writes a reference (`[ref]`) pointer, which is never NULL and still carries a referent id.
    public func referencePointer() { u32(newReferent()) }

    /// Enqueues a pointee body to be emitted by `flushDeferred()`, in call order.
    public func deferPointee(_ body: @escaping () -> Void) { deferred.append(body) }

    /// Emits every enqueued pointee body, honouring nested deferrals (FIFO).
    public func flushDeferred() {
        var i = 0
        while i < deferred.count {
            let job = deferred[i]
            i += 1
            job()
        }
        deferred.removeAll(keepingCapacity: false)
    }

    // MARK: well-known constructed types

    /// GUID / UUID as the IDL `struct { u32; u16; u16; byte[8]; }` (MS-DTYP §2.3.4.2), the
    /// same layout as `DCEUUID`'s wire bytes. 4-byte aligned.
    public func guid(_ g: DCEUUID) {
        align(4)
        raw(g.bytes)
    }

    /// FILETIME (MS-DTYP §2.3.3): dwLowDateTime, dwHighDateTime. Also serves OLD_LARGE_INTEGER.
    public func fileTime(_ t: FileTime) {
        u32(t.low)
        u32(t.high)
    }

    /// A 64-bit signed value written as two 32-bit halves (`OLD_LARGE_INTEGER`).
    public func oldLargeInteger(_ v: Int64) {
        let u = UInt64(bitPattern: v)
        u32(UInt32(truncatingIfNeeded: u))
        u32(UInt32(truncatingIfNeeded: u >> 32))
    }

    /// A conformant array of UInt32 (MaximumCount then elements). Used by RPC_SID subauthorities.
    public func conformantUInt32Array(_ elems: [UInt32]) {
        u32(UInt32(elems.count))
        for e in elems { u32(e) }
    }

    /// A conformant array of bytes (MaximumCount then the bytes). Used for self-relative
    /// SECURITY_DESCRIPTOR blobs and other `[size_is] byte*` payloads.
    public func conformantByteArray(_ b: [UInt8]) {
        u32(UInt32(b.count))
        raw(b)
    }

    /// RPC_SID (MS-DTYP §2.4.2.3): a struct whose trailing conformant array of subauthorities
    /// hoists its MaximumCount to the front of the struct.
    public func sid(_ s: SID) {
        u32(UInt32(s.subAuthorities.count))       // hoisted conformance (MaximumCount)
        u8(s.revision)
        u8(UInt8(s.subAuthorities.count))
        for shift in stride(from: 40, through: 0, by: -8) {
            u8(UInt8(truncatingIfNeeded: s.identifierAuthority >> UInt64(shift)))
        }
        for sub in s.subAuthorities { u32(sub) }
    }

    /// A conformant+varying array of WCHARs for a counted (no NUL) string body: MaximumCount,
    /// Offset(0), ActualCount, then the UTF-16LE code units. This is the deferred body of an
    /// `RPC_UNICODE_STRING` buffer pointer; see `unicodeString`.
    public func varyingWCharBody(_ s: String, includeNUL: Bool) {
        var units = Array(s.utf16)
        if includeNUL { units.append(0) }
        u32(UInt32(units.count))   // MaximumCount
        u32(0)                     // Offset
        u32(UInt32(units.count))   // ActualCount
        for u in units {
            buf.append(UInt8(truncatingIfNeeded: u))
            buf.append(UInt8(truncatingIfNeeded: u >> 8))
        }
    }

    /// RPC_UNICODE_STRING (MS-DTYP §2.3.10): Length, MaximumLength (byte counts) and a unique
    /// pointer to the WCHAR buffer, whose conformant+varying body is deferred. A nil string is
    /// Length 0, MaximumLength 0 and a NULL buffer. `maximumIsLengthPlusTerminator` reproduces
    /// the Windows convention some fields use (MaximumLength = Length + 2).
    ///
    /// The struct holds a pointer, so its NDR alignment is 4: the header is 4-aligned even when
    /// it follows a 16-bit field (e.g. `SID_NAME_USE`, a union discriminant).
    public func unicodeString(_ s: String?,
                              maximumIsLengthPlusTerminator: Bool = false) {
        alignStruct(4)
        guard let s else {
            u16(0); u16(0); u32(0)
            return
        }
        let byteLen = s.utf16.count * 2
        u16(UInt16(byteLen))
        u16(UInt16(maximumIsLengthPlusTerminator ? byteLen + 2 : byteLen))
        let present = uniquePointer(true)
        if present {
            deferPointee { [weak self] in self?.varyingWCharBody(s, includeNUL: false) }
        }
    }

    /// A standalone `[string,unique] wchar_t*` (a NUL-terminated conformant+varying array behind
    /// a unique pointer), the form used by many `[in,string]` parameters. nil → NULL pointer.
    public func stringPointer(_ s: String?) {
        guard let s else { u32(0); return }
        _ = uniquePointer(true)
        deferPointee { [weak self] in self?.varyingWCharBody(s, includeNUL: true) }
    }
}
