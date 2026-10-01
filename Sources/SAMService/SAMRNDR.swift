import Foundation
import RPCKit
import MSPAC

/// A mutable reference cell for values that an NDR deferred-pointee closure fills in later.
final class Ref<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

// MARK: - Reading SAMR [in] parameters

extension NDRReader {
    /// Reads an `RPC_UNICODE_STRING` (§2.3.10): Length, MaximumLength and a unique buffer pointer.
    /// The counted (no-NUL) WCHAR body is deferred; call `flushDeferred()` before using the box.
    /// The struct is 4-aligned (it carries a pointer), so pad to 4 before the header.
    func samrUnicodeString() throws -> Ref<String?> {
        let box = Ref<String?>(nil)
        align(4)
        _ = try u16()                    // Length
        _ = try u16()                    // MaximumLength
        if try pointer() != nil {
            deferPointee { box.value = try self.varyingWCharBody(stripNUL: false) }
        }
        return box
    }

    /// Reads an `[string,unique] wchar_t*` (LPWSTR, e.g. a server name), deferring and discarding
    /// the NUL-terminated body (for use inside a struct/array, where referents defer).
    func samrSkipWideStringPointer() throws {
        if try pointer() != nil {
            deferPointee { _ = try self.varyingWCharBody(stripNUL: true) }
        }
    }

    /// Reads a top-level `[string,unique] wchar_t*` param whose referent is marshalled inline
    /// (immediately after the pointer), discarding it.
    func readWideStringPointerInline() throws {
        if try pointer() != nil { _ = try varyingWCharBody(stripNUL: true) }
    }

    /// Reads a top-level `RPC_UNICODE_STRING` param whose buffer referent is marshalled inline.
    func readUnicodeStringInline() throws -> String? {
        align(4)
        _ = try u16()                    // Length
        _ = try u16()                    // MaximumLength
        guard try pointer() != nil else { return nil }
        return try varyingWCharBody(stripNUL: false)
    }

    /// Reads a unique pointer to a fixed `count`-byte buffer (alignment 1: encrypted password /
    /// OWF blobs). The body is deferred; nil pointer → the box stays nil.
    func samrFixedBytesPointer(_ count: Int) throws -> Ref<[UInt8]?> {
        let box = Ref<[UInt8]?>(nil)
        if try pointer() != nil {
            deferPointee { box.value = try self.take(count) }
        }
        return box
    }

    /// Reads a conformant+varying byte array body (MaxCount, Offset, ActualCount, bytes).
    func samrConformantVaryingByteArray() throws -> [UInt8] {
        let maxCount = Int(try u32())
        let offset = Int(try u32())
        let actual = Int(try u32())
        guard offset == 0, actual <= maxCount, actual <= remaining else { throw SAMRError(.invalidParameter) }
        return try take(actual)
    }

    /// Reads a conformant+varying WCHAR array behind a unique pointer (`PRPC_UNICODE_STRING`'s
    /// pointee is itself an `RPC_UNICODE_STRING`; here the caller has already read the pointer).
    func samrConformantVaryingUInt16Array() throws -> [UInt16] {
        let maxCount = Int(try u32())
        let offset = Int(try u32())
        let actual = Int(try u32())
        guard offset == 0, actual <= maxCount, actual <= remaining / 2 else {
            throw SAMRError(.invalidParameter)
        }
        var out = [UInt16](); out.reserveCapacity(actual)
        for _ in 0..<actual { out.append(UInt16(try u8()) | (UInt16(try u8()) << 8)) }
        return out
    }
}

// MARK: - Writing SAMR [out] parameters

extension NDRWriter {
    /// Writes an `RPC_UNICODE_STRING` whose `MaximumLength` equals `Length` (SAMR's convention for
    /// returned names). nil → an all-zero empty string with a NULL buffer. The struct is 4-aligned
    /// (it carries a pointer), so pad to 4 before the header.
    func samrUnicodeString(_ s: String?) {
        align(4)
        unicodeString(s)
    }

    /// Writes an `RPC_UNICODE_STRING` as a top-level parameter, with its buffer referent inline
    /// (immediately after the flat header) rather than deferred. Used by request builders.
    func samrUnicodeStringInline(_ s: String?) {
        align(4)
        guard let s else { u16(0); u16(0); u32(0); return }
        let byteLen = s.utf16.count * 2
        u16(UInt16(byteLen)); u16(UInt16(byteLen))
        _ = uniquePointer(true)
        varyingWCharBody(s, includeNUL: false)
    }

    /// A unique pointer to an `RPC_SID` (`PRPC_SID`): the referent id now, the hoisted-conformance
    /// SID body deferred. nil → NULL.
    func samrSidPointer(_ sid: SID?) {
        guard let sid else { u32(0); return }
        _ = uniquePointer(true)
        deferPointee { self.sid(sid) }
    }

    /// A `SAMPR_ULONG_ARRAY` (§2.2.3.4): Count then a unique pointer to a conformant ULONG array.
    func samrULongArray(_ values: [UInt32]) {
        u32(UInt32(values.count))
        if values.isEmpty { u32(0); return }
        _ = uniquePointer(true)
        deferPointee { self.conformantUInt32Array(values) }
    }

    /// A `SAMPR_RETURNED_USTRING_ARRAY` (§2.2.3.8): Count then a unique pointer to a conformant
    /// array of `RPC_UNICODE_STRING` (each string's buffer deferred after the array's flat part).
    func samrReturnedUStringArray(_ names: [String?]) {
        u32(UInt32(names.count))
        if names.isEmpty { u32(0); return }
        _ = uniquePointer(true)
        deferPointee {
            self.u32(UInt32(names.count))    // conformant MaximumCount
            for n in names { self.samrUnicodeString(n) }
        }
    }

    /// A `PGROUP_MEMBERSHIP_ARRAY`-bearing `SAMPR_GET_GROUPS_BUFFER` body: MembershipCount then a
    /// unique pointer to a conformant array of {RelativeId, Attributes}.
    func samrGroupMembershipBuffer(_ rids: [UInt32], attributes: UInt32) {
        _ = uniquePointer(true)               // PSAMPR_GET_GROUPS_BUFFER
        deferPointee {
            self.u32(UInt32(rids.count))      // MembershipCount
            _ = self.uniquePointer(true)      // Groups pointer
            self.deferPointee {
                self.u32(UInt32(rids.count))  // conformant MaximumCount
                for rid in rids { self.u32(rid); self.u32(attributes) }
            }
        }
    }

    /// A `PSAMPR_GET_MEMBERS_BUFFER` (group members): MemberCount, then Members and Attributes,
    /// each a unique pointer to a conformant ULONG array.
    func samrGetMembersBuffer(rids: [UInt32], attributes: [UInt32]) {
        _ = uniquePointer(true)
        deferPointee {
            self.u32(UInt32(rids.count))          // MemberCount
            if rids.isEmpty { self.u32(0); self.u32(0); return }
            _ = self.uniquePointer(true)          // Members
            _ = self.uniquePointer(true)          // Attributes
            self.deferPointee { self.conformantUInt32Array(rids) }
            self.deferPointee { self.conformantUInt32Array(attributes) }
        }
    }

    /// A `SAMPR_PSID_ARRAY_OUT` (alias members): Count then a unique pointer to a conformant array
    /// of `PSAMPR_SID_INFORMATION` (each a unique pointer to an `RPC_SID`).
    func samrSidArrayOut(_ sids: [SID]) {
        u32(UInt32(sids.count))
        if sids.isEmpty { u32(0); return }
        _ = uniquePointer(true)                   // PSAMPR_SID_INFORMATION_ARRAY
        deferPointee {
            self.u32(UInt32(sids.count))          // conformant MaximumCount
            for _ in sids { _ = self.uniquePointer(true) }   // per-element SID pointers (flat)
            for s in sids { self.deferPointee { self.sid(s) } }
        }
    }
}
