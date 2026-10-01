/// Little-endian writer for netlogon structures with the RFC 1035 name compression of
/// MS-ADTS §6.3.7.
///
/// Compression works like Samba's `ndr_push_nbt_string`: each name is written label by
/// label. Before each label the writer checks whether the rest of the name (that label and
/// everything after it) was written before, compared case-sensitively. If it was, the writer
/// emits a 2-byte pointer `0xC000 | offset` and the name ends there. Otherwise it writes the
/// label and records where that rest started. Offsets count from the first byte of the
/// structure. A name that is never cut short by a pointer ends with a zero byte, and so does
/// the empty name (a single `00`).
struct NetlogonWriter {
    private(set) var bytes: [UInt8] = []
    /// The rest of a name (case-sensitive) → offset where it was first written.
    private var written: [String: Int] = [:]

    mutating func u8(_ v: UInt8) { bytes.append(v) }
    mutating func u16(_ v: UInt16) { bytes += [UInt8(v & 0xFF), UInt8(v >> 8)] }
    mutating func u32(_ v: UInt32) { for i in 0..<4 { bytes.append(UInt8((v >> (8 * UInt32(i))) & 0xFF)) } }
    mutating func raw(_ b: [UInt8]) { bytes += b }

    /// NUL-terminated UTF-16LE (`nstring` of the NT40 and V5 structures).
    mutating func utf16z(_ s: String) {
        for unit in s.utf16 { u16(unit) }
        u16(0)
    }

    /// A compressed UTF-8 DNS-style name. A trailing dot is dropped; labels longer than 63
    /// bytes are cut to 63 (they cannot be expressed).
    mutating func name(_ s: String) {
        var rest = s.hasSuffix(".") ? String(s.dropLast()) : s
        while !rest.isEmpty {
            if let offset = written[rest] {
                u16be(0xC000 | UInt16(offset))
                return
            }
            if bytes.count <= 0x3FFF { written[rest] = bytes.count }
            let label: Substring
            if let dot = rest.firstIndex(of: ".") {
                label = rest[..<dot]
                rest = String(rest[rest.index(after: dot)...])
            } else {
                label = rest[...]
                rest = ""
            }
            let utf8 = Array(label.utf8.prefix(63))
            u8(UInt8(utf8.count))
            raw(utf8)
        }
        u8(0)
    }

    private mutating func u16be(_ v: UInt16) { bytes += [UInt8(v >> 8), UInt8(v & 0xFF)] }
}

/// Reader for netlogon structures (the inverse of `NetlogonWriter`; used by tests and for
/// diagnostics). Pointers must point strictly backwards, so loops are impossible.
struct NetlogonReader {
    let bytes: [UInt8]
    private(set) var offset = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var remaining: Int { bytes.count - offset }

    mutating func u8(_ what: String) throws -> UInt8 {
        guard remaining >= 1 else { throw NetlogonError.truncated(what) }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func u16(_ what: String) throws -> UInt16 {
        guard remaining >= 2 else { throw NetlogonError.truncated(what) }
        defer { offset += 2 }
        return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
    }

    mutating func u32(_ what: String) throws -> UInt32 {
        guard remaining >= 4 else { throw NetlogonError.truncated(what) }
        defer { offset += 4 }
        return (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << (8 * UInt32($1)) }
    }

    mutating func raw(_ n: Int, _ what: String) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw NetlogonError.truncated(what) }
        defer { offset += n }
        return Array(bytes[offset..<offset + n])
    }

    mutating func utf16z(_ what: String) throws -> String {
        var units: [UInt16] = []
        while true {
            let u = try u16(what)
            if u == 0 { break }
            units.append(u)
        }
        return String(decoding: units, as: UTF16.self)
    }

    /// A compressed name at the cursor; the cursor ends after the terminator or first pointer.
    mutating func name(_ what: String) throws -> String {
        var labels: [String] = []
        var position = offset
        var jumped = false
        var limit = position   // pointers must go strictly before this
        while true {
            guard position < bytes.count else { throw NetlogonError.truncated(what) }
            let len = bytes[position]
            if len == 0 {
                if !jumped { offset = position + 1 }
                break
            }
            switch len & 0xC0 {
            case 0xC0:
                guard position + 1 < bytes.count else { throw NetlogonError.truncated(what) }
                let target = Int(len & 0x3F) << 8 | Int(bytes[position + 1])
                guard target < limit else { throw NetlogonError.badName("\(what): pointer to \(target) is not backwards") }
                if !jumped { offset = position + 2 }
                jumped = true
                limit = target
                position = target
            case 0x00:
                let n = Int(len)
                guard position + 1 + n <= bytes.count else { throw NetlogonError.truncated(what) }
                labels.append(String(decoding: bytes[position + 1..<position + 1 + n], as: UTF8.self))
                position += 1 + n
            default:
                throw NetlogonError.badName("\(what): label type 0x\(String(len, radix: 16))")
            }
        }
        return labels.joined(separator: ".")
    }
}
