import Foundation
import KerberosASN1
import KerberosCrypto

/// MIT/Heimdal keytab files, format version 0x0502 (big-endian throughout).
///
/// ```
/// file   = 0x05 0x02 entry*
/// entry  = int32 size, then `size` bytes:
///          uint16 num_components, counted realm, counted component * n,
///          uint32 name_type, uint32 timestamp, uint8 kvno,
///          uint16 keytype, uint16 keylen, key bytes,
///          [uint32 kvno]      -- 32-bit kvno extension, always written
/// counted = uint16 length + bytes
/// ```
/// A negative `size` marks a deleted slot of `-size` bytes (skipped on read).
public enum Keytab {
    public struct Entry: Sendable, Equatable {
        public var realm: String
        public var components: [String]
        public var nameType: UInt32
        public var timestamp: UInt32
        public var kvno: UInt32
        public var key: KerberosKey

        public init(realm: String, components: [String], nameType: UInt32, timestamp: UInt32, kvno: UInt32, key: KerberosKey) {
            self.realm = realm
            self.components = components
            self.nameType = nameType
            self.timestamp = timestamp
            self.kvno = kvno
            self.key = key
        }

        /// `host/dc1.lab.sheep@LAB.SHEEP`
        public var principal: String { components.joined(separator: "/") + "@" + realm }
    }

    /// One entry per key of every principal.
    public static func entries(for principals: [Principal], timestamp: Date = Date()) -> [Entry] {
        let ts = UInt32(clamping: Int64(timestamp.timeIntervalSince1970))
        return principals.flatMap { p in
            p.keys.map { key in
                Entry(realm: p.realm, components: p.name.nameString, nameType: UInt32(bitPattern: p.name.nameType),
                      timestamp: ts, kvno: p.kvno, key: key)
            }
        }
    }

    /// Serializes `entries` as a 0x0502 keytab.
    public static func encode(_ entries: [Entry]) throws -> [UInt8] {
        var out: [UInt8] = [0x05, 0x02]
        for e in entries {
            var body: [UInt8] = []
            guard e.components.count <= Int(UInt16.max) else { throw KDCError.invalidKeytab("too many components") }
            body.appendBE(UInt16(e.components.count))
            try body.appendCounted(Array(e.realm.utf8))
            for c in e.components { try body.appendCounted(Array(c.utf8)) }
            body.appendBE(e.nameType)
            body.appendBE(e.timestamp)
            body.append(UInt8(truncatingIfNeeded: e.kvno))
            body.appendBE(UInt16(bitPattern: Int16(truncatingIfNeeded: e.key.type.rawValue)))
            try body.appendCounted(e.key.bytes)
            body.appendBE(e.kvno)
            guard body.count <= Int(Int32.max) else { throw KDCError.invalidKeytab("entry too large") }
            out.appendBE(UInt32(body.count))
            out += body
        }
        return out
    }

    /// Parses a 0x0502 keytab (entries with unknown enctypes are skipped).
    public static func parse(_ bytes: [UInt8]) throws -> [Entry] {
        guard bytes.count >= 2, bytes[0] == 0x05, bytes[1] == 0x02 else {
            throw KDCError.invalidKeytab("not a version 0x0502 keytab")
        }
        var entries: [Entry] = []
        var r = Reader(bytes: bytes, offset: 2)
        while !r.atEnd {
            let size = Int32(bitPattern: try r.u32())
            if size < 0 { try r.skip(Int(-Int64(size))); continue }
            let end = r.offset + Int(size)
            guard end <= bytes.count else { throw KDCError.invalidKeytab("entry runs past end of file") }
            var e = Reader(bytes: Array(bytes[r.offset..<end]), offset: 0)
            r.offset = end
            let n = Int(try e.u16())
            let realm = try e.string()
            var components: [String] = []
            for _ in 0..<n { components.append(try e.string()) }
            let nameType = try e.u32()
            let timestamp = try e.u32()
            var kvno = UInt32(try e.u8())
            let keyType = Int32(Int16(bitPattern: try e.u16()))
            let keyBytes = try e.counted()
            if e.remaining >= 4 { kvno = try e.u32() }
            guard let type = EncryptionType(rawValue: keyType) else { continue }
            let key: KerberosKey
            do { key = try KerberosKey(type: type, bytes: keyBytes) } catch {
                throw KDCError.invalidKeytab("\(error)")
            }
            entries.append(Entry(realm: realm, components: components, nameType: nameType,
                                 timestamp: timestamp, kvno: kvno, key: key))
        }
        return entries
    }

    /// Writes the keytab with mode 0600.
    public static func write(_ entries: [Entry], to url: URL) throws {
        let bytes = try encode(entries)
        do {
            try Data(bytes).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw KDCError.io("cannot write \(url.path): \(error.localizedDescription)")
        }
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset: Int
        var atEnd: Bool { offset >= bytes.count }
        var remaining: Int { bytes.count - offset }

        mutating func take(_ n: Int) throws -> ArraySlice<UInt8> {
            guard n >= 0, remaining >= n else { throw KDCError.invalidKeytab("truncated") }
            defer { offset += n }
            return bytes[offset..<(offset + n)]
        }
        mutating func skip(_ n: Int) throws { _ = try take(n) }
        mutating func u8() throws -> UInt8 { try take(1).first! }
        mutating func u16() throws -> UInt16 { try take(2).reduce(0) { $0 << 8 | UInt16($1) } }
        mutating func u32() throws -> UInt32 { try take(4).reduce(0) { $0 << 8 | UInt32($1) } }
        mutating func counted() throws -> [UInt8] { Array(try take(Int(try u16()))) }
        mutating func string() throws -> String {
            guard let s = String(validating: try counted(), as: UTF8.self) else { throw KDCError.invalidKeytab("name is not UTF-8") }
            return s
        }
    }
}

extension [UInt8] {
    mutating func appendBE(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xFF)) }
    mutating func appendBE(_ v: UInt32) {
        append(UInt8(v >> 24)); append(UInt8((v >> 16) & 0xFF)); append(UInt8((v >> 8) & 0xFF)); append(UInt8(v & 0xFF))
    }
    mutating func appendCounted(_ bytes: [UInt8]) throws {
        guard bytes.count <= Int(UInt16.max) else { throw KDCError.invalidKeytab("field longer than 65535 bytes") }
        appendBE(UInt16(bytes.count))
        self += bytes
    }
}
