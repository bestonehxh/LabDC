import Foundation

/// A few DER encoders for the structures swift-certificates does not build (CRLs, CRL
/// distribution points, the Microsoft certificate-template extension).
enum DERWriter {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func sequence(_ items: [[UInt8]]) -> [UInt8] { tlv(0x30, items.flatMap { $0 }) }

    static let null: [UInt8] = [0x05, 0x00]

    static func boolean(_ v: Bool) -> [UInt8] { [0x01, 0x01, v ? 0xFF : 0x00] }

    /// A non-negative INTEGER from big-endian magnitude bytes (leading zeros trimmed, a 0x00 pad
    /// added when the top bit is set).
    static func unsignedInteger(_ magnitude: [UInt8]) -> [UInt8] {
        var bytes = Array(magnitude.drop(while: { $0 == 0 }))
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return tlv(0x02, bytes)
    }

    static func integer(_ value: Int64) -> [UInt8] {
        precondition(value >= 0)
        var bytes: [UInt8] = []
        var v = value
        repeat { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 } while v > 0
        return unsignedInteger(bytes)
    }

    static func enumerated(_ value: Int) -> [UInt8] {
        var content = integer(Int64(value))
        content[0] = 0x0A
        return content
    }

    static func octetString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x04, bytes) }

    static func bitString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + bytes) }

    static func oid(_ dotted: String) -> [UInt8] {
        let arcs = dotted.split(separator: ".").map { UInt64($0) ?? 0 }
        precondition(arcs.count >= 2, "OID \(dotted)")
        var body: [UInt8] = base128(arcs[0] * 40 + arcs[1])
        for arc in arcs.dropFirst(2) { body += base128(arc) }
        return tlv(0x06, body)
    }

    private static func base128(_ value: UInt64) -> [UInt8] {
        var out: [UInt8] = [UInt8(value & 0x7F)]
        var v = value >> 7
        while v > 0 {
            out.insert(UInt8(v & 0x7F) | 0x80, at: 0)
            v >>= 7
        }
        return out
    }

    /// UTCTime before 2050, GeneralizedTime from 2050 on (RFC 5280 §4.1.2.5).
    static func time(_ date: Date) -> [UInt8] {
        var t = time_t(date.timeIntervalSince1970.rounded(.down))
        var tm = tm()
        gmtime_r(&t, &tm)
        let year = Int(tm.tm_year) + 1900
        let rest = String(format: "%02d%02d%02d%02d%02dZ", tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
        if year < 2050 {
            return tlv(0x17, Array((String(format: "%02d", year % 100) + rest).utf8))
        }
        return tlv(0x18, Array((String(format: "%04d", year) + rest).utf8))
    }

    /// `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
    static func `extension`(oid dotted: String, critical: Bool = false, value: [UInt8]) -> [UInt8] {
        sequence([oid(dotted)] + (critical ? [boolean(true)] : []) + [octetString(value)])
    }

    /// `GeneralName` uniformResourceIdentifier (`[6] IMPLICIT IA5String`).
    static func uri(_ text: String) -> [UInt8] { tlv(0x86, Array(text.utf8)) }
}
