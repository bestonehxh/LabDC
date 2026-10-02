import Foundation

// GSS-TSIG wire formats: TKEY (RFC 2930 §2) and TSIG (RFC 8945 §4) RDATA, the TSIG digest
// (RFC 8945 §4.3) and the raw-message helpers signing needs. The MAC covers the message bytes as
// they travelled (name compression included), so verification works on the received bytes, never
// on a re-encoding.

/// TSIG / TKEY error codes (RFC 8945 §3, RFC 2930 §2.6). In a TSIG failure the message RCODE is
/// NOTAUTH and the code travels in the TSIG (or TKEY) RR.
public enum DNSTSIGError: UInt16, Sendable {
    case noError = 0
    case badSig = 16
    case badKey = 17
    case badTime = 18
    case badMode = 19
    case badName = 20
    case badAlg = 21
    case badTrunc = 22

    public var label: String {
        switch self {
        case .noError: "NOERROR"
        case .badSig: "BADSIG"
        case .badKey: "BADKEY"
        case .badTime: "BADTIME"
        case .badMode: "BADMODE"
        case .badName: "BADNAME"
        case .badAlg: "BADALG"
        case .badTrunc: "BADTRUNC"
        }
    }
}

/// Uncompressed names inside TSIG / TKEY RDATA (RFC 8945 §4.2: the algorithm name MUST NOT be
/// compressed; RFC 3597 §4 for TKEY).
struct DNSRDataCursor {
    let bytes: [UInt8]
    var pos = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var remaining: Int { bytes.count - pos }

    mutating func u8() throws -> UInt8 {
        guard pos < bytes.count else { throw DNSKitError.malformed("RDATA truncated at \(pos)") }
        defer { pos += 1 }
        return bytes[pos]
    }

    mutating func u16() throws -> UInt16 { UInt16(try u8()) << 8 | UInt16(try u8()) }
    mutating func u32() throws -> UInt32 { UInt32(try u16()) << 16 | UInt32(try u16()) }
    mutating func u48() throws -> UInt64 { UInt64(try u16()) << 32 | UInt64(try u32()) }

    mutating func take(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw DNSKitError.malformed("RDATA truncated at \(pos), need \(n)") }
        defer { pos += n }
        return Array(bytes[pos..<(pos + n)])
    }

    mutating func name() throws -> DNSName {
        var labels: [[UInt8]] = []
        var length = 1
        while true {
            let len = try u8()
            if len == 0 { return DNSName(labels: labels) }
            guard len & 0xC0 == 0 else { throw DNSKitError.malformed("compressed name in TSIG/TKEY RDATA") }
            labels.append(try take(Int(len)))
            length += 1 + Int(len)
            guard length <= 255 else { throw DNSKitError.malformed("name longer than 255 bytes") }
        }
    }
}

extension Array where Element == UInt8 {
    mutating func appendU16(_ v: UInt16) { append(contentsOf: [UInt8(v >> 8), UInt8(v & 0xFF)]) }
    mutating func appendU32(_ v: UInt32) { appendU16(UInt16(v >> 16)); appendU16(UInt16(v & 0xFFFF)) }
    mutating func appendU48(_ v: UInt64) { appendU16(UInt16(truncatingIfNeeded: v >> 32)); appendU32(UInt32(truncatingIfNeeded: v)) }
}

extension DNSName {
    /// Uncompressed wire form; `canonical` lower-cases it (RFC 4034 §6.2, as the TSIG digest wants).
    func wire(canonical: Bool) -> [UInt8] {
        var out: [UInt8] = []
        for label in canonical ? canonicalLabels : labels {
            out.append(UInt8(label.count))
            out += label
        }
        out.append(0)
        return out
    }
}

/// TKEY RDATA (RFC 2930 §2).
public struct DNSTKEY: Hashable, Sendable {
    /// RFC 2930 §2.5 mode 3: GSS-API negotiation (RFC 3645).
    public static let modeGSSAPI: UInt16 = 3

    public var algorithm: DNSName
    public var inception: UInt32
    public var expiration: UInt32
    public var mode: UInt16
    public var error: UInt16
    public var keyData: [UInt8]
    public var otherData: [UInt8]

    public init(algorithm: DNSName, inception: UInt32, expiration: UInt32, mode: UInt16 = DNSTKEY.modeGSSAPI,
                error: UInt16 = 0, keyData: [UInt8], otherData: [UInt8] = []) {
        self.algorithm = algorithm
        self.inception = inception
        self.expiration = expiration
        self.mode = mode
        self.error = error
        self.keyData = keyData
        self.otherData = otherData
    }

    public init(rdata: [UInt8]) throws {
        var c = DNSRDataCursor(rdata)
        algorithm = try c.name()
        inception = try c.u32()
        expiration = try c.u32()
        mode = try c.u16()
        error = try c.u16()
        keyData = try c.take(Int(try c.u16()))
        otherData = try c.take(Int(try c.u16()))
        guard c.remaining == 0 else { throw DNSKitError.malformed("\(c.remaining) bytes after TKEY RDATA") }
    }

    public var rdata: [UInt8] {
        var out = algorithm.wire(canonical: false)
        out.appendU32(inception)
        out.appendU32(expiration)
        out.appendU16(mode)
        out.appendU16(error)
        out.appendU16(UInt16(truncatingIfNeeded: keyData.count))
        out += keyData
        out.appendU16(UInt16(truncatingIfNeeded: otherData.count))
        out += otherData
        return out
    }

    /// The record for a response: owner = the key name, class ANY, TTL 0 (RFC 2930 §2).
    public func record(keyName: DNSName) -> DNSRecord {
        DNSRecord(name: keyName, type: .tkey, rrClass: .any, ttl: 0, rdata: .unknown(rdata))
    }
}

/// TSIG RDATA (RFC 8945 §4.2).
public struct DNSTSIG: Hashable, Sendable {
    /// RFC 3645 §2: `gss-tsig`; Windows 2000's draft name `gss.microsoft.com` is accepted too.
    public static let gssTSIG: DNSName = "gss-tsig"
    public static let gssMicrosoft: DNSName = "gss.microsoft.com"
    /// The time window this server allows (RFC 8945 §10 recommends 300 s).
    public static let fudge: UInt16 = 300

    public var algorithm: DNSName
    /// Seconds since 1970 (48 bits).
    public var timeSigned: UInt64
    public var fudge: UInt16
    public var mac: [UInt8]
    public var originalID: UInt16
    public var error: UInt16
    public var otherData: [UInt8]

    public init(algorithm: DNSName, timeSigned: UInt64, fudge: UInt16 = DNSTSIG.fudge, mac: [UInt8] = [], originalID: UInt16,
                error: UInt16 = 0, otherData: [UInt8] = []) {
        self.algorithm = algorithm
        self.timeSigned = timeSigned
        self.fudge = fudge
        self.mac = mac
        self.originalID = originalID
        self.error = error
        self.otherData = otherData
    }

    public init(rdata: [UInt8]) throws {
        var c = DNSRDataCursor(rdata)
        algorithm = try c.name()
        timeSigned = try c.u48()
        fudge = try c.u16()
        mac = try c.take(Int(try c.u16()))
        originalID = try c.u16()
        error = try c.u16()
        otherData = try c.take(Int(try c.u16()))
        guard c.remaining == 0 else { throw DNSKitError.malformed("\(c.remaining) bytes after TSIG RDATA") }
    }

    public var rdata: [UInt8] {
        var out = algorithm.wire(canonical: false)
        out.appendU48(timeSigned)
        out.appendU16(fudge)
        out.appendU16(UInt16(truncatingIfNeeded: mac.count))
        out += mac
        out.appendU16(originalID)
        out.appendU16(error)
        out.appendU16(UInt16(truncatingIfNeeded: otherData.count))
        out += otherData
        return out
    }

    /// Whether the algorithm is GSS-TSIG (either spelling).
    public var isGSS: Bool { algorithm == Self.gssTSIG || algorithm == Self.gssMicrosoft }

    /// The TSIG variables (RFC 8945 §4.3.3): key name and algorithm in canonical form, class ANY,
    /// TTL 0, then time, fudge, error and other data (MAC and original ID are not included).
    func variables(keyName: DNSName) -> [UInt8] {
        var out = keyName.wire(canonical: true)
        out.appendU16(DNSClass.any.rawValue)
        out.appendU32(0)
        out += algorithm.wire(canonical: true)
        out.appendU48(timeSigned)
        out.appendU16(fudge)
        out.appendU16(error)
        out.appendU16(UInt16(truncatingIfNeeded: otherData.count))
        out += otherData
        return out
    }

    /// The data a MAC covers (RFC 8945 §4.3): the prior MAC (length-prefixed) for a response or a
    /// later message of a TCP stream, the message without its TSIG RR (ID set back to the original
    /// ID, ARCOUNT without the TSIG), and the TSIG variables.
    func digest(message: [UInt8], keyName: DNSName, priorMAC: [UInt8]?) -> [UInt8] {
        var out: [UInt8] = []
        if let priorMAC {
            out.appendU16(UInt16(truncatingIfNeeded: priorMAC.count))
            out += priorMAC
        }
        var m = message
        if m.count >= 2 {
            m[0] = UInt8(originalID >> 8)
            m[1] = UInt8(originalID & 0xFF)
        }
        out += m
        out += variables(keyName: keyName)
        return out
    }

    /// The record: owner = the key name, class ANY, TTL 0.
    public func record(keyName: DNSName) -> DNSRecord {
        DNSRecord(name: keyName, type: .tsig, rrClass: .any, ttl: 0, rdata: .unknown(rdata))
    }
}

/// Raw-message helpers for TSIG.
enum DNSWireTSIG {
    /// A received message whose last additional record is a TSIG: the bytes before that record
    /// with ARCOUNT reduced by one (what the MAC covers), the key name and the TSIG.
    struct Signed {
        var unsignedMessage: [UInt8]
        var keyName: DNSName
        var tsig: DNSTSIG
    }

    /// nil when the message carries no TSIG; throws when one is present but not the last record
    /// (RFC 8945 §5.1: FORMERR), or malformed.
    static func split(_ bytes: [UInt8]) throws -> Signed? {
        var r = DNSWireReader(bytes)
        _ = try r.u16(); _ = try r.u16()
        let qd = Int(try r.u16()), an = Int(try r.u16()), ns = Int(try r.u16()), ar = Int(try r.u16())
        for _ in 0..<qd {
            _ = try r.name()
            _ = try r.take(4)
        }
        var tsigAt: (start: Int, index: Int)?
        var count = 0
        for i in 0..<(an + ns + ar) {
            let start = r.pos
            _ = try r.name()
            let type = try r.u16()
            _ = try r.take(6)
            _ = try r.take(Int(try r.u16()))
            if type == DNSRecordType.tsig.rawValue {
                guard i >= an + ns, tsigAt == nil else { throw DNSKitError.malformed("TSIG outside the end of the additional section") }
                tsigAt = (start, i)
            }
            count += 1
        }
        guard let tsigAt else { return nil }
        guard tsigAt.index == count - 1 else { throw DNSKitError.malformed("TSIG is not the last record") }
        var tail = DNSWireReader(bytes)
        tail.pos = tsigAt.start
        let keyName = try tail.name()
        _ = try tail.take(8)            // type, class, TTL
        let length = Int(try tail.u16())
        let tsig = try DNSTSIG(rdata: try tail.take(length))
        var message = Array(bytes[0..<tsigAt.start])
        let newAR = UInt16(ar - 1)
        message[10] = UInt8(newAR >> 8)
        message[11] = UInt8(newAR & 0xFF)
        return Signed(unsignedMessage: message, keyName: keyName, tsig: tsig)
    }

    /// `message` with `record` appended as the last additional record (ARCOUNT + 1), owner
    /// uncompressed.
    static func append(_ record: DNSRecord, to message: [UInt8]) -> [UInt8] {
        guard message.count >= 12, case .unknown(let rdata) = record.rdata else { return message }
        var out = message
        let ar = (UInt16(out[10]) << 8 | UInt16(out[11])) &+ 1
        out[10] = UInt8(ar >> 8)
        out[11] = UInt8(ar & 0xFF)
        out += record.name.wire(canonical: false)
        out.appendU16(record.type.rawValue)
        out.appendU16(record.rrClass.rawValue)
        out.appendU32(record.ttl)
        out.appendU16(UInt16(truncatingIfNeeded: rdata.count))
        out += rdata
        return out
    }
}
