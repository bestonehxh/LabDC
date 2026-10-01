/// OPCODE (RFC 1035 §4.1.1, RFC 2136).
public struct DNSOpcode: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue & 0x0F }

    public static let query = DNSOpcode(rawValue: 0)
    public static let status = DNSOpcode(rawValue: 2)
    public static let notify = DNSOpcode(rawValue: 4)
    public static let update = DNSOpcode(rawValue: 5)
}

/// RCODE, including the EDNS extended range (RFC 6891 §6.1.3).
public struct DNSRCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue & 0x0FFF }

    public static let noError = DNSRCode(rawValue: 0)
    public static let formErr = DNSRCode(rawValue: 1)
    public static let servFail = DNSRCode(rawValue: 2)
    public static let nxDomain = DNSRCode(rawValue: 3)
    public static let notImp = DNSRCode(rawValue: 4)
    public static let refused = DNSRCode(rawValue: 5)
    public static let yxDomain = DNSRCode(rawValue: 6)
    public static let yxRRSet = DNSRCode(rawValue: 7)
    public static let nxRRSet = DNSRCode(rawValue: 8)
    public static let notAuth = DNSRCode(rawValue: 9)
    public static let notZone = DNSRCode(rawValue: 10)
    public static let badVers = DNSRCode(rawValue: 16)

    public var description: String {
        let names = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
                     "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"]
        if Int(rawValue) < names.count { return names[Int(rawValue)] }
        return rawValue == 16 ? "BADVERS" : "RCODE\(rawValue)"
    }
}

/// A question entry (RFC 1035 §4.1.2); also the RFC 2136 zone section entry.
public struct DNSQuestion: Hashable, Sendable {
    public var name: DNSName
    public var type: DNSRecordType
    public var qclass: DNSClass

    public init(name: DNSName, type: DNSRecordType, qclass: DNSClass = .in) {
        self.name = name
        self.type = type
        self.qclass = qclass
    }
}

/// An EDNS(0) option (RFC 6891 §6.1.2).
public struct DNSEDNSOption: Hashable, Sendable {
    public var code: UInt16
    public var data: [UInt8]
    public init(code: UInt16, data: [UInt8]) {
        self.code = code
        self.data = data
    }
}

/// The OPT pseudo-RR (RFC 6891), lifted out of the additional section.
public struct DNSEDNS: Hashable, Sendable {
    /// Requestor's (or responder's) UDP payload size; values below 512 are treated as 512.
    public var udpPayloadSize: UInt16
    public var version: UInt8
    public var dnssecOK: Bool
    public var options: [DNSEDNSOption]

    public init(udpPayloadSize: UInt16 = 4096, version: UInt8 = 0, dnssecOK: Bool = false, options: [DNSEDNSOption] = []) {
        self.udpPayloadSize = udpPayloadSize
        self.version = version
        self.dnssecOK = dnssecOK
        self.options = options
    }
}

/// A DNS message (RFC 1035 §4.1).
///
/// For UPDATE (RFC 2136 §2) the four sections are zone, prerequisite, update and additional;
/// `zone`, `prerequisites` and `updates` are aliases for `questions`, `answers` and `authority`.
/// The OPT record is not kept in `additional`: it is decoded into `edns` and re-emitted last.
public struct DNSMessage: Hashable, Sendable {
    public var id: UInt16
    public var isResponse: Bool
    public var opcode: DNSOpcode
    public var authoritative: Bool
    public var truncated: Bool
    public var recursionDesired: Bool
    public var recursionAvailable: Bool
    public var authenticData: Bool
    public var checkingDisabled: Bool
    /// Full 12-bit RCODE; the upper 8 bits travel in the OPT record.
    public var rcode: DNSRCode
    public var questions: [DNSQuestion]
    public var answers: [DNSRecord]
    public var authority: [DNSRecord]
    public var additional: [DNSRecord]
    public var edns: DNSEDNS?

    public init(id: UInt16 = 0, isResponse: Bool = false, opcode: DNSOpcode = .query, authoritative: Bool = false,
                truncated: Bool = false, recursionDesired: Bool = false, recursionAvailable: Bool = false,
                authenticData: Bool = false, checkingDisabled: Bool = false, rcode: DNSRCode = .noError,
                questions: [DNSQuestion] = [], answers: [DNSRecord] = [], authority: [DNSRecord] = [],
                additional: [DNSRecord] = [], edns: DNSEDNS? = nil) {
        self.id = id
        self.isResponse = isResponse
        self.opcode = opcode
        self.authoritative = authoritative
        self.truncated = truncated
        self.recursionDesired = recursionDesired
        self.recursionAvailable = recursionAvailable
        self.authenticData = authenticData
        self.checkingDisabled = checkingDisabled
        self.rcode = rcode
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
        self.edns = edns
    }

    /// A standard query with RD set.
    public static func query(id: UInt16, name: DNSName, type: DNSRecordType, edns: DNSEDNS? = nil) -> DNSMessage {
        DNSMessage(id: id, recursionDesired: true, questions: [DNSQuestion(name: name, type: type)], edns: edns)
    }

    public var zone: [DNSQuestion] {
        get { questions }
        set { questions = newValue }
    }
    public var prerequisites: [DNSRecord] {
        get { answers }
        set { answers = newValue }
    }
    public var updates: [DNSRecord] {
        get { authority }
        set { authority = newValue }
    }

    /// The response skeleton for this request: same ID, opcode, RD, CD and questions, QR set.
    public func responseSkeleton(rcode: DNSRCode = .noError) -> DNSMessage {
        DNSMessage(id: id, isResponse: true, opcode: opcode, recursionDesired: recursionDesired,
                   checkingDisabled: checkingDisabled, rcode: rcode, questions: questions)
    }

    // MARK: Wire form

    /// Decodes a message; name compression pointers are followed anywhere in the message.
    public init(bytes: [UInt8]) throws {
        var r = DNSWireReader(bytes)
        id = try r.u16()
        let flags = try r.u16()
        isResponse = flags & 0x8000 != 0
        opcode = DNSOpcode(rawValue: UInt8((flags >> 11) & 0x0F))
        authoritative = flags & 0x0400 != 0
        truncated = flags & 0x0200 != 0
        recursionDesired = flags & 0x0100 != 0
        recursionAvailable = flags & 0x0080 != 0
        authenticData = flags & 0x0020 != 0
        checkingDisabled = flags & 0x0010 != 0
        let lowRCode = flags & 0x000F
        let qd = try r.u16(), an = try r.u16(), ns = try r.u16(), ar = try r.u16()
        questions = []
        for _ in 0..<qd {
            questions.append(DNSQuestion(name: try r.name(), type: DNSRecordType(rawValue: try r.u16()),
                                         qclass: DNSClass(rawValue: try r.u16())))
        }
        answers = try (0..<an).map { _ in try r.record() }
        authority = try (0..<ns).map { _ in try r.record() }
        additional = []
        edns = nil
        var extendedRCode: UInt16 = 0
        for _ in 0..<ar {
            let (record, opt) = try r.recordOrOPT()
            if let opt {
                guard edns == nil else { throw DNSKitError.malformed("more than one OPT record") }
                edns = opt.edns
                extendedRCode = UInt16(opt.extendedRCode) << 4
            } else if let record {
                additional.append(record)
            }
        }
        guard r.remaining == 0 else { throw DNSKitError.malformed("\(r.remaining) trailing bytes") }
        rcode = DNSRCode(rawValue: extendedRCode | lowRCode)
    }

    /// Encodes the message. Owner names and the names inside NS/CNAME/PTR/SOA/MX RDATA are
    /// compressed when `compress` is true; SRV targets never are (RFC 2782).
    public func encode(compress: Bool = true) throws -> [UInt8] {
        var w = DNSWireWriter(compress: compress)
        w.u16(id)
        var flags: UInt16 = 0
        if isResponse { flags |= 0x8000 }
        flags |= UInt16(opcode.rawValue) << 11
        if authoritative { flags |= 0x0400 }
        if truncated { flags |= 0x0200 }
        if recursionDesired { flags |= 0x0100 }
        if recursionAvailable { flags |= 0x0080 }
        if authenticData { flags |= 0x0020 }
        if checkingDisabled { flags |= 0x0010 }
        flags |= rcode.rawValue & 0x0F
        w.u16(flags)
        guard rcode.rawValue <= 0x0F || edns != nil else {
            throw DNSKitError.unencodable("extended RCODE \(rcode.rawValue) needs EDNS")
        }
        for count in [questions.count, answers.count, authority.count, additional.count + (edns == nil ? 0 : 1)] {
            guard count <= 0xFFFF else { throw DNSKitError.unencodable("section with \(count) entries") }
            w.u16(UInt16(count))
        }
        for q in questions {
            try w.name(q.name)
            w.u16(q.type.rawValue)
            w.u16(q.qclass.rawValue)
        }
        for record in answers + authority + additional { try w.record(record) }
        if let edns {
            w.bytes.append(0)                                   // root owner
            w.u16(DNSRecordType.opt.rawValue)
            w.u16(max(edns.udpPayloadSize, 512))
            w.bytes.append(UInt8(truncatingIfNeeded: rcode.rawValue >> 4))
            w.bytes.append(edns.version)
            w.u16(edns.dnssecOK ? 0x8000 : 0)
            var rdata: [UInt8] = []
            for option in edns.options {
                rdata += [UInt8(option.code >> 8), UInt8(option.code & 0xFF),
                          UInt8(option.data.count >> 8 & 0xFF), UInt8(option.data.count & 0xFF)] + option.data
            }
            w.u16(UInt16(rdata.count))
            w.bytes += rdata
        }
        return w.bytes
    }
}

// MARK: - Reader

struct DNSWireReader {
    let bytes: [UInt8]
    var pos = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var remaining: Int { bytes.count - pos }

    mutating func u8() throws -> UInt8 {
        guard pos < bytes.count else { throw DNSKitError.malformed("truncated at offset \(pos)") }
        defer { pos += 1 }
        return bytes[pos]
    }

    mutating func u16() throws -> UInt16 { UInt16(try u8()) << 8 | UInt16(try u8()) }

    mutating func u32() throws -> UInt32 { UInt32(try u16()) << 16 | UInt32(try u16()) }

    mutating func take(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw DNSKitError.malformed("truncated at offset \(pos), need \(n) bytes") }
        defer { pos += n }
        return Array(bytes[pos..<(pos + n)])
    }

    /// Reads a possibly compressed name. Each pointer must point strictly before the
    /// position it was read from, so loops are impossible.
    mutating func name() throws -> DNSName {
        var labels: [[UInt8]] = []
        var cursor = pos
        var jumped = false
        var wireLength = 1
        var limit = cursor                      // pointers must go below this offset
        while true {
            guard cursor < bytes.count else { throw DNSKitError.malformed("name runs past the end") }
            let len = bytes[cursor]
            switch len & 0xC0 {
            case 0x00:
                if len == 0 {
                    if !jumped { pos = cursor + 1 }
                    return DNSName(labels: labels)
                }
                let end = cursor + 1 + Int(len)
                guard end <= bytes.count else { throw DNSKitError.malformed("label runs past the end") }
                labels.append(Array(bytes[(cursor + 1)..<end]))
                wireLength += 1 + Int(len)
                guard wireLength <= 255 else { throw DNSKitError.malformed("name longer than 255 bytes") }
                cursor = end
            case 0xC0:
                guard cursor + 1 < bytes.count else { throw DNSKitError.malformed("truncated pointer") }
                let target = Int(len & 0x3F) << 8 | Int(bytes[cursor + 1])
                guard target < limit else { throw DNSKitError.malformed("forward or looping pointer to \(target)") }
                if !jumped { pos = cursor + 2 }
                jumped = true
                limit = target
                cursor = target
            default:
                throw DNSKitError.malformed("unsupported label type 0x\(String(len, radix: 16))")
            }
        }
    }

    mutating func record() throws -> DNSRecord {
        let (record, opt) = try recordOrOPT()
        guard let record, opt == nil else { throw DNSKitError.malformed("OPT outside the additional section") }
        return record
    }

    struct OPT {
        var edns: DNSEDNS
        var extendedRCode: UInt8
    }

    mutating func recordOrOPT() throws -> (DNSRecord?, OPT?) {
        let owner = try name()
        let type = DNSRecordType(rawValue: try u16())
        let rrClass = try u16()
        let ttl = try u32()
        let rdLength = Int(try u16())
        guard remaining >= rdLength else { throw DNSKitError.malformed("RDATA runs past the end") }
        let end = pos + rdLength
        if type == .opt {
            guard owner.isRoot else { throw DNSKitError.malformed("OPT owner is not the root") }
            var options: [DNSEDNSOption] = []
            while pos < end {
                let code = try u16()
                let len = Int(try u16())
                guard pos + len <= end else { throw DNSKitError.malformed("EDNS option runs past RDATA") }
                options.append(DNSEDNSOption(code: code, data: try take(len)))
            }
            let edns = DNSEDNS(udpPayloadSize: rrClass, version: UInt8(ttl >> 16 & 0xFF),
                               dnssecOK: ttl & 0x8000 != 0, options: options)
            return (nil, OPT(edns: edns, extendedRCode: UInt8(ttl >> 24)))
        }
        let rdata = try self.rdata(type: type, length: rdLength)
        guard pos == end else { throw DNSKitError.malformed("\(type) RDATA length \(rdLength) does not match its content") }
        return (DNSRecord(name: owner, type: type, rrClass: DNSClass(rawValue: rrClass), ttl: ttl, rdata: rdata), nil)
    }

    mutating func rdata(type: DNSRecordType, length: Int) throws -> DNSRData {
        if length == 0 { return .empty }
        let end = pos + length
        switch type {
        case .a:
            guard length == 4 else { throw DNSKitError.malformed("A RDATA of \(length) bytes") }
            return .a(DNSAddress(bytes: try take(4)))
        case .aaaa:
            guard length == 16 else { throw DNSKitError.malformed("AAAA RDATA of \(length) bytes") }
            return .aaaa(DNSAddress(bytes: try take(16)))
        case .ns: return .ns(try name())
        case .cname: return .cname(try name())
        case .ptr: return .ptr(try name())
        case .soa:
            return .soa(DNSSOA(mname: try name(), rname: try name(), serial: try u32(), refresh: try u32(),
                               retry: try u32(), expire: try u32(), minimum: try u32()))
        case .mx: return .mx(preference: try u16(), exchange: try name())
        case .txt:
            var strings: [[UInt8]] = []
            while pos < end {
                let len = Int(try u8())
                guard pos + len <= end else { throw DNSKitError.malformed("TXT string runs past RDATA") }
                strings.append(try take(len))
            }
            return .txt(strings)
        case .srv:
            return .srv(DNSSRV(priority: try u16(), weight: try u16(), port: try u16(), target: try name()))
        default:
            return .unknown(try take(length))
        }
    }
}

// MARK: - Writer

struct DNSWireWriter {
    var bytes: [UInt8] = []
    let compress: Bool
    /// Canonical (lower-cased) name suffix -> offset of its first occurrence.
    private var offsets: [[[UInt8]]: Int] = [:]

    init(compress: Bool) { self.compress = compress }

    mutating func u16(_ v: UInt16) { bytes += [UInt8(v >> 8), UInt8(v & 0xFF)] }
    mutating func u32(_ v: UInt32) { bytes += [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }

    mutating func name(_ name: DNSName, compressible: Bool = true) throws {
        guard name.wireLength <= 255 else { throw DNSKitError.unencodable("name longer than 255 bytes: \(name)") }
        let canonical = name.canonicalLabels
        for i in name.labels.indices {
            let suffix = Array(canonical[i...])
            if compress, compressible, let offset = offsets[suffix] {
                u16(0xC000 | UInt16(offset))
                return
            }
            let label = name.labels[i]
            guard (1...63).contains(label.count) else { throw DNSKitError.unencodable("label of \(label.count) bytes in \(name)") }
            if bytes.count < 0x4000, offsets[suffix] == nil { offsets[suffix] = bytes.count }
            bytes.append(UInt8(label.count))
            bytes += label
        }
        bytes.append(0)
    }

    mutating func record(_ r: DNSRecord) throws {
        try name(r.name)
        u16(r.type.rawValue)
        u16(r.rrClass.rawValue)
        u32(r.ttl)
        let lengthAt = bytes.count
        u16(0)
        switch r.rdata {
        case .a(let x), .aaaa(let x): bytes += x.bytes
        case .ns(let n), .cname(let n), .ptr(let n): try name(n)
        case .soa(let s):
            try name(s.mname)
            try name(s.rname)
            for v in [s.serial, s.refresh, s.retry, s.expire, s.minimum] { u32(v) }
        case let .mx(preference, exchange):
            u16(preference)
            try name(exchange)
        case .txt(let strings):
            for s in strings {
                guard s.count <= 255 else { throw DNSKitError.unencodable("TXT string of \(s.count) bytes") }
                bytes.append(UInt8(s.count))
                bytes += s
            }
        case .srv(let s):
            u16(s.priority)
            u16(s.weight)
            u16(s.port)
            try name(s.target, compressible: false)
        case .empty: break
        case .unknown(let b): bytes += b
        }
        let length = bytes.count - lengthAt - 2
        guard length <= 0xFFFF else { throw DNSKitError.unencodable("RDATA of \(length) bytes") }
        bytes[lengthAt] = UInt8(length >> 8)
        bytes[lengthAt + 1] = UInt8(length & 0xFF)
    }
}

/// RFC 1035 §4.2.2 / RFC 7766 TCP framing: a 2-byte big-endian length before each message.
public enum DNSTCPFraming {
    public static func frame(_ message: [UInt8]) -> [UInt8] {
        [UInt8(message.count >> 8 & 0xFF), UInt8(message.count & 0xFF)] + message
    }

    /// Accumulates stream bytes and yields complete messages.
    public struct Deframer: Sendable {
        private var buffer: [UInt8] = []
        public init() {}
        public mutating func append(_ bytes: some Sequence<UInt8>) { buffer.append(contentsOf: bytes) }

        /// The next complete message, or nil if more bytes are needed.
        public mutating func next() -> [UInt8]? {
            guard buffer.count >= 2 else { return nil }
            let length = Int(buffer[0]) << 8 | Int(buffer[1])
            guard buffer.count >= 2 + length else { return nil }
            let message = Array(buffer[2..<(2 + length)])
            buffer.removeFirst(2 + length)
            return message
        }

        public var pendingCount: Int { buffer.count }
    }
}
