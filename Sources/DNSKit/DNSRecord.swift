import Darwin

/// RR TYPE / QTYPE (RFC 1035 §3.2.2–3.2.3 and later RFCs).
public struct DNSRecordType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let a = DNSRecordType(rawValue: 1)
    public static let ns = DNSRecordType(rawValue: 2)
    public static let cname = DNSRecordType(rawValue: 5)
    public static let soa = DNSRecordType(rawValue: 6)
    public static let ptr = DNSRecordType(rawValue: 12)
    public static let hinfo = DNSRecordType(rawValue: 13)
    public static let mx = DNSRecordType(rawValue: 15)
    public static let txt = DNSRecordType(rawValue: 16)
    public static let aaaa = DNSRecordType(rawValue: 28)
    public static let srv = DNSRecordType(rawValue: 33)
    public static let opt = DNSRecordType(rawValue: 41)
    /// RFC 4701: written by the DHCP server next to the A/AAAA it registers for a lease.
    public static let dhcid = DNSRecordType(rawValue: 49)
    public static let tkey = DNSRecordType(rawValue: 249)
    public static let tsig = DNSRecordType(rawValue: 250)
    public static let ixfr = DNSRecordType(rawValue: 251)
    public static let axfr = DNSRecordType(rawValue: 252)
    public static let mailb = DNSRecordType(rawValue: 253)
    public static let maila = DNSRecordType(rawValue: 254)
    public static let any = DNSRecordType(rawValue: 255)

    /// QTYPEs and pseudo types that never name stored data (RFC 2136 §3.4.1.2 rejects them in updates).
    public var isMeta: Bool { [41, 249, 250, 251, 252, 253, 254, 255].contains(rawValue) }

    public var description: String {
        switch rawValue {
        case 1: "A"
        case 2: "NS"
        case 5: "CNAME"
        case 6: "SOA"
        case 12: "PTR"
        case 13: "HINFO"
        case 15: "MX"
        case 16: "TXT"
        case 28: "AAAA"
        case 33: "SRV"
        case 41: "OPT"
        case 49: "DHCID"
        case 249: "TKEY"
        case 250: "TSIG"
        case 251: "IXFR"
        case 252: "AXFR"
        case 255: "ANY"
        default: "TYPE\(rawValue)"
        }
    }
}

/// RR CLASS / QCLASS. `none` (254) and `any` (255) are the RFC 2136 update meta classes.
public struct DNSClass: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let `in` = DNSClass(rawValue: 1)
    public static let ch = DNSClass(rawValue: 3)
    public static let none = DNSClass(rawValue: 254)
    public static let any = DNSClass(rawValue: 255)

    public var description: String {
        switch rawValue {
        case 1: "IN"
        case 3: "CH"
        case 254: "NONE"
        case 255: "ANY"
        default: "CLASS\(rawValue)"
        }
    }
}

/// An IPv4 (4 bytes) or IPv6 (16 bytes) address in network byte order.
public struct DNSAddress: Hashable, Sendable, CustomStringConvertible, Comparable {
    public let bytes: [UInt8]

    /// - Precondition: `bytes.count` is 4 or 16.
    public init(bytes: [UInt8]) {
        precondition(bytes.count == 4 || bytes.count == 16, "an address has 4 or 16 bytes")
        self.bytes = bytes
    }

    /// Parses dotted-quad IPv4 or RFC 4291 IPv6 text; nil when neither.
    public init?(_ text: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            self.bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            self.bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return
        }
        return nil
    }

    public var isIPv4: Bool { bytes.count == 4 }

    public var description: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = isIPv4 ? AF_INET : AF_INET6
        let ok = bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &buffer, socklen_t(buffer.count)) != nil
        }
        guard ok else { return bytes.map(String.init).joined(separator: ".") }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    public static func < (a: DNSAddress, b: DNSAddress) -> Bool {
        a.bytes.count != b.bytes.count ? a.bytes.count < b.bytes.count : a.bytes.lexicographicallyPrecedes(b.bytes)
    }
}

/// SOA RDATA (RFC 1035 §3.3.13).
public struct DNSSOA: Hashable, Sendable {
    public var mname: DNSName
    public var rname: DNSName
    public var serial: UInt32
    public var refresh: UInt32
    public var retry: UInt32
    public var expire: UInt32
    public var minimum: UInt32

    public init(mname: DNSName, rname: DNSName, serial: UInt32, refresh: UInt32, retry: UInt32, expire: UInt32, minimum: UInt32) {
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum
    }
}

/// SRV RDATA (RFC 2782).
public struct DNSSRV: Hashable, Sendable {
    public var priority: UInt16
    public var weight: UInt16
    public var port: UInt16
    public var target: DNSName

    public init(priority: UInt16, weight: UInt16, port: UInt16, target: DNSName) {
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target
    }
}

/// Typed RDATA. Names compare case-insensitively (RFC 4343), so two records with the
/// same data in different case are equal, as RFC 2136 §1.1.1 requires.
public enum DNSRData: Hashable, Sendable {
    case a(DNSAddress)
    case aaaa(DNSAddress)
    case ns(DNSName)
    case cname(DNSName)
    case ptr(DNSName)
    case soa(DNSSOA)
    case mx(preference: UInt16, exchange: DNSName)
    /// One or more character-strings, each up to 255 bytes.
    case txt([[UInt8]])
    case srv(DNSSRV)
    /// RDLENGTH 0: the RFC 2136 update/prerequisite forms with class ANY or NONE.
    case empty
    /// Any other type, kept as opaque bytes (RFC 3597).
    case unknown([UInt8])

    /// The TYPE this RDATA belongs to, when it implies one.
    public var impliedType: DNSRecordType? {
        switch self {
        case .a: .a
        case .aaaa: .aaaa
        case .ns: .ns
        case .cname: .cname
        case .ptr: .ptr
        case .soa: .soa
        case .mx: .mx
        case .txt: .txt
        case .srv: .srv
        case .empty, .unknown: nil
        }
    }
}

/// A resource record (RFC 1035 §4.1.3).
public struct DNSRecord: Hashable, Sendable, CustomStringConvertible {
    public var name: DNSName
    public var type: DNSRecordType
    public var rrClass: DNSClass
    public var ttl: UInt32
    public var rdata: DNSRData

    public init(name: DNSName, type: DNSRecordType, rrClass: DNSClass = .in, ttl: UInt32, rdata: DNSRData) {
        self.name = name
        self.type = type
        self.rrClass = rrClass
        self.ttl = ttl
        self.rdata = rdata
    }

    /// A class IN record whose TYPE follows from `rdata`.
    /// - Precondition: `rdata` implies a type (not `.empty` / `.unknown`).
    public init(name: DNSName, ttl: UInt32, _ rdata: DNSRData) {
        guard let type = rdata.impliedType else { preconditionFailure("rdata \(rdata) does not imply a type") }
        self.init(name: name, type: type, ttl: ttl, rdata: rdata)
    }

    /// Same owner, type, class and RDATA; TTL ignored (RFC 2136 §1.1.1 "RR" identity).
    public func sameData(as other: DNSRecord) -> Bool {
        name == other.name && type == other.type && rrClass == other.rrClass && rdata == other.rdata
    }

    public var description: String {
        let data: String = switch rdata {
        case .a(let x), .aaaa(let x): "\(x)"
        case .ns(let n), .cname(let n), .ptr(let n): "\(n)."
        case .soa(let s): "\(s.mname). \(s.rname). \(s.serial) \(s.refresh) \(s.retry) \(s.expire) \(s.minimum)"
        case let .mx(p, e): "\(p) \(e)."
        case .txt(let strings): strings.map { "\"\(String(decoding: $0, as: UTF8.self))\"" }.joined(separator: " ")
        case .srv(let s): "\(s.priority) \(s.weight) \(s.port) \(s.target)."
        case .empty: ""
        case .unknown(let b): "\\# \(b.count)"
        }
        return "\(name). \(ttl) \(rrClass) \(type) \(data)"
    }
}
