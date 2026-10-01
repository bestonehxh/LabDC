/// `NETLOGON_SAM_LOGON_RESPONSE_EX` (MS-ADTS §6.3.1.9), the answer to a ping whose `NtVer`
/// has `V5EX`.
///
/// Layout (little-endian, no alignment):
///
/// | field | size |
/// | --- | --- |
/// | Opcode (23, or 25 when the `User` is unknown) | 2 |
/// | Sbz | 2 |
/// | Flags (`NetlogonDSFlags`) | 4 |
/// | DomainGuid (wire order) | 16 |
/// | DnsForestName, DnsDomainName, DnsHostName, NetbiosDomainName, NetbiosComputerName, UserName, DcSiteName, ClientSiteName | compressed names |
/// | DcSockAddrSize (16) + DcSockAddr (`SOCKADDR_IN`), only with `V5EX_WITH_IP` | 1 + 16 |
/// | NextClosestSiteName, only with `WITH_CLOSEST_SITE` | compressed name |
/// | NtVersion | 4 |
/// | LmNtToken, Lm20Token (0xFFFF) | 2 + 2 |
///
/// `DcSockAddr` is `sin_family` 2 (little-endian, 2 bytes), `sin_port` 0, the IPv4 address in
/// network order and 8 zero bytes.
public struct NetlogonSamLogonResponseEx: Sendable, Hashable {
    public var opcode: NetlogonOpcode
    public var flags: NetlogonDSFlags
    public var domainGUID: [UInt8]
    public var dnsForestName: String
    public var dnsDomainName: String
    public var dnsHostName: String
    public var netbiosDomainName: String
    public var netbiosComputerName: String
    public var userName: String
    public var dcSiteName: String
    public var clientSiteName: String
    /// IPv4 address (4 bytes, network order) for `DcSockAddr`; nil leaves the field out.
    public var dcIPv4: [UInt8]?
    /// Present only when the client asked for `WITH_CLOSEST_SITE`.
    public var nextClosestSiteName: String?
    public var ntVersion: NetlogonNtVersion
    public var lmNtToken: UInt16
    public var lm20Token: UInt16

    public init(opcode: NetlogonOpcode = .samLogonResponseEx, flags: NetlogonDSFlags, domainGUID: [UInt8],
                dnsForestName: String, dnsDomainName: String, dnsHostName: String, netbiosDomainName: String,
                netbiosComputerName: String, userName: String, dcSiteName: String, clientSiteName: String,
                dcIPv4: [UInt8]? = nil, nextClosestSiteName: String? = nil, ntVersion: NetlogonNtVersion? = nil,
                lmNtToken: UInt16 = 0xFFFF, lm20Token: UInt16 = 0xFFFF) {
        self.opcode = opcode
        self.flags = flags
        self.domainGUID = domainGUID
        self.dnsForestName = dnsForestName
        self.dnsDomainName = dnsDomainName
        self.dnsHostName = dnsHostName
        self.netbiosDomainName = netbiosDomainName
        self.netbiosComputerName = netbiosComputerName
        self.userName = userName
        self.dcSiteName = dcSiteName
        self.clientSiteName = clientSiteName
        self.dcIPv4 = dcIPv4
        self.nextClosestSiteName = nextClosestSiteName
        var v: NetlogonNtVersion = [.v1, .v5ex]
        if dcIPv4 != nil { v.insert(.v5exWithIP) }
        if nextClosestSiteName != nil { v.insert(.withClosestSite) }
        self.ntVersion = ntVersion ?? v
        self.lmNtToken = lmNtToken
        self.lm20Token = lm20Token
    }

    public func encoded() -> [UInt8] {
        var w = NetlogonWriter()
        w.u16(opcode.rawValue)
        w.u16(0)
        w.u32(flags.rawValue)
        w.raw(Self.guid16(domainGUID))
        for n in [dnsForestName, dnsDomainName, dnsHostName, netbiosDomainName, netbiosComputerName, userName,
                  dcSiteName, clientSiteName] {
            w.name(n)
        }
        if let ip = dcIPv4 {
            w.u8(16)
            w.raw(sockaddrIn(ip))
        }
        if let next = nextClosestSiteName { w.name(next) }
        w.u32(ntVersion.rawValue)
        w.u16(lmNtToken)
        w.u16(lm20Token)
        return w.bytes
    }

    /// Decodes a structure produced by any conforming DC. Whether `DcSockAddr` and
    /// `NextClosestSiteName` are present is read from the trailing `NtVersion`, as Wireshark does.
    public init(bytes: [UInt8]) throws {
        guard bytes.count >= 8 + 24 else { throw NetlogonError.truncated("NETLOGON_SAM_LOGON_RESPONSE_EX") }
        let tail = bytes.count - 8
        let version = NetlogonNtVersion(rawValue: (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[tail + $1]) << (8 * UInt32($1)) })
        var r = NetlogonReader(bytes)
        let op = try r.u16("Opcode")
        guard let opcode = NetlogonOpcode(rawValue: op) else { throw NetlogonError.badPing("opcode \(op)") }
        self.opcode = opcode
        _ = try r.u16("Sbz")
        flags = NetlogonDSFlags(rawValue: try r.u32("Flags"))
        domainGUID = try r.raw(16, "DomainGuid")
        dnsForestName = try r.name("DnsForestName")
        dnsDomainName = try r.name("DnsDomainName")
        dnsHostName = try r.name("DnsHostName")
        netbiosDomainName = try r.name("NetbiosDomainName")
        netbiosComputerName = try r.name("NetbiosComputerName")
        userName = try r.name("UserName")
        dcSiteName = try r.name("DcSiteName")
        clientSiteName = try r.name("ClientSiteName")
        if version.contains(.v5exWithIP) {
            let size = Int(try r.u8("DcSockAddrSize"))
            let sa = try r.raw(size, "DcSockAddr")
            guard size >= 8, sa[0] == 2, sa[1] == 0 else { throw NetlogonError.badName("DcSockAddr family") }
            dcIPv4 = Array(sa[4..<8])
        } else {
            dcIPv4 = nil
        }
        nextClosestSiteName = version.contains(.withClosestSite) ? try r.name("NextClosestSiteName") : nil
        ntVersion = NetlogonNtVersion(rawValue: try r.u32("NtVersion"))
        lmNtToken = try r.u16("LmNtToken")
        lm20Token = try r.u16("Lm20Token")
        guard r.remaining == 0 else { throw NetlogonError.badName("\(r.remaining) trailing bytes") }
    }

    static func guid16(_ b: [UInt8]) -> [UInt8] {
        b.count == 16 ? b : Array((b + [UInt8](repeating: 0, count: 16)).prefix(16))
    }
}

/// `SOCKADDR_IN` as a netlogon response carries it: family 2 little-endian, port 0, the
/// address in network order, 8 zero bytes.
func sockaddrIn(_ ipv4: [UInt8]) -> [UInt8] {
    [0x02, 0x00, 0x00, 0x00] + Array((ipv4 + [0, 0, 0, 0]).prefix(4)) + [UInt8](repeating: 0, count: 8)
}

/// `NETLOGON_SAM_LOGON_RESPONSE` (MS-ADTS §6.3.1.8), the answer when `NtVer` has `V5` but
/// not `V5EX`.
///
/// Layout: Opcode (2; 19, or 21 when the `User` is unknown), UnicodeLogonServer,
/// UnicodeUserName and UnicodeDomainName (NUL-terminated UTF-16LE), DomainGuid (16),
/// NullGuid (16 zero bytes), DnsForestName, DnsDomainName and DnsHostName (compressed),
/// DcIpAddress (4), Flags (4), NtVersion (4, `V1|V5`), LmNtToken and Lm20Token (0xFFFF).
/// `DcIpAddress` is in network order ("as specified in RFC 791"; Wireshark reads it so).
/// MS-ADTS §6.3.3.2 limits the flags of this structure to `PDC` and `DS`.
public struct NetlogonSamLogonResponse: Sendable, Hashable {
    public var opcode: NetlogonOpcode
    /// `\\DC1`.
    public var unicodeLogonServer: String
    public var unicodeUserName: String
    public var unicodeDomainName: String
    public var domainGUID: [UInt8]
    public var dnsForestName: String
    public var dnsDomainName: String
    public var dnsHostName: String
    public var dcIPv4: [UInt8]
    public var flags: NetlogonDSFlags
    public var ntVersion: NetlogonNtVersion

    public init(opcode: NetlogonOpcode = .samLogonResponse, unicodeLogonServer: String, unicodeUserName: String,
                unicodeDomainName: String, domainGUID: [UInt8], dnsForestName: String, dnsDomainName: String,
                dnsHostName: String, dcIPv4: [UInt8], flags: NetlogonDSFlags, ntVersion: NetlogonNtVersion = [.v1, .v5]) {
        self.opcode = opcode
        self.unicodeLogonServer = unicodeLogonServer
        self.unicodeUserName = unicodeUserName
        self.unicodeDomainName = unicodeDomainName
        self.domainGUID = domainGUID
        self.dnsForestName = dnsForestName
        self.dnsDomainName = dnsDomainName
        self.dnsHostName = dnsHostName
        self.dcIPv4 = dcIPv4
        self.flags = flags
        self.ntVersion = ntVersion
    }

    public func encoded() -> [UInt8] {
        var w = NetlogonWriter()
        w.u16(opcode.rawValue)
        w.utf16z(unicodeLogonServer)
        w.utf16z(unicodeUserName)
        w.utf16z(unicodeDomainName)
        w.raw(NetlogonSamLogonResponseEx.guid16(domainGUID))
        w.raw([UInt8](repeating: 0, count: 16))
        w.name(dnsForestName)
        w.name(dnsDomainName)
        w.name(dnsHostName)
        w.raw(Array((dcIPv4 + [0, 0, 0, 0]).prefix(4)))
        w.u32(flags.rawValue)
        w.u32(ntVersion.rawValue)
        w.u16(0xFFFF)
        w.u16(0xFFFF)
        return w.bytes
    }
}

/// `NETLOGON_SAM_LOGON_RESPONSE_NT40` (MS-ADTS §6.3.1.7), the answer when `NtVer` has
/// neither `V5` nor `V5EX`.
///
/// Layout: Opcode (2; 19 or 21), UnicodeLogonServer, UnicodeUserName, UnicodeDomainName
/// (NUL-terminated UTF-16LE), NtVersion (4, `V1`), LmNtToken and Lm20Token (0xFFFF).
public struct NetlogonSamLogonResponseNT40: Sendable, Hashable {
    public var opcode: NetlogonOpcode
    public var unicodeLogonServer: String
    public var unicodeUserName: String
    public var unicodeDomainName: String
    public var ntVersion: NetlogonNtVersion

    public init(opcode: NetlogonOpcode = .samLogonResponse, unicodeLogonServer: String, unicodeUserName: String,
                unicodeDomainName: String, ntVersion: NetlogonNtVersion = .v1) {
        self.opcode = opcode
        self.unicodeLogonServer = unicodeLogonServer
        self.unicodeUserName = unicodeUserName
        self.unicodeDomainName = unicodeDomainName
        self.ntVersion = ntVersion
    }

    public func encoded() -> [UInt8] {
        var w = NetlogonWriter()
        w.u16(opcode.rawValue)
        w.utf16z(unicodeLogonServer)
        w.utf16z(unicodeUserName)
        w.utf16z(unicodeDomainName)
        w.u32(ntVersion.rawValue)
        w.u16(0xFFFF)
        w.u16(0xFFFF)
        return w.bytes
    }
}
