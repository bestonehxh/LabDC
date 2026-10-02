import Foundation

/// DHCPv4 message types (option 53, RFC 2132 §9.6).
public enum DHCPv4MessageType: UInt8, Sendable, CaseIterable, CustomStringConvertible {
    case discover = 1, offer, request, decline, ack, nak, release, inform

    public var description: String {
        switch self {
        case .discover: "DISCOVER"
        case .offer: "OFFER"
        case .request: "REQUEST"
        case .decline: "DECLINE"
        case .ack: "ACK"
        case .nak: "NAK"
        case .release: "RELEASE"
        case .inform: "INFORM"
        }
    }
}

/// Option codes LabDC reads or writes (RFC 2132 and later).
public enum DHCPv4OptionCode {
    public static let pad: UInt8 = 0
    public static let subnetMask: UInt8 = 1
    public static let router: UInt8 = 3
    public static let dnsServers: UInt8 = 6
    public static let hostName: UInt8 = 12
    public static let domainName: UInt8 = 15
    public static let interfaceMTU: UInt8 = 26
    public static let broadcastAddress: UInt8 = 28
    public static let ntpServers: UInt8 = 42
    public static let vendorSpecific: UInt8 = 43
    public static let requestedAddress: UInt8 = 50
    public static let leaseTime: UInt8 = 51
    public static let overload: UInt8 = 52
    public static let messageType: UInt8 = 53
    public static let serverIdentifier: UInt8 = 54
    public static let parameterRequestList: UInt8 = 55
    public static let message: UInt8 = 56
    public static let maxMessageSize: UInt8 = 57
    public static let renewalTime: UInt8 = 58
    public static let rebindingTime: UInt8 = 59
    public static let vendorClass: UInt8 = 60
    public static let clientIdentifier: UInt8 = 61
    public static let tftpServerName: UInt8 = 66
    public static let bootfileName: UInt8 = 67
    public static let userClass: UInt8 = 77
    public static let clientFQDN: UInt8 = 81
    public static let relayAgentInformation: UInt8 = 82
    public static let clientSystemArchitecture: UInt8 = 93
    public static let clientNetworkInterface: UInt8 = 94
    public static let subnetSelection: UInt8 = 118
    public static let domainSearch: UInt8 = 119
    public static let classlessStaticRoute: UInt8 = 121
    public static let capwapAC: UInt8 = 138
    public static let tftpServerAddress: UInt8 = 150
    /// Microsoft's pre-RFC 3442 copy of option 121 (Windows XP-era clients ask for it).
    public static let msClasslessStaticRoute: UInt8 = 249
    public static let end: UInt8 = 255
}

/// One DHCPv4 option as it appears on the wire (`data` already concatenated when the option was
/// split, RFC 3396).
public struct DHCPv4Option: Sendable, Equatable {
    public var code: UInt8
    public var data: [UInt8]

    public init(_ code: UInt8, _ data: [UInt8]) {
        self.code = code
        self.data = data
    }
}

/// A BOOTP/DHCPv4 message (RFC 2131 §2). Parsing checks every length; the option area may
/// continue in `sname`/`file` (option 52 overload) and an option may be split into several
/// instances (RFC 3396), which are concatenated in order.
public struct DHCPv4Packet: Sendable, Equatable {
    public var op: UInt8
    public var htype: UInt8
    public var hlen: UInt8
    public var hops: UInt8
    public var xid: UInt32
    public var secs: UInt16
    public var flags: UInt16
    public var ciaddr: IPv4Address
    public var yiaddr: IPv4Address
    public var siaddr: IPv4Address
    public var giaddr: IPv4Address
    /// Always 16 bytes.
    public var chaddr: [UInt8]
    /// Always 64 bytes.
    public var sname: [UInt8]
    /// Always 128 bytes.
    public var file: [UInt8]
    /// Options in the order they first appeared (concatenated instances merged).
    public var options: [DHCPv4Option]
    /// Option codes in the order the client wrote them, every instance (fingerprinting).
    public var optionOrder: [UInt8]

    public static let magicCookie: [UInt8] = [99, 130, 83, 99]
    /// Fixed header (236) + magic cookie.
    public static let headerSize = 240
    public static let broadcastFlag: UInt16 = 0x8000

    public init(op: UInt8 = 1, htype: UInt8 = 1, hlen: UInt8 = 6, hops: UInt8 = 0, xid: UInt32 = 0, secs: UInt16 = 0,
                flags: UInt16 = 0, ciaddr: IPv4Address = .zero, yiaddr: IPv4Address = .zero, siaddr: IPv4Address = .zero,
                giaddr: IPv4Address = .zero, chaddr: [UInt8] = [], options: [DHCPv4Option] = []) {
        self.op = op; self.htype = htype; self.hlen = hlen; self.hops = hops; self.xid = xid; self.secs = secs
        self.flags = flags; self.ciaddr = ciaddr; self.yiaddr = yiaddr; self.siaddr = siaddr; self.giaddr = giaddr
        self.chaddr = Array((chaddr + [UInt8](repeating: 0, count: 16)).prefix(16))
        self.sname = [UInt8](repeating: 0, count: 64)
        self.file = [UInt8](repeating: 0, count: 128)
        self.options = options
        self.optionOrder = options.map(\.code)
    }

    public init(bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        guard bytes.count >= Self.headerSize else { throw DHCPError.truncated("DHCPv4 header (\(bytes.count) bytes)") }
        op = try r.u8(); htype = try r.u8(); hlen = try r.u8(); hops = try r.u8()
        xid = try r.u32(); secs = try r.u16(); flags = try r.u16()
        ciaddr = IPv4Address(try r.u32()); yiaddr = IPv4Address(try r.u32())
        siaddr = IPv4Address(try r.u32()); giaddr = IPv4Address(try r.u32())
        chaddr = try r.take(16); sname = try r.take(64); file = try r.take(128)
        guard try r.take(4) == Self.magicCookie else { throw DHCPError.malformed("no DHCP magic cookie (BOOTP is not served)") }
        guard op == 1 || op == 2 else { throw DHCPError.malformed("op \(op)") }
        guard hlen <= 16 else { throw DHCPError.malformed("hlen \(hlen)") }

        var merged: [(UInt8, [UInt8])] = []
        var order: [UInt8] = []
        var overload: UInt8 = 0
        func scan(_ area: [UInt8]) throws {
            var r = DHCPReader(area)
            while !r.isAtEnd {
                let code = try r.u8("option code")
                if code == DHCPv4OptionCode.pad { continue }
                if code == DHCPv4OptionCode.end { return }
                let len = Int(try r.u8("length of option \(code)"))
                let data = try r.take(len, "option \(code) (\(len) bytes)")
                order.append(code)
                if let i = merged.firstIndex(where: { $0.0 == code }) {
                    merged[i].1 += data
                } else {
                    merged.append((code, data))
                }
                guard merged.count <= 255, order.count <= 1024 else { throw DHCPError.malformed("too many options") }
            }
            // No END: tolerated (many embedded clients stop at the last option).
        }
        try scan(r.rest())
        if let o = merged.first(where: { $0.0 == DHCPv4OptionCode.overload })?.1, o.count == 1 { overload = o[0] }
        if overload & 1 != 0 { try scan(file) }
        if overload & 2 != 0 { try scan(sname) }
        options = merged.map { DHCPv4Option($0.0, $0.1) }
        optionOrder = order
    }

    /// The wire form: options split at 255 bytes (RFC 3396), option 82 moved last before END
    /// (RFC 3046 §2.2), padded to `minimumSize` (300, the BOOTP minimum relays expect).
    public func encode(minimumSize: Int = 300) -> [UInt8] {
        var out: [UInt8] = [op, htype, hlen, hops]
        out.appendU32(xid); out.appendU16(secs); out.appendU16(flags)
        out.appendU32(ciaddr.value); out.appendU32(yiaddr.value); out.appendU32(siaddr.value); out.appendU32(giaddr.value)
        out += Array((chaddr + [UInt8](repeating: 0, count: 16)).prefix(16))
        out += Array((sname + [UInt8](repeating: 0, count: 64)).prefix(64))
        out += Array((file + [UInt8](repeating: 0, count: 128)).prefix(128))
        out += Self.magicCookie
        let ordered = options.filter { $0.code != DHCPv4OptionCode.relayAgentInformation }
            + options.filter { $0.code == DHCPv4OptionCode.relayAgentInformation }
        for option in ordered where option.code != DHCPv4OptionCode.pad && option.code != DHCPv4OptionCode.end {
            if option.data.isEmpty {
                out += [option.code, 0]
                continue
            }
            var start = 0
            while start < option.data.count {
                let chunk = option.data[start..<min(option.data.count, start + 255)]
                out.append(option.code)
                out.append(UInt8(chunk.count))
                out += chunk
                start += chunk.count
            }
        }
        out.append(DHCPv4OptionCode.end)
        if out.count < minimumSize { out += [UInt8](repeating: 0, count: minimumSize - out.count) }
        return out
    }

    // MARK: Options

    public subscript(code: UInt8) -> [UInt8]? {
        get { options.first { $0.code == code }?.data }
        set {
            if let newValue {
                if let i = options.firstIndex(where: { $0.code == code }) { options[i].data = newValue } else { options.append(.init(code, newValue)) }
            } else {
                options.removeAll { $0.code == code }
            }
        }
    }

    public var messageType: DHCPv4MessageType? {
        guard let v = self[DHCPv4OptionCode.messageType], v.count == 1 else { return nil }
        return DHCPv4MessageType(rawValue: v[0])
    }

    /// The hardware address (`hlen` bytes of `chaddr`).
    public var hardwareAddress: [UInt8] { Array(chaddr.prefix(Int(min(hlen, 16)))) }
    /// `aa:bb:…` for Ethernet (htype 1, hlen 6); nil for other link types.
    public var mac: String? { htype == 1 && hlen == 6 ? DHCPMAC.string(hardwareAddress) : nil }
    public var isBroadcastFlag: Bool { flags & Self.broadcastFlag != 0 }

    public func address(_ code: UInt8) -> IPv4Address? {
        guard let v = self[code], v.count == 4 else { return nil }
        return IPv4Address(bytes: v)
    }

    public func addresses(_ code: UInt8) -> [IPv4Address] {
        guard let v = self[code], v.count % 4 == 0 else { return [] }
        return stride(from: 0, to: v.count, by: 4).compactMap { IPv4Address(bytes: v[$0..<$0 + 4]) }
    }

    public func uint32(_ code: UInt8) -> UInt32? {
        guard let v = self[code], v.count == 4 else { return nil }
        return v.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }

    public func text(_ code: UInt8) -> String? {
        guard let v = self[code], !v.isEmpty else { return nil }
        // NUL-terminated strings happen (some printers): cut at the first NUL.
        let trimmed = v.prefix { $0 != 0 }
        return trimmed.isEmpty ? nil : String(decoding: trimmed, as: UTF8.self)
    }

    public var requestedAddress: IPv4Address? { address(DHCPv4OptionCode.requestedAddress) }
    public var serverIdentifier: IPv4Address? { address(DHCPv4OptionCode.serverIdentifier) }
    public var clientIdentifier: [UInt8]? { self[DHCPv4OptionCode.clientIdentifier].flatMap { $0.isEmpty ? nil : $0 } }
    public var hostName: String? { text(DHCPv4OptionCode.hostName) }
    public var vendorClass: String? { text(DHCPv4OptionCode.vendorClass) }
    public var parameterRequestList: [UInt8] { self[DHCPv4OptionCode.parameterRequestList] ?? [] }
    public var requestedLeaseTime: UInt32? { uint32(DHCPv4OptionCode.leaseTime) }

    /// Option 57, at least 576 (RFC 2132 §9.10); nil when absent or smaller.
    public var maxMessageSize: Int? {
        guard let v = self[DHCPv4OptionCode.maxMessageSize], v.count == 2 else { return nil }
        let size = Int(v[0]) << 8 | Int(v[1])
        return size >= 576 ? size : nil
    }

    /// Option 77 user class (RFC 3004 TLV list, or a plain string from older Windows clients).
    public var userClass: String? {
        guard let v = self[DHCPv4OptionCode.userClass], !v.isEmpty else { return nil }
        var r = DHCPReader(v)
        var parts: [String] = []
        while !r.isAtEnd {
            guard let len = try? r.u8(), let data = try? r.take(Int(len)), !data.isEmpty else {
                return DHCPHex.printable(v)
            }
            parts.append(DHCPHex.printable(data))
        }
        return parts.joined(separator: ",")
    }

    public var relayAgentInformation: RelayAgentInformation? {
        self[DHCPv4OptionCode.relayAgentInformation].flatMap { RelayAgentInformation(bytes: $0) }
    }

    public var clientFQDN: ClientFQDN? { self[DHCPv4OptionCode.clientFQDN].flatMap { try? ClientFQDN(v4: $0) } }
}

/// Option 82 (RFC 3046) and its sub-options: kept byte-for-byte for the echo, decoded for
/// scope selection and display.
public struct RelayAgentInformation: Sendable, Equatable {
    public struct SubOption: Sendable, Equatable {
        public var code: UInt8
        public var data: [UInt8]
        public init(_ code: UInt8, _ data: [UInt8]) { self.code = code; self.data = data }
    }

    public static let circuitID: UInt8 = 1
    public static let remoteID: UInt8 = 2
    /// RFC 3527 link selection.
    public static let linkSelection: UInt8 = 5
    /// RFC 4243 vendor-specific information.
    public static let vendorSpecific: UInt8 = 9
    /// RFC 5107 server identifier override.
    public static let serverIDOverride: UInt8 = 11
    /// RFC 8357 relay source port.
    public static let relaySourcePort: UInt8 = 19
    /// Cisco's pre-standard link selection (same meaning as 5).
    public static let ciscoLinkSelection: UInt8 = 150
    /// RFC 6607 virtual subnet selection (Cisco's 151).
    public static let vss: UInt8 = 151
    /// Cisco's pre-standard server identifier override (same meaning as 11).
    public static let ciscoServerIDOverride: UInt8 = 152

    public var raw: [UInt8]
    public var subOptions: [SubOption]

    /// Nil when a sub-option length runs past the end (the option is then ignored, not echoed).
    public init?(bytes: [UInt8]) {
        var r = DHCPReader(bytes)
        var subs: [SubOption] = []
        while !r.isAtEnd {
            guard let code = try? r.u8(), let len = try? r.u8(), let data = try? r.take(Int(len)) else { return nil }
            subs.append(SubOption(code, data))
        }
        raw = bytes
        subOptions = subs
    }

    public init(_ subOptions: [SubOption]) {
        self.subOptions = subOptions
        raw = subOptions.flatMap { [$0.code, UInt8(min($0.data.count, 255))] + $0.data.prefix(255) }
    }

    public func sub(_ code: UInt8) -> [UInt8]? { subOptions.first { $0.code == code }?.data }

    public var circuit: [UInt8]? { sub(Self.circuitID) }
    public var remote: [UInt8]? { sub(Self.remoteID) }

    /// RFC 3527 (or Cisco 150) link-selection address.
    public var linkSelectionAddress: IPv4Address? {
        for code in [Self.linkSelection, Self.ciscoLinkSelection] {
            if let v = sub(code), v.count == 4 { return IPv4Address(bytes: v) }
        }
        return nil
    }

    /// RFC 5107 (or Cisco 152) server identifier override.
    public var serverIDOverride: IPv4Address? {
        for code in [Self.serverIDOverride, Self.ciscoServerIDOverride] {
            if let v = sub(code), v.count == 4 { return IPv4Address(bytes: v) }
        }
        return nil
    }

    /// RFC 8357: the relay listens on the port the packet came from.
    public var hasRelaySourcePort: Bool { sub(Self.relaySourcePort) != nil }
}

/// The client FQDN option: v4 option 81 (RFC 4702) and v6 option 39 (RFC 4704).
public struct ClientFQDN: Sendable, Equatable {
    /// S: the server should do the A/AAAA update.
    public var s: Bool
    /// O: the server overrode the client's S.
    public var o: Bool
    /// E: canonical wire encoding (v4 only; v6 is always wire encoding).
    public var e: Bool
    /// N: the server must not do any update.
    public var n: Bool
    /// The name (possibly partial, without the domain).
    public var name: String
    /// True when the name ended in the root label (fully qualified).
    public var fullyQualified: Bool

    public init(s: Bool, o: Bool = false, e: Bool = true, n: Bool = false, name: String, fullyQualified: Bool) {
        self.s = s; self.o = o; self.e = e; self.n = n; self.name = name; self.fullyQualified = fullyQualified
    }

    /// Option 81: flags, RCODE1, RCODE2, name (wire form when E, else ASCII).
    public init(v4 bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        let flags = try r.u8("option 81 flags")
        _ = try r.u8("option 81 rcode1"); _ = try r.u8("option 81 rcode2")
        let rest = r.rest()
        s = flags & 0x01 != 0; o = flags & 0x02 != 0; e = flags & 0x04 != 0; n = flags & 0x08 != 0
        if e {
            let (decoded, _) = try DHCPDNSWire.decode(rest, at: 0)
            name = decoded
            fullyQualified = rest.last == 0
        } else {
            let text = String(decoding: rest.prefix { $0 != 0 }, as: UTF8.self)
            fullyQualified = text.hasSuffix(".")
            name = fullyQualified ? String(text.dropLast()) : text
        }
    }

    /// Option 39: flags, name in wire form.
    public init(v6 bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        let flags = try r.u8("option 39 flags")
        let rest = r.rest()
        s = flags & 0x01 != 0; o = flags & 0x02 != 0; n = flags & 0x04 != 0; e = true
        let (decoded, _) = try DHCPDNSWire.decode(rest, at: 0)
        name = decoded
        fullyQualified = rest.last == 0
    }

    public func encodeV4() -> [UInt8] {
        var flags: UInt8 = 0
        if s { flags |= 0x01 }
        if o { flags |= 0x02 }
        if e { flags |= 0x04 }
        if n { flags |= 0x08 }
        // RFC 4702 §4: a server sets RCODE1/RCODE2 to 255.
        var out: [UInt8] = [flags, 255, 255]
        if e {
            out += (try? DHCPDNSWire.encode(name, terminate: fullyQualified)) ?? []
        } else {
            out += Array((name + (fullyQualified ? "." : "")).utf8)
        }
        return out
    }

    public func encodeV6() -> [UInt8] {
        var flags: UInt8 = 0
        if s { flags |= 0x01 }
        if o { flags |= 0x02 }
        if n { flags |= 0x04 }
        return [flags] + ((try? DHCPDNSWire.encode(name, terminate: fullyQualified)) ?? [])
    }
}
