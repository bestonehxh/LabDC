import Foundation

/// DHCPv6 message types (RFC 8415 §7.3).
public enum DHCPv6MessageType: UInt8, Sendable, CaseIterable, CustomStringConvertible {
    case solicit = 1, advertise, request, confirm, renew, rebind, reply, release, decline, reconfigure, informationRequest
    case relayForward = 12, relayReply = 13

    public var description: String {
        switch self {
        case .solicit: "SOLICIT"
        case .advertise: "ADVERTISE"
        case .request: "REQUEST"
        case .confirm: "CONFIRM"
        case .renew: "RENEW"
        case .rebind: "REBIND"
        case .reply: "REPLY"
        case .release: "RELEASE"
        case .decline: "DECLINE"
        case .reconfigure: "RECONFIGURE"
        case .informationRequest: "INFORMATION-REQUEST"
        case .relayForward: "RELAY-FORW"
        case .relayReply: "RELAY-REPL"
        }
    }
}

/// Option codes (RFC 8415 §21 and others).
public enum DHCPv6OptionCode {
    public static let clientID: UInt16 = 1
    public static let serverID: UInt16 = 2
    public static let iaNA: UInt16 = 3
    public static let iaTA: UInt16 = 4
    public static let iaAddress: UInt16 = 5
    public static let oro: UInt16 = 6
    public static let preference: UInt16 = 7
    public static let elapsedTime: UInt16 = 8
    public static let relayMessage: UInt16 = 9
    public static let serverUnicast: UInt16 = 12
    public static let statusCode: UInt16 = 13
    public static let rapidCommit: UInt16 = 14
    public static let userClass: UInt16 = 15
    public static let vendorClass: UInt16 = 16
    public static let vendorOpts: UInt16 = 17
    public static let interfaceID: UInt16 = 18
    public static let dnsServers: UInt16 = 23
    public static let domainList: UInt16 = 24
    public static let iaPD: UInt16 = 25
    public static let remoteID: UInt16 = 37
    public static let subscriberID: UInt16 = 38
    public static let clientFQDN: UInt16 = 39
    public static let ntpServer: UInt16 = 56
    public static let clientLinkLayerAddress: UInt16 = 79
    public static let relaySourcePort: UInt16 = 135
}

/// Status codes (RFC 8415 §21.13).
public enum DHCPv6Status: UInt16, Sendable {
    case success = 0, unspecFail, noAddrsAvail, noBinding, notOnLink, useMulticast, noPrefixAvail

    public var text: String {
        switch self {
        case .success: "Success"
        case .unspecFail: "UnspecFail"
        case .noAddrsAvail: "NoAddrsAvail"
        case .noBinding: "NoBinding"
        case .notOnLink: "NotOnLink"
        case .useMulticast: "UseMulticast"
        case .noPrefixAvail: "NoPrefixAvail"
        }
    }
}

public struct DHCPv6Option: Sendable, Equatable {
    public var code: UInt16
    public var data: [UInt8]
    public init(_ code: UInt16, _ data: [UInt8]) { self.code = code; self.data = data }

    /// A list of options (`code`, `length`, `data`), every length checked.
    public static func parseList(_ bytes: [UInt8]) throws -> [DHCPv6Option] {
        var r = DHCPReader(bytes)
        var out: [DHCPv6Option] = []
        while !r.isAtEnd {
            let code = try r.u16("option code")
            let len = Int(try r.u16("length of option \(code)"))
            out.append(DHCPv6Option(code, try r.take(len, "option \(code) (\(len) bytes)")))
            guard out.count <= 512 else { throw DHCPError.malformed("too many options") }
        }
        return out
    }

    public static func encodeList(_ options: [DHCPv6Option]) -> [UInt8] {
        var out: [UInt8] = []
        for o in options {
            out.appendU16(o.code)
            out.appendU16(UInt16(min(o.data.count, 0xFFFF)))
            out += o.data.prefix(0xFFFF)
        }
        return out
    }

    public static func status(_ status: DHCPv6Status, _ message: String = "") -> DHCPv6Option {
        DHCPv6Option(DHCPv6OptionCode.statusCode, DHCPOptionBuilder.uint16(status.rawValue) + Array(message.utf8))
    }
}

extension Array where Element == DHCPv6Option {
    public func first(_ code: UInt16) -> [UInt8]? { first { $0.code == code }?.data }
    public func all(_ code: UInt16) -> [[UInt8]] { filter { $0.code == code }.map(\.data) }
}

/// A client/server message: type, 24-bit transaction id, options.
public struct DHCPv6Message: Sendable, Equatable {
    public var type: DHCPv6MessageType
    public var transactionID: UInt32
    public var options: [DHCPv6Option]

    public init(type: DHCPv6MessageType, transactionID: UInt32, options: [DHCPv6Option] = []) {
        self.type = type; self.transactionID = transactionID & 0xFF_FFFF; self.options = options
    }

    public init(bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        let t = try r.u8("message type")
        guard let type = DHCPv6MessageType(rawValue: t), type != .relayForward, type != .relayReply else {
            throw DHCPError.malformed("DHCPv6 message type \(t)")
        }
        let tid = try r.take(3, "transaction id")
        self.type = type
        transactionID = UInt32(tid[0]) << 16 | UInt32(tid[1]) << 8 | UInt32(tid[2])
        options = try DHCPv6Option.parseList(r.rest())
    }

    public func encode() -> [UInt8] {
        [type.rawValue, UInt8(transactionID >> 16 & 0xFF), UInt8(transactionID >> 8 & 0xFF), UInt8(transactionID & 0xFF)]
            + DHCPv6Option.encodeList(options)
    }

    public var clientDUID: [UInt8]? { options.first(DHCPv6OptionCode.clientID) }
    public var serverDUID: [UInt8]? { options.first(DHCPv6OptionCode.serverID) }
    public var hasRapidCommit: Bool { options.contains { $0.code == DHCPv6OptionCode.rapidCommit } }

    public var oro: [UInt16] {
        guard let v = options.first(DHCPv6OptionCode.oro), v.count % 2 == 0 else { return [] }
        return stride(from: 0, to: v.count, by: 2).map { UInt16(v[$0]) << 8 | UInt16(v[$0 + 1]) }
    }

    public var iaNAs: [DHCPv6IANA] { options.all(DHCPv6OptionCode.iaNA).compactMap { try? DHCPv6IANA(bytes: $0) } }
    public var clientFQDN: ClientFQDN? { options.first(DHCPv6OptionCode.clientFQDN).flatMap { try? ClientFQDN(v6: $0) } }

    /// Vendor class (16): enterprise number + the first opaque string.
    public var vendorClass: (enterprise: UInt32, text: String)? {
        guard let v = options.first(DHCPv6OptionCode.vendorClass) else { return nil }
        var r = DHCPReader(v)
        guard let ent = try? r.u32() else { return nil }
        var parts: [String] = []
        while !r.isAtEnd {
            guard let len = try? r.u16(), let data = try? r.take(Int(len)) else { break }
            parts.append(DHCPHex.printable(data))
        }
        return (ent, parts.joined(separator: ","))
    }

    /// User class (15): the opaque strings joined.
    public var userClass: String? {
        guard let v = options.first(DHCPv6OptionCode.userClass) else { return nil }
        var r = DHCPReader(v)
        var parts: [String] = []
        while !r.isAtEnd {
            guard let len = try? r.u16(), let data = try? r.take(Int(len)) else { break }
            parts.append(DHCPHex.printable(data))
        }
        return parts.isEmpty ? nil : parts.joined(separator: ",")
    }
}

/// Relay-forward / Relay-reply (RFC 8415 §9).
public struct DHCPv6RelayMessage: Sendable, Equatable {
    public var type: DHCPv6MessageType
    public var hopCount: UInt8
    public var linkAddress: IPv6Address
    public var peerAddress: IPv6Address
    public var options: [DHCPv6Option]

    public init(type: DHCPv6MessageType, hopCount: UInt8, linkAddress: IPv6Address, peerAddress: IPv6Address,
                options: [DHCPv6Option]) {
        self.type = type; self.hopCount = hopCount; self.linkAddress = linkAddress; self.peerAddress = peerAddress
        self.options = options
    }

    public init(bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        let t = try r.u8("message type")
        guard let type = DHCPv6MessageType(rawValue: t), type == .relayForward || type == .relayReply else {
            throw DHCPError.malformed("not a relay message (\(t))")
        }
        self.type = type
        hopCount = try r.u8("hop count")
        linkAddress = IPv6Address(bytes: try r.take(16, "link-address"))!
        peerAddress = IPv6Address(bytes: try r.take(16, "peer-address"))!
        options = try DHCPv6Option.parseList(r.rest())
    }

    public func encode() -> [UInt8] {
        [type.rawValue, hopCount] + linkAddress.bytes + peerAddress.bytes + DHCPv6Option.encodeList(options)
    }

    public var relayedMessage: [UInt8]? { options.first(DHCPv6OptionCode.relayMessage) }
    public var interfaceID: [UInt8]? { options.first(DHCPv6OptionCode.interfaceID) }
}

/// A datagram on udp 547 unwrapped: the relay chain (outermost first) and the client message.
public struct DHCPv6Envelope: Sendable, Equatable {
    /// Outermost (the relay that sent us the datagram) first, the relay nearest the client last.
    public var relays: [DHCPv6RelayMessage]
    public var message: DHCPv6Message

    /// RFC 8415 §7.6 HOP_COUNT_LIMIT.
    public static let maxHops = 32

    public init(relays: [DHCPv6RelayMessage], message: DHCPv6Message) {
        self.relays = relays
        self.message = message
    }

    public init(bytes: [UInt8]) throws {
        var relays: [DHCPv6RelayMessage] = []
        var current = bytes
        while let first = current.first, first == DHCPv6MessageType.relayForward.rawValue || first == DHCPv6MessageType.relayReply.rawValue {
            let relay = try DHCPv6RelayMessage(bytes: current)
            guard relay.type == .relayForward else { throw DHCPError.malformed("Relay-reply sent to a server") }
            relays.append(relay)
            guard relays.count <= Self.maxHops else { throw DHCPError.malformed("more than \(Self.maxHops) relay layers") }
            guard let inner = relay.relayedMessage else { throw DHCPError.malformed("Relay-forward without a Relay Message option") }
            current = inner
        }
        self.relays = relays
        message = try DHCPv6Message(bytes: current)
    }

    public var isRelayed: Bool { !relays.isEmpty }

    /// RFC 8415 §13.1: the link-address of the relay nearest the client that is not `::`.
    public var linkAddress: IPv6Address? {
        relays.reversed().first { !$0.linkAddress.isZero }?.linkAddress
    }

    /// RFC 6939 client link-layer address from the relay nearest the client: (type, bytes).
    public var clientLinkLayer: (type: UInt16, address: [UInt8])? {
        for relay in relays.reversed() {
            if let v = relay.options.first(DHCPv6OptionCode.clientLinkLayerAddress), v.count > 2 {
                return (UInt16(v[0]) << 8 | UInt16(v[1]), Array(v.dropFirst(2)))
            }
        }
        return nil
    }

    public func relayOption(_ code: UInt16) -> [UInt8]? {
        for relay in relays.reversed() { if let v = relay.options.first(code) { return v } }
        return nil
    }

    /// Wraps `reply` in Relay-reply messages that mirror the chain exactly: same hop count,
    /// link-address and peer-address per layer, Interface-ID echoed per layer (RFC 8415 §19.3),
    /// and the Relay Source Port option echoed per layer (RFC 8357 §5.2) so each relay that used
    /// a non-547 source port gets it back in its own layer.
    public func wrapReply(_ reply: DHCPv6Message) -> [UInt8] {
        var inner = reply.encode()
        for relay in relays.reversed() {
            var options: [DHCPv6Option] = []
            if let iid = relay.interfaceID { options.append(DHCPv6Option(DHCPv6OptionCode.interfaceID, iid)) }
            if let port = relay.options.first(DHCPv6OptionCode.relaySourcePort) {
                options.append(DHCPv6Option(DHCPv6OptionCode.relaySourcePort, port))
            }
            options.append(DHCPv6Option(DHCPv6OptionCode.relayMessage, inner))
            inner = DHCPv6RelayMessage(type: .relayReply, hopCount: relay.hopCount, linkAddress: relay.linkAddress,
                                       peerAddress: relay.peerAddress, options: options).encode()
        }
        return inner
    }
}

/// IA_NA (RFC 8415 §21.4) with its IA Address options (§21.6).
public struct DHCPv6IANA: Sendable, Equatable {
    public struct Address: Sendable, Equatable {
        public var address: IPv6Address
        public var preferred: UInt32
        public var valid: UInt32
        public var options: [DHCPv6Option]
        public init(address: IPv6Address, preferred: UInt32, valid: UInt32, options: [DHCPv6Option] = []) {
            self.address = address; self.preferred = preferred; self.valid = valid; self.options = options
        }
    }

    public var iaid: UInt32
    public var t1: UInt32
    public var t2: UInt32
    public var addresses: [Address]
    /// Options other than IA Address (status code).
    public var options: [DHCPv6Option]

    public init(iaid: UInt32, t1: UInt32 = 0, t2: UInt32 = 0, addresses: [Address] = [], options: [DHCPv6Option] = []) {
        self.iaid = iaid; self.t1 = t1; self.t2 = t2; self.addresses = addresses; self.options = options
    }

    public init(bytes: [UInt8]) throws {
        var r = DHCPReader(bytes)
        iaid = try r.u32("IAID"); t1 = try r.u32("T1"); t2 = try r.u32("T2")
        var addresses: [Address] = []
        var others: [DHCPv6Option] = []
        for o in try DHCPv6Option.parseList(r.rest()) {
            if o.code == DHCPv6OptionCode.iaAddress {
                var a = DHCPReader(o.data)
                let addr = IPv6Address(bytes: try a.take(16, "IA address"))!
                let pref = try a.u32("preferred lifetime"), valid = try a.u32("valid lifetime")
                addresses.append(Address(address: addr, preferred: pref, valid: valid, options: try DHCPv6Option.parseList(a.rest())))
            } else {
                others.append(o)
            }
        }
        self.addresses = addresses
        options = others
    }

    public func encode() -> [UInt8] {
        var out: [UInt8] = []
        out.appendU32(iaid); out.appendU32(t1); out.appendU32(t2)
        var inner: [DHCPv6Option] = addresses.map { a in
            var d = a.address.bytes
            d.appendU32(a.preferred); d.appendU32(a.valid)
            d += DHCPv6Option.encodeList(a.options)
            return DHCPv6Option(DHCPv6OptionCode.iaAddress, d)
        }
        inner += options
        return out + DHCPv6Option.encodeList(inner)
    }

    public var option: DHCPv6Option { DHCPv6Option(DHCPv6OptionCode.iaNA, encode()) }

    public var status: DHCPv6Status? {
        guard let v = options.first(DHCPv6OptionCode.statusCode), v.count >= 2 else { return nil }
        return DHCPv6Status(rawValue: UInt16(v[0]) << 8 | UInt16(v[1]))
    }
}

/// DUIDs (RFC 8415 §11).
public enum DHCPv6DUID {
    /// The DUID type (1 LLT, 2 EN, 3 LL, 4 UUID).
    public static func type(_ duid: [UInt8]) -> UInt16? {
        guard duid.count >= 2 else { return nil }
        return UInt16(duid[0]) << 8 | UInt16(duid[1])
    }

    /// The link-layer address inside a DUID-LLT/DUID-LL with hardware type 1 (Ethernet).
    public static func mac(_ duid: [UInt8]) -> String? {
        guard let t = type(duid), duid.count >= 4 else { return nil }
        let htype = UInt16(duid[2]) << 8 | UInt16(duid[3])
        guard htype == 1 else { return nil }
        if t == 1, duid.count == 14 { return DHCPMAC.string(Array(duid[8..<14])) }
        if t == 3, duid.count == 10 { return DHCPMAC.string(Array(duid[4..<10])) }
        return nil
    }

    /// DUID-LLT for Ethernet: type 1, htype 1, seconds since 2000-01-01 UTC, the MAC.
    public static func llt(mac: [UInt8], time: Date) -> [UInt8] {
        var out: [UInt8] = [0, 1, 0, 1]
        let seconds = UInt32(truncatingIfNeeded: Int64(max(0, time.timeIntervalSince1970 - 946_684_800)))
        out.appendU32(seconds)
        return out + mac
    }

    public static func describe(_ duid: [UInt8]) -> String {
        switch type(duid) {
        case 1: "DUID-LLT"
        case 2: "DUID-EN"
        case 3: "DUID-LL"
        case 4: "DUID-UUID"
        default: "DUID"
        }
    }
}
