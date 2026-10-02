import DHCPKit
import Darwin
import Foundation
import Store

/// The configuration snapshot from a store (shared by the server, `labdc dhcp test` and the
/// app's Test box).
public enum DHCPConfigLoader {
    public static func load(_ store: DirectoryStore, advertised: String?) async throws -> DHCPConfig {
        let info = DHCPInterfaceInfo.current()
        var dc6: [String] = []
        if let advertised, let a = IPv4Address(advertised), let owner = info.interfaces.first(where: { $0.ipv4.contains { $0.0 == a } }) {
            dc6 = owner.ipv6.map(\.description)
        }
        return DHCPConfig(scopes: try await store.dhcpScopes(), reservations: try await store.dhcpReservations(),
                          settings: try await store.dhcpSettings(), domain: (try? await store.domainInfo().dnsDomain) ?? "",
                          dcIPv4: advertised, dcIPv6: dc6, serverDUID: try await store.dhcpServerDUID(mac: info.firstMAC ?? []))
    }
}

/// A relayed DISCOVER / SOLICIT run through the real engine against the stored config and
/// leases — nothing is sent and nothing is saved (`labdc dhcp test`, DHCP ▸ Test).
public enum DHCPDryRun {
    public struct V4: Sendable {
        public var giaddr: String
        public var mac: String
        public var vendorClass: String?
        public var hostname: String?
        public var circuitID: String?
        public var remoteID: String?
        public var linkSelection: String?
        public var userClass: String?
        public var parameterList: [UInt8]

        public init(giaddr: String, mac: String, vendorClass: String? = nil, hostname: String? = nil, circuitID: String? = nil,
                    remoteID: String? = nil, linkSelection: String? = nil, userClass: String? = nil,
                    parameterList: [UInt8] = [1, 3, 6, 15, 42, 43, 119, 121, 138, 150]) {
            self.giaddr = giaddr; self.mac = mac; self.vendorClass = vendorClass; self.hostname = hostname
            self.circuitID = circuitID; self.remoteID = remoteID; self.linkSelection = linkSelection; self.userClass = userClass
            self.parameterList = parameterList
        }
    }

    public struct V6: Sendable {
        public var linkAddress: String
        public var duid: String?
        public var mac: String?
        public var vendorClass: String?
        public var hostname: String?

        public init(linkAddress: String, duid: String? = nil, mac: String? = nil, vendorClass: String? = nil, hostname: String? = nil) {
            self.linkAddress = linkAddress; self.duid = duid; self.mac = mac; self.vendorClass = vendorClass; self.hostname = hostname
        }
    }

    /// The relayed DISCOVER the request describes.
    public static func discover(_ r: V4) throws -> DHCPv4Packet {
        guard let gi = IPv4Address(r.giaddr) else { throw CLIError.usage("--giaddr \(r.giaddr) is not an IPv4 address") }
        guard let mac = DHCPMAC.bytes(r.mac) else { throw CLIError.usage("--mac \(r.mac) is not a MAC address") }
        var p = DHCPv4Packet(op: 1, hops: 1, xid: UInt32.random(in: 1...UInt32.max), giaddr: gi, chaddr: mac, options: [
            DHCPv4Option(DHCPv4OptionCode.messageType, [DHCPv4MessageType.discover.rawValue]),
            DHCPv4Option(DHCPv4OptionCode.parameterRequestList, r.parameterList),
        ])
        if let v = r.vendorClass { p[DHCPv4OptionCode.vendorClass] = Array(v.utf8) }
        if let h = r.hostname { p[DHCPv4OptionCode.hostName] = Array(h.utf8) }
        if let u = r.userClass { p[DHCPv4OptionCode.userClass] = [UInt8(min(255, u.utf8.count))] + Array(u.utf8.prefix(255)) }
        var subs: [RelayAgentInformation.SubOption] = []
        if let c = r.circuitID { subs.append(.init(RelayAgentInformation.circuitID, DHCPHex.bytes(c) ?? Array(c.utf8))) }
        if let rid = r.remoteID { subs.append(.init(RelayAgentInformation.remoteID, DHCPHex.bytes(rid) ?? Array(rid.utf8))) }
        if let l = r.linkSelection {
            guard let a = IPv4Address(l) else { throw CLIError.usage("--link-selection \(l) is not an IPv4 address") }
            subs.append(.init(RelayAgentInformation.linkSelection, a.bytes))
        }
        if !subs.isEmpty { p[DHCPv4OptionCode.relayAgentInformation] = RelayAgentInformation(subs).raw }
        return p
    }

    public static func solicit(_ r: V6) throws -> [UInt8] {
        guard let link = IPv6Address(r.linkAddress) else { throw CLIError.usage("--link-address \(r.linkAddress) is not an IPv6 address") }
        let mac = r.mac.flatMap(DHCPMAC.bytes) ?? [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        let duid = try r.duid.map { d -> [UInt8] in
            guard let b = DHCPHex.bytes(d), !b.isEmpty else { throw CLIError.usage("--duid \(d) is not hex") }
            return b
        } ?? ([0, 3, 0, 1] + mac)
        var m = DHCPv6Message(type: .solicit, transactionID: UInt32.random(in: 0...0xFF_FFFF), options: [
            DHCPv6Option(DHCPv6OptionCode.clientID, duid),
            DHCPv6Option(DHCPv6OptionCode.oro, [0, 23, 0, 24, 0, 56]),
            DHCPv6Option(DHCPv6OptionCode.elapsedTime, [0, 0]),
            DHCPv6IANA(iaid: 1).option,
        ])
        if let v = r.vendorClass { m.options.append(DHCPv6Option(DHCPv6OptionCode.vendorClass, [0, 0, 1, 55] + DHCPOptionBuilder.uint16(UInt16(v.utf8.count)) + Array(v.utf8))) }
        if let h = r.hostname { m.options.append(DHCPv6Option(DHCPv6OptionCode.clientFQDN, [1] + ((try? DHCPDNSWire.encode(h, terminate: false)) ?? []))) }
        var relayOptions = [DHCPv6Option(DHCPv6OptionCode.relayMessage, m.encode())]
        if let mb = r.mac.flatMap(DHCPMAC.bytes) { relayOptions.append(DHCPv6Option(DHCPv6OptionCode.clientLinkLayerAddress, [0, 1] + mb)) }
        return DHCPv6RelayMessage(type: .relayForward, hopCount: 0, linkAddress: link, peerAddress: IPv6Address("fe80::1")!,
                                  options: relayOptions).encode()
    }

    /// `OFFER 10.20.0.31 · scope Staff VLAN 20` + the options, or why there is none.
    public static func offer(store: DirectoryStore, _ r: V4, advertised: String?) async throws -> (ok: Bool, lines: [String]) {
        let config = try await DHCPConfigLoader.load(store, advertised: advertised)
        var table = DHCPLeaseTable(try await store.dhcpLeases())
        let p = try discover(r)
        let server = config.settings.serverAddress.flatMap(IPv4Address.init) ?? DHCPInterfaceInfo.localAddress(toward: p.giaddr)
            ?? advertised.flatMap(IPv4Address.init) ?? .zero
        let arrival = DHCPv4Arrival(source: p.giaddr, destination: server, serverAddress: server)
        let out = DHCPv4Engine.handle(p, arrival: arrival, config: config, leases: &table, now: Date())
        guard let reply = out.reply else {
            return (false, ["No OFFER: " + (out.common.quiet?.text ?? "nothing matched")])
        }
        let scope = out.common.scopeID.flatMap { config.scope(id: $0) }
        var lines = ["OFFER \(reply.yiaddr) to \(r.mac) via relay \(r.giaddr)" + (scope.map { " · scope \($0.name)" + ($0.vlan.map { " (VLAN \($0))" } ?? "") } ?? "")]
        if out.common.delayMs > 0 { lines.append("sent after \(out.common.delayMs) ms (offer delay)") }
        lines += DHCPDescribe.v4(reply).map { "  " + $0 }
        if let profile = out.common.profile { lines.append("Device: \(profile.result.category.title) — \(profile.result.os) (\(profile.result.reason))") }
        return (true, lines)
    }

    public static func advertise(store: DirectoryStore, _ r: V6, advertised: String?) async throws -> (ok: Bool, lines: [String]) {
        let config = try await DHCPConfigLoader.load(store, advertised: advertised)
        var table = DHCPLeaseTable(try await store.dhcpLeases())
        let bytes = try solicit(r)
        let arrival = DHCPv6Arrival(source: IPv6Address(r.linkAddress) ?? .zero, destination: IPv6Address("::1"))
        let out = DHCPv6Engine.handle(bytes, arrival: arrival, config: config, leases: &table, now: Date())
        guard let reply = out.reply else { return (false, ["No ADVERTISE: " + (out.common.quiet?.text ?? "nothing matched")]) }
        let scope = out.common.scopeID.flatMap { config.scope(id: $0) }
        let address = reply.iaNAs.first?.addresses.first?.address.description ?? "no address"
        var lines = ["\(reply.type) \(address) via relay link \(r.linkAddress)" + (scope.map { " · scope \($0.name)" } ?? "")]
        lines += DHCPDescribe.v6(reply).map { "  " + $0 }
        return (reply.iaNAs.first?.addresses.isEmpty == false, lines)
    }
}

/// A DHCP relay agent on a UDP socket (tests, `labdc dhcp simulate`, Scripts/dhcp-check.sh):
/// relays a full exchange to a server on any port. v4 sets `giaddr` to the relay's own
/// address plus RFC 3527 link selection and RFC 8357 relay-source-port (82/19), so the server
/// answers to this socket's port; v6 wraps in Relay-forward with option 135.
public final class DHCPTestRelay: @unchecked Sendable {
    let fd: Int32
    let v6: Bool
    public let port: UInt16

    public init(v6: Bool = false) throws {
        self.v6 = v6
        let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self.fd = fd
        guard fd >= 0 else { throw CLIError.failure("socket: \(String(cString: strerror(errno)))") }
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var bound = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        if v6 {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            a.sin6_addr = in6addr_loopback
            _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_addr.s_addr = inet_addr("127.0.0.1")
            _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        let bound6 = v6
        port = withUnsafePointer(to: &bound) { p in
            bound6 ? p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
                   : p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
        }
    }

    deinit { close(fd) }

    /// Sends `bytes` to the server (loopback) and returns the next datagram (nil after the timeout).
    public func exchange(_ bytes: [UInt8], serverPort: UInt16, expectReply: Bool = true) -> [UInt8]? {
        let sent: Int
        if v6 {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            a.sin6_port = serverPort.bigEndian
            a.sin6_addr = in6addr_loopback
            sent = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_port = serverPort.bigEndian
            a.sin_addr.s_addr = inet_addr("127.0.0.1")
            sent = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard sent == bytes.count, expectReply else { return nil }
        return receive()
    }

    public func receive(timeout: TimeInterval? = nil) -> [UInt8]? {
        if let timeout {
            var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1e6))
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        }
        var buf = [UInt8](repeating: 0, count: 65_536)
        let n = recv(fd, &buf, buf.count, 0)
        return n > 0 ? Array(buf.prefix(n)) : nil
    }

    /// Relay agent information for a loopback relay: link selection + relay source port.
    public static func agentInfo(link: IPv4Address, circuit: [UInt8]? = nil, remote: [UInt8]? = nil) -> [UInt8] {
        var subs: [RelayAgentInformation.SubOption] = []
        if let circuit { subs.append(.init(RelayAgentInformation.circuitID, circuit)) }
        if let remote { subs.append(.init(RelayAgentInformation.remoteID, remote)) }
        subs.append(.init(RelayAgentInformation.linkSelection, link.bytes))
        subs.append(.init(RelayAgentInformation.relaySourcePort, []))
        return RelayAgentInformation(subs).raw
    }

    /// A full relayed DORA for `mac` on the scope containing `link`: (OFFER, ACK).
    public func dora(serverPort: UInt16, mac: [UInt8], link: IPv4Address, hostname: String? = nil, vendorClass: String? = nil,
                     extra: [DHCPv4Option] = []) throws -> (offer: DHCPv4Packet?, ack: DHCPv4Packet?) {
        let xid = UInt32.random(in: 1...UInt32.max)
        let agent = Self.agentInfo(link: link)
        var discover = DHCPv4Packet(op: 1, hops: 1, xid: xid, giaddr: IPv4Address("127.0.0.1")!, chaddr: mac, options: [
            DHCPv4Option(DHCPv4OptionCode.messageType, [DHCPv4MessageType.discover.rawValue]),
            DHCPv4Option(DHCPv4OptionCode.parameterRequestList, [1, 3, 6, 15, 42, 43, 119, 121]),
        ] + extra)
        if let hostname { discover[DHCPv4OptionCode.hostName] = Array(hostname.utf8) }
        if let vendorClass { discover[DHCPv4OptionCode.vendorClass] = Array(vendorClass.utf8) }
        discover[DHCPv4OptionCode.relayAgentInformation] = agent
        guard let ob = exchange(discover.encode(), serverPort: serverPort) else { return (nil, nil) }
        let offer = try DHCPv4Packet(bytes: ob)
        guard offer.messageType == .offer, let sid = offer.serverIdentifier else { return (offer, nil) }
        var request = discover
        request[DHCPv4OptionCode.messageType] = [DHCPv4MessageType.request.rawValue]
        request[DHCPv4OptionCode.requestedAddress] = offer.yiaddr.bytes
        request[DHCPv4OptionCode.serverIdentifier] = sid.bytes
        guard let ab = exchange(request.encode(), serverPort: serverPort) else { return (offer, nil) }
        return (offer, try DHCPv4Packet(bytes: ab))
    }

    /// Relay-forward around a client message, with option 135 so the server answers this port.
    public static func relayForward(_ message: DHCPv6Message, link: IPv6Address, mac: [UInt8]? = nil, interfaceID: [UInt8]? = nil) -> [UInt8] {
        var options = [DHCPv6Option(DHCPv6OptionCode.relayMessage, message.encode()), DHCPv6Option(DHCPv6OptionCode.relaySourcePort, [0, 0])]
        if let mac { options.append(DHCPv6Option(DHCPv6OptionCode.clientLinkLayerAddress, [0, 1] + mac)) }
        if let interfaceID { options.append(DHCPv6Option(DHCPv6OptionCode.interfaceID, interfaceID)) }
        return DHCPv6RelayMessage(type: .relayForward, hopCount: 0, linkAddress: link, peerAddress: IPv6Address("fe80::1")!,
                                  options: options).encode()
    }

    /// The client message inside a Relay-reply.
    public static func unwrap(_ bytes: [UInt8]) throws -> (relay: DHCPv6RelayMessage, message: DHCPv6Message) {
        let relay = try DHCPv6RelayMessage(bytes: bytes)
        guard let inner = relay.relayedMessage else { throw CLIError.failure("Relay-reply without a message") }
        return (relay, try DHCPv6Message(bytes: inner))
    }

    /// SOLICIT → ADVERTISE → REQUEST → REPLY for one IA_NA through this relay.
    public func solicitRequest(serverPort: UInt16, duid: [UInt8], link: IPv6Address, mac: [UInt8]? = nil, fqdn: String? = nil,
                               rapidCommit: Bool = false) throws -> (advertise: DHCPv6Message?, reply: DHCPv6Message?) {
        var solicit = DHCPv6Message(type: .solicit, transactionID: UInt32.random(in: 0...0xFF_FFFF), options: [
            DHCPv6Option(DHCPv6OptionCode.clientID, duid), DHCPv6Option(DHCPv6OptionCode.elapsedTime, [0, 0]),
            DHCPv6Option(DHCPv6OptionCode.oro, [0, 23, 0, 24]), DHCPv6IANA(iaid: 7).option,
        ])
        if let fqdn { solicit.options.append(DHCPv6Option(DHCPv6OptionCode.clientFQDN, [1] + ((try? DHCPDNSWire.encode(fqdn, terminate: false)) ?? []))) }
        if rapidCommit { solicit.options.append(DHCPv6Option(DHCPv6OptionCode.rapidCommit, [])) }
        guard let ab = exchange(Self.relayForward(solicit, link: link, mac: mac), serverPort: serverPort) else { return (nil, nil) }
        let advertise = try Self.unwrap(ab).message
        if rapidCommit || advertise.type == .reply { return (nil, advertise) }
        guard let sid = advertise.serverDUID, let ia = advertise.iaNAs.first else { return (advertise, nil) }
        var request = DHCPv6Message(type: .request, transactionID: UInt32.random(in: 0...0xFF_FFFF), options: [
            DHCPv6Option(DHCPv6OptionCode.clientID, duid), DHCPv6Option(DHCPv6OptionCode.serverID, sid),
            DHCPv6Option(DHCPv6OptionCode.elapsedTime, [0, 0]), DHCPv6IANA(iaid: ia.iaid, addresses: ia.addresses).option,
        ])
        if let fqdn { request.options.append(DHCPv6Option(DHCPv6OptionCode.clientFQDN, [1] + ((try? DHCPDNSWire.encode(fqdn, terminate: false)) ?? []))) }
        guard let rb = exchange(Self.relayForward(request, link: link, mac: mac), serverPort: serverPort) else { return (advertise, nil) }
        return (advertise, try Self.unwrap(rb).message)
    }
}
