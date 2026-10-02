import DHCPKit
import Darwin
import Foundation
import Synchronization

/// One datagram from `recvmsg` with what the control messages said.
struct DHCPDatagram: Sendable {
    var bytes: [UInt8]
    var sourceV4: IPv4Address?
    var sourceV6: IPv6Address?
    var sourcePort: UInt16
    var destinationV4: IPv4Address?
    var destinationV6: IPv6Address?
    var interfaceIndex: UInt32?
}

/// A BSD UDP socket for udp 67 / 547 (spec rev 2 §Sockets): `recvmsg` with `IP_RECVDSTADDR` +
/// `IP_RECVIF` (v4) or `IPV6_RECVPKTINFO` (v6), so the server knows whether a datagram was a
/// broadcast on the Mac's own segment; replies go to `giaddr`:67 / the relay's source :547
/// rather than back along the flow. Bound exclusively (no SO_REUSEPORT): another DHCP server
/// on this Mac (bootpd for Internet Sharing) shows as a port problem.
final class DHCPUDPSocket: @unchecked Sendable {
    enum Family: Sendable { case v4, v6 }

    let fd: Int32
    let family: Family
    let port: UInt16
    private let source: DispatchSourceRead

    init(family: Family, port: UInt16, queue: DispatchQueue, handler: @escaping @Sendable (DHCPDatagram) -> Void) throws {
        let fd = socket(family == .v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw DHCPNetError.posix("socket", errno) }
        var one: Int32 = 1
        func set(_ level: Int32, _ name: Int32) { _ = setsockopt(fd, level, name, &one, socklen_t(MemoryLayout<Int32>.size)) }
        let rc: Int32
        if family == .v4 {
            set(SOL_SOCKET, SO_BROADCAST)
            set(IPPROTO_IP, IP_RECVDSTADDR)
            set(IPPROTO_IP, IP_RECVIF)
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        } else {
            set(IPPROTO_IPV6, IPV6_V6ONLY)
            set(IPPROTO_IPV6, Self.ipv6RecvPktInfo)
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            addr.sin6_addr = in6addr_any
            rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        }
        guard rc == 0 else {
            let e = errno
            close(fd)
            throw DHCPNetError.posix("bind udp \(port)", e)
        }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        var bound = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        let boundPort: UInt16 = withUnsafePointer(to: &bound) { p in
            family == .v4 ? p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
                          : p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
        }
        self.fd = fd
        self.family = family
        self.port = boundPort
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [fd, family] in
            while let d = DHCPUDPSocket.receive(fd: fd, family: family) { handler(d) }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
    }

    func cancel() { source.cancel() }

    // MARK: Receive

    /// RFC 3542 values (Darwin exposes them only under `__APPLE_USE_RFC_3542`).
    static let ipv6RecvPktInfo: Int32 = 61
    static let ipv6PktInfo: Int32 = 46

    static let cmsgHeader = 12   // CMSG_DATA offset on Darwin (align32(sizeof(cmsghdr)))

    static func align32(_ n: Int) -> Int { (n + 3) & ~3 }

    static func receive(fd: Int32, family: Family) -> DHCPDatagram? {
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var control = [UInt8](repeating: 0, count: 512)
        var storage = sockaddr_storage()
        var controlLength = 0
        let n: Int = buffer.withUnsafeMutableBytes { buf in
            control.withUnsafeMutableBytes { ctl in
                withUnsafeMutablePointer(to: &storage) { name in
                    var iov = iovec(iov_base: buf.baseAddress, iov_len: buf.count)
                    return withUnsafeMutablePointer(to: &iov) { iovp in
                        var msg = msghdr(msg_name: UnsafeMutableRawPointer(name), msg_namelen: socklen_t(MemoryLayout<sockaddr_storage>.size),
                                         msg_iov: iovp, msg_iovlen: 1, msg_control: ctl.baseAddress,
                                         msg_controllen: socklen_t(ctl.count), msg_flags: 0)
                        let r = recvmsg(fd, &msg, 0)
                        controlLength = Int(msg.msg_controllen)
                        return r
                    }
                }
            }
        }
        guard n > 0 else { return nil }
        var d = DHCPDatagram(bytes: Array(buffer.prefix(n)), sourcePort: 0)
        withUnsafePointer(to: &storage) { p in
            if family == .v4 {
                p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    d.sourceV4 = IPv4Address(UInt32(bigEndian: $0.pointee.sin_addr.s_addr))
                    d.sourcePort = UInt16(bigEndian: $0.pointee.sin_port)
                }
            } else {
                p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    let a = $0.pointee.sin6_addr
                    d.sourceV6 = IPv6Address(bytes: withUnsafeBytes(of: a) { Array($0) })
                    d.sourcePort = UInt16(bigEndian: $0.pointee.sin6_port)
                    if $0.pointee.sin6_scope_id != 0 { d.interfaceIndex = $0.pointee.sin6_scope_id }
                }
            }
        }
        parseControl(Array(control.prefix(max(0, min(controlLength, control.count)))), into: &d)
        return d
    }

    /// Walks the cmsg list: IP_RECVDSTADDR (in_addr), IP_RECVIF (sockaddr_dl → sdl_index),
    /// IPV6_PKTINFO (in6_pktinfo).
    static func parseControl(_ c: [UInt8], into d: inout DHCPDatagram) {
        var offset = 0
        while offset + cmsgHeader <= c.count {
            let len = Int(c[offset..<offset + 4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
            let level = c[offset + 4..<offset + 8].withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
            let type = c[offset + 8..<offset + 12].withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
            guard len >= cmsgHeader, offset + len <= c.count else { return }
            let data = Array(c[offset + cmsgHeader..<offset + len])
            if level == IPPROTO_IP, type == IP_RECVDSTADDR, data.count >= 4 {
                d.destinationV4 = IPv4Address(bytes: data.prefix(4))
            } else if level == IPPROTO_IP, type == IP_RECVIF, data.count >= 4 {
                d.interfaceIndex = UInt32(data[2...3].withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            } else if level == IPPROTO_IPV6, type == ipv6PktInfo, data.count >= 20 {
                d.destinationV6 = IPv6Address(bytes: data.prefix(16))
                d.interfaceIndex = data[16..<20].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            }
            offset += align32(len)
        }
    }

    // MARK: Send

    /// Sends to `address`:`port`; `interface` picks the outgoing interface (IP_PKTINFO /
    /// IPV6_PKTINFO) for broadcasts and link-local destinations. Returns errno or nil.
    @discardableResult
    func send(_ bytes: [UInt8], v4 address: IPv4Address, port: UInt16, interface: UInt32? = nil) -> Int32? {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = address.value.bigEndian
        var control: [UInt8] = []
        if let interface {
            // struct in_pktinfo { ipi_ifindex; ipi_spec_dst; ipi_addr } = 12 bytes.
            control = Self.cmsg(level: IPPROTO_IP, type: IP_PKTINFO, data: withUnsafeBytes(of: interface) { Array($0) } + [UInt8](repeating: 0, count: 8))
        }
        let r = Self.sendmsg(fd, bytes, &addr, control)
        if r != nil, interface != nil, address == .broadcast {
            // Fallback: a one-off socket bound to the interface (IP_BOUND_IF).
            return Self.boundBroadcast(bytes, port: port, interface: interface!)
        }
        return r
    }

    @discardableResult
    func send(_ bytes: [UInt8], v6 address: IPv6Address, port: UInt16, interface: UInt32? = nil) -> Int32? {
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        let b = address.bytes
        withUnsafeMutableBytes(of: &addr.sin6_addr) { raw in for i in 0..<16 { raw[i] = b[i] } }
        if let interface, address.isLinkLocal || address.isMulticast { addr.sin6_scope_id = interface }
        return Self.sendmsg(fd, bytes, &addr, [])
    }

    static func cmsg(level: Int32, type: Int32, data: [UInt8]) -> [UInt8] {
        let len = cmsgHeader + data.count
        var out = withUnsafeBytes(of: UInt32(len)) { Array($0) } + withUnsafeBytes(of: level) { Array($0) } + withUnsafeBytes(of: type) { Array($0) }
        out += data
        out += [UInt8](repeating: 0, count: align32(len) - len)
        return out
    }

    private static func sendmsg<A>(_ fd: Int32, _ bytes: [UInt8], _ addr: inout A, _ control: [UInt8]) -> Int32? {
        var control = control
        let size = socklen_t(MemoryLayout<A>.size)
        let r: Int = bytes.withUnsafeBytes { buf in
            control.withUnsafeMutableBytes { ctl in
                withUnsafeMutablePointer(to: &addr) { name in
                    var iov = iovec(iov_base: UnsafeMutableRawPointer(mutating: buf.baseAddress), iov_len: buf.count)
                    return withUnsafeMutablePointer(to: &iov) { iovp in
                        var msg = msghdr(msg_name: UnsafeMutableRawPointer(name), msg_namelen: size, msg_iov: iovp, msg_iovlen: 1,
                                         msg_control: ctl.isEmpty ? nil : ctl.baseAddress, msg_controllen: socklen_t(ctl.count), msg_flags: 0)
                        return Darwin.sendmsg(fd, &msg, 0)
                    }
                }
            }
        }
        return r < 0 ? errno : nil
    }

    static func boundBroadcast(_ bytes: [UInt8], port: UInt16, interface: UInt32) -> Int32? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return errno }
        defer { close(fd) }
        var one: Int32 = 1
        var index = interface
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_BROADCAST
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return r < 0 ? errno : nil
    }

    /// Direct mode on v6: listen to All_DHCP_Relay_Agents_and_Servers on `interface`.
    func joinAllDHCPAgents(interface: UInt32) -> Int32? {
        var mreq = ipv6_mreq()
        let b = IPv6Address.allRelayAgentsAndServers.bytes
        withUnsafeMutableBytes(of: &mreq.ipv6mr_multiaddr) { raw in for i in 0..<16 { raw[i] = b[i] } }
        mreq.ipv6mr_interface = interface
        let r = setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, socklen_t(MemoryLayout<ipv6_mreq>.size))
        return r == 0 ? nil : errno
    }
}

enum DHCPNetError: Error, CustomStringConvertible {
    case posix(String, Int32)
    case refused(String)

    var description: String {
        switch self {
        case .posix(let what, let e): "\(what): \(String(cString: strerror(e)))"
        case .refused(let s): s
        }
    }
}

/// This Mac's interfaces as the DHCP server needs them: index ↔ name, IPv4 + mask, global IPv6,
/// MAC. Re-read on demand (cheap) and cached for a few seconds by the server.
public struct DHCPInterfaceInfo: Sendable {
    public struct Interface: Sendable {
        public var name: String
        public var index: UInt32
        public var ipv4: [(IPv4Address, IPv4Subnet)]
        public var ipv6: [IPv6Address]
        public var mac: [UInt8]?
    }

    public var interfaces: [Interface]

    public static func current() -> DHCPInterfaceInfo {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return DHCPInterfaceInfo(interfaces: []) }
        defer { freeifaddrs(head) }
        var byName: [String: Interface] = [:]
        var order: [String] = []
        var cursor = head
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            if byName[name] == nil {
                byName[name] = Interface(name: name, index: if_nametoindex(name), ipv4: [], ipv6: [], mac: nil)
                order.append(name)
            }
            guard let sa = entry.pointee.ifa_addr else { continue }
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                let a = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { IPv4Address(UInt32(bigEndian: $0.pointee.sin_addr.s_addr)) }
                var prefix = 32
                if let m = entry.pointee.ifa_netmask {
                    let mask = m.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                    prefix = mask.nonzeroBitCount
                }
                byName[name]?.ipv4.append((a, IPv4Subnet(address: a, prefix: prefix)))
            case AF_INET6:
                let a = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                    IPv6Address(bytes: withUnsafeBytes(of: p.pointee.sin6_addr) { Array($0) })
                }
                if let a, !a.isLinkLocal, a.value != 1, !a.isMulticast { byName[name]?.ipv6.append(a) }
            case AF_LINK:
                let mac: [UInt8]? = sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { p in
                    let nlen = Int(p.pointee.sdl_nlen), alen = Int(p.pointee.sdl_alen)
                    guard alen == 6 else { return nil }
                    return withUnsafeBytes(of: p.pointee.sdl_data) { raw in
                        guard nlen + 6 <= raw.count else { return nil }
                        return Array(raw[nlen..<nlen + 6])
                    }
                }
                if let mac { byName[name]?.mac = mac }
            default: break
            }
        }
        return DHCPInterfaceInfo(interfaces: order.compactMap { byName[$0] })
    }

    public func interface(index: UInt32) -> Interface? { interfaces.first { $0.index == index } }
    public func interface(named name: String) -> Interface? { interfaces.first { $0.name == name } }

    public var allIPv4: Set<IPv4Address> { Set(interfaces.flatMap { $0.ipv4.map(\.0) }) }

    /// A MAC for the server DUID: the first Ethernet-like interface's.
    public var firstMAC: [UInt8]? {
        interfaces.first { $0.name.hasPrefix("en") && $0.mac != nil }?.mac ?? interfaces.first { $0.mac != nil }?.mac
    }

    /// The local IPv4 the kernel would use to reach `destination` (the server identifier for a relay).
    public static func localAddress(toward destination: IPv4Address) -> IPv4Address? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(67).bigEndian
        addr.sin_addr.s_addr = destination.value.bigEndian
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0 else { return nil }
        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let r = withUnsafeMutablePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        guard r == 0 else { return nil }
        let a = IPv4Address(UInt32(bigEndian: local.sin_addr.s_addr))
        return a.isZero ? nil : a
    }
}

/// ICMP echo without root (macOS `SOCK_DGRAM` + `IPPROTO_ICMP`): ping-before-offer.
public enum DHCPPing {
    /// True when `address` answers within `timeout`.
    public static func isInUse(_ address: IPv4Address, timeout: TimeInterval = 0.3) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        let ident = UInt16.random(in: 1...UInt16.max)
        var packet: [UInt8] = [8, 0, 0, 0, UInt8(ident >> 8), UInt8(ident & 0xFF), 0, 1] + Array("labdc-dhcp".utf8)
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8); packet[3] = UInt8(sum & 0xFF)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = address.value.bigEndian
        let sent = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, packet, packet.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard sent == packet.count else { return false }
        let deadline = Date().addingTimeInterval(timeout)
        var buffer = [UInt8](repeating: 0, count: 1500)
        while Date() < deadline {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ms = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
            guard poll(&pfd, 1, ms) > 0 else { return false }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &len) }
            }
            guard n > 0 else { continue }
            guard UInt32(bigEndian: from.sin_addr.s_addr) == address.value else { continue }
            // macOS delivers the IP header on ICMP datagram sockets.
            var offset = 0
            if buffer[0] >> 4 == 4 { offset = Int(buffer[0] & 0x0F) * 4 }
            if n > offset, buffer[offset] == 0 { return true }
        }
        return false
    }

    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count { sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1]); i += 2 }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum)
    }
}

/// The direct-mode probe (spec §1): a DISCOVER broadcast on the interface; any OFFER means
/// another DHCP server serves that segment and direct mode is refused.
public enum DHCPProbe {
    public struct Result: Sendable, Equatable {
        /// Server identifiers (or source addresses) of the servers that answered.
        public var servers: [String]
        public var problem: String?
        public var clear: Bool { servers.isEmpty && problem == nil }
    }

    /// - Parameters:
    ///   - interface: BSD name to send on (nil: no interface binding, tests).
    ///   - destination / serverPort / clientPort: 255.255.255.255:67 from :68 normally; tests
    ///     use loopback and high ports.
    public static func run(interface: String?, timeout: TimeInterval = 3, destination: IPv4Address = .broadcast,
                           serverPort: UInt16 = 67, clientPort: UInt16 = 68) -> Result {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return Result(servers: [], problem: "socket: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, socklen_t(MemoryLayout<Int32>.size))
        var mac: [UInt8] = [0x02] + (0..<5).map { _ in UInt8.random(in: 0...255) }
        if let interface {
            var index = if_nametoindex(interface)
            guard index != 0 else { return Result(servers: [], problem: "no interface \(interface)") }
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
            if let real = DHCPInterfaceInfo.current().interface(named: interface)?.mac { mac = real }
        }
        var local = sockaddr_in()
        local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        local.sin_family = sa_family_t(AF_INET)
        local.sin_port = clientPort.bigEndian
        let rc = withUnsafePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0 else {
            return Result(servers: [], problem: "cannot listen on udp \(clientPort) for the probe: \(String(cString: strerror(errno)))")
        }
        let xid = UInt32.random(in: 1...UInt32.max)
        var discover = DHCPv4Packet(op: 1, xid: xid, flags: DHCPv4Packet.broadcastFlag, chaddr: mac, options: [
            DHCPv4Option(DHCPv4OptionCode.messageType, [DHCPv4MessageType.discover.rawValue]),
            DHCPv4Option(DHCPv4OptionCode.parameterRequestList, [1, 3, 6, 15]),
            DHCPv4Option(DHCPv4OptionCode.vendorClass, Array("LabDC probe".utf8)),
        ])
        discover.secs = 0
        let bytes = discover.encode()
        var dest = sockaddr_in()
        dest.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port = serverPort.bigEndian
        dest.sin_addr.s_addr = destination.value.bigEndian
        var servers: [String] = []
        let deadline = Date().addingTimeInterval(timeout)
        var nextSend = Date()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while Date() < deadline {
            if Date() >= nextSend {
                let sent = withUnsafePointer(to: &dest) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
                if sent < 0 { return Result(servers: servers, problem: "cannot send the probe: \(String(cString: strerror(errno)))") }
                nextSend = Date().addingTimeInterval(1)
            }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ms = Int32(max(1, min(deadline, nextSend).timeIntervalSinceNow * 1000))
            guard poll(&pfd, 1, ms) > 0 else { continue }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &len) }
            }
            guard n > 0, let reply = try? DHCPv4Packet(bytes: Array(buffer.prefix(n))), reply.op == 2, reply.xid == xid,
                  reply.messageType == .offer else { continue }
            let who = reply.serverIdentifier?.description ?? IPv4Address(UInt32(bigEndian: from.sin_addr.s_addr)).description
            if !servers.contains(who) { servers.append(who) }
        }
        return Result(servers: servers, problem: nil)
    }
}
