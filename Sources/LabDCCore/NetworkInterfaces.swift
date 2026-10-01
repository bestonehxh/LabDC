import Darwin
import Foundation
import SystemConfiguration

/// One IPv4 interface of this Mac, as the interface picker lists it (`Wi-Fi 192.168.1.155`).
public struct NetworkInterfaceChoice: Hashable, Sendable, Identifiable {
    /// `en0`, `utun4`, `bridge100`.
    public var bsdName: String
    /// `Wi-Fi`, `Ethernet`, `Tailscale`, `VPN (utun4)`, or the BSD name.
    public var displayName: String
    public var ipv4: String

    public var id: String { ipv4 }

    public init(bsdName: String, displayName: String, ipv4: String) {
        self.bsdName = bsdName
        self.displayName = displayName
        self.ipv4 = ipv4
    }

    /// `Wi-Fi 192.168.1.155`.
    public var label: String { "\(displayName) \(ipv4)" }
}

/// The interfaces devices can reach this Mac on, with names people recognise.
public enum NetworkInterfaces {
    /// Every up, non-loopback, non-link-local IPv4 address with its interface, in the order
    /// "automatic" uses (`ServeAddresses.current()`: numeric), names from SystemConfiguration.
    public static func current() -> [NetworkInterfaceChoice] {
        let scNames = systemConfigurationNames()
        return ipv4ByInterface().map { bsd, ip in
            NetworkInterfaceChoice(bsdName: bsd, displayName: displayName(bsdName: bsd, ipv4: ip, scName: scNames[bsd]), ipv4: ip)
        }
        .sorted { numeric($0.ipv4) < numeric($1.ipv4) }
    }

    /// The interface an address belongs to (nil when no interface has it).
    public static func choice(for ipv4: String?, in list: [NetworkInterfaceChoice] = current()) -> NetworkInterfaceChoice? {
        guard let ipv4 else { return nil }
        return list.first { $0.ipv4 == ipv4 }
    }

    /// The label rules: SystemConfiguration's name (`Wi-Fi`, `Ethernet`, `Thunderbolt Bridge`); a
    /// `utun` in 100.64.0.0/10 (CGNAT, Tailscale's range) is `Tailscale`; another `utun`/`ipsec`/`ppp`
    /// is `VPN (utun4)`; `bridge1xx` is `Virtual machines`; else the BSD name.
    public static func displayName(bsdName: String, ipv4: String, scName: String?) -> String {
        let isTunnel = bsdName.hasPrefix("utun") || bsdName.hasPrefix("ipsec") || bsdName.hasPrefix("ppp")
        if bsdName.hasPrefix("utun"), isCGNAT(ipv4) { return "Tailscale" }
        if let scName, !scName.isEmpty { return scName }
        if isTunnel { return "VPN (\(bsdName))" }
        if bsdName.hasPrefix("bridge") { return "Virtual machines (\(bsdName))" }
        return bsdName
    }

    /// 100.64.0.0/10.
    public static func isCGNAT(_ ipv4: String) -> Bool {
        let parts = ipv4.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 100 && (64...127).contains(parts[1])
    }

    static func numeric(_ ipv4: String) -> UInt32 {
        ipv4.split(separator: ".").compactMap { UInt32($0) }.reduce(0) { $0 << 8 | $1 }
    }

    /// `en0` → `Wi-Fi` from SystemConfiguration (empty when unavailable).
    static func systemConfigurationNames() -> [String: String] {
        guard let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [:] }
        var names: [String: String] = [:]
        for interface in all {
            guard let bsd = SCNetworkInterfaceGetBSDName(interface) as String? else { continue }
            if let name = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String? { names[bsd] = name }
        }
        return names
    }

    /// `(bsd name, ipv4)` for every usable IPv4 address (the same filter as `NetworkAddresses`).
    static func ipv4ByInterface() -> [(String, String)] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return [] }
        defer { freeifaddrs(head) }
        var out: [(String, String)] = []
        var seen = Set<String>()
        var cursor = head
        while let ifa = cursor {
            cursor = ifa.pointee.ifa_next
            let flags = Int32(bitPattern: ifa.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let address = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let a = address >> 24, b = (address >> 16) & 0xFF
            if a == 127 || a == 0 || (a == 169 && b == 254) { continue }
            let ip = "\(a).\(b).\((address >> 8) & 0xFF).\(address & 0xFF)"
            guard seen.insert(ip).inserted else { continue }
            out.append((String(cString: ifa.pointee.ifa_name), ip))
        }
        return out
    }
}
