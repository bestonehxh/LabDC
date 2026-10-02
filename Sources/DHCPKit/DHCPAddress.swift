import Darwin
import Foundation

/// An IPv4 address as a host-order integer (arithmetic for ranges and subnets).
public struct IPv4Address: Hashable, Comparable, Sendable, CustomStringConvertible, Codable {
    public var value: UInt32

    public init(_ value: UInt32) { self.value = value }

    public init?(_ text: String) {
        var a = in_addr()
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, inet_pton(AF_INET, t, &a) == 1 else { return nil }
        value = UInt32(bigEndian: a.s_addr)
    }

    /// Four bytes in network order; nil for any other length.
    public init?(bytes: some Collection<UInt8>) {
        guard bytes.count == 4 else { return nil }
        value = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }

    public static let zero = IPv4Address(0)
    public static let broadcast = IPv4Address(0xFFFF_FFFF)

    public var bytes: [UInt8] { [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)] }
    public var isZero: Bool { value == 0 }
    public var description: String { bytes.map(String.init).joined(separator: ".") }
    public static func < (a: IPv4Address, b: IPv4Address) -> Bool { a.value < b.value }

    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let a = IPv4Address(text) else { throw DHCPError.invalid("\(text) is not an IPv4 address") }
        self = a
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }
}

/// An IPv6 address as a 128-bit integer.
public struct IPv6Address: Hashable, Comparable, Sendable, CustomStringConvertible {
    public var value: UInt128

    public init(_ value: UInt128) { self.value = value }

    /// Text form; a `%scope` suffix is ignored.
    public init?(_ text: String) {
        var a = in6_addr()
        let t = text.trimmingCharacters(in: .whitespaces).split(separator: "%", maxSplits: 1).first.map(String.init) ?? ""
        guard !t.isEmpty, inet_pton(AF_INET6, t, &a) == 1 else { return nil }
        let b = withUnsafeBytes(of: a) { Array($0) }
        self.init(bytes: b)!
    }

    public init?(bytes: some Collection<UInt8>) {
        guard bytes.count == 16 else { return nil }
        value = bytes.reduce(UInt128(0)) { $0 << 8 | UInt128($1) }
    }

    public static let zero = IPv6Address(0)
    /// All_DHCP_Relay_Agents_and_Servers (RFC 8415 §7.1).
    public static let allRelayAgentsAndServers = IPv6Address("ff02::1:2")!

    public var bytes: [UInt8] { (0..<16).map { UInt8(truncatingIfNeeded: value >> (8 * (15 - $0))) } }
    public var isZero: Bool { value == 0 }
    public var isLinkLocal: Bool { value >> 118 == 0x3FA }       // fe80::/10
    public var isMulticast: Bool { value >> 120 == 0xFF }

    public var description: String {
        var a = in6_addr()
        let b = bytes
        withUnsafeMutableBytes(of: &a) { raw in for i in 0..<16 { raw[i] = b[i] } }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &a, &buffer, socklen_t(buffer.count)) != nil else { return "::" }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    public static func < (a: IPv6Address, b: IPv6Address) -> Bool { a.value < b.value }
}

/// An IPv4 subnet (`10.20.0.0/24`).
public struct IPv4Subnet: Hashable, Sendable, CustomStringConvertible {
    public var network: IPv4Address
    public var prefix: Int

    public init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/")
        guard parts.count == 2, let a = IPv4Address(String(parts[0])), let p = Int(parts[1]), (0...32).contains(p) else { return nil }
        self.init(address: a, prefix: p)
    }

    public init(address: IPv4Address, prefix: Int) {
        self.prefix = max(0, min(32, prefix))
        network = IPv4Address(address.value & Self.mask(self.prefix))
    }

    static func mask(_ prefix: Int) -> UInt32 { prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix) }

    public var mask: IPv4Address { IPv4Address(Self.mask(prefix)) }
    public var broadcast: IPv4Address { IPv4Address(network.value | ~Self.mask(prefix)) }
    public var size: UInt64 { UInt64(1) << UInt64(32 - prefix) }
    public func contains(_ a: IPv4Address) -> Bool { a.value & Self.mask(prefix) == network.value }
    /// A usable host address: not the network or broadcast address (both usable in /31, /32).
    public func isHost(_ a: IPv4Address) -> Bool {
        guard contains(a) else { return false }
        return prefix >= 31 || (a != network && a != broadcast)
    }
    public var description: String { "\(network)/\(prefix)" }
}

/// An IPv6 prefix (`2001:db8:20::/64`).
public struct IPv6Subnet: Hashable, Sendable, CustomStringConvertible {
    public var network: IPv6Address
    public var prefix: Int

    public init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/")
        guard parts.count == 2, let a = IPv6Address(String(parts[0])), let p = Int(parts[1]), (0...128).contains(p) else { return nil }
        self.init(address: a, prefix: p)
    }

    public init(address: IPv6Address, prefix: Int) {
        self.prefix = max(0, min(128, prefix))
        network = IPv6Address(address.value & Self.mask(self.prefix))
    }

    static func mask(_ prefix: Int) -> UInt128 { prefix == 0 ? 0 : UInt128.max << UInt128(128 - prefix) }
    public func contains(_ a: IPv6Address) -> Bool { a.value & Self.mask(prefix) == network.value }
    public var description: String { "\(network)/\(prefix)" }
}

/// Address-or-CIDR-or-range patterns (allowed relays, profiler lists).
public enum DHCPAddressPattern {
    /// `10.0.0.1`, `10.0.0.0/8`, `10.0.0.1-10.0.0.9`, `fd00::/64`, `fd00::1`.
    public static func matches(_ pattern: String, _ address: String) -> Bool {
        let p = pattern.trimmingCharacters(in: .whitespaces)
        let host = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        if let v4 = IPv4Address(host) {
            if let s = IPv4Subnet(p) { return s.contains(v4) }
            if let range = rangeV4(p) { return range.contains(v4) }
            return IPv4Address(p) == v4
        }
        if let v6 = IPv6Address(host) {
            // IPv4-mapped (::ffff:a.b.c.d) matches IPv4 patterns too.
            if v6.value >> 32 == 0xFFFF, let v4 = IPv4Address(bytes: v6.bytes.suffix(4)) {
                if matches(p, v4.description) { return true }
            }
            if let s = IPv6Subnet(p) { return s.contains(v6) }
            return IPv6Address(p) == v6
        }
        return false
    }

    public static func isValid(_ pattern: String) -> Bool {
        let p = pattern.trimmingCharacters(in: .whitespaces)
        return IPv4Address(p) != nil || IPv4Subnet(p) != nil || rangeV4(p) != nil || IPv6Address(p) != nil || IPv6Subnet(p) != nil
    }

    static func rangeV4(_ p: String) -> ClosedRange<IPv4Address>? {
        let parts = p.split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2, let a = IPv4Address(parts[0]), let b = IPv4Address(parts[1]), a <= b else { return nil }
        return a...b
    }
}
