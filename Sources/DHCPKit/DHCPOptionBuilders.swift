import Foundation

/// Encoders for the structured options a scope hands out.
public enum DHCPOptionBuilder {
    /// A list of IPv4 addresses (options 3, 6, 42, 150; 138 CAPWAP AC list, RFC 5417 §3).
    public static func ipv4List(_ addresses: [String]) throws -> [UInt8] {
        try addresses.flatMap { text -> [UInt8] in
            guard let a = IPv4Address(text) else { throw DHCPError.invalid("\(text) is not an IPv4 address") }
            return a.bytes
        }
    }

    public static func ipv6List(_ addresses: [String]) throws -> [UInt8] {
        try addresses.flatMap { text -> [UInt8] in
            guard let a = IPv6Address(text) else { throw DHCPError.invalid("\(text) is not an IPv6 address") }
            return a.bytes
        }
    }

    /// Option 138 (RFC 5417): CAPWAP access controllers, 4 bytes each, in order of preference.
    public static func capwap(_ controllers: [String]) throws -> [UInt8] { try ipv4List(controllers) }

    /// Option 119 (RFC 3397) / v6 option 24 (RFC 3646): domain names in wire form.
    public static func domainSearch(_ names: [String]) throws -> [UInt8] { try DHCPDNSWire.encodeList(names) }

    public struct StaticRoute: Codable, Sendable, Hashable {
        /// `10.30.0.0/16` (`0.0.0.0/0` is a default route).
        public var destination: String
        public var gateway: String
        public init(destination: String, gateway: String) { self.destination = destination; self.gateway = gateway }
    }

    /// Option 121 (RFC 3442): prefix length, the significant octets of the destination, router.
    public static func classlessRoutes(_ routes: [StaticRoute]) throws -> [UInt8] {
        var out: [UInt8] = []
        for route in routes {
            guard let subnet = IPv4Subnet(route.destination) else { throw DHCPError.invalid("\(route.destination) is not a CIDR") }
            guard let gw = IPv4Address(route.gateway) else { throw DHCPError.invalid("\(route.gateway) is not an IPv4 address") }
            out.append(UInt8(subnet.prefix))
            out += subnet.network.bytes.prefix((subnet.prefix + 7) / 8)
            out += gw.bytes
        }
        return out
    }

    /// Decodes option 121 (display, tests).
    public static func decodeClasslessRoutes(_ bytes: [UInt8]) throws -> [StaticRoute] {
        var r = DHCPReader(bytes)
        var routes: [StaticRoute] = []
        while !r.isAtEnd {
            let prefix = Int(try r.u8("route prefix"))
            guard prefix <= 32 else { throw DHCPError.malformed("route prefix \(prefix)") }
            let significant = try r.take((prefix + 7) / 8, "route destination")
            let dest = IPv4Address(bytes: significant + [UInt8](repeating: 0, count: 4 - significant.count))!
            let gw = IPv4Address(bytes: try r.take(4, "route gateway"))!
            routes.append(StaticRoute(destination: "\(dest)/\(prefix)", gateway: gw.description))
        }
        return routes
    }

    public static func uint32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }

    public static func uint16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
}

/// A custom option on a scope, reservation or class policy: code + type + text value.
public struct DHCPCustomOption: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case text, ipList, hex, uint8, uint16, uint32, bool, domainList

        public var title: String {
            switch self {
            case .text: "Text"
            case .ipList: "Address list"
            case .hex: "Hex bytes"
            case .uint8: "Number (1 byte)"
            case .uint16: "Number (2 bytes)"
            case .uint32: "Number (4 bytes)"
            case .bool: "Yes/No"
            case .domainList: "Domain list"
            }
        }
    }

    public var id: UUID
    public var code: UInt16
    public var kind: Kind
    public var value: String

    public init(id: UUID = UUID(), code: UInt16, kind: Kind, value: String) {
        self.id = id; self.code = code; self.kind = kind; self.value = value
    }

    /// The option's data for `family` (v4 codes 1–254, v6 codes 1–65535).
    public func encode(v6: Bool = false) throws -> [UInt8] {
        let v = value.trimmingCharacters(in: .whitespaces)
        let list = v.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init).filter { !$0.isEmpty }
        switch kind {
        case .text: return Array(value.utf8)
        case .ipList: return v6 ? try DHCPOptionBuilder.ipv6List(list) : try DHCPOptionBuilder.ipv4List(list)
        case .hex:
            guard let b = DHCPHex.bytes(v) else { throw DHCPError.invalid("option \(code): \(v) is not hex") }
            return b
        case .uint8:
            guard let n = UInt8(v) else { throw DHCPError.invalid("option \(code): \(v) is not 0–255") }
            return [n]
        case .uint16:
            guard let n = UInt16(v) else { throw DHCPError.invalid("option \(code): \(v) is not 0–65535") }
            return DHCPOptionBuilder.uint16(n)
        case .uint32:
            guard let n = UInt32(v) else { throw DHCPError.invalid("option \(code): \(v) is not a 32-bit number") }
            return DHCPOptionBuilder.uint32(n)
        case .bool:
            return [["1", "yes", "true", "on"].contains(v.lowercased()) ? 1 : 0]
        case .domainList: return try DHCPOptionBuilder.domainSearch(list)
        }
    }

    /// v4 options the server writes itself (a custom option would override the lease time, the
    /// message type, the server identifier or the client's own identifier).
    public static let serverManagedV4: [UInt16: String] = [
        51: "lease time — set the scope's lease time", 52: "option overload", 53: "message type", 54: "server identifier",
        55: "parameter request list", 58: "renewal time T1 — derived from the lease time",
        59: "rebinding time T2 — derived from the lease time", 61: "client identifier", 82: "relay agent information",
    ]

    /// v6 options the server writes itself.
    public static let serverManagedV6: [UInt16: String] = [
        1: "client identifier", 2: "server identifier", 3: "IA_NA — addresses come from the ranges", 13: "status code",
    ]

    public func validate(v6: Bool = false) throws {
        guard v6 ? (1...65534).contains(code) : (1...254).contains(code) else {
            throw DHCPError.invalid("option code \(code) is out of range")
        }
        if let what = v6 ? Self.serverManagedV6[code] : Self.serverManagedV4[code] {
            throw DHCPError.invalid("option \(code) (\(what)) is set by the server and cannot be a custom option")
        }
        let data = try encode(v6: v6)
        if !v6, data.count > 255 * 4 { throw DHCPError.invalid("option \(code) is too long") }
    }
}
