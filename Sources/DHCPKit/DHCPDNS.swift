import CryptoKit
import Foundation

/// The DNS side of a lease: names, reverse zones and DHCID (RFC 4701/4702/4703/4704).
public enum DHCPDNS {
    /// The DHCID RR type (RFC 4701).
    public static let dhcidType: UInt16 = 49

    /// RFC 4701 §3.3 identifier types.
    public enum IdentifierType: UInt16, Sendable {
        /// htype (1 byte) + chaddr.
        case hardware = 0x0000
        /// DHCPv4 option 61 data.
        case clientID = 0x0001
        /// DHCPv6 client DUID.
        case duid = 0x0002
    }

    /// DHCID RDATA: identifier type (2), digest type 1 (SHA-256), SHA-256(identifier ‖ FQDN in
    /// canonical wire form) — RFC 4701 §3.3–3.5.
    public static func dhcid(type: IdentifierType, identifier: [UInt8], fqdn: String) -> [UInt8] {
        let wire = (try? DHCPDNSWire.encode(fqdn.lowercased())) ?? []
        let digest = SHA256.hash(data: identifier + wire)
        return DHCPOptionBuilder.uint16(type.rawValue) + [1] + Array(digest)
    }

    /// A host label from what a client sent: lower case, `[a-z0-9-]`, no leading/trailing
    /// hyphen, at most 63; nil when nothing usable is left. Spaces/underscores become hyphens.
    public static func sanitizeLabel(_ raw: String) -> String? {
        let first = raw.split(separator: ".").first.map(String.init) ?? raw
        var out = ""
        for ch in first.lowercased() {
            if ch.isASCII, ch.isLetter || ch.isNumber { out.append(ch) } else if ch == "-" || ch == "_" || ch == " " { out.append("-") }
        }
        while out.hasPrefix("-") { out.removeFirst() }
        while out.hasSuffix("-") { out.removeLast() }
        if out.count > 63 { out = String(out.prefix(63)); while out.hasSuffix("-") { out.removeLast() } }
        return out.isEmpty ? nil : out
    }

    /// The FQDN for a client: its label in `domain`.
    public static func fqdn(label: String, domain: String) -> String {
        let d = domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        return d.isEmpty ? label : "\(label).\(d)"
    }

    /// The reverse zones a v4 subnet needs: classful octet boundaries at or below the prefix
    /// (`10.20.0.0/24` → `0.20.10.in-addr.arpa`; a /22 → four /24 zones; a /16 → one zone).
    /// At most 256 zones.
    public static func reverseZones(v4 subnet: IPv4Subnet) -> [String] {
        let boundary = max(8, min(24, ((subnet.prefix + 7) / 8) * 8))
        let count = subnet.prefix >= boundary ? 1 : min(256, 1 << (boundary - subnet.prefix))
        let step = UInt32(1) << UInt32(32 - boundary)
        return (0..<count).map { i in
            let base = IPv4Address(subnet.network.value &+ UInt32(i) &* step)
            let octets = base.bytes.prefix(boundary / 8)
            return octets.reversed().map(String.init).joined(separator: ".") + ".in-addr.arpa"
        }
    }

    /// The v6 reverse zone at /64 (spec rev 2), or at the prefix rounded down to a nibble when
    /// the scope is longer than /64 (a /66 needs the /64 zone: a /68 zone would miss three
    /// quarters of its addresses).
    public static func reverseZone(v6 subnet: IPv6Subnet) -> String {
        let nibbles = max(16, subnet.prefix / 4)
        let all = nibbleList(subnet.network)
        return all.prefix(nibbles).reversed().joined(separator: ".") + ".ip6.arpa"
    }

    static func nibbleList(_ a: IPv6Address) -> [String] {
        a.bytes.flatMap { [String($0 >> 4, radix: 16), String($0 & 0xF, radix: 16)] }
    }

    /// `31.0.20.10.in-addr.arpa`.
    public static func ptrName(v4 a: IPv4Address) -> String {
        a.bytes.reversed().map(String.init).joined(separator: ".") + ".in-addr.arpa"
    }

    public static func ptrName(v6 a: IPv6Address) -> String {
        nibbleList(a).reversed().joined(separator: ".") + ".ip6.arpa"
    }

    /// The zone (from `zones`) that holds `name`, longest match first.
    public static func zone(for name: String, in zones: [String]) -> String? {
        let n = name.lowercased()
        return zones.map { $0.lowercased() }.sorted { $0.count > $1.count }.first { n == $0 || n.hasSuffix("." + $0) }
    }

    /// `name` relative to `zone` (`@` for the apex).
    public static func relative(_ name: String, zone: String) -> String {
        let n = name.lowercased(), z = zone.lowercased()
        if n == z { return "@" }
        return n.hasSuffix("." + z) ? String(n.dropLast(z.count + 1)) : n + "."
    }
}
