import Foundation

/// Option 43 (vendor-specific information, RFC 2132 §8.4) for access-point discovery. Each
/// builder follows the vendor's own documentation; the tests carry the documented hex.
///
/// - Cisco lightweight APs: TLV type 0xF1, length 4 × controllers, the WLC management
///   addresses. Cisco, "Configure DHCP OPTION 43 for Lightweight Access Points" (doc 97066):
///   https://www.cisco.com/c/en/us/support/docs/wireless-mobility/wireless-lan-wlan/97066-dhcp-option-43-00.html
///   — 192.168.1.10 → `f104c0a8010a`; .10 and .11 → `f108c0a8010ac0a8010b`. Option 60 is
///   per model (`Cisco AP c1810`, `Cisco AP C9120AX`).
/// - Aruba campus APs (option 60 `ArubaAP`): the controller (conductor) address as a plain
///   ASCII string, no TLV. HPE Aruba Networking, "DHCP for APs — server configuration
///   examples": https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/network-operations/dhcp-for-aps/server-config-examples/
/// - Huawei APs: sub-option 3 = AC addresses as ASCII, comma separated (Huawei's recommended
///   form, `option 43 sub-option 3 ascii 192.168.0.1,192.168.0.2`). Huawei, "Option 43
///   formats supported by DHCP servers of different vendors" (EDOC1000060368):
///   https://support.huawei.com/enterprise/en/doc/EDOC1000060368/bda10fc8/option-43-formats-supported-by-dhcp-servers-of-different-vendors
///   and the WLAN AC command reference for `option 43 sub-option 1/2/3` (EDOC1100008283):
///   https://support.huawei.com/enterprise/en/doc/EDOC1100008283/873b5b13/option
///   — 192.168.100.1 → `030d3139322e3136382e3130302e31`. Sub-options 1 (`hex C0A80001`) and
///   2 (`ip-address 192.168.0.1 …`) carry the list as 4-byte binary addresses;
///   `huaweiBinary` writes sub-option 2 that way.
/// - Ubiquiti UniFi (option 60 `ubnt`): sub-option 1, length 4, one controller. Ubiquiti
///   help center article 204909754: https://help.ui.com/hc/en-us/articles/204909754 —
///   192.168.3.10 → `0104c0a8030a`.
/// - Ruckus (option 60 `Ruckus CPE`): ASCII comma-separated controller list (≤ 128 chars),
///   sub-option 6 for SmartZone/SCG and sub-option 3 for ZoneDirector (factory APs run
///   ZoneDirector-compatible firmware and look for 3 until they join a SmartZone).
///   Ruckus KB 000008703 "Understanding DHCP Option 43 Hexadecimal code" (code "03 or 06,
///   typically 06 for SmartZone"): https://support.ruckuswireless.com/articles/000008703 ;
///   RUCKUS FastIron DHCP guide ("SmartZone IP addresses are sent with a sub-option value of 6"):
///   https://docs.ruckuswireless.com/fastiron/08.0.90/fastiron-08090-dhcpguide/GUID-48818153-DE73-4624-A38A-FF087BAB1D9F.html ;
///   RUCKUS community "AP Discovery: how to configure DHCP option 43" (03 = ZoneDirector,
///   06 = SmartZone): https://community.ruckuswireless.com/t5/RUCKUS-Self-Help/AP-Discovery-How-to-configure-DHCP-option-43-to-discover-the/td-p/65975
///   — SmartZone 192.168.1.120 → `060d3139322e3136382e312e313230` (the KB page prints extra
///   digits; this is the correct encoding of the same text), ZoneDirector 10.10.10.10 →
///   `030b31302e31302e31302e3130`.
///
/// The first draft of spec revision 2 (§8) listed "Huawei sub-option 2 ASCII" and "Ruckus
/// SmartZone 3 / ZD 6"; re-verified against the vendor documents above (1 Oct 2026): Huawei
/// sub-option 3 ASCII, Ruckus SmartZone 6 / ZoneDirector 3. LabDC follows the vendor documents
/// and the spec now says the same (see docs/notes/dhcp.md).
public struct VendorOption43: Codable, Sendable, Hashable {
    public enum Vendor: String, Codable, Sendable, CaseIterable, Identifiable {
        case cisco, aruba, huawei, huaweiBinary, unifi, ruckusSmartZone, ruckusZoneDirector, raw

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .cisco: "Cisco (WLC discovery)"
            case .aruba: "Aruba (controller address)"
            case .huawei: "Huawei (AC list, sub-option 3)"
            case .huaweiBinary: "Huawei (AC list, sub-option 2 binary)"
            case .unifi: "Ubiquiti UniFi"
            case .ruckusSmartZone: "Ruckus SmartZone"
            case .ruckusZoneDirector: "Ruckus ZoneDirector"
            case .raw: "Raw hex"
            }
        }

        /// The option 60 text the vendor's APs send (matched as "contains", case-insensitive).
        public var defaultVendorClass: String {
            switch self {
            case .cisco: "Cisco AP"
            case .aruba: "ArubaAP"
            case .huawei, .huaweiBinary: "Huawei"
            case .unifi: "ubnt"
            case .ruckusSmartZone, .ruckusZoneDirector: "Ruckus CPE"
            case .raw: ""
            }
        }

        /// How many controller addresses the format carries (nil = any number).
        public var maxControllers: Int? {
            switch self {
            case .aruba, .unifi: 1
            case .raw: 0
            default: nil
            }
        }
    }

    public var vendor: Vendor
    /// Controller addresses (IPv4) in order of preference.
    public var controllers: [String]
    /// For `.raw`: the option bytes as hex.
    public var rawHex: String
    /// Option 60 must contain this (case-insensitive); empty = every client that asks for 43.
    public var vendorClass: String

    public init(vendor: Vendor, controllers: [String] = [], rawHex: String = "", vendorClass: String? = nil) {
        self.vendor = vendor
        self.controllers = controllers
        self.rawHex = rawHex
        self.vendorClass = vendorClass ?? vendor.defaultVendorClass
    }

    /// The option 43 bytes.
    public func encode() throws -> [UInt8] {
        let list = controllers.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        if vendor != .raw {
            guard !list.isEmpty else { throw DHCPError.invalid("\(vendor.title): enter a controller address") }
            for c in list where IPv4Address(c) == nil { throw DHCPError.invalid("\(c) is not an IPv4 address") }
            if let max = vendor.maxControllers, list.count > max {
                throw DHCPError.invalid("\(vendor.title) carries \(max) controller address")
            }
        }
        func ascii(_ sub: UInt8) throws -> [UInt8] {
            let text = Array(list.joined(separator: ",").utf8)
            guard text.count <= 255 else { throw DHCPError.invalid("controller list too long") }
            return [sub, UInt8(text.count)] + text
        }
        func binary(_ sub: UInt8) throws -> [UInt8] {
            let data = try DHCPOptionBuilder.ipv4List(list)
            guard data.count <= 255 else { throw DHCPError.invalid("too many controllers") }
            return [sub, UInt8(data.count)] + data
        }
        switch vendor {
        case .cisco: return try binary(0xF1)
        case .aruba: return Array(list[0].utf8)
        case .huawei: return try ascii(3)
        case .huaweiBinary: return try binary(2)
        case .unifi: return try binary(1)
        case .ruckusSmartZone: return try ascii(6)
        case .ruckusZoneDirector: return try ascii(3)
        case .raw:
            guard let bytes = DHCPHex.bytes(rawHex), !bytes.isEmpty else { throw DHCPError.invalid("option 43: \(rawHex) is not hex") }
            return bytes
        }
    }

    /// `f108c0a8010ac0a8010b` (what the editor shows), or the error text.
    public var hexPreview: String {
        do { return DHCPHex.string(try encode()) } catch { return "\(error)" }
    }

    /// Whether a client with `vendorClassText` (option 60) gets this option 43.
    public func applies(to vendorClassText: String?) -> Bool {
        let want = vendorClass.trimmingCharacters(in: .whitespaces)
        guard !want.isEmpty else { return true }
        guard let have = vendorClassText else { return false }
        return have.range(of: want, options: [.caseInsensitive]) != nil
    }
}

/// Circuit-ID / Remote-ID (option 82/1, 82/2) in the forms switches send, decoded for display
/// and for option-82 reservations.
public enum CircuitIDDecoder {
    /// - Cisco IOS default (RFC 3046 + Cisco's "vlan-mod-port"): type 0, length 4,
    ///   VLAN (2 bytes), module, port → `Vlan20 Gi1/0/3`-ish text `vlan 20 mod 1 port 3`.
    /// - Aruba CX / Huawei / most others: printable ASCII (`1/1/7`, `Eth0/0/1:20`).
    /// - Anything else: hex.
    public static func describe(_ bytes: [UInt8]) -> String {
        if bytes.count == 6, bytes[0] == 0, bytes[1] == 4 {
            let vlan = Int(bytes[2]) << 8 | Int(bytes[3])
            return "vlan \(vlan) mod \(bytes[4]) port \(bytes[5])"
        }
        return DHCPHex.printable(bytes)
    }

    /// A reservation's circuit/remote text matches the bytes when it equals the decoded text,
    /// the printable text or the hex (case-insensitive).
    public static func matches(_ pattern: String, _ bytes: [UInt8]) -> Bool {
        let p = pattern.trimmingCharacters(in: .whitespaces)
        guard !p.isEmpty else { return false }
        if describe(bytes).caseInsensitiveCompare(p) == .orderedSame { return true }
        if DHCPHex.printable(bytes).caseInsensitiveCompare(p) == .orderedSame { return true }
        if let hex = DHCPHex.bytes(p), hex == bytes { return true }
        return false
    }
}
