import Foundation

/// Built-in light device profiling (spec §7). LabDC's own small rule table — vendor class,
/// the option 55 / ORO shape and host-name hints — written from the vendors' documented option
/// 60 strings and common client behaviour; no third-party fingerprint database is used.
public enum DeviceClassifier {
    /// Raw values match `Store.DeviceCategory`.
    public enum Category: String, Sendable, CaseIterable, Codable {
        case windows, macOS, iOS, android, linux, chromeOS, printer, ipPhone, accessPoint
        case `switch`, cameraIoT, unknown

        public var title: String {
            switch self {
            case .windows: "Windows"
            case .macOS: "macOS"
            case .iOS: "iOS/iPadOS"
            case .android: "Android"
            case .linux: "Linux"
            case .chromeOS: "ChromeOS"
            case .printer: "Printer"
            case .ipPhone: "IP phone"
            case .accessPoint: "Access point"
            case .switch: "Switch"
            case .cameraIoT: "Camera/IoT"
            case .unknown: "Unknown"
            }
        }
    }

    public struct Result: Sendable, Equatable {
        public var category: Category
        /// `Windows`, `Android 14`, `macOS`, `HP printer` …
        public var os: String
        /// 0–100: 90 vendor class, 70 option-55 shape, 50 host name, 0 unknown.
        public var confidence: Int
        /// Which rule decided (for the lease detail).
        public var reason: String

        public init(category: Category, os: String, confidence: Int, reason: String) {
            self.category = category; self.os = os; self.confidence = confidence; self.reason = reason
        }

        public static let unknown = Result(category: .unknown, os: "Unknown", confidence: 0, reason: "no rule matched")
    }

    struct VendorRule {
        let contains: String
        let category: Category
        let os: String
    }

    /// Option 60 / v6 vendor-class text, matched as case-insensitive "contains" in this order.
    static let vendorRules: [VendorRule] = [
        VendorRule(contains: "MSFT", category: .windows, os: "Windows"),
        VendorRule(contains: "android-dhcp", category: .android, os: "Android"),
        VendorRule(contains: "Cisco AP", category: .accessPoint, os: "Cisco AP"),
        VendorRule(contains: "ArubaInstantAP", category: .accessPoint, os: "Aruba Instant AP"),
        VendorRule(contains: "ArubaAP", category: .accessPoint, os: "Aruba AP"),
        VendorRule(contains: "Ruckus CPE", category: .accessPoint, os: "Ruckus AP"),
        VendorRule(contains: "ubnt", category: .accessPoint, os: "UniFi"),
        VendorRule(contains: "HUAWEI AP", category: .accessPoint, os: "Huawei AP"),
        VendorRule(contains: "Mist", category: .accessPoint, os: "Juniper Mist AP"),
        VendorRule(contains: "Cisco Systems, Inc. IP Phone", category: .ipPhone, os: "Cisco IP phone"),
        VendorRule(contains: "IP Phone", category: .ipPhone, os: "IP phone"),
        VendorRule(contains: "Polycom", category: .ipPhone, os: "Polycom phone"),
        VendorRule(contains: "Yealink", category: .ipPhone, os: "Yealink phone"),
        VendorRule(contains: "Avaya", category: .ipPhone, os: "Avaya phone"),
        VendorRule(contains: "Mitel", category: .ipPhone, os: "Mitel phone"),
        VendorRule(contains: "Grandstream", category: .ipPhone, os: "Grandstream phone"),
        VendorRule(contains: "snom", category: .ipPhone, os: "snom phone"),
        VendorRule(contains: "Aastra", category: .ipPhone, os: "Aastra phone"),
        VendorRule(contains: "Hewlett-Packard JetDirect", category: .printer, os: "HP printer"),
        VendorRule(contains: "JetDirect", category: .printer, os: "HP printer"),
        VendorRule(contains: "Canon", category: .printer, os: "Canon printer"),
        VendorRule(contains: "Brother", category: .printer, os: "Brother printer"),
        VendorRule(contains: "EPSON", category: .printer, os: "Epson printer"),
        VendorRule(contains: "Lexmark", category: .printer, os: "Lexmark printer"),
        VendorRule(contains: "Xerox", category: .printer, os: "Xerox printer"),
        VendorRule(contains: "Ricoh", category: .printer, os: "Ricoh printer"),
        VendorRule(contains: "KYOCERA", category: .printer, os: "Kyocera printer"),
        VendorRule(contains: "ciscopnp", category: .switch, os: "Cisco switch"),
        VendorRule(contains: "Cisco Switch", category: .switch, os: "Cisco switch"),
        VendorRule(contains: "ArubaOS-CX", category: .switch, os: "Aruba CX switch"),
        VendorRule(contains: "HP J", category: .switch, os: "HPE/Aruba switch"),
        VendorRule(contains: "Juniper", category: .switch, os: "Juniper switch"),
        VendorRule(contains: "HUAWEI", category: .switch, os: "Huawei switch"),
        VendorRule(contains: "AXIS", category: .cameraIoT, os: "Axis camera"),
        VendorRule(contains: "Hikvision", category: .cameraIoT, os: "Hikvision camera"),
        VendorRule(contains: "Dahua", category: .cameraIoT, os: "Dahua camera"),
        VendorRule(contains: "udhcp", category: .cameraIoT, os: "Embedded Linux (udhcp)"),
        VendorRule(contains: "chromeos", category: .chromeOS, os: "ChromeOS"),
        VendorRule(contains: "dhcpcd", category: .linux, os: "Linux (dhcpcd)"),
    ]

    struct NameRule {
        let prefix: Bool
        let text: String
        let category: Category
        let os: String
    }

    /// Host-name hints (option 12 / FQDN first label), case-insensitive.
    static let nameRules: [NameRule] = [
        NameRule(prefix: false, text: "iphone", category: .iOS, os: "iOS"),
        NameRule(prefix: false, text: "ipad", category: .iOS, os: "iPadOS"),
        NameRule(prefix: false, text: "macbook", category: .macOS, os: "macOS"),
        NameRule(prefix: false, text: "imac", category: .macOS, os: "macOS"),
        NameRule(prefix: false, text: "mac-mini", category: .macOS, os: "macOS"),
        NameRule(prefix: false, text: "chromebook", category: .chromeOS, os: "ChromeOS"),
        NameRule(prefix: true, text: "android", category: .android, os: "Android"),
        NameRule(prefix: true, text: "galaxy", category: .android, os: "Android"),
        NameRule(prefix: true, text: "pixel", category: .android, os: "Android"),
        NameRule(prefix: true, text: "desktop-", category: .windows, os: "Windows"),
        NameRule(prefix: true, text: "laptop-", category: .windows, os: "Windows"),
        NameRule(prefix: true, text: "npi", category: .printer, os: "HP printer"),
        NameRule(prefix: true, text: "hp", category: .printer, os: "HP printer"),
        NameRule(prefix: true, text: "brn", category: .printer, os: "Brother printer"),
        NameRule(prefix: true, text: "brw", category: .printer, os: "Brother printer"),
        NameRule(prefix: true, text: "epson", category: .printer, os: "Epson printer"),
        NameRule(prefix: true, text: "sep", category: .ipPhone, os: "Cisco IP phone"),
        NameRule(prefix: true, text: "esp32", category: .cameraIoT, os: "ESP32 device"),
        NameRule(prefix: true, text: "esp-", category: .cameraIoT, os: "ESP device"),
        NameRule(prefix: true, text: "espressif", category: .cameraIoT, os: "ESP device"),
        NameRule(prefix: true, text: "tasmota", category: .cameraIoT, os: "Tasmota device"),
        NameRule(prefix: true, text: "shelly", category: .cameraIoT, os: "Shelly device"),
        NameRule(prefix: true, text: "raspberrypi", category: .linux, os: "Raspberry Pi OS"),
        NameRule(prefix: true, text: "ubuntu", category: .linux, os: "Ubuntu"),
    ]

    /// Classifies one fingerprint: vendor class first, then the option 55/ORO shape, then the
    /// host name.
    public static func classify(_ fp: DHCPFingerprint) -> Result {
        if let vc = fp.vendorClass?.trimmingCharacters(in: .whitespaces), !vc.isEmpty {
            for rule in vendorRules where vc.range(of: rule.contains, options: .caseInsensitive) != nil {
                var os = rule.os
                if rule.category == .android, let v = vc.split(separator: "-").last, v.first?.isNumber == true { os = "Android \(v)" }
                return Result(category: rule.category, os: os, confidence: 90, reason: "vendor class \(vc)")
            }
        }
        if fp.family == .v6, let ent = fp.vendorEnterprise {
            switch ent {
            case 311: return Result(category: .windows, os: "Windows", confidence: 85, reason: "vendor class enterprise 311 (Microsoft)")
            case 9: return Result(category: .ipPhone, os: "Cisco device", confidence: 50, reason: "vendor class enterprise 9 (Cisco)")
            default: break
            }
        }
        let prl = fp.parameterList
        let set = Set(prl)
        if fp.family == .v4, !prl.isEmpty {
            // Apple: 55 starts 1,121,3,6,15 and asks for 119 and 252 (WPAD), no vendor class.
            if prl.starts(with: [1, 121, 3, 6, 15]), set.contains(119), set.contains(252) {
                if set.contains(95) || set.contains(44) || set.contains(46) {
                    return refine(Result(category: .macOS, os: "macOS", confidence: 70, reason: "option 55 \(fp.parameterListText)"), fp)
                }
                return refine(Result(category: .iOS, os: "iOS/iPadOS", confidence: 70, reason: "option 55 \(fp.parameterListText)"), fp)
            }
            // Windows without option 60 (rare): 1,3,6,15,31,33,43,44,46,47,119,121,249,252.
            if set.isSuperset(of: [1, 15, 31, 33, 43, 44, 46, 47, 249]) {
                return Result(category: .windows, os: "Windows", confidence: 70, reason: "option 55 \(fp.parameterListText)")
            }
            // VoIP phones ask for TFTP (66/150) and often 42/160.
            if set.contains(150) || (set.contains(66) && set.contains(42)) {
                return refine(Result(category: .ipPhone, os: "IP phone", confidence: 60, reason: "asks for TFTP options (66/150)"), fp)
            }
            // Access points ask for option 43 or 138 without being Windows.
            if set.contains(138) || (set.contains(43) && !set.contains(44)) {
                return refine(Result(category: .accessPoint, os: "Access point", confidence: 55, reason: "asks for option 43/138"), fp)
            }
            // ISC dhclient / systemd-networkd / NetworkManager shapes.
            if prl.starts(with: [1, 28, 2, 3, 15, 6]) || prl.starts(with: [1, 3, 6, 12, 15, 28]) || set.isSuperset(of: [1, 28, 2, 3, 15, 6, 119]) {
                return refine(Result(category: .linux, os: "Linux", confidence: 60, reason: "option 55 \(fp.parameterListText)"), fp)
            }
        }
        if let named = byName(fp) { return named }
        return .unknown
    }

    /// A host-name hint can only sharpen a guess of the same family (Apple, Linux/Android).
    static func refine(_ result: Result, _ fp: DHCPFingerprint) -> Result {
        guard let named = byName(fp) else { return result }
        switch (result.category, named.category) {
        case (.iOS, .macOS), (.macOS, .iOS), (.linux, .android), (.linux, .chromeOS), (.linux, .cameraIoT):
            return Result(category: named.category, os: named.os, confidence: result.confidence, reason: result.reason + " + host name")
        default:
            return result
        }
    }

    static func byName(_ fp: DHCPFingerprint) -> Result? {
        let name = (fp.hostname ?? fp.fqdn?.split(separator: ".").first.map(String.init) ?? "").lowercased()
        guard !name.isEmpty else { return nil }
        for rule in nameRules {
            let hit = rule.prefix ? name.hasPrefix(rule.text) : name.contains(rule.text)
            if hit { return Result(category: rule.category, os: rule.os, confidence: 50, reason: "host name \(name)") }
        }
        return nil
    }
}
