import Foundation

/// Activity ▸ Log: which lines show (component chips + search), independent of the view.
public struct LogFilter: Equatable, Sendable {
    /// Components to show; empty shows every component.
    public var components: Set<String> = []
    /// Case-insensitive substring over the whole line; words must all match.
    public var search: String = ""
    /// Only warnings ("Problems").
    public var warningsOnly = false
    /// One of the plain-word groups (Sign-ins, Devices, Certificates, System); nil = all.
    public var category: LogCategory?

    public init(components: Set<String> = [], search: String = "", warningsOnly: Bool = false, category: LogCategory? = nil) {
        self.components = components
        self.search = search
        self.warningsOnly = warningsOnly
        self.category = category
    }

    public var isActive: Bool {
        !components.isEmpty || !search.trimmingCharacters(in: .whitespaces).isEmpty || warningsOnly || category != nil
    }

    public func matches(_ line: LogLine) -> Bool {
        if warningsOnly, line.level != .warning { return false }
        if let category, LogCategory(component: line.component) != category { return false }
        if !components.isEmpty, !components.contains(line.component) { return false }
        let words = search.split(separator: " ", omittingEmptySubsequences: true)
        for w in words where line.raw.range(of: w, options: [.caseInsensitive, .diacriticInsensitive]) == nil { return false }
        return true
    }

    public func apply(_ lines: [LogLine]) -> [LogLine] {
        isActive ? lines.filter(matches) : lines
    }

    /// The chips: well-known components first (in this order), then any other seen in `lines`.
    public static let knownComponents = ["KDC", "NETLOGON", "LDAP", "DRSUAPI", "SMB", "RPC", "DNS", "SCEP", "EST", "HTTP", "PKI",
                                         "GPO", "SYSVOL", "SNTP", "Store", "kpasswd", "serve"]

    public static func components(in lines: [LogLine]) -> [String] {
        let seen = Set(lines.map(\.component))
        return knownComponents.filter(seen.contains) + seen.subtracting(knownComponents).sorted()
    }

    /// The lines as text (Copy / Export).
    public static func text(_ lines: [LogLine]) -> String {
        lines.map(\.raw).joined(separator: "\n") + (lines.isEmpty ? "" : "\n")
    }
}

/// The log's plain-word groups (owner, 27 Sep 2026: "easy to read"): what a line is about,
/// instead of the protocol that wrote it.
public enum LogCategory: String, CaseIterable, Sendable, Hashable {
    case signIns = "Sign-ins"
    case devices = "Devices"
    case certificates = "Certificates"
    case system = "System"

    public init(component: String) {
        switch component.uppercased() {
        case "KDC", "KPASSWD", "NETLOGON", "LDAP", "CLDAP", "RADIUS": self = .signIns
        case "DNS", "SMB", "RPC", "DRSUAPI", "GPO", "SYSVOL", "SNTP", "NBNS", "LSA", "SAMR": self = .devices
        case "SCEP", "EST", "HTTP", "HTTPS", "PKI", "CEP", "CES": self = .certificates
        default: self = .system
        }
    }

    /// A component in words: `NETLOGON` → "NAC / Windows", `KDC` → "Kerberos".
    public static func label(_ component: String) -> String {
        switch component.uppercased() {
        case "KDC": "Kerberos"
        case "KPASSWD": "Password change"
        case "NETLOGON": "NAC / Windows"
        case "LDAP", "CLDAP": "Directory"
        case "DNS": "DNS"
        case "SMB": "File sharing"
        case "RPC", "LSA", "SAMR": "Windows calls"
        case "DRSUAPI": "Windows join"
        case "GPO", "SYSVOL": "Group Policy"
        case "SNTP": "Time"
        case "NBNS": "NetBIOS"
        case "SCEP": "SCEP"
        case "EST": "EST"
        case "HTTP", "HTTPS", "CEP", "CES": "Web"
        case "RADIUS": "RADIUS / 802.1X"
        case "PKI": "Certificates"
        case "STORE": "Directory data"
        case "SERVE": "LabDC"
        default: component
        }
    }
}
