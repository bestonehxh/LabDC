import Foundation

/// Parsing what people type into the DHCP page and `labdc dhcp`: lists are separated by commas
/// or new lines (never spaces, so `10.20.0.150 - 10.20.0.159` stays one range), and anything
/// that does not parse is an error naming the field — never silently dropped or defaulted.
public enum DHCPInput {
    /// `a, b` / one per line → `["a", "b"]` (trimmed, empty entries dropped).
    public static func list(_ text: String?) -> [String] {
        guard let text else { return [] }
        return text.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == "\r" || $0 == ";" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Domain names (the search list): separated by commas, semicolons, new lines or spaces
    /// (`a.lab b.lab` is two names; a name never holds a space).
    public static func domains(_ text: String?) -> [String] {
        guard let text else { return [] }
        return text.split(whereSeparator: { $0 == "," || $0 == ";" || $0.isWhitespace }).map(String.init).filter { !$0.isEmpty }
    }

    /// Ranges: `a-b`, `a - b` or one address; each end must be an address of `family`.
    public static func ranges(_ text: String?, family: DHCPFamily, field: String) throws -> [DHCPRange] {
        try list(text).map { entry in
            guard let r = DHCPRange(text: entry), family == .v4 ? r.v4 != nil : r.v6 != nil else {
                throw DHCPError.invalid("\(field): “\(entry)” is not an \(family.title) address range (start-end)")
            }
            return r
        }
    }

    /// Addresses of `family`.
    public static func addresses(_ text: String?, family: DHCPFamily, field: String) throws -> [String] {
        try list(text).map { entry in
            guard family == .v4 ? IPv4Address(entry) != nil : IPv6Address(entry) != nil else {
                throw DHCPError.invalid("\(field): “\(entry)” is not an \(family.title) address")
            }
            return entry
        }
    }

    /// Static routes `10.30.0.0/16@10.20.0.254`.
    public static func routes(_ text: String?, field: String = "Static routes") throws -> [DHCPOptionBuilder.StaticRoute] {
        try list(text).map { entry in
            let p = entry.split(separator: "@").map { $0.trimmingCharacters(in: .whitespaces) }
            guard p.count == 2, IPv4Subnet(p[0]) != nil, IPv4Address(p[1]) != nil else {
                throw DHCPError.invalid("\(field): “\(entry)” is not destination/prefix@gateway (10.30.0.0/16@10.20.0.254)")
            }
            return DHCPOptionBuilder.StaticRoute(destination: p[0], gateway: p[1])
        }
    }

    /// A whole number in `range`; blank gives nil.
    public static func integer(_ text: String?, field: String, in range: ClosedRange<Int>) throws -> Int? {
        let t = (text ?? "").trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return nil }
        guard let n = Int(t), range.contains(n) else {
            throw DHCPError.invalid("\(field): “\(t)” is not a whole number from \(range.lowerBound) to \(range.upperBound)")
        }
        return n
    }

    /// A positive number of hours (`8`, `0.5`, `1,5`) as seconds; blank gives nil.
    public static func hours(_ text: String?, field: String) throws -> Int? {
        let t = (text ?? "").trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ",", with: ".")
        guard !t.isEmpty else { return nil }
        guard let h = Double(t), h.isFinite, h > 0, h <= 366 * 24 else {
            throw DHCPError.invalid("\(field): “\(t)” is not a number of hours")
        }
        return Int((h * 3600).rounded())
    }
}
