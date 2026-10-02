import Foundation

/// Custom options with a code the server sets itself (`DHCPCustomOption.serverManagedV4` /
/// `serverManagedV6`). Validation refuses them since 2 Oct 2026, but scopes and reservations
/// saved earlier may still hold them: the engines never send them, the server warns once at
/// load, and saving such a scope or reservation again drops them with a note instead of failing
/// (adding one anew is still refused).
extension DHCPCustomOption {
    public func isServerManaged(v6: Bool) -> Bool {
        v6 ? Self.serverManagedV6[code] != nil : Self.serverManagedV4[code] != nil
    }

    /// `51 (lease time …), 58 (…)`.
    static func describe(_ codes: [UInt16], v6: Bool) -> String {
        codes.map { code in
            let what = (v6 ? serverManagedV6[code] : serverManagedV4[code]) ?? "set by the server"
            return "\(code) (\(what.components(separatedBy: " — ").first ?? what))"
        }.joined(separator: ", ")
    }

    /// Drops the server-managed options of `options` whose code `saved` already held.
    static func strip(_ options: [DHCPCustomOption], savedCodes: Set<UInt16>, v6: Bool) -> (kept: [DHCPCustomOption], removed: [UInt16]) {
        var kept: [DHCPCustomOption] = [], removed: [UInt16] = []
        for o in options {
            if o.isServerManaged(v6: v6), savedCodes.contains(o.code) { removed.append(o.code) } else { kept.append(o) }
        }
        return (kept, removed)
    }
}

extension DHCPScope {
    /// Codes of this scope's custom options (class policies included) the server ignores
    /// because it sets them itself; sorted, no repeats.
    public var serverManagedCustomCodes: [UInt16] {
        let v6 = family == .v6
        let all = customOptions + (v6 ? [] : classPolicies.flatMap(\.options))
        return Array(Set(all.filter { $0.isServerManaged(v6: v6) }.map(\.code))).sorted()
    }

    /// This scope without the server-managed custom options `saved` (the stored version) already
    /// had, and a note saying what was removed (nil when nothing was). New ones are kept, so
    /// `validate` still refuses them.
    public func strippingSavedServerManagedOptions(saved: DHCPScope?) -> (scope: DHCPScope, note: String?) {
        guard let saved else { return (self, nil) }
        let savedCodes = Set(saved.serverManagedCustomCodes)
        guard !savedCodes.isEmpty else { return (self, nil) }
        let v6 = family == .v6
        var out = self
        var removed: [UInt16] = []
        let top = DHCPCustomOption.strip(customOptions, savedCodes: savedCodes, v6: v6)
        out.customOptions = top.kept
        removed += top.removed
        if !v6 {
            for i in out.classPolicies.indices {
                let p = DHCPCustomOption.strip(out.classPolicies[i].options, savedCodes: savedCodes, v6: false)
                out.classPolicies[i].options = p.kept
                removed += p.removed
            }
        }
        guard !removed.isEmpty else { return (self, nil) }
        let codes = Array(Set(removed)).sorted()
        return (out, "scope \(name): removed custom option\(codes.count == 1 ? "" : "s") \(DHCPCustomOption.describe(codes, v6: v6)) — "
            + "the server sets \(codes.count == 1 ? "it" : "them") itself and never sent the saved value\(codes.count == 1 ? "" : "s")")
    }

    /// The search list with entries typed space-separated (`a.lab b.lab`) split into names.
    public static func splitSearchList(_ list: [String]) -> [String] {
        list.flatMap { $0.split(whereSeparator: { $0.isWhitespace }).map(String.init) }
    }
}

extension DHCPReservation {
    /// Codes of this reservation's custom options the server ignores (sets them itself).
    public func serverManagedCustomCodes(v6: Bool) -> [UInt16] {
        Array(Set(options.filter { $0.isServerManaged(v6: v6) }.map(\.code))).sorted()
    }

    /// As `DHCPScope.strippingSavedServerManagedOptions`.
    public func strippingSavedServerManagedOptions(saved: DHCPReservation?, v6: Bool) -> (reservation: DHCPReservation, note: String?) {
        guard let saved else { return (self, nil) }
        let savedCodes = Set(saved.serverManagedCustomCodes(v6: v6))
        guard !savedCodes.isEmpty else { return (self, nil) }
        let r = DHCPCustomOption.strip(options, savedCodes: savedCodes, v6: v6)
        guard !r.removed.isEmpty else { return (self, nil) }
        var out = self
        out.options = r.kept
        let codes = Array(Set(r.removed)).sorted()
        return (out, "reservation \(name): removed custom option\(codes.count == 1 ? "" : "s") \(DHCPCustomOption.describe(codes, v6: v6)) — "
            + "the server sets \(codes.count == 1 ? "it" : "them") itself and never sent the saved value\(codes.count == 1 ? "" : "s")")
    }
}
