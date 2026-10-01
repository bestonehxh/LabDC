/// Resolves the identity a pass-through logon names (`NETLOGON_LOGON_IDENTITY_INFO`
/// `LogonDomainName` + `UserName`, or an NTLM AUTHENTICATE's DomainName + UserName) into account
/// lookups against this domain (WP-AK).
///
/// Accepted forms, all case-insensitive:
/// - `user` with `LogonDomainName` empty, our NetBIOS name, our DNS name, or this DC's name;
/// - `DOMAIN\user` in `UserName` (a client that did not split the name), where `DOMAIN` is ours;
/// - `user@suffix` (UPN): looked up by userPrincipalName first, then — when the suffix is our DNS
///   or NetBIOS domain — by sAMAccountName of the part before `@`;
/// - machine authentication: `NAME$`, `DOMAIN\NAME$` (plain sAMAccountNames) and `host/fqdn` /
///   `host/NAME` (by SPN, then `NAME$`). Whether a trust account may log on is the caller's policy
///   (`MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT`).
///
/// Trailing NULs (a counted `RPC_UNICODE_STRING` whose Length includes the terminator) and
/// anything after an embedded NUL are dropped. A name that points at another domain is not ours
/// to validate: Samba's AD DC `auth_sam` returns NOT_IMPLEMENTED for it and, with no trusted
/// domain to route to, `auth_check_password` answers `NT_STATUS_NO_SUCH_USER` — callers map
/// `.foreignDomain` to that status.
public struct LogonName: Sendable, Equatable, CustomStringConvertible {
    /// One store lookup to try, in order.
    public enum Lookup: Sendable, Equatable {
        case sam(String)
        case upn(String)
        /// A service principal name (`host/pc.lab.sheep`), for machine authentication.
        case spn(String)
    }

    public enum Outcome: Sendable, Equatable {
        /// Ours: try `lookups` in order; the first account found is the user.
        case local([Lookup])
        /// The name targets a domain we do not serve (the domain as given).
        case foreignDomain(String)
        /// No user name at all.
        case empty
    }

    /// The names this DC answers for.
    public struct LocalNames: Sendable, Equatable {
        public var netbiosDomain: String
        public var dnsDomain: String
        public var dcName: String
        public init(netbiosDomain: String, dnsDomain: String, dcName: String) {
            self.netbiosDomain = netbiosDomain
            self.dnsDomain = dnsDomain
            self.dcName = dcName
        }

        /// Empty, `.`, the NetBIOS or DNS domain (the realm is its upper-case form) or the DC's own
        /// NetBIOS name (a DC's "local SAM" is the domain).
        public func isLocal(_ domain: String) -> Bool {
            let d = domain.uppercased()
            if d.isEmpty || d == "." { return true }
            if d == netbiosDomain.uppercased() || d == dnsDomain.uppercased() { return true }
            if !dcName.isEmpty, d == dcName.uppercased() { return true }
            return false
        }
    }

    /// `LogonDomainName` as received (NULs stripped).
    public var logonDomain: String
    /// `UserName` as received (NULs stripped).
    public var userName: String
    public var outcome: Outcome

    /// `DOMAIN\user` exactly as received, for logs.
    public var description: String { logonDomain.isEmpty ? userName : "\(logonDomain)\\\(userName)" }

    /// Truncates at the first NUL (a counted string whose Length covered the terminator, or a
    /// fixed buffer with garbage after it).
    public static func stripNUL(_ s: String) -> String {
        guard let i = s.firstIndex(of: "\u{0}") else { return s }
        return String(s[..<i])
    }

    public init(logonDomain rawDomain: String, userName rawUser: String, local: LocalNames) {
        let domain = Self.stripNUL(rawDomain)
        let user = Self.stripNUL(rawUser)
        self.logonDomain = domain
        self.userName = user
        self.outcome = Self.resolve(domain: domain, user: user, local: local)
    }

    static func resolve(domain: String, user: String, local: LocalNames) -> Outcome {
        guard !user.isEmpty else { return .empty }
        // An explicit LogonDomainName is authoritative.
        if !domain.isEmpty, !local.isLocal(domain) { return .foreignDomain(domain) }
        var name = user
        // `DOMAIN\user` inside UserName (a client that did not split the name): the prefix must
        // be ours too.
        if let slash = name.firstIndex(of: "\\") {
            let prefix = String(name[..<slash])
            name = String(name[name.index(after: slash)...])
            guard !name.isEmpty else { return .empty }
            if !local.isLocal(prefix) { return .foreignDomain(prefix) }
        }
        if name.lowercased().hasPrefix("host/") { return hostLookups(String(name.dropFirst(5)), local: local) }
        if name.contains("@") { return upnLookups(name, local: local) }
        return .local([.sam(name)])
    }

    /// `host/pc.lab.sheep` or `host/PC` — how an 802.1X supplicant names the computer in machine
    /// authentication (Huawei iMaster doc, Windows `host/<fqdn>` identity). Resolved by the SPN,
    /// then by the computer's sAMAccountName `PC$` when the name is in our DNS domain. `NAME$` and
    /// `DOMAIN\NAME$` need nothing special: they are sAMAccountNames.
    static func hostLookups(_ host: String, local: LocalNames) -> Outcome {
        guard !host.isEmpty, !host.contains("/") else { return .empty }
        var lookups: [Lookup] = [.spn("host/" + host)]
        let label: String
        if let dot = host.firstIndex(of: ".") {
            label = String(host[..<dot])
            let suffix = String(host[host.index(after: dot)...])
            if suffix.caseInsensitiveCompare(local.dnsDomain) == .orderedSame { lookups.append(.sam(label.uppercased() + "$")) }
        } else {
            label = host
            lookups.append(.sam(label.uppercased() + "$"))
        }
        return label.isEmpty ? .empty : .local(lookups)
    }

    /// `user@suffix`: the UPN first (alternate UPN suffixes live in the store), then the sAMAccountName
    /// when the suffix is our domain (an implicit UPN, MS-ADTS §5.1.1.1.1). A foreign suffix that
    /// matches no stored UPN is still reported as NO_SUCH_USER by the caller, not as a foreign domain,
    /// because the UPN lookup is authoritative for the forest.
    static func upnLookups(_ name: String, local: LocalNames) -> Outcome {
        var lookups: [Lookup] = [.upn(name)]
        if let at = name.lastIndex(of: "@") {
            let before = String(name[..<at])
            let suffix = String(name[name.index(after: at)...])
            if !before.isEmpty, !suffix.isEmpty, local.isLocal(suffix) { lookups.append(.sam(before)) }
        }
        // A sAMAccountName may itself contain '@' (legal in AD); try it verbatim last.
        lookups.append(.sam(name))
        return .local(lookups)
    }
}
