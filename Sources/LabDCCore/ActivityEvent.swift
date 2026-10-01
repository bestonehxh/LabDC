import Foundation

/// A sign-in the Overview "Recent activity" table shows, parsed from one serve log line:
///
/// - `KDC AS alice@LABSHEEP from 172.18.1.210/tcp etype=18 -> OK ticket krbtgt/LAB.SHEEP 10h`
/// - `NETLOGON SamLogon Network LABSHEEP\alice ws=\\CLEARPASS-ENTRY … from CLEARPASS-ENTRY$@172.18.1.210/tcp -> OK as alice`
/// - `NETLOGON Authenticate3 WIN10-PC1$ (WIN10-PC1) type=workstation … from 172.18.1.210/tcp -> OK aes rid=1011`
/// - `LDAP bind simple cn=alice,… from 192.0.2.7/ldaps -> OK as LABSHEEP\alice`
///
/// Protocol steps that are not an outcome (`KDC_ERR_PREAUTH_REQUIRED`, `KRB_ERR_RESPONSE_TOO_BIG`,
/// NETLOGON ReqChallenge/GetDomainInfo/…) are not events.
public struct ActivityEvent: Sendable, Hashable, Identifiable {
    public enum Result: String, Sendable, Hashable {
        case success, failure
        public var label: String { self == .success ? "Passed" : "Failed" }
    }

    /// The log line's `seq`.
    public var id: Int
    public var date: Date
    public var result: Result
    /// The account, without realm/domain (`alice`, `WIN10-PC1$`).
    public var user: String
    /// `Kerberos`, `Kerberos ticket`, `NTLM (NAC)`, `Computer secure channel`, `LDAP bind`, …
    public var method: String
    /// The client: `CLEARPASS-ENTRY (172.18.1.210)` or `172.18.1.210`.
    public var from: String
    /// Human reason on failure (`Wrong password`), the service on a ticket, else empty.
    public var detail: String

    public init(id: Int, date: Date, result: Result, user: String, method: String, from: String, detail: String) {
        self.id = id
        self.date = date
        self.result = result
        self.user = user
        self.method = method
        self.from = from
        self.detail = detail
    }

    /// The event in `line`, or nil when the line is not a sign-in outcome.
    public static func parse(_ line: LogLine) -> ActivityEvent? {
        guard line.level == .info else { return nil }
        switch line.component {
        case "KDC": return parseKDC(line)
        case "NETLOGON": return parseNetlogon(line)
        case "LDAP": return parseLDAPBind(line)
        default: return nil
        }
    }

    /// The last `limit` events in `lines`, newest first.
    public static func recent(_ lines: [LogLine], limit: Int = 20) -> [ActivityEvent] {
        var out: [ActivityEvent] = []
        for line in lines.reversed() {
            if let e = parse(line) {
                out.append(e)
                if out.count == limit { break }
            }
        }
        return out
    }

    // MARK: KDC

    static func parseKDC(_ line: LogLine) -> ActivityEvent? {
        let t = stripVerbose(line.text)
        let words = t.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard words.count >= 5, words[0] == "AS" || words[0] == "TGS", words[2] == "from",
              let arrow = words.firstIndex(of: "->"), arrow + 1 < words.count else { return nil }
        let outcome = words[(arrow + 1)...]
        let code = outcome.first ?? ""
        if code == "KDC_ERR_PREAUTH_REQUIRED" || code == "KRB_ERR_RESPONSE_TOO_BIG" { return nil }
        let user = stripRealm(words[1])
        let from = address(words[3])
        let isAS = words[0] == "AS"
        if code == "OK" {
            // `OK ticket krbtgt/LAB.SHEEP 10h`
            let service = outcome.count >= 3 ? Array(outcome)[2] : ""
            return ActivityEvent(id: line.seq, date: line.date, result: .success, user: user,
                                 method: isAS ? "Kerberos sign-in" : "Kerberos ticket", from: from,
                                 detail: isAS ? "" : service)
        }
        return ActivityEvent(id: line.seq, date: line.date, result: .failure, user: user,
                             method: isAS ? "Kerberos sign-in" : "Kerberos ticket", from: from, detail: kerberosReason(code))
    }

    public static func kerberosReason(_ code: String) -> String {
        switch code {
        case "KDC_ERR_PREAUTH_FAILED": "Wrong password"
        case "KDC_ERR_C_PRINCIPAL_UNKNOWN": "Unknown user"
        case "KDC_ERR_S_PRINCIPAL_UNKNOWN": "Unknown service"
        case "KDC_ERR_CLIENT_REVOKED": "Account disabled or locked"
        case "KDC_ERR_KEY_EXPIRED": "Password expired"
        case "KDC_ERR_ETYPE_NOSUPP": "No common encryption type"
        case "KRB_AP_ERR_SKEW": "Clock difference too large"
        case "KDC_ERR_BADOPTION": "Request option not allowed"
        default: code
        }
    }

    // MARK: NETLOGON

    static func parseNetlogon(_ line: LogLine) -> ActivityEvent? {
        let t = line.text
        guard let arrowRange = t.range(of: " -> ") else { return nil }
        let head = String(t[..<arrowRange.lowerBound])
        let outcome = String(t[arrowRange.upperBound...])
        let ok = outcome.hasPrefix("OK")
        let words = head.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let op = words.first, let fromIdx = words.lastIndex(of: "from"), fromIdx + 1 < words.count else { return nil }
        let fromClause = words[fromIdx + 1]
        if op == "SamLogon" {
            guard words.count >= 3 else { return nil }
            let level = words[1]
            let account = words[2].hasPrefix("ws=") || words[2].hasPrefix("val=") ? "-" : stripDomain(words[2])
            let ws = words.first { $0.hasPrefix("ws=") }.map { String($0.dropFirst(3)).replacingOccurrences(of: "\\\\", with: "") }
            let device = deviceName(fromClause) ?? ws.flatMap { $0 == "-" ? nil : $0 }
            let from = [device, address(viaAddress(fromClause))].compactMap { $0 }.joined(separator: " · ")
            let method = level.hasPrefix("Interactive") ? "Password (NAC)" : "NTLM (NAC)"
            return ActivityEvent(id: line.seq, date: line.date, result: ok ? .success : .failure, user: account,
                                 method: method, from: from, detail: ok ? "" : netlogonReason(outcome))
        }
        if op.hasPrefix("Authenticate") || op.hasPrefix("ServerPasswordSet") {
            guard words.count >= 2 else { return nil }
            let account = words[1]
            let method = op.hasPrefix("Authenticate") ? "Computer secure channel" : "Computer password change"
            return ActivityEvent(id: line.seq, date: line.date, result: ok ? .success : .failure, user: account,
                                 method: method, from: address(viaAddress(fromClause)), detail: ok ? "" : netlogonReason(outcome))
        }
        return nil
    }

    public static func netlogonReason(_ outcome: String) -> String {
        let code = outcome.split(separator: " ").first.map(String.init) ?? outcome
        switch code {
        case "STATUS_WRONG_PASSWORD": return "Wrong password"
        case "STATUS_NO_SUCH_USER": return "Unknown user"
        case "STATUS_ACCOUNT_DISABLED": return "Account disabled"
        case "STATUS_ACCOUNT_EXPIRED": return "Account expired"
        case "STATUS_PASSWORD_MUST_CHANGE": return "Password must change"
        case "STATUS_ACCESS_DENIED": return "Access denied"
        case "STATUS_NO_TRUST_SAM_ACCOUNT": return "Computer not joined"
        default: return code
        }
    }

    // MARK: LDAP

    static func parseLDAPBind(_ line: LogLine) -> ActivityEvent? {
        let t = line.text
        guard t.hasPrefix("bind "), let arrowRange = t.range(of: " -> "), let fromRange = t.range(of: " from ", options: .backwards,
                                                                                                 range: t.startIndex..<arrowRange.lowerBound)
        else { return nil }
        let head = t[t.index(t.startIndex, offsetBy: 5)..<fromRange.lowerBound]
        guard let space = head.firstIndex(of: " ") else { return nil }
        let mech = String(head[..<space])
        let name = String(head[head.index(after: space)...])
        let fromClause = String(t[fromRange.upperBound..<arrowRange.lowerBound])
        let outcome = String(t[arrowRange.upperBound...])
        let ok = outcome.hasPrefix("OK")
        var user = name
        if ok, let asRange = outcome.range(of: " as ") { user = String(outcome[asRange.upperBound...]) }
        let listener = fromClause.split(separator: "/").dropFirst().first.map(String.init) ?? ""
        let method = "LDAP bind" + (mech == "simple" ? "" : " (\(mech))") + (listener.hasPrefix("ldaps") || listener.contains("tls") ? " · TLS" : "")
        return ActivityEvent(id: line.seq, date: line.date, result: ok ? .success : .failure, user: userName(user),
                             method: method, from: address(fromClause), detail: ok ? "" : ldapReason(outcome))
    }

    public static func ldapReason(_ outcome: String) -> String {
        if outcome.hasPrefix("strongerAuthRequired") { return "Plain LDAP not allowed" }
        if outcome.hasPrefix("invalidCredentials") {
            if outcome.contains("(533)") { return "Account disabled" }
            if outcome.contains("(701)") { return "Account expired" }
            if outcome.contains("(773)") { return "Password must change" }
            return "Wrong user or password"
        }
        return outcome
    }

    // MARK: Helpers

    /// Drops `--verbose` suffixes: ` [1453 bytes]` and ` (reason)`.
    static func stripVerbose(_ s: String) -> String {
        guard let r = s.range(of: " [") else { return s }
        return String(s[..<r.lowerBound])
    }

    /// `alice@LAB.SHEEP` → `alice`.
    static func stripRealm(_ s: String) -> String {
        guard let at = s.lastIndex(of: "@") else { return s }
        return String(s[..<at])
    }

    /// `LABSHEEP\alice` → `alice`.
    static func stripDomain(_ s: String) -> String {
        guard let bs = s.lastIndex(of: "\\") else { return s }
        return String(s[s.index(after: bs)...])
    }

    /// A user name for display: DNs become their first RDN value, `DOMAIN\user` and
    /// `user@realm` their account part.
    static func userName(_ s: String) -> String {
        if s.contains("="), let eq = s.firstIndex(of: "=") {
            let rest = s[s.index(after: eq)...]
            return String(rest.prefix { $0 != "," })
        }
        return stripRealm(stripDomain(s))
    }

    /// `CLEARPASS-ENTRY$@172.18.1.210/tcp` → `172.18.1.210/tcp`.
    static func viaAddress(_ s: String) -> String {
        guard let at = s.lastIndex(of: "@") else { return s }
        return String(s[s.index(after: at)...])
    }

    /// `CLEARPASS-ENTRY$@…` → `CLEARPASS-ENTRY`.
    static func deviceName(_ s: String) -> String? {
        guard let at = s.lastIndex(of: "@") else { return nil }
        var name = String(s[..<at])
        if name.hasSuffix("$") { name.removeLast() }
        return name.isEmpty ? nil : name
    }

    /// `172.18.1.210/tcp` / `172.18.1.210:5555` → `172.18.1.210`.
    static func address(_ s: String) -> String {
        var a = s
        if let slash = a.firstIndex(of: "/") { a = String(a[..<slash]) }
        if a.filter({ $0 == ":" }).count == 1, let colon = a.firstIndex(of: ":") { a = String(a[..<colon]) }
        return a
    }
}
