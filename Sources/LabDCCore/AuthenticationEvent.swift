import Foundation

/// One row of Activity ▸ Authentications: a credential check parsed from one serve log line.
///
/// Line formats (component, then text):
/// - `KDC AS alice@LAB.SHEEP from 172.18.1.210/tcp etype=18 -> OK ticket krbtgt/LAB.SHEEP 10h`
///   (`-> KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_CLIENT_REVOKED`, …; `KDC_ERR_PREAUTH_REQUIRED` is a
///   protocol step, not an outcome, and TGS lines are ticket use, not sign-ins)
/// - `NETLOGON SamLogon Network LABSHEEP\alice ws=\\CLEARPASS-ENTRY val=6 pc=0x10820 ntlmv1 from
///   CLEARPASS-ENTRY$@172.18.1.210/tcp -> OK as alice` (`-> STATUS_WRONG_PASSWORD (bad password)`)
/// - `NETLOGON Authenticate3 PC1$ (PC1) type=workstation flags=0x… from 172.18.1.50/tcp -> OK aes rid=1105`
/// - `LDAP bind simple CN=Administrator,… from 192.0.2.7/ldaps -> OK as LABSHEEP\Administrator`
///   (`-> invalidCredentials (52e)`, `-> strongerAuthRequired (plain LDAP not allowed)`)
/// - `XCEP GetPolicies from WS1$@10.0.0.5 -> 4 policies (…)`, `WSTEP RequestSecurityToken from
///   alice@10.0.0.5 template=Computer -> Denied (…)`, `HTTPS XCEP from 10.0.0.5 -> 401 (…)`
/// - `SCEP PKCSReq device=sw1 -> OK serial=… template=Device from 10.0.0.5`,
///   `EST simpleenroll device=ap1 -> 401 (…) from 10.0.0.5`
/// - `TEST login kerberos 38ms -> OK name=alice@LAB.SHEEP` — written by Test login after the
///   request it made; it marks that request's row "(test)" instead of adding one.
public struct AuthenticationEvent: Sendable, Hashable, Identifiable {
    public enum Result: String, Sendable, Hashable, CaseIterable {
        case passed, failed
        public var label: String { self == .passed ? "Passed" : "Failed" }
    }

    public enum Method: String, Sendable, Hashable, CaseIterable {
        /// AS exchange with a password (PA-ENC-TIMESTAMP).
        case kerberos
        /// NTLMv2 (or plain NTLMv1) network logon forwarded by a NAC / member over NETLOGON.
        case ntlm
        /// NTLMv1-style response with `MSV1_0_ALLOW_MSVCHAPV2`: PEAP-MSCHAPv2 pass-through.
        case mschapv2
        /// NETLOGON interactive logon (a NAC's plaintext `ad auth`, `wbinfo -a`).
        case nacPassword
        case ldapBind
        /// A computer account: Kerberos AS as `PC$`, or the NETLOGON secure channel.
        case computer
        /// SCEP / EST challenge, Windows auto-enrollment (XCEP/WSTEP over Negotiate).
        case enrollment

        public var label: String {
            switch self {
            case .kerberos: "Kerberos password"
            case .ntlm: "NTLM network"
            case .mschapv2: "MS-CHAPv2 via NAC"
            case .nacPassword: "Password via NAC"
            case .ldapBind: "LDAP bind"
            case .computer: "Computer"
            case .enrollment: "Certificate enrollment"
            }
        }
    }

    /// Why a row failed, where the app can say more than the code (and offer an action).
    public enum Failure: String, Sendable, Hashable {
        case wrongPassword, unknownUser, unknownComputer, disabled, expired, locked, passwordMustChange
        /// A computer account on a network logon without `MSV1_0_ALLOW_*_TRUST_ACCOUNT`.
        case trustAccountGate
        /// A secure channel for an account that is not a joined computer, or no channel at all.
        case notJoined
        case plainLDAPRefused
        /// NTLMv1 refused by the NTLM policy (Settings ▸ Directory ▸ NAC password checks).
        case ntlmPolicy
        case clockSkew
        case other
    }

    /// The contextual button of a failed row.
    public enum Action: Sendable, Hashable {
        /// Users ▸ that account (wrong password, disabled, expired, locked, must change).
        case openUser(String)
        /// Connect ▸ pick the device (unknown workstation, not joined, trust-account gate).
        case connectDevice
        /// Settings (plain LDAP refused, NTLMv1 refused by policy).
        case openSettings

        public var title: String {
            switch self {
            case .openUser: "Open User"
            case .connectDevice: "Connect a Device"
            case .openSettings: "Open Settings"
            }
        }
    }

    /// Assigned by the feed (unique within it).
    public var id: Int
    /// The `LogHub` sequence number (0 for lines read from older day files).
    public var seq: Int
    public var date: Date
    public var result: Result
    /// The account without domain/realm (`alice`, `PC1$`); `-` when the request named nobody.
    public var user: String
    /// The name exactly as the client sent it (`alice@LAB.SHEEP`, `LABSHEEP\alice`, a DN).
    public var sentName: String
    public var method: Method
    /// `AES256`, `ntlmv2`, `simple · TLS`, `SCEP`, `secure channel`, …
    public var methodDetail: String
    /// The workstation / NAC / device name, when the line names one.
    public var device: String?
    /// The client address (`172.18.1.210`).
    public var address: String?
    /// The reason in plain words on failure (`Wrong password`), else empty.
    public var reason: String
    public var failure: Failure?
    /// The protocol outcome (`KDC_ERR_PREAUTH_FAILED`, `STATUS_WRONG_PASSWORD (bad password)`, `OK`).
    public var code: String
    /// Made by Activity ▸ Test login.
    public var isTest: Bool
    /// Test login's measured duration, when its `TEST` line was seen.
    public var testMilliseconds: Int?
    public var component: String
    public var raw: String

    public init(id: Int = 0, seq: Int = 0, date: Date, result: Result, user: String, sentName: String? = nil, method: Method,
                methodDetail: String = "", device: String? = nil, address: String? = nil, reason: String = "",
                failure: Failure? = nil, code: String = "", isTest: Bool = false, testMilliseconds: Int? = nil,
                component: String = "", raw: String = "") {
        self.id = id
        self.seq = seq
        self.date = date
        self.result = result
        self.user = user
        self.sentName = sentName ?? user
        self.method = method
        self.methodDetail = methodDetail
        self.device = device
        self.address = address
        self.reason = reason
        self.failure = failure
        self.code = code
        self.isTest = isTest
        self.testMilliseconds = testMilliseconds
        self.component = component
        self.raw = raw
    }

    /// `Kerberos password`, `MS-CHAPv2 via NAC`, `Computer · secure channel`.
    public var methodLabel: String {
        method == .computer || method == .enrollment ? (methodDetail.isEmpty ? method.label : "\(method.label) · \(methodDetail)")
            : method.label
    }

    /// `CLEARPASS-ENTRY · 172.18.1.210`, `172.18.1.210`, `This Mac` for a Test login.
    public var from: String {
        let parts = [device, address.map { Self.isLoopback($0) ? "This Mac" : $0 }].compactMap { $0 }.filter { !$0.isEmpty }
        return parts.isEmpty ? "—" : parts.joined(separator: " · ")
    }

    public var isComputerAccount: Bool { user.hasSuffix("$") }

    /// What a failed row offers, when it makes sense.
    public var action: Action? {
        guard result == .failed, let failure else { return nil }
        switch failure {
        case .wrongPassword, .disabled, .expired, .locked, .passwordMustChange:
            return user.isEmpty || user == "-" ? nil : .openUser(user)
        case .unknownComputer, .notJoined, .trustAccountGate:
            return .connectDevice
        case .plainLDAPRefused, .ntlmPolicy:
            return .openSettings
        case .unknownUser:
            return isComputerAccount ? .connectDevice : nil
        case .clockSkew, .other:
            return nil
        }
    }

    // MARK: Parsing

    /// What a log line contributes to the feed.
    public enum Item: Sendable, Hashable {
        case event(AuthenticationEvent)
        case testMarker(TestMarker)
    }

    /// `TEST login <method> <ms>ms -> OK name=<sent name>` / `-> FAILED (<reason>) name=<sent name>`.
    public struct TestMarker: Sendable, Hashable {
        public var date: Date
        public var method: Method
        public var passed: Bool
        public var reason: String
        public var milliseconds: Int?
        /// The name as the test sent it (matches `sentName` of the request's own row).
        public var name: String

        public init(date: Date, method: Method, passed: Bool, reason: String = "", milliseconds: Int?, name: String) {
            self.date = date
            self.method = method
            self.passed = passed
            self.reason = reason
            self.milliseconds = milliseconds
            self.name = name
        }

        /// The line Test login writes (component `TEST`).
        public var logText: String {
            "login \(method.rawValue) \(milliseconds.map { "\($0)ms" } ?? "-")"
                + (passed ? " -> OK" : " -> FAILED" + (reason.isEmpty ? "" : " (\(reason))")) + " name=\(name)"
        }

        /// Whether `event` is the request this marker reports on.
        public func matches(_ event: AuthenticationEvent) -> Bool {
            guard event.testMilliseconds == nil, abs(event.date.timeIntervalSince(date)) <= 30 else { return false }
            guard event.isTest || event.address.map(AuthenticationEvent.isLoopback) == true else { return false }
            let sameMethod: Bool = switch method {
            case .kerberos, .computer: event.method == .kerberos || (event.method == .computer && event.component == "KDC")
            case .ntlm, .mschapv2, .nacPassword: event.component == "NETLOGON" && event.method != .computer
            case .ldapBind: event.method == .ldapBind
            case .enrollment: event.method == .enrollment
            }
            guard sameMethod else { return false }
            // The KDC logs a canonicalized name on success (`alice@LAB.SHEEP` for `ALICE@LAB.SHEEP`).
            return event.sentName.caseInsensitiveCompare(name) == .orderedSame
                || AuthenticationEvent.userName(event.sentName).caseInsensitiveCompare(AuthenticationEvent.userName(name)) == .orderedSame
        }

        /// The row for a test whose request left no line of its own (the service did not answer).
        func standaloneEvent(seq: Int, raw: String) -> AuthenticationEvent {
            AuthenticationEvent(seq: seq, date: date, result: passed ? .passed : .failed, user: AuthenticationEvent.userName(name),
                                sentName: name, method: method, address: "127.0.0.1", reason: passed ? "" : reason,
                                failure: passed ? nil : .other, code: passed ? "OK" : "FAILED", isTest: true,
                                testMilliseconds: milliseconds, component: "TEST", raw: raw)
        }
    }

    public static func parse(_ line: LogLine) -> Item? {
        guard line.level == .info else { return nil }
        let e: AuthenticationEvent?
        switch line.component {
        case "KDC": e = parseKDC(line)
        case "NETLOGON": e = parseNetlogon(line)
        case "LDAP": e = parseLDAP(line)
        case "SCEP", "EST": e = parseDeviceEnrollment(line)
        case "XCEP", "WSTEP": e = parseWindowsEnrollment(line)
        case "HTTPS": e = parseNegotiateFailure(line)
        case "TEST": return parseTestMarker(line).map { .testMarker($0) }
        default: return nil
        }
        return e.map { .event($0) }
    }

    /// The events of `line`, ignoring test markers (convenience for tests and one-off lines).
    public static func event(_ line: LogLine) -> AuthenticationEvent? {
        if case .event(let e)? = parse(line) { return e }
        return nil
    }

    // MARK: KDC

    static func parseKDC(_ line: LogLine) -> AuthenticationEvent? {
        let t = ActivityEvent.stripVerbose(line.text)
        guard t.hasPrefix("AS "), let arrow = t.range(of: " -> "), let from = t.range(of: " from ", range: t.startIndex..<arrow.lowerBound)
        else { return nil }
        let client = String(t[t.index(t.startIndex, offsetBy: 3)..<from.lowerBound])
        guard client != "-" else { return nil }
        let middle = t[from.upperBound..<arrow.lowerBound].split(separator: " ").map(String.init)
        let fromClause = middle.first ?? ""
        let etype = middle.first { $0.hasPrefix("etype=") }.map { String($0.dropFirst(6)) }
        let outcome = String(t[arrow.upperBound...])
        let code = outcome.split(separator: " ").first.map(String.init) ?? outcome
        if code == "KDC_ERR_PREAUTH_REQUIRED" || code == "KRB_ERR_RESPONSE_TOO_BIG" { return nil }
        let user = stripRealm(client)
        let computer = user.hasSuffix("$")
        let ok = code == "OK"
        var e = AuthenticationEvent(seq: line.seq, date: line.date, result: ok ? .passed : .failed, user: user, sentName: client,
                                    method: computer ? .computer : .kerberos,
                                    methodDetail: computer ? "Kerberos" : (etype.map(enctypeName) ?? ""),
                                    address: ActivityEvent.address(fromClause), code: code, component: line.component,
                                    raw: line.raw)
        if !ok {
            let (reason, failure) = kerberosFailure(code, computer: computer)
            e.reason = reason
            e.failure = failure
        }
        return e
    }

    static func kerberosFailure(_ code: String, computer: Bool) -> (String, Failure) {
        switch code {
        case "KDC_ERR_PREAUTH_FAILED": ("Wrong password", .wrongPassword)
        case "KDC_ERR_C_PRINCIPAL_UNKNOWN": computer ? ("Unknown computer (not joined)", .unknownComputer) : ("Unknown user", .unknownUser)
        case "KDC_ERR_CLIENT_REVOKED": ("Account disabled or locked", .disabled)
        case "KDC_ERR_KEY_EXPIRED": ("Password expired", .passwordMustChange)
        case "KRB_AP_ERR_SKEW": ("Clock difference too large", .clockSkew)
        case "KDC_ERR_ETYPE_NOSUPP": ("No common encryption type", .other)
        case "KDC_ERR_WRONG_REALM": ("Wrong realm", .other)
        case "KDC_ERR_POLICY": ("Refused by policy", .other)
        default: (code, .other)
        }
    }

    /// `18` → `AES256`.
    static func enctypeName(_ raw: String) -> String {
        switch raw {
        case "18": "AES256"
        case "17": "AES128"
        case "23": "RC4"
        default: "etype \(raw)"
        }
    }

    // MARK: NETLOGON

    static func parseNetlogon(_ line: LogLine) -> AuthenticationEvent? {
        let t = line.text
        guard let arrow = t.range(of: " -> "), let from = t.range(of: " from ", options: .backwards, range: t.startIndex..<arrow.lowerBound)
        else { return nil }
        let outcome = String(t[arrow.upperBound...])
        let ok = outcome.hasPrefix("OK")
        let fromClause = String(t[from.upperBound..<arrow.lowerBound])
        let (via, transport) = splitTransport(ActivityEvent.viaAddress(fromClause))
        let channelAccount = ActivityEvent.deviceName(fromClause)
        let code = ok ? "OK" : outcome
        if t.hasPrefix("SamLogon ") {
            // `SamLogon <Level> <domain\user> ws=<ws> val=<n> pc=0x<pc> <kind> from … -> …`
            guard let ws = t.range(of: " ws=", range: t.startIndex..<from.lowerBound) else { return nil }
            let head = t[t.index(t.startIndex, offsetBy: 9)..<ws.lowerBound]
            guard let space = head.firstIndex(of: " ") else { return nil }
            let level = String(head[..<space])
            let sent = String(head[head.index(after: space)...])
            let rest = t[ws.upperBound..<from.lowerBound].split(separator: " ").map(String.init)
            var workstation = rest.first ?? "-"
            while workstation.hasPrefix("\\") { workstation.removeFirst() }
            let pc = rest.first { $0.hasPrefix("pc=0x") }.flatMap { UInt32($0.dropFirst(5), radix: 16) } ?? 0
            let kind = rest.last { ["ntlmv1", "ntlmv2", "interactive"].contains($0) } ?? ""
            let method: Method = if level.hasPrefix("Interactive") || kind == "interactive" { .nacPassword }
                else if kind == "ntlmv1" && pc & 0x0001_0000 != 0 { .mschapv2 } else { .ntlm }
            var user = ActivityEvent.stripDomain(sent)
            if ok, let asRange = outcome.range(of: " as ") { user = String(outcome[asRange.upperBound...]) }
            let device = channelAccount ?? (workstation == "-" ? nil : workstation)
            var e = AuthenticationEvent(seq: line.seq, date: line.date, result: ok ? .passed : .failed,
                                        user: user.isEmpty ? "-" : user, sentName: sent, method: method,
                                        methodDetail: kind == "interactive" ? "" : kind, device: device,
                                        address: via, code: code, isTest: transport == "test", component: line.component,
                                        raw: line.raw)
            if !ok {
                let (reason, failure) = netlogonFailure(outcome, computer: user.hasSuffix("$"), hasChannel: channelAccount != nil)
                e.reason = reason
                e.failure = failure
            }
            return e
        }
        if t.hasPrefix("Authenticate") {
            // `Authenticate3 PC1$ (PC1) type=workstation flags=0x… from 172.18.1.50/tcp -> OK aes rid=1105`
            let words = t[..<from.lowerBound].split(separator: " ").map(String.init)
            guard words.count >= 2 else { return nil }
            let account = words[1]
            let computer = words.count >= 3 && words[2].hasPrefix("(") ? String(words[2].dropFirst().dropLast()) : nil
            var e = AuthenticationEvent(seq: line.seq, date: line.date, result: ok ? .passed : .failed, user: account,
                                        method: .computer, methodDetail: "secure channel", device: computer,
                                        address: via, code: code, component: line.component, raw: line.raw)
            if !ok {
                let (reason, failure) = netlogonFailure(outcome, computer: true, hasChannel: false)
                e.reason = reason
                e.failure = failure
            }
            return e
        }
        return nil
    }

    static func netlogonFailure(_ outcome: String, computer: Bool, hasChannel: Bool) -> (String, Failure) {
        let code = outcome.split(separator: " ").first.map(String.init) ?? outcome
        let detail = parenthesized(outcome) ?? ""
        switch code {
        case "STATUS_WRONG_PASSWORD":
            if detail.hasPrefix("NTLMv1 refused") { return ("NTLMv1 not allowed by the NTLM policy", .ntlmPolicy) }
            return ("Wrong password", .wrongPassword)
        case "STATUS_NO_SUCH_USER":
            if detail.hasPrefix("domain '"), let end = detail.dropFirst(8).firstIndex(of: "'") {
                return ("Unknown domain '\(detail.dropFirst(8)[..<end])'", .unknownUser)
            }
            if detail == "account has no NT hash" { return ("No password set", .other) }
            return computer ? ("Unknown computer (not joined)", .unknownComputer) : ("Unknown user", .unknownUser)
        case "STATUS_ACCOUNT_DISABLED": return ("Account disabled", .disabled)
        case "STATUS_ACCOUNT_EXPIRED": return ("Account expired", .expired)
        case "STATUS_ACCOUNT_LOCKED_OUT": return ("Account locked", .locked)
        case "STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED": return ("Password must change", .passwordMustChange)
        case "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT", "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT":
            return ("Computer account not allowed here (trust-account gate)", .trustAccountGate)
        case "STATUS_NO_TRUST_SAM_ACCOUNT":
            return (detail.isEmpty ? "Computer not joined" : "Computer not joined (\(detail))", .notJoined)
        case "STATUS_ACCESS_DENIED":
            if detail.hasPrefix("no secure channel") || detail == "authenticator mismatch" {
                return ("The device's secure channel is not set up (join it again)", .notJoined)
            }
            return ("Access denied" + (detail.isEmpty ? "" : " (\(detail))"), computer ? .notJoined : .other)
        case "STATUS_DOWNGRADE_DETECTED": return ("Old NETLOGON authentication refused", .other)
        default: return (detail.isEmpty ? code : "\(code) (\(detail))", .other)
        }
    }

    // MARK: LDAP

    static func parseLDAP(_ line: LogLine) -> AuthenticationEvent? {
        let t = line.text
        guard t.hasPrefix("bind "), let arrow = t.range(of: " -> "),
              let from = t.range(of: " from ", options: .backwards, range: t.startIndex..<arrow.lowerBound) else { return nil }
        let head = t[t.index(t.startIndex, offsetBy: 5)..<from.lowerBound]
        guard let space = head.firstIndex(of: " ") else { return nil }
        let mech = String(head[..<space])
        let name = String(head[head.index(after: space)...])
        let fromClause = String(t[from.upperBound..<arrow.lowerBound])
        let outcome = String(t[arrow.upperBound...])
        let ok = outcome.hasPrefix("OK")
        var user = ActivityEvent.userName(name)
        if ok, let asRange = outcome.range(of: " as ") { user = ActivityEvent.stripDomain(String(outcome[asRange.upperBound...])) }
        let (address, listener) = splitTransport(fromClause)
        let tls = listener.hasPrefix("ldaps") || listener.contains("tls")
        var detail = mech == "simple" ? "simple" : mech
        if tls { detail += " · TLS" }
        if listener.hasPrefix("gc") { detail += " · GC" }
        var e = AuthenticationEvent(seq: line.seq, date: line.date, result: ok ? .passed : .failed, user: user.isEmpty ? "-" : user,
                                    sentName: name, method: .ldapBind, methodDetail: detail, address: address,
                                    code: ok ? "OK" : outcome, component: line.component, raw: line.raw)
        if !ok {
            let (reason, failure) = ldapFailure(outcome)
            e.reason = reason
            e.failure = failure
        }
        return e
    }

    static func ldapFailure(_ outcome: String) -> (String, Failure) {
        if outcome.hasPrefix("strongerAuthRequired") { return ("Plain LDAP not allowed (use LDAPS)", .plainLDAPRefused) }
        if outcome.hasPrefix("invalidCredentials") {
            if outcome.contains("(533)") { return ("Account disabled", .disabled) }
            if outcome.contains("(701)") { return ("Account expired", .expired) }
            if outcome.contains("(773)") || outcome.contains("(532)") { return ("Password must change", .passwordMustChange) }
            if outcome.contains("(775)") { return ("Account locked", .locked) }
            return ("Wrong user or password", .wrongPassword)
        }
        if outcome.hasPrefix("unwillingToPerform") { return ("Empty password refused", .other) }
        return (outcome, .other)
    }

    // MARK: Certificate enrollment

    /// `PKCSReq device=sw1 -> OK serial=… from 10.0.0.5`, `simpleenroll device=ap1 -> 401 (…) from …`.
    static func parseDeviceEnrollment(_ line: LogLine) -> AuthenticationEvent? {
        let t = line.text
        guard let arrow = t.range(of: " -> ") else { return nil }
        let head = t[..<arrow.lowerBound].split(separator: " ").map(String.init)
        let tail = String(t[arrow.upperBound...])
        let device = head.first { $0.hasPrefix("device=") }.map { String($0.dropFirst(7)) }
        let unauthorized = tail.hasPrefix("401")
        guard device != nil || unauthorized, let op = head.first else { return nil }
        // The client is at the end (`… from 10.0.0.5`) or in the head (`simpleenroll from 10.0.0.5 -> 401`).
        var address: String?
        if let r = tail.range(of: " from ", options: .backwards) { address = String(tail[r.upperBound...]) }
        else if let i = head.firstIndex(of: "from"), i + 1 < head.count { address = head[i + 1] }
        var outcome = tail
        if let r = outcome.range(of: " from ", options: .backwards) { outcome = String(outcome[..<r.lowerBound]) }
        let ok = outcome.hasPrefix("OK")
        let reason = ok ? "" : (parenthesized(outcome).map { $0.prefix(1).uppercased() + $0.dropFirst() } ?? outcome)
        return AuthenticationEvent(seq: line.seq, date: line.date, result: ok ? .passed : .failed, user: device ?? "-",
                                   method: .enrollment, methodDetail: "\(line.component) \(op)", device: nil,
                                   address: address.map(ActivityEvent.address), reason: reason, failure: ok ? nil : .other,
                                   code: outcome, component: line.component, raw: line.raw)
    }

    /// `GetPolicies from WS1$@10.0.0.5 -> 4 policies (…)`, `RequestSecurityToken from alice@10.0.0.5 template=Computer -> Issued …`.
    static func parseWindowsEnrollment(_ line: LogLine) -> AuthenticationEvent? {
        let t = line.text
        guard let arrow = t.range(of: " -> ") else { return nil }
        let head = t[..<arrow.lowerBound].split(separator: " ").map(String.init)
        guard head.count >= 3, let i = head.firstIndex(of: "from"), i + 1 < head.count, head[i + 1].contains("@") else { return nil }
        let caller = head[i + 1]
        let op = head[0]
        let template = head.first { $0.hasPrefix("template=") }.map { String($0.dropFirst(9)) }
        let outcome = String(t[arrow.upperBound...])
        let failed = outcome.hasPrefix("fault") || outcome.hasPrefix("Denied")
        var reason = ""
        if failed {
            reason = outcome.hasPrefix("Denied") ? "Not allowed to enrol" + (template.map { " for template '\($0)'" } ?? "")
                : "Request failed" + (parenthesized(outcome).map { " (\($0))" } ?? "")
        }
        let user = ActivityEvent.stripRealm(caller)
        return AuthenticationEvent(seq: line.seq, date: line.date, result: failed ? .failed : .passed, user: user,
                                   method: .enrollment, methodDetail: "Windows \(op)" + (template.map { " (\($0))" } ?? ""),
                                   address: ActivityEvent.viaAddress(caller), reason: reason, failure: failed ? .other : nil,
                                   code: outcome, component: line.component, raw: line.raw)
    }

    /// `HTTPS XCEP from 10.0.0.5 -> 401 (why Negotiate failed)`.
    static func parseNegotiateFailure(_ line: LogLine) -> AuthenticationEvent? {
        let t = line.text
        guard t.hasPrefix("XCEP from ") || t.hasPrefix("WSTEP from "), let arrow = t.range(of: " -> "),
              t[arrow.upperBound...].hasPrefix("401") else { return nil }
        let words = t[..<arrow.lowerBound].split(separator: " ").map(String.init)
        let outcome = String(t[arrow.upperBound...])
        let why = parenthesized(outcome) ?? "no credentials"
        return AuthenticationEvent(seq: line.seq, date: line.date, result: .failed, user: "-", method: .enrollment,
                                   methodDetail: "Windows \(words[0]) sign-in", address: words.last.map(ActivityEvent.address),
                                   reason: "Windows sign-in failed (\(why))", failure: .other, code: outcome,
                                   component: line.component, raw: line.raw)
    }

    // MARK: TEST

    static func parseTestMarker(_ line: LogLine) -> TestMarker? {
        let t = line.text
        guard t.hasPrefix("login "), let arrow = t.range(of: " -> "), let nameRange = t.range(of: " name=", options: .backwards),
              nameRange.lowerBound > arrow.lowerBound else { return nil }
        let head = t[t.index(t.startIndex, offsetBy: 6)..<arrow.lowerBound].split(separator: " ").map(String.init)
        guard let method = head.first.flatMap(Method.init(rawValue:)) else { return nil }
        let ms = head.dropFirst().first.flatMap { $0.hasSuffix("ms") ? Int($0.dropLast(2)) : nil }
        let outcome = String(t[arrow.upperBound..<nameRange.lowerBound])
        let passed = outcome.hasPrefix("OK")
        return TestMarker(date: line.date, method: method, passed: passed, reason: passed ? "" : (parenthesized(outcome) ?? outcome),
                          milliseconds: ms, name: String(t[nameRange.upperBound...]))
    }

    // MARK: Helpers

    /// `127.0.0.1`, `::1`, `localhost`.
    public static func isLoopback(_ address: String) -> Bool {
        address == "::1" || address == "localhost" || address.hasPrefix("127.") || address == "::ffff:127.0.0.1"
    }

    /// `172.18.1.210/tcp` → (`172.18.1.210`, `tcp`).
    static func splitTransport(_ s: String) -> (String, String) {
        guard let slash = s.firstIndex(of: "/") else { return (ActivityEvent.address(s), "") }
        return (ActivityEvent.address(String(s[..<slash])), String(s[s.index(after: slash)...]))
    }

    /// The text inside the first `(…)` (up to the matching last `)`).
    static func parenthesized(_ s: String) -> String? {
        guard let open = s.firstIndex(of: "("), let close = s.lastIndex(of: ")"), open < close else { return nil }
        return String(s[s.index(after: open)..<close])
    }

    static func stripRealm(_ s: String) -> String { ActivityEvent.stripRealm(s) }

    /// A display account for any name form (DN → first RDN value, `DOMAIN\user`, `user@realm`).
    public static func userName(_ s: String) -> String { ActivityEvent.userName(s) }
}
