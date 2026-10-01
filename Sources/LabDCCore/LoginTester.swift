import AuthKit
import CryptoKit
import Foundation
import KerberosASN1
import KerberosCrypto
import LDAPCore
import MSPAC
import NetlogonService
import SheepCrypto
import Store

/// Activity ▸ Test login: what to try.
public struct LoginTestRequest: Sendable, Equatable {
    public enum Preset: String, Sendable, CaseIterable, Identifiable {
        /// AS exchange (PA-ENC-TIMESTAMP) against the embedded KDC over loopback TCP.
        case kerberos
        /// A NETLOGON network logon as a NAC forwards it, validated in-process.
        case ntlm
        /// A simple bind to the running LDAP / LDAPS listener over loopback.
        case ldap

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .kerberos: "Password (Kerberos)"
            case .ntlm: "NTLM network logon (as a NAC would)"
            case .ldap: "LDAP bind"
            }
        }

        public var shortTitle: String {
            switch self {
            case .kerberos: "Kerberos"
            case .ntlm: "NTLM (NAC)"
            case .ldap: "LDAP bind"
            }
        }
    }

    /// The realm in the AS-REQ: the Kerberos realm or its NetBIOS alias (what Windows sends for
    /// `LAB\alice`).
    public enum RealmForm: String, Sendable, CaseIterable, Identifiable {
        case realm, netbios
        public var id: String { rawValue }
    }

    /// How the account is named in the NETLOGON logon / the LDAP bind.
    public enum NameForm: String, Sendable, CaseIterable, Identifiable {
        /// NTLM: LogonDomainName = NetBIOS, UserName = account (ClearPass, iMaster, winbind).
        /// LDAP: `LAB\alice`.
        case downLevel
        /// `alice@lab.sheep`.
        case upn
        /// NTLM: UserName only, no domain. LDAP: the sAMAccountName alone.
        case accountOnly
        /// LDAP only: the account's DN (`CN=Alice,CN=Users,DC=lab,DC=sheep`).
        case dn
        /// Exactly what was typed in User.
        case asTyped
        public var id: String { rawValue }
    }

    public enum LDAPConnection: String, Sendable, CaseIterable, Identifiable {
        /// Plain LDAP when "Allow plain LDAP" is on, LDAPS otherwise.
        case automatic
        case plain
        case tls
        public var id: String { rawValue }
    }

    public var preset: Preset
    public var user: String
    public var password: String
    public var realmForm: RealmForm = .realm
    /// NTLM: the Workstation field (the NAC's name).
    public var workstation: String = "LABDC-TEST"
    public var ntlmNameForm: NameForm = .downLevel
    public var ldapNameForm: NameForm = .upn
    /// NTLM: a 24-byte NTLMv1-style response over an RFC 2759 ChallengeHash with
    /// `MSV1_0_ALLOW_MSVCHAPV2`, exactly what a NAC forwards for PEAP-MSCHAPv2.
    public var msCHAPv2Style = false
    /// NTLM: `MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT | …SERVER…` (ntlm_auth and NACs set it).
    public var allowComputerAccounts = true
    public var ldapConnection: LDAPConnection = .automatic

    public init(preset: Preset, user: String, password: String) {
        self.preset = preset
        self.user = user
        self.password = password
    }
}

/// The outcome: one sentence plus the detail block.
public struct LoginTestResult: Sendable, Equatable {
    public struct Detail: Sendable, Equatable, Identifiable {
        public var label: String
        public var value: String
        public var id: String { label }
        public init(_ label: String, _ value: String) {
            self.label = label
            self.value = value
        }
    }

    public var passed: Bool
    public var milliseconds: Int
    /// `Kerberos AS`, `NTLM network logon`, `MS-CHAPv2 (NTLMv1)`, `LDAP bind`.
    public var method: String
    /// Plain words on failure (`Wrong password`), nil when it passed.
    public var reason: String?
    public var failure: AuthenticationEvent.Failure?
    /// Group names (primary first), when the server told us.
    public var groups: [String]
    /// The account the server resolved (`LAB\alice`).
    public var account: String?
    public var details: [Detail]

    public init(passed: Bool, milliseconds: Int, method: String, reason: String? = nil, failure: AuthenticationEvent.Failure? = nil,
                groups: [String] = [], account: String? = nil, details: [Detail] = []) {
        self.passed = passed
        self.milliseconds = milliseconds
        self.method = method
        self.reason = reason
        self.failure = failure
        self.groups = groups
        self.account = account
        self.details = details
    }

    /// `Passed · 38 ms · Kerberos AS · groups: Domain Users, Staff` / `Failed · wrong password`.
    public var sentence: String {
        guard passed else {
            let r = reason ?? "unknown reason"
            return "Failed · " + r.prefix(1).lowercased() + r.dropFirst()
        }
        var parts = ["Passed", "\(milliseconds) ms", method]
        if !groups.isEmpty {
            let shown = groups.prefix(4).joined(separator: ", ")
            parts.append("groups: " + shown + (groups.count > 4 ? " +\(groups.count - 4)" : ""))
        }
        return parts.joined(separator: " · ")
    }
}

public enum LoginTestError: Error, CustomStringConvertible, Equatable {
    case notRunning(String)
    case timedOut(Double)
    case connection(String)
    case protocolError(String)

    public var description: String {
        switch self {
        case .notRunning(let what): "\(what) is not running"
        case .timedOut(let s): "no answer within \(Int(s)) s"
        case .connection(let why): "could not connect (\(why))"
        case .protocolError(let why): "unexpected answer (\(why))"
        }
    }
}

/// What the tester talks to: the running store, log and listener ports.
public struct LoginTestEnvironment: Sendable {
    public var store: DirectoryStore
    public var log: ServeLog
    public var info: DomainInfo
    public var kdcPort: UInt16?
    public var ldapPort: Int?
    public var ldapsPort: Int?
    public var allowPlainLDAP: Bool
    public var ntlmAuth: NTLMAuthPolicy
    /// The lab CA (DER): the only anchor the LDAPS test trusts.
    public var caCertificateDER: [UInt8]?

    public init(store: DirectoryStore, log: ServeLog, info: DomainInfo, kdcPort: UInt16?, ldapPort: Int?, ldapsPort: Int?,
                allowPlainLDAP: Bool, ntlmAuth: NTLMAuthPolicy, caCertificateDER: [UInt8]?) {
        self.store = store
        self.log = log
        self.info = info
        self.kdcPort = kdcPort
        self.ldapPort = ldapPort
        self.ldapsPort = ldapsPort
        self.allowPlainLDAP = allowPlainLDAP
        self.ntlmAuth = ntlmAuth
        self.caCertificateDER = caCertificateDER
    }
}

extension ServerController {
    /// The environment of the running server, or nil when it is not running.
    public func loginTestEnvironment() async -> LoginTestEnvironment? {
        guard let rt = runtime, let store, let info = try? await store.domainInfo() else { return nil }
        let bound = await rt.bound
        let options = await rt.options
        let ca = try? await caCertificate(der: true)
        return LoginTestEnvironment(store: store, log: serveLog, info: info, kdcPort: bound.kdc, ldapPort: bound.ldap,
                                    ldapsPort: bound.ldaps, allowPlainLDAP: options.allowPlainLDAP, ntlmAuth: options.ntlmAuth,
                                    caCertificateDER: ca.map { [UInt8]($0) })
    }
}

/// Runs one Test login the way a client or NAC would, against the running server, and logs it like
/// a normal request (plus a `TEST login …` line that marks that request "(test)" in the feed).
/// Cancellable; every network wait has a deadline.
public struct LoginTester: Sendable {
    public let environment: LoginTestEnvironment

    public init(environment: LoginTestEnvironment) {
        self.environment = environment
    }

    /// Runs `request`; never throws (a failure to run is a failed result with the reason).
    public func run(_ request: LoginTestRequest, timeout: Double = 10) async -> LoginTestResult {
        let clock = ContinuousClock()
        let start = clock.now
        var result: LoginTestResult
        var sentName = request.user
        do {
            let outcome = try await Self.withDeadline(timeout) { () async throws -> (LoginTestResult, String) in
                switch request.preset {
                case .kerberos: try await kerberos(request)
                case .ntlm: try await ntlm(request)
                case .ldap: try await ldap(request)
                }
            }
            result = outcome.0
            sentName = outcome.1
        } catch where error is CancellationError || Task.isCancelled {
            // A cancelled connection may surface as its own error; the caller cancelled either way.
            result = LoginTestResult(passed: false, milliseconds: 0, method: Self.methodName(request), reason: "Cancelled",
                                     failure: .other)
        } catch let e as LoginTestError {
            result = LoginTestResult(passed: false, milliseconds: 0, method: Self.methodName(request),
                                     reason: e.description.prefix(1).uppercased() + e.description.dropFirst(), failure: .other)
        } catch {
            result = LoginTestResult(passed: false, milliseconds: 0, method: Self.methodName(request), reason: "\(error)",
                                     failure: .other)
        }
        let elapsed = clock.now - start
        result.milliseconds = max(1, Int((Double(elapsed.components.seconds) * 1000
                                          + Double(elapsed.components.attoseconds) / 1e15).rounded()))
        if result.reason != "Cancelled" {
            let marker = AuthenticationEvent.TestMarker(date: Date(), method: Self.markerMethod(request), passed: result.passed,
                                                         reason: result.reason ?? "", milliseconds: result.milliseconds,
                                                         name: sentName)
            environment.log.event("TEST", marker.logText)
        }
        return result
    }

    static func methodName(_ r: LoginTestRequest) -> String {
        switch r.preset {
        case .kerberos: "Kerberos AS"
        case .ntlm: r.msCHAPv2Style ? "MS-CHAPv2 (NTLMv1)" : "NTLM network logon"
        case .ldap: "LDAP bind"
        }
    }

    static func markerMethod(_ r: LoginTestRequest) -> AuthenticationEvent.Method {
        switch r.preset {
        case .kerberos: .kerberos
        case .ntlm: r.msCHAPv2Style ? .mschapv2 : .ntlm
        case .ldap: .ldapBind
        }
    }

    /// Runs `work`, cancelling it after `seconds`.
    static func withDeadline<T: Sendable>(_ seconds: Double, _ work: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await work() }
            group.addTask {
                try await Task.sleep(for: .milliseconds(Int(seconds * 1000)))
                return nil
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw CancellationError() }
            guard let value = first else { throw LoginTestError.timedOut(seconds) }
            return value
        }
    }

    // MARK: Names

    /// The account part of what was typed: `LAB\alice`, `alice@lab.sheep`, `CN=alice,…` → `alice`.
    public static func accountName(_ typed: String) -> String {
        let t = typed.trimmingCharacters(in: .whitespaces)
        if let slash = t.lastIndex(of: "\\") { return String(t[t.index(after: slash)...]) }
        if t.contains("="), let eq = t.firstIndex(of: "=") {
            return String(t[t.index(after: eq)...].prefix { $0 != "," })
        }
        if let at = t.lastIndex(of: "@") { return String(t[..<at]) }
        return t
    }

    /// NETLOGON `(LogonDomainName, UserName)` for a name form.
    public static func ntlmNames(_ typed: String, form: LoginTestRequest.NameForm, info: DomainInfo) -> (domain: String, user: String) {
        let account = accountName(typed)
        switch form {
        case .downLevel, .dn: return (info.netbiosDomain, account)
        case .upn: return ("", account + "@" + info.dnsDomain)
        case .accountOnly: return ("", account)
        case .asTyped:
            let t = typed.trimmingCharacters(in: .whitespaces)
            if let slash = t.firstIndex(of: "\\") { return (String(t[..<slash]), String(t[t.index(after: slash)...])) }
            return ("", t)
        }
    }

    /// The LDAP bind name for a name form (`dn` reads the account's DN from the store).
    public static func ldapName(_ typed: String, form: LoginTestRequest.NameForm, info: DomainInfo,
                                store: DirectoryStore) async -> String {
        let account = accountName(typed)
        switch form {
        case .downLevel: return info.netbiosDomain + "\\" + account
        case .upn: return account + "@" + info.dnsDomain
        case .accountOnly: return account
        case .asTyped: return typed.trimmingCharacters(in: .whitespaces)
        case .dn:
            if let e = try? await store.read(sam: account) { return e.dn.description }
            if let e = try? await store.read(sam: account + "$") { return e.dn.description }
            return "CN=\(account),CN=Users,\(info.domainDN)"
        }
    }

    // MARK: Groups

    /// Group names for RIDs of the domain (unknown RIDs as `RID 1234`), primary group first, unique.
    func groupNames(rids: [UInt32], extraSIDs: [SID] = []) async -> [String] {
        var names: [String] = []
        var sids = rids.compactMap { try? environment.info.domainSID.appending(rid: $0) }
        sids += extraSIDs
        for sid in sids {
            let name: String
            if let e = try? await environment.store.read(sid: sid, attrs: ["sAMAccountName", "cn"]),
               let n = e.string("sAMAccountName") ?? e.string("cn") {
                name = n
            } else {
                name = sid.rid.map { "RID \($0)" } ?? sid.description
            }
            if !names.contains(name) { names.append(name) }
        }
        return names
    }

    func accountGroups(sam: String) async -> [String] {
        guard let (a, _) = try? await environment.store.kerberosAccount(components: [sam], realm: environment.info.realm) else {
            return []
        }
        return await groupNames(rids: a.groupRIDs)
    }

    // MARK: Kerberos

    func kerberos(_ r: LoginTestRequest) async throws -> (LoginTestResult, String) {
        let info = environment.info
        guard let port = environment.kdcPort else { throw LoginTestError.notRunning("Kerberos (KDC)") }
        let account = Self.accountName(r.user)
        let realm = r.realmForm == .netbios ? info.netbiosDomain : info.realm
        let cname = PrincipalName(nameType: NameType.principal, nameString: [account])
        let sentName = "\(cname)@\(realm)"
        let method = Self.methodName(r)
        var opts = KDCOptions()
        opts.forwardable = true
        opts.renewable = true
        opts.canonicalize = true
        opts.renewableOK = true
        let now = Date()
        let body = KDCReqBody(kdcOptions: opts, cname: cname, realm: realm, sname: .krbtgt(realm: realm),
                              till: KerberosTime(now.addingTimeInterval(10 * 3600)), rtime: KerberosTime(now.addingTimeInterval(7 * 86_400)),
                              nonce: UInt32.random(in: 1...UInt32.max), etype: [18, 17, 23])
        let pacRequest = PAPacRequest(includePAC: true).paData

        // Leg 1 without pre-authentication: the KDC answers PREAUTH_REQUIRED with the salt.
        let first = try await Self.kdcExchange(port: port, ASReq(padata: [pacRequest], reqBody: body).encode())
        var etype: Int32 = 18
        var salt = info.realm + account
        var s2kparams: [UInt8]?
        if let err = try? KRBError(derBytes: first) {
            guard err.errorCode == KerberosErrorCode.kdcErrPreauthRequired else {
                return (kerberosFailure(err.errorCode, account: account, method: method, realm: realm), sentName)
            }
            if let methods = try? err.methodData(),
               let pa = methods.elements.first(where: { $0.type == PADataType.etypeInfo2 }),
               let entries = try? ETypeInfo2(derBytes: pa.value).entries,
               let entry = entries.first(where: { [18, 17, 23].contains($0.etype) }) {
                etype = entry.etype
                if let s = entry.salt { salt = s }
                s2kparams = entry.s2kparams
            }
        } else if (try? ASRep(derBytes: first)) == nil {
            throw LoginTestError.protocolError("not an AS-REP or KRB-ERROR")
        }
        guard let etypeValue = EncryptionType(rawValue: etype) else { throw LoginTestError.protocolError("etype \(etype)") }
        let key = try KerberosCrypto.stringToKey(etypeValue, password: r.password, salt: salt, parameters: s2kparams)

        // Leg 2 with PA-ENC-TIMESTAMP.
        let stamp = Date()
        let usec = Int32(stamp.timeIntervalSince1970.truncatingRemainder(dividingBy: 1) * 1_000_000)
        let ts = PAEncTSEnc(patimestamp: KerberosTime(stamp), pausec: usec)
        let cipher = try KerberosCrypto.encrypt(ts.encode(), key: key, usage: KeyUsage.asReqPaEncTimestamp, rng: RandomBytes())
        let encTS = PAData(type: PADataType.encTimestamp, value: EncryptedData(etype: etype, cipher: cipher).encode())
        var body2 = body
        body2.nonce = UInt32.random(in: 1...UInt32.max)
        let reply = try await Self.kdcExchange(port: port, ASReq(padata: [encTS, pacRequest], reqBody: body2).encode())
        if let err = try? KRBError(derBytes: reply) {
            return (kerberosFailure(err.errorCode, account: account, method: method, realm: realm), sentName)
        }
        guard let rep = try? ASRep(derBytes: reply) else { throw LoginTestError.protocolError("not an AS-REP") }
        guard let plain = try? KerberosCrypto.decrypt(rep.encPart.cipher, key: key, usage: KeyUsage.asRepEncPart),
              let part = (try? EncASRepPart(derBytes: plain))?.part ?? (try? EncTGSRepPart(derBytes: plain))?.part else {
            return (LoginTestResult(passed: false, milliseconds: 0, method: method,
                                    reason: "The reply could not be decrypted with this password", failure: .wrongPassword), sentName)
        }

        var details: [LoginTestResult.Detail] = [
            .init("Client", "\(rep.cname)@\(rep.crealm)"),
            .init("Realm asked", realm),
            .init("Ticket", "\(part.sname)@\(part.srealm), enctype \(Self.etypeName(rep.ticket.encPart.etype))"),
            .init("Session key", Self.etypeName(part.key.keytype)),
            .init("Flags", Self.flagNames(part.flags).joined(separator: ", ")),
            .init("Valid until", Self.stamp(part.endtime.date) + (part.renewTill.map { " (renewable until \(Self.stamp($0.date)))" } ?? "")),
        ]
        var groups: [String] = []
        var accountLabel = "\(info.netbiosDomain)\\\(rep.cname)"
        if let pac = await ticketPAC(rep.ticket) {
            if let logon = pac.logonInfo {
                accountLabel = "\(logon.logonDomainName)\\\(logon.effectiveName)"
                var rids = [logon.primaryGroupId]
                rids += logon.groupIds.map(\.relativeId).filter { $0 != logon.primaryGroupId }
                groups = await groupNames(rids: rids, extraSIDs: logon.extraSids.map(\.sid).filter { !Self.isWellKnown($0) })
                details.append(.init("PAC user", "\(accountLabel) (RID \(logon.userId))"))
                details.append(.init("PAC groups", groups.isEmpty ? "none" : groups.joined(separator: ", ")))
            }
            if let upn = pac.upnDNS { details.append(.init("PAC UPN", "\(upn.upn) (\(upn.dnsDomainName))")) }
        } else {
            groups = await accountGroups(sam: rep.cname.nameString.first ?? account)
        }
        details.append(.init("Server", "KDC 127.0.0.1:\(port)/tcp"))
        return (LoginTestResult(passed: true, milliseconds: 0, method: method, groups: groups, account: accountLabel, details: details),
                sentName)
    }

    func kerberosFailure(_ code: Int32, account: String, method: String, realm: String) -> LoginTestResult {
        let name = KerberosErrorCode.name(code)
        let (reason, failure) = AuthenticationEvent.kerberosFailure(name, computer: account.hasSuffix("$"))
        return LoginTestResult(passed: false, milliseconds: 0, method: method, reason: reason, failure: failure,
                               details: [.init("KDC answer", name), .init("Realm asked", realm)])
    }

    /// The TGT's PAC, read with the krbtgt key (the app is the DC; the key never leaves the process).
    func ticketPAC(_ ticket: Ticket) async -> ParsedPAC? {
        let info = environment.info
        guard let (krbtgt, _) = try? await environment.store.kerberosAccount(components: ["krbtgt", info.realm], realm: info.realm),
              let key = krbtgt.keys.first(where: { $0.type.rawValue == ticket.encPart.etype }),
              let plain = try? KerberosCrypto.decrypt(ticket.encPart.cipher, key: key, usage: KeyUsage.kdcRepTicket),
              let enc = try? EncTicketPart(derBytes: plain),
              let pacBytes = try? enc.authorizationData.findPAC() else { return nil }
        return try? PACParser.parse(pacBytes)
    }

    static func isWellKnown(_ sid: SID) -> Bool {
        let s = sid.description
        return s.hasPrefix("S-1-18-") || s.hasPrefix("S-1-5-32-") || s == "S-1-5-11" || s == "S-1-5-2"
    }

    /// One AS exchange over TCP (4-byte length prefix, RFC 4120 §7.2.2).
    static func kdcExchange(port: UInt16, _ request: [UInt8]) async throws -> [UInt8] {
        let conn = LoopbackConnection(port: Int(port))
        defer { conn.close() }
        try await conn.open()
        let n = UInt32(request.count)
        try await conn.send([UInt8(n >> 24), UInt8(truncatingIfNeeded: n >> 16), UInt8(truncatingIfNeeded: n >> 8),
                             UInt8(truncatingIfNeeded: n)] + request)
        let reply = try await conn.receive { buffer in
            guard buffer.count >= 4 else { return nil }
            let len = Int(buffer[0]) << 24 | Int(buffer[1]) << 16 | Int(buffer[2]) << 8 | Int(buffer[3])
            return 4 + len
        }
        return Array(reply.dropFirst(4))
    }

    static func etypeName(_ etype: Int32) -> String {
        switch etype {
        case 18: "AES256 (18)"
        case 17: "AES128 (17)"
        case 23: "RC4 (23)"
        default: "etype \(etype)"
        }
    }

    static func flagNames(_ f: TicketFlags) -> [String] {
        var out: [String] = []
        if f.forwardable { out.append("forwardable") }
        if f.proxiable { out.append("proxiable") }
        if f.renewable { out.append("renewable") }
        if f.initial { out.append("initial") }
        if f.preAuthent { out.append("pre-authent") }
        if f.okAsDelegate { out.append("ok-as-delegate") }
        if f.encPARep { out.append("enc-pa-rep") }
        return out
    }

    /// `27 Sep 2026 07:56` in the Gregorian calendar (never the Mac's calendar: 2569 BE here).
    static func stamp(_ d: Date) -> String {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        f.dateFormat = "d MMM yyyy HH:mm"
        return f.string(from: d)
    }

    // MARK: NTLM (NETLOGON network logon)

    func ntlm(_ r: LoginTestRequest) async throws -> (LoginTestResult, String) {
        let info = environment.info
        let log = environment.log
        let service = NetlogonService(store: environment.store, state: NetlogonStateStore(),
                                      dcInfo: StaticNetlogonDCInfoProvider(),
                                      config: NetlogonServiceConfig(ntlmAuth: environment.ntlmAuth,
                                                                    onEvent: { line in log.event("NETLOGON", line) }))
        let (domain, user) = Self.ntlmNames(r.user, form: r.ntlmNameForm, info: info)
        let workstation = r.workstation.trimmingCharacters(in: .whitespaces).isEmpty ? "LABDC-TEST"
            : r.workstation.trimmingCharacters(in: .whitespaces).uppercased()
        let ntHash = NTLMCrypto.ntHash(password: r.password)
        var pc: UInt32 = r.allowComputerAccounts ? NetlogonTestLogon.allowTrustAccounts : 0
        let challenge: [UInt8]
        let nt: [UInt8]
        var lm: [UInt8] = []
        if r.msCHAPv2Style {
            // RFC 2759: ChallengeHash = SHA1(PeerChallenge | AuthenticatorChallenge | UserName)[0..<8];
            // the NAC forwards it as LmChallenge with the 24-byte NT-Response.
            let peer = Self.random(16), authenticator = Self.random(16)
            let hashUser = Self.accountName(user)
            var sha = Insecure.SHA1()
            sha.update(data: peer + authenticator + Array(hashUser.utf8))
            challenge = Array(Array(sha.finalize()).prefix(8))
            nt = NTLMNetworkLogon.ntlmv1Response(ntHash: ntHash, challenge: challenge)
            pc |= NetlogonTestLogon.allowMSCHAPv2
        } else {
            challenge = Self.random(8)
            let clientChallenge = Self.random(8)
            let key = NTLMCrypto.ntowfv2(ntHash: ntHash, user: user, domain: domain)
            let filetime = UInt64((Date().timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
            let temp = NTLMCrypto.temp(timestamp: filetime, clientChallenge: clientChallenge,
                                       avPairs: [.string(2, info.netbiosDomain), .string(1, workstation)])
            nt = NTLMCrypto.ntProofStr(responseKeyNT: key, serverChallenge: challenge, temp: temp) + temp
            lm = NTLMCrypto.lmv2Response(responseKeyLM: key, serverChallenge: challenge, clientChallenge: clientChallenge)
        }
        let logon = NetlogonTestLogon(logonDomain: domain, userName: user, workstation: workstation, serverChallenge: challenge,
                                      ntResponse: nt, lmResponse: lm, parameterControl: pc)
        try Task.checkCancellation()
        let answer = try await service.testNetworkLogon(logon)
        let sentName = domain.isEmpty ? user : domain + "\\" + user
        let method = Self.methodName(r)
        var details: [LoginTestResult.Detail] = [
            .init("Sent", "LogonDomainName \"\(domain)\", UserName \"\(user)\", Workstation \"\(workstation)\""),
            .init("ParameterControl", "0x" + String(pc, radix: 16) + Self.parameterControlNames(pc)),
            .init("Response", r.msCHAPv2Style ? "NTLMv1 24 bytes over the MS-CHAPv2 ChallengeHash" : "NTLMv2 (\(nt.count) bytes)"),
            .init("SamLogon status", answer.statusName + (answer.reason.map { " (\($0))" } ?? "")),
            .init("NTLM policy", environment.ntlmAuth.rawValue),
        ]
        guard answer.succeeded else {
            let outcome = answer.statusName + (answer.reason.map { " (\($0))" } ?? "")
            let (reason, failure) = AuthenticationEvent.netlogonFailure(outcome, computer: Self.accountName(user).hasSuffix("$"),
                                                                         hasChannel: true)
            return (LoginTestResult(passed: false, milliseconds: 0, method: method, reason: reason, failure: failure,
                                    account: answer.account, details: details), sentName)
        }
        let groups = await groupNames(rids: answer.groupRIDs)
        let account = "\(answer.logonDomainName ?? info.netbiosDomain)\\\(answer.effectiveName ?? answer.account ?? user)"
        details.append(.init("Validation", "SamInfo4: \(account), RID \(answer.userId ?? 0), primary group \(answer.primaryGroupId ?? 0)"))
        details.append(.init("Groups", groups.isEmpty ? "none" : groups.joined(separator: ", ")))
        if let upn = answer.upn, !upn.isEmpty { details.append(.init("UPN", upn)) }
        return (LoginTestResult(passed: true, milliseconds: 0, method: method, groups: groups, account: account, details: details),
                sentName)
    }

    static func parameterControlNames(_ pc: UInt32) -> String {
        var names: [String] = []
        if pc & 0x20 != 0 { names.append("ALLOW_SERVER_TRUST_ACCOUNT") }
        if pc & 0x800 != 0 { names.append("ALLOW_WORKSTATION_TRUST_ACCOUNT") }
        if pc & 0x10000 != 0 { names.append("ALLOW_MSVCHAPV2") }
        return names.isEmpty ? "" : " (" + names.joined(separator: ", ") + ")"
    }

    static func random(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
    }

    // MARK: LDAP

    func ldap(_ r: LoginTestRequest) async throws -> (LoginTestResult, String) {
        let env = environment
        let name = await Self.ldapName(r.user, form: r.ldapNameForm, info: env.info, store: env.store)
        let method = Self.methodName(r)
        let useTLS: Bool = switch r.ldapConnection {
        case .automatic: !env.allowPlainLDAP || env.ldapPort == nil
        case .plain: false
        case .tls: true
        }
        guard let port = useTLS ? env.ldapsPort : env.ldapPort else {
            throw LoginTestError.notRunning(useTLS ? "LDAPS" : "LDAP")
        }
        if useTLS, env.caCertificateDER == nil { throw LoginTestError.notRunning("the lab CA (needed to trust LDAPS)") }
        let conn = LoopbackConnection(port: port, trustAnchorDER: useTLS ? env.caCertificateDER : nil)
        defer { conn.close() }
        try await conn.open()
        let bind = LDAPMessage(messageID: 1, .bindRequest(BindRequest(name: name, authentication: .simple(Array(r.password.utf8)))))
        try await conn.send(bind.encoded())
        let response = try LDAPMessage(bytes: try await conn.receive(frame: Self.ldapFrame))
        guard case .bindResponse(let bound) = response.operation else { throw LoginTestError.protocolError("no BindResponse") }
        let code = bound.result.resultCode
        var details: [LoginTestResult.Detail] = [
            .init("Bind name", name),
            .init("Connection", (useTLS ? "LDAPS" : "LDAP") + " 127.0.0.1:\(port)" + (useTLS ? " (TLS, lab CA)" : " (plain)")),
            .init("Result code", "\(code.rawValue) (\(code))"),
        ]
        if !bound.result.diagnosticMessage.isEmpty { details.append(.init("Diagnostic", bound.result.diagnosticMessage)) }
        guard code == .success else {
            try? await conn.send(LDAPMessage(messageID: 2, .unbindRequest).encoded())
            var outcome = code == .invalidCredentials ? "invalidCredentials" : code == .strongerAuthRequired ? "strongerAuthRequired"
                : code == .unwillingToPerform ? "unwillingToPerform" : "result \(code.rawValue)"
            if let range = bound.result.diagnosticMessage.range(of: #"data ([0-9a-fA-F]+)"#, options: .regularExpression) {
                let data = bound.result.diagnosticMessage[range].dropFirst(5)
                if data != "0" { outcome += " (\(data))" }
            }
            var (reason, failure) = AuthenticationEvent.ldapFailure(outcome)
            if failure == .passwordMustChange {
                // Data 773 is only sent after the password matched (30 Sep 2026): say so, so a
                // reset with "must change" on does not read as a wrong password.
                reason = "Password is correct, but must be changed at next sign-in"
                details.append(.init("Next step", "Sign in on a device to change it, or turn off “must change password”"))
            }
            return (LoginTestResult(passed: false, milliseconds: 0, method: method, reason: reason, failure: failure, details: details),
                    name)
        }
        // Who am I (RFC 4532): the identity the server bound.
        try await conn.send(LDAPMessage(messageID: 2, .extendedRequest(ExtendedRequest(name: LDAPExtendedOID.whoAmI))).encoded())
        var account: String?
        if let who = try? LDAPMessage(bytes: try await conn.receive(frame: Self.ldapFrame)),
           case .extendedResponse(let ext) = who.operation, let value = ext.value {
            let authz = String(decoding: value, as: UTF8.self)
            account = authz.hasPrefix("u:") ? String(authz.dropFirst(2)) : authz
            details.append(.init("Who am I", authz))
        }
        try? await conn.send(LDAPMessage(messageID: 3, .unbindRequest).encoded())
        let sam = account.map { ActivityEvent.stripDomain($0) } ?? Self.accountName(r.user)
        let groups = await accountGroups(sam: sam)
        details.append(.init("Groups", groups.isEmpty ? "none" : groups.joined(separator: ", ")))
        return (LoginTestResult(passed: true, milliseconds: 0, method: method, groups: groups, account: account, details: details), name)
    }

    static func ldapFrame(_ buffer: [UInt8]) -> Int? {
        (try? BERElement.frameLength(buffer, limit: 1 << 20)) ?? nil
    }
}
