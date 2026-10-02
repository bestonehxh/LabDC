import Foundation
import PKIKit
import SYSVOL
import Store

// UI-4 Connect: the live checklist next to each guide ("Joined ✓ 26 Sep 14:24 as WIN10-PC1$",
// "Last authentication ✓ 15:56 alice via CLEARPASS-ENTRY", …), derived from what the store and
// the log already know. Nothing here blocks or polls: the page reloads the observations when a
// relevant log line arrives.

/// A computer account as the checklist needs it.
public struct JoinedComputer: Sendable, Hashable, Identifiable {
    /// `WIN10-PC1$`
    public var account: String
    /// `WIN10-PC1`
    public var name: String
    public var dnsHostName: String?
    public var operatingSystem: String?
    public var operatingSystemVersion: String?
    /// `whenCreated` (the join).
    public var joined: Date?

    public var id: String { account }

    public init(account: String, name: String? = nil, dnsHostName: String? = nil, operatingSystem: String? = nil,
                operatingSystemVersion: String? = nil, joined: Date? = nil) {
        self.account = account
        self.name = name ?? (account.hasSuffix("$") ? String(account.dropLast()) : account)
        self.dnsHostName = dnsHostName
        self.operatingSystem = operatingSystem
        self.operatingSystemVersion = operatingSystemVersion
        self.joined = joined
    }

    /// `Windows 10 Pro 10.0 (19045)`
    public var osDescription: String? {
        guard let os = operatingSystem, !os.isEmpty else { return nil }
        return [os, operatingSystemVersion].compactMap { $0 }.joined(separator: " ")
    }
}

/// An issued certificate (the `pki_issued` row, without the DER).
public struct IssuedCertificateRecord: Sendable, Hashable {
    public var serial: String
    public var template: String
    public var subject: String
    public var requester: String
    public var issuedAt: Date
    public var revoked: Bool

    public init(serial: String, template: String, subject: String, requester: String, issuedAt: Date, revoked: Bool = false) {
        self.serial = serial
        self.template = template
        self.subject = subject
        self.requester = requester
        self.issuedAt = issuedAt
        self.revoked = revoked
    }

    /// `CN=sw1,O=…` → `sw1`.
    public var commonName: String {
        for part in subject.split(separator: ",") {
            let p = part.trimmingCharacters(in: .whitespaces)
            if p.uppercased().hasPrefix("CN=") { return String(p.dropFirst(3)) }
        }
        return subject
    }
}

/// Everything the checklists are derived from.
public struct ConnectObservations: Sendable, Equatable {
    /// Computer accounts other than domain controllers, newest join first.
    public var computers: [JoinedComputer]
    public var issued: [IssuedCertificateRecord]
    /// Sign-in outcomes, newest first (Kerberos, NETLOGON, LDAP binds).
    public var events: [ActivityEvent]
    /// SCEP / EST / WSTEP log lines, newest first.
    public var enrollment: [LogLine]
    /// The current CA is in the Default Domain Policy's trusted roots.
    public var trustedRootPublished: Bool
    /// Auto-enrollment in the Default Domain Policy (nil = unknown).
    public var autoEnrollment: Bool?
    /// Challenges that can still be used (not revoked, not expired, one-time ones unused).
    public var usableChallenges: Int
    public var allowPlainLDAP: Bool
    /// RADIUS clients (NAS) by name, for the Switch / AP checklist.
    public var radiusClients: [String]

    public init(computers: [JoinedComputer] = [], issued: [IssuedCertificateRecord] = [], events: [ActivityEvent] = [],
                enrollment: [LogLine] = [], trustedRootPublished: Bool = false, autoEnrollment: Bool? = nil,
                usableChallenges: Int = 0, allowPlainLDAP: Bool = true, radiusClients: [String] = []) {
        self.computers = computers
        self.issued = issued
        self.events = events
        self.enrollment = enrollment
        self.trustedRootPublished = trustedRootPublished
        self.autoEnrollment = autoEnrollment
        self.usableChallenges = usableChallenges
        self.allowPlainLDAP = allowPlainLDAP
        self.radiusClients = radiusClients
    }

    /// Reads the store, the Default Domain Policy and the log. Every part is best effort.
    public static func load(store: DirectoryStore?, pki: LabPKI?, data: DataDirectory, log: [LogLine],
                            allowPlainLDAP: Bool, now: Date = Date()) async -> ConnectObservations {
        var o = ConnectObservations(allowPlainLDAP: allowPlainLDAP)
        o.events = ActivityEvent.recent(log, limit: 1000)
        o.enrollment = log.reversed().filter { ["SCEP", "EST", "WSTEP", "XCEP"].contains($0.component) }.prefix(200).map { $0 }
        guard let store, let info = try? await store.domainInfo() else { return o }
        let oc = FilterAST.equality(attribute: "objectClass", value: Array("computer".utf8))
        if let rows = try? await store.search(base: info.domainDN, scope: .subtree, filter: oc,
                                              attrs: ["cn", "sAMAccountName", "dNSHostName", "operatingSystem",
                                                      "operatingSystemVersion", "whenCreated", "userAccountControl"]) {
            o.computers = rows.filter {
                UInt32(truncatingIfNeeded: $0.int("userAccountControl") ?? 0) & UserAccountControl.serverTrustAccount == 0
            }.map {
                JoinedComputer(account: $0.samAccountName ?? ($0.string("cn") ?? "?") + "$", name: $0.string("cn"),
                               dnsHostName: $0.string("dNSHostName"), operatingSystem: $0.string("operatingSystem"),
                               operatingSystemVersion: $0.string("operatingSystemVersion"),
                               joined: $0.string("whenCreated").flatMap(parseGeneralizedTime))
            }.sorted { ($0.joined ?? .distantPast) > ($1.joined ?? .distantPast) }
        }
        if let rows = try? await store.issuedCertificates() {
            o.issued = rows.map {
                IssuedCertificateRecord(serial: $0.serial, template: $0.templateName, subject: $0.subject, requester: $0.requesterName,
                                  issuedAt: $0.issuedAt, revoked: $0.revoked)
            }.sorted { $0.issuedAt > $1.issuedAt }
        }
        if let clients = try? await store.listNAS() {
            o.radiusClients = clients.map(\.name)
        }
        if let rows = try? await store.pkiChallenges() {
            o.usableChallenges = rows.filter { !$0.revoked && $0.expiresAt > now && ($0.reusable || $0.usedAt == nil) }.count
        }
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        if let pki, let ca = try? await pki.currentAuthority(), let der = try? ca.der(),
           let roots = try? await editor.trustedRoots() {
            let thumbprint = CertificateBlob.thumbprint(der)
            o.trustedRootPublished = roots.contains { $0.thumbprint == thumbprint }
        }
        if let state = try? await editor.autoEnrollment() {
            if case .enabled = state { o.autoEnrollment = true } else { o.autoEnrollment = false }
        }
        return o
    }

    /// `20260926142400.0Z` (AD's GeneralizedTime) → Date.
    public static func parseGeneralizedTime(_ s: String) -> Date? {
        let digits = s.prefix(14)
        guard digits.count == 14, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        let n = Array(digits).map { Int(String($0))! }
        func v(_ r: Range<Int>) -> Int { r.reduce(0) { $0 * 10 + n[$1] } }
        var c = DateComponents()
        c.year = v(0..<4); c.month = v(4..<6); c.day = v(6..<8)
        c.hour = v(8..<10); c.minute = v(10..<12); c.second = v(12..<14)
        c.timeZone = TimeZone(identifier: "UTC")
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: c)
    }
}

/// One line of the live checklist.
public struct ChecklistItem: Identifiable, Sendable, Equatable {
    public enum State: String, Sendable, Equatable {
        /// Seen: ✓
        case done
        /// Not seen yet.
        case waiting
        /// Seen, and it failed.
        case problem
        /// Can't be seen from the DC: check on the device.
        case checkOnDevice
        /// Arrives in a later phase.
        case later
    }

    public var id: String
    public var title: String
    public var state: State
    /// When it happened (shown before `detail`).
    public var date: Date?
    /// `as WIN10-PC1$`, `alice via CLEARPASS-ENTRY`, `Wrong password`.
    public var detail: String
    /// One action that moves it forward.
    public var action: GuideAction?

    public init(id: String, title: String, state: State, date: Date? = nil, detail: String = "", action: GuideAction? = nil) {
        self.id = id
        self.title = title
        self.state = state
        self.date = date
        self.detail = detail
        self.action = action
    }
}

extension DeviceKind {
    /// Whether `computer` looks like this kind of device (by `operatingSystem` and the names
    /// ClearPass/iMaster use). A computer matches at most one kind; `.switchAP` and `.other` none.
    public func matches(_ computer: JoinedComputer) -> Bool {
        DeviceKind.kind(of: computer) == self
    }

    /// The device kind a computer account most likely belongs to.
    public static func kind(of c: JoinedComputer) -> DeviceKind? {
        let os = (c.operatingSystem ?? "").lowercased()
        let name = c.name.uppercased()
        if name.contains("CLEARPASS") || name.hasPrefix("CPPM") || os.contains("clearpass") { return .clearpass }
        if os.contains("imaster") || name.contains("IMASTER") || name.hasPrefix("NCE")
            || name == "OMP" || name == "DATABACKUP" || name.range(of: #"^SERVICE\d*$"#, options: .regularExpression) != nil {
            return .imaster
        }
        if os.hasPrefix("windows") { return .windows }
        if os.contains("mac") || os.contains("os x") { return .apple }
        if ["ubuntu", "debian", "linux", "red hat", "rhel", "fedora", "centos", "rocky", "alma", "suse", "samba"]
            .contains(where: os.contains) { return .linux }
        return nil
    }

    /// The computers of this kind (newest first); `pinned` (an account the user picked) first.
    public func computers(in all: [JoinedComputer], pinned: String? = nil) -> [JoinedComputer] {
        if let pinned, let c = all.first(where: { $0.account.caseInsensitiveCompare(pinned) == .orderedSame }) {
            return [c]
        }
        switch self {
        case .switchAP, .other: return []
        default: return all.filter(matches)
        }
    }

    /// Whether this kind of device joins the domain (the checklist then offers a computer picker).
    public var joins: Bool {
        switch self {
        case .switchAP, .other: false
        default: true
        }
    }
}

/// The checklist per device.
public enum DeviceChecklist {
    public static func items(for kind: DeviceKind, _ o: ConnectObservations, pinned: String? = nil) -> [ChecklistItem] {
        // A NAC cluster is every node; a PC, Mac or Linux machine is the picked or newest one.
        let all = kind.computers(in: o.computers, pinned: pinned)
        let computers = kind == .clearpass || kind == .imaster ? all : Array(all.prefix(1))
        let addresses = addresses(of: computers, in: o.events)
        switch kind {
        case .windows:
            return [
                joined(kind, computers, total: all.count),
                secureChannel(computers, o.events),
                lastSignIn(title: "Last sign-in", computers, addresses, o.events, noun: "PC"),
                trustedRoot(o),
                computerCertificate(computers, o),
            ]
        case .clearpass, .imaster:
            return [
                joined(kind, computers, total: all.count),
                nacAuthentication(computers, addresses, o.events, kind: kind),
                ldapLookup(addresses, o, device: kind == .clearpass ? "ClearPass" : "iMaster"),
                kind == .clearpass ? radiusCertificate(o) : extendedUser(o),
            ]
        case .linux:
            return [
                joined(kind, computers, total: all.count),
                machineKerberos(computers, o.events),
                lastSignIn(title: "Last user sign-in", computers, addresses, o.events, noun: "machine"),
            ]
        case .apple:
            var bound = joined(kind, computers, total: all.count)
            if bound.state == .waiting {
                bound.state = .checkOnDevice
                bound.detail = "No Mac bound (only needed for network accounts on a Mac)"
            }
            return [
                // A status line; the save link is step 1's, not repeated here (owner, 2 Oct 2026).
                ChecklistItem(id: "profile", title: "CA profile installed", state: .checkOnDevice,
                              detail: "Install the profile and turn on full trust (step 1)"),
                bound,
                lastSignIn(title: "Last sign-in", computers, addresses, o.events, noun: "Mac"),
            ]
        case .switchAP:
            return [
                challengeReady(o),
                deviceCertificate(o),
                lastEnrollment(o),
                radiusClient(o),
            ]
        case .other:
            return [
                lastEvent(id: "ldap", title: "Last LDAP bind", o.events.first { $0.method.hasPrefix("LDAP bind") },
                          none: "No LDAP bind yet"),
                lastEvent(id: "kerberos", title: "Last Kerberos sign-in", o.events.first { $0.method == "Kerberos sign-in" },
                          none: "No Kerberos sign-in yet"),
                ChecklistItem(id: "ca", title: "CA", state: .checkOnDevice, detail: "Trust it on the device (step 3)"),
            ]
        }
    }

    // MARK: Pieces

    static func joined(_ kind: DeviceKind, _ computers: [JoinedComputer], total: Int) -> ChecklistItem {
        guard let newest = computers.first else {
            return ChecklistItem(id: "joined", title: "Joined", state: .waiting, detail: "Not joined yet")
        }
        var detail = "as \(newest.account)"
        if computers.count > 1 {
            detail = "\(computers.count) nodes: " + computers.map(\.account).joined(separator: ", ")
        } else if total > 1 {
            detail += " (newest of \(total))"
        }
        return ChecklistItem(id: "joined", title: "Joined", state: .done, date: newest.joined, detail: detail)
    }

    /// Addresses the computers' own sign-ins came from, and the NAC's SamLogons name them.
    static func addresses(of computers: [JoinedComputer], in events: [ActivityEvent]) -> Set<String> {
        let accounts = Set(computers.map { $0.account.uppercased() })
        let names = Set(computers.map { $0.name.uppercased() })
        var out = Set<String>()
        for e in events {
            if accounts.contains(e.user.uppercased()) { out.insert(e.from) }
            let parts = e.from.components(separatedBy: " · ")
            if parts.count == 2, names.contains(parts[0].uppercased()) { out.insert(parts[1]) }
        }
        return out
    }

    static func secureChannel(_ computers: [JoinedComputer], _ events: [ActivityEvent]) -> ChecklistItem {
        let accounts = Set(computers.map { $0.account.uppercased() })
        guard let e = events.first(where: { $0.method == "Computer secure channel" && accounts.contains($0.user.uppercased()) }) else {
            return ChecklistItem(id: "channel", title: "Secure channel", state: .waiting,
                                 detail: computers.isEmpty ? "After the join" : "Not seen since the log started (nltest /sc_verify)")
        }
        return ChecklistItem(id: "channel", title: "Secure channel", state: e.result == .success ? .done : .problem, date: e.date,
                             detail: e.result == .success ? e.user : "\(e.user): \(e.detail)")
    }

    static func lastSignIn(title: String, _ computers: [JoinedComputer], _ addresses: Set<String>, _ events: [ActivityEvent],
                           noun: String) -> ChecklistItem {
        let e = events.first {
            ($0.method == "Kerberos sign-in") && !$0.user.hasSuffix("$") && addresses.contains($0.from)
        }
        guard let e else {
            return ChecklistItem(id: "signin", title: title, state: .waiting,
                                 detail: computers.isEmpty ? "After the join" : "No domain user has signed in on this \(noun) yet")
        }
        let device = computers.first.map { " on \($0.name)" } ?? ""
        return ChecklistItem(id: "signin", title: title, state: e.result == .success ? .done : .problem, date: e.date,
                             detail: e.result == .success ? "\(e.user)\(device)" : "\(e.user)\(device): \(e.detail)")
    }

    static func trustedRoot(_ o: ConnectObservations) -> ChecklistItem {
        o.trustedRootPublished
            ? ChecklistItem(id: "root", title: "Trusted root delivered", state: .checkOnDevice,
                            detail: "In the Default Domain Policy; check on the PC with gpupdate /force and certutil -store -grouppolicy Root")
            : ChecklistItem(id: "root", title: "Trusted root delivered", state: .waiting,
                            detail: "The CA is not published in the Default Domain Policy yet", action: .publishCA)
    }

    static func computerCertificate(_ computers: [JoinedComputer], _ o: ConnectObservations) -> ChecklistItem {
        let names = Set(computers.flatMap { [$0.account.uppercased(), $0.name.uppercased(), ($0.dnsHostName ?? "").uppercased()] })
        let cert = o.issued.first { c in
            !c.revoked && (names.contains(Self.accountPart(c.requester).uppercased()) || names.contains(c.commonName.uppercased()))
        }
        if let cert {
            return ChecklistItem(id: "cert", title: "Certificate enrolled", state: .done, date: cert.issuedAt,
                                 detail: "\(cert.template) for \(cert.commonName)")
        }
        if o.autoEnrollment == false {
            return ChecklistItem(id: "cert", title: "Certificate enrolled", state: .waiting,
                                 detail: "Auto-enrollment is off", action: .openEnrollment)
        }
        return ChecklistItem(id: "cert", title: "Certificate enrolled", state: .waiting,
                             detail: computers.isEmpty ? "After the join" : "Not yet (certutil -pulse asks now)")
    }

    static func nacAuthentication(_ computers: [JoinedComputer], _ addresses: Set<String>, _ events: [ActivityEvent],
                                  kind: DeviceKind) -> ChecklistItem {
        let names = Set(computers.map { $0.name.uppercased() })
        let e = events.first { e in
            guard e.method.hasSuffix("(NAC)") else { return false }
            let parts = e.from.components(separatedBy: " · ")
            return names.contains(parts[0].uppercased()) || (parts.count == 2 && addresses.contains(parts[1]))
                || (parts.count == 1 && addresses.contains(parts[0]))
        }
        guard let e else {
            return ChecklistItem(id: "auth", title: "Last authentication", state: .waiting,
                                 detail: computers.isEmpty ? "After the join" : "No sign-in through the \(kind.shortTitle) yet")
        }
        let via = e.from.components(separatedBy: " · ").first ?? e.from
        return ChecklistItem(id: "auth", title: "Last authentication", state: e.result == .success ? .done : .problem, date: e.date,
                             detail: e.result == .success ? "\(e.user) via \(via)" : "\(e.user) via \(via): \(e.detail)")
    }

    static func ldapLookup(_ addresses: Set<String>, _ o: ConnectObservations, device: String) -> ChecklistItem {
        let e = o.events.first { $0.method.hasPrefix("LDAP bind") && addresses.contains($0.from) }
        if let e {
            return ChecklistItem(id: "ldap", title: "LDAP lookups", state: e.result == .success ? .done : .problem, date: e.date,
                                 detail: e.result == .success ? "as \(e.user)" : "\(e.user): \(e.detail)",
                                 action: e.result == .success || o.allowPlainLDAP ? nil : .openDirectorySettings)
        }
        if !o.allowPlainLDAP {
            return ChecklistItem(id: "ldap", title: "LDAP lookups", state: .waiting,
                                 detail: "Allow plain LDAP is off: use port 636 (LDAP over SSL)", action: .openDirectorySettings)
        }
        return ChecklistItem(id: "ldap", title: "LDAP lookups", state: .waiting,
                             detail: addresses.isEmpty ? "Not seen yet (known after the join)" : "No bind from the \(device) yet")
    }

    static func radiusCertificate(_ o: ConnectObservations) -> ChecklistItem {
        if let c = o.issued.first(where: { !$0.revoked && ($0.commonName.lowercased().contains("clearpass") || $0.commonName.lowercased().contains("cppm")) }) {
            return ChecklistItem(id: "radiuscert", title: "RADIUS certificate signed", state: .done, date: c.issuedAt,
                                 detail: "\(c.commonName) (\(c.template))")
        }
        return ChecklistItem(id: "radiuscert", title: "RADIUS certificate signed", state: .checkOnDevice,
                             detail: "Sign ClearPass's CSR here, or add its CA as a trusted root", action: .openSignCSR)
    }

    static func extendedUser(_ o: ConnectObservations) -> ChecklistItem {
        let windows = o.computers.filter { DeviceKind.windows.matches($0) }
        return windows.isEmpty
            ? ChecklistItem(id: "machines", title: "Computers to sync", state: .waiting, detail: "No Windows PC has joined yet")
            : ChecklistItem(id: "machines", title: "Computers to sync", state: .done, date: windows.first?.joined,
                            detail: "\(windows.count) Windows PC\(windows.count == 1 ? "" : "s") with dNSHostName")
    }

    static func machineKerberos(_ computers: [JoinedComputer], _ events: [ActivityEvent]) -> ChecklistItem {
        let accounts = Set(computers.map { $0.account.uppercased() })
        guard let e = events.first(where: { $0.method == "Kerberos sign-in" && accounts.contains($0.user.uppercased()) }) else {
            return ChecklistItem(id: "machine", title: "Computer Kerberos (SSSD)", state: .waiting,
                                 detail: computers.isEmpty ? "After the join" : "Not seen yet (sudo systemctl restart sssd)")
        }
        return ChecklistItem(id: "machine", title: "Computer Kerberos (SSSD)", state: e.result == .success ? .done : .problem,
                             date: e.date, detail: e.result == .success ? e.user : "\(e.user): \(e.detail)")
    }

    static func challengeReady(_ o: ConnectObservations) -> ChecklistItem {
        o.usableChallenges > 0
            ? ChecklistItem(id: "challenge", title: "Challenge ready", state: .done,
                            detail: "\(o.usableChallenges) usable challenge\(o.usableChallenges == 1 ? "" : "s")")
            : ChecklistItem(id: "challenge", title: "Challenge ready", state: .waiting, detail: "No usable challenge yet",
                            action: .openEnrollment)
    }

    static func deviceCertificate(_ o: ConnectObservations) -> ChecklistItem {
        guard let c = o.issued.first(where: { !$0.revoked && $0.template.caseInsensitiveCompare("Device") == .orderedSame }) else {
            return ChecklistItem(id: "cert", title: "Certificate enrolled", state: .waiting, detail: "No device certificate yet")
        }
        return ChecklistItem(id: "cert", title: "Certificate enrolled", state: .done, date: c.issuedAt, detail: "\(c.commonName) (\(c.template))")
    }

    /// Done once any RADIUS client exists (the DC cannot tell which one is this device).
    static func radiusClient(_ o: ConnectObservations) -> ChecklistItem {
        o.radiusClients.isEmpty
            ? ChecklistItem(id: "radius", title: "RADIUS client added", state: .waiting,
                            detail: "Add the switch or AP with a shared secret", action: .openRadiusClients)
            : ChecklistItem(id: "radius", title: "RADIUS client added", state: .done,
                            detail: o.radiusClients.joined(separator: ", "))
    }

    static func lastEnrollment(_ o: ConnectObservations) -> ChecklistItem {
        guard let line = o.enrollment.first(where: { ["SCEP", "EST"].contains($0.component) && $0.text.contains(" -> ") }) else {
            return ChecklistItem(id: "request", title: "Last SCEP/EST request", state: .waiting, detail: "None yet")
        }
        let ok = line.text.range(of: " -> OK") != nil || line.text.range(of: " -> RA") != nil
        let head = line.text.components(separatedBy: " -> ").first ?? line.text
        var detail = "\(line.component) \(head)"
        if !ok, let outcome = line.text.components(separatedBy: " -> ").dropFirst().first {
            detail += ": " + (outcome.components(separatedBy: " from ").first ?? outcome)
        }
        return ChecklistItem(id: "request", title: "Last SCEP/EST request", state: ok ? .done : .problem, date: line.date, detail: detail)
    }

    static func lastEvent(id: String, title: String, _ e: ActivityEvent?, none: String) -> ChecklistItem {
        guard let e else { return ChecklistItem(id: id, title: title, state: .waiting, detail: none) }
        return ChecklistItem(id: id, title: title, state: e.result == .success ? .done : .problem, date: e.date,
                             detail: e.result == .success ? "\(e.user) from \(e.from)" : "\(e.user) from \(e.from): \(e.detail)")
    }

    /// `LABSHEEP\PC$` → `PC$`
    static func accountPart(_ s: String) -> String {
        guard let bs = s.lastIndex(of: "\\") else { return s }
        return String(s[s.index(after: bs)...])
    }
}
