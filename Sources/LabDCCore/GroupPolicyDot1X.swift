import Foundation
import PKIKit
import Store
import SYSVOL
import X509

/// What the Group Policy page shows.
public struct GroupPolicySnapshot: Equatable, Sendable {
    /// The profiles as edited.
    public var draft: Dot1XProfileSet
    /// The profiles in the Default Domain Policy now.
    public var published: Dot1XProfileSet
    /// The Default Domain Policy's machine version (what `gpupdate` compares).
    public var version: Int
    public var trust: GroupPolicyDot1X.Trust?
    /// The Default Domain Policy's trusted roots (names).
    public var trustedRoots: [String]
    public var passwordPolicy: PasswordPolicy?
    /// What a profile can trust for another RADIUS server: the trusted roots, then the draft's
    /// certificates waiting for the next publish (`pending`).
    public var certificates: [Dot1XTrustCertificate]

    public init(draft: Dot1XProfileSet, published: Dot1XProfileSet, version: Int, trust: GroupPolicyDot1X.Trust?,
                trustedRoots: [String], passwordPolicy: PasswordPolicy?, certificates: [Dot1XTrustCertificate] = []) {
        self.draft = draft; self.published = published; self.version = version; self.trust = trust
        self.trustedRoots = trustedRoots; self.passwordPolicy = passwordPolicy; self.certificates = certificates
    }

    /// The trusted roots plus the draft's pending certificates.
    public var choosableCertificates: [Dot1XTrustCertificate] {
        certificates + draft.pendingRoots.compactMap { root -> Dot1XTrustCertificate? in
            guard !certificates.contains(where: { $0.thumbprint == root.thumbprint }),
                  var c = try? Dot1XTrustCertificate(der: Array(root.der), friendlyName: root.name) else { return nil }
            c.pending = true
            return c
        }
    }

    /// Overview ▸ Trust, one line per profile: "Staff → this DC (dc1.lab.sheep), LabDC Lab CA",
    /// "Guest → ClearPass (cppm.lab.sheep), self-signed".
    public var serverLines: [String] {
        let certs = choosableCertificates
        func line(_ label: String, _ server: Dot1XProfileSet.RadiusServer?, suiteB: Bool = false) -> String {
            guard let server else {
                return "\(label) → this DC" + (trust.map {
                    " (\($0.serverName)), " + (suiteB ? $0.suiteBName ?? "the 802.1X 192-bit CA" : $0.caName)
                } ?? "")
            }
            if let c = certs.first(where: { $0.thumbprint == server.trustedRoot }) {
                let more = server.alsoTrusted.count
                return "\(label) → \(c.describe(serverNames: server.serverNames))"
                    + (more == 0 ? "" : " (+\(more) more trusted certificate\(more == 1 ? "" : "s"))")
            }
            return "\(label) → \(server.serverNames.joined(separator: "; ")), certificate \(server.trustedRoot) (not in the trusted roots)"
        }
        return draft.wireless.map { line($0.name, $0.server, suiteB: $0.security == .wpa3Suite192) } + (draft.wired.map { [line("Wired", $0.server)] } ?? [])
    }

    public var hasUnpublishedChanges: Bool { draft != published }

    /// How many things Publish would change (the badge on the Publish button, owner 2 Oct 2026):
    /// each Wi-Fi profile added, changed or removed, the wireless policy's name/description, the
    /// wired policy, and certificates waiting to join the trusted roots. Never 0 while
    /// `hasUnpublishedChanges`.
    public var changeCount: Int {
        guard hasUnpublishedChanges else { return 0 }
        var n = 0
        for w in draft.wireless where published.wireless(named: w.name) != w { n += 1 }
        n += published.wireless.filter { draft.wireless(named: $0.name) == nil }.count
        if draft.wireless.map(\.name) != published.wireless.map(\.name),
           Set(draft.wireless.map(\.name)) == Set(published.wireless.map(\.name)) { n += 1 }  // order only
        if !draft.wireless.isEmpty, !published.wireless.isEmpty,
           draft.name != published.name || draft.description != published.description { n += 1 }
        if draft.wired != published.wired { n += 1 }
        n += draft.pendingRoots.count
        return max(n, 1)
    }
    public var isPublished: Bool { !published.isEmpty }

    /// "Version 7 published", or "Not published". The Publish button says when Windows applies it (owner, 2 Oct 2026).
    public var statusLine: String {
        isPublished ? "Version \(version) published" : "Not published"
    }

    /// Where one policy (wireless or wired) stands, GPMC-style: it exists or not.
    public enum PolicyState: Equatable, Sendable {
        /// No such policy, here or in Group Policy.
        case notSet
        /// Deleted here, still in Group Policy until Publish changes.
        case deletedNotPublished
        /// Here, not in Group Policy yet.
        case notPublished
        /// In Group Policy, changed here since.
        case changed
        case published

        /// "published", "changes not published yet", …
        public var words: String {
            switch self {
            case .notSet: "not set"
            case .deletedNotPublished: "deleted, PCs keep it until you publish"
            case .notPublished: "not published yet"
            case .changed: "changes not published yet"
            case .published: "published"
            }
        }
    }

    /// The wireless policy exists while it holds at least one profile.
    public var wirelessState: PolicyState {
        if draft.wireless.isEmpty { return published.wireless.isEmpty ? .notSet : .deletedNotPublished }
        if published.wireless.isEmpty { return .notPublished }
        return draft.wireless == published.wireless && draft.name == published.name
            && draft.description == published.description ? .published : .changed
    }

    public var wiredState: PolicyState {
        guard let wired = draft.wired else { return published.wired == nil ? .notSet : .deletedNotPublished }
        guard let old = published.wired else { return .notPublished }
        return wired == old ? .published : .changed
    }

    /// Group Policy ▸ Overview: "Wireless — policy “LabDC 802.1X”, 3 profiles, published".
    public var wirelessSummary: String {
        switch wirelessState {
        case .notSet, .deletedNotPublished: return "Wireless — \(wirelessState.words)"
        default:
            let n = draft.wireless.count
            return "Wireless — policy “\(draft.name)”, \(n) profile\(n == 1 ? "" : "s"), \(wirelessState.words)"
        }
    }

    /// Group Policy ▸ Overview: "Wired — policy “LabDC 802.1X”, 1 profile, published".
    public var wiredSummary: String {
        switch wiredState {
        case .notSet, .deletedNotPublished: return "Wired — \(wiredState.words)"
        default: return "Wired — policy “\(draft.wired?.name ?? "")”, 1 profile, \(wiredState.words)"
        }
    }

    /// "At least 7 characters · complexity · 24 remembered" / "Any password (lab)".
    public static func describe(_ p: PasswordPolicy) -> String {
        if p.relaxed { return "Any password (lab)" }
        return ["At least \(p.minLength) characters", p.complexity ? "complexity" : "no complexity",
                p.historyLength == 0 ? "no history" : "\(p.historyLength) remembered"].joined(separator: " · ")
    }
}

/// Group Policy ▸ Wi-Fi profiles / Wired (1 Oct 2026): the 802.1X profiles the app and
/// `labdc gpo wifi|wired` publish into the Default Domain Policy.
///
/// The choices being edited (the draft) live in `<data>/group-policy-8021x.json`, so a backup
/// carries them and the app and the CLI see the same list. Without that file the draft is what is
/// published now: a domain that published one profile from the old RADIUS ▸ 802.1X tab gets that
/// profile as the first entry of the list, and publishing again updates the same policy object
/// (same CN, same GUID) in place.
public enum GroupPolicyDot1X {
    public static func draftURL(_ data: DataDirectory) -> URL {
        data.url.appendingPathComponent("group-policy-8021x.json")
    }

    /// The saved draft, or nil when there is none (then the published set is the draft).
    public static func savedDraft(_ data: DataDirectory) -> Dot1XProfileSet? {
        guard let bytes = try? Data(contentsOf: draftURL(data)) else { return nil }
        return try? JSONDecoder().decode(Dot1XProfileSet.self, from: bytes)
    }

    public static func saveDraft(_ set: Dot1XProfileSet, _ data: DataDirectory) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            try encoder.encode(set).write(to: draftURL(data), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: draftURL(data).path)
        } catch {
            throw CLIError.failure("cannot save \(draftURL(data).path): \(error.localizedDescription)")
        }
    }

    /// The draft: the saved one, else what is published.
    public static func draft(_ data: DataDirectory, editor: GroupPolicyEditor) async throws -> Dot1XProfileSet {
        if let saved = savedDraft(data) { return saved }
        return try await editor.publishedDot1XProfiles().set
    }

    /// The trust every profile carries (filled in at publish time).
    public struct Trust: Equatable, Sendable {
        /// The DC's DNS name: the server name Windows checks.
        public var serverName: String
        /// The lab root (current CA): its common name and SHA-1 thumbprint.
        public var caName: String
        public var caThumbprint: String
        /// The 802.1X 192-bit (P-384) root, when it exists.
        public var suiteBName: String?
        public var suiteBThumbprint: String?
        /// During a root migration that keeps the old root: its thumbprint (trusted as well).
        public var previousRootThumbprint: String?
        /// During a migration away from a P-384 root that served 192-bit itself: its thumbprint,
        /// still trusted by the 192-bit profiles (their client certificates came from it).
        public var previousSuiteBThumbprint: String?
    }

    public static func trust(store: DirectoryStore, pki: LabPKI) async throws -> Trust {
        let dc = try await store.domainInfo().dcDNSName
        let ca = try await pki.currentAuthority()
        let der = try ca.der()
        var trust = Trust(serverName: dc, caName: ServerController.commonName(ca.certificate.subject) ?? ca.name,
                          caThumbprint: CertificateBlob.thumbprint(der))
        if let suiteB = try await pki.suiteBAuthority() {
            trust.suiteBName = ServerController.commonName(suiteB.certificate.subject) ?? suiteB.name
            trust.suiteBThumbprint = CertificateBlob.thumbprint(try suiteB.der())
        }
        if let state = try? await CAService(pki: pki, store: store).migrationState(),
           let old = try? await pki.authority(named: state.from), let oldDER = try? old.der() {
            let t = CertificateBlob.thumbprint(oldDER)
            if t != trust.caThumbprint { trust.previousRootThumbprint = t }
            if old.keyType == .p384, t != trust.suiteBThumbprint { trust.previousSuiteBThumbprint = t }
        }
        return trust
    }

    public struct PublishReport: Sendable {
        public var version: GPOVersion
        /// Log lines for what else changed (the 192-bit CA created, templates switched on).
        public var events: [String]
        public var summary: String
        /// What was published: the set given, with each other server's issuing roots in
        /// `alsoTrusted` (save it as the draft).
        public var set: Dot1XProfileSet
    }

    /// Publishes `set` into the Default Domain Policy in one go (one version bump for the 802.1X
    /// objects): every Wi-Fi network in one `<WLANPolicy>`, the wired profile (if any) in one
    /// `<LANPolicy>`. The server-name check is this DC's FQDN (what the RADIUS server certificate
    /// is issued for); EAP-TLS profiles offer only client certificates of the matching CA.
    /// A WPA3-Enterprise 192-bit network uses the 802.1X 192-bit (P-384) CA — created on first
    /// use, put into the policy's trusted roots, the Computer192 / User192 templates switched on
    /// with auto-enrollment. Wired 802.1X has no 192-bit mode: it keeps the lab root. During a
    /// root migration that keeps the old root trusted, the profiles trust both roots.
    /// Another RADIUS server: its names and only its certificate as `TrustedRootCA` (the
    /// client-certificate filter keeps the lab CA: the clients' certificates still come from it).
    /// Windows compares `TrustedRootCA` with the root of the server's chain, not with the server
    /// certificate itself: a profile trusting ClearPass's own certificate (issued by a CA) failed
    /// with unknown_ca while the manual "Connect" prompt worked (1 Oct 2026). The roots that
    /// issued the trusted certificates are named as well, found among `pool` by issuer name.
    static func otherServer(_ server: Dot1XProfileSet.RadiusServer?, _ p: inout Dot1XPolicy, pool: [[UInt8]] = []) {
        guard let server else { return }
        p.serverNames = server.serverNames
        p.requireCryptoBinding = false
        p.caThumbprint = server.trustedRoot
        var also = server.alsoTrusted
        for t in [server.trustedRoot] + server.alsoTrusted {
            for root in issuingChain(of: t, pool: pool) where root != server.trustedRoot && !also.contains(root) { also.append(root) }
        }
        p.additionalTrustedRoots = also
    }

    static func withIssuingRoots(_ set: Dot1XProfileSet, pool: [[UInt8]]) -> Dot1XProfileSet {
        func fix(_ server: inout Dot1XProfileSet.RadiusServer?) {
            guard var s = server else { return }
            for t in [s.trustedRoot] + s.alsoTrusted {
                for root in issuingChain(of: t, pool: pool) where root != s.trustedRoot && !s.alsoTrusted.contains(root) {
                    s.alsoTrusted.append(root)
                }
            }
            server = s
        }
        var out = set
        for i in out.wireless.indices { fix(&out.wireless[i].server) }
        if var w = out.wired { fix(&w.server); out.wired = w }
        return out
    }

    /// The thumbprints of the CAs above certificate `thumbprint` (nearest first, up to its
    /// self-signed root), as far as `pool` holds them; empty for a self-signed certificate.
    static func issuingChain(of thumbprint: String, pool: [[UInt8]]) -> [String] {
        let certs = pool.compactMap { der in (try? Certificate(derEncoded: der)).map { (CertificateBlob.thumbprint(der), $0) } }
        guard var current = certs.first(where: { $0.0 == thumbprint }) else { return [] }
        var out: [String] = []
        // A renewed CA can keep its name with a new key: of the CAs named like the issuer, the one
        // whose key identifier matches the certificate's authority key identifier is the issuer;
        // without identifiers to compare, every same-named CA is named (Windows matches any of
        // them), so the right one is never left out.
        func keyID(_ c: Certificate) -> ArraySlice<UInt8>? {
            ((try? c.extensions.subjectKeyIdentifier) ?? nil)?.keyIdentifier
        }
        func authorityKeyID(_ c: Certificate) -> ArraySlice<UInt8>? {
            ((try? c.extensions.authorityKeyIdentifier) ?? nil)?.keyIdentifier
        }
        while current.1.issuer != current.1.subject, out.count < 5 {
            let named = certs.filter { $0.1.subject == current.1.issuer && $0.0 != current.0 && !out.contains($0.0) }
            let aki = authorityKeyID(current.1)
            let exact = aki.map { a in named.filter { keyID($0.1) == a } } ?? []
            let issuers = exact.isEmpty ? named : exact
            guard let up = issuers.first else { break }
            out.append(contentsOf: issuers.map(\.0))
            current = up
        }
        return out
    }

    /// Refuses to remove a trusted root that a profile (in the draft or published) trusts for
    /// another RADIUS server: Windows would then reject that server.
    public static func checkRootUnused(_ thumbprint: String, data: DataDirectory, editor: GroupPolicyEditor) async throws {
        let published = try await editor.publishedDot1XProfiles().set
        let draft = savedDraft(data) ?? published
        var users = draft.profiles(trusting: thumbprint)
        for u in published.profiles(trusting: thumbprint) where !users.contains(u) { users.append(u + " (published)") }
        guard !users.isEmpty else { return }
        throw CLIError.failure("this certificate is the RADIUS server certificate trusted by "
            + users.joined(separator: ", ")
            + "; choose another certificate (or This DC) for them on the Group Policy page and publish first")
    }

    public static func publish(_ set: Dot1XProfileSet, store: DirectoryStore, pki: LabPKI,
                               editor: GroupPolicyEditor) async throws -> PublishReport {
        try set.validate()
        var events: [String] = []
        // Another RADIUS server's certificates added with "Add a certificate…" join the trusted
        // roots first; every other-server profile must trust one of them.
        for root in set.pendingRoots {
            let c = try Dot1XTrustCertificate(der: Array(root.der), friendlyName: root.name)
            let change = try await editor.addTrustedRoot(CACertificateInfo(der: c.der, commonName: c.name, subject: c.name),
                                                         friendlyName: c.name)
            if change.edit.changed { events.append("trusted root \(c.thumbprint) \(c.name) added for 802.1X") }
        }
        let roots = try await editor.trustedRoots()
        var pool = roots.map(\.der)
        if let ca = try? await pki.currentAuthority(), let der = try? ca.der() { pool.append(der) }
        let known = Set(pool.map(CertificateBlob.thumbprint))
        func checkServer(_ server: Dot1XProfileSet.RadiusServer?, _ label: String, p384: Bool) throws {
            guard let server else { return }
            for t in server.alsoTrusted where !known.contains(t) {
                throw CLIError.failure("\(label) trusts certificate \(t), which is not in the Default Domain Policy's trusted roots (Certificates ▸ Trusted Roots)")
            }
            guard known.contains(server.trustedRoot),
                  let rootDER = pool.first(where: { CertificateBlob.thumbprint($0) == server.trustedRoot }) else {
                throw CLIError.failure("\(label) trusts certificate \(server.trustedRoot), which is not in the Default Domain Policy's trusted roots (Certificates ▸ Trusted Roots)")
            }
            if p384, (try? Dot1XTrustCertificate(der: rootDER))?.p384 != true {
                throw CLIError.failure("\(label) is WPA3-Enterprise 192-bit: its RADIUS server certificate must be ECDSA P-384")
            }
        }
        for w in set.wireless { try checkServer(w.server, "Wi-Fi profile \(w.name)", p384: w.security == .wpa3Suite192) }
        try checkServer(set.wired?.server, "the wired profile", p384: false)
        // The roots above another server's own certificate become part of the profile (and of
        // the saved draft, so the page does not show it changed after every publish).
        let set = withIssuingRoots(set, pool: pool)
        let trust = try await trust(store: store, pki: pki)
        let previous = trust.previousRootThumbprint.map { [$0] } ?? []
        func policy(ssid: String, method: Dot1XPolicy.Method, authMode: Dot1XPolicy.AuthMode,
                    security: Dot1XPolicy.Security = .wpa2, auto: Bool = true) -> Dot1XPolicy {
            var p = Dot1XPolicy(name: Dot1XPolicy.defaultName, ssid: ssid, authMode: authMode, caThumbprint: trust.caThumbprint,
                        method: method, security: security, serverNames: [trust.serverName],
                        clientIssuerThumbprint: method == .tls ? trust.caThumbprint : nil,
                        additionalTrustedRoots: previous, connectAutomatically: auto)
            // The client-certificate filter keeps both lab roots even when `otherServer`
            // replaces the server trust.
            p.additionalClientIssuers = previous
            return p
        }
        var suiteB: String?
        if set.wireless.contains(where: { $0.security == .wpa3Suite192 }) {
            let service = try await CAService.open(pki: pki, store: store)
            if try await service.ensureSuiteBAuthority() {
                events.append("802.1X 192-bit CA (P-384) created for a 192-bit Wi-Fi profile")
            }
            // The 802.1X 192-bit CA, or the current CA itself when it is P-384.
            guard let ca = try await pki.suiteBAuthority() else { throw CLIError.failure("no P-384 CA for the 192-bit profile") }
            let der = try ca.der()
            suiteB = CertificateBlob.thumbprint(der)
            let cn = ServerController.commonName(ca.certificate.subject)
            _ = try await editor.addTrustedRoot(CACertificateInfo(der: der, commonName: cn, subject: ca.certificate.subject.description),
                                                friendlyName: cn)
            for name in ["Computer192", "User192"] {
                guard var t = try? await service.template(named: name), !t.autoEnroll || !t.enabled else { continue }
                t.autoEnroll = true; t.enabled = true
                try await service.saveTemplate(t)
                events.append("template \(name) auto-enrollment on (802.1X 192-bit profile)")
            }
        }
        let wireless = set.wireless.map { w -> Dot1XPolicy in
            var p = policy(ssid: w.ssids.first ?? w.name, method: w.method, authMode: w.signInAs, security: w.security,
                           auto: w.connectAutomatically)
            p.name = set.name
            p.profileName = w.name
            p.additionalSSIDs = Array(w.ssids.dropFirst())
            p.connectHidden = w.connectHidden
            p.autoSwitch = w.autoSwitch
            p.singleSignOn = w.singleSignOn
            p.cacheUserData = w.cacheUserData
            if w.security == .wpa3Suite192, let suiteB {
                p.caThumbprint = suiteB
                p.clientIssuerThumbprint = suiteB
                p.additionalTrustedRoots = trust.previousSuiteBThumbprint.map { [$0] } ?? []
                p.additionalClientIssuers = p.additionalTrustedRoots
            }
            otherServer(w.server, &p, pool: pool)
            w.validation.apply(to: &p)
            return p
        }
        let wired = set.wired.map { w -> Dot1XPolicy in
            var p = policy(ssid: "", method: w.method, authMode: w.signInAs)
            p.name = w.name
            p.policyDescription = w.description
            otherServer(w.server, &p, pool: pool)
            w.validation.apply(to: &p)
            return p
        }
        let version = try await editor.publishDot1X(wireless: wireless, wired: wired,
                                                    wirelessName: set.name, wirelessDescription: set.description)
        // Each profile with the server it checks (1 Oct 2026: the log said dc1 for a ClearPass profile).
        func server(_ s: Dot1XProfileSet.RadiusServer?) -> String {
            s.map { $0.serverNames.isEmpty ? "any server name" : $0.serverNames.joined(separator: "; ") } ?? trust.serverName
        }
        let parts = set.wireless.map { "Wi-Fi \($0.name) → \(server($0.server))" }
            + (set.wired.map { ["wired (\($0.method.shortTitle)) → \(server($0.server))"] } ?? [])
        let summary = (parts.isEmpty ? "no 802.1X profiles" : parts.joined(separator: " + ")) + ", version \(version.machine)"
        return PublishReport(version: version, events: events, summary: summary, set: set)
    }
}
