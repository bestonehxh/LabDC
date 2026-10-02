import CertConvert
import Foundation
import Observation
import PKIKit
import Store
import SYSVOL
import X509

/// UI-3: the Certificates page's model of the PKI — CAs, CRLs, issued certificates, templates,
/// the Default Domain Policy's trusted roots and autoenrollment, SCEP/EST challenges — with every
/// change going through the same PKIKit / SYSVOL calls as `labdc ca|gpo|scep …` (no second
/// code path). Mutations log a line like the CLI prints (component `PKI` / `GPO`) and reload the
/// state; `follow(_:)` reloads on the runtime's PKI/GPO/SCEP/EST/WSTEP lines too (a device that
/// enrolled, the hourly CRL, a CLI command against the same data folder that logs through serve).
@MainActor @Observable
public final class PKIEditor {
    public let data: DataDirectory
    @ObservationIgnored public let pki: LabPKI
    @ObservationIgnored public let store: DirectoryStore
    @ObservationIgnored public let service: CAService
    @ObservationIgnored let log: ServeLog?
    @ObservationIgnored let clock: @Sendable () -> Date
    /// Called after "Use as current" so the running server reissues the DC certificate (the app:
    /// `ServerController.restart`). Without it the next start does.
    @ObservationIgnored public var reissueDCCertificate: (@MainActor () async -> Void)?

    public var endpoints: PKIEndpoints
    public private(set) var domain: DomainInfo?
    public private(set) var authorities: [CAInfo] = []
    public private(set) var crls: [String: CRLStatus] = [:]
    public private(set) var issued: [IssuedCertificate] = []
    public private(set) var templates: [CertificateTemplate] = []
    public private(set) var trustedRoots: [TrustedRootInfo] = []
    /// `versionNumber` of the Default Domain Policy (user << 16 | machine), nil when it is missing.
    public private(set) var gpoVersion: UInt32?
    public private(set) var autoEnrollment = AutoEnrollmentStatus()
    public private(set) var challenges: [PKIChallengeRow] = []
    public private(set) var scepRA: (subject: String, notAfter: Date)?
    public private(set) var directorySync: DirectorySyncStatus?
    public private(set) var groups: [PKIDirectoryGroup] = []
    /// Every root: issuing, trusted, retired, active certificates (CA page ▸ Roots).
    public private(set) var roots: [CAService.RootStatus] = []
    /// A root change that keeps the old root trusted (`from` → `to`), until it is retired.
    public private(set) var migration: RootMigrationState?
    /// Bumped after every reload (views and tests wait on it).
    public private(set) var generation = 0
    /// The last reload problem (the page shows it; mutations throw instead).
    public private(set) var loadError: String?

    @ObservationIgnored private var followTask: Task<Void, Never>?
    @ObservationIgnored private var reloadTask: Task<Void, Never>?

    public init(data: DataDirectory, pki: LabPKI, store: DirectoryStore, service: CAService, endpoints: PKIEndpoints,
                log: ServeLog? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.data = data
        self.pki = pki
        self.store = store
        self.service = service
        self.endpoints = endpoints
        self.log = log
        self.clock = clock
    }

    /// Opens the PKI of a data folder like the offline CLI commands do (the store must be
    /// provisioned; the lab CA exists once `serve` or the app has started once).
    public static func open(data: DataDirectory, endpoints: PKIEndpoints? = nil, log: ServeLog? = nil) async throws -> PKIEditor {
        let pki: LabPKI
        do { pki = try await LabPKI.open(directory: data.pkiURL) } catch {
            throw CLIError.failure("PKI in \(data.pkiURL.path): \(error)")
        }
        let store = try data.openExistingStore()
        let info = try await store.requireInfo()
        let service = try await CAService.open(pki: pki, store: store)
        let editor = PKIEditor(data: data, pki: pki, store: store, service: service,
                               endpoints: endpoints ?? PKIEndpoints(dcDNSName: info.dcDNSName), log: log)
        await editor.reload()
        return editor
    }

    // MARK: Observation

    /// Reloads (debounced) whenever the runtime logs a line that may change the PKI state.
    public func follow(_ hub: LogHub) {
        if directorySync == nil { directorySync = DirectorySyncStatus.fromLog(hub.history()) }
        followTask?.cancel()
        let lines = hub.stream()
        followTask = Task { [weak self] in
            for await line in lines {
                guard let self else { return }
                if line.component == "PKI", let sync = DirectorySyncStatus.fromLog([line]) { self.directorySync = sync }
                if Self.touchesPKI(line) { self.scheduleReload() }
            }
        }
    }

    public func stopFollowing() {
        followTask?.cancel()
        followTask = nil
    }

    nonisolated public static func touchesPKI(_ line: LogLine) -> Bool {
        switch line.component {
        case "PKI", "GPO", "SCEP", "WSTEP": true
        case "EST": line.text.hasPrefix("simpleenroll") || line.text.hasPrefix("simplereenroll")
        default: false
        }
    }

    private func scheduleReload() {
        guard reloadTask == nil else { return }
        reloadTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(400))
            guard let self else { return }
            self.reloadTask = nil
            await self.reload()
        }
    }

    /// Re-reads everything (cheap: a few SQLite queries and two Registry.pol files).
    public func reload() async {
        var problems: [String] = []
        do {
            let info = try await store.domainInfo()
            domain = info
            let currentName = await pki.currentCAName
            let all = try await pki.authorities()
            authorities = try all.map { try CAInfo($0, current: $0.name == currentName) }
            var crls: [String: CRLStatus] = [:]
            for ca in authorities {
                guard let row = try await store.pkiCRL(caName: ca.name) else { continue }
                let entries = (try? CertificateRevocationList(derEncoded: row.der).entries.count) ?? 0
                crls[ca.name] = CRLStatus(caName: ca.name, number: row.crlNumber, thisUpdate: row.thisUpdate,
                                          nextUpdate: row.nextUpdate, entries: entries,
                                          url: try await service.crlURL(caName: ca.name))
            }
            self.crls = crls
            issued = try await service.issuedCertificates().sorted { $0.issuedAt > $1.issuedAt }
            templates = try await service.templates()
            challenges = try await service.challenges().sorted { $0.createdAt > $1.createdAt }
            if let ra = try? await SCEPService.existingRA(pki: pki) {
                scepRA = (ra.certificate.subject.description, ra.certificate.notValidAfter)
            } else {
                scepRA = nil
            }
            groups = try await Self.loadGroups(store: store, info: info)
            roots = try await service.rootStatuses()
            migration = try await service.migrationState().map { RootMigrationState(from: $0.from, to: $0.to) }
        } catch {
            problems.append("\(error)")
        }
        do { try await reloadGroupPolicy() } catch { problems.append("Group Policy: \(error)") }
        loadError = problems.isEmpty ? nil : problems.joined(separator: "; ")
        generation += 1
    }

    private func reloadGroupPolicy() async throws {
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        let ours = Dictionary(authorities.map { ($0.thumbprint, $0.name) }, uniquingKeysWith: { a, _ in a })
        do {
            let state = try await editor.state(.defaultDomainPolicy)
            gpoVersion = state.containerVersion.raw
        } catch {
            gpoVersion = nil
            trustedRoots = []
            autoEnrollment = AutoEnrollmentStatus(cepURL: endpoints.cepURL)
            throw error
        }
        let published = Set(try await CertificationAuthorityDirectory.published(store: store).map { CertificateBlob.thumbprint($0.der) })
        trustedRoots = try await editor.trustedRoots().map { root in
            let cert = try? Certificate(derEncoded: root.der)
            return TrustedRootInfo(thumbprint: root.thumbprint, subject: cert?.subject.description ?? "?",
                                   commonName: cert.flatMap { ServerController.commonName($0.subject) },
                                   notAfter: cert?.notValidAfter, friendlyName: root.friendlyName,
                                   publishedInConfiguration: published.contains(root.thumbprint),
                                   labDCCA: ours[root.thumbprint], der: root.der)
        }
        let machine = try await editor.autoEnrollment()
        let user = try await editor.autoEnrollment(scope: .user)
        var status = AutoEnrollmentStatus(cepURL: endpoints.cepURL)
        switch machine {
        case .notConfigured: break
        case .disabled: status.configured = true
        case let .enabled(_, urls):
            status.configured = true
            status.enabled = true
            if let url = urls.first { status.cepURL = url }
        }
        if case .enabled = user { status.userEnabled = true }
        status.policyID = try await editor.autoEnrollmentPolicyID()
        if status.policyID == nil { status.policyID = try? await AutoEnrollmentSettings.defaultPolicyID(store: store) }
        autoEnrollment = status
    }

    static func loadGroups(store: DirectoryStore, info: DomainInfo) async throws -> [PKIDirectoryGroup] {
        let filter = FilterAST.equality(attribute: "objectClass", value: Array("group".utf8))
        return try await store.search(base: info.domainDN, scope: .subtree, filter: filter, attrs: ["sAMAccountName", "objectSid"])
            .compactMap { e in
                guard let sid = e.sid?.description else { return nil }
                return PKIDirectoryGroup(sid: sid, name: e.samAccountName ?? e.dn.description)
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    // MARK: Derived

    public var currentCA: CAInfo? { authorities.first(where: \.isCurrent) }
    public var otherCAs: [CAInfo] { authorities.filter { !$0.isCurrent } }

    /// SCEP/EST facts for the current CA (nil before the lab CA exists).
    public var deviceEnrollment: DeviceEnrollmentInfo? {
        guard let ca = currentCA else { return nil }
        let labels = templates.filter { $0.enabled && !$0.manualApproval && $0.sanPolicy == .fromRequest }.map(\.name)
        return DeviceEnrollmentInfo(scepURL: endpoints.scepURL, scepAlternateURLs: endpoints.scepAlternateURLs,
                                    estURL: endpoints.estURL, estLabels: labels, caName: ca.name, caSHA256: ca.sha256,
                                    caSHA1: ca.sha1, caMD5: ca.md5, raSubject: scepRA?.subject, raValidUntil: scepRA?.notAfter)
    }

    /// Templates a challenge can name (enabled, no manual approval).
    public var challengeTemplates: [String] {
        templates.filter { $0.enabled && !$0.manualApproval }.map(\.name)
    }

    /// The group name for a SID (the template list shows names, not SIDs).
    public func groupName(_ sid: String) -> String {
        groups.first { $0.sid == sid }?.name ?? sid
    }

    // MARK: CA (`labdc ca create | use | crl | export`)

    /// `ca create`: a new CA (not current), its first CRL, then the Configuration NC sync.
    @discardableResult
    public func createCA(name: String, commonName: String?, keyType: CAKeyType, years: Int) async throws -> CAInfo {
        let ca = try await pki.createCA(name: name, commonName: commonName, keyType: keyType, years: years)
        log?.event("PKI", "created CA \(ca.name): \(ca.keyType.displayName), \(ca.certificate.subject), valid until \(PKIText.day(ca.certificate.notValidAfter)) (app)")
        let crl = try await service.generateCRL(caName: ca.name)
        log?.event("PKI", "CRL #\(crl.crlNumber ?? 0) of CA \(ca.name) published at \(try await service.crlURL(caName: ca.name))")
        await publishToDirectory()
        await reload()
        return try CAInfo(ca, current: false)
    }

    /// `ca use`: makes `name` issue from now on, syncs the Configuration NC, then asks the running
    /// server to reissue the DC certificate (`reissueDCCertificate`).
    public func useCA(name: String) async throws {
        try await pki.useCA(name: name)
        let ca = try await pki.currentAuthority()
        log?.event("PKI", "current CA is now \(ca.name) (\(ca.certificate.subject)) (app)")
        await publishToDirectory()
        await reload()
        if let reissueDCCertificate { await reissueDCCertificate() }
    }

    /// "Change the lab CA key…" (`labdc ca migrate --key … [--now]`): a new root of `keyType`
    /// issues from now on; the DC certificate is reissued and the server restarts to serve it.
    /// Without `keepOldTrusted` the old root is retired in the same step (see `LabCASwitch`).
    @discardableResult
    public func changeLabCAKey(to keyType: CAKeyType, keepOldTrusted: Bool = false) async throws -> LabCASwitch.Report {
        let log = self.log
        let report = try await LabCASwitch.change(to: keyType, keepOldTrusted: keepOldTrusted, data: data, pki: pki, store: store,
                                                  service: service) { log?.event("PKI", $0 + " (app)") }
        await reload()
        if let reissueDCCertificate { await reissueDCCertificate() }
        return report
    }

    /// "Retire the old root…": no longer trusted (GPO, NTAuth, 802.1X profiles, EAP-TLS).
    /// Returns how many certificates it issued are still unexpired.
    @discardableResult
    public func retireCA(name: String) async throws -> Int {
        let log = self.log
        let active = try await LabCASwitch.retire(name: name, data: data, pki: pki, store: store, service: service) {
            log?.event("PKI", $0 + " (app)")
        }
        await reload()
        return active.count
    }

    /// Certificates `caName` issued that are neither revoked nor expired (the Retire confirmation).
    public func activeCertificates(caName: String) -> [IssuedCertificate] {
        let now = clock()
        return issued.filter { $0.caName == caName && !$0.revoked && $0.notAfter > now }
    }

    /// `ca crl`: a new CRL now.
    @discardableResult
    public func regenerateCRL(caName: String) async throws -> CRLStatus {
        let crl = try await service.generateCRL(caName: caName)
        let url = try await service.crlURL(caName: caName)
        log?.event("PKI", "CRL #\(crl.crlNumber ?? 0) of CA \(caName) regenerated: \(crl.entries.count) entries, \(url) (app)")
        await reload()
        return crls[caName] ?? CRLStatus(caName: caName, number: crl.crlNumber ?? 0, thisUpdate: crl.thisUpdate,
                                         nextUpdate: crl.nextUpdate ?? crl.thisUpdate, entries: crl.entries.count, url: url)
    }

    /// Export CA ▸ .pem / .cer / .mobileconfig (default: the current CA).
    public func exportCA(_ format: CAExportFormat, caName: String? = nil) async throws -> Data {
        let ca: CertificateAuthority
        if let caName { ca = try await pki.authority(named: caName) } else { ca = try await pki.currentAuthority() }
        let info = try CAInfo(ca, current: false)
        switch format {
        case .pem: return Data(info.pem.utf8)
        case .der: return Data(info.der)
        case .mobileconfig:
            return try AppleConfigurationProfile.trustedRoot(der: info.der, displayName: info.title,
                                                             organization: domain.map { "LabDC \($0.dnsDomain)" })
        }
    }

    /// Sign a CSR ▸ "Save root CA" (30 Sep 2026): the self-signed root the signing CA chains to
    /// among the CAs held here — the signing CA itself when it is a root, never an intermediate.
    public func exportRootCA(_ format: CAExportFormat, caName: String) async throws -> Data {
        let signing = try await pki.authority(named: caName)
        let root = try Self.root(of: signing, among: try await pki.authorities(), certificate: \.certificate)
        return try await exportCA(format, caName: root.name)
    }

    /// Walks issuer → subject (matching the AKI to the parent's SKI when both are present) to a
    /// self-signed certificate; throws when the chain leaves the CAs held here.
    static func root<T>(of start: T, among all: [T], certificate: (T) -> Certificate) throws -> T {
        var current = start
        for _ in 0..<8 {
            let cert = certificate(current)
            if cert.issuer == cert.subject { return current }
            let aki = (try? cert.extensions.authorityKeyIdentifier?.keyIdentifier).flatMap { $0.map(Array.init) }
            guard let parent = all.first(where: { candidate in
                let c = certificate(candidate)
                guard c.subject == cert.issuer, c != cert else { return false }
                guard let aki, let ski = (try? c.extensions.subjectKeyIdentifier?.keyIdentifier).map(Array.init) else { return true }
                return aki == ski
            }) else {
                throw CLIError.failure("the root CA above \(cert.issuer) is not held here; export it from where it lives")
            }
            current = parent
        }
        throw CLIError.failure("the CA chain of \(certificate(start).subject) is too long")
    }

    // MARK: Issued (`ca issued | revoke`)

    public func revoke(serial: String, reason: RevocationReason) async throws {
        let row = try await service.revoke(serial: serial, reason: reason)
        let crl = try await service.currentCRL(caName: row.caName)
        log?.event("PKI", "revoked \(row.serial) (\(row.subject), template \(row.templateName)) reason \(reason.cliName); "
                   + "CRL #\(crl.crlNumber ?? 0) of CA \(row.caName) regenerated (app)")
        await reload()
    }

    public enum IssuedExport: String, CaseIterable, Sendable {
        case pem, der, p7b, chainPEM
        public var fileExtension: String {
            switch self {
            case .pem: "pem"
            case .der: "cer"
            case .p7b: "p7b"
            case .chainPEM: "pem"
            }
        }
    }

    /// Export ▸ PEM / DER / P7B (leaf + CA) / chain (PEM, leaf + CA).
    public func export(_ row: IssuedCertificate, as format: IssuedExport) async throws -> Data {
        let leaf = try CertificateItem(der: row.der)
        switch format {
        case .pem: return Data(leaf.pem.utf8)
        case .der: return Data(row.der)
        case .p7b, .chainPEM:
            let ca = try CertificateItem(der: try await pki.authority(named: row.caName).der())
            return format == .p7b ? Data(PKCS7.write(certificates: [leaf.der, ca.der])) : Data((leaf.pem + ca.pem).utf8)
        }
    }

    // MARK: Sign CSR (`ca sign`)

    /// The dry run: every check `sign` makes, nothing issued.
    public func review(_ request: SignRequest) async throws -> CSRReview {
        try await service.review(request)
    }

    public func sign(_ request: SignRequest) async throws -> SignResult {
        let result = try await service.sign(request)
        log?.event("PKI", "issued \(result.serial) from CA \(result.caName), template \(result.review.template.name), "
                   + "requester \(result.review.requester.name) (\(result.certificate.subject)) (app)")
        await reload()
        return result
    }

    // MARK: Templates (PK-1 `saveTemplate`, PK-5 sync)

    public func saveTemplate(_ template: CertificateTemplate) async throws {
        try await service.saveTemplate(template)
        log?.event("PKI", "template \(template.name) saved (\(template.enabled ? "enabled" : "disabled"), \(template.validityDays) days) (app)")
        if let warning = template.esc1Warning() { log?.warning("PKI", warning) }
        await publishToDirectory()
        await reload()
    }

    /// Creates a custom template from the editor's draft: a fresh OID from the domain's arc,
    /// never `built in`, and a unique name. `saveTemplate`'s publishing follows in the caller.
    public func createTemplate(_ template: CertificateTemplate) async throws {
        var t = template
        let name = t.name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, name.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" }) else {
            throw CLIError.failure("the template name needs ASCII letters, digits or hyphens (no spaces)")
        }
        t.name = name
        if (try? await service.template(named: name)) != nil {
            throw CLIError.failure("a template named \(name) already exists")
        }
        t.oid = try await service.newTemplateOID()
        t.builtIn = false
        try await service.saveTemplate(t)
        log?.event("PKI", "template \(name) created (custom, \(t.validityDays) days) (app)")
        if let warning = t.esc1Warning() { log?.warning("PKI", warning) }
        await publishToDirectory()
        await reload()
    }

    public func setTemplate(_ name: String, enabled: Bool) async throws {
        var t = try await service.template(named: name)
        guard t.enabled != enabled else { return }
        t.enabled = enabled
        try await saveTemplate(t)
    }

    /// PK-5's full Configuration NC sync (idempotent), recorded as the "Publish to directory" status.
    public func publishToDirectory() async {
        do {
            let report = try await service.publishToDirectory()
            let status = DirectorySyncStatus.from(report: report, at: clock())
            directorySync = status
            log?.event("PKI", status.text)
        } catch {
            directorySync = DirectorySyncStatus(date: clock(), text: "publishing the PKI objects in the Configuration NC failed: \(error)", ok: false)
            log?.warning("PKI", "publishing the PKI objects in the Configuration NC failed: \(error)")
        }
    }

    // MARK: Trusted roots (`gpo trusted-root add | add-ca | remove`)

    /// Adds the chosen certificates of a PEM / DER / P7B file (others are left out). Like GPMC's
    /// Trusted Root import any certificate goes (owner, 1 Oct 2026: ClearPass's own certificate
    /// issued by another CA); `pick` nil: the self-signed ones, else the server's certificate.
    @discardableResult
    public func addTrustedRoots(from bytes: [UInt8], fileName: String, friendlyName: String? = nil,
                                pick: Dot1XTrustCertificate.Pick? = nil) async throws -> TrustedRootAddReport {
        let file = try Dot1XTrustCertificate.candidates(bytes, fileName: fileName)
        let chosen = try Dot1XTrustCertificate.pick(pick, from: file.certificates, fileName: fileName)
        var report = TrustedRootAddReport()
        for c in file.certificates where !chosen.contains(where: { $0.thumbprint == c.thumbprint }) {
            report.skipped.append("\(c.subject) (\(c.role))")
        }
        for c in chosen {
            let item = try CertificateItem(der: c.der)
            let cn = ServerController.commonName(item.certificate.subject)
            let name = chosen.count == 1 ? friendlyName : friendlyName.map { "\($0) (\(cn ?? "certificate"))" }
            let changed = try await addTrustedRoot(der: c.der, subject: c.subject, commonName: cn, friendlyName: name)
            let label = cn ?? c.subject
            if changed { report.added.append(label) } else { report.alreadyPresent.append(label) }
        }
        await reload()
        return report
    }

    /// "Add current CA" (`gpo trusted-root add-ca`); the friendly name is the CA's CN.
    @discardableResult
    public func addCurrentCATrustedRoot() async throws -> Bool {
        let ca = try await pki.currentAuthority()
        let cn = ServerController.commonName(ca.certificate.subject)
        let changed = try await addTrustedRoot(der: try ca.der(), subject: ca.certificate.subject.description, commonName: cn,
                                               friendlyName: cn ?? ca.certificate.subject.description)
        await reload()
        return changed
    }

    private func addTrustedRoot(der: [UInt8], subject: String, commonName: String?, friendlyName: String?) async throws -> Bool {
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        let change = try await editor.addTrustedRoot(CACertificateInfo(der: der, commonName: commonName, subject: subject),
                                                     friendlyName: friendlyName)
        log?.event("GPO", "trusted root \(change.thumbprint) \(subject) in Default Domain Policy"
                   + (change.edit.changed ? " (version \(change.edit.previous.raw) -> \(change.edit.version.raw))" : " (already there)")
                   + " (app)")
        return change.edit.changed || !change.directoryObjects.isEmpty
    }

    public func removeTrustedRoot(thumbprint: String) async throws {
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        try await GroupPolicyDot1X.checkRootUnused(thumbprint, data: data, editor: editor)
        let change = try await editor.removeTrustedRoot(thumbprint: thumbprint)
        log?.event("GPO", "removed trusted root \(change.thumbprint) from Default Domain Policy"
                   + (change.edit.changed ? " (version \(change.edit.version.raw))" : " (was not in it)") + " (app)")
        await reload()
    }

    // MARK: Enrollment (`gpo autoenroll`, `scep challenge …`)

    /// The auto-enrollment switch: `gpo autoenroll --enable` (machine + user halves) / `--disable`.
    public func setAutoEnrollment(_ on: Bool) async throws {
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        if on {
            let id = try await AutoEnrollmentSettings.defaultPolicyID(store: store)
            let settings = AutoEnrollmentSettings(cepURL: endpoints.cepURL, policyID: id.uppercased())
            let edit = try await editor.enableAutoEnrollment(settings)
            _ = try await editor.enableAutoEnrollment(settings, scope: .user)
            log?.event("GPO", "autoenrollment enabled in Default Domain Policy (AEPolicy 7, CEP \(settings.cepURL), Kerberos, "
                       + "policy ID \(settings.policyID)), version \(edit.version.raw) (app)")
        } else {
            let edit = try await editor.disableAutoEnrollment()
            _ = try await editor.disableAutoEnrollment(scope: .user)
            log?.event("GPO", "autoenrollment disabled in Default Domain Policy (AEPolicy 0x8000), version \(edit.version.raw) (app)")
        }
        await reload()
    }

    /// `scep challenge new`: the text is returned once and never stored (only its SHA-256).
    public func newChallenge(device: String?, template: String, ttl: TimeInterval, reusable: Bool) async throws -> NewChallenge {
        let made = try await service.newChallenge(device: device, template: template, ttl: ttl, reusable: reusable)
        let c = made.challenge
        log?.event("SCEP", "challenge \(c.id) created: \(c.reusable ? "reusable" : "one-time"), template \(c.template), "
                   + "device \(c.device ?? "any"), expires \(PKIText.stamp(c.expiresAt)) (app)")
        await reload()
        return NewChallenge(row: c, secret: made.secret)
    }

    public func revokeChallenge(id: String) async throws {
        let row = try await service.revokeChallenge(id: id)
        log?.event("SCEP", "challenge \(row.id) revoked (template \(row.template), device \(row.device ?? "any")) (app)")
        await reload()
    }
}
