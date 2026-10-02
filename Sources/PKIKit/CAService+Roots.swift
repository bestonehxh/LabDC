import Foundation
import Store
import SYSVOL
import X509

/// Which roots are trusted, and the two 1 Oct 2026 root features:
///
/// - **RSA-only devices** (opt-in, "Allow RSA-only devices"): a separate RSA-3072 root
///   (`rsa-compat`) with an RSA RADIUS certificate and the `Computer-RSA` / `User-RSA` templates.
///   While switched off the root is not trusted (no NTAuth, no `Certification Authorities`, no
///   EAP-TLS client certificates chaining to it) and its templates are disabled.
/// - **Root migration** (`migrateCurrentCA`): a new root (P-384 by default) next to the current
///   one, made current at once; the old root stays trusted until it is retired (`retireCA`), and
///   keeps publishing its CRL afterwards. Keys are never deleted and never re-keyed in place.
///
/// The state lives in the `domain` table (`rsaCompatibilityKey`, `retiredCAsKey`,
/// `migrationKey`, `templateRevisionsKey`).
extension CAService {
    /// `on` while RSA-only devices are allowed.
    public static let rsaCompatibilityKey = "pki.rsaCompatibility"
    /// JSON array of retired CA names.
    public static let retiredCAsKey = "pki.retiredCAs"
    /// JSON `MigrationRecord` (`{"from": <old root>, "to": <new root>, …}`) while a migration's
    /// old root is still trusted (and while a migration that stopped half-way is unfinished).
    public static let migrationKey = "pki.migration"
    /// JSON `{<template>: <major revision>}` for templates bumped by a migration.
    public static let templateRevisionsKey = "pki.templateRevisions"
    /// The lab CA key chosen at provisioning (`p384` / `p256`), used when the lab CA is created.
    public static let labCAKeyTypeKey = "pki.labCAKeyType"
    /// The client templates of the RSA compatibility root.
    public static let rsaTemplateNames = ["Computer-RSA", "User-RSA"]

    // MARK: - Trust

    /// The CAs whose certificates are trusted: published to NTAuth and `Certification
    /// Authorities`, and accepted as issuers of EAP-TLS client certificates. Every CA except a
    /// retired one and the RSA compatibility root while RSA-only devices are not allowed. The
    /// current CA is always trusted (it issues the DC certificate), even if it was retired before
    /// `ca use` made it current again.
    public func trustedAuthorities() async throws -> [CertificateAuthority] {
        let retired = try await retiredCANames()
        let rsa = await rsaCompatibilityEnabled()
        let current = await pki.currentCAName.lowercased()
        return try await pki.authorities().filter { ca in
            if ca.name.lowercased() == current { return true }
            if retired.contains(ca.name.lowercased()) { return false }
            if ca.name.lowercased() == LabPKI.rsaCompatCAName { return rsa }
            return true
        }
    }

    /// What an EAP-TLS client certificate may chain to (DER), read per use by the RADIUS server.
    public func eapTrustedRootsDER() async throws -> [[UInt8]] {
        try await trustedAuthorities().map { try $0.der() }
    }

    // MARK: - RSA-only devices

    public func rsaCompatibilityEnabled() async -> Bool {
        ((try? await store.domainValue(forKey: Self.rsaCompatibilityKey)) ?? nil) == "on"
    }

    /// Switches "Allow RSA-only devices". On: the RSA compatibility root is created on first use
    /// (with its CRL), the `Computer-RSA` / `User-RSA` templates are enabled and the root is
    /// published (NTAuth, `Certification Authorities`). Off: the templates are disabled and the
    /// root leaves NTAuth / `Certification Authorities` (it is kept, with its CRL, so it can be
    /// switched on again without re-keying). Returns true when the root was created now.
    @discardableResult
    public func setRSACompatibility(_ on: Bool) async throws -> Bool {
        var created = false
        if on { created = try await ensureRSACompatAuthority(publish: false) }
        try await store.setDomainValue(on ? "on" : "off", forKey: Self.rsaCompatibilityKey)
        for name in Self.rsaTemplateNames {
            guard var t = try? await template(named: name), t.enabled != on else { continue }
            t.enabled = on
            try await store.savePKITemplate(t.row)
        }
        try await publishToDirectory()
        logger.info("RSA-only devices \(on ? "allowed" : "not allowed", privacy: .public)")
        return created
    }

    /// The RSA compatibility root, created on first use with its CRL. Returns true when created now.
    @discardableResult
    public func ensureRSACompatAuthority(publish: Bool = true) async throws -> Bool {
        if try await pki.hasRSACompatCA() { return false }
        let info = try await store.domainInfo()
        try await pki.ensureRSACompatCA(commonName: "LabDC RSA Compatibility CA (\(info.realm))")
        _ = try await generateCRL(caName: LabPKI.rsaCompatCAName)
        if publish { try await publishToDirectory() }
        logger.info("created the RSA compatibility CA (RSA-3072)")
        return true
    }

    // MARK: - Retired roots and migration

    public func retiredCANames() async throws -> Set<String> {
        guard let text = try await store.domainValue(forKey: Self.retiredCAsKey),
              let names = try? JSONDecoder().decode([String].self, from: Data(text.utf8)) else { return [] }
        return Set(names.map { $0.lowercased() })
    }

    /// `ca use`: makes `name` the current CA. A retired CA made current is no longer retired
    /// (it is trusted again: NTAuth, `Certification Authorities`, EAP-TLS). `publish`: sync the
    /// Configuration NC now (the CLI does it itself, to report what changed).
    public func useCA(name: String, publish: Bool = true) async throws {
        let ca = try await pki.authority(named: name)
        var retired = try await retiredCANames()
        if retired.remove(ca.name.lowercased()) != nil {
            try await store.setDomainValue(String(decoding: try JSONEncoder().encode(retired.sorted()), as: UTF8.self),
                                           forKey: Self.retiredCAsKey)
            logger.info("CA \(ca.name, privacy: .public) is no longer retired (made current)")
        }
        try await pki.useCA(name: ca.name)
        if publish { try await publishToDirectory() }
    }

    /// Whether issuance from `ca` is allowed at all: not from a retired root, and not from the
    /// RSA compatibility root while RSA-only devices are not allowed (both are untrusted, so
    /// their certificates would not work anyway).
    func checkMayIssue(from ca: CertificateAuthority) async throws {
        if ca.name.lowercased() == LabPKI.rsaCompatCAName, !(await rsaCompatibilityEnabled()) {
            throw IssuanceError.caNotTrusted(ca.name)
        }
        guard ca.name.lowercased() != (await pki.currentCAName).lowercased() else { return }
        if try await retiredCANames().contains(ca.name.lowercased()) { throw IssuanceError.caRetired(ca.name) }
    }

    /// The WPA3-Enterprise 192-bit client templates.
    public static let suiteBTemplateNames = ["Computer192", "User192"]

    /// What `migrationKey` holds. A migration is written down before anything changes and
    /// marked `committed` only once the new root issues, the templates are bumped and the
    /// directory is published, so a run that failed half-way is finished (never repeated
    /// differently) by running it again with the same key type.
    public struct MigrationRecord: Codable, Sendable, Equatable {
        /// The root being replaced.
        public var from: String
        /// The new root (nil while only the 192-bit preparation is written down).
        public var to: String?
        public var commonName: String?
        public var keyType: CAKeyType?
        /// WPA3-Enterprise 192-bit and this migration: `served` — the old root served it itself
        /// (P-384, no separate 802.1X 192-bit CA); `created` — and this migration moved it to
        /// the 802.1X 192-bit CA it created. nil: the old root did not serve 192-bit (or a
        /// record written before 2 Oct 2026).
        public var suiteB: String?
        /// The template major revisions this migration sets (Windows re-enrols their holders).
        public var reenroll: [String: Int]?
        /// The new root issues and the directory is published. nil (records written before
        /// 2 Oct 2026) counts as committed.
        public var committed: Bool?

        public init(from: String) { self.from = from }

        public static let suiteBServed = "served", suiteBCreated = "created"
        public var isCommitted: Bool { committed ?? true }
        /// The old root served 192-bit itself.
        public var oldRootServedSuiteB: Bool { suiteB != nil }
    }

    /// The migration as written down (in progress, or only prepared), if any.
    public func migrationRecord() async throws -> MigrationRecord? {
        guard let text = try await store.domainValue(forKey: Self.migrationKey), !text.isEmpty else { return nil }
        return try? JSONDecoder().decode(MigrationRecord.self, from: Data(text.utf8))
    }

    func saveMigrationRecord(_ record: MigrationRecord) async throws {
        let json = try JSONEncoder().encode(record)
        try await store.setDomainValue(String(decoding: json, as: UTF8.self), forKey: Self.migrationKey)
    }

    /// The migration in progress (its old root still trusted), if any.
    public func migrationState() async throws -> (from: String, to: String)? {
        guard let record = try await migrationRecord(), let to = record.to else { return nil }
        return (record.from, to)
    }

    /// Whether the current root serves WPA3-Enterprise 192-bit itself — or served it, for a
    /// migration that stopped half-way: once that migration created the 802.1X 192-bit CA,
    /// `LabPKI.mainCAServesSuiteB` is false, but the old root's 192-bit certificates still exist.
    public func currentRootServesSuiteB() async throws -> Bool {
        if try await pki.mainCAServesSuiteB() { return true }
        let current = await pki.currentCAName.lowercased()
        guard let record = try await migrationRecord(), record.oldRootServedSuiteB else { return false }
        return record.from.lowercased() == current || (record.to?.lowercased() == current && !record.isCommitted)
    }

    /// What `migrateCurrentCA` did.
    public struct RootMigration: Sendable {
        /// The former current root (still trusted until retired).
        public let from: CertificateAuthority
        /// The new root, now current.
        public let to: CertificateAuthority
        /// Auto-enrollment templates whose major version was bumped (Windows re-enrols holders).
        public let reenrollTemplates: [String]
        /// The 802.1X 192-bit CA (P-384) created by this migration: the old root was P-384 and
        /// served WPA3-Enterprise 192-bit itself, the new one is not P-384, and 192-bit was in use.
        public let suiteBCreated: CertificateAuthority?
        /// The old root served WPA3-Enterprise 192-bit itself.
        public let oldRootServedSuiteB: Bool
        /// This call finished a migration that had stopped half-way.
        public let resumed: Bool
    }

    /// Where `migrateCurrentCA` stands (fault injection in tests).
    enum MigrationStep: Sendable { case suiteBPrepared, created, switched, bumped }

    /// Moves issuing to a new root of `keyType` (default P-384 / SHA-384) without touching the
    /// current one: a new CA `<base><n>` (`lab` → `lab2`, CN `… 2`) is created with its CRL and
    /// made current; the old root stays trusted (NTAuth, `Certification Authorities`, EAP-TLS)
    /// until `retireCA`. The major version of every enabled auto-enrollment template issued by
    /// the current CA is bumped, so Windows re-enrols machine and user certificates from the new
    /// root at its next auto-enrollment pulse. The DC certificate is reissued by the caller
    /// (`LabPKI.ensureServerCertificate`, which follows the current CA).
    ///
    /// WPA3-Enterprise 192-bit: a P-384 current CA serves 192-bit itself (`mainCAServesSuiteB`),
    /// decided before the switch. Its Computer192 / User192 are bumped whatever the new key type
    /// (their holders' certificates came from the old root). Moving to a P-256 root while 192-bit
    /// is in use (`suiteBInUse`, a Computer192 / User192 template enabled, or certificates of them
    /// still active) first creates the P-384 802.1X 192-bit CA (`dot1x-suiteb`, with its CRL) —
    /// before the switch, so 192-bit never falls to the P-256 root. A new P-384 root serves
    /// 192-bit itself.
    ///
    /// `allowSameKeyType`: a new root of the current key type (root renewal); refused otherwise.
    /// A migration that stopped half-way (`MigrationRecord.committed` false) is finished by
    /// calling this again with the same key type.
    public func migrateCurrentCA(to keyType: CAKeyType = .p384, years: Int = 10, suiteBInUse: Bool = false,
                                 allowSameKeyType: Bool = false) async throws -> RootMigration {
        try await migrateCurrentCA(to: keyType, years: years, suiteBInUse: suiteBInUse, allowSameKeyType: allowSameKeyType,
                                   checkpoint: { _ in })
    }

    func migrateCurrentCA(to keyType: CAKeyType, years: Int, suiteBInUse: Bool, allowSameKeyType: Bool,
                          checkpoint: @Sendable (MigrationStep) throws -> Void) async throws -> RootMigration {
        let current = try await pki.currentAuthority()
        let existingRecord = try await migrationRecord()
        if let r = existingRecord, let to = r.to {
            let ours = r.from.lowercased() == current.name.lowercased() || to.lowercased() == current.name.lowercased()
            guard !r.isCommitted, ours, r.keyType == keyType else {
                if !r.isCommitted, !ours {
                    // Another CA was made current meanwhile: the switch only resumes from its own pair.
                    throw PKIKitError.encoding("the switch from \(r.from) to \(to) did not finish: make \(r.from) or \(to) current, then run it again")
                }
                if !r.isCommitted, let kind = r.keyType {
                    // Unfinished: retiring now would lose the saved template bump (review, 2 Oct 2026).
                    throw PKIKitError.encoding("the switch from \(r.from) to \(to) did not finish: run it again with \(kind.displayName) to complete it")
                }
                throw PKIKitError.encoding("a migration from \(r.from) to \(to) is in progress: retire \(r.from) first")
            }
            return try await finishMigration(r, years: years, resumed: true, checkpoint: checkpoint)
        }
        let old = current
        guard old.keyType != keyType || allowSameKeyType else {
            throw PKIKitError.encoding("the current CA \(old.name) is already \(keyType.displayName)")
        }
        // A preparation written by an earlier run that stopped before the switch (same old root).
        var record = existingRecord.flatMap { $0.from.lowercased() == old.name.lowercased() ? $0 : nil }
            ?? MigrationRecord(from: old.name)
        // 192-bit served by the old root: decided now, before anything changes.
        if record.suiteB == nil, try await pki.mainCAServesSuiteB() {
            record.suiteB = MigrationRecord.suiteBServed
            try await saveMigrationRecord(record)
        }
        if record.oldRootServedSuiteB, keyType != .p384 {
            // Is 192-bit in use, so it must move to its own P-384 root?
            var inUse = suiteBInUse || record.suiteB == MigrationRecord.suiteBCreated
            if !inUse {
                inUse = try await templates().contains { $0.enabled && $0.issuingCA == LabPKI.suiteBCAName }
            }
            if !inUse {
                inUse = try await activeCertificates(caName: old.name).contains { Self.suiteBTemplateNames.contains($0.templateName) }
            }
            if inUse {
                record.suiteB = MigrationRecord.suiteBCreated
                try await saveMigrationRecord(record)
                let info = try await store.domainInfo()
                try await pki.ensureSuiteBCA(commonName: "LabDC 802.1X 192-bit CA (\(info.realm))")
                _ = try await generateCRL(caName: LabPKI.suiteBCAName)
                logger.info("802.1X 192-bit CA (P-384) created: \(old.name, privacy: .public) served 192-bit and the new root is \(keyType.displayName, privacy: .public)")
            }
        }
        try checkpoint(.suiteBPrepared)
        let existing = Set(try await pki.authorities().map { $0.name.lowercased() })
        let base = String(old.name.reversed().drop(while: \.isNumber).reversed())
        let stem = base.isEmpty ? old.name : base
        var generation = 2
        while existing.contains("\(stem)\(generation)".lowercased()) { generation += 1 }
        let oldCN = PKIDirectory.commonName(old.certificate) ?? old.name
        let cnStem = oldCN.replacingOccurrences(of: #"\s\d+$"#, with: "", options: .regularExpression)
        record.to = "\(stem)\(generation)"
        record.commonName = "\(cnStem) \(generation)"
        record.keyType = keyType
        record.committed = false
        try await saveMigrationRecord(record)
        return try await finishMigration(record, years: years, resumed: false, checkpoint: checkpoint)
    }

    /// The steps after the migration is written down; each is idempotent, so a run that
    /// stopped anywhere is finished by running them again.
    private func finishMigration(_ start: MigrationRecord, years: Int, resumed: Bool,
                                 checkpoint: @Sendable (MigrationStep) throws -> Void) async throws -> RootMigration {
        var record = start
        guard let name = record.to, let keyType = record.keyType else {
            throw PKIKitError.encoding("the migration from \(record.from) has no new root")
        }
        let old = try await pki.authority(named: record.from)
        let new: CertificateAuthority
        if try await pki.authorities().contains(where: { $0.name.lowercased() == name.lowercased() }) {
            new = try await pki.authority(named: name)
        } else {
            new = try await pki.createCA(name: name, commonName: record.commonName, keyType: keyType, years: years)
        }
        _ = try await generateCRL(caName: new.name)
        try checkpoint(.created)
        if await pki.currentCAName.lowercased() != new.name.lowercased() { try await pki.useCA(name: new.name) }
        try checkpoint(.switched)

        // Re-enrolment: bump the major version of the templates Windows auto-enrols that the
        // old root issued — never twice: the plan is written down before it is applied.
        if record.reenroll == nil {
            var plan: [String: Int] = [:]
            for t in try await templates() where t.enabled && t.autoEnroll
                && (t.issuingCA == nil || (record.oldRootServedSuiteB && t.issuingCA == LabPKI.suiteBCAName)) {
                // The 192-bit templates follow when the old root served 192-bit itself, whatever
                // the new root: their holders' certificates came from it.
                plan[t.name] = t.majorRevision + 1
            }
            record.reenroll = plan
            try await saveMigrationRecord(record)
        }
        let plan = record.reenroll ?? [:]
        var revisions = try await templateRevisions()
        for (template, revision) in plan { revisions[template] = revision }
        try await store.setDomainValue(String(decoding: try JSONEncoder().encode(revisions), as: UTF8.self),
                                       forKey: Self.templateRevisionsKey)
        try checkpoint(.bumped)
        try await publishToDirectory()
        record.committed = true
        try await saveMigrationRecord(record)
        logger.info("root migration: \(old.name, privacy: .public) -> \(new.name, privacy: .public) (\(keyType.displayName, privacy: .public))\(resumed ? " (resumed)" : "", privacy: .public)")
        let suiteBCreated = record.suiteB == MigrationRecord.suiteBCreated ? try await pki.authority(named: LabPKI.suiteBCAName) : nil
        return RootMigration(from: old, to: new, reenrollTemplates: plan.keys.sorted(), suiteBCreated: suiteBCreated,
                             oldRootServedSuiteB: record.oldRootServedSuiteB, resumed: resumed)
    }

    /// Certificates of `caName` that are neither revoked nor expired.
    public func activeCertificates(caName: String) async throws -> [IssuedCertificate] {
        let now = clock()
        return try await issuedCertificates(caName: caName).filter { !$0.revoked && $0.notAfter > now }
    }

    /// Retires a root that no longer issues: it leaves NTAuth and `Certification Authorities`,
    /// EAP-TLS stops accepting client certificates from it, and the migration (if it was the
    /// old root) ends. Its key and certificate stay, and its CRL keeps being published.
    /// Returns the certificates it issued that are still active (the confirmation lists them).
    @discardableResult
    public func retireCA(name: String) async throws -> [IssuedCertificate] {
        let ca = try await pki.authority(named: name)
        guard ca.name != (try await pki.currentAuthority()).name else {
            throw PKIKitError.encoding("\(ca.name) is the current CA: it cannot be retired")
        }
        if let r = try await migrationRecord(), !r.isCommitted, r.from.lowercased() == ca.name.lowercased() {
            // The switch away from it stopped half-way: its saved template bump and directory
            // publish have not run; retiring would drop them and strand its certificates.
            let kind = r.keyType.map { " with \($0.displayName)" } ?? ""
            let to = r.to ?? "the new root"
            throw PKIKitError.encoding("the switch from \(r.from) to \(to) did not finish: make \(r.from) or \(to) current if it is not, run the switch again\(kind), then retire \(ca.name)")
        }
        var retired = try await retiredCANames()
        retired.insert(ca.name.lowercased())
        try await store.setDomainValue(String(decoding: try JSONEncoder().encode(retired.sorted()), as: UTF8.self),
                                       forKey: Self.retiredCAsKey)
        if let state = try await migrationState(), state.from.lowercased() == ca.name.lowercased() {
            try await store.setDomainValue("", forKey: Self.migrationKey)
        }
        try await publishToDirectory()
        logger.info("retired CA \(ca.name, privacy: .public)")
        return try await activeCertificates(caName: ca.name)
    }

    /// One root as the CA page shows it.
    public struct RootStatus: Sendable, Equatable {
        public let name: String
        public let subject: String
        public let keyType: CAKeyType
        public let thumbprint: String
        /// Issues new certificates.
        public let isCurrent: Bool
        /// Published and accepted (NTAuth, `Certification Authorities`, EAP-TLS).
        public let trusted: Bool
        public let retired: Bool
        /// Issued, not revoked, not expired.
        public let activeCertificates: Int
        public let notAfter: Date
    }

    public func rootStatuses() async throws -> [RootStatus] {
        let current = await pki.currentCAName
        let trusted = Set(try await trustedAuthorities().map(\.name))
        let retired = try await retiredCANames()
        var out: [RootStatus] = []
        for ca in try await pki.authorities() {
            out.append(RootStatus(name: ca.name, subject: ca.certificate.subject.description, keyType: ca.keyType,
                                  thumbprint: CertificateBlob.thumbprint(try ca.der()), isCurrent: ca.name == current,
                                  trusted: trusted.contains(ca.name), retired: retired.contains(ca.name.lowercased()),
                                  activeCertificates: try await activeCertificates(caName: ca.name).count,
                                  notAfter: ca.certificate.notValidAfter))
        }
        return out
    }

    func templateRevisions() async throws -> [String: Int] {
        guard let text = try await store.domainValue(forKey: Self.templateRevisionsKey),
              let map = try? JSONDecoder().decode([String: Int].self, from: Data(text.utf8)) else { return [:] }
        return map
    }
}
