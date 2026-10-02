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
    /// JSON `{"from": <old root>, "to": <new root>}` while a migration's old root is still trusted.
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
    /// retired one and the RSA compatibility root while RSA-only devices are not allowed.
    public func trustedAuthorities() async throws -> [CertificateAuthority] {
        let retired = try await retiredCANames()
        let rsa = await rsaCompatibilityEnabled()
        return try await pki.authorities().filter { ca in
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

    /// The migration in progress (its old root still trusted), if any.
    public func migrationState() async throws -> (from: String, to: String)? {
        guard let text = try await store.domainValue(forKey: Self.migrationKey),
              let object = try? JSONDecoder().decode([String: String].self, from: Data(text.utf8)),
              let from = object["from"], let to = object["to"] else { return nil }
        return (from, to)
    }

    /// What `migrateCurrentCA` did.
    public struct RootMigration: Sendable {
        /// The former current root (still trusted until retired).
        public let from: CertificateAuthority
        /// The new root, now current.
        public let to: CertificateAuthority
        /// Auto-enrollment templates whose major version was bumped (Windows re-enrols holders).
        public let reenrollTemplates: [String]
    }

    /// Moves issuing to a new root of `keyType` (default P-384 / SHA-384) without touching the
    /// current one: a new CA `<base><n>` (`lab` → `lab2`, CN `… 2`) is created with its CRL and
    /// made current; the old root stays trusted (NTAuth, `Certification Authorities`, EAP-TLS)
    /// until `retireCA`. The major version of every enabled auto-enrollment template issued by
    /// the current CA is bumped, so Windows re-enrols machine and user certificates from the new
    /// root at its next auto-enrollment pulse. The DC certificate is reissued by the caller
    /// (`LabPKI.ensureServerCertificate`, which follows the current CA).
    public func migrateCurrentCA(to keyType: CAKeyType = .p384, years: Int = 10) async throws -> RootMigration {
        let old = try await pki.currentAuthority()
        if let state = try await migrationState() {
            throw PKIKitError.encoding("a migration from \(state.from) to \(state.to) is in progress: retire \(state.from) first")
        }
        guard old.keyType != keyType else {
            throw PKIKitError.encoding("the current CA \(old.name) is already \(keyType.displayName)")
        }
        let existing = Set(try await pki.authorities().map { $0.name.lowercased() })
        let base = String(old.name.reversed().drop(while: \.isNumber).reversed())
        let stem = base.isEmpty ? old.name : base
        var generation = 2
        while existing.contains("\(stem)\(generation)".lowercased()) { generation += 1 }
        let name = "\(stem)\(generation)"
        let oldCN = PKIDirectory.commonName(old.certificate) ?? old.name
        let cnStem = oldCN.replacingOccurrences(of: #"\s\d+$"#, with: "", options: .regularExpression)
        let new = try await pki.createCA(name: name, commonName: "\(cnStem) \(generation)", keyType: keyType, years: years)
        _ = try await generateCRL(caName: new.name)
        try await pki.useCA(name: new.name)
        let json = try JSONEncoder().encode(["from": old.name, "to": new.name])
        try await store.setDomainValue(String(decoding: json, as: UTF8.self), forKey: Self.migrationKey)

        // Re-enrolment: bump the major version of the templates Windows auto-enrols that the
        // current CA issues (not the 192-bit / RSA ones with their own roots).
        var revisions = try await templateRevisions()
        var bumped: [String] = []
        for t in try await templates() where t.enabled && t.autoEnroll && t.issuingCA == nil {
            revisions[t.name] = t.majorRevision + 1
            bumped.append(t.name)
        }
        try await store.setDomainValue(String(decoding: try JSONEncoder().encode(revisions), as: UTF8.self),
                                       forKey: Self.templateRevisionsKey)
        try await publishToDirectory()
        logger.info("root migration: \(old.name, privacy: .public) -> \(new.name, privacy: .public) (\(keyType.displayName, privacy: .public))")
        return RootMigration(from: old, to: new, reenrollTemplates: bumped)
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
