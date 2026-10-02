import Foundation
import MSPAC
import os
import Store
import SwiftASN1
import X509

/// Who asks for a certificate. PK-6 builds it from the Kerberos PAC (user/computer SID + group
/// SIDs); the CLI and UI use `CAService.requester(account:isAdmin:)` or `.administrator`.
public struct RequesterIdentity: Sendable, Equatable, CustomStringConvertible {
    /// A display name (`LABSHEEP\WS1$`, `alice`, `administrator (CLI)`).
    public var name: String
    /// The account SID; the SAN policies `dnsHostName` / `upn` look the account up by it.
    public var sid: String?
    /// Transitive group SIDs (as in the PAC), checked against `enrolAllowedGroupSIDs`.
    public var groupSIDs: [String]
    /// An administrator (CLI / UI): may use manual templates, skips the group check, and may
    /// pass subject / SAN / validity overrides. With a `sid`, it acts for that account.
    public var isAdmin: Bool

    public init(name: String, sid: String? = nil, groupSIDs: [String] = [], isAdmin: Bool = false) {
        self.name = name
        self.sid = sid
        self.groupSIDs = groupSIDs
        self.isAdmin = isAdmin
    }

    /// An administrator acting for no particular account.
    public static func administrator(_ name: String = "administrator (CLI)") -> RequesterIdentity {
        RequesterIdentity(name: name, isAdmin: true)
    }

    public var description: String { name + (sid.map { " (\($0))" } ?? "") + (isAdmin ? " [admin]" : "") }
}

/// Caller-supplied changes to what the template and CSR say.
public struct IssuanceOverrides: Sendable {
    /// Issue from this CA instead of the current one.
    public var caName: String?
    /// Shorter validity (anyone) or longer (admins only; always capped at the CA's expiry).
    public var validityDays: Int?
    /// Replace the CSR's SANs (admins only, `fromRequest` templates only).
    public var subjectAltNames: [GeneralName]?
    /// Replace the CSR's subject (admins only, `fromRequest` / `none` templates only).
    public var subject: DistinguishedName?

    public init(caName: String? = nil, validityDays: Int? = nil, subjectAltNames: [GeneralName]? = nil,
                subject: DistinguishedName? = nil) {
        self.caName = caName
        self.validityDays = validityDays
        self.subjectAltNames = subjectAltNames
        self.subject = subject
    }
}

/// What `CAService.issue` would issue for a request that passed every check (`CAService.plan`).
public struct IssuancePlan: Sendable {
    public let template: CertificateTemplate
    public let requester: RequesterIdentity
    /// The issuing CA.
    public let ca: CertificateAuthority
    public let subject: DistinguishedName
    public let subjectAltNames: [GeneralName]
    public let keyKind: SubjectKeyKind
    public let notBefore: Date
    public let notAfter: Date
    /// `notAfter` was cut back to the CA's own expiry.
    public let cappedByCA: Bool
    /// The validity asked for (template or override), before any cap.
    public let validityDays: Int
    let now: Date
    /// The CDP and AIA caIssuers URLs the certificate will carry.
    public let crlURL: String
    public let caIssuersURL: String
}

/// Why `issue` / `revoke` refused.
public enum IssuanceError: Error, Sendable, Equatable, CustomStringConvertible {
    case unknownTemplate(String)
    case templateDisabled(String)
    case adminRequired(template: String)
    case notAllowedToEnrol(requester: String, template: String)
    case invalidCSRSignature
    case malformedCSR(String)
    case keyTypeNotAllowed(found: String, allowed: [String], template: String)
    case keyTooSmall(bits: Int, minimum: Int, template: String)
    case requesterUnknown(String)
    case requesterHasNoSID(template: String)
    case requesterHasNoDNSHostName(String)
    case subjectAltNameNotAllowed(requested: String, allowed: String)
    case unsupportedSubjectAltName(String)
    case missingSubjectAltName(template: String)
    case emptySubject(template: String)
    case overrideRequiresAdmin(String)
    case overrideNotApplicable(String)
    case invalidValidity(requested: Int, maximum: Int)
    case caExpired(String)
    case notProvisioned
    case unknownSerial(String)
    case alreadyRevoked(serial: String, reason: String)
    case invalidRevocationReason(String)

    public var description: String {
        switch self {
        case .unknownTemplate(let t): "no certificate template named '\(t)'"
        case .templateDisabled(let t): "template '\(t)' is disabled"
        case .adminRequired(let t): "template '\(t)' is a manual template: only an administrator may issue from it"
        case .notAllowedToEnrol(let r, let t): "\(r) is not in any group allowed to enrol for template '\(t)'"
        case .invalidCSRSignature: "the CSR's signature does not verify with the public key it carries"
        case .malformedCSR(let s): "malformed CSR: \(s)"
        case .keyTypeNotAllowed(let found, let allowed, let t):
            "template '\(t)' does not accept \(found) keys (allowed: \(allowed.joined(separator: ", ")))"
        case .keyTooSmall(let bits, let minimum, let t): "template '\(t)' needs RSA keys of at least \(minimum) bits, the CSR has \(bits)"
        case .requesterUnknown(let s): "requester \(s) is not in the directory"
        case .requesterHasNoSID(let t): "template '\(t)' takes the SAN from the requester's account, but the requester has no SID"
        case .requesterHasNoDNSHostName(let s): "\(s) is not a computer with a dNSHostName"
        case .subjectAltNameNotAllowed(let requested, let allowed): "the CSR asks for SAN \(requested); only \(allowed) is allowed"
        case .unsupportedSubjectAltName(let s): "unsupported or invalid SAN \(s)"
        case .missingSubjectAltName(let t): "template '\(t)' issues server certificates: the CSR must name at least one SAN"
        case .emptySubject(let t): "the CSR has an empty subject and template '\(t)' gives none"
        case .overrideRequiresAdmin(let s): "only an administrator may override \(s)"
        case .overrideNotApplicable(let s): "\(s)"
        case .invalidValidity(let requested, let maximum): "validity of \(requested) days is not allowed (1...\(maximum))"
        case .caExpired(let s): "CA '\(s)' has expired"
        case .notProvisioned: "the store is not provisioned (the DC name is needed for the CRL/AIA URLs)"
        case .unknownSerial(let s): "no issued certificate with serial \(s)"
        case .alreadyRevoked(let s, let reason): "certificate \(s) is already revoked (\(reason))"
        case .invalidRevocationReason(let s): "\(s) cannot be used to revoke (see RFC 5280 CRLReason)"
        }
    }
}

/// An issued certificate as recorded in the store (`pki_issued`).
public typealias IssuedCertificate = PKIIssuedRow

extension PKIIssuedRow {
    public var reason: RevocationReason? { revocationReason.flatMap(RevocationReason.init(rawValue:)) }

    public func certificate() throws -> Certificate {
        do { return try Certificate(derEncoded: der) } catch {
            throw PKIKitError.corruptFile(path: "pki_issued \(serial)", reason: "\(error)")
        }
    }
}

/// The certificate authority service (PK-1): templates, issuance, the issuance database,
/// revocation and CRLs, over a `LabPKI` (CA files) and a `DirectoryStore` (tables, accounts).
///
/// Issued certificates carry a CRL distribution point `http://<dc fqdn>/pki/<ca>.crl` and an AIA
/// caIssuers `http://<dc fqdn>/pki/<ca>.crt`, served by `PKIHTTPServer` via `httpResponse`.
public actor CAService {
    public let pki: LabPKI
    public let store: DirectoryStore
    let clock: @Sendable () -> Date
    let logger = Logger(subsystem: "dev.labdc.app", category: "pki")
    /// `domain` table key holding the HTTP port the CRL and CA certificate are served on (audit
    /// 27 Sep 2026: the CDP/AIA URLs ignored `--ports http=N`, so members could not fetch the CRL).
    /// Kept in the store so `ca sign` and the app's Sign use the port the running serve bound.
    public static let publicationPortKey = "pki.publicationPort"

    /// Sets the port written into CDP/AIA URLs of certificates issued from now on (nil or 80 = none).
    public func setPublicationPort(_ port: Int?) async throws {
        try await store.setDomainValue(port.map(String.init) ?? "80", forKey: Self.publicationPortKey)
    }

    /// The stored publication port; nil when none was recorded.
    public func publicationPort() async throws -> Int? {
        try await store.domainValue(forKey: Self.publicationPortKey).flatMap { Int($0) }
    }

    /// CRL nextUpdate − thisUpdate.
    public static let crlLifetime: TimeInterval = 7 * 86400
    /// A stored CRL older than this is regenerated (the "daily" refresh).
    public static let crlRefreshAge: TimeInterval = 86400
    /// `domain` table key holding the forest template arc (`1.3.6.1.4.1.311.21.8.a.b.c.d.e.f`).
    public static let templateArcKey = "pki.templateOIDArc"
    static let backdate: TimeInterval = 300

    public init(pki: LabPKI, store: DirectoryStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.pki = pki
        self.store = store
        self.clock = clock
    }

    /// Opens the service and makes sure the built-in templates exist.
    public static func open(pki: LabPKI, store: DirectoryStore,
                            clock: @escaping @Sendable () -> Date = { Date() }) async throws -> CAService {
        let service = CAService(pki: pki, store: store, clock: clock)
        try await service.ensureBuiltInTemplates()
        return service
    }

    // MARK: - Templates

    /// Creates the missing built-in templates (existing rows, possibly edited, are left alone).
    /// Returns the names created.
    @discardableResult
    public func ensureBuiltInTemplates() async throws -> [String] {
        guard await store.isProvisioned else { throw IssuanceError.notProvisioned }
        let info = try await store.domainInfo()
        let arc = try await templateArc()
        var created: [String] = []
        for template in CertificateTemplate.builtIns(domainSID: info.domainSID.description,
                                                     oid: { _ in CertificateTemplate.randomTemplateOID(arc: arc) }) {
            if try await store.pkiTemplate(named: template.name) == nil {
                try await store.savePKITemplate(template.row)
                created.append(template.name)
            }
        }
        if !created.isEmpty {
            logger.info("created certificate templates \(created.joined(separator: ", "), privacy: .public)")
            // PK-5: new templates appear in the Configuration NC at once.
            try await publishToDirectory()
        }
        return created
    }

    public func templates() async throws -> [CertificateTemplate] {
        let revisions = try await templateRevisions()
        return try await store.pkiTemplates().map { row in
            var t = CertificateTemplate(row: row)
            if let r = revisions[t.name] { t.majorRevision = r }
            return t
        }
    }

    public func template(named name: String) async throws -> CertificateTemplate {
        guard let row = try await store.pkiTemplate(named: name) else { throw IssuanceError.unknownTemplate(name) }
        var t = CertificateTemplate(row: row)
        if let r = try await templateRevisions()[t.name] { t.majorRevision = r }
        return t
    }

    /// Inserts or replaces a template (UI edits, custom templates) and republishes the PKI
    /// objects (PK-5: the template object, its OID object, the enrollment service's
    /// `certificateTemplates`).
    public func saveTemplate(_ template: CertificateTemplate) async throws {
        // An enabled 192-bit template needs its issuer: the P-384 802.1X CA is made on first use.
        if template.enabled, template.issuingCA == LabPKI.suiteBCAName { try await ensureSuiteBAuthority() }
        if template.enabled, template.issuingCA == LabPKI.rsaCompatCAName { try await ensureRSACompatAuthority() }
        try await store.savePKITemplate(template.row)
        try await publishToDirectory()
    }

    /// WPA3-Enterprise 192-bit: the P-384 802.1X root is created only when it is first needed —
    /// a 192-bit 802.1X profile is published or a template it issues is enabled — with its CRL,
    /// and published to the Configuration NC (NTAuth, AIA, Certification Authorities) at once.
    /// Returns true when it was created now (an existing one is kept as is). A P-384 current CA
    /// serves 192-bit itself (`LabPKI.mainCAServesSuiteB`): nothing is created then.
    @discardableResult
    public func ensureSuiteBAuthority() async throws -> Bool {
        if try await pki.hasSuiteBCA() { return false }
        if try await pki.mainCAServesSuiteB() { return false }
        let info = try await store.domainInfo()
        try await pki.ensureSuiteBCA(commonName: "LabDC 802.1X 192-bit CA (\(info.realm))")
        _ = try await generateCRL(caName: LabPKI.suiteBCAName)
        try await publishToDirectory()
        logger.info("created the 802.1X 192-bit CA (P-384) on first use")
        return true
    }

    /// A new template OID under this forest's arc.
    public func newTemplateOID() async throws -> String {
        CertificateTemplate.randomTemplateOID(arc: try await templateArc())
    }

    /// The forest arc, generated once and kept in the `domain` table.
    public func templateArc() async throws -> String {
        if let arc = try await store.domainValue(forKey: Self.templateArcKey) { return arc }
        let arc = CertificateTemplate.randomForestArc()
        try await store.setDomainValue(arc, forKey: Self.templateArcKey)
        return arc
    }

    // MARK: - Requesters

    /// Resolves an account (`sAMAccountName`, `NAME$`, UPN or SID string) into a requester with
    /// its transitive groups plus Everyone (S-1-1-0) and Authenticated Users (S-1-5-11).
    public func requester(account: String, isAdmin: Bool = false) async throws -> RequesterIdentity {
        var entry: DirectoryEntry?
        if account.uppercased().hasPrefix("S-1-"), let sid = try? SID(string: account) {
            entry = try await store.read(sid: sid)
        }
        if entry == nil { entry = try await store.read(sam: account) }
        if entry == nil, !account.hasSuffix("$") { entry = try await store.read(sam: account + "$") }
        if entry == nil, account.contains("@") { entry = try await store.read(upn: account) }
        guard let entry, let sid = entry.sid else { throw IssuanceError.requesterUnknown(account) }
        var groups = try await store.groupSIDs(of: entry.id).map(\.description)
        groups += ["S-1-1-0", "S-1-5-11"]
        return RequesterIdentity(name: entry.samAccountName ?? account, sid: sid.description, groupSIDs: groups,
                                 isAdmin: isAdmin)
    }

    // MARK: - Publication URLs

    public static func crlPath(caName: String) -> String { "/pki/\(caName).crl" }
    public static func caCertificatePath(caName: String) -> String { "/pki/\(caName).crt" }

    /// `http://<dc fqdn>` (the DNS name DNSKit already answers for the DC).
    public func publicationBaseURL() async throws -> String {
        guard await store.isProvisioned else { throw IssuanceError.notProvisioned }
        let host = try await store.domainInfo().dcDNSName
        if let port = try await publicationPort(), port > 0, port != 80 { return "http://\(host):\(port)" }
        return "http://\(host)"
    }

    public func crlURL(caName: String) async throws -> String {
        try await publicationBaseURL() + Self.crlPath(caName: caName)
    }

    public func caIssuersURL(caName: String) async throws -> String {
        try await publicationBaseURL() + Self.caCertificatePath(caName: caName)
    }

    // MARK: - Issuance

    /// Signs `csr` with the current CA (or `overrides.caName`) under `template`, records it and
    /// returns the certificate.
    ///
    /// Checks, in order: the template is enabled; manual templates need an admin; non-admins
    /// must have a SID or group SID in `enrolAllowedGroupSIDs`; the CSR signature verifies; the
    /// key type / RSA size is allowed; the SAN policy (see `SANPolicy`); the validity.
    public func issue(csr: CertificateSigningRequest, template: CertificateTemplate, requester: RequesterIdentity,
                      overrides: IssuanceOverrides = IssuanceOverrides()) async throws -> Certificate {
        let plan = try await plan(csr: csr, template: template, requester: requester, overrides: overrides)
        let ca = plan.ca

        // Extensions
        let extensions = try await leafExtensions(template: template, ca: ca, subjectKey: csr.publicKey,
                                                  keyKind: plan.keyKind, subjectEmpty: plan.subject.isEmpty,
                                                  sans: plan.subjectAltNames,
                                                  accountSID: template.isAccountBound ? requester.sid : nil)

        // Sign, with a serial not used before
        var certificate: Certificate?
        for _ in 0..<5 {
            let serial = LabPKI.randomSerial()
            if try await store.issuedCertificate(serial: LabPKI.hex(serial)) != nil { continue }
            do {
                certificate = try Certificate(
                    version: .v3, serialNumber: serial, publicKey: csr.publicKey,
                    notValidBefore: plan.notBefore, notValidAfter: plan.notAfter,
                    issuer: ca.certificate.subject, subject: plan.subject,
                    signatureAlgorithm: ca.key.signatureAlgorithm, extensions: extensions,
                    issuerPrivateKey: ca.key.certificateKey)
            } catch {
                throw PKIKitError.encoding("certificate: \(error)")
            }
            break
        }
        guard let certificate else { throw PKIKitError.encoding("could not find an unused serial number") }
        try await recordIssued(certificate, caName: ca.name, templateName: template.name, requester: requester,
                               issuedAt: plan.now)
        logger.info("issued \(template.name, privacy: .public) certificate \(LabPKI.hex(certificate.serialNumber), privacy: .public) from CA \(ca.name, privacy: .public) to \(requester.description, privacy: .public)")
        return certificate
    }

    /// Runs every check `issue` runs and works out what it would issue, without signing or
    /// recording anything (PK-2's review / `--dry-run`). Throws the same `IssuanceError`s.
    public func plan(csr: CertificateSigningRequest, template: CertificateTemplate, requester: RequesterIdentity,
                     overrides: IssuanceOverrides = IssuanceOverrides()) async throws -> IssuancePlan {
        // Authorisation
        guard template.enabled else { throw IssuanceError.templateDisabled(template.name) }
        if template.manualApproval && !requester.isAdmin { throw IssuanceError.adminRequired(template: template.name) }
        if !requester.isAdmin {
            guard Self.mayEnrol(groupSIDs: requester.groupSIDs, sid: requester.sid, template: template) else {
                throw IssuanceError.notAllowedToEnrol(requester: requester.description, template: template.name)
            }
            if overrides.subjectAltNames != nil { throw IssuanceError.overrideRequiresAdmin("the subjectAltName") }
            if overrides.subject != nil { throw IssuanceError.overrideRequiresAdmin("the subject") }
        }

        // The request itself
        guard csr.publicKey.isValidSignature(csr.signature, for: csr) else { throw IssuanceError.invalidCSRSignature }
        let keyKind = SubjectKeyKind(csr.publicKey)
        guard template.allowedKeyTypes.map({ $0.lowercased() }).contains(keyKind.token) else {
            throw IssuanceError.keyTypeNotAllowed(found: keyKind.description, allowed: template.allowedKeyTypes,
                                                  template: template.name)
        }
        if case .rsa(let bits) = keyKind, bits < template.minKeyBits {
            throw IssuanceError.keyTooSmall(bits: bits, minimum: template.minKeyBits, template: template.name)
        }
        let requested: [GeneralName]
        do {
            requested = Array(try csr.attributes.extensionRequest?.extensions.subjectAlternativeNames ?? SubjectAlternativeNames())
        } catch {
            throw IssuanceError.malformedCSR("extensionRequest / subjectAltName: \(error)")
        }

        // Subject and SANs from the policy
        let (subject, sans) = try await subjectAndNames(template: template, csr: csr, requested: requested,
                                                         requester: requester, overrides: overrides)

        // Validity
        var days = template.validityDays
        if let d = overrides.validityDays {
            let maximum = requester.isAdmin ? 36500 : template.validityDays
            guard (1...maximum).contains(d) else { throw IssuanceError.invalidValidity(requested: d, maximum: maximum) }
            days = d
        }
        let ca: CertificateAuthority
        if let name = overrides.caName ?? template.issuingCA { ca = try await pki.issuingAuthority(named: name) } else { ca = try await pki.currentAuthority() }
        let now = clock()
        guard ca.certificate.notValidAfter > now else { throw IssuanceError.caExpired(ca.name) }
        let notBefore = now.addingTimeInterval(-Self.backdate)
        let wanted = notBefore.addingTimeInterval(TimeInterval(days) * 86400)
        let notAfter = min(wanted, ca.certificate.notValidAfter)
        return IssuancePlan(template: template, requester: requester, ca: ca, subject: subject, subjectAltNames: sans,
                            keyKind: keyKind, notBefore: notBefore, notAfter: notAfter, cappedByCA: notAfter < wanted,
                            validityDays: days, now: now, crlURL: try await crlURL(caName: ca.name),
                            caIssuersURL: try await caIssuersURL(caName: ca.name))
    }

    /// Records a certificate issued elsewhere (the DC server certificate). No-op when the serial
    /// is already recorded.
    public func record(_ certificate: Certificate, caName: String, templateName: String,
                       requester: RequesterIdentity) async throws {
        if try await store.issuedCertificate(serial: LabPKI.hex(certificate.serialNumber)) != nil { return }
        try await recordIssued(certificate, caName: caName, templateName: templateName, requester: requester,
                               issuedAt: clock())
    }

    private func recordIssued(_ certificate: Certificate, caName: String, templateName: String,
                              requester: RequesterIdentity, issuedAt: Date) async throws {
        let sans = (try? certificate.extensions.subjectAlternativeNames).map { $0.map(Self.describe) } ?? []
        try await store.insertIssuedCertificate(PKIIssuedRow(
            serial: LabPKI.hex(certificate.serialNumber), caName: caName, templateName: templateName,
            subject: certificate.subject.description, subjectAltNames: sans,
            notBefore: certificate.notValidBefore, notAfter: certificate.notValidAfter,
            requesterSID: requester.sid, requesterName: requester.name, der: try LabPKI.der(certificate),
            issuedAt: issuedAt))
    }

    private func subjectAndNames(template: CertificateTemplate, csr: CertificateSigningRequest, requested: [GeneralName],
                                 requester: RequesterIdentity,
                                 overrides: IssuanceOverrides) async throws -> (DistinguishedName, [GeneralName]) {
        switch template.sanPolicy {
        case .dnsHostName:
            if overrides.subjectAltNames != nil || overrides.subject != nil {
                throw IssuanceError.overrideNotApplicable("template '\(template.name)' takes the subject and SAN from the computer account")
            }
            let entry = try await account(of: requester, template: template)
            guard var host = entry.string("dNSHostName")?.lowercased(), !host.isEmpty else {
                throw IssuanceError.requesterHasNoDNSHostName(entry.samAccountName ?? requester.name)
            }
            if host.hasSuffix(".") { host.removeLast() }
            try await refuseDomainControllerName(host, for: entry)
            for name in requested {
                guard case .dnsName(let asked) = name, Self.normalizedHost(asked) == host else {
                    throw IssuanceError.subjectAltNameNotAllowed(requested: Self.describe(name), allowed: "DNS:\(host)")
                }
            }
            return (try DistinguishedName { CommonName(host) }, [.dnsName(host)])

        case .upn:
            if overrides.subjectAltNames != nil || overrides.subject != nil {
                throw IssuanceError.overrideNotApplicable("template '\(template.name)' takes the subject and SAN from the user account")
            }
            let entry = try await account(of: requester, template: template)
            let sam = entry.samAccountName ?? requester.name
            let upn: String
            if let stored = entry.string("userPrincipalName"), !stored.isEmpty {
                upn = stored
            } else {
                upn = "\(sam)@\(try await store.domainInfo().dnsDomain)"
            }
            for name in requested {
                guard let asked = Self.upn(of: name), asked.lowercased() == upn.lowercased() else {
                    throw IssuanceError.subjectAltNameNotAllowed(requested: Self.describe(name), allowed: "UPN:\(upn)")
                }
            }
            return (try DistinguishedName { CommonName(sam) }, [try Self.upnName(upn)])

        case .fromRequest:
            let sans = overrides.subjectAltNames ?? requested
            for name in sans { try Self.validate(name) }
            if !requester.isAdmin {
                // ESC1: a CSR-supplied UPN (or a SID URL, KB5014754) would sign the requester in
                // as somebody else. Only an administrator may put an identity in the SAN.
                for name in sans where Self.upn(of: name) != nil || Self.isSIDURL(name) {
                    throw IssuanceError.subjectAltNameNotAllowed(requested: Self.describe(name),
                                                                 allowed: "DNS names and addresses (an identity SAN needs an administrator)")
                }
            }
            if sans.isEmpty && template.ekus.contains(PKIOID.serverAuth) {
                throw IssuanceError.missingSubjectAltName(template: template.name)
            }
            var subject = overrides.subject ?? csr.subject
            if subject.isEmpty, let first = sans.lazy.compactMap({ n -> String? in
                if case .dnsName(let h) = n { return h } else { return nil }
            }).first {
                subject = try DistinguishedName { CommonName(first) }
            }
            guard !subject.isEmpty || !sans.isEmpty else { throw IssuanceError.emptySubject(template: template.name) }
            return (subject, sans)

        case .none:
            if overrides.subjectAltNames != nil {
                throw IssuanceError.overrideNotApplicable("template '\(template.name)' issues no subjectAltName")
            }
            let subject = overrides.subject ?? csr.subject
            guard !subject.isEmpty else { throw IssuanceError.emptySubject(template: template.name) }
            return (subject, [])
        }
    }

    /// Certifried (CVE-2022-26923): a `dnsHostName` certificate for an account that is not a
    /// domain controller may not name a DC (this DC's or any DC account's `dNSHostName`, or a DC's
    /// computer name as the first label) or the domain itself, like `checkDeviceNames` for devices.
    func refuseDomainControllerName(_ host: String, for entry: DirectoryEntry) async throws {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & (UserAccountControl.serverTrustAccount | UserAccountControl.partialSecretsAccount) != 0 { return }
        let info = try await store.domainInfo()
        var hosts: Set<String> = [Self.normalizedHost(info.dcDNSName), Self.normalizedHost(info.dnsDomain)]
        var labels: Set<String> = [info.dcName.lowercased()]
        let dcs = try await store.search(base: info.domainDN, scope: .subtree,
                                         filter: .or([.eq("primaryGroupID", "516"), .eq("primaryGroupID", "521")]),
                                         attrs: ["sAMAccountName", "dNSHostName"])
        for dc in dcs where dc.id != entry.id {
            if let h = dc.string("dNSHostName") { hosts.insert(Self.normalizedHost(h)) }
            if let sam = dc.samAccountName?.lowercased() { labels.insert(sam.hasSuffix("$") ? String(sam.dropLast()) : sam) }
        }
        let host = Self.normalizedHost(host)
        let label = host.split(separator: ".").first.map(String.init) ?? host
        if hosts.contains(host) || labels.contains(label) {
            throw IssuanceError.subjectAltNameNotAllowed(requested: "DNS:\(host)",
                                                         allowed: "a name that is not a domain controller's or the domain's")
        }
    }

    /// The KB5014754 SAN URL `tag:microsoft.com,2022-09-14:sid:<SID>` (strong mapping by SAN).
    static func isSIDURL(_ name: GeneralName) -> Bool {
        guard case .uniformResourceIdentifier(let uri) = name else { return false }
        return uri.lowercased().hasPrefix("tag:microsoft.com,2022-09-14:sid:")
    }

    private func account(of requester: RequesterIdentity, template: CertificateTemplate) async throws -> DirectoryEntry {
        guard let sidText = requester.sid else { throw IssuanceError.requesterHasNoSID(template: template.name) }
        guard let sid = try? SID(string: sidText), let entry = try await store.read(sid: sid) else {
            throw IssuanceError.requesterUnknown(sidText)
        }
        return entry
    }

    private func leafExtensions(template: CertificateTemplate, ca: CertificateAuthority,
                                subjectKey: Certificate.PublicKey, keyKind: SubjectKeyKind, subjectEmpty: Bool,
                                sans: [GeneralName], accountSID: String? = nil) async throws -> Certificate.Extensions {
        var usage = template.keyUsage
        // keyEncipherment means RSA key transport; an EC key cannot do it.
        if keyKind.isEC { usage.remove(.keyEncipherment) }
        if usage.isEmpty { usage = .digitalSignature }
        let crl = try await crlURL(caName: ca.name)
        let aia = try await caIssuersURL(caName: ca.name)
        do {
            var ext = Certificate.Extensions()
            try ext.append(Certificate.Extension(
                template.isCA ? BasicConstraints.isCertificateAuthority(maxPathLength: 0) : .notCertificateAuthority,
                critical: true))
            try ext.append(Certificate.Extension(usage.x509, critical: true))
            if !template.ekus.isEmpty {
                let ekus = try ExtendedKeyUsage(template.ekus.map {
                    ExtendedKeyUsage.Usage(oid: try ASN1ObjectIdentifier(dotRepresentation: $0))
                })
                try ext.append(Certificate.Extension(ekus, critical: false))
            }
            try ext.append(Certificate.Extension(SubjectKeyIdentifier(hash: subjectKey), critical: false))
            if let keyID = ca.keyIdentifier {
                try ext.append(Certificate.Extension(AuthorityKeyIdentifier(keyIdentifier: keyID[...]), critical: false))
            }
            if !sans.isEmpty {
                // RFC 5280 §4.2.1.6: critical when the subject is empty.
                try ext.append(Certificate.Extension(SubjectAlternativeNames(sans), critical: subjectEmpty))
            }
            // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint { [0] { [0] fullName GeneralNames } }
            let cdp = DERWriter.sequence([DERWriter.sequence([
                DERWriter.tlv(0xA0, DERWriter.tlv(0xA0, DERWriter.uri(crl))),
            ])])
            try ext.append(Certificate.Extension(oid: try ASN1ObjectIdentifier(dotRepresentation: PKIOID.crlDistributionPoints),
                                                 critical: false, value: cdp[...]))
            let aiaValue = DERWriter.sequence([DERWriter.sequence([DERWriter.oid(PKIOID.caIssuers), DERWriter.uri(aia)])])
            try ext.append(Certificate.Extension(oid: try ASN1ObjectIdentifier(dotRepresentation: PKIOID.authorityInfoAccess),
                                                 critical: false, value: aiaValue[...]))
            // szOID_CERTIFICATE_TEMPLATE { templateID, majorVersion, minorVersion }
            let templateExt = DERWriter.sequence([DERWriter.oid(template.oid),
                                                  DERWriter.integer(Int64(template.majorRevision)),
                                                  DERWriter.integer(Int64(CertificateTemplate.minorVersion))])
            try ext.append(Certificate.Extension(
                oid: try ASN1ObjectIdentifier(dotRepresentation: PKIOID.certificateTemplateExtension),
                critical: false, value: templateExt[...]))
            // KB5014754: account-bound certificates carry the account's SID (strong mapping).
            if let accountSID {
                let value = NTDSSecurityExtension.value(sid: accountSID)
                try ext.append(Certificate.Extension(
                    oid: try ASN1ObjectIdentifier(dotRepresentation: PKIOID.ntdsCASecurityExtension),
                    critical: false, value: value[...]))
            }
            return ext
        } catch {
            throw PKIKitError.encoding("certificate extensions: \(error)")
        }
    }

    // MARK: - Queries

    public func issuedCertificates(caName: String? = nil, revokedOnly: Bool = false) async throws -> [IssuedCertificate] {
        try await store.issuedCertificates(caName: caName, revokedOnly: revokedOnly)
    }

    public func issuedCertificate(serial: String) async throws -> IssuedCertificate? {
        try await store.issuedCertificate(serial: Self.normalizedSerial(serial))
    }

    // MARK: - Revocation and CRLs

    /// Revokes a recorded certificate and regenerates its CA's CRL. A certificate on hold may be
    /// revoked again with a final reason; `removeFromCRL` is refused (no delta CRLs).
    @discardableResult
    public func revoke(serial: String, reason: RevocationReason, date: Date? = nil) async throws -> IssuedCertificate {
        guard reason != .removeFromCRL else { throw IssuanceError.invalidRevocationReason(reason.cliName) }
        let key = Self.normalizedSerial(serial)
        guard let row = try await store.issuedCertificate(serial: key) else { throw IssuanceError.unknownSerial(serial) }
        if row.revoked, row.reason != .certificateHold {
            throw IssuanceError.alreadyRevoked(serial: row.serial, reason: row.reason?.cliName ?? "unspecified")
        }
        try await store.setRevocation(serial: key, reason: reason.rawValue, date: date ?? clock())
        logger.info("revoked \(row.serial, privacy: .public) (\(reason.cliName, privacy: .public))")
        _ = try await generateCRL(caName: row.caName)
        guard let updated = try await store.issuedCertificate(serial: key) else { throw IssuanceError.unknownSerial(serial) }
        return updated
    }

    /// Signs a fresh CRL for `caName` (number = previous + 1, nextUpdate = now + 7 days) with the
    /// revoked, not yet expired certificates, and stores it.
    @discardableResult
    public func generateCRL(caName: String) async throws -> CertificateRevocationList {
        let ca = try await pki.authority(named: caName)
        let now = clock()
        let previous = try await store.pkiCRL(caName: ca.name)
        let entries = try await store.issuedCertificates(caName: ca.name, revokedOnly: true)
            .filter { $0.notAfter > now }
            .sorted { ($0.revocationDate ?? .distantPast, $0.serial) < ($1.revocationDate ?? .distantPast, $1.serial) }
            .map { row in
                CertificateRevocationList.Entry(serial: Self.bytes(hex: row.serial), revocationDate: row.revocationDate ?? now,
                                                reason: row.reason)
            }
        let crl = try CertificateRevocationList.make(ca: ca, entries: entries, crlNumber: (previous?.crlNumber ?? 0) + 1,
                                                     thisUpdate: now, nextUpdate: now.addingTimeInterval(Self.crlLifetime))
        try await store.savePKICRL(PKICRLRow(caName: ca.name, crlNumber: crl.crlNumber ?? 0, thisUpdate: crl.thisUpdate,
                                             nextUpdate: crl.nextUpdate ?? now, der: crl.der))
        logger.info("CRL #\(crl.crlNumber ?? 0) for CA \(ca.name, privacy: .public): \(entries.count) entries")
        // PK-5: the CDP object in the Configuration NC follows. A failure there must not stop
        // the CRL itself (HTTP keeps serving it); `labdc pki publish` repairs it.
        do { try await publishCRLToDirectory(caName: ca.name, der: crl.der) } catch {
            logger.error("CRL of CA \(ca.name, privacy: .public) not published in the directory: \(String(describing: error), privacy: .public)")
        }
        return crl
    }

    /// The stored CRL of `caName`, regenerated first when missing, older than `crlRefreshAge`
    /// or past its nextUpdate.
    public func currentCRL(caName: String) async throws -> CertificateRevocationList {
        let ca = try await pki.authority(named: caName)
        let now = clock()
        if let row = try await store.pkiCRL(caName: ca.name), row.thisUpdate > now.addingTimeInterval(-Self.crlRefreshAge),
           row.nextUpdate > now, let crl = try? CertificateRevocationList(derEncoded: row.der),
           crl.isSignatureValid(issuer: ca.certificate) {
            return crl
        }
        return try await generateCRL(caName: ca.name)
    }

    /// Regenerates every CA's CRL older than `maxAge` (the daily timer in `serve`). Returns the
    /// names of the CAs whose CRL was regenerated.
    @discardableResult
    public func refreshCRLs(maxAge: TimeInterval = CAService.crlRefreshAge) async throws -> [String] {
        let now = clock()
        var done: [String] = []
        for ca in try await pki.authorities() {
            let row = try await store.pkiCRL(caName: ca.name)
            let fresh = row.map { $0.thisUpdate > now.addingTimeInterval(-maxAge) && $0.nextUpdate > now } ?? false
            // A CRL signed by an older key of this CA (the lab CA was renewed) is stale too.
            let signedByThis = row.flatMap { try? CertificateRevocationList(derEncoded: $0.der) }?
                .isSignatureValid(issuer: ca.certificate) ?? false
            if !fresh || !signedByThis {
                _ = try await generateCRL(caName: ca.name)
                done.append(ca.name)
            }
        }
        return done
    }

    // MARK: - HTTP (CDP / AIA)

    /// `GET /pki/<ca>.crl` (DER CRL, `application/pkix-crl`) and `GET /pki/<ca>.crt` (DER CA
    /// certificate, `application/pkix-cert`); anything else is 404.
    public func httpResponse(method: String, path rawPath: String) async -> PKIHTTPServer.Response {
        guard method == "GET" || method == "HEAD" else {
            return .init(status: 405, contentType: "text/plain", body: Array("method not allowed\n".utf8))
        }
        var path = rawPath
        if let q = path.firstIndex(where: { $0 == "?" || $0 == "#" }) { path = String(path[..<q]) }
        path = path.removingPercentEncoding ?? path
        guard path.hasPrefix("/pki/"), !path.dropFirst(5).contains("/") else { return .notFound }
        let file = String(path.dropFirst(5))
        do {
            if file.hasSuffix(".crl") {
                let crl = try await currentCRL(caName: String(file.dropLast(4)))
                return .init(status: 200, contentType: "application/pkix-crl", body: crl.der)
            }
            if file.hasSuffix(".crt") || file.hasSuffix(".cer") {
                let ca = try await pki.authority(named: String(file.dropLast(4)))
                return .init(status: 200, contentType: "application/pkix-cert", body: try ca.der())
            }
        } catch PKIKitError.unknownCA, PKIKitError.caNotInitialized {
            return .notFound
        } catch {
            logger.error("HTTP \(path, privacy: .public): \(String(describing: error), privacy: .public)")
            return .init(status: 500, contentType: "text/plain", body: Array("internal error\n".utf8))
        }
        return .notFound
    }

    // MARK: - Helpers

    /// Lower-case hex without separators or leading `0x`.
    public static func normalizedSerial(_ text: String) -> String {
        var t = text.lowercased().replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "")
        if t.hasPrefix("0x") { t.removeFirst(2) }
        return t
    }

    static func bytes(hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var chars = Array(hex)
        if chars.count % 2 == 1 { chars.insert("0", at: 0) }
        var i = 0
        while i + 1 < chars.count {
            out.append(UInt8(String(chars[i...i + 1]), radix: 16) ?? 0)
            i += 2
        }
        return out
    }

    static func normalizedHost(_ host: String) -> String {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        return h
    }

    static func upnName(_ upn: String) throws -> GeneralName {
        .otherName(GeneralName.OtherName(
            typeID: try ASN1ObjectIdentifier(dotRepresentation: PKIOID.userPrincipalName),
            value: try ASN1Any(erasing: ASN1UTF8String(upn))))
    }

    static func upn(of name: GeneralName) -> String? {
        guard case .otherName(let other) = name, other.typeID.description == PKIOID.userPrincipalName,
              let value = other.value, let utf8 = try? ASN1UTF8String(asn1Any: value) else { return nil }
        return String(utf8)
    }

    /// `DNS:host`, `IP:addr`, `UPN:user@realm`, `email:…`, `URI:…`, `DirName:…`, `other:<oid>`.
    public static func describe(_ name: GeneralName) -> String {
        switch name {
        case .dnsName(let h): return "DNS:\(h)"
        case .ipAddress(let octets): return "IP:\(NetworkAddresses.format(Array(octets.bytes)) ?? "?")"
        case .rfc822Name(let m): return "email:\(m)"
        case .uniformResourceIdentifier(let u): return "URI:\(u)"
        case .directoryName(let dn): return "DirName:\(dn)"
        case .otherName(let other):
            if let upn = upn(of: name) { return "UPN:\(upn)" }
            return "other:\(other.typeID)"
        default: return "\(name)"
        }
    }

    static func validate(_ name: GeneralName) throws {
        switch name {
        case .dnsName(let h):
            guard LabPKI.isPlausibleHostname(normalizedHost(h)) else { throw IssuanceError.unsupportedSubjectAltName("DNS:\(h)") }
        case .ipAddress(let octets):
            guard octets.bytes.count == 4 || octets.bytes.count == 16 else {
                throw IssuanceError.unsupportedSubjectAltName(describe(name))
            }
        case .rfc822Name(let m):
            guard m.contains("@"), !m.contains(" ") else { throw IssuanceError.unsupportedSubjectAltName("email:\(m)") }
        case .uniformResourceIdentifier(let u):
            guard URL(string: u)?.scheme != nil else { throw IssuanceError.unsupportedSubjectAltName("URI:\(u)") }
        case .otherName:
            guard upn(of: name) != nil else { throw IssuanceError.unsupportedSubjectAltName(describe(name)) }
        default:
            throw IssuanceError.unsupportedSubjectAltName(describe(name))
        }
    }
}
