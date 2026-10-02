import Foundation
import MSPAC
import Store
import SYSVOL
import X509

/// What a publish changed in the Configuration NC.
public struct PKIPublishReport: Sendable, Equatable {
    public var created: [DN] = []
    public var modified: [DN] = []
    public var deleted: [DN] = []

    public init() {}

    public var isNoOp: Bool { created.isEmpty && modified.isEmpty && deleted.isEmpty }

    public var lines: [String] {
        created.map { "created \($0)" } + modified.map { "updated \($0)" } + deleted.map { "removed \($0)" }
    }

    mutating func merge(_ other: PKIPublishReport) {
        created += other.created
        modified += other.modified
        deleted += other.deleted
    }
}

/// PK-5: the PKI objects an AD CS Enterprise CA keeps in
/// `CN=Public Key Services,CN=Services,<Configuration NC>` (MS-WCCE §2.2.2.11, MS-CRTD, MS-CAESO),
/// so that Windows members find our CA, trust it, and see the templates they may enrol for:
///
///     CN=Certificate Templates       pKICertificateTemplate per PK-1 template (MS-CRTD)
///     CN=Enrollment Services         pKIEnrollmentService for the current CA (MS-WCCE §2.2.2.11.2)
///     CN=Certification Authorities   certificationAuthority per CA root (PK-4's publisher)
///     CN=AIA                         certificationAuthority per CA (intermediate/issuer store)
///     CN=CDP / CN=<DC>               cRLDistributionPoint per CA with its current CRL
///     CN=OID                         msPKI-Enterprise-Oid (forest arc) + one object per template OID
///     CN=KRA                         empty container
///     CN=NTAuthCertificates          certificationAuthority, cACertificate = every LabDC CA
///
/// Every write is idempotent: an attribute is replaced only when its values differ, so a
/// republish without changes leaves the USNs alone.
public enum PKIDirectory {
    // MARK: Names

    public static func publicKeyServicesDN(configurationDN: DN) -> DN {
        CertificationAuthorityDirectory.publicKeyServicesDN(configurationDN: configurationDN)
    }

    static func child(_ configurationDN: DN, _ name: String) -> DN {
        publicKeyServicesDN(configurationDN: configurationDN).child(RDN("CN", name))
    }

    public static func certificateTemplatesDN(configurationDN: DN) -> DN { child(configurationDN, "Certificate Templates") }
    public static func enrollmentServicesDN(configurationDN: DN) -> DN { child(configurationDN, "Enrollment Services") }
    public static func aiaDN(configurationDN: DN) -> DN { child(configurationDN, "AIA") }
    public static func cdpDN(configurationDN: DN) -> DN { child(configurationDN, "CDP") }
    public static func oidDN(configurationDN: DN) -> DN { child(configurationDN, "OID") }
    public static func ntAuthDN(configurationDN: DN) -> DN { child(configurationDN, "NTAuthCertificates") }

    /// `pKIEnrollmentService` `flags`: CA_FLAG_SUPPORTS_NT_AUTHENTICATION (0x2) |
    /// CA_FLAG_CA_SERVERTYPE_ADVANCED (0x8) — what an AD CS Enterprise CA on Windows Server 2008+
    /// writes (certca.h); without 0x8 schema-2+ templates are not offered by the CA.
    public static let enrollmentServiceFlags = 10

    /// The MS-WSTEP URL PK-6 serves for a LabDC CA (named by its LabDC CA name, which is
    /// URL-safe): `https://<dc>/<CA>_CES_Kerberos/service.svc/CES`.
    public static func cesURL(dcDNSName: String, caName: String) -> String {
        "https://\(dcDNSName)/\(caName)_CES_Kerberos/service.svc/CES"
    }

    /// One `msPKI-Enrollment-Servers` value as `certutil -enrollmentServerURL <url> Kerberos 1`
    /// writes it: `<priority>\n<authentication>\n<renewal only>\n<url>\n<allow key-based renewal>`
    /// — priority 1, authentication 2 (Kerberos; 1 anonymous, 4 user name, 8 certificate),
    /// renewal-only 0, key-based renewal 0.
    public static func enrollmentServerEntry(url: String, priority: Int = 1, authentication: Int = 2,
                                             renewalOnly: Bool = false, keyBasedRenewal: Bool = false) -> String {
        "\(priority)\n\(authentication)\n\(renewalOnly ? 1 : 0)\n\(url)\n\(keyBasedRenewal ? 1 : 0)"
    }

    /// The last CN of the CA certificate's subject (nil if it has none).
    public static func commonName(_ certificate: Certificate) -> String? {
        CAService.commonNames(certificate.subject).last
    }

    /// The object name of a CA in the Configuration NC: its subject CN "sanitized" as certutil /
    /// AD CS name CA objects (MS-WCCE §3.1.1.4.1.1; PK-4's `CertificationAuthorityDirectory.objectName`).
    public static func objectName(_ ca: CertificateAuthority) throws -> String {
        CertificationAuthorityDirectory.objectName(commonName: commonName(ca.certificate),
                                                   thumbprint: CertificateBlob.thumbprint(try ca.der()))
    }

    /// AIA / CDP object names for every CA, made unique as AD CS does for a renewed key
    /// (`Name`, `Name(1)`, …) when two LabDC CAs share a CN.
    static func uniqueObjectNames(_ cas: [CertificateAuthority]) throws -> [String: String] {
        var used: [String: Int] = [:]
        var out: [String: String] = [:]
        for ca in cas.sorted(by: { $0.name < $1.name }) {
            let base = try objectName(ca)
            let n = used[base.lowercased(), default: 0]
            used[base.lowercased()] = n + 1
            out[ca.name] = n == 0 ? base : "\(base)(\(n))"
        }
        return out
    }

    // MARK: Publishing

    /// Everything a publish needs (gathered by `CAService.publishToDirectory`).
    public struct Snapshot: Sendable {
        public var authorities: [CertificateAuthority]
        /// The CA Windows enrols from (the `Enrollment Services` object); nil = none yet.
        public var current: CertificateAuthority?
        public var templates: [CertificateTemplate]
        /// The forest template arc (`CN=OID`'s `msPKI-Cert-Template-OID`).
        public var templateArc: String
        /// Latest CRL (DER) per CA name.
        public var crls: [String: [UInt8]]
        /// CAs that are not trusted (a retired root, the RSA compatibility root while switched
        /// off): AIA and CDP stay (existing certificates still chain and check revocation), but
        /// they leave `Certification Authorities` and NTAuth.
        public var untrusted: Set<String>

        public init(authorities: [CertificateAuthority], current: CertificateAuthority?, templates: [CertificateTemplate],
                    templateArc: String, crls: [String: [UInt8]], untrusted: Set<String> = []) {
            self.untrusted = untrusted
            self.authorities = authorities
            self.current = current
            self.templates = templates
            self.templateArc = templateArc
            self.crls = crls
        }
    }

    /// Brings every PKI object in line with `snapshot`.
    public static func publish(_ snapshot: Snapshot, store: DirectoryStore) async throws -> PKIPublishReport {
        let info = try await store.domainInfo()
        var w = Writer(store: store)
        try await ensureContainers(&w, info: info, arc: snapshot.templateArc)

        // CAs: Certification Authorities, AIA, CDP, NTAuth.
        let names = try uniqueObjectNames(snapshot.authorities)
        var ntAuth: [[UInt8]] = []
        var untrustedDERs: [[UInt8]] = []
        for ca in snapshot.authorities.sorted(by: { $0.name < $1.name }) {
            let der = try ca.der()
            if snapshot.untrusted.contains(ca.name) {
                untrustedDERs.append(der)
                let removed = try await CertificationAuthorityDirectory.unpublish(thumbprint: CertificateBlob.thumbprint(der), store: store)
                w.report.modified.append(contentsOf: removed)
            } else {
                ntAuth.append(der)
                let (dn, changed) = try await CertificationAuthorityDirectory.publish(
                    CACertificateInfo(der: der, commonName: commonName(ca.certificate), subject: ca.certificate.subject.description),
                    store: store)
                if changed { w.report.modified.append(dn) }
            }
            try await w.ensureCertificationAuthority(parent: aiaDN(configurationDN: info.configurationDN),
                                                     name: names[ca.name] ?? ca.name, certificates: [der],
                                                     subject: ca.certificate.subject.description)
            if let crl = snapshot.crls[ca.name] {
                try await publishCRL(&w, info: info, objectName: names[ca.name] ?? ca.name, der: crl)
            }
        }
        try await w.ensureCertificationAuthority(parent: publicKeyServicesDN(configurationDN: info.configurationDN),
                                                 name: "NTAuthCertificates", certificates: ntAuth, subject: nil,
                                                 removing: untrustedDERs)

        // Templates and their enterprise OID objects.
        try await publishTemplates(&w, info: info, templates: snapshot.templates, arc: snapshot.templateArc)

        // Enrollment Services: the current CA only (a second one would make autoenrollment pick
        // among CAs); objects of the other LabDC CAs are removed.
        let ours = Set(try snapshot.authorities.map { try $0.der() })
        let container = enrollmentServicesDN(configurationDN: info.configurationDN)
        var keep: DN?
        if let ca = snapshot.current {
            keep = try await publishEnrollmentService(&w, info: info, ca: ca,
                                                      templates: snapshot.templates.filter(\.enabled).map(\.name))
        }
        for e in try await store.search(base: container, scope: .oneLevel, attrs: ["cACertificate"])
        where e.dn.normalized != keep?.normalized && e.values("cACertificate").contains(where: ours.contains) {
            try await w.delete(e)
        }
        return w.report
    }

    /// Only the CDP object of one CA (after a CRL is regenerated).
    public static func publishCRL(caName: String, der: [UInt8], authorities: [CertificateAuthority],
                                  store: DirectoryStore) async throws -> PKIPublishReport {
        let info = try await store.domainInfo()
        var w = Writer(store: store)
        try await w.ensureContainer(parent: info.configurationDN.child(RDN("CN", "Services")), name: "Public Key Services")
        try await w.ensureContainer(parent: publicKeyServicesDN(configurationDN: info.configurationDN), name: "CDP")
        let names = try uniqueObjectNames(authorities)
        guard let name = names[caName] else { return w.report }
        try await publishCRL(&w, info: info, objectName: name, der: der)
        return w.report
    }

    static func ensureContainers(_ w: inout Writer, info: DomainInfo, arc: String) async throws {
        let pks = publicKeyServicesDN(configurationDN: info.configurationDN)
        try await w.ensureContainer(parent: info.configurationDN.child(RDN("CN", "Services")), name: "Public Key Services")
        for name in ["AIA", "CDP", "Certificate Templates", "Certification Authorities", "Enrollment Services", "KRA"] {
            try await w.ensureContainer(parent: pks, name: name)
        }
        // CN=OID is itself an msPKI-Enterprise-Oid holding the forest arc.
        try await w.ensure(parent: pks, rdn: RDN("CN", "OID"), objectClass: "msPKI-Enterprise-Oid", attributes: [
            "msPKI-Cert-Template-OID": [Array(arc.utf8)],
            "showInAdvancedViewOnly": [Array("TRUE".utf8)],
        ])
    }

    static func publishCRL(_ w: inout Writer, info: DomainInfo, objectName: String, der: [UInt8]) async throws {
        let cdp = cdpDN(configurationDN: info.configurationDN)
        try await w.ensureContainer(parent: cdp, name: info.dcName)
        try await w.ensure(parent: cdp.child(RDN("CN", info.dcName)), rdn: RDN("CN", objectName),
                           objectClass: "cRLDistributionPoint", attributes: [
                               "certificateRevocationList": [der],
                               "showInAdvancedViewOnly": [Array("TRUE".utf8)],
                           ])
    }

    static func publishTemplates(_ w: inout Writer, info: DomainInfo, templates: [CertificateTemplate],
                                 arc: String) async throws {
        let container = certificateTemplatesDN(configurationDN: info.configurationDN)
        for t in templates {
            let attrs = try TemplateDirectory.attributes(t, domainSID: info.domainSID)
            try await w.ensure(parent: container, rdn: RDN("CN", t.name), objectClass: "pKICertificateTemplate",
                               attributes: attrs, remove: TemplateDirectory.optionalAttributes.filter { attrs[$0] == nil })
        }
        // Templates deleted from the store: their objects (recognised by an OID under our arc) go.
        let names = Set(templates.map { $0.name.lowercased() })
        for e in try await w.store.search(base: container, scope: .oneLevel, attrs: ["cn", "msPKI-Cert-Template-OID"])
        where !names.contains((e.dn.rdn?.value ?? "").lowercased())
            && (e.string("msPKI-Cert-Template-OID") ?? "").hasPrefix(arc + ".") {
            try await w.delete(e)
        }

        let oidContainer = oidDN(configurationDN: info.configurationDN)
        for t in templates {
            try await w.ensure(parent: oidContainer, rdn: RDN("CN", TemplateDirectory.oidObjectName(t.oid)),
                               objectClass: "msPKI-Enterprise-Oid", attributes: [
                                   "displayName": [Array(t.displayName.utf8)],
                                   "flags": [Array(String(TemplateDirectory.oidTypeTemplate).utf8)],
                                   "msPKI-Cert-Template-OID": [Array(t.oid.utf8)],
                                   "showInAdvancedViewOnly": [Array("TRUE".utf8)],
                               ])
        }
        let oids = Set(templates.map(\.oid))
        for e in try await w.store.search(base: oidContainer, scope: .oneLevel, attrs: ["flags", "msPKI-Cert-Template-OID"]) {
            guard let oid = e.string("msPKI-Cert-Template-OID"), oid.hasPrefix(arc + "."), !oids.contains(oid),
                  e.int("flags") == Int64(TemplateDirectory.oidTypeTemplate) else { continue }
            try await w.delete(e)
        }
    }

    /// The enrollment service SD: full control for Enterprise Admins, Domain Admins and SYSTEM,
    /// Read and Enroll for Authenticated Users (who may request from the CA is decided per
    /// template).
    public static let enrollmentServiceSDDL = "O:EAG:EAD:PAI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)"
        + "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        + "(OA;;CR;\(TemplateDirectory.enrollRight);;AU)"

    static func publishEnrollmentService(_ w: inout Writer, info: DomainInfo, ca: CertificateAuthority,
                                         templates: [String]) async throws -> DN {
        func s(_ v: String) -> [UInt8] { Array(v.utf8) }
        let cn = commonName(ca.certificate) ?? ca.name
        var attrs: [String: [[UInt8]]] = [
            "displayName": [s(cn)],
            "cACertificate": [try ca.der()],
            "cACertificateDN": [s(ca.certificate.subject.description)],
            "dNSHostName": [s(info.dcDNSName)],
            "flags": [s(String(enrollmentServiceFlags))],
            "msPKI-Enrollment-Servers": [s(enrollmentServerEntry(url: cesURL(dcDNSName: info.dcDNSName, caName: ca.name)))],
            "msPKI-Site-Name": [s(info.site)],
            "showInAdvancedViewOnly": [s("TRUE")],
            "nTSecurityDescriptor": [try SecurityDescriptor.fromSDDL(enrollmentServiceSDDL, domainSID: info.domainSID)],
        ]
        if !templates.isEmpty { attrs["certificateTemplates"] = templates.map(s) }
        return try await w.ensure(parent: enrollmentServicesDN(configurationDN: info.configurationDN),
                                  rdn: RDN("CN", try objectName(ca)), objectClass: "pKIEnrollmentService",
                                  attributes: attrs, remove: templates.isEmpty ? ["certificateTemplates"] : [])
    }

    // MARK: Writer

    struct Writer {
        let store: DirectoryStore
        var report = PKIPublishReport()

        /// Creates the object, or replaces the attributes in `attributes` whose values differ and
        /// clears those in `remove`. `initial` is only written on creation.
        @discardableResult
        mutating func ensure(parent: DN, rdn: RDN, objectClass: String, attributes: [String: [[UInt8]]],
                             initial: [String: [[UInt8]]] = [:], remove: [String] = []) async throws -> DN {
            let dn = parent.child(rdn)
            guard let existing = try await store.read(dn: dn) else {
                try await store.create(parent: parent, rdn: rdn, objectClass: objectClass,
                                       attributes: initial.merging(attributes) { _, new in new })
                report.created.append(dn)
                return dn
            }
            var ops: [ModifyOp] = []
            for (name, values) in attributes.sorted(by: { $0.key < $1.key }) where existing.values(name) != values {
                ops.append(.replace(name, values))
            }
            for name in remove where existing.has(name) { ops.append(.replace(name, [])) }
            if !ops.isEmpty {
                try await store.update(id: existing.id, ops: ops)
                report.modified.append(dn)
            }
            return dn
        }

        mutating func ensureContainer(parent: DN, name: String) async throws {
            if try await store.id(of: parent.child(RDN("CN", name))) != nil { return }
            try await ensure(parent: parent, rdn: RDN("CN", name), objectClass: "container",
                             attributes: ["showInAdvancedViewOnly": [Array("TRUE".utf8)]])
        }

        /// A `certificationAuthority` object (AIA entry, NTAuthCertificates) holding at least
        /// `certificates` in `cACertificate`: values already there (renewed or foreign CAs) are
        /// kept, missing ones appended. authorityRevocationList / certificateRevocationList are
        /// mustContain; they get one NUL byte on creation, as `certutil -dspublish` writes them.
        /// Adds `certificates` (values added by hand stay) and drops `removing` (an untrusted LabDC CA).
        mutating func ensureCertificationAuthority(parent: DN, name: String, certificates: [[UInt8]],
                                                   subject: String?, removing: [[UInt8]] = []) async throws {
            let existing = try await store.read(dn: parent.child(RDN("CN", name)), attrs: ["cACertificate"])
            var values = existing?.values("cACertificate") ?? []
            values.removeAll { removing.contains($0) }
            for der in certificates where !values.contains(der) { values.append(der) }
            var initial: [String: [[UInt8]]] = ["authorityRevocationList": [[0]], "certificateRevocationList": [[0]]]
            if let subject { initial["cACertificateDN"] = [Array(subject.utf8)] }
            try await ensure(parent: parent, rdn: RDN("CN", name), objectClass: "certificationAuthority", attributes: [
                "cACertificate": values,
                "showInAdvancedViewOnly": [Array("TRUE".utf8)],
            ], initial: initial)
        }

        mutating func delete(_ entry: DirectoryEntry) async throws {
            try await store.delete(id: entry.id)
            report.deleted.append(entry.dn)
        }
    }
}

// MARK: - CAService hooks

extension CAService {
    /// Re-publishes every PKI object in the Configuration NC (`labdc pki publish`, `serve`
    /// start, `ca create` / `ca use`, template changes). CRLs come from the store as they are
    /// (nothing is regenerated here).
    @discardableResult
    public func publishToDirectory() async throws -> PKIPublishReport {
        let authorities = try await pki.authorities()
        let current = try? await pki.currentAuthority()
        var crls: [String: [UInt8]] = [:]
        for ca in authorities {
            if let row = try await store.pkiCRL(caName: ca.name) { crls[ca.name] = row.der }
        }
        let trusted = Set(try await trustedAuthorities().map(\.name))
        let snapshot = PKIDirectory.Snapshot(authorities: authorities, current: current, templates: try await templates(),
                                             templateArc: try await templateArc(), crls: crls,
                                             untrusted: Set(authorities.map(\.name)).subtracting(trusted))
        return try await PKIDirectory.publish(snapshot, store: store)
    }

    /// The CDP object of `caName` after its CRL was regenerated.
    @discardableResult
    func publishCRLToDirectory(caName: String, der: [UInt8]) async throws -> PKIPublishReport {
        try await PKIDirectory.publishCRL(caName: caName, der: der, authorities: try await pki.authorities(), store: store)
    }
}
