import Foundation
import PKIKit
import Store
import SYSVOL

/// "Change the lab CA key…" / `labdc ca migrate --key p256|p384 [--now]` (1 Oct 2026). A root is
/// never re-keyed in place and no key is ever deleted: a new root of the chosen key type is
/// created next to the current one and becomes the issuing CA (`CAService.migrateCurrentCA`).
///
/// One-step switch (the default, `keepOldTrusted: false`): the DC certificate (LDAPS, HTTPS,
/// RADIUS/EAP) is reissued from the new root at once; only the new root is in the Default Domain
/// Policy's trusted roots, `Certification Authorities` and NTAuth; the published 802.1X profiles
/// trust (and filter client certificates by) the new root only; the GPO versions are bumped; the
/// auto-enrollment templates' major version is bumped so joined Windows PCs re-enrol their
/// machine and user certificates from the new root. The old root is retired: EAP-TLS no longer
/// accepts its client certificates, its CRL keeps being published.
///
/// Transition (`keepOldTrusted: true`): the same, but the old root stays trusted everywhere
/// (both roots in the GPO, NTAuth and the 802.1X profiles) until `retire` — for networks where
/// devices cannot re-enrol at once.
public enum LabCASwitch {
    public struct Report: Sendable {
        public let from: String
        public let to: String
        public let keyType: CAKeyType
        public let dcCertificateReissued: Bool
        /// 802.1X profiles (wireless + wired) rewritten.
        public let dot1xProfilesUpdated: Int
        /// Templates whose holders Windows re-enrols.
        public let reenrollTemplates: [String]
        public let oldRootKeptTrusted: Bool
        /// Certificates of the old root still active (they stop working for EAP-TLS when it is retired).
        public let stillActiveOnOldRoot: Int
    }

    public static func change(to keyType: CAKeyType, keepOldTrusted: Bool, data: DataDirectory, pki: LabPKI,
                              store: DirectoryStore, service: CAService, log: @Sendable (String) -> Void) async throws -> Report {
        let migration = try await service.migrateCurrentCA(to: keyType)
        let old = migration.from, new = migration.to
        log("new root \(new.name) (\(keyType.displayName), \(new.certificate.subject)) now issues; \(old.name) "
            + (keepOldTrusted ? "stays trusted until it is retired" : "is retired"))

        // The DC certificate (LDAPS, HTTPS, RADIUS/EAP) from the new root, same names.
        let info = try await store.domainInfo()
        var names = LabPKI.defaultServerNames(dcHostname: info.dcDNSName, dnsDomain: info.dnsDomain)
        if let sans = try? await pki.serverSubjectAltNames(), !sans.hostnames.isEmpty { names = sans }
        let reissued = try await pki.ensureServerCertificate(hostnames: names.hostnames, ips: names.ips) == .issued
        if let dc = try? await pki.serverCertificate() {
            let dcSID = try? await store.read(dn: info.dcComputerDN)?.sid?.description
            try? await service.record(dc, caName: new.name, templateName: "DomainControllerTLS",
                                      requester: RequesterIdentity(name: info.dcName.uppercased() + "$", sid: dcSID))
        }
        log("DC certificate (LDAPS, HTTPS, RADIUS) \(reissued ? "reissued" : "kept") from \(new.name)")

        // Group Policy: the new root in the trusted roots; the 802.1X profiles follow.
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        let newDER = try new.der(), oldDER = try old.der()
        let newThumb = CertificateBlob.thumbprint(newDER), oldThumb = CertificateBlob.thumbprint(oldDER)
        let cn = ServerController.commonName(new.certificate.subject)
        let added = try await editor.addTrustedRoot(CACertificateInfo(der: newDER, commonName: cn, subject: new.certificate.subject.description),
                                                    friendlyName: cn)
        try await store.setDomainValue(newThumb, forKey: ServerController.publishedCAKey)
        log("trusted root \(newThumb) in Default Domain Policy (version \(added.edit.version.raw))")
        let profiles = try await editor.rewriteDot1XTrustedRoots(whereListed: oldThumb, adding: [newThumb],
                                                                 removing: keepOldTrusted ? [] : [oldThumb])
        if profiles > 0 { log("802.1X profiles: \(profiles) now trust \(keepOldTrusted ? "both roots" : new.name)") }
        if !migration.reenrollTemplates.isEmpty {
            log("templates \(migration.reenrollTemplates.joined(separator: ", ")): new major version, Windows re-enrolls their holders")
        }

        var active = try await service.activeCertificates(caName: old.name).count
        if !keepOldTrusted {
            active = try await retire(name: old.name, data: data, pki: pki, store: store, service: service, log: log).count
        }
        return Report(from: old.name, to: new.name, keyType: keyType, dcCertificateReissued: reissued, dot1xProfilesUpdated: profiles,
                      reenrollTemplates: migration.reenrollTemplates, oldRootKeptTrusted: keepOldTrusted, stillActiveOnOldRoot: active)
    }

    /// "Retire the old root…": out of the Default Domain Policy's trusted roots, `Certification
    /// Authorities`, NTAuth and the 802.1X profiles; EAP-TLS refuses its client certificates.
    /// Its key, certificate and CRL stay. Returns its certificates that are still active.
    @discardableResult
    public static func retire(name: String, data: DataDirectory, pki: LabPKI, store: DirectoryStore, service: CAService,
                              log: @Sendable (String) -> Void) async throws -> [IssuedCertificate] {
        let ca = try await pki.authority(named: name)
        let active = try await service.retireCA(name: ca.name)
        let thumb = CertificateBlob.thumbprint(try ca.der())
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        do {
            let change = try await editor.removeTrustedRoot(thumbprint: thumb)
            log("trusted root \(thumb) removed from Default Domain Policy (version \(change.edit.version.raw))")
        } catch GroupPolicyError.unknownThumbprint {}
        let profiles = try await editor.rewriteDot1XTrustedRoots(whereListed: thumb, adding: [], removing: [thumb])
        if profiles > 0 { log("802.1X profiles: \(profiles) no longer trust \(ca.name)") }
        log("retired root \(ca.name): no longer trusted (NTAuth, EAP-TLS); \(active.count) certificate(s) it issued are still unexpired; its CRL keeps being published")
        return active
    }
}
