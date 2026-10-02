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
///
/// WPA3-Enterprise 192-bit (review, 2 Oct 2026): a P-384 root serves 192-bit itself. Switching
/// it to P-256 while 192-bit is in use moves 192-bit to the P-384 802.1X 192-bit CA
/// (`dot1x-suiteb`, created before the switch): the 192-bit Wi-Fi profiles trust that CA (never
/// the P-256 root), it serves the 192-bit RADIUS certificate, and Computer192 / User192 are
/// bumped so their holders re-enrol from it. The one-step switch is refused while Computer192 /
/// User192 certificates of the old root are still active (retiring it would cut those PCs off
/// 192-bit Wi-Fi until they re-enrol): use the transition and retire once they have. The same
/// holds for a new P-384 root (root renewal): it serves 192-bit itself, Computer192 / User192
/// are bumped, the 192-bit profiles trust the new root and the old one until it is retired.
/// Whether the old root served 192-bit is decided before the switch and written down in the
/// migration (`CAService.MigrationRecord.suiteB`).
///
/// A switch that failed half-way is finished by running it again with the same key type: inside
/// the migration (`CAService.migrateCurrentCA` resumes it: new root, switch, template bump,
/// directory publish) or after its commit (the new root already current, Group Policy not
/// updated yet).
public enum LabCASwitch {
    public struct Report: Sendable {
        public let from: String
        public let to: String
        public let keyType: CAKeyType
        public let dcCertificateReissued: Bool
        /// 802.1X policy objects (wireless + wired) rewritten.
        public let dot1xProfilesUpdated: Int
        /// Templates whose holders Windows re-enrols.
        public let reenrollTemplates: [String]
        public let oldRootKeptTrusted: Bool
        /// Certificates of the old root still active (they stop working for EAP-TLS when it is retired).
        public let stillActiveOnOldRoot: Int
        /// The 802.1X 192-bit CA that WPA3-Enterprise 192-bit moved to (old root P-384, new one not).
        public let suiteBAuthority: String?
        /// This run finished a switch that had failed after the new root became current.
        public let resumed: Bool
    }

    /// Where a switch stands (fault injection in tests).
    enum Step: Sendable { case committed, dcCertificate, trustedRoot, profiles }

    public static func change(to keyType: CAKeyType, keepOldTrusted: Bool, data: DataDirectory, pki: LabPKI,
                              store: DirectoryStore, service: CAService, log: @Sendable (String) -> Void) async throws -> Report {
        try await change(to: keyType, keepOldTrusted: keepOldTrusted, data: data, pki: pki, store: store, service: service,
                         log: log, checkpoint: { _ in })
    }

    static func change(to keyType: CAKeyType, keepOldTrusted: Bool, data: DataDirectory, pki: LabPKI,
                       store: DirectoryStore, service: CAService, log: @Sendable (String) -> Void,
                       allowSameKeyType: Bool = false,
                       checkpoint: @Sendable (Step) throws -> Void) async throws -> Report {
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        let current = try await pki.currentAuthority()
        let old: CertificateAuthority, new: CertificateAuthority
        let reenroll: [String]
        var resumed = false
        let record = try await service.migrationRecord()
        if let record, let to = record.to, record.isCommitted, to.lowercased() == current.name.lowercased(),
           current.keyType == keyType {
            // The new root is already current: a previous run stopped before Group Policy was
            // done. Every step below is idempotent; finish them.
            old = try await pki.authority(named: record.from)
            new = current
            if let plan = record.reenroll {
                reenroll = plan.keys.sorted()
            } else {
                reenroll = try await service.templates()
                    .filter { $0.enabled && $0.autoEnroll && $0.majorRevision > CertificateTemplate.majorVersion }.map(\.name)
            }
            resumed = true
            log("resuming the switch from \(old.name) to \(new.name) (\(keyType.displayName)): \(new.name) already issues")
        } else {
            // The old root served WPA3-Enterprise 192-bit itself (decided before any switch,
            // also for a migration that stopped half-way): retiring it in one step would cut its
            // Computer192 / User192 holders off 192-bit Wi-Fi, whatever the new key type.
            if !keepOldTrusted, try await service.currentRootServesSuiteB() {
                let oldName = record.flatMap { $0.to != nil && !$0.isCommitted ? $0.from : nil } ?? current.name
                let held = try await service.activeCertificates(caName: oldName)
                    .filter { CAService.suiteBTemplateNames.contains($0.templateName) }
                if !held.isEmpty {
                    let reenrolFrom = keyType == .p384 ? "the new root" : "the 802.1X 192-bit CA"
                    throw PKIKitError.encoding("\(oldName) (P-384) serves WPA3-Enterprise 192-bit and \(held.count) Computer192 / User192 "
                        + "certificate(s) it issued are still active: switching to a new \(keyType.displayName) root in one step would retire it and "
                        + "cut those PCs off 192-bit Wi-Fi until they re-enrol. Keep the old root trusted (transition), then retire it "
                        + "once they have re-enrolled from \(reenrolFrom).")
                }
            }
            let suiteBProfiles = try await editor.publishedDot1XPolicies().contains(where: Dot1XPolicy.containsSuiteBProfile)
            let migration = try await service.migrateCurrentCA(to: keyType, suiteBInUse: suiteBProfiles, allowSameKeyType: allowSameKeyType)
            old = migration.from
            new = migration.to
            reenroll = migration.reenrollTemplates
            resumed = migration.resumed
            if resumed { log("finished the migration from \(old.name) to \(new.name) that had stopped half-way") }
            if let suiteB = migration.suiteBCreated {
                log("802.1X 192-bit CA \(suiteB.name) (P-384) created: WPA3-Enterprise 192-bit stays on a P-384 root")
            }
        }
        try checkpoint(.committed)
        log("new root \(new.name) (\(keyType.displayName), \(new.certificate.subject)) now issues; \(old.name) "
            + (keepOldTrusted ? "stays trusted until it is retired" : "is retired"))

        // The DC certificate (LDAPS, HTTPS, RADIUS/EAP) from the new root, same names.
        let info = try await store.domainInfo()
        let dcSID = try? await store.read(dn: info.dcComputerDN)?.sid?.description
        let dcRequester = RequesterIdentity(name: info.dcName.uppercased() + "$", sid: dcSID)
        var names = LabPKI.defaultServerNames(dcHostname: info.dcDNSName, dnsDomain: info.dnsDomain)
        if let sans = try? await pki.serverSubjectAltNames(), !sans.hostnames.isEmpty { names = sans }
        let reissued = try await pki.ensureServerCertificate(hostnames: names.hostnames, ips: names.ips) == .issued
        if let dc = try? await pki.serverCertificate() {
            try? await service.record(dc, caName: new.name, templateName: "DomainControllerTLS", requester: dcRequester)
        }
        log("DC certificate (LDAPS, HTTPS, RADIUS) \(reissued ? "reissued" : "kept") from \(new.name)")
        try checkpoint(.dcCertificate)

        // Group Policy: the new root in the trusted roots; the 802.1X profiles follow.
        let newDER = try new.der(), oldDER = try old.der()
        let newThumb = CertificateBlob.thumbprint(newDER), oldThumb = CertificateBlob.thumbprint(oldDER)
        let cn = ServerController.commonName(new.certificate.subject)
        let added = try await editor.addTrustedRoot(CACertificateInfo(der: newDER, commonName: cn, subject: new.certificate.subject.description),
                                                    friendlyName: cn)
        try await store.setDomainValue(newThumb, forKey: ServerController.publishedCAKey)
        log("trusted root \(newThumb) in Default Domain Policy (version \(added.edit.version.raw))")
        try checkpoint(.trustedRoot)

        // WPA3-Enterprise 192-bit leaves a P-384 root for the P-384 802.1X 192-bit CA (this
        // migration created it). A new P-384 root serves 192-bit itself: the 192-bit profiles
        // follow it like the others (the old root too, until it is retired).
        var suiteBThumb: String?
        var suiteBName: String?
        let committed = try await service.migrationRecord()
        let suiteBMoved: Bool
        if let committed, committed.committed != nil {
            suiteBMoved = committed.suiteB == CAService.MigrationRecord.suiteBCreated
        } else {
            // A migration written down before 2 Oct 2026.
            let hasSuiteB = try await pki.hasSuiteBCA()
            suiteBMoved = old.keyType == .p384 && new.keyType != .p384 && hasSuiteB
        }
        if suiteBMoved {
            let suiteB = try await pki.authority(named: LabPKI.suiteBCAName)
            let der = try suiteB.der()
            let suiteCN = ServerController.commonName(suiteB.certificate.subject)
            _ = try await editor.addTrustedRoot(CACertificateInfo(der: der, commonName: suiteCN, subject: suiteB.certificate.subject.description),
                                                friendlyName: suiteCN)
            suiteBThumb = CertificateBlob.thumbprint(der)
            suiteBName = suiteB.name
            if try await pki.ensureSuiteBServerCertificate(hostname: info.dcDNSName) == .issued,
               let radius = await pki.suiteBServerCertificate() {
                try? await service.record(radius, caName: LabPKI.suiteBCAName, templateName: "RadiusServerSuiteB", requester: dcRequester)
            }
            log("WPA3-Enterprise 192-bit: RADIUS certificate and 192-bit profiles on \(suiteB.name) (P-384), not \(new.name)")
        }
        let removing = keepOldTrusted ? [] : [oldThumb]
        let profiles: Int
        if let suiteBThumb {
            // One count per policy object (the WPA2 and 192-bit profiles share a <WLANPolicy>).
            profiles = try await editor.rewriteDot1XTrustedRoots([
                Dot1XTrustRewrite(whereListed: oldThumb, adding: [newThumb], removing: removing, suiteB: false),
                Dot1XTrustRewrite(whereListed: oldThumb, adding: [suiteBThumb], removing: removing, suiteB: true),
            ])
        } else {
            profiles = try await editor.rewriteDot1XTrustedRoots(whereListed: oldThumb, adding: [newThumb], removing: removing)
        }
        if profiles > 0 { log("802.1X profiles: \(profiles) now trust \(keepOldTrusted ? "both roots" : new.name)") }
        try checkpoint(.profiles)
        if !reenroll.isEmpty {
            log("templates \(reenroll.joined(separator: ", ")): new major version, Windows re-enrolls their holders")
        }

        var active = try await service.activeCertificates(caName: old.name).count
        if !keepOldTrusted {
            active = try await retire(name: old.name, data: data, pki: pki, store: store, service: service, log: log).count
        }
        return Report(from: old.name, to: new.name, keyType: keyType, dcCertificateReissued: reissued, dot1xProfilesUpdated: profiles,
                      reenrollTemplates: reenroll, oldRootKeptTrusted: keepOldTrusted, stillActiveOnOldRoot: active,
                      suiteBAuthority: suiteBName, resumed: resumed)
    }

    /// "Retire the old root…": out of the Default Domain Policy's trusted roots, `Certification
    /// Authorities`, NTAuth and the 802.1X profiles; EAP-TLS refuses its client certificates.
    /// Its key, certificate and CRL stay. Returns its certificates that are still active.
    /// Group Policy is edited first and the root marked retired last, so a failure in between
    /// leaves the migration open and `change` / `retire` can be run again.
    @discardableResult
    public static func retire(name: String, data: DataDirectory, pki: LabPKI, store: DirectoryStore, service: CAService,
                              log: @Sendable (String) -> Void) async throws -> [IssuedCertificate] {
        let ca = try await pki.authority(named: name)
        guard ca.name != (try await pki.currentAuthority()).name else {
            throw PKIKitError.encoding("\(ca.name) is the current CA: it cannot be retired")
        }
        let thumb = CertificateBlob.thumbprint(try ca.der())
        let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
        do {
            let change = try await editor.removeTrustedRoot(thumbprint: thumb)
            log("trusted root \(thumb) removed from Default Domain Policy (version \(change.edit.version.raw))")
        } catch GroupPolicyError.unknownThumbprint {}
        let profiles = try await editor.rewriteDot1XTrustedRoots(whereListed: thumb, adding: [], removing: [thumb])
        if profiles > 0 { log("802.1X profiles: \(profiles) no longer trust \(ca.name)") }
        let active = try await service.retireCA(name: ca.name)
        log("retired root \(ca.name): no longer trusted (NTAuth, EAP-TLS); \(active.count) certificate(s) it issued are still unexpired; its CRL keeps being published")
        return active
    }
}
