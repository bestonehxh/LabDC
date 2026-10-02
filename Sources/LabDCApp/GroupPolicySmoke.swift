import AppKit
import CryptoKit
import LabDCCore
import SwiftUI
import SYSVOL
import X509

/// `--smoke` part for the Group Policy page (1 Oct 2026): publishes two Wi-Fi profiles and wired
/// 802.1X, then adds a third profile that trusts another RADIUS server (a self-signed ClearPass
/// certificate, pending) without publishing (so the page shows "Changes not published yet" and
/// the primary Publish button), and renders `ui-7-*.png`: each tab
/// (`group-policy-overview|wireless|wired`) at the minimum window width, light and dark, the
/// Wi-Fi and wired profile sheets, the policy-name sheet and RADIUS ▸ Settings.
enum GroupPolicySmoke {
    @MainActor
    static func run(model: AppModel, out: URL) async -> Bool {
        let c = model.controller
        do {
            var set = Dot1XProfileSet()
            try set.save(Dot1XProfileSet.Wireless(name: "Staff", ssids: ["Staff", "Staff-5G"], security: .wpa3,
                                                  method: .tls, autoSwitch: true))
            try set.save(Dot1XProfileSet.Wireless(name: "Lab-Secure", security: .wpa3Suite192, method: .tls,
                                                  signInAs: .machine, connectHidden: true))
            set.wired = Dot1XProfileSet.Wired(method: .peapMSCHAPv2)
            try c.saveDot1XDraft(set)
            let report = try await c.publishDot1X()
            print("smoke: Group Policy published \(report.summary)")
            let cppm = try clearPassCertificate()
            set.addPendingRoot(Dot1XProfileSet.PendingRoot(der: cppm, name: "ClearPass"))
            try set.save(Dot1XProfileSet.Wireless(name: "Guest-Enterprise", security: .wpa2, method: .peapMSCHAPv2,
                                                  signInAs: .user, connectAutomatically: false,
                                                  server: .init(serverNames: ["cppm.lab.sheep"],
                                                                trustedRoot: CertificateBlob.thumbprint(cppm))))
            try c.saveDot1XDraft(set)
        } catch {
            print("smoke: Group Policy sample failed: \(error)")
            return false
        }

        var written = 0
        func shot<V: View>(_ name: String, width: CGFloat, height: CGFloat, dark: Bool = false, _ view: V) async {
            let url = out.appendingPathComponent("ui-7-\(name).png")
            if await Smoke.render(view.environment(model).environment(\.smokeRendering, true),
                                  size: CGSize(width: width, height: height), to: url,
                                  appearance: NSAppearance(named: dark ? .darkAqua : .aqua)) {
                written += 1
            } else {
                print("smoke: could not render \(name)")
            }
        }
        model.selection = .groupPolicy
        // Every tab at the window's minimum width (LabDCApp: 1260), light and dark.
        for tab in GroupPolicyTab.allCases {
            model.groupPolicyTab = tab
            await shot("group-policy-\(tab.rawValue)", width: 1260, height: 1000, MainView())
            await shot("group-policy-\(tab.rawValue)-dark", width: 1260, height: 1000, dark: true, MainView())
        }
        model.groupPolicyTab = .overview
        let staff = (await c.groupPolicySnapshot())?.draft.wireless.first
        await shot("wifi-profile-sheet", width: 680, height: 640,
                   WiFiProfileSheet(profile: staff, existing: ["Staff", "Lab-Secure", "Guest-Enterprise"], published: true) { _, _ in })
        await shot("wifi-profile-sheet-dark", width: 680, height: 640, dark: true,
                   WiFiProfileSheet(profile: staff, existing: ["Staff", "Lab-Secure", "Guest-Enterprise"], published: true) { _, _ in })
        let snapshot = await c.groupPolicySnapshot()
        await shot("wifi-profile-sheet-clearpass", width: 680, height: 760,
                   WiFiProfileSheet(profile: snapshot?.draft.wireless.last, existing: ["Staff", "Lab-Secure", "Guest-Enterprise"],
                                    certificates: snapshot?.choosableCertificates ?? []) { _, _ in })
        let wired = snapshot?.draft.wired
        await shot("wired-profile-sheet", width: 680, height: 480, WiredProfileSheet(profile: wired) { _, _ in })
        await shot("policy-name-sheet", width: 520, height: 260,
                   PolicyNameSheet(title: "Wireless policy", name: Dot1XPolicy.defaultName,
                                   description: Dot1XProfileSet.defaultDescription) { _, _ in })
        await shot("radius-settings", width: 1100, height: 720, RadiusView(tab: .settings).background(Theme.background))
        print("smoke: Group Policy \(written) screenshot(s); trust: \(snapshot?.serverLines ?? [])")
        return written == GroupPolicyTab.allCases.count * 2 + 6
    }

    /// A self-signed server certificate like the one ClearPass makes for itself.
    static func clearPassCertificate() throws -> [UInt8] {
        let key = P256.Signing.PrivateKey()
        let subject = try DistinguishedName { CommonName("cppm.lab.sheep") }
        let now = Date()
        let cert = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
                                   notValidBefore: now - 60, notValidAfter: now + 86400 * 365, issuer: subject,
                                   subject: subject, signatureAlgorithm: .ecdsaWithSHA256,
                                   extensions: try .init { SubjectAlternativeNames([.dnsName("cppm.lab.sheep")]) },
                                   issuerPrivateKey: .init(key))
        return try cert.serializeAsPEM().derBytes
    }
}
