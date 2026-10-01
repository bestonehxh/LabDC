import AppKit
import CertConvert
import CryptoKit
import Foundation
import PKIKit
import LabDCCore
import SwiftUI
import X509

/// `--smoke` for UI-3: fills the running lab through `PKIEditor` (a second CA, signed and
/// revoked certificates, trusted roots, auto-enrollment, challenges) and renders every
/// Certificates section, the template editor, a new challenge, and the standalone converter
/// window (with files loaded the way a Dock drop loads them) into `ui-3-*.png`.
@MainActor
enum CertificatesSmoke {
    static func run(model: AppModel, out: URL) async -> Bool {
        let certs = model.certificates
        await certs.attach(model.controller)
        guard let editor = certs.editor else {
            print("smoke: ui-3: no PKI editor (server not running?)")
            return false
        }
        var written: [String] = []
        func shot<V: View>(_ name: String, width: CGFloat = 1280, height: CGFloat = 800, _ view: V) async {
            let url = out.appendingPathComponent("ui-3-\(name).png")
            let framed = view.background(Color(nsColor: .windowBackgroundColor))
                .environment(model).environment(\.smokeRendering, true)
            if await Smoke.render(framed, size: CGSize(width: width, height: height), to: url) {
                written.append(url.lastPathComponent)
            } else {
                print("smoke: ui-3: could not render \(name)")
            }
        }

        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("labdc-ui3-smoke-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        let cppmKey = P256.Signing.PrivateKey()
        var cppmPFX: [UInt8] = []
        do {
            try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
            try await editor.createCA(name: "Radius", commonName: "Sheep RADIUS CA", keyType: .rsa2048, years: 10)
            let cppm = try await editor.sign(SignRequest(csr: Array(try csrPEM(key: cppmKey, cn: "cppm.lab.sheep", dns: ["cppm.lab.sheep"]).utf8),
                                                         sourceName: "cppm.csr", templateName: "WebServer"))
            let swKey = P256.Signing.PrivateKey()
            let sw = try await editor.sign(SignRequest(csr: Array(try csrPEM(key: swKey, cn: "sw1.lab.sheep", dns: ["sw1.lab.sheep"]).utf8),
                                                       sourceName: "sw1.csr", templateName: "Device"))
            _ = try await editor.sign(SignRequest(csr: Array(try csrPEM(key: P256.Signing.PrivateKey(), cn: "imaster.lab.sheep", dns: ["imaster.lab.sheep"]).utf8),
                                                  sourceName: "imaster.csr", templateName: "WebServer"))
            try await editor.revoke(serial: sw.serial, reason: .superseded)
            try await editor.addCurrentCATrustedRoot()
            let external = try externalRoot(cn: "ClearPass RADIUS Root CA")
            _ = try await editor.addTrustedRoots(from: Array(external.utf8), fileName: "clearpass-root.pem", friendlyName: "ClearPass RADIUS CA")
            try await editor.setAutoEnrollment(true)
            _ = try await editor.newChallenge(device: "sw1", template: "Device", ttl: 86400, reusable: false)
            _ = try await editor.newChallenge(device: nil, template: "Device", ttl: 30 * 86400, reusable: true)
            // The CA issued this PFX; the converter opens it with its password.
            let key = try PrivateKeyItem(der: Array(cppmKey.derRepresentation))
            cppmPFX = try PKCS12.write(key: key, certificates: [try CertificateItem(der: cppm.der), try CertificateItem(der: cppm.caDER)],
                                       password: "Sheep!Pfx1")
            try Data(cppmPFX).write(to: temp.appendingPathComponent("cppm.pfx"))
            try Data(try CertificateItem(der: sw.der).pem.utf8).write(to: temp.appendingPathComponent("sw1.crt"))
            try Data(try PrivateKeyItem(der: Array(swKey.derRepresentation)).pem(.traditional, password: nil, legacy: false).utf8)
                .write(to: temp.appendingPathComponent("sw1.key"))
        } catch {
            print("smoke: ui-3: preparing PKI data failed: \(error)")
            return false
        }
        print("smoke: ui-3: \(editor.authorities.count) CAs, \(editor.issued.count) issued, \(editor.trustedRoots.count) trusted roots, "
              + "\(editor.challenges.count) challenges, auto-enrollment \(editor.autoEnrollment.enabled ? "on" : "off")")

        model.selection = .certificates
        for section in CertificatesSection.allCases {
            certs.section = section
            switch section {
            case .sign:
                certs.sign.reset()
                let pem = (try? csrPEM(key: P256.Signing.PrivateKey(), cn: "nce.lab.sheep", dns: ["nce.lab.sheep", "nce"])) ?? ""
                certs.sign.load(bytes: Array(pem.utf8), name: "nce.csr")
                certs.sign.templateName = "WebServer"
                await certs.sign.refresh(using: editor)
            case .issued:
                certs.issued.selection = [editor.issued.first?.serial ?? ""]
            case .converter:
                certs.converter.clear()
                certs.converter.add(bytes: cppmPFX, name: "cppm.pfx")
                if let input = certs.converter.inputs.first { certs.converter.unlock(input.id, password: "Sheep!Pfx1") }
                certs.converter.target = .preset(.clearpass)
            default:
                break
            }
            // Enrollment and the converter are long pages: taller pictures show all of them.
            await shot(section.slug, height: section == .enrollment ? 1640 : (section == .converter ? 1180 : 800), MainView())
        }

        // Sheets.
        if let computer = editor.templates.first(where: { $0.name == "Computer" }) {
            await shot("template-editor", width: 560, height: 640,
                       TemplateEditorSheet(draft: TemplateDraft(computer), groups: editor.groups) { _ in true })
        }
        certs.challenges.device = "ap1"
        try? await certs.challenges.create(using: editor)
        await shot("challenge-new", width: 460, height: 300,
                   NewChallengeSheet(model: certs, editor: editor, challenges: certs.challenges))
        certs.challenges.dismiss()
        let form = CreateCAForm(existing: editor.authorities.map(\.name))
        form.name = "Branch"
        form.keyType = .rsa3072
        await shot("create-ca", width: 460, height: 330, CreateCASheet(form: form) { _ in true })

        // The standalone window, files loaded like a Dock drop (the PFX waits for its password).
        let window = ConverterWindowController.shared
        window.model.clear()
        window.model.add(urls: ["sw1.crt", "sw1.key", "cppm.pfx"].map { temp.appendingPathComponent($0) })
        window.model.target = .preset(.switch)
        await shot("converter-window", width: 640, height: 820, ConverterWindowView(model: window.model))

        print("smoke: ui-3: wrote \(written.count) screenshots: \(written.joined(separator: ", "))")
        return written.count == CertificatesSection.allCases.count + 4
    }

    static func csrPEM(key: P256.Signing.PrivateKey, cn: String, dns: [String]) throws -> String {
        let subject = try DistinguishedName { CommonName(cn) }
        let ext = try Certificate.Extensions { SubjectAlternativeNames(dns.map { .dnsName($0) }) }
        let attributes = CertificateSigningRequest.Attributes([try .init(ExtensionRequest(extensions: ext))])
        let csr = try CertificateSigningRequest(version: .v1, subject: subject, privateKey: .init(key), attributes: attributes,
                                                signatureAlgorithm: .ecdsaWithSHA256)
        return try csr.serializeAsPEM().pemString
    }

    static func externalRoot(cn: String) throws -> String {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(cn) }
        let now = Date()
        let cert = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey), notValidBefore: now - 86400,
                                   notValidAfter: now + 86400 * 3650, issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                                   extensions: try .init { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
                                   issuerPrivateKey: .init(key))
        return try cert.serializeAsPEM().pemString
    }
}
