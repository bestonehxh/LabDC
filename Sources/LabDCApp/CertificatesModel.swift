import AppKit
import CertConvert
import Foundation
import Observation
import PKIKit
import LabDCCore
import Store
import UniformTypeIdentifiers
import X509

/// The Certificates page's sections, in sidebar order.
enum CertificatesSection: String, CaseIterable, Identifiable, Hashable {
    case ca, issued, sign, templates, trustedRoots, enrollment, converter

    var id: String { rawValue }

    var title: String {
        switch self {
        case .ca: "Authority"
        case .issued: "Issued"
        case .sign: "Sign a request"
        case .templates: "Templates"
        case .trustedRoots: "Trusted roots"
        case .enrollment: "Enrollment"
        case .converter: "Converter"
        }
    }

    var symbol: String {
        switch self {
        case .ca: "checkmark.seal"
        case .issued: "list.bullet.rectangle.portrait"
        case .sign: "signature"
        case .templates: "doc.on.doc"
        case .trustedRoots: "building.columns"
        case .enrollment: "arrow.down.doc"
        case .converter: "arrow.triangle.2.circlepath"
        }
    }

    /// The smoke screenshot name (`ui-3-<slug>.png`).
    var slug: String {
        switch self {
        case .ca: "ca"
        case .issued: "issued"
        case .sign: "sign-csr"
        case .templates: "templates"
        case .trustedRoots: "trusted-roots"
        case .enrollment: "enrollment"
        case .converter: "converter"
        }
    }
}

/// State of the Certificates page: the section, the `PKIEditor` of the running server and each
/// section's view model. Lives in `AppModel` so switching pages keeps it.
@MainActor @Observable
final class CertificatesModel {
    var section: CertificatesSection = .ca
    private(set) var editor: PKIEditor?
    /// A failed action, shown as an alert.
    var alert: String?
    /// A one-line result ("Added ClearPass Root CA."), shown under the section.
    var notice: String?
    /// Bumped after each successful mutation (the "Saved" pill).
    private(set) var savedGeneration = 0

    let issued = IssuedFilterModel()
    let sign = SignCSRModel()
    let challenges = ChallengeRevealModel()
    let converter = ConverterModel()

    /// Creates (or keeps) the editor for the running server; nil while it is stopped.
    func attach(_ controller: ServerController) async {
        guard let store = controller.store, let pki = controller.pki, let runtime = controller.runtime,
              let service = await runtime.caService else {
            editor?.stopFollowing()
            editor = nil
            return
        }
        let endpoints = PKIEndpoints.from(status: controller.status)
        if let editor, editor.store === store {
            if let endpoints, endpoints != editor.endpoints { editor.endpoints = endpoints }
            return
        }
        editor?.stopFollowing()
        let info = try? await store.domainInfo()
        let e = PKIEditor(data: controller.data, pki: pki, store: store, service: service,
                          endpoints: endpoints ?? PKIEndpoints(dcDNSName: info?.dcDNSName ?? "localhost"),
                          log: controller.serveLog)
        e.reissueDCCertificate = { [weak controller] in await controller?.restartToApply() }
        e.follow(controller.logs)
        await e.reload()
        use(e)
    }

    /// Uses an editor directly (tests, the smoke run).
    func use(_ e: PKIEditor) {
        editor = e
        converter.caProvider = { [weak e] in
            guard let e else { return [] }
            return e.authorities.compactMap { try? CertificateItem(der: $0.der) }
        }
    }

    /// Runs a mutation: errors become the alert, success bumps the Saved pill.
    @discardableResult
    func perform(_ what: String, _ action: (PKIEditor) async throws -> Void) async -> Bool {
        guard let editor else {
            alert = "\(what) needs the server to be running."
            return false
        }
        do {
            try await action(editor)
            savedGeneration += 1
            return true
        } catch {
            alert = "\(what) failed: \(Self.describe(error))"
            return false
        }
    }

    static func describe(_ error: Error) -> String {
        if let e = error as? CLIError, case .failure(let text) = e { return text }
        return "\(error)"
    }
}

// MARK: - CA

/// "Create CA…" sheet: name, CN, key type, years.
@MainActor @Observable
final class CreateCAForm {
    var name = ""
    var commonName = ""
    var keyType: CAKeyType = .p256
    var years = 10
    var existing: [String] = []

    init(existing: [String] = []) {
        self.existing = existing
    }

    /// The CN when left empty: `<name> CA`.
    var effectiveCommonName: String {
        let cn = commonName.trimmingCharacters(in: .whitespaces)
        return cn.isEmpty ? "\(name.trimmingCharacters(in: .whitespaces)) CA" : cn
    }

    /// Why Create is disabled (nil = OK).
    var problem: String? {
        let n = name.trimmingCharacters(in: .whitespaces)
        if n.isEmpty { return "Give the CA a short name." }
        if !LabPKI.isValidCAName(n) {
            return "Use letters, digits, “.”, “_” or “-” only (the name is part of the CRL address)."
        }
        if n.lowercased() == LabPKI.labCAName || existing.contains(where: { $0.lowercased() == n.lowercased() }) {
            return "A CA named “\(n)” already exists."
        }
        if !(1...50).contains(years) { return "Validity is 1 to 50 years." }
        return nil
    }

    var keyTypeHint: String {
        switch keyType {
        case .p256: "P-256: small and fast; every current device accepts it."
        case .p384: "P-384 / SHA-384: for WPA3-Enterprise 192-bit (the whole chain must be P-384)."
        case .rsa2048: "RSA-2048: for devices that only accept RSA chains."
        case .rsa3072: "RSA-3072: RSA with a longer key (slower, same compatibility)."
        }
    }
}

// MARK: - Issued

/// Issued ▸ search + status + template filter.
@MainActor @Observable
final class IssuedFilterModel {
    enum Status: String, CaseIterable, Identifiable {
        case all = "All", valid = "Valid", expired = "Expired", revoked = "Revoked"
        var id: String { rawValue }
    }

    var search = ""
    var status: Status = .all
    /// nil = every template.
    var template: String?
    var selection: Set<String> = []

    func rows(_ issued: [IssuedCertificate], now: Date = Date()) -> [IssuedRow] {
        IssuedRow.filter(issued, search: search, status: status, template: template, now: now)
    }
}

/// One line of the Issued table.
struct IssuedRow: Identifiable, Equatable {
    enum State: Equatable {
        case valid, expired, revoked(RevocationReason?)
    }

    var id: String { serial }
    let serial: String
    let template: String
    let subject: String
    let names: String
    let requester: String
    let issued: Date
    let expires: Date
    let caName: String
    let state: State

    init(_ r: IssuedCertificate, now: Date) {
        serial = r.serial
        template = r.templateName
        subject = r.subject
        names = r.subjectAltNames.joined(separator: ", ")
        requester = r.requesterName
        issued = r.issuedAt
        expires = r.notAfter
        caName = r.caName
        state = r.revoked ? .revoked(r.reason) : (r.notAfter <= now ? .expired : .valid)
    }

    /// `3F2A…91C0` (the table column; the full serial is copyable).
    var shortSerial: String {
        serial.count <= 12 ? serial.uppercased() : (serial.prefix(6) + "…" + serial.suffix(4)).uppercased()
    }

    var statusText: String {
        switch state {
        case .valid: "Valid"
        case .expired: "Expired"
        case .revoked(let reason): "Revoked" + (reason.map { $0 == .unspecified ? "" : " (\(PKIText.reason($0)))" } ?? "")
        }
    }

    /// "Valid", "Expired", "Revoked": the table's column (the reason is in `statusText`).
    var statusWord: String {
        switch state {
        case .valid: "Valid"
        case .expired: "Expired"
        case .revoked: "Revoked"
        }
    }

    var isRevoked: Bool { if case .revoked = state { true } else { false } }

    /// The subject's CN for file names (`CN=ws1.lab.sheep,O=Sheep` → `ws1.lab.sheep`), else the serial.
    var fileBaseName: String {
        for part in subject.split(separator: ",") {
            let p = part.trimmingCharacters(in: .whitespaces)
            if p.uppercased().hasPrefix("CN=") {
                let cn = String(p.dropFirst(3)).replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
                if !cn.isEmpty { return cn }
            }
        }
        return serial.uppercased()
    }

    static func filter(_ rows: [IssuedCertificate], search: String, status: IssuedFilterModel.Status, template: String?,
                       now: Date) -> [IssuedRow] {
        let words = search.lowercased().split(separator: " ").map(String.init)
        return rows.map { IssuedRow($0, now: now) }.filter { row in
            switch status {
            case .all: break
            case .valid: guard row.state == .valid else { return false }
            case .expired: guard row.state == .expired else { return false }
            case .revoked: guard row.isRevoked else { return false }
            }
            if let template, row.template.lowercased() != template.lowercased() { return false }
            guard !words.isEmpty else { return true }
            let hay = [row.serial, row.subject, row.names, row.requester, row.template, row.caName].joined(separator: " ").lowercased()
            let compactSerial = row.serial.lowercased()
            return words.allSatisfy { w in
                hay.contains(w) || compactSerial.contains(w.replacingOccurrences(of: ":", with: ""))
            }
        }
    }
}

// MARK: - Enrollment challenges

/// New challenge… form and the one-time display of its text.
@MainActor @Observable
final class ChallengeRevealModel {
    enum TTL: TimeInterval, CaseIterable, Identifiable {
        case hour = 3600, day = 86400, week = 604_800, month = 2_592_000
        var id: TimeInterval { rawValue }
        var title: String { PKIText.duration(rawValue) }
    }

    var device = ""
    var template = CAService.defaultDeviceTemplate
    var ttl: TTL = .day
    var reusable = false
    /// The challenge just made; its text is shown once and dropped by `dismiss()`.
    private(set) var revealed: NewChallenge?
    var selection: Set<String> = []

    var deviceName: String? {
        let d = device.trimmingCharacters(in: .whitespaces)
        return d.isEmpty ? nil : d
    }

    func create(using editor: PKIEditor) async throws {
        revealed = try await editor.newChallenge(device: deviceName, template: template, ttl: ttl.rawValue, reusable: reusable)
    }

    /// Done: the text is gone for good (only its hash is stored).
    func dismiss() {
        revealed = nil
        device = ""
        reusable = false
    }

    /// The hint under the text: what to type where.
    var usageHint: String? {
        guard let c = revealed?.row else { return nil }
        let who = c.device.map { "device \($0)" } ?? "any device"
        let kind = c.reusable ? "Reusable until it expires" : "Works once"
        return "\(kind), for \(who), template \(c.template), until \(PKIText.stamp(c.expiresAt)). "
            + "SCEP: challenge password. EST: user name = device name, password = this text."
    }

    /// Table row values (never the text).
    struct Row: Identifiable, Equatable {
        var id: String
        var device: String
        var template: String
        var reusable: String
        var expires: Date
        var used: String
        var state: PKIChallengeRow.State

        /// Under the state in the State column: when and by whom, nil while unused.
        var usedText: String? { used == "Not yet" ? nil : used }
    }

    static func rows(_ challenges: [PKIChallengeRow], now: Date = Date()) -> [Row] {
        challenges.map { c in
            let used: String
            if let at = c.usedAt {
                used = "\(PKIText.stamp(at)) by \(c.usedBy ?? "?")" + (c.reusable ? " (\(c.useCount)×)" : "")
            } else {
                used = "Not yet"
            }
            return Row(id: c.id, device: c.device ?? "Any device", template: c.template, reusable: c.reusable ? "Reusable" : "One-time",
                       expires: c.expiresAt, used: used, state: c.state(at: now))
        }
    }
}

// MARK: - Files

/// Save panels and file reading shared by the sections.
@MainActor
enum CertificateFiles {
    static let certificateTypes: [UTType] = {
        var t: [UTType] = [.x509Certificate, .pkcs12]
        for ext in ["pem", "crt", "der", "p7b", "p7c", "key", "jks", "csr", "req", "txt"] {
            if let u = UTType(filenameExtension: ext), !t.contains(u) { t.append(u) }
        }
        return t
    }()

    /// Save panel for one file; returns the URL written, nil when cancelled.
    @discardableResult
    static func save(_ data: Data, suggestedName: String, message: String? = nil, privateKey: Bool = false) throws -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.allowsOtherFileTypes = true
        if let message { panel.message = message }
        let ext = (suggestedName as NSString).pathExtension
        if !ext.isEmpty, let t = UTType(filenameExtension: ext) { panel.allowedContentTypes = [t] }
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        try write(data, to: url, privateKey: privateKey)
        return url
    }

    /// Atomic write; key material 0600, everything else 0644.
    static func write(_ data: Data, to url: URL, privateKey: Bool) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: privateKey ? 0o600 : 0o644], ofItemAtPath: url.path)
    }

    /// Open panel for certificate-like files.
    static func choose(multiple: Bool, message: String) -> [URL] {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = multiple
        panel.canChooseDirectories = false
        panel.message = message
        panel.allowedContentTypes = certificateTypes + [.data]
        guard panel.runModal() == .OK else { return [] }
        return panel.urls
    }

    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
