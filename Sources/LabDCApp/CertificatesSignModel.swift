import Foundation
import Observation
import PKIKit
import LabDCCore
import X509

/// Sign CSR: the dropped/pasted request, the template and the Advanced overrides → a live dry-run
/// review (`CAService.review`, the same checks `sign` makes) → the signed certificate.
@MainActor @Observable
final class SignCSRModel {
    enum Verdict: Equatable {
        /// Nothing dropped or pasted yet.
        case empty
        /// The input is not a CSR, or an override does not parse.
        case invalid(String)
        /// What will be issued, in one sentence.
        case willIssue(String)
        /// The policy refuses it (the reason).
        case refused(String)
    }

    private(set) var input: [UInt8]?
    private(set) var sourceName = "request"
    /// The paste field (PEM or bare base64).
    var pasted = ""
    var templateName = "WebServer"
    // Advanced
    /// `dns:host, ip:10.0.0.5, upn:a@lab.sheep` (commas or spaces).
    var sanText = ""
    var replaceSANs = false
    var daysText = ""
    var commonName = ""
    /// nil = the current CA.
    var caName: String?
    /// Computer / User templates: the directory account the certificate is for.
    var account = ""

    private(set) var review: CSRReview?
    private(set) var reviewError: String?
    private(set) var result: SignResult?
    private(set) var reviewing = false

    /// Changes whenever something the review depends on changes (the view's `.task(id:)`).
    var reviewKey: String {
        [String(input?.count ?? -1), String(input?.hashValue ?? 0), templateName, sanText, String(replaceSANs), daysText,
         commonName, caName ?? "", account].joined(separator: "|")
    }

    /// Takes a dropped or chosen file.
    func load(bytes: [UInt8], name: String) {
        input = bytes
        sourceName = name
        pasted = ""
        result = nil
    }

    /// Takes the paste field's text (empty clears the input).
    func usePasted() {
        let text = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        input = Array(text.utf8)
        sourceName = "Pasted text"
        result = nil
    }

    func reset() {
        input = nil
        pasted = ""
        review = nil
        reviewError = nil
        result = nil
        sanText = ""
        replaceSANs = false
        daysText = ""
        commonName = ""
        caName = nil
        account = ""
    }

    /// The SAN overrides typed under Advanced.
    func sanOverride() throws -> SANOverride {
        let parts = sanText.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }).map(String.init)
        guard !parts.isEmpty else {
            if replaceSANs { throw SignFormError("“Replace” needs at least one name.") }
            return .fromRequest
        }
        var names: [GeneralName] = []
        for p in parts {
            do { names.append(try CAService.parseSubjectAltName(p)) } catch {
                throw SignFormError("“\(p)” is not a name: write dns:host, ip:10.0.0.5, upn:user@realm, email:… or uri:…")
            }
        }
        return replaceSANs ? .replace(names) : .add(names)
    }

    /// The request as `labdc ca sign` would build it.
    func request() throws -> SignRequest {
        guard let input else { throw SignFormError("Drop or paste a certificate request.") }
        var days: Int?
        let d = daysText.trimmingCharacters(in: .whitespaces)
        if !d.isEmpty {
            guard let n = Int(d), (1...36500).contains(n) else { throw SignFormError("Days must be 1 to 36500.") }
            days = n
        }
        let cn = commonName.trimmingCharacters(in: .whitespaces)
        let acct = account.trimmingCharacters(in: .whitespaces)
        return SignRequest(csr: input, sourceName: sourceName, templateName: templateName,
                           subjectAltNames: try sanOverride(), validityDays: days, commonName: cn.isEmpty ? nil : cn,
                           caName: caName, account: acct.isEmpty ? nil : acct, operatorName: "operator")
    }

    /// The dry run (no certificate issued, nothing recorded).
    func refresh(using editor: PKIEditor) async {
        guard input != nil else {
            review = nil
            reviewError = nil
            return
        }
        reviewing = true
        defer { reviewing = false }
        do {
            let r = try request()
            review = try await editor.review(r)
            reviewError = nil
        } catch {
            review = nil
            reviewError = CertificatesModel.describe(error)
        }
    }

    var verdict: Verdict {
        if input == nil { return .empty }
        if let reviewError { return .invalid(reviewError) }
        guard let review else { return .empty }
        switch review.verdict {
        case .willIssue: return .willIssue(Self.summary(review))
        case .refused(let e): return .refused(e.description)
        }
    }

    var canSign: Bool { if case .willIssue = verdict { result == nil } else { false } }

    /// `Will issue CN=clearpass.lab.sheep for 730 days from CA lab with DNS:clearpass.lab.sheep.`
    static func summary(_ review: CSRReview) -> String {
        guard let plan = review.plan else { return "Will issue." }
        let names = plan.subjectAltNames.map(CAService.describe)
        return "Will issue \(plan.subject) for \(plan.validityDays) days from CA \(plan.ca.name)"
            + (names.isEmpty ? " (no alternative names)." : " with \(names.joined(separator: ", ")).")
    }

    /// Whether the chosen template takes its name from a directory account.
    func needsAccount(_ template: CertificateTemplate?) -> Bool {
        guard let template else { return false }
        return template.sanPolicy == .dnsHostName || template.sanPolicy == .upn
    }

    /// Sign (re-reviews first; the same refusal as the dry run).
    func sign(using editor: PKIEditor) async throws {
        result = try await editor.sign(try request())
    }

    /// Where to import the certificate (the result card's hint).
    static let importHint = "Windows: double-click the .p7b ▸ Install Certificate (or `certreq -accept`). "
        + "ClearPass: Administration ▸ Certificates ▸ Certificate Store ▸ Import, the PEM with its chain."
}

struct SignFormError: Error, CustomStringConvertible {
    let description: String
    init(_ text: String) { description = text }
}

// MARK: - Template editor

/// The template editor sheet's working copy with validation (nothing is saved until Save).
struct TemplateDraft: Equatable {
    static let knownEKUs: [(oid: String, name: String)] = [
        (PKIOID.serverAuth, "Server authentication"),
        (PKIOID.clientAuth, "Client authentication"),
        (PKIOID.emailProtection, "Secure email"),
        ("1.3.6.1.5.5.7.3.3", "Code signing"),
        ("1.3.6.1.5.5.7.3.17", "IP security IKE"),
        ("1.3.6.1.4.1.311.20.2.2", "Smart card logon"),
    ]

    static let keyUsages: [(TemplateKeyUsage, String)] = [
        (.digitalSignature, "Digital signature"), (.keyEncipherment, "Key encipherment"),
        (.nonRepudiation, "Non-repudiation"), (.dataEncipherment, "Data encipherment"),
        (.keyAgreement, "Key agreement"), (.keyCertSign, "Certificate signing"), (.cRLSign, "CRL signing"),
    ]

    static let keyTypes: [(String, String)] = [("p256", "P-256"), ("p384", "P-384"), ("p521", "P-521"), ("rsa", "RSA")]

    static func sanPolicyTitle(_ p: SANPolicy) -> String {
        switch p {
        case .dnsHostName: "Computer's DNS name (from the directory)"
        case .upn: "User's sign-in name (UPN, from the directory)"
        case .fromRequest: "Names in the request"
        case .none: "No alternative names"
        }
    }

    static func ekuName(_ oid: String) -> String {
        knownEKUs.first { $0.oid == oid }?.name ?? oid
    }

    let original: CertificateTemplate
    /// False while creating a new template: the sheet then edits the name, and saving goes
    /// through `createTemplate` (fresh OID, not built in).
    var isNew = false
    var name: String
    var displayName: String
    var validityDays: Int
    var renewalDays: Int
    var ekus: Set<String>
    /// Other purposes as dotted OIDs, comma separated (Advanced).
    var customEKUs: String
    var keyUsage: TemplateKeyUsage
    var sanPolicy: SANPolicy
    var minKeyBits: Int
    var allowedKeyTypes: Set<String>
    var autoEnroll: Bool
    var manualApproval: Bool
    var enabled: Bool
    var groupSIDs: [String]

    /// A draft for a brand-new template cloned from `base` (the sheet asks for the name;
    /// `PKIEditor.createTemplate` assigns the OID and clears built-in).
    static func new(basedOn base: CertificateTemplate) -> TemplateDraft {
        var draft = TemplateDraft(base)
        draft.isNew = true
        draft.name = ""
        draft.displayName = ""
        return draft
    }

    init(_ t: CertificateTemplate) {
        original = t
        name = t.name
        displayName = t.displayName
        validityDays = t.validityDays
        renewalDays = t.renewalDays
        let known = Set(Self.knownEKUs.map(\.oid))
        ekus = Set(t.ekus.filter(known.contains))
        customEKUs = t.ekus.filter { !known.contains($0) }.joined(separator: ", ")
        keyUsage = t.keyUsage
        sanPolicy = t.sanPolicy
        minKeyBits = t.minKeyBits
        allowedKeyTypes = Set(t.allowedKeyTypes)
        autoEnroll = t.autoEnroll
        manualApproval = t.manualApproval
        enabled = t.enabled
        groupSIDs = t.enrolAllowedGroupSIDs
    }

    static func == (a: TemplateDraft, b: TemplateDraft) -> Bool { a.template == b.template && a.customEKUs == b.customEKUs }

    var customEKUList: [String] {
        customEKUs.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
    }

    static func isOID(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count >= 2 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) } && ["0", "1", "2"].contains(String(parts[0]))
    }

    /// Why Save is disabled (empty = OK).
    var errors: [String] {
        var e: [String] = []
        if displayName.trimmingCharacters(in: .whitespaces).isEmpty { e.append("The display name is empty.") }
        if !(1...36500).contains(validityDays) { e.append("Validity is 1 to 36500 days.") }
        if renewalDays < 0 || renewalDays >= validityDays { e.append("The renewal window must be shorter than the validity.") }
        if allowedKeyTypes.isEmpty { e.append("Allow at least one key type.") }
        if allowedKeyTypes.contains("rsa"), !(1024...16384).contains(minKeyBits) { e.append("Minimum RSA key size is 1024 to 16384 bits.") }
        for oid in customEKUList where !Self.isOID(oid) { e.append("“\(oid)” is not an OID (like 1.3.6.1.5.5.7.3.9).") }
        if keyUsage.isEmpty && ekus.isEmpty && customEKUList.isEmpty { e.append("Choose at least one key usage or purpose.") }
        if autoEnroll && manualApproval { e.append("Auto-enrollment cannot wait for manual approval.") }
        if autoEnroll && groupSIDs.isEmpty { e.append("Auto-enrollment needs at least one group that may enrol.") }
        if autoEnroll && sanPolicy == .fromRequest { e.append("Auto-enrolled certificates take their name from the directory (computer DNS name or UPN).") }
        return e
    }

    var isValid: Bool { errors.isEmpty }
    var hasChanges: Bool { template != original }

    /// The edited template (OID, name, built-in flag unchanged).
    var template: CertificateTemplate {
        var t = original
        t.name = name.trimmingCharacters(in: .whitespaces)
        t.displayName = displayName.trimmingCharacters(in: .whitespaces)
        t.validityDays = validityDays
        t.renewalDays = renewalDays
        // Keep the template's own order; newly ticked purposes and other OIDs go after it.
        let custom = customEKUList
        var all = original.ekus.filter { ekus.contains($0) || custom.contains($0) }
        for oid in Self.knownEKUs.map(\.oid) where ekus.contains(oid) && !all.contains(oid) { all.append(oid) }
        for oid in custom where !all.contains(oid) { all.append(oid) }
        t.ekus = all
        t.keyUsage = keyUsage
        t.sanPolicy = sanPolicy
        t.minKeyBits = minKeyBits
        t.allowedKeyTypes = Self.keyTypes.map(\.0).filter(allowedKeyTypes.contains)
        t.autoEnroll = autoEnroll
        t.manualApproval = manualApproval
        t.enabled = enabled
        t.enrolAllowedGroupSIDs = groupSIDs
        return t
    }

    mutating func toggleGroup(_ sid: String) {
        if let i = groupSIDs.firstIndex(of: sid) { groupSIDs.remove(at: i) } else { groupSIDs.append(sid) }
    }
}

extension CertificateTemplate {
    /// `Client + Server authentication` for the list.
    var purposeText: String {
        if ekus.isEmpty { return isCA ? "Certification authority" : "Any purpose" }
        return ekus.map(TemplateDraft.ekuName).joined(separator: ", ")
    }
}
