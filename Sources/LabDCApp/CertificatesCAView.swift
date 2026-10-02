import PKIKit
import LabDCCore
import SwiftUI

/// Certificates ▸ Authority: the current CA (name, key, validity, fingerprint, revocation list) on
/// the left, what it issued recently on the right; then its details, the other CAs, Create a new CA,
/// Use as current and Save CA.
struct CertificatesCAView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @State private var createForm: CreateCAForm?
    @State private var confirmUse: CAInfo?
    @State private var regenerating = false
    @State private var changeKey: ChangeKeyForm?
    @State private var confirmRetire: CAService.RootStatus?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 40) {
                if let ca = editor.currentCA {
                    HStack(alignment: .top, spacing: 56) {
                        authority(ca)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        issuedRecently
                            .frame(minWidth: 240, maxWidth: 340, alignment: .leading)
                    }
                    details(ca)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("No CA yet")
                            .font(Theme.subtitle)
                            .tracking(-0.4)
                            .foregroundStyle(Theme.ink)
                            .accessibilityAddTraits(.isHeader)
                        Text("The lab CA is created the first time the server starts.")
                            .font(Theme.body)
                            .foregroundStyle(Theme.muted)
                        Button("Create a new CA") { newCA() }
                            .buttonStyle(.quietLink)
                            .padding(.top, 6)
                    }
                }
                roots
                otherCAs
            }
            .padding(.bottom, 24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .sheet(item: $createForm) { form in
            CreateCASheet(form: form) { f in
                let ok = await model.perform("Create CA") {
                    try await $0.createCA(name: f.name.trimmingCharacters(in: .whitespaces), commonName: f.effectiveCommonName,
                                          keyType: f.keyType, years: f.years)
                }
                if ok { model.notice = "Created CA \(f.name). It is not used until you choose Use as current." }
                return ok
            }
        }
        .sheet(item: $changeKey) { form in
            ChangeKeySheet(form: form) { f in
                var report: LabCASwitch.Report?
                let ok = await model.perform("Change the lab CA key") {
                    report = try await $0.changeLabCAKey(to: f.keyType, keepOldTrusted: f.keepOldTrusted)
                }
                if ok, let report {
                    model.notice = "The lab CA is now \(report.to) (\(report.keyType.signatureDescription)). "
                        + (report.oldRootKeptTrusted ? "\(report.from) stays trusted until you retire it."
                           : "\(report.from) is retired; \(report.stillActiveOnOldRoot) of its certificates are still unexpired.")
                        + " Windows PCs re-enroll at their next gpupdate."
                }
                return ok
            }
        }
        .confirmationDialog("Retire “\(confirmRetire?.name ?? "")”?",
                            isPresented: Binding(get: { confirmRetire != nil }, set: { if !$0 { confirmRetire = nil } }),
                            presenting: confirmRetire) { root in
            Button("Retire", role: .destructive) {
                Task { await model.perform("Retire the old root") { _ = try await $0.retireCA(name: root.name) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: { root in
            Text(retireMessage(root))
        }
        .confirmationDialog("Use “\(confirmUse?.title ?? "")” as the current CA?",
                            isPresented: Binding(get: { confirmUse != nil }, set: { if !$0 { confirmUse = nil } }),
                            presenting: confirmUse) { ca in
            Button("Use as current") {
                Task { await model.perform("Use as current") { try await $0.useCA(name: ca.name) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: { ca in
            Text(CertificatesCAView.useMessage(ca))
        }
    }

    /// What "Use as current" does, in the confirmation.
    static func useMessage(_ ca: CAInfo) -> String {
        "New certificates are issued by \(ca.title) (\(ca.keyType.displayName)). The DC certificate (LDAPS, HTTPS, EST) and the "
            + "SCEP RA certificate are reissued from it now: every service restarts for a moment. Devices must trust \(ca.title) "
            + "before they connect again — add it under Trusted roots and export it for non-Windows devices."
    }

    private func newCA() {
        createForm = CreateCAForm(existing: editor.authorities.map(\.name))
    }

    // MARK: Left column

    private func authority(_ ca: CAInfo) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(ca.title)
                .font(Theme.subtitle)
                .tracking(-0.4)
                .foregroundStyle(Theme.ink)
                .textSelection(.enabled)
                .accessibilityAddTraits(.isHeader)
            Text(ca.isLab
                 ? "Issues every certificate of this domain. The lab CA, made when the domain was created."
                 : "Issues every certificate of this domain.")
                .font(Theme.body)
                .foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 8)
                .padding(.bottom, 24)
            InfoRow(label: "Key", value: ca.keyType.signatureDescription)
            InfoRow(label: "Valid until", value: ca.validUntilText(), attention: ca.expiresSoon())
            InfoRow(label: "Fingerprint", value: ca.sha256, copyable: true, monospaced: true)
            revocationLine(ca)
            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(spacing: 24) {
                saveMenu(ca, title: "Save CA")
                Button("Change the lab CA key…") { changeKey = ChangeKeyForm(current: ca.keyType) }
                    .buttonStyle(.quietLink)
                    .disabled(editor.migration != nil)
                    .accessibilityHint("Moves issuing to a new P-256 or P-384 root")
                Button("Create a new CA") { newCA() }
                    .buttonStyle(.quietLink)
            }
            .padding(.top, 20)
        }
    }

    private func revocationLine(_ ca: CAInfo) -> some View {
        let crl = editor.crls[ca.name]
        let stale = crl?.isStale() ?? false
        return LabeledLine(label: "Revocation list") {
            if let crl {
                if stale {
                    StateText(text: "Stale — regenerate", attention: true)
                } else {
                    Text("\(crl.entries) revoked · next update \(PKIText.stamp(crl.nextUpdate))")
                        .font(Theme.body)
                        .foregroundStyle(Theme.ink)
                }
            } else {
                StateText(text: "Not generated yet")
            }
        } trailing: {
            Button(regenerating ? "Regenerating…" : "Regenerate") {
                regenerating = true
                Task {
                    await model.perform("Regenerate the CRL") { _ = try await $0.regenerateCRL(caName: ca.name) }
                    regenerating = false
                }
            }
            .buttonStyle(.quietLink)
            .disabled(regenerating)
            .accessibilityLabel("Regenerate the revocation list now")
        }
    }

    // MARK: Right column

    private var issuedRecently: some View {
        let now = Date()
        let rows = Array(editor.issued.map { IssuedRow($0, now: now) }.sorted { $0.issued > $1.issued }.prefix(6))
        return QuietSection(title: "Issued recently") {
            Button("All issued") { model.section = .issued }
                .buttonStyle(.quietLink)
        } content: {
            if rows.isEmpty {
                QuietRow(first: true) {
                    Text("Nothing issued yet.")
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                }
            } else {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, r in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(r.fileBaseName)
                                    .font(Theme.body)
                                    .foregroundStyle(Theme.ink)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                roleLine(r)
                                    .font(Theme.detail)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 8)
                            Text(PKIText.day(r.expires))
                                .font(Theme.caption)
                                .foregroundStyle(Theme.faint)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
    }

    private func roleLine(_ r: IssuedRow) -> Text {
        switch r.state {
        case .valid: Text(r.template).foregroundStyle(Theme.muted)
        case .expired: Text("\(r.template) · Expired").foregroundStyle(Theme.muted)
        case .revoked: Text("\(Text("\(r.template) · ").foregroundStyle(Theme.muted))\(Text("Revoked").foregroundStyle(Theme.attention))")
        }
    }

    // MARK: Below

    private func details(_ ca: CAInfo) -> some View {
        Card(title: "Details") {
            VStack(alignment: .leading, spacing: 0) {
                InfoRow(label: "Name", value: ca.name + (ca.isLab ? " (lab CA)" : ""))
                InfoRow(label: "Subject", value: ca.subject)
                // Validity, SHA-256 and the revocation list are on the left already (owner, 2 Oct 2026).
                InfoRow(label: "SHA-1", value: ca.sha1, copyable: true, monospaced: true)
                InfoRow(label: "Download", value: editor.endpoints.caCertificateURL(ca.name), copyable: true)
                if let crl = editor.crls[ca.name] {
                    InfoRow(label: "Address (CDP)", value: crl.url, copyable: true)
                }
            }
            QuietNote("The revocation list is regenerated after every revocation and daily; it is valid for 7 days.")
        }
    }

    /// Roots: which one issues, which are trusted, how many active certificates each has.
    private var roots: some View {
        Card(title: "Roots") {
            if let m = editor.migration {
                Text("Changing roots: \(m.to) issues, \(m.from) is still trusted. Retire \(m.from) once its devices have re-enrolled.")
                    .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(editor.roots.enumerated()), id: \.element.name) { index, root in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 24) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(root.name).font(Theme.body).foregroundStyle(Theme.ink)
                                Text(Self.rootLine(root)).font(Theme.detail).foregroundStyle(Theme.muted)
                            }
                            Spacer(minLength: 12)
                            if !root.isCurrent, root.trusted, root.name != LabPKI.rsaCompatCAName {
                                Button("Retire…") { confirmRetire = root }
                                    .buttonStyle(.quietLink)
                            }
                        }
                        .accessibilityElement(children: .contain)
                    }
                }
            }
        }
    }

    /// `P-384 · ECDSA SHA-384 · issues · trusted · 12 active`.
    static func rootLine(_ root: CAService.RootStatus) -> String {
        var parts = [root.keyType.signatureDescription]
        if root.isCurrent { parts.append("issues") }
        parts.append(root.retired ? "retired (CRL still published)" : root.trusted ? "trusted" : "not trusted")
        parts.append("\(root.activeCertificates) active")
        return parts.joined(separator: " · ")
    }

    private func retireMessage(_ root: CAService.RootStatus) -> String {
        let active = editor.activeCertificates(caName: root.name)
        let names = active.prefix(8).map(\.subject).joined(separator: ", ")
        return "\(root.name) leaves the trusted roots (Group Policy, NTAuth) and the 802.1X profiles, and EAP-TLS refuses its client certificates. "
            + (active.isEmpty ? "It has no active certificates." : "\(active.count) certificate(s) it issued are still active: \(names)\(active.count > 8 ? ", …" : "").")
            + " Its key stays and its revocation list keeps being published."
    }

    private var otherCAs: some View {
        Card(title: "Other CAs") {
            Text("Keep an older CA to verify what it issued, or create a new one (RSA for devices that need it).")
                .font(Theme.detail)
                .foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            if editor.otherCAs.isEmpty {
                Text("No other CA.").font(Theme.detail).foregroundStyle(Theme.faint)
            }
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(editor.otherCAs.enumerated()), id: \.element.id) { index, ca in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 24) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(ca.title).font(Theme.body).foregroundStyle(Theme.ink)
                                Text("\(ca.name) · \(ca.keyType.displayName) · \(ca.validityText())")
                                    .font(Theme.detail)
                                    .foregroundStyle(ca.notAfter <= Date() ? Theme.attention : Theme.muted)
                            }
                            Spacer(minLength: 12)
                            Button("Use as current") { confirmUse = ca }
                                .buttonStyle(.quietLink)
                                .disabled(ca.notAfter <= Date())
                            saveMenu(ca, title: "Save")
                        }
                        .accessibilityElement(children: .contain)
                    }
                }
            }
            if let notice = model.notice {
                Text(notice).font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// "Save CA": a text link that opens the export formats.
    private func saveMenu(_ ca: CAInfo, title: String) -> some View {
        Menu {
            ForEach(CAExportFormat.allCases) { format in
                Button(format.menuTitle) {
                    Task {
                        await model.perform("Save CA") { e in
                            let data = try await e.exportCA(format, caName: ca.name)
                            try CertificateFiles.save(data, suggestedName: format.fileName(for: ca),
                                                      message: format == .mobileconfig
                                                          ? "Open the profile on the iPhone or Mac, then trust it in Settings ▸ General ▸ About ▸ Certificate Trust Settings."
                                                          : nil)
                        }
                    }
                }
            }
            Divider()
            Button("Copy for Switches (PEM)") { CertificateFiles.copy(ca.pem) }
        } label: {
            Text(title)
        }
        .menuStyle(.button)
        .buttonStyle(.quietLink)
        .fixedSize()
        .accessibilityLabel("Save \(ca.title)")
    }
}

extension CreateCAForm: Identifiable {
    nonisolated var id: ObjectIdentifier { ObjectIdentifier(self) }
}

/// Create CA… — name, common name, key type, years.
struct CreateCASheet: View {
    @Bindable var form: CreateCAForm
    let onCreate: (CreateCAForm) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var working = false

    var body: some View {
        QuietSheet(title: "New CA", width: 480,
                   failure: form.name.isEmpty ? nil : form.problem) {
            SheetField("Name", note: "A short name; it is part of the CRL address.") {
                QuietTextField("Name", text: $form.name, prompt: "Prod").textFieldStyle(.quiet)
                    .accessibilityHint("A short name; it is part of the CRL address")
            }
            SheetField("Common name") {
                QuietTextField("Common name", text: $form.commonName, prompt: form.name.trimmingCharacters(in: .whitespaces).isEmpty ? "Prod CA" : form.effectiveCommonName).textFieldStyle(.quiet)
            }
            SheetField("Key type", note: form.keyTypeHint) {
                SheetPicker("Key type", selection: $form.keyType) {
                    ForEach(CAKeyType.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
            }
            SheetField("Valid for") {
                Stepper("\(form.years) year\(form.years == 1 ? "" : "s")", value: $form.years, in: 1...50)
                    .font(Theme.body).foregroundStyle(Theme.ink).fixedSize()
            }
        } actions: {
            SheetButtons("Create", disabled: form.problem != nil || working) {
                working = true
                Task {
                    if await onCreate(form) { dismiss() }
                    working = false
                }
            }
        }
    }
}

/// "Change the lab CA key…": the new key (the current one is not offered) and whether the old
/// root stays trusted for a while.
@MainActor @Observable
final class ChangeKeyForm: Identifiable {
    let current: CAKeyType
    var keyType: CAKeyType
    var keepOldTrusted = false

    init(current: CAKeyType) {
        self.current = current
        keyType = current == .p384 ? .p256 : .p384
    }
}

struct ChangeKeySheet: View {
    @Bindable var form: ChangeKeyForm
    let onChange: (ChangeKeyForm) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var working = false

    var body: some View {
        QuietSheet(title: "Change the lab CA key", width: 520) {
            SheetField("New key") {
                SheetPicker("New key", selection: $form.keyType) {
                    ForEach([CAKeyType.p384, .p256], id: \.self) { k in
                        Text(k.signatureDescription + (k == form.current ? " (current)" : "")).tag(k)
                            .selectionDisabled(k == form.current)
                    }
                }
            }
            SheetToggle("Keep the old root trusted for a while", isOn: $form.keepOldTrusted)
            QuietNote(Self.explanation(form))
        } actions: {
            SheetButtons(working ? "Changing…" : "Change", disabled: working || form.keyType == form.current) {
                working = true
                Task {
                    if await onChange(form) { dismiss() }
                    working = false
                }
            }
        }
    }

    static func explanation(_ form: ChangeKeyForm) -> String {
        "A new \(form.keyType.displayName) root is created and issues from now on (the old root is never re-keyed or deleted). "
            + "The DC certificate (LDAPS, HTTPS, RADIUS) is reissued from it and every service restarts for a moment. "
            + "Group Policy trusts the new root, the 802.1X profiles point at it, and joined Windows PCs re-enroll their "
            + "machine and user certificates at the next gpupdate. "
            + (form.keepOldTrusted
               ? "The old root stays trusted (Group Policy, NTAuth, 802.1X, EAP-TLS) until you retire it under Roots."
               : "The old root is retired at once: devices still using its certificates must re-enroll before they connect again.")
            + " Non-Windows devices need the new root installed."
    }
}
