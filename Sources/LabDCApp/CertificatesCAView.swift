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
        .confirmationDialog("Use “\(confirmUse?.title ?? "")” as the current CA?",
                            isPresented: Binding(get: { confirmUse != nil }, set: { if !$0 { confirmUse = nil } }),
                            presenting: confirmUse) { ca in
            Button("Use as Current") {
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
            InfoRow(label: "Key", value: ca.keyType.displayName)
            InfoRow(label: "Valid until", value: ca.validityText(), attention: ca.expiresSoon())
            InfoRow(label: "Fingerprint", value: ca.sha256, copyable: true, monospaced: true)
            revocationLine(ca)
            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(spacing: 24) {
                saveMenu(ca, title: "Save CA")
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
                InfoRow(label: "Validity", value: ca.validityText(), attention: ca.expiresSoon())
                InfoRow(label: "SHA-256", value: ca.sha256, copyable: true, monospaced: true)
                InfoRow(label: "SHA-1", value: ca.sha1, copyable: true, monospaced: true)
                InfoRow(label: "Download", value: editor.endpoints.caCertificateURL(ca.name), copyable: true)
                if let crl = editor.crls[ca.name] {
                    InfoRow(label: "Revocation list", value: crl.summary(), attention: crl.isStale())
                    InfoRow(label: "Address (CDP)", value: crl.url, copyable: true)
                } else {
                    InfoRow(label: "Revocation list", value: "No CRL has been generated for \(ca.title) yet.")
                }
            }
            QuietNote("The revocation list is regenerated after every revocation and daily; it is valid for 7 days.")
        }
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
                        await model.perform("Export CA") { e in
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
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $form.name, prompt: Text("Prod"))
                        .accessibilityHint("A short name; it is part of the CRL address")
                    TextField("Common name", text: $form.commonName, prompt: Text(form.effectiveCommonName))
                    Picker("Key type", selection: $form.keyType) {
                        ForEach(CAKeyType.allCases, id: \.self) { Text($0.displayName).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    Stepper("Valid for \(form.years) year\(form.years == 1 ? "" : "s")", value: $form.years, in: 1...50)
                } header: {
                    Text("Create CA")
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(form.keyTypeHint)
                        if let problem = form.problem, !form.name.isEmpty {
                            Text(problem).foregroundStyle(Theme.attention)
                        }
                    }
                    .font(Theme.caption)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            HStack(spacing: 24) {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .buttonStyle(.quietLink)
                    .keyboardShortcut(.cancelAction)
                Button("Create") {
                    working = true
                    Task {
                        if await onCreate(form) { dismiss() }
                        working = false
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(form.problem != nil || working)
            }
            .padding([.horizontal, .bottom], 20)
        }
        .frame(width: 460)
        .background(Theme.background)
    }
}
