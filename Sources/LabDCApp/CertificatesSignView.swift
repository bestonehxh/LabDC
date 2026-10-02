import PKIKit
import LabDCCore
import SwiftUI

/// Certificates ▸ Sign CSR: drop/paste a request → its review (live dry run) → template (+
/// Advanced overrides) → Sign → download PEM / P7B.
struct CertificatesSignView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @Bindable var sign: SignCSRModel
    @State private var signing = false
    @State private var advanced = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                requestCard
                if let review = sign.review { detailsCard(review) }
                policyCard
                if let result = sign.result { resultCard(result) }
            }
            .padding(.bottom, 24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: sign.reviewKey) {
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            await sign.refresh(using: editor)
        }
        .onAppear {
            if editor.templates.first(where: { $0.name == sign.templateName && $0.enabled }) == nil,
               let first = editor.templates.first(where: \.enabled) {
                sign.templateName = first.name
            }
        }
    }

    private var requestCard: some View {
        Card(title: "Certificate request") {
            if sign.input == nil {
                FileDropZone(title: "Drop a CSR here", subtitle: "PEM (.csr, .req) or DER, from ClearPass, iMaster NCE, a switch or openssl",
                             onDrop: { urls in load(urls.first) },
                             onChoose: { load(CertificateFiles.choose(multiple: false, message: "Choose a certificate request (CSR)").first) })
                VStack(alignment: .leading, spacing: 8) {
                    FieldCaption("Or paste it")
                    TextEditor(text: $sign.pasted)
                        .font(Theme.mono)
                        .scrollContentBackground(.hidden)
                        .padding(6)
                        .frame(height: 80)
                        .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Theme.line))
                        .accessibilityLabel("Paste a PEM certificate request")
                    Button("Review pasted text") { sign.usePasted() }
                        .buttonStyle(.quietLink)
                        .disabled(sign.pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            } else {
                HStack(alignment: .firstTextBaseline) {
                    Text(sign.sourceName).font(Theme.body).foregroundStyle(Theme.ink)
                    Spacer()
                    Button("Clear") { sign.reset() }
                        .buttonStyle(.quietLink)
                }
            }
        }
    }

    private func detailsCard(_ r: CSRReview) -> some View {
        Card(title: "What the request asks for") {
            VStack(alignment: .leading, spacing: 0) {
                InfoRow(label: "Subject", value: r.subject.isEmpty ? "(empty)" : r.subject)
                InfoRow(label: "Key", value: r.keyType)
                InfoRow(label: "Signature", value: r.signatureAlgorithm + (r.signatureChecked ? (r.signatureValid ? " — valid" : " — invalid") : " — not checked"),
                        attention: r.signatureChecked && !r.signatureValid)
                InfoRow(label: "Names", value: r.requestedSubjectAltNames.isEmpty ? "none" : r.requestedSubjectAltNames.joined(separator: ", "))
                if !r.requestedExtensions.isEmpty {
                    InfoRow(label: "Extensions", value: r.requestedExtensions.map { "\($0.name)\($0.honoured ? "" : " (not copied)")" }.joined(separator: ", "))
                }
            }
        }
    }

    private var policyCard: some View {
        let template = editor.templates.first { $0.name == sign.templateName }
        return Card(title: "Certificate") {
            VStack(alignment: .leading, spacing: 6) {
                FieldCaption("Template")
                Picker("Template", selection: $sign.templateName) {
                    ForEach(editor.templates.filter(\.enabled), id: \.name) { t in
                        Text("\(t.displayName) — \(t.purposeText), \(t.validityDays) days").tag(t.name)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 520, alignment: .leading)
            }
            if sign.needsAccount(template) {
                VStack(alignment: .leading, spacing: 6) {
                    FieldCaption("Account")
                    TextField("Account", text: $sign.account, prompt: Text(template?.sanPolicy == .upn ? "alice" : "WS1$"))
                        .textFieldStyle(.quiet)
                        .frame(maxWidth: 320)
                        .accessibilityHint("The directory account the certificate is for; its name comes from the directory")
                }
            }
            Button(advanced ? "Hide advanced" : "Advanced") { advanced.toggle() }
                .buttonStyle(.quietLink)
                .accessibilityValue(advanced ? "Shown" : "Hidden")
            if advanced {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        FieldCaption("Names")
                        TextField("Names", text: $sign.sanText, prompt: Text("dns:host.lab.sheep, ip:10.0.0.5"))
                            .textFieldStyle(.quiet)
                    }
                    Toggle("Replace the names in the request (instead of adding)", isOn: $sign.replaceSANs)
                        .toggleStyle(.quiet)
                        .font(Theme.body)
                        .frame(maxWidth: 520)
                    HStack(alignment: .top, spacing: 24) {
                        VStack(alignment: .leading, spacing: 6) {
                            FieldCaption("Days")
                            TextField("Days", text: $sign.daysText, prompt: Text("\(template?.validityDays ?? 365)"))
                                .textFieldStyle(.quiet)
                        }
                        .frame(width: 120)
                        VStack(alignment: .leading, spacing: 6) {
                            FieldCaption("Common name")
                            TextField("Common name", text: $sign.commonName, prompt: Text("from the request"))
                                .textFieldStyle(.quiet)
                        }
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        FieldCaption("CA")
                        Picker("CA", selection: $sign.caName) {
                            Text("Current CA (\(editor.currentCA?.name ?? "?"))").tag(String?.none)
                            ForEach(editor.otherCAs) { Text("\($0.title) (\($0.name))").tag(String?.some($0.name)) }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 360, alignment: .leading)
                    }
                }
                .padding(.leading, 2)
            }
            verdictView
            if let warnings = sign.review?.warnings, !warnings.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(warnings, id: \.self) { w in
                        Text(w).font(Theme.detail).foregroundStyle(Theme.attention)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            HStack(alignment: .center, spacing: 16) {
                Button("Sign") {
                    signing = true
                    Task {
                        await model.perform("Sign") { try await sign.sign(using: $0) }
                        signing = false
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(!sign.canSign || signing)
                if sign.reviewing { StateText(text: "Checking…", dimmed: true) }
            }
            .padding(.top, 4)
        }
    }

    @ViewBuilder private var verdictView: some View {
        switch sign.verdict {
        case .empty:
            Text("Drop or paste a request to see what would be issued.").font(Theme.detail).foregroundStyle(Theme.muted)
        case .invalid(let why):
            Text(why).font(Theme.detail).foregroundStyle(Theme.attention)
                .fixedSize(horizontal: false, vertical: true)
        case .refused(let why):
            Text("Will not be signed: \(why)").font(Theme.detail).foregroundStyle(Theme.attention)
                .fixedSize(horizontal: false, vertical: true)
        case .willIssue(let what):
            Text(what).font(Theme.detail).foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func resultCard(_ result: SignResult) -> some View {
        Card(title: "Signed") {
            VStack(alignment: .leading, spacing: 0) {
                InfoRow(label: "Subject", value: result.certificate.subject.description)
                InfoRow(label: "Serial", value: result.serial.uppercased(), copyable: true, monospaced: true)
                InfoRow(label: "Valid", value: "\(PKIText.day(result.certificate.notValidBefore)) – \(PKIText.day(result.certificate.notValidAfter))")
                InfoRow(label: "CA", value: result.caName)
            }
            HStack(spacing: 24) {
                Button("Save PEM (leaf only)…") { save(result, .pem, chain: false) }
                    .buttonStyle(.quietLink)
                    .help("Just this certificate. ClearPass's Import Certificate (server certificate) wants this; add the CA to its Trust List separately.")
                Button("Save PEM (with CA chain)…") { save(result, .pem, chain: true) }
                    .buttonStyle(.quietLink)
                    .help("This certificate followed by the root CA, for devices that import the chain in one file.")
                Button("Save P7B…") { save(result, .p7b, chain: true) }
                    .buttonStyle(.quietLink)
                Button("Save root CA (PEM)…") { saveCA(result) }
                    .buttonStyle(.quietLink)
                    .help("The root CA this certificate chains to — for ClearPass's Trust List (usage EAP and AD/LDAP Servers) or any device that must trust it.")
                Button("Copy PEM") { CertificateFiles.copy(String(decoding: result.encoded(.pem, includeChain: true), as: UTF8.self)) }
                    .buttonStyle(.quietLink)
                Spacer()
                Button("Sign another") { sign.reset() }
                    .buttonStyle(.quietLink)
            }
            QuietNote(SignCSRModel.importHint)
        }
    }

    private func load(_ url: URL?) {
        guard let url else { return }
        do {
            sign.load(bytes: Array(try Data(contentsOf: url)), name: url.lastPathComponent)
        } catch {
            model.alert = "Cannot read \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    /// The root the signing CA chains to (the signing CA itself when it is a root), for the
    /// ClearPass Trust List.
    private func saveCA(_ result: SignResult) {
        Task {
            await model.perform("Save CA") { e in
                let data = try await e.exportRootCA(.pem, caName: result.caName)
                try CertificateFiles.save(data, suggestedName: "\(result.caName)-ca.pem")
            }
        }
    }

    private func save(_ result: SignResult, _ format: SignResult.Format, chain: Bool) {
        let base = result.certificate.subject.commonNameText ?? result.serial
        let suffix = chain && format == .pem ? "-chain" : ""
        do {
            try CertificateFiles.save(Data(result.encoded(format, includeChain: chain)),
                                      suggestedName: "\(base)\(suffix).\(format == .p7b ? "p7b" : "pem")")
        } catch {
            model.alert = "Saving failed: \(error.localizedDescription)"
        }
    }
}
