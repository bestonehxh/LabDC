import AppKit
import CertConvert
import LabDCCore
import SwiftUI

/// The converter, in the Certificates page (`compact: false`) and in the standalone window.
struct ConverterView: View {
    @Bindable var model: ConverterModel
    var compact: Bool
    @State private var passwords: [UUID: String] = [:]
    @State private var showPaste = false
    @State private var inspecting = false
    @State private var advanced = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: compact ? 20 : 28) {
                VStack(alignment: .leading, spacing: 12) {
                    FileDropZone(title: "Drop certificates or keys here",
                                 subtitle: "PEM, DER (.cer/.crt), P7B, PFX/P12, private keys or a Java keystore (JKS). Drop several files to combine a key with its certificate and chain.",
                                 height: compact ? 120 : 130,
                                 onDrop: { model.add(urls: $0) },
                                 onChoose: { model.add(urls: CertificateFiles.choose(multiple: true, message: "Choose certificate or key files")) })
                    Button(showPaste ? "Hide pasted text" : "Paste PEM text") { showPaste.toggle() }
                        .buttonStyle(.quietLink)
                        .accessibilityValue(showPaste ? "Shown" : "Hidden")
                    if showPaste {
                        VStack(alignment: .leading, spacing: 8) {
                            TextEditor(text: $model.pasted)
                                .font(Theme.mono)
                                .scrollContentBackground(.hidden)
                                .padding(6)
                                .frame(height: 90)
                                .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Theme.line))
                                .accessibilityLabel("PEM text")
                            Button("Add pasted text") { model.addPasted() }
                                .buttonStyle(.quietLink)
                                .disabled(model.pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                    }
                }
                if !model.inputs.isEmpty {
                    inputsCard
                    detectedCard
                    convertCard
                }
            }
            .padding(compact ? 24 : 0)
            .padding(.bottom, 24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.background)
        .sheet(isPresented: $inspecting) { InspectSheet(rows: model.certificateRows) }
        .alert("Converter", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(error ?? "")
        }
    }

    private var inputsCard: some View {
        Card(title: "Files") {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(model.inputs.enumerated()), id: \.element.id) { index, input in
                    QuietRow(first: index == 0) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(input.name).font(Theme.body).foregroundStyle(Theme.ink)
                                    Text(input.summary)
                                        .font(Theme.detail)
                                        .foregroundStyle(hasProblem(input) ? Theme.attention : Theme.muted)
                                        .lineLimit(2)
                                }
                                Spacer(minLength: 12)
                                Button("Remove") { model.remove(input.id) }
                                    .buttonStyle(.quietLink)
                                    .accessibilityLabel("Remove \(input.name)")
                            }
                            if input.isLocked {
                                HStack(alignment: .firstTextBaseline, spacing: 16) {
                                    QuietTextField("Password", text: Binding(get: { passwords[input.id] ?? "" }, set: { passwords[input.id] = $0 }), prompt: "Password", secure: true)
                                        .textFieldStyle(.quiet)
                                        .frame(maxWidth: 240)
                                        .onSubmit { model.unlock(input.id, password: passwords[input.id] ?? "") }
                                        .accessibilityLabel("Password for \(input.name)")
                                    Button("Unlock") { model.unlock(input.id, password: passwords[input.id] ?? "") }
                                        .buttonStyle(.quietLink)
                                    if input.state == .wrongPassword {
                                        StateText(text: "Wrong password", attention: true)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Clear all") {
                    passwords = [:]
                    model.clear()
                }
                .buttonStyle(.quietLink)
            }
        }
    }

    /// True when the file could not be read (or its password was wrong).
    private func hasProblem(_ input: ConverterModel.Input) -> Bool {
        switch input.state {
        case .loaded, .needsPassword: false
        case .wrongPassword, .failed: true
        }
    }

    private var detectedCard: some View {
        Card(title: "Detected") {
            let certs = model.certificateRows
            let keys = model.keyRows
            if certs.isEmpty && keys.isEmpty {
                Text(model.phase == .needsPassword ? "Enter the password to see what the file holds." : "Nothing usable yet.")
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
            }
            if !certs.isEmpty || !keys.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(certs.enumerated()), id: \.element.id) { index, c in
                        QuietRow(first: index == 0) {
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                CertStatusText(text: c.role)
                                    .frame(width: 96, alignment: .leading)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(c.subject).font(Theme.body).foregroundStyle(Theme.ink).textSelection(.enabled)
                                    Text("Issued by \(c.issuer) · until \(PKIText.day(c.notAfter)) · \(String(describing: c.summary.publicKey))")
                                        .font(Theme.detail)
                                        .foregroundStyle(c.notAfter < Date() ? Theme.attention : Theme.muted)
                                    if !c.sans.isEmpty {
                                        Text("SAN: " + c.sans.joined(separator: ", "))
                                            .font(Theme.detail.monospaced())
                                            .foregroundStyle(Theme.muted)
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                    }
                    ForEach(Array(keys.enumerated()), id: \.element.id) { index, k in
                        QuietRow(first: certs.isEmpty && index == 0) {
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                CertStatusText(text: "Key")
                                    .frame(width: 96, alignment: .leading)
                                Text(k.algorithm).font(Theme.body).foregroundStyle(Theme.ink)
                                if let m = k.matches {
                                    StateText(text: "matches \(m)")
                                } else {
                                    StateText(text: "no matching certificate", attention: true)
                                }
                            }
                        }
                    }
                }
            }
            if let chain = model.chainText {
                StateText(text: chain, attention: !model.bundle.chainIsComplete)
            }
            ForEach(model.notes, id: \.self) { note in
                QuietNote(note)
            }
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Button("Inspect…") { inspecting = true }
                    .buttonStyle(.quietLink)
                    .disabled(certs.isEmpty)
                Menu {
                    Button("LabDC CA") { Task { await model.verifyAgainstDomainCA() } }
                        .disabled(model.caProvider == nil)
                    Button("A CA File…") { verifyWithFile() }
                } label: {
                    Text("Verify against a CA")
                }
                .menuStyle(.button)
                .buttonStyle(.quietLink)
                .menuIndicator(.hidden)
                .fixedSize()
                .disabled(certs.isEmpty)
                Button("Match key and certificate") { model.match() }
                    .buttonStyle(.quietLink)
                    .disabled(keys.isEmpty || certs.isEmpty)
            }
            if !model.toolLines.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(model.toolLines, id: \.self) {
                        Text($0)
                            .font(Theme.detail)
                            .foregroundStyle(model.toolOK == false ? Theme.attention : Theme.ink)
                            .textSelection(.enabled)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.inset, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
        }
    }

    private var convertCard: some View {
        Card(title: "Convert") {
            VStack(alignment: .leading, spacing: 6) {
                FieldCaption("Convert to")
                Picker("Convert to", selection: $model.target) {
                    Section("Format") {
                        ForEach(ConverterModel.Target.formats) { Text($0.title).tag($0) }
                    }
                    Section("For a device") {
                        ForEach(ConverterModel.Target.presets) { Text($0.title).tag($0) }
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 420, alignment: .leading)
                Text(model.target.detail).font(Theme.caption).foregroundStyle(Theme.faint)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if model.outputHasKey || model.needsOutputPassword {
                let label = model.needsOutputPassword ? "Password for the file" : "Key password (empty = not encrypted)"
                VStack(alignment: .leading, spacing: 6) {
                    FieldCaption(label)
                    QuietTextField(label, text: $model.outputPassword, prompt: label, secure: true)
                        .textFieldStyle(.quiet)
                        .frame(maxWidth: 320)
                        .accessibilityLabel("Output password")
                }
            }
            if model.showsLegacySwitch {
                Toggle("Legacy encryption (3DES, SHA-1) for older devices", isOn: $model.legacy)
                    .toggleStyle(.quiet)
                    .font(Theme.body)
                    .frame(maxWidth: 520)
            }
            Button(advanced ? "Hide advanced" : "Advanced") { advanced.toggle() }
                .buttonStyle(.quietLink)
                .accessibilityValue(advanced ? "Shown" : "Hidden")
            if advanced {
                VStack(alignment: .leading, spacing: 14) {
                    Toggle("Include the chain", isOn: $model.includeChain)
                        .toggleStyle(.quiet)
                        .font(Theme.body)
                        .frame(maxWidth: 520)
                    VStack(alignment: .leading, spacing: 6) {
                        FieldCaption("Friendly name (PKCS#12)")
                        QuietTextField("Friendly name (PKCS#12)", text: $model.friendlyName, prompt: "from the input")
                            .textFieldStyle(.quiet)
                            .frame(maxWidth: 320)
                    }
                }
            }
            HStack(alignment: .center, spacing: 16) {
                Button(model.target.isPreset ? "Export…" : "Convert…") {
                    convert()
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canConvert)
                if let problem = model.problem {
                    Text(problem).font(Theme.detail).foregroundStyle(Theme.muted)
                }
            }
            .padding(.top, 4)
            if let result = model.lastResult {
                Text(result).font(Theme.detail).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func convert() {
        do {
            let files = try model.outputs()
            if files.count == 1, let f = files.first {
                if let url = try CertificateFiles.save(Data(f.data), suggestedName: f.name, privateKey: f.containsPrivateKey) {
                    model.lastResult = "Saved \(url.lastPathComponent): \(f.summary)"
                }
            } else {
                let panel = NSOpenPanel()
                panel.canChooseDirectories = true
                panel.canChooseFiles = false
                panel.canCreateDirectories = true
                panel.prompt = "Save Here"
                panel.message = "Choose where to put the \(files.count) files (a new folder is created)."
                guard panel.runModal() == .OK, let folder = panel.url else { return }
                try model.write(files, into: folder)
            }
        } catch {
            self.error = CertificatesModel.describe(error)
        }
    }

    private func verifyWithFile() {
        guard let url = CertificateFiles.choose(multiple: false, message: "Choose the CA certificate to verify against").first else { return }
        do {
            let roots = try CertConvert.load(contentsOf: url).certificates
            Task { await model.verify(against: roots, rootsName: url.lastPathComponent) }
        } catch {
            self.error = "\(url.lastPathComponent): \(error)"
        }
    }
}

/// Inspect: the decoded facts of every certificate.
struct InspectSheet: View {
    let rows: [ConverterModel.CertificateRow]
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        QuietSheet(title: rows.count == 1 ? "Certificate" : "\(rows.count) certificates", width: 640) {
            ForEach(rows) { r in
                Card(title: "\(r.role): \(r.subject)") {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Self.fields(r.summary), id: \.0) { label, value in
                            InfoRow(label: label, value: value, monospaced: label.contains("SHA") || label.contains("Serial"))
                        }
                    }
                }
            }
        } actions: {
            Button("Done") { dismiss() }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
        }
    }

    static func fields(_ s: CertificateSummary) -> [(String, String)] {
        var out: [(String, String)] = [
            ("Subject", s.subject), ("Issuer", s.issuer), ("Serial", s.serial),
            ("Valid from", PKIText.stamp(s.notBefore)), ("Valid until", PKIText.stamp(s.notAfter)),
            ("Public key", "\(s.publicKey)"), ("Signature", s.signatureAlgorithm),
        ]
        if !s.subjectAlternativeNames.isEmpty { out.append(("Names (SAN)", s.subjectAlternativeNames.joined(separator: ", "))) }
        if !s.keyUsage.isEmpty { out.append(("Key usage", s.keyUsage.joined(separator: ", "))) }
        if !s.extendedKeyUsage.isEmpty { out.append(("Purposes (EKU)", s.extendedKeyUsage.joined(separator: ", "))) }
        if let bc = s.basicConstraints { out.append(("Basic constraints", bc)) }
        if let ski = s.subjectKeyIdentifier { out.append(("Subject key ID", ski)) }
        if let aki = s.authorityKeyIdentifier { out.append(("Authority key ID", aki)) }
        out.append(("SHA-256", s.sha256Fingerprint))
        out.append(("SHA-1", s.sha1Fingerprint))
        return out
    }
}
