import LabDCCore
import SwiftUI

/// Certificates ▸ Trusted Roots: the Default Domain Policy's Trusted Root list (what every joined
/// Windows PC trusts), Add Certificate…, Add Current CA, Remove, and the GPO version line.
struct CertificatesTrustedRootsView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @State private var selection: String?
    @State private var confirmRemove: TrustedRootInfo?
    @State private var report: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Joined Windows PCs trust these certificates (Default Domain Policy ▸ Trusted Root Certification Authorities). Add the CA of your RADIUS server — for example ClearPass — so 802.1X (PEAP) works without warnings.")
                .font(Theme.detail)
                .foregroundStyle(Theme.muted)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 720, alignment: .leading)
                .padding(.bottom, 16)
            Table(editor.trustedRoots, selection: $selection) {
                TableColumn("Name") { r in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.title).font(Theme.emphasis).foregroundStyle(Theme.ink)
                        if let ca = r.labDCCA { Text("LabDC CA \(ca)").font(Theme.caption).foregroundStyle(Theme.muted) }
                    }
                }
                .width(min: 130, ideal: 180, max: 280)
                TableColumn("Subject") { r in Text(r.subject).font(Theme.body) }.width(min: 120, ideal: 170)
                TableColumn("Thumbprint (SHA-1)") { r in
                    Text(r.groupedThumbprint).font(Theme.mono).foregroundStyle(Theme.muted).lineLimit(2)
                }
                .width(min: 150, ideal: 220, max: 260)
                TableColumn("Valid until") { r in
                    Text(r.notAfter.map(PKIText.day) ?? "?").font(Theme.detail).foregroundStyle(Theme.muted)
                }
                .width(88)
                TableColumn("In Configuration") { r in
                    CertStatusText(text: r.publishedInConfiguration ? "Published" : "Group Policy only",
                                   dimmed: !r.publishedInConfiguration)
                        .accessibilityLabel(r.publishedInConfiguration ? "Published in Configuration" : "Group Policy only")
                }
                .width(120)
            }
            .tableStyle(.inset)
            .scrollContentBackground(.hidden)
            .contextMenu(forSelectionType: String.self) { ids in
                if let r = editor.trustedRoots.first(where: { ids.contains($0.id) }) {
                    Button("Copy Thumbprint") { CertificateFiles.copy(r.thumbprint) }
                    Button("Remove…") { confirmRemove = r }
                }
            }
            .overlay {
                if editor.trustedRoots.isEmpty {
                    VStack(spacing: 8) {
                        Text("No trusted roots")
                            .font(Theme.emphasis)
                            .foregroundStyle(Theme.ink)
                        Text("Drop a CA certificate here (PEM, DER or P7B), or add the current CA.")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .multilineTextAlignment(.center)
                    }
                    .padding(24)
                }
            }
            if let report {
                Text(report)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Rectangle().fill(Theme.line).frame(height: 1).padding(.top, 10)
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Button("Add a certificate…") {
                    add(CertificateFiles.choose(multiple: true, message: "Choose root CA certificates (PEM, DER or P7B); every self-signed one is added."))
                }
                .buttonStyle(.quietLink)
                Button("Add the current CA") {
                    Task {
                        if await model.perform("Add current CA", { _ = try await $0.addCurrentCATrustedRoot() }) {
                            report = "Added \(editor.currentCA?.title ?? "the current CA")."
                        }
                    }
                }
                .buttonStyle(.quietLink)
                .disabled(currentCAPresent)
                Button("Remove…") { confirmRemove = editor.trustedRoots.first { $0.id == selection } }
                    .buttonStyle(.quietDestructive)
                    .disabled(selection == nil)
                Spacer(minLength: 12)
                Text(GPOVersionText.line(version: editor.gpoVersion))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.faint)
                    .textSelection(.enabled)
            }
            .padding(.top, 14)
        }
        .dropDestination(for: URL.self) { urls, _ in
            add(urls.filter(\.isFileURL))
            return true
        }
        .confirmationDialog("Remove “\(confirmRemove?.title ?? "")” from the trusted roots?",
                            isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } }),
                            presenting: confirmRemove) { r in
            Button("Remove", role: .destructive) {
                Task { await model.perform("Remove trusted root") { try await $0.removeTrustedRoot(thumbprint: r.thumbprint) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("Joined PCs drop it at their next policy refresh. It is also removed from the Configuration NC.")
        }
    }

    private var currentCAPresent: Bool {
        guard let t = editor.currentCA?.thumbprint else { return true }
        return editor.trustedRoots.contains { $0.thumbprint == t }
    }

    private func add(_ urls: [URL]) {
        guard !urls.isEmpty else { return }
        Task {
            var messages: [String] = []
            for url in urls {
                await model.perform("Add \(url.lastPathComponent)") { e in
                    let bytes = Array(try Data(contentsOf: url))
                    messages.append(try await e.addTrustedRoots(from: bytes, fileName: url.lastPathComponent).message)
                }
            }
            report = messages.isEmpty ? nil : messages.joined(separator: " ")
        }
    }
}
