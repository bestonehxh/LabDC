import AppKit
import LabDCCore
import SwiftUI
import UniformTypeIdentifiers

/// Certificates in the Quiet look: the page title, text tabs (Authority · Issued · Sign a request ·
/// Templates · Trusted roots · Enrollment · Converter) and the selected section. Every change goes
/// through `PKIEditor` (the CLI's APIs).
struct CertificatesView: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        let model = app.certificates
        QuietPage(title: "Certificates", scrolls: false) {
            VStack(alignment: .leading, spacing: 0) {
                QuietTabs(items: CertificatesSection.allCases.map { ($0, $0.tabTitle) },
                          selection: Binding(get: { model.section }, set: { model.section = $0 }))
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Certificate sections")
                CertificatesDetail(model: model)
                    .padding(.top, 28)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .navigationSubtitle(model.section.tabTitle)
        .task(id: app.controller.status.startedAt) { await model.attach(app.controller) }
        .alert("Certificates", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.alert ?? "")
        }
    }
}

extension CertificatesSection {
    /// The tab's word in the Quiet look; the same as `title` everywhere (owner, 2 Oct 2026).
    var tabTitle: String { title }
}

struct CertificatesDetail: View {
    let model: CertificatesModel
    @Environment(AppModel.self) private var app

    var body: some View {
        if model.section == .converter {
            ConverterView(model: model.converter, compact: false)
        } else if let editor = model.editor {
            VStack(alignment: .leading, spacing: 0) {
                if let error = editor.loadError {
                    QuietNote(error, attention: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.bottom, 12)
                }
                switch model.section {
                case .ca: CertificatesCAView(model: model, editor: editor)
                case .issued: CertificatesIssuedView(model: model, editor: editor, filter: model.issued)
                case .sign: CertificatesSignView(model: model, editor: editor, sign: model.sign)
                case .templates: CertificatesTemplatesView(model: model, editor: editor)
                case .trustedRoots: CertificatesTrustedRootsView(model: model, editor: editor)
                case .enrollment: CertificatesEnrollmentView(model: model, editor: editor, challenges: model.challenges)
                case .converter: EmptyView()
                }
            }
            .overlay(alignment: .topTrailing) {
                SavedPill(generation: model.savedGeneration)
            }
        } else {
            VStack(spacing: 10) {
                Text(app.controller.status.phase == .starting ? "Starting…" : "The server is not running")
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.ink)
                Text("The CA, issued certificates and enrollment appear once every service runs. The converter works anyway.")
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
                Button("Open Converter") { model.section = .converter }
                    .buttonStyle(.quietLink)
                    .padding(.top, 6)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: - Shared pieces

/// A label on the left, a value, something on the right; a hairline above.
struct LabeledLine<Value: View, Trailing: View>: View {
    let label: String
    @ViewBuilder var value: Value
    @ViewBuilder var trailing: Trailing

    var body: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(label)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .frame(width: 128, alignment: .leading)
                value
                    .frame(maxWidth: .infinity, alignment: .leading)
                trailing
            }
            .padding(.vertical, 10)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label)
    }
}

/// `Label   value   Copy` as a hairline row.
struct InfoRow: View {
    let label: String
    let value: String
    var copyable = false
    var monospaced = false
    var attention = false

    var body: some View {
        LabeledLine(label: label) {
            Text(value)
                .font(monospaced ? Theme.mono : Theme.body)
                .foregroundStyle(attention ? Theme.attention : Theme.ink)
                .textSelection(.enabled)
                .lineLimit(3)
        } trailing: {
            if copyable { CopyButton(value: value) }
        }
    }
}

/// The dashed drop area of Sign a request and the converter: a hairline, muted words, no icon.
struct FileDropZone: View {
    let title: String
    let subtitle: String
    var height: CGFloat = 110
    let onDrop: ([URL]) -> Void
    let onChoose: () -> Void
    @State private var targeted = false

    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(Theme.body)
                .foregroundStyle(targeted ? Theme.ink : Theme.muted)
            Text(subtitle)
                .font(Theme.caption)
                .foregroundStyle(Theme.faint)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Choose a file…", action: onChoose)
                .buttonStyle(.quietLink)
                .padding(.top, 4)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: height)
        .background(targeted ? Theme.inset : Color.clear, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(targeted ? Theme.muted : Theme.line, style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
        )
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty else { return false }
            onDrop(files)
            return true
        } isTargeted: { targeted = $0 }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }
}

/// A status word (Valid / Revoked / …): muted, or the attention colour when something is wrong.
struct CertStatusText: View {
    let text: String
    var attention = false
    var dimmed = false

    var body: some View {
        Text(text)
            .font(Theme.detail)
            .foregroundStyle(attention ? Theme.attention : (dimmed ? Theme.faint : Theme.muted))
    }
}

/// A small label above a control (fields outside a Form).
struct FieldCaption: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(Theme.caption).foregroundStyle(Theme.muted)
    }
}
