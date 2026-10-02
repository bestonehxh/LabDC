import PKIKit
import LabDCCore
import SwiftUI

/// Certificates ▸ Issued: every certificate the CAs issued, search/filter, Revoke…, Export.
struct CertificatesIssuedView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @Bindable var filter: IssuedFilterModel
    @State private var revoking: IssuedRow?

    var body: some View {
        let rows = filter.rows(editor.issued)
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 28) {
                QuietTextField("Search", text: $filter.search, prompt: "Serial, subject, name or requester")
                    .textFieldStyle(.quiet)
                    .frame(maxWidth: 260)
                    .accessibilityLabel("Search issued certificates")
                QuietTabs(items: IssuedFilterModel.Status.allCases.map { ($0, $0.rawValue) }, selection: $filter.status)
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Status filter")
                Picker("Template", selection: $filter.template) {
                    Text("All templates").tag(String?.none)
                    ForEach(Set(editor.issued.map(\.templateName)).sorted(), id: \.self) { Text($0).tag(String?.some($0)) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .accessibilityLabel("Template filter")
                Spacer(minLength: 12)
                Text("\(rows.count) of \(editor.issued.count)")
                    .font(Theme.detail.monospacedDigit())
                    .foregroundStyle(Theme.faint)
            }
            .padding(.bottom, 16)
            // Owner, 27 Sep 2026: the same quiet table as Users (no system chrome, no blue rows).
            IssuedTable(rows: rows, selection: $filter.selection) { row in actions(row) }
            .overlay {
                if rows.isEmpty {
                    VStack(spacing: 8) {
                        Text(editor.issued.isEmpty ? "No certificates issued yet" : "No match")
                            .font(Theme.emphasis)
                            .foregroundStyle(Theme.ink)
                        Text(editor.issued.isEmpty
                             ? "Certificates signed here, enrolled by Windows PCs (auto-enrollment) or by devices (SCEP/EST) appear in this list."
                             : "Change the search or the filters.")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 380)
                    }
                    .padding(24)
                }
            }
            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                let selected = rows.first { filter.selection.contains($0.id) }
                Button("Revoke…") { revoking = selected }
                    .buttonStyle(.quietDestructive)
                    .disabled(selected == nil || selected?.isRevoked == true)
                Menu {
                    if let selected { exportItems(selected) }
                } label: {
                    Text("Export")
                }
                .menuStyle(.button)
                .buttonStyle(.quietLink)
                .menuIndicator(.hidden)
                .fixedSize()
                .disabled(selected == nil)
                Button("Copy serial") { if let s = selected { CertificateFiles.copy(s.serial.uppercased()) } }
                    .buttonStyle(.quietLink)
                    .disabled(selected == nil)
                Spacer(minLength: 12)
                QuietNote("Revoked certificates go into the CA's CRL at once.")
            }
            .padding(.top, 14)
        }
        .sheet(item: $revoking) { row in
            RevokeSheet(row: row) { reason in
                await model.perform("Revoke") { try await $0.revoke(serial: row.serial, reason: reason) }
            }
        }
    }

    @ViewBuilder private func actions(_ row: IssuedRow) -> some View {
        Button("Revoke…") { revoking = row }.disabled(row.isRevoked)
        Menu("Download") { exportItems(row) }
        Button("Copy Serial") { CertificateFiles.copy(row.serial.uppercased()) }
    }

    @ViewBuilder private func exportItems(_ row: IssuedRow) -> some View {
        Button("PEM (.pem)…") { export(row, .pem) }
        Button("DER (.cer)…") { export(row, .der) }
        Button("PKCS#7 with CA (.p7b)…") { export(row, .p7b) }
        Divider()
        Button("Export Chain (PEM)…") { export(row, .chainPEM) }
    }

    private func export(_ row: IssuedRow, _ format: PKIEditor.IssuedExport) {
        guard let cert = editor.issued.first(where: { $0.serial == row.serial }) else { return }
        let cn = row.fileBaseName
        Task {
            await model.perform("Export") { e in
                let data = try await e.export(cert, as: format)
                let suffix = format == .chainPEM ? "-chain" : ""
                try CertificateFiles.save(data, suggestedName: "\(cn)\(suffix).\(format.fileExtension)")
            }
        }
    }
}

/// Revoke… — the reason picker.
struct RevokeSheet: View {
    let row: IssuedRow
    let onRevoke: (RevocationReason) async -> Bool
    @State private var reason: RevocationReason = .unspecified
    @State private var working = false
    @Environment(\.dismiss) private var dismiss

    static let reasons = RevocationReason.allCases.filter { $0 != .removeFromCRL && $0 != .aaCompromise }

    var body: some View {
        QuietSheet(title: "Revoke \(row.subject)?",
                   subtitle: "Serial \(row.serial.uppercased()), template \(row.template), CA \(row.caName). The certificate goes into the CRL at once; devices that check the CRL refuse it from their next download.",
                   width: 480) {
            SheetField("Reason",
                       note: reason == .certificateHold ? "A hold can later be made final with another reason; it cannot be lifted." : nil) {
                SheetPicker("Reason", selection: $reason) {
                    ForEach(Self.reasons, id: \.self) { Text(PKIText.reason($0)).tag($0) }
                }
            }
        } actions: {
            SheetButtons("Revoke", role: .destructive, disabled: working) {
                working = true
                Task {
                    if await onRevoke(reason) { dismiss() }
                    working = false
                }
            }
        }
    }
}

/// Serial · Subject (names under it) · Template · Requester · Issued · Expires · Status: hairline
/// rows, the selected one with a soft fill and an ink edge; right-click for Revoke / Export.
private struct IssuedTable<RowMenu: View>: View {
    let rows: [IssuedRow]
    @Binding var selection: Set<String>
    @ViewBuilder let menu: (IssuedRow) -> RowMenu

    private static var spacing: CGFloat { 16 }
    private static var inset: CGFloat { 10 }

    /// Which optional columns fit: Requester goes first, then Template, then Issued, so the
    /// subject keeps at least 180 pt in a narrow window.
    private struct Shown { var template = true, requester = true, issued = true }

    private static func shown(width: CGFloat) -> Shown {
        var s = Shown()
        func needed() -> CGFloat {
            var w: CGFloat = 104 + 180 + 92 + 110 + 2 * inset
            var n = 4
            if s.template { w += 120; n += 1 }
            if s.requester { w += 120; n += 1 }
            if s.issued { w += 92; n += 1 }
            return w + spacing * CGFloat(n - 1)
        }
        if needed() > width { s.requester = false }
        if needed() > width { s.template = false }
        if needed() > width { s.issued = false }
        return s
    }

    var body: some View {
        GeometryReader { geo in
            table(Self.shown(width: geo.size.width))
                .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
        }
    }

    private func table(_ show: Shown) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: Self.spacing) {
                title("Serial").frame(width: 104, alignment: .leading)
                title("Subject").frame(maxWidth: .infinity, alignment: .leading)
                if show.template { title("Template").frame(width: 120, alignment: .leading) }
                if show.requester { title("Requester").frame(width: 120, alignment: .leading) }
                if show.issued { title("Issued").frame(width: 92, alignment: .trailing) }
                title("Expires").frame(width: 92, alignment: .trailing)
                title("Status").frame(width: 110, alignment: .leading)
            }
            .padding(.horizontal, Self.inset)
            .padding(.bottom, 8)
            Rectangle().fill(Theme.line).frame(height: 1)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(rows) { r in row(r, show) }
                }
            }
            .scrollIndicators(.automatic)
        }
    }

    private func title(_ text: String) -> some View {
        Text(text).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
    }

    private func row(_ r: IssuedRow, _ show: Shown) -> some View {
        let selected = selection.contains(r.id)
        let dim = r.state == .expired
        return VStack(spacing: 0) {
            HStack(alignment: .center, spacing: Self.spacing) {
                Text(r.shortSerial)
                    .font(Theme.mono)
                    .foregroundStyle(Theme.muted)
                    .help(r.serial.uppercased())
                    .frame(width: 104, alignment: .leading)
                VStack(alignment: .leading, spacing: 1) {
                    Text(r.subject)
                        .foregroundStyle(dim ? Theme.faint : Theme.ink)
                        .fontWeight(selected ? .medium : .regular)
                    if !r.names.isEmpty {
                        Text(r.names).font(Theme.caption).foregroundStyle(Theme.muted)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if show.template { Text(r.template).frame(width: 120, alignment: .leading) }
                if show.requester { Text(r.requester).frame(width: 120, alignment: .leading) }
                if show.issued { Text(PKIText.day(r.issued)).monospacedDigit().frame(width: 92, alignment: .trailing) }
                Text(PKIText.day(r.expires)).monospacedDigit().frame(width: 92, alignment: .trailing)
                // One word in the column ("Revoked (Supers…" was cut); the reason in the tooltip.
                CertStatusText(text: r.statusWord, attention: r.isRevoked, dimmed: dim)
                    .frame(width: 110, alignment: .leading)
                    .help(r.statusText)
            }
            .font(Theme.body)
            .foregroundStyle(dim ? Theme.faint : Theme.muted)
            .lineLimit(1)
            .truncationMode(.tail)
            .padding(.horizontal, Self.inset)
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .background(selected ? Theme.selection : Color.clear)
            .overlay(alignment: .leading) {
                if selected { Rectangle().fill(Theme.ink).frame(width: 2) }
            }
            Rectangle().fill(Theme.line).frame(height: 1)
        }
        .contentShape(Rectangle())
        .onTapGesture { selection = [r.id] }
        .contextMenu { menu(r) }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}
