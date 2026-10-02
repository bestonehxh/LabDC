import PKIKit
import LabDCCore
import Store
import SwiftUI

/// Certificates ▸ Enrollment: Windows auto-enrollment (GPO), the web services (CEP/CES), SCEP,
/// EST and the device challenges.
struct CertificatesEnrollmentView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @Bindable var challenges: ChallengeRevealModel
    @State private var newChallenge = false
    @State private var switching = false
    @State private var confirmRevoke: ChallengeRevealModel.Row?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                autoEnrollmentCard
                webServicesCard
                scepCard
                estCard
                challengesCard
            }
            .padding(.bottom, 24)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .sheet(isPresented: $newChallenge, onDismiss: { challenges.dismiss() }) {
            NewChallengeSheet(model: model, editor: editor, challenges: challenges)
        }
    }

    private var autoEnrollmentCard: some View {
        let ae = editor.autoEnrollment
        return Card(title: "Auto-enrollment") {
            Toggle(isOn: Binding(get: { ae.enabled }, set: { on in
                switching = true
                Task {
                    await model.perform(on ? "Turn on auto-enrollment" : "Turn off auto-enrollment") { try await $0.setAutoEnrollment(on) }
                    switching = false
                }
            })) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Joined Windows PCs and users get their certificates by themselves")
                        .font(Theme.body)
                        .foregroundStyle(Theme.ink)
                    Text(ae.enabled ? "On in the Default Domain Policy (computers\(ae.userEnabled ? " and users" : ""))"
                         : (ae.configured ? "Off in the Default Domain Policy" : "Not configured"))
                        .font(Theme.detail).foregroundStyle(Theme.muted)
                }
            }
            .toggleStyle(.quiet)
            .disabled(switching)
            VStack(alignment: .leading, spacing: 0) {
                InfoRow(label: "Policy server (CEP)", value: ae.cepURL, copyable: true)
                if let id = ae.policyID { InfoRow(label: "Policy ID", value: id, copyable: true, monospaced: true) }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("What Windows will do").font(Theme.emphasis).foregroundStyle(Theme.ink)
                ForEach(Array(AutoEnrollmentStatus.whatWindowsWillDo.enumerated()), id: \.offset) { i, line in
                    Text("\(i + 1). \(line)").font(Theme.detail).foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.top, 4)
        }
    }

    private var webServicesCard: some View {
        let ep = editor.endpoints
        return Card(title: "Enrollment web services") {
            if let port = ep.httpsPort {
                VStack(alignment: .leading, spacing: 0) {
                    InfoRow(label: "HTTPS port", value: "\(port) (Kerberos / Negotiate)")
                    // The policy server (CEP) URL is in Auto-enrollment above (owner, 2 Oct 2026).
                    if let ca = editor.currentCA {
                        InfoRow(label: "Enrollment (CES)", value: ep.cesURL(caName: ca.name), copyable: true)
                    }
                }
            } else {
                Text("HTTPS is off, so Windows auto-enrollment cannot reach the CA.").font(Theme.detail).foregroundStyle(Theme.attention)
            }
        }
    }

    private var scepCard: some View {
        Card(title: "SCEP") {
            if let info = editor.deviceEnrollment {
                VStack(alignment: .leading, spacing: 0) {
                    InfoRow(label: "URL", value: info.scepURL, copyable: true)
                    InfoRow(label: "CA SHA-256", value: info.caSHA256, copyable: true, monospaced: true)
                    InfoRow(label: "CA SHA-1", value: info.caSHA1, copyable: true, monospaced: true)
                    InfoRow(label: "CA MD5", value: info.caMD5, copyable: true, monospaced: true)
                    InfoRow(label: "RA", value: info.raSubject.map { "\($0), until \(PKIText.day(info.raValidUntil ?? Date()))" }
                        ?? "Issued when the server starts")
                }
                QuietNote("Also " + info.scepAlternateURLs.joined(separator: ", "))
            }
        }
    }

    private var estCard: some View {
        Card(title: "EST") {
            if let info = editor.deviceEnrollment {
                VStack(alignment: .leading, spacing: 0) {
                    if editor.endpoints.estPort != nil {
                        InfoRow(label: "URL", value: info.estURL, copyable: true)
                    } else {
                        InfoRow(label: "URL", value: "EST is off.", attention: true)
                    }
                    InfoRow(label: "Labels", value: info.estLabels.isEmpty ? "none" : info.estLabels.joined(separator: ", "))
                }
                QuietNote("User name = device name, password = a challenge. With a label: \(info.estURL)/<label>/simpleenroll.")
            }
        }
    }

    private var challengesCard: some View {
        let rows = ChallengeRevealModel.rows(editor.challenges)
        return Card(title: "Challenges") {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text("A challenge lets one device (or any device, if reusable) enroll through SCEP or EST. It is shown once.")
                    .font(Theme.detail).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 12)
                Button("New challenge…") { newChallenge = true }
                    .buttonStyle(.quietLink)
                    .disabled(editor.challengeTemplates.isEmpty)
            }
            Table(rows, selection: $challenges.selection) {
                TableColumn("ID") { r in Text(r.id).font(Theme.mono) }.width(min: 70, ideal: 80)
                TableColumn("Device") { r in Text(r.device).font(Theme.body) }.width(min: 80, ideal: 120)
                TableColumn("Template") { r in Text(r.template).font(Theme.body) }.width(min: 60, ideal: 80)
                TableColumn("Kind") { r in Text(r.reusable).font(Theme.detail).foregroundStyle(Theme.muted) }.width(min: 60, ideal: 80)
                TableColumn("Expires") { r in Text(PKIText.stamp(r.expires)).font(Theme.detail).foregroundStyle(Theme.muted) }.width(min: 100, ideal: 130)
                // One State column: the state, and when it was used under it (owner, 2 Oct 2026).
                TableColumn("State") { r in
                    VStack(alignment: .leading, spacing: 1) {
                        CertStatusText(text: r.state.rawValue.capitalized, attention: r.state == .revoked,
                                       dimmed: r.state == .expired || r.state == .used)
                        if let used = r.usedText {
                            Text(used).font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                    }
                }
                .width(min: 100, ideal: 180)
            }
            .tableStyle(.inset(alternatesRowBackgrounds: false))
            .scrollContentBackground(.hidden)
            .frame(minHeight: 150, idealHeight: 190)
            .overlay {
                if rows.isEmpty {
                    Text("No challenges yet.").font(Theme.detail).foregroundStyle(Theme.muted)
                }
            }
            HStack {
                let selected = rows.first { challenges.selection.contains($0.id) }
                Button("Revoke…") { confirmRevoke = selected }
                .buttonStyle(.quietDestructive)
                .disabled(selected == nil || selected?.state != .active)
                Spacer()
            }
        }
        // Revoking cannot be undone: ask first (owner, 2 Oct 2026).
        .alert("Revoke the challenge \(confirmRevoke?.id ?? "")?",
               isPresented: Binding(get: { confirmRevoke != nil }, set: { if !$0 { confirmRevoke = nil } }),
               presenting: confirmRevoke) { row in
            Button("Revoke", role: .destructive) {
                Task { await model.perform("Revoke challenge") { try await $0.revokeChallenge(id: row.id) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: { row in
            Text("\(row.device) can no longer enroll with it. This cannot be undone; create a new challenge if it is needed again.")
        }
    }
}

/// New Challenge… — device, template, lifetime, reusable; then the text, once.
struct NewChallengeSheet: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @Bindable var challenges: ChallengeRevealModel
    @Environment(\.dismiss) private var dismiss
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let made = challenges.revealed {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Challenge \(made.row.id) created")
                        .font(Theme.emphasis).foregroundStyle(Theme.ink)
                    HStack {
                        Text(made.secret)
                            .font(.system(size: 22, design: .monospaced))
                            .foregroundStyle(Theme.ink)
                            .textSelection(.enabled)
                            .accessibilityLabel("Challenge text")
                        Spacer()
                        CopyButton(value: made.secret)
                    }
                    .padding(12)
                    .background(Theme.inset, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    Text("Shown once — copy it now. Only its hash is stored.")
                        .font(Theme.detail).foregroundStyle(Theme.attention)
                    if let hint = challenges.usageHint {
                        QuietNote(hint)
                    }
                    HStack {
                        Spacer()
                        Button("Done") {
                            challenges.dismiss()
                            dismiss()
                        }
                        .buttonStyle(.quietPrimary)
                        .keyboardShortcut(.defaultAction)
                    }
                }
                .padding(20)
            } else {
                Form {
                    Section("New challenge") {
                        TextField("Device name", text: $challenges.device, prompt: Text("Any device"))
                            .accessibilityHint("The switch or AP host name; empty for any device")
                        Picker("Template", selection: $challenges.template) {
                            ForEach(editor.challengeTemplates, id: \.self) { Text($0).tag($0) }
                        }
                        Picker("Valid for", selection: $challenges.ttl) {
                            ForEach(ChallengeRevealModel.TTL.allCases) { Text($0.title).tag($0) }
                        }
                        Toggle("Reusable (for ClearPass Onboard and similar)", isOn: $challenges.reusable)
                    }
                }
                .formStyle(.grouped)
                .toggleStyle(.quiet)
                .scrollContentBackground(.hidden)
                HStack(spacing: 24) {
                    Spacer()
                    Button("Cancel", role: .cancel) { dismiss() }
                        .buttonStyle(.quietLink)
                        .keyboardShortcut(.cancelAction)
                    Button("Create") {
                        working = true
                        Task {
                            await model.perform("New challenge") { try await challenges.create(using: $0) }
                            working = false
                        }
                    }
                    .buttonStyle(.quietPrimary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || editor.challengeTemplates.isEmpty)
                }
                .padding([.horizontal, .bottom], 20)
            }
        }
        .frame(width: 460)
        .background(Theme.background)
        .onAppear {
            if !editor.challengeTemplates.contains(challenges.template), let first = editor.challengeTemplates.first {
                challenges.template = first
            }
        }
    }
}
