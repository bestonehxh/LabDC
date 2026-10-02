import PKIKit
import LabDCCore
import SwiftUI

/// Certificates ▸ Templates: the list with its enable switch, the editor sheet and the
/// Configuration NC publish status (PK-5 syncs after every save).
struct CertificatesTemplatesView: View {
    let model: CertificatesModel
    let editor: PKIEditor
    @State private var selection: String?
    @State private var editing: TemplateEditorItem?

    struct Row: Identifiable {
        var id: String { template.name }
        let template: CertificateTemplate
    }

    var body: some View {
        let rows = editor.templates.map(Row.init)
        VStack(alignment: .leading, spacing: 0) {
            Table(rows, selection: $selection) {
                TableColumn("On") { r in
                    Toggle(isOn: Binding(get: { r.template.enabled }, set: { on in
                        Task { await model.perform("Enable template") { try await $0.setTemplate(r.template.name, enabled: on) } }
                    })) {
                        EmptyView()
                    }
                    .toggleStyle(.quiet)
                    .accessibilityLabel("\(r.template.displayName) enabled")
                }
                .width(44)
                TableColumn("Template") { r in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.template.displayName).font(Theme.emphasis).foregroundStyle(Theme.ink)
                        // The internal name only when it differs ("Computer · Computer" said it twice).
                        if let caption = Self.caption(r.template) {
                            Text(caption).font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                    }
                }
                .width(min: 110, ideal: 150, max: 220)
                TableColumn("Purpose") { r in Text(r.template.purposeText).font(Theme.body).lineLimit(2) }.width(min: 110, ideal: 160, max: 240)
                TableColumn("Validity") { r in Text("\(r.template.validityDays) days").font(Theme.body) }.width(76)
                TableColumn("Names from") { r in Text(Self.sanShort(r.template.sanPolicy)).font(Theme.body) }.width(min: 70, ideal: 100, max: 150)
                TableColumn("Enrollment") { r in
                    Text(r.template.autoEnroll ? "Automatic" : (r.template.manualApproval ? "Admin only" : "Request"))
                        .font(Theme.body)
                }
                .width(84)
                TableColumn("Who may enroll") { r in
                    Text(r.template.enrolAllowedGroupSIDs.map(editor.groupName).joined(separator: ", "))
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                        .lineLimit(2)
                }
                .width(min: 110, ideal: 160)
            }
            .tableStyle(.inset(alternatesRowBackgrounds: false))
            .scrollContentBackground(.hidden)
            .contextMenu(forSelectionType: String.self) { ids in
                if let name = ids.first, let t = editor.templates.first(where: { $0.name == name }) {
                    Button("Edit…") { editing = TemplateEditorItem(draft: TemplateDraft(t)) }
                }
            } primaryAction: { ids in
                if let name = ids.first, let t = editor.templates.first(where: { $0.name == name }) {
                    editing = TemplateEditorItem(draft: TemplateDraft(t))
                }
            }
            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Button("New template…") {
                    // Clone the picked template (a 802.1X-ready User template by default) under
                    // a new name and OID; the sheet collects the name.
                    let base = editor.templates.first { $0.name == selection }
                        ?? editor.templates.first { $0.name == "User" }
                        ?? editor.templates.first
                    if let base { editing = TemplateEditorItem(draft: TemplateDraft.new(basedOn: base)) }
                }
                .buttonStyle(.quietLink)
                .disabled(editor.templates.isEmpty)
                Button("Edit…") {
                    if let t = editor.templates.first(where: { $0.name == selection }) { editing = TemplateEditorItem(draft: TemplateDraft(t)) }
                }
                .buttonStyle(.quietLink)
                .disabled(selection == nil)
                Spacer(minLength: 12)
                syncStatus
                Button("Publish") { Task { await editor.publishToDirectory() } }
                    .buttonStyle(.quietLink)
                    .help("Re-sync the Configuration NC objects (templates, CAs, enrollment services); runs by itself after every change")
            }
            .padding(.top, 14)
        }
        .sheet(item: $editing) { item in
            TemplateEditorSheet(draft: item.draft, groups: editor.groups) { t in
                await model.perform(item.draft.isNew ? "Create template" : "Save template") { editor in
                    if item.draft.isNew { try await editor.createTemplate(t) } else { try await editor.saveTemplate(t) }
                }
            }
        }
    }

    @ViewBuilder private var syncStatus: some View {
        if let s = editor.directorySync {
            StateText(text: "Directory: \(s.ok ? (s.text.contains("up to date") ? "up to date" : "published") : "publish failed") · \(PKIText.stamp(s.date))",
                      attention: !s.ok)
                .help(s.text)
        } else {
            StateText(text: "Directory: synced at every server start")
        }
    }

    /// Empty for no names: the cell stays blank rather than saying "None".
    static func sanShort(_ p: SANPolicy) -> String {
        switch p {
        case .dnsHostName: "Computer DNS name"
        case .upn: "User UPN"
        case .fromRequest: "Request"
        case .none: ""
        }
    }

    /// "WebServer · built in", "built in", or nil when the internal name is the display name
    /// and the template is the admin's own.
    static func caption(_ t: CertificateTemplate) -> String? {
        var parts: [String] = []
        if t.name != t.displayName { parts.append(t.name) }
        if t.builtIn { parts.append("built in") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}

struct TemplateEditorItem: Identifiable {
    let id = UUID()
    let draft: TemplateDraft
}

/// The template editor: validity, renewal, purposes, key usage, names, keys, enrollment, groups.
struct TemplateEditorSheet: View {
    @State var draft: TemplateDraft
    let groups: [PKIDirectoryGroup]
    let onSave: (CertificateTemplate) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var working = false
    @State private var advanced = false

    var body: some View {
        QuietSheet(title: draft.isNew ? "New template" : "Edit \(draft.original.displayName)", width: 560,
                   note: "Saved and published to the directory; Windows sees it at its next policy refresh.") {
            if draft.isNew {
                SheetField("Name", note: "Letters, digits and hyphens.") {
                    QuietTextField("Name", text: $draft.name, prompt: "WebServer2").textFieldStyle(.quiet)
                        .autocorrectionDisabled()
                }
            }
            SheetField("Display name") {
                QuietTextField("Display name", text: $draft.displayName, prompt: "Web server").textFieldStyle(.quiet)
            }
            SheetToggle("Enabled", isOn: $draft.enabled)
            HStack(alignment: .top, spacing: 32) {
                SheetField("Valid for") {
                    Stepper("\(draft.validityDays) days", value: $draft.validityDays, in: 1...36500, step: 1)
                        .font(Theme.body).foregroundStyle(Theme.ink).fixedSize()
                }
                .fixedSize()
                SheetField("Renew") {
                    Stepper("\(draft.renewalDays) days before expiry", value: $draft.renewalDays, in: 0...36499)
                        .font(Theme.body).foregroundStyle(Theme.ink).fixedSize()
                }
            }

            section("Purpose")
            ForEach(TemplateDraft.knownEKUs, id: \.oid) { eku in
                SheetToggle(eku.name, isOn: Binding(get: { draft.ekus.contains(eku.oid) }, set: { on in
                    if on { draft.ekus.insert(eku.oid) } else { draft.ekus.remove(eku.oid) }
                }))
            }

            section("Key usage")
            ForEach(TemplateDraft.keyUsages, id: \.1) { usage, name in
                SheetToggle(name, isOn: Binding(get: { draft.keyUsage.contains(usage) }, set: { on in
                    if on { draft.keyUsage.insert(usage) } else { draft.keyUsage.remove(usage) }
                }))
            }

            section("Names and keys")
            SheetField("Alternative names") {
                SheetPicker("Alternative names", selection: $draft.sanPolicy) {
                    ForEach(SANPolicy.allCases, id: \.self) { Text(TemplateDraft.sanPolicyTitle($0)).tag($0) }
                }
            }
            ForEach(TemplateDraft.keyTypes, id: \.0) { key, name in
                SheetToggle("Allow \(name) keys", isOn: Binding(get: { draft.allowedKeyTypes.contains(key) }, set: { on in
                    if on { draft.allowedKeyTypes.insert(key) } else { draft.allowedKeyTypes.remove(key) }
                }))
            }
            SheetField("Smallest RSA key") {
                SheetPicker("Smallest RSA key", selection: $draft.minKeyBits) {
                    ForEach([1024, 2048, 3072, 4096], id: \.self) { Text("\($0) bits").tag($0) }
                }
            }
            .disabled(!draft.allowedKeyTypes.contains("rsa"))

            section("Enrollment")
            SheetToggle("Auto-enroll (Windows PCs and users get it by themselves)", isOn: $draft.autoEnroll)
            SheetToggle("Administrator approval (only signed here or by an admin)", isOn: $draft.manualApproval)
            Text("Groups that may enroll (their members, computers included)")
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .padding(.top, 4)
            ForEach(groups) { g in
                SheetToggle(g.name, isOn: Binding(get: { draft.groupSIDs.contains(g.sid) }, set: { _ in draft.toggleGroup(g.sid) }))
            }
            ForEach(draft.groupSIDs.filter { sid in !groups.contains { $0.sid == sid } }, id: \.self) { sid in
                SheetToggle(sid, isOn: Binding(get: { true }, set: { _ in draft.toggleGroup(sid) }))
            }

            Button(advanced ? "Hide advanced" : "Advanced") { advanced.toggle() }
                .buttonStyle(.quietLink)
                .padding(.top, 8)
                .accessibilityValue(advanced ? "Shown" : "Hidden")
            if advanced {
                // A new template gets its own OID when it is created, not the base's (owner review, 30 Sep 2026).
                SheetField("Template OID") {
                    if draft.isNew {
                        Text("A new OID on create").font(Theme.body).foregroundStyle(Theme.muted)
                    } else {
                        Text(draft.original.oid).font(Theme.body).foregroundStyle(Theme.ink).textSelection(.enabled)
                    }
                }
                SheetField("Other purposes (OIDs)") {
                    QuietTextField("Other purposes (OIDs)", text: $draft.customEKUs, prompt: "1.3.6.1.5.5.7.3.9").textFieldStyle(.quietMonospaced)
                }
            }
            if let warning = draft.template.esc1Warning() {
                Text(warning).font(Theme.detail).foregroundStyle(Theme.attention)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel("Warning: \(warning)")
            }
            ForEach(draft.errors, id: \.self) { e in
                Text(e).font(Theme.detail).foregroundStyle(Theme.attention)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } actions: {
            SheetButtons("Save", disabled: !draft.isValid || !draft.hasChanges || working) {
                working = true
                Task {
                    if await onSave(draft.template) { dismiss() }
                    working = false
                }
            }
        }
        .navigationTitle(draft.isNew ? "New template" : "Template \(draft.original.displayName)")
    }

    /// A group title inside the sheet, with room above it.
    private func section(_ title: String) -> some View {
        Text(title).font(Theme.emphasis).foregroundStyle(Theme.ink)
            .padding(.top, 10)
            .accessibilityAddTraits(.isHeader)
    }
}
