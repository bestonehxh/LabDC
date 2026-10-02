import AppKit
import LabDCCore
import SwiftUI
import SYSVOL

/// Shared measures of the Group Policy page and RADIUS ▸ Settings: one readable column (so no
/// switch or link ends up at the far edge of a wide window) and one label column.
enum GroupPolicyLayout {
    static let columnWidth: CGFloat = 860
    static let labelWidth: CGFloat = 170
}

/// The Group Policy page's tabs (owner, 1 Oct 2026): what is published and what else the
/// Default Domain Policy carries, then one tab per 802.1X policy, both laid out the same way.
enum GroupPolicyTab: String, CaseIterable, Identifiable {
    case overview, wireless, wired
    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: "Overview"
        case .wireless: "Wireless"
        case .wired: "Wired"
        }
    }
}

/// Group Policy (owner, 1 Oct 2026): what the Default Domain Policy gives joined Windows PCs.
/// Overview: publish status, one line per 802.1X policy, the trust, the trusted roots and the
/// password policy (with links to where they are edited). Wireless and Wired: the same layout,
/// GPMC-style — a policy exists or not (no on/off): its name and description with Edit policy… /
/// Delete policy…, then its profiles as a table with Edit sheets. Nothing reaches Windows until
/// Publish changes, which sends both policies at once.
struct GroupPolicyView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    @State private var snapshot: GroupPolicySnapshot?
    @State private var loaded = false
    @State private var editing: Dot1XProfileSet.Wireless?
    @State private var adding = false
    @State private var editingWired = false
    @State private var creatingWired = false
    @State private var editingWirelessPolicy = false
    @State private var editingWiredPolicy = false
    @State private var confirmRemove: Dot1XProfileSet.Wireless?
    @State private var confirmDeleteWireless = false
    @State private var confirmDeleteWired = false
    @State private var showDetails = false
    @State private var busy = false
    @State private var message: String?
    @State private var failed = false
    @State private var confirmDiscard = false

    var body: some View {
        @Bindable var model = model
        QuietPage(title: "Group Policy", scrolls: false) {
            QuietTabs(items: GroupPolicyTab.allCases.map { ($0, $0.title) }, selection: $model.groupPolicyTab)
            if let snapshot { publishButton(snapshot) }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 36) {
                    if let snapshot {
                        switch model.groupPolicyTab {
                        case .overview:
                            status(snapshot)
                            policies(snapshot)
                            trust(snapshot)
                            alsoCarried(snapshot)
                        case .wireless:
                            pendingLine(snapshot)
                            wireless(snapshot)
                        case .wired:
                            pendingLine(snapshot)
                            wired(snapshot)
                        }
                    } else if loaded {
                        QuietNote("The server is not running. Start it on Services (Restart all services).")
                    }
                }
                .frame(maxWidth: GroupPolicyLayout.columnWidth, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task { await reload() }
        .alert("Discard the changes not published yet?", isPresented: $confirmDiscard) {
            Button("Discard", role: .destructive) { discard() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The wireless and wired lists go back to what is published in Group Policy. Windows is not affected.")
        }
        .onChange(of: model.controllerGeneration) { _, _ in Task { await reload() } }
        .onChange(of: model.controller.status.phase) { _, _ in Task { await reload() } }
        .sheet(isPresented: $adding) {
            WiFiProfileSheet(profile: nil, existing: snapshot?.draft.wireless.map(\.name) ?? [],
                             certificates: snapshot?.choosableCertificates ?? []) { profile, roots in
                try change { set in
                    try set.save(profile)
                    for root in roots { set.addPendingRoot(root) }
                }
            }
        }
        .sheet(item: $editing) { profile in
            WiFiProfileSheet(profile: profile, existing: snapshot?.draft.wireless.map(\.name) ?? [],
                             published: snapshot?.published.wireless(named: profile.name) != nil,
                             certificates: snapshot?.choosableCertificates ?? []) { changed, roots in
                try change { set in
                    try set.save(changed, replacing: profile.name)
                    for root in roots { set.addPendingRoot(root) }
                }
            }
        }
        .sheet(isPresented: $editingWired) {
            WiredProfileSheet(profile: snapshot?.draft.wired, certificates: snapshot?.choosableCertificates ?? []) { w, roots in
                try change { set in
                    set.wired = w
                    for root in roots { set.addPendingRoot(root) }
                }
            }
        }
        .sheet(isPresented: $creatingWired) {
            WiredProfileSheet(profile: nil, certificates: snapshot?.choosableCertificates ?? []) { w, roots in
                try change { set in
                    set.wired = w
                    for root in roots { set.addPendingRoot(root) }
                }
            }
        }
        .sheet(isPresented: $editingWirelessPolicy) {
            PolicyNameSheet(title: "Wireless policy", name: snapshot?.draft.name ?? Dot1XPolicy.defaultName,
                            description: snapshot?.draft.description ?? "") { name, description in
                try change { $0.name = name; $0.description = description }
            }
        }
        .sheet(isPresented: $editingWiredPolicy) {
            PolicyNameSheet(title: "Wired policy", name: snapshot?.draft.wired?.name ?? Dot1XPolicy.defaultName,
                            description: snapshot?.draft.wired?.description ?? "") { name, description in
                try change { $0.wired?.name = name; $0.wired?.description = description }
            }
        }
        .alert("Remove the profile “\(confirmRemove?.name ?? "")”?",
               isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } }),
               presenting: confirmRemove) { profile in
            Button("Remove", role: .destructive) { apply { $0.remove(named: profile.name) } }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text(snapshot?.draft.wireless.count == 1
                 ? "It is the only profile, so the wireless policy goes with it. PCs drop it at their next gpupdate after you publish the changes."
                 : "It leaves the list now; PCs drop it at their next gpupdate after you publish the changes.")
        }
        .alert("Delete the wireless policy?", isPresented: $confirmDeleteWireless) {
            Button("Delete", role: .destructive) { apply { $0.deleteWirelessPolicy() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            let n = snapshot?.draft.wireless.count ?? 0
            Text("Its \(n) profile\(n == 1 ? "" : "s") leave the list. PCs drop the policy at their next gpupdate after you publish the changes.")
        }
        .alert("Delete the wired policy?", isPresented: $confirmDeleteWired) {
            Button("Delete", role: .destructive) { apply { $0.wired = nil } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("PCs stop using 802.1X on Ethernet at their next gpupdate after you publish the changes.")
        }
    }

    // MARK: Overview

    private func status(_ s: GroupPolicySnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(s.statusLine).font(Theme.body).foregroundStyle(s.isPublished ? Theme.ink : Theme.muted)
            if let message { QuietNote(message, attention: failed).textSelection(.enabled) }
        }
    }

    /// Top right after the tabs (owner, 2 Oct 2026): **Publish** in bold green with a badge
    /// counting the changes while there are any; otherwise a plain "Publish again" once
    /// something is published (a newer LabDC can write the same profiles differently).
    @ViewBuilder
    private func publishButton(_ s: GroupPolicySnapshot) -> some View {
        if s.hasUnpublishedChanges {
            Button(busy ? "Publishing…" : "Publish") { publish() }
                .buttonStyle(QuietLinkStyle(size: 14, tint: Theme.go, weight: .bold))
                .disabled(busy)
                .overlay(alignment: .topTrailing) {
                    Text("\(s.changeCount)")
                        .font(.system(size: 10, weight: .bold).monospacedDigit())
                        .foregroundStyle(Theme.background)
                        .padding(.horizontal, 5)
                        .frame(minWidth: 17, minHeight: 17)
                        .background(Capsule().fill(Theme.go))
                        .offset(x: 14, y: -10)
                        .accessibilityLabel("\(s.changeCount) unpublished change\(s.changeCount == 1 ? "" : "s")")
                }
                .padding(.trailing, 12)
                .help("Sends both 802.1X policies to the Default Domain Policy; Windows applies them at gpupdate.")
            // After Publish (owner, 2 Oct 2026): the main action first, the way back second.
            Button("Discard…") { confirmDiscard = true }
                .buttonStyle(.quietDestructive)
                .disabled(busy)
                .help("Forgets the changes not published yet; the lists go back to what Windows has.")
        } else if s.isPublished {
            Button(busy ? "Publishing…" : "Publish again") { publish() }
                .buttonStyle(.quietLink)
                .disabled(busy)
                .help("Sends both policies again as this version of LabDC writes them; the version goes up and Windows re-applies them at gpupdate.")
        }
    }

    /// One line per policy; the whole row opens its tab (owner, 2 Oct 2026: no separate
    /// "Wireless"/"Wired" link repeating the tabs above).
    private func policies(_ s: GroupPolicySnapshot) -> some View {
        QuietSection("802.1X policies") {
            VStack(alignment: .leading, spacing: 0) {
                summaryRow(s.wirelessSummary, state: s.wirelessState, tab: .wireless, first: true)
                summaryRow(s.wiredSummary, state: s.wiredState, tab: .wired)
            }
        }
    }

    private func summaryRow(_ text: String, state: GroupPolicySnapshot.PolicyState, tab: GroupPolicyTab,
                            first: Bool = false) -> some View {
        QuietRow(first: first) {
            Button { model.groupPolicyTab = tab } label: {
                Text(text).font(Theme.body)
                    .foregroundStyle(state == .notSet ? Theme.muted : Theme.ink)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Opens the \(tab.title) tab")
            .accessibilityHint("Opens the \(tab.title) tab")
        }
    }

    /// Wireless / Wired: the last publish result (the Publish button sits top right).
    @ViewBuilder
    private func pendingLine(_ s: GroupPolicySnapshot) -> some View {
        if let message { QuietNote(message, attention: failed).textSelection(.enabled) }
    }

    // MARK: Wireless / Wired (one layout)

    /// The policy header both tabs share: its name, Edit policy… and Delete policy… right after
    /// it, the description, and where the policy stands.
    private func policyHeader(name: String, description: String, state: GroupPolicySnapshot.PolicyState,
                              edit: @escaping () -> Void, delete: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                Text(name).font(Theme.emphasis).foregroundStyle(Theme.ink)
                    .lineLimit(1).truncationMode(.tail)
                Button("Edit policy…", action: edit).buttonStyle(.quietLink).fixedSize()
                Button("Delete policy…", action: delete).buttonStyle(.quietDestructive).fixedSize()
            }
            if !description.isEmpty {
                Text(description)
                    .font(Theme.detail).foregroundStyle(Theme.muted)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// No policy yet: what it is for and the one way to create it.
    private func emptyPolicy(title: String, text: String, action: String, state: GroupPolicySnapshot.PolicyState,
                             create: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(Theme.emphasis).foregroundStyle(Theme.ink)
            Text(text).font(Theme.detail).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            if state == .deletedNotPublished {
                QuietNote("Deleted here; PCs keep the published policy until you publish the changes.")
            }
            Button(action, action: create).buttonStyle(.quietLink).padding(.top, 4)
        }
    }

    @ViewBuilder
    private func wireless(_ s: GroupPolicySnapshot) -> some View {
        if s.draft.wireless.isEmpty {
            emptyPolicy(title: "No wireless policy yet",
                        text: "Add a profile per network your access points broadcast with 802.1X (WPA2/WPA3-Enterprise). The policy exists while it holds a profile.",
                        action: "Add a profile", state: s.wirelessState) { adding = true }
        } else {
            VStack(alignment: .leading, spacing: 28) {
                policyHeader(name: s.draft.name, description: s.draft.description, state: s.wirelessState,
                             edit: { editingWirelessPolicy = true }, delete: { confirmDeleteWireless = true })
                QuietSection(title: "Profiles") {
                    Button("Add a profile") { adding = true }.buttonStyle(.quietLink)
                } content: {
                    VStack(alignment: .leading, spacing: 12) {
                        GPProfileTable(rows: s.draft.wireless.map { Self.row($0, published: s.published.wireless(named: $0.name)) }) { row in
                            wirelessMenu(s, row.id)
                        }
                        QuietNote("Windows tries the profiles in this order. Renaming a profile removes the old-named one from PCs at their next gpupdate.")
                    }
                }
            }
        }
    }

    static func row(_ p: Dot1XProfileSet.Wireless, published old: Dot1XProfileSet.Wireless?) -> GPProfileRow {
        GPProfileRow(id: p.name, name: p.name,
                     detail: p.ssids != [p.name] ? "SSID " + p.ssids.joined(separator: ", ") : nil,
                     pending: old == p ? nil : (old == nil ? "Not published yet" : "Changed, not published yet"),
                     server: radius(p.server), security: p.security.title, method: p.method.shortTitle,
                     signInAs: p.signInAs.title, connection: connection(p))
    }

    static func row(_ w: Dot1XProfileSet.Wired, published old: Dot1XProfileSet.Wired?) -> GPProfileRow {
        GPProfileRow(id: "wired", name: WiredProfileSheet.profileName, detail: "Every wired adapter",
                     pending: old == w ? nil : (old == nil ? "Not published yet" : "Changed, not published yet"),
                     server: radius(w.server), security: nil, method: w.method.shortTitle, signInAs: w.signInAs.title, connection: "Automatic")
    }

    /// "RADIUS cppm.lab.sheep" for another server.
    static func radius(_ server: Dot1XProfileSet.RadiusServer?) -> String? {
        server.map { "RADIUS " + $0.serverNames.joined(separator: "; ") }
    }

    @ViewBuilder
    private func wirelessMenu(_ s: GroupPolicySnapshot, _ name: String) -> some View {
        let index = s.draft.wireless.firstIndex { $0.name == name } ?? 0
        Button("Edit…") { editing = s.draft.wireless(named: name) }
        Button("Move up") { apply { $0.move(named: name, to: index - 1) } }.disabled(index == 0)
        Button("Move down") { apply { $0.move(named: name, to: index + 1) } }
            .disabled(index == s.draft.wireless.count - 1)
        Divider()
        Button("Remove…", role: .destructive) { confirmRemove = s.draft.wireless(named: name) }
    }

    static func connection(_ p: Dot1XProfileSet.Wireless) -> String {
        var parts = [p.connectAutomatically ? "Automatic" : "Manual"]
        if p.connectHidden { parts.append("hidden") }
        if p.connectAutomatically && p.autoSwitch { parts.append("switches") }
        if p.singleSignOn { parts.append("SSO") }
        return parts.joined(separator: ", ")
    }

    @ViewBuilder
    private func wired(_ s: GroupPolicySnapshot) -> some View {
        if let w = s.draft.wired {
            VStack(alignment: .leading, spacing: 28) {
                policyHeader(name: w.name, description: w.description, state: s.wiredState,
                             edit: { editingWiredPolicy = true }, delete: { confirmDeleteWired = true })
                // No "Profile" heading: the table's first column already says it (owner, 2 Oct 2026).
                VStack(alignment: .leading, spacing: 12) {
                    GPProfileTable(rows: [Self.row(w, published: s.published.wired)]) { _ in
                        Button("Edit…") { editingWired = true }
                        Divider()
                        Button("Delete policy…", role: .destructive) { confirmDeleteWired = true }
                    }
                    QuietNote("A wired policy carries one profile. Windows applies it only with the Wired AutoConfig service running; publishing sets it to Automatic.")
                }
            }
        } else {
            emptyPolicy(title: "No wired policy yet",
                        text: "802.1X on Ethernet: joined PCs sign in to the switch port through RADIUS before they get the network. A wired policy carries one profile for every wired adapter.",
                        action: "Create wired policy", state: s.wiredState) { creatingWired = true }
        }
    }

    // MARK: Trust


    private func trust(_ s: GroupPolicySnapshot) -> some View {
        QuietSection(title: "Trust") {
            if s.trust != nil {
                Button(showDetails ? "Hide details" : "Details") { showDetails.toggle() }.buttonStyle(.quietLink)
            }
        } content: {
            VStack(alignment: .leading, spacing: 8) {
                if let t = s.trust {
                    Text("Clients check the RADIUS server's certificate without asking the user. This DC: \(t.serverName), a certificate from \(t.caName).")
                        .font(Theme.body).foregroundStyle(Theme.ink)
                        .fixedSize(horizontal: false, vertical: true)
                    if s.draft.wireless.contains(where: { $0.security == .wpa3Suite192 }) {
                        Text("WPA3-Enterprise 192-bit profiles: a certificate from \(t.suiteBName ?? "the 802.1X 192-bit CA, created when you publish"); clients use P-384 Computer192 / User192 certificates (auto-enrollment is switched on when you publish).")
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if t.previousRootThumbprint != nil {
                        Text("While the root changes, the previous root is trusted as well.")
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                    }
                    if !s.serverLines.isEmpty {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(s.serverLines, id: \.self) { line in
                                Text(line).font(Theme.detail).foregroundStyle(Theme.muted).textSelection(.enabled)
                            }
                        }
                        .padding(.top, 4)
                    }
                    if showDetails {
                        VStack(alignment: .leading, spacing: 6) {
                            thumbprintRow(t.caName, t.caThumbprint)
                            if let name = t.suiteBName, let thumb = t.suiteBThumbprint { thumbprintRow(name, thumb) }
                            if let old = t.previousRootThumbprint { thumbprintRow("Previous root", old) }
                        }
                        .padding(.top, 4)
                    }
                } else {
                    QuietNote("No lab CA yet.")
                }
            }
        }
    }

    private func thumbprintRow(_ name: String, _ thumbprint: String) -> some View {
        GPFormRow(name) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text("SHA-1 " + Self.grouped(thumbprint))
                    .font(Theme.mono).foregroundStyle(Theme.muted)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                CopyButton(value: thumbprint)
            }
        }
    }

    static func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 4).map { i in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: min(4, hex.count - i))]).uppercased()
        }.joined(separator: " ")
    }

    // MARK: Also in the Default Domain Policy

    private func alsoCarried(_ s: GroupPolicySnapshot) -> some View {
        QuietSection("Also in the Default Domain Policy") {
            VStack(alignment: .leading, spacing: 10) {
                GPFormRow("Trusted roots") {
                    HStack(alignment: .firstTextBaseline, spacing: 16) {
                        Text(s.trustedRoots.isEmpty ? "No trusted roots yet" : s.trustedRoots.joined(separator: ", "))
                            .font(Theme.body).foregroundStyle(s.trustedRoots.isEmpty ? Theme.muted : Theme.ink)
                            .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                        Button("Certificates ▸ Trusted roots") {
                            model.certificates.section = .trustedRoots
                            model.selection = .certificates
                        }
                        .buttonStyle(.quietLink).fixedSize()
                    }
                }
                GPFormRow("Password policy") {
                    HStack(alignment: .firstTextBaseline, spacing: 16) {
                        Text(s.passwordPolicy.map(GroupPolicySnapshot.describe) ?? "Unknown")
                            .font(Theme.body).foregroundStyle(Theme.ink)
                            .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                        Button("Settings ▸ System") {
                            model.requestedSettingsTab = .directory
                            openSettings()
                        }
                        .buttonStyle(.quietLink).fixedSize()
                    }
                }
            }
        }
    }

    // MARK: Actions

    private func discard() {
        do {
            try model.controller.discardDot1XDraft()
            message = "Changes discarded; the lists show what is published."
            failed = false
        } catch {
            message = "Not discarded: \(error)"; failed = true
        }
        Task { await reload() }
    }

    private func reload() async {
        snapshot = await model.controller.groupPolicySnapshot()
        loaded = true
    }

    /// Changes the draft and saves it (nothing reaches Windows until Publish changes); throws
    /// for the sheets, which show the error themselves.
    private func change(_ edit: (inout Dot1XProfileSet) throws -> Void) throws {
        guard var draft = snapshot?.draft else { throw CLIError.failure("the server is not running") }
        try edit(&draft)
        draft.prunePendingRoots()
        try model.controller.saveDot1XDraft(draft)
        snapshot?.draft = draft
        message = nil
    }

    /// `change` for menu and alert actions: a failure stays on screen.
    private func apply(_ edit: (inout Dot1XProfileSet) throws -> Void) {
        do { try change(edit) } catch {
            message = "Not changed: \(error)"; failed = true
        }
    }

    private func publish() {
        busy = true
        Task {
            do {
                let report = try await model.controller.publishDot1X()
                let checks = [snapshot?.draft.wireless.isEmpty == false ? "netsh wlan show profiles" : nil,
                              snapshot?.draft.wired != nil ? "netsh lan show profiles" : nil].compactMap { $0 }
                message = "Published as version \(report.version.machine). On a Windows PC: gpupdate /force"
                    + (checks.isEmpty ? "." : ", then \(checks.joined(separator: " and ")).")
                    + (snapshot?.draft.wireless.isEmpty == false
                       ? " A change to a profile the PC already has takes effect after a restart (or net stop wlansvc, net start wlansvc); new and renamed profiles apply at gpupdate."
                       : "")
                failed = false
            } catch {
                message = "Not published: \(error)"; failed = true
            }
            await reload()
            busy = false
        }
    }
}

// MARK: - Building blocks

/// One row of a policy's profile table (Wireless: one per profile; Wired: its one profile).
struct GPProfileRow: Identifiable, Equatable {
    let id: String
    let name: String
    /// Under the name: the SSIDs when they differ from it, "Every wired adapter".
    var detail: String?
    /// "Not published yet" / "Changed, not published yet".
    var pending: String?
    /// Another RADIUS server: "RADIUS cppm.lab.sheep" (nil: this DC).
    var server: String? = nil
    /// Nil for wired: 802.1X on Ethernet has no security mode, so the column is left out.
    let security: String?
    let method: String
    let signInAs: String
    let connection: String
}

/// The profile table both policy tabs use: the same columns, an Edit menu at the end of each row.
struct GPProfileTable<Actions: View>: View {
    let rows: [GPProfileRow]
    @ViewBuilder var actions: (GPProfileRow) -> Actions

    static var columns: [String] { ["Profile", "Security", "Method", "Sign in as", "Connection"] }
    /// Fixed widths of the first four columns, so both tabs' tables line up the same.
    static var widths: [CGFloat] { [170, 170, 120, 130] }

    /// Security only when a row has one (the wired table has none, owner 2 Oct 2026).
    private var showsSecurity: Bool { rows.contains { $0.security != nil } }

    /// The fixed columns, then Connection taking what is left (the Edit column stays narrow).
    @ViewBuilder
    private func cell<V: View>(_ column: Int, _ view: V) -> some View {
        if column < Self.widths.count {
            view.frame(width: Self.widths[column], alignment: .leading)
        } else if column == Self.widths.count {
            view.frame(maxWidth: .infinity, alignment: .leading)
        } else {
            view
        }
    }

    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 18, verticalSpacing: 10) {
            GridRow {
                ForEach(Array((Self.columns + [""]).enumerated()).filter { showsSecurity || $0.offset != 1 }, id: \.offset) { i, title in
                    cell(i, Text(title).font(Theme.caption).foregroundStyle(Theme.muted))
                }
            }
            ForEach(rows) { row in
                Rectangle().fill(Theme.line).frame(height: 1)
                GridRow {
                    cell(0, VStack(alignment: .leading, spacing: 2) {
                        Text(row.name).font(Theme.emphasis).foregroundStyle(Theme.ink)
                        if let detail = row.detail {
                            Text(detail).font(Theme.detail).foregroundStyle(Theme.muted)
                        }
                        if let server = row.server {
                            Text(server).font(Theme.detail).foregroundStyle(Theme.muted)
                        }
                        if let pending = row.pending {
                            Text(pending).font(Theme.caption).foregroundStyle(Theme.faint)
                        }
                    })
                    if showsSecurity {
                        cell(1, Text(row.security ?? "").font(Theme.body).foregroundStyle(Theme.ink))
                    }
                    cell(2, Text(row.method).font(Theme.body).foregroundStyle(Theme.ink))
                    cell(3, Text(row.signInAs).font(Theme.body).foregroundStyle(Theme.ink))
                    cell(4, Text(row.connection).font(Theme.body).foregroundStyle(Theme.ink)
                        .fixedSize(horizontal: false, vertical: true))
                    Menu("Edit") { actions(row) }
                        .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                        .gridColumnAlignment(.trailing)
                }
            }
        }
    }
}

/// A label in the label column, the control after it (left-aligned, never pushed to the far edge).
/// In a sheet the label goes above the control, like every other sheet (UI audit, 2 Oct 2026).
struct GPFormRow<Control: View>: View {
    let label: String
    var alignment: VerticalAlignment = .firstTextBaseline
    @ViewBuilder var control: Control
    @Environment(\.inSheet) private var inSheet

    init(_ label: String, alignment: VerticalAlignment = .firstTextBaseline, @ViewBuilder control: () -> Control) {
        self.label = label
        self.alignment = alignment
        self.control = control()
    }

    var body: some View {
        if inSheet {
            SheetField(label) { control }
        } else {
            HStack(alignment: alignment, spacing: 16) {
                Text(label)
                    .font(Theme.body).foregroundStyle(Theme.muted)
                    .frame(width: GroupPolicyLayout.labelWidth, alignment: .leading)
                control
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// A pop-up choice drawn as a quiet link: the current value, a menu of the others. In a sheet,
/// the pop-up menu every sheet uses (`SheetPicker`).
struct QuietChoice<Value: Hashable>: View {
    /// The field's name (the row's label), read by VoiceOver.
    let label: String
    let options: [Value]
    let title: KeyPath<Value, String>
    @Binding var selection: Value
    var disabled: (Value) -> Bool = { _ in false }
    @Environment(\.inSheet) private var inSheet

    var body: some View {
        if inSheet {
            SheetPicker(label, selection: $selection) {
                ForEach(options, id: \.self) { option in
                    Text(option[keyPath: title]).tag(option).selectionDisabled(disabled(option))
                }
            }
        } else {
            link
        }
    }

    private var link: some View {
        Menu(selection[keyPath: title]) {
            ForEach(options, id: \.self) { option in
                Button(option[keyPath: title]) { selection = option }
                    .disabled(disabled(option))
            }
        }
        .menuStyle(.button)
        .buttonStyle(.quietLink)
        .fixedSize()
        .accessibilityLabel(label)
        .accessibilityValue(selection[keyPath: title])
    }
}

/// Add / edit one Wi-Fi profile: GPMC's profile properties with labels, validated as you type.
struct WiFiProfileSheet: View {
    @Environment(\.dismiss) private var dismiss
    let profile: Dot1XProfileSet.Wireless?
    /// Names already in the list (a new name must not be one of them).
    let existing: [String]
    /// The profile being edited is published (renaming it then removes the old-named one from PCs).
    var published = false
    /// What "Another server" can trust (trusted roots and pending certificates).
    let certificates: [Dot1XTrustCertificate]
    /// The profile, and a certificate added with "Add a certificate…" (joins the trusted roots).
    let save: (Dot1XProfileSet.Wireless, [Dot1XProfileSet.PendingRoot]) throws -> Void

    @State private var name = ""
    @State private var ssidText = ""
    /// The SSID field follows the name until it is edited.
    @State private var ssidFollowsName = true
    @State private var security = Dot1XPolicy.Security.wpa2
    @State private var method = Dot1XPolicy.Method.tls
    @State private var signInAs = Dot1XPolicy.AuthMode.machineOrUser
    @State private var autoConnect = true
    @State private var hidden = false
    @State private var autoSwitch = false
    @State private var singleSignOn = false
    @State private var cacheUserData = true
    @State private var server = RadiusServerChoice()
    @State private var validation = Dot1XProfileSet.ServerValidation.standard
    @State private var failure: String?

    init(profile: Dot1XProfileSet.Wireless?, existing: [String], published: Bool = false,
         certificates: [Dot1XTrustCertificate] = [],
         save: @escaping (Dot1XProfileSet.Wireless, [Dot1XProfileSet.PendingRoot]) throws -> Void) {
        self.profile = profile
        self.existing = existing
        self.published = published
        self.certificates = certificates
        self.save = save
        _server = State(initialValue: RadiusServerChoice(profile?.server))
        _validation = State(initialValue: profile?.validation ?? .standard)
    }

    private var ssids: [String] {
        ssidText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private var candidate: Dot1XProfileSet.Wireless {
        Dot1XProfileSet.Wireless(name: name.trimmingCharacters(in: .whitespaces), ssids: ssids, security: security,
                                 method: method, signInAs: signInAs, connectAutomatically: autoConnect,
                                 connectHidden: hidden, autoSwitch: autoSwitch, singleSignOn: singleSignOn,
                                 cacheUserData: cacheUserData, server: server.server, validation: validation)
    }

    /// What is wrong with the fields, in words (nil: Save is allowed).
    private var problem: String? {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return nil }
        if trimmed != profile?.name, existing.contains(trimmed) { return "There is already a profile named \(trimmed)." }
        do { try candidate.validate() } catch let e as Dot1XPolicy.Invalid {
            switch e {
            case .noSSID: return ssidText.isEmpty ? nil : "Each SSID needs at least one character."
            case let .ssidTooLong(s, n): return "An SSID is 1–32 bytes; “\(s)” is \(n)."
            case .duplicateSSID(let s): return "“\(s)” is listed twice."
            case .tooManySSIDs: return "A profile holds at most 25 SSIDs."
            case .suiteB192NeedsTLS: return "WPA3-Enterprise 192-bit works with EAP-TLS only."
            default: return "\(e)"
            }
        } catch { return "\(error)" }
        return server.problem(certificates: certificates, suiteB: security == .wpa3Suite192)
    }

    private var canSave: Bool {
        problem == nil && !name.trimmingCharacters(in: .whitespaces).isEmpty && !ssids.isEmpty && server.complete
    }

    var body: some View {
        QuietSheet(title: profile == nil ? "New Wi-Fi profile" : "Edit “\(profile?.name ?? "")”", width: 600,
                   failure: failure ?? problem, note: "Saved to the list; Publish sends it to Windows.") {
                GPFormRow("Profile name") {
                    QuietTextField("Profile name", text: $name, prompt: "Staff")
                        .textFieldStyle(.quiet)
                        .onChange(of: name) { _, new in if ssidFollowsName { ssidText = new } }
                }
                SheetField("Network name (SSID)",
                           note: "As the access points broadcast it (case-sensitive). Several SSIDs: separate with commas.") {
                    QuietTextField("Network name (SSID)", text: Binding(get: { ssidText }, set: { ssidText = $0; ssidFollowsName = false }), prompt: "Staff")
                        .textFieldStyle(.quiet)
                }
                GPFormRow("Security") {
                    QuietChoice(label: "Security", options: Dot1XPolicy.Security.allCases, title: \.title,
                                selection: Binding(get: { security }, set: { s in
                                    security = s
                                    if s == .wpa3Suite192 { method = .tls }
                                }))
                }
                GPFormRow("Method") {
                    QuietChoice(label: "Method", options: Dot1XPolicy.Method.allCases, title: \.title, selection: $method,
                                disabled: { security == .wpa3Suite192 && $0 != .tls })
                }
                GPFormRow("Sign in as") {
                    QuietChoice(label: "Sign in as", options: Dot1XPolicy.AuthMode.allCases, title: \.title, selection: $signInAs)
                }
                RadiusServerFields(choice: $server, certificates: certificates)
                ServerValidationFields(validation: $validation)
                GPFormRow("Connection", alignment: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        check("Connect automatically when this network is in range", $autoConnect)
                        check("Switch to a more preferred network if available", $autoSwitch)
                            .disabled(!autoConnect)
                        check("Connect even if the network is not broadcasting its name", $hidden)
                    }
                }
                GPFormRow("Sign-in", alignment: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        check("Single sign-on (connect before the user signs in)", $singleSignOn)
                        check("Cache user information for later connections", $cacheUserData)
                    }
                }
            QuietNote(methodNote)
            if published, let old = profile?.name, name.trimmingCharacters(in: .whitespaces) != old,
               !name.trimmingCharacters(in: .whitespaces).isEmpty {
                QuietNote("Renaming removes the profile named “\(old)” from PCs at their next gpupdate; they get “\(name.trimmingCharacters(in: .whitespaces))” instead.")
            }
        } actions: {
            SheetButtons("Save", disabled: !canSave) {
                do { try save(candidate, server.pendingRoots); dismiss() } catch { failure = "\(error)" }
            }
        }
        .onAppear {
            guard let p = profile else { return }
            name = p.name; ssidText = p.ssids.joined(separator: ", "); ssidFollowsName = p.ssids == [p.name]
            security = p.security; method = p.method; signInAs = p.signInAs
            autoConnect = p.connectAutomatically; hidden = p.connectHidden; autoSwitch = p.autoSwitch
            singleSignOn = p.singleSignOn; cacheUserData = p.cacheUserData
        }
    }

    private var methodNote: String {
        if security == .wpa3Suite192 {
            return "192-bit: clients use a P-384 certificate from the 802.1X 192-bit CA (Computer192 / User192, auto-enrollment switched on when you publish). The access point needs WPA3-Enterprise 192-bit (GCMP-256)."
        }
        return method == .tls
            ? "EAP-TLS signs in with the auto-enrolled Computer or User certificate."
            : "PEAP-MSCHAPv2 signs in with the Windows password."
    }

    /// A checkbox line: its words, the quiet switch at the end of the field column (the switches
    /// of a group line up).
    private func check(_ title: String, _ value: Binding<Bool>) -> some View {
        Toggle(isOn: value) {
            Text(title).font(Theme.body).foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
        .toggleStyle(.quiet)
        .frame(maxWidth: .infinity)
    }
}

/// Create / edit the wired policy's one profile, laid out like the Wi-Fi profile sheet (the same
/// rows; what Ethernet has no choice for is shown as text).
struct WiredProfileSheet: View {
    /// What the profile table calls the wired profile (a `<LANProfile>` has no name of its own).
    static let profileName = "Ethernet"

    @Environment(\.dismiss) private var dismiss
    let profile: Dot1XProfileSet.Wired?
    let certificates: [Dot1XTrustCertificate]
    let save: (Dot1XProfileSet.Wired, [Dot1XProfileSet.PendingRoot]) throws -> Void

    @State private var method = Dot1XPolicy.Method.tls
    @State private var signInAs = Dot1XPolicy.AuthMode.machineOrUser
    @State private var server = RadiusServerChoice()
    @State private var validation = Dot1XProfileSet.ServerValidation.standard
    @State private var failure: String?

    init(profile: Dot1XProfileSet.Wired?, certificates: [Dot1XTrustCertificate] = [],
         save: @escaping (Dot1XProfileSet.Wired, [Dot1XProfileSet.PendingRoot]) throws -> Void) {
        self.profile = profile
        self.certificates = certificates
        self.save = save
        _method = State(initialValue: profile?.method ?? .tls)
        _signInAs = State(initialValue: profile?.signInAs ?? .machineOrUser)
        _server = State(initialValue: RadiusServerChoice(profile?.server))
        _validation = State(initialValue: profile?.validation ?? .standard)
    }

    private var candidate: Dot1XProfileSet.Wired {
        var w = profile ?? Dot1XProfileSet.Wired()
        w.method = method
        w.signInAs = signInAs
        w.server = server.server
        w.validation = validation
        return w
    }

    var body: some View {
        QuietSheet(title: profile == nil ? "New wired policy" : "Edit “\(Self.profileName)”", width: 600,
                   failure: failure ?? server.problem(certificates: certificates, suiteB: false),
                   note: "Saved to the list; Publish sends it to Windows.") {
                SheetField("Profile name", note: "A wired policy carries one profile, used on every wired adapter.") {
                    Text(Self.profileName).font(Theme.body).foregroundStyle(Theme.ink)
                }
                GPFormRow("Method") {
                    QuietChoice(label: "Method", options: Dot1XPolicy.Method.allCases, title: \.title, selection: $method)
                }
                GPFormRow("Sign in as") {
                    QuietChoice(label: "Sign in as", options: Dot1XPolicy.AuthMode.allCases, title: \.title, selection: $signInAs)
                }
                RadiusServerFields(choice: $server, certificates: certificates)
                ServerValidationFields(validation: $validation)
                GPFormRow("Connection") {
                    Text("Automatic: Windows signs in when a cable is plugged in.").font(Theme.body).foregroundStyle(Theme.ink)
                }
            QuietNote(method == .tls
                 ? "EAP-TLS signs in with the auto-enrolled Computer or User certificate."
                 : "PEAP-MSCHAPv2 signs in with the Windows password.")
        } actions: {
            SheetButtons(profile == nil ? "Create" : "Save",
                         disabled: !server.complete || server.problem(certificates: certificates, suiteB: false) != nil) {
                do { try save(candidate, server.pendingRoots); dismiss() } catch { failure = "\(error)" }
            }
        }
    }
}

/// The "RADIUS server" choice of a profile sheet (owner, 1 Oct 2026): this DC, or another server
/// (e.g. ClearPass with a self-signed certificate) by the names in its certificate and the one
/// certificate Windows trusts for it.
struct RadiusServerChoice: Equatable {
    enum Kind: String, CaseIterable, Hashable {
        case labDC, other
        var title: String { self == .labDC ? "This DC (LabDC RADIUS)" : "Another server (e.g. ClearPass)" }
    }

    var kind = Kind.labDC
    /// "cppm.lab.sheep; cppm2.lab.sheep".
    var namesText = ""
    var thumbprint: String?
    /// More certificates the profile trusts (picked from the same file as the chosen one).
    var alsoTrusted: [String] = []
    /// Added with "Add a certificate…" (not trusted roots yet).
    var imported: [Dot1XTrustCertificate] = []

    init(_ server: Dot1XProfileSet.RadiusServer? = nil) {
        guard let server else { return }
        kind = .other
        namesText = server.serverNames.joined(separator: "; ")
        thumbprint = server.trustedRoot
        alsoTrusted = server.alsoTrusted
    }

    var names: [String] { Dot1XProfileSet.RadiusServer.names(namesText) }

    /// What the profile stores: nil for this DC.
    var server: Dot1XProfileSet.RadiusServer? {
        guard kind == .other, let thumbprint else { return nil }
        return Dot1XProfileSet.RadiusServer(serverNames: names, trustedRoot: thumbprint, alsoTrusted: alsoTrusted)
    }

    var complete: Bool { kind == .labDC || thumbprint != nil }

    /// The imported certificates the profile trusts.
    var pendingRoots: [Dot1XProfileSet.PendingRoot] {
        guard let server else { return [] }
        return imported.filter { server.allTrusted.contains($0.thumbprint) }
            .map { Dot1XProfileSet.PendingRoot(der: $0.der, name: $0.name) }
    }

    /// One certificate from the menu: the profile trusts only it.
    mutating func choose(_ c: Dot1XTrustCertificate) {
        thumbprint = c.thumbprint
        alsoTrusted = []
    }

    /// Certificates picked from a file: the profile trusts all of them (a self-signed one named
    /// first); the server names come from the file when none are typed yet.
    mutating func importPicked(_ picked: [Dot1XTrustCertificate], known: [Dot1XTrustCertificate], serverNames: [String]) {
        guard let first = Dot1XTrustCertificate.primary(picked) else { return }
        for var c in picked where !known.contains(where: { $0.thumbprint == c.thumbprint }) {
            c.pending = true
            imported.removeAll { $0.thumbprint == c.thumbprint }
            imported.append(c)
        }
        thumbprint = first.thumbprint
        alsoTrusted = picked.map(\.thumbprint).filter { $0 != first.thumbprint }
        if names.isEmpty { namesText = serverNames.joined(separator: "; ") }
    }

    func all(_ certificates: [Dot1XTrustCertificate]) -> [Dot1XTrustCertificate] {
        certificates + imported.filter { c in !certificates.contains { $0.thumbprint == c.thumbprint } }
    }

    func chosen(_ certificates: [Dot1XTrustCertificate]) -> Dot1XTrustCertificate? {
        all(certificates).first { $0.thumbprint == thumbprint }
    }

    /// The other trusted certificates, as known.
    func others(_ certificates: [Dot1XTrustCertificate]) -> [Dot1XTrustCertificate] {
        let list = all(certificates)
        return alsoTrusted.compactMap { t in list.first { $0.thumbprint == t } }
    }

    /// In words, what keeps Save off (nil: fine or not filled in yet).
    func problem(certificates: [Dot1XTrustCertificate], suiteB: Bool) -> String? {
        guard kind == .other else { return nil }
        if let thumbprint, chosen(certificates) == nil {
            return "Certificate \(thumbprint) is no longer in the trusted roots: choose another."
        }
        if let missing = alsoTrusted.first(where: { t in !all(certificates).contains { $0.thumbprint == t } }) {
            return "Certificate \(missing) is no longer in the trusted roots: choose the certificate again."
        }
        if suiteB, let c = chosen(certificates), !c.p384 {
            return "WPA3-Enterprise 192-bit needs an ECDSA P-384 server certificate; \(c.name) is not."
        }
        return nil
    }
}

/// The RADIUS server rows of both profile sheets.
struct RadiusServerFields: View {
    @Binding var choice: RadiusServerChoice
    let certificates: [Dot1XTrustCertificate]
    @State private var importFailure: String?
    @State private var picking: CertificatePickRequest?

    /// The chosen server certificate's CN when the typed names leave it out (nil: fine, none
    /// typed, or a CA was chosen). An IP-literal CN is not asked for: the muted IP note below
    /// says to prefer a name instead (owner, 2 Oct 2026).
    private var cnMissing: String? {
        guard let c = choice.chosen(certificates), !c.isCA, let cn = c.commonName, !choice.names.isEmpty,
              !Dot1XTrustCertificate.isIPLiteral(cn),
              !choice.names.contains(where: { $0.caseInsensitiveCompare(cn) == .orderedSame }) else { return nil }
        return cn
    }

    /// IP addresses in the chosen server certificate or typed as server names.
    private var ipNames: [String] {
        let fromCertificate = ([choice.chosen(certificates)] + choice.others(certificates)).compactMap { $0 }
            .filter { !$0.isCA }.flatMap(\.ipNames)
        return fromCertificate + choice.names.filter(Dot1XTrustCertificate.isIPLiteral)
    }

    var body: some View {
        GPFormRow("RADIUS server") {
            QuietChoice(label: "RADIUS server", options: RadiusServerChoice.Kind.allCases, title: \.title, selection: $choice.kind)
        }
        if choice.kind == .other {
            GPFormRow("Server name(s)") {
                VStack(alignment: .leading, spacing: 4) {
                    QuietTextField("Server names", text: $choice.namesText, prompt: "cppm.lab.sheep").textFieldStyle(.quiet)
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text("The names in that server's certificate (separate with semicolons). Empty: Windows checks only the trusted certificate, not the name.")
                            .font(Theme.caption).foregroundStyle(Theme.faint)
                            .fixedSize(horizontal: false, vertical: true)
                        if let c = choice.chosen(certificates), !c.isCA, !c.serverNames.isEmpty {
                            Button("Use the certificate's names") { choice.namesText = c.serverNames.joined(separator: "; ") }
                                .buttonStyle(QuietLinkStyle(size: 11, tint: Theme.go, weight: .bold)).fixedSize()
                        }
                    }
                    if let cn = cnMissing {
                        Text("Windows compares the server name with the certificate's name, \(cn); without it the PC refuses the server and the connection times out.")
                            .font(Theme.caption).foregroundStyle(Theme.attention)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if !ipNames.isEmpty {
                        Text("Windows matches server names against the certificate's name; an IP address may not match — prefer that name.")
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            GPFormRow("Trusted certificate") {
                VStack(alignment: .leading, spacing: 4) {
                    Menu(choice.chosen(certificates).map(Self.title) ?? "Choose…") {
                        ForEach(choice.all(certificates)) { c in
                            Button(Self.title(c)) { choice.choose(c) }
                        }
                        if !choice.all(certificates).isEmpty { Divider() }
                        Button("Add a certificate…") { importCertificate() }
                    }
                    .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                    Text(choice.chosen(certificates).map { "SHA-1 " + GroupPolicyView.grouped($0.thumbprint) }
                         ?? "One of Certificates ▸ Trusted Roots (a root CA or the server's own certificate), or a .pem / .cer / .der / .p7b file.")
                        .font(Theme.caption).foregroundStyle(Theme.faint)
                        .fixedSize(horizontal: false, vertical: true)
                    let others = choice.others(certificates)
                    if !others.isEmpty {
                        Text("Also trusts " + others.map(Self.title).joined(separator: "; ") + ".")
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text("Windows trusts this exactly as GPMC does; if the server also sends its CA, Windows may check that CA instead.")
                        .font(Theme.caption).foregroundStyle(Theme.faint)
                        .fixedSize(horizontal: false, vertical: true)
                    if let importFailure {
                        Text(importFailure).font(Theme.caption).foregroundStyle(Theme.attention)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .sheet(item: $picking) { request in
                CertificatePickSheet(fileName: request.fileName, certificates: request.certificates) { picked in
                    choice.importPicked(picked, known: certificates, serverNames: request.serverNames)
                }
            }
        }
    }

    /// "ClearPass (root CA)", "cppm.lab.sheep (server certificate issued by ClearPass CA)".
    static func title(_ c: Dot1XTrustCertificate) -> String {
        // Say which kind it is (owner, 1 Oct 2026: "why self-signed?").
        "\(c.name) (\(c.role))" + (c.pending ? " · added when you publish" : "")
    }

    private func importCertificate() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the RADIUS server's certificate, the root CA that issued it, or a file with both."
        panel.allowedContentTypes = CertificateFiles.certificateTypes + [.data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let file = try Dot1XTrustCertificate.candidates(Array(try Data(contentsOf: url)), fileName: url.lastPathComponent)
            importFailure = nil
            if file.certificates.count == 1 {
                choice.importPicked(file.certificates, known: certificates, serverNames: file.serverNames)
            } else {
                picking = CertificatePickRequest(fileName: url.lastPathComponent, certificates: file.certificates,
                                                 serverNames: file.serverNames)
            }
        } catch {
            importFailure = "\(error)"
        }
    }
}

/// GPMC's server-validation choices of a profile (owner, 1 Oct 2026: a ClearPass profile failed
/// with access_denied and Windows never said why).
struct ServerValidationFields: View {
    @Binding var validation: Dot1XProfileSet.ServerValidation

    var body: some View {
        GPFormRow("Server check", alignment: .top) {
            VStack(alignment: .leading, spacing: 8) {
                check("Verify the server's identity", $validation.verify)
                if !validation.verify {
                    Text("Windows connects to any server that answers: anyone with an access point can collect sign-ins. Turn it back on after testing.")
                        .font(Theme.caption).foregroundStyle(Theme.attention)
                        .fixedSize(horizontal: false, vertical: true)
                }
                check("Ask the user when the server can't be verified", $validation.promptUser)
                Text("Turn on while testing: Windows then shows the certificate the server sent.")
                    .font(Theme.caption).foregroundStyle(Theme.faint)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func check(_ title: String, _ value: Binding<Bool>) -> some View {
        Toggle(isOn: value) {
            Text(title).font(Theme.body).foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
        .toggleStyle(.quiet)
        .frame(maxWidth: .infinity)
    }
}

/// The name and description of the Wi-Fi or wired policy (`<name>` / `<description>`). The
/// directory object keeps its CN and GUID: a rename updates it in place.
struct PolicyNameSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    @State var name: String
    @State var description: String
    let save: (String, String) throws -> Void
    @State private var failure: String?

    init(title: String, name: String, description: String, save: @escaping (String, String) throws -> Void) {
        self.title = title
        _name = State(initialValue: name)
        _description = State(initialValue: description)
        self.save = save
    }

    var body: some View {
        QuietSheet(title: title, width: 520, failure: failure) {
            SheetField("Name") { QuietTextField("Name", text: $name, prompt: Dot1XPolicy.defaultName).textFieldStyle(.quiet) }
            SheetField("Description") {
                // Two to four lines, not one clipped line (owner, 2 Oct 2026).
                QuietTextField("Description", text: $description, prompt: "Optional", axis: .vertical).textFieldStyle(.quiet).lineLimit(2...4)
            }
            QuietNote("Shown in Group Policy Management on Windows. Publish updates the published policy in place.")
        } actions: {
            SheetButtons("Save", disabled: name.trimmingCharacters(in: .whitespaces).isEmpty) {
                do { try save(name.trimmingCharacters(in: .whitespaces), description.trimmingCharacters(in: .whitespacesAndNewlines)); dismiss() } catch { failure = "\(error)" }
            }
        }
    }
}
