import AppKit
import AuthKit
import DNSKit
import NetlogonService
import LabDCCore
import Store
import SwiftUI

/// §7.7 without the RADIUS tab: General / System / Backup, in the Quiet look (owner, 27 Sep
/// 2026; the Directory tab is titled System): text-only tabs, the page background, one row per setting (label and a one-line
/// description on the left, the control on the right, hairlines between). Every change applies at
/// once and shows the 1-second "Saved" note; there is no Apply.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var tab: SettingsTab

    init(tab: SettingsTab = .general) {
        _tab = State(initialValue: tab)
    }

    var body: some View {
        // Owner, 28 Sep 2026: the system tab bar left an empty icon box above text-only tabs, so
        // the tabs are the same text tabs as every page (QuietTabs), under the window title.
        VStack(alignment: .leading, spacing: 0) {
            QuietTabs(items: SettingsTab.allCases.map { ($0, $0.title) }, selection: $tab)
                .padding(.horizontal, 36)
                .padding(.top, 14)
                .padding(.bottom, 12)
            Rectangle().fill(Theme.line).frame(height: 1)
            Group {
                switch tab {
                case .general: GeneralSettings()
                case .directory: DirectorySettings()
                case .backup: BackupSettings()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(width: 620, height: 560)
        .background(Theme.background)
        .navigationTitle("Settings")
        .onAppear { takeRequestedTab() }
        .onChange(of: model.requestedSettingsTab) { _, _ in takeRequestedTab() }
        .overlay(alignment: .bottom) {
            SavedPill(generation: model.controller.savedGeneration)
                .padding(.bottom, 12)
        }
    }

    private func takeRequestedTab() {
        guard let requested = model.requestedSettingsTab else { return }
        tab = requested
        model.requestedSettingsTab = nil
    }
}

enum SettingsTab: Hashable, CaseIterable {
    case general, directory, backup

    var title: String {
        switch self {
        case .general: "General"
        case .directory: "System"
        case .backup: "Backup"
        }
    }
}

// MARK: - Quiet settings building blocks

/// One settings tab: the page background, generous margins, sections stacked with whitespace.
struct SettingsPage<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 36) {
                content
            }
            .padding(.horizontal, 36)
            .padding(.top, 28)
            .padding(.bottom, 64)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.background)
    }
}

/// The left side of a settings row: the label, and a one-line description under it in muted.
struct SettingsLabel: View {
    let title: String
    var detail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(Theme.body)
                .foregroundStyle(Theme.ink)
            if let detail {
                Text(detail)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A settings row: label and description on the left, the control on the right, a hairline above.
struct SettingsRow<Control: View>: View {
    let title: String
    var detail: String?
    var first = false
    @ViewBuilder var control: Control

    var body: some View {
        QuietRow(first: first) {
            HStack(alignment: .center, spacing: 24) {
                SettingsLabel(title: title, detail: detail)
                control
            }
        }
    }
}

/// A read-only fact: label on the left, the value (selectable) on the right.
struct SettingsFact: View {
    let title: String
    let value: String
    var first = false

    var body: some View {
        QuietRow(first: first) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                // The label in ink like every other settings row's; the value is what is muted
                // (a label in muted beside "NetBIOS name" in ink read as two kinds of row).
                Text(title)
                    .font(Theme.body)
                    .foregroundStyle(Theme.ink)
                Spacer(minLength: 16)
                Text(value)
                    .font(Theme.body)
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
        }
    }
}

// MARK: General

struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(GreetingPicture.storageKey) private var greetingPicture = GreetingPicture.five.rawValue
    @State private var message: String?
    @State private var failed = false
    @State private var netbiosName = ""
    @State private var netbiosBusy = false
    @State private var confirmNetbios = false
    @State private var switchTarget: AppProfile?
    @State private var deleteTarget: AppProfile?
    @State private var showRenameDomain = false
    @State private var newDomainName = ""
    @State private var domainMessage: String?
    @State private var showNewProfile = false
    @State private var profileError: String?
    @State private var renaming: AppProfile?
    @State private var renameTo = ""
    /// Shown inside the Rename sheet (not behind it).
    @State private var renameError: String?
    @State private var renameBusy = false
    /// New profile ▸ Create and switch asks first, like Switch… (it stops every service).
    @State private var createTarget: String?
    @State private var profilesRevision = 0
    @State private var profileList: [AppProfile] = []
    @State private var confirmStartOver = false
    @State private var startOverFailed: String?
    @State private var startOverMessage: String?

    var body: some View {
        let status = model.controller.status
        // While services start, stop or restart (a domain rename included), nothing may replace
        // the controller or move its folder.
        let settling = status.isBusy
        SettingsPage {
            QuietSection("Greeting") {
                SettingsRow(title: "Greeting picture",
                            detail: "The picture beside the greeting on the Overview. It plays when LabDC opens and when the greeting changes.",
                            first: true) {
                    Picker("Greeting picture", selection: $greetingPicture) {
                        ForEach(GreetingPicture.allCases) { picture in
                            Text(picture.title).tag(picture.rawValue)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel("Greeting picture")
                }
                QuietRow {
                    VStack(alignment: .leading, spacing: 8) {
                        SettingsLabel(title: "Try a picture",
                                      detail: "Plays it on the Overview now, without waiting for the clock or a problem.")
                        FlowLayout(spacing: 16) {
                            ForEach(GreetingPreviewScene.allCases) { scene in
                                Button(scene.title) {
                                    model.selection = .overview
                                    model.greetingPreview = GreetingPreviewRequest(scene: scene)
                                    NSApp.windows.first { $0.identifier?.rawValue == "main" || $0.title == "LabDC" }?
                                        .makeKeyAndOrderFront(nil)
                                }
                                .buttonStyle(.quietLink)
                                .accessibilityLabel("Try the \(scene.title) picture")
                            }
                        }
                    }
                }
            }

            QuietSection("Domain") {
                SettingsFact(title: "Domain", value: status.dnsDomain ?? "—", first: true)
                SettingsFact(title: "Kerberos realm", value: status.realm ?? "—")
                SettingsRow(title: "NetBIOS name") {
                    HStack(alignment: .center, spacing: 14) {
                        QuietTextField("NetBIOS name", text: $netbiosName, prompt: "LAB")
                            .textFieldStyle(.quiet)
                            .frame(width: 160)
                            .autocorrectionDisabled()
                            .accessibilityLabel("NetBIOS domain name")
                        Button(netbiosBusy ? "Renaming…" : "Rename…") { confirmNetbios = true }
                            .buttonStyle(.quietLink)
                            .disabled(netbiosBusy || !model.controller.isRunning
                                      || DomainSetup.validNetbios(netbiosName) == nil
                                      || DomainSetup.validNetbios(netbiosName) == status.netbiosDomain)
                            // Renaming restarts every service and strands joined devices (owner review, 30 Sep 2026).
                            .alert("Rename the NetBIOS domain to \(DomainSetup.validNetbios(netbiosName) ?? netbiosName)?",
                                   isPresented: $confirmNetbios) {
                                Button("Rename and restart", role: .destructive) { renameNetbios() }
                                Button("Cancel", role: .cancel) {}
                            } message: {
                                Text("The services restart. Devices that joined under \(status.netbiosDomain ?? "the old name") need to rejoin or be reconfigured.")
                            }
                    }
                }
                .onAppear { if netbiosName.isEmpty { netbiosName = status.netbiosDomain ?? "" } }
                .onChange(of: status.netbiosDomain) { _, now in
                    if !netbiosBusy, let now { netbiosName = now }
                }
                if !netbiosName.trimmingCharacters(in: .whitespaces).isEmpty, DomainSetup.validNetbios(netbiosName) == nil {
                    QuietNote(DomainSetup.netbiosRule, attention: true).padding(.top, 4)
                }
                SettingsFact(title: "Domain controller", value: status.dcDNSName ?? "—")
                SettingsFact(title: "Base DN", value: status.baseDN ?? "—")
                QuietNote("The NetBIOS name is what devices show as the logon domain. Renaming it restarts the services; devices that joined under the old name keep it until they rejoin. Renaming the domain below changes the domain, realm and base DN in place; joined devices must join again.")
                    .padding(.top, 8)
                DomainRenameSection(currentDomain: status.dnsDomain, newDomainName: $newDomainName,
                                    showConfirm: $showRenameDomain, message: $domainMessage)
                QuietRow {
                    HStack(alignment: .firstTextBaseline, spacing: 24) {
                        QuietNote("Start over with a new domain: the current data (accounts, certificates, settings) moves to a timestamped backup folder and the Setup wizard opens for the new name. Devices must join the new domain again.", attention: false)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button("Start over…") { confirmStartOver = true }
                            .buttonStyle(.quietDestructive)
                            .disabled(settling || (!model.controller.isRunning && !model.controller.data.hasStore))
                            .help(settling ? Self.settlingHelp : "")
                    }
                }
                .confirmationDialog("Back up and start over?", isPresented: $confirmStartOver) {
                    Button("Back up and start over", role: .destructive) {
                        startOverFailed = nil
                        Task {
                            do {
                                let backup = try await model.controller.startOverWithNewDomain()
                                startOverMessage = "Old domain moved to \(backup). The Setup wizard opens next."
                                model.beginSetupAfterStartOver(backup: backup)
                            } catch {
                                startOverFailed = "Could not start over: \(error)"
                            }
                        }
                    }
                } message: {
                    Text("Everything in the current domain moves to a timestamped backup folder beside the data folder — nothing is deleted. Devices that joined must join the new domain again.")
                }
                if let startOverFailed {
                    QuietNote(startOverFailed, attention: true).padding(.top, 4)
                }
                if let startOverMessage {
                    QuietNote(startOverMessage, attention: false).padding(.top, 4)
                }
                if let message {
                    QuietNote(message, attention: failed)
                        .textSelection(.enabled)
                        .padding(.top, 4)
                }
            }

            QuietSection("Data profiles") {
                if !model.profilesApply {
                    QuietNote("This window was opened with --data \(model.controller.data.url.path), so profiles do not apply: the app uses that folder only.", attention: false)
                        .textSelection(.enabled)
                } else {
                    ForEach(profileList) { profile in
                        QuietRow {
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 10) {
                                        Text(profile.name).font(Theme.body).foregroundStyle(Theme.ink)
                                        if profile.name == AppProfile.activeName {
                                            Text("In use")
                                                .font(Theme.caption.weight(.semibold))
                                                .foregroundStyle(Theme.background)
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 2)
                                                .background(Theme.ink, in: Capsule())
                                        }
                                    }
                                    Text(profile.provisioned ? "Domain provisioned" : "Empty")
                                        .font(Theme.detail).foregroundStyle(Theme.muted)
                                }
                                Spacer(minLength: 8)
                                if profile.name != AppProfile.activeName {
                                    Button("Switch…") { switchTarget = profile }
                                        .buttonStyle(.quietLink)
                                        .disabled(settling)
                                        .help(settling ? Self.settlingHelp : "Stop the services and open this domain")
                                }
                                Menu("Edit") {
                                    Button("Rename…") { renameTo = ""; renameError = nil; renaming = profile }
                                        .disabled(profile.isLegacy || (settling && profile.name == AppProfile.activeName))
                                    Button("Move to Trash…", role: .destructive) { deleteTarget = profile }
                                        .disabled(profile.isLegacy || profile.name == AppProfile.activeName)
                                }
                                .menuStyle(.button)
                                .buttonStyle(.quietLink)
                                .fixedSize()
                            }
                        }
                    }
                    QuietRow {
                        HStack(alignment: .firstTextBaseline, spacing: 24) {
                            QuietNote("A profile is one domain with its own directory, CA and settings. The active profile's folder opens at launch; switching stops the services first.", attention: false)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Button("New profile…") { showNewProfile = true }
                                .buttonStyle(.quietLink)
                                .disabled(settling)
                        }
                    }
                    if settling { QuietNote(Self.settlingHelp, attention: false) }
                    if let profileError { QuietNote(profileError, attention: true) }
                }
            }
            .task(id: profilesRevision) { profileList = model.profiles }
            // Switching stops every service (owner review, 30 Sep 2026).
            .alert("Switch to \(switchTarget?.name ?? "")?", isPresented: Binding(
                get: { switchTarget != nil }, set: { if !$0 { switchTarget = nil } }), presenting: switchTarget) { profile in
                Button("Stop and switch") {
                    Task { await model.switchToProfile(profile.name); profilesRevision += 1 }
                }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("Every service of \(AppProfile.activeName) stops; devices using it cannot sign in until you switch back.")
            }
            // Delete always asks first, says what the folder holds, and moves it to the Trash;
            // the profile in use cannot be deleted (owner, 30 Sep 2026).
            .alert("Move \(deleteTarget?.name ?? "") to the Trash?", isPresented: Binding(
                get: { deleteTarget != nil }, set: { if !$0 { deleteTarget = nil } }), presenting: deleteTarget) { profile in
                Button("Move to Trash", role: .destructive) {
                    do { try AppProfile.moveToTrash(name: profile.name); profileError = nil; profilesRevision += 1 }
                    catch { profileError = error.localizedDescription }
                }
                Button("Cancel", role: .cancel) {}
            } message: { profile in
                Text(Self.trashMessage(profile))
            }
            .sheet(isPresented: $showNewProfile) {
                NewProfileSheet(existing: profileList.map(\.name), settling: settling) { name in
                    createTarget = name
                    showNewProfile = false
                }
            }
            // Creating switches, and switching stops every service: the same question as Switch….
            .alert("Create \(createTarget ?? "") and switch to it?", isPresented: Binding(
                get: { createTarget != nil }, set: { if !$0 { createTarget = nil } }), presenting: createTarget) { name in
                Button("Stop and switch") {
                    Task {
                        do {
                            let profile = try AppProfile.create(name: name)
                            profileError = nil
                            await model.switchToProfile(profile.name)
                        } catch {
                            profileError = error.localizedDescription
                        }
                        profilesRevision += 1
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("Every service of \(AppProfile.activeName) stops and the Setup wizard opens for the new domain; devices using \(AppProfile.activeName) cannot sign in until you switch back.")
            }
            .sheet(item: $renaming) { profile in
                RenameProfileSheet(name: profile.name, isActive: profile.name == AppProfile.activeName,
                                   existing: profileList.map(\.name), settling: settling,
                                   renameTo: $renameTo, failure: $renameError, busy: $renameBusy) {
                    let from = profile.name, to = renameTo
                    renameBusy = true
                    renameError = nil
                    Task {
                        do {
                            try await model.renameProfile(from, to: to)
                            renaming = nil; profileError = nil
                        } catch { renameError = error.localizedDescription }
                        renameBusy = false
                        profilesRevision += 1
                    }
                }
            }

            QuietSection("Administrator") {
                QuietNote("Change the password in Directory ▸ select Administrator ▸ Reset. Devices that sign in as Administrator (an LDAP lookup account, a NAC test) need the new one.",
                          attention: false)
            }
        }
    }

    static let settlingHelp = "The services are starting, stopping or restarting; profiles can change once they have settled."

    /// Why `name` cannot be a new profile name (`AppProfile.validatedNewName`), nil when it can.
    static func nameProblem(_ name: String, existing: [String]) -> String? {
        do {
            _ = try AppProfile.validatedNewName(name, existing: existing)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// The delete alert's text: what the folder holds (a domain first), and that it goes to the Trash.
    static func trashMessage(_ profile: AppProfile) -> String {
        let inside = AppProfile.contents(of: profile.url)
        guard !inside.isEmpty else {
            return "The folder is empty. It goes to the Trash; you can put it back from there."
        }
        let list = ListFormatter.localizedString(byJoining: inside)
        let domain = profile.provisioned ? "It holds a domain: \(list)." : "It holds data: \(list)."
        return "\(domain) Devices joined to it can no longer sign in. The folder goes to the Trash; you can put it back from there until the Trash is emptied."
    }

    private func renameNetbios() {
        netbiosBusy = true
        let name = netbiosName
        Task {
            do {
                try await model.controller.setNetbiosDomain(name)
                message = "NetBIOS name is \(model.controller.status.netbiosDomain ?? name). Devices that joined under the old name need to rejoin or be reconfigured."
                failed = false
            } catch {
                message = "Not changed: \(error)"
                failed = true
            }
            netbiosBusy = false
        }
    }
}

/// Settings ▸ General ▸ Data profiles ▸ New profile…: the name, checked as it is typed (the
/// reason stays in the sheet, not behind it).
struct NewProfileSheet: View {
    let existing: [String]
    let settling: Bool
    let create: (String) -> Void
    @State private var name = ""

    var body: some View {
        let problem = GeneralSettings.nameProblem(name, existing: existing)
        let typed = !name.trimmingCharacters(in: .whitespaces).isEmpty
        QuietSheet(title: "New profile", width: 460, failure: typed ? problem : nil) {
            SheetField("Name", note: "An empty folder is created in Application Support/LabDC Profiles; the Setup wizard opens for the new domain.") {
                QuietTextField("Name", text: $name, prompt: "Branch lab").textFieldStyle(.quiet)
                    .autocorrectionDisabled()
            }
        } actions: {
            SheetButtons("Create and switch…", disabled: problem != nil || settling) {
                guard problem == nil else { return }
                create(name.trimmingCharacters(in: .whitespacesAndNewlines))
            }
        }
    }
}

/// Settings ▸ General ▸ Data profiles ▸ Edit ▸ Rename….
struct RenameProfileSheet: View {
    let name: String
    let isActive: Bool
    let existing: [String]
    let settling: Bool
    @Binding var renameTo: String
    @Binding var failure: String?
    @Binding var busy: Bool
    let rename: () -> Void

    var body: some View {
        let trimmed = renameTo.trimmingCharacters(in: .whitespacesAndNewlines)
        let problem = trimmed == name ? "That is its name already."
            : GeneralSettings.nameProblem(renameTo, existing: existing.filter { $0 != name })
        QuietSheet(title: "Rename the profile \(name)", width: 460, failure: failure ?? (trimmed.isEmpty ? nil : problem)) {
            SheetField("New name",
                       note: isActive ? "This is the active profile: the services stop, the folder is renamed, and LabDC reopens it under the new name." : nil) {
                QuietTextField("New name", text: $renameTo, prompt: name).textFieldStyle(.quiet)
                    .autocorrectionDisabled()
            }
        } actions: {
            SheetButtons(busy ? "Renaming…" : "Rename", disabled: problem != nil || busy || (isActive && settling), action: rename)
        }
    }
}

// MARK: Directory

struct DirectorySettings: View {
    @Environment(AppModel.self) private var model
    @State private var error: String?

    var body: some View {
        let settings = model.controller.settings
        let services = model.controller.status.services
        SettingsPage {
            // UI-1c: the network devices use (was the Advanced address picker).
            QuietSection("Network") {
                QuietRow(first: true) {
                    AdvertisedInterfaceSetting()
                }
                QuietRow {
                    DNSForwardingSetting()
                }
                QuietRow {
                    DNSAllowedClientsSetting()
                }
                SettingsRow(title: "Dynamic updates",
                            detail: dynamicUpdatesDetail(settings.dnsDynamicUpdates)) {
                    Picker("Dynamic updates", selection: dynamicUpdatesBinding) {
                        ForEach(DNSDynamicUpdateMode.allCases, id: \.self) { Text($0.settingsLabel).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel("DNS dynamic updates")
                }
            }

            QuietSection("LDAP") {
                QuietRow(first: true) {
                    Toggle(isOn: binding(\.allowPlainLDAP)) {
                        SettingsLabel(title: "Allow plain LDAP",
                                      detail: settings.allowPlainLDAP
                                          ? "Devices may send a password over port 389 unencrypted. StartTLS on 389 and LDAPS on 636 are always available."
                                          : "Port 389 refuses passwords unless the device turns on StartTLS; LDAPS on 636 works as before.")
                    }
                    .toggleStyle(.quiet)
                    .accessibilityLabel("Allow plain LDAP")
                    .accessibilityHint("Simple binds with a password on port 389 without encryption")
                }
                QuietRow {
                    Toggle(isOn: binding(\.requireLDAPSigning)) {
                        SettingsLabel(title: "Require LDAP signing",
                                      detail: settings.requireLDAPSigning
                                          ? "Kerberos and NTLM binds on port 389 must sign or encrypt, as Windows, Samba and macOS do. Like a Windows DC's \"Require signing\"."
                                          : "Kerberos and NTLM binds on port 389 may skip signing, so the session can be tampered with or relayed.")
                    }
                    .toggleStyle(.quiet)
                    .accessibilityLabel("Require LDAP signing")
                }
                SettingsRow(title: "LDAP channel binding",
                            detail: "Ties Kerberos and NTLM binds on LDAPS and StartTLS to the TLS connection, so a relayed login fails. \"When supported\" checks every client that sends a binding.") {
                    Picker("LDAP channel binding", selection: binding(\.ldapChannelBinding)) {
                        ForEach(ChannelBindingPolicy.allCases, id: \.self) { Text($0.settingsLabel).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel("LDAP channel binding")
                }
            }

            QuietSection("Certificate enrollment over HTTPS") {
                QuietRow(first: true) {
                    Toggle(isOn: binding(\.cesAllowNTLM)) {
                        SettingsLabel(title: "Allow NTLM",
                                      detail: settings.cesAllowNTLM
                                          ? "Windows may enroll with NTLM when Kerberos is unavailable; NTLM must be bound to the TLS connection, so a relayed login is refused."
                                          : "Only Kerberos signs in to the enrollment web services.")
                    }
                    .toggleStyle(.quiet)
                    .accessibilityLabel("Allow NTLM for certificate enrollment")
                }
                SettingsRow(title: "Kerberos channel binding",
                            detail: "Whether Kerberos logins to the enrollment web services must be tied to the TLS connection.") {
                    Picker("Kerberos channel binding", selection: binding(\.cesChannelBinding)) {
                        ForEach(ChannelBindingPolicy.allCases, id: \.self) { Text($0.settingsLabel).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel("Kerberos channel binding for certificate enrollment")
                }
            }

            PasswordPolicySection()

            QuietSection("Windows and NAC") {
                QuietRow(first: true) {
                    Toggle(isOn: binding(\.joinDomain)) {
                        SettingsLabel(title: "Let devices join the domain",
                                      detail: settings.joinDomain
                                          ? "DNS, SMB, RPC and time run so Windows PCs, ClearPass and iMaster can join."
                                          : "Only LDAP, Kerberos and the certificate services run. Joined devices can't reach the domain.")
                    }
                    .toggleStyle(.quiet)
                    .accessibilityLabel("Let devices join the domain")
                }
                SettingsRow(title: "NAC password checks",
                            detail: "How a NAC may check a user's password through the domain (NTLM pass-through). MS-CHAPv2 is what 802.1X PEAP needs.") {
                    Picker("NAC password checks", selection: binding(\.ntlmAuth)) {
                        ForEach(NTLMAuthPolicy.allCases, id: \.self) { Text($0.settingsLabel).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel("NAC password checks")
                }
            }

            // UI-1b: ports grouped by service, like the Services page (owner decision 26 Sep 2026).
            // Listeners that are off (NetBIOS by default) have no port to set and don't show.
            ForEach(services) { row in
                let shown = row.service.listeners.filter { $0.isEnabled(in: model.controller.serveOptions()) }
                if !shown.isEmpty {
                    QuietSection(title: "Ports · " + row.service.title) {
                        ServiceStateBadge(row: row)
                    } content: {
                        ForEach(Array(shown.enumerated()), id: \.element.id) { index, listener in
                            PortRow(listener: listener, first: index == 0)
                        }
                    }
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                QuietNote("Changing a port restarts only that service; everything else keeps running.")
                if let error {
                    QuietNote(error, attention: true)
                }
            }
        }
    }

    /// DNS "Dynamic updates" applies live (DNS keeps running), unlike the settings that restart.
    private var dynamicUpdatesBinding: Binding<DNSDynamicUpdateMode> {
        Binding(get: { model.controller.settings.dnsDynamicUpdates }, set: { value in
            Task {
                do {
                    try await model.controller.setDNSDynamicUpdates(value)
                    error = nil
                } catch {
                    self.error = "Not saved: \(error)"
                }
            }
        })
    }

    private func dynamicUpdatesDetail(_ mode: DNSDynamicUpdateMode) -> String {
        switch mode {
        case .secureAndNonsecure:
            "Joined PCs update their own names signed with Kerberos (GSS-TSIG) from any address; other devices may register their own address."
        case .secureOnly:
            "Only joined PCs and DNS admins, signed with Kerberos (GSS-TSIG). Unsigned updates are refused; Windows then retries signed."
        case .off:
            "Nobody may change DNS names with dynamic updates. The DHCP server still registers its leases."
        }
    }

    private func binding<T: Equatable>(_ key: WritableKeyPath<ServerSettings, T>) -> Binding<T> {
        Binding(get: { model.controller.settings[keyPath: key] }, set: { value in
            Task {
                do {
                    try await model.controller.updateSettings { $0[keyPath: key] = value }
                    error = nil
                } catch {
                    self.error = "Not saved: \(error)"
                }
            }
        })
    }
}

/// "Other names for": the networks besides this Mac's own and the DHCP scopes whose devices may
/// resolve names outside the domain here (CVE audit 1 Oct 2026: no open resolver).
struct DNSAllowedClientsSetting: View {
    @Environment(AppModel.self) private var model
    @State private var text = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SettingsLabel(title: "Other names for",
                          detail: "Names outside the domain are looked up only for devices on this Mac's networks and the DHCP scopes. Add other networks (routed subnets, VPNs) here.")
            HStack(alignment: .firstTextBaseline, spacing: 16) {
                QuietTextField("Networks", text: $text, prompt: "10.8.0.0/16, fd00::/64")
                    .textFieldStyle(.quietMonospaced)
                    .labelsHidden()
                    .onSubmit { save() }
                    .accessibilityLabel("Networks allowed to resolve other names")
                Button("Save") { save() }
                    .buttonStyle(.quietLink)
            }
            if let error {
                QuietNote(error, attention: true)
            }
        }
        .onAppear { text = model.controller.settings.dnsAllowedClients.joined(separator: ", ") }
    }

    private func save() {
        Task {
            do {
                try await model.controller.setDNSAllowedClients(text)
                error = nil
                text = model.controller.settings.dnsAllowedClients.joined(separator: ", ")
            } catch {
                self.error = "Not saved: \(error)"
            }
        }
    }
}

/// "Other names": where LabDC's DNS sends every name outside the domain, for the PCs and NAC
/// devices that point their DNS at this Mac to join. This Mac's DNS, or servers typed here.
struct DNSForwardingSetting: View {
    @Environment(AppModel.self) private var model
    @State private var custom = false
    @State private var text = ""
    @State private var error: String?
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .center, spacing: 24) {
                SettingsLabel(title: "Other names",
                              detail: "Devices that use this Mac for DNS get every name outside the domain (websites, your servers) from here.")
                Picker("Other names", selection: $custom) {
                    Text("This Mac's DNS").tag(false)
                    Text("These servers").tag(true)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .accessibilityLabel("Other names go to")
            }
            if custom {
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    QuietTextField("DNS servers", text: $text, prompt: "10.0.0.53, 8.8.8.8")
                        .textFieldStyle(.quietMonospaced)
                        .labelsHidden()
                        .onSubmit { save(text) }
                        .accessibilityLabel("DNS servers")
                    Button("Save") { save(text) }
                        .buttonStyle(.quietLink)
                }
                QuietNote("IP addresses, separated by commas. Add :port for a port other than 53. The first that answers is used.")
            }
            if let error {
                QuietNote(error, attention: true)
            }
        }
        .onAppear {
            let list = model.controller.settings.dnsForwarders
            custom = !list.isEmpty
            text = list.joined(separator: ", ")
            loaded = true
        }
        .onChange(of: custom) { _, on in
            guard loaded, !on else { return }
            save("")
        }
    }

    private func save(_ value: String) {
        Task {
            do {
                try await model.controller.setDNSForwarders(value)
                error = nil
                let list = model.controller.settings.dnsForwarders
                text = list.joined(separator: ", ")
                if list.isEmpty, !value.trimmingCharacters(in: .whitespaces).isEmpty { custom = false }
            } catch {
                self.error = "Not saved: \(error)"
            }
        }
    }
}

/// Settings ▸ Directory ▸ Password policy: the rules every later password set or change goes
/// through (the app, kpasswd, SAMR, LDAP). AD defaults: 7 characters, complexity on, 24 old
/// passwords remembered; `relaxed` accepts anything, for a lab.
struct PasswordPolicySection: View {
    @Environment(AppModel.self) private var model
    @State private var minLength = "7"
    @State private var complexity = true
    @State private var history = "24"
    @State private var relaxed = false
    /// `AppModel.controllerGeneration` the fields were loaded from; a profile switch brings a new controller, whose
    /// policy is loaded again (owner review, 30 Sep 2026).
    @State private var loadedFrom: Int?
    private var loaded: Bool { loadedFrom == model.controllerGeneration }
    @State private var busy = false
    @State private var message: String?
    @State private var failed = false

    var body: some View {
        QuietSection("Password policy") {
            SettingsRow(title: "Minimum length") {
                QuietTextField("Minimum password length", text: $minLength, prompt: "7")
                    .textFieldStyle(.quiet)
                    .frame(width: 60)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Minimum password length")
            }
            SettingsRow(title: "Remember old passwords") {
                QuietTextField("Password history length", text: $history, prompt: "24")
                    .textFieldStyle(.quiet)
                    .frame(width: 60)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Password history length")
            }
            QuietRow(first: false) {
                Toggle(isOn: $complexity) {
                    SettingsLabel(title: "Require complexity",
                                  detail: "3 of: upper case, lower case, digits, symbols — and not the account's own name.")
                }
                .toggleStyle(.quiet)
            }
            QuietRow {
                Toggle(isOn: $relaxed) {
                    SettingsLabel(title: "Accept any password (lab)",
                                  detail: "Skips every rule above. Convenient while setting up; turn off before real devices sign in.")
                }
                .toggleStyle(.quiet)
            }
            QuietRow {
                HStack(alignment: .firstTextBaseline, spacing: 24) {
                    if let message {
                        QuietNote(message, attention: failed)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        QuietNote("Applies to every later password set or change.", attention: false)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Button(busy ? "Saving…" : "Save policy") { save() }
                        .buttonStyle(.quietLink)
                        .disabled(busy || !valid || !loaded)
                }
            }
        }
        .onAppear { load() }
        .onChange(of: model.controller.status.phase) { _, _ in load() }
        .onChange(of: model.controllerGeneration) { _, _ in
            message = nil
            load()
        }
    }

    private var valid: Bool {
        let min = Int(minLength.trimmingCharacters(in: .whitespaces)) ?? 0
        let hist = Int(history.trimmingCharacters(in: .whitespaces)) ?? -1
        return (1...PasswordPolicy.maxLength).contains(min) && (0...PasswordPolicy.maxLength).contains(hist)
    }

    private func load() {
        let controller = model.controller, generation = model.controllerGeneration
        guard !loaded, controller.isRunning else { return }
        Task {
            if let policy = await controller.passwordPolicy(), generation == model.controllerGeneration {
                minLength = String(policy.minLength)
                history = String(policy.historyLength)
                complexity = policy.complexity
                relaxed = policy.relaxed
                loadedFrom = generation
            }
        }
    }

    private func save() {
        busy = true
        message = nil
        let policy = PasswordPolicy(minLength: Int(minLength.trimmingCharacters(in: .whitespaces)) ?? 7,
                                    complexity: complexity,
                                    historyLength: Int(history.trimmingCharacters(in: .whitespaces)) ?? 24,
                                    relaxed: relaxed)
        Task {
            do {
                try await model.controller.setPasswordPolicy(policy)
                failed = false
                message = "Policy saved."
            } catch {
                failed = true
                message = "Not saved: \(error)"
            }
            busy = false
        }
    }
}

/// One port: a number field that applies on Return (the listener moves in place).
struct PortRow: View {
    @Environment(AppModel.self) private var model
    let listener: ServeListener
    var first = false
    @State private var text = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        let current = model.controller.serveOptions().ports[listener]
        QuietRow(first: first) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .center, spacing: 24) {
                    SettingsLabel(title: listener.displayName, detail: listener.transport)
                    if busy {
                        Text("Moving…")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.faint)
                    }
                    QuietTextField("Port", text: $text, prompt: current == 0 ? "auto" : String(current))
                        .textFieldStyle(.quiet)
                        .labelsHidden()
                        .frame(width: 70)
                        .multilineTextAlignment(.trailing)
                        .monospacedDigit()
                        .onSubmit(apply)
                        .accessibilityLabel("\(listener.displayName) port")
                }
                if let error {
                    QuietNote(error, attention: true)
                }
            }
        }
        .onAppear { text = current == 0 ? "" : String(current) }
    }

    private func apply() {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        let port: UInt16
        if trimmed.isEmpty || trimmed == "auto" {
            port = 0
        } else if let p = UInt16(trimmed) {
            port = p
        } else {
            error = "A port is a number from 1 to 65535 (empty = any free port)."
            return
        }
        busy = true
        error = nil
        Task {
            do {
                try await model.controller.setPort(listener, port)
            } catch {
                self.error = "Stayed on the old port: \(error)"
                let current = model.controller.serveOptions().ports[listener]
                text = current == 0 ? "" : String(current)
            }
            busy = false
        }
    }
}

// MARK: Backup

struct BackupSettings: View {
    @Environment(AppModel.self) private var model
    @State private var message: String?
    @State private var failed = false
    @State private var busy = false
    @State private var confirmImport: URL?

    var body: some View {
        let data = model.controller.data
        SettingsPage {
            QuietSection("Data folder") {
                QuietRow(first: true) {
                    HStack(alignment: .firstTextBaseline, spacing: 24) {
                        Text("Location")
                            .font(Theme.body)
                            .foregroundStyle(Theme.muted)
                        Spacer(minLength: 16)
                        Text(data.url.path)
                            .font(Theme.mono)
                            .foregroundStyle(Theme.ink)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                            .multilineTextAlignment(.trailing)
                    }
                    .accessibilityElement(children: .combine)
                }
                QuietRow {
                    HStack(spacing: 24) {
                        Button("Open data folder") { model.openDataFolder() }
                            .buttonStyle(.quietLink)
                        Button("Open log folder") { model.openLogFolder() }
                            .buttonStyle(.quietLink)
                        Spacer(minLength: 0)
                    }
                }
                QuietNote("The directory (lab.sqlite), the CA and certificates (pki), SYSVOL and one log file per day. "
                          + "The labdc command line works on the same folder.")
                    .padding(.top, 8)
            }

            QuietSection("Backup") {
                QuietRow(first: true) {
                    HStack(spacing: 24) {
                        Button("Export backup…") { exportBackup() }
                            .buttonStyle(.quietLink)
                            .disabled(busy || !model.controller.isSetUp)
                        Button("Import backup…") { chooseImport() }
                            .buttonStyle(.quietLink)
                            .disabled(busy || model.controller.status.isBusy)
                        if busy {
                            StateText(text: "Working…")
                        }
                        Spacer(minLength: 0)
                    }
                }
                QuietNote("A backup holds every account with its password keys and the CA's private key. Keep it like the Mac itself.")
                    .padding(.top, 8)
                if let message {
                    QuietNote(message, attention: failed)
                        .textSelection(.enabled)
                        .padding(.top, 6)
                }
            }
        }
        .confirmationDialog("Replace this domain with the backup?", isPresented: Binding(get: { confirmImport != nil },
                                                                                          set: { if !$0 { confirmImport = nil } })) {
            Button("Replace", role: .destructive) {
                if let url = confirmImport { importBackup(url) }
            }
        } message: {
            Text("The server restarts with the backup. The current data folder is kept next to it as “… before import …”.")
        }
    }

    private func exportBackup() {
        let panel = NSOpenPanel()
        panel.title = "Choose where to save the backup"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Save Backup Here"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            do {
                let target = try await model.controller.exportBackup(into: url)
                failed = false
                message = "Saved to \(target.path)"
            } catch {
                failed = true
                message = "Backup failed: \(error)"
            }
            busy = false
        }
    }

    private func chooseImport() {
        let panel = NSOpenPanel()
        panel.title = "Choose a LabDC backup folder"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Import"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard FileManager.default.fileExists(atPath: url.appendingPathComponent("store.json").path) else {
            failed = true
            message = "\(url.lastPathComponent) is not a LabDC backup (no store.json)."
            return
        }
        confirmImport = url
    }

    private func importBackup(_ url: URL) {
        busy = true
        Task {
            do {
                try await model.controller.importBackup(from: url)
                failed = false
                message = "Imported \(url.lastPathComponent)."
                model.screen = .main
            } catch {
                failed = true
                message = "Import failed: \(error)"
            }
            busy = false
        }
    }
}
