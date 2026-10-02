import LabDCCore
import Store
import SwiftUI

/// The right-hand inspector for the selection, in the Quiet look: the name large and light, a
/// muted line under it, then label-above-value rows with hairlines and one text action each.
/// People (six fields + More details + Advanced), Groups, Computers, several, or the folder when
/// nothing is selected. Text fields save on Return or when they lose focus; the rest at once.
struct UsersInspector: View {
    @Environment(AppModel.self) private var app
    @Binding var sheet: UsersSheet?
    @Binding var confirmDelete: Bool

    var body: some View {
        let model = app.usersModel
        ScrollViewReader { proxy in
        ScrollView {
            Color.clear.frame(height: 0).id("inspector-top")
            Group {
                switch model.inspected {
                case .nothing: FolderSummary()
                case .person(let p): PersonInspector(person: p, sheet: $sheet, confirmDelete: $confirmDelete).id(p.id)
                case .group(let g): GroupInspector(group: g, confirmDelete: $confirmDelete).id(g.id)
                case .computer(let c): ComputerInspector(computer: c).id(c.id)
                case .several(let n): SeveralInspector(count: n, confirmDelete: $confirmDelete)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // Room for the scroll bar, so it never covers Edit / Reset / Copy.
            .padding(.trailing, 16)
            .padding(.bottom, 32)
        }
        .scrollIndicators(.automatic)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        // Picking someone else starts at their name, not halfway down the last person.
        .onChange(of: model.selection) { _, _ in
            proxy.scrollTo("inspector-top", anchor: .top)
        }
        }
    }
}

// MARK: - People

private struct PersonInspector: View {
    @Environment(AppModel.self) private var app
    let person: DirectoryPerson
    @Binding var sheet: UsersSheet?
    @Binding var confirmDelete: Bool
    @State private var showMore = false
    @State private var showAdvanced = false

    var body: some View {
        let model = app.usersModel
        let id = person.id
        let status = person.status(now: model.now)
        let protectedAdmin = person.isCritical && person.username.caseInsensitiveCompare("Administrator") == .orderedSame
        VStack(alignment: .leading, spacing: 0) {
            InspectorHeader(title: person.displayName, subtitle: headerLine, dimmed: status == .disabled)
            if protectedAdmin {
                QuietNote("The built-in Administrator is protected: only its password can be changed here.")
            }

            CommitField("Display name", value: person.displayName, first: true, disabled: protectedAdmin) { v in
                await model.perform { try await $0.setDisplayName(id, v) }
            }
            CommitField("Username", value: person.username, disabled: protectedAdmin) { v in
                await model.perform { try await $0.setUsername(id, v) }
            }
            // Owner, 27 Sep 2026: the UPN sits with the names, not under Advanced.
            CommitField("Sign-in name (UPN)", value: person.upn ?? "", disabled: protectedAdmin) { v in
                await model.perform { try await $0.setText(id, "userPrincipalName", v) }
            }
            InspectorRow(label: "Password") {
                Text(passwordText)
            } action: {
                Button("Reset") { sheet = .password(id) }
                    .buttonStyle(.quietLink)
                    .accessibilityLabel("Set password of \(person.username)")
            }
            FolderPicker(objectID: id, parentID: person.parentID, disabled: protectedAdmin)
            if person.groupNames.isEmpty {
                // No "None" + "Change": one link that says what it does (owner, 2 Oct 2026).
                if !protectedAdmin {
                    InspectorRow(label: "Groups") {
                        GroupMembership(person: person, title: "Add to a group")
                    }
                }
            } else {
                InspectorRow(label: "Groups") {
                    Text(person.groupsText)
                        .fixedSize(horizontal: false, vertical: true)
                } action: {
                    GroupMembership(person: person, disabled: protectedAdmin)
                }
            }
            InspectorRow(label: "Account") {
                StateText(text: status.rawValue, attention: status == .expired, dimmed: status == .disabled)
            } action: {
                Button(person.enabled ? "Disable" : "Enable") {
                    let v = !person.enabled
                    Task { await model.perform { try await $0.setEnabled(id, v) } }
                }
                .buttonStyle(.quietLink)
                .disabled(protectedAdmin)
                .accessibilityLabel(person.enabled ? "Disable \(person.username)" : "Enable \(person.username)")
            }

            DisclosureLink(title: "More details", hideTitle: "Fewer details", expanded: $showMore)
            if showMore {
                CommitField("Email", value: person.mail ?? "", disabled: protectedAdmin) { v in
                    await model.perform { try await $0.setText(id, "mail", v) }
                }
                CommitField("Phone", value: person.phone ?? "", disabled: protectedAdmin) { v in
                    await model.perform { try await $0.setText(id, "telephoneNumber", v) }
                }
                CommitField("Title", value: person.title ?? "", disabled: protectedAdmin) { v in
                    await model.perform { try await $0.setText(id, "title", v) }
                }
                CommitField("Department", value: person.department ?? "", disabled: protectedAdmin) { v in
                    await model.perform { try await $0.setText(id, "department", v) }
                }
            }

            DisclosureLink(title: "Advanced", hideTitle: "Hide advanced", expanded: $showAdvanced)
            if showAdvanced {
                QuietRow {
                    Toggle(isOn: Binding(get: { person.mustChangePassword }, set: { v in
                        Task { await model.perform { try await $0.setMustChangePassword(id, v) } }
                    })) {
                        Text("Must change password at next sign-in").font(Theme.body).foregroundStyle(Theme.ink)
                    }
                    .toggleStyle(.quiet)
                    .disabled(protectedAdmin)
                }
                QuietRow {
                    Toggle(isOn: Binding(get: { person.passwordNeverExpires }, set: { v in
                        Task { await model.perform { try await $0.setPasswordNeverExpires(id, v) } }
                    })) {
                        Text("Password never expires").font(Theme.body).foregroundStyle(Theme.ink)
                    }
                    .toggleStyle(.quiet)
                    .disabled(protectedAdmin)
                }
                Text(PasswordOptions.note).font(Theme.detail).foregroundStyle(Theme.muted)
                ExpiryField(person: person)
                CommitField("Description", value: person.description ?? "", disabled: protectedAdmin) { v in
                    await model.perform { try await $0.setText(id, "description", v) }
                }
                if let sid = person.sid {
                    InspectorRow(label: "SID") {
                        Text(sid).font(Theme.mono).textSelection(.enabled)
                    } action: {
                        CopyButton(value: sid)
                    }
                }
                InspectorRow(label: "Distinguished name") {
                    Text(person.dn.description).font(Theme.caption).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Button("Delete this person") { confirmDelete = true }
                .buttonStyle(.quietDestructive)
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(person.isCritical)
                .help(person.isCritical ? "Built-in accounts cannot be deleted" : "Delete (⌘⌫)")
                .padding(.top, 32)
        }
    }

    /// `Last signed in 26 Sep 14:24` / `Never signed in` (the Folder row below says where).
    private var headerLine: String {
        person.lastLogon.map { "Last signed in \(UsersFormat.date($0))" } ?? "Never signed in"
    }

    private var passwordText: String {
        if person.mustChangePassword { return "Must be changed at next sign-in" }
        return person.passwordLastSet.map { "Set \(UsersFormat.date($0))" } ?? "Set"
    }
}

/// "Change" next to Groups: every group, the person's marked "Member"; a click joins or leaves.
private struct GroupMembership: View {
    @Environment(AppModel.self) private var app
    let person: DirectoryPerson
    var title = "Change"
    var disabled = false
    @State private var picking = false
    @State private var query = ""

    var body: some View {
        let model = app.usersModel
        let id = person.id
        let current = Set(person.groupIDs)
        Button(title) { picking = true }
            .buttonStyle(.quietLink)
            .disabled(disabled)
            .help("Add to a group or remove from one")
            .accessibilityLabel("Change the groups of \(person.username)")
            .popover(isPresented: $picking, arrowEdge: .leading) {
                PickerList(title: "Groups of \(person.displayName)", query: $query,
                           items: model.snapshot.groups
                               .filter { $0.matches(query) }
                               .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
                               .map { (g: DirectoryGroup) -> PickerItem in
                                   let member = current.contains(g.id)
                                   return PickerItem(id: g.id, name: g.name, detail: g.scope.title,
                                                     mark: member ? "Member" : "",
                                                     accessibility: member ? "Remove from \(g.name)" : "Add \(person.username) to \(g.name)")
                               },
                           empty: "No groups.") { gid in
                    let groups = current.contains(gid) ? current.subtracting([gid]) : current.union([gid])
                    Task { await model.perform { try await $0.setGroups(of: id, to: groups) } }
                }
            }
    }
}

/// "Account expires": never, or a day.
private struct ExpiryField: View {
    @Environment(AppModel.self) private var app
    let person: DirectoryPerson

    var body: some View {
        let model = app.usersModel
        let id = person.id
        QuietRow {
            Toggle(isOn: Binding(get: { person.accountExpires != nil }, set: { on in
                let date: Date? = on ? Calendar.current.date(byAdding: .day, value: 30, to: Calendar.current.startOfDay(for: Date())) : nil
                Task { await model.perform { try await $0.setAccountExpires(id, date) } }
            })) {
                Text("Account expires").font(Theme.body).foregroundStyle(Theme.ink)
            }
            .toggleStyle(.quiet)
        }
        if let expires = person.accountExpires {
            InspectorRow(label: "Expires on") {
                DatePicker("Expires on", selection: Binding(get: { expires }, set: { d in
                    Task { await model.perform { try await $0.setAccountExpires(id, d) } }
                }), displayedComponents: .date)
                .labelsHidden()
                .fixedSize()
            }
        }
    }
}

// MARK: - Groups

private struct GroupInspector: View {
    @Environment(AppModel.self) private var app
    let group: DirectoryGroup
    @Binding var confirmDelete: Bool
    @State private var picking = false
    @State private var pickingScope = false
    @State private var query = ""

    var body: some View {
        let model = app.usersModel
        let id = group.id
        let builtIn = group.scope == .builtinLocal
        let members = model.members(of: group)
        VStack(alignment: .leading, spacing: 0) {
            // No subtitle: Scope and Members below say it (owner, 2 Oct 2026).
            InspectorHeader(title: group.name)

            CommitField("Name", value: group.name, first: true) { v in
                await model.perform { try await $0.renameGroup(id, to: v) }
            }
            .disabled(group.isCritical)
            InspectorRow(label: "Scope") {
                Text(group.scope.title)
            } action: {
                if !builtIn {
                    Button("Change") { pickingScope = true }
                        .buttonStyle(.quietLink)
                        .accessibilityLabel("Change the scope of \(group.name)")
                        .popover(isPresented: $pickingScope, arrowEdge: .leading) {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Scope").font(Theme.emphasis).foregroundStyle(Theme.ink)
                                ForEach(GroupScope.editable, id: \.self) { s in
                                    Button {
                                        pickingScope = false
                                        guard s != group.scope else { return }
                                        Task { await model.perform { try await $0.setScope(id, s) } }
                                    } label: {
                                        Text(s.title)
                                            .font(.system(size: 13, weight: s == group.scope ? .semibold : .regular))
                                            .foregroundStyle(s == group.scope ? Theme.ink : Theme.muted)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityAddTraits(s == group.scope ? .isSelected : [])
                                }
                            }
                            .padding(16)
                            .frame(width: 200, alignment: .leading)
                            .background(Theme.background)
                        }
                }
            }
            FolderPicker(objectID: id, parentID: group.parentID)
            CommitField("Description", value: group.description ?? "") { v in
                await model.perform { try await $0.setText(id, "description", v) }
            }

            QuietSection(title: "Members") {
                Button("Add members") { picking = true }
                    .buttonStyle(.quietLink)
                    .accessibilityLabel("Add members to \(group.name)")
                    .popover(isPresented: $picking, arrowEdge: .leading) {
                        PickerList(title: "Add to \(group.name)", query: $query,
                                   items: model.candidates(for: group, matching: query).map {
                                       PickerItem(id: $0.id, name: $0.name, detail: $0.detail, accessibility: "Add \($0.name)")
                                   }) { mid in
                            Task { await model.perform { try await $0.addMembers([mid], to: id) } }
                        }
                    }
            } content: {
                if members.isEmpty {
                    QuietNote("No members yet.")
                }
                ForEach(Array(members.enumerated()), id: \.offset) { index, m in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(m.name).font(Theme.body).foregroundStyle(Theme.ink).lineLimit(1)
                                if !m.detail.isEmpty {
                                    Text(m.detail).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                                }
                            }
                            Spacer(minLength: 12)
                            if m.id >= 0 {
                                Button("Remove") {
                                    let mid = m.id
                                    Task { await model.perform { try await $0.removeMembers([mid], from: id) } }
                                }
                                .buttonStyle(.quietLink)
                                .accessibilityLabel("Remove \(m.name) from \(group.name)")
                            }
                        }
                    }
                }
            }
            .padding(.top, 32)

            Button("Delete this group") { confirmDelete = true }
                .buttonStyle(.quietDestructive)
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(group.isCritical || builtIn)
                .padding(.top, 32)
        }
    }
}

// MARK: - Computers

private struct ComputerInspector: View {
    @Environment(AppModel.self) private var app
    let computer: DirectoryComputer
    @State private var confirmReset = false
    @State private var confirmLeave = false
    @State private var showAdvanced = false

    var body: some View {
        let model = app.usersModel
        let id = computer.id
        VStack(alignment: .leading, spacing: 0) {
            InspectorHeader(title: computer.name,
                            subtitle: computer.isDomainController ? "Domain controller" : computer.samAccountName,
                            dimmed: !computer.enabled)

            // Empty read-only rows are left out, not shown as "None" (owner, 2 Oct 2026).
            if let dns = computer.dnsName {
                InspectorRow(label: "DNS name", first: true) { Text(dns).textSelection(.enabled) }
            }
            if let os = computer.operatingSystem {
                InspectorRow(label: "OS", first: computer.dnsName == nil) { Text(os) }
            }
            if let v = computer.operatingSystemVersion {
                InspectorRow(label: "Version") { Text(v) }
            }
            InspectorRow(label: "Last sign-in", first: computer.dnsName == nil && computer.operatingSystem == nil) {
                Text(computer.lastLogon.map(UsersFormat.date) ?? "Never")
                    .foregroundStyle(computer.lastLogon == nil ? Theme.faint : Theme.ink)
            }
            if let joined = joinedText {
                InspectorRow(label: "Joined") { Text(joined) }
            }
            FolderPicker(objectID: id, parentID: computer.parentID)
            InspectorRow(label: "Account") {
                StateText(text: computer.enabled ? "Enabled" : "Disabled", dimmed: !computer.enabled)
            } action: {
                Button(computer.enabled ? "Disable" : "Enable") {
                    let v = !computer.enabled
                    Task { await model.perform { try await $0.setEnabled(id, v) } }
                }
                .buttonStyle(.quietLink)
                .disabled(computer.isDomainController)
                .accessibilityLabel(computer.enabled ? "Disable \(computer.name)" : "Enable \(computer.name)")
            }

            DisclosureLink(title: "Advanced", hideTitle: "Hide advanced", expanded: $showAdvanced)
            if showAdvanced {
                if !computer.spns.isEmpty {
                    InspectorRow(label: "Service principal names") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(computer.spns, id: \.self) { spn in
                                Text(spn).font(Theme.mono).textSelection(.enabled)
                            }
                        }
                    }
                }
                if let sid = computer.sid {
                    InspectorRow(label: "SID") {
                        Text(sid).font(Theme.mono).textSelection(.enabled)
                    } action: {
                        CopyButton(value: sid)
                    }
                }
                InspectorRow(label: "Distinguished name") {
                    Text(computer.dn.description).font(Theme.caption).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if !computer.isDomainController {
                VStack(alignment: .leading, spacing: 14) {
                    Button("Reset computer account") { confirmReset = true }
                        .buttonStyle(.quietLink)
                    Button("Remove from domain") { confirmLeave = true }
                        .buttonStyle(.quietDestructive)
                        .keyboardShortcut(.delete, modifiers: .command)
                    QuietNote("Resetting breaks the computer's link to the domain until it joins again.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, 32)
            }
        }
        .confirmationDialog("Reset the account of \(computer.name)?", isPresented: $confirmReset) {
            Button("Reset account", role: .destructive) {
                Task { await model.perform { try await $0.resetMachineAccount(id) } }
            }
        } message: {
            Text("\(computer.name) can no longer sign in to the domain until it is joined again.")
        }
        .confirmationDialog("Remove \(computer.name) from the domain?", isPresented: $confirmLeave) {
            Button("Remove from domain", role: .destructive) {
                Task { await model.perform { try await $0.delete([id]) } }
            }
        } message: {
            Text("The computer's account is deleted; it has to join the domain again. This cannot be undone.")
        }
    }

    /// "26 Sep 14:24 by Administrator", "by Administrator", or nil when nothing is known.
    private var joinedText: String? {
        let when = computer.joined.map(UsersFormat.date)
        switch (when, computer.joinedBy) {
        case let (w?, by?): return "\(w) by \(by)"
        case let (w?, nil): return w
        case let (nil, by?): return "by \(by)"
        case (nil, nil): return nil
        }
    }
}

// MARK: - Several / nothing

private struct SeveralInspector: View {
    @Environment(AppModel.self) private var app
    let count: Int
    @Binding var confirmDelete: Bool

    var body: some View {
        let model = app.usersModel
        let ids = model.selection.sorted()
        let deletable = model.deletableSelection.count
        let deleteTitle: String = model.tab == .computers
            ? "Remove \(model.tab.count(deletable)) from the domain" : "Delete \(model.tab.count(deletable))"
        VStack(alignment: .leading, spacing: 0) {
            InspectorHeader(title: "\(model.tab.count(count)) selected", subtitle: "Drag them onto a folder to move them.")
            if model.tab != .groups {
                HStack(spacing: 24) {
                    Button("Enable") { Task { await model.perform { e in for id in ids { try await e.setEnabled(id, true) } } } }
                    Button("Disable") { Task { await model.perform { e in for id in ids { try await e.setEnabled(id, false) } } } }
                }
                .buttonStyle(.quietLink)
                .padding(.bottom, 20)
            }
            Button(deleteTitle) {
                confirmDelete = true
            }
            .buttonStyle(.quietDestructive)
            .keyboardShortcut(.delete, modifiers: .command)
            .disabled(deletable == 0)
        }
    }
}

private struct FolderSummary: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        let model = app.usersModel
        let folder = model.currentFolder
        VStack(alignment: .leading, spacing: 0) {
            // No count here: the folder chip carries it (owner, 2 Oct 2026).
            InspectorHeader(title: folder.kind == .domain ? folder.name : folder.path)
            if let d = folder.description {
                Text(d)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 12)
            }
            QuietNote(model.loaded ? "Select a \(model.tab.noun) on the left to see and change \(model.tab == .people ? "them" : "it") here." : "Waiting for the directory…")
        }
    }
}

// MARK: - Pieces

/// The name (large, light) and, when there is one, a muted line under it.
private struct InspectorHeader: View {
    let title: String
    var subtitle: String? = nil
    var dimmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(Theme.subtitle)
                .tracking(-0.4)
                .foregroundStyle(dimmed ? Theme.faint : Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if let subtitle {
                Text(subtitle)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.bottom, 20)
        .accessibilityElement(children: .combine)
    }
}

/// A label above a value, a text action on the right, a hairline above (none with `first`).
private struct InspectorRow<Value: View, Action: View>: View {
    let label: String
    var first = false
    @ViewBuilder var value: Value
    @ViewBuilder var action: Action

    var body: some View {
        QuietRow(first: first) {
            HStack(alignment: .lastTextBaseline, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(label).font(Theme.caption).foregroundStyle(Theme.muted)
                    value.font(Theme.body).foregroundStyle(Theme.ink)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                action
            }
        }
    }
}

extension InspectorRow where Action == EmptyView {
    init(label: String, first: Bool = false, @ViewBuilder value: () -> Value) {
        self.init(label: label, first: first, value: value, action: { EmptyView() })
    }
}

/// "More details" / "Advanced" as a text link that shows or hides the rows under it.
private struct DisclosureLink: View {
    let title: String
    let hideTitle: String
    @Binding var expanded: Bool

    var body: some View {
        Button {
            withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() }
        } label: {
            Text(expanded ? hideTitle : title)
        }
        .buttonStyle(.quietLink)
        .padding(.top, 24)
        .padding(.bottom, 4)
        .accessibilityLabel(title)
        .accessibilityValue(expanded ? "Expanded" : "Collapsed")
    }
}

/// The Folder row: "Change" lists every folder; choosing one moves the object (⌘Z undoes).
private struct FolderPicker: View {
    @Environment(AppModel.self) private var app
    let objectID: ObjectID
    let parentID: ObjectID?
    var disabled = false
    @State private var picking = false

    var body: some View {
        let model = app.usersModel
        InspectorRow(label: "Folder") {
            Text(model.snapshot.folderPath(parentID))
        } action: {
            Button("Change") { picking = true }
                .buttonStyle(.quietLink)
                .disabled(disabled)
                .accessibilityLabel("Change folder")
                .popover(isPresented: $picking, arrowEdge: .leading) {
                    PickerList(title: "Move to",
                               items: model.snapshot.folderList.filter { $0.folder.kind != .domain }.map { item in
                                   PickerItem(id: item.folder.id, name: item.folder.path,
                                              mark: item.folder.id == parentID ? "Here" : "",
                                              accessibility: "Move to \(item.folder.path)")
                               },
                               empty: "No folders.") { new in
                        picking = false
                        guard new != parentID else { return }
                        Task { await model.move([objectID], to: new) }
                    }
                }
        }
    }
}

/// A field row that shows its value with "Edit"; editing, it saves on Return, on "Save" or when
/// focus leaves (only when the value changed); Escape puts the old value back.
struct CommitField: View {
    let title: String
    let value: String
    let first: Bool
    var disabled = false
    let commit: (String) async -> Void
    @State private var text: String
    @State private var editing = false
    @FocusState private var focused: Bool

    init(_ title: String, value: String, first: Bool = false, disabled: Bool = false,
         commit: @escaping (String) async -> Void) {
        self.title = title
        self.value = value
        self.first = first
        self.disabled = disabled
        self.commit = commit
        _text = State(initialValue: value)
    }

    var body: some View {
        if value.isEmpty && !editing {
            // Empty: one "Add email" link, not "None" + "Edit"; nothing at all when it cannot be
            // edited (owner, 2 Oct 2026).
            if !disabled {
                InspectorRow(label: title, first: first) {
                    Button("Add \(Self.lowercasedFirst(title))") { begin() }
                        .buttonStyle(.quietLink)
                        .accessibilityLabel("Add \(title)")
                }
            }
        } else {
            row
        }
    }

    /// "Email" → "email"; "Sign-in name (UPN)" → "sign-in name (UPN)".
    static func lowercasedFirst(_ s: String) -> String {
        guard let first = s.first else { return s }
        return String(first).lowercased() + s.dropFirst()
    }

    private var row: some View {
        InspectorRow(label: title, first: first) {
            if editing {
                TextField(title, text: $text)
                    .textFieldStyle(.quiet)
                    .focused($focused)
                    .onSubmit(finish)
                    .onExitCommand(perform: cancel)
                    .onChange(of: focused) { _, now in if !now { finish() } }
                    .onAppear { Task { focused = true } }
                    .accessibilityLabel(title)
            } else {
                Text(value)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } action: {
            Button(editing ? "Save" : "Edit") {
                if editing { finish() } else { begin() }
            }
            .buttonStyle(.quietLink)
            .disabled(disabled)
            .help(disabled ? "Protected" : "")
            .accessibilityLabel(editing ? "Save \(title)" : "Edit \(title)")
        }
        .onChange(of: value) { _, new in if !editing { text = new } }
    }

    private func begin() {
        text = value
        editing = true
    }

    private func finish() {
        guard editing else { return }
        editing = false
        guard text != value else { return }
        let v = text
        Task { await commit(v) }
    }

    private func cancel() {
        text = value
        editing = false
    }
}

/// One choice in a picker popover.
private struct PickerItem: Identifiable {
    let id: ObjectID
    let name: String
    var detail = ""
    /// A word on the right: "Member", "Here".
    var mark = ""
    let accessibility: String
}

/// A searchable list of words in a popover (groups, members, folders).
private struct PickerList: View {
    let title: String
    var query: Binding<String>?
    let items: [PickerItem]
    var empty = "Nothing to add."
    let choose: (ObjectID) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(Theme.emphasis).foregroundStyle(Theme.ink).lineLimit(1)
            if let query {
                TextField("Search", text: query).textFieldStyle(.quiet)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        Button {
                            choose(item.id)
                        } label: {
                            VStack(spacing: 0) {
                                if index > 0 { Rectangle().fill(Theme.line).frame(height: 1) }
                                HStack(alignment: .firstTextBaseline, spacing: 12) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.name).font(Theme.body).foregroundStyle(Theme.ink).lineLimit(1)
                                        if !item.detail.isEmpty {
                                            Text(item.detail).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                                        }
                                    }
                                    Spacer(minLength: 8)
                                    if !item.mark.isEmpty {
                                        Text(item.mark).font(Theme.caption).foregroundStyle(Theme.muted)
                                    }
                                }
                                .padding(.vertical, 8)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(item.accessibility)
                    }
                }
            }
            .frame(height: 260)
            if items.isEmpty { QuietNote(empty) }
        }
        .padding(16)
        .frame(width: 300)
        .background(Theme.background)
    }
}

// MARK: - Sheets

struct UsersSheetView: View {
    let which: UsersSheet

    var body: some View {
        switch which {
        case .newUser(let folder): NewUserSheet(folder: folder)
        case .newGroup(let folder): NewGroupSheet(folder: folder)
        case .newFolder(let parent): FolderNameSheet(mode: .create(parent: parent))
        case .renameFolder(let id): FolderNameSheet(mode: .rename(id))
        case .password(let id): PasswordSheet(personID: id)
        }
    }
}

/// Password: strength hint (the store's rules), a generated suggestion, "must change".
struct PasswordSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let personID: ObjectID
    @State private var password = UsersModel.suggestPassword()
    @State private var mustChange = false
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        let model = app.usersModel
        let person = model.snapshot.person(personID)
        let strength = PasswordStrength.evaluate(password, account: person?.username ?? "")
        VStack(alignment: .leading, spacing: 14) {
            Text("Set password for \(person?.displayName ?? "user")").font(Theme.emphasis).foregroundStyle(Theme.ink)
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Password").font(Theme.caption).foregroundStyle(Theme.muted)
                        TextField("Password", text: $password)
                            .font(.body.monospaced())
                            .textFieldStyle(.quiet)
                            .accessibilityLabel("New password")
                    }
                    Button("Suggest") { password = UsersModel.suggestPassword() }.buttonStyle(.quietLink)
                        .help("Generate a strong password")
                }
                PasswordHint(strength: strength)
                Toggle("Must change password at next sign-in", isOn: $mustChange)
                    .toggleStyle(.quiet)
                    .disabled(person?.isCritical == true && person?.username.caseInsensitiveCompare("Administrator") == .orderedSame)
                if mustChange, person?.passwordNeverExpires == true {
                    Text("This also turns off Password never expires.").font(Theme.detail).foregroundStyle(Theme.muted)
                }
            }
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                CopyButton(value: password, label: "Copy")
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Set password") {
                    busy = true
                    let pw = password, must = mustChange
                    Task {
                        let before = model.error
                        let ok = await model.perform { try await $0.setPassword(personID, pw, mustChange: must) }
                        busy = false
                        if ok { dismiss() } else { failure = model.error; model.error = before }
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(busy || !strength.isAcceptable)
            }
        }
        .padding(24)
        .frame(width: 440)
        .background(Theme.background)
    }
}

/// "Must change at next sign-in" and "Password never expires" exclude each other, as in ADUC.
enum PasswordOptions {
    static let note = "A password that never expires is never asked to change, so ticking one clears the other."
}

/// UI-1's 3-segment meter with the one-sentence hint under it.
struct PasswordHint: View {
    let strength: PasswordStrength

    var body: some View {
        HStack(spacing: 8) {
            StrengthMeter(level: strength.level)
            Text(strength.hint)
                .font(Theme.detail)
                .foregroundStyle(strength.level == .refused ? Theme.attention : Theme.muted)
        }
    }
}

private struct NewUserSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let folder: ObjectID?
    @State private var displayName = ""
    @State private var username = ""
    @State private var usernameEdited = false
    @State private var password = UsersModel.suggestPassword()
    @State private var mustChange = false
    @State private var neverExpires = false
    @State private var folderID: ObjectID = -1
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        let model = app.usersModel
        let strength = PasswordStrength.evaluate(password, account: username)
        VStack(alignment: .leading, spacing: 14) {
            Text("New User").font(Theme.emphasis).foregroundStyle(Theme.ink)
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Display name").font(Theme.caption).foregroundStyle(Theme.muted)
                    TextField("Display name", text: $displayName)
                        .textFieldStyle(.quiet)
                        .onChange(of: displayName) { _, v in if !usernameEdited { username = UsersModel.suggestUsername(v) } }
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Username").font(Theme.caption).foregroundStyle(Theme.muted)
                    TextField("Username", text: Binding(get: { username }, set: { username = $0; usernameEdited = true }))
                        .textFieldStyle(.quiet)
                }
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Password").font(Theme.caption).foregroundStyle(Theme.muted)
                        TextField("Password", text: $password).font(.body.monospaced())
                            .textFieldStyle(.quiet)
                            .accessibilityLabel("Password")
                    }
                    Button("Suggest") { password = UsersModel.suggestPassword() }.buttonStyle(.quietLink)
                }
                PasswordHint(strength: strength)
                Picker("Folder", selection: $folderID) {
                    Text("Users (default)").tag(ObjectID(-1))
                    ForEach(model.snapshot.folderList.filter { $0.folder.kind == .organizationalUnit || ($0.folder.kind == .container && $0.folder.name != "Users") }, id: \.folder.id) {
                        Text($0.folder.path).tag($0.folder.id)
                    }
                }
                .labelsHidden()
                Toggle("Must change password at next sign-in", isOn: $mustChange)
                    .toggleStyle(.quiet)
                    .onChange(of: mustChange) { _, on in if on { neverExpires = false } }
                Toggle("Password never expires", isOn: $neverExpires)
                    .toggleStyle(.quiet)
                    .onChange(of: neverExpires) { _, on in if on { mustChange = false } }
                Text(PasswordOptions.note).font(Theme.detail).foregroundStyle(Theme.muted)
            }
            Text("Signs in as \(username.isEmpty ? "username" : username)@\(model.snapshot.dnsDomain) or \(app.controller.status.netbiosDomain ?? "DOMAIN")\\\(username.isEmpty ? "username" : username).")
                .font(Theme.detail).foregroundStyle(Theme.muted)
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            if !username.isEmpty, !strength.isAcceptable {
                Text(strength.hint).foregroundStyle(Theme.attention).font(Theme.detail)
            }
            HStack {
                CopyButton(value: password, label: "Copy Password")
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Create") {
                    busy = true
                    let new = DirectoryEditor.NewUser(displayName: displayName, username: username, password: password,
                                                      folder: model.snapshot.folders[folderID]?.dn, mustChangePassword: mustChange,
                                                      passwordNeverExpires: neverExpires)
                    Task {
                        let before = model.error
                        let ok = await model.perform { try await $0.createUser(new) }
                        busy = false
                        if ok {
                            if let p = model.snapshot.people.first(where: { $0.username.caseInsensitiveCompare(new.username) == .orderedSame }) {
                                model.tab = .people
                                model.selection = [p.id]
                            }
                            dismiss()
                        } else { failure = model.error; model.error = before }
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(busy || username.isEmpty || !strength.isAcceptable)
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear { folderID = folder ?? -1 }
    }
}

private struct NewGroupSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let folder: ObjectID?
    @State private var name = ""
    @State private var scope = GroupScope.global
    @State private var description = ""
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        let model = app.usersModel
        VStack(alignment: .leading, spacing: 14) {
            Text("New Group").font(Theme.emphasis).foregroundStyle(Theme.ink)
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Name").font(Theme.caption).foregroundStyle(Theme.muted)
                    TextField("Name", text: $name).textFieldStyle(.quiet)
                }
                HStack(alignment: .center, spacing: 16) {
                    Text("Scope").font(Theme.caption).foregroundStyle(Theme.muted)
                    Picker("Scope", selection: $scope) {
                        ForEach(GroupScope.editable, id: \.self) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Description").font(Theme.caption).foregroundStyle(Theme.muted)
                    TextField("Description", text: $description).textFieldStyle(.quiet)
                }
            }
            Text("Folder: \(model.snapshot.folder(folder)?.path ?? "Users")").font(Theme.detail).foregroundStyle(Theme.muted)
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Create") {
                    busy = true
                    let n = name, s = scope, d = description, dn = model.snapshot.folder(folder)?.dn
                    Task {
                        let before = model.error
                        let ok = await model.perform { try await $0.createGroup(name: n, scope: s, in: dn, description: d) }
                        busy = false
                        if ok {
                            if let g = model.snapshot.groups.first(where: { $0.name == n }) {
                                model.tab = .groups
                                model.selection = [g.id]
                            }
                            dismiss()
                        } else { failure = model.error; model.error = before }
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 400)
        .background(Theme.background)
    }
}

private struct FolderNameSheet: View {
    enum Mode { case create(parent: ObjectID), rename(ObjectID) }
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let mode: Mode
    @State private var name = ""
    @State private var failure: String?

    var body: some View {
        let model = app.usersModel
        VStack(alignment: .leading, spacing: 14) {
            switch mode {
            case .create(let parent):
                Text("New Folder").font(Theme.emphasis).foregroundStyle(Theme.ink)
                Text("In \(model.snapshot.folder(parent)?.path ?? model.snapshot.dnsDomain)").font(Theme.detail).foregroundStyle(Theme.muted)
            case .rename(let id):
                Text("Rename \(model.snapshot.folder(id)?.name ?? "folder")").font(Theme.emphasis).foregroundStyle(Theme.ink)
            }
            TextField("Folder name", text: $name).textFieldStyle(.quiet).onSubmit(save)
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button(isCreate ? "Create" : "Rename", action: save)
                    .buttonStyle(.quietPrimary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 360)
        .background(Theme.background)
        .onAppear { if case .rename(let id) = mode { name = model.snapshot.folder(id)?.name ?? "" } }
    }

    private var isCreate: Bool { if case .create = mode { true } else { false } }

    private func save() {
        let model = app.usersModel
        let n = name
        Task {
            let before = model.error
            let ok: Bool
            switch mode {
            case .create(let parent):
                guard let dn = model.snapshot.folder(parent)?.dn else { return }
                ok = await model.perform { try await $0.createFolder(name: n, in: dn) }
                if ok, let f = model.snapshot.folders.values.first(where: { $0.name == n && $0.parentID == parent }) {
                    model.expanded.insert(parent)
                    model.folderID = f.id
                }
            case .rename(let id):
                ok = await model.perform { try await $0.renameFolder(id, to: n) }
            }
            if ok { dismiss() } else { failure = model.error; model.error = before }
        }
    }
}
