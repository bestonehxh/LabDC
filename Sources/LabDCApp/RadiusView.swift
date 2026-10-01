import LabDCCore
import SYSVOL
import SwiftUI
import RADIUSKit
import Store

/// Phase 4a: the RADIUS page — one sidebar item, inner tabs (owner, 28 Sep 2026):
/// Clients (NAS + shared secrets), Policies (ordered rules with AND rows / ANY-of subgroups),
/// 802.1X (the Windows profile) and Test (which rule would match, what would come back).
/// RADIUS has no on/off switch: it runs with the directory (owner, 30 Sep 2026); the state line
/// is the Services row's.
struct RadiusView: View {
    @Environment(AppModel.self) private var model
    @State private var tab = RadiusTab.clients

    enum RadiusTab: String, CaseIterable, Identifiable {
        case clients, policies, dot1x, test
        var id: String { rawValue }
        var title: String { switch self { case .clients: "Clients"; case .policies: "Policies"; case .dot1x: "802.1X"; case .test: "Test" } }
    }

    var body: some View {
        QuietPage(title: "RADIUS", scrolls: false) {
            QuietTabs(items: RadiusTab.allCases.map { ($0, $0.title) }, selection: $tab)
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                if let service = model.controller.status.services.first(where: { $0.service == .radius }) {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        StateText(text: service.stateLabel, attention: service.problemMessage != nil,
                                  dimmed: service.state != .running)
                        Text(service.problemMessage ?? service.portsText)
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                            .lineLimit(2).textSelection(.enabled)
                    }
                    .padding(.bottom, 14)
                }
                switch tab {
                case .clients: RadiusClients()
                case .policies: RadiusPolicies()
                case .dot1x: Radius8021X()
                case .test: RadiusTest()
                }
            }
        }
    }
}

// MARK: - Clients

struct RadiusClients: View {
    @Environment(AppModel.self) private var model
    @State private var clients: [DirectoryStore.NASClient] = []
    @State private var editing: DirectoryStore.NASClient?
    @State private var adding = false
    @State private var confirmDelete: DirectoryStore.NASClient?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text("\(clients.count) client\(clients.count == 1 ? "" : "s")").font(Theme.body).foregroundStyle(Theme.muted)
                Spacer(minLength: 16)
                Button("Add a client") { adding = true }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if clients.isEmpty {
                QuietNote("No NAS yet. Add the switch or access point that will send Access-Requests: its address and a shared secret.", attention: false)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(clients) { client in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(client.name).font(Theme.body).foregroundStyle(client.enabled ? Theme.ink : Theme.faint)
                                        Text("\(client.ip) · secret ••••••••"
                                             + (client.requireMessageAuthenticator ? "" : " · Message-Authenticator optional"))
                                            .font(Theme.detail.monospaced()).foregroundStyle(Theme.muted)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                    Button("Edit…") { editing = client }
                                    Button("Copy secret") { CertificateFiles.copy(client.secret) }
                                    Button(client.enabled ? "Disable" : "Enable") {
                                        var c = client; c.enabled.toggle()
                                        run("\(c.enabled ? "Enable" : "Disable") \(client.name)") { try await model.controller.updateRadiusNAS(c) }
                                    }
                                    Button("Delete…", role: .destructive) { confirmDelete = client }
                                }
                                .menuStyle(.button)
                                .buttonStyle(.quietLink)
                                .fixedSize()
                                }
                            }
                            Divider().overlay(Theme.line)
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(isPresented: $adding) { RadiusClientSheet(onDone: { Task { await reload() } }) }
        .sheet(item: $editing) { client in
            RadiusClientSheet(client: client, onDone: { Task { await reload() } })
        }
        .alert("Delete the RADIUS client “\(confirmDelete?.name ?? "")”?",
               isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
               presenting: confirmDelete) { client in
            Button("Delete", role: .destructive) {
                run("Delete \(client.name)") { try await model.controller.deleteRadiusNAS(id: client.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { client in
            Text("Requests from \(client.ip) are dropped from now on (no reply). Its shared secret is gone; adding the client again needs a new one on the device too.")
        }
    }

    private func reload() async {
        clients = await model.controller.radiusNAS()
    }

    /// Runs an edit; a failure stays on screen instead of vanishing.
    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        Task {
            do { try await body(); failure = nil } catch { failure = "\(what) failed: \(error)" }
            await reload()
        }
    }
}

struct RadiusClientSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var client: DirectoryStore.NASClient?
    let onDone: () -> Void

    @State private var name = ""
    @State private var ip = ""
    @State private var secret = UsersModel.suggestPassword(length: 24)
    @State private var enabled = true
    @State private var requireMA = true
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(client == nil ? "New RADIUS client" : "Edit \(client?.name ?? "")")
                .font(Theme.emphasis).foregroundStyle(Theme.ink)
            VStack(alignment: .leading, spacing: 14) {
                field("Name") { TextField("Switch 3F", text: $name).textFieldStyle(.quiet) }
                field("IP or CIDR") { TextField("10.10.0.5, 10.10.0.0/24 or fd00::/64", text: $ip).textFieldStyle(.quiet) }
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    field("Shared secret") { TextField("secret", text: $secret).textFieldStyle(.quiet).font(.body.monospaced()) }
                    Button("Generate") { secret = UsersModel.suggestPassword(length: 24) }.buttonStyle(.quietLink)
                }
                Toggle("Enabled", isOn: $enabled).toggleStyle(.quiet)
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Require Message-Authenticator", isOn: $requireMA).toggleStyle(.quiet)
                    Text(requireMA
                         ? "Requests without it are dropped (Blast-RADIUS protection). EAP always needs it."
                         : "Only for an old NAS that cannot send it: PAP/MS-CHAPv2 requests are then open to Blast-RADIUS forgery.")
                        .font(Theme.detail).foregroundStyle(requireMA ? Theme.muted : Theme.attention)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Save") {
                    busy = true
                    let c = DirectoryStore.NASClient(id: client?.id ?? 0, name: name, ip: ip, secret: secret, enabled: enabled,
                                                     requireMessageAuthenticator: requireMA)
                    Task {
                        do {
                            if client == nil { try await model.controller.addRadiusNAS(c) } else { try await model.controller.updateRadiusNAS(c) }
                            onDone(); dismiss()
                        } catch { failure = "\(error)" }
                        busy = false
                    }
                }
                .buttonStyle(.quietPrimary).keyboardShortcut(.defaultAction)
                .disabled(busy || name.isEmpty || ip.isEmpty || secret.isEmpty)
            }
        }
        .padding(24).frame(width: 480)
        .background(Theme.background)
        .onAppear {
            if let client {
                name = client.name; ip = client.ip; secret = client.secret; enabled = client.enabled
                requireMA = client.requireMessageAuthenticator
            }
        }
    }

    private func field(_ label: String, @ViewBuilder control: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(Theme.caption).foregroundStyle(Theme.muted)
            control()
        }
    }
}

// MARK: - Policies

struct RadiusPolicies: View {
    @Environment(AppModel.self) private var model
    @State private var policies: [RADIUSPolicy] = []
    @State private var defaultAction = RADIUSDefaultAction.reject
    @State private var editing: RADIUSPolicy?
    @State private var adding = false
    @State private var confirmDelete: RADIUSPolicy?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text("First match wins.").font(Theme.body).foregroundStyle(Theme.muted)
                Menu("No match: \(defaultAction.title)") {
                    ForEach(RADIUSDefaultAction.allCases, id: \.self) { action in
                        Button(action.title) {
                            run("Set the no-match action") { try await model.controller.setRadiusDefaultAction(action) }
                        }
                    }
                }
                .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                Spacer(minLength: 16)
                Button("Add a policy") { adding = true }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if policies.isEmpty {
                QuietNote("No policies yet: every request gets the no-match action (\(defaultAction.title)). A rule is ALL of its rows; a row can be an ANY-of group — OR inside the AND.", attention: false)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(policies) { policy in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack(spacing: 10) {
                                            Text("\(policy.position + 1).").font(Theme.detail.monospacedDigit()).foregroundStyle(Theme.faint)
                                            Text(policy.name).font(Theme.body).foregroundStyle(policy.enabled ? Theme.ink : Theme.faint)
                                            StateText(text: policy.action == .acceptVLAN ? "Accept, VLAN \(policy.vlan ?? "?")" : policy.action.title,
                                                      attention: policy.action == .reject, dimmed: !policy.enabled)
                                        }
                                        Text(policy.rows.count == 1 ? "1 condition row" : "\(policy.rows.count) condition rows")
                                            .font(Theme.detail).foregroundStyle(Theme.muted)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                    Button("Edit…") { editing = policy }
                                    Button("Move up") { move(policy, -1) }
                                    Button("Move down") { move(policy, 1) }
                                    Button("Delete…", role: .destructive) { confirmDelete = policy }
                                }
                                .menuStyle(.button)
                                .buttonStyle(.quietLink)
                                .fixedSize()
                                }
                            }
                            Divider().overlay(Theme.line)
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(isPresented: $adding) {
            RadiusPolicySheet(position: (policies.map(\.position).max() ?? -1) + 1, onDone: { Task { await reload() } })
        }
        .sheet(item: $editing) { policy in
            RadiusPolicySheet(policy: policy, position: policy.position, onDone: { Task { await reload() } })
        }
        .alert("Delete the policy “\(confirmDelete?.name ?? "")”?",
               isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
               presenting: confirmDelete) { policy in
            Button("Delete", role: .destructive) {
                run("Delete \(policy.name)") { try await model.controller.deleteRadiusPolicy(id: policy.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("Requests it matched fall through to the next rule, or to the no-match action (\(defaultAction.title)).")
        }
    }

    /// Move up/down: the whole order is written in one store transaction — never half-moved.
    private func move(_ policy: RADIUSPolicy, _ delta: Int) {
        var sorted = policies.sorted { $0.position < $1.position }
        guard let i = sorted.firstIndex(where: { $0.id == policy.id }) else { return }
        let j = i + delta
        guard (0..<sorted.count).contains(j) else { return }
        sorted.swapAt(i, j)
        let ids = sorted.map(\.id)
        run("Move \(policy.name)") { try await model.controller.reorderRadiusPolicies(ids) }
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        Task {
            do { try await body(); failure = nil } catch { failure = "\(what) failed: \(error)" }
            await reload()
        }
    }

    private func reload() async {
        policies = await model.controller.radiusPolicies()
        defaultAction = await model.controller.radiusDefaultAction()
    }
}

struct RadiusPolicySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var policy: RADIUSPolicy?
    var position: Int = 0
    let onDone: () -> Void

    @State private var name = ""
    @State private var enabled = true
    @State private var action = RADIUSPolicy.Action.accept
    @State private var vlan = ""
    @State private var rows: [EditableRow] = []
    @State private var attributes: [RADIUSPolicy.ReturnedAttribute] = []
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(policy == nil ? "New policy" : "Edit \(policy?.name ?? "")")
                .font(Theme.emphasis).foregroundStyle(Theme.ink)
            TextField("Policy name", text: $name).textFieldStyle(.quiet)
            Toggle("Enabled", isOn: $enabled).toggleStyle(.quiet)
            HStack(alignment: .firstTextBaseline, spacing: 16) {
                Text("Then").font(Theme.caption).foregroundStyle(Theme.muted)
                Menu(action.title) {
                    ForEach(RADIUSPolicy.Action.allCases, id: \.self) { a in Button(a.title) { action = a } }
                }
                .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                if action == .acceptVLAN {
                    TextField("VLAN", text: $vlan).textFieldStyle(.quiet).frame(width: 90)
                }
            }

            Text("When ALL of these match").font(Theme.caption).foregroundStyle(Theme.muted)
            Text("User-Name is what the NAS sent — for PEAP/TTLS the outer identity, often anonymous. "
                 + "account is who actually signed in: the sAMAccountName or UPN of the inner identity, the certificate or the PAP user.")
                .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach($rows) { $item in
                        HStack(alignment: .top) {
                            RadiusRowEditor(row: $item.row)
                            Button("Remove") { rows.removeAll { $0.id == item.id } }.buttonStyle(.quietLink)
                        }
                        Divider().overlay(Theme.line)
                    }
                }
            }
            HStack(spacing: 24) {
                Button("Add condition") { rows.append(EditableRow(.condition(.init(field: .account, op: .is, value: "")))) }
                    .buttonStyle(.quietLink)
                Button("Add ANY-of group") { rows.append(EditableRow(.anyOf([.init(field: .calledStationId, op: .ends, value: "")]))) }
                    .buttonStyle(.quietLink)
                Spacer()
            }

            if action.accepts {
                Text(action == .acceptVLAN ? "Also return" : "Return attributes").font(Theme.caption).foregroundStyle(Theme.muted)
                ForEach($attributes) { $attr in
                    HStack {
                        Text(attr.title).font(Theme.detail).foregroundStyle(Theme.ink).frame(width: 200, alignment: .leading)
                        TextField("value", text: $attr.value).textFieldStyle(.quiet).font(Theme.detail.monospaced())
                        Button("Remove") { attributes.removeAll { $0.id == attr.id } }.buttonStyle(.quietLink)
                    }
                }
                Menu("Add attribute") {
                    ForEach(RADIUSPolicy.ReturnedAttribute.Standard.allCases, id: \.self) { standard in
                        Button(standard.rawValue) { attributes.append(.init(standard: standard, value: "")) }
                    }
                    Divider()
                    ForEach(RADIUSPolicy.ReturnedAttribute.vendorPresets, id: \.name) { preset in
                        Button("\(preset.name) (\(preset.vendor))") {
                            if let a = RADIUSPolicy.ReturnedAttribute.preset(named: preset.name) { attributes.append(a) }
                        }
                    }
                }
                .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
            }

            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Save") {
                    busy = true
                    var updated = policy ?? RADIUSPolicy(position: position, name: name)
                    updated.name = name; updated.enabled = enabled
                    updated.action = action
                    updated.vlan = action == .acceptVLAN ? vlan.trimmingCharacters(in: .whitespaces) : nil
                    updated.rows = rows.map(\.row); updated.attributes = action.accepts ? attributes : []
                    Task {
                        do {
                            try await model.controller.saveRadiusPolicy(updated)
                            onDone(); dismiss()
                        } catch { failure = "\(error)" }
                        busy = false
                    }
                }
                .buttonStyle(.quietPrimary).keyboardShortcut(.defaultAction)
                .disabled(busy || name.isEmpty || (action == .acceptVLAN && vlan.trimmingCharacters(in: .whitespaces).isEmpty))
            }
        }
        .padding(24).frame(width: 680, height: 660)
        .background(Theme.background)
        .onAppear {
            if let policy {
                name = policy.name; enabled = policy.enabled
                action = policy.action; vlan = policy.vlan ?? ""
                rows = policy.rows.map(EditableRow.init); attributes = policy.attributes
            }
        }
    }
}

/// A rule row with a stable identity for SwiftUI (removing one never re-binds another's index).
struct EditableRow: Identifiable {
    let id = UUID()
    var row: RADIUSPolicy.Row
    init(_ row: RADIUSPolicy.Row) { self.row = row }
}

/// One row of a rule: a single condition, or an ANY-of group of conditions.
struct RadiusRowEditor: View {
    @Binding var row: RADIUSPolicy.Row

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch row {
            case .condition:
                RadiusConditionEditor(condition: Binding(get: {
                    if case .condition(let c) = row { return c }; return .init(field: .userName, op: .is, value: "")
                }, set: { row = .condition($0) }))
            case .anyOf(let list):
                Text("ANY of (one is enough)").font(Theme.caption).foregroundStyle(Theme.muted)
                ForEach(Array(list.enumerated()), id: \.offset) { i, _ in
                    HStack(alignment: .firstTextBaseline) {
                        RadiusConditionEditor(condition: Binding(get: {
                            if case .anyOf(let list) = row, list.indices.contains(i) { return list[i] }
                            return .init(field: .userName, op: .is, value: "")
                        }, set: {
                            if case .anyOf(var list) = row, list.indices.contains(i) { list[i] = $0; row = .anyOf(list) }
                        }))
                        if list.count > 1 {
                            Button("Remove") {
                                if case .anyOf(var list) = row, list.indices.contains(i) { list.remove(at: i); row = .anyOf(list) }
                            }
                            .buttonStyle(.quietLink)
                        }
                    }
                }
                Button("Add OR condition") {
                    if case .anyOf(var list) = row {
                        list.append(.init(field: .calledStationId, op: .ends, value: ""))
                        row = .anyOf(list)
                    }
                }
                .buttonStyle(.quietLink)
            }
        }
        .padding(10)
        .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6))
    }
}

struct RadiusConditionEditor: View {
    @Binding var condition: RADIUSPolicy.Condition

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Menu(condition.field.rawValue) {
                ForEach(RADIUSPolicy.Condition.Field.allCases, id: \.self) { f in Button(f.rawValue) { condition.field = f } }
            }
            .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
            Menu(condition.op.rawValue) {
                ForEach(RADIUSPolicy.Condition.Op.allCases, id: \.self) { o in Button(o.rawValue) { condition.op = o } }
            }
            .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
            TextField(condition.field.placeholder, text: $condition.value).textFieldStyle(.quiet).frame(width: 200)
        }
        .font(Theme.detail)
    }
}

// MARK: - Test

/// Paste the attributes a NAS would send (one `Name = value` per line): the account's directory
/// facts are merged in and the policies run exactly as for a live request — nothing is sent.
struct RadiusTest: View {
    @Environment(AppModel.self) private var model
    @State private var text = """
        User-Name = alice
        Called-Station-Id = 00-11-22-33-44-55:Staff
        NAS-IP-Address = 10.10.0.5
        Service-Type = Framed-User
        """
    @State private var result: RadiusTestResult?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            QuietNote("Paste what a NAS would send, one Name = value per line (Time = 09:30 and Weekday = Sat test time rules; account is looked up from User-Name, or set it with Account = alice). The directory facts are looked up and the policies run as for a live request; no password is checked and nothing is sent.", attention: false)
            TextEditor(text: $text)
                .font(Theme.detail.monospaced())
                .scrollContentBackground(.hidden)
                .padding(8)
                .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6))
                .frame(minHeight: 120, maxHeight: 180)
            HStack {
                Button(busy ? "Testing…" : "Test") {
                    busy = true
                    Task {
                        result = await model.controller.testRadius(attributes: text)
                        busy = false
                    }
                }
                .buttonStyle(.quietPrimary)
                .disabled(busy || text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Spacer()
            }
            if let result {
                Text(result.text).font(Theme.body.monospaced()).foregroundStyle(result.ok ? Theme.ink : Theme.attention)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
    }
}


// MARK: - 802.1X profile

/// Publishes a wired and/or wireless 802.1X profile (EAP-TLS or PEAP-MSCHAPv2) into the Default
/// Domain Policy; joined Windows machines pick it up at `gpupdate /force`.
struct Radius8021X: View {
    @Environment(AppModel.self) private var model
    @State private var ssid = ""
    @State private var authMode: Dot1XPolicy.AuthMode = .machineOrUser
    @State private var method: Dot1XPolicy.Method = .tls
    @State private var security: Dot1XPolicy.Security = .wpa2
    @State private var wireless = true
    @State private var wired = true
    @State private var thumbprint: String?
    @State private var suiteBThumbprint: String?
    @State private var busy = false
    @State private var message: String?
    @State private var failed = false
    @State private var confirmRemove = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            QuietNote("Publishes an 802.1X profile into the Default Domain Policy. Joined Windows PCs apply it at `gpupdate /force`: EAP-TLS signs in with the auto-enrolled User/Computer certificate, PEAP-MSCHAPv2 with the Windows password. Both check that the RADIUS server's certificate comes from the lab CA.", attention: false)
            HStack(spacing: 24) {
                Toggle("Wireless", isOn: $wireless).toggleStyle(.quiet)
                Toggle("Wired", isOn: $wired).toggleStyle(.quiet)
            }
            HStack(spacing: 24) {
                TextField("SSID (Wi-Fi name)", text: $ssid).textFieldStyle(.quiet).frame(width: 220).disabled(!wireless)
                Picker("Security", selection: $security) {
                    ForEach(Dot1XPolicy.Security.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .frame(width: 260).disabled(!wireless)
            }
            HStack(spacing: 24) {
                Picker("Method", selection: $method) {
                    ForEach(Dot1XPolicy.Method.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .frame(width: 280)
                Picker("Sign in as", selection: $authMode) {
                    ForEach(Dot1XPolicy.AuthMode.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .frame(width: 220)
            }
            if wireless, security == .wpa3Suite192, method != .tls {
                Text("WPA3-Enterprise 192-bit works with EAP-TLS only.").font(Theme.detail).foregroundStyle(Theme.attention)
            } else if wireless, security == .wpa3Suite192 {
                Text("192-bit: clients use a P-384 certificate from the 802.1X 192-bit CA (the Computer192 / User192 templates, switched on with auto-enrollment when you publish) and trust that root. The access point needs WPA3-Enterprise 192-bit (GCMP-256); wired 802.1X keeps the lab CA.")
                    .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 24) {
                Button(busy ? "Publishing…" : "Publish profile") {
                    busy = true
                    let policy = Dot1XPolicy(name: Dot1XPolicy.defaultName, ssid: ssid, authMode: authMode,
                                             caThumbprint: thumbprint ?? "", method: method, security: security)
                    Task {
                        do {
                            try await model.controller.set80211Profile(policy, wireless: wireless, wired: wired)
                            let checks = [wireless ? "netsh wlan show profiles" : nil, wired ? "netsh lan show profiles" : nil].compactMap { $0 }
                            message = "Published. On a Windows PC: gpupdate /force, then \(checks.joined(separator: " and "))."
                            failed = false
                        } catch {
                            message = "Not published: \(error)"; failed = true
                        }
                        busy = false
                    }
                }
                .buttonStyle(.quietPrimary)
                .disabled(busy || thumbprint == nil || (!wireless && !wired)
                          || (wireless && ssid.trimmingCharacters(in: .whitespaces).isEmpty)
                          || (wireless && security == .wpa3Suite192 && method != .tls))
                Button("Remove published profiles…") { confirmRemove = true }
                    .buttonStyle(.quietLink)
            }
            if wireless, security == .wpa3Suite192, method == .tls {
                Text("Trusted root: the 802.1X 192-bit CA (SHA-1 \(suiteBThumbprint ?? "created when you publish")); server name: this DC")
                    .font(Theme.detail.monospaced()).foregroundStyle(Theme.muted).textSelection(.enabled)
            } else if let thumbprint {
                Text("Trusted root: the lab CA (SHA-1 \(thumbprint)); server name: this DC")
                    .font(Theme.detail.monospaced()).foregroundStyle(Theme.muted).textSelection(.enabled)
            }
            if let message { QuietNote(message, attention: failed).textSelection(.enabled) }
            Spacer()
        }
        .task {
            thumbprint = await model.controller.caThumbprint()
            suiteBThumbprint = await model.controller.suiteBThumbprint()
        }
        .alert("Remove the published 802.1X profiles?", isPresented: $confirmRemove) {
            Button("Remove", role: .destructive) {
                Task {
                    do {
                        try await model.controller.remove80211Profiles()
                        message = "802.1X profiles removed. PCs drop them at their next gpupdate."; failed = false
                    } catch { message = "Not removed: \(error)"; failed = true }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The wireless and wired profiles leave the Default Domain Policy. Joined PCs lose them at their next policy refresh and stop connecting to the SSID or the 802.1X port until a profile is published again.")
        }
    }
}
