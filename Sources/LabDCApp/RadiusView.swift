import LabDCCore
import SYSVOL
import SwiftUI
import RADIUSKit
import Store

/// Phase 4a: the RADIUS page — one sidebar item, inner tabs (owner, 28 Sep 2026):
/// Clients (NAS + shared secrets), Policies (ordered rules with AND rows / ANY-of subgroups),
/// Settings (PEAP crypto binding, RSA-only devices; the Windows 802.1X profiles are on the Group
/// Policy page since 1 Oct 2026) and Test (which rule would match, what would come back).
/// RADIUS has no on/off switch: it runs with the directory (owner, 30 Sep 2026); the state line
/// is the Services row's.
struct RadiusView: View {
    @Environment(AppModel.self) private var model
    @State private var tab: RadiusTab

    init(tab: RadiusTab = .clients) {
        _tab = State(initialValue: tab)
    }

    enum RadiusTab: String, CaseIterable, Identifiable {
        case clients, policies, sessions, devices, settings, test
        var id: String { rawValue }
        var title: String {
            switch self {
            case .clients: "Clients"
            case .policies: "Policies"
            case .sessions: "Sessions"
            case .devices: "Devices"
            case .settings: "Settings"
            case .test: "Test"
            }
        }
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
                case .sessions: RadiusSessions()
                case .devices: RadiusDevices()
                case .settings: RadiusSettingsTab()
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
                // No "0 clients" above the empty note (owner, 2 Oct 2026).
                if !clients.isEmpty {
                    Text("\(clients.count) client\(clients.count == 1 ? "" : "s")").font(Theme.body).foregroundStyle(Theme.muted)
                }
                Spacer(minLength: 16)
                Button("Add a client") { adding = true }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if clients.isEmpty {
                QuietNote("No clients yet. Add the switch or access point that will send Access-Requests: its address and a shared secret.", attention: false)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(clients) { client in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(client.name).font(Theme.body).foregroundStyle(client.enabled ? Theme.ink : Theme.faint)
                                        Text("\(client.ip) · secret •••••••• · CoA \(client.coaVendor.title), udp \(client.coaPort)"
                                             + (client.requireMessageAuthenticator ? "" : " · Message-Authenticator optional"))
                                            .font(Theme.detail.monospaced()).foregroundStyle(Theme.muted)
                                        if client.hasWeakSecret {
                                            Text("Weak shared secret (\(client.secret.utf8.count) characters, at least \(DirectoryStore.NASClient.minimumSecretLength) recommended): it still works, but one captured packet lets it be guessed offline. Edit ▸ Generate, and set the new secret on the device.")
                                                .font(Theme.detail).foregroundStyle(Theme.attention)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
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
    @State private var coaVendor = CoAVendor.generic
    @State private var coaPort = "3799"
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
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    field("Change of Authorization") {
                        Menu(coaVendor.title) {
                            ForEach(CoAVendor.allCases, id: \.self) { v in
                                Button(v.title) {
                                    // Moving between vendors follows the usual port unless it was changed by hand.
                                    if coaPort == String(coaVendor.suggestedPort) { coaPort = String(v.suggestedPort) }
                                    coaVendor = v
                                }
                            }
                        }
                        .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                    }
                    field("CoA port") { TextField("3799", text: $coaPort).textFieldStyle(.quiet).frame(width: 80) }
                }
                Text("Used to reauthenticate or disconnect a session (RFC 5176), by hand or when a device's profile changes. Cisco IOS listens on 1700, most others on 3799; the NAS must accept CoA from this Mac with the same shared secret.")
                    .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Save") {
                    busy = true
                    let c = DirectoryStore.NASClient(id: client?.id ?? 0, name: name, ip: ip, secret: secret, enabled: enabled,
                                                     requireMessageAuthenticator: requireMA,
                                                     coaPort: UInt16(coaPort.trimmingCharacters(in: .whitespaces)) ?? 0,
                                                     coaVendor: coaVendor)
                    Task {
                        do {
                            if client == nil { try await model.controller.addRadiusNAS(c) } else { try await model.controller.updateRadiusNAS(c) }
                            onDone(); dismiss()
                        } catch { failure = "\(error)" }
                        busy = false
                    }
                }
                .buttonStyle(.quietPrimary).keyboardShortcut(.defaultAction)
                .disabled(busy || name.isEmpty || ip.isEmpty || secret.isEmpty || (UInt16(coaPort.trimmingCharacters(in: .whitespaces)) ?? 0) == 0)
            }
        }
        .padding(24).frame(width: 480)
        .background(Theme.background)
        .onAppear {
            if let client {
                name = client.name; ip = client.ip; secret = client.secret; enabled = client.enabled
                requireMA = client.requireMessageAuthenticator
                coaVendor = client.coaVendor; coaPort = String(client.coaPort)
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
                                        Text((policy.rows.count == 1 ? "1 condition row" : "\(policy.rows.count) condition rows")
                                             + (policy.allowsMAB ? " · allows MAB" : ""))
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
    @State private var allowsMAB = false
    @State private var rows: [EditableRow] = []
    @State private var attributes: [RADIUSPolicy.ReturnedAttribute] = []
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(policy == nil ? "New policy" : "Edit \(policy?.name ?? "")")
                .font(Theme.emphasis).foregroundStyle(Theme.ink)
            TextField("Policy name", text: $name).textFieldStyle(.quiet)
            HStack(spacing: 24) {
                Toggle("Enabled", isOn: $enabled).toggleStyle(.quiet)
                Toggle("Allow MAC Authentication Bypass", isOn: $allowsMAB).toggleStyle(.quiet)
            }
            if allowsMAB {
                Text("MAB requests (the NAS sends the device's MAC instead of credentials) are tried only against rules that allow them, with auth_method = mab. Match them by device_category, registered_device or device_group — a MAC is easy to copy.")
                    .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
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
                    updated.allowsMAB = allowsMAB
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
                action = policy.action; vlan = policy.vlan ?? ""; allowsMAB = policy.allowsMAB
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

// MARK: - Sessions

/// Accounting sessions (Start / Interim-Update / Stop, kept 30 days) with RFC 5176 actions:
/// Reauthenticate (the NAS's flavour: Cisco reauthenticate, Aruba port bounce, else Disconnect)
/// and Disconnect, each confirmed first.
struct RadiusSessions: View {
    @Environment(AppModel.self) private var model
    @State private var sessions: [DirectoryStore.RadiusSession] = []
    @State private var showEnded = false
    @State private var confirm: (action: CoAAction, session: DirectoryStore.RadiusSession)?
    @State private var message: String?
    @State private var failed = false
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text(showEnded ? "\(sessions.count) session\(sessions.count == 1 ? "" : "s") (30 days)"
                     : "\(sessions.count) active session\(sessions.count == 1 ? "" : "s")")
                    .font(Theme.body).foregroundStyle(Theme.muted)
                Toggle("Show ended", isOn: $showEnded).toggleStyle(.quiet)
                Spacer(minLength: 16)
                Button("Refresh") { Task { await reload() } }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let message { QuietNote(message, attention: failed).padding(.bottom, 12).textSelection(.enabled) }
            if sessions.isEmpty {
                QuietNote("No accounting yet. Point the NAS's accounting at this DC (udp 1813, same shared secret); Start, Interim-Update and Stop records appear here.", attention: false)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(sessions) { session in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 10) {
                                            Text(session.userName ?? "-").font(Theme.body)
                                                .foregroundStyle(session.active ? Theme.ink : Theme.faint)
                                            Text(session.mac ?? session.callingStationId ?? "")
                                                .font(Theme.detail.monospaced()).foregroundStyle(Theme.muted)
                                            if !session.active {
                                                StateText(text: "ended" + (session.terminateCause.map { " · \(RADIUSNames.terminateCause($0))" } ?? ""),
                                                          attention: false, dimmed: true)
                                            }
                                        }
                                        Text(detail(session)).font(Theme.detail).foregroundStyle(Theme.muted)
                                            .lineLimit(1).textSelection(.enabled)
                                    }
                                    Spacer(minLength: 8)
                                    if session.active {
                                        Menu("Act") {
                                            Button("Reauthenticate…") { confirm = (.reauthenticate, session) }
                                            Button("Disconnect…", role: .destructive) { confirm = (.disconnect, session) }
                                        }
                                        .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                                        .disabled(busy)
                                    }
                                }
                            }
                            Divider().overlay(Theme.line)
                        }
                    }
                }
            }
        }
        .task(id: showEnded) { await reload() }
        .alert("\(confirm?.action.title ?? "") \(confirm?.session.mac ?? confirm?.session.userName ?? "this session")?",
               isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } }),
               presenting: confirm) { item in
            Button(item.action.title, role: item.action == .disconnect ? .destructive : nil) { act(item.action, item.session) }
            Button("Cancel", role: .cancel) {}
        } message: { item in
            Text(item.action == .disconnect
                 ? "The NAS ends the session; the device reconnects and authenticates again."
                 : "The NAS runs authentication again (Cisco: reauthenticate; Aruba switch: port bounce; others: Disconnect), so the current policy and device profile apply.")
        }
    }

    private func detail(_ s: DirectoryStore.RadiusSession) -> String {
        let port = s.nasPortId ?? s.nasPort.map { "port \($0)" }
        let bytes = ByteCountFormatter()
        return [(s.nasName ?? s.nasSource) + (port.map { " · \($0)" } ?? ""),
                s.framedIP,
                "since " + PKIText.stamp(s.startedAt),
                "\(bytes.string(fromByteCount: Int64(clamping: s.inputOctets))) in, \(bytes.string(fromByteCount: Int64(clamping: s.outputOctets))) out"]
            .compactMap { $0 }.joined(separator: " · ")
    }

    private func act(_ action: CoAAction, _ session: DirectoryStore.RadiusSession) {
        busy = true
        Task {
            let result = await model.controller.radiusCoA(action, session: session)
            message = "\(result.request) \(session.mac ?? session.userName ?? session.sessionId): \(result.text)"
            failed = !result.ok
            busy = false
            await reload()
        }
    }

    private func reload() async {
        sessions = await model.controller.radiusSessions(activeOnly: !showEnded)
    }
}

// MARK: - Registered devices

/// The MAB allow-list: MAC → description and an optional group, matched in policies by
/// `registered_device` and `device_group`.
struct RadiusDevices: View {
    @Environment(AppModel.self) private var model
    @State private var devices: [DirectoryStore.RegisteredDevice] = []
    @State private var adding = false
    @State private var editing: DirectoryStore.RegisteredDevice?
    @State private var confirmDelete: DirectoryStore.RegisteredDevice?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text("\(devices.count) registered device\(devices.count == 1 ? "" : "s")").font(Theme.body).foregroundStyle(Theme.muted)
                Spacer(minLength: 16)
                Button("Register a device") { adding = true }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if devices.isEmpty {
                QuietNote("Devices without 802.1X (printers, phones, cameras) sign in by MAC Authentication Bypass. Register their MACs here and allow MAB in a policy that tests registered_device is yes, or device_group.", attention: false)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(devices) { device in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(device.mac).font(Theme.body.monospaced()).foregroundStyle(Theme.ink)
                                        Text([device.description.isEmpty ? nil : device.description, device.group.map { "group \($0)" }]
                                            .compactMap { $0 }.joined(separator: " · "))
                                            .font(Theme.detail).foregroundStyle(Theme.muted)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                        Button("Edit…") { editing = device }
                                        Button("Remove…", role: .destructive) { confirmDelete = device }
                                    }
                                    .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                                }
                            }
                            Divider().overlay(Theme.line)
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(isPresented: $adding) { RadiusDeviceSheet(onDone: { Task { await reload() } }) }
        .sheet(item: $editing) { device in RadiusDeviceSheet(device: device, onDone: { Task { await reload() } }) }
        .alert("Remove \(confirmDelete?.mac ?? "")?",
               isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
               presenting: confirmDelete) { device in
            Button("Remove", role: .destructive) {
                Task {
                    do { try await model.controller.deleteRegisteredDevice(mac: device.mac); failure = nil }
                    catch { failure = "Remove \(device.mac) failed: \(error)" }
                    await reload()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("Its next MAB request no longer counts as registered; policies that need registered_device reject it.")
        }
    }

    private func reload() async {
        devices = await model.controller.registeredDevices()
    }
}

struct RadiusDeviceSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var device: DirectoryStore.RegisteredDevice?
    let onDone: () -> Void

    @State private var mac = ""
    @State private var description = ""
    @State private var group = ""
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(device == nil ? "Register a device" : "Edit \(device?.mac ?? "")").font(Theme.emphasis).foregroundStyle(Theme.ink)
            TextField("MAC (aa:bb:cc:dd:ee:ff, AABBCCDDEEFF, aabb.ccdd.eeff)", text: $mac).textFieldStyle(.quiet)
                .font(.body.monospaced()).disabled(device != nil)
            TextField("Description (Printer 3F)", text: $description).textFieldStyle(.quiet)
            TextField("Group (optional, e.g. Printers)", text: $group).textFieldStyle(.quiet)
            if let failure { Text(failure).foregroundStyle(Theme.attention).font(Theme.detail) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.quietLink).keyboardShortcut(.cancelAction)
                Button("Save") {
                    let d = DirectoryStore.RegisteredDevice(mac: mac, description: description, group: group,
                                                            addedAt: device?.addedAt ?? Date())
                    Task {
                        do { try await model.controller.saveRegisteredDevice(d); onDone(); dismiss() }
                        catch { failure = "\(error)" }
                    }
                }
                .buttonStyle(.quietPrimary).keyboardShortcut(.defaultAction)
                .disabled(RADIUSMAC.normalize(mac) == nil)
            }
        }
        .padding(24).frame(width: 440)
        .background(Theme.background)
        .onAppear {
            if let device { mac = device.mac; description = device.description; group = device.group ?? "" }
        }
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
            QuietNote("Paste what a NAS would send, one Name = value per line (Time = 09:30 and Weekday = Sat test time rules; account is looked up from User-Name, or set it with Account = alice; the device profile and registration come from Calling-Station-Id, or set device_category = printer; auth_method = mab tests MAC Authentication Bypass). The directory facts are looked up and the policies run as for a live request; no password is checked and nothing is sent.", attention: false)
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


// MARK: - Settings

/// RADIUS ▸ Settings (1 Oct 2026; was the 802.1X tab): only what the RADIUS server itself does.
/// The Windows 802.1X profiles moved to the Group Policy page.
struct RadiusSettingsTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                RadiusPEAPCryptoBinding()
                RadiusRSACompatibility()
                QuietRow {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text("Windows profiles:").font(Theme.body).foregroundStyle(Theme.muted)
                        Button("Group Policy ▸ Wireless") {
                            model.groupPolicyTab = .wireless
                            model.selection = .groupPolicy
                        }
                            .buttonStyle(.quietLink)
                    }
                }
            }
            .frame(maxWidth: GroupPolicyLayout.columnWidth, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// RADIUS ▸ Settings ▸ "Require PEAP crypto binding" (CVE audit 1 Oct 2026, default off for old
/// supplicants, on recommended): PEAP clients that return no valid Crypto-Binding TLV are rejected.
struct RadiusPEAPCryptoBinding: View {
    @Environment(AppModel.self) private var model
    @State private var required = false
    @State private var loaded = false
    @State private var message: String?
    @State private var failed = false

    var body: some View {
        QuietRow(first: true) {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: Binding(get: { required }, set: { change($0) })) {
                    SettingsLabel(title: "Require PEAP crypto binding",
                                  detail: "Recommended. Binds the PEAP tunnel to the inner MS-CHAPv2, so a rogue access point cannot relay a sign-in. Windows, macOS, iOS, Android and wpa_supplicant support it; if an old device stops connecting, Activity shows “no Crypto-Binding TLV”.")
                }
                .toggleStyle(.quiet)
                .disabled(!loaded)
                if let message { QuietNote(message, attention: failed) }
            }
        }
        .task {
            required = await model.controller.radiusRequirePEAPCryptoBinding()
            loaded = true
        }
    }

    private func change(_ on: Bool) {
        Task {
            do {
                try await model.controller.setRadiusRequirePEAPCryptoBinding(on)
                required = on
                message = nil; failed = false
            } catch {
                message = "Not changed: \(error)"; failed = true
            }
        }
    }
}

/// RADIUS ▸ Settings ▸ "Allow RSA-only devices" (1 Oct 2026, default off): printers, IP phones,
/// IoT and old supplicants that cannot use the ECDSA chain get a separate RSA chain (the RSA
/// compatibility root, RSA-3072) and can enrol RSA client certificates (Computer-RSA / User-RSA
/// over SCEP/EST). The Windows 802.1X profiles keep the main root: Windows 10/11 never need RSA.
struct RadiusRSACompatibility: View {
    @Environment(AppModel.self) private var model
    @State private var allowed = false
    @State private var loaded = false
    @State private var busy = false
    @State private var root: (der: [UInt8], thumbprint: String)?
    @State private var message: String?
    @State private var failed = false

    var body: some View {
        QuietRow {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: Binding(get: { allowed }, set: { change($0) })) {
                    SettingsLabel(title: "Allow RSA-only devices",
                                  detail: "For printers, IP phones, IoT and old supplicants that cannot use ECDSA: they get an RSA chain from a separate RSA compatibility root; every other client keeps ECDSA. On the device, install that root (Certificates ▸ Authority ▸ Save CA, or http://<this DC>/pki/rsa-compat.crt), set the server name to this DC and enroll over SCEP/EST with the Computer-RSA or User-RSA template.")
                }
                .toggleStyle(.quiet)
                .disabled(!loaded || busy)
                if allowed, let root {
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text("RSA compatibility root · SHA-1 \(root.thumbprint)")
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                            .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        CopyButton(value: root.thumbprint)
                    }
                }
                if let message { QuietNote(message, attention: failed).textSelection(.enabled) }
            }
        }
        .task { await load() }
    }

    private func load() async {
        allowed = await model.controller.rsaOnlyDevicesAllowed()
        root = await model.controller.rsaCompatibilityRoot()
        loaded = true
    }

    private func change(_ on: Bool) {
        busy = true
        Task {
            do {
                try await model.controller.setRSAOnlyDevicesAllowed(on)
                message = on ? "RSA-only devices allowed. The RADIUS server offers the RSA chain to clients without ECDSA." : "RSA-only devices are no longer allowed."
                failed = false
            } catch {
                message = "Not changed: \(error)"; failed = true
            }
            await load()
            busy = false
        }
    }
}
