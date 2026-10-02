import AppKit
import DHCPKit
import LabDCCore
import Store
import SwiftUI
import UniformTypeIdentifiers

/// Phase 5: the DHCP page — Scopes (v4 and v6 together, per VLAN), Reservations, Leases (search,
/// detail with the fingerprint and history, release), Settings (relay-only / direct after a
/// probe, allowed relays, profilers), Devices (the profiles RADIUS policies read) and Test (a relayed DISCOVER/SOLICIT dry run). No on/off
/// switch: DHCP runs once a scope exists; the state line is the Services row's.
struct DHCPView: View {
    @Environment(AppModel.self) private var model
    @State private var tab = DHCPTab.scopes

    enum DHCPTab: String, CaseIterable, Identifiable {
        case scopes, reservations, leases, devices, settings, test
        var id: String { rawValue }
        var title: String {
            switch self {
            case .scopes: "Scopes"
            case .reservations: "Reservations"
            case .leases: "Leases"
            case .devices: "Devices"
            case .settings: "Settings"
            case .test: "Test"
            }
        }
    }

    /// The running server's mode (`relay-only`), re-read while the page is open: the Services
    /// row's copy is only refreshed when a service changes. Only the mode: the Scopes and Leases
    /// tabs count their own rows (owner, 2 Oct 2026).
    @State private var live: String?

    init(tab: DHCPTab = .scopes) { _tab = State(initialValue: tab) }

    private func stateDetail(_ service: ServiceStatus) -> String {
        switch service.state {
        case .running: service.portsText
        case .stopped: "Stopped with Services ▸ Stop: relayed requests get no answer until Start."
        default: "Add a scope and DHCP starts with the other services."
        }
    }

    var body: some View {
        QuietPage(title: "DHCP", scrolls: false) {
            QuietTabs(items: DHCPTab.allCases.map { ($0, $0.title) }, selection: $tab)
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                if let service = model.controller.status.services.first(where: { $0.service == .dhcp }) {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        StateText(text: service.stateLabel, attention: service.problemMessage != nil, dimmed: service.state != .running)
                        Text(service.problemMessage
                             ?? (service.state == .running ? live ?? service.detail?.components(separatedBy: " · ").first : nil)
                             ?? stateDetail(service))
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                            .lineLimit(2).textSelection(.enabled)
                    }
                    .padding(.bottom, 14)
                }
                switch tab {
                case .scopes: DHCPScopesTab()
                case .reservations: DHCPReservationsTab()
                case .leases: DHCPLeasesTab()
                case .devices: DHCPDevicesTab()
                case .settings: DHCPSettingsTab()
                case .test: DHCPTestTab()
                }
            }
        }
        .task {
            while !Task.isCancelled {
                live = await model.controller.dhcpStatus()?.modeText
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
}

/// Field label above a control (the sheets' layout).
@MainActor private func dhcpField(_ label: String, @ViewBuilder control: () -> some View) -> some View {
    SheetField(label, control: control)
}

/// `10.0.0.1, 10.0.0.2` ↔ list (commas or new lines; `a - b` stays one entry).
private func dhcpList(_ text: String) -> [String] { DHCPInput.list(text) }

/// A sheet's pop-up menu under its label: left-aligned, its natural width.
@MainActor private func dhcpPicker<V: Hashable>(_ label: String, _ selection: Binding<V>, @ViewBuilder _ items: () -> some View) -> some View {
    SheetPicker(label, selection: selection, items: items)
}

/// The Option 43 row of a sheet: what is set (or what applies without it) in body text, then the actions.
@MainActor private func dhcpOption43Row(_ option: VendorOption43?, unset: String, edit: @escaping () -> Void, remove: @escaping () -> Void) -> some View {
    dhcpField("Option 43") {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(option.map { "\($0.vendor.title) · " + ($0.controllers.isEmpty ? $0.hexPreview : $0.controllers.joined(separator: ", ")) } ?? unset)
                .font(Theme.body).foregroundStyle(option == nil ? Theme.muted : Theme.ink)
                .lineLimit(1).truncationMode(.tail).textSelection(.enabled)
            Button(option == nil ? "Set…" : "Edit…", action: edit).buttonStyle(.quietLink)
            if option != nil { Button("Remove", action: remove).buttonStyle(.quietLink) }
            Spacer(minLength: 0)
        }
    }
}

// MARK: - Scopes

struct DHCPScopesTab: View {
    @Environment(AppModel.self) private var model
    @State private var scopes: [DHCPScope] = []
    @State private var status: DHCPRuntimeStatus?
    @State private var editing: DHCPScope?
    @State private var adding = false
    @State private var confirmDelete: DHCPScope?
    @State private var failure: String?
    @State private var notice: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                if !scopes.isEmpty {
                    Text("\(scopes.count) scope\(scopes.count == 1 ? "" : "s")").font(Theme.body).foregroundStyle(Theme.muted)
                }
                Spacer(minLength: 16)
                Button("Add a scope") { adding = true }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if let notice { QuietNote(notice).padding(.bottom, 12).textSelection(.enabled) }
            if scopes.isEmpty {
                QuietNote("No scope yet. Add one per test VLAN, then point that VLAN's switch relay (ip helper-address) at this Mac. "
                          + "LabDC only answers relayed requests, so the production DHCP server keeps the rest of the network.")
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(scopes) { scope in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 10) {
                                            Text(scope.name).font(Theme.body).foregroundStyle(scope.enabled ? Theme.ink : Theme.faint)
                                            StateText(text: scope.family.title, dimmed: true)
                                            if !scope.enabled { StateText(text: "Disabled", dimmed: true) }
                                        }
                                        Text(summary(scope)).font(Theme.detail).foregroundStyle(Theme.muted)
                                            .lineLimit(2).textSelection(.enabled)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                        Button("Edit…") { editing = scope }
                                        Button(scope.enabled ? "Disable" : "Enable") {
                                            var s = scope; s.enabled.toggle()
                                            run("\(s.enabled ? "Enable" : "Disable") \(scope.name)") { show(try await model.controller.saveDHCPScope(s)) }
                                        }
                                        Button("Delete…", role: .destructive) { confirmDelete = scope }
                                    }
                                    .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                                }
                            }
                        }
                        if scopes.contains(where: { $0.family == .v6 }) {
                            QuietNote("IPv6: clients ask DHCPv6 for an address only when the router's Router Advertisement sets the M "
                                      + "(managed) flag — that is the router's or switch's setting, not LabDC's. Without it they use SLAAC.")
                                .padding(.top, 14)
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(isPresented: $adding) { DHCPScopeSheet(onDone: { notes in show(notes); Task { await reload() } }) }
        .sheet(item: $editing) { scope in DHCPScopeSheet(scope: scope, onDone: { notes in show(notes); Task { await reload() } }) }
        .alert("Delete the scope “\(confirmDelete?.name ?? "")”?",
               isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
               presenting: confirmDelete) { scope in
            Button("Delete", role: .destructive) { run("Delete \(scope.name)") { try await model.controller.deleteDHCPScope(scope) } }
            Button("Cancel", role: .cancel) {}
        } message: { scope in
            Text("Its reservations and lease history go too, and its clients' DNS records are removed. Clients keep their address until "
                 + "their lease runs out, then ask again\(scope.family == .v4 ? " — through the relay, which will get no answer from LabDC" : "").")
        }
    }

    private func summary(_ s: DHCPScope) -> String {
        var parts: [String] = []
        if let vlan = s.vlan { parts.append("VLAN \(vlan)") }
        parts.append(s.subnet)
        parts.append(s.ranges.map(\.text).joined(separator: ", "))
        if let active = status?.activePerScope[s.id] { parts.append("\(active) of \(s.poolSize) in use") }
        if let o = s.option43 { parts.append("option 43 \(o.vendor.title)") }
        if s.knownClientsOnly { parts.append("known clients only") }
        if s.authoritative { parts.append("authoritative") }
        return parts.joined(separator: " · ")
    }

    private func reload() async {
        scopes = await model.controller.dhcpScopes().sorted { ($0.vlan ?? 0, $0.family.rawValue, $0.name) < ($1.vlan ?? 0, $1.family.rawValue, $1.name) }
        status = await model.controller.dhcpStatus()
    }

    /// Save notes (e.g. "option 51 removed: the server sets it") stay on the page until the next save.
    private func show(_ notes: [String]) {
        notice = notes.isEmpty ? nil : notes.joined(separator: "\n")
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        // A delete (or a failed save) clears the last save's notes: they were about another row.
        notice = nil
        Task {
            do { try await body(); failure = nil } catch { failure = "\(what) failed: \(error)" }
            await reload()
        }
    }
}

struct DHCPScopeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var scope: DHCPScope?
    /// Notes from the save (server-set options dropped from an older row), shown on the page.
    let onDone: ([String]) -> Void

    @State private var name = ""
    @State private var family = DHCPFamily.v4
    @State private var vlan = ""
    @State private var subnet = ""
    @State private var ranges = ""
    @State private var exclusions = ""
    @State private var routers = ""
    @State private var leaseHours = "8"
    @State private var dns = ""
    @State private var domain = ""
    @State private var ntp = ""
    @State private var search = ""
    @State private var mtu = ""
    @State private var routes = ""
    @State private var capwap = ""
    @State private var tftp = ""
    @State private var bootfile = ""
    @State private var tftp150 = ""
    @State private var shared = ""
    @State private var offerDelay = "0"
    @State private var authoritative = false
    @State private var knownOnly = false
    @State private var ping = false
    @State private var dnsUpdates = true
    @State private var rapidCommit = true
    @State private var enabled = true
    @State private var option43: VendorOption43?
    @State private var editing43 = false
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        QuietSheet(title: scope == nil ? "New scope" : "Edit \(scope?.name ?? "")", width: 640, failure: failure) {
                    HStack(alignment: .top, spacing: 16) {
                        dhcpField("Name") { QuietTextField("Name", text: $name, prompt: "Staff VLAN 20").textFieldStyle(.quiet) }
                        dhcpField("VLAN") { QuietTextField("VLAN", text: $vlan, prompt: "20").textFieldStyle(.quiet).frame(width: 70) }
                    }
                    dhcpField("Family") {
                        dhcpPicker("Family", $family) { ForEach(DHCPFamily.allCases, id: \.self) { Text($0.title).tag($0) } }.disabled(scope != nil)
                    }
                    dhcpField(family == .v4 ? "Subnet" : "Prefix") {
                        QuietTextField(family == .v4 ? "Subnet" : "Prefix", text: $subnet, prompt: family == .v4 ? "10.20.0.0/24" : "2001:db8:20::/64").textFieldStyle(.quietMonospaced)
                    }
                    dhcpField("Address ranges (comma separated)") {
                        QuietTextField("Address ranges (comma separated)", text: $ranges, prompt: family == .v4 ? "10.20.0.100-10.20.0.199" : "2001:db8:20::100-2001:db8:20::1ff")
                            .textFieldStyle(.quietMonospaced)
                    }
                    dhcpField("Excluded (optional)") { QuietTextField("Excluded (optional)", text: $exclusions, prompt: family == .v4 ? "10.20.0.150-10.20.0.159" : "2001:db8:20::150-2001:db8:20::15f").textFieldStyle(.quietMonospaced) }
                    if family == .v4 {
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("Router (option 3)") { QuietTextField("Router (option 3)", text: $routers, prompt: "10.20.0.1").textFieldStyle(.quietMonospaced) }
                            dhcpField("Lease (hours)") { QuietTextField("Lease (hours)", text: $leaseHours, prompt: "8").textFieldStyle(.quiet).frame(width: 80) }
                        }
                    } else {
                        dhcpField("Valid lifetime (hours)") { QuietTextField("Valid lifetime (hours)", text: $leaseHours, prompt: "24").textFieldStyle(.quiet).frame(width: 80) }
                    }
                    HStack(alignment: .top, spacing: 16) {
                        dhcpField("DNS servers (blank = this DC)") { QuietTextField("DNS servers (blank = this DC)", text: $dns, prompt: family == .v4 ? "this DC" : "this DC's IPv6").textFieldStyle(.quiet) }
                        dhcpField("NTP servers (blank = this DC)") { QuietTextField("NTP servers (blank = this DC)", text: $ntp, prompt: "this DC").textFieldStyle(.quiet) }
                    }
                    HStack(alignment: .top, spacing: 16) {
                        dhcpField("Domain (blank = the AD domain)") { QuietTextField("Domain (blank = the AD domain)", text: $domain, prompt: model.controller.status.dnsDomain ?? "lab.sheep").textFieldStyle(.quiet) }
                        dhcpField("Search list") { QuietTextField("Search list", text: $search, prompt: "lab.sheep, corp.example").textFieldStyle(.quiet) }
                    }
                    if family == .v4 {
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("MTU (26)") { QuietTextField("MTU (26)", text: $mtu, prompt: "1500").textFieldStyle(.quiet).frame(width: 80) }
                            dhcpField("Static routes (121): cidr@gateway") { QuietTextField("Static routes (121): cidr@gateway", text: $routes, prompt: "10.30.0.0/16@10.20.0.254").textFieldStyle(.quietMonospaced) }
                        }
                        dhcpOption43Row(option43, unset: "Not sent", edit: { editing43 = true }, remove: { option43 = nil })
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("CAPWAP controllers (138)") { QuietTextField("CAPWAP controllers (138)", text: $capwap, prompt: "10.0.0.9").textFieldStyle(.quietMonospaced) }
                            dhcpField("TFTP servers (150)") { QuietTextField("TFTP servers (150)", text: $tftp150, prompt: "10.0.0.20").textFieldStyle(.quietMonospaced) }
                        }
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("TFTP server name (66)") { QuietTextField("TFTP server name (66)", text: $tftp, prompt: "tftp.lab.sheep").textFieldStyle(.quiet) }
                            dhcpField("Boot file (67)") { QuietTextField("Boot file (67)", text: $bootfile, prompt: "SEP{mac}.cnf.xml").textFieldStyle(.quiet) }
                        }
                        QuietNote("LabDC hands out 66/67/150 for phones and zero-touch switches; it does not serve TFTP or PXE itself.")
                    }
                    HStack(alignment: .top, spacing: 16) {
                        dhcpField("Shared network (optional)") { QuietTextField("Shared network (optional)", text: $shared, prompt: "floor2").textFieldStyle(.quiet) }
                        dhcpField("Offer delay (ms)") { QuietTextField("Offer delay (ms)", text: $offerDelay, prompt: "0").textFieldStyle(.quiet).frame(width: 80) }
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Toggle("Enabled", isOn: $enabled).toggleStyle(.quiet)
                        Toggle("Register clients in DNS (A/AAAA + PTR)", isOn: $dnsUpdates).toggleStyle(.quiet)
                        Toggle("Known clients only (reservations)", isOn: $knownOnly).toggleStyle(.quiet)
                        if family == .v4 { Toggle("Ping an address before offering it", isOn: $ping).toggleStyle(.quiet) }
                        if family == .v6 { Toggle("Rapid Commit (two-message exchange)", isOn: $rapidCommit).toggleStyle(.quiet) }
                        Toggle("Authoritative (NAK addresses that do not belong here)", isOn: $authoritative).toggleStyle(.quiet)
                        if authoritative {
                            Text("Only for a VLAN that has no other DHCP server: an authoritative second server NAKs the production server's clients.")
                                .font(Theme.detail).foregroundStyle(Theme.attention).fixedSize(horizontal: false, vertical: true)
                        }
                    }
        } actions: {
            SheetButtons("Save", disabled: busy || name.isEmpty || subnet.isEmpty || ranges.isEmpty) { save() }
        }
        .sheet(isPresented: $editing43) { Option43Editor(option: option43) { option43 = $0 } }
        .onAppear(perform: load)
    }

    private func load() {
        guard let s = scope else { return }
        name = s.name; family = s.family; vlan = s.vlan.map(String.init) ?? ""; subnet = s.subnet
        ranges = s.ranges.map(\.text).joined(separator: ", "); exclusions = s.exclusions.map(\.text).joined(separator: ", ")
        routers = s.routers.joined(separator: ", "); leaseHours = String(format: "%g", Double(s.leaseSeconds) / 3600)
        dns = s.dnsServers.joined(separator: ", "); domain = s.domainName ?? ""; ntp = s.ntpServers.joined(separator: ", ")
        search = s.searchList.joined(separator: ", "); mtu = s.mtu.map(String.init) ?? ""
        routes = s.staticRoutes.map { "\($0.destination)@\($0.gateway)" }.joined(separator: ", ")
        capwap = s.capwap.joined(separator: ", "); tftp = s.tftpServer ?? ""; bootfile = s.bootfile ?? ""
        tftp150 = s.tftpServers150.joined(separator: ", "); shared = s.sharedNetwork ?? ""; offerDelay = String(s.offerDelayMs)
        authoritative = s.authoritative; knownOnly = s.knownClientsOnly; ping = s.pingBeforeOffer; dnsUpdates = s.dnsUpdates
        rapidCommit = s.rapidCommit; enabled = s.enabled; option43 = s.option43
    }

    private func save() {
        var s = scope ?? DHCPScope(name: name, family: family, subnet: subnet)
        s.name = name.trimmingCharacters(in: .whitespaces)
        s.family = family
        s.subnet = subnet.trimmingCharacters(in: .whitespaces)
        // Every typed value parses or the sheet says which one does not — nothing is dropped
        // or replaced by a default silently.
        do {
            s.vlan = try DHCPInput.integer(vlan, field: "VLAN", in: 1...4094)
            s.ranges = try DHCPInput.ranges(ranges, family: family, field: "Address ranges")
            s.exclusions = try DHCPInput.ranges(exclusions, family: family, field: "Excluded")
            s.leaseSeconds = try DHCPInput.hours(leaseHours, field: family == .v4 ? "Lease (hours)" : "Valid lifetime (hours)")
                ?? (family == .v4 ? 8 * 3600 : 86_400)
            s.offerDelayMs = try DHCPInput.integer(offerDelay, field: "Offer delay (ms)", in: 0...5000) ?? 0
            if family == .v4 {
                s.routers = try DHCPInput.addresses(routers, family: .v4, field: "Router")
                s.mtu = try DHCPInput.integer(mtu, field: "MTU", in: 68...65535)
                s.staticRoutes = try DHCPInput.routes(routes)
                s.capwap = try DHCPInput.addresses(capwap, family: .v4, field: "CAPWAP controllers")
                s.tftpServers150 = try DHCPInput.addresses(tftp150, family: .v4, field: "TFTP servers (150)")
            }
            s.dnsServers = try DHCPInput.addresses(dns, family: family, field: "DNS servers")
            s.ntpServers = try DHCPInput.addresses(ntp, family: family, field: "NTP servers")
        } catch {
            failure = "\(error)"
            return
        }
        s.domainName = domain.trimmingCharacters(in: .whitespaces).isEmpty ? nil : domain.trimmingCharacters(in: .whitespaces)
        s.searchList = dhcpList(search)
        s.tftpServer = tftp.isEmpty ? nil : tftp
        s.bootfile = bootfile.isEmpty ? nil : bootfile
        s.sharedNetwork = shared.trimmingCharacters(in: .whitespaces).isEmpty ? nil : shared.trimmingCharacters(in: .whitespaces)
        s.authoritative = authoritative; s.knownClientsOnly = knownOnly; s.pingBeforeOffer = ping
        s.dnsUpdates = dnsUpdates; s.rapidCommit = rapidCommit; s.enabled = enabled
        s.option43 = family == .v4 ? option43 : nil
        busy = true
        Task {
            do {
                let notes = try await model.controller.saveDHCPScope(s)
                onDone(notes); dismiss()
            } catch { failure = "\(error)" }
            busy = false
        }
    }
}

/// Option 43 for access-point discovery: pick a vendor, type the controller addresses, see the
/// bytes that go on the wire.
struct Option43Editor: View {
    @Environment(\.dismiss) private var dismiss
    var option: VendorOption43?
    let onSave: (VendorOption43) -> Void

    @State private var vendor = VendorOption43.Vendor.cisco
    @State private var controllers = ""
    @State private var rawHex = ""
    @State private var vendorClass = VendorOption43.Vendor.cisco.defaultVendorClass

    var body: some View {
        let current = VendorOption43(vendor: vendor, controllers: dhcpList(controllers), rawHex: rawHex, vendorClass: vendorClass)
        let encoded = Result { try current.encode() }
        QuietSheet(title: "Option 43", width: 520) {
            dhcpField("Vendor") {
                dhcpPicker("Vendor", $vendor) { ForEach(VendorOption43.Vendor.allCases) { Text($0.title).tag($0) } }
                    .onChange(of: vendor) { _, v in vendorClass = v.defaultVendorClass }
            }
            if vendor == .raw {
                dhcpField("Bytes (hex)") { QuietTextField("Bytes (hex)", text: $rawHex, prompt: "f1040a000009").textFieldStyle(.quietMonospaced) }
            } else {
                dhcpField(vendor.maxControllers == 1 ? "Controller address" : "Controller addresses (in order of preference)") {
                    QuietTextField(vendor.maxControllers == 1 ? "Controller address" : "Controller addresses (in order of preference)", text: $controllers, prompt: "10.0.0.9").textFieldStyle(.quietMonospaced)
                }
            }
            dhcpField("Only for clients whose vendor class (option 60) contains") {
                QuietTextField("Only for clients whose vendor class (option 60) contains", text: $vendorClass, prompt: "blank = every client that asks for 43").textFieldStyle(.quiet)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("On the wire").font(Theme.caption).foregroundStyle(Theme.muted)
                switch encoded {
                case .success(let bytes):
                    Text(DHCPHex.string(bytes)).font(Theme.body.monospaced()).foregroundStyle(Theme.ink).textSelection(.enabled)
                    Text("\(bytes.count) bytes").font(Theme.detail).foregroundStyle(Theme.muted)
                case .failure(let error):
                    // Nothing typed yet is not an error (the red line greeted every new option).
                    if (vendor == .raw ? rawHex : controllers).trimmingCharacters(in: .whitespaces).isEmpty {
                        Text(vendor == .raw ? "The bytes appear here." : "The bytes appear here once a controller address is typed.")
                            .font(Theme.detail).foregroundStyle(Theme.muted)
                    } else {
                        Text(verbatim: "\(error)").font(Theme.detail).foregroundStyle(Theme.attention)
                    }
                }
            }
            Text(note).font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
        } actions: {
            SheetButtons("Use", disabled: (try? encoded.get()) == nil) { onSave(current); dismiss() }
        }
        .onAppear {
            if let option {
                vendor = option.vendor; controllers = option.controllers.joined(separator: ", ")
                rawHex = option.rawHex; vendorClass = option.vendorClass
            }
        }
    }

    private var note: String {
        switch vendor {
        case .cisco: "Cisco lightweight APs: type 0xF1, 4 bytes per WLC (Cisco doc 97066). Option 60 is per model, e.g. “Cisco AP C9120AX”."
        case .aruba: "Aruba campus APs (option 60 “ArubaAP”): the controller address as plain text."
        case .huawei: "Huawei APs: sub-option 3, the AC addresses as text, comma separated."
        case .huaweiBinary: "Huawei APs: sub-option 2, the AC addresses as 4-byte values."
        case .unifi: "UniFi devices (option 60 “ubnt”): sub-option 1, one controller."
        case .ruckusSmartZone: "Ruckus with SmartZone: sub-option 6, controller addresses as text."
        case .ruckusZoneDirector: "Ruckus with ZoneDirector: sub-option 3, controller addresses as text."
        case .raw: "Any vendor: the option bytes exactly as given."
        }
    }
}

// MARK: - Reservations

struct DHCPReservationsTab: View {
    @Environment(AppModel.self) private var model
    @State private var reservations: [DHCPReservation] = []
    @State private var scopes: [DHCPScope] = []
    @State private var editing: DHCPReservation?
    @State private var adding = false
    @State private var confirmDelete: DHCPReservation?
    @State private var failure: String?
    @State private var notice: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text("\(reservations.count) reservation\(reservations.count == 1 ? "" : "s")").font(Theme.body).foregroundStyle(Theme.muted)
                Spacer(minLength: 16)
                Button("Add a reservation") { adding = true }.buttonStyle(.quietLink).disabled(scopes.isEmpty)
            }
            .padding(.bottom, 16)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if let notice { QuietNote(notice).padding(.bottom, 12).textSelection(.enabled) }
            if reservations.isEmpty {
                QuietNote(scopes.isEmpty ? "Add a scope first." : "No reservations. A reservation gives one client (by MAC, client-id, DUID or the switch port's circuit-id) the same address every time.")
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(reservations) { r in
                            QuietRow {
                                HStack(alignment: .center, spacing: 16) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 10) {
                                            Text(r.name).font(Theme.body).foregroundStyle(r.enabled ? Theme.ink : Theme.faint)
                                            Text(r.address).font(Theme.body.monospaced()).foregroundStyle(Theme.ink).textSelection(.enabled)
                                        }
                                        Text(r.identifierText + " · " + (scopes.first { $0.id == r.scopeID }?.name ?? "?"))
                                            .font(Theme.detail).foregroundStyle(Theme.muted).lineLimit(1)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                        Button("Edit…") { editing = r }
                                        Button(r.enabled ? "Disable" : "Enable") {
                                            var c = r; c.enabled.toggle()
                                            run("\(c.enabled ? "Enable" : "Disable") \(r.name)") { show(try await model.controller.saveDHCPReservation(c)) }
                                        }
                                        Button("Delete…", role: .destructive) { confirmDelete = r }
                                    }
                                    .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                                }
                            }
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(isPresented: $adding) { DHCPReservationSheet(scopes: scopes, onDone: { notes in show(notes); Task { await reload() } }) }
        .sheet(item: $editing) { r in DHCPReservationSheet(reservation: r, scopes: scopes, onDone: { notes in show(notes); Task { await reload() } }) }
        .alert("Delete the reservation “\(confirmDelete?.name ?? "")”?",
               isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
               presenting: confirmDelete) { r in
            Button("Delete", role: .destructive) { run("Delete \(r.name)") { try await model.controller.deleteDHCPReservation(r) } }
            Button("Cancel", role: .cancel) {}
        } message: { r in
            Text("\(r.address) becomes an ordinary address again; the client keeps it until its lease ends, then may get another one.")
        }
    }

    private func reload() async {
        scopes = await model.controller.dhcpScopes()
        reservations = await model.controller.dhcpReservations().sorted { $0.address.localizedStandardCompare($1.address) == .orderedAscending }
    }

    /// Save notes (e.g. "option 51 removed: the server sets it") stay on the page until the next save.
    private func show(_ notes: [String]) {
        notice = notes.isEmpty ? nil : notes.joined(separator: "\n")
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        // A delete (or a failed save) clears the last save's notes: they were about another row.
        notice = nil
        Task {
            do { try await body(); failure = nil } catch { failure = "\(what) failed: \(error)" }
            await reload()
        }
    }
}

struct DHCPReservationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var reservation: DHCPReservation?
    let scopes: [DHCPScope]
    /// Notes from the save (server-set options dropped from an older row), shown on the page.
    let onDone: ([String]) -> Void

    @State private var name = ""
    @State private var scopeID: Int64 = 0
    @State private var address = ""
    @State private var mac = ""
    @State private var clientID = ""
    @State private var duid = ""
    @State private var circuitID = ""
    @State private var remoteID = ""
    @State private var hostname = ""
    @State private var enabled = true
    @State private var option43: VendorOption43?
    @State private var editing43 = false
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        let family = scopes.first { $0.id == scopeID }?.family ?? .v4
        QuietSheet(title: reservation == nil ? "New reservation" : "Edit \(reservation?.name ?? "")", width: 560, failure: failure) {
            dhcpField("Name") { QuietTextField("Name", text: $name, prompt: "Printer 2F").textFieldStyle(.quiet) }
            dhcpField("Scope") { dhcpPicker("Scope", $scopeID) { ForEach(scopes) { Text($0.name).tag($0.id) } } }
            dhcpField("Address") { QuietTextField("Address", text: $address, prompt: family == .v4 ? "10.20.0.50" : "2001:db8:20::50").textFieldStyle(.quietMonospaced) }
            QuietNote("Identify the client by any one of these (the first that matches wins).")
            HStack(alignment: .top, spacing: 16) {
                dhcpField("MAC") { QuietTextField("MAC", text: $mac, prompt: "aa:bb:cc:dd:ee:ff").textFieldStyle(.quietMonospaced) }
                if family == .v4 {
                    dhcpField("Client-id (61, hex)") { QuietTextField("Client-id (61, hex)", text: $clientID, prompt: "01aabbccddeeff").textFieldStyle(.quietMonospaced) }
                } else {
                    dhcpField("DUID (hex)") { QuietTextField("DUID (hex)", text: $duid, prompt: "000300010aabbccddeeff").textFieldStyle(.quietMonospaced) }
                }
            }
            HStack(alignment: .top, spacing: 16) {
                dhcpField("Switch port (82 circuit-id)") { QuietTextField("Switch port (82 circuit-id)", text: $circuitID, prompt: "vlan 20 mod 1 port 3 or 1/1/7").textFieldStyle(.quiet) }
                dhcpField("Remote-id (82/2)") { QuietTextField("Remote-id (82/2)", text: $remoteID, prompt: "text or hex").textFieldStyle(.quiet) }
            }
            dhcpField("DNS name (blank = the client's own)") { QuietTextField("DNS name (blank = the client's own)", text: $hostname, prompt: "printer-2f").textFieldStyle(.quiet) }
            if family == .v4 {
                dhcpOption43Row(option43, unset: "Same as the scope", edit: { editing43 = true }, remove: { option43 = nil })
            }
            Toggle("Enabled", isOn: $enabled).toggleStyle(.quiet)
        } actions: {
            SheetButtons("Save", disabled: busy || name.isEmpty || address.isEmpty || scopeID == 0) { save() }
        }
        .sheet(isPresented: $editing43) { Option43Editor(option: option43) { option43 = $0 } }
        .onAppear {
            scopeID = reservation?.scopeID ?? scopes.first?.id ?? 0
            guard let r = reservation else { return }
            name = r.name; address = r.address; mac = r.mac ?? ""; clientID = r.clientID ?? ""; duid = r.duid ?? ""
            circuitID = r.circuitID ?? ""; remoteID = r.remoteID ?? ""; hostname = r.hostname ?? ""; enabled = r.enabled
            option43 = r.option43
        }
    }

    private func save() {
        func opt(_ s: String) -> String? { let t = s.trimmingCharacters(in: .whitespaces); return t.isEmpty ? nil : t }
        var r = DHCPReservation(id: reservation?.id ?? 0, scopeID: scopeID, name: name, enabled: enabled, mac: opt(mac), clientID: opt(clientID),
                                duid: opt(duid), circuitID: opt(circuitID), remoteID: opt(remoteID), address: address.trimmingCharacters(in: .whitespaces),
                                hostname: opt(hostname), options: reservation?.options ?? [], option43: option43)
        r.id = reservation?.id ?? 0
        busy = true
        Task {
            do {
                let notes = try await model.controller.saveDHCPReservation(r)
                onDone(notes); dismiss()
            } catch { failure = "\(error)" }
            busy = false
        }
    }
}

// MARK: - Leases

struct DHCPLeasesTab: View {
    @Environment(AppModel.self) private var model
    @State private var leases: [DHCPLease] = []
    @State private var scopes: [DHCPScope] = []
    @State private var search = ""
    @State private var showAll = false
    @State private var detail: DHCPLease?

    var body: some View {
        let shown = filtered
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                QuietTextField("Search leases", text: $search, prompt: "Search address, MAC, name, device").textFieldStyle(.quiet).frame(width: 280)
                Toggle("Include history", isOn: $showAll).toggleStyle(.quiet).fixedSize()
                Spacer(minLength: 12)
                Text("\(shown.count) lease\(shown.count == 1 ? "" : "s")").font(Theme.detail).foregroundStyle(Theme.muted)
                Button("Refresh") { Task { await reload() } }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 14)
            if shown.isEmpty {
                QuietNote(leases.isEmpty ? "No leases yet. They appear as relayed clients get addresses." : "Nothing matches.")
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(shown) { l in
                            QuietRow {
                                Button { detail = l } label: {
                                    HStack(alignment: .firstTextBaseline, spacing: 14) {
                                        Text(l.address).font(Theme.body.monospaced()).foregroundStyle(Theme.ink).frame(width: 180, alignment: .leading)
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(l.whoText).font(Theme.body).foregroundStyle(Theme.ink).lineLimit(1)
                                            Text(line(l)).font(Theme.detail).foregroundStyle(Theme.muted).lineLimit(1)
                                        }
                                        Spacer(minLength: 8)
                                        StateText(text: l.state.title, attention: l.state == .declined || l.state == .abandoned,
                                                  dimmed: l.state != .active)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
        }
        .task {
            await reload()
            // A light live view: re-read every few seconds while the tab is open.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await reload()
            }
        }
        .sheet(item: $detail) { l in DHCPLeaseDetail(lease: l, scope: scopes.first { $0.id == l.scopeID }, onDone: { Task { await reload() } }) }
    }

    private var filtered: [DHCPLease] {
        let now = Date()
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return leases
            .filter { showAll || ($0.holds(at: now) && $0.state != .offered) }
            .filter { l in
                q.isEmpty || [l.address, l.mac ?? "", l.hostname ?? "", l.deviceOS ?? "", l.vendorClass ?? "",
                              l.deviceCategory.flatMap { DeviceClassifier.Category(rawValue: $0)?.title } ?? ""]
                    .contains { $0.lowercased().contains(q) }
            }
            .sorted { ($0.family.rawValue, $0.address.count, $0.address) < ($1.family.rawValue, $1.address.count, $1.address) }
    }

    private func line(_ l: DHCPLease) -> String {
        var parts: [String] = []
        if let c = l.deviceCategory.flatMap({ DeviceClassifier.Category(rawValue: $0) }), c != .unknown { parts.append(l.deviceOS ?? c.title) }
        parts.append(scopes.first { $0.id == l.scopeID }?.name ?? "")
        if l.state == .foreign, let other = l.otherServer { parts.append("leased by \(other)") }
        else { parts.append((l.expires > Date() ? "until " : "ended ") + PKIText.stamp(l.expires)) }
        if let relay = l.relay { parts.append("via \(relay)") }
        return parts.filter { !$0.isEmpty }.joined(separator: " · ")
    }

    private func reload() async {
        scopes = await model.controller.dhcpScopes()
        leases = await model.controller.dhcpLeases()
    }
}

/// One lease: who, where from (relay, switch port), DNS, the device guess and the raw
/// fingerprint, its history; Release with a confirmation.
struct DHCPLeaseDetail: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let lease: DHCPLease
    let scope: DHCPScope?
    let onDone: () -> Void
    @State private var history: [DHCPEvent] = []
    @State private var profile: DeviceProfile?
    @State private var confirmRelease = false
    @State private var failure: String?

    var body: some View {
        QuietSheet(title: lease.address, subtitle: lease.state.title, width: 600, failure: failure) {
                VStack(alignment: .leading, spacing: 12) {
                    Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 6) {
                        row("Client", lease.whoText)
                        row("Client key", lease.clientKey)
                        row("Scope", scope.map { $0.name + ($0.vlan.map { " (VLAN \($0))" } ?? "") } ?? "#\(lease.scopeID)")
                        // Gregorian like the rest of the app (the system calendar may be Buddhist).
                        row("Since", PKIText.stamp(lease.start))
                        row(lease.expires > Date() ? "Until" : "Ended", PKIText.stamp(lease.expires))
                        if let relay = lease.relay { row("Relay", relay + (lease.link.map { " · link \($0)" } ?? "")) }
                        if let c = lease.circuitID, let b = DHCPHex.bytes(c) { row("Switch port", CircuitIDDecoder.describe(b)) }
                        if let r = lease.remoteID, let b = DHCPHex.bytes(r) { row("Remote-id", DHCPHex.printable(b)) }
                        if let other = lease.otherServer { row("Other server", other) }
                        row("DNS", lease.dnsName.map { $0 + (lease.dnsForward ? " (A/AAAA + DHCID" : " (PTR only") + (lease.dnsPTR != nil ? ", PTR)" : ")") } ?? "not registered")
                        if let p = profile {
                            // "Windows (90%)", not "Windows — Windows (90%)" when the OS is only the category.
                            let os = p.os.flatMap { $0 == p.category.title ? nil : $0 }
                            row("Device", "\(p.category.title)\(os.map { " — \($0)" } ?? "") (\(p.confidence)%\(p.manualOverride ? ", set by hand" : ""))")
                        } else if let c = lease.deviceCategory.flatMap({ DeviceClassifier.Category(rawValue: $0) }) {
                            row("Device", "\(c.title) — \(lease.deviceOS ?? "?")")
                        }
                    }
                    if let fp = lease.fingerprint {
                        Text("Fingerprint").font(Theme.caption).foregroundStyle(Theme.muted)
                        Text(fp.lines.joined(separator: "\n")).font(Theme.detail.monospaced()).foregroundStyle(Theme.ink)
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                    if !history.isEmpty {
                        Text("History").font(Theme.caption).foregroundStyle(Theme.muted)
                        ForEach(history) { e in
                            Text("\(PKIText.stamp(e.date))  \(e.kind)  \(e.detail)")
                                .font(Theme.detail.monospaced()).foregroundStyle(Theme.ink).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
        } actions: {
            if lease.state == .active { Button("Release…") { confirmRelease = true }.buttonStyle(.quietDestructive) }
            Button("Done") { dismiss() }.buttonStyle(.quietPrimary).keyboardShortcut(.defaultAction)
        }
        .task {
            history = await model.controller.dhcpHistory(lease)
            if let mac = lease.mac { profile = await model.controller.deviceProfile(mac: mac) }
        }
        .alert("Release \(lease.address)?", isPresented: $confirmRelease) {
            Button("Release", role: .destructive) {
                Task {
                    do { try await model.controller.releaseDHCPLease(lease); onDone(); dismiss() } catch { failure = "\(error)" }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The lease ends now and its DNS records are removed. The client does not know: it keeps using the address until it renews, then gets an answer from LabDC again.")
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).font(Theme.caption).foregroundStyle(Theme.muted)
            Text(value).font(Theme.detail).foregroundStyle(Theme.ink).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Devices

/// The device profiles DHCP fingerprints build (§7): what RADIUS policies read as
/// `device_category` / `device_os` by Calling-Station-Id. Set by hand, back to automatic, forget.
struct DHCPDevicesTab: View {
    @Environment(AppModel.self) private var model
    @State private var devices: [DeviceProfile] = []
    @State private var search = ""
    @State private var editing: DeviceProfile?
    @State private var confirmForget: DeviceProfile?
    @State private var failure: String?

    var body: some View {
        let shown = filtered
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                QuietTextField("Search devices", text: $search, prompt: "Search MAC, name, category, OS").textFieldStyle(.quiet).frame(width: 280)
                Spacer(minLength: 12)
                Text("\(shown.count) device\(shown.count == 1 ? "" : "s")").font(Theme.detail).foregroundStyle(Theme.muted)
                Button("Refresh") { Task { await reload() } }.buttonStyle(.quietLink)
            }
            .padding(.bottom, 14)
            if let failure { QuietNote(failure, attention: true).padding(.bottom, 12).textSelection(.enabled) }
            if shown.isEmpty {
                QuietNote(devices.isEmpty
                          ? "No devices yet. Each client that gets an address is profiled from its DHCP fingerprint (vendor class, requested options, host name). RADIUS policies match the result as device_category and device_os."
                          : "Nothing matches.")
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(shown, id: \.mac) { d in
                            QuietRow {
                                HStack(alignment: .center, spacing: 14) {
                                    Text(d.mac).font(Theme.body.monospaced()).foregroundStyle(Theme.ink).frame(width: 160, alignment: .leading)
                                        .textSelection(.enabled)
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 10) {
                                            Text(d.category.title).font(Theme.body).foregroundStyle(d.category == .unknown ? Theme.faint : Theme.ink)
                                            if d.manualOverride { StateText(text: "Set by hand", dimmed: true) }
                                        }
                                        Text(line(d)).font(Theme.detail).foregroundStyle(Theme.muted).lineLimit(1)
                                    }
                                    Spacer(minLength: 8)
                                    Menu("Edit") {
                                        Button("Set category…") { editing = d }
                                        if d.manualOverride {
                                            Button("Back to automatic") { run("Back to automatic for \(d.mac)") { try await model.controller.clearDeviceOverride(mac: d.mac) } }
                                        }
                                        Button("Forget…", role: .destructive) { confirmForget = d }
                                    }
                                    .menuStyle(.button).buttonStyle(.quietLink).fixedSize()
                                }
                            }
                        }
                    }
                }
            }
        }
        .task { await reload() }
        .sheet(item: Binding(get: { editing.map(DeviceBox.init) }, set: { editing = $0?.profile })) { box in
            DHCPDeviceSheet(profile: box.profile) { category, os in
                run("Set \(box.profile.mac)") { try await model.controller.setDeviceCategory(mac: box.profile.mac, category: category, os: os) }
            }
        }
        .alert("Forget \(confirmForget?.mac ?? "")?",
               isPresented: Binding(get: { confirmForget != nil }, set: { if !$0 { confirmForget = nil } }),
               presenting: confirmForget) { d in
            Button("Forget", role: .destructive) { run("Forget \(d.mac)") { try await model.controller.deleteDeviceProfile(mac: d.mac) } }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("RADIUS treats it as an unknown device until its next DHCP request profiles it again. A category set by hand is lost.")
        }
    }

    /// `sheet(item:)` needs Identifiable; profiles are keyed by MAC.
    struct DeviceBox: Identifiable {
        let profile: DeviceProfile
        var id: String { profile.mac }
    }

    private var filtered: [DeviceProfile] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return devices }
        return devices.filter { d in
            [d.mac, d.hostname ?? "", d.os ?? "", d.vendorClass ?? "", d.category.title, d.category.rawValue].contains { $0.lowercased().contains(q) }
        }
    }

    private func line(_ d: DeviceProfile) -> String {
        var parts: [String] = []
        if let os = d.os, os != d.category.title { parts.append(os) }
        if let h = d.hostname { parts.append(h) }
        if let v = d.vendorClass { parts.append("“\(v)”") }
        parts.append(d.source == .manual ? "manual" : "\(d.source.rawValue) \(d.confidence)%")
        parts.append("seen " + PKIText.stamp(d.lastSeen))
        return parts.joined(separator: " · ")
    }

    private func reload() async { devices = await model.controller.deviceProfiles() }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        Task {
            do { try await body(); failure = nil } catch { failure = "\(what) failed: \(error)" }
            await reload()
        }
    }
}

struct DHCPDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    let profile: DeviceProfile
    let onSave: (DeviceCategory, String?) -> Void
    @State private var category = DeviceCategory.unknown
    @State private var os = ""

    var body: some View {
        QuietSheet(title: "Set the category of \(profile.mac)", width: 440) {
            dhcpField("Category") { dhcpPicker("Category", $category) { ForEach(DeviceCategory.allCases, id: \.self) { Text($0.title).tag($0) } } }
            dhcpField("OS / model (optional)") { QuietTextField("OS / model (optional)", text: $os, prompt: "HP LaserJet").textFieldStyle(.quiet) }
            QuietNote("Set by hand, DHCP fingerprints no longer change it. If the category changes and the device has an open RADIUS session, LabDC sends that switch a CoA so the new policy applies.")
        } actions: {
            SheetButtons("Save") {
                let t = os.trimmingCharacters(in: .whitespaces)
                onSave(category, t.isEmpty ? nil : t); dismiss()
            }
        }
        .onAppear { category = profile.category; os = profile.os ?? "" }
    }
}

// MARK: - Settings

struct DHCPSettingsTab: View {
    @Environment(AppModel.self) private var model
    @State private var settings = DHCPSettings()
    @State private var relays = ""
    @State private var profilers = ""
    @State private var quarantine = "10"
    @State private var serverAddress = ""
    @State private var capRelay = "0"
    @State private var capCircuit = "0"
    @State private var churn = "8"
    @State private var message: String?
    @State private var failed = false
    @State private var probing: String?
    @State private var confirmDirect: NetworkInterfaceChoice?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                QuietSection("Mode") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(settings.isRelayOnly
                             ? "Relay-only: LabDC answers only requests a switch relays to it (ip helper-address) and renewals from its own clients. Broadcasts on this Mac's own network are ignored, so the existing DHCP server is never contested."
                             : "Direct on \(settings.directInterfaces.joined(separator: ", ")): LabDC also answers broadcasts there (no other DHCP server answered the probe).")
                            .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                        ForEach(model.controller.status.interfaces) { iface in
                            HStack(alignment: .firstTextBaseline, spacing: 14) {
                                Text(iface.label).font(Theme.body).foregroundStyle(Theme.ink)
                                Spacer()
                                if probing == iface.bsdName {
                                    StateText(text: "Probing…")
                                } else if settings.directInterfaces.contains(iface.bsdName) {
                                    StateText(text: "Direct")
                                    Button("Relay-only") { disableDirect(iface.bsdName) }.buttonStyle(.quietLink)
                                } else {
                                    Button("Answer broadcasts here…") { confirmDirect = iface }.buttonStyle(.quietLink)
                                }
                            }
                        }
                    }
                }
                QuietSection("Relays and profilers") {
                    VStack(alignment: .leading, spacing: 10) {
                        dhcpField("Allowed relays (addresses, CIDRs or ranges; blank = relays whose giaddr is inside a scope)") {
                            QuietTextField("Allowed relays", text: $relays, prompt: "10.0.0.0/8").textFieldStyle(.quietMonospaced)
                        }
                        if relays.trimmingCharacters(in: .whitespaces).isEmpty {
                            Text("Recommended: list your relays (the switches' helper addresses). With the list blank, LabDC accepts any "
                                 + "relayed packet whose giaddr lies in one of its scopes, so a host on a scope VLAN can forge relayed "
                                 + "DHCP to make up device profiles that RADIUS rules read. A relay whose giaddr is outside every scope "
                                 + "(option 82 link selection) must be listed.")
                                .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                        }
                        dhcpField("Profilers (ClearPass / ISE data-port addresses; get a relay copy of each client message)") {
                            QuietTextField("Profilers", text: $profilers, prompt: "10.0.0.40").textFieldStyle(.quietMonospaced)
                        }
                        Toggle("Also send LabDC's replies (ACKs) to the profilers", isOn: $settings.forwardReplies).toggleStyle(.quiet)
                        Toggle("Also send DHCPv6 messages (wrapped in Relay-forward)", isOn: $settings.forwardV6).toggleStyle(.quiet)
                    }
                }
                QuietSection("IPv6") {
                    // Off by default (owner, 1 Oct 2026): macOS's dhcp6d holds udp 547 while Internet
                    // Sharing runs (a VM on a Shared network), and launchd restarts it.
                    Toggle("Serve DHCPv6 (udp 547)", isOn: $settings.enableV6).toggleStyle(.quiet)
                    Text("Off by default. If a VM uses a Shared network (UTM, Parallels, VMware) or Internet Sharing is on, macOS's own "
                         + "dhcp6d holds udp 547; switch the VM to Bridged first.")
                        .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                    Text("DHCPv6 is relay-first like v4 (ipv6 dhcp relay destination / ipv6 helper-address toward this Mac). Clients ask "
                         + "DHCPv6 for an address only when the router's Router Advertisement sets the M (managed) flag; with only the O flag "
                         + "they take SLAAC addresses and ask LabDC for DNS and NTP. The RA is the router's or switch's setting, not LabDC's.")
                        .font(Theme.detail).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                }
                QuietSection("Dynamic DNS") {
                    Picker("", selection: $settings.ddns) { ForEach(DHCPSettings.DDNSMode.allCases, id: \.self) { Text($0.title).tag($0) } }
                        .labelsHidden().fixedSize()
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                QuietSection("Safety") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("Declined address quarantine (minutes)") { QuietTextField("Declined address quarantine (minutes)", text: $quarantine, prompt: "10").textFieldStyle(.quiet).frame(width: 80) }
                            dhcpField("Server address (blank = automatic)") { QuietTextField("Server address (blank = automatic)", text: $serverAddress, prompt: "toward each relay").textFieldStyle(.quiet).frame(width: 180) }
                        }
                        HStack(alignment: .top, spacing: 16) {
                            dhcpField("Leases per relay (0 = no cap)") { QuietTextField("Leases per relay (0 = no cap)", text: $capRelay, prompt: "0").textFieldStyle(.quiet).frame(width: 80) }
                            dhcpField("Leases per switch port") { QuietTextField("Leases per switch port", text: $capCircuit, prompt: "0").textFieldStyle(.quiet).frame(width: 80) }
                            dhcpField("Client-ids per MAC per hour") { QuietTextField("Client-ids per MAC per hour", text: $churn, prompt: "8").textFieldStyle(.quiet).frame(width: 80) }
                        }
                    }
                }
                HStack(spacing: 24) {
                    Button("Save") { save() }.buttonStyle(.quietPrimary)
                    Button("Export…") { exportConfig() }.buttonStyle(.quietLink)
                    Button("Import…") { importConfig() }.buttonStyle(.quietLink)
                }
                if let message { QuietNote(message, attention: failed).textSelection(.enabled) }
            }
            // One reading column, like RADIUS ▸ Settings (lines across 1 800 px were hard to read).
            .frame(maxWidth: GroupPolicyLayout.columnWidth, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task { await reload() }
        .alert("Answer DHCP broadcasts on \(confirmDirect?.label ?? "")?",
               isPresented: Binding(get: { confirmDirect != nil }, set: { if !$0 { confirmDirect = nil } }),
               presenting: confirmDirect) { iface in
            Button("Probe and turn on") { enableDirect(iface.bsdName) }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("LabDC first sends a DHCP DISCOVER on this network for 3 seconds. If any DHCP server answers, direct mode stays off — two servers on one segment hand out conflicting addresses.")
        }
    }

    private func reload() async {
        settings = await model.controller.dhcpSettings()
        relays = settings.allowedRelays.joined(separator: ", ")
        profilers = settings.profilers.joined(separator: ", ")
        quarantine = String(settings.declineQuarantineSeconds / 60)
        serverAddress = settings.serverAddress ?? ""
        capRelay = String(settings.maxLeasesPerRelay); capCircuit = String(settings.maxLeasesPerCircuit); churn = String(settings.clientIDChurnLimit)
    }

    private func save() {
        var s = settings
        s.allowedRelays = dhcpList(relays)
        s.profilers = dhcpList(profilers)
        s.serverAddress = serverAddress.trimmingCharacters(in: .whitespaces).isEmpty ? nil : serverAddress.trimmingCharacters(in: .whitespaces)
        // A typo must not save 0 (which switches a cap off): refuse and say which field.
        do {
            s.declineQuarantineSeconds = (try DHCPInput.integer(quarantine, field: "Declined address quarantine (minutes)", in: 1...1440) ?? 10) * 60
            s.maxLeasesPerRelay = try DHCPInput.integer(capRelay, field: "Leases per relay", in: 0...1_000_000) ?? 0
            s.maxLeasesPerCircuit = try DHCPInput.integer(capCircuit, field: "Leases per switch port", in: 0...1_000_000) ?? 0
            s.clientIDChurnLimit = try DHCPInput.integer(churn, field: "Client-ids per MAC per hour", in: 0...1_000_000) ?? 8
        } catch {
            message = "Not saved: \(error)"; failed = true
            return
        }
        Task {
            do { try await model.controller.saveDHCPSettings(s); message = "Saved."; failed = false } catch { message = "\(error)"; failed = true }
            await reload()
        }
    }

    private func enableDirect(_ name: String) {
        probing = name
        Task {
            do { message = try await model.controller.enableDHCPDirect(interface: name); failed = false } catch { message = "\(error)"; failed = true }
            probing = nil
            await reload()
        }
    }

    private func disableDirect(_ name: String) {
        Task {
            do { try await model.controller.disableDHCPDirect(interface: name); message = "Relay-only on \(name)."; failed = false } catch { message = "\(error)"; failed = true }
            await reload()
        }
    }

    private func exportConfig() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "LabDC DHCP.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do { try await model.controller.exportDHCPConfig().write(to: url, options: .atomic); message = "Exported to \(url.lastPathComponent)."; failed = false }
            catch { message = "\(error)"; failed = true }
        }
    }

    private func importConfig() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do { message = try await model.controller.importDHCPConfig(try Data(contentsOf: url)); failed = false } catch { message = "Import failed: \(error)"; failed = true }
            await reload()
        }
    }
}

// MARK: - Test

/// What a relayed DISCOVER/SOLICIT would get — through the real engine, nothing sent or saved.
struct DHCPTestTab: View {
    @Environment(AppModel.self) private var model
    @State private var v6 = false
    @State private var giaddr = "10.20.0.1"
    @State private var link6 = "2001:db8:20::1"
    @State private var mac = "aa:bb:cc:dd:ee:01"
    @State private var vendorClass = ""
    @State private var hostname = ""
    @State private var circuitID = ""
    @State private var linkSelection = ""
    @State private var result: (ok: Bool, text: String)?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            QuietNote("Builds the request a switch would relay and runs it through the server exactly as a live one — nothing is sent and no lease is kept.")
            Toggle("IPv6 (SOLICIT through a relay)", isOn: $v6).toggleStyle(.quiet)
            HStack(alignment: .top, spacing: 16) {
                if v6 {
                    dhcpField("Relay link-address") { QuietTextField("Relay link-address", text: $link6, prompt: "2001:db8:20::1").textFieldStyle(.quietMonospaced) }
                } else {
                    dhcpField("Relay address (giaddr)") { QuietTextField("Relay address (giaddr)", text: $giaddr, prompt: "10.20.0.1").textFieldStyle(.quietMonospaced) }
                    dhcpField("Link selection (82/5, optional)") { QuietTextField("Link selection (82/5, optional)", text: $linkSelection, prompt: "").textFieldStyle(.quietMonospaced) }
                }
                dhcpField("Client MAC") { QuietTextField("Client MAC", text: $mac, prompt: "aa:bb:cc:dd:ee:01").textFieldStyle(.quietMonospaced) }
            }
            HStack(alignment: .top, spacing: 16) {
                dhcpField("Vendor class (60)") { QuietTextField("Vendor class (60)", text: $vendorClass, prompt: "Cisco AP c9120, MSFT 5.0").textFieldStyle(.quiet) }
                dhcpField("Host name") { QuietTextField("Host name", text: $hostname, prompt: "LAPTOP-7").textFieldStyle(.quiet) }
                if !v6 { dhcpField("Circuit-id (82/1)") { QuietTextField("Circuit-id (82/1)", text: $circuitID, prompt: "Gi1/0/3").textFieldStyle(.quiet) } }
            }
            HStack {
                Button(busy ? "Testing…" : "Test") { test() }.buttonStyle(.quietPrimary).disabled(busy)
                Spacer()
            }
            if let result {
                ScrollView {
                    Text(result.text).font(Theme.body.monospaced()).foregroundStyle(result.ok ? Theme.ink : Theme.attention)
                        .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Spacer()
        }
    }

    private func test() {
        func opt(_ s: String) -> String? { let t = s.trimmingCharacters(in: .whitespaces); return t.isEmpty ? nil : t }
        busy = true
        Task {
            if v6 {
                result = await model.controller.dhcpTest(v6: DHCPDryRun.V6(linkAddress: link6, mac: opt(mac), vendorClass: opt(vendorClass), hostname: opt(hostname)))
            } else {
                result = await model.controller.dhcpTest(v4: DHCPDryRun.V4(giaddr: giaddr, mac: mac, vendorClass: opt(vendorClass), hostname: opt(hostname),
                                                                          circuitID: opt(circuitID), linkSelection: opt(linkSelection)))
            }
            busy = false
        }
    }
}
