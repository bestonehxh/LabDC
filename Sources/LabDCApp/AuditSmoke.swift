import AppKit
import CertConvert
import CryptoKit
import DHCPKit
import LabDCCore
import PKIKit
import RADIUSKit
import Store
import SYSVOL
import SwiftUI

/// `--smoke`, the UI audit part (2 Oct 2026): every page and inner tab, and every sheet, each
/// rendered light | dark side by side (`ui-8-*.png`). Pages at the window's minimum size (1260 ×
/// 600) and a typical one (1440 × 900); sheets at their own height with the room the minimum
/// window and a typical window give them (`-min`, `-typ`), so a sheet that does not fit shows its
/// scrolling fields. The sample data has long names, empty values and many rows.
@MainActor
enum AuditSmoke {
    static let minimum = CGSize(width: 1260, height: 600)
    static let typical = CGSize(width: 1440, height: 900)

    static func run(model: AppModel, out: URL) async -> Int {
        await seed(model)
        var written = 0

        /// A page as the window shows it: the sidebar and the page.
        func window(_ page: some View) -> some View {
            HStack(spacing: 0) {
                Sidebar()
                    .frame(width: 220)
                    .frame(maxHeight: .infinity)
                    .background(Theme.sidebar)
                page
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Theme.background)
            }
        }
        func page(_ name: String, sizes: [CGSize] = [minimum, typical], _ view: @escaping () -> some View) async {
            // The sidebar marks the page being shown.
            let prefixes: [(String, SidebarItem)] = [("overview", .overview), ("services", .services), ("users", .users),
                                                     ("group-policy", .groupPolicy), ("certificates", .certificates),
                                                     ("radius", .radius), ("dhcp", .dhcp), ("activity", .activity),
                                                     ("connect", .connect)]
            model.selection = prefixes.first { name.hasPrefix($0.0) }?.1 ?? .overview
            for size in sizes {
                let tag = size == minimum ? "min" : "typ"
                let url = out.appendingPathComponent("ui-8-page-\(name)-\(tag).png")
                if await Smoke.renderPair({ window(view()) }, size: size, model: model, to: url, stacked: true) { written += 1 }
            }
        }
        /// A sheet at its own size; `-min` with the room a 600 pt window leaves, `-typ` 900 pt.
        func sheet(_ name: String, _ view: @escaping () -> some View) async {
            for (tag, limit) in [("min", CGFloat(600 - 190)), ("typ", CGFloat(900 - 190))] {
                let url = out.appendingPathComponent("ui-8-sheet-\(name)-\(tag).png")
                if await Smoke.renderPair({ view().environment(\.sheetContentLimit, limit) }, size: nil, model: model, to: url) {
                    written += 1
                }
            }
        }

        let c = model.controller
        // Pages and their tabs.
        model.selection = .overview
        await page("overview") { OverviewView() }
        await page("services") { ServicesView() }
        let users = model.usersModel
        let snapshot = users.snapshot
        let alice = snapshot.people.first { $0.username == "alice" }
        for tab in UsersModel.Tab.allCases {
            users.tab = tab
            users.folderID = nil
            switch tab {
            case .people: users.selection = Set([alice?.id].compactMap { $0 })
            case .groups: users.selection = Set(snapshot.groups.filter { $0.name == "NetAdmins" }.map(\.id))
            case .computers: users.selection = Set(snapshot.computers.filter { $0.name == "PC01" }.map(\.id))
            }
            await page("users-\(tab.rawValue)") { UsersView().environment(\.smokeExpandInspector, true) }
        }
        users.tab = .people
        users.selection = []
        await page("users-nothing-selected", sizes: [minimum]) { UsersView() }
        for tab in GroupPolicyTab.allCases {
            model.groupPolicyTab = tab
            await page("group-policy-\(tab.rawValue)") { GroupPolicyView() }
        }
        model.groupPolicyTab = .overview
        model.selection = .certificates
        for section in CertificatesSection.allCases {
            model.certificates.section = section
            await page("certificates-\(section.slug)") { CertificatesView() }
        }
        model.certificates.section = .ca
        for tab in RadiusView.RadiusTab.allCases {
            await page("radius-\(tab.rawValue)") { RadiusView(tab: tab) }
        }
        for tab in DHCPView.DHCPTab.allCases {
            await page("dhcp-\(tab.rawValue)") { DHCPView(tab: tab) }
        }
        for tab in ActivityTab.allCases {
            model.authentications.tab = tab
            await page("activity-\(tab.rawValue)") { ActivityView() }
        }
        model.authentications.tab = .log
        let connect = ConnectModel(defaults: UserDefaults(suiteName: "dev.labdc.app.smoke") ?? .standard)
        await connect.reload(c)
        for kind in DeviceKind.allCases {
            connect.device = kind
            await page("connect-\(kind.rawValue)", sizes: [minimum]) { ConnectView(connect: connect) }
        }
        for tab in SettingsTab.allCases {
            let url = out.appendingPathComponent("ui-8-settings-\(tab.title.lowercased()).png")
            if await Smoke.renderPair({ SettingsView(tab: tab) }, size: CGSize(width: 620, height: 560), model: model, to: url) {
                written += 1
            }
        }
        // The setup wizard (as before the domain exists) at the minimum window size.
        let wizard = SetupWizardModel()
        for step in [SetupWizardModel.Step.domain, .administrator, .done] {
            wizard.step = step
            if step == .administrator { wizard.password = "Sheep!Admin1"; wizard.confirm = "Sheep!Admin" }
            let url = out.appendingPathComponent("ui-8-wizard-\(step.rawValue)-\(step).png")
            if await Smoke.renderPair({ SetupWizardContent(wizard: wizard, cancel: {}) { _, _, _ in nil } },
                                      size: minimum, model: model, to: url) { written += 1 }
        }
        // The standalone converter window (before a domain exists), at its minimum size.
        let converter = ConverterWindowController.shared.model
        if let url = out.appendingPathComponent("ui-8-converter-window.png") as URL?,
           await Smoke.renderPair({ ConverterWindowView(model: converter) }, size: CGSize(width: 520, height: 600), model: model, to: url) {
            written += 1
        }

        // Directory sheets and pickers.
        let staffIT = snapshot.folders.values.first { $0.path == "Staff / IT" }
        await sheet("users-new-person") { UsersSheetView(which: .newUser(folder: staffIT?.id)) }
        await sheet("users-new-group") { UsersSheetView(which: .newGroup(folder: staffIT?.id)) }
        await sheet("users-new-folder") { UsersSheetView(which: .newFolder(parent: staffIT?.id ?? snapshot.root.id)) }
        if let it = staffIT { await sheet("users-rename-folder") { UsersSheetView(which: .renameFolder(it.id)) } }
        if let alice { await sheet("users-password") { UsersSheetView(which: .password(alice.id)) } }
        if let alice {
            let current = Set(alice.groupIDs)
            await sheet("users-groups-popover") {
                PickerList(title: "Groups of \(alice.displayName)", query: .constant(""),
                           items: snapshot.groups.sorted { $0.name < $1.name }.map {
                               PickerItem(id: $0.id, name: $0.name, detail: $0.scope.title,
                                          mark: current.contains($0.id) ? "Member" : "", accessibility: $0.name)
                           }) { _ in }
            }
            await sheet("users-move-popover") {
                PickerList(title: "Move to", items: snapshot.folderList.filter { $0.folder.kind != .domain }.map {
                    PickerItem(id: $0.folder.id, name: $0.folder.path, mark: $0.folder.id == alice.parentID ? "Here" : "",
                               accessibility: $0.folder.path)
                }, empty: "No folders.") { _ in }
            }
        }

        // Group Policy sheets.
        let gp = await c.groupPolicySnapshot()
        let certificates = gp?.choosableCertificates ?? []
        let names = gp?.draft.wireless.map(\.name) ?? []
        await sheet("gp-wifi-new") { WiFiProfileSheet(profile: nil, existing: names, certificates: certificates) { _, _ in } }
        if let staff = gp?.draft.wireless.first {
            await sheet("gp-wifi-edit") { WiFiProfileSheet(profile: staff, existing: names, published: true, certificates: certificates) { _, _ in } }
        }
        if let other = gp?.draft.wireless.first(where: { $0.server != nil }) {
            await sheet("gp-wifi-edit-clearpass") { WiFiProfileSheet(profile: other, existing: names, certificates: certificates) { _, _ in } }
        }
        await sheet("gp-wired-new") { WiredProfileSheet(profile: nil, certificates: certificates) { _, _ in } }
        if let wired = gp?.draft.wired {
            await sheet("gp-wired-edit") { WiredProfileSheet(profile: wired, certificates: certificates) { _, _ in } }
        }
        await sheet("gp-policy-name") {
            PolicyNameSheet(title: "Wireless policy", name: Dot1XPolicy.defaultName, description: Dot1XProfileSet.defaultDescription) { _, _ in }
        }
        if let file = try? chainFile(), let picked = try? Dot1XTrustCertificate.candidates(file, fileName: "cppm-chain.pem") {
            await sheet("gp-certificate-pick") { CertificatePickSheet(fileName: "cppm-chain.pem", certificates: picked.certificates) { _ in } }
        }

        // Certificates sheets.
        let certs = model.certificates
        if let editor = certs.editor {
            if let computer = editor.templates.first(where: { $0.name == "Computer" }) {
                await sheet("certs-template-edit") { TemplateEditorSheet(draft: TemplateDraft(computer), groups: editor.groups) { _ in true } }
                var copy = TemplateDraft(computer)
                copy.isNew = true
                copy.name = ""
                await sheet("certs-template-new") { TemplateEditorSheet(draft: copy, groups: editor.groups) { _ in true } }
            }
            let form = CreateCAForm(existing: editor.authorities.map(\.name))
            await sheet("certs-new-ca") { CreateCASheet(form: form) { _ in true } }
            let taken = CreateCAForm(existing: editor.authorities.map(\.name))
            taken.name = editor.authorities.first?.name ?? "Lab"
            await sheet("certs-new-ca-taken-name") { CreateCASheet(form: taken) { _ in true } }
            await sheet("certs-change-key") { ChangeKeySheet(form: ChangeKeyForm(current: .p384)) { _ in true } }
            if let issued = editor.issued.first(where: { !$0.revoked }) {
                await sheet("certs-revoke") { RevokeSheet(row: IssuedRow(issued, now: Date())) { _ in true } }
            }
            certs.challenges.dismiss()
            await sheet("certs-challenge-new") { NewChallengeSheet(model: certs, editor: editor, challenges: certs.challenges) }
            certs.challenges.device = "sw-core-01.building-a.lab.sheep"
            try? await certs.challenges.create(using: editor)
            await sheet("certs-challenge-created") { NewChallengeSheet(model: certs, editor: editor, challenges: certs.challenges) }
            certs.challenges.dismiss()
        }
        if let file = try? chainFile(), let picked = try? Dot1XTrustCertificate.candidates(file, fileName: "clearpass-roots.p7b") {
            await sheet("certs-trusted-root-pick") { CertificatePickSheet(fileName: "clearpass-roots.p7b", certificates: picked.certificates) { _ in } }
        }
        let rows = certs.converter.certificateRows
        if !rows.isEmpty { await sheet("certs-inspect") { InspectSheet(rows: rows) } }

        // RADIUS sheets.
        let clients = await c.radiusNAS()
        await sheet("radius-client-new") { RadiusClientSheet(onDone: {}) }
        if let long = clients.max(by: { $0.name.count < $1.name.count }) {
            await sheet("radius-client-edit") { RadiusClientSheet(client: long, onDone: {}) }
        }
        let policies = await c.radiusPolicies()
        await sheet("radius-policy-new") { RadiusPolicySheet(position: policies.count, onDone: {}) }
        if let rich = policies.max(by: { $0.rows.count < $1.rows.count }) {
            await sheet("radius-policy-edit") { RadiusPolicySheet(policy: rich, position: rich.position, onDone: {}) }
        }
        await sheet("radius-device-new") { RadiusDeviceSheet(onDone: {}) }
        if let device = await c.registeredDevices().first {
            await sheet("radius-device-edit") { RadiusDeviceSheet(device: device, onDone: {}) }
        }

        // DHCP sheets.
        let scopes = await c.dhcpScopes()
        await sheet("dhcp-scope-new") { DHCPScopeSheet(onDone: { _ in }) }
        if let v4 = scopes.first(where: { $0.family == .v4 }) { await sheet("dhcp-scope-edit-v4") { DHCPScopeSheet(scope: v4, onDone: { _ in }) } }
        if let v6 = scopes.first(where: { $0.family == .v6 }) { await sheet("dhcp-scope-edit-v6") { DHCPScopeSheet(scope: v6, onDone: { _ in }) } }
        await sheet("dhcp-reservation-new") { DHCPReservationSheet(scopes: scopes, onDone: { _ in }) }
        if let r = await c.dhcpReservations().first {
            await sheet("dhcp-reservation-edit") { DHCPReservationSheet(reservation: r, scopes: scopes, onDone: { _ in }) }
        }
        await sheet("dhcp-option43-new") { Option43Editor(option: nil) { _ in } }
        await sheet("dhcp-option43-edit") {
            Option43Editor(option: VendorOption43(vendor: .huawei, controllers: ["10.0.0.9", "10.0.0.10"],
                                                  vendorClass: VendorOption43.Vendor.huawei.defaultVendorClass)) { _ in }
        }
        let leases = await c.dhcpLeases()
        if let lease = leases.first(where: { $0.hostname == "NPI00030" }) ?? leases.first {
            await sheet("dhcp-lease") { DHCPLeaseDetail(lease: lease, scope: scopes.first { $0.id == lease.scopeID }, onDone: {}) }
        }
        if let device = await c.deviceProfiles().first { await sheet("dhcp-device") { DHCPDeviceSheet(profile: device) { _, _ in } } }

        // Activity and Settings sheets.
        await sheet("activity-test-sign-in") {
            TestLoginContent(test: model.authentications.testLogin, close: {}).frame(width: 580)
        }
        model.authentications.testLogin.showAdvanced = true
        model.authentications.testLogin.preset = .ntlm
        await sheet("activity-test-sign-in-advanced") {
            TestLoginContent(test: model.authentications.testLogin, close: {}).frame(width: 580)
        }
        model.authentications.testLogin.showAdvanced = false
        await sheet("settings-new-profile") { NewProfileSheet(existing: ["Lab"], settling: false) { _ in } }
        await sheet("settings-rename-profile") {
            RenameProfileSheet(name: "Branch lab", isActive: true, existing: ["Branch lab", "Lab"], settling: false,
                               renameTo: .constant("Lab"), failure: .constant(nil), busy: .constant(false)) {}
        }
        print("smoke: ui-8: \(written) audit picture(s)")
        return written
    }

    /// Long names, empty values and many rows for the audit pictures.
    static func seed(_ model: AppModel) async {
        let c = model.controller
        do {
            try await c.addRadiusNAS(.init(name: "Core switch stack — Building A, floor 3 (Aruba CX 6300M, 48 ports)",
                                           ip: "10.10.0.0/24", secret: UsersModel.suggestPassword(length: 24),
                                           coaPort: 3799, coaVendor: .arubaBounce))
            try await c.addRadiusNAS(.init(name: "AP controller", ip: "10.10.1.5", secret: UsersModel.suggestPassword(length: 24),
                                           requireMessageAuthenticator: false, coaPort: 1700, coaVendor: .cisco))
            for i in 1...14 {
                try await c.addRadiusNAS(.init(name: "Access switch \(i)", ip: "10.10.2.\(i)", secret: UsersModel.suggestPassword(length: 24)))
            }
            try await c.saveRadiusPolicy(RADIUSPolicy(position: 0, name: "Staff laptops on the corporate Wi-Fi (EAP-TLS, VLAN by department)",
                rows: [.condition(.init(field: .account, op: .inList, value: "alice, bob, carol, dave, eve, frank, grace")),
                       .anyOf([.init(field: .calledStationId, op: .ends, value: ":Staff"),
                               .init(field: .calledStationId, op: .ends, value: ":Staff-5G")]),
                       .condition(.init(field: .nasIP, op: .starts, value: "10.10."))],
                action: .acceptVLAN,
                attributes: [.init(standard: .sessionTimeout, value: "28800"), .init(standard: .replyMessage, value: "")],
                vlan: "20"))
            try await c.saveRadiusPolicy(RADIUSPolicy(position: 1, name: "Printers by MAB", action: .accept, allowsMAB: true))
            try await c.saveRadiusPolicy(RADIUSPolicy(position: 2, name: "Everything else", enabled: false, action: .reject))
            try await c.saveRegisteredDevice(.init(mac: "3c:2a:f4:00:00:30", description: "HP LaserJet M507 — 2nd floor print room, next to the kitchen",
                                                   group: "Printers"))
            try await c.saveRegisteredDevice(.init(mac: "00:1b:21:aa:bb:cc"))
        } catch {
            print("smoke: ui-8 sample data: \(error)")
        }
    }

    /// A PEM file with a server certificate and its root (two certificates for the pick sheet).
    static func chainFile() throws -> [UInt8] {
        let server = try CertificateItem(der: try GroupPolicySmoke.clearPassCertificate()).pem
        let root = try CertificatesSmoke.externalRoot(cn: "ClearPass Policy Manager Root Certification Authority (Building A)")
        return Array((server + "\n" + root).utf8)
    }
}

extension Smoke {
    /// Renders `view` light and dark and writes them side by side (light left). `size` nil: the
    /// view's own fitting size (a sheet).
    @MainActor
    static func renderPair<V: View>(_ view: () -> V, size: CGSize?, model: AppModel, to url: URL, stacked: Bool = false) async -> Bool {
        var reps: [NSBitmapImageRep] = []
        for name in [NSAppearance.Name.aqua, .darkAqua] {
            let root = view().environment(model).environment(\.smokeRendering, true)
            guard let rep = await bitmap(root, size: size, appearance: NSAppearance(named: name)) else { return false }
            reps.append(rep)
        }
        // Wide pages stack light above dark (so each stays readable); sheets sit side by side.
        let gap = 24
        let width = stacked ? (reps.map(\.pixelsWide).max() ?? 0) : reps.reduce(0) { $0 + $1.pixelsWide } + gap * (reps.count - 1)
        let height = stacked ? reps.reduce(0) { $0 + $1.pixelsHigh } + gap * (reps.count - 1) : (reps.map(\.pixelsHigh).max() ?? 0)
        guard let canvas = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height, bitsPerSample: 8,
                                            samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                            bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: canvas) else { return false }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        NSColor(white: 0.5, alpha: 1).setFill()
        NSRect(x: 0, y: 0, width: width, height: height).fill()
        var x = 0, top = 0
        for rep in reps {
            rep.size = NSSize(width: rep.pixelsWide, height: rep.pixelsHigh)
            rep.draw(in: NSRect(x: x, y: height - top - rep.pixelsHigh, width: rep.pixelsWide, height: rep.pixelsHigh))
            if stacked { top += rep.pixelsHigh + gap } else { x += rep.pixelsWide + gap }
        }
        NSGraphicsContext.restoreGraphicsState()
        guard let png = canvas.representation(using: .png, properties: [:]) else { return false }
        do { try png.write(to: url, options: .atomic) } catch { return false }
        return true
    }

    /// One off-screen picture; with `size` nil the window takes the view's fitting size.
    @MainActor
    static func bitmap<V: View>(_ view: V, size: CGSize?, appearance: NSAppearance?) async -> NSBitmapImageRep? {
        // A page keeps the window's size (its own content scrolls); a sheet takes its fitting size.
        let root = size.map { AnyView(view.frame(width: $0.width, height: $0.height)) } ?? AnyView(view)
        let hosting = NSHostingView(rootView: root)
        let start = size ?? CGSize(width: 600, height: 400)
        hosting.frame = CGRect(origin: .zero, size: start)
        let window = NSWindow(contentRect: CGRect(x: -20_000, y: -20_000, width: start.width, height: start.height),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.appearance = appearance
        window.backgroundColor = .windowBackgroundColor
        window.contentView = hosting
        window.orderFrontRegardless()
        defer { window.orderOut(nil) }
        for _ in 0..<6 {
            hosting.layoutSubtreeIfNeeded()
            if size == nil {
                let fit = hosting.fittingSize
                if fit.width > 1, fit.height > 1, fit != hosting.frame.size {
                    window.setContentSize(fit)
                    hosting.frame = CGRect(origin: .zero, size: fit)
                }
            }
            try? await Task.sleep(for: .milliseconds(150))
        }
        guard let rep = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return nil }
        hosting.cacheDisplay(in: hosting.bounds, to: rep)
        return rep
    }
}
