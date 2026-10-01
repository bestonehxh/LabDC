import AppKit
import LabDCCore
import Store
import SwiftUI

/// `--smoke`, UI-2 part: a few sample objects (folders Staff ▸ IT, three people, three groups,
/// two joined computers) created through `DirectoryEditor` / the store like the page would,
/// then `ui-2-users-*.png`.
enum UsersSmoke {
    static let samplePassword = "Sheep!Staff42"

    @MainActor
    static func run(model: AppModel, out: URL) async -> [String] {
        guard let store = model.controller.store else {
            print("smoke: users: no store")
            return []
        }
        let users = model.usersModel
        await users.attach(store: store) { [serveLog = model.controller.serveLog] in serveLog.event("Store", $0) }
        do {
            try await populate(store: store)
        } catch {
            print("smoke: users: sample objects failed: \(error)")
            return []
        }
        await users.reload()
        await model.controller.refreshSummary()
        model.selection = .users
        let s = users.snapshot
        users.expanded = Set(s.folders.keys)
        print("smoke: users: \(s.people.count) people, \(s.groups.count) groups, \(s.computers.count) computers, "
              + "\(s.folders.count) folders")

        var written: [String] = []
        func shot<V: View>(_ name: String, width: CGFloat = 1280, height: CGFloat = 760, _ view: V) async {
            let url = out.appendingPathComponent("ui-2-users-\(name).png")
            if await Smoke.render(view.environment(model).environment(\.smokeRendering, true),
                                  size: CGSize(width: width, height: height), to: url) {
                written.append(url.lastPathComponent)
            } else {
                print("smoke: could not render users \(name)")
            }
        }

        // People, whole domain, Alice selected.
        users.tab = .people
        users.folderID = nil
        users.selection = Set(s.people.filter { $0.username == "alice" }.map(\.id))
        await shot("people", MainView())

        // People in Staff ▸ IT (the folder tree selection).
        if let it = s.folders.values.first(where: { $0.path == "Staff / IT" }) {
            users.folderID = it.id
            users.selection = []
            await shot("folder", MainView())
        }

        // Groups, NetAdmins selected.
        users.folderID = nil
        users.tab = .groups
        users.selection = Set(s.groups.filter { $0.name == "NetAdmins" }.map(\.id))
        await shot("groups", MainView())

        // Computers, PC01 selected.
        users.tab = .computers
        users.selection = Set(s.computers.filter { $0.name == "PC01" }.map(\.id))
        await shot("computers", MainView())

        // The password sheet on its own.
        users.tab = .people
        if let alice = s.people.first(where: { $0.username == "alice" }) {
            users.selection = [alice.id]
            await shot("password", width: 440, height: 240,
                       PasswordSheet(personID: alice.id).frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(Color(nsColor: .windowBackgroundColor)))
        }
        users.selection = []
        return written
    }

    /// Folders, people, groups and computers for the pictures.
    static func populate(store: DirectoryStore) async throws {
        let editor = DirectoryEditor(store: store)
        let info = try await store.requireInfo()
        let d = info.domainDN
        try await editor.createFolder(name: "Staff", in: d)
        let staffDN = d.child(RDN("OU", "Staff"))
        try await editor.createFolder(name: "IT", in: staffDN)
        try await editor.createFolder(name: "Lab Devices", in: d)
        let itDN = staffDN.child(RDN("OU", "IT"))

        let netAdmins = try await editor.createGroup(name: "NetAdmins", scope: .global, description: "Switch and AP administrators")
        let staffGroup = try await editor.createGroup(name: "Staff", scope: .universal, description: "Everyone on the payroll")
        let visitors = try await editor.createGroup(name: "Visitors", scope: .domainLocal, description: "Guest Wi-Fi")

        let alice = try await editor.createUser(.init(displayName: "Alice Anderson", username: "alice", password: samplePassword,
                                                      folder: itDN))
        let bob = try await editor.createUser(.init(displayName: "Bob Brown", username: "bob", password: samplePassword,
                                                    folder: staffDN))
        let guest = try await editor.createUser(.init(displayName: "Guest Account", username: "visitor", password: samplePassword))
        try await editor.setGroups(of: alice, to: [netAdmins, staffGroup])
        try await editor.setGroups(of: bob, to: [staffGroup])
        try await editor.setGroups(of: guest, to: [visitors])
        try await editor.setEnabled(guest, false)
        try await editor.setText(alice, "mail", "alice@\(info.dnsDomain)")
        try await editor.setText(alice, "title", "Network engineer")
        try await editor.setText(alice, "department", "IT")

        // Two joined computers (what NETLOGON writes on a Windows join).
        let computers = d.child(RDN("CN", "Computers"))
        let now = FileTimeDate.value(Date().addingTimeInterval(-3600))
        let pc = try await store.create(parent: computers, rdn: RDN("CN", "PC01"), objectClass: "computer", strings: [
            "dNSHostName": ["pc01.\(info.dnsDomain)"],
            "operatingSystem": ["Windows 11 Pro"], "operatingSystemVersion": ["10.0 (26100)"],
            "servicePrincipalName": ["HOST/PC01", "HOST/pc01.\(info.dnsDomain)", "RestrictedKrbHost/PC01",
                                     "RestrictedKrbHost/pc01.\(info.dnsDomain)"],
            "lastLogonTimestamp": [String(now)],
        ])
        try await store.create(parent: computers, rdn: RDN("CN", "NCE-01"), objectClass: "computer", strings: [
            "dNSHostName": ["nce-01.\(info.dnsDomain)"], "operatingSystem": ["Huawei iMaster NCE-Campus"],
        ])
        try await editor.move([pc], to: d.child(RDN("OU", "Lab Devices")))
        try await editor.addMembers([pc], to: netAdmins)
    }
}
