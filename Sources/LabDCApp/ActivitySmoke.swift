import AppKit
import LabDCCore
import Store
import SwiftUI

/// `--smoke` part for UI-5: adds a few accounts to the throw-away smoke lab (alice and bob in
/// Staff, a disabled carol, a computer KIOSK-1), runs real Test logins against the embedded server
/// (Kerberos, NTLM as a NAC, MS-CHAPv2 style, LDAP bind; right and wrong passwords, a disabled
/// account, a computer without the trust-account bits) and renders
/// `ui-5-activity-authentications.png` (the feed, with UI-4's sample lines too) and
/// `ui-5-test-login.png` (the sheet with a passed Kerberos result, details open).
enum ActivitySmoke {
    static let password = "Sheep!Staff1"

    @MainActor
    static func run(model: AppModel, out: URL) async -> [String] {
        let controller = model.controller
        guard await seedAccounts(controller) else {
            print("smoke: could not create the UI-5 accounts")
            return []
        }
        let test = model.authentications.testLogin
        func attempt(_ preset: LoginTestRequest.Preset, _ user: String, _ password: String,
                     configure: (TestLoginModel) -> Void = { _ in }) async {
            test.preset = preset
            test.user = user
            test.password = password
            test.msCHAPv2Style = false
            test.allowComputerAccounts = true
            configure(test)
            test.run(controller)
            await test.wait()
            print("smoke: test login \(preset.rawValue) \(user): \(test.result?.sentence ?? "no result")")
        }
        await attempt(.ldap, "alice", Self.password)
        await attempt(.ntlm, "bob", "wrong-password")
        await attempt(.ntlm, "alice", Self.password) { $0.msCHAPv2Style = true }
        await attempt(.kerberos, "carol", Self.password)
        await attempt(.ntlm, "KIOSK-1$", Self.password) { $0.allowComputerAccounts = false }
        await attempt(.kerberos, "bob", "wrong-password")
        await attempt(.kerberos, "alice", Self.password)
        test.showAdvanced = false
        test.showDetails = true
        try? await Task.sleep(for: .milliseconds(300))

        var written: [String] = []
        model.selection = .activity
        model.authentications.tab = .authentications
        model.authentications.filter = AuthenticationsFilter()
        print("smoke: authentications \(model.authentications.feed.events.count) row(s): \(model.authentications.summary)")
        let page = MainView().environment(model).environment(\.smokeRendering, true)
        let pageURL = out.appendingPathComponent("ui-5-activity-authentications.png")
        if await Smoke.render(page, size: CGSize(width: 1280, height: 720), to: pageURL) { written.append(pageURL.lastPathComponent) }

        let sheet = TestLoginContent(test: test, close: {})
            .frame(width: 580)
            .background(Color(nsColor: .windowBackgroundColor))
            .environment(model)
            .environment(\.smokeRendering, true)
        let sheetURL = out.appendingPathComponent("ui-5-test-login.png")
        if await Smoke.render(sheet, size: CGSize(width: 580, height: 680), to: sheetURL) { written.append(sheetURL.lastPathComponent) }
        return written
    }

    /// alice, bob (Staff), carol (disabled), KIOSK-1$ — all with `password`.
    @MainActor
    static func seedAccounts(_ controller: ServerController) async -> Bool {
        guard let store = controller.store, let info = try? await store.domainInfo() else { return false }
        do {
            let users = DN(rdns: [RDN("CN", "Users")] + info.domainDN.rdns)
            let computers = DN(rdns: [RDN("CN", "Computers")] + info.domainDN.rdns)
            var members: [String] = []
            for (name, uac) in [("alice", "66048"), ("bob", "66048"), ("carol", "66050")] {
                // The Users smoke (UI-2) may already have made alice and bob: reuse them.
                if let existing = try await store.read(sam: name) {
                    try await store.setPassword(id: existing.id, password: password, enforcePolicy: false)
                    if name != "carol" { members.append(existing.dn.description) }
                    continue
                }
                let id = try await store.create(parent: users, rdn: RDN("CN", name), objectClass: "user",
                                                strings: ["sAMAccountName": [name], "userAccountControl": [uac],
                                                          "displayName": [name.capitalized]])
                try await store.setPassword(id: id, password: password, enforcePolicy: false)
                if name != "carol" { members.append(DN(rdns: [RDN("CN", name)] + users.rdns).description) }
            }
            if let staff = try await store.read(sam: "Staff") {
                try await store.update(id: staff.id, ops: [.replace("member", strings: members)], permissive: true)
            } else {
                try await store.create(parent: users, rdn: RDN("CN", "Staff"), objectClass: "group", strings: ["member": members])
            }
            let kiosk = try await store.create(parent: computers, rdn: RDN("CN", "KIOSK-1"), objectClass: "computer",
                                               strings: ["sAMAccountName": ["KIOSK-1$"], "userAccountControl": ["4096"]])
            try await store.setPassword(id: kiosk, password: password, enforcePolicy: false)
            return true
        } catch {
            print("smoke: seed accounts: \(error)")
            return false
        }
    }
}
