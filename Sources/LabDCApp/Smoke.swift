import AppKit
import Darwin
import LabDCCore
import SwiftUI

/// `LabDCApp --smoke [<folder>]`: creates `lab.sheep` in a temporary data folder on ephemeral
/// ports (the real ports may belong to a running DC), makes two real LDAP binds (one with a wrong
/// password) so Recent activity has rows, renders every page into `<folder>/ui-1-*.png`
/// (default `docs/design/screens`), stops the server and exits 0 (1 on failure).
enum Smoke {
    static let adminPassword = "Sheep!Admin1"

    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        Task { @MainActor in
            let ok = await run()
            exit(ok ? 0 : 1)
        }
        app.run()
    }

    @MainActor
    static func run() async -> Bool {
        let launch = LaunchOptions.parse(CommandLine.arguments)
        let out = launch.smokeOutput ?? URL(fileURLWithPath: "docs/design/screens", isDirectory: true)
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("labdc-smoke-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        do { try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true) } catch {
            print("smoke: cannot create \(out.path): \(error)")
            return false
        }
        var options = launch
        options.data = temp
        options.ports = .ephemeral
        let model = AppModel(launch: options)
        var written: [String] = []
        func shot<V: View>(_ name: String, width: CGFloat = 1100, height: CGFloat = 720, _ view: V) async {
            let url = out.appendingPathComponent("ui-1-\(name).png")
            if await render(view.environment(model).environment(\.smokeRendering, true), size: CGSize(width: width, height: height), to: url) {
                written.append(url.lastPathComponent)
            } else {
                print("smoke: could not render \(name)")
            }
        }

        // Setup wizard, before the domain exists.
        let wizard = SetupWizardModel()
        await shot("wizard-1-domain", SetupWizardContent(wizard: wizard, cancel: {}) { _, _, _ in nil })
        wizard.step = .administrator
        wizard.password = adminPassword
        wizard.confirm = adminPassword
        await shot("wizard-2-administrator", SetupWizardContent(wizard: wizard, cancel: {}) { _, _, _ in nil })
        wizard.step = .done
        await shot("wizard-3-done", SetupWizardContent(wizard: wizard, cancel: {}) { _, _, _ in nil })

        // Create the domain and start, as the wizard's last step does.
        guard case .success(let setup) = DomainSetup.derive(DomainSetup.suggested) else { return false }
        if let error = await model.finishSetup(setup, password: adminPassword) {
            print("smoke: setup failed: \(error)")
            return false
        }
        let status = model.controller.status
        print("smoke: \(status.headline); \(status.statusSubtitle); " + status.listeners.map(\.chipLabel).joined(separator: ", "))
        guard status.phase == .running else {
            print("smoke: not running: \(status.problems.joined(separator: "; "))")
            return false
        }

        // Two real LDAP simple binds against the embedded server.
        if let port = status.listeners.first(where: { $0.listener == .ldap })?.port {
            let upn = "Administrator@\(setup.dnsDomain)"
            let good = await LDAPProbe.simpleBind(port: port, name: upn, password: adminPassword)
            let bad = await LDAPProbe.simpleBind(port: port, name: upn, password: "wrong-password")
            print("smoke: LDAP bind good=\(good.map(String.init) ?? "?") bad=\(bad.map(String.init) ?? "?")")
        }
        // UI-1b: one Restart on a service row, so the Overview shows its result line.
        let restart = await model.controller.restartService(.directory)
        print("smoke: restart Directory \(restart.succeeded ? "OK" : "failed: \(restart.error ?? "")")")
        try? await Task.sleep(for: .milliseconds(500))
        await model.controller.refreshSummary()
        print("smoke: recent activity \(model.controller.recentActivity.count) event(s); next steps "
              + NextStep.hints(for: model.controller.summary).map(\.title).joined(separator: ", "))

        // UI-2: the Users page with sample objects (`ui-2-users-*.png`). First, so its sample
        // people/groups exist before UI-5 seeds its accounts (which reuses them).
        let usersShots = await UsersSmoke.run(model: model, out: out)
        written += usersShots
        written += await ConnectSmoke.run(model: model, out: out)  // UI-4: ui-4-connect-<device>.png
        written += await ActivitySmoke.run(model: model, out: out)  // UI-5: ui-5-*.png
        // UI-3: every Certificates section, its sheets and the converter window (ui-3-*.png).
        let ui3 = await CertificatesSmoke.run(model: model, out: out)

        // UI-1: every page last, so the dashboard shows the sample lab (computers, sign-ins,
        // certificates) the other parts created.
        await model.controller.refreshSummary()
        model.authentications.tab = .log  // ui-1-activity keeps showing the Log; UI-5 renders Authentications
        for item in SidebarItem.allCases {
            model.selection = item
            // UI-1c: the dashboard is taller than one screen at 720 pt.
            await shot(item.rawValue, height: item == .overview ? 1000 : 720, MainView())
        }
        await shot("overview-narrow", width: 860, height: 1300, { model.selection = .overview; return MainView() }())
        await shot("settings-general", width: 620, height: 560, SettingsView(tab: .general))
        await shot("settings-directory", width: 620, height: 560, SettingsView(tab: .directory))
        await shot("settings-backup", width: 620, height: 560, SettingsView(tab: .backup))

        await model.controller.stop()
        print("smoke: wrote \(written.count) screenshots to \(out.path): \(written.joined(separator: ", "))")
        return written.count - usersShots.count == 3 + SidebarItem.allCases.count + 1 + 3 + DeviceKind.allCases.count + 2
            && usersShots.count == 5 && ui3
    }

    /// Lays `view` out in an off-screen window and writes a PNG of it (`cacheDisplay`, so
    /// AppKit-backed controls — lists, forms, text fields — render, unlike `ImageRenderer`).
    @MainActor
    static func render<V: View>(_ view: V, size: CGSize, to url: URL) async -> Bool {
        let hosting = NSHostingView(rootView: view.frame(width: size.width, height: size.height))
        hosting.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: CGRect(x: -20_000, y: -20_000, width: size.width, height: size.height),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.appearance = NSApp.effectiveAppearance
        window.backgroundColor = .windowBackgroundColor
        window.contentView = hosting
        window.orderFrontRegardless()
        // Let SwiftUI run its layout passes and `.task`s.
        for _ in 0..<6 {
            hosting.layoutSubtreeIfNeeded()
            try? await Task.sleep(for: .milliseconds(150))
        }
        defer { window.orderOut(nil) }
        guard let rep = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return false }
        hosting.cacheDisplay(in: hosting.bounds, to: rep)
        guard let png = rep.representation(using: .png, properties: [:]) else { return false }
        do { try png.write(to: url, options: .atomic) } catch { return false }
        return true
    }
}

/// A minimal LDAPv3 simple bind over a plain socket (the smoke run's real sign-ins).
enum LDAPProbe {
    /// The bind's resultCode, or nil when the exchange failed.
    static func simpleBind(port: Int, name: String, password: String) async -> Int? {
        await Task.detached { bind(port: port, name: name, password: password) }.value
    }

    private static func bind(port: Int, name: String, password: String) -> Int? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else { return nil }
        // LDAPMessage { messageID 1, bindRequest [APPLICATION 0] { version 3, name, simple [0] password } }
        let bindRequest = tlv(0x60, tlv(0x02, [3]) + tlv(0x04, Array(name.utf8)) + tlv(0x80, Array(password.utf8)))
        let message = tlv(0x30, tlv(0x02, [1]) + bindRequest)
        guard message.withUnsafeBytes({ send(fd, $0.baseAddress, $0.count, 0) }) == message.count else { return nil }
        var buffer = [UInt8](repeating: 0, count: 4096)
        let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        guard n > 0 else { return nil }
        // Unbind (best effort).
        let unbind = tlv(0x30, tlv(0x02, [2]) + [0x42, 0x00])
        _ = unbind.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
        return resultCode(Array(buffer[0..<n]))
    }

    static func tlv(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        if value.count < 0x80 {
            out.append(UInt8(value.count))
        } else if value.count < 0x100 {
            out += [0x81, UInt8(value.count)]
        } else {
            out += [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
        }
        return out + value
    }

    /// The first ENUMERATED (resultCode) of a bindResponse.
    static func resultCode(_ bytes: [UInt8]) -> Int? {
        guard let i = bytes.firstIndex(of: 0x61) else { return nil }
        var j = i + 1
        guard j < bytes.count else { return nil }
        j += bytes[j] & 0x80 != 0 ? Int(bytes[j] & 0x7F) + 1 : 1
        guard j + 2 < bytes.count, bytes[j] == 0x0A else { return nil }
        return Int(bytes[j + 2])
    }
}
