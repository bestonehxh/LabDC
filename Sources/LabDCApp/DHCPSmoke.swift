import AppKit
import DHCPKit
import LabDCCore
import Store
import SwiftUI

/// `--smoke` part for phase 5: adds a v4 and a v6 scope (VLAN 20, option 43 for Huawei APs), a
/// printer reservation, runs two relayed DORAs against the embedded DHCP server on its
/// ephemeral port (a Windows laptop and an HP printer, so Leases and Devices have rows) and
/// renders every DHCP tab (`ui-6-dhcp-<tab>.png`), the Option 43 editor and a lease's detail.
enum DHCPSmoke {
    @MainActor
    static func run(model: AppModel, out: URL) async -> Bool {
        let c = model.controller
        do {
            var v4 = DHCPScope(name: "Staff VLAN 20", vlan: 20, subnet: "10.20.0.0/24",
                               ranges: [DHCPRange("10.20.0.100", "10.20.0.199")], routers: ["10.20.0.1"])
            v4.option43 = VendorOption43(vendor: .huawei, controllers: ["10.0.0.9", "10.0.0.10"],
                                         vendorClass: VendorOption43.Vendor.huawei.defaultVendorClass)
            try await c.saveDHCPScope(v4)
            try await c.saveDHCPScope(DHCPScope(name: "Staff VLAN 20 v6", family: .v6, vlan: 20, subnet: "2001:db8:20::/64",
                                                ranges: [DHCPRange("2001:db8:20::100", "2001:db8:20::1ff")]))
            let scope = await c.dhcpScopes().first { $0.family == .v4 }
            try await c.saveDHCPReservation(DHCPReservation(scopeID: scope?.id ?? 0, name: "Printer 2F", mac: "3c:2a:f4:00:00:30",
                                                            address: "10.20.0.50", hostname: "printer-2f"))
        } catch {
            print("smoke: DHCP sample failed: \(error)")
            return false
        }
        guard let port = c.status.listeners.first(where: { $0.listener == .dhcp })?.port else {
            print("smoke: DHCP is not running: \(c.status.services.first { $0.service == .dhcp }?.stateLabel ?? "?")")
            return false
        }
        let link = IPv4Address("10.20.0.1")!
        let clients: [([UInt8], String, String)] = [
            ([0x00, 0x00, 0x5e, 0x00, 0x53, 0x07], "LAPTOP-7", "MSFT 5.0"),
            ([0x3c, 0x2a, 0xf4, 0x00, 0x00, 0x30], "NPI00030", "Hewlett-Packard JetDirect"),
        ]
        for (mac, name, vendor) in clients {
            let ack = await Task.detached {
                let relay = try? DHCPTestRelay()
                return try? relay?.dora(serverPort: UInt16(port), mac: mac, link: link, hostname: name, vendorClass: vendor).ack
            }.value
            print("smoke: DHCP \(name): \(ack.flatMap { $0 }.map { "\($0.messageType.map { "\($0)" } ?? "?") \($0.yiaddr)" } ?? "no answer")")
        }
        try? await Task.sleep(for: .milliseconds(500))
        await c.refreshSummary()

        var written = 0
        func shot<V: View>(_ name: String, width: CGFloat = 1100, height: CGFloat = 720, _ view: V) async {
            let url = out.appendingPathComponent("ui-6-dhcp-\(name).png")
            if await Smoke.render(view.environment(model).environment(\.smokeRendering, true), size: CGSize(width: width, height: height), to: url) {
                written += 1
            } else {
                print("smoke: could not render dhcp-\(name)")
            }
        }
        for tab in DHCPView.DHCPTab.allCases {
            await shot(tab.rawValue, DHCPView(tab: tab).background(Theme.background))
        }
        let option = VendorOption43(vendor: .huawei, controllers: ["10.0.0.9", "10.0.0.10"],
                                    vendorClass: VendorOption43.Vendor.huawei.defaultVendorClass)
        await shot("option43", width: 520, height: 520, Option43Editor(option: option) { _ in })
        let leases = await c.dhcpLeases()
        if let printer = leases.first(where: { $0.hostname == "NPI00030" }) ?? leases.first {
            await shot("lease", width: 600, height: 560, DHCPLeaseDetail(lease: printer, scope: await c.dhcpScopes().first { $0.id == printer.scopeID },
                                                                        onDone: {}))
        } else {
            print("smoke: no DHCP lease to show")
        }
        print("smoke: DHCP \(leases.count) lease(s), \(await c.deviceProfiles().count) device(s), \(written) screenshot(s)")
        return written == DHCPView.DHCPTab.allCases.count + 2
    }
}
