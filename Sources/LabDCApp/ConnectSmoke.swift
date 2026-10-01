import AppKit
import LabDCCore
import Store
import SwiftUI

/// `--smoke` part for UI-4: seeds the temporary lab with what joined devices leave behind
/// (computer objects as a Windows join / Samba join writes them, sample NETLOGON/KDC/LDAP/SCEP log
/// lines, a challenge, the CA published) and renders the Connect page once per device type into
/// `ui-4-connect-<device>.png`. The seeded lines are samples in the throw-away smoke lab, not real
/// sign-ins; they only show what the checklist looks like once devices are connected.
enum ConnectSmoke {
    @MainActor
    static func run(model: AppModel, out: URL) async -> [String] {
        await seed(model.controller)
        let defaults = UserDefaults(suiteName: "dev.labdc.app.smoke") ?? .standard
        defaults.removePersistentDomain(forName: "dev.labdc.app.smoke")
        let connect = ConnectModel(defaults: defaults)
        await connect.reload(model.controller)
        print("smoke: connect observations: \(connect.observations.computers.count) computer(s), "
              + "\(connect.observations.events.count) event(s), CA \(connect.caDER == nil ? "missing" : "loaded")")
        var written: [String] = []
        for kind in DeviceKind.allCases {
            connect.device = kind
            let height = height(for: kind)
            let view = ConnectView(connect: connect)
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(model)
                .environment(\.smokeRendering, true)
            let url = out.appendingPathComponent("ui-4-connect-\(kind.rawValue).png")
            if await Smoke.render(view, size: CGSize(width: 1100, height: height), to: url) {
                written.append(url.lastPathComponent)
            } else {
                print("smoke: could not render connect \(kind.rawValue)")
            }
        }
        defaults.removePersistentDomain(forName: "dev.labdc.app.smoke")
        return written
    }

    static func height(for kind: DeviceKind) -> CGFloat {
        switch kind {
        case .switchAP: 1700
        case .clearpass, .imaster: 1750
        case .windows, .apple: 1600
        case .linux: 1400
        case .other: 1150
        }
    }

    /// What joins and sign-ins would have left in the store and the log.
    @MainActor
    static func seed(_ controller: ServerController) async {
        guard let store = controller.store, let info = try? await store.domainInfo() else { return }
        let computers = DN(rdns: [RDN("CN", "Computers")] + info.domainDN.rdns)
        let nb = info.netbiosDomain
        let seeds: [(String, [String: [String]])] = [
            ("WIN10-PC1", ["operatingSystem": ["Windows 10 Pro"], "operatingSystemVersion": ["10.0 (19045)"],
                              "dNSHostName": ["best-win10-2.\(info.dnsDomain)"]]),
            ("CLEARPASS-ENTRY", ["operatingSystem": ["Samba"], "operatingSystemVersion": ["4.17.12"],
                                 "dNSHostName": ["clearpass-entry.\(info.dnsDomain)"]]),
            ("OMP", ["operatingSystem": ["Samba"], "dNSHostName": ["omp.\(info.dnsDomain)"]]),
            ("SERVICE1", ["operatingSystem": ["Samba"], "dNSHostName": ["service1.\(info.dnsDomain)"]]),
            ("UBUNTU-VM", ["operatingSystem": ["Ubuntu"], "operatingSystemVersion": ["24.04"],
                           "dNSHostName": ["ubuntu-vm.\(info.dnsDomain)"]]),
        ]
        for (name, attrs) in seeds {
            _ = try? await store.create(parent: computers, rdn: RDN("CN", name), objectClass: "computer", strings: attrs)
        }
        _ = try? await store.insertPKIChallenge(PKIChallengeRow(
            id: "5eed0001", device: "sw1", template: "Device", hash: String(repeating: "ab", count: 32), reusable: false,
            createdAt: Date(), expiresAt: Date().addingTimeInterval(86_400)))
        try? await controller.publishCA()
        let log = controller.serveLog
        let realm = info.realm
        log.event("NETLOGON", "Authenticate3 WIN10-PC1$ (WIN10-PC1) type=workstation flags=0x612fffff from 172.18.1.50/tcp -> OK aes rid=1105")
        log.event("KDC", "AS alice@\(realm) from 172.18.1.50/tcp etype=18 -> OK ticket krbtgt/\(realm) 10h")
        log.event("LDAP", "bind simple CN=Administrator,CN=Users,\(info.domainDN) from 172.18.1.210/ldap -> OK as \(nb)\\Administrator")
        log.event("NETLOGON", "SamLogon Network \(nb)\\alice ws=\\\\CLEARPASS-ENTRY val=6 pc=0x10820 ntlmv1 from CLEARPASS-ENTRY$@172.18.1.210/tcp -> OK as alice")
        log.event("NETLOGON", "SamLogon Network \(nb)\\bob ws=\\\\OMP val=6 pc=0x10820 ntlmv1 from OMP$@172.18.1.220/tcp -> STATUS_WRONG_PASSWORD")
        log.event("KDC", "AS UBUNTU-VM$@\(realm) from 172.18.1.60/tcp etype=18 -> OK ticket krbtgt/\(realm) 10h")
        log.event("KDC", "AS alice@\(realm) from 172.18.1.60/tcp etype=18 -> OK ticket krbtgt/\(realm) 10h")
        log.event("SCEP", "PKCSReq device=sw1 -> FAILURE badRequest (challenge 78e64bd9 is for device sw4, the request names sw1) from 172.18.1.2")
        try? await Task.sleep(for: .milliseconds(300))
    }
}
