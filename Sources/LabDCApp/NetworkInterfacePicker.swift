import LabDCCore
import SwiftUI

/// UI-1c: which of this Mac's networks devices use to reach it — every IPv4 interface as
/// `Wi-Fi 192.168.1.155`, `Tailscale 100.64.0.10`, … plus "Automatic (first address)".
/// The selection is an IPv4 (`advertise`) or nil for automatic. Used by the Setup wizard and
/// Settings ▸ Directory. Quiet: a text menu without its own label (callers write the label
/// beside it); the title stays as the accessibility label.
struct NetworkInterfacePicker: View {
    let title: String
    let interfaces: [NetworkInterfaceChoice]
    @Binding var selection: String?

    var body: some View {
        Picker(title, selection: Binding(get: { selection ?? "" }, set: { selection = $0.isEmpty ? nil : $0 })) {
            Text(Self.automaticLabel(interfaces)).tag("")
            Divider()
            ForEach(interfaces) { choice in
                Text(choice.label).tag(choice.ipv4)
            }
            if let pinned = selection, !interfaces.contains(where: { $0.ipv4 == pinned }) {
                Text("\(pinned) (not on this Mac right now)").tag(pinned)
            }
        }
        .pickerStyle(.menu)
        .labelsHidden()
        .fixedSize()
        .font(Theme.body)
        .accessibilityLabel(title)
    }

    /// `Automatic (first address: Tailscale 100.64.0.10)`.
    static func automaticLabel(_ interfaces: [NetworkInterfaceChoice]) -> String {
        guard let first = interfaces.first else { return "Automatic (first address)" }
        return "Automatic (first address: \(first.label))"
    }
}

/// Settings ▸ Directory: the picker applied live (the listeners that hand out the address restart
/// in place; the change is logged), with the result or error underneath. Quiet: the label and a
/// one-line description on the left, the choice on the right; the settings page draws the hairline.
struct AdvertisedInterfaceSetting: View {
    @Environment(AppModel.self) private var model
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        let status = model.controller.status
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 24) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Devices reach this Mac on")
                        .font(Theme.body)
                        .foregroundStyle(Theme.ink)
                    Text(caption(status))
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .trailing, spacing: 4) {
                    NetworkInterfacePicker(title: "Devices reach this Mac on", interfaces: status.interfaces,
                                           selection: Binding(get: { model.controller.settings.advertise }, set: { apply($0) }))
                    if busy {
                        Text("Applying…")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.faint)
                    }
                }
            }
            if let error {
                QuietNote(error, attention: true)
            }
        }
    }

    /// What the choice means; not the address again, the picker beside it shows that (owner, 2 Oct 2026).
    private func caption(_ status: ServerStatus) -> String {
        model.controller.settings.advertise == nil
            ? "Automatic follows this Mac's network: a VPN or Wi-Fi change is picked up within 30 seconds."
            : "Pinned: DNS, the domain locator and NetBIOS always hand out this address."
    }

    private func apply(_ ipv4: String?) {
        busy = true
        error = nil
        Task {
            do { try await model.controller.setAdvertisedAddress(ipv4) } catch {
                self.error = "Not changed: \(error)"
            }
            busy = false
        }
    }
}
