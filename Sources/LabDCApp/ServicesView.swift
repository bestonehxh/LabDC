import LabDCCore
import SwiftUI

/// UI-1c (owner, 27 Sep 2026), Quiet look: the per-service rows with Restart on their own page.
/// One row per service (DNS · Kerberos · Directory · File & RPC · Time · Web/PKI): the name and
/// what it does, the ports in small text, the state as words and a Restart link. "Restart all
/// services" (⌘R) sits beside the title. A maintenance page — no on/off switches, no icons.
struct ServicesView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    /// Owner, 27 Sep 2026: one line per service; its details only after a click.
    @State private var expanded: Set<ServeService> = []

    var body: some View {
        let status = model.controller.status
        QuietPage(title: "Services", subtitle: Self.subtitle(status)) {
            Button("Restart all services") {
                Task { await model.controller.restartAllServices() }
            }
            .buttonStyle(.quietLink)
            .keyboardShortcut("r", modifiers: .command)
            .help("Restart all services (⌘R)")
            .disabled(!model.controller.isSetUp || model.controller.status.isBusy)
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                ServicesHeadline()
                    .padding(.bottom, 24)
                ForEach(Array(status.services.enumerated()), id: \.element.id) { index, row in
                    QuietRow(first: index == 0) {
                        ServiceRow(row: row, expanded: expanded.contains(row.service)) {
                            withAnimation(.easeOut(duration: 0.15)) {
                                if expanded.contains(row.service) { expanded.remove(row.service) } else { expanded.insert(row.service) }
                            }
                        }
                    }
                }
                Rectangle().fill(Theme.line).frame(height: 1)

                VStack(alignment: .leading, spacing: 8) {
                    ForEach(status.generalProblems, id: \.self) { problem in
                        QuietNote(problem, attention: true)
                            .textSelection(.enabled)
                    }
                    if status.services.contains(where: { $0.problemMessage?.contains("in use") ?? false }) {
                        Button("Change ports in Settings…") { openSettings() }
                            .buttonStyle(.quietLink)
                    }
                }
                .padding(.top, 20)
            }
        }
    }

    /// "Devices reach this Mac at 192.168.1.155 on Wi-Fi (this Mac has 3 addresses). You can
    /// change this in Settings." The one place on the page that says the address (owner, 2 Oct
    /// 2026: no footer note repeating it).
    static func subtitle(_ status: ServerStatus) -> String {
        guard let ip = status.advertisedIPv4 else {
            return "Devices are told this Mac's address once the services run. You can choose it in Settings."
        }
        let on = status.advertisedInterfaceName.map { " on \($0)" } ?? ""
        let several = status.addresses.count > 1 ? " (this Mac has \(status.addresses.count) addresses)" : ""
        return "Devices reach this Mac at \(ip)\(on)\(several). You can change this in Settings."
    }
}

/// "Everything is running" as one quiet line (the rows below name the services); with a
/// problem, what is not running after it, in the problem color.
struct ServicesHeadline: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let status = model.controller.status
        let trouble = status.phase == .problem || !status.problems.isEmpty
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(status.statusTitle)
                .font(Theme.emphasis)
                .foregroundStyle(trouble ? Theme.attention : Theme.ink)
            if trouble || status.phase != .running {
                Text(status.statusSubtitle)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

/// `DNS                                   Running since 14:02     Restart`; a click on the row
/// opens what the service does, its ports, its note and (DNS) where other names go.
struct ServiceRow: View {
    @Environment(AppModel.self) private var model
    let row: ServiceStatus
    let expanded: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text(row.service.title)
                    .font(Theme.body.weight(expanded ? .semibold : .regular))
                    .foregroundStyle(Theme.ink)
                    .frame(maxWidth: .infinity, alignment: .leading)
                stateText
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360, alignment: .trailing)
                    .multilineTextAlignment(.trailing)
                // Stop one service (owner, 1 Oct 2026); a stopped row offers Start instead.
                if row.canStop {
                    Button("Stop") { confirmStop = true }
                        .buttonStyle(.quietLink)
                        .disabled(model.controller.status.isBusy)
                        .help("Stop \(row.service.title); the other services keep running")
                        .accessibilityLabel("Stop \(row.service.title)")
                }
                Button(restartTitle) {
                    Task { await model.controller.restartService(row.service) }
                }
                .buttonStyle(.quietLink)
                .disabled(!row.canRestart || !model.controller.isRunning && model.controller.status.phase != .problem)
                .help(helpText)
                .accessibilityLabel("\(restartTitle) \(row.service.title)")
                .accessibilityHint(helpText)
            }
            .contentShape(Rectangle())
            .onTapGesture(perform: toggle)
            .accessibilityAddTraits(.isButton)
            .accessibilityHint(expanded ? "Hides the details" : "Shows what it does and its ports")

            if expanded {
                VStack(alignment: .leading, spacing: 5) {
                    Text(row.service.summary)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(row.state == .off ? offText : row.portsText)
                        .font(Theme.caption.monospaced())
                        .foregroundStyle(Theme.muted)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    if let detail = row.detail {
                        Text(detail)
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .textSelection(.enabled)
                    }
                    if row.service == .dhcp {
                        Button(row.state == .off ? "Add a scope on the DHCP page" : "Open the DHCP page") { model.selection = .dhcp }
                            .buttonStyle(.quietLink)
                            .padding(.top, 2)
                    }
                    if let note = row.note {
                        QuietNote(note)
                    }
                    if row.service == .dns {
                        DNSForwardingLine()
                            .padding(.top, 4)
                    }
                }
                .transition(.opacity)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(row.service.title), \(row.stateLabel)")
        .alert("Stop \(row.service.title)?", isPresented: $confirmStop) {
            Button("Stop", role: .destructive) {
                Task { await model.controller.stopService(row.service) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(stopMessage)
        }
    }

    @State private var confirmStop = false

    private var restartTitle: String {
        switch row.state {
        case .restarting: "Restarting…"
        case .stopped where model.controller.isRunning: "Start"
        default: "Restart"
        }
    }

    /// Why a row is off, where to turn it on.
    private var offText: String {
        row.service == .dhcp
            ? "Off until a scope exists: DHCP starts with the first scope on the DHCP page."
            : "Off in Settings ▸ System (Let devices join the domain)"
    }

    /// What stopping this service means for devices, in one or two sentences.
    private var stopMessage: String {
        if row.service == .dhcp {
            return "\(row.service.summary) While it is stopped, relayed requests get no answer from LabDC: clients keep the "
                + "addresses they hold until their lease runs out. New scopes do not start it; Start on this row (or reopening LabDC) does."
        }
        var s = "\(row.service.summary) Devices that need it fail until you start it again (Start on this row, Restart all, or reopening LabDC)."
        if !row.stopAlsoAffects.isEmpty {
            s += " Also stops " + row.stopAlsoAffects.map(\.title).joined(separator: ", ") + " (same server)."
        }
        return s
    }

    /// The state as words: "Running since 14:02", "Restarted at 14:05", the problem in attention.
    @ViewBuilder private var stateText: some View {
        if let message = row.problemMessage {
            StateText(text: message, attention: true)
        } else if row.state == .restarting {
            StateText(text: "Restarting…")
        } else if let last = row.lastRestart, !last.succeeded {
            StateText(text: "Restart failed: \(last.error ?? "")", attention: true)
        } else if row.state == .running {
            StateText(text: runningText)
        } else {
            StateText(text: row.stateLabel, dimmed: row.state == .off || row.state == .stopped)
        }
    }

    private var runningText: String {
        if let last = row.lastRestart, last.succeeded {
            // The same short time as "Running since" (owner, 2 Oct 2026).
            return "Restarted at \(last.date.formatted(date: .omitted, time: .shortened))"
        }
        if let started = model.controller.status.startedAt {
            return "Running since \(started.formatted(date: .omitted, time: .shortened))"
        }
        return "Running"
    }

    private var helpText: String {
        var s = "Stops and starts \(row.service.title) on the same ports; the other services keep running."
        if !row.service.restartAlsoAffects.isEmpty {
            s += " Also restarts " + row.service.restartAlsoAffects.map(\.title).joined(separator: ", ") + " (same server)."
        }
        return s
    }
}

/// A service's state as one word, for headers (Settings ▸ Directory ports).
struct ServiceStateBadge: View {
    let row: ServiceStatus

    var body: some View {
        StateText(text: row.stateLabel,
                  attention: row.problemMessage != nil,
                  dimmed: row.state == .off || row.state == .stopped)
    }
}

/// "Other names go to 192.168.1.1 (this Mac's DNS). Test" and the test's answer as a sentence.
struct DNSForwardingLine: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    @State private var info: DNSForwardingInfo?
    @State private var testing = false
    @State private var result: DNSForwardingTestResult?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 16) {
                Group {
                    if let info {
                        let servers = Text(info.servers).foregroundStyle(Theme.ink)
                        let origin = Text(" (\(info.origin))").foregroundStyle(info.isFallback ? Theme.attention : Theme.muted)
                        Text("Other names go to \(servers)\(origin)").foregroundStyle(Theme.muted)
                    } else {
                        Text("Other names are forwarded while DNS runs.").foregroundStyle(Theme.muted)
                    }
                }
                .font(Theme.detail)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 12)
                Button(testing ? "Testing…" : "Test") { test() }
                    .buttonStyle(.quietLink)
                    .disabled(info == nil || testing)
                    .help("Looks up apple.com through LabDC's DNS, as a PC that uses this Mac for DNS would")
                Button("Change…") { openSettings() }
                    .buttonStyle(.quietLink)
            }
            if let info, !info.skipped.isEmpty {
                QuietNote("Left out \(info.skipped.joined(separator: ", ")): that is this Mac itself.", attention: true)
            }
            if let result {
                QuietNote(result.text, attention: !result.ok)
                    .textSelection(.enabled)
            }
        }
        .task(id: model.controller.status.phase) {
            while !Task.isCancelled {
                info = await model.controller.dnsForwardingInfo()
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }

    private func test() {
        testing = true
        Task {
            result = await model.controller.testDNSForwarding()
            info = await model.controller.dnsForwardingInfo()
            testing = false
        }
    }
}
