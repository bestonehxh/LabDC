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
                    ForEach(status.notes, id: \.self) { note in
                        QuietNote(note)
                    }
                }
                .padding(.top, 20)
            }
        }
    }

    /// "Devices reach this Mac at 192.168.1.155 on Wi-Fi. You can change this in Settings."
    static func subtitle(_ status: ServerStatus) -> String {
        guard let ip = status.advertisedIPv4 else {
            return "Devices are told this Mac's address once the services run. You can choose it in Settings."
        }
        let on = status.advertisedInterfaceName.map { " on \($0)" } ?? ""
        return "Devices reach this Mac at \(ip)\(on). You can change this in Settings."
    }
}

/// "Everything is running · DNS, Kerberos, …" as one quiet line, the problem colour when not.
struct ServicesHeadline: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let status = model.controller.status
        let trouble = status.phase == .problem || !status.problems.isEmpty
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(status.statusTitle)
                .font(Theme.emphasis)
                .foregroundStyle(trouble ? Theme.attention : Theme.ink)
            Text(status.statusSubtitle)
                .font(Theme.detail)
                .foregroundStyle(Theme.muted)
                .lineLimit(1)
                .truncationMode(.tail)
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
                Button(row.state == .restarting ? "Restarting…" : "Restart") {
                    Task { await model.controller.restartService(row.service) }
                }
                .buttonStyle(.quietLink)
                .disabled(!row.canRestart || !model.controller.isRunning && model.controller.status.phase != .problem)
                .help(helpText)
                .accessibilityLabel(row.state == .restarting ? "Restarting \(row.service.title)" : "Restart \(row.service.title)")
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
                    Text(row.state == .off ? "Off in Settings ▸ Directory (Let devices join the domain)" : row.portsText)
                        .font(Theme.caption.monospaced())
                        .foregroundStyle(Theme.muted)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
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
    }

    /// The state as words: "Running since 14:02", "Restarted at 14:05:11", the problem in attention.
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
            return "Restarted at \(last.date.activityStamp)"
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
