import AppKit
import LabDCCore
import SwiftUI

/// §7.6 Connect a device, in the Quiet look: the devices as text tabs, then only the steps the
/// device needs, in its order — a light numeral, the title, where on the device, the fields as
/// label · value · Copy — and the live checklist as plain lines on the right.
struct ConnectView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.smokeRendering) private var smokeRendering
    @Environment(\.openSettings) private var openSettings
    @State private var connect: ConnectModel

    init(connect: ConnectModel = ConnectModel()) {
        _connect = State(initialValue: connect)
    }

    var body: some View {
        let values = connect.values(model.controller)
        QuietPage(title: connect.device.connectTitle, subtitle: connect.device.subtitle) {
            CopyAllButton(text: connect.copyAllText(values))
            // "Save…", a quiet link like the others: the steps carry their own Save links, this is
            // the one place for every format (owner, 2 Oct 2026).
            Menu("Save…") {
                Button("Save CA (.pem)…") { perform(.saveCAPEM, values) }
                Button("Save CA (.cer)…") { perform(.saveCACER, values) }
                Button("Save Profile (.mobileconfig)…") { perform(.saveMobileConfig, values) }
            }
            .menuStyle(.button)
            .buttonStyle(.quietLink)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("Save")
            .accessibilityHint("Saves the CA certificate or the Apple configuration profile")
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                DevicePicker(selection: Bindable(connect).device)
                if model.controller.status.phase != .running {
                    QuietNote("The server is not running; the values below may be incomplete.", attention: true)
                        .padding(.top, 16)
                }
                if let message = connect.message {
                    QuietNote(message, attention: true)
                        .textSelection(.enabled)
                        .padding(.top, 8)
                }
                HStack(alignment: .top, spacing: 48) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(connect.steps(values).enumerated()), id: \.element.id) { index, step in
                            QuietRow(first: index == 0) {
                                GuideStepCard(step: step, perform: { perform($0, values) },
                                              published: connect.observations.trustedRootPublished)
                                    .padding(.vertical, 6)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    ChecklistCard(connect: connect, perform: { perform($0, values) })
                        .frame(width: 240, alignment: .leading)
                }
                .padding(.top, 36)
            }
        }
        .task(id: model.controller.isRunning) {
            guard !smokeRendering else { return }
            await connect.watch(model.controller)
        }
    }

    private func perform(_ action: GuideAction, _ values: ConnectValues) {
        switch action {
        case .saveCAPEM, .saveCACER, .saveMobileConfig:
            connect.save(action, values: values, controller: model.controller)
        case .publishCA:
            Task {
                do {
                    try await model.controller.publishCA()
                    await connect.reload(model.controller)
                } catch {
                    connect.message = "Publishing failed: \(error)"
                }
            }
        case .openSignCSR, .openEnrollment, .openTrustedRoots:
            model.certificates.section = action == .openSignCSR ? .sign : action == .openEnrollment ? .enrollment : .trustedRoots
            model.selection = .certificates
        case .openUsers:
            model.selection = .users
        case .openDirectorySettings:
            model.requestedSettingsTab = .directory
            openSettings()
        case .openRadiusClients:
            model.selection = .radius
        }
    }
}

extension DeviceKind {
    /// The text tab: Windows PC · ClearPass · iMaster NCE · Linux · Mac and iPhone · Switch or AP · Other.
    var quietTabTitle: String {
        switch self {
        case .windows: "Windows PC"
        case .clearpass: "ClearPass"
        case .imaster: "iMaster NCE"
        case .linux: "Linux"
        case .apple: "Mac and iPhone"
        case .switchAP: "Switch or AP"
        case .other: "Other"
        }
    }

    /// The page title: "Connect a Windows PC".
    var connectTitle: String {
        switch self {
        case .windows: "Connect a Windows PC"
        case .clearpass: "Connect a ClearPass"
        case .imaster: "Connect an iMaster NCE"
        case .linux: "Connect a Linux computer"
        case .apple: "Connect a Mac or iPhone"
        case .switchAP: "Connect a switch or AP"
        case .other: "Connect another device"
        }
    }

    /// The small heading above the device name in the checklist column.
    var thisDeviceLabel: String {
        switch self {
        case .windows: "This PC"
        case .clearpass: "This ClearPass"
        case .imaster: "This iMaster NCE"
        case .linux: "This computer"
        case .apple: "This Mac or iPhone"
        case .switchAP: "This switch or AP"
        case .other: "This device"
        }
    }
}

/// The devices as text tabs (the choice is remembered by `ConnectModel`).
struct DevicePicker: View {
    @Binding var selection: DeviceKind

    var body: some View {
        QuietTabs(items: DeviceKind.allCases.map { ($0, $0.quietTabTitle) }, selection: $selection)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Device")
    }
}

/// One step: a light numeral, the title, where on the device, then its fields/commands/notes.
struct GuideStepCard: View {
    let step: GuideStep
    let perform: (GuideAction) -> Void
    var published = false

    /// Consecutive fields share one grid so the labels line up.
    private enum Block: Identifiable {
        case fields(Int, [GuideField])
        case item(Int, GuideItem)
        var id: Int {
            switch self {
            case .fields(let i, _), .item(let i, _): i
            }
        }
    }

    private var blocks: [Block] {
        var out: [Block] = []
        for (i, item) in step.items.enumerated() {
            if case .field(let f) = item {
                if case .fields(let start, let fs)? = out.last {
                    out[out.count - 1] = .fields(start, fs + [f])
                } else {
                    out.append(.fields(i, [f]))
                }
            } else {
                out.append(.item(i, item))
            }
        }
        return out
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Text("\(step.number)")
                .font(Font.system(size: 22, weight: .ultraLight).monospacedDigit())
                .foregroundStyle(Theme.faint)
                .frame(width: 48, alignment: .leading)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(step.title)
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(Theme.ink)
                        .fixedSize(horizontal: false, vertical: true)
                    if let location = step.location {
                        Text(location)
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                ForEach(blocks) { block in
                    switch block {
                    case .fields(_, let fields): FieldGrid(fields: fields)
                    case .item(_, let item): itemView(item)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .opacity(step.isLater ? 0.6 : 1)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Step \(step.number), \(step.title)")
    }

    @ViewBuilder
    private func itemView(_ item: GuideItem) -> some View {
        switch item {
        case .text(let s):
            Text(s)
                .font(Theme.body)
                .foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        case .field(let f):
            FieldGrid(fields: [f])
        case .command(let c, let expect):
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(c)
                        .font(Theme.mono)
                        .foregroundStyle(Theme.ink)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    CopyButton(value: c)
                }
                if let expect {
                    Text("→ \(expect)")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.faint)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        case .snippet(let title, let code):
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                    Spacer(minLength: 12)
                    CopyButton(value: code)
                }
                Text(code)
                    .font(Theme.mono)
                    .foregroundStyle(Theme.ink)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Theme.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
        case .note(let s):
            QuietNote(s)
        case .warning(let s):
            QuietNote(s, attention: true)
        case .actions(let actions):
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                ForEach(actions, id: \.self) { action in
                    if action == .publishCA && published {
                        Text("CA published")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                    } else {
                        Button(action.title) { perform(action) }
                            .buttonStyle(.quietLink)
                    }
                }
            }
        }
    }
}

/// Label (muted, one column) · value (monospace) or, for the Administrator password, words · Copy.
struct FieldGrid: View {
    let fields: [GuideField]

    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 10) {
            ForEach(Array(fields.enumerated()), id: \.offset) { _, f in
                GridRow {
                    Text(f.label)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                        .frame(width: 140, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                    VStack(alignment: .leading, spacing: 2) {
                        if let value = f.value {
                            Text(value)
                                .font(Theme.mono)
                                .foregroundStyle(Theme.ink)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            Text(Self.capitalizedFirst(f.hint ?? ""))
                                .font(Theme.detail)
                                .foregroundStyle(Theme.muted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if let note = f.note {
                            Text(note)
                                .font(Theme.caption)
                                .foregroundStyle(Theme.faint)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if let value = f.value {
                        CopyButton(value: value)
                    } else {
                        Color.clear.frame(width: 1, height: 1)
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel(f.label)
            }
        }
    }

    /// "the Administrator password you chose" → "The Administrator password you chose".
    static func capitalizedFirst(_ s: String) -> String {
        guard let first = s.first else { return s }
        return String(first).uppercased() + String(s.dropFirst())
    }
}

/// "This PC", the computer's name, then the checklist as plain lines: done in ink with a faint
/// time ("Joined 21:31"), the next one in muted ("Trusted root — waiting"), the rest faint.
struct ChecklistCard: View {
    let connect: ConnectModel
    let perform: (GuideAction) -> Void

    var body: some View {
        let items = connect.checklist
        let next = items.firstIndex { $0.state == .waiting }
        VStack(alignment: .leading, spacing: 0) {
            Text(connect.device.thisDeviceLabel)
                .font(Theme.caption)
                .foregroundStyle(Theme.muted)
            deviceName
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    ChecklistRow(item: item, isNext: index == next, perform: perform)
                }
            }
            .padding(.top, 22)
            QuietNote("Updates by itself as the device joins and signs in.")
                .padding(.top, 20)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Live checklist")
    }

    /// The joined computer this device is (a text menu: Automatic or one of the computers), or
    /// the device's name when it does not join.
    @ViewBuilder
    private var deviceName: some View {
        if connect.device.joins, !connect.observations.computers.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Menu {
                    Button("Automatic" + (connect.automaticComputer.map { " (\($0.name))" } ?? "")) { connect.pin(nil) }
                    Divider()
                    ForEach(connect.pickerComputers) { c in
                        Button(c.name + (c.osDescription.map { " · \($0)" } ?? "")) { connect.pin(c.account) }
                    }
                } label: {
                    Text(currentName)
                        .font(.system(size: 17))
                        .foregroundStyle(Theme.ink)
                }
                // Plain, so the name lines up with the label above (no menu inset).
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel("This device")
                .accessibilityValue(currentName)
                .accessibilityHint("Which joined computer is this device")
                // "Automatic" says it already; no "Chosen automatically" under it.
                if currentName != "Automatic" {
                    Text(connect.pinnedAccount == nil ? "Chosen automatically" : "Chosen by you")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.faint)
                }
            }
        } else if connect.device.joins {
            Text("Not joined yet")
                .font(.system(size: 17))
                .foregroundStyle(Theme.muted)
        } else {
            Text(connect.device.shortTitle)
                .font(.system(size: 17))
                .foregroundStyle(Theme.ink)
        }
    }

    private var currentName: String {
        if let pinned = connect.pinnedAccount,
           let computer = connect.observations.computers.first(where: { $0.account == pinned }) {
            return computer.name
        }
        return connect.automaticComputer?.name ?? "Automatic"
    }
}

/// One checklist line, state as words: "Joined 21:31", "Trusted root — waiting",
/// "Signed in 21:40 — did not succeed" (attention), "RADIUS — later".
struct ChecklistRow: View {
    let item: ChecklistItem
    var isNext = false
    let perform: (GuideAction) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            line
                .font(Theme.body)
                .fixedSize(horizontal: false, vertical: true)
            if !item.detail.isEmpty {
                Text(item.detail)
                    .font(Theme.caption)
                    .foregroundStyle(item.state == .problem ? Theme.attention : Theme.faint)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            if let action = item.action, item.state != .done {
                Button(action.title) { perform(action) }
                    .buttonStyle(QuietLinkStyle(size: 12))
                    .padding(.top, 2)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var line: Text {
        let time = item.date.map { " " + $0.connectStamp } ?? ""
        switch item.state {
        case .done:
            return Text("\(Text(item.title).foregroundStyle(Theme.ink))\(Text(time).foregroundStyle(Theme.faint))")
        case .problem:
            let title = Text(item.title).foregroundStyle(Theme.ink)
            let stamp = Text(time).foregroundStyle(Theme.faint)
            let failed = Text(" — did not succeed").foregroundStyle(Theme.attention)
            return Text("\(title)\(stamp)\(failed)")
        case .waiting:
            return isNext
                ? Text(item.title + " — waiting").foregroundStyle(Theme.muted)
                : Text(item.title).foregroundStyle(Theme.faint)
        case .checkOnDevice:
            return Text(item.title + " — check on the device").foregroundStyle(Theme.muted)
        case .later:
            return Text(item.title + " — later").foregroundStyle(Theme.faint)
        }
    }
}

/// "Copy all values" (the plain-text guide), saying "Copied" for a moment.
struct CopyAllButton: View {
    let text: String
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                copied = false
            }
        } label: {
            Text(copied ? "Copied" : "Copy all values")
        }
        .buttonStyle(.quietLink)
        .accessibilityLabel(copied ? "Copied" : "Copy all values as text")
    }
}

extension Date {
    /// `14:24` today, `26 Sep 14:24` before.
    var connectStamp: String {
        Calendar.current.isDateInToday(self)
            ? formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
            : formatted(.dateTime.day().month(.abbreviated).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
    }
}
