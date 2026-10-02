import AppKit
import Observation
import LabDCCore
import SwiftUI
import UniformTypeIdentifiers

/// Activity ▸ Log: the live serve log (today's earlier runs included, from the log file).
@MainActor @Observable
final class LogViewModel {
    private(set) var lines: [LogLine] = []
    var filter = LogFilter()
    /// While paused new lines wait in `pending` and the view stops scrolling.
    var paused = false {
        didSet { if !paused { flushPending() } }
    }
    private(set) var pending: [LogLine] = []
    /// "Raw lines": the log exactly as written, in monospace (for debugging).
    var showRaw = false
    /// Lines kept in the view (the hub keeps its own history).
    var limit = 20_000
    @ObservationIgnored private var task: Task<Void, Never>?

    init() {}

    /// Subscribes first, then takes the history, so no line falls in between (duplicates are
    /// dropped by `seq`). Attaching again (a profile switch) drops the old hub's subscription
    /// and its lines (owner review, 30 Sep 2026).
    func attach(_ hub: LogHub) {
        task?.cancel()  // ends the old stream, which unsubscribes it from its hub
        task = nil
        pending.removeAll()
        let stream = hub.stream()
        lines = hub.history()
        task = Task { [weak self] in
            for await line in stream { self?.receive(line) }
        }
    }

    func receive(_ line: LogLine) {
        if let last = pending.last ?? lines.last, line.seq != 0, line.seq <= last.seq { return }
        if paused {
            pending.append(line)
        } else {
            lines.append(line)
            trim()
        }
    }

    private func flushPending() {
        lines.append(contentsOf: pending)
        pending.removeAll()
        trim()
    }

    private func trim() {
        if lines.count > limit + limit / 10 { lines.removeFirst(lines.count - limit) }
    }

    var visible: [LogLine] { filter.apply(lines) }
    var components: [String] { LogFilter.components(in: lines) }

    func toggle(_ component: String) {
        if filter.components.contains(component) { filter.components.remove(component) } else { filter.components.insert(component) }
    }

    /// Copy: the visible lines.
    func copyVisible() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(LogFilter.text(visible), forType: .string)
    }

    /// Export: the visible lines to a file the owner picks.
    func export() {
        let panel = NSSavePanel()
        panel.title = "Export log"
        panel.nameFieldStringValue = "LabDC log \(Date().formatted(.iso8601.year().month().day())).log"
        panel.allowedContentTypes = [.log, .plainText]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? LogFilter.text(visible).write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Activity in the Quiet look: "Sign-ins" · "Server log" as text tabs with the search on the
/// right, "Test a sign-in" beside the title, and the Test login sheet.
struct ActivityView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var auth = model.authentications
        @Bindable var log = model.logModel
        QuietPage(title: "Activity", scrolls: false) {
            Button("Test a sign-in") { auth.openTestLogin() }
                .buttonStyle(.quietLink)
                .help("Try a sign-in (Kerberos, NTLM as a NAC, LDAP bind) against this server (⇧⌘T)")
                .keyboardShortcut("t", modifiers: [.command, .shift])
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline, spacing: 24) {
                    QuietTabs(items: ActivityTab.allCases.map { ($0, $0.title) }, selection: $auth.tab)
                    Spacer(minLength: 16)
                    switch auth.tab {
                    case .authentications:
                        TextField("Search", text: $auth.filter.search, prompt: Text("Search"))
                            .textFieldStyle(.quiet)
                            .frame(width: 220)
                            .accessibilityLabel("Search sign-ins")
                    case .log:
                        TextField("Search", text: $log.filter.search, prompt: Text("Search the log"))
                            .textFieldStyle(.quiet)
                            .frame(width: 220)
                            .accessibilityLabel("Search the log")
                    }
                }
                .padding(.bottom, 24)
                switch auth.tab {
                case .authentications: AuthenticationsPage()
                case .log: LogPage()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .navigationSubtitle(auth.tab.title)
        .sheet(isPresented: $auth.showingTestLogin) {
            TestLoginSheet()
        }
    }
}

/// A filter as a word: ink and medium weight when selected, muted otherwise.
struct QuietFilterLink: View {
    let title: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13, weight: selected ? .medium : .regular))
                .foregroundStyle(selected ? Theme.ink : Theme.muted)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title) filter")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Activity ▸ Server log: the live serve log (UI-1), its filters and actions as words.
struct LogPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var log = model.logModel
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                LogCategoryLinks()
                Spacer(minLength: 16)
                HStack(alignment: .firstTextBaseline, spacing: 20) {
                    if log.paused {
                        Text("Paused · \(log.pending.count) new")
                            .font(Theme.detail.monospacedDigit())
                            .foregroundStyle(Theme.muted)
                    }
                    Button(log.paused ? "Resume" : "Pause") { log.paused.toggle() }
                        .buttonStyle(.quietLink)
                        .help(log.paused ? "Resume (\(log.pending.count) new lines waiting)" : "Pause the live log")
                        .accessibilityLabel(log.paused ? "Resume live log" : "Pause live log")
                    Button(log.showRaw ? "Readable" : "Raw lines") { log.showRaw.toggle() }
                        .buttonStyle(.quietLink)
                        .help(log.showRaw ? "Show the log as sentences" : "Show the lines exactly as written, for debugging")
                    Button("Copy") { log.copyVisible() }
                        .buttonStyle(.quietLink)
                        .help("Copy the lines shown")
                    Button("Export…") { log.export() }
                        .buttonStyle(.quietLink)
                        .help("Save the lines shown to a file")
                    Button("Open log folder") { model.openLogFolder() }
                        .buttonStyle(.quietLink)
                        .help("Open the folder with one log file per day")
                }
                .fixedSize()
            }
            .padding(.bottom, 14)
            Rectangle().fill(Theme.line).frame(height: 1)
            LogList()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// All · Problems · Sign-ins · Devices · Certificates · System, as words.
struct LogCategoryLinks: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let log = model.logModel
        FlowLayout(spacing: 18) {
            QuietFilterLink(title: "All", selected: log.filter.category == nil && !log.filter.warningsOnly && log.filter.components.isEmpty) {
                log.filter.category = nil
                log.filter.warningsOnly = false
                log.filter.components.removeAll()
            }
            QuietFilterLink(title: "Problems", selected: log.filter.warningsOnly) {
                log.filter.warningsOnly.toggle()
            }
            ForEach(LogCategory.allCases, id: \.self) { c in
                QuietFilterLink(title: c.rawValue, selected: log.filter.category == c) {
                    log.filter.category = log.filter.category == c ? nil : c
                    log.filter.components.removeAll()
                }
            }
        }
    }
}

struct LogList: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let log = model.logModel
        let lines = log.visible
        ScrollViewReader { proxy in
            // A ScrollView, not a List: List's row gestures swallow drag selection on macOS, so
            // the lines could only be copied with the Copy button.
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if log.showRaw {
                        ForEach(lines) { line in
                            LogRow(line: line)
                                .padding(.vertical, 2)
                        }
                    } else {
                        ForEach(LogDay.group(lines)) { day in
                            Text(day.title)
                                .font(Theme.emphasis)
                                .foregroundStyle(Theme.ink)
                                .padding(.top, 14)
                                .padding(.bottom, 4)
                            ForEach(day.lines) { line in
                                ReadableLogRow(line: line)
                                    .padding(.vertical, 4)
                            }
                        }
                    }
                }
            }
            .background(Theme.background)
            .overlay(alignment: .topLeading) {
                if lines.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(log.lines.isEmpty ? "No log lines yet" : "Nothing matches")
                            .font(Theme.body)
                            .foregroundStyle(Theme.ink)
                        Text(log.lines.isEmpty ? "Lines appear as the server works."
                             : "Change the search or the filter.")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                    }
                    .padding(.top, 16)
                }
            }
            .onChange(of: lines.last?.id) { _, id in
                guard !log.paused, let id else { return }
                proxy.scrollTo(id, anchor: .bottom)
            }
            .onAppear {
                if let id = lines.last?.id { proxy.scrollTo(id, anchor: .bottom) }
            }
        }
    }
}

/// The lines of one day under "Today" / "Yesterday" / "Friday 26 September".
struct LogDay: Identifiable {
    let id: Date
    let title: String
    let lines: [LogLine]

    static func group(_ lines: [LogLine]) -> [LogDay] {
        let calendar = Calendar.current
        var days: [LogDay] = []
        var current: [LogLine] = []
        var currentDay: Date?
        func flush() {
            guard let day = currentDay, !current.isEmpty else { return }
            days.append(LogDay(id: day, title: title(day, calendar), lines: current))
        }
        for line in lines {
            let day = calendar.startOfDay(for: line.date)
            if day != currentDay {
                flush()
                current = []
                currentDay = day
            }
            current.append(line)
        }
        flush()
        return days
    }

    private static func title(_ day: Date, _ calendar: Calendar) -> String {
        if calendar.isDateInToday(day) { return "Today" }
        if calendar.isDateInYesterday(day) { return "Yesterday" }
        return day.formatted(.dateTime.weekday(.wide).day().month(.wide))
    }
}

/// One line as a sentence: `14:02:31   Kerberos   AS alice@LAB.SHEEP from 192.168.1.20 -> OK`;
/// problems start with "Problem" in the attention colour. The start-up banner is quiet.
struct ReadableLogRow: View {
    let line: LogLine

    var body: some View {
        if line.level == .banner {
            Text(line.text)
                .font(Theme.caption.monospaced())
                .foregroundStyle(Theme.faint)
                .textSelection(.enabled)
                .lineLimit(2)
        } else {
            HStack(alignment: .firstTextBaseline, spacing: 14) {
                Text(line.date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)))
                    .font(Theme.detail.monospacedDigit())
                    .foregroundStyle(Theme.faint)
                    .frame(width: 64, alignment: .leading)
                Text(LogCategory.label(line.component))
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                    .frame(width: 112, alignment: .leading)
                Text(message)
                    .font(Theme.body)
                    .foregroundStyle(Theme.ink)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .textSelection(.enabled)
            .accessibilityElement(children: .combine)
        }
    }

    private var message: AttributedString {
        var text = AttributedString(line.text)
        guard line.level == .warning else { return text }
        var tag = AttributedString("Problem  ")
        tag.swiftUI.foregroundColor = Theme.attention
        tag.swiftUI.font = Theme.body.weight(.semibold)
        text.swiftUI.foregroundColor = Theme.attention
        return tag + text
    }
}

/// Raw lines: time · component · text in monospace, exactly as written (warnings in the
/// attention colour).
struct LogRow: View {
    let line: LogLine

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(line.level == .banner ? "" : line.date.activityStamp)
                .foregroundStyle(Theme.faint)
                .frame(width: 108, alignment: .leading)
            Text(line.level == .banner ? "" : line.component)
                .foregroundStyle(Theme.muted)
                .frame(width: 84, alignment: .leading)
            Text(line.level == .warning ? "WARNING " + line.text : line.text)
                .foregroundStyle(line.level == .warning ? Theme.attention : Theme.ink)
                .textSelection(.enabled)
                .lineLimit(3)
        }
        .font(Theme.mono)
        .textSelection(.enabled)
        .accessibilityElement(children: .combine)
    }
}
