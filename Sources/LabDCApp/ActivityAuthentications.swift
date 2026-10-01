import AppKit
import Observation
import LabDCCore
import SwiftUI

/// Activity's two tabs (wireframe §7.5: Authentications · Log; Sessions arrives with RADIUS),
/// titled "Sign-ins" · "Server log" in the Quiet look.
enum ActivityTab: String, CaseIterable, Identifiable {
    case authentications, log
    var id: String { rawValue }
    var title: String { self == .authentications ? "Sign-ins" : "Server log" }
}

/// The words above the sign-ins: All · Did not succeed · Kerberos · NTLM · LDAP · Certificates.
/// "Did not succeed" is `AuthenticationsFilter.result == .failed`; the kinds filter by method.
enum SignInFilter: String, CaseIterable, Identifiable {
    case all, failed, kerberos, ntlm, ldap, certificates
    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All"
        case .failed: "Did not succeed"
        case .kerberos: "Kerberos"
        case .ntlm: "NTLM"
        case .ldap: "LDAP"
        case .certificates: "Certificates"
        }
    }

    func matches(_ e: AuthenticationEvent) -> Bool {
        switch self {
        case .all, .failed: true
        case .kerberos: e.method == .kerberos || e.component == "KDC"
        case .ntlm: e.method == .ntlm || e.method == .mschapv2 || e.method == .nacPassword || e.component == "NETLOGON"
        case .ldap: e.method == .ldapBind
        case .certificates: e.method == .enrollment
        }
    }
}

extension Notification.Name {
    /// Posted by Activity ▸ Authentications ▸ "Open User" (object: the account name, `alice`)
    /// after switching to Users, so the Users page can select that account.
    static let labDCOpenUser = Notification.Name("dev.labdc.app.openUser")
}

/// Activity ▸ Authentications: the feed (live log + earlier day files), the filter, the
/// selection, the contextual actions and the Test login sheet's model.
@MainActor @Observable
final class AuthenticationsViewModel {
    let feed: AuthenticationsFeed
    var filter = AuthenticationsFilter()
    /// The kind of sign-in shown (Kerberos, NTLM, …); `.all` shows every kind.
    var kind: SignInFilter = .all
    var selection: AuthenticationEvent.ID?
    var tab: ActivityTab = .authentications
    var showingTestLogin = false
    let testLogin = TestLoginModel()
    /// Injected clock (tests).
    @ObservationIgnored var now: () -> Date = { Date() }
    /// The account the last "Open User" asked for (Users picks it up via `.labDCOpenUser`).
    private(set) var lastOpenUserRequest: String?

    init(feed: AuthenticationsFeed = AuthenticationsFeed()) {
        self.feed = feed
    }

    /// Live lines from the hub, then the older day files in the background.
    /// Called again on a profile switch: the rows (and the selection) follow the new controller.
    func attach(_ controller: ServerController) {
        selection = nil
        feed.attach(controller.logs)
        let file = controller.logFile
        Task { await feed.loadEarlierDays(file) }
    }

    var visible: [AuthenticationEvent] {
        let rows = filter.apply(feed.events, now: now())
        return kind == .all ? rows : rows.filter { kind.matches($0) }
    }

    /// The selected word of the filter row ("Did not succeed" = failed results of every kind).
    var signInFilter: SignInFilter {
        get { filter.result == .failed ? .failed : kind }
        set {
            if newValue == .failed {
                filter.result = .failed
                kind = .all
            } else {
                filter.result = .all
                kind = newValue
            }
        }
    }

    /// `12 passed · 3 failed` for the rows shown.
    var summary: String {
        let rows = visible
        let failed = rows.filter { $0.result == .failed }.count
        return "\(rows.count - failed) passed · \(failed) failed"
    }

    var selectedEvent: AuthenticationEvent? { selection.flatMap(feed.event(id:)) }

    /// Runs a row's action: Users / Connect / Settings. `openSettings` is SwiftUI's action.
    func perform(_ action: AuthenticationEvent.Action, app: AppModel, openSettings: () -> Void) {
        switch action {
        case .openUser(let name):
            lastOpenUserRequest = name
            app.selection = .users
            NotificationCenter.default.post(name: .labDCOpenUser, object: name)
        case .connectDevice:
            app.selection = .connect
        case .openSettings:
            openSettings()
        }
    }

    /// Context menu ▸ Show in Log: the Log tab searching for this line.
    func showInLog(_ event: AuthenticationEvent, log: LogViewModel) {
        log.filter = LogFilter(components: [], search: Self.logSearch(for: event))
        tab = .log
    }

    /// A search that finds the row's line in the Log (its timestamp).
    static func logSearch(for event: AuthenticationEvent) -> String {
        event.raw.split(separator: " ").first.map(String.init) ?? event.user
    }

    func copy(_ event: AuthenticationEvent) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(event.raw, forType: .string)
    }

    /// Test login…: fills User from the selected row (a failed sign-in is the usual reason to test).
    func openTestLogin() {
        if let e = selectedEvent, e.user != "-", testLogin.user.isEmpty { testLogin.user = e.user }
        testLogin.result = nil
        showingTestLogin = true
    }
}


/// Activity ▸ Sign-ins: the filter words, then the sign-ins by day, written as sentences.
struct AuthenticationsPage: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            AuthenticationsFilterBar()
                .padding(.bottom, 20)
            AuthenticationsTable()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// All · Did not succeed · Kerberos · NTLM · LDAP · Certificates, then the day range and the counts.
struct AuthenticationsFilterBar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let auth = model.authentications
        HStack(alignment: .firstTextBaseline, spacing: 20) {
            ForEach(SignInFilter.allCases) { f in
                QuietFilterLink(title: f.title, selected: auth.signInFilter == f) { auth.signInFilter = f }
            }
            Spacer(minLength: 16)
            Menu {
                ForEach(AuthenticationsFilter.Range.allCases) { r in
                    Button(Self.rangeTitle(r)) { auth.filter.range = r }
                }
            } label: {
                Text(Self.rangeTitle(auth.filter.range))
                    .font(Theme.detail)
                    .foregroundStyle(Theme.ink)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("Show sign-ins from")
            .accessibilityValue(Self.rangeTitle(auth.filter.range))
            Text(auth.summary)
                .font(Theme.detail.monospacedDigit())
                .foregroundStyle(Theme.faint)
                .fixedSize()
        }
    }

    static func rangeTitle(_ range: AuthenticationsFilter.Range) -> String {
        switch range {
        case .today: "Today"
        case .week: "Last 7 days"
        case .all: "All days"
        }
    }
}

/// The sign-ins shown, newest first, under a small heading per day.
struct AuthenticationsTable: View {
    @Environment(AppModel.self) private var model

    struct Day: Identifiable {
        let id: Date
        let title: String
        var events: [AuthenticationEvent]
    }

    var body: some View {
        let auth = model.authentications
        let rows = auth.visible
        if rows.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text(auth.feed.events.isEmpty ? "No sign-ins yet" : "Nothing matches")
                    .font(Theme.body)
                    .foregroundStyle(Theme.ink)
                Text(auth.feed.events.isEmpty
                     ? "Kerberos, NTLM (NAC), LDAP binds, computers and certificate enrollment appear here. Try Test a sign-in."
                     : "Change the search, the day range or the filter.")
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 8)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(Self.days(rows).enumerated()), id: \.element.id) { dayIndex, day in
                        Text(day.title)
                            .font(Theme.caption)
                            .foregroundStyle(Theme.muted)
                            .padding(.top, dayIndex == 0 ? 0 : 28)
                            .padding(.bottom, 4)
                            .accessibilityAddTraits(.isHeader)
                        ForEach(Array(day.events.enumerated()), id: \.element.id) { index, e in
                            AuthenticationRow(event: e, first: index == 0)
                        }
                    }
                }
                .padding(.trailing, 4)
            }
        }
    }

    /// Consecutive rows grouped by calendar day (rows are newest first).
    static func days(_ rows: [AuthenticationEvent], calendar: Calendar = .current) -> [Day] {
        var out: [Day] = []
        for e in rows {
            let start = calendar.startOfDay(for: e.date)
            if let last = out.last, last.id == start {
                out[out.count - 1].events.append(e)
            } else {
                out.append(Day(id: start, title: dayTitle(start, calendar: calendar), events: [e]))
            }
        }
        return out
    }

    static func dayTitle(_ day: Date, calendar: Calendar = .current) -> String {
        if calendar.isDateInToday(day) { return "Today" }
        if calendar.isDateInYesterday(day) { return "Yesterday" }
        return day.formatted(.dateTime.weekday(.wide).day().month(.wide))
    }
}

/// time · "Bob Brown could not sign in — wrong password" · method · device.
struct AuthenticationRow: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    let event: AuthenticationEvent
    var first = false

    var body: some View {
        let auth = model.authentications
        let e = event
        let selected = auth.selection == e.id
        QuietRow(first: first) {
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                Text(e.date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)))
                    .font(Theme.body.monospacedDigit())
                    .foregroundStyle(Theme.faint)
                    .frame(width: 72, alignment: .leading)
                sentence
                    .font(Theme.body)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(e.result == .failed ? (e.reason.isEmpty ? e.code : "\(e.reason) (\(e.code))")
                          : (e.sentName == e.user ? e.user : "Sent as \(e.sentName)"))
                Spacer(minLength: 12)
                if let action = e.action {
                    Button(action.title) { auth.perform(action, app: model, openSettings: { openSettings() }) }
                        .buttonStyle(QuietLinkStyle(size: 12))
                        .fixedSize()
                        .accessibilityLabel("\(action.title) for \(e.user)")
                }
                Text(e.methodLabel)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                    .fixedSize()
                    .help(e.methodDetail.isEmpty ? e.methodLabel : "\(e.methodLabel) · \(e.methodDetail)")
                Text(e.from)
                    .font(Theme.detail)
                    .foregroundStyle(Theme.faint)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: 190, alignment: .trailing)
            }
        }
        .background(selected ? Theme.inset : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture { auth.selection = e.id }
        .accessibilityAddTraits(selected ? .isSelected : [])
        .contextMenu {
            if let action = e.action {
                Button(action.title) { auth.perform(action, app: model, openSettings: { openSettings() }) }
                Divider()
            }
            Button("Show in Log") { auth.showInLog(e, log: model.logModel) }
            Button("Copy Log Line") { auth.copy(e) }
            if e.user != "-" {
                Button("Test Login as \(e.user)…") {
                    auth.selection = e.id
                    auth.testLogin.user = e.user
                    auth.openTestLogin()
                }
            }
        }
    }

    /// "Alice Anderson signed in" / "Bob Brown could not sign in — wrong password" (the reason in
    /// the attention colour).
    private var sentence: Text {
        let e = event
        let who = e.user.isEmpty || e.user == "-" ? "Someone" : e.user
        let test = e.isTest ? " (test)" : ""
        if e.result == .passed {
            let ms = e.testMilliseconds.map { " · \($0) ms" } ?? ""
            let lead = Text("\(who) signed in\(test)").foregroundStyle(Theme.ink)
            return Text("\(lead)\(Text(ms).foregroundStyle(Theme.faint))")
        }
        let reason = e.reason.isEmpty ? "" : " — \(e.reason.lowercased())"
        let lead = Text("\(who) could not sign in\(test)").foregroundStyle(Theme.ink)
        return Text("\(lead)\(Text(reason).foregroundStyle(Theme.attention))")
    }
}
