import AppKit
import LabDCCore
import SwiftUI

/// Overview in the Quiet look (owner, 27 Sep 2026): the date, a greeting by the Mac's clock with
/// its picture rising from behind the last letters, four numbers, and the latest sign-ins written
/// as sentences. When a service has a problem a small wrench badge sits beside the headline; when
/// it clears the greeting picture plays again.
struct OverviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text(Date.now.formatted(.dateTime.weekday(.wide).day().month(.wide)))
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                GreetingHeader()
                    .padding(.top, 6)
                // "Network needs attention." says why underneath (owner, 1 Oct 2026).
                if let why = model.controller.status.networkProblem {
                    QuietNote(why, attention: true).padding(.top, 8)
                }
                OverviewNumbers()
                    .padding(.top, 56)
                NextStepsList()
                    .padding(.top, 40)
                RecentSignIns()
                    .padding(.top, 48)
            }
            .padding(Theme.pageInsets)
            // Room above the greeting for its picture (the moon and the morning glow reach about
            // 170 pt above the last line), and the picture may draw into the window's top strip.
            .padding(.top, 18)
            .frame(maxWidth: Theme.maxContentWidth, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .scrollClipDisabled()
        .background(Theme.background)
        .navigationTitle("Overview")
    }
}

// MARK: - Greeting

/// Remembers what already played in this run, so switching pages does not replay the picture.
/// Owner rules (27 Sep 2026): the picture plays when LabDC opens and when the greeting
/// changes; a change that happens while another page is open, or while the window is minimised or
/// hidden, plays when Overview is next seen. Switching pages alone never replays it. A problem
/// that was shown and cleared while Overview was not in view comes back as
/// the greeting with its picture.
@MainActor
enum GreetingPlayback {
    static var lastPlayed: GreetingPeriod?
    static var playCount = 0
    /// A problem was shown and the greeting has not played since.
    static var problemShown = false
    /// The last Settings "Try" request already played.
    static var handledPreview: UUID?
}

struct GreetingHeader: View {
    @Environment(AppModel.self) private var model
    @Environment(\.smokeRendering) private var smokeRendering
    @AppStorage(GreetingPicture.storageKey) private var pictureSetting = GreetingPicture.five.rawValue

    @State private var period = GreetingPeriod()
    @State private var showGreetingArt = false
    /// A problem is shown: a wrench badge sits beside the headline (owner, 28 + 30 Sep 2026).
    @State private var attention = false
    @State private var playID = 0
    /// False while the window is minimised, hidden or covered: nothing starts then.
    @State private var windowVisible = true
    /// The greeting changed (or a problem cleared) while the window could not be seen.
    @State private var pendingGreeting = false
    /// Settings ▸ Try: the period shown instead of the clock's, or a pretend problem.
    @State private var previewPeriod: GreetingPeriod?
    @State private var previewTrouble: String?
    /// Bumped by each Try ▸ Needs attention; its hold ends the pretend problem.
    @State private var previewTroubleID = 0
    /// Seconds a Try ▸ Needs attention stays before the greeting comes back.
    static let attentionPreviewHold: Double = 6

    private var picture: GreetingPicture { GreetingPicture(rawValue: pictureSetting) ?? .five }

    /// The service with a problem ("Directory"), the app's name when the server itself failed, nil when fine.
    private var troubled: String? {
        let status = model.controller.status
        if let service = status.services.first(where: { $0.problemMessage != nil }) { return service.service.title }
        if status.networkProblem != nil { return "Network" }
        if status.phase == .problem { return "LabDC" }
        return nil
    }

    /// What the headline says: a real problem first, then a "Try" problem.
    private var shownTrouble: String? { troubled ?? previewTrouble }
    /// Services stopped with Services ▸ Stop while the rest runs ("Directory", "DNS and Time"):
    /// not a problem, so the headline says so plainly instead of "needs attention" (owner, 1 Oct 2026).
    private var stoppedServices: String? {
        let status = model.controller.status
        guard status.phase == .running else { return nil }
        let names = status.services.filter { $0.state == .stopped }.map(\.service.title)
        guard !names.isEmpty else { return nil }
        return names.count == 1 ? names[0] : names.dropLast().joined(separator: ", ") + " and " + names.last!
    }
    private var shownPeriod: GreetingPeriod { previewPeriod ?? period }
    /// Seconds the picture stays (nil = stays); a "Try" with the picture Off uses 5.
    private var artHold: Double? {
        if previewPeriod != nil, picture == .off { return 5 }
        return picture.hold
    }

    var body: some View {
        let k = Theme.greetingSize / 48
        HStack(alignment: .center, spacing: 18) {
            headline
                .layoutPriority(1)
                .background(alignment: .bottomTrailing) {
                    // The picture and the wrench both follow what the headline says, so a problem
                    // headline never sits over a greeting picture (owner, 1 Oct 2026).
                    if !smokeRendering, showGreetingArt, shownTrouble == nil, stoppedServices == nil {
                        // The artwork view is `bleed` larger on every side than the picture, so its
                        // glows fade out inside the drawing instead of being cut at its edge (owner,
                        // 28 Sep 2026). It stops animating while the window cannot be seen.
                        let bleed = GreetingArtwork.bleed
                        GreetingArtView(scene: .greeting(shownPeriod, hold: artHold), playID: playID,
                                        active: windowVisible, onFinished: artFinished)
                            .frame(width: 220 * k + 2 * bleed, height: 156 * k + 2 * bleed)
                            .offset(x: 86 * k + bleed, y: -2 * k + bleed)
                            .allowsHitTesting(false)
                            .accessibilityHidden(true)
                    }
                }
            // The wrench sits beside the headline, never over its last letters (owner, 30 Sep 2026).
            if shownTrouble != nil, !smokeRendering {
                AttentionMark()
                    .padding(.top, 6)  // the light 52 pt face sits low in its line box
                    .transition(.scale(scale: 0.6).combined(with: .opacity))
            }
        }
        .animation(.spring(response: 0.45, dampingFraction: 0.7), value: shownTrouble != nil)
        .background(WindowVisibility { visible in
            windowVisible = visible
            if visible, pendingGreeting, troubled == nil {
                pendingGreeting = false
                playGreeting()
            }
        })
        .onChange(of: model.greetingPreview) { _, request in
            if let request { runPreview(request) }
        }
        .onAppear {
            period = GreetingPeriod()
            if let request = model.greetingPreview, request.id != GreetingPlayback.handledPreview {
                runPreview(request)
                return
            }
            if troubled != nil {
                showAttention()
            } else if GreetingPlayback.problemShown || GreetingPlayback.lastPlayed != period || picture == .always {
                playOrDefer()
            }
        }
        // A new period while Overview is open (checked every minute).
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                let now = GreetingPeriod()
                if now != period {
                    period = now
                    if troubled == nil { playOrDefer() }
                }
            }
        }
        .onDisappear {
            // A Try's pretend problem never outlives the page (its timer is cancelled with it).
            previewTrouble = nil
        }
        .onChange(of: troubled) { old, new in
            if new != nil {
                // Also when the problem comes back before the picture it cleared for has faded.
                pendingGreeting = false
                showAttention()
            } else if old != nil {
                attention = false
                if windowVisible {
                    GreetingPlayback.problemShown = false
                    GreetingPlayback.lastPlayed = period
                    playOrDefer()
                } else {
                    pendingGreeting = true
                }
            }
        }
        .onChange(of: pictureSetting) { _, _ in
            if troubled == nil { playGreeting() }
        }
        .task(id: previewTroubleID) {
            // Try ▸ Needs attention is a pretend problem: it goes away by itself.
            guard previewTrouble != nil else { return }
            try? await Task.sleep(for: .seconds(Self.attentionPreviewHold))
            if !Task.isCancelled, previewTrouble != nil {
                previewTrouble = nil
                if troubled == nil {
                    attention = false
                    playOrDefer()
                }
            }
        }
    }

    @ViewBuilder private var headline: some View {
        if let troubled = shownTrouble {
            Text("\(troubled) \(Text("needs attention.").foregroundStyle(Theme.attention))")
                .font(Theme.greeting)
                .tracking(-1)
                .foregroundStyle(Theme.ink)
                .lineLimit(1)
                .accessibilityAddTraits(.isHeader)
        } else if let stopped = stoppedServices {
            let verb = stopped.contains(" and ") ? "are stopped." : "is stopped."
            Text("\(stopped) \(Text(verb).foregroundStyle(Theme.muted))")
                .font(Theme.greeting)
                .tracking(-1)
                .foregroundStyle(Theme.ink)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
                .accessibilityAddTraits(.isHeader)
        } else {
            Text(shownPeriod.greeting)
                .font(Theme.greeting)
                .tracking(-1)
                .foregroundStyle(Theme.ink)
                .lineLimit(1)
                .accessibilityAddTraits(.isHeader)
        }
    }

    /// Settings ▸ Try: plays one picture now, whatever the clock or the services say.
    private func runPreview(_ request: GreetingPreviewRequest) {
        guard request.id != GreetingPlayback.handledPreview else { return }
        GreetingPlayback.handledPreview = request.id
        if let p = request.scene.period {
            previewTrouble = nil
            previewPeriod = p
            attention = false
            showGreetingArt = true
            playID += 1
        } else if request.scene == .attention {
            previewPeriod = nil
            previewTrouble = "Directory"
            // Not showAttention(): a Try is not a real problem, so GreetingPlayback stays as it is.
            showGreetingArt = false
            attention = true
            previewTroubleID += 1
        } else {
            previewTrouble = nil
            previewPeriod = nil
            attention = false
            playOrDefer()
        }
    }

    /// The picture has faded (counted in playing time, so a hidden window does not cut it
    /// short): take it away so nothing keeps animating, and end a Try's pretend period.
    private func artFinished() {
        showGreetingArt = false
        previewPeriod = nil
    }

    /// Plays now when the window can be seen, else when it next can.
    private func playOrDefer() {
        if windowVisible { playGreeting() } else { pendingGreeting = true }
    }

    private func playGreeting() {
        GreetingPlayback.lastPlayed = period
        GreetingPlayback.problemShown = false
        previewTrouble = nil
        attention = false
        guard picture != .off else {
            showGreetingArt = false
            return
        }
        showGreetingArt = true
        playID += 1
    }

    private func showAttention() {
        GreetingPlayback.problemShown = true
        showGreetingArt = false
        attention = true
    }
}

/// The "needs attention" mark: a wrench in a soft round badge, in the same muted red as the words.
/// It pops in and gives one small turn, like a wrench being tried; Reduce Motion keeps it still.
struct AttentionMark: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var turned = false

    var body: some View {
        ZStack {
            Circle().fill(Theme.attention.opacity(0.12))
            Circle().strokeBorder(Theme.attention.opacity(0.35), lineWidth: 1)
            Image(systemName: "wrench.adjustable.fill")
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(Theme.attention)
                .rotationEffect(.degrees(turned ? 0 : -28))
        }
        .frame(width: 44, height: 44)
        .accessibilityHidden(true)
        .onAppear {
            guard !reduceMotion else { turned = true; return }
            withAnimation(.spring(response: 0.5, dampingFraction: 0.35).delay(0.2)) { turned = true }
        }
    }
}

/// Reports whether the window holding this view can be seen: false while it is minimised, the
/// app is hidden, or other windows cover it completely.
struct WindowVisibility: NSViewRepresentable {
    let onChange: (Bool) -> Void

    func makeNSView(context: Context) -> VisibilityView {
        let view = VisibilityView()
        view.onChange = onChange
        return view
    }

    func updateNSView(_ view: VisibilityView, context: Context) {
        view.onChange = onChange
    }

    final class VisibilityView: NSView {
        var onChange: ((Bool) -> Void)?
        private var reported: Bool?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            NotificationCenter.default.removeObserver(self)
            guard let window else { return }
            for name in [NSWindow.didChangeOcclusionStateNotification, NSWindow.didMiniaturizeNotification,
                         NSWindow.didDeminiaturizeNotification] {
                NotificationCenter.default.addObserver(self, selector: #selector(windowChanged), name: name, object: window)
            }
            windowChanged()
        }

        @objc private func windowChanged() {
            guard let window else { return }
            let visible = window.occlusionState.contains(.visible) && !window.isMiniaturized
            guard visible != reported else { return }
            reported = visible
            // Not during a SwiftUI update: report on the next turn of the main loop.
            DispatchQueue.main.async { [weak self] in self?.onChange?(visible) }
        }
    }
}

// MARK: - Numbers

/// People · Computers · Devices today · Certificates: the number, the word under it.
struct OverviewNumbers: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let stats = model.dashboardStats
        HStack(alignment: .top, spacing: 0) {
            number(stats.users, "People") { model.selection = .users }
            number(stats.computersJoined, "Computers") { model.selection = .users }
            number(stats.devicesToday, "Devices today") { model.selection = .activity }
            number(stats.certificatesValid, stats.certificatesExpiringSoon == 0 ? "Certificates"
                   : "Certificates, \(stats.certificatesExpiringSoon) expiring") { model.selection = .certificates }
        }
    }

    private func number(_ value: Int, _ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(value)")
                    .font(Theme.metric)
                    .tracking(-0.5)
                    .foregroundStyle(Theme.ink)
                    .contentTransition(.numericText())
                Text(label)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.muted)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

// MARK: - Next steps

/// Only while something is still empty: one line each, with the one action that fixes it.
struct NextStepsList: View {
    @Environment(AppModel.self) private var model
    @State private var publishing = false
    @State private var publishError: String?

    var body: some View {
        let hints = model.controller.store == nil ? [] : NextStep.hints(for: model.controller.summary)
        if !hints.isEmpty {
            QuietSection("Next steps") {
                ForEach(Array(hints.enumerated()), id: \.element.id) { index, hint in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 24) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(hint.title).font(Theme.body).foregroundStyle(Theme.ink)
                                Text(hint.detail).font(Theme.detail).foregroundStyle(Theme.muted)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 16)
                            action(hint)
                        }
                    }
                }
                if let publishError {
                    QuietNote(publishError, attention: true).padding(.top, 6)
                }
            }
        }
    }

    @ViewBuilder
    private func action(_ hint: NextStep) -> some View {
        switch hint {
        case .addUser:
            Button("Add a person") { model.selection = .users }.buttonStyle(.quietLink)
        case .connectDevice:
            Button("Connect") { model.selection = .connect }.buttonStyle(.quietLink)
        case .publishCA:
            Button(publishing ? "Publishing…" : "Publish") {
                publishing = true
                publishError = nil
                Task {
                    do { try await model.controller.publishCA() } catch { publishError = "Publishing failed: \(error)" }
                    publishing = false
                }
            }
            .buttonStyle(.quietLink)
            .disabled(publishing)
            .accessibilityHint("Adds the lab CA to the Default Domain Policy's trusted roots")
        }
    }
}

// MARK: - Recent

/// The last sign-ins as sentences: "Bob Brown could not sign in — wrong password".
struct RecentSignIns: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let events = Array(model.authentications.feed.events.prefix(6))
        QuietSection(title: "Recent") {
            Button("All activity") { model.selection = .activity }
                .buttonStyle(QuietLinkStyle(size: 13))
                .foregroundStyle(Theme.muted)
        } content: {
            if events.isEmpty {
                QuietRow(first: true) {
                    Text("No sign-ins yet. Kerberos, NTLM and LDAP sign-ins show up here as they happen.")
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                }
            } else {
                ForEach(Array(events.enumerated()), id: \.element.id) { index, e in
                    QuietRow(first: index == 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 24) {
                            Text(e.date.activityStamp)
                                .font(Theme.body.monospacedDigit())
                                .foregroundStyle(Theme.faint)
                                .frame(width: 64, alignment: .leading)
                            sentence(e)
                                .font(Theme.body)
                                .lineLimit(1)
                                .truncationMode(.tail)
                                // The red reason wins over the source when the window is narrow.
                                .layoutPriority(1)
                            Spacer(minLength: 12)
                            Text(e.from)
                                .font(Theme.detail)
                                .foregroundStyle(Theme.faint)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
    }

    private func sentence(_ e: AuthenticationEvent) -> Text {
        let who = e.user.isEmpty ? "Someone" : e.user
        let test = e.isTest ? " (test)" : ""
        if e.result == .passed {
            return Text("\(Text("\(who) signed in\(test)").foregroundStyle(Theme.ink))\(Text(" · \(e.methodLabel)").foregroundStyle(Theme.muted))")
        }
        let reason = e.reason.isEmpty ? e.methodLabel : e.reason.lowercased()
        return Text("\(Text("\(who) could not sign in\(test)").foregroundStyle(Theme.ink))\(Text(" — \(reason)").foregroundStyle(Theme.attention))")
    }
}
