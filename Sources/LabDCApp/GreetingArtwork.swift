import AppKit
import SwiftUI

/// The greeting pictures (owner-approved artwork, 27 Sep 2026), drawn natively by
/// `GreetingArtView` behind the greeting. Reduce Motion shows each picture still.
enum GreetingArtwork {
    /// Room around the picture, in points: the view is this much larger on every side than the
    /// 220 × 156 pt picture (at the 52 pt greeting size), and the drawing's 180 × 128 unit space is
    /// widened by 60.5 units to match, so glows fade out inside the view instead of being cut.
    static let bleed: CGFloat = 80
}

/// Morning 05–12, afternoon 12–17, evening 17–22, late 22–05, by the Mac's clock.
enum GreetingPeriod: String, Equatable {
    case morning, afternoon, evening, late

    init(date: Date = Date(), calendar: Calendar = .current) {
        switch calendar.component(.hour, from: date) {
        case 5..<12: self = .morning
        case 12..<17: self = .afternoon
        case 17..<22: self = .evening
        default: self = .late
        }
    }

    var greeting: String {
        switch self {
        case .morning: "Good morning."
        case .afternoon: "Good afternoon."
        case .evening: "Good evening."
        case .late: "Working late."
        }
    }
}

/// Settings ▸ General ▸ Greeting picture.
enum GreetingPicture: String, CaseIterable, Identifiable {
    case three, five, ten, always, off

    static let storageKey = "greetingPicture"
    var id: String { rawValue }

    var title: String {
        switch self {
        case .three: "Show for 3 seconds"
        case .five: "Show for 5 seconds"
        case .ten: "Show for 10 seconds"
        case .always: "Always show"
        case .off: "Off"
        }
    }

    /// Seconds on screen after it has risen; nil = stays (always) or never shows (off).
    var hold: Double? {
        switch self {
        case .three: 3
        case .five: 5
        case .ten: 10
        case .always, .off: nil
        }
    }

    /// In 1.5 s + hold + out 1 s.
    var totalDuration: Double? { hold.map { 1.5 + $0 + 1 } }
}

/// Settings ▸ General ▸ Try: each picture on demand, without waiting for the clock or a failure
/// (owner, 28 Sep 2026).
enum GreetingPreviewScene: String, CaseIterable, Identifiable {
    case morning, afternoon, evening, late, attention, recovered
    var id: String { rawValue }

    var title: String {
        switch self {
        case .morning: "Morning"
        case .afternoon: "Afternoon"
        case .evening: "Evening"
        case .late: "Working late"
        case .attention: "Needs attention"
        case .recovered: "Recovered"
        }
    }

    var period: GreetingPeriod? {
        switch self {
        case .morning: .morning
        case .afternoon: .afternoon
        case .evening: .evening
        case .late: .late
        case .attention, .recovered: nil
        }
    }
}

struct GreetingPreviewRequest: Equatable {
    let id = UUID()
    let scene: GreetingPreviewScene
}

/// What the artwork view shows.
enum GreetingArtScene: Equatable {
    /// A greeting picture; `hold` nil = stays.
    case greeting(GreetingPeriod, hold: Double?)
}

// The artwork is drawn natively (SwiftUI Canvas + TimelineView) — the previous implementation
// played the same drawings in a transparent WKWebView, and WebKit corrupted the window's whole
// compositing whenever the window was resized during playback (artwork and native text rendered
// duplicated, floating outside the window). Shapes and colours are ported one to one from the
// owner-approved SVG/CSS; the loops (spin, breathe, drift, twinkle) and the timed envelope
// (1.5 s in, hold, 1 s out) behave the same.

/// The greeting artwork, drawn natively. A new `playID` replays it. The timeline pauses while
/// `active` is false (the window cannot be seen), under Reduce Motion (a still picture), and once
/// a timed picture has faded (owner review, 30 Sep 2026).
struct GreetingArtView: View {
    let scene: GreetingArtScene
    let playID: Int
    var active = true
    /// Called once a timed picture has faded out (the Overview then removes it).
    var onFinished: (() -> Void)? = nil
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date()
    /// Time spent paused (window hidden) since `start`, so a paused picture resumes where it
    /// stopped instead of jumping ahead by the wall-clock time it was away.
    @State private var pausedTotal: TimeInterval = 0
    /// When the current pause began; nil while playing.
    @State private var pausedAt: Date?
    /// A timed picture has run its course.
    @State private var finished = false
    /// The current timed hold (the evening sun sinks for it); nil in `always` scenes.
    private var hold: Double? {
        if case .greeting(_, let hold) = scene { return hold }
        return nil
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: !active || reduceMotion || finished)) { timeline in
            // Reduce Motion: one settled pose (sun risen, moon out), no envelope motion.
            let t = reduceMotion ? 2.0 : elapsed(at: timeline.date)
            Canvas { ctx, size in
                let s = min(size.width / 301, size.height / 249)
                var ctx = ctx
                ctx.translateBy(x: size.width / 2 - 90 * s, y: size.height / 2 - 64 * s)
                ctx.scaleBy(x: s, y: s)
                draw(&ctx, scene: scene, t: t)
            }
            // The timed envelope: rise + scale in, fade, rise away — as the CSS did. The fade is
            // the view's own opacity, so the date line behind stays visible.
            .scaleEffect(reduceMotion ? 1 : envelopeScale(t, hold: hold), anchor: .bottom)
            .offset(y: reduceMotion ? 0 : envelopeOffset(t, hold: hold))
            .opacity(reduceMotion ? 1 : envelope(t, hold: hold))
        }
        .onAppear { restart() }
        .onChange(of: playID) { _, _ in restart() }
        .onChange(of: active) { _, now in
            if !now {
                if pausedAt == nil { pausedAt = Date() }
            } else if let began = pausedAt {
                pausedTotal += Date().timeIntervalSince(began)
                pausedAt = nil
            }
        }
        .task(id: PlayState(playID: playID, active: active)) {
            // Stop redrawing once a timed picture has faded out: counted in playing time, so the
            // wait starts over (with what is left) each time the window comes back.
            guard let hold, active, !finished else { return }
            let remaining = 1.5 + hold + 1 - elapsed(at: Date())
            if remaining > 0 { try? await Task.sleep(for: .seconds(remaining)) }
            if !Task.isCancelled {
                finished = true
                onFinished?()
            }
        }
        .allowsHitTesting(false)
    }

    private struct PlayState: Equatable {
        let playID: Int
        let active: Bool
    }

    private func restart() {
        start = Date()
        pausedTotal = 0
        pausedAt = active ? nil : start
        finished = false
    }

    /// Seconds of playing time since `start` (paused spans left out).
    private func elapsed(at date: Date) -> Double {
        let now = pausedAt.map { min($0, date) } ?? date
        return max(0, now.timeIntervalSince(start) - pausedTotal)
    }

    private func envelopeScale(_ t: Double, hold: Double?) -> CGFloat {
        guard let hold, t < 1.5 + hold + 1 else { return 1 }
        if t < 1.5 { return CGFloat(0.92 + 0.08 * ease(t / 1.5)) }
        if t < 1.5 + hold { return 1 }
        return CGFloat(1 - 0.03 * ease((t - 1.5 - hold)))
    }
    private func envelopeOffset(_ t: Double, hold: Double?) -> CGFloat {
        // Canvas y grows down: start 22 below (22), rise to 0; the exit moves 8 up (-8).
        guard let hold else { return CGFloat((1 - ease(min(1, t / 1.5))) * 22) }
        if t < 1.5 { return CGFloat((1 - ease(t / 1.5)) * 22) }
        if t < 1.5 + hold { return 0 }
        return CGFloat(-ease(t - 1.5 - hold) * 8)
    }
    private func ease(_ p: Double) -> Double { 1 - pow(1 - min(max(p, 0), 1), 3) }

    /// The timed envelope (a `hold` scene fades out at the end; `always` stays).
    private func envelope(_ t: Double, hold: Double?) -> CGFloat {
        guard let hold else { return CGFloat(min(1, t / 1.5)) }
        let total = 1.5 + hold + 1
        guard t < total else { return 0 }
        if t < 1.5 { return CGFloat(t / 1.5) }
        if t < 1.5 + hold { return 1 }
        return CGFloat(1 - (t - 1.5 - hold))
    }

    private func draw(_ ctx: inout GraphicsContext, scene: GreetingArtScene, t: Double) {
        switch scene {
        case .greeting(let period, _):
            switch period {
            case .morning: morning(&ctx, t: t)
            case .afternoon: afternoon(&ctx, t: t)
            case .evening: evening(&ctx, t: t)
            case .late: late(&ctx, t: t)
            }
        }
    }

    // MARK: Helpers (SVG coordinates, y down; Canvas is y down too)

    private func circle(_ cx: CGFloat, _ cy: CGFloat, _ r: CGFloat) -> Path {
        Path(ellipseIn: CGRect(x: cx - r, y: cy - r, width: 2 * r, height: 2 * r))
    }
    private func line(_ x1: CGFloat, _ y1: CGFloat, _ x2: CGFloat, _ y2: CGFloat) -> Path {
        var p = Path(); p.move(to: CGPoint(x: x1, y: y1)); p.addLine(to: CGPoint(x: x2, y: y2)); return p
    }
    private func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> Color {
        Color(red: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
              blue: CGFloat(hex & 0xff) / 255, opacity: alpha)
    }
    /// A soft glow: the blur of the original SVG as a radial gradient fading to nothing.
    private func glow(_ ctx: inout GraphicsContext, _ cx: CGFloat, _ cy: CGFloat, _ r: CGFloat, _ hex: UInt32, _ alpha: CGFloat) {
        ctx.fill(circle(cx, cy, r), with: .radialGradient(
            Gradient(colors: [rgb(hex, alpha), rgb(hex, 0)]), center: CGPoint(x: cx, y: cy),
            startRadius: r * 0.15, endRadius: r))
    }
    private func fill(_ ctx: inout GraphicsContext, _ path: Path, _ hex: UInt32, _ alpha: CGFloat = 1) {
        ctx.fill(path, with: .color(rgb(hex, alpha)))
    }
    private func stroke(_ ctx: inout GraphicsContext, _ path: Path, _ hex: UInt32, _ width: CGFloat = 1.5, _ alpha: CGFloat = 1) {
        ctx.stroke(path, with: .color(rgb(hex, alpha)), style: StrokeStyle(lineWidth: width, lineCap: .round))
    }

    // MARK: Scenes

    private func morning(_ ctx: inout GraphicsContext, t: Double) {
        glow(&ctx, 90, 90, 60, 0xc8e6ec, 0.6)
        let rise = CGFloat(28 - min(1, t / 2) * 28)   // starts 28 below, rises to its place
        glow(&ctx, 90, 96 + rise, 38, 0xfdecb4, 0.55)
        ctx.fill(circle(90, 96 + rise, 24), with: .radialGradient(
            Gradient(colors: [rgb(0xfff5d6), rgb(0xf4c96a)]), center: CGPoint(x: 86, y: 88 + rise),
            startRadius: 0, endRadius: 26))
        stroke(&ctx, line(12, 94.5, 168, 94.5), 0x9fcbd3, 1.4, 0.9)
        let drift = CGFloat(sin(t * 2 * .pi / 6) * 8)
        for (x, y, w, a) in [(30.0, 102.0, 1.6, 0.85), (64.0, 109.0, 1.4, 0.85), (18.0, 116.0, 1.2, 0.6)] {
            stroke(&ctx, line(CGFloat(x) + drift, CGFloat(y), CGFloat(x) + drift + 90, CGFloat(y)), 0xc3dfe5, CGFloat(w), CGFloat(a))
        }
        birds(&ctx, t: t, y: 30)
    }

    private func afternoon(_ ctx: inout GraphicsContext, t: Double) {
        glow(&ctx, 90, 60, 56, 0xfff0c4, 0.7)
        glow(&ctx, 90, 60, 36, 0xfde9a0, CGFloat(0.35 + 0.35 * (sin(t * .pi * 2 / 3.2) + 1) / 2))
        var rays = ctx
        rays.translateBy(x: 90, y: 60)
        rays.rotate(by: .radians(t * 2 * .pi / 30))
        for a in stride(from: 0.0, to: 2 * .pi, by: .pi / 4) {
            var line = Path()
            line.move(to: CGPoint(x: cos(a) * 31, y: sin(a) * 31))
            line.addLine(to: CGPoint(x: cos(a) * 41, y: sin(a) * 41))
            rays.stroke(line, with: .color(rgb(0xf0bf45)), style: StrokeStyle(lineWidth: 1.8, lineCap: .round))
        }
        let pop = CGFloat(min(1, t / 1.5))
        let r = 22 * (0.62 + 0.38 * pop)
        ctx.fill(circle(90, 60, r), with: .radialGradient(
            Gradient(colors: [rgb(0xfff6cc), rgb(0xf5c233)]), center: CGPoint(x: 82, y: 52),
            startRadius: 0, endRadius: r * 1.3))
        let drift = CGFloat(2 - 20 * cos(t * 2 * .pi / 10))
        cloud(&ctx, x: 118 + drift - 10, y: 80)
    }

    private func evening(_ ctx: inout GraphicsContext, t: Double) {
        glow(&ctx, 112, 48, 34, 0x7f6fc0, 0.3)
        glow(&ctx, 90, 92, 46, 0xf39a64, 0.32)
        let sink = hold == nil ? CGFloat(10 + 10 * sin(t * .pi / 4)) : CGFloat(min(1, t / (1.5 + hold!)) * 24)
        glow(&ctx, 90, 80 + sink, 30, 0xf5875a, 0.35)
        // The sun sets behind the horizon: clipped in a copy, since a clip cannot be undone.
        var sun = ctx
        sun.clip(to: Path(CGRect(x: -60, y: -60, width: 301, height: 154)))
        sun.fill(circle(90, 80 + sink, 21), with: .radialGradient(
            Gradient(colors: [rgb(0xffb784), rgb(0xdc4f32)]), center: CGPoint(x: 84, y: 72 + sink),
            startRadius: 0, endRadius: 24))
        stroke(&ctx, line(12, 94.5, 168, 94.5), 0xd9825f, 1.4, 0.95)
        if t > 1.5 {
            var moon = Path(ellipseIn: CGRect(x: 141 - 10.5, y: 31 - 10.5, width: 21, height: 21))
            moon = moon.subtracting(Path(ellipseIn: CGRect(x: 146 - 9.5, y: 27 - 9.5, width: 19, height: 19)))
            fill(&ctx, moon, 0xf0e6cc)
        }
        for (x, y, r, d) in [(114.0, 18.0, 1.5, 0.0), (165.0, 54.0, 1.3, 0.8)] {
            let a = 0.2 + 0.8 * abs(sin(t * .pi + d))
            fill(&ctx, circle(CGFloat(x), CGFloat(y), CGFloat(r)), 0xecdca8, CGFloat(a))
        }
    }

    private func late(_ ctx: inout GraphicsContext, t: Double) {
        glow(&ctx, 90, 64, 50, 0x2a3163, 0.55)
        var moon = ctx
        let rock = CGFloat(sin(t * 2 * .pi / 8) * 3 * .pi / 180)
        moon.translateBy(x: 84, y: 66)
        moon.rotate(by: .radians(rock))
        moon.translateBy(x: -84, y: -66)
        var crescent = Path(ellipseIn: CGRect(x: 84 - 32, y: 66 - 32, width: 64, height: 64))
        crescent = crescent.subtracting(Path(ellipseIn: CGRect(x: 104 - 25, y: 58 - 25, width: 50, height: 50)))
        moon.fill(crescent, with: .color(rgb(0xf2e7c8)))
        stroke(&moon, line(63, 57, 72, 57), 0x8c7a55, 1.7, 0.9)
        let drift = CGFloat(sin(t * 2 * .pi / 10) * 8)
        cloud(&ctx, x: 60 + drift, y: 106, dark: true)
        for (x, y, d) in [(30.0, 40.0, 0.0), (150.0, 30.0, 1.1), (120.0, 90.0, 2.0)] {
            let a = 0.2 + 0.7 * abs(sin(t * 1.5 + d))
            fill(&ctx, circle(CGFloat(x), CGFloat(y), 1.6), 0xecdca8, CGFloat(a))
        }
    }

    private func cloud(_ ctx: inout GraphicsContext, x: CGFloat, y: CGFloat, dark: Bool = false) {
        let hex: UInt32 = dark ? 0x4a4860 : 0xeef1f5
        fill(&ctx, circle(x, y, 9), hex)
        fill(&ctx, circle(x - 12, y + 4, 7), hex)
        fill(&ctx, circle(x + 10, y - 4, 8), hex)
        fill(&ctx, circle(x, y + 2, 14), hex)
    }

    private func birds(_ ctx: inout GraphicsContext, t: Double, y: CGFloat) {
        let p = (t / 9).truncatingRemainder(dividingBy: 1)
        let x = 34 + 116 * CGFloat(p), yy = y + 20 - 26 * CGFloat(p)
        let flap = CGFloat(abs(sin(t * 2 * .pi / 0.7))) * 0.65 + 0.35
        for (dx, dy, s) in [(0.0, 0.0, 1.0), (15.0, -7.0, 0.8)] {
            var wing = Path()
            wing.move(to: CGPoint(x: x + dx, y: yy + dy))
            wing.addQuadCurve(to: CGPoint(x: x + dx + 12 * s, y: yy + dy),
                              control: CGPoint(x: x + dx + 6 * s, y: yy + dy - 6 * s * flap))
            ctx.stroke(wing, with: .color(rgb(0x6f8791)), style: StrokeStyle(lineWidth: 1.3, lineCap: .round))
        }
    }
}

