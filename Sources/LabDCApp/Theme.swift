import AppKit
import SwiftUI

/// The "Quiet" look (owner, 27 Sep 2026): simple, refined, monochrome, no icons. Hierarchy comes
/// from type size, weight and whitespace; state is written as words; the only colour outside the
/// greeting pictures is a muted red for what went wrong. Every page takes its values from here.
enum Theme {
    // MARK: Colour (light / dark)

    /// Page background: warm ivory / near-black.
    static let background = dynamic(light: 0xFBFAF7, dark: 0x141413)
    /// The sidebar: one step darker (light) or lighter (dark) than the page.
    static let sidebar = dynamic(light: 0xF3F1EC, dark: 0x1B1B1A)
    static let ink = dynamic(light: 0x141414, dark: 0xF1F0EC)
    /// Secondary text: labels, details.
    static let muted = dynamic(light: 0x8A8984, dark: 0x7B7A76)
    /// Tertiary text: times, device names.
    static let faint = dynamic(light: 0xA3A29C, dark: 0x6A6965)
    /// Hairline rules between rows.
    static let line = dynamic(light: 0xE6E4DE, dark: 0x262624)
    /// Field borders and the inactive switch track.
    static let control = dynamic(light: 0xD9D7D0, dark: 0x3A3A38)
    /// The one warning colour: what went wrong, destructive actions.
    static let attention = dynamic(light: 0x9B3B2E, dark: 0xE08A7C)
    /// Inset fill for code and copyable values.
    static let inset = dynamic(light: 0xF1EFEA, dark: 0x1E1E1D)
    /// The selected row of a table (with a 2 pt ink edge on the left).
    static let selection = dynamic(light: 0xEFEDE7, dark: 0x20201F)

    // MARK: Type

    /// The Overview greeting (owner: 52 pt, light).
    static let greetingSize: CGFloat = 52
    static let greeting = Font.system(size: greetingSize, weight: .light, design: .default)
    /// Page titles ("Users", "Certificates"). One scale for the app (owner, 27 Sep 2026):
    /// 28 title · 20 name · 13 body · 11 labels; the Overview greeting stays 52.
    static let pageTitle = Font.system(size: 28, weight: .light)
    /// A name at the top of an inspector ("Alice Anderson").
    static let subtitle = Font.system(size: 20, weight: .regular)
    /// The Overview numbers.
    static let metric = Font.system(size: 30, weight: .regular).monospacedDigit()
    /// Row titles, section titles.
    static let emphasis = Font.system(size: 13, weight: .semibold)
    static let body = Font.system(size: 13)
    static let detail = Font.system(size: 12)
    static let caption = Font.system(size: 11)
    static let mono = Font.system(size: 12, design: .monospaced)

    // MARK: Space

    static let pageInsets = EdgeInsets(top: 40, leading: 48, bottom: 24, trailing: 48)
    static let maxContentWidth: CGFloat = 1400
    static let rowPadding: CGFloat = 10

    private static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let hex = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                           green: CGFloat((hex >> 8) & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        })
    }
}

// MARK: - Page structure

/// The standard page: title (and optional line under it), actions on the right, then content,
/// on the page background with generous margins. No card, no icon.
struct QuietPage<Actions: View, Content: View>: View {
    let title: String
    var subtitle: String?
    var scrolls = true
    @ViewBuilder var actions: Actions
    @ViewBuilder var content: Content

    var body: some View {
        let stack = VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                Text(title)
                    .font(Theme.pageTitle)
                    .tracking(-0.5)
                    .foregroundStyle(Theme.ink)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 16)
                HStack(spacing: 24) { actions }
            }
            if let subtitle {
                Text(subtitle)
                    .font(Theme.body)
                    .foregroundStyle(Theme.muted)
                    .padding(.top, 10)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content
                .padding(.top, 22)
        }
        .padding(Theme.pageInsets)
        .frame(maxWidth: Theme.maxContentWidth, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)

        Group {
            if scrolls {
                ScrollView { stack }
            } else {
                stack.frame(maxHeight: .infinity, alignment: .top)
            }
        }
        .background(Theme.background)
        .navigationTitle(title)
    }
}

extension QuietPage where Actions == EmptyView {
    init(title: String, subtitle: String? = nil, scrolls: Bool = true, @ViewBuilder content: () -> Content) {
        self.init(title: title, subtitle: subtitle, scrolls: scrolls, actions: { EmptyView() }, content: content)
    }
}

/// A row of text tabs ("People  Groups  Computers"): the selected one in ink and medium weight.
struct QuietTabs<Value: Hashable>: View {
    let items: [(Value, String)]
    @Binding var selection: Value

    var body: some View {
        HStack(spacing: 22) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                Button { selection = item.0 } label: {
                    Text(item.1)
                        .font(.system(size: 13, weight: item.0 == selection ? .semibold : .regular))
                        .foregroundStyle(item.0 == selection ? Theme.ink : Theme.muted)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(item.0 == selection ? .isSelected : [])
            }
        }
    }
}

/// A group of rows under a small title: "Recent", "Issued recently".
struct QuietSection<Trailing: View, Content: View>: View {
    let title: String
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(Theme.emphasis).foregroundStyle(Theme.ink).accessibilityAddTraits(.isHeader)
                Spacer(minLength: 12)
                trailing
            }
            .padding(.bottom, 8)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension QuietSection where Trailing == EmptyView {
    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.init(title: title, trailing: { EmptyView() }, content: content)
    }
}

/// One row with a hairline above it (the first row of a list omits the line with `first: true`).
struct QuietRow<Content: View>: View {
    var first = false
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            if !first { Rectangle().fill(Theme.line).frame(height: 1) }
            content
                .padding(.vertical, Theme.rowPadding)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// A label above a value, for inspectors and detail panes.
struct QuietField<Value: View>: View {
    let label: String
    @ViewBuilder var value: Value

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(Theme.caption).foregroundStyle(Theme.muted)
            value.font(Theme.body).foregroundStyle(Theme.ink)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Buttons

/// The default action: a word with a thin underline ("Reset", "Copy", "Restart all services").
struct QuietLinkStyle: ButtonStyle {
    var role: ButtonRole?
    var size: CGFloat = 13
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let color = role == .destructive ? Theme.attention : Theme.ink
        configuration.label
            .font(.system(size: size))
            .foregroundStyle(color)
            .underline(true, color: color.opacity(0.3))
            .opacity(isEnabled ? (configuration.isPressed ? 0.55 : 1) : 0.35)
            .contentShape(Rectangle())
    }
}

/// The single strong action of a screen (wizard Continue, Sign): ink fill, background text.
struct QuietPrimaryStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(Theme.background)
            .padding(.horizontal, 22)
            .padding(.vertical, 10)
            .background(Theme.ink, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.3)
            .contentShape(Rectangle())
    }
}

extension ButtonStyle where Self == QuietLinkStyle {
    static var quietLink: QuietLinkStyle { QuietLinkStyle() }
    static var quietDestructive: QuietLinkStyle { QuietLinkStyle(role: .destructive) }
}

extension ButtonStyle where Self == QuietPrimaryStyle {
    static var quietPrimary: QuietPrimaryStyle { QuietPrimaryStyle() }
}

/// The monochrome switch of Settings (ink when on).
struct QuietToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: 12) {
                configuration.label
                Spacer(minLength: 0)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule().fill(configuration.isOn ? Theme.ink : Theme.control).frame(width: 34, height: 20)
                    Circle().fill(Theme.background).frame(width: 16, height: 16).padding(2)
                }
                .animation(.easeOut(duration: 0.15), value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

extension ToggleStyle where Self == QuietToggleStyle {
    static var quiet: QuietToggleStyle { QuietToggleStyle() }
}

/// A text field with only a line under it (search, wizard fields).
struct QuietFieldStyle: TextFieldStyle {
    var size: CGFloat = 13

    func _body(configuration: TextField<Self._Label>) -> some View {
        VStack(spacing: 4) {
            configuration
                .textFieldStyle(.plain)
                .font(.system(size: size))
                .foregroundStyle(Theme.ink)
            Rectangle().fill(Theme.control).frame(height: 1)
        }
    }
}

extension TextFieldStyle where Self == QuietFieldStyle {
    static var quiet: QuietFieldStyle { QuietFieldStyle() }
}

// MARK: - State as words

/// "Running" / "Disabled" / "Problem: …": text only; the attention colour when something is wrong.
struct StateText: View {
    let text: String
    var attention = false
    var dimmed = false

    var body: some View {
        Text(text)
            .font(Theme.detail)
            .foregroundStyle(attention ? Theme.attention : (dimmed ? Theme.faint : Theme.muted))
    }
}

/// A short note under a section ("Changes are saved as you make them.").
struct QuietNote: View {
    let text: String
    var attention = false

    init(_ text: String, attention: Bool = false) {
        self.text = text
        self.attention = attention
    }

    var body: some View {
        Text(text)
            .font(Theme.caption)
            .foregroundStyle(attention ? Theme.attention : Theme.faint)
            .fixedSize(horizontal: false, vertical: true)
    }
}
