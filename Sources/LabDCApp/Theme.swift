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
    static let control = dynamic(light: 0xD9D7D0, dark: 0x4A4946)  // dark: off switches and field lines were lost on the page (UI audit)
    /// The one warning colour: what went wrong, destructive actions.
    static let attention = dynamic(light: 0x9B3B2E, dark: 0xE08A7C)
    /// An action waiting to be taken (Group Policy ▸ Publish changes): the icon's bubble green.
    static let go = dynamic(light: 0x2F7D4E, dark: 0x6FCB92)
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
    /// Overrides the ink (or attention) colour, e.g. `Theme.go` for a pending action.
    var tint: Color?
    var weight: Font.Weight = .regular
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let color = tint ?? (role == .destructive ? Theme.attention : Theme.ink)
        configuration.label
            .font(.system(size: size, weight: weight))
            .foregroundStyle(color)
            .underline(true, color: color.opacity(0.3))
            .opacity(isEnabled ? (configuration.isPressed ? 0.55 : 1) : 0.35)
            .contentShape(Rectangle())
    }
}

/// The single strong action of a screen (wizard Continue, Sign): ink fill, background text.
struct QuietPrimaryStyle: ButtonStyle {
    /// A primary action that destroys something (Revoke): the attention colour instead of ink.
    var destructive = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(Theme.background)
            .padding(.horizontal, 22)
            .padding(.vertical, 10)
            .background(destructive ? Theme.attention : Theme.ink, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
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
    /// Monospaced, for values read character by character (a password, a shared secret). The
    /// style sets the font, so a `.font(...monospaced())` on the field itself has no effect.
    var monospaced = false

    func _body(configuration: TextField<Self._Label>) -> some View {
        VStack(spacing: 4) {
            // The placeholder: plain fields draw it nearly as dark as the value, so an empty
            // field's example ("10.20.0.150-10.20.0.159", "this DC") looked like a saved value.
            // Every quiet field passes `prompt: Text(…).foregroundStyle(Theme.faint)` (UI audit,
            // 2 Oct 2026).
            configuration
                .textFieldStyle(.plain)
                .font(.system(size: size, design: monospaced ? .monospaced : .default))
                .foregroundStyle(Theme.ink)
            Rectangle().fill(Theme.control).frame(height: 1)
        }
    }
}

/// A text field whose example ("10.20.0.1", "this DC") is drawn in the faint colour. Built
/// against the macOS 26 SDK, a plain field draws its placeholder nearly as dark as a value and
/// ignores a styled `prompt:`, so an empty field looked filled in (UI audit, 2 Oct 2026): the
/// example is drawn here, over the empty field, instead. Use with `.textFieldStyle(.quiet)`.
struct QuietTextField: View {
    let title: String
    @Binding var text: String
    let prompt: String
    var axis: Axis = .horizontal
    var secure = false

    /// The style's face (`.quietMonospaced` sets it), so the example is drawn in the same face
    /// as a value typed over it.
    @Environment(\.quietFieldMonospaced) private var monospaced
    private let hasExample: Bool

    /// `title` is the field's name (what VoiceOver reads); `prompt` is the example drawn faint
    /// in the empty field, and read as the hint.
    init(_ title: String, text: Binding<String>, prompt: String? = nil, axis: Axis = .horizontal, secure: Bool = false) {
        self.title = title
        _text = text
        self.prompt = prompt ?? title
        hasExample = !(prompt ?? "").isEmpty && prompt != title
        self.axis = axis
        self.secure = secure
    }

    var body: some View {
        Group {
            if secure {
                SecureField(title, text: $text, prompt: Text(verbatim: ""))
            } else {
                TextField(title, text: $text, prompt: Text(verbatim: ""), axis: axis)
            }
        }
        .overlay(alignment: .topLeading) {
            if text.isEmpty {
                Text(verbatim: prompt)
                    .font(.system(size: 13, design: monospaced ? .monospaced : .default))
                    .foregroundStyle(Theme.faint)
                    .lineLimit(1)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
        }
        .accessibilityHint(hasExample ? prompt : "")
    }
}

private struct QuietFieldMonospacedKey: EnvironmentKey {
    static let defaultValue = false
}

extension EnvironmentValues {
    /// Set by `.textFieldStyle(.quietMonospaced)` around the field, so `QuietTextField` draws its
    /// example in the monospaced face too.
    var quietFieldMonospaced: Bool {
        get { self[QuietFieldMonospacedKey.self] }
        set { self[QuietFieldMonospacedKey.self] = newValue }
    }
}

extension View {
    /// `.textFieldStyle(.quiet)` / `.textFieldStyle(.quietMonospaced)`: also tells a
    /// `QuietTextField` inside which face the style uses, so its example is drawn in that face
    /// (a monospaced field's example was drawn proportional). Preferred over SwiftUI's generic
    /// `textFieldStyle(_:)` for this one style type.
    func textFieldStyle(_ style: QuietFieldStyle) -> some View {
        applyingTextFieldStyle(style).environment(\.quietFieldMonospaced, style.monospaced)
    }

    /// SwiftUI's generic `textFieldStyle(_:)` (a generic context, so not the overload above).
    private func applyingTextFieldStyle<S: TextFieldStyle>(_ style: S) -> some View {
        textFieldStyle(style)
    }
}

extension TextFieldStyle where Self == QuietFieldStyle {
    static var quiet: QuietFieldStyle { QuietFieldStyle() }
    static var quietMonospaced: QuietFieldStyle { QuietFieldStyle(monospaced: true) }
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

// MARK: - Sheets

/// The one layout of every add / edit sheet (UI audit, 2 Oct 2026): the title (and an optional
/// muted line under it) at the top, the fields under it — each label above its field, pickers
/// left-aligned under their label — scrolling when they are taller than the window allows, then
/// the failure (attention colour), and the footer: an optional quiet note on the left, Cancel
/// and the primary action at the bottom right. The footer never scrolls away.
struct QuietSheet<Content: View, Actions: View>: View {
    let title: String
    var subtitle: String?
    var width: CGFloat = 480
    /// What went wrong, above the buttons.
    var failure: String?
    /// A note on the left of the footer ("Saved to the list; Publish sends it to Windows.").
    var note: String?
    @ViewBuilder var content: Content
    @ViewBuilder var actions: Actions

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.ink)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                if let subtitle {
                    Text(subtitle)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.top, 22)
            .padding(.bottom, 16)
            SheetScroll {
                VStack(alignment: .leading, spacing: 14) { content }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 2)
            }
            VStack(alignment: .leading, spacing: 12) {
                if let failure {
                    Text(failure)
                        .font(Theme.detail)
                        .foregroundStyle(Theme.attention)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                HStack(alignment: .center, spacing: 20) {
                    if let note {
                        Text(note)
                            .font(Theme.caption)
                            .foregroundStyle(Theme.faint)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    actions
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 16)
            .padding(.bottom, 20)
        }
        .frame(width: width)
        .background(Theme.background)
        .environment(\.inSheet, true)
    }
}

extension EnvironmentValues {
    /// Set by `QuietSheet`: form rows put their label above the control (`GPFormRow`).
    @Entry var inSheet = false
    /// The most a sheet's fields may take before they scroll (nil: from the window; `--smoke` sets it).
    @Entry var sheetContentLimit: CGFloat? = nil
}

/// A sheet's fields at their own height, scrolling only past the limit (the window's height less
/// the sheet's title and footer), with a hairline above the footer while they scroll.
struct SheetScroll<Content: View>: View {
    @Environment(\.sheetContentLimit) private var limit
    @ViewBuilder var content: Content
    @State private var height: CGFloat = 0

    @MainActor static var windowLimit: CGFloat {
        let window = NSApp?.mainWindow ?? NSApp?.windows.first { $0.isVisible && $0.sheetParent == nil }
        return max(260, (window?.frame.height ?? 760) - 190)
    }

    var body: some View {
        let cap = limit ?? Self.windowLimit
        let scrolls = height > cap + 0.5
        ScrollView(.vertical) {
            content
                .fixedSize(horizontal: false, vertical: true)
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { height = $0 }
        }
        .scrollBounceBehavior(.basedOnSize)
        .scrollIndicators(scrolls ? .automatic : .never)
        .frame(height: max(1, min(height, cap)))
        .overlay(alignment: .bottom) {
            if scrolls { Rectangle().fill(Theme.line).frame(height: 1) }
        }
    }
}

/// A sheet field: the label above (caption, muted), the control under it, an optional note.
struct SheetField<Control: View>: View {
    let label: String
    var note: String?
    @ViewBuilder var control: Control

    init(_ label: String, note: String? = nil, @ViewBuilder control: () -> Control) {
        self.label = label
        self.note = note
        self.control = control()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            // No maxWidth here: a narrow field (VLAN, a port) beside a wide one keeps its own
            // width; text fields and `SheetPicker` take the room they need themselves.
            control
            if let note {
                Text(note).font(Theme.caption).foregroundStyle(Theme.faint)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// A sheet's pop-up menu: its natural width, left-aligned under its label.
struct SheetPicker<Value: Hashable, Items: View>: View {
    /// The field's name: hidden on screen (the `SheetField` label above shows it), read by VoiceOver.
    let label: String
    @Binding var selection: Value
    @ViewBuilder var items: Items

    init(_ label: String, selection: Binding<Value>, @ViewBuilder items: () -> Items) {
        self.label = label
        _selection = selection
        self.items = items()
    }

    var body: some View {
        Picker(label, selection: $selection) { items }
            .labelsHidden()
            .pickerStyle(.menu)
            .fixedSize()
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A sheet's on/off line: the words on the left, the quiet switch at the right edge.
struct SheetToggle: View {
    let title: String
    @Binding var isOn: Bool

    init(_ title: String, isOn: Binding<Bool>) {
        self.title = title
        _isOn = isOn
    }

    var body: some View {
        Toggle(isOn: $isOn) {
            Text(title).font(Theme.body).foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
        .toggleStyle(.quiet)
        .frame(maxWidth: .infinity)
    }
}

/// Cancel and the primary action, bottom right (Cancel closes the sheet unless told otherwise).
struct SheetButtons: View {
    @Environment(\.dismiss) private var dismiss
    let primary: String
    var role: ButtonRole?
    var disabled = false
    var cancelTitle = "Cancel"
    var cancel: (() -> Void)?
    let action: () -> Void

    init(_ primary: String, role: ButtonRole? = nil, disabled: Bool = false, cancelTitle: String = "Cancel",
         cancel: (() -> Void)? = nil, action: @escaping () -> Void) {
        self.primary = primary
        self.role = role
        self.disabled = disabled
        self.cancelTitle = cancelTitle
        self.cancel = cancel
        self.action = action
    }

    var body: some View {
        HStack(spacing: 20) {
            Button(cancelTitle, role: .cancel) { if let cancel { cancel() } else { dismiss() } }
                .buttonStyle(.quietLink)
                .keyboardShortcut(.cancelAction)
            Button(primary, role: role, action: action)
                .buttonStyle(QuietPrimaryStyle(destructive: role == .destructive))
                .keyboardShortcut(.defaultAction)
                .disabled(disabled)
        }
    }
}
