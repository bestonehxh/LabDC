import AppKit
import LabDCCore
import SwiftUI

/// A Copy link that says "Copied" for a moment.
struct CopyButton: View {
    let value: String
    var label = "Copy"
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(value, forType: .string)
            copied = true
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                copied = false
            }
        } label: {
            Text(copied ? "Copied" : label)
                .frame(minWidth: 44, alignment: .trailing)
        }
        .buttonStyle(.quietLink)
        .accessibilityLabel(copied ? "Copied" : "\(label) \(value)")
    }
}

/// The 1-second "Saved" note (no Apply button anywhere).
struct SavedPill: View {
    let generation: Int
    @State private var visible = false
    @State private var shown = 0

    var body: some View {
        Text("Saved")
            .font(Theme.detail)
            .foregroundStyle(Theme.muted)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(Theme.background, in: Capsule())
            .overlay(Capsule().strokeBorder(Theme.line))
            .opacity(visible ? 1 : 0)
            .animation(.easeInOut(duration: 0.2), value: visible)
            .accessibilityHidden(!visible)
            .onChange(of: generation) { _, new in
                guard new > 0 else { return }
                shown = new
                visible = true
                Task {
                    try? await Task.sleep(for: .seconds(1))
                    if shown == new { visible = false }
                }
            }
    }
}

/// A listener as text: `LDAPS 636`, struck through when off, in the attention colour when it failed.
struct ListenerChip: View {
    let status: ListenerStatus

    var body: some View {
        Text(status.chipLabel)
            .font(Theme.caption.monospacedDigit())
            .strikethrough(status.state == .off)
            .foregroundStyle(isFailed ? Theme.attention : Theme.muted)
            .help(help)
            .accessibilityLabel("\(status.listener.displayName), \(help)")
    }

    private var isFailed: Bool {
        if case .failed = status.state { return true }
        return false
    }

    private var help: String {
        switch status.state {
        case .running: "\(status.listener.transport) \(status.port.map(String.init) ?? "?"), listening"
        case .starting: "starting"
        case .failed(let why): why
        case .off: "off in Settings"
        case .stopped: "not running"
        }
    }
}

/// Wraps its children like text.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map { $0.width }.max() ?? 0
        let height = rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(0, rows.count - 1))
        return CGSize(width: proposal.width ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for (i, s) in subviews.enumerated() {
            let size = s.sizeThatFits(.unspecified)
            if !row.indices.isEmpty, row.width + spacing + size.width > width {
                rows.append(row)
                row = Row()
            }
            row.width += (row.indices.isEmpty ? 0 : spacing) + size.width
            row.height = max(row.height, size.height)
            row.indices.append(i)
        }
        if !row.indices.isEmpty { rows.append(row) }
        return rows
    }
}

/// A section of a page: a title and its content, no background (the Quiet look has no cards).
struct Card<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(Theme.emphasis).foregroundStyle(Theme.ink).accessibilityAddTraits(.isHeader)
            content
        }
        .padding(.vertical, 18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
        .accessibilityElement(children: .contain)
    }
}

extension Date {
    /// `14:02:11` today, `25 Sep 14:02` before.
    var activityStamp: String {
        Calendar.current.isDateInToday(self)
            ? formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))
            : formatted(.dateTime.day().month(.abbreviated).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
    }
}
