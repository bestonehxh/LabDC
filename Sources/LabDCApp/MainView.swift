import AppKit
import LabDCCore
import SwiftUI

/// Sidebar (domain, status, the pages as words; Settings at the bottom) and the selected page.
/// Quiet look: no icons, the sidebar one shade off the page, the selected page in ink.
struct MainView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // Owner, 28 Sep 2026: no bar across the top and no sidebar toggle; the sidebar is always
        // there. A plain row instead of NavigationSplitView (which always brings a toolbar); the
        // window has no title bar, so its buttons sit over the sidebar.
        HStack(spacing: 0) {
            Sidebar()
                .frame(width: 220)
                .frame(maxHeight: .infinity)
                .background(Theme.sidebar.ignoresSafeArea())
            DetailPage(item: model.selection ?? .overview)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Theme.background.ignoresSafeArea())
        }
        .alert("LabDC", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.alert ?? "")
        }
    }
}

struct Sidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SidebarHeader()
                .padding(.bottom, 32)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(SidebarItem.allCases) { item in
                    SidebarLink(title: item.title, selected: (model.selection ?? .overview) == item) {
                        model.selection = item
                    }
                }
            }
            Spacer(minLength: 24)
            SettingsLink {
                Text("Settings")
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .padding(.vertical, 6)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(.top, 40)
        .padding(.leading, 28)
        .padding(.trailing, 16)
        .padding(.bottom, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// One page in the sidebar: a word, ink and medium weight when selected.
struct SidebarLink: View {
    let title: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? Theme.ink : Theme.muted)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Status only: domain name, then Running / Starting… / what needs attention. No switches.
struct SidebarHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let status = model.controller.status
        let problem = status.phase == .problem || !status.problems.isEmpty
        VStack(alignment: .leading, spacing: 4) {
            Text(status.dnsDomain ?? "LabDC")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Theme.ink)
                .lineLimit(1)
            Text(problem ? "Needs attention" : status.headline)
                .font(Theme.detail)
                .foregroundStyle(problem ? Theme.attention : Theme.muted)
                .lineLimit(1)
            if let label = status.advertisedLabel {
                Text(label)
                    .font(Theme.caption.monospacedDigit())
                    .foregroundStyle(Theme.faint)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .help(status.servicesTooltip)
        .accessibilityElement(children: .combine)
    }
}

struct DetailPage: View {
    let item: SidebarItem

    var body: some View {
        switch item {
        case .overview:
            OverviewView()
        case .services:
            ServicesView()
        case .groupPolicy:
            GroupPolicyView()
        case .users:
            UsersView()
        case .radius:
            RadiusView()
        case .dhcp:
            DHCPView()
        case .certificates:
            CertificatesView()
        case .activity:
            ActivityView()
        case .connect:
            ConnectView()
        }
    }
}

extension EnvironmentValues {
    /// True while `--smoke` renders pages off-screen (opaque backgrounds instead of materials).
    @Entry var smokeRendering = false
    /// `--smoke`: the person inspector opens with More details and Advanced shown.
    @Entry var smokeExpandInspector = false
}
