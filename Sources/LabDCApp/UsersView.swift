import AppKit
import LabDCCore
import Store
import SwiftUI

/// UI-2 Users in the Quiet look: the page title with "Add a person", text tabs People / Groups /
/// Computers and a Search line, then the folder (OU) tree as a narrow text column, the list, and
/// the inspector on the right. Every change saves at once ("Saved"), moves are undoable with ⌘Z.
struct UsersView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.undoManager) private var undoManager
    @State private var sheet: UsersSheet?
    @State private var confirmDelete = false
    @FocusState private var searchFocused: Bool

    private var model: UsersModel { app.usersModel }

    var body: some View {
        @Bindable var model = model
        // Plain columns (no `.inspector`, no minimum width on the list): with those, AppKit throws
        // "more Update Constraints in Window passes than there are views" on macOS 26.
        QuietPage(title: "Directory", scrolls: false) {
            UsersActions(sheet: $sheet)
        } content: {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline, spacing: 24) {
                    TabPicker()
                    Spacer(minLength: 16)
                    QuietTextField("Search", text: $model.search, prompt: "Search")
                        .textFieldStyle(.quiet)
                        .focused($searchFocused)
                        .frame(width: 200)
                        .accessibilityLabel("Search: \(searchPrompt)")
                        .help(searchPrompt)
                }
                .padding(.bottom, 20)
                HStack(alignment: .top, spacing: 0) {
                    VStack(alignment: .leading, spacing: 0) {
                        FolderFilter(sheet: $sheet)
                            .padding(.bottom, 14)
                        ObjectTable(confirmDelete: $confirmDelete)
                            .padding(.trailing, 20)
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                    }
                    UsersInspector(sheet: $sheet, confirmDelete: $confirmDelete)
                        .padding(.leading, 24)
                        .frame(width: 320)
                        .frame(maxHeight: .infinity, alignment: .top)
                        .overlay(alignment: .leading) {
                            Rectangle().fill(Theme.line).frame(width: 1)
                        }
                }
                .frame(maxHeight: .infinity, alignment: .top)
            }
        }
        .background {
            // ⌘F puts the cursor in Search (what `.searchable` in the toolbar did).
            Button("Search") { searchFocused = true }
                .keyboardShortcut("f", modifiers: .command)
                .opacity(0)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
        .overlay(alignment: .bottom) {
            SavedPill(generation: model.savedGeneration).padding(.bottom, 34)
        }
        .sheet(item: $sheet) { which in
            UsersSheetView(which: which)
        }
        .confirmationDialog(model.deleteQuestion, isPresented: $confirmDelete) {
            Button(model.tab == .computers ? "Remove from Domain" : "Delete", role: .destructive) {
                let ids = model.deletableSelection
                Task { await model.perform { try await $0.delete(ids) } }
            }
        } message: {
            Text(model.deleteExplanation)
        }
        .alert("Directory", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.error ?? "")
        }
        .task(id: app.controller.store.map(ObjectIdentifier.init)) {
            let log = app.controller.serveLog
            await model.attach(store: app.controller.store) { log.event("Store", $0) }
        }
        .onAppear { model.undoManager = undoManager }
        .onChange(of: undoManager) { _, new in model.undoManager = new }
    }

    private var searchPrompt: String {
        switch model.tab {
        case .people: "Name or username"
        case .groups: "Group name"
        case .computers: "Name or DNS name"
        }
    }
}

/// Sheets of the page.
enum UsersSheet: Identifiable, Equatable {
    case newUser(folder: ObjectID?)
    case newGroup(folder: ObjectID?)
    case newFolder(parent: ObjectID)
    case renameFolder(ObjectID)
    case password(ObjectID)

    var id: String {
        switch self {
        case .newUser: "newUser"
        case .newGroup: "newGroup"
        case .newFolder: "newFolder"
        case .renameFolder(let id): "rename-\(id)"
        case .password(let id): "password-\(id)"
        }
    }
}

// MARK: - Page actions

/// Right of the title: "Add a person" (People) or "Add a group" (Groups).
private struct UsersActions: View {
    @Environment(AppModel.self) private var app
    @Binding var sheet: UsersSheet?

    var body: some View {
        let model = app.usersModel
        switch model.tab {
        case .people:
            Button("Add a person") { sheet = .newUser(folder: model.newObjectFolder) }
                .buttonStyle(.quietLink)
                .help("New person")
        case .groups:
            Button("Add a group") { sheet = .newGroup(folder: model.newObjectFolder) }
                .buttonStyle(.quietLink)
                .help("New group")
        case .computers:
            EmptyView()
        }
    }
}

/// People / Groups / Computers as text tabs.
struct TabPicker: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        let model = app.usersModel
        QuietTabs(items: UsersModel.Tab.allCases.map { ($0, $0.title) },
                  selection: Binding(get: { model.tab }, set: { model.tab = $0 }))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("People, Groups or Computers")
    }
}

// MARK: - Folder tree

/// The folders (OUs) as a narrow column of words: nesting by indentation, the chosen one in ink,
/// counts in faint. Click a chosen folder again to fold or unfold it; drop rows onto a folder to
/// move them.
/// The folder filter as one row of quiet chips (owner, 28 Sep 2026: the AD folder tree made the
/// page read as structure first; folders matter rarely in a lab). The chips keep everything the
/// tree did: click to show a folder, drag rows onto a chip to move, right-click to manage.
struct FolderFilter: View {
    @Environment(AppModel.self) private var app
    @Binding var sheet: UsersSheet?
    @State private var confirmDeleteFolder: DirectoryFolder?

    var body: some View {
        let model = app.usersModel
        let counts = folderCounts(model)
        HStack(alignment: .center, spacing: 20) {
            // Many folders scroll sideways instead of truncating, and New folder stays on one
            // line at the end (owner, 2 Oct 2026: wrapped at 1280 pt).
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(alignment: .firstTextBaseline, spacing: 20) {
                    if model.loaded {
                        ForEach(visibleFolders(model), id: \.folder.id) { item in
                            FolderChip(folder: item.folder, count: counts[item.folder.id] ?? 0,
                                       acceptsTab: item.folder.accepts(tab: model.tab.rawValue),
                                       sheet: $sheet, confirmDelete: $confirmDeleteFolder)
                                .fixedSize()
                        }
                    }
                }
            }
            .layoutPriority(0)
            Button("New folder") { sheet = .newFolder(parent: model.newFolderParent) }
                .buttonStyle(.quietLink)
                .fixedSize()
                .layoutPriority(1)
                .padding(.trailing, 16)  // clear of the inspector's divider (UI audit)
                .help("New folder (OU) in \(model.currentFolder.canHoldFolders ? model.currentFolder.name : model.snapshot.dnsDomain)")
        }
        .padding(.bottom, 2)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Folders")
        .confirmationDialog("Delete the folder \(confirmDeleteFolder?.name ?? "")?",
                            isPresented: Binding(get: { confirmDeleteFolder != nil }, set: { if !$0 { confirmDeleteFolder = nil } }),
                            presenting: confirmDeleteFolder) { folder in
            Button("Delete", role: .destructive) {
                let id = folder.id
                Task { await model.perform { try await $0.deleteFolder(id) } }
            }
        } message: { _ in
            Text("The folder is empty.")
        }
    }

    /// Every folder, flat and in tree order (nested folders keep their chain in the name).
    private func visibleFolders(_ model: UsersModel) -> [(folder: DirectoryFolder, depth: Int)] {
        var out: [(folder: DirectoryFolder, depth: Int)] = []
        func walk(_ f: DirectoryFolder, _ depth: Int, _ chain: String) {
            let name = f.kind == .domain ? f.name : (chain.isEmpty ? f.name : chain + " ▸ " + f.name)
            out.append((folder: f, depth: depth))
            for c in f.children ?? [] { walk(c, depth + 1, f.kind == .domain ? "" : name) }
        }
        walk(model.snapshot.root, 0, "")
        return out
    }

    /// Objects of the current tab directly in each folder (everything for the domain).
    private func folderCounts(_ model: UsersModel) -> [ObjectID: Int] {
        let parents: [ObjectID?]
        switch model.tab {
        case .people: parents = model.snapshot.people.map(\.parentID)
        case .groups: parents = model.snapshot.groups.map(\.parentID)
        case .computers: parents = model.snapshot.computers.map(\.parentID)
        }
        var counts: [ObjectID: Int] = [:]
        for parent in parents {
            if let parent { counts[parent, default: 0] += 1 }
        }
        counts[model.snapshot.root.id] = parents.count
        return counts
    }
}

/// One chip: the folder's name, its count, the drop target, the menu.
private struct FolderChip: View {
    @Environment(AppModel.self) private var app
    let folder: DirectoryFolder
    let count: Int
    /// False when the folder cannot hold this tab's objects (Users with Computers open): dim.
    var acceptsTab = true
    @Binding var sheet: UsersSheet?
    @Binding var confirmDelete: DirectoryFolder?
    @State private var targeted = false

    var body: some View {
        let model = app.usersModel
        let selected = (model.folderID ?? model.snapshot.root.id) == folder.id
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(folder.kind == .domain ? "All folders" : folder.name)
                .font(.system(size: 13, weight: selected ? .medium : .regular))
                .foregroundStyle(acceptsTab ? (selected ? Theme.ink : Theme.muted) : Theme.faint.opacity(0.55))
                .underline(selected, color: Theme.faint)
                .lineLimit(1)
            if count > 0 {
                Text("\(count)")
                    .font(Theme.caption.monospacedDigit())
                    .foregroundStyle(Theme.faint.opacity(acceptsTab ? 1 : 0.55))
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onTapGesture { if acceptsTab { model.folderID = folder.id } }
        .help(!acceptsTab
              ? "\(folder.name) cannot hold \(model.tab.title.lowercased())"
              : (folder.kind == .domain ? folder.name : folder.path))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(folder.kind == .domain ? "All folders, \(folder.name)" : "Folder \(folder.path)")
        .accessibilityValue("\(count)")
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { model.folderID = folder.id }
        .dropDestination(for: DraggedObjects.self) { items, _ in
            let ids = items.flatMap(\.ids)
            guard !ids.isEmpty, acceptsTab, folder.kind != .domain else { return false }
            Task { await model.move(ids, to: folder.id) }
            return true
        } isTargeted: { targeted = $0 && acceptsTab && folder.kind != .domain }
        .background(targeted ? Theme.inset : Color.clear, in: RoundedRectangle(cornerRadius: 4))
        .contextMenu {
            Button("New folder…") { sheet = .newFolder(parent: folder.canHoldFolders ? folder.id : model.snapshot.root.id) }
            if folder.isEditable {
                Button("Rename…") { sheet = .renameFolder(folder.id) }
                Button("Delete…", role: .destructive) { confirmDelete = folder }
                    .disabled(!model.snapshot.isEmpty(folder: folder.id))
            }
        }
    }
}

struct ObjectTable: View {
    @Environment(AppModel.self) private var app
    @Binding var confirmDelete: Bool

    var body: some View {
        let model = app.usersModel
        VStack(alignment: .leading, spacing: 0) {
            switch model.tab {
            case .people: PeopleTable()
            case .groups: GroupsTable()
            case .computers: ComputersTable()
            }
            if !model.footer.isEmpty {
                Text(model.footer)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.faint)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 12)
                    .accessibilityLabel(model.footer)
            }
        }
        .onDeleteCommand { if !model.deletableSelection.isEmpty { confirmDelete = true } }
    }
}

private struct PeopleTable: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        @Bindable var model = app.usersModel
        let columns: [ListColumn<DirectoryPerson>] = [
            ListColumn("Name", sort: .text("Name", \DirectoryPerson.displayName)),
            ListColumn("Username", width: 120, drop: 3, sort: .text("Username", \DirectoryPerson.username)),
            ListColumn("Groups", drop: 1, sort: .text("Groups", \DirectoryPerson.groupsText)),
            ListColumn("Status", width: 68, drop: 4, sort: .value("Status", \DirectoryPerson.statusText)),
        ]
        FittedColumns(columns) { columns in
        VStack(alignment: .leading, spacing: 0) {
            ColumnHeader(columns: columns, order: $model.peopleOrder)
            ObjectList(rows: model.people, label: "People",
                       empty: model.loaded ? "Nobody here." : "Waiting for the directory…") { p, selected in
                let status = p.status(now: model.now)
                let off = status == .disabled
                ColumnRow(columns: columns) { index in
                    switch index {
                    case 0: Text(p.displayName).foregroundStyle(off ? Theme.faint : Theme.ink)
                            .fontWeight(selected ? .medium : .regular)
                    case 1: Text(p.username).foregroundStyle(off ? Theme.faint : Theme.muted)
                    case 2: Text(p.groupNames.isEmpty ? "" : p.groupsShort)  // blank, not "None" (UI audit)
                            .foregroundStyle(off || p.groupNames.isEmpty ? Theme.faint : Theme.muted)
                            .help(p.groupsText)
                    case 3: Text(status.rawValue)
                            .foregroundStyle(status == .expired ? Theme.attention : (off ? Theme.faint : Theme.muted))
                    default: Text(p.lastLogon.map(UsersFormat.date) ?? "Never")
                            .foregroundStyle(Theme.faint)
                            .monospacedDigit()
                    }
                }
                .help(model.snapshot.folderPath(p.parentID))
            }
        }
        }
    }
}

private struct GroupsTable: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        @Bindable var model = app.usersModel
        let columns: [ListColumn<DirectoryGroup>] = [
            ListColumn("Name", sort: .text("Name", \DirectoryGroup.name)),
            ListColumn("Folder", drop: 1),
            ListColumn("Scope", width: 100, drop: 2, sort: .value("Scope", \DirectoryGroup.scope)),
            ListColumn("Members", width: 60, alignment: .trailing, drop: 3, sort: .value("Members", \DirectoryGroup.memberCount)),
        ]
        FittedColumns(columns) { columns in
        VStack(alignment: .leading, spacing: 0) {
            ColumnHeader(columns: columns, order: $model.groupOrder)
            ObjectList(rows: model.groups, label: "Groups",
                       empty: model.loaded ? "No groups here." : "Waiting for the directory…") { g, selected in
                ColumnRow(columns: columns) { index in
                    switch index {
                    case 0: Text(g.name).foregroundStyle(Theme.ink).fontWeight(selected ? .medium : .regular)
                    case 1: Text(model.snapshot.folderPath(g.parentID)).foregroundStyle(Theme.muted)
                    case 2: Text(g.scope.title).foregroundStyle(Theme.muted)
                    default: Text("\(g.memberCount)").foregroundStyle(Theme.muted).monospacedDigit()
                    }
                }
            }
        }
        }
    }
}

private struct ComputersTable: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        @Bindable var model = app.usersModel
        let columns: [ListColumn<DirectoryComputer>] = [
            ListColumn("Name", sort: .text("Name", \DirectoryComputer.name)),
            ListColumn("DNS name", drop: 4, sort: .text("DNS name", \DirectoryComputer.dnsText)),
            ListColumn("OS", drop: 1, sort: .text("OS", \DirectoryComputer.osText)),
            ListColumn("Status", width: 84, drop: 3),
            ListColumn("Last sign-in", width: 92, alignment: .trailing, drop: 2, sort: .value("Last sign-in", \DirectoryComputer.lastLogonKey)),
        ]
        FittedColumns(columns) { columns in
        VStack(alignment: .leading, spacing: 0) {
            ColumnHeader(columns: columns, order: $model.computerOrder)
            ObjectList(rows: model.computers, label: "Computers",
                       empty: model.loaded ? "No computers here." : "Waiting for the directory…") { c, selected in
                let off = !c.enabled
                ColumnRow(columns: columns) { index in
                    switch index {
                    case 0: Text(c.name).foregroundStyle(off ? Theme.faint : Theme.ink).fontWeight(selected ? .medium : .regular)
                    case 1: Text(c.dnsName ?? c.samAccountName).foregroundStyle(off ? Theme.faint : Theme.muted)
                    case 2: Text(c.osText.isEmpty ? "Unknown" : c.osText).foregroundStyle(Theme.faint)
                    case 3: Text(c.isDomainController ? "Domain controller" : (off ? "Disabled" : "Enabled"))
                            .foregroundStyle(off ? Theme.faint : Theme.muted)
                    default: Text(c.lastLogon.map(UsersFormat.date) ?? "Never").foregroundStyle(Theme.faint).monospacedDigit()
                    }
                }
            }
        }
        }
    }
}

/// One column of a Users table: a fixed width, or nil to share the free space; optional sorting.
private struct ListColumn<Row> {
    let title: String
    var width: CGFloat?
    var alignment: Alignment = .leading
    var sort: SortOption<Row>?
    /// When the table is narrow, columns go in this order (1 first); 0 = always shown.
    var drop: Int
    var hidden = false

    init(_ title: String, width: CGFloat? = nil, alignment: Alignment = .leading, drop: Int = 0,
         sort: SortOption<Row>? = nil) {
        self.title = title
        self.width = width
        self.alignment = alignment
        self.drop = drop
        self.sort = sort
    }

    /// Hides the least important columns until the rest fit `width` (a shared column needs at
    /// least 112 pt), so a narrow window never squeezes the name away (owner, 28 Sep 2026).
    /// With the window minimum at 1260 this never triggers on the Directory pages — it is the
    /// safety net for the Certificates tables.
    static func fit(_ columns: [ListColumn<Row>], width: CGFloat) -> [ListColumn<Row>] {
        var columns = columns
        func needed() -> CGFloat {
            let shown = columns.filter { !$0.hidden }
            return shown.reduce(0) { $0 + ($1.width ?? 112) }
                + ListMetrics.spacing * CGFloat(max(0, shown.count - 1)) + 2 * ListMetrics.inset
        }
        while needed() > width,
              let i = columns.indices.filter({ !columns[$0].hidden && columns[$0].drop > 0 })
                  .min(by: { columns[$0].drop < columns[$1].drop }) {
            columns[i].hidden = true
        }
        return columns
    }
}

/// Measures the table's width and hands its content the columns that fit.
private struct FittedColumns<Row, Content: View>: View {
    let columns: [ListColumn<Row>]
    @ViewBuilder let content: ([ListColumn<Row>]) -> Content

    init(_ columns: [ListColumn<Row>], @ViewBuilder content: @escaping ([ListColumn<Row>]) -> Content) {
        self.columns = columns
        self.content = content
    }

    var body: some View {
        GeometryReader { geo in
            content(ListColumn.fit(columns, width: geo.size.width))
                .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
        }
    }
}

/// The spacing and inset every Users table row and header share, so the columns line up.
private enum ListMetrics {
    static let spacing: CGFloat = 16
    static let inset: CGFloat = 10
}

/// The cells of one row, laid out on the columns' widths.
private struct ColumnRow<Row, Cell: View>: View {
    let columns: [ListColumn<Row>]
    @ViewBuilder let cell: (Int) -> Cell

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: ListMetrics.spacing) {
            ForEach(columns.indices.filter { !columns[$0].hidden }, id: \.self) { i in
                let c = columns[i]
                cell(i)
                    .font(Theme.body)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(minWidth: c.width ?? 0, idealWidth: c.width, maxWidth: c.width ?? .infinity, alignment: c.alignment)
            }
        }
    }
}

/// The column titles above a table: a sortable title in ink with ↑/↓ when it orders the rows;
/// clicking it again reverses.
private struct ColumnHeader<Row>: View {
    let columns: [ListColumn<Row>]
    @Binding var order: [KeyPathComparator<Row>]

    var body: some View {
        let current: AnyKeyPath? = order.first?.keyPath
        let forward = (order.first?.order ?? .forward) == .forward
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: ListMetrics.spacing) {
                ForEach(columns.indices.filter { !columns[$0].hidden }, id: \.self) { i in
                    let c = columns[i]
                    Group {
                        if let option = c.sort {
                            let active = current == option.keyPath
                            Button {
                                order = [option.make(active && forward ? .reverse : .forward)]
                            } label: {
                                Text(active ? "\(c.title) \(forward ? "↓" : "↑")" : c.title)
                                    .font(.system(size: 11, weight: active ? .semibold : .regular))
                                    .foregroundStyle(active ? Theme.ink : Theme.muted)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Sort by \(c.title)")
                            .accessibilityValue(active ? (forward ? "ascending" : "descending") : "")
                            .accessibilityAddTraits(active ? .isSelected : [])
                        } else {
                            Text(c.title).font(.system(size: 11)).foregroundStyle(Theme.muted)
                        }
                    }
                    .lineLimit(1)
                    .frame(minWidth: c.width ?? 0, idealWidth: c.width, maxWidth: c.width ?? .infinity, alignment: c.alignment)
                }
            }
            .padding(.horizontal, ListMetrics.inset)
            .padding(.bottom, 8)
            Rectangle().fill(Theme.line).frame(height: 1)
        }
        .accessibilityElement(children: .contain)
    }
}

private struct SortOption<Row> {
    let title: String
    let keyPath: AnyKeyPath
    let make: (SortOrder) -> KeyPathComparator<Row>

    static func text(_ title: String, _ keyPath: any KeyPath<Row, String> & Sendable) -> SortOption<Row> {
        SortOption(title: title, keyPath: keyPath) { KeyPathComparator(keyPath, comparator: .localizedStandard, order: $0) }
    }

    static func value<Value: Comparable>(_ title: String, _ keyPath: any KeyPath<Row, Value> & Sendable) -> SortOption<Row> {
        SortOption(title: title, keyPath: keyPath) { KeyPathComparator(keyPath, order: $0) }
    }
}

/// The rows of a tab: hairlines between them, the selected ones in medium weight (no system
/// highlight). Click selects, ⌘-click adds or removes, ⇧-click selects a range, ↑/↓ move,
/// ⌘A selects all, rows drag onto a folder.
private struct ObjectList<Row: Identifiable, RowContent: View>: View where Row.ID == ObjectID {
    @Environment(AppModel.self) private var app
    let rows: [Row]
    let label: String
    let empty: String
    let content: (Row, Bool) -> RowContent
    @State private var anchor: ObjectID?
    @FocusState private var focused: Bool

    init(rows: [Row], label: String, empty: String, @ViewBuilder content: @escaping (Row, Bool) -> RowContent) {
        self.rows = rows
        self.label = label
        self.empty = empty
        self.content = content
    }

    var body: some View {
        let model = app.usersModel
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(rows) { row in
                        let selected = model.selection.contains(row.id)
                        VStack(spacing: 0) {
                            content(row, selected)
                                .padding(.horizontal, ListMetrics.inset)
                                .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
                                .background(selected ? Theme.selection : Color.clear)
                                .overlay(alignment: .leading) {
                                    if selected { Rectangle().fill(Theme.ink).frame(width: 2) }
                                }
                            Rectangle().fill(Theme.line).frame(height: 1)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { click(row.id) }
                        .draggable(DraggedObjects(ids: model.dragged(row.id)))
                        .id(row.id)
                        .accessibilityElement(children: .combine)
                        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                        .accessibilityAction { app.usersModel.selection = [row.id] }
                    }
                    if rows.isEmpty {
                        Text(empty)
                            .font(Theme.detail)
                            .foregroundStyle(Theme.faint)
                            .padding(.horizontal, ListMetrics.inset)
                            .padding(.vertical, 12)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollIndicators(.automatic)
            .focusable()
            .focused($focused)
            .focusEffectDisabled()
            .onKeyPress(.downArrow) {
                step(1, proxy: proxy)
                return .handled
            }
            .onKeyPress(.upArrow) {
                step(-1, proxy: proxy)
                return .handled
            }
            .onCommand(#selector(NSText.selectAll(_:))) {
                app.usersModel.selection = Set(rows.map(\.id))
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label)
    }

    private func click(_ id: ObjectID) {
        let model = app.usersModel
        focused = true
        let flags = NSEvent.modifierFlags
        if flags.contains(.command) {
            if model.selection.contains(id) {
                model.selection.remove(id)
            } else {
                model.selection.insert(id)
            }
            anchor = id
        } else if flags.contains(.shift), let anchor,
                  let a = rows.firstIndex(where: { $0.id == anchor }),
                  let b = rows.firstIndex(where: { $0.id == id }) {
            model.selection = Set(rows[min(a, b)...max(a, b)].map(\.id))
        } else {
            model.selection = [id]
            anchor = id
        }
    }

    private func step(_ delta: Int, proxy: ScrollViewProxy) {
        guard !rows.isEmpty else { return }
        let model = app.usersModel
        let current = rows.lastIndex { model.selection.contains($0.id) }
        let next: Int
        if let current {
            next = min(max(current + delta, 0), rows.count - 1)
        } else {
            next = delta > 0 ? 0 : rows.count - 1
        }
        let id = rows[next].id
        model.selection = [id]
        anchor = id
        proxy.scrollTo(id)
    }
}

/// A person's state as a word: nothing when enabled, "Disabled" in faint, "Expired" in the
/// attention colour.
struct StatusText: View {
    let status: DirectoryPerson.Status

    var body: some View {
        if status != .enabled {
            StateText(text: status.rawValue, attention: status == .expired, dimmed: status == .disabled)
        }
    }
}

enum UsersFormat {
    /// `26 Sep 2026`.
    static func day(_ d: Date) -> String { d.formatted(.dateTime.day().month(.abbreviated).year()) }

    /// `26 Sep 14:24` this year, `26 Sep 2025` before.
    static func date(_ d: Date) -> String {
        Calendar.current.isDate(d, equalTo: Date(), toGranularity: .year)
            ? d.formatted(.dateTime.day().month(.abbreviated).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
            : d.formatted(.dateTime.day().month(.abbreviated).year())
    }
}

extension UsersModel {
    /// New folders go into the selected folder when it can hold folders, else the domain.
    var newFolderParent: ObjectID {
        currentFolder.canHoldFolders ? currentFolder.id : snapshot.root.id
    }

    /// New users/groups go into the selected folder (the default container at the domain level).
    var newObjectFolder: ObjectID? {
        currentFolder.kind == .domain || currentFolder.kind == .builtin ? nil : currentFolder.id
    }
}
