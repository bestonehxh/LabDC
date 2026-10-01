import AppKit
import CoreTransferable
import Observation
import LabDCCore
import Store
import SwiftUI
import UniformTypeIdentifiers

/// UI-2: the Users page's state — tab, folder, search, sort, selection — over a
/// `DirectorySnapshot` that `DirectoryEditor` re-reads after every store change (the store's
/// change feed, no polling). Every edit saves at once and bumps `savedGeneration` (the pill).
@MainActor @Observable
final class UsersModel {
    enum Tab: String, CaseIterable, Identifiable {
        case people, groups, computers
        var id: String { rawValue }
        var title: String {
            switch self {
            case .people: "People"
            case .groups: "Groups"
            case .computers: "Computers"
            }
        }
        /// "3 people", "1 group".
        func count(_ n: Int) -> String {
            switch self {
            case .people: n == 1 ? "1 person" : "\(n) people"
            case .groups: n == 1 ? "1 group" : "\(n) groups"
            case .computers: n == 1 ? "1 computer" : "\(n) computers"
            }
        }
    }

    var tab: Tab = .people {
        didSet { if tab != oldValue { selection = [] } }
    }
    private(set) var snapshot: DirectorySnapshot = .empty
    private(set) var loaded = false
    /// The folder shown (nil = the whole domain).
    var folderID: ObjectID? {
        didSet { if folderID != oldValue { selection = selection.filter { visibleIDs.contains($0) } } }
    }
    var search = ""
    var selection: Set<ObjectID> = []
    var peopleOrder = [KeyPathComparator(\DirectoryPerson.displayName, comparator: .localizedStandard)]
    var groupOrder = [KeyPathComparator(\DirectoryGroup.name, comparator: .localizedStandard)]
    var computerOrder = [KeyPathComparator(\DirectoryComputer.name, comparator: .localizedStandard)]
    /// Folders shown expanded in the tree (the domain and its first level start open).
    var expanded: Set<ObjectID> = []
    /// The "Saved" pill.
    private(set) var savedGeneration = 0
    /// The last error, shown as an alert.
    var error: String?
    var showInspector = true
    var now = Date()

    @ObservationIgnored private(set) var editor: DirectoryEditor?
    @ObservationIgnored weak var undoManager: UndoManager?
    @ObservationIgnored private var watch: Task<Void, Never>?
    @ObservationIgnored private var attachedStore: ObjectIdentifier?
    /// The last undo/redo started from the Edit menu (tests await it).
    @ObservationIgnored private(set) var pendingUndo: Task<Void, Never>?

    init() {}

    // MARK: Store

    /// Uses `store` (the embedded server's) and follows its change feed. `log` receives one line
    /// per change for the serve log.
    func attach(store: DirectoryStore?, log: @escaping @Sendable (String) -> Void = { _ in }) async {
        let key = store.map(ObjectIdentifier.init)
        guard key != attachedStore else { return }
        attachedStore = key
        watch?.cancel()
        guard let store else {
            editor = nil
            return
        }
        let editor = DirectoryEditor(store: store, log: log)
        self.editor = editor
        let changes = editor.changes.stream()
        watch = Task { [weak self] in
            for await _ in changes {
                // Coalesce a burst of writes (one LDAP add is several USNs).
                try? await Task.sleep(for: .milliseconds(150))
                guard !Task.isCancelled else { return }
                await self?.reload()
            }
        }
        await reload()
    }

    func reload() async {
        guard let editor else { return }
        do {
            let s = try await editor.snapshot()
            apply(s)
        } catch {
            self.error = "The directory could not be read: \(error)"
        }
    }

    /// Replaces the snapshot, keeping the folder/selection that still exist.
    func apply(_ s: DirectorySnapshot) {
        let first = !loaded
        snapshot = s
        loaded = true
        now = Date()
        if let f = folderID, s.folders[f] == nil { folderID = nil }
        if first {
            expanded = [s.root.id]
            for c in s.root.children ?? [] where c.kind == .organizationalUnit { expanded.insert(c.id) }
        }
        let all = allIDs
        selection = selection.filter { all.contains($0) }
    }

    // MARK: Rows

    private func inFolder(_ parent: ObjectID?) -> Bool {
        guard let folderID, folderID != snapshot.root.id else { return true }
        return parent == folderID
    }

    var people: [DirectoryPerson] {
        snapshot.people.filter { inFolder($0.parentID) && $0.matches(search) }.sorted(using: peopleOrder)
    }

    var groups: [DirectoryGroup] {
        snapshot.groups.filter { inFolder($0.parentID) && $0.matches(search) }.sorted(using: groupOrder)
    }

    var computers: [DirectoryComputer] {
        snapshot.computers.filter { inFolder($0.parentID) && $0.matches(search) }.sorted(using: computerOrder)
    }

    /// Ids of the rows the current tab shows.
    var visibleIDs: Set<ObjectID> {
        switch tab {
        case .people: Set(people.map(\.id))
        case .groups: Set(groups.map(\.id))
        case .computers: Set(computers.map(\.id))
        }
    }

    private var allIDs: Set<ObjectID> {
        Set(snapshot.people.map(\.id)).union(snapshot.groups.map(\.id)).union(snapshot.computers.map(\.id))
    }

    var rowCount: Int { visibleIDs.count }

    var currentFolder: DirectoryFolder { snapshot.folder(folderID) ?? snapshot.root }

    /// Under the table: `Folder (OU): Staff / IT · 3 people`.
    var footer: String {
        let where_ = currentFolder.kind == .domain ? "All folders" : "Folder (OU): \(currentFolder.path)"
        var s = "\(where_) · \(tab.count(rowCount))"
        if tab != .groups { s += " · Drag onto a folder to move, ⌘Z to undo" }
        return s
    }

    // MARK: Inspector

    enum Inspected: Equatable {
        case nothing
        case person(DirectoryPerson)
        case group(DirectoryGroup)
        case computer(DirectoryComputer)
        case several(Int)
    }

    var inspected: Inspected {
        let ids = selection
        if ids.count > 1 { return .several(ids.count) }
        guard let id = ids.first else { return .nothing }
        if let p = snapshot.person(id) { return .person(p) }
        if let g = snapshot.group(id) { return .group(g) }
        if let c = snapshot.computer(id) { return .computer(c) }
        return .nothing
    }

    /// Groups the person is not (directly) in, for the token field's picker.
    func groupsToAdd(for person: DirectoryPerson, matching query: String = "") -> [DirectoryGroup] {
        let current = Set(person.groupIDs)
        return snapshot.groups.filter { !current.contains($0.id) && $0.matches(query) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// A group's members, resolved (people, computers, groups), sorted by kind then name.
    func members(of group: DirectoryGroup) -> [DirectoryMember] {
        group.memberDNs.compactMap { snapshot.member(dn: $0) ?? external($0) }.sorted { a, b in
            if a.kind != b.kind { return a.kind.order < b.kind.order }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }

    private func external(_ dn: DN) -> DirectoryMember? {
        // Members outside the listed folders (a foreign security principal, …): shown by RDN.
        DirectoryMember(id: -1, kind: .group, name: dn.rdn?.value ?? dn.description, detail: dn.description)
    }

    /// Who can join the group: people, computers and other groups not in it yet.
    func candidates(for group: DirectoryGroup, matching query: String = "") -> [DirectoryMember] {
        let inGroup = Set(group.memberDNs)
        var out: [DirectoryMember] = []
        out += snapshot.people.filter { !inGroup.contains($0.dn) && $0.matches(query) }.compactMap { snapshot.member(id: $0.id) }
        out += snapshot.computers.filter { !inGroup.contains($0.dn) && $0.matches(query) }.compactMap { snapshot.member(id: $0.id) }
        out += snapshot.groups.filter { $0.id != group.id && !inGroup.contains($0.dn) && $0.matches(query) }
            .compactMap { snapshot.member(id: $0.id) }
        return out.sorted { a, b in
            if a.kind != b.kind { return a.kind.order < b.kind.order }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }

    /// Selected objects that may be deleted (not built in, not the DC).
    var deletableSelection: [ObjectID] {
        selection.filter { id in
            if let p = snapshot.person(id) { return !p.isCritical }
            if let g = snapshot.group(id) { return !g.isCritical && g.scope != .builtinLocal }
            if let c = snapshot.computer(id) { return !c.isCritical && !c.isDomainController }
            return false
        }.sorted()
    }

    /// "Delete alice?" / "Delete 3 people?"
    var deleteQuestion: String {
        let ids = deletableSelection
        if ids.count == 1, let id = ids.first {
            if let p = snapshot.person(id) { return "Delete \(p.displayName)?" }
            if let g = snapshot.group(id) { return "Delete the group \(g.name)?" }
            if let c = snapshot.computer(id) { return "Remove \(c.name) from the domain?" }
        }
        return "Delete \(tab.count(ids.count))?"
    }

    var deleteExplanation: String {
        switch tab {
        case .people: "They can no longer sign in. This cannot be undone."
        case .groups: "Members stay; only the group goes. This cannot be undone."
        case .computers: "The computer's account is deleted; it has to join the domain again. This cannot be undone."
        }
    }

    // MARK: Changes (saved at once)

    /// Runs one change; on success bumps the Saved pill and re-reads, on failure shows the error
    /// (and re-reads so fields show what is stored). Returns whether it worked.
    @discardableResult
    func perform(_ change: @escaping @Sendable (DirectoryEditor) async throws -> Void) async -> Bool {
        guard let editor else {
            error = "The server is not running."
            return false
        }
        do {
            try await change(editor)
            savedGeneration += 1
            await reload()
            return true
        } catch {
            self.error = Self.sentence(error)
            await reload()
            return false
        }
    }

    /// Moves objects onto a folder (drag and drop, the Folder picker) and registers ⌘Z.
    @discardableResult
    func move(_ ids: [ObjectID], to folderID: ObjectID) async -> Bool {
        guard let editor, let target = snapshot.folders[folderID] else { return false }
        do {
            let moves = try await editor.move(ids, to: target.dn)
            if !moves.isEmpty {
                registerUndo(moves)
                savedGeneration += 1
            }
            await reload()
            return true
        } catch {
            self.error = Self.sentence(error)
            await reload()
            return false
        }
    }

    /// Ids dragged: the whole selection when the dragged row is part of it.
    func dragged(_ id: ObjectID) -> [ObjectID] {
        selection.contains(id) ? selection.sorted() : [id]
    }

    private func registerUndo(_ moves: [DirectoryEditor.Move]) {
        guard let undoManager, !moves.isEmpty else { return }
        undoManager.registerUndo(withTarget: self) { model in
            // Redo is registered at once (during the undo), the store change runs after.
            MainActor.assumeIsolated {
                model.registerUndo(moves.map(\.reversed))
                model.pendingUndo = Task { await model.revert(moves) }
            }
        }
        undoManager.setActionName(moves.count == 1 ? "Move" : "Move \(moves.count) Items")
    }

    /// Puts every moved object back where it was.
    func revert(_ moves: [DirectoryEditor.Move]) async {
        guard let editor else { return }
        do {
            try await editor.undo(moves)
            savedGeneration += 1
        } catch {
            self.error = Self.sentence(error)
        }
        await reload()
    }

    /// A store/CLI error as one sentence.
    static func sentence(_ error: Error) -> String {
        if case CLIError.failure(let why) = error {
            // "the username x is taken" → "The username x is taken."; "sAMAccountName …" stays.
            let first = why.prefix(while: { $0 != " " })
            let text = first == first.lowercased() ? why.prefix(1).uppercased() + why.dropFirst() : why
            return text.hasSuffix(".") ? text : text + "."
        }
        let text = "\(error)"
        if text.contains("passwordPolicy") || text.contains("tooShort") || text.contains("notComplex") {
            return "The password does not meet the domain's rules: \(text)"
        }
        return text
    }

    // MARK: Passwords

    /// A suggestion for the password sheet: 16 characters, upper + lower + digits + symbols,
    /// without look-alikes (0/O, 1/l/I).
    static func suggestPassword(length: Int = 16) -> String {
        let upper = Array("ABCDEFGHJKLMNPQRSTUVWXYZ"), lower = Array("abcdefghijkmnopqrstuvwxyz")
        let digits = Array("23456789"), symbols = Array("!#$%*+-=?@")
        let all = upper + lower + digits + symbols
        var chars = [upper.randomElement()!, lower.randomElement()!, digits.randomElement()!, symbols.randomElement()!]
        while chars.count < max(length, 8) { chars.append(all.randomElement()!) }
        return String(chars.shuffled())
    }

    /// A username from a display name: `Alice Anderson` → `alice`.
    static func suggestUsername(_ displayName: String) -> String {
        let first = displayName.split(separator: " ").first.map(String.init) ?? ""
        let allowed = first.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }
        return String(allowed.prefix(20))
    }
}

extension DirectoryMember.Kind {
    var order: Int {
        switch self {
        case .person: 0
        case .computer: 1
        case .group: 2
        }
    }
}

// MARK: - Sort keys for the tables

extension DirectoryPerson {
    var statusText: String { status().rawValue }
    var lastLogonKey: Date { lastLogon ?? .distantPast }
    /// `Domain Admins +4`: the first group and how many more.
    var groupsShort: String {
        guard let first = groupNames.first else { return "" }
        return groupNames.count > 1 ? "\(first) +\(groupNames.count - 1)" : first
    }
}

extension DirectoryComputer {
    var dnsText: String { dnsName ?? "" }
    var lastLogonKey: Date { lastLogon ?? .distantPast }
    var joinedKey: Date { joined ?? .distantPast }
}

// MARK: - Drag and drop

/// People/computers/groups dragged from a table onto a folder: `labdc-objects:12,15`.
struct DraggedObjects: Transferable, Equatable {
    var ids: [ObjectID]

    static let prefix = "labdc-objects:"

    var text: String { Self.prefix + ids.map(String.init).joined(separator: ",") }

    init(ids: [ObjectID]) { self.ids = ids }

    init?(text: String) {
        guard text.hasPrefix(Self.prefix) else { return nil }
        let ids = text.dropFirst(Self.prefix.count).split(separator: ",").compactMap { ObjectID($0) }
        guard !ids.isEmpty else { return nil }
        self.ids = ids
    }

    struct NotOurs: Error {}

    static var transferRepresentation: some TransferRepresentation {
        ProxyRepresentation(exporting: { $0.text }, importing: { (text: String) in
            guard let d = DraggedObjects(text: text) else { throw NotOurs() }
            return d
        })
    }
}
