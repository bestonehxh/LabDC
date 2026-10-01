import Foundation
import Store

/// UI-2: every change the Users page makes, over the same `DirectoryStore` the embedded server
/// (LDAP, SAMR, NETLOGON, KDC) uses, with the store's own rules (password policy, unique
/// sAMAccountName/UPN, links, tombstones). New users and password resets go through
/// `DirectoryAccounts`, the code path of `labdc user add` / `user passwd`.
///
/// Each change is logged as one `Store … (app)` line (Activity ▸ Log; it also refreshes the
/// Overview counts). Live updates: `changes` (the store's `StoreChangeFeed`).
public actor DirectoryEditor {
    public nonisolated let store: DirectoryStore
    private let log: @Sendable (String) -> Void

    /// - Parameter log: receives one sentence per change (the app sends it to the serve log as
    ///   component `Store`).
    public init(store: DirectoryStore, log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.store = store
        self.log = log
    }

    /// Fires after every object write through this store (debounce before re-reading).
    public nonisolated var changes: StoreChangeFeed { store.changes }

    // MARK: Read

    /// Folders, people, groups and computers of the domain partition.
    public func snapshot() async throws -> DirectorySnapshot {
        let info = try await store.requireInfo()
        let filter = FilterAST.or(DirectorySnapshot.classes.map { .equality(attribute: "objectClass", value: Array($0.utf8)) })
        let entries = try await store.search(base: info.domainDN, scope: .subtree, filter: filter)
        return DirectorySnapshot.build(entries: entries, domainDN: info.domainDN, dnsDomain: info.dnsDomain)
    }

    // MARK: Folders (OUs)

    /// Creates `OU=<name>` below `parent` (the domain or an OU).
    @discardableResult
    public func createFolder(name: String, in parent: DN) async throws -> ObjectID {
        let name = try Self.cleanName(name, what: "folder name")
        let id = try await store.create(parent: parent, rdn: RDN("OU", name), objectClass: "organizationalUnit",
                                        strings: [:])
        log("folder OU=\(name) created in \(parent) (app)")
        return id
    }

    /// Renames an OU (its DN and those of everything inside follow).
    public func renameFolder(_ id: ObjectID, to name: String) async throws {
        let name = try Self.cleanName(name, what: "folder name")
        let entry = try await require(id)
        guard entry.dn.rdn?.type.uppercased() == "OU" else { throw CLIError.failure("only folders you created can be renamed") }
        try await store.rename(id: id, newRDN: RDN("OU", name))
        log("folder \(entry.dn) renamed to \(name) (app)")
    }

    /// Deletes an empty OU (the store refuses a folder that still holds something).
    public func deleteFolder(_ id: ObjectID) async throws {
        let entry = try await require(id)
        guard entry.dn.rdn?.type.uppercased() == "OU" else { throw CLIError.failure("only folders you created can be deleted") }
        do {
            try await store.delete(id: id)
        } catch StoreError.notAllowedOnNonLeaf {
            throw CLIError.failure("the folder \(entry.dn.rdn?.value ?? "") is not empty")
        }
        log("folder \(entry.dn) deleted (app)")
    }

    // MARK: Move (undoable)

    /// One object moved: where it was and where it went (undo moves it back).
    public struct Move: Sendable, Equatable {
        public var id: ObjectID
        public var from: DN
        public var to: DN

        public init(id: ObjectID, from: DN, to: DN) {
            self.id = id
            self.from = from
            self.to = to
        }

        /// The move that undoes this one.
        public var reversed: Move { Move(id: id, from: to, to: from) }
    }

    /// Moves objects into `folder` (LDAP ModifyDN with the same RDN). Objects already there are
    /// skipped. All or nothing: a failure moves the ones already done back and throws.
    @discardableResult
    public func move(_ ids: [ObjectID], to folder: DN) async throws -> [Move] {
        var done: [Move] = []
        do {
            for id in ids {
                let entry = try await require(id)
                try Self.guardEditableAccount(entry)
                guard let rdn = entry.dn.rdn, let from = entry.dn.parent else { continue }
                if from == folder { continue }
                try await store.rename(id: id, newRDN: rdn, newParent: folder)
                done.append(Move(id: id, from: from, to: folder))
            }
        } catch {
            _ = try? await undo(done, logIt: false)
            throw error
        }
        if !done.isEmpty { log("moved \(done.count) object(s) to \(folder) (app)") }
        return done
    }

    /// Moves every object of `moves` back to where it was; returns the reverse moves (redo).
    @discardableResult
    public func undo(_ moves: [Move]) async throws -> [Move] {
        try await undo(moves, logIt: true)
    }

    private func undo(_ moves: [Move], logIt: Bool) async throws -> [Move] {
        var reverse: [Move] = []
        for m in moves.reversed() {
            guard let entry = try await store.read(id: m.id), let rdn = entry.dn.rdn, let parent = entry.dn.parent else { continue }
            if parent == m.from { continue }
            try await store.rename(id: m.id, newRDN: rdn, newParent: m.from)
            reverse.append(Move(id: m.id, from: parent, to: m.from))
        }
        if logIt, !reverse.isEmpty { log("moved \(reverse.count) object(s) back (undo) (app)") }
        return reverse.reversed()
    }

    // MARK: People

    /// A new person: the `labdc user add` path (CN = username, UPN `username@domain`, the
    /// password with the domain policy, the user removed again when it is refused).
    public struct NewUser: Sendable, Equatable {
        public var displayName: String
        public var username: String
        public var password: String
        public var folder: DN?
        public var groups: [String]
        public var mustChangePassword: Bool
        /// DONT_EXPIRE_PASSWORD. Off by default, as in AD; "must change" wins when both are set
        /// (a never-expiring password is never asked to change).
        public var passwordNeverExpires: Bool

        public init(displayName: String, username: String, password: String, folder: DN? = nil, groups: [String] = [],
                    mustChangePassword: Bool = false, passwordNeverExpires: Bool = false) {
            self.displayName = displayName
            self.username = username
            self.password = password
            self.folder = folder
            self.groups = groups
            self.mustChangePassword = mustChangePassword
            self.passwordNeverExpires = passwordNeverExpires
        }
    }

    @discardableResult
    public func createUser(_ new: NewUser) async throws -> ObjectID {
        let sam = try Self.cleanUsername(new.username)
        let entry = try await DirectoryAccounts.addUser(store, sam: sam, password: new.password, parent: new.folder,
                                                        displayName: new.displayName, groups: new.groups)
        if new.mustChangePassword {
            try await requireChange(entry)
        } else if new.passwordNeverExpires {
            try await setUAC(entry, set: UserAccountControl.dontExpirePassword)
        }
        log("user \(sam) created (\(entry.dn))\(new.mustChangePassword ? ", must change password at next logon" : "")"
            + "\(!new.mustChangePassword && new.passwordNeverExpires ? ", password never expires" : "") (app)")
        return entry.id
    }

    /// `pwdLastSet` 0 and DONT_EXPIRE_PASSWORD cleared — the two together are what the KDC,
    /// LDAP bind (773) and Netlogon read as "must change" (ADUC clears the flag the same way).
    /// Never for the built-in Administrator or a machine account.
    private func requireChange(_ entry: DirectoryEntry) async throws {
        try Self.guardMustChange(entry)
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        var ops: [ModifyOp] = [.replace("pwdLastSet", strings: ["0"])]
        if uac & UserAccountControl.dontExpirePassword != 0 {
            ops.append(.replace("userAccountControl", strings: [String(uac & ~UserAccountControl.dontExpirePassword)]))
        }
        try await store.update(id: entry.id, ops: ops)
    }

    private func setUAC(_ entry: DirectoryEntry, set: UInt32 = 0, clear: UInt32 = 0) async throws {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        let updated = (uac | set) & ~clear
        guard updated != uac else { return }
        try await store.update(id: entry.id, ops: [.replace("userAccountControl", strings: [String(updated)])])
    }

    /// The built-in Administrator keeps its never-expiring password (it is how the lab is
    /// reached), and machine passwords are changed by the machines themselves.
    static func guardMustChange(_ entry: DirectoryEntry) throws {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount
                  | UserAccountControl.interdomainTrustAccount) != 0 {
            throw CLIError.failure("a computer account changes its own password; it cannot be asked to at next logon")
        }
        let critical = entry.string("isCriticalSystemObject")?.uppercased() == "TRUE"
        if critical, let sam = entry.samAccountName, sam.caseInsensitiveCompare("Administrator") == .orderedSame {
            throw CLIError.failure("the built-in Administrator's password never expires; it cannot be made to change at next logon")
        }
    }

    /// "Password never expires" off: refused only for the built-in Administrator (it is how the
    /// lab is reached). Computer accounts may have it cleared; their machines rotate the password.
    static func guardExpiringPassword(_ entry: DirectoryEntry) throws {
        let critical = entry.string("isCriticalSystemObject")?.uppercased() == "TRUE"
        if critical, let sam = entry.samAccountName, sam.caseInsensitiveCompare("Administrator") == .orderedSame {
            throw CLIError.failure("the built-in Administrator's password never expires; that setting cannot be turned off")
        }
    }

    /// The built-in Administrator (`isCriticalSystemObject` + the RID 500 name) is the domain's
    /// highest account: only its password may change here — a rename, disable, membership or
    /// folder change could lock the lab out (owner, 28 Sep 2026). Every account setter funnels
    /// through this check; `setPassword`/`setMustChangePassword` are the exceptions.
    static func guardEditableAccount(_ entry: DirectoryEntry) throws {
        let critical = entry.string("isCriticalSystemObject")?.uppercased() == "TRUE"
        if critical, let sam = entry.samAccountName, sam.caseInsensitiveCompare("Administrator") == .orderedSame {
            throw CLIError.failure("the built-in Administrator can only have its password changed here")
        }
    }

    public func setDisplayName(_ id: ObjectID, _ name: String) async throws {
        try Self.guardEditableAccount(try await require(id))
        let value = name.trimmingCharacters(in: .whitespaces)
        try await store.update(id: id, ops: [.replace("displayName", strings: value.isEmpty ? [] : [value])])
        log("\(try await label(id)) display name set (app)")
    }

    /// Changes `sAMAccountName`; a UPN that was `old@domain` follows, and so does a CN that was
    /// the old username (as `user add` names it).
    public func setUsername(_ id: ObjectID, _ username: String) async throws {
        let sam = try Self.cleanUsername(username)
        let entry = try await require(id)
        try Self.guardEditableAccount(entry)
        guard let old = entry.samAccountName, old != sam else { return }
        if let other = try await store.read(sam: sam), other.id != id {
            throw CLIError.failure("the username \(sam) is already taken")
        }
        let info = try await store.requireInfo()
        var ops: [ModifyOp] = [.replace("sAMAccountName", strings: [sam])]
        if let upn = entry.string("userPrincipalName"), upn.caseInsensitiveCompare("\(old)@\(info.dnsDomain)") == .orderedSame {
            ops.append(.replace("userPrincipalName", strings: ["\(sam)@\(info.dnsDomain)"]))
        }
        try await store.update(id: id, ops: ops)
        if let rdn = entry.dn.rdn, rdn.value.caseInsensitiveCompare(old) == .orderedSame {
            try await store.rename(id: id, newRDN: RDN(rdn.type, sam))
        }
        log("user \(old) renamed to \(sam) (app)")
    }

    /// Sets a password with the domain policy (the `labdc user passwd` path); optionally
    /// "must change at next logon".
    public func setPassword(_ id: ObjectID, _ password: String, mustChange: Bool = false) async throws {
        let entry = try await require(id)
        guard let sam = entry.samAccountName else { throw CLIError.failure("\(entry.dn) has no username") }
        if mustChange { try Self.guardMustChange(entry) }
        try await DirectoryAccounts.setPassword(store, sam: sam, password: password)
        if mustChange { try await requireChange(try await require(id)) }
        log("password of \(sam) set\(mustChange ? ", must change at next logon" : "") (app)")
    }

    /// On: `pwdLastSet` 0 and "password never expires" cleared (they exclude each other, as in
    /// ADUC). Off: `pwdLastSet` -1 (now) and UF_PASSWORD_EXPIRED cleared in the same update
    /// (either one alone still makes every sign-in demand a change).
    public func setMustChangePassword(_ id: ObjectID, _ mustChange: Bool) async throws {
        let entry = try await require(id)
        if mustChange {
            try await requireChange(entry)
        } else {
            var ops: [ModifyOp] = [.replace("pwdLastSet", strings: ["-1"])]
            let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
            if uac & UserAccountControl.passwordExpired != 0 {
                ops.append(.replace("userAccountControl", strings: [String(uac & ~UserAccountControl.passwordExpired)]))
            }
            try await store.update(id: id, ops: ops)
        }
        log("\(try await label(id)) must change password at next logon: \(mustChange ? "on" : "off") (app)")
    }

    /// DONT_EXPIRE_PASSWORD. Turning it on also turns "must change at next logon" off
    /// (`pwdLastSet` -1), as ADUC does. The built-in Administrator keeps it on.
    public func setPasswordNeverExpires(_ id: ObjectID, _ neverExpires: Bool) async throws {
        let entry = try await require(id)
        if neverExpires {
            try await setUAC(entry, set: UserAccountControl.dontExpirePassword)
            if entry.int("pwdLastSet") == 0 {
                try await store.update(id: id, ops: [.replace("pwdLastSet", strings: ["-1"])])
            }
        } else {
            try Self.guardExpiringPassword(entry)
            try await setUAC(entry, clear: UserAccountControl.dontExpirePassword)
        }
        log("\(try await label(id)) password never expires: \(neverExpires ? "on" : "off") (app)")
    }

    /// Enables or disables an account (`userAccountControl` ACCOUNTDISABLE).
    public func setEnabled(_ id: ObjectID, _ enabled: Bool) async throws {
        let entry = try await require(id)
        try Self.guardEditableAccount(entry)
        var uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if enabled { uac &= ~UserAccountControl.accountDisable } else { uac |= UserAccountControl.accountDisable }
        try await store.update(id: id, ops: [.replace("userAccountControl", strings: [String(uac)])])
        log("\(entry.samAccountName ?? entry.dn.description) \(enabled ? "enabled" : "disabled") (app)")
    }

    /// `accountExpires`: a date, or nil for never.
    public func setAccountExpires(_ id: ObjectID, _ date: Date?) async throws {
        try Self.guardEditableAccount(try await require(id))
        let values = date.map { [String(FileTimeDate.value($0))] } ?? []
        try await store.update(id: id, ops: [.replace("accountExpires", strings: values)])
        log("\(try await label(id)) account expires: \(date.map { GeneralizedTime.string($0) } ?? "never") (app)")
    }

    /// Plain text attributes of the inspector (mail, telephoneNumber, title, department,
    /// description, userPrincipalName, dNSHostName). Empty removes the value.
    public static let textAttributes: Set<String> = [
        "mail", "telephoneNumber", "title", "department", "description", "userPrincipalName",
    ]

    public func setText(_ id: ObjectID, _ attribute: String, _ value: String) async throws {
        guard Self.textAttributes.contains(attribute) else { throw CLIError.failure("\(attribute) is not editable here") }
        try Self.guardEditableAccount(try await require(id))
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        try await store.update(id: id, ops: [.replace(attribute, strings: v.isEmpty ? [] : [v])])
        log("\(try await label(id)) \(attribute) set (app)")
    }

    // MARK: Groups and membership

    @discardableResult
    public func createGroup(name: String, scope: GroupScope = .global, in folder: DN? = nil,
                            description: String? = nil) async throws -> ObjectID {
        let name = try Self.cleanName(name, what: "group name")
        let info = try await store.requireInfo()
        if try await store.read(sam: name) != nil { throw CLIError.failure("the name \(name) is already taken") }
        var strings: [String: [String]] = ["sAMAccountName": [name], "groupType": [String(scope.groupType(security: true))]]
        if let d = description?.trimmingCharacters(in: .whitespaces), !d.isEmpty { strings["description"] = [d] }
        let id = try await store.create(parent: folder ?? info.domainDN.child(RDN("CN", "Users")), rdn: RDN("CN", name),
                                        objectClass: "group", strings: strings)
        log("group \(name) created (app)")
        return id
    }

    /// Renames a group: CN and sAMAccountName together.
    public func renameGroup(_ id: ObjectID, to name: String) async throws {
        let name = try Self.cleanName(name, what: "group name")
        let entry = try await require(id)
        if let other = try await store.read(sam: name), other.id != id {
            throw CLIError.failure("the name \(name) is already taken")
        }
        if entry.samAccountName != name { try await store.update(id: id, ops: [.replace("sAMAccountName", strings: [name])]) }
        if let rdn = entry.dn.rdn, rdn.value != name { try await store.rename(id: id, newRDN: RDN(rdn.type, name)) }
        log("group \(entry.samAccountName ?? "") renamed to \(name) (app)")
    }

    public func setScope(_ id: ObjectID, _ scope: GroupScope) async throws {
        let entry = try await require(id)
        let old = Int32(truncatingIfNeeded: entry.int("groupType") ?? Int64(GroupType.globalSecurity))
        guard GroupScope(groupType: Int64(old)) != .builtinLocal, scope != .builtinLocal else {
            throw CLIError.failure("the scope of a built-in group cannot change")
        }
        let value = scope.groupType(security: old & GroupType.security != 0)
        try await store.update(id: id, ops: [.replace("groupType", strings: [String(value)])])
        log("group \(entry.samAccountName ?? "") scope \(scope.title) (app)")
    }

    /// Group side of membership; the built-in Administrator's groups stay as they are here,
    /// exactly as on the account side (`setGroups`, 30 Sep 2026).
    public func addMembers(_ ids: [ObjectID], to group: ObjectID) async throws {
        for id in ids { try Self.guardEditableAccount(try await require(id)) }
        let dns = try await dns(ids)
        guard !dns.isEmpty else { return }
        try await store.update(id: group, ops: [.add("member", strings: dns)], permissive: true)
        log("\(dns.count) member(s) added to \(try await label(group)) (app)")
    }

    public func removeMembers(_ ids: [ObjectID], from group: ObjectID) async throws {
        for id in ids { try Self.guardEditableAccount(try await require(id)) }
        let dns = try await dns(ids)
        guard !dns.isEmpty else { return }
        try await store.update(id: group, ops: [.delete("member", strings: dns)], permissive: true)
        log("\(dns.count) member(s) removed from \(try await label(group)) (app)")
    }

    /// Makes `id` a direct member of exactly `groups` (the People inspector's token field).
    public func setGroups(of id: ObjectID, to groups: Set<ObjectID>) async throws {
        let entry = try await require(id)
        try Self.guardEditableAccount(entry)
        var current: Set<ObjectID> = []
        for text in entry.strings("memberOf") {
            if let dn = try? DN(string: text), let gid = try await store.id(of: dn) { current.insert(gid) }
        }
        for g in groups.subtracting(current).sorted() {
            try await store.update(id: g, ops: [.add("member", strings: [entry.dn.description])], permissive: true)
        }
        for g in current.subtracting(groups).sorted() {
            try await store.update(id: g, ops: [.delete("member", strings: [entry.dn.description])], permissive: true)
        }
        if groups != current { log("\(entry.samAccountName ?? entry.dn.description) groups set (app)") }
    }

    // MARK: Computers

    /// "Reset machine account": the password goes back to the default (the computer name in
    /// lower case, as Active Directory Users and Computers does); the computer's secure channel
    /// breaks until it joins again.
    public func resetMachineAccount(_ id: ObjectID) async throws {
        let entry = try await require(id)
        guard entry.strings("objectClass").contains(where: { $0.caseInsensitiveCompare("computer") == .orderedSame }) else {
            throw CLIError.failure("\(entry.dn) is not a computer")
        }
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & UserAccountControl.serverTrustAccount != 0 { throw CLIError.failure("the domain controller cannot be reset") }
        let sam = entry.samAccountName ?? ""
        let bare = (sam.hasSuffix("$") ? String(sam.dropLast()) : sam).lowercased()
        try await store.setPassword(id: id, password: String(bare.prefix(14)), enforcePolicy: false)
        log("computer \(sam) reset: it must join the domain again (app)")
    }

    // MARK: Delete

    /// Deletes people, groups and computers (tombstones, like an LDAP delete; a computer's
    /// children go with it). Critical system objects are refused by the store.
    public func delete(_ ids: [ObjectID]) async throws {
        for id in ids {
            let entry = try await require(id)
            let isComputer = entry.strings("objectClass").contains { $0.caseInsensitiveCompare("computer") == .orderedSame }
            let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
            if isComputer, uac & UserAccountControl.serverTrustAccount != 0 {
                throw CLIError.failure("the domain controller cannot be deleted")
            }
            do {
                try await store.delete(id: id, recursive: isComputer)
            } catch StoreError.unwillingToPerform(let why) where why.contains("critical") {
                throw CLIError.failure("\(entry.samAccountName ?? entry.dn.rdn?.value ?? "") is built in and cannot be deleted")
            }
            log("\(entry.samAccountName ?? entry.dn.description) deleted (app)")
        }
    }

    // MARK: Helpers

    private func require(_ id: ObjectID) async throws -> DirectoryEntry {
        guard let e = try await store.read(id: id) else { throw CLIError.failure("the object is gone (it was deleted meanwhile)") }
        return e
    }

    private func dns(_ ids: [ObjectID]) async throws -> [String] {
        var out: [String] = []
        for id in ids { out.append(try await require(id).dn.description) }
        return out
    }

    private func label(_ id: ObjectID) async throws -> String {
        let e = try await require(id)
        return e.samAccountName ?? e.dn.rdn?.value ?? "#\(id)"
    }

    /// Characters AD refuses in sAMAccountName (MS-ADTS §3.1.1.5.2.1.1 / "pre-Windows 2000").
    static let forbiddenInUsername = Set("\"/\\[]:;|=,+*?<>@")

    static func cleanUsername(_ s: String) throws -> String {
        let v = s.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { throw CLIError.failure("the username is empty") }
        guard v.count <= 20 else { throw CLIError.failure("a username has at most 20 characters") }
        if let bad = v.first(where: { forbiddenInUsername.contains($0) }) {
            throw CLIError.failure("a username cannot contain “\(bad)”")
        }
        if v.hasSuffix(".") { throw CLIError.failure("a username cannot end with a dot") }
        return v
    }

    static func cleanName(_ s: String, what: String) throws -> String {
        let v = s.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { throw CLIError.failure("the \(what) is empty") }
        guard v.count <= 64 else { throw CLIError.failure("the \(what) is longer than 64 characters") }
        return v
    }
}
