import Foundation
import Store

/// The account code paths shared by the CLI (`labdc user add` / `user passwd`) and the app's
/// Users page (UI-2), so both behave identically: same container, same attributes, same password
/// policy, same roll-back when the password is refused, same error sentences.
public enum DirectoryAccounts {
    /// Creates a user `CN=<sam>` below `parent` (default `CN=Users`) with `sAMAccountName`,
    /// `userPrincipalName` (default `sam@dnsdomain`) and `displayName` (default `sam`), sets the
    /// password with the domain policy (the user is removed again when the password is refused)
    /// and adds it to `groups` (sAMAccountName or DN of each group).
    @discardableResult
    public static func addUser(_ store: DirectoryStore, sam: String, password: String, upn: String? = nil,
                               parent: DN? = nil, displayName: String? = nil,
                               groups groupNames: [String] = []) async throws -> DirectoryEntry {
        let info = try await store.requireInfo()
        if try await store.read(sam: sam) != nil { throw CLIError.failure("sAMAccountName \(sam) already exists") }
        let parent = parent ?? info.domainDN.child(RDN("CN", "Users"))
        var groups: [DirectoryEntry] = []
        for name in groupNames {
            var found = try await store.read(sam: name)
            if found == nil, name.contains("="), let dn = try? DN(string: name) { found = try await store.read(dn: dn) }
            guard let g = found, g.objectClass == "group" else { throw CLIError.failure("no group \(name)") }
            groups.append(g)
        }
        let upn = upn ?? "\(sam)@\(info.dnsDomain)"
        let display = displayName.map { $0.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 } ?? sam
        let id: ObjectID
        do {
            id = try await store.create(parent: parent, rdn: RDN("CN", sam), objectClass: "user", strings: [
                "sAMAccountName": [sam], "userPrincipalName": [upn], "displayName": [display],
            ])
        } catch {
            throw CLIError.failure("cannot create \(sam): \(error)")
        }
        do {
            try await store.setPassword(id: id, password: password)
        } catch {
            try? await store.delete(id: id)
            throw CLIError.failure("password refused, \(sam) not created: \(error)")
        }
        let dn = try await store.read(id: id)?.dn.description ?? ""
        for g in groups {
            try await store.update(id: g.id, ops: [.add("member", strings: [dn])], permissive: true)
        }
        guard let entry = try await store.read(id: id) else { throw CLIError.failure("\(sam) vanished") }
        return entry
    }

    /// Sets the password of `sam` with the domain policy (`labdc user passwd`).
    public static func setPassword(_ store: DirectoryStore, sam: String, password: String) async throws {
        _ = try await store.requireInfo()
        guard let entry = try await store.read(sam: sam) else { throw CLIError.failure("no account \(sam)") }
        do { try await store.setPassword(id: entry.id, password: password) } catch {
            throw CLIError.failure("password of \(sam) not set: \(error)")
        }
    }
}
