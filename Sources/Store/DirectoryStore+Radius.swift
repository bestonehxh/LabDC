import Foundation
import MSPAC
import RADIUSKit

/// Phase 4a: RADIUS NAS clients and the ordered policy rules (docs/specs/phase4-radius.md).
/// Not directory data — the RADIUS server's own config tables, edited in the app or
/// `labdc radius`; the directory supplies the accounts and facts the policies test.
extension DirectoryStore {
    // MARK: NAS clients

    public struct NASClient: Sendable, Equatable, Identifiable {
        public var id: Int64
        public var name: String
        /// An address, a CIDR (`10.0.0.0/24`, `fd00::/64`) or a range (`10.0.0.10-10.0.0.20`).
        public var ip: String
        /// The shared secret in the clear (sealed in the table, see `StoreSecretBox`).
        public var secret: String
        public var enabled: Bool
        /// Access-Requests without EAP must carry a valid Message-Authenticator (Blast-RADIUS,
        /// CVE-2024-3596). On by default; off only for an old NAS that cannot send it. EAP
        /// requests always need one (RFC 3579).
        public var requireMessageAuthenticator: Bool

        public init(id: Int64 = 0, name: String, ip: String, secret: String, enabled: Bool = true,
                    requireMessageAuthenticator: Bool = true) {
            self.id = id; self.name = name; self.ip = ip; self.secret = secret; self.enabled = enabled
            self.requireMessageAuthenticator = requireMessageAuthenticator
        }

        /// Whether the request's source address falls in this client's address / CIDR / range
        /// (IPv4 or IPv6; a `%scope` on the source is ignored).
        public func matches(_ ip: String) -> Bool {
            RADIUSAddress.matches(pattern: self.ip, address: ip)
        }
    }

    public func listNAS() throws -> [NASClient] {
        try listNASSkippingUnreadable().clients
    }

    /// The clients whose secret opens; a client whose sealed secret does not (a store moved
    /// without its key, a damaged row) is skipped and named in `unreadable` rather than failing
    /// the whole list — the RADIUS server keeps serving the others and logs the skipped one.
    public func listNASSkippingUnreadable() throws -> (clients: [NASClient], unreadable: [String]) {
        var clients: [NASClient] = []
        var unreadable: [String] = []
        for row in try db.query("SELECT id, name, ip, secret, enabled, require_ma FROM radius_nas ORDER BY id") {
            let name = row[1].text ?? ""
            guard let secret = try? secretBox.open(row[3].text ?? "") else {
                unreadable.append(name.isEmpty ? "#\(row[0].int ?? 0)" : name)
                continue
            }
            clients.append(NASClient(id: row[0].int ?? 0, name: name, ip: row[2].text ?? "", secret: secret,
                                     enabled: row[4].int != 0, requireMessageAuthenticator: (row[5].int ?? 1) != 0))
        }
        return (clients, unreadable)
    }

    @discardableResult
    public func addNAS(_ client: NASClient) throws -> Int64 {
        try Self.validateNAS(client)
        return try transaction {
            try db.run("INSERT INTO radius_nas(name, ip, secret, enabled, require_ma) VALUES(?,?,?,?,?)",
                       [SQLValue.text(client.name), .text(client.ip), .text(try secretBox.seal(client.secret)),
                        .int(client.enabled ? 1 : 0), .int(client.requireMessageAuthenticator ? 1 : 0)])
            return db.lastInsertRowID
        }
    }

    public func updateNAS(_ client: NASClient) throws {
        try Self.validateNAS(client)
        try transaction {
            try db.run("UPDATE radius_nas SET name=?, ip=?, secret=?, enabled=?, require_ma=? WHERE id=?",
                       [SQLValue.text(client.name), .text(client.ip), .text(try secretBox.seal(client.secret)),
                        .int(client.enabled ? 1 : 0), .int(client.requireMessageAuthenticator ? 1 : 0), .int(Int64(client.id))])
        }
    }

    public func deleteNAS(id: Int64) throws {
        try transaction { try db.run("DELETE FROM radius_nas WHERE id=?", [.int(id)]) }
    }

    /// The enabled client whose address/CIDR/range covers the request's source.
    public func nas(forIP ip: String) throws -> NASClient? {
        try listNAS().first { $0.enabled && $0.matches(ip) }
    }

    static func validateNAS(_ client: NASClient) throws {
        guard !client.name.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw StoreError.constraintViolation("a RADIUS client needs a name")
        }
        guard RADIUSAddress.isValidPattern(client.ip) else {
            throw StoreError.constraintViolation("\(client.ip) is not an IP address, CIDR or range")
        }
        guard !client.secret.isEmpty else { throw StoreError.constraintViolation("a RADIUS client needs a shared secret") }
    }

    /// Open-time migration (30 Sep 2026): shared secrets written in the clear by earlier builds
    /// are sealed with the store's key.
    static func sealPlaintextNASSecrets(_ db: SQLiteConnection, _ box: StoreSecretBox) throws {
        let plain = try db.query("SELECT id, secret FROM radius_nas").filter { !StoreSecretBox.isSealed($0[1].text ?? "") }
        for row in plain {
            try db.run("UPDATE radius_nas SET secret=? WHERE id=?", [.text(try box.seal(row[1].text ?? "")), .int(row[0].int ?? 0)])
        }
    }

    /// The stored value of one NAS secret, as it sits in the table (tests check it is sealed).
    func storedNASSecret(id: Int64) throws -> String? {
        try db.scalar("SELECT secret FROM radius_nas WHERE id=?", [.int(id)])?.text
    }

    // MARK: Policies

    public func listRadiusPolicies() throws -> [RADIUSPolicy] {
        try db.query("SELECT id, position, name, enabled, action, rows_json, attrs_json, vlan FROM radius_policies ORDER BY position").compactMap { row -> RADIUSPolicy? in
            guard let rows = try? JSONDecoder().decode([RADIUSPolicy.Row].self, from: Data(row[5].blob ?? [])),
                  let attrs = try? JSONDecoder().decode([RADIUSPolicy.ReturnedAttribute].self, from: Data(row[6].blob ?? [])) else { return nil }
            return RADIUSPolicy(id: UUID(uuidString: row[0].text ?? "") ?? UUID(), position: Int(row[1].int ?? 0),
                                name: row[2].text ?? "?", enabled: row[3].int != 0,
                                rows: rows, action: RADIUSPolicy.Action(rawValue: row[4].text ?? "") ?? .reject,
                                attributes: attrs, vlan: row[7].text)
        }
    }

    public func saveRadiusPolicy(_ policy: RADIUSPolicy) throws {
        if policy.action == .acceptVLAN, (policy.vlan ?? "").trimmingCharacters(in: .whitespaces).isEmpty {
            throw StoreError.constraintViolation("Accept with VLAN needs a VLAN")
        }
        try transaction {
            let rows = try JSONEncoder().encode(policy.rows)
            let attrs = try JSONEncoder().encode(policy.attributes)
            try db.run("INSERT INTO radius_policies(id, position, name, enabled, action, rows_json, attrs_json, vlan) VALUES(?,?,?,?,?,?,?,?) " +
                       "ON CONFLICT(id) DO UPDATE SET position=excluded.position, name=excluded.name, enabled=excluded.enabled, " +
                       "action=excluded.action, rows_json=excluded.rows_json, attrs_json=excluded.attrs_json, vlan=excluded.vlan",
                       [.text(policy.id.uuidString), .int(Int64(policy.position)), .text(policy.name),
                        .int(policy.enabled ? 1 : 0), .text(policy.action.rawValue),
                        .blob([UInt8](rows)), .blob([UInt8](attrs)),
                        policy.action == .acceptVLAN ? .text(policy.vlan ?? "") : .null])
        }
    }

    /// Writes the order of all policies in one transaction: `ids[i]` gets position `i`. Policies
    /// not named keep their relative order after the named ones. Either every position changes or
    /// none does.
    public func reorderRadiusPolicies(_ ids: [UUID]) throws {
        try transaction {
            let existing = try db.query("SELECT id FROM radius_policies ORDER BY position").compactMap { $0[0].text }
            let named = ids.map(\.uuidString)
            for id in named where !existing.contains(id) {
                throw StoreError.constraintViolation("no RADIUS policy \(id)")
            }
            let order = named + existing.filter { !named.contains($0) }
            for (position, id) in order.enumerated() {
                try db.run("UPDATE radius_policies SET position=? WHERE id=?", [.int(Int64(position)), .text(id)])
            }
        }
    }

    public func deleteRadiusPolicy(id: UUID) throws {
        try transaction { try db.run("DELETE FROM radius_policies WHERE id=?", [.text(id.uuidString)]) }
    }

    /// What happens when no rule matches (Reject unless the owner picked Accept).
    public func radiusDefaultAction() throws -> RADIUSDefaultAction {
        try domainValue(forKey: "radiusDefaultAction").flatMap(RADIUSDefaultAction.init(rawValue:)) ?? .reject
    }

    public func setRadiusDefaultAction(_ action: RADIUSDefaultAction) throws {
        try setDomainValue(action.rawValue, forKey: "radiusDefaultAction")
    }

    // MARK: Facts

    /// Directory facts the policy evaluator needs for one account: groups (nested membership and
    /// the primary group resolved), the OU path, machine flag and account-state flags.
    public func radiusFacts(entry: DirectoryEntry, now: Date) throws -> DirectoryFacts {
        // Transitive `memberOf`: breadth-first over the member links, cycles cut by `seen`.
        var seen: Set<Int64> = []
        var names: [String] = []
        var frontier: [Int64] = [Int64(entry.id)]
        if let rid = entry.int("primaryGroupID"), let sid = try? domainInfo().domainSID.appending(rid: UInt32(truncatingIfNeeded: rid)),
           let primary = try read(sid: sid, attrs: ["sAMAccountName"]) {
            seen.insert(Int64(primary.id))
            names.append(primary.samAccountName ?? primary.dn.rdn?.value ?? "")
            frontier.append(Int64(primary.id))
        }
        while let next = frontier.popLast() {
            let groups = try db.query(
                "SELECT o.id, o.sam_account_name, o.rdn_value FROM links l JOIN objects o ON o.id = l.source_id " +
                "WHERE l.attr = 'member' AND l.target_id = ? AND o.deleted = 0", [.int(next)])
            for g in groups {
                guard let id = g[0].int, seen.insert(id).inserted else { continue }
                names.append(g[1].text ?? g[2].text ?? "")
                frontier.append(id)
            }
        }

        // OU path from the domain down: `Staff / IT` (containers such as `Users` count too).
        var path: [String] = []
        let domainDN = try domainInfo().domainDN
        var parent = entry.parentID
        while let pid = parent, let p = try read(id: pid, attrs: []), p.dn != domainDN {
            if let v = p.dn.rdn?.value { path.insert(v, at: 0) }
            parent = p.parentID
            if path.count > 64 { break }
        }

        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        let isMachine = entry.objectClass == "computer"
            || uac & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount) != 0
        var flags: [String] = []
        if uac & UserAccountControl.accountDisable != 0 { flags.append("disabled") }
        if uac & UserAccountControl.lockout != 0 { flags.append("locked") }
        if accountRefusal(entry, now: now) == .expired { flags.append("expired") }
        if uac & UserAccountControl.passwordExpired != 0 { flags.append("password expired") }
        if uac & UserAccountControl.dontExpirePassword != 0 { flags.append("password never expires") }
        if uac & UserAccountControl.smartcardRequired != 0 { flags.append("smartcard required") }
        if uac & UserAccountControl.passwordNotRequired != 0 { flags.append("password not required") }
        // The same gate as the KDC and LDAP bind: never-expiring passwords are never "must change".
        if !isMachine, uac & UserAccountControl.dontExpirePassword == 0, let secrets = try secrets(id: entry.id),
           secrets.pwdLastSet.rawValue == 0 {
            flags.append("must change password")
        }
        return DirectoryFacts(samAccountName: entry.samAccountName ?? entry.dn.rdn?.value ?? "",
                              userPrincipalName: entry.string("userPrincipalName"),
                              groups: names.filter { !$0.isEmpty }, ou: path.isEmpty ? nil : path.joined(separator: " / "),
                              isMachine: isMachine, accountFlags: flags)
    }

    /// Facts by sign-in name (any form `resolveSignInName` accepts); nil = no such account.
    public func radiusFacts(name: String, now: Date = Date()) throws -> DirectoryFacts? {
        guard let entry = try resolveSignInName(name) else { return nil }
        return try radiusFacts(entry: entry, now: now)
    }
}
