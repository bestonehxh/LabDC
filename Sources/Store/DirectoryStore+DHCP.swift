import DHCPKit
import Foundation

/// Phase 5: the DHCP server's tables (docs/specs/phase5-dhcp.md §4) — scopes, reservations,
/// leases (v4 and v6, history included), settings and the bounded `dhcp_events` audit. Like the
/// RADIUS tables: server configuration next to the directory, edited in the app or `labdc dhcp`.
/// The structured parts are stored as JSON next to the indexed columns.
extension DirectoryStore {
    /// `dhcp_events` keeps at most this many rows (oldest go first).
    public static let dhcpEventLimit = 50_000

    static func createDHCPSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS dhcp_scopes(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              family TEXT NOT NULL,
              subnet TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              data BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS dhcp_reservations(
              id INTEGER PRIMARY KEY,
              scope_id INTEGER NOT NULL REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              address TEXT NOT NULL,
              mac TEXT NULL,
              data BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS dhcp_reservations_scope ON dhcp_reservations(scope_id);
            CREATE TABLE IF NOT EXISTS dhcp_leases(
              family TEXT NOT NULL,
              address TEXT NOT NULL,
              scope_id INTEGER NOT NULL,
              state TEXT NOT NULL,
              client_key TEXT NOT NULL,
              mac TEXT NULL,
              hostname TEXT NULL,
              expires INTEGER NOT NULL,
              updated INTEGER NOT NULL,
              data BLOB NOT NULL,
              PRIMARY KEY(family, address));
            CREATE INDEX IF NOT EXISTS dhcp_leases_mac ON dhcp_leases(mac);
            CREATE INDEX IF NOT EXISTS dhcp_leases_scope ON dhcp_leases(scope_id);
            CREATE TABLE IF NOT EXISTS dhcp_settings(
              key TEXT PRIMARY KEY,
              value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS dhcp_events(
              id INTEGER PRIMARY KEY,
              time INTEGER NOT NULL,
              family TEXT NOT NULL,
              address TEXT NULL,
              mac TEXT NULL,
              client_key TEXT NULL,
              kind TEXT NOT NULL,
              detail TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS dhcp_events_address ON dhcp_events(family, address);
            CREATE INDEX IF NOT EXISTS dhcp_events_mac ON dhcp_events(mac);
            """)
        try migrateDHCPScopesToAutoincrement(db)
    }

    /// Scope ids are never reused: leases and events keyed by a deleted scope's id must not
    /// attach to a new scope. Databases made before AUTOINCREMENT get their table rebuilt with
    /// the same ids (SQLite's documented table-rebuild steps, foreign keys off meanwhile so the
    /// reservations' `ON DELETE CASCADE` does not fire), and the sequence starts above every
    /// scope id still referenced by a lease.
    static func migrateDHCPScopesToAutoincrement(_ db: SQLiteConnection) throws {
        let sql = try db.scalar("SELECT sql FROM sqlite_master WHERE type='table' AND name='dhcp_scopes'")?.text ?? ""
        guard !sql.uppercased().contains("AUTOINCREMENT") else { return }
        try db.exec("PRAGMA foreign_keys=OFF")
        defer { try? db.exec("PRAGMA foreign_keys=ON") }
        try db.exec("""
            BEGIN;
            CREATE TABLE dhcp_scopes_new(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              family TEXT NOT NULL,
              subnet TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              data BLOB NOT NULL);
            INSERT INTO dhcp_scopes_new(id, name, family, subnet, enabled, data)
              SELECT id, name, family, subnet, enabled, data FROM dhcp_scopes;
            DROP TABLE dhcp_scopes;
            ALTER TABLE dhcp_scopes_new RENAME TO dhcp_scopes;
            INSERT INTO sqlite_sequence(name, seq)
              SELECT 'dhcp_scopes', MAX(COALESCE((SELECT MAX(id) FROM dhcp_scopes), 0), COALESCE((SELECT MAX(scope_id) FROM dhcp_leases), 0))
              WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='dhcp_scopes');
            UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT MAX(scope_id) FROM dhcp_leases), 0)) WHERE name='dhcp_scopes';
            COMMIT;
            """)
    }

    private static let jsonEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    // MARK: Scopes

    /// The scopes whose data decodes (an undecodable row is left out: `dhcpUndecodableScopes`).
    public func dhcpScopes() throws -> [DHCPScope] {
        try db.query("SELECT id, data FROM dhcp_scopes ORDER BY id").compactMap { row in
            guard var scope = try? JSONDecoder().decode(DHCPScope.self, from: Data(row[1].blob ?? [])) else { return nil }
            scope.id = row[0].int ?? 0
            return scope
        }
    }

    /// Every scope id in the table, decodable or not: what "this scope still exists" means
    /// (its leases and DNS records are never dropped because its data failed to decode).
    public func dhcpScopeIDs() throws -> Set<Int64> {
        Set(try db.query("SELECT id FROM dhcp_scopes").compactMap { $0[0].int })
    }

    /// Rows of `dhcp_scopes` whose data does not decode (id, name): skipped by `dhcpScopes`.
    public func dhcpUndecodableScopes() throws -> [(id: Int64, name: String)] {
        try db.query("SELECT id, name, data FROM dhcp_scopes ORDER BY id").compactMap { row in
            if (try? JSONDecoder().decode(DHCPScope.self, from: Data(row[2].blob ?? []))) != nil { return nil }
            return (row[0].int ?? 0, row[1].text ?? "")
        }
    }

    public func dhcpScope(id: Int64) throws -> DHCPScope? { try dhcpScopes().first { $0.id == id } }

    public func dhcpScopeCount() throws -> Int { Int(try db.scalar("SELECT COUNT(*) FROM dhcp_scopes")?.int ?? 0) }

    @discardableResult
    public func addDHCPScope(_ scope: DHCPScope) throws -> Int64 {
        var scope = scope
        scope.searchList = DHCPScope.splitSearchList(scope.searchList)
        try validateScope(scope, replacing: nil)
        return try transaction {
            var s = scope
            s.id = 0
            try db.run("INSERT INTO dhcp_scopes(name, family, subnet, enabled, data) VALUES(?,?,?,?,?)",
                       [.text(s.name), .text(s.family.rawValue), .text(s.subnet), .int(s.enabled ? 1 : 0),
                        .blob([UInt8](try Self.jsonEncoder.encode(s)))])
            return db.lastInsertRowID
        }
    }

    /// Replaces the scope. Custom options the server sets itself that the stored scope already
    /// had (saved before validation refused them) are dropped instead of failing the update;
    /// the returned notes say so (the CLI prints them, the app logs them). Adding one is refused.
    @discardableResult
    public func updateDHCPScope(_ scope: DHCPScope) throws -> [String] {
        guard let saved = try dhcpScope(id: scope.id) else { throw StoreError.noSuchObject("DHCP scope \(scope.id)") }
        let stripped = scope.strippingSavedServerManagedOptions(saved: saved)
        var scope = stripped.scope
        let note = stripped.note
        scope.searchList = DHCPScope.splitSearchList(scope.searchList)
        try validateScope(scope, replacing: scope.id)
        try transaction {
            try db.run("UPDATE dhcp_scopes SET name=?, family=?, subnet=?, enabled=?, data=? WHERE id=?",
                       [.text(scope.name), .text(scope.family.rawValue), .text(scope.subnet), .int(scope.enabled ? 1 : 0),
                        .blob([UInt8](try Self.jsonEncoder.encode(scope))), .int(scope.id)])
        }
        return note.map { [$0] } ?? []
    }

    /// Deletes the scope, its reservations, its leases and their history.
    public func deleteDHCPScope(id: Int64) throws {
        try transaction {
            let addresses = try db.query("SELECT family, address FROM dhcp_leases WHERE scope_id=?", [.int(id)])
            for a in addresses {
                try db.run("DELETE FROM dhcp_events WHERE family=? AND address=?", [a[0], a[1]])
            }
            try db.run("DELETE FROM dhcp_leases WHERE scope_id=?", [.int(id)])
            try db.run("DELETE FROM dhcp_reservations WHERE scope_id=?", [.int(id)])
            try db.run("DELETE FROM dhcp_scopes WHERE id=?", [.int(id)])
        }
    }

    func validateScope(_ scope: DHCPScope, replacing id: Int64?) throws {
        do { try scope.validate() } catch { throw StoreError.constraintViolation("\(error)") }
        for other in try dhcpScopes() where other.id != id {
            if other.name.caseInsensitiveCompare(scope.name) == .orderedSame {
                throw StoreError.constraintViolation("a scope named \(scope.name) already exists")
            }
            guard other.family == scope.family else { continue }
            let overlaps: Bool
            switch scope.family {
            case .v4:
                if let a = IPv4Subnet(scope.subnet), let b = IPv4Subnet(other.subnet) {
                    overlaps = a.contains(b.network) || b.contains(a.network)
                } else { overlaps = false }
            case .v6:
                if let a = IPv6Subnet(scope.subnet), let b = IPv6Subnet(other.subnet) {
                    overlaps = a.contains(b.network) || b.contains(a.network)
                } else { overlaps = false }
            }
            if overlaps { throw StoreError.constraintViolation("\(scope.subnet) overlaps scope \(other.name) (\(other.subnet))") }
        }
    }

    /// The reverse zones the DC serves for its scopes (`0.20.10.in-addr.arpa`, v6 at /64).
    public func dhcpReverseZones() throws -> [String] {
        var zones: [String] = []
        for s in try dhcpScopes() where s.enabled && s.dnsUpdates {
            switch s.family {
            case .v4: if let n = s.subnetV4 { zones += DHCPDNS.reverseZones(v4: n) }
            case .v6: if let n = s.subnetV6 { zones.append(DHCPDNS.reverseZone(v6: n)) }
            }
        }
        var seen = Set<String>()
        return zones.filter { seen.insert($0).inserted }
    }

    // MARK: Reservations

    public func dhcpReservations(scope: Int64? = nil) throws -> [DHCPReservation] {
        let rows = scope == nil
            ? try db.query("SELECT id, scope_id, data FROM dhcp_reservations ORDER BY id")
            : try db.query("SELECT id, scope_id, data FROM dhcp_reservations WHERE scope_id=? ORDER BY id", [.int(scope!)])
        return rows.compactMap { row in
            guard var r = try? JSONDecoder().decode(DHCPReservation.self, from: Data(row[2].blob ?? [])) else { return nil }
            r.id = row[0].int ?? 0
            r.scopeID = row[1].int ?? 0
            return r
        }
    }

    @discardableResult
    public func addDHCPReservation(_ reservation: DHCPReservation) throws -> Int64 {
        try validateReservation(reservation, replacing: nil)
        return try transaction {
            var r = reservation
            r.id = 0
            try db.run("INSERT INTO dhcp_reservations(scope_id, name, address, mac, data) VALUES(?,?,?,?,?)",
                       [.int(r.scopeID), .text(r.name), .text(r.address), .optional(r.mac), .blob([UInt8](try Self.jsonEncoder.encode(r)))])
            return db.lastInsertRowID
        }
    }

    /// Replaces the reservation; server-set custom options it already had are dropped with a
    /// note, as in `updateDHCPScope`.
    @discardableResult
    public func updateDHCPReservation(_ reservation: DHCPReservation) throws -> [String] {
        let saved = try dhcpReservations().first { $0.id == reservation.id }
        let v6 = try dhcpScope(id: reservation.scopeID)?.family == .v6
        let (reservation, note) = reservation.strippingSavedServerManagedOptions(saved: saved, v6: v6)
        try validateReservation(reservation, replacing: reservation.id)
        try transaction {
            try db.run("UPDATE dhcp_reservations SET scope_id=?, name=?, address=?, mac=?, data=? WHERE id=?",
                       [.int(reservation.scopeID), .text(reservation.name), .text(reservation.address), .optional(reservation.mac),
                        .blob([UInt8](try Self.jsonEncoder.encode(reservation))), .int(reservation.id)])
        }
        return note.map { [$0] } ?? []
    }

    public func deleteDHCPReservation(id: Int64) throws {
        try transaction { try db.run("DELETE FROM dhcp_reservations WHERE id=?", [.int(id)]) }
    }

    func validateReservation(_ r: DHCPReservation, replacing id: Int64?) throws {
        guard let scope = try dhcpScope(id: r.scopeID) else { throw StoreError.constraintViolation("no DHCP scope \(r.scopeID)") }
        do { try r.validate(scope: scope) } catch { throw StoreError.constraintViolation("\(error)") }
        let scopes = try dhcpScopes()
        for other in try dhcpReservations() where other.id != id {
            let sameFamily = scopes.first { $0.id == other.scopeID }?.family == scope.family
            guard sameFamily else { continue }
            if other.address == r.address { throw StoreError.constraintViolation("\(r.address) is already reserved for \(other.name)") }
            if let m = r.mac, other.mac == m, other.scopeID == r.scopeID {
                throw StoreError.constraintViolation("\(m) already has a reservation (\(other.name)) in this scope")
            }
            if let d = r.duid, other.duid == d { throw StoreError.constraintViolation("that DUID already has a reservation (\(other.name))") }
        }
    }

    // MARK: Leases

    public func dhcpLeases(family: DHCPFamily? = nil) throws -> [DHCPLease] {
        let rows = family == nil
            ? try db.query("SELECT data FROM dhcp_leases")
            : try db.query("SELECT data FROM dhcp_leases WHERE family=?", [.text(family!.rawValue)])
        return rows.compactMap { try? JSONDecoder().decode(DHCPLease.self, from: Data($0[0].blob ?? [])) }
    }

    public func dhcpLease(family: DHCPFamily, address: String) throws -> DHCPLease? {
        try db.query("SELECT data FROM dhcp_leases WHERE family=? AND address=?", [.text(family.rawValue), .text(address)])
            .first.flatMap { try? JSONDecoder().decode(DHCPLease.self, from: Data($0[0].blob ?? [])) }
    }

    /// The newest lease (any state) for a MAC — RADIUS device facts, the CLI.
    public func dhcpLatestLease(mac: String) throws -> DHCPLease? {
        guard let key = Self.canonicalMAC(mac) else { return nil }
        return try db.query("SELECT data FROM dhcp_leases WHERE mac=? ORDER BY updated DESC LIMIT 1", [.text(key)])
            .first.flatMap { try? JSONDecoder().decode(DHCPLease.self, from: Data($0[0].blob ?? [])) }
    }

    /// The write-behind batch: changed leases upserted, removed ids (`v4/10.0.0.5`) deleted, in
    /// one transaction.
    public func saveDHCPLeases(_ changed: [DHCPLease], removed: [String] = []) throws {
        guard !changed.isEmpty || !removed.isEmpty else { return }
        try transaction {
            for l in changed {
                try db.run("""
                    INSERT INTO dhcp_leases(family, address, scope_id, state, client_key, mac, hostname, expires, updated, data)
                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(family, address) DO UPDATE SET scope_id=excluded.scope_id,
                    state=excluded.state, client_key=excluded.client_key, mac=excluded.mac, hostname=excluded.hostname,
                    expires=excluded.expires, updated=excluded.updated, data=excluded.data
                    """, [.text(l.family.rawValue), .text(l.address), .int(l.scopeID), .text(l.state.rawValue), .text(l.clientKey),
                          .optional(l.mac), .optional(l.hostname), .int(Self.epochSeconds(l.expires)), .int(Self.epochSeconds(l.updated)),
                          .blob([UInt8](try Self.jsonEncoder.encode(l)))])
            }
            for id in removed {
                let parts = id.split(separator: "/", maxSplits: 1).map(String.init)
                guard parts.count == 2 else { continue }
                try db.run("DELETE FROM dhcp_leases WHERE family=? AND address=?", [.text(parts[0]), .text(parts[1])])
            }
        }
    }

    public func deleteDHCPLease(family: DHCPFamily, address: String) throws {
        try db.run("DELETE FROM dhcp_leases WHERE family=? AND address=?", [.text(family.rawValue), .text(address)])
    }

    // MARK: Settings

    public func dhcpSettings() throws -> DHCPSettings {
        guard let blob = try db.scalar("SELECT value FROM dhcp_settings WHERE key='settings'")?.blob,
              let s = try? JSONDecoder().decode(DHCPSettings.self, from: Data(blob)) else { return DHCPSettings() }
        return s
    }

    public func setDHCPSettings(_ settings: DHCPSettings) throws {
        do { try settings.validate() } catch { throw StoreError.constraintViolation("\(error)") }
        try db.run("INSERT INTO dhcp_settings(key, value) VALUES('settings', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   [.blob([UInt8](try Self.jsonEncoder.encode(settings)))])
    }

    /// The server's DUID-LLT, created once (from `mac` and now) and kept.
    public func dhcpServerDUID(mac: [UInt8], now: Date = Date()) throws -> [UInt8] {
        if let hex = try db.scalar("SELECT value FROM dhcp_settings WHERE key='serverDUID'")?.text, let b = DHCPHex.bytes(hex), !b.isEmpty {
            return b
        }
        let duid = DHCPv6DUID.llt(mac: mac.count == 6 ? mac : [0x02, 0, 0, 0, 0, 1], time: now)
        try db.run("INSERT INTO dhcp_settings(key, value) VALUES('serverDUID', ?) ON CONFLICT(key) DO NOTHING",
                   [.text(DHCPHex.string(duid))])
        return try dhcpServerDUID(mac: mac, now: now)
    }

    // MARK: Events

    public func addDHCPEvents(_ events: [DHCPEvent]) throws {
        guard !events.isEmpty else { return }
        try transaction {
            for e in events {
                try db.run("INSERT INTO dhcp_events(time, family, address, mac, client_key, kind, detail) VALUES(?,?,?,?,?,?,?)",
                           [.int(Self.epochSeconds(e.date)), .text(e.family.rawValue), .optional(e.address), .optional(e.mac),
                            .optional(e.clientKey), .text(e.kind), .text(e.detail)])
            }
            let count = try db.scalar("SELECT COUNT(*) FROM dhcp_events")?.int ?? 0
            if count > Int64(Self.dhcpEventLimit) {
                try db.run("DELETE FROM dhcp_events WHERE id IN (SELECT id FROM dhcp_events ORDER BY id LIMIT ?)",
                           [.int(count - Int64(Self.dhcpEventLimit))])
            }
        }
    }

    /// History of one address (and/or MAC), newest first.
    public func dhcpEvents(family: DHCPFamily? = nil, address: String? = nil, mac: String? = nil, limit: Int = 200) throws -> [DHCPEvent] {
        var sql = "SELECT id, time, family, address, mac, client_key, kind, detail FROM dhcp_events WHERE 1=1"
        var params: [SQLValue] = []
        if let family { sql += " AND family=?"; params.append(.text(family.rawValue)) }
        if let address { sql += " AND address=?"; params.append(.text(address)) }
        if let mac { sql += " AND mac=?"; params.append(.text(Self.canonicalMAC(mac) ?? mac)) }
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(.int(Int64(limit)))
        return try db.query(sql, params).map {
            DHCPEvent(id: $0[0].int ?? 0, date: Self.realDate($0[1]), family: DHCPFamily(rawValue: $0[2].text ?? "") ?? .v4,
                      address: $0[3].text, mac: $0[4].text, clientKey: $0[5].text, kind: $0[6].text ?? "", detail: $0[7].text ?? "")
        }
    }

    // MARK: Export / import

    /// Scopes, reservations and settings as JSON (`labdc dhcp export`, the app's Export).
    public struct DHCPConfigExport: Codable, Sendable {
        public var scopes: [DHCPScope]
        public var reservations: [DHCPReservation]
        public var settings: DHCPSettings
        public init(scopes: [DHCPScope], reservations: [DHCPReservation], settings: DHCPSettings) {
            self.scopes = scopes; self.reservations = reservations; self.settings = settings
        }
    }

    public func exportDHCPConfig() throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try e.encode(DHCPConfigExport(scopes: try dhcpScopes(), reservations: try dhcpReservations(), settings: try dhcpSettings()))
    }

    /// Adds the scopes (by name: an existing scope of the same name is replaced) and their
    /// reservations; settings replace the current ones except `directInterfaces`, which keep
    /// their current value — direct mode is only switched on after the probe for another server
    /// (`dhcp direct <interface>`), never by a file. `ignoredDirect` lists the file's interfaces
    /// that were not applied. One transaction.
    @discardableResult
    public func importDHCPConfig(_ data: Data) throws -> (scopes: Int, reservations: Int, ignoredDirect: [String]) {
        let config = try JSONDecoder().decode(DHCPConfigExport.self, from: data)
        return try transaction {
            var idMap: [Int64: Int64] = [:]
            for s in config.scopes {
                if let existing = try dhcpScopes().first(where: { $0.name.caseInsensitiveCompare(s.name) == .orderedSame }) {
                    var updated = s
                    updated.id = existing.id
                    try updateDHCPScope(updated)
                    idMap[s.id] = existing.id
                } else {
                    idMap[s.id] = try addDHCPScope(s)
                }
            }
            var count = 0
            for var r in config.reservations {
                guard let scope = idMap[r.scopeID] else { continue }
                r.scopeID = scope
                if let existing = try dhcpReservations(scope: scope).first(where: { $0.address == r.address }) {
                    r.id = existing.id
                    try updateDHCPReservation(r)
                } else {
                    try addDHCPReservation(r)
                }
                count += 1
            }
            var settings = config.settings
            let current = try dhcpSettings().directInterfaces
            let ignored = settings.directInterfaces.filter { !current.contains($0) }
            settings.directInterfaces = current
            try setDHCPSettings(settings)
            return (config.scopes.count, count, ignored)
        }
    }

    // MARK: DNS records written for leases

    /// Stored records of one owner in a zone (any type), for the DHCP DNS updater.
    public func dnsRecordsForOwner(zone: String, name: String) throws -> [DNSRecordRow] {
        try dnsRecords(zone: zone, name: name)
    }
}
