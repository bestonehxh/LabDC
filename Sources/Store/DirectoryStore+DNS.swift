import Foundation

extension DirectoryStore {
    /// Records of `zone`, optionally only `name` (case-insensitive) and/or `type`, ordered by id.
    public func dnsRecords(zone: String, name: String? = nil, type: UInt16? = nil) throws -> [DNSRecordRow] {
        var sql = "SELECT id, zone, name, type, ttl, rdata, dynamic, updated FROM dns_records WHERE zone = ?"
        var params: [SQLValue] = [.text(zone)]
        if let name { sql += " AND name = ?"; params.append(.text(name)) }
        if let type { sql += " AND type = ?"; params.append(.int(Int64(type))) }
        return try db.query(sql + " ORDER BY id", params).map {
            DNSRecordRow(id: $0[0].int ?? 0, zone: $0[1].text ?? "", name: $0[2].text ?? "",
                         type: UInt16(truncatingIfNeeded: $0[3].int ?? 0), ttl: UInt32(truncatingIfNeeded: $0[4].int ?? 0),
                         rdata: $0[5].blob ?? [], dynamic: ($0[6].int ?? 0) != 0,
                         updated: GeneralizedTime.date($0[7].text ?? "") ?? Date(timeIntervalSince1970: 0))
        }
    }

    /// Zones that have at least one record.
    public func dnsZones() throws -> [String] {
        try db.query("SELECT DISTINCT zone FROM dns_records ORDER BY zone").compactMap { $0[0].text }
    }

    /// Adds a record unless an identical (zone, name, type, rdata) one exists; returns its id.
    @discardableResult
    public func addDNSRecord(zone: String, name: String, type: UInt16, ttl: UInt32, rdata: [UInt8],
                             dynamic: Bool = false) throws -> Int64 {
        if let existing = try db.scalar("SELECT id FROM dns_records WHERE zone = ? AND name = ? AND type = ? AND rdata = ?",
                                        [.text(zone), .text(name), .int(Int64(type)), .blob(rdata)])?.int {
            try db.run("UPDATE dns_records SET ttl = ?, updated = ? WHERE id = ?", [.int(Int64(ttl)), .text(nowString), .int(existing)])
            return existing
        }
        try db.run("INSERT INTO dns_records(zone, name, type, ttl, rdata, dynamic, updated) VALUES(?, ?, ?, ?, ?, ?, ?)",
                   [.text(zone), .text(name), .int(Int64(type)), .int(Int64(ttl)), .blob(rdata), .int(dynamic ? 1 : 0),
                    .text(nowString)])
        return db.lastInsertRowID
    }

    /// Deletes matching records (all types / all rdata when nil). Returns how many went.
    @discardableResult
    public func deleteDNSRecords(zone: String, name: String, type: UInt16? = nil, rdata: [UInt8]? = nil) throws -> Int {
        var sql = "DELETE FROM dns_records WHERE zone = ? AND name = ?"
        var params: [SQLValue] = [.text(zone), .text(name)]
        if let type { sql += " AND type = ?"; params.append(.int(Int64(type))) }
        if let rdata { sql += " AND rdata = ?"; params.append(.blob(rdata)) }
        try db.run(sql, params)
        return db.changes
    }
}

// MARK: Dynamic-update owners (CVE audit, 1 Oct 2026)

extension DirectoryStore {
    /// `dns_owners`: which client registered a name by a dynamic update and when it last did — its
    /// address (as text) for an unsigned update, `account:<SID>:<sAMAccountName>` for a secure
    /// (GSS-TSIG) one; only that client may change or delete the name with an unsigned update.
    static func createDNSOwnerSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS dns_owners(
              zone TEXT NOT NULL COLLATE NOCASE, name TEXT NOT NULL COLLATE NOCASE,
              owner TEXT NOT NULL, updated TEXT NOT NULL,
              PRIMARY KEY(zone, name));
            """)
    }

    /// The recorded owner of `name` (relative to `zone`, as in `dns_records`) and when it last
    /// registered; nil when none is recorded.
    public func dnsOwner(zone: String, name: String) throws -> (owner: String, updated: Date)? {
        guard let row = try db.query("SELECT owner, updated FROM dns_owners WHERE zone = ? AND name = ?",
                                     [.text(zone), .text(name)]).first, let owner = row[0].text else { return nil }
        return (owner, GeneralizedTime.date(row[1].text ?? "") ?? Date(timeIntervalSince1970: 0))
    }

    /// Records `owner` for `name` (updated = now), or forgets it with nil.
    public func setDNSOwner(zone: String, name: String, owner: String?) throws {
        if let owner {
            try db.run("""
                INSERT INTO dns_owners(zone, name, owner, updated) VALUES(?, ?, ?, ?)
                ON CONFLICT(zone, name) DO UPDATE SET owner = excluded.owner, updated = excluded.updated
                """, [.text(zone), .text(name), .text(owner), .text(nowString)])
        } else {
            try db.run("DELETE FROM dns_owners WHERE zone = ? AND name = ?", [.text(zone), .text(name)])
        }
    }

    /// Whether `name` has a record an administrator created (`dynamic = 0`).
    public func hasStaticDNSRecords(zone: String, name: String) throws -> Bool {
        try db.scalar("SELECT 1 FROM dns_records WHERE zone = ? AND name = ? AND dynamic = 0 LIMIT 1",
                      [.text(zone), .text(name)]) != nil
    }
}
