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
