import Foundation

/// The legacy JSON export format (version 1): domain, objects, links, secrets and DNS records
/// only. Still imported (`importJSON`); new exports are `StoreExportV2`.
public struct StoreExport: Codable, Sendable {
    public struct Object: Codable, Sendable {
        public var id: Int64
        public var guid: Data
        public var parent: Int64?
        public var rdnAttr: String
        public var rdnValue: String
        public var dn: String
        public var objectClass: String
        public var sAMAccountName: String?
        public var objectSid: Data?
        public var userPrincipalName: String?
        public var usnCreated: Int64
        public var usnChanged: Int64
        public var whenCreated: String
        public var whenChanged: String
        public var deleted: Bool
        public var attributes: [AttributeValues]
    }

    public struct AttributeValues: Codable, Sendable {
        public var name: String
        public var values: [Data]
    }

    public struct Link: Codable, Sendable {
        public var source: Int64
        public var attr: String
        public var target: Int64
    }

    public struct Secret: Codable, Sendable {
        public var object: Int64
        public var ntHash: Data?
        public var kvno: Int64
        public var aes256: Data?
        public var aes128: Data?
        public var rc4: Data?
        public var salt: String?
        public var pwdLastSet: String?
        public var history: Data?
    }

    public struct DNSRecord: Codable, Sendable {
        public var zone: String
        public var name: String
        public var type: Int64
        public var ttl: Int64
        public var rdata: Data
        public var dynamic: Bool
        public var updated: String
    }

    public var version: Int
    public var domain: [String: String]
    public var objects: [Object]
    public var links: [Link]
    public var secrets: [Secret]
    public var dnsRecords: [DNSRecord]
}

/// The JSON export format, version 2 (2 Oct 2026). Every table of the database is dumped row
/// for row — found by walking `sqlite_master`, so a table added later is carried without touching
/// this file — with ids preserved. Version 1 carried only five tables, and a restore silently lost
/// RADIUS clients/policies, DHCP, PKI issuance records, LSA secrets (DPAPI backup keys) and more.
///
/// Values: an integer is a JSON number, text a JSON string, NULL `null`, a blob `{"b": base64}`.
/// A config secret sealed with the store's key (`StoreSecretBox`: RADIUS shared secrets, LSA
/// secrets) is written **opened**, as `{"sealed": plaintext}`, and sealed again with the target
/// store's own key on import. A restore builds a new `lab.sqlite` beside a fresh
/// `lab.sqlite.secret-key`, so carrying the ciphertext would leave secrets no key opens; carrying
/// the key file instead would make the backup two coupled files. The export already holds NT
/// hashes and Kerberos keys: treat the file like the database plus its key (it is written 0600).
///
/// Why not `VACUUM INTO` (a file-level copy): the import loads into an existing, empty store the
/// caller opened, keeps reading version-1 exports, and checks every table and column as it goes
/// (refusing a newer build's backup instead of dropping what it cannot place); a raw database copy
/// would also have to carry and re-pair the secret-key file.
public struct StoreExportV2: Codable, Sendable {
    public enum Value: Codable, Sendable, Equatable {
        case null
        case int(Int64)
        case text(String)
        case blob(Data)
        /// A `StoreSecretBox`-sealed text value, opened.
        case sealed(String)

        private enum Keys: String, CodingKey { case b, sealed }

        public init(from decoder: Decoder) throws {
            let single = try decoder.singleValueContainer()
            if single.decodeNil() { self = .null; return }
            if let i = try? single.decode(Int64.self) { self = .int(i); return }
            if let s = try? single.decode(String.self) { self = .text(s); return }
            let keyed = try decoder.container(keyedBy: Keys.self)
            if let b = try keyed.decodeIfPresent(Data.self, forKey: .b) { self = .blob(b); return }
            if let s = try keyed.decodeIfPresent(String.self, forKey: .sealed) { self = .sealed(s); return }
            throw DecodingError.dataCorruptedError(in: single, debugDescription: "unknown value")
        }

        public func encode(to encoder: Encoder) throws {
            switch self {
            case .null: var c = encoder.singleValueContainer(); try c.encodeNil()
            case .int(let i): var c = encoder.singleValueContainer(); try c.encode(i)
            case .text(let s): var c = encoder.singleValueContainer(); try c.encode(s)
            case .blob(let b): var c = encoder.container(keyedBy: Keys.self); try c.encode(b, forKey: .b)
            case .sealed(let s): var c = encoder.container(keyedBy: Keys.self); try c.encode(s, forKey: .sealed)
            }
        }
    }

    public struct Table: Codable, Sendable {
        public var columns: [String]
        public var rows: [[Value]]
    }

    public var version: Int
    /// Table name → rows.
    public var tables: [String: Table]
}

extension DirectoryStore {
    /// The current export version.
    public static let exportVersion = 2

    /// The user tables of this database (everything in `sqlite_master` but SQLite's own).
    func exportableTables() throws -> [String] {
        try db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .compactMap { $0[0].text }
    }

    func tableColumns(_ table: String) throws -> [String] {
        try db.query("SELECT name FROM pragma_table_info(?) ORDER BY cid", [.text(table)]).compactMap { $0[0].text }
    }

    static func quoted(_ identifier: String) -> String {
        "\"" + identifier.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    /// Dumps the whole store as JSON (pretty, sorted keys): every table, version 2.
    public func exportJSON() throws -> Data {
        // One savepoint: a consistent snapshot even with the CLI writing beside the app (WAL).
        let export = try transaction { () throws -> StoreExportV2 in
            var tables: [String: StoreExportV2.Table] = [:]
            for name in try exportableTables() {
                let columns = try tableColumns(name)
                let list = columns.map(Self.quoted).joined(separator: ", ")
                // Every table here has a rowid (none is WITHOUT ROWID): insertion order, stable.
                let rows = try db.query("SELECT \(list) FROM \(Self.quoted(name)) ORDER BY rowid").map { row in
                    row.map { value -> StoreExportV2.Value in
                        switch value {
                        case .null: return .null
                        case .int(let i): return .int(i)
                        case .blob(let b): return .blob(Data(b))
                        case .text(let s):
                            // A value that does not open with this store's key stays as stored
                            // (it was already unreadable; the backup keeps it byte for byte).
                            if StoreSecretBox.isSealed(s), let plain = try? secretBox.open(s) { return .sealed(plain) }
                            return .text(s)
                        }
                    }
                }
                tables[name] = .init(columns: columns, rows: rows)
            }
            return StoreExportV2(version: Self.exportVersion, tables: tables)
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(export) } catch { throw StoreError.invalidExport("\(error)") }
    }

    /// Loads an export (version 2, or version 1 from an older LabDC) into this store, which must
    /// be empty. Ids, GUIDs, SIDs, USNs and keys are kept as they were; sealed config secrets are
    /// sealed again with this store's key.
    public func importJSON(_ data: Data) throws {
        struct Header: Decodable { var version: Int }
        let version: Int
        do { version = try JSONDecoder().decode(Header.self, from: data).version } catch {
            throw StoreError.invalidExport("\(error)")
        }
        guard version == 1 || version == Self.exportVersion else {
            throw StoreError.invalidExport("unsupported version \(version)")
        }
        guard (try db.scalar("SELECT COUNT(*) FROM objects")?.int ?? 0) == 0 else {
            throw StoreError.unwillingToPerform("import needs an empty store")
        }
        if version == 1 { return try importLegacyJSON(data) }
        let export: StoreExportV2
        do { export = try JSONDecoder().decode(StoreExportV2.self, from: data) } catch {
            throw StoreError.invalidExport("\(error)")
        }
        let known = Set(try exportableTables())
        // Refuse rather than drop data this build has no table or column for (a newer LabDC's export).
        for (name, table) in export.tables {
            guard known.contains(name) else { throw StoreError.invalidExport("unknown table \(name) (a newer LabDC's backup?)") }
            let columns = Set(try tableColumns(name))
            if let extra = table.columns.first(where: { !columns.contains($0) }) {
                throw StoreError.invalidExport("unknown column \(name).\(extra) (a newer LabDC's backup?)")
            }
            if let bad = table.rows.first(where: { $0.count != table.columns.count }) {
                throw StoreError.invalidExport("\(name): a row has \(bad.count) values for \(table.columns.count) columns")
            }
        }
        do {
            try transaction {
                // Rows reference each other (objects.parent_id, links, dhcp_reservations): the
                // foreign keys are checked once, at the end, not row by row.
                try db.exec("PRAGMA defer_foreign_keys = ON")
                for name in export.tables.keys.sorted() {
                    let table = export.tables[name]!
                    // A fresh store may hold defaults; the backup's rows replace them.
                    try db.run("DELETE FROM \(Self.quoted(name))")
                    guard !table.columns.isEmpty else { continue }
                    let sql = "INSERT INTO \(Self.quoted(name))(\(table.columns.map(Self.quoted).joined(separator: ", "))) VALUES("
                        + Array(repeating: "?", count: table.columns.count).joined(separator: ", ") + ")"
                    for row in table.rows {
                        try db.run(sql, try row.map { value -> SQLValue in
                            switch value {
                            case .null: .null
                            case .int(let i): .int(i)
                            case .text(let s): .text(s)
                            case .blob(let b): .blob([UInt8](b))
                            case .sealed(let plain): .text(try secretBox.seal(plain))
                            }
                        })
                    }
                }
                // sqlite_sequence is not exported: never hand out a scope id a lease still names
                // (a deleted scope's leftover leases must not join the next new scope).
                try db.exec("""
                    INSERT INTO sqlite_sequence(name, seq)
                      SELECT 'dhcp_scopes', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='dhcp_scopes');
                    UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT MAX(id) FROM dhcp_scopes), 0),
                      COALESCE((SELECT MAX(scope_id) FROM dhcp_leases), 0)) WHERE name='dhcp_scopes';
                    """)
                if let violation = try db.query("PRAGMA foreign_key_check").first {
                    throw StoreError.invalidExport("dangling reference in \(violation[0].text ?? "?") row \(violation[1].text ?? "?")")
                }
                sdCache = [:]
                try reloadInfo()
            }
        } catch {
            try? reloadInfo()
            throw error
        }
    }
}

extension DirectoryStore {
    /// The version-1 export (kept so tests can check old backups still import).
    func exportLegacyJSON() throws -> Data {
        var domain: [String: String] = [:]
        for r in try db.query("SELECT key, value FROM domain") { domain[r[0].text ?? ""] = r[1].text ?? "" }
        var objects: [StoreExport.Object] = []
        for r in try rows(where: "1 = 1", []) {
            var attrs: [StoreExport.AttributeValues] = []
            for a in try db.query("SELECT name, value FROM attributes WHERE object_id = ? ORDER BY name, ordinal", [.int(r.id)]) {
                let name = a[0].text ?? "", value = Data(a[1].blob ?? [])
                if let last = attrs.indices.last, attrs[last].name == name { attrs[last].values.append(value) } else {
                    attrs.append(.init(name: name, values: [value]))
                }
            }
            objects.append(.init(id: r.id, guid: Data(r.guid.bytes), parent: r.parentID, rdnAttr: r.rdnAttr, rdnValue: r.rdnValue,
                                 dn: r.dn, objectClass: r.objectClass, sAMAccountName: r.sam, objectSid: r.sid.map { Data($0) },
                                 userPrincipalName: r.upn, usnCreated: r.usnCreated, usnChanged: r.usnChanged,
                                 whenCreated: r.whenCreated, whenChanged: r.whenChanged, deleted: r.deleted, attributes: attrs))
        }
        let links = try db.query("SELECT source_id, attr, target_id FROM links ORDER BY rowid").map {
            StoreExport.Link(source: $0[0].int ?? 0, attr: $0[1].text ?? "", target: $0[2].int ?? 0)
        }
        func data(_ v: SQLValue) -> Data? { v.blob.map { Data($0) } }
        let secrets = try db.query("SELECT object_id, nt_hash, kvno, aes256, aes128, rc4, salt, pwd_last_set, history FROM secrets ORDER BY object_id").map {
            StoreExport.Secret(object: $0[0].int ?? 0, ntHash: data($0[1]), kvno: $0[2].int ?? 0, aes256: data($0[3]),
                               aes128: data($0[4]), rc4: data($0[5]), salt: $0[6].text, pwdLastSet: $0[7].text, history: data($0[8]))
        }
        let dns = try db.query("SELECT zone, name, type, ttl, rdata, dynamic, updated FROM dns_records ORDER BY id").map {
            StoreExport.DNSRecord(zone: $0[0].text ?? "", name: $0[1].text ?? "", type: $0[2].int ?? 0, ttl: $0[3].int ?? 0,
                                  rdata: Data($0[4].blob ?? []), dynamic: ($0[5].int ?? 0) != 0, updated: $0[6].text ?? "")
        }
        let export = StoreExport(version: 1, domain: domain, objects: objects, links: links, secrets: secrets, dnsRecords: dns)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(export) } catch { throw StoreError.invalidExport("\(error)") }
    }

    /// Loads a version-1 export (the caller checked the store is empty).
    private func importLegacyJSON(_ data: Data) throws {
        let export: StoreExport
        do { export = try JSONDecoder().decode(StoreExport.self, from: data) } catch {
            throw StoreError.invalidExport("\(error)")
        }
        do {
            try transaction {
                for (k, v) in export.domain { try setDomainValue(v, forKey: k) }
                // Parents may have larger ids than children after a move: insert without parents first.
                for o in export.objects {
                    let dn = try DN(string: o.dn)
                    try db.run("""
                        INSERT INTO objects(id, guid, parent_id, rdn_attr, rdn_value, dn, dn_norm, object_class, sam_account_name,
                          object_sid, upn, usn_created, usn_changed, when_created, when_changed, deleted)
                        VALUES(?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, [.int(o.id), .blob([UInt8](o.guid)), .text(o.rdnAttr), .text(o.rdnValue), .text(o.dn),
                              .text(dn.normalized), .text(o.objectClass), .optional(o.sAMAccountName),
                              .optional(o.objectSid.map { [UInt8]($0) }), .optional(o.userPrincipalName), .int(o.usnCreated),
                              .int(o.usnChanged), .text(o.whenCreated), .text(o.whenChanged), .int(o.deleted ? 1 : 0)])
                    for a in o.attributes { try appendStored(o.id, a.name, a.values.map { [UInt8]($0) }) }
                }
                for o in export.objects where o.parent != nil {
                    try db.run("UPDATE objects SET parent_id = ? WHERE id = ?", [.int(o.parent!), .int(o.id)])
                }
                for l in export.links {
                    try db.run("INSERT INTO links(source_id, attr, target_id) VALUES(?, ?, ?)",
                               [.int(l.source), .text(l.attr), .int(l.target)])
                }
                func blob(_ d: Data?) -> SQLValue { d.map { .blob([UInt8]($0)) } ?? .null }
                for s in export.secrets {
                    try db.run("""
                        INSERT INTO secrets(object_id, nt_hash, kvno, aes256, aes128, rc4, salt, pwd_last_set, history)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, [.int(s.object), blob(s.ntHash), .int(s.kvno), blob(s.aes256), blob(s.aes128), blob(s.rc4),
                              .optional(s.salt), .optional(s.pwdLastSet), blob(s.history)])
                }
                for r in export.dnsRecords {
                    try db.run("""
                        INSERT INTO dns_records(zone, name, type, ttl, rdata, dynamic, updated) VALUES(?, ?, ?, ?, ?, ?, ?)
                        """, [.text(r.zone), .text(r.name), .int(r.type), .int(r.ttl), .blob([UInt8](r.rdata)),
                              .int(r.dynamic ? 1 : 0), .text(r.updated)])
                }
                try reloadInfo()
            }
        } catch {
            try? reloadInfo()
            throw error
        }
    }
}
