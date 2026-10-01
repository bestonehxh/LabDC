import Foundation

/// The JSON export format (version 1). Every table is dumped row for row, ids preserved, binary
/// values base64. It contains key material: treat the file like the database itself.
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

extension DirectoryStore {
    /// Dumps the whole store as JSON (pretty, sorted keys).
    public func exportJSON() throws -> Data {
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

    /// Loads an export into this store, which must be empty. Ids, GUIDs, SIDs, USNs and keys are
    /// kept as they were.
    public func importJSON(_ data: Data) throws {
        let export: StoreExport
        do { export = try JSONDecoder().decode(StoreExport.self, from: data) } catch {
            throw StoreError.invalidExport("\(error)")
        }
        guard export.version == 1 else { throw StoreError.invalidExport("unsupported version \(export.version)") }
        guard (try db.scalar("SELECT COUNT(*) FROM objects")?.int ?? 0) == 0 else {
            throw StoreError.unwillingToPerform("import needs an empty store")
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
