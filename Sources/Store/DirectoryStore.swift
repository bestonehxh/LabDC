import Foundation
import KerberosCrypto
import MSPAC
import SheepCrypto
import os

/// The SQLite-backed directory: one actor per database file (WAL mode), synchronous SQLite
/// calls inside the actor. Holds the AD-shaped object tree, linked attributes, account secrets,
/// DNS records and the realm-wide `domain` values.
///
/// Objects are addressed by `ObjectID` (row id) or DN. Reads return `DirectoryEntry` values with
/// stored attributes plus the computed ones (objectGUID, objectSid, distinguishedName, memberOf,
/// sAMAccountType, objectCategory, whenCreated/whenChanged, uSN*, name, instanceType,
/// nTSecurityDescriptor, pwdLastSet and account defaults). Deleted objects are tombstones under
/// `CN=Deleted Objects` and are hidden unless `includeDeleted` is set.
public actor DirectoryStore {
    let db: SQLiteConnection
    let rng: RandomBytes
    let clock: @Sendable () -> Date
    var cachedInfo: DomainInfo?
    var sdCache: [String: [UInt8]] = [:]
    private var savepointDepth = 0
    /// Seals config secrets at rest (RADIUS shared secrets; `StoreSecretBox`).
    let secretBox: StoreSecretBox

    /// The database path (`:memory:` for a throwaway store).
    public nonisolated let path: String

    /// Objects the open-time fixups repaired (WP-AN: raw SAMR ACB values stored in a computer's
    /// `userAccountControl`); empty on a clean store. `labdc serve` logs one
    /// `Store fixup: …` line per entry.
    public nonisolated let openFixups: [StoreFixup]

    /// UI-2: published after every object write (see `StoreChangeFeed`).
    public nonisolated let changes = StoreChangeFeed()

    /// Phase 5: MACs whose device profile category/OS changed (`upsertDeviceProfile`).
    public nonisolated let deviceProfileEvents = DeviceProfileEvents()

    static let logger = Logger(subsystem: "dev.labdc.app", category: "Store")
    static let schemaVersion: Int64 = 1

    /// Opens (creating if needed) the database at `path`.
    /// - Parameters:
    ///   - rng: randomness for GUIDs, SIDs and random keys (tests inject a seeded one).
    ///   - clock: the store's notion of now (whenCreated, pwdLastSet, tombstone age).
    public init(path: String, rng: RandomBytes = RandomBytes(),
                clock: @escaping @Sendable () -> Date = { Date() }) throws {
        let db = try SQLiteConnection(path: path)
        try Self.createSchema(db)
        let secretBox = try StoreSecretBox.load(storePath: path)
        try Self.sealPlaintextNASSecrets(db, secretBox)
        try db.exec("SAVEPOINT open_fixups")
        do {
            self.openFixups = try Self.fixRawACBUserAccountControl(db, clock: clock)
            try db.exec("RELEASE open_fixups")
        } catch {
            try? db.exec("ROLLBACK TO open_fixups")
            try? db.exec("RELEASE open_fixups")
            throw error
        }
        self.db = db
        self.rng = rng
        self.clock = clock
        self.path = path
        self.secretBox = secretBox
        self.cachedInfo = try Self.loadInfo(db)
    }

    /// Same as `init(path:rng:clock:)`.
    public static func open(path: String, rng: RandomBytes = RandomBytes(),
                            clock: @escaping @Sendable () -> Date = { Date() }) throws -> DirectoryStore {
        try DirectoryStore(path: path, rng: rng, clock: clock)
    }

    private static func createSchema(_ db: SQLiteConnection) throws {
        _ = try db.query("PRAGMA journal_mode=WAL")
        try db.exec("PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;")
        let version = try db.scalar("PRAGMA user_version")?.int ?? 0
        if version > schemaVersion {
            throw StoreError.sqlite(code: 0, message: "database schema version \(version) is newer than \(schemaVersion)")
        }
        try db.exec("""
            CREATE TABLE IF NOT EXISTS objects(
              id INTEGER PRIMARY KEY,
              guid BLOB NOT NULL UNIQUE,
              parent_id INTEGER NULL REFERENCES objects(id),
              rdn_attr TEXT NOT NULL,
              rdn_value TEXT NOT NULL,
              dn TEXT NOT NULL,
              dn_norm TEXT NOT NULL UNIQUE,
              object_class TEXT NOT NULL,
              sam_account_name TEXT NULL UNIQUE COLLATE NOCASE,
              object_sid BLOB NULL UNIQUE,
              upn TEXT NULL UNIQUE COLLATE NOCASE,
              usn_created INTEGER NOT NULL,
              usn_changed INTEGER NOT NULL,
              when_created TEXT NOT NULL,
              when_changed TEXT NOT NULL,
              deleted INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS objects_parent ON objects(parent_id);
            CREATE TABLE IF NOT EXISTS attributes(
              object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
              name TEXT NOT NULL COLLATE NOCASE,
              value BLOB NOT NULL,
              value_norm TEXT NULL,
              ordinal INTEGER NOT NULL,
              PRIMARY KEY(object_id, name, ordinal));
            CREATE INDEX IF NOT EXISTS attributes_norm ON attributes(name, value_norm);
            CREATE TABLE IF NOT EXISTS links(
              source_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
              attr TEXT NOT NULL COLLATE NOCASE,
              target_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
              PRIMARY KEY(source_id, attr, target_id));
            CREATE INDEX IF NOT EXISTS links_target ON links(target_id, attr);
            CREATE TABLE IF NOT EXISTS secrets(
              object_id INTEGER PRIMARY KEY REFERENCES objects(id) ON DELETE CASCADE,
              nt_hash BLOB NULL, kvno INTEGER NOT NULL DEFAULT 0, aes256 BLOB NULL, aes128 BLOB NULL,
              rc4 BLOB NULL, salt TEXT NULL, pwd_last_set TEXT NULL, history BLOB NULL);
            CREATE TABLE IF NOT EXISTS dns_records(
              id INTEGER PRIMARY KEY, zone TEXT NOT NULL COLLATE NOCASE, name TEXT NOT NULL COLLATE NOCASE,
              type INTEGER NOT NULL, ttl INTEGER NOT NULL, rdata BLOB NOT NULL,
              dynamic INTEGER NOT NULL DEFAULT 0, updated TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS dns_records_name ON dns_records(zone, name, type);
            CREATE TABLE IF NOT EXISTS domain(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA user_version = \(schemaVersion);
            """)
        try createPKISchema(db)
        try createDHCPSchema(db)
        try createDNSOwnerSchema(db)
        try createDeviceProfileSchema(db)
        try createLSASecretSchema(db)
    }

    // MARK: - Transactions

    /// Runs `body` inside a savepoint; nested calls nest. Any error rolls the savepoint back.
    func transaction<T>(_ body: () throws -> T) throws -> T {
        let name = "sp\(savepointDepth)"
        try db.exec("SAVEPOINT \(name)")
        savepointDepth += 1
        do {
            let result = try body()
            savepointDepth -= 1
            try db.exec("RELEASE \(name)")
            return result
        } catch {
            savepointDepth -= 1
            try? db.exec("ROLLBACK TO \(name)")
            try? db.exec("RELEASE \(name)")
            throw error
        }
    }

    // MARK: - Domain table

    /// A raw value of the `domain` table (realm, dnsDomain, netbios, domainSID, nextRID, ...).
    public func domainValue(forKey key: String) throws -> String? {
        try db.scalar("SELECT value FROM domain WHERE key = ?", [.text(key)])?.text
    }

    /// Sets a raw `domain` table value (other modules may keep their settings here).
    public func setDomainValue(_ value: String, forKey key: String) throws {
        try db.run("INSERT INTO domain(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                   [.text(key), .text(value)])
    }

    /// Realm-wide values; throws `provisioning` before `provision`.
    public func domainInfo() throws -> DomainInfo {
        guard let cachedInfo else { throw StoreError.provisioning("the store has not been provisioned") }
        return cachedInfo
    }

    /// True once `provision` (or `importJSON`) has run.
    public var isProvisioned: Bool { cachedInfo != nil }

    static func loadInfo(_ db: SQLiteConnection) throws -> DomainInfo? {
        var kv: [String: String] = [:]
        for r in try db.query("SELECT key, value FROM domain") {
            if let k = r[0].text, let v = r[1].text { kv[k] = v }
        }
        guard let realm = kv["realm"], let dns = kv["dnsDomain"], let netbios = kv["netbios"],
              let sidText = kv["domainSID"], let domainGUID = kv["domainGUID"].flatMap(GUID.init(string:)),
              let dc = kv["dcName"], let dcDNS = kv["dcDNSName"], let site = kv["site"],
              let dsa = kv["dsaGUID"].flatMap(GUID.init(string:)),
              let invocation = kv["invocationID"].flatMap(GUID.init(string:)) else { return nil }
        let sid = try SID(string: sidText)
        let domainDN = DN(dnsDomain: dns)
        let config = domainDN.child(RDN("CN", "Configuration"))
        let schema = config.child(RDN("CN", "Schema"))
        let server = config.child(RDN("CN", "Sites")).child(RDN("CN", site)).child(RDN("CN", "Servers")).child(RDN("CN", dc))
        return DomainInfo(
            realm: realm, dnsDomain: dns, netbiosDomain: netbios, domainSID: sid, domainGUID: domainGUID,
            dcName: dc, dcDNSName: dcDNS, site: site, dsaGUID: dsa, invocationID: invocation,
            domainDN: domainDN, configurationDN: config, schemaDN: schema,
            dcComputerDN: domainDN.child(RDN("OU", "Domain Controllers")).child(RDN("CN", dc)),
            dsServiceDN: server.child(RDN("CN", "NTDS Settings")), serverDN: server,
            subschemaDN: schema.child(RDN("CN", "Aggregate")))
    }

    func reloadInfo() throws { cachedInfo = try Self.loadInfo(db) }

    // MARK: - USN, RID, time

    /// `highestCommittedUSN` for the RootDSE.
    public func highestCommittedUSN() throws -> Int64 {
        try domainValue(forKey: "highestCommittedUSN").flatMap { Int64($0) } ?? 0
    }

    func nextUSN() throws -> Int64 {
        let next = try highestCommittedUSN() + 1
        try setDomainValue(String(next), forKey: "highestCommittedUSN")
        changes.publish(next)
        return next
    }

    /// Hands out the next RID (monotonic, persisted in `domain.nextRID` and mirrored into the
    /// RID Manager$'s `rIDAvailablePool`).
    public func allocateRID() throws -> UInt32 {
        try transaction {
            guard let text = try domainValue(forKey: "nextRID"), let next = UInt32(text) else {
                throw StoreError.provisioning("no RID pool")
            }
            guard next < Self.ridPoolEnd else { throw StoreError.ridPoolExhausted }
            try setDomainValue(String(next + 1), forKey: "nextRID")
            if let info = cachedInfo,
               let rm = try row(dnNorm: info.domainDN.child(RDN("CN", "System")).child(RDN("CN", "RID Manager$")).normalized) {
                try replaceStored(rm.id, "rIDAvailablePool", [Array(String(Self.ridPool(next: next + 1)).utf8)])
            }
            return next
        }
    }

    /// Highest RID + 1 (2^30, MS-ADTS §3.1.1.1.10).
    static let ridPoolEnd: UInt32 = 1 << 30

    /// `rIDAvailablePool`: high 32 bits the pool end, low 32 bits the next free RID.
    static func ridPool(next: UInt32) -> Int64 { Int64(ridPoolEnd) << 32 | Int64(next) }

    var nowString: String { GeneralizedTime.string(clock()) }

    // MARK: - Rows

    struct ObjectRow {
        var id: ObjectID
        var guid: GUID
        var parentID: ObjectID?
        var rdnAttr: String
        var rdnValue: String
        var dn: String
        var dnNorm: String
        var objectClass: String
        var sam: String?
        var sid: [UInt8]?
        var upn: String?
        var usnCreated: Int64
        var usnChanged: Int64
        var whenCreated: String
        var whenChanged: String
        var deleted: Bool

        var parsedDN: DN { (try? DN(string: dn)) ?? DN.root }
    }

    static let rowColumns = """
        o.id, o.guid, o.parent_id, o.rdn_attr, o.rdn_value, o.dn, o.dn_norm, o.object_class, \
        o.sam_account_name, o.object_sid, o.upn, o.usn_created, o.usn_changed, o.when_created, o.when_changed, o.deleted
        """

    func decodeRow(_ r: [SQLValue]) -> ObjectRow {
        ObjectRow(id: r[0].int ?? 0, guid: GUID(unchecked: r[1].blob ?? []), parentID: r[2].int,
                  rdnAttr: r[3].text ?? "", rdnValue: r[4].text ?? "", dn: r[5].text ?? "", dnNorm: r[6].text ?? "",
                  objectClass: r[7].text ?? "", sam: r[8].text, sid: r[9].blob, upn: r[10].text,
                  usnCreated: r[11].int ?? 0, usnChanged: r[12].int ?? 0, whenCreated: r[13].text ?? "",
                  whenChanged: r[14].text ?? "", deleted: (r[15].int ?? 0) != 0)
    }

    func rows(where clause: String, _ params: [SQLValue]) throws -> [ObjectRow] {
        try db.query("SELECT \(Self.rowColumns) FROM objects o WHERE \(clause) ORDER BY o.id", params).map(decodeRow)
    }

    func row(id: ObjectID) throws -> ObjectRow? { try rows(where: "o.id = ?", [.int(id)]).first }
    func row(dnNorm: String) throws -> ObjectRow? { try rows(where: "o.dn_norm = ?", [.text(dnNorm)]).first }

    func requireRow(id: ObjectID, includeDeleted: Bool = false) throws -> ObjectRow {
        guard let r = try row(id: id), includeDeleted || !r.deleted else { throw StoreError.noSuchObject("id \(id)") }
        return r
    }

    func requireRow(dn: DN, includeDeleted: Bool = false) throws -> ObjectRow {
        guard let r = try row(dnNorm: dn.normalized), includeDeleted || !r.deleted else {
            throw StoreError.noSuchObject(dn.description)
        }
        return r
    }

    /// The id of the object at `dn` (nil if absent or deleted).
    public func id(of dn: DN) throws -> ObjectID? {
        guard let r = try row(dnNorm: dn.normalized), !r.deleted else { return nil }
        return r.id
    }

    // MARK: - Stored values

    static func canonicalName(_ name: String) -> String { DirectorySchema.attribute(name)?.name ?? name }

    func storedValues(_ id: ObjectID, _ name: String) throws -> [[UInt8]] {
        try db.query("SELECT value FROM attributes WHERE object_id = ? AND name = ? ORDER BY ordinal",
                     [.int(id), .text(name)]).map { $0[0].blob ?? [] }
    }

    func appendStored(_ id: ObjectID, _ name: String, _ values: [[UInt8]]) throws {
        guard !values.isEmpty else { return }
        let name = Self.canonicalName(name)
        var ordinal = (try db.scalar("SELECT MAX(ordinal) FROM attributes WHERE object_id = ? AND name = ?",
                                     [.int(id), .text(name)])?.int ?? -1) + 1
        for v in values {
            try db.run("INSERT INTO attributes(object_id, name, value, value_norm, ordinal) VALUES(?, ?, ?, ?, ?)",
                       [.int(id), .text(name), .blob(v), .optional(DirectorySchema.storedNorm(v, name: name)), .int(ordinal)])
            ordinal += 1
        }
    }

    func removeStored(_ id: ObjectID, _ name: String) throws {
        try db.run("DELETE FROM attributes WHERE object_id = ? AND name = ?", [.int(id), .text(name)])
    }

    func replaceStored(_ id: ObjectID, _ name: String, _ values: [[UInt8]]) throws {
        try removeStored(id, name)
        try appendStored(id, name, values)
    }

    func touch(_ id: ObjectID) throws {
        try db.run("UPDATE objects SET usn_changed = ?, when_changed = ? WHERE id = ?",
                   [.int(try nextUSN()), .text(nowString), .int(id)])
    }

    // MARK: - Insert

    /// Inserts one object row plus its stored attributes; no defaults, no RID allocation.
    func insertObject(parentID: ObjectID?, dn: DN, objectClass: String, guid: GUID? = nil, sid: [UInt8]? = nil,
                      sam: String? = nil, upn: String? = nil, attributes: [(String, [[UInt8]])] = [],
                      deleted: Bool = false) throws -> ObjectID {
        guard let rdn = dn.rdn else { throw StoreError.invalidDN("cannot create the root DSE") }
        if try row(dnNorm: dn.normalized) != nil { throw StoreError.entryAlreadyExists(dn.description) }
        if let sam, try db.scalar("SELECT id FROM objects WHERE sam_account_name = ?", [.text(sam)]) != nil {
            throw StoreError.samAccountNameExists(sam)
        }
        if let upn, try db.scalar("SELECT id FROM objects WHERE upn = ?", [.text(upn)]) != nil {
            throw StoreError.upnExists(upn)
        }
        if let sid, try db.scalar("SELECT id FROM objects WHERE object_sid = ?", [.blob(sid)]) != nil {
            throw StoreError.constraintViolation("objectSid \((try? SID(bytes: sid))?.description ?? "?") is in use")
        }
        let usn = try nextUSN()
        let now = nowString
        let g = guid ?? GUID.random(rng)
        try db.run("""
            INSERT INTO objects(guid, parent_id, rdn_attr, rdn_value, dn, dn_norm, object_class, sam_account_name,
              object_sid, upn, usn_created, usn_changed, when_created, when_changed, deleted)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [.blob(g.bytes), parentID.map { .int($0) } ?? .null, .text(rdn.type), .text(rdn.value),
                  .text(dn.description), .text(dn.normalized), .text(DirectorySchema.canonicalClassName(objectClass)),
                  .optional(sam), .optional(sid), .optional(upn), .int(usn), .int(usn), .text(now), .text(now),
                  .int(deleted ? 1 : 0)])
        let id = db.lastInsertRowID
        for (name, values) in attributes { try appendStored(id, name, values) }
        return id
    }

    // MARK: - Materialising entries

    func entry(_ row: ObjectRow) throws -> DirectoryEntry {
        var attrs: [Attribute] = []
        var index: [String: Int] = [:]
        func put(_ name: String, _ values: [[UInt8]]) {
            guard !values.isEmpty else { return }
            let key = name.lowercased()
            if let i = index[key] { attrs[i].values += values } else {
                index[key] = attrs.count
                attrs.append(Attribute(name: name, values: values))
            }
        }
        func putDefault(_ name: String, _ value: String) {
            if index[name.lowercased()] == nil { put(name, [Array(value.utf8)]) }
        }

        let chain = DirectorySchema.classChain(row.objectClass)
        var classes = chain
        var stored: [(String, [UInt8])] = []
        for r in try db.query("SELECT name, value FROM attributes WHERE object_id = ? ORDER BY name, ordinal", [.int(row.id)]) {
            let name = r[0].text ?? "", value = r[1].blob ?? []
            if name.caseInsensitiveCompare("objectClass") == .orderedSame {
                let v = String(decoding: value, as: UTF8.self)
                if !classes.contains(where: { $0.caseInsensitiveCompare(v) == .orderedSame }) { classes.append(v) }
            } else {
                stored.append((name, value))
            }
        }
        put("objectClass", classes.map { Array($0.utf8) })
        for (name, value) in stored { put(name, [value]) }

        for r in try db.query("""
            SELECT l.attr, o.dn FROM links l JOIN objects o ON o.id = l.target_id
            WHERE l.source_id = ? ORDER BY l.rowid
            """, [.int(row.id)]) {
            put(DirectorySchema.forwardLink(r[0].text ?? "") ?? (r[0].text ?? ""), [r[1].blob ?? []])
        }
        for r in try db.query("""
            SELECT l.attr, o.dn FROM links l JOIN objects o ON o.id = l.source_id
            WHERE l.target_id = ? AND o.deleted = 0 ORDER BY l.rowid
            """, [.int(row.id)]) {
            let fwd = DirectorySchema.forwardLink(r[0].text ?? "") ?? ""
            if let back = DirectorySchema.linkPairs[fwd] { put(back, [r[1].blob ?? []]) }
        }

        put("distinguishedName", [Array(row.dn.utf8)])
        put("objectGUID", [row.guid.bytes])
        if let sid = row.sid { put("objectSid", [sid]) }
        if let sam = row.sam { put("sAMAccountName", [Array(sam.utf8)]) }
        if let upn = row.upn { put("userPrincipalName", [Array(upn.utf8)]) }
        put("name", [Array(row.rdnValue.utf8)])
        put("whenCreated", [Array(row.whenCreated.utf8)])
        put("whenChanged", [Array(row.whenChanged.utf8)])
        put("uSNCreated", [Array(String(row.usnCreated).utf8)])
        put("uSNChanged", [Array(String(row.usnChanged).utf8)])
        putDefault("instanceType", "4")
        if let info = cachedInfo {
            let category = DirectorySchema.objectClass(row.objectClass).flatMap { DirectorySchema.objectClass($0.category)?.cn }
                ?? row.objectClass
            put("objectCategory", [Array(info.schemaDN.child(RDN("CN", category)).description.utf8)])
            if index["ntsecuritydescriptor"] == nil { put("nTSecurityDescriptor", [try defaultSD(row.objectClass, info)]) }
        }

        func firstInt(_ name: String) -> Int64? {
            index[name.lowercased()].flatMap { Int64(String(decoding: attrs[$0].values.first ?? [], as: UTF8.self)) }
        }
        if chain.contains("user") {
            let isComputer = chain.contains("computer")
            putDefault("userAccountControl", String(Self.legacyReadUAC(computer: isComputer)))
            let uac = UInt32(truncatingIfNeeded: firstInt("userAccountControl") ?? 0)
            putDefault("primaryGroupID", String(Self.defaultPrimaryGroup(uac: uac, computer: isComputer)))
            let pls = try db.scalar("SELECT pwd_last_set FROM secrets WHERE object_id = ?", [.int(row.id)])?.text
            putDefault("pwdLastSet", pls ?? "0")
            putDefault("accountExpires", String(Int64.max))
            putDefault("lastLogon", "0")
            putDefault("logonCount", "0")
            putDefault("badPwdCount", "0")
            putDefault("msDS-SupportedEncryptionTypes", "28")
        }
        if let t = Self.samAccountType(chain: chain, uac: firstInt("userAccountControl"), groupType: firstInt("groupType")) {
            put("sAMAccountType", [Array(String(t).utf8)])
        }
        return DirectoryEntry(id: row.id, dn: row.parsedDN, guid: row.guid, objectClass: row.objectClass,
                              isDeleted: row.deleted, parentID: row.parentID, attributes: attrs)
    }

    /// `userAccountControl` stored on a new account that names none: a workstation trust for a
    /// computer, NORMAL_ACCOUNT (0x200) for a user — as AD, the password does not "never
    /// expire" unless the admin says so, so "must change at next logon" (`pwdLastSet` 0) is
    /// honoured by the KDC, LDAP bind (773) and Netlogon (1 Oct 2026; was 0x10200).
    static func defaultUAC(computer: Bool) -> UInt32 {
        computer ? UserAccountControl.workstationTrustAccount : UserAccountControl.normalAccount
    }

    /// What a user or computer read without a stored `userAccountControl` shows: the pre-1 Oct
    /// 2026 default, so an account from before keeps behaving exactly as it did.
    static func legacyReadUAC(computer: Bool) -> UInt32 {
        computer ? UserAccountControl.workstationTrustAccount
            : UserAccountControl.normalAccount | UserAccountControl.dontExpirePassword
    }

    static func defaultPrimaryGroup(uac: UInt32, computer: Bool) -> UInt32 {
        if uac & UserAccountControl.serverTrustAccount != 0 { return 516 }
        return computer || uac & UserAccountControl.workstationTrustAccount != 0 ? 515 : 513
    }

    static func samAccountType(chain: [String], uac: Int64?, groupType: Int64?) -> UInt32? {
        if chain.contains("user") {
            let u = UInt32(truncatingIfNeeded: uac ?? 0)
            if u & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount) != 0 {
                return SAMAccountType.machineAccount
            }
            if u & UserAccountControl.interdomainTrustAccount != 0 { return SAMAccountType.trustAccount }
            return SAMAccountType.userObject
        }
        if chain.contains("group") {
            let gt = Int32(truncatingIfNeeded: groupType ?? Int64(GroupType.globalSecurity))
            let security = gt & GroupType.security != 0
            if gt & (GroupType.resourceGroup | GroupType.builtinLocal) != 0 {
                return security ? SAMAccountType.aliasObject : SAMAccountType.nonSecurityAliasObject
            }
            return security ? SAMAccountType.groupObject : SAMAccountType.nonSecurityGroupObject
        }
        return nil
    }

    func defaultSD(_ objectClass: String, _ info: DomainInfo) throws -> [UInt8] {
        let key = objectClass.lowercased()
        if let sd = sdCache[key] { return sd }
        let sd = try SecurityDescriptor.fromSDDL(SecurityDescriptor.defaultSDDL(for: objectClass), domainSID: info.domainSID)
        sdCache[key] = sd
        return sd
    }

    // MARK: - Reads

    /// The object at `dn`, or nil.
    public func read(dn: DN, attrs: [String]? = nil, includeDeleted: Bool = false) throws -> DirectoryEntry? {
        guard let r = try row(dnNorm: dn.normalized), includeDeleted || !r.deleted else { return nil }
        return try entry(r).projected(attrs)
    }

    /// The object with row id `id`, or nil.
    public func read(id: ObjectID, attrs: [String]? = nil, includeDeleted: Bool = false) throws -> DirectoryEntry? {
        guard let r = try row(id: id), includeDeleted || !r.deleted else { return nil }
        return try entry(r).projected(attrs)
    }

    /// The object with this `objectGUID`, or nil (tombstones included when asked).
    public func read(guid: GUID, attrs: [String]? = nil, includeDeleted: Bool = false) throws -> DirectoryEntry? {
        guard let r = try rows(where: "o.guid = ?", [.blob(guid.bytes)]).first, includeDeleted || !r.deleted else { return nil }
        return try entry(r).projected(attrs)
    }

    /// The object with this `objectSid`, or nil.
    public func read(sid: SID, attrs: [String]? = nil) throws -> DirectoryEntry? {
        guard let r = try rows(where: "o.object_sid = ? AND o.deleted = 0", [.blob(sid.bytes)]).first else { return nil }
        return try entry(r).projected(attrs)
    }

    /// The live object with this `sAMAccountName` (case-insensitive), or nil.
    public func read(sam: String, attrs: [String]? = nil) throws -> DirectoryEntry? {
        guard let r = try rows(where: "o.sam_account_name = ?", [.text(sam)]).first else { return nil }
        return try entry(r).projected(attrs)
    }

    /// The live object with this explicit `userPrincipalName` (case-insensitive), or nil.
    public func read(upn: String, attrs: [String]? = nil) throws -> DirectoryEntry? {
        guard let r = try rows(where: "o.upn = ?", [.text(upn)]).first else { return nil }
        return try entry(r).projected(attrs)
    }

    /// Direct children of `id`, ordered by id.
    public func children(of id: ObjectID, includeDeleted: Bool = false) throws -> [DirectoryEntry] {
        try rows(where: includeDeleted ? "o.parent_id = ?" : "o.parent_id = ? AND o.deleted = 0", [.int(id)]).map(entry)
    }

    /// `id` and everything below it (within its naming context), ordered by id.
    public func subtree(of id: ObjectID, includeDeleted: Bool = false) throws -> [DirectoryEntry] {
        let rows = try db.query("""
            WITH RECURSIVE sub(id) AS (SELECT ? UNION ALL SELECT c.id FROM objects c JOIN sub ON c.parent_id = sub.id)
            SELECT \(Self.rowColumns) FROM objects o WHERE o.id IN (SELECT id FROM sub)\(includeDeleted ? "" : " AND o.deleted = 0")
            ORDER BY o.id
            """, [.int(id)]).map(decodeRow)
        return try rows.map(entry)
    }

    // MARK: - Search

    /// Evaluates `filter` over the scope below `base`. Equality, presence and their AND/OR
    /// combinations on indexed columns, stored attributes and links narrow the candidates in
    /// SQL; the full filter is then evaluated in Swift on each materialised entry.
    /// - Parameters:
    ///   - attrs: attributes to return (`nil`/`*` all, `1.1` none).
    ///   - sizeLimit: stop after this many matches.
    ///   - after: only objects with a larger id (paged results cookie).
    public func search(base: DN, scope: SearchScope, filter: FilterAST = .everything, attrs: [String]? = nil,
                       includeDeleted: Bool = false, sizeLimit: Int? = nil,
                       after: ObjectID? = nil) throws -> [DirectoryEntry] {
        try searchEntries(base: base, scope: scope, filter: filter, includeDeleted: includeDeleted,
                          sizeLimit: sizeLimit, after: after).map { $0.projected(attrs) }
    }

    /// Number of entries `search` would return.
    public func count(base: DN, scope: SearchScope, filter: FilterAST = .everything,
                      includeDeleted: Bool = false) throws -> Int {
        try searchEntries(base: base, scope: scope, filter: filter, includeDeleted: includeDeleted,
                          sizeLimit: nil, after: nil).count
    }

    func searchEntries(base: DN, scope: SearchScope, filter: FilterAST, includeDeleted: Bool,
                       sizeLimit: Int?, after: ObjectID?) throws -> [DirectoryEntry] {
        let baseRow = try requireRow(dn: base, includeDeleted: includeDeleted)
        var sql: String
        var params: [SQLValue] = [.int(baseRow.id)]
        switch scope {
        case .base:
            sql = "SELECT \(Self.rowColumns) FROM objects o WHERE o.id = ?"
        case .oneLevel:
            sql = "SELECT \(Self.rowColumns) FROM objects o WHERE o.parent_id = ?"
        case .subtree:
            sql = """
                WITH RECURSIVE sub(id) AS (SELECT ? UNION ALL SELECT c.id FROM objects c JOIN sub ON c.parent_id = sub.id)
                SELECT \(Self.rowColumns) FROM objects o WHERE o.id IN (SELECT id FROM sub)
                """
        }
        if !includeDeleted { sql += " AND o.deleted = 0" }
        if let after {
            sql += " AND o.id > ?"
            params.append(.int(after))
        }
        let evaluator = FilterEvaluator(schemaDN: cachedInfo?.schemaDN, chain: nil)
        if let (clause, p) = prefilter(filter, evaluator) {
            sql += " AND (\(clause))"
            params += p
        }
        sql += " ORDER BY o.id"
        var chainEvaluator = evaluator
        chainEvaluator.chain = { entry, attr, target in try self.inChain(entry, attr, target) }
        var results: [DirectoryEntry] = []
        for r in try db.query(sql, params).map(decodeRow) {
            let e = try entry(r)
            if try chainEvaluator.evaluate(filter, e) == .true {
                results.append(e)
                if let sizeLimit, results.count >= sizeLimit { break }
            }
        }
        return results
    }

    /// Attributes whose values are computed or defaulted on read: never narrowed in SQL.
    static let computedAttributes: Set<String> = [
        "objectcategory", "name", "whencreated", "whenchanged", "usncreated", "usnchanged", "instancetype",
        "ntsecuritydescriptor", "pwdlastset", "accountexpires", "lastlogon", "logoncount", "badpwdcount",
        "msds-supportedencryptiontypes", "primarygroupid", "useraccountcontrol", "samaccounttype",
    ]

    /// A SQL condition that every matching row satisfies (a superset), or nil.
    func prefilter(_ f: FilterAST, _ ev: FilterEvaluator) -> (String, [SQLValue])? {
        switch f {
        case .and(let list):
            let parts = list.compactMap { prefilter($0, ev) }
            guard !parts.isEmpty else { return nil }
            return (parts.map { "(\($0.0))" }.joined(separator: " AND "), parts.flatMap(\.1))
        case .or(let list):
            var parts: [(String, [SQLValue])] = []
            for sub in list {
                guard let p = prefilter(sub, ev) else { return nil }
                parts.append(p)
            }
            guard !parts.isEmpty else { return nil }
            return (parts.map { "(\($0.0))" }.joined(separator: " OR "), parts.flatMap(\.1))
        case let .equality(attr, value):
            return equalityClause(attr, value, ev)
        case .present(let attr):
            let l = attr.lowercased()
            switch l {
            case "objectclass": return nil
            case "samaccountname": return ("o.sam_account_name IS NOT NULL", [])
            case "userprincipalname": return ("o.upn IS NOT NULL", [])
            case "objectsid": return ("o.object_sid IS NOT NULL", [])
            default:
                if Self.computedAttributes.contains(l) || DirectorySchema.backLink(l) != nil
                    || DirectorySchema.forwardLink(l) != nil || l == "distinguishedname" || l == "objectguid" {
                    return nil
                }
                return ("o.id IN (SELECT object_id FROM attributes WHERE name = ?)", [.text(attr)])
            }
        default:
            return nil
        }
    }

    private func equalityClause(_ attr: String, _ value: [UInt8], _ ev: FilterEvaluator) -> (String, [SQLValue])? {
        let l = attr.lowercased()
        guard let key = ev.assertionKey(attr, value) else { return nil }
        let text = String(decoding: value, as: UTF8.self)
        switch l {
        case "samaccountname":
            // NOCASE folds ASCII only; leave non-ASCII to the Swift pass.
            return text.allSatisfy(\.isASCII) ? ("o.sam_account_name = ?", [.text(text)]) : nil
        case "userprincipalname":
            return text.allSatisfy(\.isASCII) ? ("o.upn = ?", [.text(text)]) : nil
        case "objectsid": return ("o.object_sid = ?", [.blob(key)])
        case "objectguid": return ("o.guid = ?", [.blob(key)])
        case "distinguishedname": return ("o.dn_norm = ?", [.text(String(decoding: key, as: UTF8.self))])
        case "objectclass":
            var classes = DirectorySchema.subclasses(of: text).map { $0.lowercased() }
            if classes.isEmpty { classes = [text.lowercased()] }
            let marks = classes.map { _ in "?" }.joined(separator: ", ")
            return ("lower(o.object_class) IN (\(marks)) OR o.id IN (SELECT object_id FROM attributes WHERE name = 'objectClass' AND value_norm = ?)",
                    classes.map { .text($0) } + [.text(text.lowercased())])
        default:
            break
        }
        if let fwd = DirectorySchema.forwardLink(l) {
            return ("o.id IN (SELECT l.source_id FROM links l JOIN objects t ON t.id = l.target_id WHERE l.attr = ? AND t.dn_norm = ?)",
                    [.text(fwd), .text(String(decoding: key, as: UTF8.self))])
        }
        if let back = DirectorySchema.backLink(l), let fwd = DirectorySchema.linkPairs.first(where: { $0.value == back })?.key {
            return ("o.id IN (SELECT l.target_id FROM links l JOIN objects s ON s.id = l.source_id WHERE l.attr = ? AND s.dn_norm = ?)",
                    [.text(fwd), .text(String(decoding: key, as: UTF8.self))])
        }
        if Self.computedAttributes.contains(l) { return nil }
        if DirectorySchema.syntax(of: attr).isBinary {
            return ("o.id IN (SELECT object_id FROM attributes WHERE name = ? AND value = ?)", [.text(attr), .blob(key)])
        }
        return ("o.id IN (SELECT object_id FROM attributes WHERE name = ? AND value_norm = ?)",
                [.text(attr), .text(String(decoding: key, as: UTF8.self))])
    }

    /// `LDAP_MATCHING_RULE_IN_CHAIN`: `memberOf:…:=G` is true when the entry reaches G by
    /// following member links upwards; `member:…:=U` when U is reachable downwards.
    func inChain(_ e: DirectoryEntry, _ attr: String, _ target: DN) throws -> Bool {
        guard let t = try row(dnNorm: target.normalized) else { return false }
        if let fwd = DirectorySchema.forwardLink(attr) {
            return try reachable(from: e.id, to: t.id, attr: fwd, downwards: true)
        }
        if let back = DirectorySchema.backLink(attr), let fwd = DirectorySchema.linkPairs.first(where: { $0.value == back })?.key {
            return try reachable(from: e.id, to: t.id, attr: fwd, downwards: false)
        }
        return false
    }

    private func reachable(from: ObjectID, to: ObjectID, attr: String, downwards: Bool) throws -> Bool {
        let (a, b) = downwards ? ("target_id", "source_id") : ("source_id", "target_id")
        return try db.scalar("""
            WITH RECURSIVE r(id) AS (
              SELECT \(a) FROM links WHERE \(b) = ? AND attr = ?
              UNION SELECT l.\(a) FROM links l JOIN r ON l.\(b) = r.id WHERE l.attr = ?)
            SELECT 1 FROM r WHERE id = ? LIMIT 1
            """, [.int(from), .text(attr), .text(attr), .int(to)]) != nil
    }

    /// Primary groups any account may name: Domain Users, Domain Guests, Domain Computers.
    static let unprivilegedPrimaryGroups: Set<UInt32> = [513, 514, 515]

    /// The `primaryGroupID` that counts for `e` (group membership, the PAC, SAMR rights), or nil
    /// when it has none. Security audit (1 Oct 2026): `primaryGroupID` confers membership on its
    /// own, so a value naming a group the account is not an explicit member of (`member` links,
    /// transitively) — e.g. 512 written through SAMR SetInformationUser — is ignored in favour of
    /// the account type's default (513 / 515 / 516). Domain Users / Guests / Computers, the
    /// default for the account type, and 521 for an RODC are always valid.
    public func effectivePrimaryGroupRID(_ e: DirectoryEntry) throws -> UInt32? {
        guard let raw = e.int("primaryGroupID") else { return nil }
        let pg = UInt32(truncatingIfNeeded: raw)
        return try isValidPrimaryGroup(pg, for: e) ? pg : defaultPrimaryGroup(of: e)
    }

    /// True when `rid` may be `e`'s primary group: Domain Users / Guests / Computers, the account
    /// type's default, 521 for an RODC, or a group `e` is an explicit member of (MS-SAMR
    /// §3.1.1.8.5: anything else is STATUS_MEMBER_NOT_IN_GROUP).
    public func isValidPrimaryGroup(_ rid: UInt32, for e: DirectoryEntry) throws -> Bool {
        let uac = UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0)
        if rid == defaultPrimaryGroup(of: e) || Self.unprivilegedPrimaryGroups.contains(rid) { return true }
        if rid == 521, uac & UserAccountControl.partialSecretsAccount != 0 { return true }
        return try isExplicitMember(e.id, ofDomainRID: rid)
    }

    private func defaultPrimaryGroup(of e: DirectoryEntry) -> UInt32 {
        let uac = UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0)
        return Self.defaultPrimaryGroup(uac: uac, computer: DirectorySchema.classChain(e.objectClass).contains("computer"))
    }

    /// True when `id` reaches the domain group `rid` through `member` links (primary groups not
    /// followed) — the membership AD requires before a group may become the primary group.
    public func isExplicitMember(_ id: ObjectID, ofDomainRID rid: UInt32) throws -> Bool {
        guard let domainSID = cachedInfo?.domainSID, let sid = try? domainSID.appending(rid: rid),
              let g = try rows(where: "o.object_sid = ?", [.blob(sid.bytes)]).first, !g.deleted else { return false }
        return try reachable(from: id, to: g.id, attr: "member", downwards: false)
    }

    /// Every group `id` belongs to, transitively, including its primary group and the groups
    /// that group belongs to. Ordered by id.
    public func transitiveGroups(of id: ObjectID) throws -> [ObjectID] {
        var seen = Set<ObjectID>()
        var queue: [ObjectID] = try db.query("SELECT source_id FROM links WHERE target_id = ? AND attr = 'member'",
                                             [.int(id)]).compactMap { $0[0].int }
        if let e = try read(id: id), let pg = try effectivePrimaryGroupRID(e), let domainSID = cachedInfo?.domainSID,
           let sid = try? domainSID.appending(rid: pg),
           let g = try rows(where: "o.object_sid = ?", [.blob(sid.bytes)]).first {
            queue.append(g.id)
        }
        while let next = queue.popLast() {
            guard seen.insert(next).inserted else { continue }
            queue += try db.query("SELECT source_id FROM links WHERE target_id = ? AND attr = 'member'",
                                  [.int(next)]).compactMap { $0[0].int }
        }
        return try seen.sorted().filter { try row(id: $0).map { !$0.deleted } ?? false }
    }

    /// SIDs of `transitiveGroups(of:)` (domain and builtin groups alike).
    public func groupSIDs(of id: ObjectID) throws -> [SID] {
        try transitiveGroups(of: id).compactMap { try row(id: $0)?.sid.flatMap { try? SID(bytes: $0) } }
    }
}
