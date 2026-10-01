import Foundation

// PK-1: the certificate authority's tables. PKIKit owns their meaning (templates, issuance,
// revocation, CRLs); the Store only keeps the rows so the CLI, `serve` and later the UI / LDAP
// publishing (PK-5) share one source of truth. Dates are Unix seconds, lists are joined text.

/// One certificate template (`pki_templates`).
public struct PKITemplateRow: Sendable, Equatable {
    public var name: String
    public var displayName: String
    /// `msPKI-Cert-Template-OID` (under the forest arc `1.3.6.1.4.1.311.21.8.…`).
    public var oid: String
    public var validityDays: Int
    public var renewalDays: Int
    /// X.509 KeyUsage bits: bit i set = KeyUsage bit i (0 digitalSignature … 8 decipherOnly).
    public var keyUsage: Int
    /// Extended key usage OIDs (dotted).
    public var ekus: [String]
    /// `dnsHostName`, `upn`, `fromRequest` or `none`.
    public var sanPolicy: String
    public var enrolAllowedGroupSIDs: [String]
    public var autoEnroll: Bool
    public var manualApproval: Bool
    public var minKeyBits: Int
    /// `rsa`, `p256`, `p384`, `p521`.
    public var allowedKeyTypes: [String]
    public var enabled: Bool
    public var builtIn: Bool
    /// The CA that issues this template (nil: the current CA). 1 Oct 2026: the 802.1X 192-bit
    /// templates are bound to the P-384 CA.
    public var issuingCA: String?

    public init(name: String, displayName: String, oid: String, validityDays: Int, renewalDays: Int, keyUsage: Int,
                ekus: [String], sanPolicy: String, enrolAllowedGroupSIDs: [String], autoEnroll: Bool,
                manualApproval: Bool, minKeyBits: Int, allowedKeyTypes: [String], enabled: Bool, builtIn: Bool,
                issuingCA: String? = nil) {
        self.issuingCA = issuingCA
        self.name = name
        self.displayName = displayName
        self.oid = oid
        self.validityDays = validityDays
        self.renewalDays = renewalDays
        self.keyUsage = keyUsage
        self.ekus = ekus
        self.sanPolicy = sanPolicy
        self.enrolAllowedGroupSIDs = enrolAllowedGroupSIDs
        self.autoEnroll = autoEnroll
        self.manualApproval = manualApproval
        self.minKeyBits = minKeyBits
        self.allowedKeyTypes = allowedKeyTypes
        self.enabled = enabled
        self.builtIn = builtIn
    }
}

/// One issued certificate (`pki_issued`).
public struct PKIIssuedRow: Sendable, Equatable {
    /// Lower-case hex of the serial number's DER INTEGER content.
    public var serial: String
    public var caName: String
    public var templateName: String
    public var subject: String
    /// `DNS:host`, `IP:1.2.3.4`, `UPN:alice@lab.sheep`, `email:…`, `URI:…`.
    public var subjectAltNames: [String]
    public var notBefore: Date
    public var notAfter: Date
    public var requesterSID: String?
    public var requesterName: String
    public var der: [UInt8]
    public var issuedAt: Date
    public var revoked: Bool
    /// RFC 5280 CRLReason code.
    public var revocationReason: Int?
    public var revocationDate: Date?

    public init(serial: String, caName: String, templateName: String, subject: String, subjectAltNames: [String],
                notBefore: Date, notAfter: Date, requesterSID: String?, requesterName: String, der: [UInt8],
                issuedAt: Date, revoked: Bool = false, revocationReason: Int? = nil, revocationDate: Date? = nil) {
        self.serial = serial
        self.caName = caName
        self.templateName = templateName
        self.subject = subject
        self.subjectAltNames = subjectAltNames
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.requesterSID = requesterSID
        self.requesterName = requesterName
        self.der = der
        self.issuedAt = issuedAt
        self.revoked = revoked
        self.revocationReason = revocationReason
        self.revocationDate = revocationDate
    }
}

/// The latest CRL of one CA (`pki_crls`).
public struct PKICRLRow: Sendable, Equatable {
    public var caName: String
    public var crlNumber: Int64
    public var thisUpdate: Date
    public var nextUpdate: Date
    public var der: [UInt8]

    public init(caName: String, crlNumber: Int64, thisUpdate: Date, nextUpdate: Date, der: [UInt8]) {
        self.caName = caName
        self.crlNumber = crlNumber
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self.der = der
    }
}

extension DirectoryStore {
    static func createPKISchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS pki_templates(
              name TEXT PRIMARY KEY COLLATE NOCASE,
              display_name TEXT NOT NULL,
              oid TEXT NOT NULL UNIQUE,
              validity_days INTEGER NOT NULL,
              renewal_days INTEGER NOT NULL,
              key_usage INTEGER NOT NULL,
              ekus TEXT NOT NULL,
              san_policy TEXT NOT NULL,
              enrol_groups TEXT NOT NULL,
              auto_enroll INTEGER NOT NULL,
              manual_approval INTEGER NOT NULL,
              min_key_bits INTEGER NOT NULL,
              allowed_key_types TEXT NOT NULL,
              enabled INTEGER NOT NULL,
              builtin INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS pki_issued(
              serial TEXT PRIMARY KEY,
              ca TEXT NOT NULL,
              template TEXT NOT NULL,
              subject TEXT NOT NULL,
              sans TEXT NOT NULL,
              not_before INTEGER NOT NULL,
              not_after INTEGER NOT NULL,
              requester_sid TEXT NULL,
              requester_name TEXT NOT NULL,
              der BLOB NOT NULL,
              issued_at INTEGER NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0,
              revocation_reason INTEGER NULL,
              revocation_date INTEGER NULL);
            CREATE INDEX IF NOT EXISTS pki_issued_ca ON pki_issued(ca, revoked);
            CREATE INDEX IF NOT EXISTS pki_issued_requester ON pki_issued(requester_sid);
            CREATE TABLE IF NOT EXISTS pki_crls(
              ca TEXT PRIMARY KEY,
              crl_number INTEGER NOT NULL,
              this_update INTEGER NOT NULL,
              next_update INTEGER NOT NULL,
              der BLOB NOT NULL);
            """)
        try createPKIChallengeSchema(db)
        try createRadiusSchema(db)
        let templateColumns = try db.query("PRAGMA table_info(pki_templates)").compactMap { $0[1].text }
        if !templateColumns.contains("issuing_ca") { try db.exec("ALTER TABLE pki_templates ADD COLUMN issuing_ca TEXT NULL") }
    }

    // MARK: Templates

    private static let templateColumns = """
        name, display_name, oid, validity_days, renewal_days, key_usage, ekus, san_policy, enrol_groups,
        auto_enroll, manual_approval, min_key_bits, allowed_key_types, enabled, builtin, issuing_ca
        """

    public func pkiTemplates() throws -> [PKITemplateRow] {
        try db.query("SELECT \(Self.templateColumns) FROM pki_templates ORDER BY name").map(Self.templateRow)
    }

    public func pkiTemplate(named name: String) throws -> PKITemplateRow? {
        try db.query("SELECT \(Self.templateColumns) FROM pki_templates WHERE name = ?", [.text(name)])
            .first.map(Self.templateRow)
    }

    /// Inserts or replaces the template with this name.
    public func savePKITemplate(_ t: PKITemplateRow) throws {
        try db.run("""
            INSERT INTO pki_templates(\(Self.templateColumns)) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET display_name = excluded.display_name, oid = excluded.oid,
              validity_days = excluded.validity_days, renewal_days = excluded.renewal_days,
              key_usage = excluded.key_usage, ekus = excluded.ekus, san_policy = excluded.san_policy,
              enrol_groups = excluded.enrol_groups, auto_enroll = excluded.auto_enroll,
              manual_approval = excluded.manual_approval, min_key_bits = excluded.min_key_bits,
              allowed_key_types = excluded.allowed_key_types, enabled = excluded.enabled, builtin = excluded.builtin,
              issuing_ca = excluded.issuing_ca
            """, [
                .text(t.name), .text(t.displayName), .text(t.oid), .int(Int64(t.validityDays)), .int(Int64(t.renewalDays)),
                .int(Int64(t.keyUsage)), .text(t.ekus.joined(separator: ",")), .text(t.sanPolicy),
                .text(t.enrolAllowedGroupSIDs.joined(separator: ",")), .int(t.autoEnroll ? 1 : 0),
                .int(t.manualApproval ? 1 : 0), .int(Int64(t.minKeyBits)), .text(t.allowedKeyTypes.joined(separator: ",")),
                .int(t.enabled ? 1 : 0), .int(t.builtIn ? 1 : 0), .optional(t.issuingCA),
            ])
    }

    /// Removes a template; true when one was removed.
    @discardableResult
    public func deletePKITemplate(named name: String) throws -> Bool {
        try db.run("DELETE FROM pki_templates WHERE name = ?", [.text(name)])
        return db.changes > 0
    }

    private static func list(_ v: SQLValue, separator: Character = ",") -> [String] {
        (v.text ?? "").split(separator: separator, omittingEmptySubsequences: true).map(String.init)
    }

    private static func templateRow(_ r: [SQLValue]) -> PKITemplateRow {
        PKITemplateRow(
            name: r[0].text ?? "", displayName: r[1].text ?? "", oid: r[2].text ?? "",
            validityDays: Int(r[3].int ?? 0), renewalDays: Int(r[4].int ?? 0), keyUsage: Int(r[5].int ?? 0),
            ekus: list(r[6]), sanPolicy: r[7].text ?? "none", enrolAllowedGroupSIDs: list(r[8]),
            autoEnroll: (r[9].int ?? 0) != 0, manualApproval: (r[10].int ?? 0) != 0, minKeyBits: Int(r[11].int ?? 0),
            allowedKeyTypes: list(r[12]), enabled: (r[13].int ?? 0) != 0, builtIn: (r[14].int ?? 0) != 0,
            issuingCA: r.count > 15 ? r[15].text : nil)
    }

    // MARK: Issued certificates

    private static let issuedColumns = """
        serial, ca, template, subject, sans, not_before, not_after, requester_sid, requester_name, der, issued_at,
        revoked, revocation_reason, revocation_date
        """

    /// Records an issued certificate. A duplicate serial is a `constraintViolation`.
    public func insertIssuedCertificate(_ row: PKIIssuedRow) throws {
        try db.run("INSERT INTO pki_issued(\(Self.issuedColumns)) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
            .text(row.serial.lowercased()), .text(row.caName), .text(row.templateName), .text(row.subject),
            .text(row.subjectAltNames.joined(separator: "\n")), .int(Self.seconds(row.notBefore)),
            .int(Self.seconds(row.notAfter)), .optional(row.requesterSID), .text(row.requesterName), .blob(row.der),
            .int(Self.seconds(row.issuedAt)), .int(row.revoked ? 1 : 0),
            row.revocationReason.map { .int(Int64($0)) } ?? .null,
            row.revocationDate.map { .int(Self.seconds($0)) } ?? .null,
        ])
    }

    /// Issued certificates, newest first; `caName` narrows to one CA, `revokedOnly` to revoked ones.
    public func issuedCertificates(caName: String? = nil, revokedOnly: Bool = false) throws -> [PKIIssuedRow] {
        var sql = "SELECT \(Self.issuedColumns) FROM pki_issued WHERE 1 = 1"
        var params: [SQLValue] = []
        if let caName { sql += " AND ca = ?"; params.append(.text(caName)) }
        if revokedOnly { sql += " AND revoked = 1" }
        sql += " ORDER BY issued_at DESC, serial"
        return try db.query(sql, params).map(Self.issuedRow)
    }

    public func issuedCertificate(serial: String) throws -> PKIIssuedRow? {
        try db.query("SELECT \(Self.issuedColumns) FROM pki_issued WHERE serial = ?", [.text(serial.lowercased())])
            .first.map(Self.issuedRow)
    }

    /// Marks a certificate revoked (or updates the reason/date). False when the serial is unknown.
    @discardableResult
    public func setRevocation(serial: String, reason: Int, date: Date) throws -> Bool {
        try db.run("UPDATE pki_issued SET revoked = 1, revocation_reason = ?, revocation_date = ? WHERE serial = ?",
                   [.int(Int64(reason)), .int(Self.seconds(date)), .text(serial.lowercased())])
        return db.changes > 0
    }

    private static func issuedRow(_ r: [SQLValue]) -> PKIIssuedRow {
        PKIIssuedRow(
            serial: r[0].text ?? "", caName: r[1].text ?? "", templateName: r[2].text ?? "", subject: r[3].text ?? "",
            subjectAltNames: list(r[4], separator: "\n"), notBefore: date(r[5]), notAfter: date(r[6]),
            requesterSID: r[7].text, requesterName: r[8].text ?? "", der: r[9].blob ?? [], issuedAt: date(r[10]),
            revoked: (r[11].int ?? 0) != 0, revocationReason: r[12].int.map { Int($0) },
            revocationDate: r[13].int.map { Date(timeIntervalSince1970: TimeInterval($0)) })
    }

    // MARK: CRLs

    public func pkiCRL(caName: String) throws -> PKICRLRow? {
        try db.query("SELECT ca, crl_number, this_update, next_update, der FROM pki_crls WHERE ca = ?", [.text(caName)])
            .first.map { r in
                PKICRLRow(caName: r[0].text ?? "", crlNumber: r[1].int ?? 0, thisUpdate: Self.date(r[2]),
                          nextUpdate: Self.date(r[3]), der: r[4].blob ?? [])
            }
    }

    public func savePKICRL(_ row: PKICRLRow) throws {
        try db.run("""
            INSERT INTO pki_crls(ca, crl_number, this_update, next_update, der) VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(ca) DO UPDATE SET crl_number = excluded.crl_number, this_update = excluded.this_update,
              next_update = excluded.next_update, der = excluded.der
            """, [.text(row.caName), .int(row.crlNumber), .int(Self.seconds(row.thisUpdate)),
                  .int(Self.seconds(row.nextUpdate)), .blob(row.der)])
    }

    private static func seconds(_ date: Date) -> Int64 { Int64(date.timeIntervalSince1970.rounded(.down)) }
    private static func date(_ v: SQLValue) -> Date { Date(timeIntervalSince1970: TimeInterval(v.int ?? 0)) }
}

// PK-7: SCEP / EST enrollment challenges. Only a SHA-256 of the challenge is kept (the
// challenge itself is shown once, by `labdc scep challenge new`).

/// One enrollment challenge (`pki_challenges`).
public struct PKIChallengeRow: Sendable, Equatable {
    /// Short random hex id (`scep challenge list` / `revoke`).
    public var id: String
    /// The device it is for (nil: any device); matched case-insensitively.
    public var device: String?
    /// The certificate template it enrols for.
    public var template: String
    /// Lower-case hex SHA-256 of the challenge text.
    public var hash: String
    /// Static: usable any number of times until it expires or is revoked (else one-time).
    public var reusable: Bool
    public var createdAt: Date
    public var expiresAt: Date
    /// Last use (for one-time challenges: the use).
    public var usedAt: Date?
    public var usedBy: String?
    public var useCount: Int
    public var revoked: Bool

    public init(id: String, device: String?, template: String, hash: String, reusable: Bool, createdAt: Date,
                expiresAt: Date, usedAt: Date? = nil, usedBy: String? = nil, useCount: Int = 0, revoked: Bool = false) {
        self.id = id
        self.device = device
        self.template = template
        self.hash = hash
        self.reusable = reusable
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.usedAt = usedAt
        self.usedBy = usedBy
        self.useCount = useCount
        self.revoked = revoked
    }
}

extension DirectoryStore {
    /// Phase 4a: RADIUS NAS clients and the ordered policy rules (idempotent, runs on open —
    /// existing stores pick the tables up without a schema-version bump).
    static func createRadiusSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS radius_nas(
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              ip TEXT NOT NULL,
              secret TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS radius_policies(
              id TEXT PRIMARY KEY,
              position INTEGER NOT NULL,
              name TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              action TEXT NOT NULL,
              rows_json TEXT NOT NULL,
              attrs_json TEXT NOT NULL);
            """)
        // 30 Sep 2026: the Accept-with-VLAN shorthand's VLAN.
        let columns = try db.query("PRAGMA table_info(radius_policies)").compactMap { $0[1].text }
        if !columns.contains("vlan") { try db.exec("ALTER TABLE radius_policies ADD COLUMN vlan TEXT NULL") }
        // 1 Oct 2026: per-NAS "Require Message-Authenticator" (Blast-RADIUS), on by default.
        let nasColumns = try db.query("PRAGMA table_info(radius_nas)").compactMap { $0[1].text }
        if !nasColumns.contains("require_ma") {
            try db.exec("ALTER TABLE radius_nas ADD COLUMN require_ma INTEGER NOT NULL DEFAULT 1")
        }
    }

    static func createPKIChallengeSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS pki_challenges(
              id TEXT PRIMARY KEY,
              device TEXT NULL COLLATE NOCASE,
              template TEXT NOT NULL,
              hash TEXT NOT NULL UNIQUE,
              reusable INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at INTEGER NULL,
              used_by TEXT NULL,
              use_count INTEGER NOT NULL DEFAULT 0,
              revoked INTEGER NOT NULL DEFAULT 0);
            """)
    }

    private static let challengeColumns =
        "id, device, template, hash, reusable, created_at, expires_at, used_at, used_by, use_count, revoked"

    public func insertPKIChallenge(_ row: PKIChallengeRow) throws {
        try db.run("INSERT INTO pki_challenges(\(Self.challengeColumns)) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
            .text(row.id), .optional(row.device), .text(row.template), .text(row.hash.lowercased()),
            .int(row.reusable ? 1 : 0), .int(Self.challengeSeconds(row.createdAt)), .int(Self.challengeSeconds(row.expiresAt)),
            row.usedAt.map { .int(Self.challengeSeconds($0)) } ?? .null, .optional(row.usedBy), .int(Int64(row.useCount)),
            .int(row.revoked ? 1 : 0),
        ])
    }

    /// Every challenge, newest first.
    public func pkiChallenges() throws -> [PKIChallengeRow] {
        try db.query("SELECT \(Self.challengeColumns) FROM pki_challenges ORDER BY created_at DESC, id").map(Self.challengeRow)
    }

    public func pkiChallenge(id: String) throws -> PKIChallengeRow? {
        try db.query("SELECT \(Self.challengeColumns) FROM pki_challenges WHERE id = ?", [.text(id.lowercased())])
            .first.map(Self.challengeRow)
    }

    public func pkiChallenge(hash: String) throws -> PKIChallengeRow? {
        try db.query("SELECT \(Self.challengeColumns) FROM pki_challenges WHERE hash = ?", [.text(hash.lowercased())])
            .first.map(Self.challengeRow)
    }

    /// Records a use. A one-time challenge is claimed only if unused (atomic); a reusable one
    /// while not revoked. False when the claim lost.
    @discardableResult
    public func claimPKIChallenge(id: String, by user: String, at date: Date) throws -> Bool {
        try db.run("""
            UPDATE pki_challenges SET used_at = ?, used_by = ?, use_count = use_count + 1
            WHERE id = ? AND revoked = 0 AND (reusable = 1 OR used_at IS NULL)
            """, [.int(Self.challengeSeconds(date)), .text(user), .text(id.lowercased())])
        return db.changes > 0
    }

    /// Gives a one-time challenge back after the enrollment it was claimed for failed.
    public func releasePKIChallenge(id: String) throws {
        try db.run("""
            UPDATE pki_challenges SET used_at = NULL, used_by = NULL, use_count = MAX(use_count - 1, 0)
            WHERE id = ? AND reusable = 0
            """, [.text(id.lowercased())])
    }

    /// False when there is no such challenge.
    @discardableResult
    public func revokePKIChallenge(id: String) throws -> Bool {
        try db.run("UPDATE pki_challenges SET revoked = 1 WHERE id = ?", [.text(id.lowercased())])
        return db.changes > 0
    }

    private static func challengeRow(_ r: [SQLValue]) -> PKIChallengeRow {
        PKIChallengeRow(
            id: r[0].text ?? "", device: r[1].text, template: r[2].text ?? "", hash: r[3].text ?? "",
            reusable: (r[4].int ?? 0) != 0, createdAt: challengeDate(r[5]), expiresAt: challengeDate(r[6]),
            usedAt: r[7].int.map { Date(timeIntervalSince1970: TimeInterval($0)) }, usedBy: r[8].text,
            useCount: Int(r[9].int ?? 0), revoked: (r[10].int ?? 0) != 0)
    }

    private static func challengeSeconds(_ date: Date) -> Int64 { Int64(date.timeIntervalSince1970.rounded(.down)) }
    private static func challengeDate(_ v: SQLValue) -> Date { Date(timeIntervalSince1970: TimeInterval(v.int ?? 0)) }
}
