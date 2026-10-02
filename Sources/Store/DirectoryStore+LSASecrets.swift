import Foundation

/// LSA global secrets (MS-LSAD §3.1.1.4): named values only the DC itself reads, such as the
/// BackupKey Remote Protocol keys `G$BCKUPKEY_PREFERRED`, `G$BCKUPKEY_P` and `G$BCKUPKEY_<guid>`
/// (MS-BKRP §3.1.1). AD keeps them as `secret` objects under `CN=System` that LDAP never
/// returns; here they live in their own table, outside the object tree, so no LDAP search or
/// export path can reach them. Each value is sealed at rest with the store's `StoreSecretBox`
/// key (the same model as the RADIUS shared secrets), so a copied `lab.sqlite` alone does not
/// reveal a DPAPI backup key.
extension DirectoryStore {
    static func createLSASecretSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS lsa_secrets(
              name TEXT PRIMARY KEY COLLATE NOCASE,
              current_value TEXT NOT NULL,
              last_set TEXT NOT NULL);
            """)
    }

    /// The current value of the global secret `name` (`G$BCKUPKEY_PREFERRED`), or nil when there
    /// is none. Throws when the stored value does not open with this store's key.
    public func lsaSecret(named name: String) throws -> [UInt8]? {
        guard let stored = try db.scalar("SELECT current_value FROM lsa_secrets WHERE name = ?", [.text(name)])?.text else {
            return nil
        }
        guard let bytes = Data(base64Encoded: try secretBox.open(stored)) else { throw StoreSecretBox.BoxError.corrupt }
        return [UInt8](bytes)
    }

    /// Writes (or replaces) the global secret `name`.
    public func setLSASecret(named name: String, value: [UInt8]) throws {
        try db.run("""
            INSERT INTO lsa_secrets(name, current_value, last_set) VALUES(?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET current_value = excluded.current_value, last_set = excluded.last_set
            """, [.text(name), .text(try secretBox.seal(Data(value).base64EncodedString())),
                  .text(GeneralizedTime.string(clock()))])
    }

    /// Writes every secret in `values` in one transaction, unless the secret `pointer` already
    /// exists — then nothing is written and false is returned. MS-BKRP keys are created on first
    /// use; two callers racing to create the domain's first backup key must end up agreeing on one
    /// `G$BCKUPKEY_PREFERRED`, and the actor plus this check-and-write makes the loser's key vanish
    /// before anyone could have wrapped a secret with it.
    public func createLSASecrets(_ values: [(name: String, value: [UInt8])], unlessPresent pointer: String) throws -> Bool {
        try transaction {
            if try db.scalar("SELECT 1 FROM lsa_secrets WHERE name = ?", [.text(pointer)]) != nil { return false }
            for v in values { try setLSASecret(named: v.name, value: v.value) }
            return true
        }
    }

    /// The stored (sealed) form of one secret, as it sits in the table (tests check it is sealed).
    func storedLSASecret(named name: String) throws -> String? {
        try db.scalar("SELECT current_value FROM lsa_secrets WHERE name = ?", [.text(name)])?.text
    }
}
