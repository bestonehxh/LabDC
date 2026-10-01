import Foundation

/// One repaired object from the open-time fixups (`DirectoryStore.openFixups`).
public struct StoreFixup: Sendable, Equatable, CustomStringConvertible {
    public let samAccountName: String
    public let attribute: String
    public let oldValue: UInt32
    public let newValue: UInt32

    /// `WIN10-PC1$ userAccountControl 0x81 -> 0x1002` (the serve log prefixes `Store fixup:`).
    public var description: String {
        "\(samAccountName) \(attribute) 0x\(String(oldValue, radix: 16)) -> 0x\(String(newValue, radix: 16))"
    }
}

extension DirectoryStore {
    /// WP-AN: before the SAMR ACB↔UF mapping, `SamrSetInformationUser` level 16/21 stored the raw
    /// SAMR ACB flags a Windows join sends (`ACB_WSTRUST` 0x80, `| ACB_DISABLED` 0x81) in
    /// `userAccountControl`, so those computer objects carry no UF account-type bit and Windows
    /// refuses to reuse them ("Account type not reusable: 0x81"). On every open, a computer (class
    /// `computer`, or a user-class object whose sAMAccountName ends in `$`) whose stored
    /// `userAccountControl` has none of UF_NORMAL/INTERDOMAIN_TRUST/WORKSTATION_TRUST/SERVER_TRUST
    /// but does have an ACB account-type bit is converted with `UserAccountControl.fromACB`.
    /// Objects with a valid account-type bit are never touched, so the pass is idempotent (after
    /// the first open there is nothing left to fix). Tombstones are skipped.
    static func fixRawACBUserAccountControl(_ db: SQLiteConnection, clock: () -> Date) throws -> [StoreFixup] {
        let rows = try db.query("""
            SELECT o.id, o.object_class, o.sam_account_name, a.value FROM objects o
            JOIN attributes a ON a.object_id = o.id AND a.name = 'userAccountControl' AND a.ordinal =
              (SELECT MIN(ordinal) FROM attributes WHERE object_id = o.id AND name = 'userAccountControl')
            WHERE o.deleted = 0 AND (o.object_class = 'computer' OR o.sam_account_name LIKE '%$')
            ORDER BY o.id
            """)
        var fixes: [StoreFixup] = []
        for r in rows {
            guard let id = r[0].int, let objectClass = r[1].text else { continue }
            let chain = DirectorySchema.classChain(objectClass)
            guard chain.contains("user") else { continue }
            let isComputer = chain.contains("computer") || (r[2].text?.hasSuffix("$") ?? false)
            guard isComputer, let raw = r[3].blob ?? r[3].text.map({ Array($0.utf8) }),
                  let value = Int64(String(decoding: raw, as: UTF8.self)) else { continue }
            let old = UInt32(truncatingIfNeeded: value)
            guard old & UserAccountControl.accountTypeMask == 0 else { continue }
            guard old & ACB.accountTypeMask != 0 else {
                logger.warning("Store fixup: \(r[2].text ?? "id \(id)", privacy: .public) userAccountControl 0x\(String(old, radix: 16), privacy: .public) has no account type; left unchanged")
                continue
            }
            let new = UserAccountControl.fromACB(old)
            let usn = (Int64(try db.scalar("SELECT value FROM domain WHERE key = 'highestCommittedUSN'")?.text ?? "0") ?? 0) + 1
            try db.run("INSERT INTO domain(key, value) VALUES('highestCommittedUSN', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       [.text(String(usn))])
            try db.run("UPDATE attributes SET value = ?, value_norm = ? WHERE object_id = ? AND name = 'userAccountControl'",
                       [.blob(Array(String(new).utf8)),
                        .optional(DirectorySchema.storedNorm(Array(String(new).utf8), name: "userAccountControl")), .int(id)])
            try db.run("UPDATE objects SET usn_changed = ?, when_changed = ? WHERE id = ?",
                       [.int(usn), .text(GeneralizedTime.string(clock())), .int(id)])
            let fix = StoreFixup(samAccountName: r[2].text ?? "id \(id)", attribute: "userAccountControl",
                                 oldValue: old, newValue: new)
            logger.notice("Store fixup: \(fix.description, privacy: .public)")
            fixes.append(fix)
        }
        return fixes
    }
}
