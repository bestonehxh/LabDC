import Foundation
import KerberosCrypto
import MSPAC
import SheepCrypto

extension DirectoryStore {
    /// The AES salt for an account (MS-KILE §3.1.1.2):
    /// - users: `REALM` + sAMAccountName without a trailing `$`;
    /// - computers (`computer` class or a trust-account UAC bit): `REALM` + `host` +
    ///   lower-case name without `$` + `.` + lower-case DNS domain;
    /// - krbtgt: `REALM` + `krbtgt` + `REALM` (the RFC default for `krbtgt/REALM`).
    public func kerberosSalt(id: ObjectID) throws -> String {
        let info = try domainInfo()
        let row = try requireRow(id: id)
        guard let sam = row.sam else { throw StoreError.constraintViolation("\(row.dn) has no sAMAccountName") }
        return Self.salt(sam: sam, isComputer: try isComputerAccount(row), info: info)
    }

    static func salt(sam: String, isComputer: Bool, info: DomainInfo) -> String {
        let bare = sam.hasSuffix("$") ? String(sam.dropLast()) : sam
        if sam.caseInsensitiveCompare("krbtgt") == .orderedSame { return info.realm + "krbtgt" + info.realm }
        if isComputer { return info.realm + "host" + bare.lowercased() + "." + info.dnsDomain.lowercased() }
        return info.realm + bare
    }

    func isComputerAccount(_ row: ObjectRow) throws -> Bool {
        if DirectorySchema.classChain(row.objectClass).contains("computer") { return true }
        let uac = UInt32(truncatingIfNeeded: Int64(String(decoding: try storedValues(row.id, "userAccountControl").first ?? [],
                                                          as: UTF8.self)) ?? 0)
        return uac & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount) != 0
    }

    /// NT hash: MD4 over the UTF-16LE password.
    public static func ntHash(_ password: String) -> [UInt8] {
        MD4.hash(password.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] })
    }

    // MARK: - Policy

    /// The domain password policy.
    public func passwordPolicy() throws -> PasswordPolicy {
        let info = try domainInfo()
        guard let domain = try read(dn: info.domainDN) else { throw StoreError.noSuchObject(info.domainDN.description) }
        return PasswordPolicy(minLength: Int(domain.int("minPwdLength") ?? 7),
                              complexity: ((domain.int("pwdProperties") ?? 1) & 1) != 0,
                              historyLength: Int(domain.int("pwdHistoryLength") ?? 24),
                              relaxed: try domainValue(forKey: "relaxPasswordPolicy") == "1")
    }

    /// Writes the policy onto the domain object (and the lab toggle into the domain table).
    public func setPasswordPolicy(_ policy: PasswordPolicy) throws {
        try transaction {
            let info = try domainInfo()
            let domain = try requireRow(dn: info.domainDN)
            let props = Int64(try storedValues(domain.id, "pwdProperties").first.flatMap {
                Int64(String(decoding: $0, as: UTF8.self)) } ?? 1)
            try replaceStored(domain.id, "minPwdLength", [Array(String(policy.minLength).utf8)])
            try replaceStored(domain.id, "pwdHistoryLength", [Array(String(policy.historyLength).utf8)])
            try replaceStored(domain.id, "pwdProperties", [Array(String(policy.complexity ? props | 1 : props & ~1).utf8)])
            try setDomainValue(policy.relaxed ? "1" : "0", forKey: "relaxPasswordPolicy")
            try touch(domain.id)
        }
    }

    /// Checks `password` for account `id` against the policy: length (min, and 256 max),
    /// complexity (3 of: upper, lower, digit, symbol, other letters; must not contain the
    /// sAMAccountName or a displayName token of 3+ characters) and history (the current and
    /// the previous `historyLength - 1` NT hashes). Does nothing when the policy is relaxed.
    public func checkPasswordPolicy(id: ObjectID, password: String) throws {
        let policy = try passwordPolicy()
        guard !policy.relaxed else { return }
        let length = password.count
        if length < policy.minLength { throw StoreError.passwordPolicy(.tooShort(minimum: policy.minLength)) }
        if length > PasswordPolicy.maxLength { throw StoreError.passwordPolicy(.tooLong(maximum: PasswordPolicy.maxLength)) }
        let entry = try read(id: id)
        if policy.complexity {
            if !Self.isComplex(password) { throw StoreError.passwordPolicy(.notComplex) }
            let lower = password.lowercased()
            if let sam = entry?.samAccountName, sam.count >= 3, lower.contains(sam.lowercased()) {
                throw StoreError.passwordPolicy(.containsAccountName)
            }
            if let display = entry?.string("displayName") {
                let separators: Set<Character> = [",", ".", "-", "_", "#", "\t", " "]
                for token in display.split(whereSeparator: { separators.contains($0) }) where token.count >= 3 {
                    if lower.contains(token.lowercased()) { throw StoreError.passwordPolicy(.containsAccountName) }
                }
            }
        }
        if policy.historyLength > 0, let s = try secrets(id: id), let current = s.ntHash {
            let hash = Self.ntHash(password)
            let recent = [current] + s.history.prefix(max(0, policy.historyLength - 1))
            if recent.contains(where: { ConstantTime.equal($0, hash) }) { throw StoreError.passwordPolicy(.inHistory) }
        }
    }

    static func isComplex(_ password: String) -> Bool {
        var upper = false, lower = false, digit = false, symbol = false, other = false
        let symbols = Set("~!@#$%^&*_-+=`|\\(){}[]:;\"'<>,.?/")
        for c in password {
            if c.isASCII, c.isNumber { digit = true }
            else if symbols.contains(c) { symbol = true }
            else if c.isUppercase { upper = true }
            else if c.isLowercase { lower = true }
            else if c.isLetter { other = true }
        }
        return [upper, lower, digit, symbol, other].filter { $0 }.count >= 3
    }

    // MARK: - Secrets

    /// Sets a password: NT hash, AES256/AES128 (4096 iterations, salt from `kerberosSalt`)
    /// and RC4 keys, kvno + 1, `pwdLastSet` = now, history updated, and UF_PASSWORD_EXPIRED
    /// cleared — all in one transaction, so every path that sets a password (kpasswd, SAMR,
    /// LDAP password modify, the app, RADIUS change-password) leaves the account usable, and
    /// never a new password with the account still flagged expired.
    /// - Parameter enforcePolicy: false for administrative/lab resets that skip the policy.
    public func setPassword(id: ObjectID, password: String, enforcePolicy: Bool = true) throws {
        try setPassword(id: id, password: password, enforcePolicy: enforcePolicy, beforeCommit: nil)
    }

    /// `beforeCommit` runs last inside the transaction (tests inject a failure there).
    func setPassword(id: ObjectID, password: String, enforcePolicy: Bool, beforeCommit: (() throws -> Void)?) throws {
        try transaction {
            if enforcePolicy { try checkPasswordPolicy(id: id, password: password) }
            let salt = try kerberosSalt(id: id)
            let nt = Self.ntHash(password)
            let aes256 = try KerberosCrypto.stringToKey(.aes256CtsHmacSha1, password: password, salt: salt, parameters: nil)
            let aes128 = try KerberosCrypto.stringToKey(.aes128CtsHmacSha1, password: password, salt: salt, parameters: nil)
            let old = try secrets(id: id)
            var history = old?.history ?? []
            if let current = old?.ntHash { history.insert(current, at: 0) }
            let keep = max(0, (try? passwordPolicy().historyLength) ?? 24)
            history = Array(history.prefix(keep))
            try writeSecrets(id: id, nt: nt, aes256: aes256.bytes, aes128: aes128.bytes, rc4: nt, salt: salt,
                             kvno: (old?.kvno ?? 0) + 1, history: history)
            try clearPasswordExpired(id: id)
            try beforeCommit?()
        }
    }

    /// Clears UF_PASSWORD_EXPIRED on `id` (no write when it is not set).
    func clearPasswordExpired(id: ObjectID) throws {
        let uac = UInt32(truncatingIfNeeded: try read(id: id, attrs: ["userAccountControl"])?.int("userAccountControl") ?? 0)
        guard uac & UserAccountControl.passwordExpired != 0 else { return }
        try update(id: id, ops: [.replace("userAccountControl", strings: [String(uac & ~UserAccountControl.passwordExpired)])])
    }

    /// A user's own password change (MS-CHAPv2 Change-Password after E=648): `setPassword`,
    /// which clears UF_PASSWORD_EXPIRED in the same transaction.
    public func changePassword(id: ObjectID, password: String, enforcePolicy: Bool = true) throws {
        try setPassword(id: id, password: password, enforcePolicy: enforcePolicy, beforeCommit: nil)
    }

    /// `beforeCommit` runs last inside the transaction (tests inject a failure there).
    func changePassword(id: ObjectID, password: String, enforcePolicy: Bool, beforeCommit: (() throws -> Void)?) throws {
        try setPassword(id: id, password: password, enforcePolicy: enforcePolicy, beforeCommit: beforeCommit)
    }

    /// Stores keys directly (krbtgt random keys, keytab imports). `kvno` nil increments.
    public func setSecretsRaw(id: ObjectID, keys: [KerberosKey], ntHash: [UInt8]? = nil, salt: String? = nil,
                              kvno: UInt32? = nil) throws {
        try transaction {
            _ = try requireRow(id: id)
            let old = try secrets(id: id)
            let rc4 = keys.first { $0.type == .rc4Hmac }?.bytes
            try writeSecrets(id: id, nt: ntHash ?? rc4, aes256: keys.first { $0.type == .aes256CtsHmacSha1 }?.bytes,
                             aes128: keys.first { $0.type == .aes128CtsHmacSha1 }?.bytes, rc4: rc4, salt: salt,
                             kvno: kvno ?? (old?.kvno ?? 0) + 1, history: old?.history ?? [])
        }
    }

    /// Sets an account's secrets from an NT hash alone (MS-SAMR `SamrSetInformationUser2` levels
    /// 18/23/25, which carry `ENCRYPTED_NT_OWF_PASSWORD`/`SAMPR_USER_INTERNAL1` hashes and no
    /// cleartext): NT hash and the RC4-HMAC key (= the NT hash) are stored; AES256/AES128 keys are
    /// **absent** because they cannot be derived from an NT hash. A KDC therefore offers only RC4
    /// for this account until a cleartext password is set (levels 24/26, or kpasswd). `kvno`
    /// increments, `pwdLastSet` is now, and the previous NT hash joins the history.
    /// - Note: additive Store API for WP-U; existing callers are unaffected.
    public func setPasswordFromNTHash(id: ObjectID, ntHash: [UInt8]) throws {
        try transaction {
            _ = try requireRow(id: id)
            let old = try secrets(id: id)
            var history = old?.history ?? []
            if let current = old?.ntHash { history.insert(current, at: 0) }
            let keep = max(0, (try? passwordPolicy().historyLength) ?? 24)
            history = Array(history.prefix(keep))
            try writeSecrets(id: id, nt: ntHash, aes256: nil, aes128: nil, rc4: ntHash, salt: nil,
                             kvno: (old?.kvno ?? 0) + 1, history: history)
            try clearPasswordExpired(id: id)
        }
    }

    /// Fresh random AES256/AES128/RC4 keys (krbtgt, DC machine account), kvno + 1.
    public func setRandomKeys(id: ObjectID) throws {
        try setSecretsRaw(id: id, keys: [KerberosCrypto.randomKey(.aes256CtsHmacSha1, rng: rng),
                                         KerberosCrypto.randomKey(.aes128CtsHmacSha1, rng: rng),
                                         KerberosCrypto.randomKey(.rc4Hmac, rng: rng)])
    }

    private func writeSecrets(id: ObjectID, nt: [UInt8]?, aes256: [UInt8]?, aes128: [UInt8]?, rc4: [UInt8]?,
                              salt: String?, kvno: UInt32, history: [[UInt8]]) throws {
        let now = String(FileTime(clock()).rawValue)
        try db.run("""
            INSERT INTO secrets(object_id, nt_hash, kvno, aes256, aes128, rc4, salt, pwd_last_set, history)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(object_id) DO UPDATE SET nt_hash = excluded.nt_hash, kvno = excluded.kvno,
              aes256 = excluded.aes256, aes128 = excluded.aes128, rc4 = excluded.rc4, salt = excluded.salt,
              pwd_last_set = excluded.pwd_last_set, history = excluded.history
            """, [.int(id), .optional(nt), .int(Int64(kvno)), .optional(aes256), .optional(aes128), .optional(rc4),
                  .optional(salt), .text(now), history.isEmpty ? .null : .blob(history.flatMap { $0 })])
        try touch(id)
    }

    /// The account's keys and NT hash, or nil when it has none.
    public func secrets(id: ObjectID) throws -> AccountSecrets? {
        guard let r = try db.query("""
            SELECT nt_hash, kvno, aes256, aes128, rc4, salt, pwd_last_set, history FROM secrets WHERE object_id = ?
            """, [.int(id)]).first else { return nil }
        var keys: [KerberosKey] = []
        if let b = r[2].blob, !b.isEmpty { keys.append(try KerberosKey(type: .aes256CtsHmacSha1, bytes: b)) }
        if let b = r[3].blob, !b.isEmpty { keys.append(try KerberosKey(type: .aes128CtsHmacSha1, bytes: b)) }
        if let b = r[4].blob, !b.isEmpty { keys.append(try KerberosKey(type: .rc4Hmac, bytes: b)) }
        let hist = r[7].blob ?? []
        let history = stride(from: 0, to: hist.count - hist.count % 16, by: 16).map { Array(hist[$0..<($0 + 16)]) }
        let nt = r[0].blob.flatMap { $0.isEmpty ? nil : $0 }
        guard nt != nil || !keys.isEmpty else { return nil }
        return AccountSecrets(ntHash: nt, kvno: UInt32(truncatingIfNeeded: r[1].int ?? 0), keys: keys, salt: r[5].text,
                              pwdLastSet: FileTime(rawValue: UInt64(max(0, r[6].int ?? 0))), history: history)
    }
}
