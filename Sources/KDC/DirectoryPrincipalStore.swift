import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC
import SheepCrypto
import Store
import os

/// `PrincipalStore` over a provisioned `DirectoryStore`.
///
/// Name resolution is `DirectoryStore.kerberosAccount(components:realm:)`: `krbtgt/REALM`,
/// `user`, `NAME$` (and `name` retried as `NAME$`), NT-ENTERPRISE `user@suffix` by UPN, and any
/// `servicePrincipalName` (plus the sPNMappings `host/` aliases). Mapping to `Principal`:
/// - the krbtgt account asked for as `krbtgt/REALM` -> `.krbtgt` (enabled despite AD's
///   ACCOUNTDISABLE on krbtgt);
/// - `kadmin/changepw` -> a `.service` principal with **its own random keys**, generated when
///   this value is created (at KDC start) and kept in memory only. Provisioning puts the
///   `kadmin/changepw` SPN on krbtgt, as AD does, but a changepw ticket sealed with the krbtgt
///   key could be replayed as a TGT by editing its clear-text `sname` (Samba CVE-2022-32744);
///   separate keys make that impossible. A restart only invalidates changepw tickets, which
///   live 5 minutes at most;
/// - a user or computer asked for by SPN -> `.service` with the account's keys;
/// - otherwise `.user(sid, upn, sam, groups)` / `.computer(sid, sam, groups)`, groups being the
///   domain RIDs, primary group first.
/// `enabled` is `!ACCOUNTDISABLE`; `flags` follow `msDS-SupportedEncryptionTypes` (0x4 RC4,
/// 0x8/0x10 AES); `salt` is the stored MS-KILE salt; `accountExpires`, `mustChangePassword`
/// (`pwdLastSet` 0 or PASSWORD_EXPIRED, unless DONT_EXPIRE_PASSWORD), `directoryID`,
/// `trustedForDelegation` (TRUSTED_FOR_DELEGATION) and `notDelegated` (NOT_DELEGATED) come
/// from the account, whichever name it was asked for by.
public struct DirectoryPrincipalStore: PrincipalStore {
    public let directory: DirectoryStore
    public let realm: String
    public let domainSID: SID
    public let netbiosDomain: String
    public let dcName: String
    public let dnsDomain: String
    /// The in-memory keys of `kadmin/changepw` (AES256, AES128, RC4).
    let changePasswordKeys: [KerberosKey]

    private static let logger = Logger(subsystem: "dev.labdc.app", category: "KDC")

    /// Reads the realm values of a provisioned store and generates the kadmin/changepw keys.
    public init(directory: DirectoryStore, rng: RandomBytes = RandomBytes()) async throws {
        let info = try await directory.domainInfo()
        self.directory = directory
        realm = info.realm
        domainSID = info.domainSID
        netbiosDomain = info.netbiosDomain
        dcName = info.dcName
        dnsDomain = info.dnsDomain
        changePasswordKeys = [EncryptionType.aes256CtsHmacSha1, .aes128CtsHmacSha1, .rc4Hmac].map {
            KerberosCrypto.randomKey($0, rng: rng)
        }
    }

    public func principal(_ name: PrincipalName, realm: String) async throws -> Principal? {
        if name.matchesIgnoringCase(.changePassword) {
            guard realm.caseInsensitiveCompare(self.realm) == .orderedSame
                || realm.caseInsensitiveCompare(dnsDomain) == .orderedSame else { return nil }
            return changePasswordPrincipal
        }
        guard let (account, match) = try await directory.kerberosAccount(components: name.nameString, realm: realm) else {
            return nil
        }
        return principal(account, match: match, requested: name)
    }

    /// The kpasswd service principal (random in-memory keys, kvno 1).
    public var changePasswordPrincipal: Principal {
        Principal(name: .changePassword, realm: realm, keys: changePasswordKeys, kvno: 1, kind: .service,
                  supportedEncryptionTypes: 0x1C)
    }

    /// krbtgt, then every user/computer by sAMAccountName, then one service entry per SPN.
    /// `kadmin/changepw` is left out: its keys are not in the store and change at every start.
    public func allPrincipals() async throws -> [Principal] {
        var result: [Principal] = []
        var services: [Principal] = []
        for account in try await directory.kerberosAccounts() {
            if account.kind == .krbtgt {
                result.insert(principal(account, match: .krbtgt, requested: .krbtgt(realm: realm)), at: 0)
            } else {
                result.append(principal(account, match: .samAccountName,
                                        requested: PrincipalName(nameType: NameType.principal, nameString: [account.samAccountName])))
            }
            for spn in account.servicePrincipalNames {
                let parts = spn.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
                let name = PrincipalName(nameType: parts.count == 2 ? NameType.srvHst : NameType.srvInst, nameString: parts)
                if name.matchesIgnoringCase(.changePassword) { continue }
                services.append(principal(account, match: .servicePrincipalName, requested: name))
            }
        }
        return result + services
    }

    /// Sets `lastLogon` to `date` and increments `logonCount` (AD does not replicate either;
    /// here they are ordinary attribute writes).
    public func recordLogon(_ principal: Principal, at date: Date) async {
        guard let id = principal.directoryID else { return }
        switch principal.kind {
        case .user, .computer: break
        case .service, .krbtgt: return
        }
        do {
            // `logonCount` is computed (0) until first stored, so read it rather than
            // `.increment`, which needs a stored value. Two logons racing may count once.
            let count = try await directory.read(id: id, attrs: ["logonCount"])?.int("logonCount") ?? 0
            try await directory.update(id: id, ops: [
                .replace("lastLogon", strings: [String(FileTime(date).rawValue)]),
                .replace("logonCount", strings: [String(count + 1)]),
            ])
        } catch {
            Self.logger.error("cannot record logon of \(principal.displayName, privacy: .public): \(String(describing: error), privacy: .public)")
        }
    }

    func principal(_ a: KerberosAccount, match: KerberosNameMatch, requested: PrincipalName) -> Principal {
        let kind: Principal.Kind
        let name: PrincipalName
        switch (match, a.kind) {
        case (.krbtgt, _):
            kind = .krbtgt
            name = .krbtgt(realm: realm)
        case (.servicePrincipalName, _):
            kind = .service
            name = requested
        case (_, .computer):
            kind = .computer(sid: a.sid ?? domainSID, samName: a.samAccountName, groups: a.groupRIDs)
            name = PrincipalName(nameType: NameType.principal, nameString: [a.samAccountName])
        case (_, .user), (_, .krbtgt):
            kind = .user(sid: a.sid ?? domainSID, upn: a.userPrincipalName ?? "\(a.samAccountName)@\(dnsDomain)",
                         samName: a.samAccountName, groups: a.groupRIDs)
            name = PrincipalName(nameType: NameType.principal, nameString: [a.samAccountName])
        }
        var flags: Principal.Flags = []
        if a.supportedEncryptionTypes & 0x4 != 0 { flags.insert(.supportsRC4) }
        if a.supportedEncryptionTypes & 0x18 != 0 { flags.insert(.supportsAES) }
        if flags.isEmpty { flags = [.supportsAES, .supportsRC4] }
        let enabled = kind == .krbtgt || (match == .servicePrincipalName && a.kind == .krbtgt) || !a.isDisabled
        let expires = a.accountExpires.rawValue == 0 || a.accountExpires.isNever ? nil : a.accountExpires.date
        let uac = a.userAccountControl
        let mustChange = a.kind != .krbtgt && uac & UserAccountControl.dontExpirePassword == 0
            && (a.pwdLastSet.rawValue == 0 || uac & UserAccountControl.passwordExpired != 0)
        return Principal(name: name, realm: realm, keys: a.keys, kvno: a.kvno, kind: kind,
                         passwordSet: a.pwdLastSet.date ?? Date(timeIntervalSince1970: 0), enabled: enabled,
                         flags: flags, salt: a.salt, accountExpires: expires, mustChangePassword: mustChange,
                         supportedEncryptionTypes: a.supportedEncryptionTypes,
                         hasExplicitUPN: a.userPrincipalName != nil, directoryID: a.id,
                         primaryGroupID: a.kind == .krbtgt ? nil : a.primaryGroupID,
                         trustedForDelegation: uac & UserAccountControl.trustedForDelegation != 0,
                         notDelegated: uac & UserAccountControl.notDelegated != 0)
    }
}
