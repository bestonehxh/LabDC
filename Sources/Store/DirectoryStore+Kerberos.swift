import Foundation
import KerberosCrypto
import MSPAC

/// An account as the KDC and the GSS acceptor see it.
public struct KerberosAccount: Sendable, CustomStringConvertible {
    public enum Kind: Sendable, Hashable { case user, computer, krbtgt }

    public var id: ObjectID
    public var dn: DN
    public var kind: Kind
    public var samAccountName: String
    public var sid: SID?
    /// Explicit `userPrincipalName`, if set.
    public var userPrincipalName: String?
    public var servicePrincipalNames: [String]
    public var dnsHostName: String?
    public var keys: [KerberosKey]
    public var ntHash: [UInt8]?
    public var kvno: UInt32
    public var salt: String?
    public var pwdLastSet: FileTime
    public var accountExpires: FileTime
    public var userAccountControl: UInt32
    /// `msDS-SupportedEncryptionTypes` (0x1C by default).
    public var supportedEncryptionTypes: UInt32
    public var primaryGroupID: UInt32
    /// Domain-relative RIDs of the global and universal groups the account is in (transitively),
    /// primary group first. Domain-local and builtin groups are left out.
    public var groupRIDs: [UInt32]

    /// `ACCOUNTDISABLE`; never true for krbtgt (AD keeps krbtgt disabled but it still works).
    public var isDisabled: Bool {
        kind != .krbtgt && userAccountControl & UserAccountControl.accountDisable != 0
    }

    public var description: String {
        "KerberosAccount(\(samAccountName), \(kind), kvno \(kvno), etypes \(keys.map(\.type.rawValue)))"
    }
}

/// How a name resolved.
public enum KerberosNameMatch: Sendable, Hashable {
    /// `krbtgt/REALM`.
    case krbtgt
    /// A single-component name matched a sAMAccountName (possibly after appending `$`).
    case samAccountName
    /// A multi-component name matched a `servicePrincipalName` (possibly via sPNMappings to `host/`).
    case servicePrincipalName
    /// An NT-ENTERPRISE-style `user@suffix` matched a UPN (explicit, or implicit `sam@dnsdomain`).
    case userPrincipalName
}

/// An account whose password can be set, whether or not it has keys yet (kpasswd set-password).
public struct PasswordAccount: Sendable, CustomStringConvertible {
    public var id: ObjectID
    public var dn: DN
    public var kind: KerberosAccount.Kind
    public var samAccountName: String
    public var sid: SID?
    public var userAccountControl: UInt32
    /// Whether the account has Kerberos keys (false for a computer created without a password).
    public var hasKeys: Bool

    public var description: String {
        "PasswordAccount(\(samAccountName), \(kind), \(hasKeys ? "keys" : "no keys"))"
    }
}

extension DirectoryStore {
    /// Service classes that AD's default `sPNMappings` alias to `host`.
    static let hostAliases: Set<String> = [
        "alerter", "appmgmt", "cisvc", "clipsrv", "browser", "dhcp", "dnscache", "replicator", "eventlog",
        "eventsystem", "policyagent", "oakley", "dmserver", "dns", "mcsvc", "fax", "msiserver", "ias", "messenger",
        "netlogon", "netman", "netdde", "netddedsm", "nmagent", "plugplay", "protectedstorage", "rasman",
        "rpclocator", "rpc", "rpcss", "remoteaccess", "rsvp", "samss", "scardsvr", "scesrv", "seclogon", "scm",
        "dcom", "cifs", "spooler", "snmp", "schedule", "tapisrv", "trksvr", "trkwks", "ups", "time", "wins", "www",
        "http", "w3svc", "iisadmin", "msdtc",
    ]

    /// Resolves a Kerberos principal name in `realm` (the realm or the DNS domain, any case):
    /// - `krbtgt/REALM` -> the krbtgt account;
    /// - one component with `@` (enterprise, `alice@lab.sheep`) -> explicit UPN, else
    ///   `sam@<dnsDomain or realm>`;
    /// - one component -> sAMAccountName, retried with `$` (`dc1` -> `DC1$`);
    /// - two or more -> `servicePrincipalName` (case-insensitive), retried with `host/` for the
    ///   sPNMappings aliases (`cifs/dc1.lab.sheep`).
    /// Tombstones and accounts without keys are not returned.
    public func kerberosAccount(components: [String], realm: String) throws -> (KerberosAccount, KerberosNameMatch)? {
        try resolveAccount(components: components, realm: realm) { try kerberosAccount(row: $0) }
    }

    /// Resolves a name exactly as `kerberosAccount(components:realm:)` does, but also returns
    /// accounts that have no keys yet (a computer just created over LDAP without `unicodePwd`,
    /// whose password is then set with kpasswd set-password). Only user-class objects with a
    /// sAMAccountName are returned; tombstones are not.
    public func passwordAccount(components: [String], realm: String) throws -> (PasswordAccount, KerberosNameMatch)? {
        try resolveAccount(components: components, realm: realm) { try passwordAccount(row: $0) }
    }

    /// The password view of account `id` (keys or not), or nil when it is not a live account.
    public func passwordAccount(id: ObjectID) throws -> PasswordAccount? {
        guard let r = try row(id: id), !r.deleted else { return nil }
        return try passwordAccount(row: r)
    }

    /// The name resolution shared by the Kerberos and password lookups; `view` maps a candidate
    /// row to the result (nil: not acceptable, try the next form).
    private func resolveAccount<T>(components: [String], realm: String,
                                   _ view: (ObjectRow) throws -> T?) throws -> (T, KerberosNameMatch)? {
        guard let info = cachedInfo else { return nil }
        guard realm.caseInsensitiveCompare(info.realm) == .orderedSame
            || realm.caseInsensitiveCompare(info.dnsDomain) == .orderedSame else { return nil }
        guard !components.isEmpty, !components.contains(where: \.isEmpty) else { return nil }
        func sam(_ name: String) throws -> T? {
            guard let r = try rows(where: "o.sam_account_name = ? AND o.deleted = 0", [.text(name)]).first else { return nil }
            return try view(r)
        }
        func spn(_ name: String) throws -> T? {
            let rows = try rows(where: """
                o.deleted = 0 AND o.id IN (SELECT object_id FROM attributes WHERE name = 'servicePrincipalName' AND value_norm = ?)
                """, [.text(name.lowercased())])
            guard let r = rows.first else { return nil }
            return try view(r)
        }
        if components.count == 2, components[0].caseInsensitiveCompare("krbtgt") == .orderedSame,
           components[1].caseInsensitiveCompare(info.realm) == .orderedSame
            || components[1].caseInsensitiveCompare(info.dnsDomain) == .orderedSame {
            return try sam("krbtgt").map { ($0, .krbtgt) }
        }
        if components.count == 1 {
            let name = components[0]
            if let at = name.lastIndex(of: "@") {
                if let r = try rows(where: "o.upn = ? AND o.deleted = 0", [.text(name)]).first,
                   let a = try view(r) {
                    return (a, .userPrincipalName)
                }
                let user = String(name[..<at]), suffix = String(name[name.index(after: at)...])
                if suffix.caseInsensitiveCompare(info.dnsDomain) == .orderedSame
                    || suffix.caseInsensitiveCompare(info.realm) == .orderedSame,
                   let a = try sam(user) ?? sam(user + "$") {
                    return (a, .userPrincipalName)
                }
                return nil
            }
            if let a = try sam(name) { return (a, .samAccountName) }
            if !name.hasSuffix("$"), let a = try sam(name + "$") { return (a, .samAccountName) }
            return nil
        }
        let joined = components.joined(separator: "/")
        if let a = try spn(joined) { return (a, .servicePrincipalName) }
        if Self.hostAliases.contains(components[0].lowercased()) {
            let hostSPN = (["host"] + components.dropFirst()).joined(separator: "/")
            if let a = try spn(hostSPN) { return (a, .servicePrincipalName) }
        }
        return nil
    }

    func passwordAccount(row: ObjectRow) throws -> PasswordAccount? {
        guard cachedInfo != nil, let sam = row.sam, !row.deleted else { return nil }
        guard DirectorySchema.classChain(row.objectClass).contains("user") else { return nil }
        let kind: KerberosAccount.Kind = sam.caseInsensitiveCompare("krbtgt") == .orderedSame
            ? .krbtgt : (try isComputerAccount(row) ? .computer : .user)
        let uac = UInt32(truncatingIfNeeded: Int64(String(decoding: try storedValues(row.id, "userAccountControl").first ?? [],
                                                          as: UTF8.self)) ?? 0)
        let hasKeys = !(try secrets(id: row.id)?.keys.isEmpty ?? true)
        return PasswordAccount(id: row.id, dn: row.parsedDN, kind: kind, samAccountName: sam,
                               sid: row.sid.flatMap { try? SID(bytes: $0) }, userAccountControl: uac, hasKeys: hasKeys)
    }

    /// The Kerberos view of account `id` (nil when it has no keys or is not an account).
    public func kerberosAccount(id: ObjectID) throws -> KerberosAccount? {
        guard let r = try row(id: id), !r.deleted else { return nil }
        return try kerberosAccount(row: r)
    }

    /// Every live account with keys (krbtgt, users, computers), ordered by id.
    public func kerberosAccounts() throws -> [KerberosAccount] {
        try rows(where: "o.deleted = 0 AND o.id IN (SELECT object_id FROM secrets)", []).compactMap { try kerberosAccount(row: $0) }
    }

    func kerberosAccount(row: ObjectRow) throws -> KerberosAccount? {
        guard let info = cachedInfo, let sam = row.sam else { return nil }
        guard DirectorySchema.classChain(row.objectClass).contains("user") else { return nil }
        guard let secrets = try secrets(id: row.id), !secrets.keys.isEmpty else { return nil }
        let e = try entry(row)
        let kind: KerberosAccount.Kind = sam.caseInsensitiveCompare("krbtgt") == .orderedSame
            ? .krbtgt : (try isComputerAccount(row) ? .computer : .user)
        // Validated against explicit membership: a forged primaryGroupID never reaches the PAC.
        let primary = try effectivePrimaryGroupRID(e) ?? 513
        var rids = [primary]
        for gid in try transitiveGroups(of: row.id) {
            guard let g = try self.row(id: gid), let sid = g.sid.flatMap({ try? SID(bytes: $0) }),
                  sid.domain == info.domainSID, let rid = sid.rid, !rids.contains(rid) else { continue }
            // Account-domain GroupIds carry global and universal groups; domain-local groups
            // belong to resource-group expansion (not done in phase 1).
            let gt = Int32(truncatingIfNeeded: Int64(String(decoding: try storedValues(gid, "groupType").first ?? [],
                                                            as: UTF8.self)) ?? Int64(GroupType.globalSecurity))
            if gt & (GroupType.resourceGroup | GroupType.builtinLocal) != 0 { continue }
            rids.append(rid)
        }
        return KerberosAccount(
            id: row.id, dn: row.parsedDN, kind: kind, samAccountName: sam, sid: row.sid.flatMap { try? SID(bytes: $0) },
            userPrincipalName: row.upn, servicePrincipalNames: e.strings("servicePrincipalName"),
            dnsHostName: e.string("dNSHostName"), keys: secrets.keys, ntHash: secrets.ntHash, kvno: secrets.kvno,
            salt: secrets.salt, pwdLastSet: secrets.pwdLastSet,
            accountExpires: FileTime(rawValue: UInt64(max(0, e.int("accountExpires") ?? Int64.max))),
            userAccountControl: UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0),
            supportedEncryptionTypes: UInt32(truncatingIfNeeded: e.int("msDS-SupportedEncryptionTypes") ?? 0x1C),
            primaryGroupID: primary, groupRIDs: rids)
    }
}
