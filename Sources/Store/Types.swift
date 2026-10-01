import Foundation
import KerberosCrypto
import MSPAC

/// Row id of an object in the `objects` table. Stable for the life of the object (also across
/// rename, move and tombstoning) and increasing with creation order.
public typealias ObjectID = Int64

/// One attribute of an entry: the name as stored (or the canonical schema spelling for
/// computed attributes) and its values as octet strings.
public struct Attribute: Sendable, Hashable {
    public var name: String
    public var values: [[UInt8]]

    public init(name: String, values: [[UInt8]]) {
        self.name = name
        self.values = values
    }

    public init(_ name: String, strings: [String]) {
        self.init(name: name, values: strings.map { Array($0.utf8) })
    }
}

/// An object as read from the store, with stored and computed attributes.
public struct DirectoryEntry: Sendable, Hashable {
    public var id: ObjectID
    public var dn: DN
    public var guid: GUID
    /// Most specific structural class (`user`, `computer`, `group`, ...).
    public var objectClass: String
    public var isDeleted: Bool
    public var parentID: ObjectID?
    /// In store order; names unique ignoring case.
    public var attributes: [Attribute]

    /// Values of `name` (case-insensitive); empty when absent.
    public func values(_ name: String) -> [[UInt8]] {
        attributes.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.values ?? []
    }

    public func has(_ name: String) -> Bool { !values(name).isEmpty }

    /// UTF-8 values of `name`.
    public func strings(_ name: String) -> [String] { values(name).map { String(decoding: $0, as: UTF8.self) } }

    /// The first value of `name` as UTF-8.
    public func string(_ name: String) -> String? { strings(name).first }

    /// The first value of `name` as a decimal integer.
    public func int(_ name: String) -> Int64? { string(name).flatMap { Int64($0) } }

    /// `objectSid`, if the entry has one.
    public var sid: SID? { values("objectSid").first.flatMap { try? SID(bytes: $0) } }

    /// `sAMAccountName`, if the entry has one.
    public var samAccountName: String? { string("sAMAccountName") }

    /// Keeps only `names` (case-insensitive). `nil`, `*` or `+` keep everything; `1.1` alone keeps nothing.
    public func projected(_ names: [String]?) -> DirectoryEntry {
        guard let names, !names.contains("*"), !names.contains("+") else { return self }
        var copy = self
        let wanted = Set(names.map { $0.lowercased() })
        copy.attributes = attributes.filter { wanted.contains($0.name.lowercased()) }
        return copy
    }
}

/// One modification (RFC 4511 §4.6). Values are octet strings; DN-valued attributes take the
/// DN string. An empty value list on `delete` or `replace` removes the whole attribute.
public enum ModifyOp: Sendable, Hashable {
    case add(String, [[UInt8]])
    case delete(String, [[UInt8]])
    case replace(String, [[UInt8]])
    /// RFC 4525 increment of a single-valued integer attribute.
    case increment(String, Int64)

    public var attribute: String {
        switch self {
        case .add(let n, _), .delete(let n, _), .replace(let n, _), .increment(let n, _): n
        }
    }

    public static func add(_ name: String, strings: [String]) -> ModifyOp { .add(name, strings.map { Array($0.utf8) }) }
    public static func delete(_ name: String, strings: [String]) -> ModifyOp { .delete(name, strings.map { Array($0.utf8) }) }
    public static func replace(_ name: String, strings: [String]) -> ModifyOp { .replace(name, strings.map { Array($0.utf8) }) }
}

/// Search scope (RFC 4511 §4.5.1.2).
public enum SearchScope: Int, Sendable, Hashable {
    case base = 0, oneLevel = 1, subtree = 2
}

/// Realm-wide values written by `provision` (the `domain` table).
public struct DomainInfo: Sendable, Hashable {
    /// `LAB.SHEEP`
    public var realm: String
    /// `lab.sheep`
    public var dnsDomain: String
    /// `LABSHEEP`
    public var netbiosDomain: String
    public var domainSID: SID
    public var domainGUID: GUID
    /// NetBIOS name of the DC, upper case: `DC1`.
    public var dcName: String
    /// `dc1.lab.sheep`
    public var dcDNSName: String
    /// `Default-First-Site-Name`
    public var site: String
    /// objectGUID of the DC's `CN=NTDS Settings` (DNS `<dsaGUID>._msdcs` CNAME).
    public var dsaGUID: GUID
    public var invocationID: GUID
    /// `DC=lab,DC=sheep`
    public var domainDN: DN
    /// `CN=Configuration,DC=lab,DC=sheep`
    public var configurationDN: DN
    /// `CN=Schema,CN=Configuration,DC=lab,DC=sheep`
    public var schemaDN: DN
    /// `CN=DC1,OU=Domain Controllers,DC=lab,DC=sheep`
    public var dcComputerDN: DN
    /// `CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,...`
    public var dsServiceDN: DN
    /// `CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,...`
    public var serverDN: DN
    /// `CN=Aggregate,CN=Schema,CN=Configuration,...`
    public var subschemaDN: DN
}

/// Long-term secrets of an account.
public struct AccountSecrets: Sendable, Equatable, CustomStringConvertible {
    /// MD4(UTF-16LE(password)); nil for random-key accounts without an NT hash.
    public var ntHash: [UInt8]?
    public var kvno: UInt32
    /// AES256, AES128, RC4 (whichever exist), strongest first.
    public var keys: [KerberosKey]
    /// The AES salt the keys were derived with; nil for random keys.
    public var salt: String?
    public var pwdLastSet: FileTime
    /// Previous NT hashes, newest first (not including the current one).
    public var history: [[UInt8]]

    public var description: String { "AccountSecrets(kvno \(kvno), etypes \(keys.map(\.type.rawValue)))" }
}

/// Domain password policy (the domain object's `minPwdLength`, `pwdProperties` bit 0x1 and
/// `pwdHistoryLength`) plus the lab toggle that turns every check off.
public struct PasswordPolicy: Sendable, Hashable {
    public var minLength: Int
    public var complexity: Bool
    public var historyLength: Int
    /// Lab toggle: accept any password.
    public var relaxed: Bool

    /// AD defaults: 7, complexity on, 24.
    public init(minLength: Int = 7, complexity: Bool = true, historyLength: Int = 24, relaxed: Bool = false) {
        self.minLength = minLength
        self.complexity = complexity
        self.historyLength = historyLength
        self.relaxed = relaxed
    }

    /// Longest password AD accepts (`unicodePwd` limit).
    public static let maxLength = 256
}

/// A row of `dns_records`.
public struct DNSRecordRow: Sendable, Hashable {
    public var id: Int64
    public var zone: String
    /// Owner name relative to the zone (`dc1`, `_ldap._tcp`, `@` for the apex) or absolute;
    /// the store does not interpret it.
    public var name: String
    public var type: UInt16
    public var ttl: UInt32
    public var rdata: [UInt8]
    public var dynamic: Bool
    public var updated: Date
}

/// `userAccountControl` bits (MS-ADTS §2.2.16).
public enum UserAccountControl {
    public static let script: UInt32 = 0x1
    public static let accountDisable: UInt32 = 0x2
    public static let homedirRequired: UInt32 = 0x8
    public static let lockout: UInt32 = 0x10
    public static let passwordNotRequired: UInt32 = 0x20
    public static let passwordCantChange: UInt32 = 0x40
    public static let encryptedTextPasswordAllowed: UInt32 = 0x80
    public static let normalAccount: UInt32 = 0x200
    public static let interdomainTrustAccount: UInt32 = 0x800
    public static let workstationTrustAccount: UInt32 = 0x1000
    public static let serverTrustAccount: UInt32 = 0x2000
    public static let dontExpirePassword: UInt32 = 0x10000
    public static let smartcardRequired: UInt32 = 0x40000
    public static let trustedForDelegation: UInt32 = 0x80000
    public static let notDelegated: UInt32 = 0x100000
    public static let useDESKeyOnly: UInt32 = 0x200000
    public static let dontRequirePreauth: UInt32 = 0x400000
    public static let passwordExpired: UInt32 = 0x800000
    public static let trustedToAuthForDelegation: UInt32 = 0x1000000
    public static let mnsLogonAccount: UInt32 = 0x20000
    public static let tempDuplicateAccount: UInt32 = 0x100
    public static let noAuthDataRequired: UInt32 = 0x2000000
    public static let partialSecretsAccount: UInt32 = 0x4000000
    public static let useAESKeys: UInt32 = 0x8000000

    /// The account-type bits (Samba `UF_ACCOUNT_TYPE_MASK` minus TEMP_DUPLICATE): an account
    /// object has exactly one of these.
    public static let accountTypeMask: UInt32 =
        normalAccount | interdomainTrustAccount | workstationTrustAccount | serverTrustAccount

    /// `ds_acb2uf`: SAMR account-control (ACB, MS-SAMR §2.2.1.12) flags → `userAccountControl`
    /// (UF, MS-ADTS §2.2.16) bits, per MS-SAMR §3.1.5.14.2 / Samba `libds/common/flag_mapping.c`.
    /// ACB bits without a UF counterpart are dropped.
    public static func fromACB(_ acb: UInt32) -> UInt32 {
        var uf: UInt32 = 0
        for (u, a) in ACB.mapping where acb & a != 0 { uf |= u }
        return uf
    }

    /// `ds_uf2acb`: `userAccountControl` bits → SAMR ACB flags (MS-SAMR §3.1.5.14.3). UF bits
    /// without an ACB counterpart (UF_SCRIPT, UF_PASSWD_CANT_CHANGE, …) are dropped.
    public static func toACB(_ uf: UInt32) -> UInt32 {
        var acb: UInt32 = 0
        for (u, a) in ACB.mapping where uf & u != 0 { acb |= a }
        return acb
    }

    /// The UF bits that have an ACB counterpart (what a SAMR set can express).
    public static let acbMappedBits: UInt32 = ACB.mapping.reduce(0) { $0 | $1.uf }
}

/// SAMR `USER_ACCOUNT` codes (ACB flags, MS-SAMR §2.2.1.12 / Samba `samr.idl` `samr_AcctFlags`):
/// the account-control representation on the SAMR and Netlogon wires and in the PAC. The
/// directory stores `userAccountControl` (UF bits); `UserAccountControl.fromACB/toACB` convert.
public enum ACB {
    public static let disabled: UInt32 = 0x0000_0001
    public static let homedirRequired: UInt32 = 0x0000_0002
    public static let passwordNotRequired: UInt32 = 0x0000_0004
    public static let tempDuplicate: UInt32 = 0x0000_0008
    public static let normal: UInt32 = 0x0000_0010
    public static let mns: UInt32 = 0x0000_0020
    public static let domainTrust: UInt32 = 0x0000_0040
    public static let workstationTrust: UInt32 = 0x0000_0080
    public static let serverTrust: UInt32 = 0x0000_0100
    public static let passwordNoExpire: UInt32 = 0x0000_0200
    public static let autoLock: UInt32 = 0x0000_0400
    public static let encryptedTextPasswordAllowed: UInt32 = 0x0000_0800
    public static let smartcardRequired: UInt32 = 0x0000_1000
    public static let trustedForDelegation: UInt32 = 0x0000_2000
    public static let notDelegated: UInt32 = 0x0000_4000
    public static let useDESKeyOnly: UInt32 = 0x0000_8000
    public static let dontRequirePreauth: UInt32 = 0x0001_0000
    public static let passwordExpired: UInt32 = 0x0002_0000
    public static let trustedToAuthForDelegation: UInt32 = 0x0004_0000
    public static let noAuthDataRequired: UInt32 = 0x0008_0000
    public static let partialSecretsAccount: UInt32 = 0x0010_0000
    public static let useAESKeys: UInt32 = 0x0020_0000

    /// The account-type ACB bits.
    public static let accountTypeMask: UInt32 = normal | domainTrust | workstationTrust | serverTrust

    /// Samba's `acct_flags_map` (UF ↔ ACB), in its order.
    public static let mapping: [(uf: UInt32, acb: UInt32)] = [
        (UserAccountControl.accountDisable, disabled),
        (UserAccountControl.homedirRequired, homedirRequired),
        (UserAccountControl.passwordNotRequired, passwordNotRequired),
        (UserAccountControl.tempDuplicateAccount, tempDuplicate),
        (UserAccountControl.normalAccount, normal),
        (UserAccountControl.mnsLogonAccount, mns),
        (UserAccountControl.interdomainTrustAccount, domainTrust),
        (UserAccountControl.workstationTrustAccount, workstationTrust),
        (UserAccountControl.serverTrustAccount, serverTrust),
        (UserAccountControl.dontExpirePassword, passwordNoExpire),
        (UserAccountControl.lockout, autoLock),
        (UserAccountControl.encryptedTextPasswordAllowed, encryptedTextPasswordAllowed),
        (UserAccountControl.smartcardRequired, smartcardRequired),
        (UserAccountControl.trustedForDelegation, trustedForDelegation),
        (UserAccountControl.notDelegated, notDelegated),
        (UserAccountControl.useDESKeyOnly, useDESKeyOnly),
        (UserAccountControl.dontRequirePreauth, dontRequirePreauth),
        (UserAccountControl.passwordExpired, passwordExpired),
        (UserAccountControl.noAuthDataRequired, noAuthDataRequired),
        (UserAccountControl.trustedToAuthForDelegation, trustedToAuthForDelegation),
        (UserAccountControl.partialSecretsAccount, partialSecretsAccount),
        (UserAccountControl.useAESKeys, useAESKeys),
    ]
}

/// `groupType` bits (MS-ADTS §2.2.12).
public enum GroupType {
    public static let builtinLocal: Int32 = 0x1
    public static let accountGroup: Int32 = 0x2  // global
    public static let resourceGroup: Int32 = 0x4  // domain local
    public static let universalGroup: Int32 = 0x8
    public static let security: Int32 = Int32(bitPattern: 0x8000_0000)

    public static let globalSecurity = security | accountGroup
    public static let domainLocalSecurity = security | resourceGroup
    public static let universalSecurity = security | universalGroup
    public static let builtinSecurity = security | resourceGroup | builtinLocal
}

/// `sAMAccountType` values (MS-ADTS §2.2.17).
public enum SAMAccountType {
    public static let groupObject: UInt32 = 0x1000_0000
    public static let nonSecurityGroupObject: UInt32 = 0x1000_0001
    public static let aliasObject: UInt32 = 0x2000_0000
    public static let nonSecurityAliasObject: UInt32 = 0x2000_0001
    public static let userObject: UInt32 = 0x3000_0000
    public static let machineAccount: UInt32 = 0x3000_0001
    public static let trustAccount: UInt32 = 0x3000_0002
}
