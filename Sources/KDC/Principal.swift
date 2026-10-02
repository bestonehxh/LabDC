import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC

/// One account in the KDC database: a user, a computer, a service or the krbtgt account.
///
/// `keys` holds one long-term key per enctype, all with the same `kvno`. `description` never
/// prints key material.
public struct Principal: Sendable, CustomStringConvertible {
    /// What the account is; users and computers carry what the PAC needs.
    public enum Kind: Sendable, Hashable {
        /// A user account: SID (domain SID + RID), UPN, sAMAccountName and group RIDs.
        case user(sid: SID, upn: String, samName: String, groups: [UInt32])
        /// A service principal (no PAC of its own).
        case service
        /// The ticket-granting service of the realm.
        case krbtgt
        /// A computer account (`NAME$`): SID, sAMAccountName and group RIDs.
        case computer(sid: SID, samName: String, groups: [UInt32])

        /// Short lowercase name used in JSON and in `show`.
        public var label: String {
            switch self {
            case .user: "user"
            case .service: "service"
            case .krbtgt: "krbtgt"
            case .computer: "computer"
            }
        }
    }

    /// Enctype families the account supports (`msDS-SupportedEncryptionTypes`, simplified).
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let supportsAES = Flags(rawValue: 1 << 0)
        public static let supportsRC4 = Flags(rawValue: 1 << 1)
    }

    public var name: PrincipalName
    public var realm: String
    public var keys: [KerberosKey]
    public var kvno: UInt32
    public var kind: Kind
    public var passwordSet: Date
    public var enabled: Bool
    public var flags: Flags
    /// The salt the AES keys were derived with (announced in PA-ETYPE-INFO2); nil for random keys.
    public var salt: String?
    /// `accountExpires`; nil means never (AD's 0 and 0x7FFFFFFFFFFFFFFF).
    public var accountExpires: Date?
    /// The password must be changed before a TGT is issued (AD: `pwdLastSet` = 0 and no
    /// DONT_EXPIRE_PASSWORD); the KDC answers KDC_ERR_KEY_EXPIRED except for kadmin/changepw.
    public var mustChangePassword: Bool
    /// Raw `msDS-SupportedEncryptionTypes` (announced in PA-SUPPORTED-ENCTYPES); nil when the
    /// store has no such attribute.
    public var supportedEncryptionTypes: UInt32?
    /// False when the UPN in `kind` is the constructed `sam@dnsdomain` (UPN_DNS_INFO flag U).
    public var hasExplicitUPN: Bool
    /// The directory object behind the account (Store `ObjectID`), for logon bookkeeping and
    /// kpasswd; nil for other stores.
    public var directoryID: Int64?
    /// The account's `primaryGroupID` (users and computers from the directory); nil when the
    /// store has none. The PAC then uses 513 for users and the first group RID for computers.
    public var primaryGroupID: UInt32?
    /// TRUSTED_FOR_DELEGATION (UAC 0x80000): service tickets for this account carry
    /// OK-AS-DELEGATE (MS-KILE §3.3.5.7), so clients forward their TGT to it (unconstrained
    /// delegation; Windows' CES client refuses a Kerberos endpoint without it).
    public var trustedForDelegation: Bool
    /// NOT_DELEGATED (UAC 0x100000, "account is sensitive and cannot be delegated"): tickets
    /// issued to this client are never FORWARDABLE (MS-KILE §3.3.5.7).
    public var notDelegated: Bool

    /// `flags` defaults to what `keys` contains.
    public init(name: PrincipalName, realm: String, keys: [KerberosKey], kvno: UInt32, kind: Kind,
                passwordSet: Date = Date(timeIntervalSince1970: 0), enabled: Bool = true,
                flags: Flags? = nil, salt: String? = nil, accountExpires: Date? = nil,
                mustChangePassword: Bool = false, supportedEncryptionTypes: UInt32? = nil,
                hasExplicitUPN: Bool = false, directoryID: Int64? = nil, primaryGroupID: UInt32? = nil,
                trustedForDelegation: Bool = false, notDelegated: Bool = false) {
        self.name = name
        self.realm = realm
        self.keys = keys
        self.kvno = kvno
        self.kind = kind
        self.passwordSet = passwordSet
        self.enabled = enabled
        var f: Flags = []
        if keys.contains(where: { $0.type != .rc4Hmac }) { f.insert(.supportsAES) }
        if keys.contains(where: { $0.type == .rc4Hmac }) { f.insert(.supportsRC4) }
        self.flags = flags ?? f
        self.salt = salt
        self.accountExpires = accountExpires
        self.mustChangePassword = mustChangePassword
        self.supportedEncryptionTypes = supportedEncryptionTypes
        self.hasExplicitUPN = hasExplicitUPN
        self.directoryID = directoryID
        self.primaryGroupID = primaryGroupID
        self.trustedForDelegation = trustedForDelegation
        self.notDelegated = notDelegated
    }

    /// `msDS-SupportedEncryptionTypes` as stored, else derived from `flags`
    /// (0x4 RC4, 0x8 AES128, 0x10 AES256).
    public var supportedEncryptionTypesValue: UInt32 {
        if let supportedEncryptionTypes { return supportedEncryptionTypes }
        var v: UInt32 = 0
        if flags.contains(.supportsRC4) { v |= 0x4 }
        if flags.contains(.supportsAES) { v |= 0x18 }
        return v
    }

    /// True for `kadmin/changepw` (the kpasswd service principal).
    public var isChangePasswordService: Bool { name.matchesIgnoringCase(.changePassword) }

    /// Whether `accountExpires` has passed at `now`.
    public func isExpired(at now: Date) -> Bool { accountExpires.map { $0 <= now } ?? false }

    /// The long-term key of `type`, if the account has one and its flags allow it.
    public func key(_ type: EncryptionType) -> KerberosKey? {
        switch type {
        case .rc4Hmac: guard flags.contains(.supportsRC4) else { return nil }
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1: guard flags.contains(.supportsAES) else { return nil }
        }
        return keys.first { $0.type == type }
    }

    /// Usable enctypes, strongest first (18, 17, 23).
    public var enctypes: [EncryptionType] {
        KDCPolicy.enctypePreference.filter { key($0) != nil }
    }

    /// The strongest usable key.
    public var strongestKey: KerberosKey? { enctypes.first.flatMap { key($0) } }

    /// `alice@LAB.SHEEP`, `host/dc1.lab.sheep@LAB.SHEEP`.
    public var displayName: String { "\(name.nameString.joined(separator: "/"))@\(realm)" }

    /// The account SID for users and computers.
    public var sid: SID? {
        switch kind {
        case .user(let sid, _, _, _), .computer(let sid, _, _): sid
        case .service, .krbtgt: nil
        }
    }

    public var description: String {
        "Principal(\(displayName), \(kind.label), kvno \(kvno), etypes \(enctypes.map(\.rawValue)))"
    }
}

/// Fixed policy values of the phase-0 KDC.
public enum KDCPolicy {
    /// Enctype preference, strongest first.
    public static let enctypePreference: [EncryptionType] = [.aes256CtsHmacSha1, .aes128CtsHmacSha1, .rc4Hmac]
    /// Maximum clock skew in seconds (RFC 4120 §1.6 default).
    public static let maxSkew: Int64 = 300
    /// Maximum ticket lifetime (10 h).
    public static let maxTicketLifetime: Int64 = 10 * 3600
    /// Maximum renewable lifetime (7 d).
    public static let maxRenewableLifetime: Int64 = 7 * 24 * 3600
    /// UDP replies larger than this are replaced by KRB_ERR_RESPONSE_TOO_BIG.
    public static let maxUDPReply = 1465
    /// AES string-to-key iteration count announced in PA-ETYPE-INFO2.
    public static let aesIterations: UInt32 = 4096
    /// Longest lifetime of a kadmin/changepw ticket (MIT and Samba also keep these short).
    public static let changePasswordTicketLifetime: Int64 = 5 * 60
    /// How long a PA-ENC-TIMESTAMP (and a kpasswd authenticator) stays in the replay cache:
    /// the skew window on either side of the KDC's clock.
    public static let replayWindow: Int64 = 2 * maxSkew
}

/// The KDC's account database.
public protocol PrincipalStore: Sendable {
    /// Looks an account up by name (components compared case-insensitively) in `realm`.
    func principal(_ name: PrincipalName, realm: String) async throws -> Principal?
    /// Every account, in file order (for keytab export and `show`).
    func allPrincipals() async throws -> [Principal]
    /// Canonical (uppercase) realm.
    var realm: String { get }
    /// Domain SID `S-1-5-21-x-y-z`.
    var domainSID: SID { get }
    /// NetBIOS domain name, uppercase (`LABSHEEP`).
    var netbiosDomain: String { get }
    /// NetBIOS name of the DC (`DC1`).
    var dcName: String { get }
    /// DNS domain name (`lab.sheep`).
    var dnsDomain: String { get }
    /// Called after every successful AS exchange of `principal` (AD: `lastLogon`,
    /// `logonCount`). Failures are the store's business; the exchange has already succeeded.
    func recordLogon(_ principal: Principal, at date: Date) async
}

extension PrincipalStore {
    /// Default: no logon bookkeeping.
    public func recordLogon(_ principal: Principal, at date: Date) async {}
}

extension PrincipalName {
    /// `kadmin/changepw` (NT-SRV-INST), the kpasswd service (RFC 3244).
    public static let changePassword = PrincipalName(nameType: NameType.srvInst, nameString: ["kadmin", "changepw"])
}

extension PrincipalName {
    /// Name equality as the KDC uses it: same component count, components equal ignoring case.
    /// The name-type is ignored (Heimdal asks for `host/…` as NT-PRINCIPAL).
    public func matchesIgnoringCase(_ other: PrincipalName) -> Bool {
        nameString.count == other.nameString.count
            && zip(nameString, other.nameString).allSatisfy { $0.caseInsensitiveCompare($1) == .orderedSame }
    }

    /// True for `krbtgt/<realm>` (any case).
    public func isKrbtgt(realm: String) -> Bool {
        matchesIgnoringCase(.krbtgt(realm: realm))
    }
}
