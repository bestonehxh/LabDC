import KerberosCrypto
import MSPAC
import Synchronization

/// Who authenticated: the result of every AuthKit mechanism.
public struct AuthenticatedIdentity: Sendable, Hashable, CustomStringConvertible {
    /// The account SID (domain SID + RID), or S-1-5-7 for anonymous.
    public var sid: SID
    /// sAMAccountName (`alice`, `DC1$`).
    public var sam: String
    /// NetBIOS domain name (`LABSHEEP`), `NT AUTHORITY` for anonymous.
    public var domain: String
    /// Group SIDs (primary group, other groups, extra SIDs).
    public var groups: [SID]
    /// The Kerberos client principal (`alice@LAB.SHEEP`) when Kerberos was used.
    public var principal: String?

    public init(sid: SID, sam: String, domain: String, groups: [SID] = [], principal: String? = nil) {
        self.sid = sid
        self.sam = sam
        self.domain = domain
        self.groups = groups
        self.principal = principal
    }

    /// `NT AUTHORITY\ANONYMOUS LOGON` (S-1-5-7), what an NTLM anonymous logon yields.
    public static let anonymous = AuthenticatedIdentity(
        sid: try! SID(identifierAuthority: 5, subAuthorities: [7]),
        sam: "ANONYMOUS LOGON", domain: "NT AUTHORITY")

    public var isAnonymous: Bool { sid == Self.anonymous.sid }

    /// `DOMAIN\sam`, the form LDAP WhoAmI (`u:LABSHEEP\alice`) uses.
    public var downLevelName: String { "\(domain)\\\(sam)" }

    public var description: String { "\(downLevelName) (\(sid))" }

    /// The identity a PAC describes: SID = LogonDomainId + UserId, groups = domain SID + each
    /// GroupIds RID (primary group first), then ExtraSids, then resource groups. Returns `nil`
    /// when the PAC has no PAC_LOGON_INFO.
    public init?(pac: ParsedPAC, principal: String? = nil) {
        guard let info = pac.logonInfo, let userSID = info.userSID else { return nil }
        var groups: [SID] = []
        var rids = [info.primaryGroupId]
        rids += info.groupIds.map(\.relativeId).filter { $0 != info.primaryGroupId }
        for rid in rids { if let g = try? info.logonDomainId.appending(rid: rid) { groups.append(g) } }
        groups += info.extraSids.map(\.sid)
        if let rsid = info.resourceGroupDomainSid {
            for g in info.resourceGroupIds { if let s = try? rsid.appending(rid: g.relativeId) { groups.append(s) } }
        }
        self.init(sid: userSID, sam: info.effectiveName, domain: info.logonDomainName, groups: groups,
                  principal: principal)
    }
}

/// Where AuthKit gets secrets and account data. The Store implements it in WP-L; tests use
/// `InMemorySecretSource`.
public protocol AuthSecretSource: Sendable {
    /// NT hash (MD4 of UTF-16LE password) and identity of an account, looked up by
    /// sAMAccountName (case-insensitive). `nil` when the account does not exist or is disabled.
    func ntHash(forSAM sam: String) async -> (hash: [UInt8], identity: AuthenticatedIdentity)?
    /// Long-term keys for a service principal name without realm (`host/dc1.lab.sheep`,
    /// `ldap/dc1.lab.sheep`, `GC/dc1.lab.sheep/lab.sheep`, `DC1$`). Empty when unknown.
    func serviceKeys(forSPN spn: String) async -> [KerberosKey]
    /// Maps a verified PAC to an identity (the Store may enrich it; the default uses the PAC only).
    func identity(fromPAC pac: ParsedPAC) -> AuthenticatedIdentity
    /// Identity for a Kerberos client whose ticket has no PAC. Default: the `ntHash` identity.
    func identity(forSAM sam: String) async -> AuthenticatedIdentity?
    /// NetBIOS domain (`LABSHEEP`).
    var netbiosDomain: String { get }
    /// DNS domain (`lab.sheep`); the realm is its upper-case form.
    var dnsDomain: String { get }
    /// NetBIOS computer name of this DC (`DC1`).
    var dcName: String { get }
}

extension AuthSecretSource {
    public func identity(fromPAC pac: ParsedPAC) -> AuthenticatedIdentity {
        AuthenticatedIdentity(pac: pac) ?? .anonymous
    }

    public func identity(forSAM sam: String) async -> AuthenticatedIdentity? {
        await ntHash(forSAM: sam)?.identity
    }

    /// The Kerberos realm: the DNS domain in upper case.
    public var realm: String { dnsDomain.uppercased() }
    /// `dc1.lab.sheep`.
    public var dcDNSName: String { dcName.lowercased() + "." + dnsDomain.lowercased() }
}

/// In-memory `AuthSecretSource` for tests and tools.
public final class InMemorySecretSource: AuthSecretSource {
    public struct Account: Sendable {
        public var ntHash: [UInt8]
        public var identity: AuthenticatedIdentity
        public init(ntHash: [UInt8], identity: AuthenticatedIdentity) {
            self.ntHash = ntHash
            self.identity = identity
        }
    }

    public let netbiosDomain: String
    public let dnsDomain: String
    public let dcName: String
    private let state: Mutex<(accounts: [String: Account], services: [String: [KerberosKey]])>

    public init(netbiosDomain: String, dnsDomain: String, dcName: String) {
        self.netbiosDomain = netbiosDomain
        self.dnsDomain = dnsDomain
        self.dcName = dcName
        state = Mutex((accounts: [:], services: [:]))
    }

    /// Adds an account with a password (NT hash computed here).
    public func addAccount(sam: String, password: String, sid: SID, groups: [SID] = []) {
        addAccount(sam: sam, ntHash: NTLMCrypto.ntHash(password: password),
                   identity: AuthenticatedIdentity(sid: sid, sam: sam, domain: netbiosDomain, groups: groups))
    }

    public func addAccount(sam: String, ntHash: [UInt8], identity: AuthenticatedIdentity) {
        state.withLock { $0.accounts[sam.lowercased()] = Account(ntHash: ntHash, identity: identity) }
    }

    /// Registers keys for one or more SPNs (case-insensitive).
    public func addService(spns: [String], keys: [KerberosKey]) {
        state.withLock { s in for spn in spns { s.services[spn.lowercased()] = keys } }
    }

    public func ntHash(forSAM sam: String) async -> (hash: [UInt8], identity: AuthenticatedIdentity)? {
        state.withLock { s in s.accounts[sam.lowercased()].map { ($0.ntHash, $0.identity) } }
    }

    public func serviceKeys(forSPN spn: String) async -> [KerberosKey] {
        state.withLock { $0.services[spn.lowercased()] ?? [] }
    }
}
