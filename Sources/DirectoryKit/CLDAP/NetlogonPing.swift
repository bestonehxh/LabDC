import MSPAC
import Store

/// The terms of an LDAP ping filter (MS-ADTS §6.3.3): an AND of equality items over
/// `DnsDomain`, `Host`, `DnsHostName`, `User`, `AAC`, `DomainSid`, `DomainGuid` and `NtVer`.
///
/// Parsing follows Samba's `parse_netlogon_request`: nested ANDs are flattened, a single
/// equality item without an AND is accepted too, and names are matched case-insensitively.
/// Unknown attribute names are ignored. Any non-equality item (OR, NOT, substrings…) makes
/// the filter invalid, and the ping gets the §6.3.3.3 answer (an entry without attributes).
/// `NtVer` and `AAC` are 4-byte little-endian integers; any other length is ignored. `DomainGuid` is 16 bytes in
/// wire order or the string form, and `DomainSid` is a binary SID or `S-1-…` text.
public struct NetlogonPing: Sendable, Hashable {
    public var dnsDomain: String?
    /// NetBIOS name of the client.
    public var host: String?
    /// DNS host name of the client.
    public var dnsHostName: String?
    /// Account the client will log on with (`MACTEST$`, `alice`).
    public var user: String?
    /// Account control bits, in the MS-SAMR `USER_ACCOUNT` (ACB) form.
    public var aac: UInt32?
    public var domainSID: SID?
    public var domainGUID: GUID?
    public var ntVersion: NetlogonNtVersion?

    public init(dnsDomain: String? = nil, host: String? = nil, dnsHostName: String? = nil, user: String? = nil,
                aac: UInt32? = nil, domainSID: SID? = nil, domainGUID: GUID? = nil, ntVersion: NetlogonNtVersion? = nil) {
        self.dnsDomain = dnsDomain
        self.host = host
        self.dnsHostName = dnsHostName
        self.user = user
        self.aac = aac
        self.domainSID = domainSID
        self.domainGUID = domainGUID
        self.ntVersion = ntVersion
    }

    /// Parses a ping filter. `(objectClass=*)` (or any presence filter) counts as a ping
    /// with no terms, the "plain" RootDSE search for `Netlogon`.
    public init(filter: FilterAST) throws {
        self.init()
        var items: [FilterAST] = []
        func flatten(_ f: FilterAST) throws {
            switch f {
            case .and(let parts): for p in parts { try flatten(p) }
            case .equality, .approx: items.append(f)
            case .present: break
            default: throw NetlogonError.badPing("unsupported filter item \(f)")
            }
        }
        try flatten(filter)
        for item in items {
            let attribute: String, value: [UInt8]
            switch item {
            case .equality(let a, let v), .approx(let a, let v): (attribute, value) = (a, v)
            default: continue
            }
            let text = String(decoding: value, as: UTF8.self)
            switch attribute.lowercased() {
            case "dnsdomain": dnsDomain = text
            case "host": host = text
            case "dnshostname": dnsHostName = text
            case "user": user = text
            case "aac": if value.count == 4 { aac = Self.le32(value) }
            case "ntver": if value.count == 4 { ntVersion = NetlogonNtVersion(rawValue: Self.le32(value)) }
            case "domainguid":
                if value.count == 16, let g = try? GUID(bytes: value) {
                    domainGUID = g
                } else if let g = GUID(string: text) {
                    domainGUID = g
                } else {
                    throw NetlogonError.badPing("DomainGuid of \(value.count) bytes")
                }
            case "domainsid":
                if let s = try? SID(bytes: value) {
                    domainSID = s
                } else if let s = try? SID(string: text) {
                    domainSID = s
                } else {
                    throw NetlogonError.badPing("DomainSid of \(value.count) bytes")
                }
            default:
                continue
            }
        }
    }

    /// Whether the ping is addressed to this domain (MS-ADTS §6.3.3.2): every one of
    /// `DomainGuid`, `DnsDomain` and `DomainSid` that is present must name it. `DnsDomain` is
    /// compared case-insensitively and may end with a dot; an empty `DnsDomain` is invalid. A
    /// ping with none of the three is for the default NC, this domain.
    public func isAddressed(to info: DomainInfo) -> Bool {
        if let sid = domainSID, sid != info.domainSID { return false }
        if let guid = domainGUID, guid != info.domainGUID { return false }
        guard var name = dnsDomain else { return true }
        if name.hasSuffix(".") { name.removeLast() }
        return !name.isEmpty && name.lowercased() == info.dnsDomain.lowercased()
    }

    /// The `NtVer` the answer is built for: V1 when the term is missing.
    public var effectiveNtVersion: NetlogonNtVersion { ntVersion ?? .v1 }

    /// Which structure answers this ping (MS-ADTS §6.3.3.2): `V5EX` (or `V5EX_WITH_IP`)
    /// selects `NETLOGON_SAM_LOGON_RESPONSE_EX`, else `V5` selects
    /// `NETLOGON_SAM_LOGON_RESPONSE`, else `NETLOGON_SAM_LOGON_RESPONSE_NT40`.
    public var responseKind: NetlogonResponseKind {
        let v = effectiveNtVersion
        if !v.isDisjoint(with: [.v5ex, .v5exWithIP]) { return .ex }
        if v.contains(.v5) { return .v5 }
        return .nt40
    }

    /// The `userAccountControl` bits of which a `User` account must have at least one
    /// (MS-ADTS §6.3.3.2: `aac & uac & (TEMP_DUPLICATE | NORMAL | INTERDOMAIN_TRUST |
    /// WORKSTATION_TRUST | SERVER_TRUST)` must be non-zero). `AAC` carries MS-SAMR `USER_*`
    /// bits (0x8, 0x10, 0x40, 0x80, 0x100), mapped here to their `userAccountControl`
    /// equivalents (0x100, 0x200, 0x800, 0x1000, 0x2000). A missing `AAC` counts as 0, so a
    /// `User` term without `AAC` never finds an account, as the spec and Samba say.
    public var requiredUACBits: UInt32 {
        guard let aac else { return 0 }
        let map: [(UInt32, UInt32)] = [(0x8, 0x100), (0x10, 0x200), (0x40, 0x800), (0x80, 0x1000), (0x100, 0x2000)]
        return map.reduce(0) { aac & $1.0 != 0 ? $0 | $1.1 : $0 }
    }

    static func le32(_ b: [UInt8]) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | UInt32(b[$1]) << (8 * UInt32($1)) }
    }
}

/// Which netlogon structure a ping gets.
public enum NetlogonResponseKind: Sendable, Hashable {
    case nt40, v5, ex
}
