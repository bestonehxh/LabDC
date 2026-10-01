/// `NETLOGON_NT_VERSION` options (MS-ADTS §6.3.1.1): the `NtVer` ping term and the
/// `NtVersion` field of every response.
public struct NetlogonNtVersion: OptionSet, Sendable, Hashable, CustomStringConvertible {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let v1 = NetlogonNtVersion(rawValue: 0x0000_0001)
    public static let v5 = NetlogonNtVersion(rawValue: 0x0000_0002)
    public static let v5ex = NetlogonNtVersion(rawValue: 0x0000_0004)
    public static let v5exWithIP = NetlogonNtVersion(rawValue: 0x0000_0008)
    public static let withClosestSite = NetlogonNtVersion(rawValue: 0x0000_0010)
    public static let avoidNT4Emul = NetlogonNtVersion(rawValue: 0x0100_0000)
    public static let pdc = NetlogonNtVersion(rawValue: 0x1000_0000)
    public static let ip = NetlogonNtVersion(rawValue: 0x2000_0000)
    public static let local = NetlogonNtVersion(rawValue: 0x4000_0000)
    public static let gc = NetlogonNtVersion(rawValue: 0x8000_0000)

    public var description: String {
        let names: [(NetlogonNtVersion, String)] = [
            (.v1, "V1"), (.v5, "V5"), (.v5ex, "V5EX"), (.v5exWithIP, "V5EX_WITH_IP"), (.withClosestSite, "WITH_CLOSEST_SITE"),
            (.avoidNT4Emul, "AVOID_NT4EMUL"), (.pdc, "PDC"), (.ip, "IP"), (.local, "LOCAL"), (.gc, "GC"),
        ]
        let parts = names.filter { contains($0.0) }.map(\.1)
        return parts.isEmpty ? "0x0" : parts.joined(separator: "|")
    }
}

/// `DS_FLAG` server capability bits of a netlogon response (MS-ADTS §6.3.1.2).
public struct NetlogonDSFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let pdc = NetlogonDSFlags(rawValue: 0x0000_0001)
    public static let gc = NetlogonDSFlags(rawValue: 0x0000_0004)
    public static let ldap = NetlogonDSFlags(rawValue: 0x0000_0008)
    public static let ds = NetlogonDSFlags(rawValue: 0x0000_0010)
    public static let kdc = NetlogonDSFlags(rawValue: 0x0000_0020)
    public static let timeServ = NetlogonDSFlags(rawValue: 0x0000_0040)
    public static let closest = NetlogonDSFlags(rawValue: 0x0000_0080)
    public static let writable = NetlogonDSFlags(rawValue: 0x0000_0100)
    public static let goodTimeServ = NetlogonDSFlags(rawValue: 0x0000_0200)
    public static let ndnc = NetlogonDSFlags(rawValue: 0x0000_0400)
    public static let selectSecretDomain6 = NetlogonDSFlags(rawValue: 0x0000_0800)
    public static let fullSecretDomain6 = NetlogonDSFlags(rawValue: 0x0000_1000)
    /// Active Directory Web Services running (LabDC has none).
    public static let ws = NetlogonDSFlags(rawValue: 0x0000_2000)
    /// Windows Server 2012 DC.
    public static let ds8 = NetlogonDSFlags(rawValue: 0x0000_4000)
    /// Windows Server 2012 R2 DC.
    public static let ds9 = NetlogonDSFlags(rawValue: 0x0000_8000)
    /// Windows Server 2016 DC.
    public static let ds10 = NetlogonDSFlags(rawValue: 0x0001_0000)
    public static let keyList = NetlogonDSFlags(rawValue: 0x0002_0000)
    public static let dnsController = NetlogonDSFlags(rawValue: 0x2000_0000)
    public static let dnsDomain = NetlogonDSFlags(rawValue: 0x4000_0000)
    public static let dnsForest = NetlogonDSFlags(rawValue: 0x8000_0000)

    /// What this DC announces (0xE001D3FD): a writable PDC and GC with LDAP, DS and KDC; time
    /// server; closest (there is one site); full secrets; the 2012, 2012 R2 and 2016 levels
    /// (RootDSE says `domainControllerFunctionality 7`); and the three DNS name flags.
    /// There is no `WS` flag because LabDC runs no AD Web Services.
    public static let sheepDC: NetlogonDSFlags = [
        .pdc, .gc, .ldap, .ds, .kdc, .timeServ, .closest, .writable, .goodTimeServ, .fullSecretDomain6,
        .ds8, .ds9, .ds10, .dnsController, .dnsDomain, .dnsForest,
    ]
}

/// Netlogon response operation codes (MS-ADTS §6.3.1.7–§6.3.1.9).
public enum NetlogonOpcode: UInt16, Sendable, Hashable {
    /// `LOGON_SAM_LOGON_RESPONSE`: NT40 and V5 structures, account found (or none asked for).
    case samLogonResponse = 19
    /// `LOGON_SAM_PAUSE_RESPONSE`.
    case samPauseResponse = 20
    /// `LOGON_SAM_USER_UNKNOWN`: NT40 and V5 structures, the `User` does not exist.
    case samUserUnknown = 21
    /// `LOGON_SAM_LOGON_RESPONSE_EX`.
    case samLogonResponseEx = 23
    /// `LOGON_SAM_PAUSE_RESPONSE_EX`.
    case samPauseResponseEx = 24
    /// `LOGON_SAM_USER_UNKNOWN_EX`.
    case samUserUnknownEx = 25
}

/// Errors decoding netlogon structures (tests, diagnostics) or parsing a ping filter.
public enum NetlogonError: Error, Sendable, Equatable, CustomStringConvertible {
    case truncated(String)
    case badName(String)
    case badPing(String)

    public var description: String {
        switch self {
        case .truncated(let s): "netlogon: truncated \(s)"
        case .badName(let s): "netlogon: bad compressed name: \(s)"
        case .badPing(let s): "netlogon ping: \(s)"
        }
    }
}
