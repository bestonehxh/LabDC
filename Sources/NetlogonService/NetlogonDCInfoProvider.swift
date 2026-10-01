import Foundation

/// The advertised DC identity a NETLOGON `DsrGetDcName*` reply needs beyond what the Store holds:
/// the routable address to hand back and the site names. Injected so the acceptance harness can set
/// the VPN-facing IPv4 (matching CLDAP's `--advertise`).
public protocol NetlogonDCInfoProvider: Sendable {
    /// The DC's advertised IPv4 in dotted form (e.g. "10.8.0.1"), or nil to omit the address.
    var advertisedIPv4: String? { get }
    /// The DC's own site (`DcSiteName`).
    var dcSiteName: String { get }
    /// The client's site (`ClientSiteName`); typically the same single-site lab value.
    func clientSiteName(forClientAddress address: String) -> String
    /// DS flags advertised in `DOMAIN_CONTROLLER_INFOW.Flags`, mirroring CLDAP plus `DS_DNS_*`.
    var dcFlags: UInt32 { get }
}

/// A fixed provider for the lab / tests.
public struct StaticNetlogonDCInfoProvider: NetlogonDCInfoProvider {
    public var advertisedIPv4: String?
    public var dcSiteName: String
    public var siteForClient: String
    public var dcFlags: UInt32

    /// `flags` default: PDC|GC|LDAP|DS|KDC|TIMESERV|WRITABLE|DNS_CONTROLLER|DNS_DOMAIN|DNS_FOREST
    /// plus CLOSEST — the same shape CLDAP advertises, with the `DS_*_FLAG` bits set.
    public init(advertisedIPv4: String? = nil, dcSiteName: String = "Default-First-Site-Name",
                siteForClient: String? = nil, dcFlags: UInt32 = 0xE001_03FD) {
        self.advertisedIPv4 = advertisedIPv4
        self.dcSiteName = dcSiteName
        self.siteForClient = siteForClient ?? dcSiteName
        self.dcFlags = dcFlags
    }

    public func clientSiteName(forClientAddress address: String) -> String { siteForClient }
}
