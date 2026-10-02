import Foundation

/// One listening socket group of `serve`, named like the `--ports` keys.
public enum ServeListener: String, CaseIterable, Sendable, Codable, Identifiable {
    case dns, kdc, kpasswd, ldap, ldaps, gc, gcs, cldap, smb, sntp, epm, rpc, http, est, https, nbns, nbss, radius, radacct, dhcp, dhcpv6

    public var id: String { rawValue }

    /// The name on screen (`Kerberos`, `LDAPS`, …).
    public var displayName: String {
        switch self {
        case .dns: "DNS"
        case .kdc: "Kerberos"
        case .kpasswd: "Password change (kpasswd)"
        case .ldap: "LDAP"
        case .ldaps: "LDAPS"
        case .gc: "Global Catalog"
        case .gcs: "Global Catalog (TLS)"
        case .cldap: "CLDAP"
        case .smb: "SMB"
        case .sntp: "Time (SNTP)"
        case .epm: "RPC endpoint mapper"
        case .rpc: "RPC (dynamic)"
        case .http: "HTTP (CRL, SCEP)"
        case .est: "EST (HTTPS)"
        case .https: "Enrollment web services (HTTPS)"
        case .nbns: "NetBIOS name service"
        case .nbss: "NetBIOS session (SMB over 139)"
        case .radius: "RADIUS"
        case .radacct: "RADIUS accounting"
        case .dhcp: "DHCP"
        case .dhcpv6: "DHCPv6"
        }
    }

    /// Short chip label (`LDAPS 636`).
    public var shortName: String {
        switch self {
        case .dns: "DNS"
        case .kdc: "Kerberos"
        case .kpasswd: "kpasswd"
        case .ldap: "LDAP"
        case .ldaps: "LDAPS"
        case .gc: "GC"
        case .gcs: "GC-TLS"
        case .cldap: "CLDAP"
        case .smb: "SMB"
        case .sntp: "SNTP"
        case .epm: "EPM"
        case .rpc: "RPC"
        case .http: "HTTP"
        case .est: "EST"
        case .https: "HTTPS"
        case .nbns: "NBNS"
        case .nbss: "NBSS"
        case .radius: "RADIUS"
        case .radacct: "RADIUS acct"
        case .dhcp: "DHCP"
        case .dhcpv6: "DHCPv6"
        }
    }

    public var transport: String {
        switch self {
        case .dns, .kdc, .kpasswd: "udp+tcp"
        case .cldap, .sntp, .nbns, .radius, .radacct, .dhcp, .dhcpv6: "udp"
        default: "tcp"
        }
    }

    /// The service family the Overview status line names ("DNS, Kerberos, LDAP, SMB, RPC, HTTP").
    public var service: String {
        switch self {
        case .dns: "DNS"
        case .kdc, .kpasswd: "Kerberos"
        case .ldap, .ldaps, .gc, .gcs, .cldap: "LDAP"
        case .smb, .nbns, .nbss: "SMB"
        case .sntp: "Time"
        case .epm, .rpc: "RPC"
        case .http, .est, .https: "HTTP"
        case .radius, .radacct: "RADIUS"
        case .dhcp, .dhcpv6: "DHCP"
        }
    }

    /// The service families in Overview order.
    public static let services = ["DNS", "Kerberos", "LDAP", "SMB", "RPC", "HTTP", "Time", "RADIUS", "DHCP"]

    /// Listeners that move together (one server object behind them).
    public var restartsWith: [ServeListener] {
        switch self {
        case .ldap, .ldaps, .gc, .gcs: [.ldap, .ldaps, .gc, .gcs]
        // NBSS is a second port of the SMB server; NBNS is its own server (restarts alone).
        case .smb, .sntp, .nbss: [.smb, .sntp, .nbss]
        case .epm, .rpc: [.epm, .rpc]
        case .dhcp, .dhcpv6: [.dhcp, .dhcpv6]
        default: [self]
        }
    }

    /// Whether `options` runs this listener at all.
    public func isEnabled(in options: ServeOptions) -> Bool {
        switch self {
        case .dns: options.dnsEnabled
        case .smb: options.smbEnabled
        case .nbns: options.netbiosEnabled
        case .nbss: options.netbiosEnabled && options.smbEnabled
        case .sntp: options.sntpEnabled
        case .epm, .rpc: options.rpcTcpEnabled
        case .radius, .radacct: options.radiusEnabled
        case .dhcp: options.dhcpEnabled
        case .dhcpv6: options.dhcpEnabled && options.dhcpV6Enabled
        case .http: options.httpEnabled
        case .est: options.estEnabled
        case .https: options.httpsEnabled
        default: true
        }
    }

    /// The bound port in `ports` (nil: not listening).
    public func bound(in ports: ServeBoundPorts) -> Int? {
        switch self {
        case .dns: ports.dns.map(Int.init)
        case .kdc: ports.kdc.map(Int.init)
        case .kpasswd: ports.kpasswd.map(Int.init)
        case .ldap: ports.ldap
        case .ldaps: ports.ldaps
        case .gc: ports.gc
        case .gcs: ports.gcs
        case .cldap: ports.cldap.map(Int.init)
        case .smb: ports.smb
        case .sntp: ports.sntp.map(Int.init)
        case .epm: ports.epm
        case .rpc: ports.rpc
        case .http: ports.http
        case .est: ports.est
        case .https: ports.https
        case .nbns: ports.nbns
        case .nbss: ports.nbss
        case .radius: ports.radius.map { Int($0) }
        case .radacct: ports.radacct.map { Int($0) }
        case .dhcp: ports.dhcp
        case .dhcpv6: ports.dhcpv6
        }
    }
}

extension PortSet {
    /// The configured port of one listener.
    public subscript(listener: ServeListener) -> UInt16 {
        get {
            switch listener {
            case .dns: dns
            case .kdc: kdc
            case .kpasswd: kpasswd
            case .ldap: ldap
            case .ldaps: ldaps
            case .gc: gc
            case .gcs: gcs
            case .cldap: cldap
            case .smb: smb
            case .sntp: sntp
            case .epm: epm
            case .rpc: rpc
            case .http: http
            case .est: est
            case .https: https
            case .nbns: nbns
            case .nbss: nbss
            case .radius: radius
            case .radacct: radacct
            case .dhcp: dhcp
            case .dhcpv6: dhcpv6
            }
        }
        set {
            switch listener {
            case .dns: dns = newValue
            case .kdc: kdc = newValue
            case .kpasswd: kpasswd = newValue
            case .ldap: ldap = newValue
            case .ldaps: ldaps = newValue
            case .gc: gc = newValue
            case .gcs: gcs = newValue
            case .cldap: cldap = newValue
            case .smb: smb = newValue
            case .sntp: sntp = newValue
            case .epm: epm = newValue
            case .rpc: rpc = newValue
            case .http: http = newValue
            case .est: est = newValue
            case .https: https = newValue
            case .nbns: nbns = newValue
            case .nbss: nbss = newValue
            case .radius: radius = newValue
            case .radacct: radacct = newValue
            case .dhcp: dhcp = newValue
            case .dhcpv6: dhcpv6 = newValue
            }
        }
    }
}
