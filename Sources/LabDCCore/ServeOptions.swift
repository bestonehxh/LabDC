// UI-1: the `serve` configuration types, moved from LabDCCLI/Arguments.swift into LabDCCore
// so the CLI and the app share them (CLIParser, in LabDCCLI, still fills them from argv).
import DNSKit
import Foundation
import NetlogonService

/// A command-line failure: `usage` exits 64 (EX_USAGE) with the usage text, `failure` exits 1.
public enum CLIError: Error, Equatable, CustomStringConvertible {
    case usage(String)
    case failure(String)

    public var description: String {
        switch self {
        case .usage(let s), .failure(let s): s
        }
    }

    public var exitCode: Int32 {
        switch self {
        case .usage: 64
        case .failure: 1
        }
    }
}

/// Every listening port of `serve`. 0 picks an ephemeral port (tests).
public struct PortSet: Equatable, Sendable {
    public var dns: UInt16 = 53
    public var kdc: UInt16 = 88
    public var kpasswd: UInt16 = 464
    public var ldap: UInt16 = 389
    public var ldaps: UInt16 = 636
    public var gc: UInt16 = 3268
    public var gcs: UInt16 = 3269
    public var cldap: UInt16 = 389
    public var smb: UInt16 = 445
    public var sntp: UInt16 = 123
    /// The RPC endpoint mapper (well-known TCP 135).
    public var epm: UInt16 = 135
    /// The shared dynamic `ncacn_ip_tcp` port; 0 asks the OS for one in the 49152–65535 range.
    public var rpc: UInt16 = 0
    /// PK-1: plain HTTP for the CRL distribution point and AIA (`/pki/<ca>.crl`, `/pki/<ca>.crt`).
    public var http: UInt16 = 80
    /// PK-7: EST over HTTPS (`/.well-known/est/…`).
    public var est: UInt16 = 8443
    /// PK-6: HTTPS for the enrollment web services (MS-XCEP CEP + MS-WSTEP CES, Windows auto-enrollment).
    public var https: UInt16 = 443
    /// WP-AR2: the NetBIOS name service (udp 137, `NBNSServer`).
    public var nbns: UInt16 = 137
    /// WP-AR2: the NetBIOS session service (tcp 139): SMB over NetBIOS, served by the SMB server.
    public var nbss: UInt16 = 139
    /// Phase 4a: RADIUS authentication (udp 1812) and accounting (udp 1813).
    public var radius: UInt16 = 1812
    public var radacct: UInt16 = 1813

    public init() {}

    public static let standard = PortSet()

    /// Every listener on an ephemeral port.
    public static var ephemeral: PortSet {
        var p = PortSet()
        p.dns = 0; p.kdc = 0; p.kpasswd = 0; p.ldap = 0; p.ldaps = 0; p.gc = 0; p.gcs = 0; p.cldap = 0
        p.smb = 0; p.sntp = 0; p.epm = 0; p.rpc = 0; p.http = 0; p.est = 0; p.https = 0
        p.nbns = 0; p.nbss = 0
        p.radius = 0; p.radacct = 0
        return p
    }

    public static let names = ["dns", "kdc", "kpasswd", "ldap", "ldaps", "gc", "gcs", "cldap", "smb", "sntp", "epm", "rpc", "http", "est", "https",
                               "nbns", "nbss", "radius", "radacct"]

    /// Applies `dns=53,kdc=88,...` (any subset, any order).
    public mutating func apply(_ spec: String) throws {
        for item in spec.split(separator: ",", omittingEmptySubsequences: true) {
            let kv = item.split(separator: "=", maxSplits: 1).map(String.init)
            guard kv.count == 2, let port = UInt16(kv[1]) else { throw CLIError.usage("bad --ports item '\(item)' (want name=port)") }
            switch kv[0].lowercased() {
            case "dns": dns = port
            case "kdc", "kerberos": kdc = port
            case "kpasswd": kpasswd = port
            case "ldap": ldap = port
            case "ldaps": ldaps = port
            case "gc": gc = port
            case "gcs", "gc-tls", "gctls": gcs = port
            case "cldap": cldap = port
            case "smb", "cifs": smb = port
            case "sntp", "ntp": sntp = port
            case "epm", "epmapper", "portmap": epm = port
            case "rpc", "rpc-tcp", "ncacn": rpc = port
            case "http", "cdp", "scep": http = port
            case "est", "https-est": est = port
            case "https", "ces", "cep": https = port
            case "nbns", "netbios-ns": nbns = port
            case "radius", "rad": radius = port
            case "radacct", "radius-acct": radacct = port
            case "nbss", "netbios-ssn": nbss = port
            default: throw CLIError.usage("unknown port name '\(kv[0])' (known: \(Self.names.joined(separator: ", ")))")
            }
        }
    }
}

/// `--provision realm=LAB.SHEEP dns=lab.sheep netbios=LABSHEEP dc=dc1 admin-password=...`.
public struct ProvisionSpec: Equatable, Sendable {
    public var realm: String
    public var dnsDomain: String
    public var netbios: String
    public var dcName: String
    public var adminPassword: String

    public init(realm: String, dnsDomain: String, netbios: String, dcName: String, adminPassword: String) {
        self.realm = realm
        self.dnsDomain = dnsDomain
        self.netbios = netbios
        self.dcName = dcName
        self.adminPassword = adminPassword
    }

    /// Parses `key=value` tokens. Defaults: `realm` = upper-case `dns`, `dns` = lower-case
    /// `realm`, `netbios` = the first DNS label upper-cased (15 characters at most), `dc` = `dc1`.
    /// `admin-password` is required.
    public static func parse(_ tokens: [String]) throws -> ProvisionSpec {
        var kv: [String: String] = [:]
        for token in tokens {
            let parts = token.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2, !parts[0].isEmpty else { throw CLIError.usage("bad --provision item '\(token)' (want key=value)") }
            let key = parts[0].lowercased()
            guard ["realm", "dns", "netbios", "dc", "admin-password"].contains(key) else {
                throw CLIError.usage("unknown --provision key '\(parts[0])' (known: realm, dns, netbios, dc, admin-password)")
            }
            kv[key] = parts[1]
        }
        guard let password = kv["admin-password"], !password.isEmpty else {
            throw CLIError.usage("--provision needs admin-password=<password>")
        }
        guard let dns = kv["dns"]?.lowercased() ?? kv["realm"]?.lowercased(), !dns.isEmpty else {
            throw CLIError.usage("--provision needs realm= or dns=")
        }
        let realm = (kv["realm"] ?? dns).uppercased()
        let firstLabel = dns.split(separator: ".").first.map(String.init) ?? dns
        let netbios = (kv["netbios"] ?? String(firstLabel.prefix(15))).uppercased()
        let dc = (kv["dc"] ?? "dc1").lowercased()
        guard netbios.count <= 15 else { throw CLIError.usage("netbios name '\(netbios)' is longer than 15 characters") }
        guard !dc.contains("."), !dc.isEmpty else { throw CLIError.usage("dc= must be a single host label, like dc1") }
        return ProvisionSpec(realm: realm, dnsDomain: dns, netbios: netbios, dcName: dc, adminPassword: password)
    }
}

public struct ServeOptions: Equatable, Sendable {
    public var dataDirectory: URL
    public var provision: ProvisionSpec?
    public var ports: PortSet
    public var dnsEnabled: Bool
    /// SMB2/3 server on 445 with SYSVOL/NETLOGON/IPC$ and the RPC pipes (`--no-smb` disables).
    public var smbEnabled: Bool
    /// SNTP server on udp 123 (`--no-sntp` disables).
    public var sntpEnabled: Bool
    /// RPC endpoint mapper (tcp 135) + the shared dynamic `ncacn_ip_tcp` port (`--no-rpc-tcp` disables).
    public var rpcTcpEnabled: Bool
    /// PK-1: the HTTP listener for CRLs and CA certificates (`--no-http` disables).
    public var httpEnabled: Bool = true
    /// PK-7: the EST listener (HTTPS, 8443; `--no-est` disables). SCEP rides on the HTTP listener.
    public var estEnabled: Bool = true
    /// PK-6: the CEP / CES listener (HTTPS, 443; `--no-https` disables).
    public var httpsEnabled: Bool = true
    /// WP-AR2: NetBIOS name service (udp 137) and session service (tcp 139, with SMB). Off by
    /// default — nothing in the join, LDAP or RADIUS flows needs NetBIOS, and on a Mac macOS's own
    /// `netbiosd` owns 137. `--netbios` enables it (`--no-netbios` stays for older scripts).
    public var netbiosEnabled: Bool = false
    /// Phase 4a: the RADIUS server (udp 1812/1813). Always on with the directory (owner,
    /// 30 Sep 2026); `labdc serve --no-radius` turns it off for tests and scripts.
    public var radiusEnabled: Bool = true
    /// UI-1 ("Allow plain LDAP"): simple binds with a password on 389 without TLS/StartTLS.
    public var allowPlainLDAP: Bool = true
    /// PK-1: seconds between checks that every CA's CRL is less than a day old; 0 disables.
    public var crlCheckInterval: Double = 3600
    /// The IPv4 DNS publishes for the DC and CLDAP/LDAP pings return (`--advertise`).
    public var advertise: String?
    public var verbose: Bool
    /// Netlogon network-logon NTLM policy (`--ntlm-auth`, Samba's `ntlm auth` values; WP-Z).
    public var ntlmAuth: NTLMAuthPolicy = .mschapv2AndNTLMv2Only
    /// Seconds between checks of the Mac's IPv4 addresses (certificate reissue); 0 disables.
    public var addressCheckInterval: Double
    /// Where DNS sends names outside the domain (`--forwarders`; default this Mac's DNS).
    public var dnsForwarding: DNSForwarding = .system

    public init(dataDirectory: URL, provision: ProvisionSpec? = nil, ports: PortSet = .standard, dnsEnabled: Bool = true,
                smbEnabled: Bool = true, sntpEnabled: Bool = true, rpcTcpEnabled: Bool = true,
                advertise: String? = nil, verbose: Bool = false, addressCheckInterval: Double = 30) {
        self.dataDirectory = dataDirectory
        self.provision = provision
        self.ports = ports
        self.dnsEnabled = dnsEnabled
        self.smbEnabled = smbEnabled
        self.sntpEnabled = sntpEnabled
        self.rpcTcpEnabled = rpcTcpEnabled
        self.advertise = advertise
        self.verbose = verbose
        self.addressCheckInterval = addressCheckInterval
    }
}
