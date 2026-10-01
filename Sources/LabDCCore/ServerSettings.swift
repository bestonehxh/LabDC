import DNSKit
import Foundation
import NetlogonService

/// The app's server settings (Settings ▸ Directory), kept in `<data>/settings.json` next to the
/// store so a backup carries them. Only what differs from `labdc serve`'s defaults is
/// meaningful; the CLI does not read this file (its flags stay the source of truth there).
public struct ServerSettings: Codable, Equatable, Sendable {
    /// Ports that differ from `PortSet.standard`, keyed by `ServeListener` raw value.
    public var ports: [String: UInt16]
    /// "Let devices join the domain": DNS, SMB (+ RPC pipes), RPC over TCP and SNTP. Off leaves
    /// LDAP/CLDAP, Kerberos and HTTP/EST running.
    public var joinDomain: Bool
    /// "Allow plain LDAP": simple binds with a password on 389 without TLS.
    public var allowPlainLDAP: Bool
    /// "Let NAC read password hashes": the Netlogon NTLM policy (`--ntlm-auth`).
    public var ntlmAuth: NTLMAuthPolicy
    /// A pinned advertised IPv4 (`--advertise`); nil follows the Mac's address.
    public var advertise: String?
    /// Settings ▸ Directory ▸ Other names: where DNS sends names outside the domain. Empty = this
    /// Mac's DNS (followed as the network changes), else these servers (`--forwarders`).
    public var dnsForwarders: [String] = []
    /// Serve the NetBIOS name service (udp 137) and session service (tcp 139). Off by default:
    /// nothing in the join, LDAP or RADIUS flows uses NetBIOS (it is a legacy-name fallback), and
    /// on a Mac macOS's own `netbiosd` owns 137 — with it off the app starts without any error.
    /// Turn on with `"netbios": true` here; the CLI is off by default too and turns it on with
    /// `--netbios` (`--no-netbios` is still accepted for older scripts).
    public var netbios: Bool = false

    public init(ports: [String: UInt16] = [:], joinDomain: Bool = true, allowPlainLDAP: Bool = true,
                ntlmAuth: NTLMAuthPolicy = .mschapv2AndNTLMv2Only, advertise: String? = nil, netbios: Bool = false) {
        self.ports = ports
        self.joinDomain = joinDomain
        self.allowPlainLDAP = allowPlainLDAP
        self.ntlmAuth = ntlmAuth
        self.advertise = advertise
        self.netbios = netbios
    }

    /// RADIUS has no switch (owner, 30 Sep 2026: it starts with the directory, always on); an old
    /// file's `"radius"` key is ignored on read and dropped on the next save.
    enum CodingKeys: String, CodingKey { case ports, joinDomain, allowPlainLDAP, ntlmAuth, advertise, dnsForwarders, netbios }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ServerSettings()
        ports = try c.decodeIfPresent([String: UInt16].self, forKey: .ports) ?? d.ports
        joinDomain = try c.decodeIfPresent(Bool.self, forKey: .joinDomain) ?? d.joinDomain
        allowPlainLDAP = try c.decodeIfPresent(Bool.self, forKey: .allowPlainLDAP) ?? d.allowPlainLDAP
        ntlmAuth = (try c.decodeIfPresent(String.self, forKey: .ntlmAuth)).flatMap(NTLMAuthPolicy.init(rawValue:)) ?? d.ntlmAuth
        advertise = try c.decodeIfPresent(String.self, forKey: .advertise)
        dnsForwarders = try c.decodeIfPresent([String].self, forKey: .dnsForwarders) ?? []
        netbios = try c.decodeIfPresent(Bool.self, forKey: .netbios) ?? d.netbios
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(ports, forKey: .ports)
        try c.encode(joinDomain, forKey: .joinDomain)
        try c.encode(allowPlainLDAP, forKey: .allowPlainLDAP)
        try c.encode(ntlmAuth.rawValue, forKey: .ntlmAuth)
        try c.encodeIfPresent(advertise, forKey: .advertise)
        if !dnsForwarders.isEmpty { try c.encode(dnsForwarders, forKey: .dnsForwarders) }
        if netbios { try c.encode(netbios, forKey: .netbios) }
    }

    /// `dnsForwarders` as the serve option.
    public var dnsForwarding: DNSForwarding { DNSForwarding(settingsList: dnsForwarders) }

    /// `PortSet.standard` with the overrides applied.
    public var portSet: PortSet {
        var p = PortSet.standard
        for (name, port) in ports {
            if let l = ServeListener(rawValue: name) { p[l] = port }
        }
        return p
    }

    public func port(_ listener: ServeListener) -> UInt16 { portSet[listener] }

    public mutating func setPort(_ listener: ServeListener, _ port: UInt16) {
        if PortSet.standard[listener] == port { ports.removeValue(forKey: listener.rawValue) } else { ports[listener.rawValue] = port }
    }

    /// The `serve` options for `data` (what `labdc serve --data … [flags]` would build).
    public func serveOptions(data: URL, portOverride: PortSet? = nil, provision: ProvisionSpec? = nil) -> ServeOptions {
        var o = ServeOptions(dataDirectory: data, provision: provision, ports: portOverride ?? portSet)
        o.dnsEnabled = joinDomain
        o.smbEnabled = joinDomain
        o.rpcTcpEnabled = joinDomain
        o.sntpEnabled = joinDomain
        o.netbiosEnabled = netbios             // off by default: macOS's netbiosd owns 137, and nothing in the join needs it
        o.allowPlainLDAP = allowPlainLDAP
        o.ntlmAuth = ntlmAuth
        o.advertise = advertise
        o.dnsForwarding = dnsForwarding
        return o
    }

    public static func load(_ url: URL) -> ServerSettings {
        guard let data = try? Data(contentsOf: url), let s = try? JSONDecoder().decode(ServerSettings.self, from: data) else {
            return ServerSettings()
        }
        return s
    }

    public func save(_ url: URL) throws {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        try e.encode(self).write(to: url, options: .atomic)
    }
}

extension NTLMAuthPolicy {
    /// Settings ▸ Directory picker label.
    public var settingsLabel: String {
        switch self {
        case .ntlmv2Only: "Only NTLMv2"
        case .mschapv2AndNTLMv2Only: "MS-CHAPv2 and NTLMv2 (recommended)"
        case .on: "Any NTLM, including NTLMv1"
        }
    }
}
