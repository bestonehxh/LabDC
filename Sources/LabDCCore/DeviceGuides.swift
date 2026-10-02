import CryptoKit
import Foundation
import PKIKit
import SYSVOL

// UI-4 Connect: which device, the live values it asks for, and the steps in the order the device
// asks for them. Pure data (no SwiftUI) so the guides are testable and "Copy all values" is the
// same text the page shows.

/// The device types on the Connect page, in picker order.
public enum DeviceKind: String, CaseIterable, Identifiable, Sendable, Codable {
    case windows, clearpass, imaster, linux, apple, switchAP, other

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .windows: "Windows PC"
        case .clearpass: "Aruba ClearPass"
        case .imaster: "Huawei iMaster NCE-Campus"
        case .linux: "Ubuntu / Linux (SSSD)"
        case .apple: "Apple (Mac / iPhone)"
        case .switchAP: "Switch / AP"
        case .other: "Other"
        }
    }

    /// The picker tile's short name.
    public var shortTitle: String {
        switch self {
        case .windows: "Windows PC"
        case .clearpass: "ClearPass"
        case .imaster: "iMaster NCE"
        case .linux: "Ubuntu / Linux"
        case .apple: "Mac / iPhone"
        case .switchAP: "Switch / AP"
        case .other: "Other"
        }
    }

    /// One line under the page title.
    public var subtitle: String {
        switch self {
        case .windows: "Join the domain, get the policy and the CA, sign in with a domain account."
        case .clearpass: "Join AD for MS-CHAPv2, add the LDAP source, give RADIUS a certificate from this CA."
        case .imaster: "Every controller node joins; users and computers sync over LDAP."
        case .linux: "realmd + SSSD: join with realm join, sign in as a domain user."
        case .apple: "One profile trusts the CA; a Mac can also bind to the domain."
        case .switchAP: "Certificates by SCEP or EST with a challenge; 802.1X through this DC's RADIUS."
        case .other: "The generic LDAP, Kerberos and CA values."
        }
    }

    public var symbol: String {
        switch self {
        case .windows: "pc"
        case .clearpass: "shield.lefthalf.filled"
        case .imaster: "server.rack"
        case .linux: "terminal"
        case .apple: "laptopcomputer.and.iphone"
        case .switchAP: "wifi.router"
        case .other: "square.grid.2x2"
        }
    }
}

/// The live values the guides fill in (from `ServerStatus`, the bound ports, the settings and the
/// current CA).
public struct ConnectValues: Equatable, Sendable {
    /// The address devices use (the advertised IPv4, else the DC's DNS name).
    public var address: String
    public var dnsDomain: String
    public var realm: String
    public var netbios: String
    public var dcFQDN: String
    public var baseDN: String
    /// `CN=Administrator,CN=Users,<base>`
    public var lookupAccountDN: String
    public var adminAccount = "Administrator"
    public var ldapPort: Int
    public var ldapsPort: Int
    public var kerberosPort: Int
    public var httpPort: Int
    public var estPort: Int
    public var httpsPort: Int
    /// RADIUS authentication and accounting (1812 / 1813 unless moved).
    public var radiusPort: Int
    public var radiusAccountingPort: Int
    public var caName: String
    /// Upper-case colon hex, nil until the CA is known.
    public var caSHA256: String?
    public var caSHA1: String?
    /// "Allow plain LDAP" (Settings ▸ System): simple binds on 389 work only when on.
    public var allowPlainLDAP: Bool

    public init(address: String, dnsDomain: String, realm: String, netbios: String, dcFQDN: String, baseDN: String,
                ldapPort: Int = 389, ldapsPort: Int = 636, kerberosPort: Int = 88, httpPort: Int = 80, estPort: Int = 8443,
                httpsPort: Int = 443, radiusPort: Int = 1812, radiusAccountingPort: Int = 1813, caName: String = LabPKI.labCAName, caDER: [UInt8]? = nil, allowPlainLDAP: Bool = true) {
        self.address = address
        self.dnsDomain = dnsDomain
        self.realm = realm
        self.netbios = netbios
        self.dcFQDN = dcFQDN
        self.baseDN = baseDN
        lookupAccountDN = baseDN.isEmpty ? "CN=Administrator,CN=Users" : "CN=Administrator,CN=Users,\(baseDN)"
        self.ldapPort = ldapPort
        self.ldapsPort = ldapsPort
        self.kerberosPort = kerberosPort
        self.httpPort = httpPort
        self.estPort = estPort
        self.httpsPort = httpsPort
        self.radiusPort = radiusPort
        self.radiusAccountingPort = radiusAccountingPort
        self.caName = caName
        if let caDER {
            caSHA256 = Self.fingerprint(Array(SHA256.hash(data: caDER)))
            caSHA1 = Self.fingerprint(Array(Insecure.SHA1.hash(data: caDER)))
        }
        self.allowPlainLDAP = allowPlainLDAP
    }

    /// From what the app knows. Missing names fall back to the wizard's defaults so the page never
    /// shows empty fields before the server has started.
    public static func make(address: String?, dnsDomain: String?, realm: String?, netbios: String?, dcFQDN: String?,
                            baseDN: String?, ports: [ServeListener: Int], caName: String?, caDER: [UInt8]?,
                            allowPlainLDAP: Bool) -> ConnectValues {
        let domain = dnsDomain ?? DomainSetup.suggested
        let dc = dcFQDN ?? "dc1.\(domain)"
        return ConnectValues(address: address ?? dc, dnsDomain: domain, realm: realm ?? domain.uppercased(),
                             netbios: netbios ?? String(domain.split(separator: ".").first ?? "LAB").uppercased(),
                             dcFQDN: dc,
                             baseDN: baseDN ?? domain.split(separator: ".").map { "DC=\($0)" }.joined(separator: ","),
                             ldapPort: ports[.ldap] ?? 389, ldapsPort: ports[.ldaps] ?? 636, kerberosPort: ports[.kdc] ?? 88,
                             httpPort: ports[.http] ?? 80, estPort: ports[.est] ?? 8443, httpsPort: ports[.https] ?? 443,
                             radiusPort: ports[.radius] ?? 1812, radiusAccountingPort: ports[.radacct] ?? 1813,
                             caName: caName ?? LabPKI.labCAName, caDER: caDER, allowPlainLDAP: allowPlainLDAP)
    }

    static func fingerprint(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    private func port(_ p: Int, default d: Int) -> String { p == d ? "" : ":\(p)" }

    /// `ldap://10.0.0.5:389`
    public var ldapURL: String { "ldap://\(address):\(ldapPort)" }
    /// `ldaps://10.0.0.5:636`
    public var ldapsURL: String { "ldaps://\(address):\(ldapsPort)" }
    /// `http://10.0.0.5/pki/lab.crt`
    public var caDownloadURL: String { "http://\(address)\(port(httpPort, default: 80))\(CAService.caCertificatePath(caName: caName))" }
    /// `http://10.0.0.5/scep`
    public var scepURL: String { "http://\(address)\(port(httpPort, default: 80))/scep" }
    /// The NDES path Huawei and ClearPass Onboard expect.
    public var scepNDESURL: String { "http://\(address)\(port(httpPort, default: 80))/certsrv/mscep/mscep.dll" }
    /// `https://10.0.0.5:8443/.well-known/est`
    public var estURL: String { "https://\(address):\(estPort)/.well-known/est" }
    /// Windows auto-enrollment's policy server (by DNS name: Kerberos needs it).
    public var cepURL: String {
        let base = AutoEnrollmentSettings.defaultCEPURL(dcDNSName: dcFQDN)
        guard httpsPort != 443 else { return base }
        return base.replacingOccurrences(of: "https://\(dcFQDN)/", with: "https://\(dcFQDN):\(httpsPort)/")
    }
    /// ClearPass's authentication filter for an AD user.
    public static let clearPassFilter = "(&(sAMAccountName=%{Authentication:Username})(objectClass=user))"
    /// iMaster user sync: people only (computers are also class user).
    public static let iMasterUserFilter = "(&(objectCategory=person)(objectClass=user))"
}

/// One copyable value. `value == nil` shows `hint` instead (a secret such as the Administrator
/// password, or something only the device knows) and has no Copy button.
public struct GuideField: Equatable, Sendable {
    public var label: String
    public var value: String?
    public var hint: String?
    public var note: String?
    public var isSecret: Bool

    public init(_ label: String, _ value: String?, hint: String? = nil, note: String? = nil, secret: Bool = false) {
        self.label = label
        self.value = value
        self.hint = hint
        self.note = note
        isSecret = secret
    }

    /// The Administrator password: never shown.
    public static func adminPassword(_ label: String = "Password", note: String? = nil) -> GuideField {
        GuideField(label, nil, hint: "the Administrator password you chose", note: note, secret: true)
    }

    /// What "Copy all values" prints for this field.
    public var plainValue: String { value ?? "<\(hint ?? "")>" }
}

/// Buttons a step offers (the page performs them).
public enum GuideAction: String, Equatable, Sendable {
    case saveCAPEM, saveCACER, saveMobileConfig
    case publishCA
    case openSignCSR, openEnrollment, openTrustedRoots, openUsers, openDirectorySettings, openRadiusClients

    public var title: String {
        switch self {
        case .saveCAPEM: "Save CA (.pem)…"
        case .saveCACER: "Save CA (.cer)…"
        case .saveMobileConfig: "Save Profile (.mobileconfig)…"
        case .publishCA: "Publish CA"
        case .openSignCSR: "Certificates ▸ Sign a request"
        case .openEnrollment: "Certificates ▸ Enrollment"
        case .openTrustedRoots: "Certificates ▸ Trusted roots"
        case .openUsers: "Open Directory"
        case .openDirectorySettings: "Settings ▸ System"
        case .openRadiusClients: "RADIUS ▸ Clients"
        }
    }
}

public enum GuideItem: Equatable, Sendable {
    case text(String)
    case field(GuideField)
    /// A command to type on the device, with what it should answer.
    case command(String, expect: String?)
    /// Several lines of configuration (resolv.conf, a switch's CLI), copied as one.
    case snippet(title: String, code: String)
    case note(String)
    case warning(String)
    case actions([GuideAction])
}

public struct GuideStep: Identifiable, Equatable, Sendable {
    public var number: Int
    public var title: String
    /// Where on the device (`Administration ▸ Server Manager ▸ …`).
    public var location: String?
    public var items: [GuideItem]
    /// A step that only arrives later: shown dimmed.
    public var isLater = false

    public var id: Int { number }

    public var fields: [GuideField] {
        items.compactMap { if case .field(let f) = $0 { f } else { nil } }
    }

    public var commands: [String] {
        items.compactMap { if case .command(let c, _) = $0 { c } else { nil } }
    }

    public var actions: [GuideAction] {
        items.flatMap { item -> [GuideAction] in
            if case .actions(let a) = item { return a }
            return []
        }
    }
}

/// The steps per device, numbered in the order the device asks.
public enum DeviceGuide {
    public static func steps(for kind: DeviceKind, _ v: ConnectValues) -> [GuideStep] {
        let raw: [GuideStep]
        switch kind {
        case .windows: raw = windows(v)
        case .clearpass: raw = clearPass(v)
        case .imaster: raw = iMaster(v)
        case .linux: raw = linux(v)
        case .apple: raw = apple(v)
        case .switchAP: raw = switchAP(v)
        case .other: raw = other(v)
        }
        return raw.enumerated().map { i, s in
            var s = s
            s.number = i + 1
            return s
        }
    }

    /// "Copy all values": the guide as plain text (secrets as `<the Administrator password you chose>`).
    public static func plainText(for kind: DeviceKind, _ v: ConnectValues) -> String {
        var out = "LabDC · \(v.dnsDomain) · \(kind.title)\n"
        for step in steps(for: kind, v) {
            out += "\n\(step.number). \(step.title)" + (step.isLater ? " (later)" : "") + "\n"
            if let location = step.location { out += "   \(location)\n" }
            for item in step.items {
                switch item {
                case .field(let f):
                    out += "   \(f.label): \(f.plainValue)\n"
                case .command(let c, _):
                    out += "   $ \(c)\n"
                case .snippet(let title, let code):
                    out += "   \(title):\n" + code.split(separator: "\n", omittingEmptySubsequences: false)
                        .map { "      \($0)" }.joined(separator: "\n") + "\n"
                case .text, .note, .warning, .actions:
                    break
                }
            }
        }
        return out
    }

    private static func step(_ title: String, _ location: String? = nil, later: Bool = false, _ items: [GuideItem]) -> GuideStep {
        GuideStep(number: 0, title: title, location: location, items: items, isLater: later)
    }

    private static func wifiStep(_ v: ConnectValues) -> GuideStep {
        step("Wi-Fi with 802.1X", nil, [
            .text("Keep \"Verify the server's identity by validating the certificate\" on."),
            .text("The RADIUS server's certificate must be issued by this CA, or its own CA must be a trusted root so joined PCs trust it."),
            .actions([.openSignCSR, .openTrustedRoots]),
        ])
    }

    // MARK: Windows

    static func windows(_ v: ConnectValues) -> [GuideStep] {
        [
            step("Point the PC's DNS at LabDC", "Settings ▸ Network & internet ▸ (adapter) ▸ DNS server assignment ▸ Edit ▸ Manual ▸ IPv4", [
                .field(GuideField("Preferred DNS", v.address)),
                .command("nslookup -type=SRV _ldap._tcp.dc._msdcs.\(v.dnsDomain)", expect: "answers \(v.dcFQDN), port \(v.ldapPort)"),
            ]),
            step("Join the domain", "Settings ▸ System ▸ About ▸ Domain or workgroup (sysdm.cpl) ▸ Change… ▸ Member of: Domain", [
                .field(GuideField("Domain", v.dnsDomain)),
                .field(GuideField("User name", v.adminAccount, note: "when Windows asks for an account with permission to join")),
                .field(.adminPassword()),
                .command("Add-Computer -DomainName \(v.dnsDomain) -Credential \(v.netbios)\\\(v.adminAccount) -Restart",
                         expect: "the same from PowerShell (as administrator)"),
                .note("\"Welcome to the \(v.dnsDomain) domain\" means it worked."),
            ]),
            step("Restart and sign in", nil, [
                .text("Restart when asked. On the sign-in screen choose Other user and sign in as \(v.netbios)\\<user> with a person from Directory."),
                .field(GuideField("Sign in as", "\(v.netbios)\\alice", note: "example; any person")),
                .actions([.openUsers]),
            ]),
            step("Apply the domain policy", "Command Prompt (Run as administrator)", [
                .command("gpupdate /force", expect: "Computer Policy update has completed successfully."),
                .command("gpresult /r /scope computer", expect: "Default Domain Policy under Applied Group Policy Objects"),
            ]),
            step("Check", "Command Prompt (Run as administrator)", [
                .command("nltest /sc_verify:\(v.dnsDomain)", expect: "Trusted DC Connection Status Status = 0 0x0 NERR_Success"),
                .command("certutil -store -grouppolicy Root", expect: "lists the lab CA once it is published"),
                .command("certutil -pulse", expect: "asks for the computer certificate now when auto-enrollment is on; certlm.msc ▸ Personal shows it"),
                .field(GuideField("Enrollment policy server", v.cepURL, note: "the Default Domain Policy hands this to the PC when auto-enrollment is on")),
                .actions([.publishCA, .openEnrollment]),
            ]),
            wifiStep(v),
        ]
    }

    // MARK: ClearPass

    static func clearPass(_ v: ConnectValues) -> [GuideStep] {
        var ldap: [GuideItem] = [
            .field(GuideField("Hostname", v.address)),
            .field(GuideField("Connection Security", "None", note: "or StartTLS on the same port, or LDAP over SSL on port \(v.ldapsPort), after adding the CA to the Trust List")),
            .field(GuideField("Port", String(v.ldapPort))),
            .field(GuideField("Bind DN", v.lookupAccountDN, note: "the Lookup account")),
            .field(.adminPassword("Bind Password")),
            .field(GuideField("NetBIOS Domain Name", v.netbios)),
            .field(GuideField("Base DN", v.baseDN, note: "Search from")),
            .field(GuideField("Search Scope", "Subtree Search")),
            .field(GuideField("Filter", ConnectValues.clearPassFilter, note: "Attributes tab ▸ Authentication filter")),
        ]
        if !v.allowPlainLDAP {
            ldap.append(.warning("Allow plain LDAP is off, so a Bind DN on port \(v.ldapPort) is refused. Use LDAP over SSL (port \(v.ldapsPort)) or turn it on."))
            ldap.append(.actions([.openDirectorySettings]))
        }
        return [
            step("DNS and time", "Administration ▸ Server Manager ▸ Server Configuration ▸ (server) ▸ System", [
                .field(GuideField("Primary DNS", v.address)),
                .field(GuideField("NTP server", v.address, note: "Set Date & Time ▸ Synchronize time with NTP server; Kerberos refuses clocks more than 5 minutes apart")),
            ]),
            step("Join the AD domain", "Administration ▸ Server Manager ▸ Server Configuration ▸ (server) ▸ Join AD Domain", [
                .field(GuideField("Domain Controller", v.dcFQDN, note: "must resolve through the DNS from step 1")),
                .field(GuideField("NetBIOS Name", v.netbios, note: "ClearPass fills it in")),
                .field(GuideField("In case of controller name conflict", "Use specified domain controller")),
                .field(GuideField("Username", v.adminAccount)),
                .field(.adminPassword()),
                .command("ad netjoin \(v.dcFQDN) \(v.netbios)", expect: "the same from the ClearPass CLI (appadmin); it asks for the account and its password"),
                .note("ClearPass joins as its own computer account (for example CLEARPASS-ENTRY$); it shows under Directory ▸ Computers."),
            ]),
            step("LDAP source", "Configuration ▸ Authentication ▸ Sources ▸ Add ▸ Type: Active Directory", ldap),
            step("RADIUS server certificate", "Administration ▸ Certificates ▸ Certificate Store ▸ Server Certificate ▸ Create Certificate Signing Request (usage RADIUS/EAP Server)", [
                .text("1. Create the CSR in ClearPass and download it."),
                .text("2. Sign it here with the template WebServer."),
                .text("3. Back in ClearPass: Import Certificate with the same usage."),
                .actions([.openSignCSR]),
                .text("Or keep ClearPass's own certificate and add its CA to the PCs as a trusted root."),
                .text("Trust List: Administration ▸ Certificates ▸ Trust List ▸ Add this CA with usage EAP and AD/LDAP Servers."),
                .actions([.saveCAPEM, .openTrustedRoots]),
            ]),
            step("Test from the ClearPass CLI", "SSH as appadmin", [
                .command("ad testjoin \(v.netbios)", expect: "Join is OK"),
                .command("ad auth -u alice -n \(v.netbios)", expect: "type the password at the prompt → NT_STATUS_OK"),
                .warning("Never pass the password with -p: ClearPass then sends it as the domain name and the DC answers \"no such user\"."),
            ]),
            step("What Access Tracker shows", "Monitoring ▸ Live Monitoring ▸ Access Tracker", [
                .text("Login Status ACCEPT, Authentication Source AD:\(v.address) (or the source's name), Authentication Method EAP-PEAP,EAP-MSCHAPv2, and an empty Alerts tab."),
                .text("Here the same sign-in shows as \"NTLM (NAC)\" from the ClearPass in the checklist and in Activity."),
            ]),
        ]
    }

    // MARK: iMaster NCE-Campus

    static func iMaster(_ v: ConnectValues) -> [GuideStep] {
        var sync: [GuideItem] = [
            .field(GuideField("Server IP", v.address)),
            .field(GuideField("Port", String(v.ldapPort), note: "TLS off (iMaster's default); \(v.ldapsPort) with TLS on after importing the CA")),
            .field(GuideField("Administrator DN", v.lookupAccountDN, note: "iMaster asks for the full DN here")),
            .field(.adminPassword()),
            .field(GuideField("Base DN", v.baseDN)),
            .field(GuideField("User filter", ConnectValues.iMasterUserFilter, note: "people only; plain (objectClass=user) also brings in computer accounts")),
            .text("Sync mode: by OU (root OU = Base DN or a folder), by group with folders, or by nested groups — all three work."),
        ]
        if !v.allowPlainLDAP {
            sync.append(.warning("Allow plain LDAP is off, so the Administrator DN on port \(v.ldapPort) with TLS off is refused. Turn TLS on (port \(v.ldapsPort)) or turn plain LDAP on."))
            sync.append(.actions([.openDirectorySettings, .saveCAPEM]))
        } else {
            sync.append(.actions([.saveCAPEM]))
        }
        return [
            step("DNS and time on every controller node", "each node's /etc/resolv.conf and NTP settings", [
                .snippet(title: "/etc/resolv.conf", code: "nameserver \(v.address)\nsearch \(v.dnsDomain)"),
                .command("dig _ldap._tcp.dc._msdcs.\(v.dnsDomain) SRV", expect: "\(v.dcFQDN), port \(v.ldapPort)"),
                .field(GuideField("NTP server", v.address, note: "Kerberos refuses clocks more than 5 minutes apart; the join fails otherwise")),
            ]),
            step("Ports the nodes must reach", nil, [
                .field(GuideField("DNS", "53 udp/tcp")),
                .field(GuideField("Kerberos", "\(v.kerberosPort) udp/tcp")),
                .field(GuideField("LDAP + CLDAP", "\(v.ldapPort) tcp/udp")),
                .field(GuideField("LDAPS", "\(v.ldapsPort) tcp", note: "only for sync with TLS on")),
                .field(GuideField("SMB", "445 tcp")),
                .field(GuideField("RPC", "135 tcp + the dynamic RPC port")),
                .field(GuideField("NTP", "123 udp")),
                .note("NetBIOS (137 udp, 139 tcp) is off by default and not needed: iMaster finds the DC through DNS and CLDAP."),
            ]),
            step("Add to Domain", "AD Domain Configuration ▸ Add to Domain", [
                .field(GuideField("AD domain name", v.dnsDomain)),
                .field(GuideField("NetBIOS domain name", v.netbios)),
                .field(GuideField("Domain account", v.adminAccount)),
                .field(.adminPassword()),
                .text("Run Domain Name Resolution Verification first; it must pass before Add to Domain."),
                .note("Every controller node joins as its own computer (for example OMP$, SERVICE1$, DATABACKUP$)."),
                .warning("The join account must be in Domain Admins (Administrator is), or be allowed to add computers (ms-DS-MachineAccountQuota)."),
                .warning("Don't change this account's password afterwards: MS-CHAPv2 pass-through stops until you Add to Domain again."),
                .field(GuideField("Detection account (optional)", v.adminAccount, note: "a user whose sign-in iMaster tries through the join")),
            ]),
            step("User synchronization (LDAP)", "AD/LDAP server settings", sync),
            step("Machine authentication (extended user)", "Extended user settings", [
                .field(GuideField("Object", "computer")),
                .field(GuideField("Extended username", "cn")),
                .field(GuideField("Extended account", "cn")),
                .field(GuideField("Host name attribute", "dNSHostName")),
                .note("Windows PCs that joined appear under ROOT\\computers after the next sync."),
            ]),
            step("RADIUS / EAP server certificate", "System ▸ Certificate Management (802.1X / Portal server certificate)", [
                .text("PEAP clients must trust the certificate iMaster presents. Create a CSR on iMaster, sign it here with the template WebServer, then import it with this CA as the chain."),
                .text("The Certificate Converter's iMaster preset writes srv.crt, srv.key and srv-chain.crt in the form iMaster imports."),
                .note("MS-CHAPv2 pass-through needs Settings ▸ System ▸ NAC password checks to allow MS-CHAPv2 (the default); \"Only NTLMv2\" stops PEAP sign-ins."),
                .actions([.openSignCSR, .saveCAPEM]),
            ]),
            step("Check", nil, [
                .text("Trust status Normal on every node, and a test with the detection account passes."),
                .text("Here each node's sign-ins show as \"NTLM (NAC)\" in the checklist and in Activity."),
            ]),
        ]
    }

    // MARK: Ubuntu / Linux

    static func linux(_ v: ConnectValues) -> [GuideStep] {
        [
            step("DNS", "/etc/resolv.conf (or resolvectl with systemd-resolved)", [
                .snippet(title: "/etc/resolv.conf", code: "nameserver \(v.address)\nsearch \(v.dnsDomain)"),
                .command("sudo resolvectl dns eth0 \(v.address) && sudo resolvectl domain eth0 \(v.dnsDomain)", expect: "replace eth0 with the interface"),
                .command("host -t SRV _ldap._tcp.\(v.dnsDomain)", expect: "\(v.dcFQDN), port \(v.ldapPort)"),
            ]),
            step("Install the tools", nil, [
                .command("sudo apt install realmd sssd sssd-tools adcli krb5-user samba-common-bin packagekit", expect: nil),
            ]),
            step("Discover and join", nil, [
                .command("realm discover \(v.dnsDomain)", expect: "realm-name: \(v.realm), server-software: active-directory"),
                .command("sudo realm join \(v.dnsDomain) -U \(v.adminAccount)", expect: "asks for the Administrator password you chose; no output means joined"),
            ]),
            step("Check", nil, [
                .command("id alice@\(v.dnsDomain)", expect: "uid=… groups=…domain users@\(v.dnsDomain)"),
                .command("kinit alice@\(v.realm) && klist", expect: "krbtgt/\(v.realm)@\(v.realm)"),
                .command("sudo klist -k", expect: "the computer's keys (host/…, NAME$)"),
            ]),
            step("SSSD notes", "/etc/sssd/sssd.conf", [
                .text("Users sign in as alice@\(v.dnsDomain). For plain alice set use_fully_qualified_names = False and run sudo systemctl restart sssd."),
                .command("sudo pam-auth-update --enable mkhomedir", expect: "home folders are created at the first sign-in"),
                .text("Kerberos needs the clocks within 5 minutes; LabDC answers NTP at \(v.address)."),
                .field(GuideField("Kerberos realm", v.realm)),
                .field(GuideField("KDC", v.dcFQDN)),
            ]),
        ]
    }

    // MARK: Apple

    static func apple(_ v: ConnectValues) -> [GuideStep] {
        [
            step("Trust the CA (iPhone, iPad, Mac)", nil, [
                .text("The profile holds this CA and the directory as an LDAP account (Contacts). It asks for the password on the device."),
                .actions([.saveMobileConfig]),
                .text("iPhone / iPad: AirDrop or mail it ▸ Settings ▸ General ▸ VPN & Device Management ▸ Install, then Settings ▸ General ▸ About ▸ Certificate Trust Settings ▸ turn on full trust for the CA."),
                .text("Mac: open it ▸ System Settings ▸ General ▸ Device Management ▸ Install."),
                .actions([.saveCAPEM, .saveCACER]),
            ]),
            step("Mac: DNS", "System Settings ▸ Network ▸ (service) ▸ Details ▸ DNS", [
                .field(GuideField("DNS Server", v.address)),
                .field(GuideField("Search Domain", v.dnsDomain)),
            ]),
            step("Mac: bind to Active Directory", "System Settings ▸ Users & Groups ▸ Network Account Server ▸ Edit… ▸ Open Directory Utility ▸ Active Directory", [
                .field(GuideField("Active Directory Domain", v.dnsDomain)),
                .field(GuideField("Computer ID", nil, hint: "this Mac's name, 15 characters or fewer")),
                .field(GuideField("Username", v.adminAccount, note: "asked for when you click Bind")),
                .field(.adminPassword()),
                .command("sudo dsconfigad -add \(v.dnsDomain) -computer \"$(scutil --get LocalHostName)\" -username \(v.adminAccount)",
                         expect: "the same in Terminal; it asks for the password"),
                .command("dsconfigad -show", expect: "Active Directory Domain = \(v.dnsDomain)"),
                .command("id alice", expect: "the domain user's uid and groups"),
                .note("Kerberos works after binding: sign in as alice, or kinit alice@\(v.realm). A Mac whose DNS points here can also kinit without binding."),
            ]),
            step("LDAP (Directory Utility ▸ LDAPv3, Contacts)", nil, [
                .field(GuideField("Server", v.ldapsURL, note: "SSL on; the CA from step 1 must be trusted")),
                .field(GuideField("Search base", v.baseDN)),
                .field(GuideField("Bind DN", v.lookupAccountDN, note: "the Lookup account")),
                .field(.adminPassword()),
            ]),
            wifiStep(v),
        ]
    }

    // MARK: Switch / AP

    static func switchAP(_ v: ConnectValues) -> [GuideStep] {
        let sha256 = v.caSHA256 ?? "<SHA-256 of the CA>"
        let sha256Plain = sha256.replacingOccurrences(of: ":", with: "")
        return [
            step("Trust the CA", nil, [
                .field(GuideField("CA certificate", v.caDownloadURL)),
                .field(GuideField("SHA-256 fingerprint", v.caSHA256, hint: "appears once the CA is loaded")),
                .field(GuideField("SHA-1 fingerprint", v.caSHA1, hint: "appears once the CA is loaded")),
                .actions([.saveCAPEM, .saveCACER]),
            ]),
            step("A challenge for the device", nil, [
                .text("One-time and bound to the switch's name, or reusable for ClearPass Onboard. It is shown only once."),
                .actions([.openEnrollment]),
            ]),
            step("Enrollment URLs", nil, [
                .field(GuideField("SCEP", v.scepURL)),
                .field(GuideField("SCEP (NDES path)", v.scepNDESURL, note: "Huawei VRP and ClearPass Onboard")),
                .field(GuideField("EST", v.estURL, note: "user = device name, password = challenge")),
                .field(GuideField("EST label", "Device", note: "the certificate template")),
            ]),
            step("Device commands", nil, [
                .note("Written from the vendors' CLI guides and not yet run on real hardware; command names shift between firmware trains."),
                .snippet(title: "Aruba AOS-CX 10.x — EST", code: """
                    crypto pki ta-profile LABDC-CA
                        ta-certificate import terminal
                    crypto pki est-profile LABDC
                        url \(v.estURL)
                        arbitrary-label Device
                        username sw1 password plaintext <challenge>
                        reenrollment-lead-time 30
                    crypto pki certificate sw1-cert
                        key-type rsa key-size 2048
                        subject common-name sw1
                        enroll est-profile LABDC
                    """),
                .snippet(title: "Aruba AOS-S 16.x — SCEP", code: """
                    crypto pki ta-profile LABDC-CA
                    copy tftp ta-certificate LABDC-CA <tftp-ip> \(v.caName).crt
                    crypto pki identity-profile sw1 subject common-name sw1
                    crypto pki enroll-certificate profile-name sw1-cert usage web url \(v.scepURL) password <challenge> key-size 2048
                    """),
                .snippet(title: "Huawei VRP — SCEP", code: """
                    pki entity sw1
                     common-name sw1
                     fqdn sw1.\(v.dnsDomain)
                    pki rsa local-key-pair create sw1-key modulus 2048
                    pki realm labdc
                     ca id LabDC
                     enrollment-url \(v.scepNDESURL) ra
                     entity sw1
                     fingerprint sha256 \(sha256Plain)
                     rsa local-key-pair sw1-key
                     enrollment-request signature message-digest-method sha-256
                     password cipher <challenge>
                     auto-enroll 60 regenerate
                    pki get-certificate ca realm labdc
                    pki enroll-certificate realm labdc password <challenge>
                    """),
                .snippet(title: "ClearPass Onboard — SCEP", code: """
                    Onboard ▸ Certificate Authorities ▸ Add
                    Mode: Use a SCEP server
                    SCEP Server URL: \(v.scepNDESURL)
                    Challenge type: Static (a reusable challenge)
                    Key type: RSA 2048, signature SHA-256
                    """),
                .text("Replace sw1 with the device's name and <challenge> with the challenge."),
            ]),
            // LabDC has its own RADIUS server (phase 4 shipped); the old "later" step is gone (owner, 2 Oct 2026).
            step("Point 802.1X at this DC", "the device's AAA / RADIUS server settings", [
                .text("Add the switch or AP as a RADIUS client with its address and a shared secret, then point the device's RADIUS server at this DC."),
                .field(GuideField("RADIUS server", v.address)),
                .field(GuideField("Authentication port", String(v.radiusPort))),
                .field(GuideField("Accounting port", String(v.radiusAccountingPort))),
                .field(GuideField("Shared secret", nil, hint: "the secret you gave the client")),
                .actions([.openRadiusClients]),
            ]),
        ]
    }

    // MARK: Other

    static func other(_ v: ConnectValues) -> [GuideStep] {
        [
            step("Directory (LDAP)", nil, [
                .field(GuideField("Domain controller", v.address, note: v.dcFQDN)),
                .field(GuideField("LDAPS", v.ldapsURL, note: "encrypted; trust the CA below")),
                .field(GuideField("LDAP", v.ldapURL, note: v.allowPlainLDAP ? "plain; Allow plain LDAP is on" : "plain binds are refused (Allow plain LDAP is off)")),
                .field(GuideField("Base DN", v.baseDN, note: "Search from")),
                .field(GuideField("Lookup account", v.lookupAccountDN)),
                .field(.adminPassword()),
                .field(GuideField("User filter", "(&(objectClass=user)(sAMAccountName=%s))", note: "use the device's placeholder for %s")),
            ]),
            step("Kerberos and DNS", nil, [
                .field(GuideField("Kerberos realm", v.realm)),
                .field(GuideField("KDC", v.kerberosPort == 88 ? v.dcFQDN : "\(v.dcFQDN):\(v.kerberosPort)")),
                .field(GuideField("DNS domain", v.dnsDomain)),
                .field(GuideField("NetBIOS domain", v.netbios)),
                .field(GuideField("DNS server", v.address)),
            ]),
            step("CA", nil, [
                .field(GuideField("CA certificate", v.caDownloadURL)),
                .field(GuideField("SHA-256 fingerprint", v.caSHA256, hint: "appears once the CA is loaded")),
                .actions([.saveCAPEM, .saveCACER]),
            ]),
            step("Certificate enrollment", nil, [
                .field(GuideField("SCEP", v.scepURL)),
                .field(GuideField("EST", v.estURL)),
                .field(GuideField("Windows enrollment policy (CEP)", v.cepURL)),
                .actions([.openEnrollment]),
            ]),
        ]
    }
}
