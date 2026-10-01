import Foundation
import Store

/// IEEE 802.11 / 802.3 Group Policy profiles ([MS-GPWL]): the XML-based wireless/wired policy
/// is stored as LDAP objects of class `ms-net-ieee-80211-GroupPolicy` / `ms-net-ieee-8023-GroupPolicy`
/// under `CN=IEEE80211|IEEE8023, CN=Windows, CN=Microsoft, CN=Machine, <GPO DN>`; the Windows
/// WLAN/LAN client-side extensions search that subtree at policy refresh and apply the profile.
///
/// 30 Sep 2026: EAP-TLS or PEAP-MSCHAPv2, WPA2 / WPA3-Enterprise / WPA3-Enterprise 192-bit, the
/// server certificate checked against the lab root and the RADIUS server's DNS name.
public struct Dot1XPolicy: Sendable, Equatable {
    public enum AuthMode: String, Sendable, CaseIterable {
        case machineOrUser, machine, user
        public var title: String {
            switch self {
            case .machineOrUser: "Computer or user"
            case .machine: "Computer only"
            case .user: "User"
            }
        }
    }

    /// The EAP method Windows uses.
    public enum Method: String, Sendable, CaseIterable {
        /// EAP-TLS (type 13) with the auto-enrolled User/Computer certificate.
        case tls
        /// PEAP (type 25) with inner EAP-MSCHAPv2 (type 26): the Windows sign-in password.
        case peapMSCHAPv2
        public var title: String { self == .tls ? "EAP-TLS (certificate)" : "PEAP-MSCHAPv2 (password)" }
        public var eapType: Int { self == .tls ? 13 : 25 }
    }

    /// Wireless security (`authentication` / `encryption` in the WLAN profile). Wired ignores it.
    public enum Security: String, Sendable, CaseIterable {
        case wpa2, wpa3, wpa3Suite192
        public var title: String {
            switch self {
            case .wpa2: "WPA2-Enterprise"
            case .wpa3: "WPA3-Enterprise"
            case .wpa3Suite192: "WPA3-Enterprise 192-bit"
            }
        }
        var authentication: String {
            switch self {
            case .wpa2: "WPA2"
            case .wpa3: "WPA3ENT"
            case .wpa3Suite192: "WPA3ENT192"
            }
        }
        var encryption: String { self == .wpa3Suite192 ? "GCMP256" : "AES" }
    }

    /// The name the app publishes under. Domains set up while the app was SheepAuth keep
    /// their `SheepAuth 802.1X` object (its GUID is the profile's identity on joined PCs), see
    /// `GroupPolicyEditor.keepingFormerName`.
    public static let defaultName = "LabDC 802.1X"
    public static let formerDefaultNames = ["SheepAuth 802.1X"]

    public var name: String
    public var ssid: String
    public var authMode: AuthMode
    /// SHA-1 thumbprint (hex, any spacing) of the trusted root CA — the lab root that issued the
    /// RADIUS server certificate.
    public var caThumbprint: String
    public var method: Method
    public var security: Security
    /// DNS names the RADIUS server certificate must carry (the DC's FQDN).
    public var serverNames: [String]
    /// EAP-TLS: only client certificates issued by this CA (SHA-1 thumbprint) are offered —
    /// the P-256 lab certificate for WPA2/WPA3, the P-384 one for 192-bit, when a machine holds
    /// both (EapTlsConnectionPropertiesV3 `FilteringInfo/CAHashList`). nil: no filter.
    public var clientIssuerThumbprint: String?

    public init(name: String, ssid: String, authMode: AuthMode = .machineOrUser, caThumbprint: String,
                method: Method = .tls, security: Security = .wpa2, serverNames: [String] = [],
                clientIssuerThumbprint: String? = nil) {
        self.name = name; self.ssid = ssid; self.authMode = authMode; self.caThumbprint = caThumbprint
        self.method = method; self.security = security; self.serverNames = serverNames
        self.clientIssuerThumbprint = clientIssuerThumbprint
    }

    public enum Invalid: Error, CustomStringConvertible, Equatable {
        case suiteB192NeedsTLS, noSSID
        public var description: String {
            switch self {
            case .suiteB192NeedsTLS: "WPA3-Enterprise 192-bit works with EAP-TLS only"
            case .noSSID: "a wireless profile needs an SSID"
            }
        }
    }

    public func validate() throws {
        if security == .wpa3Suite192, method != .tls { throw Invalid.suiteB192NeedsTLS }
        if ssid.trimmingCharacters(in: .whitespaces).isEmpty { throw Invalid.noSSID }
    }

    // MARK: XML ([MS-GPWL] §2.2.1.2; the WLAN/LAN profile schemas = `netsh … export` format)

    /// `<WLANPolicy>`: the string stored in `ms-net-ieee-80211-GP-PolicyData`.
    public var wirelessXML: String {
        """
        <WLANPolicy xmlns="http://www.microsoft.com/networking/WLAN/policy/v1">\
        <name>\(Self.escape(name))</name>\
        <description>\(Self.escape(description))</description>\
        <globalFlags><enableAutoConfig>true</enableAutoConfig><showDeniedNetwork>false</showDeniedNetwork>\
        <allowEveryoneToCreateAllUserProfiles>true</allowEveryoneToCreateAllUserProfiles></globalFlags>\
        <profileList>\(wlanProfile)</profileList>\
        </WLANPolicy>
        """
    }

    /// The WLANProfile: the chosen security, 802.1X, the chosen EAP method.
    public var wlanProfile: String {
        let hexSSID = ssid.utf8.map { String(format: "%02X", $0) }.joined()
        return """
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\
        <name>\(Self.escape(ssid))</name>\
        <SSIDConfig><SSID><hex>\(hexSSID)</hex><name>\(Self.escape(ssid))</name></SSID>\
        <nonBroadcast>false</nonBroadcast></SSIDConfig>\
        <connectionType>ESS</connectionType><connectionMode>auto</connectionMode><autoSwitch>false</autoSwitch>\
        <MSM><security><authEncryption>\
        <authentication>\(security.authentication)</authentication><encryption>\(security.encryption)</encryption>\
        <useOneX>true</useOneX></authEncryption>\
        \(oneX)\
        </security></MSM>\
        </WLANProfile>
        """
    }

    /// `<LANPolicy>`: the string stored in `ms-net-ieee-8023-GP-PolicyData` (wired 802.1X).
    public var wiredXML: String {
        """
        <LANPolicy xmlns="http://www.microsoft.com/networking/LAN/policy/v1">\
        <name>\(Self.escape(name))</name>\
        <description>\(Self.escape(description))</description>\
        <globalFlags><enableAutoConfig>true</enableAutoConfig></globalFlags>\
        <profileList>\
        <LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1">\
        <MSM><security><OneXEnforced>false</OneXEnforced><OneXEnabled>true</OneXEnabled>\
        \(oneX)\
        </security></MSM>\
        </LANProfile></profileList>\
        </LANPolicy>
        """
    }

    var description: String { "802.1X \(method.title)" }

    /// `<OneX>`: the auth mode and the EapHostConfig of the method.
    var oneX: String {
        """
        <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">\
        <authMode>\(authMode.rawValue)</authMode>\
        <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">\
        <EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">\(method.eapType)</Type>\
        <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>\
        <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>\
        <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>\
        \(method == .tls ? tlsConfig : peapConfig)\
        </EapHostConfig></EAPConfig>\
        </OneX>
        """
    }

    /// `<ServerValidation>` children: no prompt, the RADIUS server's names, the lab root.
    var serverValidation: String {
        "<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>"
            + "<ServerNames>\(Self.escape(serverNames.joined(separator: ";")))</ServerNames>"
            + "<TrustedRootCA>\(Self.spacedThumbprint(caThumbprint))</TrustedRootCA>"
    }

    /// EAP-TLS (MS-GPWL §4 / the EapTlsConnectionPropertiesV1 schema).
    var tlsConfig: String {
        """
        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">\
        <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type>\
        <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">\
        <CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>\
        <ServerValidation>\(serverValidation)</ServerValidation>\
        <DifferentUsername>false</DifferentUsername>\
        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>\
        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">\(serverNames.isEmpty ? "false" : "true")</AcceptServerName>\
        \(certificateFilter)\
        </EapType></Eap></Config>
        """
    }

    /// `TLSExtensions/FilteringInfo/CAHashList`: pick the client certificate by its issuer.
    var certificateFilter: String {
        guard let issuer = clientIssuerThumbprint, !issuer.isEmpty else { return "" }
        return "<TLSExtensions xmlns=\"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2\">"
            + "<FilteringInfo xmlns=\"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3\">"
            + "<CAHashList Enabled=\"true\"><IssuerHash>\(Self.spacedThumbprint(issuer))</IssuerHash></CAHashList>"
            + "</FilteringInfo></TLSExtensions>"
    }

    /// PEAP with inner EAP-MSCHAPv2 using the Windows sign-in (MS-GPWL §4.1 example). The server
    /// answers the Crypto-Binding TLV, so Windows may require it (binds the tunnel to the inner
    /// authentication).
    var peapConfig: String {
        """
        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">\
        <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type>\
        <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">\
        <ServerValidation>\(serverValidation)</ServerValidation>\
        <FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional>\
        <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type>\
        <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">\
        <UseWinLogonCredentials>true</UseWinLogonCredentials></EapType></Eap>\
        <EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>true</RequireCryptoBinding>\
        <PeapExtensions>\
        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>\
        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">\(serverNames.isEmpty ? "false" : "true")</AcceptServerName>\
        </PeapExtensions>\
        </EapType></Eap></Config>
        """
    }

    /// `8a 14 … 3c ` — how `netsh` exports a TrustedRootCA thumbprint.
    static func spacedThumbprint(_ hex: String) -> String {
        let clean = hex.lowercased().filter { $0.isHexDigit }
        var out = ""
        var i = clean.startIndex
        while i < clean.endIndex {
            let j = clean.index(i, offsetBy: 2, limitedBy: clean.endIndex) ?? clean.endIndex
            out += clean[i..<j] + " "
            i = j
        }
        return out
    }

    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
