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
    public enum AuthMode: String, Sendable, CaseIterable, Codable {
        case machineOrUser, machine, user
        public var title: String {
            switch self {
            case .machineOrUser: "Computer or user"
            case .machine: "Computer"
            case .user: "User"
            }
        }
    }

    /// The EAP method Windows uses.
    public enum Method: String, Sendable, CaseIterable, Codable {
        /// EAP-TLS (type 13) with the auto-enrolled User/Computer certificate.
        case tls
        /// PEAP (type 25) with inner EAP-MSCHAPv2 (type 26): the Windows sign-in password.
        case peapMSCHAPv2
        public var title: String { self == .tls ? "EAP-TLS (certificate)" : "PEAP-MSCHAPv2 (password)" }
        /// "EAP-TLS" / "PEAP-MSCHAPv2": list rows.
        public var shortTitle: String { self == .tls ? "EAP-TLS" : "PEAP-MSCHAPv2" }
        public var eapType: Int { self == .tls ? 13 : 25 }
    }

    /// Wireless security (`authentication` / `encryption` in the WLAN profile). Wired ignores it.
    public enum Security: String, Sendable, CaseIterable, Codable {
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

    /// The policy's name (`<name>` of the WLAN/LAN policy; `set80211Policy` also uses it as the
    /// object's CN).
    public var name: String
    /// The first (or only) SSID.
    public var ssid: String
    public var authMode: AuthMode
    /// SHA-1 thumbprint (hex, any spacing) of the trusted root CA — the lab root that issued the
    /// RADIUS server certificate.
    public var caThumbprint: String
    public var method: Method
    public var security: Security
    /// DNS names the RADIUS server certificate must carry (the DC's FQDN).
    public var serverNames: [String]
    /// PEAP: Windows requires the Crypto-Binding TLV. LabDC's RADIUS sends it; another server
    /// (ClearPass) usually does not by default — GPMC's default is off (owner, 1 Oct 2026: a
    /// ClearPass SSID failed with access_denied while the same profile works from Windows AD).
    public var requireCryptoBinding = true
    /// EAP-TLS: only client certificates issued by this CA (SHA-1 thumbprint) are offered —
    /// the P-256 lab certificate for WPA2/WPA3, the P-384 one for 192-bit, when a machine holds
    /// both (EapTlsConnectionPropertiesV3 `FilteringInfo/CAHashList`). nil: no filter.
    public var clientIssuerThumbprint: String?
    /// More roots trusted next to `caThumbprint` (and, with a client-issuer filter, accepted as
    /// issuers too): the old root during a root migration that keeps it trusted for a while.
    public var additionalTrustedRoots: [String] = []

    // GPMC's Wireless Network (IEEE 802.11) Policies ▸ profile properties (1 Oct 2026).

    /// The WLAN profile's `<name>` (what `netsh wlan show profiles` lists); nil = the SSID.
    /// Windows replaces a Group Policy profile by name: renaming one removes the old-named
    /// profile from PCs at the next policy refresh.
    public var profileName: String?
    /// More SSIDs of the same profile (`SSIDConfig` holds up to 25).
    public var additionalSSIDs: [String] = []
    /// "Connect automatically when this network is in range": `connectionMode` auto / manual.
    public var connectAutomatically = true
    /// "Connect even if the network is not broadcasting its name": `nonBroadcast`.
    public var connectHidden = false
    /// "Switch to a more preferred network if available": `autoSwitch` (only with auto connect).
    public var autoSwitch = false
    /// "Enable Single Sign On" (perform immediately before user logon): `singleSignOn/preLogon`.
    public var singleSignOn = false
    /// "Cache user information for subsequent connections": `cacheUserData` (Windows' default
    /// is on, written only when off).
    public var cacheUserData = true
    /// The policy's `<description>`; nil = "802.1X <method>".
    public var policyDescription: String?
    /// "Verify the server's identity by validating the certificate": `PerformServerValidation`.
    /// Off: `ServerValidation` is still written, but Windows does not check the server.
    public var performServerValidation = true
    /// GPMC's "Do not prompt user to authorize new servers or trusted CAs" turned off: Windows
    /// shows the certificate it could not verify and asks (`DisableUserPromptForServerValidation`
    /// false). Off by default: no prompt, the connection just fails (1 Oct 2026: ClearPass
    /// access_denied with no clue why).
    public var promptUserForServerValidation = false

    public init(name: String, ssid: String, authMode: AuthMode = .machineOrUser, caThumbprint: String,
                method: Method = .tls, security: Security = .wpa2, serverNames: [String] = [],
                clientIssuerThumbprint: String? = nil, additionalTrustedRoots: [String] = [],
                connectAutomatically: Bool = true) {
        self.name = name; self.ssid = ssid; self.authMode = authMode; self.caThumbprint = caThumbprint
        self.method = method; self.security = security; self.serverNames = serverNames
        self.clientIssuerThumbprint = clientIssuerThumbprint
        self.additionalTrustedRoots = additionalTrustedRoots
        self.connectAutomatically = connectAutomatically
    }

    /// Every SSID of the profile, the first one first.
    public var ssids: [String] { [ssid] + additionalSSIDs }

    /// An SSID is 1–32 octets (IEEE 802.11 §9.4.2.2); Windows takes the UTF-8 bytes.
    public static let maxSSIDBytes = 32
    /// `SSIDConfig` holds at most 25 SSIDs (WLAN profile schema).
    public static let maxSSIDsPerProfile = 25

    public enum Invalid: Error, CustomStringConvertible, Equatable {
        case suiteB192NeedsTLS, noSSID, ssidTooLong(String, Int), duplicateSSID(String), tooManySSIDs
        case noProfileName, duplicateProfile(String)
        case noServerName, badTrustedRoot(String)
        public var description: String {
            switch self {
            case .suiteB192NeedsTLS: "WPA3-Enterprise 192-bit works with EAP-TLS only"
            case .noSSID: "a wireless profile needs an SSID"
            case let .ssidTooLong(s, n): "an SSID is 1–32 bytes; \(s) is \(n)"
            case .duplicateSSID(let s): "\(s) is listed twice"
            case .tooManySSIDs: "a profile holds at most 25 SSIDs"
            case .noProfileName: "a wireless profile needs a name"
            case .duplicateProfile(let s): "there is already a profile named \(s)"
            case .noServerName: "another RADIUS server needs the name(s) in its certificate"
            case .badTrustedRoot(let s): "\(s) is not a 40-digit hex SHA-1 thumbprint"
            }
        }
    }

    public func validate() throws {
        try Self.validate(ssids: ssids, security: security, method: method)
        if let profileName, profileName.trimmingCharacters(in: .whitespaces).isEmpty { throw Invalid.noProfileName }
    }

    /// The wireless rules: an SSID of 1–32 bytes, 192-bit only with EAP-TLS.
    public static func validate(ssid: String, security: Security, method: Method) throws {
        try validate(ssids: [ssid], security: security, method: method)
    }

    /// 1–25 SSIDs of 1–32 bytes each, none twice; 192-bit only with EAP-TLS.
    public static func validate(ssids: [String], security: Security, method: Method) throws {
        if security == .wpa3Suite192, method != .tls { throw Invalid.suiteB192NeedsTLS }
        if ssids.isEmpty { throw Invalid.noSSID }
        if ssids.count > maxSSIDsPerProfile { throw Invalid.tooManySSIDs }
        var seen = Set<String>()
        for ssid in ssids {
            if ssid.trimmingCharacters(in: .whitespaces).isEmpty { throw Invalid.noSSID }
            if ssid.utf8.count > maxSSIDBytes { throw Invalid.ssidTooLong(ssid, ssid.utf8.count) }
            guard seen.insert(ssid).inserted else { throw Invalid.duplicateSSID(ssid) }
        }
    }

    // MARK: XML ([MS-GPWL] §2.2.1.2; the WLAN/LAN profile schemas = `netsh … export` format)

    /// `<WLANPolicy>`: the string stored in `ms-net-ieee-80211-GP-PolicyData`.
    public var wirelessXML: String { Self.wirelessPolicyXML(name: name, description: description, profiles: [self]) }

    /// One `<WLANPolicy>` carrying a `<WLANProfile>` per profile, in the given order (the
    /// preference order Windows uses).
    public static func wirelessPolicyXML(name: String, description: String, profiles: [Dot1XPolicy]) -> String {
        """
        <WLANPolicy xmlns="http://www.microsoft.com/networking/WLAN/policy/v1">\
        <name>\(escape(name))</name>\
        <description>\(escape(description))</description>\
        <globalFlags><enableAutoConfig>true</enableAutoConfig><showDeniedNetwork>false</showDeniedNetwork>\
        <allowEveryoneToCreateAllUserProfiles>true</allowEveryoneToCreateAllUserProfiles></globalFlags>\
        <profileList>\(profiles.map(\.wlanProfile).joined())</profileList>\
        </WLANPolicy>
        """
    }

    /// The WLANProfile: name, SSIDs, connection settings, the chosen security, 802.1X, the chosen
    /// EAP method.
    public var wlanProfile: String {
        let ssidElements = ssids.map { s in
            "<SSID><hex>\(s.utf8.map { String(format: "%02X", $0) }.joined())</hex><name>\(Self.escape(s))</name></SSID>"
        }.joined()
        return """
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\
        <name>\(Self.escape(profileName ?? ssid))</name>\
        <SSIDConfig>\(ssidElements)\
        <nonBroadcast>\(connectHidden)</nonBroadcast></SSIDConfig>\
        <connectionType>ESS</connectionType><connectionMode>\(connectAutomatically ? "auto" : "manual")</connectionMode>\
        <autoSwitch>\(connectAutomatically && autoSwitch)</autoSwitch>\
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

    var description: String { policyDescription ?? "802.1X \(method.title)" }

    /// `<OneX>`: cacheUserData, the auth mode, single sign-on and the EapHostConfig of the method
    /// (in the order of the OneX schema).
    var oneX: String {
        """
        <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">\
        \(cacheUserData ? "" : "<cacheUserData>false</cacheUserData>")\
        <authMode>\(authMode.rawValue)</authMode>\
        \(singleSignOn ? "<singleSignOn><type>preLogon</type><maxDelay>10</maxDelay></singleSignOn>" : "")\
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

    /// `<ServerValidation>` children: (no) prompt, the RADIUS server's names, the lab root.
    var serverValidation: String {
        "<DisableUserPromptForServerValidation>\(!promptUserForServerValidation)</DisableUserPromptForServerValidation>"
            + "<ServerNames>\(Self.escape(serverNames.joined(separator: ";")))</ServerNames>"
            + ([caThumbprint] + additionalTrustedRoots).map { "<TrustedRootCA>\(Self.spacedThumbprint($0))</TrustedRootCA>" }.joined()
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
        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">\(performServerValidation)</PerformServerValidation>\
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
            + "<CAHashList Enabled=\"true\">"
            + ([issuer] + additionalTrustedRoots).map { "<IssuerHash>\(Self.spacedThumbprint($0))</IssuerHash>" }.joined()
            + "</CAHashList>"
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
        <EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>\(requireCryptoBinding ? "true" : "false")</RequireCryptoBinding>\
        <PeapExtensions>\
        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">\(performServerValidation)</PerformServerValidation>\
        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">\(serverNames.isEmpty ? "false" : "true")</AcceptServerName>\
        </PeapExtensions>\
        </EapType></Eap></Config>
        """
    }

    /// Rewrites the `<TrustedRootCA>` and (when present) `<IssuerHash>` lists of a published
    /// WLAN/LAN policy that list `anchor`: `removing` thumbprints leave, `adding` ones join
    /// (once). Lists without `anchor` (a 192-bit profile pinned to its own root) and lists that
    /// would end up empty stay as they are. Root migration (1 Oct 2026) updates the published
    /// profiles in place with it, so their GUIDs (the profiles' identity on joined PCs) stay.
    public static func rewriteTrustedRoots(_ xml: String, whereListed anchor: String, adding: [String],
                                           removing: [String]) -> String {
        let anchor = anchor.lowercased().filter(\.isHexDigit)
        let add = adding.map { $0.lowercased().filter(\.isHexDigit) }
        let remove = Set(removing.map { $0.lowercased().filter(\.isHexDigit) })
        var out = xml
        for tag in ["TrustedRootCA", "IssuerHash"] {
            let open = "<\(tag)>", close = "</\(tag)>"
            var ranges: [Range<String.Index>] = []
            var values: [String] = []
            var search = out.startIndex
            while let a = out.range(of: open, range: search..<out.endIndex),
                  let b = out.range(of: close, range: a.upperBound..<out.endIndex) {
                ranges.append(a.lowerBound..<b.upperBound)
                values.append(String(out[a.upperBound..<b.lowerBound]).lowercased().filter(\.isHexDigit))
                search = b.upperBound
            }
            guard let first = ranges.first, let last = ranges.last, values.contains(anchor) else { continue }
            var list = values.filter { !remove.contains($0) }
            for t in add where !list.contains(t) { list.append(t) }
            guard !list.isEmpty, list != values else { continue }
            let replacement = list.map { open + spacedThumbprint($0) + close }.joined()
            // The elements are contiguous in what we publish: replace from the first to the last.
            out.replaceSubrange(first.lowerBound..<last.upperBound, with: replacement)
        }
        return out
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
