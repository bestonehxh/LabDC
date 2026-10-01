import CryptoKit
import Foundation
import Store

/// "Certificate Services Client - Auto-Enrollment" and "Certificate Services Client - Certificate
/// Enrollment Policy" (Computer Configuration > Policies > Windows Settings > Security Settings >
/// Public Key Policies) as machine Registry.pol instructions, in the order GPMC writes them
/// (Samba's `advanced_enroll_reg_pol` test fixture, captured from Windows):
///
///     [Software\Policies\Microsoft\Cryptography;**DeleteKeys;REG_SZ;"Software\Policies\Microsoft\Cryptography\PolicyServers"]
///     [Software\Policies\Microsoft\Cryptography\AutoEnrollment;AEPolicy;REG_DWORD;7]
///     [Software\Policies\Microsoft\Cryptography\AutoEnrollment;OfflineExpirationPercent;REG_DWORD;10]
///     [Software\Policies\Microsoft\Cryptography\AutoEnrollment;OfflineExpirationStoreNames;REG_SZ;"MY"]
///     [Software\Policies\Microsoft\Cryptography\PolicyServers;;REG_SZ;"<default PolicyID>"]
///     [Software\Policies\Microsoft\Cryptography\PolicyServers;Flags;REG_DWORD;0]
///     [...\PolicyServers\<id>;URL;REG_SZ;"https://dc1.lab.sheep/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"]
///     [...\PolicyServers\<id>;PolicyID;REG_SZ;"{<forest root domain objectGUID>}"]
///     [...\PolicyServers\<id>;FriendlyName;REG_SZ;"Active Directory Enrollment Policy"]
///     [...\PolicyServers\<id>;Flags;REG_DWORD;16]        (0x10 AutoEnrollmentEnabled)
///     [...\PolicyServers\<id>;AuthFlags;REG_DWORD;2]     (Kerberos)
///     [...\PolicyServers\<id>;Cost;REG_DWORD;2147483645] (0x7FFFFFFD, the MS-CAESO default)
///
/// `AEPolicy` bits (MS-CAESO §4.4.5.1): 0x1 enroll, 0x2 renew/update ("manage"), 0x4 retrieve
/// pending; 0x8000 = autoenrollment disabled. `<id>` is lower-case hex SHA-1 of the lower-cased URL
/// in UTF-16LE (reproduces the fixture's `37c9dc30…` key for `LDAP:`; MS-CAESO allows any name).
public struct AutoEnrollmentSettings: Sendable, Hashable {
    public var cepURL: String
    /// The CEP's policy ID. An AD-backed CEP (`ADPolicyProvider_CEP_*`) reports the forest root
    /// domain's objectGUID in braces, upper case; PK-6's XCEP `GetPolicies` must return the same.
    public var policyID: String
    public var friendlyName: String = "Active Directory Enrollment Policy"
    public var aePolicy: UInt32 = 7
    public var offlineExpirationPercent: UInt32 = 10
    public var offlineExpirationStoreNames: String = "MY"
    /// `PolicyServers\Flags` (GPMC writes 0; the 2009 MS-CAESO text reads bit 0x2 as "use Group
    /// Policy configuration" — configurable in case a client needs it).
    public var policyServersFlags: UInt32 = 0
    /// Per end point: 0x10 AutoEnrollmentEnabled (| 0x20 AllowUntrustedIssuer).
    public var endpointFlags: UInt32 = 0x10
    /// 1 anonymous, 2 Kerberos, 3 user name + password, 8 certificate.
    public var authFlags: UInt32 = 2
    public var cost: UInt32 = 0x7FFF_FFFD

    public init(cepURL: String, policyID: String) {
        self.cepURL = cepURL
        self.policyID = policyID
    }

    /// `{<objectGUID of the domain NC head>}` upper case (the forest root domain: this DC's domain).
    public static func defaultPolicyID(store: DirectoryStore) async throws -> String {
        "{" + (try await store.domainInfo()).domainGUID.description.uppercased() + "}"
    }

    /// `https://<dc>/ADPolicyProvider_CEP_Kerberos/service.svc/CEP`.
    public static func defaultCEPURL(dcDNSName: String) -> String {
        "https://\(dcDNSName)/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"
    }
}

/// What a policy file says about autoenrollment.
public enum AutoEnrollmentState: Sendable, Equatable {
    case notConfigured
    case disabled
    /// `AEPolicy` value and the configured enrollment policy server URLs.
    case enabled(aePolicy: UInt32, cepURLs: [String])
}

public enum AutoEnrollmentPolicy {
    public static let cryptographyKey = #"Software\Policies\Microsoft\Cryptography"#
    public static let autoEnrollmentKey = cryptographyKey + #"\AutoEnrollment"#
    public static let policyServersKey = cryptographyKey + #"\PolicyServers"#
    public static let disabledAEPolicy: UInt32 = 0x8000

    /// The `PolicyServers\<id>` key name for a URL.
    public static func endpointKeyName(_ url: String) -> String {
        let bytes = RegistryPolicyFile.utf16z(url.lowercased()).dropLast(2)
        return Insecure.SHA1.hash(data: Array(bytes)).map { String(format: "%02x", $0) }.joined()
    }

    /// The instructions for "enabled" with one enrollment policy server.
    public static func entries(_ s: AutoEnrollmentSettings) -> [RegistryPolicyEntry] {
        let ep = policyServersKey + "\\" + endpointKeyName(s.cepURL)
        return [
            .deleteKeys(cryptographyKey, [policyServersKey]),
            .dword(autoEnrollmentKey, "AEPolicy", s.aePolicy),
            .dword(autoEnrollmentKey, "OfflineExpirationPercent", s.offlineExpirationPercent),
            .string(autoEnrollmentKey, "OfflineExpirationStoreNames", s.offlineExpirationStoreNames),
            .string(policyServersKey, "", s.policyID),
            .dword(policyServersKey, "Flags", s.policyServersFlags),
            .string(ep, "URL", s.cepURL),
            .string(ep, "PolicyID", s.policyID),
            .string(ep, "FriendlyName", s.friendlyName),
            .dword(ep, "Flags", s.endpointFlags),
            .dword(ep, "AuthFlags", s.authFlags),
            .dword(ep, "Cost", s.cost),
        ]
    }

    /// Replaces any autoenrollment / policy-server instructions with `entries(s)`.
    public static func enable(_ s: AutoEnrollmentSettings, in file: inout RegistryPolicyFile) {
        clear(&file)
        file.entries += entries(s)
    }

    /// "Disabled" (`AEPolicy` = 0x8000) and no enrollment policy servers.
    public static func disable(in file: inout RegistryPolicyFile) {
        clear(&file)
        file.entries.append(.dword(autoEnrollmentKey, "AEPolicy", disabledAEPolicy))
    }

    /// "Not configured": removes every instruction of both settings.
    public static func clear(_ file: inout RegistryPolicyFile) {
        file.removeKey(autoEnrollmentKey)
        file.removeKey(policyServersKey)
        file.entries.removeAll {
            $0.key.caseInsensitiveCompare(cryptographyKey) == .orderedSame
                && $0.valueName.caseInsensitiveCompare("**DeleteKeys") == .orderedSame
                && ($0.stringValue ?? "").lowercased().contains("policyservers")
        }
    }

    public static func state(in file: RegistryPolicyFile) -> AutoEnrollmentState {
        guard let ae = file.entry(key: autoEnrollmentKey, valueName: "AEPolicy")?.dwordValue else { return .notConfigured }
        if ae & disabledAEPolicy != 0 { return .disabled }
        let urls = file.entries(under: policyServersKey)
            .filter { $0.valueName.caseInsensitiveCompare("URL") == .orderedSame }
            .compactMap(\.stringValue)
        return .enabled(aePolicy: ae, cepURLs: urls)
    }

    /// The policy ID the file hands to the autoenrollment client (`PolicyServers` default value),
    /// which PK-6's XCEP `GetPolicies` must echo.
    public static func policyID(in file: RegistryPolicyFile) -> String? {
        file.entry(key: policyServersKey, valueName: "")?.stringValue
    }
}

extension GroupPolicyEditor {
    public func autoEnrollment(_ gpo: DefaultGPO = .defaultDomainPolicy, scope: GPOScope = .machine) async throws -> AutoEnrollmentState {
        AutoEnrollmentPolicy.state(in: try await registryPolicy(gpo, scope: scope))
    }

    /// The policy ID the GPO gives the client (machine side first, then user side); nil when
    /// no enrollment policy server is configured (PK-6's CEP then uses the default ID).
    public func autoEnrollmentPolicyID(_ gpo: DefaultGPO = .defaultDomainPolicy) async throws -> String? {
        for scope in [GPOScope.machine, .user] {
            if let id = AutoEnrollmentPolicy.policyID(in: try await registryPolicy(gpo, scope: scope)), !id.isEmpty {
                return id
            }
        }
        return nil
    }

    /// Turns autoenrollment on with `settings` on the `scope` side of `gpo`: `.machine` for
    /// computer certificates, `.user` (PK-6) for user certificates at logon — the same
    /// instructions, applied under HKCU.
    @discardableResult
    public func enableAutoEnrollment(_ settings: AutoEnrollmentSettings, gpo: DefaultGPO = .defaultDomainPolicy,
                                     scope: GPOScope = .machine) async throws -> GPOEditResult {
        try await editRegistryPolicy(gpo, scope: scope) { AutoEnrollmentPolicy.enable(settings, in: &$0) }
    }

    /// Sets autoenrollment to "Disabled" on the `scope` side.
    @discardableResult
    public func disableAutoEnrollment(gpo: DefaultGPO = .defaultDomainPolicy,
                                      scope: GPOScope = .machine) async throws -> GPOEditResult {
        try await editRegistryPolicy(gpo, scope: scope) { AutoEnrollmentPolicy.disable(in: &$0) }
    }
}
