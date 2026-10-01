import CryptoKit
import Foundation

/// Connect ▸ Mac / iPhone: an unsigned configuration profile with the CA as a trusted root
/// (`com.apple.security.root`) and, optionally, the directory as an LDAP account
/// (`com.apple.ldap.account`, Contacts lookups; the device asks for the password).
///
/// UUIDs are derived from the CA certificate and the domain, so installing a newer profile for
/// the same CA replaces the old one instead of adding a second.
public enum ConnectMobileConfig {
    public struct LDAPAccount: Sendable, Equatable {
        public var host: String
        public var useSSL: Bool
        public var bindDN: String
        public var searchBase: String

        public init(host: String, useSSL: Bool = true, bindDN: String, searchBase: String) {
            self.host = host
            self.useSSL = useSSL
            self.bindDN = bindDN
            self.searchBase = searchBase
        }
    }

    /// The profile as an XML property list.
    public static func profile(caDER: [UInt8], caName: String, dnsDomain: String, ldap: LDAPAccount?) throws -> Data {
        // Kept from the SheepAuth days (renamed LabDC, 1 Oct 2026): the identifier is how a Mac or
        // iPhone recognises the profile, so a re-download replaces the installed one instead of
        // installing a second copy beside it.
        let base = "dev.sheep.auth.\(dnsDomain)"
        var payloads: [[String: Any]] = [[
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": "\(base).ca",
            "PayloadUUID": uuid(caDER, "root"),
            "PayloadDisplayName": "\(dnsDomain) CA (\(caName))",
            "PayloadDescription": "Trusts the LabDC certificate authority of \(dnsDomain).",
            "PayloadCertificateFileName": "\(caName).cer",
            "PayloadContent": Data(caDER),
        ]]
        if let ldap {
            payloads.append([
                "PayloadType": "com.apple.ldap.account",
                "PayloadVersion": 1,
                "PayloadIdentifier": "\(base).ldap",
                "PayloadUUID": uuid(caDER, "ldap:\(dnsDomain)"),
                "PayloadDisplayName": "\(dnsDomain) directory",
                "LDAPAccountDescription": "\(dnsDomain) directory",
                "LDAPAccountHostName": ldap.host,
                "LDAPAccountUseSSL": ldap.useSSL,
                "LDAPAccountUserName": ldap.bindDN,
                "LDAPSearchSettings": [[
                    "LDAPSearchSettingDescription": "People",
                    "LDAPSearchSettingScope": "LDAPSearchSettingScopeSubtree",
                    "LDAPSearchSettingSearchBase": ldap.searchBase,
                ]],
            ])
        }
        let top: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": base,
            "PayloadUUID": uuid(caDER, "profile:\(dnsDomain)"),
            "PayloadDisplayName": "LabDC \(dnsDomain)",
            "PayloadDescription": ldap == nil ? "The \(dnsDomain) CA." : "The \(dnsDomain) CA and directory.",
            "PayloadOrganization": "LabDC",
            "PayloadRemovalDisallowed": false,
            "PayloadContent": payloads,
        ]
        return try PropertyListSerialization.data(fromPropertyList: top, format: .xml, options: 0)
    }

    /// A stable version-4-shaped UUID from SHA-256(der ‖ label).
    static func uuid(_ der: [UInt8], _ label: String) -> String {
        var b = Array(SHA256.hash(data: der + Array(label.utf8)).prefix(16))
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        let u = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
        return u.uuidString
    }
}
