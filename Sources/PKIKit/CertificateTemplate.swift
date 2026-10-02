import Foundation
import Store
import X509

/// Where the subjectAltName of an issued certificate comes from.
public enum SANPolicy: String, Sendable, Codable, CaseIterable {
    /// `DNS:<dNSHostName>` of the requesting computer account (from the store). A CSR may ask for
    /// that name only.
    case dnsHostName
    /// `otherName UPN:<userPrincipalName>` of the requesting user (from the store; the implicit
    /// `sam@dnsDomain` when the attribute is unset). A CSR may ask for that UPN only.
    case upn
    /// The SANs in the CSR's extensionRequest (an admin may replace them with overrides).
    case fromRequest
    /// No subjectAltName extension.
    case none
}

/// X.509 KeyUsage bits of a template; bit i is KeyUsage bit i (RFC 5280 §4.2.1.3), which is
/// also how the store keeps them.
public struct TemplateKeyUsage: OptionSet, Sendable, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    public static let digitalSignature = TemplateKeyUsage(rawValue: 1 << 0)
    public static let nonRepudiation = TemplateKeyUsage(rawValue: 1 << 1)
    public static let keyEncipherment = TemplateKeyUsage(rawValue: 1 << 2)
    public static let dataEncipherment = TemplateKeyUsage(rawValue: 1 << 3)
    public static let keyAgreement = TemplateKeyUsage(rawValue: 1 << 4)
    public static let keyCertSign = TemplateKeyUsage(rawValue: 1 << 5)
    public static let cRLSign = TemplateKeyUsage(rawValue: 1 << 6)
    public static let encipherOnly = TemplateKeyUsage(rawValue: 1 << 7)
    public static let decipherOnly = TemplateKeyUsage(rawValue: 1 << 8)

    static let named: [(String, TemplateKeyUsage)] = [
        ("digitalSignature", .digitalSignature), ("nonRepudiation", .nonRepudiation),
        ("keyEncipherment", .keyEncipherment), ("dataEncipherment", .dataEncipherment),
        ("keyAgreement", .keyAgreement), ("keyCertSign", .keyCertSign), ("cRLSign", .cRLSign),
        ("encipherOnly", .encipherOnly), ("decipherOnly", .decipherOnly),
    ]

    public var names: [String] { Self.named.filter { contains($0.1) }.map(\.0) }

    public var x509: KeyUsage {
        KeyUsage(digitalSignature: contains(.digitalSignature), nonRepudiation: contains(.nonRepudiation),
                 keyEncipherment: contains(.keyEncipherment), dataEncipherment: contains(.dataEncipherment),
                 keyAgreement: contains(.keyAgreement), keyCertSign: contains(.keyCertSign),
                 cRLSign: contains(.cRLSign), encipherOnly: contains(.encipherOnly),
                 decipherOnly: contains(.decipherOnly))
    }
}

/// Well-known OIDs used by the CA.
public enum PKIOID {
    public static let serverAuth = "1.3.6.1.5.5.7.3.1"
    public static let clientAuth = "1.3.6.1.5.5.7.3.2"
    public static let emailProtection = "1.3.6.1.5.5.7.3.4"
    /// `szOID_NT_PRINCIPAL_NAME`, the UPN otherName.
    public static let userPrincipalName = "1.3.6.1.4.1.311.20.2.3"
    /// `szOID_NTDS_CA_SECURITY_EXT` (KB5014754): the account's SID, for strong certificate mapping.
    public static let ntdsCASecurityExtension = "1.3.6.1.4.1.311.25.2"
    /// `szOID_NTDS_OBJECTSID`, the otherName inside it.
    public static let ntdsObjectSID = "1.3.6.1.4.1.311.25.2.1"
    /// Smart card logon and Any Purpose EKUs (both sign a user in, like clientAuth).
    public static let smartcardLogon = "1.3.6.1.4.1.311.20.2.2"
    public static let anyExtendedKeyUsage = "2.5.29.37.0"
    /// `szOID_CERTIFICATE_TEMPLATE` (template OID + major/minor version), how Windows
    /// auto-enrollment matches a certificate to its template.
    public static let certificateTemplateExtension = "1.3.6.1.4.1.311.21.7"
    /// The arc Windows generates forest template OIDs under.
    public static let templateArc = "1.3.6.1.4.1.311.21.8"
    public static let crlDistributionPoints = "2.5.29.31"
    public static let authorityInfoAccess = "1.3.6.1.5.5.7.1.1"
    public static let caIssuers = "1.3.6.1.5.5.7.48.2"
    public static let authorityKeyIdentifier = "2.5.29.35"
    public static let crlNumber = "2.5.29.20"
    public static let crlReason = "2.5.29.21"
}

/// A certificate template (spec §3): what a certificate issued from it contains and who may
/// enrol for it. Stored in the store's `pki_templates` table.
public struct CertificateTemplate: Sendable, Equatable {
    public var name: String
    public var displayName: String
    /// `msPKI-Cert-Template-OID`, under `1.3.6.1.4.1.311.21.8.<forest arc>`.
    public var oid: String
    public var validityDays: Int
    /// Auto-enrollment renews this many days before expiry (Windows `pKIOverlapPeriod`).
    public var renewalDays: Int
    public var keyUsage: TemplateKeyUsage
    /// EKU OIDs, dotted.
    public var ekus: [String]
    public var sanPolicy: SANPolicy
    /// Requesters in one of these groups (or with one of these SIDs) may enrol; admins always may.
    public var enrolAllowedGroupSIDs: [String]
    public var autoEnroll: Bool
    /// Only an admin (CLI / UI) may issue from this template.
    public var manualApproval: Bool
    /// Minimum RSA modulus size; EC keys are governed by `allowedKeyTypes` alone.
    public var minKeyBits: Int
    /// Subject key types accepted: `p256`, `p384`, `p521`, `rsa`.
    public var allowedKeyTypes: [String]
    public var enabled: Bool
    public var builtIn: Bool
    /// The CA that issues from this template (nil: the current CA).
    public var issuingCA: String?
    /// The template's major version (`revision`, `szOID_CERTIFICATE_TEMPLATE` major): 100 until
    /// a root migration bumps it, which makes Windows auto-enrollment re-enrol every holder
    /// ("Reenroll All Certificate Holders"). Kept in the `domain` table (`CAService.templateRevisionsKey`).
    public var majorRevision = CertificateTemplate.majorVersion

    /// Template extension versions (`szOID_CERTIFICATE_TEMPLATE` major/minor; PK-5 publishes
    /// `revision` = 100 and `msPKI-Template-Minor-Revision` = 0 to match).
    public static let majorVersion = 100
    public static let minorVersion = 0

    public init(name: String, displayName: String? = nil, oid: String, validityDays: Int, renewalDays: Int,
                keyUsage: TemplateKeyUsage, ekus: [String], sanPolicy: SANPolicy, enrolAllowedGroupSIDs: [String],
                autoEnroll: Bool, manualApproval: Bool, minKeyBits: Int = 2048,
                allowedKeyTypes: [String] = ["p256", "p384", "rsa"], enabled: Bool = true, builtIn: Bool = false,
                issuingCA: String? = nil) {
        self.issuingCA = issuingCA
        self.name = name
        self.displayName = displayName ?? name
        self.oid = oid
        self.validityDays = validityDays
        self.renewalDays = renewalDays
        self.keyUsage = keyUsage
        self.ekus = ekus
        self.sanPolicy = sanPolicy
        self.enrolAllowedGroupSIDs = enrolAllowedGroupSIDs
        self.autoEnroll = autoEnroll
        self.manualApproval = manualApproval
        self.minKeyBits = minKeyBits
        self.allowedKeyTypes = allowedKeyTypes
        self.enabled = enabled
        self.builtIn = builtIn
    }

    /// A SubCA-style template (keyCertSign) issues `CA:TRUE, pathlen:0`.
    public var isCA: Bool { keyUsage.contains(.keyCertSign) }

    /// The subject and SAN come from the requesting account (and its SID goes in the
    /// certificate's `szOID_NTDS_CA_SECURITY_EXT`).
    public var isAccountBound: Bool { sanPolicy == .dnsHostName || sanPolicy == .upn }

    /// Certificates from this template sign someone in (clientAuth, smart card logon, any
    /// purpose, or no EKU at all).
    public var authenticatesClients: Bool {
        !isCA && (ekus.isEmpty || ekus.contains { [PKIOID.clientAuth, PKIOID.smartcardLogon, PKIOID.anyExtendedKeyUsage].contains($0) })
    }

    /// ESC1: SANs from the CSR + client authentication + enrollable by someone who is not an
    /// administrator lets that someone ask for a certificate naming anybody. The CA refuses UPN
    /// SANs from non-administrators, but the template is still a footgun worth a warning.
    /// `nil` when the template is fine (or only administrators may enrol).
    public func esc1Warning() -> String? {
        guard sanPolicy == .fromRequest, authenticatesClients, !manualApproval else { return nil }
        let others = enrolAllowedGroupSIDs.filter { !Self.isAdministratorSID($0) }
        guard !others.isEmpty else { return nil }
        return "Template \(name) takes its names from the request, signs clients in and may be enrolled by "
            + "non-administrators (\(others.joined(separator: ", "))). Anyone in those groups can ask for a "
            + "certificate naming another account (ESC1); LabDC refuses UPNs from them, but restrict enrollment "
            + "to administrators, require approval, or take the names from the account."
    }

    public init(row: PKITemplateRow) {
        self.init(name: row.name, displayName: row.displayName, oid: row.oid, validityDays: row.validityDays,
                  renewalDays: row.renewalDays, keyUsage: TemplateKeyUsage(rawValue: row.keyUsage), ekus: row.ekus,
                  sanPolicy: SANPolicy(rawValue: row.sanPolicy) ?? .none, enrolAllowedGroupSIDs: row.enrolAllowedGroupSIDs,
                  autoEnroll: row.autoEnroll, manualApproval: row.manualApproval, minKeyBits: row.minKeyBits,
                  allowedKeyTypes: row.allowedKeyTypes, enabled: row.enabled, builtIn: row.builtIn, issuingCA: row.issuingCA)
    }

    public var row: PKITemplateRow {
        PKITemplateRow(name: name, displayName: displayName, oid: oid, validityDays: validityDays,
                       renewalDays: renewalDays, keyUsage: keyUsage.rawValue, ekus: ekus, sanPolicy: sanPolicy.rawValue,
                       enrolAllowedGroupSIDs: enrolAllowedGroupSIDs, autoEnroll: autoEnroll,
                       manualApproval: manualApproval, minKeyBits: minKeyBits, allowedKeyTypes: allowedKeyTypes,
                       enabled: enabled, builtIn: builtIn, issuingCA: issuingCA)
    }

    /// Administrator (-500), Domain Admins (-512), Enterprise Admins (-519) of a domain, or
    /// BUILTIN Administrators (S-1-5-32-544).
    static func isAdministratorSID(_ sid: String) -> Bool {
        let s = sid.uppercased()
        if s == "S-1-5-32-544" { return true }
        guard s.hasPrefix("S-1-5-21-") else { return false }
        return s.hasSuffix("-500") || s.hasSuffix("-512") || s.hasSuffix("-519")
    }

    // MARK: Built-ins

    public static let builtInNames = ["Computer", "User", "WebServer", "Device", "SubCA", "Computer192", "User192",
                                      "Computer-RSA", "User-RSA"]

    /// The five built-in templates of spec §3 for a domain. `oid` gives each template's OID.
    ///
    /// - Computer: clientAuth + serverAuth, SAN DNS = dNSHostName, 1 y, auto-enroll; Domain
    ///   Computers (515) and Domain Controllers (516).
    /// - User: clientAuth + emailProtection, SAN UPN, 1 y, auto-enroll; Domain Users (513).
    /// - WebServer: serverAuth, SANs from the CSR, 2 y, manual; Domain Admins (512), Enterprise Admins (519).
    /// - Device: clientAuth (SCEP/EST devices), SANs from the CSR, 1 y; admins / challenge-authorised callers.
    /// - SubCA: keyCertSign + cRLSign, no SAN, 5 y, manual, disabled by default.
    public static func builtIns(domainSID: String, oid: (String) -> String) -> [CertificateTemplate] {
        let sid = { (rid: Int) in "\(domainSID)-\(rid)" }
        let signAndEncrypt: TemplateKeyUsage = [.digitalSignature, .keyEncipherment]
        return [
            CertificateTemplate(name: "Computer", oid: oid("Computer"), validityDays: 365, renewalDays: 42,
                                keyUsage: signAndEncrypt, ekus: [PKIOID.clientAuth, PKIOID.serverAuth],
                                sanPolicy: .dnsHostName, enrolAllowedGroupSIDs: [sid(515), sid(516)],
                                autoEnroll: true, manualApproval: false, builtIn: true),
            CertificateTemplate(name: "User", oid: oid("User"), validityDays: 365, renewalDays: 42,
                                keyUsage: signAndEncrypt, ekus: [PKIOID.clientAuth, PKIOID.emailProtection],
                                sanPolicy: .upn, enrolAllowedGroupSIDs: [sid(513)],
                                autoEnroll: true, manualApproval: false, builtIn: true),
            CertificateTemplate(name: "WebServer", displayName: "Web Server", oid: oid("WebServer"), validityDays: 730,
                                renewalDays: 42, keyUsage: signAndEncrypt, ekus: [PKIOID.serverAuth],
                                sanPolicy: .fromRequest, enrolAllowedGroupSIDs: [sid(512), sid(519)],
                                autoEnroll: false, manualApproval: true, builtIn: true),
            CertificateTemplate(name: "Device", oid: oid("Device"), validityDays: 365, renewalDays: 42,
                                keyUsage: signAndEncrypt, ekus: [PKIOID.clientAuth],
                                sanPolicy: .fromRequest, enrolAllowedGroupSIDs: [sid(512), sid(519)],
                                autoEnroll: false, manualApproval: false, builtIn: true),
            CertificateTemplate(name: "SubCA", displayName: "Subordinate Certification Authority", oid: oid("SubCA"),
                                validityDays: 1825, renewalDays: 42,
                                keyUsage: [.digitalSignature, .keyCertSign, .cRLSign], ekus: [],
                                sanPolicy: .none, enrolAllowedGroupSIDs: [sid(512), sid(519)],
                                autoEnroll: false, manualApproval: true, enabled: false, builtIn: true),
            // WPA3-Enterprise 192-bit (1 Oct 2026): P-384 keys, issued by the P-384 802.1X CA with
            // SHA-384. Disabled until a 192-bit 802.1X profile is published, which enables them
            // with auto-enrollment (RADIUS ▸ 802.1X).
            CertificateTemplate(name: "Computer192", displayName: "Computer (802.1X 192-bit)", oid: oid("Computer192"),
                                validityDays: 365, renewalDays: 42, keyUsage: [.digitalSignature],
                                ekus: [PKIOID.clientAuth], sanPolicy: .dnsHostName, enrolAllowedGroupSIDs: [sid(515)],
                                autoEnroll: false, manualApproval: false, allowedKeyTypes: ["p384"], enabled: false, builtIn: true,
                                issuingCA: LabPKI.suiteBCAName),
            CertificateTemplate(name: "User192", displayName: "User (802.1X 192-bit)", oid: oid("User192"),
                                validityDays: 365, renewalDays: 42, keyUsage: [.digitalSignature],
                                ekus: [PKIOID.clientAuth], sanPolicy: .upn, enrolAllowedGroupSIDs: [sid(513)],
                                autoEnroll: false, manualApproval: false, allowedKeyTypes: ["p384"], enabled: false, builtIn: true,
                                issuingCA: LabPKI.suiteBCAName),
            // RSA-only devices (1 Oct 2026): RSA-2048+ client certificates from the RSA
            // compatibility root, for EAP-TLS on printers, phones and old supplicants. Enrolled
            // over SCEP / EST (a challenge is the authorisation, the names come from the CSR) or
            // signed by an administrator; switched on with "Allow RSA-only devices".
            CertificateTemplate(name: "Computer-RSA", displayName: "Computer (RSA-only devices)", oid: oid("Computer-RSA"),
                                validityDays: 365, renewalDays: 42, keyUsage: signAndEncrypt, ekus: [PKIOID.clientAuth],
                                sanPolicy: .fromRequest, enrolAllowedGroupSIDs: [sid(512), sid(519)],
                                autoEnroll: false, manualApproval: false, minKeyBits: 2048, allowedKeyTypes: ["rsa"], enabled: false,
                                builtIn: true, issuingCA: LabPKI.rsaCompatCAName),
            CertificateTemplate(name: "User-RSA", displayName: "User (RSA-only devices)", oid: oid("User-RSA"),
                                validityDays: 365, renewalDays: 42, keyUsage: signAndEncrypt, ekus: [PKIOID.clientAuth],
                                sanPolicy: .fromRequest, enrolAllowedGroupSIDs: [sid(512), sid(519)],
                                autoEnroll: false, manualApproval: false, minKeyBits: 2048, allowedKeyTypes: ["rsa"], enabled: false,
                                builtIn: true, issuingCA: LabPKI.rsaCompatCAName),
        ]
    }

    /// A fresh forest arc like Windows generates: `1.3.6.1.4.1.311.21.8` + six random numbers.
    static func randomForestArc() -> String {
        var rng = SystemRandomNumberGenerator()
        let parts = (0..<5).map { _ in String(UInt32.random(in: 1_000_000...16_777_215, using: &rng)) }
            + [String(UInt32.random(in: 1...255, using: &rng))]
        return ([PKIOID.templateArc] + parts).joined(separator: ".")
    }

    /// A template OID under `arc`: two more random numbers (Windows' `msPKI-Cert-Template-OID` shape).
    static func randomTemplateOID(arc: String) -> String {
        var rng = SystemRandomNumberGenerator()
        return "\(arc).\(UInt32.random(in: 1_000_000...16_777_215, using: &rng)).\(UInt32.random(in: 1_000_000...16_777_215, using: &rng))"
    }
}
