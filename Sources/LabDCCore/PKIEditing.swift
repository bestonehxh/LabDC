import CertConvert
import CryptoKit
import Foundation
import PKIKit
import Store
import SYSVOL
import X509

// UI-3: value types of the Certificates page (derived from PKIKit / SYSVOL / Store state), shared
// by `PKIEditor` and the app's view models.

/// Upper-case colon hex (`AB:CD:…`), as certificate viewers and device configs show fingerprints.
public func colonHex(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
}

extension DistinguishedName {
    /// The last (most specific) CN, for names on screen and file names.
    public var commonNameText: String? { ServerController.commonName(self) }
}

/// A CA of the PKI as the CA card shows it.
public struct CAInfo: Identifiable, Equatable, Sendable {
    public var id: String { name }
    /// LabDC CA name (`lab`, `Prod`): part of the CRL/AIA URLs.
    public let name: String
    public let commonName: String?
    public let subject: String
    public let keyType: CAKeyType
    public let notBefore: Date
    public let notAfter: Date
    public let der: [UInt8]
    public let isCurrent: Bool

    public init(name: String, commonName: String?, subject: String, keyType: CAKeyType, notBefore: Date, notAfter: Date,
                der: [UInt8], isCurrent: Bool) {
        self.name = name
        self.commonName = commonName
        self.subject = subject
        self.keyType = keyType
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.der = der
        self.isCurrent = isCurrent
    }

    public init(_ ca: CertificateAuthority, current: Bool) throws {
        self.init(name: ca.name, commonName: ServerController.commonName(ca.certificate.subject),
                  subject: ca.certificate.subject.description, keyType: ca.keyType,
                  notBefore: ca.certificate.notValidBefore, notAfter: ca.certificate.notValidAfter,
                  der: try ca.der(), isCurrent: current)
    }

    public var isLab: Bool { name == LabPKI.labCAName }
    /// The name on screen: the CN, else the LabDC name.
    public var title: String { commonName ?? name }
    public var sha256: String { colonHex(SHA256.hash(data: der)) }
    public var sha1: String { colonHex(Insecure.SHA1.hash(data: der)) }
    public var md5: String { colonHex(Insecure.MD5.hash(data: der)) }
    /// The GPO / Windows thumbprint (SHA-1, upper case, no separators).
    public var thumbprint: String { CertificateBlob.thumbprint(der) }
    public var pem: String { PEMBlock(label: "CERTIFICATE", der: der).text }

    public func daysLeft(now: Date = Date()) -> Int {
        Int((notAfter.timeIntervalSince(now) / 86400).rounded(.down))
    }

    /// `Valid until 26 Sep 2036 (3,652 days)` / `Expires in 12 days` / `Expired on 1 Jan 2026`.
    public func validityText(now: Date = Date()) -> String {
        let days = daysLeft(now: now)
        if notAfter <= now { return "Expired on \(PKIText.day(notAfter))" }
        if days < 30 { return "Expires in \(days) day\(days == 1 ? "" : "s") (\(PKIText.day(notAfter)))" }
        return "Valid until \(PKIText.day(notAfter)) (\(days.formatted()) days)"
    }

    /// True when it expires within 90 days (the card turns orange).
    public func expiresSoon(now: Date = Date()) -> Bool { daysLeft(now: now) < 90 }
}

/// The CRL of one CA: what the CA card's "CRL" row says.
public struct CRLStatus: Equatable, Sendable {
    public var caName: String
    public var number: Int64
    public var thisUpdate: Date
    public var nextUpdate: Date
    public var entries: Int
    /// The CDP URL in every issued certificate (`http://dc1.lab.sheep/pki/lab.crl`).
    public var url: String

    public init(caName: String, number: Int64, thisUpdate: Date, nextUpdate: Date, entries: Int, url: String) {
        self.caName = caName
        self.number = number
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self.entries = entries
        self.url = url
    }

    /// Past its next update (clients refuse it) — "Regenerate now" is the fix.
    public func isStale(now: Date = Date()) -> Bool { nextUpdate <= now }

    /// `CRL #4 · 2 revoked · generated 26 Sep 14:02 · next update 3 Oct 14:02`.
    public func summary(now: Date = Date()) -> String {
        "CRL #\(number) · \(entries) revoked · generated \(PKIText.stamp(thisUpdate)) · "
            + (isStale(now: now) ? "out of date since \(PKIText.stamp(nextUpdate))" : "next update \(PKIText.stamp(nextUpdate))")
    }
}

/// One certificate in the Default Domain Policy's Trusted Root list.
public struct TrustedRootInfo: Identifiable, Equatable, Sendable {
    public var id: String { thumbprint }
    public var thumbprint: String
    public var subject: String
    public var commonName: String?
    public var notAfter: Date?
    public var friendlyName: String?
    /// Also under `CN=Certification Authorities` in the Configuration NC (members' Enterprise store).
    public var publishedInConfiguration: Bool
    /// One of this server's own CAs.
    public var labDCCA: String?
    public var der: [UInt8]

    public init(thumbprint: String, subject: String, commonName: String?, notAfter: Date?, friendlyName: String?,
                publishedInConfiguration: Bool, labDCCA: String?, der: [UInt8]) {
        self.thumbprint = thumbprint
        self.subject = subject
        self.commonName = commonName
        self.notAfter = notAfter
        self.friendlyName = friendlyName
        self.publishedInConfiguration = publishedInConfiguration
        self.labDCCA = labDCCA
        self.der = der
    }

    /// Friendly name, else CN, else the subject.
    public var title: String { friendlyName ?? commonName ?? subject }
    /// `AB12 CD34 …` (groups of four, easier to compare with certlm.msc).
    public var groupedThumbprint: String {
        stride(from: 0, to: thumbprint.count, by: 4).map { i in
            let a = thumbprint.index(thumbprint.startIndex, offsetBy: i)
            return String(thumbprint[a..<thumbprint.index(a, offsetBy: min(4, thumbprint.count - i))])
        }.joined(separator: " ")
    }
}

/// What "Add certificate…" did with a file.
public struct TrustedRootAddReport: Equatable, Sendable {
    public var added: [String] = []
    /// Roots that were already in the list.
    public var alreadyPresent: [String] = []
    /// Certificates that are not self-signed (only roots belong in Trusted Root).
    public var skipped: [String] = []

    public init(added: [String] = [], alreadyPresent: [String] = [], skipped: [String] = []) {
        self.added = added
        self.alreadyPresent = alreadyPresent
        self.skipped = skipped
    }

    public var message: String {
        var parts: [String] = []
        if !added.isEmpty { parts.append("Added \(added.joined(separator: ", ")).") }
        if !alreadyPresent.isEmpty { parts.append("Already in the list: \(alreadyPresent.joined(separator: ", ")).") }
        if !skipped.isEmpty {
            parts.append("Skipped \(skipped.count) certificate\(skipped.count == 1 ? "" : "s") that \(skipped.count == 1 ? "is" : "are") not a root: \(skipped.joined(separator: "; ")).")
        }
        return parts.joined(separator: " ")
    }
}

/// The Default Domain Policy version line under the trusted-root list.
public enum GPOVersionText {
    public static func line(version: UInt32?) -> String {
        guard let version else { return "Default Domain Policy not found — it is created when the server starts." }
        let v = GPOVersion(raw: version)
        return "Default Domain Policy version \(v.machine) (computers), \(v.user) (users) — members refresh within 90 min or `gpupdate /force`"
    }
}

/// The addresses devices use for the PKI services (ports from the running listeners).
public struct PKIEndpoints: Equatable, Sendable {
    public var dcDNSName: String
    /// HTTP (CRL, AIA, SCEP); nil when off.
    public var httpPort: Int?
    /// HTTPS (CEP/CES); nil when off.
    public var httpsPort: Int?
    /// EST (HTTPS); nil when off.
    public var estPort: Int?

    public init(dcDNSName: String, httpPort: Int? = 80, httpsPort: Int? = 443, estPort: Int? = 8443) {
        self.dcDNSName = dcDNSName
        self.httpPort = httpPort
        self.httpsPort = httpsPort
        self.estPort = estPort
    }

    private func host(_ scheme: String, _ port: Int?, standard: Int) -> String {
        "\(scheme)://\(dcDNSName)" + (port == nil || port == standard || port == 0 ? "" : ":\(port!)")
    }

    public var httpBase: String { host("http", httpPort, standard: 80) }
    public var httpsBase: String { host("https", httpsPort, standard: 443) }
    public var caCertificateURL: (String) -> String { { self.httpBase + CAService.caCertificatePath(caName: $0) } }
    /// `https://dc1.lab.sheep/ADPolicyProvider_CEP_Kerberos/service.svc/CEP` (what the GPO carries).
    public var cepURL: String { httpsBase + "/ADPolicyProvider_CEP_Kerberos/service.svc/CEP" }
    public func cesURL(caName: String) -> String { httpsBase + "/\(caName)_CES_Kerberos/service.svc/CES" }
    public var scepURL: String { httpBase + "/scep" }
    public var scepAlternateURLs: [String] { [httpBase + "/certsrv/mscep/mscep.dll", httpBase + "/cgi-bin/pkiclient.exe"] }
    public var estURL: String {
        "https://\(dcDNSName)" + (estPort == nil || estPort == 443 || estPort == 0 ? "" : ":\(estPort!)") + "/.well-known/est"
    }
    public func estLabelURL(template: String) -> String { estURL + "/\(template)" }

    /// From the app's listener table (the bound ports; standard ones when unknown).
    @MainActor public static func from(status: ServerStatus) -> PKIEndpoints? {
        guard let dc = status.dcDNSName else { return nil }
        func port(_ l: ServeListener) -> Int? {
            guard let s = status.listeners.first(where: { $0.listener == l }) else { return nil }
            if s.state == .off { return nil }
            return s.port ?? Int(s.configuredPort)
        }
        return PKIEndpoints(dcDNSName: dc, httpPort: port(.http), httpsPort: port(.https), estPort: port(.est))
    }
}

/// Auto-enrollment as the Enrollment card shows it (the machine half decides the switch).
public struct AutoEnrollmentStatus: Equatable, Sendable {
    public var enabled: Bool
    public var userEnabled: Bool
    /// The CEP URL in the GPO (when enabled) or the one enabling would write.
    public var cepURL: String
    public var policyID: String?
    public var configured: Bool

    public init(enabled: Bool = false, userEnabled: Bool = false, cepURL: String = "", policyID: String? = nil,
                configured: Bool = false) {
        self.enabled = enabled
        self.userEnabled = userEnabled
        self.cepURL = cepURL
        self.policyID = policyID
        self.configured = configured
    }

    /// The three-line "What Windows will do" explanation.
    public static let whatWindowsWillDo = [
        "At the next policy refresh (90 min, or `gpupdate /force`) each joined PC reads the enrollment policy server from the Default Domain Policy.",
        "It asks that server (CEP, Kerberos) which templates it may enrol for: computers get Computer, users get User at sign-in.",
        "It creates a key, sends the request to the CA (CES) and installs the certificate; it renews by itself 42 days before expiry.",
    ]
}

/// SCEP / EST facts for device configuration (what `labdc scep info` prints).
public struct DeviceEnrollmentInfo: Equatable, Sendable {
    public var scepURL: String
    public var scepAlternateURLs: [String]
    public var estURL: String
    /// Templates a challenge can enrol for: `/.well-known/est/<label>/simpleenroll`.
    public var estLabels: [String]
    public var caName: String
    public var caSHA256: String
    public var caSHA1: String
    public var caMD5: String
    public var raSubject: String?
    public var raValidUntil: Date?

    public init(scepURL: String, scepAlternateURLs: [String], estURL: String, estLabels: [String], caName: String,
                caSHA256: String, caSHA1: String, caMD5: String, raSubject: String?, raValidUntil: Date?) {
        self.scepURL = scepURL
        self.scepAlternateURLs = scepAlternateURLs
        self.estURL = estURL
        self.estLabels = estLabels
        self.caName = caName
        self.caSHA256 = caSHA256
        self.caSHA1 = caSHA1
        self.caMD5 = caMD5
        self.raSubject = raSubject
        self.raValidUntil = raValidUntil
    }
}

/// A new challenge with its text — the only time the text exists outside the device.
public struct NewChallenge: Equatable, Sendable {
    public var row: PKIChallengeRow
    public var secret: String

    public init(row: PKIChallengeRow, secret: String) {
        self.row = row
        self.secret = secret
    }
}

/// A group from the directory for the template editor's "Who may enrol" picker.
public struct PKIDirectoryGroup: Identifiable, Hashable, Sendable {
    public var id: String { sid }
    public var sid: String
    public var name: String

    public init(sid: String, name: String) {
        self.sid = sid
        self.name = name
    }
}

/// When the Configuration NC PKI objects (PK-5) were last synced and what changed.
public struct DirectorySyncStatus: Equatable, Sendable {
    public var date: Date
    public var text: String
    public var ok: Bool

    public init(date: Date, text: String, ok: Bool = true) {
        self.date = date
        self.text = text
        self.ok = ok
    }

    /// The last `PKI directory objects …` line of the log (serve start / earlier syncs).
    public static func fromLog(_ lines: [LogLine]) -> DirectorySyncStatus? {
        guard let line = lines.last(where: {
            $0.component == "PKI" && ($0.text.hasPrefix("directory objects") || $0.text.contains("Configuration NC failed"))
        }) else { return nil }
        return DirectorySyncStatus(date: line.date, text: line.text, ok: line.level != .warning)
    }

    public static func from(report: PKIPublishReport, at date: Date) -> DirectorySyncStatus {
        DirectorySyncStatus(date: date, text: report.isNoOp ? "directory objects up to date (Public Key Services)"
                            : "directory objects: \(report.created.count) created, \(report.modified.count) updated, "
                              + "\(report.deleted.count) removed (Public Key Services)")
    }
}

/// Export CA ▸ …
public enum CAExportFormat: String, CaseIterable, Identifiable, Sendable {
    /// PEM (`.pem`), most devices.
    case pem
    /// DER (`.cer`), Windows.
    case der
    /// Apple configuration profile (`.mobileconfig`) with the CA as a trusted root.
    case mobileconfig

    public var id: String { rawValue }
    public var fileExtension: String {
        switch self {
        case .pem: "pem"
        case .der: "cer"
        case .mobileconfig: "mobileconfig"
        }
    }
    public var menuTitle: String {
        switch self {
        case .pem: "PEM (.pem)…"
        case .der: "DER (.cer) for Windows…"
        case .mobileconfig: "Apple Profile (.mobileconfig)…"
        }
    }
    public func fileName(for ca: CAInfo) -> String {
        let base = ca.title.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
        return "\(base).\(fileExtension)"
    }
}

/// An unsigned Apple configuration profile holding one CA certificate as a trusted root
/// (Configuration Profile Reference: payload `com.apple.security.root`, PayloadContent = DER).
public enum AppleConfigurationProfile {
    public static func trustedRoot(der: [UInt8], displayName: String, organization: String? = nil) throws -> Data {
        let thumbprint = CertificateBlob.thumbprint(der)
        // The SheepAuth-era identifier and UUID seed stay (renamed LabDC, 1 Oct 2026): same CA → same
        // profile, so a device that installed it before replaces it instead of adding a second one.
        let identifier = "dev.sheep.auth.ca.\(thumbprint)"
        let payload: [String: Any] = [
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier + ".root",
            "PayloadUUID": uuid(thumbprint, "root"),
            "PayloadDisplayName": displayName,
            "PayloadDescription": "Adds \(displayName) as a trusted root certificate.",
            "PayloadCertificateFileName": "\(thumbprint).cer",
            "PayloadContent": Data(der),
        ]
        var profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier,
            "PayloadUUID": uuid(thumbprint, "profile"),
            "PayloadDisplayName": "\(displayName) (trusted root)",
            "PayloadDescription": "Installs the certificate authority \(displayName) so this device trusts the servers and certificates it issues.",
            "PayloadRemovalDisallowed": false,
            "PayloadScope": "System",
            "PayloadContent": [payload],
        ]
        if let organization { profile["PayloadOrganization"] = organization }
        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }

    /// A stable UUID (same CA → same profile, so reinstalling replaces it) with RFC 4122 v5-style bits.
    static func uuid(_ thumbprint: String, _ role: String) -> String {
        var b = Array(Insecure.SHA1.hash(data: Data("dev.sheep.auth/\(role)/\(thumbprint)".utf8)).prefix(16))
        b[6] = (b[6] & 0x0F) | 0x50
        b[8] = (b[8] & 0x3F) | 0x80
        let u = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
        return u.uuidString
    }
}

/// Short date texts of the Certificates page (Gregorian, whatever the Mac's calendar).
public enum PKIText {
    static let gregorian: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = .current
        return c
    }()

    /// `26 Sep 2036`
    public static func day(_ date: Date) -> String {
        var style = Date.FormatStyle(date: .abbreviated, time: .omitted)
        style.calendar = gregorian
        style.locale = Locale(identifier: "en_GB")
        return date.formatted(style)
    }

    /// `26 Sep 2026, 14:02`
    public static func stamp(_ date: Date) -> String {
        var style = Date.FormatStyle(date: .abbreviated, time: .shortened)
        style.calendar = gregorian
        style.locale = Locale(identifier: "en_GB")
        return date.formatted(style)
    }

    /// `Unspecified`, `Key compromise`, …
    public static func reason(_ r: RevocationReason) -> String {
        switch r {
        case .unspecified: "Unspecified"
        case .keyCompromise: "Key compromise"
        case .caCompromise: "CA compromise"
        case .affiliationChanged: "Affiliation changed"
        case .superseded: "Superseded"
        case .cessationOfOperation: "Cessation of operation"
        case .certificateHold: "Certificate hold"
        case .removeFromCRL: "Remove from CRL"
        case .privilegeWithdrawn: "Privilege withdrawn"
        case .aaCompromise: "AA compromise"
        }
    }

    /// `1 hour`, `24 hours`, `7 days`
    public static func duration(_ seconds: TimeInterval) -> String {
        if seconds >= 86400, seconds.truncatingRemainder(dividingBy: 86400) == 0 {
            let d = Int(seconds / 86400)
            return "\(d) day\(d == 1 ? "" : "s")"
        }
        if seconds >= 3600, seconds.truncatingRemainder(dividingBy: 3600) == 0 {
            let h = Int(seconds / 3600)
            return "\(h) hour\(h == 1 ? "" : "s")"
        }
        let m = Int(seconds / 60)
        return "\(m) minute\(m == 1 ? "" : "s")"
    }
}
