import CryptoKit
import Foundation
import MSPAC
import Store

/// PK-5: how a `CertificateTemplate` (PK-1 store row) is published as a `pKICertificateTemplate`
/// object in `CN=Certificate Templates,CN=Public Key Services,CN=Services,<Configuration NC>`,
/// with the attribute encodings of MS-CRTD. Every value and its source is listed in
/// docs/notes/pk-5.md.
public enum TemplateDirectory {
    // MARK: Extended rights (MS-CRTD §2.5.2 table)

    /// `Certificate-Enrollment` control access right.
    public static let enrollRight = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    /// `Certificate-AutoEnrollment` control access right.
    public static let autoEnrollRight = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

    // MARK: flags (MS-CRTD §2.4)

    public static let flagAutoEnrollment: Int64 = 0x20
    public static let flagMachineType: Int64 = 0x40
    public static let flagIsCA: Int64 = 0x80
    public static let flagIsModified: Int64 = 0x20000

    // MARK: msPKI-Enrollment-Flag (MS-CRTD §2.26)

    public static let enrollPublishToDS: Int64 = 0x08
    public static let enrollAutoEnrollment: Int64 = 0x20

    // MARK: msPKI-Certificate-Name-Flag (MS-CRTD §2.28)

    public static let nameEnrolleeSuppliesSubject: UInt32 = 0x0000_0001
    public static let nameSubjectAltRequireUPN: UInt32 = 0x0200_0000
    public static let nameSubjectAltRequireDNS: UInt32 = 0x0800_0000
    public static let nameSubjectRequireDNSAsCN: UInt32 = 0x1000_0000
    public static let nameSubjectRequireCommonName: UInt32 = 0x4000_0000

    /// `msPKI-Private-Key-Flag` client/server compatibility nibbles (MS-CRTD §2.27, MS-WCCE
    /// §3.1.2.4.2.2.2.8 / §3.2.2.6.2.1.4.5.7): 0x0Y0Z0000 with Y = minimum client version,
    /// Z = minimum CA version. Schema 2: 1/1 (Windows XP / Server 2003); schema 3: 2/2 (Vista / 2008).
    public static func privateKeyFlag(schemaVersion: Int) -> Int64 {
        schemaVersion >= 3 ? 0x0202_0000 : 0x0101_0000
    }

    // MARK: Encodings

    /// `pKIExpirationPeriod` / `pKIOverlapPeriod` (MS-CRTD §2.11 / §2.15): a FILETIME interval,
    /// i.e. the *negative* number of 100 ns ticks as a little-endian 64-bit integer.
    /// 365 days → `00 40 39 87 2e e1 fe ff`, 42 days → `00 80 a6 0a ff de ff ff`.
    public static func fileTimeInterval(days: Int) -> [UInt8] {
        let ticks = -Int64(days) * 86_400 * 10_000_000
        return (0..<8).map { UInt8(truncatingIfNeeded: UInt64(bitPattern: ticks) >> (8 * UInt64($0))) }
    }

    /// The inverse of `fileTimeInterval` (whole seconds; nil unless 8 bytes).
    public static func interval(fromFileTime bytes: [UInt8]) -> TimeInterval? {
        guard bytes.count == 8 else { return nil }
        let raw = bytes.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
        return -TimeInterval(Int64(bitPattern: raw)) / 10_000_000
    }

    /// certutil's rendering of a period: `1 Years`, `6 Weeks`, `2 Days`.
    public static func describePeriod(_ bytes: [UInt8]) -> String {
        guard let seconds = interval(fromFileTime: bytes) else { return "?" }
        let days = Int((seconds / 86_400).rounded())
        if days > 0, days % 365 == 0 { return "\(days / 365) Years" }
        if days > 0, days % 7 == 0 { return "\(days / 7) Weeks" }
        if Double(days) * 86_400 == seconds { return "\(days) Days" }
        return "\(Int(seconds / 3600)) Hours"
    }

    /// `pKIKeyUsage` (MS-CRTD §2.13): the KeyUsage BIT STRING's content bytes without the
    /// unused-bits octet, always two bytes as Windows writes them — X.509 bit i is bit (7 − i % 8)
    /// of byte i / 8. digitalSignature | keyEncipherment → `a0 00` (the MS-CRTD §3 example).
    public static func keyUsageBytes(_ usage: TemplateKeyUsage) -> [UInt8] {
        var out: [UInt8] = [0, 0]
        for bit in 0..<9 where usage.rawValue & (1 << bit) != 0 { out[bit / 8] |= 0x80 >> UInt8(bit % 8) }
        return out
    }

    /// The inverse of `keyUsageBytes`.
    public static func keyUsage(fromBytes bytes: [UInt8]) -> TemplateKeyUsage {
        var raw = 0
        for bit in 0..<9 where bit / 8 < bytes.count && bytes[bit / 8] & (0x80 >> UInt8(bit % 8)) != 0 { raw |= 1 << bit }
        return TemplateKeyUsage(rawValue: raw)
    }

    /// A 32-bit flag word as AD stores an INTEGER: signed decimal (`0xa6000000` → `-1509949440`).
    public static func signed32(_ v: UInt32) -> String { String(Int32(bitPattern: v)) }

    // MARK: Template → attributes

    /// Schema 2 (CryptoAPI CSPs, Windows Server 2003 compatibility) while the template accepts
    /// RSA keys — Windows autoenrollment then generates RSA keys of `msPKI-Minimal-Key-Size`.
    /// EC-only templates need schema 3 (CNG: a KSP and `msPKI-RA-Application-Policies`
    /// naming the curve, MS-CRTD §2.23.2).
    public static func schemaVersion(_ t: CertificateTemplate) -> Int { t.allowedKeyTypes.contains("rsa") ? 2 : 3 }

    /// Machine templates (enrolled in the computer context, `certlm.msc`): everything that is
    /// not a user (UPN) or CA template.
    public static func isMachineTemplate(_ t: CertificateTemplate) -> Bool { t.sanPolicy != .upn && !t.isCA }

    public static func generalFlags(_ t: CertificateTemplate) -> Int64 {
        var f = flagIsModified
        if isMachineTemplate(t) { f |= flagMachineType }
        if t.autoEnroll { f |= flagAutoEnrollment }
        if t.isCA { f |= flagIsCA }
        return f
    }

    public static func enrollmentFlag(_ t: CertificateTemplate) -> Int64 {
        var f: Int64 = 0
        if t.autoEnroll { f |= enrollAutoEnrollment }
        // PK-6 appends certificates issued for an account (dNSHostName / UPN templates) to its
        // userCertificate, as CT_FLAG_PUBLISH_TO_DS tells the client it will.
        if t.sanPolicy == .dnsHostName || t.sanPolicy == .upn { f |= enrollPublishToDS }
        return f
    }

    public static func certificateNameFlag(_ t: CertificateTemplate) -> UInt32 {
        switch t.sanPolicy {
        case .dnsHostName: nameSubjectAltRequireDNS | nameSubjectRequireDNSAsCN     // 0x18000000, Windows' Machine
        case .upn: nameSubjectAltRequireUPN | nameSubjectRequireCommonName          // SAN UPN, CN=<sAMAccountName>
        case .fromRequest, .none: nameEnrolleeSuppliesSubject                      // WebServer / SubCA
        }
    }

    /// Curves the template accepts, smallest first (`p256` → 256).
    static func curveBits(_ t: CertificateTemplate) -> [Int] {
        t.allowedKeyTypes.compactMap { k -> Int? in
            switch k.lowercased() {
            case "p256": 256
            case "p384": 384
            case "p521": 521
            default: nil
            }
        }.sorted()
    }

    public static func minimalKeySize(_ t: CertificateTemplate) -> Int {
        schemaVersion(t) == 2 ? t.minKeyBits : (curveBits(t).first ?? 256)
    }

    /// `pKIDefaultCSPs` (MS-CRTD §2.8, `<priority>,<provider>`): the providers Windows' own
    /// schema-1/2 templates list (Machine / WebServer: RSA SChannel; User / others: Enhanced),
    /// or the Software KSP for CNG (schema 3).
    public static func defaultCSPs(_ t: CertificateTemplate) -> [String] {
        if schemaVersion(t) >= 3 { return ["1,Microsoft Software Key Storage Provider"] }
        return isMachineTemplate(t) ? ["1,Microsoft RSA SChannel Cryptographic Provider"]
            : ["1,Microsoft Enhanced Cryptographic Provider v1.0"]
    }

    /// `pKIDefaultKeySpec` (MS-CRTD §2.9): AT_KEYEXCHANGE (1) for RSA templates whose key usage
    /// includes keyEncipherment, else AT_SIGNATURE (2).
    public static func defaultKeySpec(_ t: CertificateTemplate) -> Int {
        schemaVersion(t) == 2 && t.keyUsage.contains(.keyEncipherment) ? 1 : 2
    }

    /// Schema 3 only: the CNG properties (MS-CRTD §2.23.2 syntax 2, grave-accent triplets).
    public static func raApplicationPolicies(_ t: CertificateTemplate) -> [String] {
        guard schemaVersion(t) >= 3 else { return [] }
        let bits = curveBits(t).first ?? 256
        let hash = bits >= 521 ? "SHA512" : bits >= 384 ? "SHA384" : "SHA256"
        return ["msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P\(bits)`msPKI-Hash-Algorithm`PZPWSTR`\(hash)`"
            + "msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`"]
    }

    /// Extensions PK-1 marks critical in what it issues: basicConstraints and keyUsage.
    public static let criticalExtensions = ["2.5.29.19", "2.5.29.15"]

    /// The template's security descriptor: owner/group Enterprise Admins, protected DACL with
    /// full control minus extended rights (CC DC LC SW RP WP DT LO SD RC WD WO, as Windows' default
    /// templates) for Enterprise Admins, Domain Admins and SYSTEM, Read (RP LC LO RC) for
    /// Authenticated Users, and for every SID in `enrolAllowedGroupSIDs` an Enroll object ACE plus,
    /// on auto-enroll templates, an AutoEnroll object ACE (MS-CRTD §2.5.1 / §2.5.2).
    public static func securityDescriptorSDDL(_ t: CertificateTemplate) -> String {
        // Windows' default templates give admins every right *except* control access (CR):
        // an ACCESS_ALLOWED_ACE with CR would grant Enroll and AutoEnroll on every template
        // (MS-CRTD §2.5.1 / §2.5.2 accept a plain allow ACE with that bit).
        let full = "CCDCLCSWRPWPDTLOSDRCWDWO"
        var sddl = "O:EAG:EAD:PAI(A;;\(full);;;EA)(A;;\(full);;;DA)(A;;\(full);;;SY)(A;;RPLCLORC;;;AU)"
        for sid in t.enrolAllowedGroupSIDs {
            sddl += "(OA;;CR;\(enrollRight);;\(sid))"
            if t.autoEnroll { sddl += "(OA;;CR;\(autoEnrollRight);;\(sid))" }
        }
        return sddl
    }

    /// Every attribute of the template object except `cn`/`objectClass` (values as the store
    /// keeps them: text for strings and integers, raw bytes for octet strings).
    public static func attributes(_ t: CertificateTemplate, domainSID: SID) throws -> [String: [[UInt8]]] {
        func s(_ v: String) -> [UInt8] { Array(v.utf8) }
        let schema = schemaVersion(t)
        var a: [String: [[UInt8]]] = [
            "displayName": [s(t.displayName)],
            "showInAdvancedViewOnly": [s("TRUE")],
            "flags": [s(String(generalFlags(t)))],
            "revision": [s(String(CertificateTemplate.majorVersion))],
            "msPKI-Template-Schema-Version": [s(String(schema))],
            "msPKI-Template-Minor-Revision": [s(String(CertificateTemplate.minorVersion))],
            "msPKI-Cert-Template-OID": [s(t.oid)],
            "pKIKeyUsage": [keyUsageBytes(t.keyUsage)],
            "pKIExpirationPeriod": [fileTimeInterval(days: t.validityDays)],
            "pKIOverlapPeriod": [fileTimeInterval(days: t.renewalDays)],
            "pKIMaxIssuingDepth": [s("0")],
            "pKICriticalExtensions": criticalExtensions.map(s),
            "pKIDefaultKeySpec": [s(String(defaultKeySpec(t)))],
            "pKIDefaultCSPs": defaultCSPs(t).map(s),
            "msPKI-RA-Signature": [s("0")],
            "msPKI-Minimal-Key-Size": [s(String(minimalKeySize(t)))],
            "msPKI-Enrollment-Flag": [s(String(enrollmentFlag(t)))],
            "msPKI-Private-Key-Flag": [s(String(privateKeyFlag(schemaVersion: schema)))],
            "msPKI-Certificate-Name-Flag": [s(signed32(certificateNameFlag(t)))],
            "nTSecurityDescriptor": [try SecurityDescriptor.fromSDDL(securityDescriptorSDDL(t), domainSID: domainSID)],
        ]
        if !t.ekus.isEmpty {
            a["pKIExtendedKeyUsage"] = t.ekus.map(s)
            a["msPKI-Certificate-Application-Policy"] = t.ekus.map(s)
        }
        let ra = raApplicationPolicies(t)
        if !ra.isEmpty { a["msPKI-RA-Application-Policies"] = ra.map(s) }
        return a
    }

    /// Attributes a republish may remove when the template no longer has them.
    static let optionalAttributes = ["pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                                     "msPKI-RA-Application-Policies"]

    // MARK: Enterprise OID objects (CN=OID)

    /// `msPKI-Enterprise-Oid` `flags` for a template OID (certca.h `CERT_OID_TYPE_TEMPLATE`).
    public static let oidTypeTemplate = 1

    /// The CN Windows gives an enterprise OID object: `<last arc>.<32 hex digits>`. Windows
    /// derives the hex part from the OID; we use MD5 of the dotted OID (clients look objects up
    /// by `msPKI-Cert-Template-OID`, never by CN).
    public static func oidObjectName(_ oid: String) -> String {
        let last = oid.split(separator: ".").last.map(String.init) ?? oid
        return last + "." + md5Hex(oid)
    }

    static func md5Hex(_ text: String) -> String {
        Insecure.MD5.hash(data: Data(text.utf8)).map { String(format: "%02X", $0) }.joined()
    }
}
