import Foundation
import Store

/// A certificate in the GPO's Trusted Root Certification Authorities policy.
public struct TrustedRoot: Sendable, Hashable {
    /// Upper-case hex SHA-1 of the DER (the registry key name).
    public var thumbprint: String
    public var der: [UInt8]
    public var friendlyName: String?

    public init(der: [UInt8], friendlyName: String? = nil) {
        self.der = der
        self.friendlyName = friendlyName
        thumbprint = CertificateBlob.thumbprint(der)
    }

    /// `AB:CD…`, `ab cd …` or `abcd…` to `ABCD…`; nil unless 40 hex digits remain.
    public static func normalizedThumbprint(_ text: String) -> String? {
        let hex = text.filter { !$0.isWhitespace && $0 != ":" }.uppercased()
        guard hex.count == 40, hex.allSatisfy(\.isHexDigit) else { return nil }
        return hex
    }
}

/// The machine Registry.pol instructions of "Computer Configuration > Policies > Windows Settings
/// > Security Settings > Public Key Policies > Trusted Root Certification Authorities", which the
/// Registry CSE writes to `HKLM\Software\Policies\Microsoft\SystemCertificates\Root` — the
/// "Group Policy" physical store that crypt32 merges into the machine's Trusted Root store.
///
/// Layout (MS-GPEF §2.2.1 / §2.2.1.1 define it for the `EFS` store; the Public Key Policies
/// editor writes every store the same way):
///
///     [Software\Policies\Microsoft\SystemCertificates\Root\Certificates\<THUMBPRINT>;Blob;REG_BINARY;n;<CertificateBlob>]
///     [Software\Policies\Microsoft\SystemCertificates\Root\CRLs;;REG_NONE;0;]    (key only, "MUST be empty")
///     [Software\Policies\Microsoft\SystemCertificates\Root\CTLs;;REG_NONE;0;]    (key only)
///
/// The section is rewritten as a whole on every change: certificates sorted by thumbprint, then
/// the two empty keys; with no certificate left the section disappears.
public enum TrustedRootPolicy {
    public static let storeKey = #"Software\Policies\Microsoft\SystemCertificates\Root"#
    public static let certificatesKey = storeKey + #"\Certificates"#
    public static let blobValue = "Blob"

    /// The certificates in a policy file (entries that do not decode are skipped).
    public static func roots(in file: RegistryPolicyFile) -> [TrustedRoot] {
        var out: [TrustedRoot] = []
        for e in file.entries(under: certificatesKey)
        where e.valueName.caseInsensitiveCompare(blobValue) == .orderedSame && e.typeCode == RegistryValueType.binary.rawValue {
            guard let (props, der) = try? CertificateBlob.decode(e.data) else { continue }
            out.append(TrustedRoot(der: der, friendlyName: CertificateBlob.friendlyName(in: props)))
        }
        return out
    }

    /// Rewrites the Root section to hold exactly `roots`.
    public static func setRoots(_ roots: [TrustedRoot], in file: inout RegistryPolicyFile) {
        file.removeKey(storeKey)
        guard !roots.isEmpty else { return }
        var seen = Set<String>()
        for r in roots.sorted(by: { $0.thumbprint < $1.thumbprint }) where seen.insert(r.thumbprint).inserted {
            file.entries.append(.binary(certificatesKey + "\\" + r.thumbprint, blobValue,
                                        CertificateBlob.encode(der: r.der, friendlyName: r.friendlyName)))
        }
        file.entries.append(.createKey(storeKey + #"\CRLs"#))
        file.entries.append(.createKey(storeKey + #"\CTLs"#))
    }

    /// Adds (or replaces, when the friendly name differs) one certificate.
    public static func add(_ root: TrustedRoot, in file: inout RegistryPolicyFile) {
        var roots = self.roots(in: file).filter { $0.thumbprint != root.thumbprint }
        roots.append(root)
        setRoots(roots, in: &file)
    }

    /// Removes one certificate; returns whether it was there.
    @discardableResult
    public static func remove(thumbprint: String, in file: inout RegistryPolicyFile) -> Bool {
        let roots = self.roots(in: file)
        let kept = roots.filter { $0.thumbprint != thumbprint.uppercased() }
        guard kept.count != roots.count else { return false }
        setRoots(kept, in: &file)
        return true
    }
}

/// What the caller knows about a certificate (the SYSVOL module does not parse X.509; the CLI
/// passes the subject from swift-certificates).
public struct CACertificateInfo: Sendable, Hashable {
    public var der: [UInt8]
    /// The subject's CN, used for the directory object's name.
    public var commonName: String?
    /// The subject DN as text (`cACertificateDN`).
    public var subject: String

    public init(der: [UInt8], commonName: String?, subject: String) {
        self.der = der
        self.commonName = commonName
        self.subject = subject
    }

    public var thumbprint: String { CertificateBlob.thumbprint(der) }
}

/// `CN=Certification Authorities,CN=Public Key Services,CN=Services,<Configuration NC>`: the
/// enterprise trusted roots every member copies into its "Enterprise" Trusted Root store during
/// autoenrollment's "Update Issuer Stores" step (MS-CAESO §4.4.5.2), independent of any GPO.
/// Objects are `certificationAuthority` as `certutil -dspublish -f <cert> RootCA` makes them:
/// `cACertificate` (DER, multi-valued: a renewed CA with the same name gets a second value),
/// `authorityRevocationList` and `certificateRevocationList` (mustContain; a single NUL byte, as
/// certutil writes), `cACertificateDN`, `showInAdvancedViewOnly`.
///
/// `CN=NTAuthCertificates` (the CAs trusted for smart-card / PKINIT logon) is deliberately not
/// touched: an external root such as a RADIUS server's CA must not be trusted for domain logon.
public enum CertificationAuthorityDirectory {
    public static func publicKeyServicesDN(configurationDN: DN) -> DN {
        configurationDN.child(RDN("CN", "Services")).child(RDN("CN", "Public Key Services"))
    }

    public static func containerDN(configurationDN: DN) -> DN {
        publicKeyServicesDN(configurationDN: configurationDN).child(RDN("CN", "Certification Authorities"))
    }

    /// The object's CN: the certificate's CN "sanitized" the way certutil names CA objects
    /// (simplified from MS-WCCE "sanitized CA name": characters outside letters, digits, space, `-`, `.` and `_` become
    /// `!` + four lower-case hex digits), at most 64 characters (longer names keep 51 characters
    /// plus `-` and 12 thumbprint digits). No CN: the thumbprint.
    public static func objectName(commonName: String?, thumbprint: String) -> String {
        guard let cn = commonName?.trimmingCharacters(in: .whitespaces), !cn.isEmpty else { return thumbprint }
        var out = ""
        for u in cn.unicodeScalars {
            if (u.isASCII && (u.properties.isAlphabetic || ("0"..."9").contains(u))) || " -._".unicodeScalars.contains(u) {
                out.unicodeScalars.append(u)
            } else {
                for unit in String(u).utf16 { out += "!" + String(format: "%04x", unit) }
            }
        }
        if out.count > 64 { out = String(out.prefix(51)) + "-" + String(thumbprint.prefix(12)) }
        return out
    }

    /// Creates `CN=Public Key Services` and `CN=Certification Authorities` when missing.
    static func ensureContainers(store: DirectoryStore, configurationDN: DN) async throws {
        let services = configurationDN.child(RDN("CN", "Services"))
        let pks = publicKeyServicesDN(configurationDN: configurationDN)
        for (parent, name) in [(services, "Public Key Services"), (pks, "Certification Authorities")] {
            if try await store.id(of: parent.child(RDN("CN", name))) == nil {
                try await store.create(parent: parent, rdn: RDN("CN", name), objectClass: "container",
                                       strings: ["showInAdvancedViewOnly": ["TRUE"]])
            }
        }
    }

    /// Publishes a CA certificate. Returns the object's DN and whether anything changed.
    @discardableResult
    public static func publish(_ ca: CACertificateInfo, store: DirectoryStore) async throws -> (dn: DN, changed: Bool) {
        let info = try await store.domainInfo()
        try await ensureContainers(store: store, configurationDN: info.configurationDN)
        let container = containerDN(configurationDN: info.configurationDN)
        // Already published under any name?
        for entry in try await store.search(base: container, scope: .oneLevel, attrs: ["cACertificate"])
        where entry.values("cACertificate").contains(ca.der) {
            return (entry.dn, false)
        }
        let name = objectName(commonName: ca.commonName, thumbprint: ca.thumbprint)
        let dn = container.child(RDN("CN", name))
        if let existing = try await store.read(dn: dn, attrs: ["cACertificate"]) {
            try await store.update(id: existing.id, ops: [.add("cACertificate", [ca.der])])
            return (dn, true)
        }
        try await store.create(parent: container, rdn: RDN("CN", name), objectClass: "certificationAuthority", attributes: [
            "cACertificate": [ca.der],
            "authorityRevocationList": [[0]],
            "certificateRevocationList": [[0]],
            "cACertificateDN": [Array(ca.subject.utf8)],
            "showInAdvancedViewOnly": [Array("TRUE".utf8)],
        ])
        return (dn, true)
    }

    /// Removes the certificate with `thumbprint` from every object (deleting objects left with
    /// no `cACertificate`). Returns the DNs changed.
    @discardableResult
    public static func unpublish(thumbprint: String, store: DirectoryStore) async throws -> [DN] {
        let info = try await store.domainInfo()
        let container = containerDN(configurationDN: info.configurationDN)
        guard try await store.id(of: container) != nil else { return [] }
        var changed: [DN] = []
        for entry in try await store.search(base: container, scope: .oneLevel, attrs: ["cACertificate"]) {
            let values = entry.values("cACertificate")
            let matching = values.filter { CertificateBlob.thumbprint($0) == thumbprint.uppercased() }
            guard !matching.isEmpty else { continue }
            if matching.count == values.count {
                try await store.delete(id: entry.id)
            } else {
                try await store.update(id: entry.id, ops: [.delete("cACertificate", matching)])
            }
            changed.append(entry.dn)
        }
        return changed
    }

    /// Every published certificate: (object DN, DER).
    public static func published(store: DirectoryStore) async throws -> [(dn: DN, der: [UInt8])] {
        let info = try await store.domainInfo()
        let container = containerDN(configurationDN: info.configurationDN)
        guard try await store.id(of: container) != nil else { return [] }
        return try await store.search(base: container, scope: .oneLevel, attrs: ["cACertificate"])
            .flatMap { e in e.values("cACertificate").map { (e.dn, $0) } }
    }
}

/// Result of adding or removing a trusted root.
public struct TrustedRootChange: Sendable {
    public let thumbprint: String
    public let edit: GPOEditResult
    /// The `certificationAuthority` objects created or changed.
    public let directoryObjects: [DN]
}

extension GroupPolicyEditor {
    /// The trusted roots distributed by `gpo` (machine side).
    public func trustedRoots(_ gpo: DefaultGPO = .defaultDomainPolicy) async throws -> [TrustedRoot] {
        TrustedRootPolicy.roots(in: try await registryPolicy(gpo, scope: .machine))
    }

    /// Adds a root CA certificate to the GPO's Trusted Root policy and (with `publish`) to
    /// `CN=Certification Authorities` in the Configuration NC. Idempotent.
    public func addTrustedRoot(_ ca: CACertificateInfo, friendlyName: String? = nil,
                               gpo: DefaultGPO = .defaultDomainPolicy, publish: Bool = true) async throws -> TrustedRootChange {
        let root = TrustedRoot(der: ca.der, friendlyName: friendlyName)
        let edit = try await editRegistryPolicy(gpo, scope: .machine) { TrustedRootPolicy.add(root, in: &$0) }
        var objects: [DN] = []
        if publish {
            let (dn, changed) = try await CertificationAuthorityDirectory.publish(ca, store: store)
            if changed { objects.append(dn) }
        }
        return TrustedRootChange(thumbprint: root.thumbprint, edit: edit, directoryObjects: objects)
    }

    /// Removes a root by thumbprint from the GPO and (with `unpublish`) from the Configuration
    /// NC. Throws `unknownThumbprint` when it is in neither.
    public func removeTrustedRoot(thumbprint text: String, gpo: DefaultGPO = .defaultDomainPolicy,
                                  unpublish: Bool = true) async throws -> TrustedRootChange {
        guard let thumbprint = TrustedRoot.normalizedThumbprint(text) else {
            throw GroupPolicyError.invalidCertificate("\(text) is not a 40-digit hex SHA-1 thumbprint")
        }
        let edit = try await editRegistryPolicy(gpo, scope: .machine) { TrustedRootPolicy.remove(thumbprint: thumbprint, in: &$0) }
        let objects = unpublish ? try await CertificationAuthorityDirectory.unpublish(thumbprint: thumbprint, store: store) : []
        if !edit.changed && objects.isEmpty { throw GroupPolicyError.unknownThumbprint(thumbprint) }
        return TrustedRootChange(thumbprint: thumbprint, edit: edit, directoryObjects: objects)
    }
}
