import Foundation
import PKIKit
import SYSVOL
import Store

/// What the Overview needs to know about the directory: people, joined computers, whether the
/// CA is published as a trusted root, and the CA itself.
public struct DirectorySummary: Equatable, Sendable {
    /// Users other than the built-in Administrator, Guest and krbtgt.
    public var users: Int
    /// Computer accounts other than domain controllers.
    public var computers: Int
    /// The current CA is in the Default Domain Policy's trusted roots (pushed to joined Windows PCs).
    public var trustedRootPublished: Bool
    /// The current CA's name (`lab`) and subject.
    public var caName: String?
    public var caSubject: String?
    /// UI-1c: certificates the CA issued that are neither revoked nor expired.
    public var certificatesValid: Int = 0
    /// UI-1c: of those, the ones that expire within 30 days.
    public var certificatesExpiringSoon: Int = 0

    public init(users: Int = 0, computers: Int = 0, trustedRootPublished: Bool = false, caName: String? = nil,
                caSubject: String? = nil) {
        self.users = users
        self.computers = computers
        self.trustedRootPublished = trustedRootPublished
        self.caName = caName
        self.caSubject = caSubject
    }

    public static let builtInAccounts: Set<String> = ["administrator", "guest", "krbtgt"]

    /// Reads the counts from the store and the trusted roots from SYSVOL.
    public static func load(store: DirectoryStore, pki: LabPKI?, data: DataDirectory) async -> DirectorySummary {
        var s = DirectorySummary()
        guard let info = try? await store.domainInfo() else { return s }
        let oc = { (v: String) in FilterAST.equality(attribute: "objectClass", value: Array(v.utf8)) }
        if let users = try? await store.search(base: info.domainDN, scope: .subtree, filter: .and([oc("user"), .not(oc("computer"))]),
                                               attrs: ["sAMAccountName"]) {
            s.users = users.filter { !builtInAccounts.contains(($0.samAccountName ?? "").lowercased()) }.count
        }
        if let computers = try? await store.search(base: info.domainDN, scope: .subtree, filter: oc("computer"),
                                                   attrs: ["userAccountControl"]) {
            s.computers = computers.filter {
                UInt32(truncatingIfNeeded: $0.int("userAccountControl") ?? 0) & UserAccountControl.serverTrustAccount == 0
            }.count
        }
        if let issued = try? await store.issuedCertificates() {
            let now = Date()
            let valid = issued.filter { !$0.revoked && $0.notAfter > now }
            s.certificatesValid = valid.count
            s.certificatesExpiringSoon = valid.filter { $0.notAfter <= now.addingTimeInterval(30 * 86_400) }.count
        }
        if let pki, let ca = try? await pki.currentAuthority() {
            s.caName = ca.name
            s.caSubject = ca.certificate.subject.description
            if let der = try? ca.der() {
                let thumbprint = CertificateBlob.thumbprint(der)
                let editor = GroupPolicyEditor(root: data.sysvolURL, store: store)
                if let roots = try? await editor.trustedRoots() {
                    s.trustedRootPublished = roots.contains { $0.thumbprint == thumbprint }
                }
            }
        }
        return s
    }
}

/// The Overview "Next steps" line: what is still empty, in the order to do it.
public enum NextStep: String, CaseIterable, Identifiable, Sendable {
    case addUser
    case connectDevice
    case publishCA

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .addUser: "Add a user"
        case .connectDevice: "Connect a device"
        case .publishCA: "Publish CA"
        }
    }

    public var detail: String {
        switch self {
        case .addUser: "Only the built-in Administrator exists. People sign in with their own account."
        case .connectDevice: "No computer has joined the domain yet. Connect shows the steps for each kind of device."
        case .publishCA: "Joined Windows PCs trust the lab CA once it is in the Default Domain Policy."
        }
    }

    public var symbol: String {
        switch self {
        case .addUser: "person.badge.plus"
        case .connectDevice: "laptopcomputer.and.arrow.down"
        case .publishCA: "checkmark.seal"
        }
    }

    /// The hints for `summary` (empty when everything is in place).
    public static func hints(for summary: DirectorySummary) -> [NextStep] {
        var out: [NextStep] = []
        if summary.users == 0 { out.append(.addUser) }
        if summary.computers == 0 { out.append(.connectDevice) }
        if !summary.trustedRootPublished { out.append(.publishCA) }
        return out
    }
}
