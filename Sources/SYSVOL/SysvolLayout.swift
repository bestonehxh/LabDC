import Foundation
import Store
import os

/// Errors of the SYSVOL module.
public enum SysvolError: Error, CustomStringConvertible, Sendable {
    /// The store has no domain yet.
    case notProvisioned
    /// A folder or file could not be created.
    case filesystem(String)
    /// A path exists but has the wrong type (a file where a folder belongs, or the reverse).
    case unexpectedItem(String)
    /// The object a GPO is linked on is missing.
    case missingLinkTarget(String)

    public var description: String {
        switch self {
        case .notProvisioned: "SYSVOL: the directory store is not provisioned"
        case .filesystem(let s): "SYSVOL: \(s)"
        case .unexpectedItem(let s): "SYSVOL: unexpected item at \(s)"
        case .missingLinkTarget(let s): "SYSVOL: GPO link target \(s) does not exist"
        }
    }
}

/// What one `SysvolLayout.ensure` run changed. Empty on a re-run.
public struct SysvolEnsureResult: Sendable, Equatable {
    /// Folders and files created, relative to the SYSVOL root (`lab.sheep/Policies/...`).
    public var createdPaths: [String] = []
    /// DNs of directory objects created.
    public var createdObjects: [String] = []
    /// DNs of objects whose `gPLink`/`gPOptions` were set.
    public var modifiedObjects: [String] = []
    /// The two shares to export.
    public var shares: SysvolShares
    /// GPOs whose GPC object this run created (for the `serve` / `gpo init` log).
    public var createdGPOs: [DefaultGPO] = []

    public var isNoOp: Bool { createdPaths.isEmpty && createdObjects.isEmpty && modifiedObjects.isEmpty }
}

/// Creates the SYSVOL folder tree and the default GPO objects (idempotent).
///
/// Folder tree under `root` (every folder 0700, files 0600):
///
///     <dnsDomain>/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
///     <dnsDomain>/Policies/{31B2F340-...}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
///     <dnsDomain>/Policies/{31B2F340-...}/USER/
///     <dnsDomain>/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/... (same shape)
///     <dnsDomain>/scripts/                       (the NETLOGON share)
///
/// Directory objects: `CN=<guid>,CN=Policies,CN=System,<domain>` (`groupPolicyContainer`) with
/// `CN=Machine` and `CN=User` below, and `gPLink`/`gPOptions` on the domain root and
/// `OU=Domain Controllers`. Existing files, objects and links are left alone, so a re-run changes
/// nothing (and never rewrites a template an administrator edited).
public enum SysvolLayout {
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "SYSVOL")

    /// `nTSecurityDescriptor` of the GPCs: Samba's default GPO descriptor minus the SACL. The
    /// `OA;;CR;edacfd8f-...;;AU` ACE is the Apply-Group-Policy right the GP client checks before
    /// it applies a GPO (MS-GPOL §3.2.5.1.6 security filtering).
    public static let gpoSDDL =
        "O:DAG:DAD:PAI(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;;RPWPCCDCLCLORCWOWDSDDTSW;;;DA)"
        + "(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIIO;RPWPCCDCLCLORCWOWDSDDTSW;;;CO)"
        + "(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)"
        + "(A;CI;RPLCLORC;;;AU)(A;CI;RPLCLORC;;;ED)"

    @discardableResult
    public static func ensure(root: URL, store: DirectoryStore) async throws -> SysvolEnsureResult {
        guard await store.isProvisioned else { throw SysvolError.notProvisioned }
        let info = try await store.domainInfo()
        let dns = info.dnsDomain
        var result = SysvolEnsureResult(shares: SysvolShares(root: root, dnsDomain: dns))

        // Folders and files.
        var fs = FolderWriter(root: root)
        try fs.directory("")
        try fs.directory(dns)
        try fs.directory("\(dns)/Policies")
        try fs.directory("\(dns)/scripts")
        let access = try await SystemAccessPolicy.from(store: store)
        for gpo in DefaultGPO.all {
            let base = "\(dns)/Policies/\(gpo.guid)"
            try fs.directory(base)
            try fs.file("\(base)/GPT.INI", DefaultGPO.gptINI)
            try fs.directory("\(base)/USER")
            try fs.directory("\(base)/MACHINE")
            try fs.directory("\(base)/MACHINE/Microsoft")
            try fs.directory("\(base)/MACHINE/Microsoft/Windows NT")
            try fs.directory("\(base)/MACHINE/Microsoft/Windows NT/SecEdit")
            try fs.file("\(base)/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf", gpo.encodedTemplate(access))
        }
        result.createdPaths = fs.created

        // Directory objects.
        let sd = try SecurityDescriptor.fromSDDL(gpoSDDL, domainSID: info.domainSID)
        for gpo in DefaultGPO.all {
            let dn = gpo.dn(domainDN: info.domainDN)
            if try await store.id(of: dn) == nil {
                func s(_ v: String) -> [[UInt8]] { [Array(v.utf8)] }
                try await store.create(parent: DefaultGPO.policiesDN(domainDN: info.domainDN), rdn: RDN("CN", gpo.guid),
                                       objectClass: "groupPolicyContainer", attributes: [
                                           "displayName": s(gpo.displayName),
                                           "gPCFileSysPath": s(gpo.fileSysPath(dnsDomain: dns)),
                                           "gPCFunctionalityVersion": s("2"),
                                           "versionNumber": s("0"),
                                           "flags": s("0"),
                                           "gPCMachineExtensionNames": s(DefaultGPO.secEditMachineExtensionNames),
                                           "isCriticalSystemObject": s("TRUE"),
                                           "showInAdvancedViewOnly": s("TRUE"),
                                           "nTSecurityDescriptor": [sd],
                                       ])
                result.createdObjects.append(dn.description)
                result.createdGPOs.append(gpo)
            } else if let gpc = try await store.read(dn: dn, attrs: ["gPCFileSysPath"]),
                      let path = gpc.string("gPCFileSysPath"), path != gpo.fileSysPath(dnsDomain: dns),
                      path.caseInsensitiveCompare(gpo.fileSysPath(dnsDomain: dns)) == .orderedSame {
                // WP-W wrote `\\dom\sysvol\...`; Windows spells it `SysVol`.
                try await store.update(id: gpc.id, ops: [.replace("gPCFileSysPath", strings: [gpo.fileSysPath(dnsDomain: dns)])])
                result.modifiedObjects.append(dn.description)
            }
            for child in ["Machine", "User"] {
                guard try await store.id(of: dn.child(RDN("CN", child))) == nil else { continue }
                try await store.create(parent: dn, rdn: RDN("CN", child), objectClass: "container",
                                       attributes: ["showInAdvancedViewOnly": [Array("TRUE".utf8)]])
                result.createdObjects.append(dn.child(RDN("CN", child)).description)
            }

            // Link.
            let target = gpo.linkedDN(domainDN: info.domainDN)
            guard let entry = try await store.read(dn: target, attrs: ["gPLink", "gPOptions"]) else {
                throw SysvolError.missingLinkTarget(target.description)
            }
            var ops: [ModifyOp] = []
            let current = entry.string("gPLink") ?? ""
            if !current.lowercased().contains("cn=\(gpo.guid.lowercased()),") {
                ops.append(.replace("gPLink", strings: [current + gpo.gPLinkElement(domainDN: info.domainDN)]))
            }
            if !entry.has("gPOptions") { ops.append(.replace("gPOptions", strings: ["0"])) }
            if !ops.isEmpty {
                try await store.update(id: entry.id, ops: ops)
                result.modifiedObjects.append(target.description)
            }
        }
        if !result.isNoOp {
            logger.notice("""
                SYSVOL ensured at \(root.path, privacy: .public): \(result.createdPaths.count) paths, \
                \(result.createdObjects.count) objects created, \(result.modifiedObjects.count) linked
                """)
        }
        return result
    }
}

/// Creates folders (0700) and files (0600) below a root, never overwriting.
struct FolderWriter {
    let root: URL
    var created: [String] = []
    private let fm = FileManager.default

    init(root: URL) { self.root = root }

    func url(_ relative: String) -> URL {
        relative.isEmpty ? root : root.appendingPathComponent(relative, isDirectory: false)
    }

    mutating func directory(_ relative: String) throws {
        let u = url(relative)
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: u.path, isDirectory: &isDir) {
            guard isDir.boolValue else { throw SysvolError.unexpectedItem(u.path) }
            return
        }
        do {
            try fm.createDirectory(at: u, withIntermediateDirectories: relative.isEmpty,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            throw SysvolError.filesystem("cannot create folder \(u.path): \(error.localizedDescription)")
        }
        if !relative.isEmpty { created.append(relative + "/") }
    }

    mutating func file(_ relative: String, _ bytes: [UInt8]) throws {
        let u = url(relative)
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: u.path, isDirectory: &isDir) {
            guard !isDir.boolValue else { throw SysvolError.unexpectedItem(u.path) }
            return
        }
        guard fm.createFile(atPath: u.path, contents: Data(bytes), attributes: [.posixPermissions: 0o600]) else {
            throw SysvolError.filesystem("cannot write \(u.path)")
        }
        created.append(relative)
    }
}
