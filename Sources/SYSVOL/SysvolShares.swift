import Foundation

/// One read-only disk share backed by a folder (what WP-X hands to SMBKit).
public struct SysvolShare: Sendable, Hashable {
    /// Share name as clients type it (`SYSVOL`, `NETLOGON`); matched case-insensitively.
    public let name: String
    /// Backing folder.
    public let path: URL
    /// `shi1_remark` for srvsvc `NetrShareEnum`.
    public let remark: String
    /// SYSVOL and NETLOGON are served read-only.
    public let readOnly: Bool

    public init(name: String, path: URL, remark: String = "Logon server share", readOnly: Bool = true) {
        self.name = name
        self.path = path
        self.remark = remark
        self.readOnly = readOnly
    }
}

/// The two domain controller disk shares:
/// `SYSVOL` -> `<root>` and `NETLOGON` -> `<root>/<dnsDomain>/scripts`.
public struct SysvolShares: Sendable, Hashable {
    public let sysvol: SysvolShare
    public let netlogon: SysvolShare

    public init(root: URL, dnsDomain: String) {
        sysvol = SysvolShare(name: "SYSVOL", path: root)
        netlogon = SysvolShare(name: "NETLOGON",
                               path: root.appendingPathComponent(dnsDomain, isDirectory: true)
                                   .appendingPathComponent("scripts", isDirectory: true))
    }

    /// Finds the domain folder under `root` (the one sub-folder holding `scripts`), for callers
    /// that only know the SYSVOL root. Throws when there is not exactly one.
    public init(root: URL) throws {
        let fm = FileManager.default
        let names = (try? fm.contentsOfDirectory(atPath: root.path)) ?? []
        let domains = names.filter { name in
            var isDir: ObjCBool = false
            let scripts = root.appendingPathComponent(name).appendingPathComponent("scripts").path
            return fm.fileExists(atPath: scripts, isDirectory: &isDir) && isDir.boolValue
        }
        guard domains.count == 1 else {
            throw SysvolError.unexpectedItem("\(root.path): expected one <dnsDomain>/scripts folder, found \(domains.count)")
        }
        self.init(root: root, dnsDomain: domains[0])
    }

    /// `[SYSVOL, NETLOGON]`.
    public var all: [SysvolShare] { [sysvol, netlogon] }

    /// Case-insensitive lookup by share name.
    public func share(named name: String) -> SysvolShare? {
        all.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }
}
