import Darwin
import Foundation

/// A share the server exports.
public struct SMBShare: Sendable, Hashable {
    public enum Kind: Sendable, Hashable {
        /// `IPC$`: named pipes only.
        case ipc
        /// A read-only disk share backed by a folder.
        case readOnlyFolder(path: String)
    }

    public var name: String
    public var kind: Kind
    public var comment: String

    public init(name: String, kind: Kind, comment: String = "") {
        self.name = name
        self.kind = kind
        self.comment = comment
    }

    public static let ipc = SMBShare(name: "IPC$", kind: .ipc, comment: "Remote IPC")

    /// `IPC$`, `SYSVOL` (the folder) and `NETLOGON` (`<sysvol>/<dnsDomain>/scripts`), as a DC exports them.
    public static func domainController(sysvol: String, dnsDomain: String) -> [SMBShare] {
        [.ipc,
         SMBShare(name: "SYSVOL", kind: .readOnlyFolder(path: sysvol), comment: "Logon server share"),
         SMBShare(name: "NETLOGON", kind: .readOnlyFolder(path: (sysvol as NSString).appendingPathComponent("\(dnsDomain)/scripts")),
                  comment: "Logon server share")]
    }
}

/// One file or directory of a folder share, from `lstat`.
struct FSNode: Sendable {
    var path: String
    var name: String
    var isDirectory: Bool
    var size: UInt64
    var allocation: UInt64
    var inode: UInt64
    var creation: UInt64
    var lastAccess: UInt64
    var lastWrite: UInt64
    var change: UInt64

    init?(path: String, name: String) {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        let mode = st.st_mode & S_IFMT
        guard mode == S_IFDIR || mode == S_IFREG else { return nil }
        self.path = path
        self.name = name
        isDirectory = mode == S_IFDIR
        size = isDirectory ? 0 : UInt64(max(0, st.st_size))
        allocation = isDirectory ? 0 : (size + 4095) / 4096 * 4096
        inode = UInt64(st.st_ino)
        func ft(_ t: timespec) -> UInt64 { FileTime.from(Date(timeIntervalSince1970: Double(t.tv_sec) + Double(t.tv_nsec) / 1e9)) }
        creation = ft(st.st_birthtimespec)
        lastAccess = ft(st.st_atimespec)
        lastWrite = ft(st.st_mtimespec)
        change = ft(st.st_ctimespec)
    }

    var attributes: UInt32 {
        var a = isDirectory ? FileAttributes.directory : FileAttributes.archive
        if name.hasPrefix("."), name != ".", name != ".." { a |= FileAttributes.hidden }
        return a
    }

    var times: SMB2FileTimes {
        var t = SMB2FileTimes()
        t.creation = creation
        t.lastAccess = lastAccess
        t.lastWrite = lastWrite
        t.change = change
        t.allocationSize = allocation
        t.endOfFile = size
        t.attributes = attributes
        return t
    }
}

/// Maps SMB2 names (backslash separated, relative to the share root, case-insensitive) to
/// paths below a folder, never escaping it.
struct FolderResolver: Sendable {
    let root: String

    init(root: String) {
        self.root = (root as NSString).resolvingSymlinksInPath
    }

    enum Resolution {
        case found(FSNode, relative: String)
        case failed(UInt32)
    }

    func resolve(_ smbName: String) -> Resolution {
        var name = smbName
        while name.hasPrefix("\\") { name.removeFirst() }
        // Streams: only the default data stream exists.
        if let colon = name.firstIndex(of: ":") {
            let stream = name[colon...].lowercased()
            guard stream == "::$data" else { return .failed(NTStatus.objectNameNotFound) }
            name = String(name[..<colon])
        }
        let parts = name.split(separator: "\\", omittingEmptySubsequences: true).map(String.init)
        var path = root
        var relative: [String] = []
        for (i, part) in parts.enumerated() {
            if part == "." { continue }
            if part == ".." || part.contains("/") || part.contains("\0") || part.contains("*") || part.contains("?") {
                return .failed(NTStatus.objectNameInvalid)
            }
            let last = i == parts.count - 1
            var candidate = (path as NSString).appendingPathComponent(part)
            var st = stat()
            if lstat(candidate, &st) != 0 {
                // Case-insensitive fallback for case-sensitive volumes.
                guard let entries = try? FileManager.default.contentsOfDirectory(atPath: path),
                      let match = entries.first(where: { $0.caseInsensitiveCompare(part) == .orderedSame }) else {
                    return .failed(last ? NTStatus.objectNameNotFound : NTStatus.objectPathNotFound)
                }
                candidate = (path as NSString).appendingPathComponent(match)
            }
            path = candidate
            relative.append((candidate as NSString).lastPathComponent)
        }
        // Symlinks must stay inside the share.
        let real = (path as NSString).resolvingSymlinksInPath
        guard real == root || real.hasPrefix(root.hasSuffix("/") ? root : root + "/") else {
            return .failed(NTStatus.accessDenied)
        }
        guard let node = FSNode(path: real, name: relative.last ?? "") else {
            return .failed(NTStatus.objectNameNotFound)
        }
        return .found(node, relative: relative.joined(separator: "\\"))
    }

    /// Directory entries (without `.`/`..`), sorted by name.
    func list(_ dir: FSNode) -> [FSNode] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return names.sorted().compactMap { n in
            let p = (dir.path as NSString).appendingPathComponent(n)
            let real = (p as NSString).resolvingSymlinksInPath
            guard real == root || real.hasPrefix(root + "/") else { return nil }
            return FSNode(path: real, name: n)
        }
    }

    /// Volume statistics of the folder's file system.
    func volume() -> (total: UInt64, free: UInt64, blockSize: UInt32) {
        var s = statfs()
        guard statfs(root, &s) == 0 else { return (0, 0, 4096) }
        return (UInt64(s.f_blocks), UInt64(s.f_bavail), UInt32(s.f_bsize))
    }
}

/// Windows wildcard matching for QUERY_DIRECTORY (MS-FSA §2.1.4.4): `*`, `?`, and the DOS
/// forms `<` (DOS_STAR), `>` (DOS_QM), `"` (DOS_DOT), case-insensitive.
enum Wildcard {
    static func matches(_ name: String, pattern: String) -> Bool {
        if pattern.isEmpty || pattern == "*" || pattern == "*.*" || pattern == "<.*" { return true }
        let n = Array(name.uppercased().unicodeScalars)
        let p = Array(pattern.uppercased().unicodeScalars)
        return match(n, 0, p, 0, depth: 0)
    }

    private static func match(_ n: [Unicode.Scalar], _ i: Int, _ p: [Unicode.Scalar], _ j: Int, depth: Int) -> Bool {
        if depth > 64 { return false }
        var i = i, j = j
        while j < p.count {
            switch p[j] {
            case "*", "<":
                // DOS_STAR is treated as `*` (close enough for the patterns clients send).
                if j == p.count - 1 { return true }
                for k in i...n.count where match(n, k, p, j + 1, depth: depth + 1) { return true }
                return false
            case ">":
                if i < n.count, n[i] != "." { i += 1 }
                j += 1
            case "\"":
                if i < n.count, n[i] == "." { i += 1 } else if i < n.count { return false }
                j += 1
            case "?":
                guard i < n.count else { return false }
                i += 1
                j += 1
            default:
                guard i < n.count, n[i] == p[j] else { return false }
                i += 1
                j += 1
            }
        }
        return i == n.count
    }
}
