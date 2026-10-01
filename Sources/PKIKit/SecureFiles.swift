import Foundation

/// POSIX helpers: the PKI directory is 0700 and every file in it 0600, written atomically.
enum SecureFiles {
    static func ensureDirectory(_ url: URL) throws {
        let path = url.path
        var st = stat()
        if stat(path, &st) != 0 {
            guard errno == ENOENT else { throw PKIKitError.fileSystem(path: path, operation: "stat", errno: errno) }
            let parent = url.deletingLastPathComponent()
            do {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            } catch {
                throw PKIKitError.fileSystem(path: parent.path, operation: "mkdir", errno: EIO)
            }
            if mkdir(path, 0o700) != 0, errno != EEXIST {
                throw PKIKitError.fileSystem(path: path, operation: "mkdir", errno: errno)
            }
        } else if (st.st_mode & S_IFMT) != S_IFDIR {
            throw PKIKitError.fileSystem(path: path, operation: "open directory", errno: ENOTDIR)
        }
        // mkdir honours the umask, and an existing folder may be looser: force 0700.
        if chmod(path, 0o700) != 0 {
            throw PKIKitError.fileSystem(path: path, operation: "chmod", errno: errno)
        }
    }

    /// Reads a whole file. Returns nil when it does not exist.
    static func read(_ url: URL) throws -> [UInt8]? {
        let path = url.path
        let fd = open(path, O_RDONLY | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw PKIKitError.fileSystem(path: path, operation: "open", errno: errno)
        }
        defer { close(fd) }
        var out: [UInt8] = []
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = buf.withUnsafeMutableBytes { Foundation.read(fd, $0.baseAddress, $0.count) }
            if n < 0 {
                if errno == EINTR { continue }
                throw PKIKitError.fileSystem(path: path, operation: "read", errno: errno)
            }
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }

    /// Writes `bytes` to a temporary file created with `mode` next to `url`, then renames it into place.
    static func write(_ bytes: [UInt8], to url: URL, mode: mode_t = 0o600) throws {
        let path = url.path
        let tmp = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UInt32.random(in: 0...UInt32.max)).tmp").path
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode)
        if fd < 0 { throw PKIKitError.fileSystem(path: tmp, operation: "create", errno: errno) }
        var renamed = false
        defer { if !renamed { unlink(tmp) } }
        do {
            defer { close(fd) }
            // O_CREAT honours the umask; make the mode exact.
            if fchmod(fd, mode) != 0 { throw PKIKitError.fileSystem(path: tmp, operation: "chmod", errno: errno) }
            var offset = 0
            while offset < bytes.count {
                let n = bytes.withUnsafeBytes { raw in
                    Foundation.write(fd, raw.baseAddress! + offset, raw.count - offset)
                }
                if n < 0 {
                    if errno == EINTR { continue }
                    throw PKIKitError.fileSystem(path: tmp, operation: "write", errno: errno)
                }
                offset += n
            }
            if fsync(fd) != 0 { throw PKIKitError.fileSystem(path: tmp, operation: "fsync", errno: errno) }
        }
        if rename(tmp, path) != 0 { throw PKIKitError.fileSystem(path: path, operation: "rename", errno: errno) }
        renamed = true
    }

    /// Tightens an existing file to 0600 if it is looser.
    static func restrict(_ url: URL) throws {
        var st = stat()
        guard stat(url.path, &st) == 0 else { return }
        if (st.st_mode & 0o777) != 0o600, chmod(url.path, 0o600) != 0 {
            throw PKIKitError.fileSystem(path: url.path, operation: "chmod", errno: errno)
        }
    }
}
