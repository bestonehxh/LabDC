import Crypto
import Foundation

/// Config secrets at rest (RADIUS shared secrets, 30 Sep 2026): AES-256-GCM with a per-store key
/// kept in `<store>.secret-key` (mode 0600) beside the database, so a copied `lab.sqlite` alone
/// does not reveal them — the same "key file beside the data, 0600" model as the CA keys in
/// `pki/`. A `:memory:` store keeps its key in memory. Account secrets (NT hash, Kerberos keys)
/// stay as they are: they are hashes the protocols need as such.
struct StoreSecretBox: Sendable {
    let key: SymmetricKey
    static let prefix = "sealed:v1:"

    enum BoxError: Error, CustomStringConvertible {
        case keyFile(String), corrupt

        var description: String {
            switch self {
            case .keyFile(let why): "store secret key: \(why)"
            case .corrupt: "a sealed secret does not open with this store's key"
            }
        }
    }

    /// The key file for the store at `path`, created (atomically, 0600) on first use.
    static func load(storePath path: String) throws -> StoreSecretBox {
        if path.isEmpty || path == ":memory:" || path.hasPrefix("file::memory:") {
            return StoreSecretBox(key: SymmetricKey(size: .bits256))
        }
        let keyPath = path + ".secret-key"
        if let existing = FileManager.default.contents(atPath: keyPath) {
            guard existing.count == 32 else { throw BoxError.keyFile("\(keyPath) is not a 32-byte key") }
            return StoreSecretBox(key: SymmetricKey(data: existing))
        }
        // Write a temporary file, then link() it into place: link fails if another process won
        // the race, and nobody ever reads a half-written key.
        let fresh = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let temp = keyPath + ".\(getpid()).\(UInt32.random(in: 0...UInt32.max)).tmp"
        let fd = Darwin.open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw BoxError.keyFile("cannot create \(temp): errno \(errno)") }
        let wrote = fresh.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        fsync(fd)
        close(fd)
        defer { unlink(temp) }
        guard wrote == 32 else { throw BoxError.keyFile("cannot write \(temp)") }
        if link(temp, keyPath) != 0, errno != EEXIST { throw BoxError.keyFile("cannot create \(keyPath): errno \(errno)") }
        guard let final = FileManager.default.contents(atPath: keyPath), final.count == 32 else {
            throw BoxError.keyFile("\(keyPath) unreadable")
        }
        return StoreSecretBox(key: SymmetricKey(data: final))
    }

    static func isSealed(_ stored: String) -> Bool { stored.hasPrefix(prefix) }

    func seal(_ plain: String) throws -> String {
        let box = try AES.GCM.seal(Data(plain.utf8), using: key)
        guard let combined = box.combined else { throw BoxError.corrupt }
        return Self.prefix + combined.base64EncodedString()
    }

    /// Opens a sealed value; a legacy plaintext value (no prefix) comes back as it is.
    func open(_ stored: String) throws -> String {
        guard Self.isSealed(stored) else { return stored }
        guard let data = Data(base64Encoded: String(stored.dropFirst(Self.prefix.count))),
              let box = try? AES.GCM.SealedBox(combined: data),
              let plain = try? AES.GCM.open(box, using: key) else { throw BoxError.corrupt }
        return String(decoding: plain, as: UTF8.self)
    }
}
