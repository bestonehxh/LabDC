import Foundation
import Store

/// The `--data` folder: `lab.sqlite` (the directory, WAL) and `pki/` (lab CA + DC certificate).
public struct DataDirectory: Sendable {
    public let url: URL

    public init(_ url: URL) { self.url = url }

    public var storeURL: URL { url.appendingPathComponent("lab.sqlite") }
    public var pkiURL: URL { url.appendingPathComponent("pki", isDirectory: true) }
    /// The SYSVOL tree root (`SysvolLayout.ensure`), served by the SMB `SYSVOL`/`NETLOGON` shares.
    public var sysvolURL: URL { url.appendingPathComponent("sysvol", isDirectory: true) }
    /// The lab CA certificate as written by `LabPKI` (the file to trust).
    public var caURL: URL { pkiURL.appendingPathComponent("ca.pem") }
    /// UI-1: the daily serve logs (`serve-YYYY-MM-DD.log`, `ServeLogFile`).
    public var logsURL: URL { url.appendingPathComponent("logs", isDirectory: true) }
    /// UI-1: the app's server settings (ports, join, plain LDAP, NTLM policy; `ServerSettings`).
    public var settingsURL: URL { url.appendingPathComponent("settings.json") }
    /// UI-1: true when the store file exists (the app shows the setup wizard otherwise).
    public var hasStore: Bool { FileManager.default.fileExists(atPath: storeURL.path) }

    /// UI-1: true when the store exists and holds a domain (else the app runs the setup wizard).
    public func isProvisioned() async -> Bool {
        guard hasStore, let store = try? DirectoryStore(path: storeURL.path) else { return false }
        return await store.isProvisioned
    }

    /// Creates the folder (0700) when missing.
    public func prepare() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) {
            do {
                try fm.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            } catch {
                throw CLIError.failure("cannot create \(url.path): \(error.localizedDescription)")
            }
        }
    }

    /// Opens the store for the offline commands; the file must exist and be provisioned.
    public func openExistingStore() throws -> DirectoryStore {
        guard FileManager.default.fileExists(atPath: storeURL.path) else {
            throw CLIError.failure("no store at \(storeURL.path); run `labdc serve --data \(url.path) --provision ...` first")
        }
        let store: DirectoryStore
        do { store = try DirectoryStore(path: storeURL.path) } catch {
            throw CLIError.failure("cannot open \(storeURL.path): \(error)")
        }
        for fix in store.openFixups {
            FileHandle.standardError.write(Data("Store fixup: \(fix)\n".utf8))
        }
        return store
    }
}

public extension DirectoryStore {
    /// `domainInfo()` with a CLI-friendly error.
    func requireInfo() throws -> DomainInfo {
        guard isProvisioned else { throw CLIError.failure("the store at \(path) is not provisioned") }
        return try domainInfo()
    }
}
