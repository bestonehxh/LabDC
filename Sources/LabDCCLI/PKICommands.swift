import Foundation
import PKIKit
import Store

/// `labdc pki …` (PK-5): the PKI objects in the Configuration NC.
public enum PKICommand: Equatable, Sendable {
    /// Re-sync NTAuth, Enrollment Services, templates, AIA/CDP/OID from the CA and the store.
    case publish
    /// Dump everything under `CN=Public Key Services`.
    case show
}

extension CLIParser {
    static let pkiUsage = """
          labdc pki publish | show [--data <dir>]
        """

    static func parsePKI(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("pki needs publish or show") }
        let o = try Options(Array(rest.dropFirst()), valued: ["--data"])
        switch sub {
        case "publish": return .pki(data: o.data(defaultData), .publish)
        case "show": return .pki(data: o.data(defaultData), .show)
        default: throw CLIError.usage("unknown pki command \(sub)")
        }
    }
}

public enum PKICommands {
    public static func run(data url: URL, _ command: PKICommand, out: (String) -> Void) async throws {
        let dir = DataDirectory(url)
        switch command {
        case .publish:
            let pki = try await CACommands.openPKI(dir)
            let service = try await CACommands.openService(dir, pki: pki)
            let report: PKIPublishReport
            do { report = try await service.publishToDirectory() } catch { throw CLIError.failure("\(error)") }
            for line in report.lines { out(line) }
            out(report.isNoOp ? "PKI objects in the Configuration NC are up to date"
                : "\(report.created.count) created, \(report.modified.count) updated, \(report.deleted.count) removed")
        case .show:
            let store = try dir.openExistingStore()
            _ = try await store.requireInfo()
            do { for line in try await PKIDirectory.describe(store: store) { out(line) } } catch {
                throw CLIError.failure("\(error)")
            }
        }
    }
}
