import CryptoKit
import Foundation
import PKIKit
import Store
import X509

/// `labdc scep …` / `labdc est …` (PK-7): enrollment challenges (one store for both
/// protocols) and the URLs / fingerprints a device needs.
public enum EnrollmentCommand: Equatable, Sendable {
    case challengeNew(device: String?, ttl: TimeInterval, template: String, reusable: Bool)
    case challengeList
    case challengeRevoke(id: String)
    case info
}

extension CLIParser {
    static let enrollmentUsage = """
          labdc scep|est challenge new [--device <name>] [--ttl 24h] [--template Device] [--reusable] [--data <dir>]
          labdc scep|est challenge list | revoke <id> [--data <dir>]
          labdc scep|est info [--data <dir>]
        """

    static func parseEnrollment(_ rest: [String], protocolName: String, defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("\(protocolName) needs challenge or info") }
        let args = Array(rest.dropFirst())
        switch sub {
        case "info":
            let o = try Options(args, valued: ["--data"])
            return .enrollment(data: o.data(defaultData), protocolName: protocolName, .info)
        case "challenge":
            guard let action = args.first else { throw CLIError.usage("\(protocolName) challenge needs new, list or revoke") }
            let more = Array(args.dropFirst())
            switch action {
            case "new":
                let a = try CertCLIParser.Args(more, valued: ["--data", "--device", "--ttl", "--template"], flags: ["--reusable"])
                if let extra = a.positionals.first { throw CLIError.usage("unexpected argument \(extra)") }
                var ttl = CAService.defaultChallengeTTL
                if let text = try a.one("--ttl") {
                    do { ttl = try CAService.parseTTL(text) } catch { throw CLIError.usage("--ttl: \(error)") }
                }
                let device = try a.one("--device")
                if let device, device.isEmpty || device.contains(where: { $0.isWhitespace || $0 == ":" }) {
                    throw CLIError.usage("--device must be a name without spaces or ':' (it is the EST user name)")
                }
                let data = try a.one("--data").map(CLIParser.expand) ?? defaultData
                return .enrollment(data: data, protocolName: protocolName,
                                   .challengeNew(device: device, ttl: ttl, template: try a.one("--template") ?? CAService.defaultDeviceTemplate,
                                                 reusable: a.flags.contains("--reusable")))
            case "list":
                let o = try Options(more, valued: ["--data"])
                return .enrollment(data: o.data(defaultData), protocolName: protocolName, .challengeList)
            case "revoke":
                let o = try Options(more, valued: ["--data"], positionals: 1)
                return .enrollment(data: o.data(defaultData), protocolName: protocolName, .challengeRevoke(id: o.positionals[0]))
            default:
                throw CLIError.usage("unknown \(protocolName) challenge command \(action)")
            }
        default:
            throw CLIError.usage("unknown \(protocolName) command \(sub)")
        }
    }
}

public enum EnrollmentCommands {
    public static func run(data url: URL, protocolName: String, _ command: EnrollmentCommand, out: (String) -> Void) async throws {
        let dir = DataDirectory(url)
        let pki = try await CACommands.openPKI(dir)
        let service = try await CACommands.openService(dir, pki: pki)
        let info = try await service.store.domainInfo()
        switch command {
        case let .challengeNew(device, ttl, template, reusable):
            let made: (challenge: PKIChallengeRow, secret: String)
            do { made = try await service.newChallenge(device: device, template: template, ttl: ttl, reusable: reusable) } catch {
                throw CLIError.failure("\(error)")
            }
            let c = made.challenge
            out("challenge \(made.secret)")
            out("id \(c.id), \(c.reusable ? "reusable (static)" : "one-time"), template \(c.template), "
                + "device \(c.device ?? "any"), expires \(CACommands.stamp(c.expiresAt))")
            out("shown once: only its SHA-256 is stored")
            out("SCEP  \(scepURL(info)) (challenge password)")
            out("EST   \(estURL(info)) (user \(c.device ?? "<device name>"), password = the challenge)")

        case .challengeList:
            let rows = try await service.challenges()
            if rows.isEmpty { out("no enrollment challenges; `labdc \(protocolName) challenge new` makes one") }
            let now = Date()
            for r in rows {
                out([r.id, r.state(at: now).rawValue, r.reusable ? "reusable" : "one-time", r.template, r.device ?? "any",
                     "created \(CACommands.stamp(r.createdAt))", "expires \(CACommands.stamp(r.expiresAt))",
                     r.usedAt.map { "used \(CACommands.stamp($0)) by \(r.usedBy ?? "?")\(r.reusable ? " (\(r.useCount)x)" : "")" } ?? "unused"]
                    .joined(separator: "\t"))
            }

        case .challengeRevoke(let id):
            do {
                let row = try await service.revokeChallenge(id: id)
                out("revoked challenge \(row.id) (template \(row.template), device \(row.device ?? "any"))")
            } catch {
                throw CLIError.failure("\(error)")
            }

        case .info:
            let ca = try await pki.currentAuthority()
            let der = try ca.der()
            out("SCEP      \(scepURL(info))  (also http://\(info.dcDNSName)/certsrv/mscep/mscep.dll and /cgi-bin/pkiclient.exe)")
            out("EST       \(estURL(info))  (labels: /.well-known/est/<template>/simpleenroll)")
            out("CA        \(ca.name) (\(ca.keyType.displayName)) \(ca.certificate.subject)")
            out("  SHA-256 \(fingerprint(SHA256.hash(data: der)))")
            out("  SHA-1   \(fingerprint(Insecure.SHA1.hash(data: der)))")
            out("  MD5     \(fingerprint(Insecure.MD5.hash(data: der)))")
            out("  file    \(ca.certificateURL.path); download http://\(info.dcDNSName)\(CAService.caCertificatePath(caName: ca.name))")
            if let ra = try await SCEPService.existingRA(pki: pki) {
                out("SCEP RA   \(ra.certificate.subject), serial \(ra.certificate.serialNumber), until \(CACommands.day(ra.certificate.notValidAfter))")
            } else {
                out("SCEP RA   not issued yet (`labdc serve` issues it at start)")
            }
            let active = try await service.challenges().filter { $0.state(at: Date()) == .active }.count
            out("challenges \(active) active")
        }
    }

    static func scepURL(_ info: DomainInfo) -> String { "http://\(info.dcDNSName)/scep" }
    static func estURL(_ info: DomainInfo, port: Int = 8443) -> String {
        "https://\(info.dcDNSName)\(port == 443 ? "" : ":\(port)")/.well-known/est"
    }

    static func fingerprint<D: Digest>(_ digest: D) -> String {
        digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
