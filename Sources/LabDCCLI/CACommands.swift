import CertConvert
import Foundation
import PKIKit
import Store
import X509

/// `labdc ca …` (PK-1): CAs, templates, issued certificates, revocation and CRLs.
public enum CACommand: Equatable, Sendable {
    case create(name: String, commonName: String?, keyType: CAKeyType, years: Int)
    case list
    case use(name: String)
    case export(name: String?, out: String, format: CAExportFormat)
    /// `target` is a serial (hex) or a certificate file (PEM/DER).
    case revoke(target: String, reason: RevocationReason)
    case crl(name: String?, out: String?, format: CAExportFormat)
    case issued(name: String?, revokedOnly: Bool)
    case templates
    /// Switches a template on or off (an enabled 192-bit template creates the P-384 802.1X CA
    /// on first use).
    case template(name: String, enabled: Bool)
    /// PK-2: sign an external CSR.
    case sign(CASignOptions)
}

/// `labdc ca sign` (PK-2).
public struct CASignOptions: Equatable, Sendable {
    public var csr: String
    public var template: String
    /// `dns:…`, `ip:…`, `upn:…`, `email:…`, `uri:…` (validated at parse time).
    public var sans: [String] = []
    /// `--replace-sans`: the `--san` list replaces the CSR's SANs instead of adding to them.
    public var replaceSANs = false
    public var days: Int?
    public var commonName: String?
    public var caName: String?
    public var account: String?
    public var out: String?
    public var chain = false
    public var format: SignResult.Format = .pem
    public var dryRun = false

    public init(csr: String, template: String) {
        self.csr = csr
        self.template = template
    }
}

extension CLIParser {
    static let caUsage = """
          labdc ca create --name <name> [--cn <common name>] [--key p256|rsa2048|rsa3072] [--years N] [--data <dir>]
          labdc ca list | templates [--data <dir>]
          labdc ca template <name> --enable|--disable [--data <dir>]
          labdc ca use <name> [--data <dir>]
          labdc ca export [--name <ca>] --out <file> [--format pem|der] [--data <dir>]
          labdc ca revoke <serial|cert-file> [--reason key-compromise|superseded|...] [--data <dir>]
          labdc ca crl [--name <ca>] [--out <file>] [--format pem|der] [--data <dir>]
          labdc ca issued [--name <ca>] [--revoked] [--data <dir>]
          labdc ca sign --csr <file> --template <name> [--san dns:<host>|ip:<addr>|upn:<user@realm>]… [--replace-sans]
                            [--days N] [--cn <common name>] [--ca <name>] [--account <sAMAccountName>]
                            --out <cert> [--chain] [--format pem|der|p7b] [--dry-run] [--data <dir>]
        """

    static func parseCA(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else {
            throw CLIError.usage("ca needs create, list, use, export, revoke, crl, issued, templates, template or sign")
        }
        var args = Array(rest.dropFirst())
        func format(_ o: Options) throws -> CAExportFormat {
            let text = o.values["--format"] ?? "pem"
            guard let f = CAExportFormat(rawValue: text.lowercased()) else {
                throw CLIError.usage("--format is pem or der, not \(text)")
            }
            return f
        }
        switch sub {
        case "create":
            let o = try Options(args, valued: ["--data", "--name", "--cn", "--key", "--years"])
            let keyText = o.values["--key"] ?? "p256"
            guard let key = CAKeyType(rawValue: keyText.lowercased().replacingOccurrences(of: "-", with: "")) else {
                throw CLIError.usage("--key is p256, rsa2048 or rsa3072, not \(keyText)")
            }
            let yearsText = o.values["--years"] ?? "10"
            guard let years = Int(yearsText), (1...50).contains(years) else {
                throw CLIError.usage("--years must be 1 to 50, not \(yearsText)")
            }
            let name = try o.required("--name")
            guard LabPKI.isValidCAName(name) else {
                throw CLIError.usage("--name must be 1-64 letters, digits, '.', '_' or '-' (it is part of the CRL URL), not \(name)")
            }
            return .ca(data: o.data(defaultData), .create(name: name, commonName: o.values["--cn"], keyType: key, years: years))
        case "list":
            let o = try Options(args, valued: ["--data"])
            return .ca(data: o.data(defaultData), .list)
        case "templates":
            let o = try Options(args, valued: ["--data"])
            return .ca(data: o.data(defaultData), .templates)
        case "template":
            let enable = args.contains("--enable"), disable = args.contains("--disable")
            guard enable != disable else { throw CLIError.usage("ca template <name> needs --enable or --disable") }
            args.removeAll { $0 == "--enable" || $0 == "--disable" }
            let o = try Options(args, valued: ["--data"], positionals: 1)
            return .ca(data: o.data(defaultData), .template(name: o.positionals[0], enabled: enable))
        case "use":
            let o = try Options(args, valued: ["--data"], positionals: 1)
            return .ca(data: o.data(defaultData), .use(name: o.positionals[0]))
        case "export":
            let o = try Options(args, valued: ["--data", "--out", "--format", "--name"])
            return .ca(data: o.data(defaultData), .export(name: o.values["--name"], out: try o.required("--out"), format: try format(o)))
        case "revoke":
            let o = try Options(args, valued: ["--data", "--reason"], positionals: 1)
            let text = o.values["--reason"] ?? "unspecified"
            guard let reason = RevocationReason(text: text), reason != .removeFromCRL else {
                let names = RevocationReason.allCases.filter { $0 != .removeFromCRL }.map(\.cliName)
                throw CLIError.usage("--reason is one of \(names.joined(separator: ", ")), not \(text)")
            }
            return .ca(data: o.data(defaultData), .revoke(target: o.positionals[0], reason: reason))
        case "crl":
            let o = try Options(args, valued: ["--data", "--name", "--out", "--format"])
            return .ca(data: o.data(defaultData), .crl(name: o.values["--name"], out: o.values["--out"], format: try format(o)))
        case "issued":
            let revoked = args.contains("--revoked")
            args.removeAll { $0 == "--revoked" }
            let o = try Options(args, valued: ["--data", "--name"])
            return .ca(data: o.data(defaultData), .issued(name: o.values["--name"], revokedOnly: revoked))
        case "sign":
            let a = try CertCLIParser.Args(args, valued: ["--data", "--csr", "--template", "--san", "--days", "--cn", "--ca",
                                                          "--account", "--out", "--format"],
                                           flags: ["--chain", "--dry-run", "--replace-sans"])
            if let extra = a.positionals.first { throw CLIError.usage("unexpected argument \(extra)") }
            guard let csr = try a.one("--csr") else { throw CLIError.usage("missing --csr") }
            guard let template = try a.one("--template") else { throw CLIError.usage("missing --template") }
            var o = CASignOptions(csr: csr, template: template)
            o.sans = a.values["--san"] ?? []
            for san in o.sans {
                do { _ = try CAService.parseSubjectAltName(san) } catch { throw CLIError.usage("--san: \(error)") }
            }
            o.replaceSANs = a.flags.contains("--replace-sans")
            if o.replaceSANs && o.sans.isEmpty { throw CLIError.usage("--replace-sans needs at least one --san") }
            if let text = try a.one("--days") {
                guard let d = Int(text), (1...36500).contains(d) else { throw CLIError.usage("--days must be 1 to 36500, not \(text)") }
                o.days = d
            }
            o.commonName = try a.one("--cn")
            o.caName = try a.one("--ca")
            o.account = try a.one("--account")
            o.out = try a.one("--out")
            o.chain = a.flags.contains("--chain")
            o.dryRun = a.flags.contains("--dry-run")
            if let text = try a.one("--format") {
                guard let f = SignResult.Format(rawValue: text.lowercased()) else {
                    throw CLIError.usage("--format is pem, der or p7b, not \(text)")
                }
                o.format = f
            }
            if o.format == .der && o.chain {
                throw CLIError.usage("a DER file holds one certificate: use --format pem or p7b for the chain")
            }
            if o.out == nil && !o.dryRun { throw CLIError.usage("missing --out (or --dry-run)") }
            let data = try a.one("--data").map(CLIParser.expand) ?? defaultData
            return .ca(data: data, .sign(o))
        default:
            throw CLIError.usage("unknown ca command \(sub)")
        }
    }
}

public enum CACommands {
    public static func run(data url: URL, _ command: CACommand, out: (String) -> Void) async throws {
        let dir = DataDirectory(url)
        switch command {
        case let .create(name, commonName, keyType, years):
            try dir.prepare()
            let pki = try await openPKI(dir)
            let ca: CertificateAuthority
            do { ca = try await pki.createCA(name: name, commonName: commonName, keyType: keyType, years: years) } catch {
                throw CLIError.failure("\(error)")
            }
            out("created CA \(ca.name): \(ca.keyType.displayName), \(ca.certificate.subject), valid until \(day(ca.certificate.notValidAfter))")
            out("certificate: \(ca.certificateURL.path)")
            // First CRL right away when the store is there (the CDP URL must answer).
            if FileManager.default.fileExists(atPath: dir.storeURL.path) {
                let service = try await openService(dir, pki: pki)
                let crl = try await service.generateCRL(caName: ca.name)
                out("CRL #\(crl.crlNumber ?? 0) published at \(try await service.crlURL(caName: ca.name))")
                try await publish(service, out: out)
            }
            let current = await pki.currentCAName
            out("current CA is still \(current); `labdc ca use \(ca.name)` makes it issue (the DC certificate is reissued at the next serve start)")

        case .list:
            let pki = try await openPKI(dir)
            let current = await pki.currentCAName
            let all = try await pki.authorities()
            if all.isEmpty { out("no CA yet; `labdc serve` creates the lab CA, `labdc ca create` another one") }
            for ca in all {
                out([ca.name + (ca.name == current ? " *" : ""), ca.keyType.displayName, ca.certificate.subject.description,
                     "until \(day(ca.certificate.notValidAfter))", ca.certificateURL.path].joined(separator: "\t"))
            }
            if !all.contains(where: { $0.name == current }) { out("current CA \(current) is missing!") }

        case .use(let name):
            let pki = try await openPKI(dir)
            do { try await pki.useCA(name: name) } catch { throw CLIError.failure("\(error)") }
            let ca = try await pki.currentAuthority()
            out("current CA is now \(ca.name) (\(ca.certificate.subject)); restart `labdc serve` to reissue the DC certificate from it")
            out("clients must trust \(ca.certificateURL.path)")
            if FileManager.default.fileExists(atPath: dir.storeURL.path) {
                try await publish(try await openService(dir, pki: pki), out: out)
            }

        case let .export(name, path, format):
            let pki = try await openPKI(dir)
            if name == nil, (try? await pki.currentAuthority()) == nil {
                throw CLIError.failure("no lab CA in \(dir.pkiURL.path); `labdc serve` creates it on first start")
            }
            do {
                try await pki.exportCA(name: name, to: URL(fileURLWithPath: path), format: format == .pem ? .pem : .der)
            } catch {
                throw CLIError.failure("\(error)")
            }
            let currentName = await pki.currentCAName
            let shown = name ?? currentName
            out("wrote CA \(shown) (\(format.rawValue.uppercased())) to \(path)")

        case let .revoke(target, reason):
            let pki = try await openPKI(dir)
            let service = try await openService(dir, pki: pki)
            let serial = try serialOf(target)
            let row: IssuedCertificate
            do { row = try await service.revoke(serial: serial, reason: reason) } catch {
                throw CLIError.failure("\(error)")
            }
            let crl = try await service.currentCRL(caName: row.caName)
            out("revoked \(row.serial) (\(row.subject), template \(row.templateName)) reason \(reason.cliName)")
            out("CRL #\(crl.crlNumber ?? 0) of CA \(row.caName) regenerated: \(crl.entries.count) entries, \(try await service.crlURL(caName: row.caName))")

        case let .crl(name, path, format):
            let pki = try await openPKI(dir)
            let service = try await openService(dir, pki: pki)
            let currentName = await pki.currentCAName
            let caName = name ?? currentName
            let crl: CertificateRevocationList
            do { crl = try await service.generateCRL(caName: caName) } catch { throw CLIError.failure("\(error)") }
            out("CRL #\(crl.crlNumber ?? 0) of CA \(caName): \(crl.entries.count) entries, next update \(stamp(crl.nextUpdate ?? crl.thisUpdate))")
            out("published at \(try await service.crlURL(caName: caName))")
            if let path {
                let bytes = format == .pem ? Array(crl.pem.utf8) : crl.der
                do { try Data(bytes).write(to: URL(fileURLWithPath: path)) } catch {
                    throw CLIError.failure("cannot write \(path): \(error.localizedDescription)")
                }
                out("wrote \(path)")
            }

        case let .issued(name, revokedOnly):
            let pki = try await openPKI(dir)
            let service = try await openService(dir, pki: pki)
            let rows = try await service.issuedCertificates(caName: name, revokedOnly: revokedOnly)
            if rows.isEmpty { out("no certificates issued\(name.map { " by \($0)" } ?? "")") }
            for r in rows {
                let status = r.revoked ? "revoked \(r.reason?.cliName ?? "unspecified") \(day(r.revocationDate ?? r.issuedAt))"
                    : (r.notAfter < Date() ? "expired" : "valid")
                out([r.serial, r.caName, r.templateName, r.subject, r.subjectAltNames.joined(separator: ","),
                     "until \(day(r.notAfter))", r.requesterName, status].joined(separator: "\t"))
            }

        case .sign(let o):
            try await sign(dir, o, out: out)

        case let .template(name, enabled):
            let pki = try await openPKI(dir)
            let service = try await openService(dir, pki: pki)
            var t: CertificateTemplate
            do { t = try await service.template(named: name) } catch { throw CLIError.failure("\(error)") }
            let hadSuiteB = try await pki.hasSuiteBCA()
            if t.enabled != enabled {
                t.enabled = enabled
                do { try await service.saveTemplate(t) } catch { throw CLIError.failure("\(error)") }
            }
            out("template \(t.name) \(enabled ? "enabled" : "disabled")")
            if !hadSuiteB, try await pki.hasSuiteBCA() {
                out("created the 802.1X 192-bit CA (P-384) \(LabPKI.suiteBCAName) and published it (NTAuth)")
            }

        case .templates:
            let pki = try await openPKI(dir)
            let service = try await openService(dir, pki: pki)
            for t in try await service.templates() {
                let flags = [t.enabled ? nil : "disabled", t.autoEnroll ? "auto-enroll" : nil, t.manualApproval ? "manual" : nil]
                    .compactMap { $0 }.joined(separator: ",")
                out([t.name, t.oid, "\(t.validityDays)d", "SAN \(t.sanPolicy.rawValue)",
                     "EKU \(t.ekus.isEmpty ? "-" : t.ekus.joined(separator: ","))", "KU \(t.keyUsage.names.joined(separator: ","))",
                     "keys \(t.allowedKeyTypes.joined(separator: ","))≥\(t.minKeyBits)", flags.isEmpty ? "-" : flags,
                     "enrol \(t.enrolAllowedGroupSIDs.joined(separator: ","))"].joined(separator: "\t"))
            }
        }
    }

    /// `ca sign`: review the CSR against the template (always printed), then sign unless
    /// `--dry-run` or the verdict refuses. The requester is the operator (an administrator).
    static func sign(_ dir: DataDirectory, _ o: CASignOptions, out: (String) -> Void) async throws {
        let path = (o.csr as NSString).expandingTildeInPath
        let bytes: [UInt8]
        do { bytes = Array(try Data(contentsOf: URL(fileURLWithPath: path))) } catch {
            throw CLIError.failure("cannot read \(o.csr): \(error.localizedDescription)")
        }
        let names: [GeneralName]
        do { names = try o.sans.map(CAService.parseSubjectAltName) } catch { throw CLIError.usage("--san: \(error)") }
        let request = SignRequest(
            csr: bytes, sourceName: URL(fileURLWithPath: path).lastPathComponent, templateName: o.template,
            subjectAltNames: names.isEmpty ? .fromRequest : (o.replaceSANs ? .replace(names) : .add(names)),
            validityDays: o.days, commonName: o.commonName, caName: o.caName, account: o.account)
        let pki = try await openPKI(dir)
        let service = try await openService(dir, pki: pki)
        let review: CSRReview
        do { review = try await service.review(request) } catch { throw CLIError.failure("\(error)") }
        for line in review.lines() { out(line) }
        if case .refused(let e) = review.verdict { throw CLIError.failure("not signed: \(e)") }
        if o.dryRun {
            out("dry run: nothing issued")
            return
        }
        guard let target = o.out else { throw CLIError.usage("missing --out") }
        let result: SignResult
        do { result = try await service.sign(request) } catch { throw CLIError.failure("\(error)") }
        for line in result.lines() { out(line) }
        let url = URL(fileURLWithPath: (target as NSString).expandingTildeInPath)
        let includeChain = o.chain || o.format == .p7b
        try CertCLI.write(OutputFile(name: url.lastPathComponent, data: result.encoded(o.format, includeChain: includeChain),
                                     containsPrivateKey: false, summary: ""), to: url)
        let what = switch o.format {
        case .pem: includeChain ? "PEM, certificate + CA \(result.caName)" : "PEM, certificate"
        case .der: "DER, certificate"
        case .p7b: "PKCS#7, certificate + CA \(result.caName)"
        }
        out("issued \(result.serial) from CA \(result.caName), template \(review.template.name), requester \(review.requester.name)")
        out("wrote \(url.path) (\(what))")
    }

    /// PK-5: republishes the Configuration NC PKI objects and says what changed.
    static func publish(_ service: CAService, out: (String) -> Void) async throws {
        let report: PKIPublishReport
        do { report = try await service.publishToDirectory() } catch {
            throw CLIError.failure("publishing the PKI objects in the Configuration NC: \(error)")
        }
        out(report.isNoOp ? "Configuration NC PKI objects already up to date"
            : "Configuration NC PKI objects: \(report.created.count) created, \(report.modified.count) updated, "
              + "\(report.deleted.count) removed (`labdc pki show` lists them)")
    }

    static func openPKI(_ dir: DataDirectory) async throws -> LabPKI {
        do { return try await LabPKI.open(directory: dir.pkiURL) } catch {
            throw CLIError.failure("PKI in \(dir.pkiURL.path): \(error)")
        }
    }

    static func openService(_ dir: DataDirectory, pki: LabPKI) async throws -> CAService {
        let store = try dir.openExistingStore()
        _ = try await store.requireInfo()
        do { return try await CAService.open(pki: pki, store: store) } catch {
            throw CLIError.failure("\(error)")
        }
    }

    /// A serial (hex, colons allowed) or a certificate file's serial.
    static func serialOf(_ target: String) throws -> String {
        guard FileManager.default.fileExists(atPath: target) else {
            let serial = CAService.normalizedSerial(target)
            guard !serial.isEmpty, serial.allSatisfy(\.isHexDigit) else {
                throw CLIError.failure("\(target) is neither a certificate file nor a hex serial number")
            }
            return serial
        }
        let bytes: [UInt8]
        do { bytes = Array(try Data(contentsOf: URL(fileURLWithPath: target))) } catch {
            throw CLIError.failure("cannot read \(target): \(error.localizedDescription)")
        }
        let text = String(decoding: bytes, as: UTF8.self)
        let certificate: Certificate
        do {
            certificate = text.contains("-----BEGIN CERTIFICATE-----") ? try Certificate(pemEncoded: text)
                : try Certificate(derEncoded: bytes)
        } catch {
            throw CLIError.failure("\(target) is not a PEM or DER certificate: \(error)")
        }
        return certificate.serialNumber.bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func day(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle().year().month().day())
    }

    static func stamp(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle())
    }
}
