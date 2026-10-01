import CertConvert
import Foundation
import PKIKit
import Store
import SYSVOL
import X509

/// `labdc gpo …` (PK-4): the default GPOs, Trusted Root distribution and autoenrollment
/// policy in the Default Domain Policy.
public enum GPOCommand: Equatable, Sendable {
    case initialize
    case show
    /// `file`: PEM / DER / P7B with one or more root certificates.
    case trustedRootAdd(file: String, name: String?)
    /// A LabDC CA (`nil` = the current one).
    case trustedRootAddCA(ca: String?, name: String?)
    case trustedRootRemove(thumbprint: String)
    case trustedRootList
    case autoEnrollShow
    case autoEnrollEnable(cepURL: String?, policyID: String?)
    case autoEnrollDisable
}

extension CLIParser {
    static let gpoUsage = """
          labdc gpo init | show [--data <dir>]
          labdc gpo trusted-root add <cert.pem|cert.der|chain.p7b> [--name <friendly name>] [--data <dir>]
          labdc gpo trusted-root add-ca [<LabDC CA name>] [--name <friendly name>] [--data <dir>]
          labdc gpo trusted-root remove <sha1 thumbprint> | list [--data <dir>]
          labdc gpo autoenroll [--enable [--cep-url <url>] [--policy-id <{GUID}>] | --disable] [--data <dir>]
        """

    static func parseGPO(_ rest: [String], defaultData: URL) throws -> CLICommand {
        guard let sub = rest.first else { throw CLIError.usage("gpo needs init, show, trusted-root or autoenroll") }
        var args = Array(rest.dropFirst())
        switch sub {
        case "init":
            let o = try Options(args, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .initialize)
        case "show":
            let o = try Options(args, valued: ["--data"])
            return .gpo(data: o.data(defaultData), .show)
        case "trusted-root", "trusted-roots":
            guard let verb = args.first else { throw CLIError.usage("gpo trusted-root needs add, add-ca, remove or list") }
            args.removeFirst()
            switch verb {
            case "add":
                let o = try Options(args, valued: ["--data", "--name"], positionals: 1)
                return .gpo(data: o.data(defaultData), .trustedRootAdd(file: o.positionals[0], name: o.values["--name"]))
            case "add-ca":
                // Optional CA name: count the positionals first.
                var positionals = 0, i = 0
                while i < args.count {
                    if args[i] == "--data" || args[i] == "--name" { i += 2; continue }
                    if !args[i].hasPrefix("--") { positionals += 1 }
                    i += 1
                }
                guard positionals <= 1 else { throw CLIError.usage("gpo trusted-root add-ca takes at most one CA name") }
                let o = try Options(args, valued: ["--data", "--name"], positionals: positionals)
                return .gpo(data: o.data(defaultData), .trustedRootAddCA(ca: o.positionals.first, name: o.values["--name"]))
            case "remove":
                let o = try Options(args, valued: ["--data"], positionals: 1)
                return .gpo(data: o.data(defaultData), .trustedRootRemove(thumbprint: o.positionals[0]))
            case "list":
                let o = try Options(args, valued: ["--data"])
                return .gpo(data: o.data(defaultData), .trustedRootList)
            default:
                throw CLIError.usage("unknown gpo trusted-root command \(verb)")
            }
        case "autoenroll", "auto-enroll":
            let enable = args.contains("--enable"), disable = args.contains("--disable")
            args.removeAll { $0 == "--enable" || $0 == "--disable" }
            let o = try Options(args, valued: ["--data", "--cep-url", "--policy-id"])
            if enable && disable { throw CLIError.usage("--enable and --disable exclude each other") }
            if !enable && (o.values["--cep-url"] != nil || o.values["--policy-id"] != nil) {
                throw CLIError.usage("--cep-url / --policy-id go with --enable")
            }
            if let url = o.values["--cep-url"] {
                guard let u = URL(string: url), u.scheme?.lowercased() == "https", u.host != nil else {
                    throw CLIError.usage("--cep-url must be an https:// URL, not \(url)")
                }
            }
            if let id = o.values["--policy-id"], !(id.hasPrefix("{") && id.hasSuffix("}") && GUID(string: id) != nil) {
                throw CLIError.usage("--policy-id must be a braced GUID like {3F2504E0-4F89-11D3-9A0C-0305E82C3301}, not \(id)")
            }
            let command: GPOCommand = enable ? .autoEnrollEnable(cepURL: o.values["--cep-url"], policyID: o.values["--policy-id"])
                : disable ? .autoEnrollDisable : .autoEnrollShow
            return .gpo(data: o.data(defaultData), command)
        default:
            throw CLIError.usage("unknown gpo command \(sub)")
        }
    }
}

public enum GPOCommands {
    public static func run(data url: URL, _ command: GPOCommand, out: (String) -> Void) async throws {
        let dir = DataDirectory(url)
        let store = try dir.openExistingStore()
        let info = try await store.requireInfo()
        let editor = GroupPolicyEditor(root: dir.sysvolURL, store: store)
        do {
            try await run(command, editor: editor, info: info, dir: dir, out: out)
        } catch let e as CLIError {
            throw e
        } catch {
            throw CLIError.failure("\(error)")
        }
    }

    static func run(_ command: GPOCommand, editor: GroupPolicyEditor, info: DomainInfo, dir: DataDirectory,
                    out: (String) -> Void) async throws {
        switch command {
        case .initialize:
            let result = try await editor.ensureDefaultGPOs()
            for gpo in result.createdGPOs { out("created \(gpo.displayName) \(gpo.guid)") }
            if result.isNoOp { out("default GPOs already present") }
            for gpo in DefaultGPO.all { out(try await summary(editor, gpo)) }

        case .show:
            for gpo in DefaultGPO.all {
                out(try await summary(editor, gpo))
                let state = try await editor.state(gpo)
                out("  gPCFileSysPath \(state.fileSysPath)")
                out("  machine extensions \(state.machineExtensions.description.isEmpty ? "-" : state.machineExtensions.description)")
                for scope in GPOScope.allCases {
                    let pol = try await editor.registryPolicy(gpo, scope: scope)
                    for e in pol.entries { out("  \(scope.rawValue)/Registry.pol \(e)") }
                }
            }

        case let .trustedRootAdd(file, name):
            let bundle: CertBundle
            do { bundle = try CertConvert.load(contentsOf: URL(fileURLWithPath: file)) } catch {
                throw CLIError.failure("\(file): \(error)")
            }
            guard !bundle.certificates.isEmpty else { throw CLIError.failure("\(file) holds no certificate") }
            let roots = bundle.certificates.filter(\.isSelfIssued)
            for c in bundle.certificates where !c.isSelfIssued {
                out("skipped \(c.certificate.subject) (issued by \(c.certificate.issuer), not a root; only self-signed CA certificates belong in Trusted Root)")
            }
            guard !roots.isEmpty else { throw CLIError.failure("\(file) holds no self-signed (root) certificate") }
            for c in roots { try await add(c, name: roots.count == 1 ? name : name.map { "\($0) (\(commonName(c.certificate.subject) ?? "root"))" }, editor: editor, out: out) }

        case let .trustedRootAddCA(caName, name):
            let pki: LabPKI
            do { pki = try await LabPKI.open(directory: dir.pkiURL) } catch { throw CLIError.failure("PKI in \(dir.pkiURL.path): \(error)") }
            let ca: CertificateAuthority
            do {
                if let caName { ca = try await pki.authority(named: caName) } else { ca = try await pki.currentAuthority() }
            } catch {
                throw CLIError.failure("\(error)")
            }
            try await add(try CertificateItem(der: ca.der()),
                          name: name ?? commonName(ca.certificate.subject) ?? ca.certificate.subject.description,
                          editor: editor, out: out)

        case .trustedRootRemove(let thumbprint):
            let change = try await editor.removeTrustedRoot(thumbprint: thumbprint)
            out("removed \(change.thumbprint) from Default Domain Policy" + (change.edit.changed ? " (version \(change.edit.version.raw))" : " (was not in it)"))
            for dn in change.directoryObjects { out("removed from \(dn)") }

        case .trustedRootList:
            let roots = try await editor.trustedRoots()
            let published = Set(try await CertificationAuthorityDirectory.published(store: editor.store).map { CertificateBlob.thumbprint($0.der) })
            if roots.isEmpty { out("no trusted roots in Default Domain Policy") }
            for r in roots {
                let subject = (try? Certificate(derEncoded: r.der)).map { "\($0.subject)\tuntil \(day($0.notValidAfter))" } ?? "?"
                out([r.thumbprint, subject, r.friendlyName.map { "name \"\($0)\"" } ?? "-",
                     published.contains(r.thumbprint) ? "published in Configuration" : "GPO only"].joined(separator: "\t"))
            }

        case .autoEnrollShow:
            out(describe(try await editor.autoEnrollment()))
            out("  users: " + describe(try await editor.autoEnrollment(scope: .user)).dropFirst("autoenrollment: ".count))

        case let .autoEnrollEnable(cepURL, policyID):
            var id = policyID
            if id == nil { id = try await AutoEnrollmentSettings.defaultPolicyID(store: editor.store) }
            let settings = AutoEnrollmentSettings(
                cepURL: cepURL ?? AutoEnrollmentSettings.defaultCEPURL(dcDNSName: info.dcDNSName),
                policyID: (id ?? "").uppercased())
            let edit = try await editor.enableAutoEnrollment(settings)
            out("autoenrollment enabled in Default Domain Policy (AEPolicy 7, CEP \(settings.cepURL), Kerberos, policy ID \(settings.policyID))"
                + (edit.changed ? ", version \(edit.previous.raw) -> \(edit.version.raw)" : ", unchanged"))
            // PK-6: the user side too, so users get their User certificate at logon.
            let user = try await editor.enableAutoEnrollment(settings, scope: .user)
            out("  users: same policy in User Configuration"
                + (user.changed ? ", version \(user.previous.raw) -> \(user.version.raw)" : ", unchanged"))

        case .autoEnrollDisable:
            let edit = try await editor.disableAutoEnrollment()
            out("autoenrollment disabled in Default Domain Policy (AEPolicy 0x8000)"
                + (edit.changed ? ", version \(edit.previous.raw) -> \(edit.version.raw)" : ", unchanged"))
            let user = try await editor.disableAutoEnrollment(scope: .user)
            out("  users: disabled in User Configuration"
                + (user.changed ? ", version \(user.previous.raw) -> \(user.version.raw)" : ", unchanged"))
        }
    }

    static func add(_ c: CertificateItem, name: String?, editor: GroupPolicyEditor, out: (String) -> Void) async throws {
        let info = CACertificateInfo(der: c.der, commonName: commonName(c.certificate.subject), subject: c.certificate.subject.description)
        if !c.isCA { out("warning: \(c.certificate.subject) has no basicConstraints CA:TRUE") }
        let change = try await editor.addTrustedRoot(info, friendlyName: name)
        out("trusted root \(change.thumbprint) \(c.certificate.subject) in Default Domain Policy"
            + (change.edit.changed ? " (version \(change.edit.previous.raw) -> \(change.edit.version.raw))" : " (already there)"))
        for dn in change.directoryObjects { out("published in \(dn)") }
    }

    static func summary(_ editor: GroupPolicyEditor, _ gpo: DefaultGPO) async throws -> String {
        let s = try await editor.state(gpo)
        let links = s.linkedOn.map(\.description).joined(separator: "; ")
        return "\(s.displayName) \(gpo.guid) version \(s.containerVersion.raw) (user \(s.containerVersion.user), machine \(s.containerVersion.machine))"
            + (s.versionsMatch ? "" : " GPT.INI \(s.fileVersion.raw) MISMATCH")
            + " linked on \(links.isEmpty ? "-" : links)"
    }

    static func describe(_ state: AutoEnrollmentState) -> String {
        switch state {
        case .notConfigured: "autoenrollment: not configured"
        case .disabled: "autoenrollment: disabled"
        case let .enabled(ae, urls): "autoenrollment: enabled (AEPolicy \(ae)), enrollment policy servers: \(urls.isEmpty ? "-" : urls.joined(separator: ", "))"
        }
    }

    /// The last (most specific) CN of a name.
    static func commonName(_ name: DistinguishedName) -> String? {
        var cn: String?
        for rdn in name { for ava in rdn where ava.type == .RDNAttributeType.commonName { cn = String(describing: ava.value) } }
        return cn
    }

    static func day(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle().year().month().day())
    }
}
