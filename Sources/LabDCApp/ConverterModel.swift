import CertConvert
import Foundation
import Observation
import LabDCCore
import X509

/// The certificate converter (Certificates ▸ Converter and the standalone window): dropped /
/// chosen / pasted inputs → detected contents (asking for a password only when an input needs
/// one) → a target format or device preset → output files. Everything goes through
/// `CertConvert` (no openssl); nothing is stored.
@MainActor @Observable
final class ConverterModel {
    struct Input: Identifiable, Equatable {
        enum State: Equatable {
            case loaded(CertBundle)
            case needsPassword
            case wrongPassword
            case failed(String)
        }

        let id = UUID()
        let name: String
        let bytes: [UInt8]
        let format: InputFormat?
        var password: String?
        var state: State

        var bundle: CertBundle? { if case .loaded(let b) = state { b } else { nil } }
        var isLocked: Bool { state == .needsPassword || state == .wrongPassword }

        /// `PKCS#12 (PFX) · 1 key, 3 certificates` / `Password needed` / the error.
        var summary: String {
            let kind = format?.rawValue ?? "Unknown"
            switch state {
            case .loaded(let b):
                var parts: [String] = []
                if !b.keys.isEmpty { parts.append(ConverterModel.count(b.keys.count, "key")) }
                if !b.certificates.isEmpty { parts.append(ConverterModel.count(b.certificates.count, "certificate")) }
                if !b.requests.isEmpty { parts.append(ConverterModel.count(b.requests.count, "request")) }
                return "\(kind) · " + (parts.isEmpty ? "nothing usable" : parts.joined(separator: ", "))
            case .needsPassword: return "\(kind) · password needed"
            case .wrongPassword: return "\(kind) · wrong password"
            case .failed(let why): return why
            }
        }
    }

    enum Target: Hashable, Identifiable {
        case format(OutputFormat)
        case preset(ExportPreset)

        var id: String {
            switch self {
            case .format(let f): "format-\(f.rawValue)"
            case .preset(let p): "preset-\(p.rawValue)"
            }
        }

        static let formats: [Target] = [.pem, .der, .p7b, .p12, .keyPKCS8, .keyPKCS1, .combined].map { .format($0) }
        static let presets: [Target] = ExportPreset.allCases.map { .preset($0) }

        var title: String {
            switch self {
            case .format(let f):
                switch f {
                case .pem: "PEM certificate (.pem)"
                case .der: "DER certificate (.cer)"
                case .p7b: "PKCS#7 chain (.p7b)"
                case .p12: "PKCS#12 (.p12 / .pfx)"
                case .keyPKCS8: "Private key, PKCS#8 (.key)"
                case .keyPKCS1: "Private key, PKCS#1 / SEC1 (.key)"
                case .combined: "Combined PEM (key + chain)"
                }
            case .preset(let p):
                switch p {
                case .clearpass: "Aruba ClearPass"
                case .imaster: "Huawei iMaster NCE"
                case .switch: "Aruba / Huawei switch"
                case .windows: "Windows"
                case .macos: "macOS"
                }
            }
        }

        /// One line under the picker: what comes out.
        var detail: String {
            switch self {
            case .format(let f):
                switch f {
                case .pem: "Every certificate as PEM text (leaf first)."
                case .der: "The leaf certificate in binary DER (Windows .cer)."
                case .p7b: "All certificates in one PKCS#7 file, in chain order."
                case .p12: "Key + certificate + chain, password protected."
                case .keyPKCS8: "“BEGIN PRIVATE KEY”; encrypted when you set a password."
                case .keyPKCS1: "“BEGIN RSA/EC PRIVATE KEY” for older devices; encrypted with a password."
                case .combined: "Key, certificate and chain in one PEM file."
                }
            case .preset(let p):
                switch p {
                case .clearpass: "A .pfx with the full chain (server certificate), or the chain as PEM for the trust list."
                case .imaster: "Certificate, key (PKCS#8, encrypted with the password) and chain as separate PEM files."
                case .switch: "Certificate, CA chain and a PKCS#1/SEC1 key as PEM, plus one combined file."
                case .windows: "A .pfx to import, the certificate as .cer and the chain as .p7b."
                case .macos: "A .p12 for Keychain Access and the chain as PEM."
                }
            }
        }

        var isPreset: Bool { if case .preset = self { true } else { false } }
    }

    private(set) var inputs: [Input] = []
    var target: Target = .format(.pem)
    /// PKCS#12 password / key encryption password.
    var outputPassword = ""
    /// PKCS#12: 3DES + SHA-1 MAC for old appliances (else AES-256 + SHA-256).
    var legacy = false
    var includeChain = true
    var friendlyName = ""
    var pasted = ""
    /// The certificates "Verify against CA" uses (the domain's CAs); nil = pick a file.
    var caProvider: (@MainActor () async -> [CertificateItem])?
    /// The last conversion ("Saved clearpass.pfx …").
    var lastResult: String?
    /// Verify / Match output lines.
    private(set) var toolLines: [String] = []
    private(set) var toolOK: Bool?

    // MARK: Inputs

    nonisolated static func count(_ n: Int, _ word: String) -> String { "\(n) \(word)\(n == 1 ? "" : "s")" }

    /// Adds one input (a dropped file, a chosen file, pasted text). A PFX/JKS without its password
    /// waits in `pendingPassword`.
    func add(bytes: [UInt8], name: String) {
        let format = CertConvert.sniff(bytes)
        let input = Input(name: name, bytes: bytes, format: format, password: nil,
                          state: Self.load(bytes, name: name, password: nil, format: format))
        inputs.append(input)
        lastResult = nil
        clearTool()
    }

    func add(urls: [URL]) {
        for url in urls {
            do {
                add(bytes: Array(try Data(contentsOf: url)), name: url.lastPathComponent)
            } catch {
                inputs.append(Input(name: url.lastPathComponent, bytes: [], format: nil, password: nil,
                                    state: .failed("Cannot read \(url.lastPathComponent): \(error.localizedDescription)")))
            }
        }
    }

    func addPasted() {
        let text = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        add(bytes: Array(text.utf8), name: "Pasted text")
        pasted = ""
    }

    /// Tries a password for a locked input. A correct PFX password also becomes the default
    /// output password (as `labdc cert convert` reuses it).
    func unlock(_ id: Input.ID, password: String) {
        guard let i = inputs.firstIndex(where: { $0.id == id }) else { return }
        let state = Self.load(inputs[i].bytes, name: inputs[i].name, password: password, format: inputs[i].format)
        inputs[i].state = state == .needsPassword ? .wrongPassword : state
        if case .loaded = state {
            inputs[i].password = password
            if outputPassword.isEmpty { outputPassword = password }
        }
        clearTool()
    }

    func remove(_ id: Input.ID) {
        inputs.removeAll { $0.id == id }
        clearTool()
    }

    func clear() {
        inputs = []
        outputPassword = ""
        friendlyName = ""
        lastResult = nil
        clearTool()
    }

    static func load(_ bytes: [UInt8], name: String, password: String?, format: InputFormat?) -> Input.State {
        guard format != nil else {
            return .failed("\(name): not a certificate, key, PKCS#7, PKCS#12 or JKS file")
        }
        do {
            return .loaded(try CertConvert.load(bytes, name: name, password: password))
        } catch let e as CertConvertError {
            switch e {
            case .passwordRequired: return .needsPassword
            case .badPassword: return .wrongPassword
            default: return .failed("\(name): \(e)")
            }
        } catch {
            return .failed("\(name): \(error)")
        }
    }

    /// The first input still waiting for its password.
    var pendingPassword: Input? { inputs.first(where: \.isLocked) }

    /// Every loaded input merged (duplicates removed), as `--key` / `--chain` merge them.
    var bundle: CertBundle {
        var b = CertBundle()
        for input in inputs { if let x = input.bundle { b.add(x) } }
        return b
    }

    enum Phase: Equatable { case empty, needsPassword, ready, nothingUsable }

    var phase: Phase {
        if inputs.isEmpty { return .empty }
        if pendingPassword != nil { return .needsPassword }
        let b = bundle
        return b.certificates.isEmpty && b.keys.isEmpty ? .nothingUsable : .ready
    }

    // MARK: Detected

    struct CertificateRow: Identifiable, Equatable {
        var id: String
        var subject: String
        var issuer: String
        var notAfter: Date
        var role: String
        var summary: CertificateSummary
        /// SANs as `DNS:host` / `IP:…` (CertConvert's summary), empty when none.
        var sans: [String] = []
    }

    struct KeyRow: Identifiable, Equatable {
        var id: String
        var algorithm: String
        /// The certificate it belongs to (CN or subject), nil = none loaded.
        var matches: String?
    }

    var certificateRows: [CertificateRow] {
        let b = bundle
        let leaf = b.leaf
        return b.orderedCertificates.map { c in
            let role = c.isSelfIssued ? "Root CA" : (c.isCA ? "Intermediate CA" : (c == leaf ? "Leaf" : "Certificate"))
            return CertificateRow(id: c.sha256Fingerprint.map { String(format: "%02x", $0) }.joined(),
                                  subject: c.certificate.subject.commonNameText ?? c.certificate.subject.description,
                                  issuer: c.certificate.issuer.commonNameText ?? c.certificate.issuer.description,
                                  notAfter: c.certificate.notValidAfter, role: role, summary: CertificateSummary(c),
                                  sans: CertificateSummary(c).subjectAlternativeNames)
        }
    }

    var keyRows: [KeyRow] {
        let b = bundle
        return b.keys.enumerated().map { i, k in
            let cert = b.certificate(for: k)
            return KeyRow(id: "\(i)-\(k.publicKeyFingerprint ?? "")", algorithm: "\(k.algorithm)",
                          matches: cert.map { $0.certificate.subject.commonNameText ?? $0.certificate.subject.description })
        }
    }

    /// `Chain complete` / `Chain incomplete: the issuer of X is not loaded`.
    var chainText: String? {
        let b = bundle
        guard !b.certificates.isEmpty else { return nil }
        return b.chainIsComplete ? "Chain complete up to a root" : "Chain ends without its root (add the CA certificate to include it)"
    }

    var notes: [String] {
        var out = inputs.compactMap(\.bundle).flatMap { $0.sources.flatMap { $0.notes + $0.protection } }
        if !bundle.requests.isEmpty { out.append("A certificate request (CSR) is decoded but not converted — sign it under Sign CSR.") }
        return out
    }

    // MARK: Convert

    var baseName: String {
        let first = inputs.first { $0.bundle != nil }?.name ?? "certificate"
        let base = (first as NSString).deletingPathExtension
        return base.isEmpty || base == "Pasted text" ? "certificate" : base
    }

    /// True when the output holds a private key (a password field matters then).
    var outputHasKey: Bool {
        switch target {
        case .format(let f): [.p12, .keyPKCS8, .keyPKCS1, .combined].contains(f)
        case .preset: !bundle.keys.isEmpty
        }
    }

    /// PKCS#12 (and the presets that write one) cannot be written without a password.
    var needsOutputPassword: Bool {
        switch target {
        case .format(let f): f == .p12
        case .preset(let p): !bundle.keys.isEmpty && [.clearpass, .windows, .macos].contains(p)
        }
    }

    var showsLegacySwitch: Bool {
        switch target {
        case .format(let f): f == .p12 || f == .keyPKCS8 || f == .keyPKCS1 || f == .combined
        case .preset: !bundle.keys.isEmpty
        }
    }

    /// Why Convert is disabled (nil = ready).
    var problem: String? {
        switch phase {
        case .empty: return "Drop or choose a certificate, key, PFX/P12, P7B or JKS file."
        case .needsPassword: return "Enter the password of \(pendingPassword?.name ?? "the file")."
        case .nothingUsable: return "Nothing to convert: the inputs hold no certificate or key."
        case .ready: break
        }
        let b = bundle
        let hasKey = !b.keys.isEmpty, hasCert = !b.certificates.isEmpty
        let keyMatches = b.keys.contains { b.certificate(for: $0) != nil }
        switch target {
        case .format(let f):
            switch f {
            case .pem, .der, .p7b: if !hasCert { return "This needs a certificate." }
            case .keyPKCS8, .keyPKCS1: if !hasKey { return "This needs a private key." }
            case .p12, .combined:
                if !hasKey { return "This needs the private key too (add the .key file)." }
                if !hasCert { return "This needs the certificate too." }
                if !keyMatches { return "The private key does not match any loaded certificate." }
            }
        case .preset:
            if !hasCert { return "This needs a certificate." }
            if hasKey && !keyMatches { return "The private key does not match any loaded certificate." }
        }
        if needsOutputPassword && outputPassword.isEmpty { return "Set a password for the PKCS#12 file." }
        return nil
    }

    var canConvert: Bool { problem == nil }

    var options: OutputOptions {
        OutputOptions(password: outputPassword.isEmpty ? nil : outputPassword, legacy: legacy,
                      friendlyName: friendlyName.trimmingCharacters(in: .whitespaces).isEmpty ? nil : friendlyName,
                      includeChain: includeChain)
    }

    /// The output files (one for a format, several for a preset).
    func outputs() throws -> [OutputFile] {
        if let problem { throw SignFormError(problem) }
        switch target {
        case .format(let f):
            return [try CertConvert.convert(bundle, to: f, options: options, baseName: baseName)]
        case .preset(let p):
            return try CertConvert.export(bundle, for: p, options: options, baseName: baseName)
        }
    }

    /// Writes a preset's files into `<folder>/<base> for <preset>/` (keys 0600) and returns it.
    @discardableResult
    func write(_ files: [OutputFile], into folder: URL) throws -> URL {
        let title: String = switch target {
        case .preset(let p): p.title.replacingOccurrences(of: "/", with: "-")
        case .format: "converted"
        }
        var dir = folder.appendingPathComponent("\(baseName) for \(title)", isDirectory: true)
        var n = 2
        while FileManager.default.fileExists(atPath: dir.path) {
            dir = folder.appendingPathComponent("\(baseName) for \(title) \(n)", isDirectory: true)
            n += 1
        }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for f in files {
            let url = dir.appendingPathComponent(f.name)
            try Data(f.data).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: f.containsPrivateKey ? 0o600 : 0o644], ofItemAtPath: url.path)
        }
        lastResult = "Saved \(files.count) file\(files.count == 1 ? "" : "s") in “\(dir.lastPathComponent)”: " + files.map(\.name).joined(separator: ", ")
        return dir
    }

    // MARK: Tools

    private func clearTool() {
        toolLines = []
        toolOK = nil
    }

    /// Match key ↔ cert: which key belongs to which certificate.
    func match() {
        let b = bundle
        guard !b.keys.isEmpty, !b.certificates.isEmpty else {
            toolLines = ["Load a private key and a certificate to compare them."]
            toolOK = nil
            return
        }
        var ok = true
        toolLines = b.keys.map { k in
            if let c = b.certificate(for: k) {
                return "✓ The \(k.algorithm) key matches \(c.certificate.subject)."
            }
            ok = false
            return "✗ The \(k.algorithm) key matches none of the \(Self.count(b.certificates.count, "certificate"))."
        }
        toolOK = ok
    }

    /// Verify the leaf against CA certificates (the domain's CAs, or a chosen CA file).
    func verify(against roots: [CertificateItem], rootsName: String) async {
        let b = bundle
        guard let leaf = b.leaf else {
            toolLines = ["Load a certificate to verify."]
            toolOK = nil
            return
        }
        guard !roots.isEmpty else {
            toolLines = ["No CA certificate to verify against."]
            toolOK = false
            return
        }
        let intermediates = b.certificates.filter { $0 != leaf && !$0.isSelfIssued }
        let result = await CertConvert.verify(leaf, intermediates: intermediates, roots: roots)
        toolOK = result.valid
        toolLines = (result.valid ? ["✓ \(leaf.certificate.subject) chains to \(rootsName)."]
                     : ["✗ \(leaf.certificate.subject) does not chain to \(rootsName)."]) + result.lines()
    }

    /// Verify against the domain's CAs (the in-page button / the window when a domain exists).
    func verifyAgainstDomainCA() async {
        let roots = await caProvider?() ?? []
        await verify(against: roots, rootsName: "the LabDC CA")
    }
}
