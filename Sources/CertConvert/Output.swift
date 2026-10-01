import Foundation
import X509

/// Conversion targets (`labdc cert convert --to`).
public enum OutputFormat: String, CaseIterable, Equatable, Sendable {
    /// Certificates as PEM: leaf first, then its chain, then anything else loaded.
    case pem
    /// The leaf certificate as DER.
    case der
    /// PKCS#7 certificate bag (DER), leaf first.
    case p7b
    /// PKCS#12 with the key, leaf and chain (needs a key and a password).
    case p12
    /// The private key as PKCS#8 PEM (`ENCRYPTED PRIVATE KEY` with a password).
    case keyPKCS8 = "key-pkcs8"
    /// The private key as PKCS#1 (RSA) / SEC1 (EC) PEM.
    case keyPKCS1 = "key-pkcs1"
    /// Key (PKCS#8 PEM), leaf, chain in one PEM file.
    case combined

    /// Default file extension.
    public var fileExtension: String {
        switch self {
        case .pem: "pem"
        case .der: "cer"
        case .p7b: "p7b"
        case .p12: "p12"
        case .keyPKCS8, .keyPKCS1: "key"
        case .combined: "pem"
        }
    }

    public init?(argument: String) {
        switch argument.lowercased() {
        case "pem", "crt": self = .pem
        case "der", "cer": self = .der
        case "p7b", "p7c", "pkcs7": self = .p7b
        case "p12", "pfx", "pkcs12": self = .p12
        case "key-pkcs8", "pkcs8", "key": self = .keyPKCS8
        case "key-pkcs1", "key-sec1", "pkcs1", "sec1", "key-traditional": self = .keyPKCS1
        case "combined", "bundle": self = .combined
        default: return nil
        }
    }
}

/// Options shared by `convert` and `export`.
public struct OutputOptions: Equatable, Sendable {
    /// PKCS#12 password (required for p12), and, when set, the password the key is encrypted
    /// with in key/combined PEM outputs.
    public var password: String?
    /// PKCS#12: 3DES + SHA-1 MAC instead of AES-256 + SHA-256; PEM keys: 3DES instead of AES-256.
    public var legacy: Bool
    /// PKCS#12 friendlyName for the key and leaf.
    public var friendlyName: String?
    /// Include the issuer chain (and other loaded certificates) in pem/p7b/p12/combined.
    public var includeChain: Bool
    /// PBKDF/MAC iteration count for written PKCS#12 and encrypted keys.
    public var iterations: Int

    public init(password: String? = nil, legacy: Bool = false, friendlyName: String? = nil, includeChain: Bool = true,
                iterations: Int = 2048) {
        self.password = password
        self.legacy = legacy
        self.friendlyName = friendlyName
        self.includeChain = includeChain
        self.iterations = iterations
    }
}

/// One produced file.
public struct OutputFile: Equatable, Sendable {
    /// Suggested file name (`<base>.<ext>`).
    public var name: String
    public var data: [UInt8]
    /// Holds a private key: write it with mode 0600.
    public var containsPrivateKey: Bool
    /// One line describing the content, e.g. "PKCS#12 (AES-256-CBC, MAC sha256): key + 3 certificates".
    public var summary: String

    public init(name: String, data: [UInt8], containsPrivateKey: Bool, summary: String) {
        self.name = name
        self.data = data
        self.containsPrivateKey = containsPrivateKey
        self.summary = summary
    }
}

/// "Export for" presets: named bundles of files that a device or OS accepts.
public enum ExportPreset: String, CaseIterable, Equatable, Sendable {
    /// Aruba ClearPass: PFX with key and full chain (server certificate import); without a key,
    /// a PEM of the certificates for the trust list.
    case clearpass
    /// Huawei iMaster NCE: PEM certificate and PEM (PKCS#8) key as separate files, plus the chain.
    case imaster
    /// Aruba / Huawei switches: PEM certificate, PKCS#1/SEC1 key, chain, and all three combined.
    case `switch`
    /// Windows: PFX with chain, leaf as DER `.cer`, chain as `.p7b`.
    case windows
    /// macOS: `.p12` with chain, plus the certificates as PEM.
    case macos

    public var title: String {
        switch self {
        case .clearpass: "Aruba ClearPass"
        case .imaster: "Huawei iMaster NCE"
        case .switch: "Aruba / Huawei switch"
        case .windows: "Windows"
        case .macos: "macOS"
        }
    }
}

extension CertConvert {
    /// Converts a loaded bundle to one output file.
    public static func convert(_ bundle: CertBundle, to format: OutputFormat, options: OutputOptions = OutputOptions(),
                               baseName: String = "output") throws -> OutputFile {
        let name = "\(baseName).\(format.fileExtension)"
        switch format {
        case .pem:
            let certs = try certificates(bundle, options)
            return OutputFile(name: name, data: Array(certs.map(\.pem).joined().utf8), containsPrivateKey: false,
                              summary: "PEM: \(count(certs.count, "certificate"))")
        case .der:
            guard let leaf = bundle.leaf else { throw CertConvertError.missing("no certificate to write") }
            return OutputFile(name: name, data: leaf.der, containsPrivateKey: false, summary: "DER certificate \(leaf.certificate.subject)")
        case .p7b:
            let certs = try certificates(bundle, options)
            return OutputFile(name: name, data: PKCS7.write(certificates: certs.map(\.der)), containsPrivateKey: false,
                              summary: "PKCS#7: \(count(certs.count, "certificate"))")
        case .p12:
            let (key, certs) = try keyAndChain(bundle, options, what: "PKCS#12")
            guard let password = options.password else {
                throw CertConvertError.invalidOptions("PKCS#12 output needs a password")
            }
            let data = try PKCS12.write(key: key, certificates: certs, password: password,
                                        profile: options.legacy ? .legacy : .modern,
                                        friendlyName: options.friendlyName ?? key.friendlyName ?? certs.first?.friendlyName,
                                        iterations: options.iterations)
            let enc = options.legacy ? "3DES, MAC sha1" : "AES-256-CBC, MAC sha256"
            return OutputFile(name: name, data: data, containsPrivateKey: true,
                              summary: "PKCS#12 (\(enc)): key + \(count(certs.count, "certificate"))")
        case .keyPKCS8, .keyPKCS1:
            guard let key = bundle.primaryKey else { throw CertConvertError.missing("no private key to write (add --key)") }
            let encoding: KeyEncoding = format == .keyPKCS8 ? .pkcs8 : .traditional
            let text = try key.pem(encoding, password: options.password, legacy: options.legacy)
            let kind = encoding == .pkcs8 ? "PKCS#8" : (key.algorithm.isRSA ? "PKCS#1" : "SEC1")
            return OutputFile(name: name, data: Array(text.utf8), containsPrivateKey: true,
                              summary: "\(key.algorithm) key, \(kind) PEM\(options.password == nil ? "" : ", encrypted")")
        case .combined:
            let (key, certs) = try keyAndChain(bundle, options, what: "combined PEM")
            let text = try key.pem(.pkcs8, password: options.password, legacy: options.legacy) + certs.map(\.pem).joined()
            return OutputFile(name: name, data: Array(text.utf8), containsPrivateKey: true,
                              summary: "PEM: key\(options.password == nil ? "" : " (encrypted)") + \(count(certs.count, "certificate"))")
        }
    }

    /// Every certificate as its own file (`<base>-1.cer`, ...), leaf first.
    public static func splitCertificates(_ bundle: CertBundle, pem: Bool, baseName: String = "output") -> [OutputFile] {
        bundle.orderedCertificates.enumerated().map { i, c in
            OutputFile(name: "\(baseName)-\(i + 1).\(pem ? "pem" : "cer")", data: pem ? Array(c.pem.utf8) : c.der,
                       containsPrivateKey: false, summary: "\(c.certificate.subject)")
        }
    }

    /// Produces the files of an export preset.
    public static func export(_ bundle: CertBundle, for preset: ExportPreset, options: OutputOptions = OutputOptions(),
                              baseName: String = "certificate") throws -> [OutputFile] {
        guard let leaf = bundle.leaf else { throw CertConvertError.missing("no certificate to export") }
        let key = bundle.primaryKey
        if let key, !key.matches(leaf) {
            throw CertConvertError.missing("the private key does not match any loaded certificate")
        }
        let chain = bundle.orderedCertificates
        let issuers = Array(chain.dropFirst())
        var files: [OutputFile] = []
        func pemFile(_ name: String, _ certs: [CertificateItem], _ what: String) {
            files.append(OutputFile(name: name, data: Array(certs.map(\.pem).joined().utf8), containsPrivateKey: false,
                                    summary: "\(what): \(count(certs.count, "certificate")) (PEM)"))
        }
        func pfx(_ ext: String) throws {
            guard options.password != nil else {
                throw CertConvertError.invalidOptions("the \(preset.title) PFX needs a password")
            }
            var f = try convert(bundle, to: .p12, options: options, baseName: baseName)
            f.name = "\(baseName).\(ext)"
            files.append(f)
        }
        switch preset {
        case .clearpass:
            if key != nil {
                try pfx("pfx")
            } else {
                pemFile("\(baseName)-trust.pem", chain, "certificates for the ClearPass trust list")
            }
        case .imaster:
            pemFile("\(baseName).crt", [leaf], "certificate")
            if let key {
                files.append(OutputFile(name: "\(baseName).key",
                                        data: Array(try key.pem(.pkcs8, password: options.password, legacy: options.legacy).utf8),
                                        containsPrivateKey: true,
                                        summary: "private key (PKCS#8 PEM\(options.password == nil ? ", NOT encrypted" : ", encrypted"))"))
            }
            if !issuers.isEmpty { pemFile("\(baseName)-chain.crt", issuers, "CA chain") }
        case .switch:
            pemFile("\(baseName).crt", [leaf], "certificate")
            if !issuers.isEmpty { pemFile("\(baseName)-ca.crt", issuers, "CA chain") }
            if let key {
                let keyPEM = try key.pem(.traditional, password: options.password, legacy: options.legacy)
                let kind = key.algorithm.isRSA ? "PKCS#1" : "SEC1"
                files.append(OutputFile(name: "\(baseName).key", data: Array(keyPEM.utf8), containsPrivateKey: true,
                                        summary: "private key (\(kind) PEM\(options.password == nil ? "" : ", encrypted"))"))
                files.append(OutputFile(name: "\(baseName)-combined.pem",
                                        data: Array((chain.map(\.pem).joined() + keyPEM).utf8), containsPrivateKey: true,
                                        summary: "certificate + chain + key (PEM)"))
            }
        case .windows:
            if key != nil { try pfx("pfx") }
            files.append(OutputFile(name: "\(baseName).cer", data: leaf.der, containsPrivateKey: false,
                                    summary: "certificate (DER)"))
            if chain.count > 1 {
                files.append(OutputFile(name: "\(baseName)-chain.p7b", data: PKCS7.write(certificates: chain.map(\.der)),
                                        containsPrivateKey: false, summary: "chain: \(count(chain.count, "certificate")) (PKCS#7)"))
            }
        case .macos:
            if key != nil { try pfx("p12") }
            pemFile("\(baseName).pem", chain, "certificates")
        }
        return files
    }

    private static func certificates(_ bundle: CertBundle, _ options: OutputOptions) throws -> [CertificateItem] {
        let certs = bundle.orderedCertificates
        guard let first = certs.first else { throw CertConvertError.missing("no certificate to write") }
        return options.includeChain ? certs : [first]
    }

    private static func keyAndChain(_ bundle: CertBundle, _ options: OutputOptions,
                                    what: String) throws -> (PrivateKeyItem, [CertificateItem]) {
        guard let key = bundle.primaryKey else { throw CertConvertError.missing("\(what) output needs the private key (add --key)") }
        guard let leaf = bundle.certificate(for: key) else {
            throw CertConvertError.missing(bundle.certificates.isEmpty
                ? "\(what) output needs the certificate too"
                : "the private key does not match any loaded certificate")
        }
        let certs = bundle.orderedCertificates
        precondition(certs.first == leaf)
        return (key, options.includeChain ? certs : [leaf])
    }

    private static func count(_ n: Int, _ noun: String) -> String { "\(n) \(noun)\(n == 1 ? "" : "s")" }
}

extension KeyAlgorithm {
    var isRSA: Bool { if case .rsa = self { true } else { false } }
}
