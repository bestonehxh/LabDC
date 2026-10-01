import Foundation
import X509

/// Everything loaded from one or more inputs: certificates (input order), private keys and
/// certificate requests, plus what each input was.
public struct CertBundle: Equatable, Sendable {
    public var certificates: [CertificateItem]
    public var keys: [PrivateKeyItem]
    public var requests: [CSRItem]
    public var sources: [SourceInfo]

    public init(certificates: [CertificateItem] = [], keys: [PrivateKeyItem] = [], requests: [CSRItem] = [],
                sources: [SourceInfo] = []) {
        self.certificates = certificates
        self.keys = keys
        self.requests = requests
        self.sources = sources
    }

    /// Adds `other`, dropping certificates, keys and requests already present (same DER).
    public mutating func add(_ other: CertBundle) {
        for c in other.certificates where !certificates.contains(where: { $0.der == c.der }) { certificates.append(c) }
        for k in other.keys where !keys.contains(where: { $0.pkcs8 == k.pkcs8 }) { keys.append(k) }
        for r in other.requests where !requests.contains(where: { $0.der == r.der }) { requests.append(r) }
        sources += other.sources
    }

    /// The key conversions use: the first key.
    public var primaryKey: PrivateKeyItem? { keys.first }

    /// The end-entity certificate: the one matching the primary key; otherwise the first
    /// certificate that issued none of the others; otherwise the first.
    public var leaf: CertificateItem? {
        if let key = primaryKey, let c = certificates.first(where: { key.matches($0) }) { return c }
        return certificates.first { candidate in
            !certificates.contains { $0.der != candidate.der && $0.isIssued(by: candidate) }
        } ?? certificates.first
    }

    /// `leaf` followed by its issuers as far as the bundle holds them (signature-checked).
    public func chain(for leaf: CertificateItem) -> [CertificateItem] {
        var chain = [leaf]
        var current = leaf
        while !current.isSelfIssued,
              let issuer = certificates.first(where: { c in !chain.contains { $0.der == c.der } && current.isIssued(by: c) }) {
            chain.append(issuer)
            current = issuer
        }
        return chain
    }

    /// Leaf, its chain, then any unrelated certificates in input order.
    public var orderedCertificates: [CertificateItem] {
        guard let leaf else { return [] }
        let chain = chain(for: leaf)
        return chain + certificates.filter { c in !chain.contains { $0.der == c.der } }
    }

    /// The certificate matching `key`, if the bundle holds it.
    public func certificate(for key: PrivateKeyItem) -> CertificateItem? {
        certificates.first { key.matches($0) }
    }

    /// Whether the chain from the leaf ends in a self-issued certificate.
    public var chainIsComplete: Bool {
        guard let leaf else { return false }
        return chain(for: leaf).last?.isSelfIssued == true
    }

    /// Only the key entry named `alias` (PKCS#12 friendlyName / JKS alias) with its chain, or
    /// the certificate with that name.
    public func selecting(alias: String) throws -> CertBundle {
        if let key = keys.first(where: { $0.friendlyName == alias }) {
            var b = CertBundle(keys: [key], sources: sources)
            if let leaf = certificate(for: key) { b.certificates = chain(for: leaf) }
            return b
        }
        if let cert = certificates.first(where: { $0.friendlyName == alias }) {
            return CertBundle(certificates: chain(for: cert), sources: sources)
        }
        let names = Set(keys.compactMap(\.friendlyName) + certificates.compactMap(\.friendlyName)).sorted()
        throw CertConvertError.missing("no entry named \(alias) (entries: \(names.isEmpty ? "none named" : names.joined(separator: ", ")))")
    }
}

/// Entry points: detect, load, describe, verify, match, convert, export.
public enum CertConvert {
    /// Cheap format detection from the first bytes / structure; nil when unknown.
    public static func sniff(_ bytes: [UInt8]) -> InputFormat? {
        if bytes.starts(with: JKS.magic) { return .jks }
        if let text = String(bytes: bytes, encoding: .utf8), text.contains("-----BEGIN ") { return .pem }
        if let root = try? ASN.parsePrefix(bytes) { return classify(root) }
        if let der = bareBase64(bytes), let root = try? ASN.parsePrefix(der) { return classify(root) }
        return nil
    }

    /// True when loading `bytes` needs a password (tries without one).
    public static func needsPassword(_ bytes: [UInt8]) -> Bool {
        do {
            _ = try load(bytes)
            return false
        } catch CertConvertError.passwordRequired {
            return true
        } catch {
            return false
        }
    }

    public static func load(contentsOf url: URL, password: String? = nil, keyPassword: String? = nil) throws -> CertBundle {
        let data: Data
        do { data = try Data(contentsOf: url) } catch {
            throw CertConvertError.missing("cannot read \(url.path): \(error.localizedDescription)")
        }
        return try load([UInt8](data), name: url.lastPathComponent, password: password, keyPassword: keyPassword)
    }

    /// Loads any supported input. Throws `passwordRequired` when the input is encrypted and
    /// `password` is nil, `badPassword` when it is wrong.
    public static func load(_ bytes: [UInt8], name: String = "input", password: String? = nil,
                            keyPassword: String? = nil) throws -> CertBundle {
        if bytes.starts(with: JKS.jceksMagic) {
            throw CertConvertError.unsupported("\(name) is a JCEKS keystore; convert it with keytool -importkeystore -deststoretype pkcs12 first")
        }
        if bytes.starts(with: JKS.magic) {
            let c = try JKS.read(bytes, password: password, keyPassword: keyPassword)
            return CertBundle(certificates: c.certificates, keys: c.keys,
                              sources: [SourceInfo(name: name, format: .jks, protection: c.protection, notes: c.notes)])
        }
        if let text = String(bytes: bytes, encoding: .utf8), text.contains("-----BEGIN ") {
            return try loadPEM(text, name: name, password: password)
        }
        let der: [UInt8]
        if (try? ASN.parsePrefix(bytes)).flatMap(classify) != nil {
            der = bytes
        } else if let decoded = bareBase64(bytes) {
            der = decoded
        } else {
            throw CertConvertError.unrecognizedInput("\(name) is not PEM, DER, PKCS#7, PKCS#12 or JKS")
        }
        return try loadDER(der, name: name, password: password)
    }

    // MARK: Internals

    static func classify(_ root: ASN) -> InputFormat? {
        if PKCS12.looksLike(root) { return .pkcs12 }
        if PKCS7.looksLike(root) { return .pkcs7 }
        if EncryptedPKCS8.looksLike(root) { return .derEncryptedPrivateKey }
        let c = root.children
        if root.isSequence, c.count == 3, c[0].isSequence, c[1].isSequence, c[2].isUniversal(3) {
            let tbs = c[0].children
            if tbs.count == 4, tbs[3].isContext(0) { return .derCSR }
            if tbs.count >= 6 { return .derCertificate }
        }
        if (try? PrivateKeyItem(der: root.encoded)) != nil { return .derPrivateKey }
        return nil
    }

    /// Base64 text without PEM armour (pasted blobs); nil if it is not that.
    static func bareBase64(_ bytes: [UInt8]) -> [UInt8]? {
        guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }
        let compact = text.filter { !$0.isWhitespace }
        guard compact.count >= 16, compact.allSatisfy({ $0.isLetter || $0.isNumber || "+/=".contains($0) }),
              let data = Data(base64Encoded: compact) else { return nil }
        return [UInt8](data)
    }

    static func loadDER(_ der: [UInt8], name: String, password: String?) throws -> CertBundle {
        let root = try ASN.parsePrefix(der)
        guard let format = classify(root) else {
            throw CertConvertError.unrecognizedInput("\(name) is DER but not a certificate, key, PKCS#7 or PKCS#12")
        }
        var source = SourceInfo(name: name, format: format)
        var bundle = CertBundle()
        switch format {
        case .pkcs12:
            let c = try PKCS12.read(root, password: password)
            bundle.certificates = c.certificates
            bundle.keys = c.keys
            source.protection = c.protection
            source.notes = c.notes
        case .pkcs7:
            let (certs, crls, signers) = try PKCS7.read(root)
            bundle.certificates = try certs.map(CertificateItem.init(der:))
            if crls > 0 { source.notes.append("skipped \(crls) CRL\(crls == 1 ? "" : "s")") }
            if signers > 0 { source.notes.append("signed data with \(signers) signer\(signers == 1 ? "" : "s"); only the certificates were read") }
        case .derEncryptedPrivateKey:
            guard let password else { throw CertConvertError.passwordRequired("\(name) is an encrypted private key") }
            let (scheme, plain) = try EncryptedPKCS8.decrypt(root.encoded, password: password)
            var key = try PrivateKeyItem(der: plain)
            key.protection = scheme.description
            bundle.keys = [key]
            source.protection = ["key: \(scheme)"]
        case .derCertificate:
            bundle.certificates = [try CertificateItem(der: root.encoded)]
        case .derCSR:
            bundle.requests = [try CSRItem(der: root.encoded)]
        case .derPrivateKey:
            bundle.keys = [try PrivateKeyItem(der: root.encoded)]
        case .pem, .jks:
            break
        }
        bundle.sources = [source]
        return bundle
    }

    static func loadPEM(_ text: String, name: String, password: String?) throws -> CertBundle {
        let blocks = try PEMBlock.parseAll(text)
        guard !blocks.isEmpty else { throw CertConvertError.unrecognizedInput("\(name) has no complete PEM block") }
        var bundle = CertBundle()
        var source = SourceInfo(name: name, format: .pem)
        for block in blocks {
            switch block.label {
            case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
                // TRUSTED CERTIFICATE (OpenSSL) appends trust settings after the certificate.
                let cert = try CertificateItem(der: try ASN.parsePrefix(block.der).encoded)
                if !bundle.certificates.contains(where: { $0.der == cert.der }) { bundle.certificates.append(cert) }
            case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
                bundle.requests.append(try CSRItem(der: block.der))
            case "PRIVATE KEY":
                bundle.keys.append(try PrivateKeyItem(der: block.der))
            case "RSA PRIVATE KEY", "EC PRIVATE KEY":
                if block.headers["Proc-Type"]?.contains("ENCRYPTED") == true {
                    guard let password else { throw CertConvertError.passwordRequired("the \(block.label) in \(name) is encrypted") }
                    var key = try PrivateKeyItem(der: try PrivateKeyItem.decryptTraditional(block, password: password))
                    key.protection = "PEM \(block.headers["DEK-Info"]?.split(separator: ",").first ?? "encrypted")"
                    source.protection.append("key: \(key.protection!)")
                    bundle.keys.append(key)
                } else {
                    bundle.keys.append(try PrivateKeyItem(der: block.der))
                }
            case "ENCRYPTED PRIVATE KEY":
                guard let password else { throw CertConvertError.passwordRequired("the private key in \(name) is encrypted") }
                let (scheme, plain) = try EncryptedPKCS8.decrypt(block.der, password: password)
                var key = try PrivateKeyItem(der: plain)
                key.protection = scheme.description
                source.protection.append("key: \(scheme)")
                bundle.keys.append(key)
            case "PKCS7", "CMS":
                let (certs, crls, _) = try PKCS7.read(try ASN.parse(block.der))
                for c in try certs.map(CertificateItem.init(der:)) where !bundle.certificates.contains(where: { $0.der == c.der }) {
                    bundle.certificates.append(c)
                }
                if crls > 0 { source.notes.append("skipped \(crls) CRL\(crls == 1 ? "" : "s") in the PKCS#7 block") }
            case "EC PARAMETERS":
                break
            default:
                source.notes.append("skipped a \(block.label) block")
            }
        }
        bundle.sources = [source]
        return bundle
    }
}
