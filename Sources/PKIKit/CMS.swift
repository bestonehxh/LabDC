import _CryptoExtras
import CommonCrypto
import CryptoKit
import Foundation
import SwiftASN1
import X509

// PK-7: the minimal CMS (RFC 5652) / PKCS#7 (RFC 2315) SCEP needs. swift-certificates only has
// an internal SignedData (behind `@_spi(CMS)`, without caller-chosen signed attributes) and no
// EnvelopedData, so both are read with SwiftASN1 (`ASNReader`, DER or BER) and written with
// `DERWriter`. RSA key transport (PKCS#1 v1.5 and OAEP) comes from `_CryptoExtras`; the content
// ciphers (AES-CBC, 3DES-CBC, single DES for old devices) from CommonCrypto.

enum CMSOID {
    static let data = "1.2.840.113549.1.7.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let envelopedData = "1.2.840.113549.1.7.3"
    static let contentType = "1.2.840.113549.1.9.3"
    static let messageDigest = "1.2.840.113549.1.9.4"
    static let signingTime = "1.2.840.113549.1.9.5"
    static let challengePassword = "1.2.840.113549.1.9.7"
    static let extensionRequest = "1.2.840.113549.1.9.14"
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let rsaesOAEP = "1.2.840.113549.1.1.7"
    static let mgf1 = "1.2.840.113549.1.1.8"
    static let sha1WithRSA = "1.2.840.113549.1.1.5"
    static let sha256WithRSA = "1.2.840.113549.1.1.11"
    static let sha384WithRSA = "1.2.840.113549.1.1.12"
    static let sha512WithRSA = "1.2.840.113549.1.1.13"
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    static let ecPublicKey = "1.2.840.10045.2.1"
}

/// The digest of a SignerInfo.
enum CMSDigest: String, Sendable, CaseIterable {
    case sha1 = "SHA-1", sha256 = "SHA-256", sha384 = "SHA-384", sha512 = "SHA-512"

    var oid: String {
        switch self {
        case .sha1: "1.3.14.3.2.26"
        case .sha256: "2.16.840.1.101.3.4.2.1"
        case .sha384: "2.16.840.1.101.3.4.2.2"
        case .sha512: "2.16.840.1.101.3.4.2.3"
        }
    }

    /// Also accepts the `shaNWithRSAEncryption` OIDs some clients put in the digest field.
    init?(oid: String) {
        switch oid {
        case "1.3.14.3.2.26", CMSOID.sha1WithRSA: self = .sha1
        case "2.16.840.1.101.3.4.2.1", CMSOID.sha256WithRSA: self = .sha256
        case "2.16.840.1.101.3.4.2.2", CMSOID.sha384WithRSA: self = .sha384
        case "2.16.840.1.101.3.4.2.3", CMSOID.sha512WithRSA: self = .sha512
        default: return nil
        }
    }

    /// `AlgorithmIdentifier`: parameters absent for SHA-2 (RFC 5754), NULL for SHA-1.
    var algorithmDER: [UInt8] { DERWriter.algorithm(oid, self == .sha1 ? DERWriter.null : nil) }

    func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .sha1: Array(Insecure.SHA1.hash(data: bytes))
        case .sha256: Array(SHA256.hash(data: bytes))
        case .sha384: Array(SHA384.hash(data: bytes))
        case .sha512: Array(SHA512.hash(data: bytes))
        }
    }

    func isValidRSASignature(_ signature: [UInt8], for data: [UInt8], key: _RSA.Signing.PublicKey) -> Bool {
        let sig = _RSA.Signing.RSASignature(rawRepresentation: signature)
        switch self {
        case .sha1: return key.isValidSignature(sig, for: Insecure.SHA1.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha256: return key.isValidSignature(sig, for: SHA256.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha384: return key.isValidSignature(sig, for: SHA384.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha512: return key.isValidSignature(sig, for: SHA512.hash(data: data), padding: .insecurePKCS1v1_5)
        }
    }

    func rsaSign(_ data: [UInt8], key: _RSA.Signing.PrivateKey) throws -> [UInt8] {
        let sig: _RSA.Signing.RSASignature
        switch self {
        case .sha1: sig = try key.signature(for: Insecure.SHA1.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha256: sig = try key.signature(for: SHA256.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha384: sig = try key.signature(for: SHA384.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha512: sig = try key.signature(for: SHA512.hash(data: data), padding: .insecurePKCS1v1_5)
        }
        return Array(sig.rawRepresentation)
    }
}

/// The content-encryption algorithm of an EnvelopedData.
enum CMSContentCipher: String, Sendable, CaseIterable {
    case des = "DES-CBC", des3 = "3DES-CBC", aes128 = "AES-128-CBC", aes192 = "AES-192-CBC", aes256 = "AES-256-CBC"

    var oid: String {
        switch self {
        case .des: "1.3.14.3.2.7"
        case .des3: "1.2.840.113549.3.7"
        case .aes128: "2.16.840.1.101.3.4.1.2"
        case .aes192: "2.16.840.1.101.3.4.1.22"
        case .aes256: "2.16.840.1.101.3.4.1.42"
        }
    }

    init?(oid: String) {
        guard let c = Self.allCases.first(where: { $0.oid == oid }) else { return nil }
        self = c
    }

    var keyLength: Int {
        switch self {
        case .des: 8
        case .des3: 24
        case .aes128: 16
        case .aes192: 24
        case .aes256: 32
        }
    }

    var blockSize: Int { self == .des || self == .des3 ? 8 : 16 }

    private var ccAlgorithm: CCAlgorithm {
        switch self {
        case .des: CCAlgorithm(kCCAlgorithmDES)
        case .des3: CCAlgorithm(kCCAlgorithm3DES)
        default: CCAlgorithm(kCCAlgorithmAES)
        }
    }

    /// CBC with PKCS#7 padding.
    func crypt(encrypt: Bool, key: [UInt8], iv: [UInt8], _ input: [UInt8]) throws -> [UInt8] {
        guard key.count == keyLength, iv.count == blockSize else { throw ASNError("\(rawValue): bad key or IV length") }
        if !encrypt, input.isEmpty || input.count % blockSize != 0 {
            throw ASNError("\(rawValue): ciphertext is not a whole number of blocks")
        }
        var out = [UInt8](repeating: 0, count: input.count + blockSize)
        var moved = 0
        let status = CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), ccAlgorithm, CCOptions(kCCOptionPKCS7Padding),
                             key, key.count, iv, input, input.count, &out, out.count, &moved)
        guard status == kCCSuccess else { throw ASNError("\(rawValue) \(encrypt ? "encryption" : "decryption") failed (\(status))") }
        return Array(out.prefix(moved))
    }
}

/// RSA key transport of the content-encryption key.
enum CMSKeyTransport: String, Sendable, CaseIterable {
    case pkcs1v15 = "RSA PKCS#1 v1.5", oaepSHA1 = "RSA-OAEP (SHA-1)", oaepSHA256 = "RSA-OAEP (SHA-256)"

    /// From a `keyEncryptionAlgorithm` AlgorithmIdentifier.
    static func parse(_ algorithm: ASNReader) throws -> CMSKeyTransport {
        let oid = try algorithm.child(0).oid()
        switch oid {
        case CMSOID.rsaEncryption: return .pkcs1v15
        case CMSOID.rsaesOAEP:
            // RSAES-OAEP-params ::= SEQUENCE { [0] hashAlgorithm DEFAULT sha1, [1] maskGenAlgorithm DEFAULT mgf1SHA1, [2] pSource }
            var hash = "1.3.14.3.2.26"
            var mgfHash = "1.3.14.3.2.26"
            if let params = algorithm.children.dropFirst().first, params.isSequence {
                for p in params.children {
                    if p.isContext(0) { hash = try p.child(0).child(0).oid() }
                    if p.isContext(1) {
                        let mgf = try p.child(0)
                        guard try mgf.child(0).oid() == CMSOID.mgf1 else { throw ASNError("RSA-OAEP: unsupported mask generation") }
                        mgfHash = try mgf.child(1).child(0).oid()
                    }
                    if p.isContext(2) { throw ASNError("RSA-OAEP: a label (pSource) is not supported") }
                }
            }
            switch (hash, mgfHash) {
            case ("1.3.14.3.2.26", "1.3.14.3.2.26"): return .oaepSHA1
            case (CMSDigest.sha256.oid, CMSDigest.sha256.oid): return .oaepSHA256
            default: throw ASNError("RSA-OAEP with hash \(hash) / MGF1 \(mgfHash) is not supported")
            }
        default:
            throw ASNError("key transport \(oid) is not supported")
        }
    }

    var algorithmDER: [UInt8] {
        switch self {
        case .pkcs1v15: DERWriter.algorithm(CMSOID.rsaEncryption, DERWriter.null)
        case .oaepSHA1: DERWriter.algorithm(CMSOID.rsaesOAEP, DERWriter.sequence([]))
        case .oaepSHA256:
            DERWriter.algorithm(CMSOID.rsaesOAEP, DERWriter.sequence([
                DERWriter.explicit(0, CMSDigest.sha256.algorithmDER),
                DERWriter.explicit(1, DERWriter.algorithm(CMSOID.mgf1, CMSDigest.sha256.algorithmDER)),
            ]))
        }
    }

    var padding: _RSA.Encryption.Padding {
        switch self {
        case .pkcs1v15: ._WEAK_AND_INSECURE_PKCS_V1_5
        case .oaepSHA1: .PKCS1_OAEP
        case .oaepSHA256: .PKCS1_OAEP_SHA256
        }
    }
}

/// `IssuerAndSerialNumber` or `[0] SubjectKeyIdentifier`.
enum CMSIdentifier: Equatable, Sendable {
    case issuerSerial(issuer: [UInt8], serial: [UInt8])
    case subjectKeyIdentifier([UInt8])

    static func parse(_ node: ASNReader) throws -> CMSIdentifier {
        if node.isSequence {
            return .issuerSerial(issuer: try node.child(0).encoded, serial: try node.child(1).unsignedInteger())
        }
        if node.isContext(0) { return .subjectKeyIdentifier(node.bytes) }
        throw ASNError("unknown signer/recipient identifier")
    }

    /// The certificate's own issuer (raw DER Name) and serial.
    static func of(certificateDER der: [UInt8]) throws -> CMSIdentifier {
        let tbs = try ASNReader.parse(der).child(0)
        var i = 0
        if try tbs.child(0).isContext(0) { i = 1 }
        return .issuerSerial(issuer: try tbs.child(i + 2).encoded, serial: try tbs.child(i).unsignedInteger())
    }

    func matches(_ certificate: Certificate, der: [UInt8]) -> Bool {
        switch self {
        case .issuerSerial:
            return (try? Self.of(certificateDER: der)) == self
        case .subjectKeyIdentifier(let ski):
            guard let own = try? certificate.extensions.subjectKeyIdentifier?.keyIdentifier else { return false }
            return Array(own) == ski
        }
    }

    /// `IssuerAndSerialNumber` DER (issuerSerial only).
    var der: [UInt8] {
        switch self {
        case .issuerSerial(let issuer, let serial): DERWriter.sequence([issuer, DERWriter.unsignedInteger(serial)])
        case .subjectKeyIdentifier(let ski): DERWriter.implicitPrimitive(0, ski)
        }
    }
}

struct CMSSignerInfo {
    var sid: CMSIdentifier
    var digestOID: String
    /// The signed attributes re-tagged as `SET OF` (what the signature covers).
    var signedAttributesDER: [UInt8]?
    var attributes: [(oid: String, values: [ASNReader])]
    var signatureAlgorithmOID: String
    var signature: [UInt8]

    func attribute(_ oid: String) -> ASNReader? { attributes.first { $0.oid == oid }?.values.first }
}

/// A parsed `ContentInfo { signedData }`.
struct CMSSignedMessage {
    var contentType: String
    /// The encapsulated content (nil when absent / detached).
    var content: [UInt8]?
    var certificates: [[UInt8]]
    var crls: [[UInt8]]
    var signers: [CMSSignerInfo]

    static func parse(_ bytes: [UInt8]) throws -> CMSSignedMessage {
        let ci = try ASNReader.parse(bytes)
        guard ci.isSequence, try ci.child(0).oid() == CMSOID.signedData else { throw ASNError("not a PKCS#7 SignedData") }
        let sd = try ci.child(1).child(0)
        guard sd.isSequence else { throw ASNError("SignedData is not a SEQUENCE") }
        let parts = sd.children
        guard parts.count >= 4 else { throw ASNError("SignedData is too short") }
        let encap = parts[2]
        let contentType = try encap.child(0).oid()
        var content: [UInt8]?
        if let wrapped = encap.children.dropFirst().first {
            guard wrapped.isContext(0) else { throw ASNError("eContent is not [0]") }
            let inner = try wrapped.child(0)
            content = inner.isUniversal(4) ? inner.bytes : inner.encoded
        }
        var certificates: [[UInt8]] = []
        var crls: [[UInt8]] = []
        var signerSet: ASNReader?
        for p in parts.dropFirst(3) {
            if p.isContext(0) { certificates = p.children.filter(\.isSequence).map(\.encoded) }
            else if p.isContext(1) { crls = p.children.map(\.encoded) }
            else if p.isSet { signerSet = p }
        }
        guard let signerSet else { throw ASNError("SignedData has no signerInfos") }
        var signers: [CMSSignerInfo] = []
        for si in signerSet.children {
            let f = si.children
            guard f.count >= 5 else { throw ASNError("SignerInfo is too short") }
            let sid = try CMSIdentifier.parse(f[1])
            let digestOID = try f[2].child(0).oid()
            var i = 3
            var signedDER: [UInt8]?
            var attributes: [(String, [ASNReader])] = []
            if f[i].isContext(0) {
                var raw = f[i].encoded
                raw[0] = 0x31
                signedDER = raw
                for a in f[i].children {
                    attributes.append((try a.child(0).oid(), try a.child(1).children))
                }
                i += 1
            }
            guard i + 1 < f.count else { throw ASNError("SignerInfo has no signature") }
            let algorithm = try f[i].child(0).oid()
            let signature = try f[i + 1].octets()
            signers.append(CMSSignerInfo(sid: sid, digestOID: digestOID, signedAttributesDER: signedDER,
                                         attributes: attributes, signatureAlgorithmOID: algorithm, signature: signature))
        }
        return CMSSignedMessage(contentType: contentType, content: content, certificates: certificates, crls: crls,
                                signers: signers)
    }
}

/// A parsed `ContentInfo { envelopedData }` (key-transport recipients only).
struct CMSEnvelopedMessage {
    struct Recipient {
        var rid: CMSIdentifier
        var algorithm: ASNReader
        var encryptedKey: [UInt8]
    }

    var recipients: [Recipient]
    var contentType: String
    var cipherOID: String
    var cipherParameters: ASNReader?
    var encryptedContent: [UInt8]

    static func parse(_ bytes: [UInt8]) throws -> CMSEnvelopedMessage {
        let ci = try ASNReader.parse(bytes)
        guard ci.isSequence, try ci.child(0).oid() == CMSOID.envelopedData else { throw ASNError("not a PKCS#7 EnvelopedData") }
        let ed = try ci.child(1).child(0)
        var parts = ed.children
        guard parts.count >= 3 else { throw ASNError("EnvelopedData is too short") }
        parts.removeFirst() // version
        if parts.first?.isContext(0) == true { parts.removeFirst() } // originatorInfo
        guard let set = parts.first, set.isSet, parts.count >= 2 else { throw ASNError("EnvelopedData has no recipientInfos") }
        var recipients: [Recipient] = []
        for ri in set.children where ri.isSequence {  // KeyTransRecipientInfo; kari/kekri/pwri are tagged
            recipients.append(Recipient(rid: try CMSIdentifier.parse(try ri.child(1)), algorithm: try ri.child(2),
                                        encryptedKey: try ri.child(3).octets()))
        }
        let eci = parts[1]
        let alg = try eci.child(1)
        guard let encrypted = eci.children.dropFirst(2).first, encrypted.isContext(0) else {
            throw ASNError("EnvelopedData has no encryptedContent")
        }
        return CMSEnvelopedMessage(recipients: recipients, contentType: try eci.child(0).oid(), cipherOID: try alg.child(0).oid(),
                                   cipherParameters: alg.children.dropFirst().first, encryptedContent: encrypted.bytes)
    }

    /// Unwraps the content-encryption key with `key` (trying the recipient that names
    /// `certificate` first) and decrypts the content.
    func decrypt(certificate: Certificate, certificateDER: [UInt8], key: _RSA.Encryption.PrivateKey) throws
        -> (plaintext: [UInt8], cipher: CMSContentCipher, keyTransport: CMSKeyTransport) {
        guard let cipher = CMSContentCipher(oid: cipherOID) else { throw ASNError("content cipher \(cipherOID) is not supported") }
        guard let iv = cipherParameters.flatMap({ try? $0.octets() }), iv.count == cipher.blockSize else {
            throw ASNError("\(cipher.rawValue): missing or bad IV")
        }
        guard !recipients.isEmpty else { throw ASNError("EnvelopedData has no key-transport recipient") }
        let ordered = recipients.filter { $0.rid.matches(certificate, der: certificateDER) }
            + recipients.filter { !$0.rid.matches(certificate, der: certificateDER) }
        var lastError: Error = ASNError("no recipient")
        for r in ordered {
            do {
                let transport = try CMSKeyTransport.parse(r.algorithm)
                let cek = Array(try key.decrypt(r.encryptedKey, padding: transport.padding))
                guard cek.count == cipher.keyLength else { throw ASNError("content key has \(cek.count) bytes, \(cipher.rawValue) needs \(cipher.keyLength)") }
                return (try cipher.crypt(encrypt: false, key: cek, iv: iv, encryptedContent), cipher, transport)
            } catch {
                lastError = error
            }
        }
        throw ASNError("cannot decrypt the EnvelopedData: \(lastError)")
    }
}

enum CMS {
    static func contentInfo(_ type: String, _ content: [UInt8]) -> [UInt8] {
        DERWriter.sequence([DERWriter.oid(type), DERWriter.explicit(0, content)])
    }

    static func attribute(_ oid: String, _ values: [[UInt8]]) -> [UInt8] {
        DERWriter.sequence([DERWriter.oid(oid), DERWriter.setOf(values)])
    }

    /// A degenerate ("certs-only") SignedData: certificates and CRLs, no content, no signers.
    static func certsOnly(certificates: [[UInt8]], crls: [[UInt8]] = []) -> [UInt8] {
        var parts = [DERWriter.integer(1), DERWriter.tlv(0x31, []), DERWriter.sequence([DERWriter.oid(CMSOID.data)])]
        if !certificates.isEmpty { parts.append(DERWriter.tlv(0xA0, sortedSet(certificates))) }
        if !crls.isEmpty { parts.append(DERWriter.tlv(0xA1, sortedSet(crls))) }
        parts.append(DERWriter.tlv(0x31, []))
        return contentInfo(CMSOID.signedData, DERWriter.sequence(parts))
    }

    /// SignedData over `content` (id-data; nil = no eContent, the digest is of the empty
    /// string) with one RSA signer. `attributes` are added to contentType + messageDigest.
    static func signed(content: [UInt8]?, signerDER: [UInt8], signerKey: _RSA.Signing.PrivateKey, digest: CMSDigest,
                       attributes: [[UInt8]], certificates: [[UInt8]]) throws -> [UInt8] {
        let all = [attribute(CMSOID.contentType, [DERWriter.oid(CMSOID.data)]),
                   attribute(CMSOID.messageDigest, [DERWriter.octetString(digest.hash(content ?? []))])] + attributes
        let set = DERWriter.setOf(all)
        let signature = try digest.rsaSign(set, key: signerKey)
        var implicit = set
        implicit[0] = 0xA0
        let signerInfo = DERWriter.sequence([
            DERWriter.integer(1), try CMSIdentifier.of(certificateDER: signerDER).der, digest.algorithmDER, implicit,
            DERWriter.algorithm(CMSOID.rsaEncryption, DERWriter.null), DERWriter.octetString(signature),
        ])
        var encap = [DERWriter.oid(CMSOID.data)]
        if let content { encap.append(DERWriter.explicit(0, DERWriter.octetString(content))) }
        let sd = DERWriter.sequence([
            DERWriter.integer(1), DERWriter.tlv(0x31, digest.algorithmDER), DERWriter.sequence(encap),
            DERWriter.tlv(0xA0, sortedSet(certificates)), DERWriter.tlv(0x31, signerInfo),
        ])
        return contentInfo(CMSOID.signedData, sd)
    }

    /// EnvelopedData of `plaintext` (id-data) for the RSA key of `recipientDER`.
    static func envelope(_ plaintext: [UInt8], recipientDER: [UInt8], recipientKey: _RSA.Encryption.PublicKey,
                         cipher: CMSContentCipher, keyTransport: CMSKeyTransport) throws -> [UInt8] {
        let cek = randomBytes(cipher.keyLength)
        let iv = randomBytes(cipher.blockSize)
        let encrypted = try cipher.crypt(encrypt: true, key: cek, iv: iv, plaintext)
        let wrapped = Array(try recipientKey.encrypt(cek, padding: keyTransport.padding))
        let ktri = DERWriter.sequence([
            DERWriter.integer(0), try CMSIdentifier.of(certificateDER: recipientDER).der, keyTransport.algorithmDER,
            DERWriter.octetString(wrapped),
        ])
        let eci = DERWriter.sequence([
            DERWriter.oid(CMSOID.data), DERWriter.algorithm(cipher.oid, DERWriter.octetString(iv)),
            DERWriter.implicitPrimitive(0, encrypted),
        ])
        return contentInfo(CMSOID.envelopedData, DERWriter.sequence([DERWriter.integer(0), DERWriter.tlv(0x31, ktri), eci]))
    }

    /// The content of a DER `SET OF` (`[0] IMPLICIT` certificates, `[1]` CRLs): sorted encodings.
    static func sortedSet(_ items: [[UInt8]]) -> [UInt8] {
        items.sorted { $0.lexicographicallyPrecedes($1) }.flatMap { $0 }
    }

    static func randomBytes(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
    }
}
