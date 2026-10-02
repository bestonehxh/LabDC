import _CryptoExtras
import CryptoKit
import Foundation
import X509

/// The key algorithm of a certificate authority, chosen at `createCA` (P-256 is the default;
/// RSA is offered for network devices that only accept RSA chains; P-384 / SHA-384 for
/// WPA3-Enterprise 192-bit, whose whole chain must be P-384 or RSA-3072+).
public enum CAKeyType: String, Sendable, CaseIterable, Codable {
    case p256
    case p384
    case rsa2048
    case rsa3072

    public var displayName: String {
        switch self {
        case .p256: "P-256"
        case .p384: "P-384"
        case .rsa2048: "RSA-2048"
        case .rsa3072: "RSA-3072"
        }
    }

    /// Key and signature, as the CA page shows them: `P-384 · ECDSA SHA-384`.
    public var signatureDescription: String {
        switch self {
        case .p256: "P-256 · ECDSA SHA-256"
        case .p384: "P-384 · ECDSA SHA-384"
        case .rsa2048: "RSA-2048 · RSA SHA-256"
        case .rsa3072: "RSA-3072 · RSA SHA-256"
        }
    }
}

/// A CA's private key: P-256 (ECDSA-SHA256 signatures), P-384 (ECDSA-SHA384) or RSA
/// (SHA256withRSA, PKCS#1 v1.5).
enum CASigningKey: Sendable {
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case rsa(_RSA.Signing.PrivateKey)

    static func generate(_ type: CAKeyType) throws -> CASigningKey {
        switch type {
        case .p256: return .p256(P256.Signing.PrivateKey())
        case .p384: return .p384(P384.Signing.PrivateKey())
        case .rsa2048, .rsa3072:
            do {
                return .rsa(try _RSA.Signing.PrivateKey(keySize: type == .rsa2048 ? .bits2048 : .bits3072))
            } catch {
                throw PKIKitError.encoding("RSA key generation: \(error)")
            }
        }
    }

    /// Parses a PKCS#8 (or PKCS#1 RSA) PEM private key.
    init(pem: String) throws {
        if let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
            self = .p256(key)
        } else if let key = try? P384.Signing.PrivateKey(pemRepresentation: pem) {
            self = .p384(key)
        } else {
            self = .rsa(try _RSA.Signing.PrivateKey(pemRepresentation: pem))
        }
    }

    /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) for both key types.
    var pemRepresentation: String {
        switch self {
        case .p256(let k): k.pemRepresentation
        case .p384(let k): k.pemRepresentation
        case .rsa(let k): k.pkcs8PEMRepresentation
        }
    }

    var keyType: CAKeyType {
        switch self {
        case .p256: .p256
        case .p384: .p384
        case .rsa(let k): k.keySizeInBits >= 3072 ? .rsa3072 : .rsa2048
        }
    }

    var publicKey: Certificate.PublicKey {
        switch self {
        case .p256(let k): Certificate.PublicKey(k.publicKey)
        case .p384(let k): Certificate.PublicKey(k.publicKey)
        case .rsa(let k): Certificate.PublicKey(k.publicKey)
        }
    }

    var certificateKey: Certificate.PrivateKey {
        switch self {
        case .p256(let k): Certificate.PrivateKey(k)
        case .p384(let k): Certificate.PrivateKey(k)
        case .rsa(let k): Certificate.PrivateKey(k)
        }
    }

    var signatureAlgorithm: Certificate.SignatureAlgorithm {
        switch self {
        case .p256: .ecdsaWithSHA256
        case .p384: .ecdsaWithSHA384
        case .rsa: .sha256WithRSAEncryption
        }
    }

    /// DER `AlgorithmIdentifier` of `signatureAlgorithm` (CRLs are encoded by hand).
    var algorithmIdentifierDER: [UInt8] {
        switch self {
        case .p256: DERWriter.sequence([DERWriter.oid("1.2.840.10045.4.3.2")])
        case .p384: DERWriter.sequence([DERWriter.oid("1.2.840.10045.4.3.3")])
        case .rsa: DERWriter.sequence([DERWriter.oid("1.2.840.113549.1.1.11"), DERWriter.null])
        }
    }

    /// The digest this key signs with (SHA-384 for P-384, else SHA-256).
    var digest: CMSDigest {
        if case .p384 = self { return .sha384 }
        return .sha256
    }

    /// Signs `bytes` (hashing them with `digest`) and returns the signature as it goes in a BIT
    /// STRING: DER `ECDSA-Sig-Value` or the raw RSA signature.
    func sign(_ bytes: [UInt8]) throws -> [UInt8] {
        do {
            return try certificateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm).rawRepresentation
        } catch {
            throw PKIKitError.encoding("signature: \(error)")
        }
    }
}

/// The public-key algorithm of a subject key (CSR or certificate).
public enum SubjectKeyKind: Sendable, Equatable, CustomStringConvertible {
    case p256
    case p384
    case p521
    case rsa(bits: Int)
    case ed25519

    public init(_ key: Certificate.PublicKey) {
        if P256.Signing.PublicKey(key) != nil { self = .p256 }
        else if P384.Signing.PublicKey(key) != nil { self = .p384 }
        else if P521.Signing.PublicKey(key) != nil { self = .p521 }
        else if let rsa = _RSA.Signing.PublicKey(key) { self = .rsa(bits: rsa.keySizeInBits) }
        else { self = .ed25519 }
    }

    /// The `allowedKeyTypes` token: `p256`, `p384`, `p521`, `rsa`, `ed25519`.
    public var token: String {
        switch self {
        case .p256: "p256"
        case .p384: "p384"
        case .p521: "p521"
        case .rsa: "rsa"
        case .ed25519: "ed25519"
        }
    }

    public var isEC: Bool {
        switch self {
        case .p256, .p384, .p521: true
        default: false
        }
    }

    public var description: String {
        switch self {
        case .p256: "P-256"
        case .p384: "P-384"
        case .p521: "P-521"
        case .rsa(let bits): "RSA-\(bits)"
        case .ed25519: "Ed25519"
        }
    }
}

/// The key of a server certificate LabDC issues to itself (the DC / LDAPS / EAP certificate and
/// the 192-bit RADIUS one): P-256 or P-384. Since 1 Oct 2026 it follows the issuing CA — a P-384
/// CA gets a P-384 server key, anything else (P-256 or RSA) the P-256 key it always had.
enum ServerKey: Sendable {
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)

    /// A fresh key for a certificate signed by a CA of type `issuer`.
    static func generate(issuedBy issuer: CAKeyType) -> ServerKey {
        issuer == .p384 ? .p384(P384.Signing.PrivateKey()) : .p256(P256.Signing.PrivateKey())
    }

    /// Parses a PKCS#8 PEM P-256 or P-384 private key (whichever is on disk).
    init(pem: String) throws {
        if let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
            self = .p256(key)
        } else {
            self = .p384(try P384.Signing.PrivateKey(pemRepresentation: pem))
        }
    }

    var pemRepresentation: String {
        switch self {
        case .p256(let k): k.pemRepresentation
        case .p384(let k): k.pemRepresentation
        }
    }

    /// PKCS#8 DER.
    var derRepresentation: [UInt8] {
        switch self {
        case .p256(let k): Array(k.derRepresentation)
        case .p384(let k): Array(k.derRepresentation)
        }
    }

    var publicKey: Certificate.PublicKey {
        switch self {
        case .p256(let k): Certificate.PublicKey(k.publicKey)
        case .p384(let k): Certificate.PublicKey(k.publicKey)
        }
    }

    var isP384: Bool {
        if case .p384 = self { return true }
        return false
    }
}
