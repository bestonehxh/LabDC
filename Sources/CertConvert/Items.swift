import CryptoKit
import Foundation
import SwiftASN1
import X509

/// An X.509 certificate with its exact DER bytes (outputs reuse these bytes unchanged).
public struct CertificateItem: Equatable, Sendable {
    public let der: [UInt8]
    public let certificate: Certificate
    /// PKCS#12 friendlyName / JKS alias, if the container had one.
    public var friendlyName: String?
    /// PKCS#12 localKeyID, if the container had one.
    public var localKeyID: [UInt8]?

    public init(der: [UInt8]) throws {
        do {
            self.certificate = try Certificate(derEncoded: der)
        } catch {
            throw CertConvertError.malformed("certificate does not parse: \(error)")
        }
        self.der = der
    }

    public var pem: String { PEMBlock(label: "CERTIFICATE", der: der).text }

    /// Subject and issuer names are equal (a root, or a self-issued certificate).
    public var isSelfIssued: Bool { certificate.subject == certificate.issuer }

    /// basicConstraints CA:TRUE.
    public var isCA: Bool {
        if case .isCertificateAuthority = (try? certificate.extensions.basicConstraints) ?? .notCertificateAuthority { return true }
        return false
    }

    /// Whether `issuer` signed this certificate (name match plus a signature check).
    public func isIssued(by issuer: CertificateItem) -> Bool {
        certificate.issuer == issuer.certificate.subject
            && issuer.certificate.publicKey.isValidSignature(certificate.signature, for: certificate)
    }

    /// The DER SubjectPublicKeyInfo exactly as the certificate carries it.
    public func subjectPublicKeyInfo() throws -> [UInt8] {
        let tbs = try ASN.parse(der).child(0)
        let hasVersion = tbs.children.first?.isContext(0) == true
        return try tbs.child(hasVersion ? 6 : 5).encoded
    }

    public var sha1Fingerprint: [UInt8] { Array(Insecure.SHA1.hash(data: der)) }
    public var sha256Fingerprint: [UInt8] { Array(SHA256.hash(data: der)) }
}

/// A PKCS#10 certificate signing request.
public struct CSRItem: Equatable, Sendable {
    public let der: [UInt8]
    public let request: CertificateSigningRequest

    public init(der: [UInt8]) throws {
        do {
            self.request = try CertificateSigningRequest(derEncoded: der)
        } catch {
            throw CertConvertError.malformed("certificate request does not parse: \(error)")
        }
        self.der = der
    }

    public var pem: String { PEMBlock(label: "CERTIFICATE REQUEST", der: der).text }

    /// The DER SubjectPublicKeyInfo of the requested key.
    public func subjectPublicKeyInfo() throws -> [UInt8] {
        try ASN.parse(der).child(0).child(2).encoded
    }
}

/// What an input file turned out to be.
public enum InputFormat: String, Equatable, Sendable {
    case pem = "PEM"
    case derCertificate = "DER certificate"
    case pkcs7 = "PKCS#7 (P7B)"
    case pkcs12 = "PKCS#12 (PFX)"
    case jks = "Java keystore (JKS)"
    case derPrivateKey = "DER private key"
    case derEncryptedPrivateKey = "DER encrypted private key (PKCS#8)"
    case derCSR = "DER certificate request (PKCS#10)"
}

/// One loaded input.
public struct SourceInfo: Equatable, Sendable {
    public var name: String
    public var format: InputFormat
    /// Encryption and integrity details, e.g. "MAC: sha256, Iteration 2048" or
    /// "key: PBES2, PBKDF2, AES-256-CBC, ...". Empty when nothing was protected.
    public var protection: [String]
    /// Things that were present but skipped (CRLs, secret bags, public keys, ...).
    public var notes: [String]

    public init(name: String, format: InputFormat, protection: [String] = [], notes: [String] = []) {
        self.name = name
        self.format = format
        self.protection = protection
        self.notes = notes
    }

    /// True when any part used a legacy algorithm (3DES, RC2, RC4, SHA-1 MAC, PBES1).
    public var usesLegacyProtection: Bool {
        protection.contains { p in
            ["TripleDES", "RC2", "RC4", "PBES1", "DES-EDE3", "DES-CBC", "MAC: sha1"].contains { p.contains($0) }
        }
    }
}
