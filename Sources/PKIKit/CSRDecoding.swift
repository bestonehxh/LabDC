import _CryptoExtras
import CertConvert
import CryptoKit
import Foundation
import SwiftASN1
import X509

/// A CSR as `CAService.review` needs it. Normally the swift-certificates
/// `CertificateSigningRequest` decoded by CertConvert; for RSA keys under 2048 bits, which
/// swift-certificates refuses to load, the parts are read from the DER so the review can show
/// the request and refuse it with `keyTooSmall` instead of "not a CSR".
struct DecodedRequest {
    var der: [UInt8]
    var format: String
    /// Nil for the weak-key case.
    var csr: CertificateSigningRequest?
    var subject: DistinguishedName
    var attributes: CertificateSigningRequest.Attributes
    var keyKind: SubjectKeyKind
    var signatureAlgorithm: String
    var signatureValid: Bool
    /// False when the signature could not be checked (RSA under 1024 bits).
    var signatureChecked: Bool

    static func decode(_ bytes: [UInt8], name: String) throws -> DecodedRequest {
        let bundle: CertBundle
        do { bundle = try CertConvert.load(bytes, name: name) } catch {
            if let (der, format) = requestDER(bytes), let weak = try? weakRSA(der, format: format) { return weak }
            throw SignRequestError.notACSR("\(name) is not a certificate request: \(error)")
        }
        guard let item = bundle.requests.first else {
            var found: [String] = []
            if !bundle.certificates.isEmpty { found.append("\(bundle.certificates.count) certificate(s)") }
            if !bundle.keys.isEmpty { found.append("\(bundle.keys.count) private key(s)") }
            throw SignRequestError.notACSR("\(name) holds no certificate request\(found.isEmpty ? "" : " (found \(found.joined(separator: ", ")))")")
        }
        guard bundle.requests.count == 1 else { throw SignRequestError.severalCSRs(source: name, count: bundle.requests.count) }
        let summary = RequestSummary(item)
        let csr = item.request
        return DecodedRequest(der: item.der, format: bundle.sources.first?.format.rawValue ?? "?", csr: csr,
                              subject: csr.subject, attributes: csr.attributes, keyKind: SubjectKeyKind(csr.publicKey),
                              signatureAlgorithm: summary.signatureAlgorithm, signatureValid: summary.signatureValid,
                              signatureChecked: true)
    }

    /// The one CSR's DER in PEM, DER or bare base64 input; nil otherwise.
    static func requestDER(_ bytes: [UInt8]) -> (der: [UInt8], format: String)? {
        let text = String(bytes: bytes, encoding: .utf8)
        if let text, text.contains("-----BEGIN") {
            let requests = ((try? PEMBlock.parseAll(text)) ?? [])
                .filter { $0.label == "CERTIFICATE REQUEST" || $0.label == "NEW CERTIFICATE REQUEST" }
            return requests.count == 1 ? (requests[0].der, InputFormat.pem.rawValue) : nil
        }
        if bytes.first == 0x30 { return (bytes, InputFormat.derCSR.rawValue) }
        if let text, let data = Data(base64Encoded: text.filter { !$0.isWhitespace }) {
            return ([UInt8](data), InputFormat.derCSR.rawValue)
        }
        return nil
    }

    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let signatureNames: [String: String] = [
        "1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "RSASSA-PSS",
    ]

    /// A PKCS#10 request with an RSA key swift-certificates will not load.
    static func weakRSA(_ der: [UInt8], format: String) throws -> DecodedRequest {
        func children(_ node: ASN1Node) throws -> [ASN1Node] {
            guard case .constructed(let c) = node.content else { throw PKIKitError.encoding("not a SEQUENCE") }
            return Array(c)
        }
        let top = try children(try DER.parse(der))
        guard top.count == 3 else { throw PKIKitError.encoding("not a PKCS#10 request") }
        let info = try children(top[0])
        guard info.count >= 3 else { throw PKIKitError.encoding("not a PKCS#10 request") }
        let subject = try DistinguishedName(derEncoded: info[1])
        var attributes = CertificateSigningRequest.Attributes()
        if info.count > 3, case .constructed(let nodes) = info[3].content {
            attributes = CertificateSigningRequest.Attributes(try nodes.map { try CertificateSigningRequest.Attribute(derEncoded: $0) })
        }

        // SubjectPublicKeyInfo { { rsaEncryption, NULL }, BIT STRING RSAPublicKey { n, e } }
        let spki = try children(info[2])
        guard spki.count == 2, let algorithm = try children(spki[0]).first,
              try ASN1ObjectIdentifier(derEncoded: algorithm).description == rsaEncryption else {
            throw PKIKitError.encoding("not an RSA key")
        }
        let keyBits = try ASN1BitString(derEncoded: spki[1])
        let rsaKey = try children(try DER.parse(Array(keyBits.bytes)))
        guard let modulusNode = rsaKey.first, case .primitive(let modulusBytes) = modulusNode.content else {
            throw PKIKitError.encoding("bad RSA key")
        }
        let modulus = modulusBytes.drop { $0 == 0 }
        guard let first = modulus.first else { throw PKIKitError.encoding("bad RSA key") }
        let bits = (modulus.count - 1) * 8 + (8 - first.leadingZeroBitCount)
        guard bits < 2048 else { throw PKIKitError.encoding("not a weak key") }

        // The signature, when the key is at least 1024 bits (the smallest _RSA loads).
        let sigOID = try ASN1ObjectIdentifier(derEncoded: try children(top[1])[0]).description
        let signature = Array(try ASN1BitString(derEncoded: top[2]).bytes)
        var valid = false
        var checked = false
        if let key = try? _RSA.Signing.PublicKey(unsafeDERRepresentation: info[2].encodedBytes) {
            let sig = _RSA.Signing.RSASignature(rawRepresentation: signature)
            let tbs = Array(top[0].encodedBytes)
            checked = true
            switch sigOID {
            case "1.2.840.113549.1.1.5": valid = key.isValidSignature(sig, for: Insecure.SHA1.hash(data: tbs), padding: .insecurePKCS1v1_5)
            case "1.2.840.113549.1.1.11": valid = key.isValidSignature(sig, for: SHA256.hash(data: tbs), padding: .insecurePKCS1v1_5)
            case "1.2.840.113549.1.1.12": valid = key.isValidSignature(sig, for: SHA384.hash(data: tbs), padding: .insecurePKCS1v1_5)
            case "1.2.840.113549.1.1.13": valid = key.isValidSignature(sig, for: SHA512.hash(data: tbs), padding: .insecurePKCS1v1_5)
            default: checked = false
            }
        }
        return DecodedRequest(der: der, format: format, csr: nil, subject: subject, attributes: attributes,
                              keyKind: .rsa(bits: bits), signatureAlgorithm: signatureNames[sigOID] ?? sigOID,
                              signatureValid: valid, signatureChecked: checked)
    }
}
