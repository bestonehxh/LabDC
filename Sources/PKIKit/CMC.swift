import CryptoKit
import Foundation
import SwiftASN1
import X509

// PK-6: the request and response wrappers MS-WSTEP carries in `wsse:BinarySecurityToken`
// (MS-WCCE §2.2.2.6 request formats; RFC 5272 CMC; the AD CS response of MS-WSTEP §4.1.1.2).

enum CMCOID {
    /// id-cct-PKIData (a CMC full PKI request).
    static let pkiData = "1.3.6.1.5.5.7.12.2"
    /// id-cct-PKIResponse.
    static let pkiResponse = "1.3.6.1.5.5.7.12.3"
    /// id-cmc-statusInfo.
    static let statusInfo = "1.3.6.1.5.5.7.7.1"
    /// szOID_CMC_ADD_ATTRIBUTES.
    static let addAttributes = "1.3.6.1.4.1.311.10.10.1"
    /// szOID_ISSUED_CERT_HASH (SHA-1 of the issued certificate).
    static let issuedCertHash = "1.3.6.1.4.1.311.21.17"
    /// szOID_ENROLLMENT_NAME_VALUE_PAIR: SEQUENCE { name BMPString, value BMPString }.
    static let enrollmentNameValuePair = "1.3.6.1.4.1.311.13.2.1"
    /// szOID_ENROLL_CERTTYPE_EXTENSION: the template name as a BMPString (v1 templates).
    static let certificateTypeName = "1.3.6.1.4.1.311.20.2"
}

/// A certificate request as a Windows client submits it over the CES: a bare PKCS#10, a PKCS#7
/// SignedData wrapping one (renewal: signed with the certificate being renewed), or a CMC full
/// PKI request (SignedData over PKIData).
struct WrappedEnrollmentRequest {
    enum Format: String { case pkcs10 = "PKCS#10", pkcs7 = "PKCS#7", cmc = "CMC" }

    var format: Format
    var csrDER: [UInt8]
    /// The CMC body part ID of the certification request (1 for PKCS#10 / PKCS#7, as AD CS answers).
    var bodyPartID: Int
    /// Enrollment name/value pairs found in the CMC controls or the PKCS#10 attributes
    /// (`CertificateTemplate:Computer`, `ccm:…`), names lower-cased.
    var nameValuePairs: [String: String]
    /// Certificates carried by the PKCS#7 / CMC wrapper (the old certificate on renewal).
    var certificates: [[UInt8]]

    static func parse(_ der: [UInt8]) throws -> WrappedEnrollmentRequest {
        let top = try ASNReader.parse(der)
        guard top.isSequence else { throw ASNError("the request is not an ASN.1 SEQUENCE") }
        // ContentInfo { signedData, [0] SignedData } vs CertificationRequest { info, alg, sig }.
        if let first = top.children.first, first.isUniversal(6) {
            let message = try CMSSignedMessage.parse(der)
            guard let content = message.content else { throw ASNError("the PKCS#7 request has no content") }
            if message.contentType == CMCOID.pkiData {
                var r = try parsePKIData(content)
                r.certificates = message.certificates
                return r
            }
            // id-data (renewal): the content is the PKCS#10 itself.
            var r = WrappedEnrollmentRequest(format: .pkcs7, csrDER: content, bodyPartID: 1, nameValuePairs: [:],
                                             certificates: message.certificates)
            r.nameValuePairs.merge(try csrNameValuePairs(content)) { a, _ in a }
            return r
        }
        return WrappedEnrollmentRequest(format: .pkcs10, csrDER: der, bodyPartID: 1,
                                        nameValuePairs: (try? csrNameValuePairs(der)) ?? [:], certificates: [])
    }

    /// PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }.
    static func parsePKIData(_ bytes: [UInt8]) throws -> WrappedEnrollmentRequest {
        let pkiData = try ASNReader.parse(bytes)
        guard pkiData.isSequence, pkiData.children.count >= 2 else { throw ASNError("PKIData is not a SEQUENCE") }
        var pairs: [String: String] = [:]
        for control in try pkiData.child(0).children {
            // TaggedAttribute ::= SEQUENCE { bodyPartID, attrType, attrValues SET }
            guard control.children.count >= 3, let type = try? control.child(1).oid() else { continue }
            let values = try control.child(2).children
            if type == CMCOID.addAttributes {
                // SEQUENCE { dataReference, certReferences, attributes SET OF Attribute }
                for value in values {
                    guard value.children.count >= 3 else { continue }
                    for attribute in try value.child(2).children {
                        collectNameValuePairs(attribute, into: &pairs)
                    }
                }
            } else if type == CMCOID.enrollmentNameValuePair {
                for value in values { if let (n, v) = nameValuePair(value) { pairs[n] = v } }
            }
        }
        for request in try pkiData.child(1).children {
            // TaggedRequest: tcr [0] IMPLICIT TaggedCertificationRequest { bodyPartID, certificationRequest }
            guard request.isContext(0), request.children.count >= 2 else { continue }
            let id = (try? request.child(0).int()) ?? 1
            let csr = try request.child(1).encoded
            pairs.merge((try? csrNameValuePairs(csr)) ?? [:]) { a, _ in a }
            return WrappedEnrollmentRequest(format: .cmc, csrDER: csr, bodyPartID: id, nameValuePairs: pairs, certificates: [])
        }
        throw ASNError("the CMC request carries no PKCS#10 certification request")
    }

    /// Name/value pairs in the PKCS#10 attributes (`szOID_ENROLLMENT_NAME_VALUE_PAIR`).
    static func csrNameValuePairs(_ der: [UInt8]) throws -> [String: String] {
        let info = try ASNReader.parse(der).child(0)
        var pairs: [String: String] = [:]
        for part in info.children where part.isContext(0) {
            for attribute in part.children { collectNameValuePairs(attribute, into: &pairs) }
        }
        return pairs
    }

    static func collectNameValuePairs(_ attribute: ASNReader, into pairs: inout [String: String]) {
        guard attribute.children.count >= 2, (try? attribute.child(0).oid()) == CMCOID.enrollmentNameValuePair,
              let values = try? attribute.child(1).children else { return }
        for v in values { if let (n, value) = nameValuePair(v) { pairs[n] = value } }
    }

    static func nameValuePair(_ node: ASNReader) -> (String, String)? {
        guard node.children.count >= 2, let name = try? node.child(0).string(), let value = try? node.child(1).string() else {
            return nil
        }
        return (name.lowercased(), value)
    }
}

/// How the request names its template: the `szOID_CERTIFICATE_TEMPLATE` extension (template OID,
/// schema 2+), the `szOID_ENROLL_CERTTYPE_EXTENSION` name (schema 1), or a name/value pair.
enum RequestedTemplate: Equatable {
    case oid(String)
    case name(String)

    static func from(csr: CertificateSigningRequest) -> [RequestedTemplate] {
        var out: [RequestedTemplate] = []
        guard let extensions = try? csr.attributes.extensionRequest?.extensions else { return out }
        for ext in extensions {
            switch ext.oid.description {
            case PKIOID.certificateTemplateExtension:
                if let seq = try? ASNReader.parse(Array(ext.value)), let oid = try? seq.child(0).oid() { out.append(.oid(oid)) }
            case CMCOID.certificateTypeName:
                if let name = try? ASNReader.parse(Array(ext.value)).string(), !name.isEmpty { out.append(.name(name)) }
            default: continue
            }
        }
        return out
    }
}

/// The CMC full PKI response AD CS returns as the CES `BinarySecurityToken` (MS-WSTEP §4.1.1.2):
/// SignedData (version 3) over PKIResponse { controlSequence { statusInfo(success, bodyList
/// {request body part}, "Issued"), addAttributes(szOID_ISSUED_CERT_HASH = SHA-1 of the leaf) },
/// {}, {} }, with the leaf and the CA certificate, signed by the CA (contentType + messageDigest
/// signed attributes, SHA-256).
enum CMCResponse {
    static func issued(leafDER: [UInt8], chain: [[UInt8]], bodyPartID: Int, statusString: String = "Issued",
                       authority: CertificateAuthority) throws -> [UInt8] {
        let status = DERWriter.sequence([
            DERWriter.integer(1), DERWriter.oid(CMCOID.statusInfo),
            DERWriter.setOf([DERWriter.sequence([
                DERWriter.integer(0),                                              // success
                DERWriter.sequence([DERWriter.integer(Int64(bodyPartID))]),
                DERWriter.tlv(0x0C, Array(statusString.utf8)),                     // UTF8String
            ])]),
        ])
        let hash = Array(Insecure.SHA1.hash(data: leafDER))
        let addAttributes = DERWriter.sequence([
            DERWriter.integer(2), DERWriter.oid(CMCOID.addAttributes),
            DERWriter.setOf([DERWriter.sequence([
                DERWriter.integer(0),
                DERWriter.sequence([DERWriter.integer(Int64(bodyPartID))]),
                DERWriter.setOf([CMS.attribute(CMCOID.issuedCertHash, [DERWriter.octetString(hash)])]),
            ])]),
        ])
        let pkiResponse = DERWriter.sequence([DERWriter.sequence([status, addAttributes]),
                                              DERWriter.sequence([]), DERWriter.sequence([])])
        return try signed(contentType: CMCOID.pkiResponse, content: pkiResponse,
                          certificates: [leafDER] + chain, authority: authority)
    }

    /// SignedData version 3 over `content` with one signer, the CA (issuerAndSerialNumber, SHA-256).
    static func signed(contentType: String, content: [UInt8], certificates: [[UInt8]],
                       authority: CertificateAuthority) throws -> [UInt8] {
        let digest = authority.key.digest
        let attributes = DERWriter.setOf([
            CMS.attribute(CMSOID.contentType, [DERWriter.oid(contentType)]),
            CMS.attribute(CMSOID.messageDigest, [DERWriter.octetString(digest.hash(content))]),
        ])
        let signature = try authority.key.sign(attributes)
        let signatureAlgorithm: [UInt8] = switch authority.key {
        case .p256: DERWriter.algorithm(CMSOID.ecdsaWithSHA256, nil)
        case .p384: DERWriter.algorithm("1.2.840.10045.4.3.3", nil)
        case .rsa: DERWriter.algorithm(CMSOID.rsaEncryption, DERWriter.null)
        }
        var implicit = attributes
        implicit[0] = 0xA0
        let caDER = try authority.der()
        let signerInfo = DERWriter.sequence([
            DERWriter.integer(1), try CMSIdentifier.of(certificateDER: caDER).der, digest.algorithmDER, implicit,
            signatureAlgorithm, DERWriter.octetString(signature),
        ])
        let sd = DERWriter.sequence([
            DERWriter.integer(3), DERWriter.tlv(0x31, digest.algorithmDER),
            DERWriter.sequence([DERWriter.oid(contentType), DERWriter.explicit(0, DERWriter.octetString(content))]),
            DERWriter.tlv(0xA0, CMS.sortedSet(certificates)), DERWriter.tlv(0x31, signerInfo),
        ])
        return CMS.contentInfo(CMSOID.signedData, sd)
    }
}
