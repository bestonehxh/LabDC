import _CryptoExtras
import CryptoKit
import Foundation
import os
import Store
import SwiftASN1
import X509

/// The SCEP registration authority: an RSA-2048 certificate issued by the current CA
/// (`<ca dir>/scep-ra.pem` + `scep-ra-key.pem`). Devices encrypt their requests to it and it
/// signs the replies; a P-256 CA cannot do RSA key transport, so SCEP always needs one.
public struct SCEPRegistrationAuthority: Sendable {
    public let caName: String
    public let certificate: Certificate
    public let der: [UInt8]
    let signingKey: _RSA.Signing.PrivateKey
    /// PKCS#8 PEM of the key (`_RSA.Encryption.PrivateKey` is not Sendable; made per request).
    let keyPEM: String

    func decryptionKey() throws -> _RSA.Encryption.PrivateKey { try _RSA.Encryption.PrivateKey(pemRepresentation: keyPEM) }

    public static let certificateFileName = "scep-ra.pem"
    public static let keyFileName = "scep-ra-key.pem"
    /// Template name recorded in `pki_issued` for the RA certificate.
    public static let templateName = "SCEPRA"
    static let lifetimeDays = 730
    static let renewBefore: TimeInterval = 30 * 86400
}

/// SCEP (RFC 8894) on the PK-1 HTTP listener: `GetCACaps`, `GetCACert`, `GetCACertChain` and
/// `PKIOperation` (`PKCSReq`, `RenewalReq`, `CertPoll`/`GetCertInitial`, `GetCert`, `GetCRL`)
/// at `/scep`, the Microsoft NDES path `/certsrv/mscep/mscep.dll` and `/cgi-bin/pkiclient.exe`.
///
/// Requests are CMS SignedData (signed with the device's self-signed or existing certificate)
/// around an EnvelopedData (encrypted to the RA) around the PKCS#10 / IssuerAndSerial. Replies
/// are SignedData by the RA carrying `pkiStatus`; on SUCCESS the content is an EnvelopedData,
/// encrypted to the device's signer certificate, of a certs-only SignedData holding the issued
/// certificate. There is no PENDING: a template that needs approval gets FAILURE badRequest.
public actor SCEPService {
    public let ca: CAService
    private let onEvent: (@Sendable (String) -> Void)?
    private var ra: SCEPRegistrationAuthority?
    private var transactions: [String: Transaction] = [:]
    private let logger = Logger(subsystem: "dev.labdc.app", category: "scep")

    struct Transaction {
        var publicKey: [UInt8]
        var certificate: [UInt8]
        var serial: String
        var device: String
        var at: Date
    }

    /// `messageType` values.
    enum MessageType: Int {
        case certRep = 3, renewalReq = 17, pkcsReq = 19, certPoll = 20, getCert = 21, getCRL = 22

        var name: String {
            switch self {
            case .certRep: "CertRep"
            case .renewalReq: "RenewalReq"
            case .pkcsReq: "PKCSReq"
            case .certPoll: "GetCertInitial"
            case .getCert: "GetCert"
            case .getCRL: "GetCRL"
            }
        }
    }

    /// `failInfo` values.
    public enum FailInfo: Int, Sendable {
        case badAlg = 0, badMessageCheck = 1, badRequest = 2, badTime = 3, badCertId = 4

        public var name: String {
            switch self {
            case .badAlg: "badAlg"
            case .badMessageCheck: "badMessageCheck"
            case .badRequest: "badRequest"
            case .badTime: "badTime"
            case .badCertId: "badCertId"
            }
        }
    }

    enum OID {
        static let messageType = "2.16.840.1.113733.1.9.2"
        static let pkiStatus = "2.16.840.1.113733.1.9.3"
        static let failInfo = "2.16.840.1.113733.1.9.4"
        static let senderNonce = "2.16.840.1.113733.1.9.5"
        static let recipientNonce = "2.16.840.1.113733.1.9.6"
        static let transactionID = "2.16.840.1.113733.1.9.7"
        static let failInfoText = "1.3.6.1.5.5.7.24.1"
    }

    /// The URL paths answered (matched case-insensitively; NDES clients use Windows spelling).
    public static let paths = ["/scep", "/scep/pkiclient.exe", "/cgi-bin/pkiclient.exe", "/certsrv/mscep/mscep.dll",
                               "/certsrv/mscep/mscep.dll/pkiclient.exe", "/certsrv/mscep", "/certsrv/mscep/"]

    public static let capabilities = ["POSTPKIOperation", "Renewal", "SHA-512", "SHA-256", "SHA-1", "AES", "DES3",
                                      "SCEPStandard"]

    public static func handles(path rawPath: String) -> Bool {
        var path = rawPath
        if let q = path.firstIndex(where: { $0 == "?" || $0 == "#" }) { path = String(path[..<q]) }
        return paths.contains(path.lowercased())
    }

    public init(ca: CAService, onEvent: (@Sendable (String) -> Void)? = nil) {
        self.ca = ca
        self.onEvent = onEvent
    }

    // MARK: - Registration authority

    /// Loads the RA of the current CA, issuing a new one when it is missing, issued by another
    /// CA or within 30 days of expiry. Returns it and whether it was issued now.
    @discardableResult
    public func prepare() async throws -> (ra: SCEPRegistrationAuthority, issued: Bool) {
        let authority = try await ca.pki.currentAuthority()
        if let ra, ra.caName == authority.name, Self.usable(ra.certificate, ca: authority, now: ca.clock()) { return (ra, false) }
        let dir = ca.pki.caDirectory(authority.name)
        let certURL = dir.appendingPathComponent(SCEPRegistrationAuthority.certificateFileName)
        let keyURL = dir.appendingPathComponent(SCEPRegistrationAuthority.keyFileName)
        if let loaded = try? Self.load(certURL: certURL, keyURL: keyURL, caName: authority.name),
           Self.usable(loaded.certificate, ca: authority, now: ca.clock()) {
            ra = loaded
            return (loaded, false)
        }
        let issued = try await issueRA(authority: authority)
        try SecureFiles.write(Array(try LabPKI.pem(issued.certificate).utf8), to: certURL)
        try SecureFiles.write(Array(issued.signingKey.pkcs8PEMRepresentation.utf8), to: keyURL, mode: 0o600)
        try await ca.record(issued.certificate, caName: authority.name, templateName: SCEPRegistrationAuthority.templateName,
                            requester: RequesterIdentity(name: "SCEP RA"))
        ra = issued
        logger.info("issued SCEP RA certificate \(LabPKI.hex(issued.certificate.serialNumber), privacy: .public) from CA \(authority.name, privacy: .public)")
        return (issued, true)
    }

    /// The RA as it is on disk for the current CA (nil when `serve` has not made one yet).
    public static func existingRA(pki: LabPKI) async throws -> SCEPRegistrationAuthority? {
        let authority = try await pki.currentAuthority()
        let dir = pki.caDirectory(authority.name)
        return try? load(certURL: dir.appendingPathComponent(SCEPRegistrationAuthority.certificateFileName),
                         keyURL: dir.appendingPathComponent(SCEPRegistrationAuthority.keyFileName), caName: authority.name)
    }

    static func usable(_ certificate: Certificate, ca: CertificateAuthority, now: Date) -> Bool {
        LabPKI.isIssued(certificate, by: ca.certificate)
            && certificate.notValidAfter > now.addingTimeInterval(SCEPRegistrationAuthority.renewBefore)
    }

    static func load(certURL: URL, keyURL: URL, caName: String) throws -> SCEPRegistrationAuthority? {
        guard let certBytes = try SecureFiles.read(certURL), let keyBytes = try SecureFiles.read(keyURL) else { return nil }
        let certificate = try Certificate(pemEncoded: String(decoding: certBytes, as: UTF8.self))
        let pem = String(decoding: keyBytes, as: UTF8.self)
        let signing = try _RSA.Signing.PrivateKey(pemRepresentation: pem)
        guard Certificate.PublicKey(signing.publicKey) == certificate.publicKey else {
            throw PKIKitError.corruptFile(path: keyURL.path, reason: "the RA key does not match \(certURL.lastPathComponent)")
        }
        return SCEPRegistrationAuthority(caName: caName, certificate: certificate, der: try LabPKI.der(certificate),
                                         signingKey: signing, keyPEM: pem)
    }

    private func issueRA(authority: CertificateAuthority) async throws -> SCEPRegistrationAuthority {
        let key: _RSA.Signing.PrivateKey
        do { key = try _RSA.Signing.PrivateKey(keySize: .bits2048) } catch {
            throw PKIKitError.encoding("RSA key generation: \(error)")
        }
        let publicKey = Certificate.PublicKey(key.publicKey)
        let host = (try? await ca.store.domainInfo().dcDNSName) ?? "labdc"
        let now = ca.clock()
        let notBefore = now.addingTimeInterval(-CAService.backdate)
        let notAfter = min(notBefore.addingTimeInterval(TimeInterval(SCEPRegistrationAuthority.lifetimeDays) * 86400),
                           authority.certificate.notValidAfter)
        do {
            let subject = try DistinguishedName {
                OrganizationName("LabDC")
                CommonName("SCEP RA \(host)")
            }
            var ext = Certificate.Extensions()
            try ext.append(Certificate.Extension(BasicConstraints.notCertificateAuthority, critical: true))
            try ext.append(Certificate.Extension(KeyUsage(digitalSignature: true, keyEncipherment: true), critical: true))
            try ext.append(Certificate.Extension(try ExtendedKeyUsage([.clientAuth, .serverAuth]), critical: false))
            try ext.append(Certificate.Extension(SubjectKeyIdentifier(hash: publicKey), critical: false))
            if let keyID = authority.keyIdentifier {
                try ext.append(Certificate.Extension(AuthorityKeyIdentifier(keyIdentifier: keyID[...]), critical: false))
            }
            try ext.append(Certificate.Extension(SubjectAlternativeNames([.dnsName(host)]), critical: false))
            let certificate = try Certificate(
                version: .v3, serialNumber: LabPKI.randomSerial(), publicKey: publicKey, notValidBefore: notBefore,
                notValidAfter: notAfter, issuer: authority.certificate.subject, subject: subject,
                signatureAlgorithm: authority.key.signatureAlgorithm, extensions: ext,
                issuerPrivateKey: authority.key.certificateKey)
            return SCEPRegistrationAuthority(caName: authority.name, certificate: certificate, der: try LabPKI.der(certificate),
                                             signingKey: key, keyPEM: key.pkcs8PEMRepresentation)
        } catch let e as PKIKitError {
            throw e
        } catch {
            throw PKIKitError.encoding("SCEP RA certificate: \(error)")
        }
    }

    // MARK: - HTTP

    public func handle(_ request: PKIHTTPServer.Request) async -> PKIHTTPServer.Response {
        let operation = request.query.first { $0.key.lowercased() == "operation" }?.value ?? ""
        switch operation.lowercased() {
        case "getcacaps":
            return .init(status: 200, contentType: "text/plain", body: Array((Self.capabilities.joined(separator: "\n") + "\n").utf8))
        case "getcacert", "getcacertchain":
            do {
                let ra = try await prepare().ra
                let authority = try await ca.pki.authority(named: ra.caName)
                let body = CMS.certsOnly(certificates: [ra.der, try authority.der()])
                let chain = operation.lowercased() == "getcacertchain"
                emit("SCEP \(chain ? "GetCACertChain" : "GetCACert") -> RA + CA \(authority.name) from \(request.remoteAddress)")
                let type = chain ? "application/x-x509-ca-ra-cert-chain" : "application/x-x509-ca-ra-cert"
                return .init(status: 200, contentType: type, body: body)
            } catch {
                logger.error("GetCACert: \(String(describing: error), privacy: .public)")
                return .init(status: 500, contentType: "text/plain", body: Array("SCEP RA unavailable: \(error)\n".utf8))
            }
        case "getnextcacert":
            return .init(status: 404, contentType: "text/plain", body: Array("no rollover CA certificate\n".utf8))
        case "pkioperation":
            let message: [UInt8]?
            if request.method == "POST" {
                message = Self.decodeMessage(request.body)
            } else if let text = request.query.first(where: { $0.key.lowercased() == "message" })?.value {
                message = Data(base64Encoded: Self.base64Clean(text)).map { [UInt8]($0) }
            } else {
                message = nil
            }
            guard let message, !message.isEmpty else {
                emit("SCEP PKIOperation from \(request.remoteAddress) -> 400 (no message)")
                return .init(status: 400, contentType: "text/plain", body: Array("PKIOperation needs a message\n".utf8))
            }
            return await pkiOperation(message, remote: request.remoteAddress)
        case "":
            return .init(status: 200, contentType: "text/plain",
                         body: Array("LabDC SCEP (RFC 8894). Operations: GetCACaps, GetCACert, PKIOperation.\n".utf8))
        default:
            return .init(status: 400, contentType: "text/plain", body: Array("unknown SCEP operation \(operation)\n".utf8))
        }
    }

    /// A POSTed message: DER, or base64 (some clients POST the GET encoding).
    static func decodeMessage(_ body: [UInt8]) -> [UInt8]? {
        if body.first == 0x30 { return body }
        let text = String(decoding: body, as: UTF8.self)
        return Data(base64Encoded: base64Clean(text)).map { [UInt8]($0) }
    }

    /// Undoes query-string damage: a `+` decoded as a space, whitespace, missing padding.
    static func base64Clean(_ text: String) -> String {
        var t = text.replacingOccurrences(of: " ", with: "+").filter { !$0.isNewline && $0 != "\r" && $0 != "\t" }
        t = t.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return t
    }

    // MARK: - PKIOperation

    struct Failure: Error {
        var info: FailInfo
        var reason: String
    }

    private struct RequestContext {
        var type: MessageType?
        var typeText = "?"
        var transactionID: String?
        var senderNonce: [UInt8]?
        var digest: CMSDigest = .sha256
        var signerDER: [UInt8]?
        var signer: Certificate?
        var cipher: CMSContentCipher = .aes256
        var keyTransport: CMSKeyTransport = .pkcs1v15
        var device = "?"
    }

    func pkiOperation(_ message: [UInt8], remote: String) async -> PKIHTTPServer.Response {
        let ra: SCEPRegistrationAuthority
        do { ra = try await prepare().ra } catch {
            return .init(status: 500, contentType: "text/plain", body: Array("SCEP RA unavailable: \(error)\n".utf8))
        }
        let signed: CMSSignedMessage
        do { signed = try CMSSignedMessage.parse(message) } catch {
            emit("SCEP PKIOperation from \(remote) -> 400 (not a PKCS#7 SignedData: \(error))")
            return .init(status: 400, contentType: "text/plain", body: Array("not a SCEP message: \(error)\n".utf8))
        }
        var context = RequestContext()
        do {
            let (issued, extraLog) = try await process(signed, ra: ra, context: &context)
            let body = try reply(ra: ra, context: context, success: issued)
            emit("SCEP \(context.typeText) device=\(context.device) -> OK\(extraLog) from \(remote)")
            return .init(status: 200, contentType: "application/x-pki-message", body: body)
        } catch {
            let failure = (error as? Failure) ?? Failure(info: .badRequest, reason: "\(error)")
            emit("SCEP \(context.typeText) device=\(context.device) -> FAILURE \(failure.info.name) (\(failure.reason)) from \(remote)")
            do {
                let body = try reply(ra: ra, context: context, failure: failure)
                return .init(status: 200, contentType: "application/x-pki-message", body: body)
            } catch {
                return .init(status: 500, contentType: "text/plain", body: Array("cannot build the SCEP reply: \(error)\n".utf8))
            }
        }
    }

    /// Verifies, decrypts and executes one request. Returns the reply payload (a certs-only
    /// SignedData) and the log suffix.
    private func process(_ signed: CMSSignedMessage, ra: SCEPRegistrationAuthority,
                         context: inout RequestContext) async throws -> (payload: [UInt8], log: String) {
        guard let signer = signed.signers.first else { throw Failure(info: .badMessageCheck, reason: "no signer") }
        // The attributes first, so even a failure echoes the transaction and nonce.
        if let t = signer.attribute(OID.transactionID) { context.transactionID = try? t.string() }
        if let n = signer.attribute(OID.senderNonce) { context.senderNonce = try? n.octets() }
        if let m = signer.attribute(OID.messageType), let text = try? m.string() {
            context.typeText = text
            if let v = Int(text.trimmingCharacters(in: .whitespaces)), let type = MessageType(rawValue: v) {
                context.type = type
                context.typeText = type.name
            }
        }
        guard let digest = CMSDigest(oid: signer.digestOID) else {
            throw Failure(info: .badAlg, reason: "digest \(signer.digestOID) is not supported")
        }
        context.digest = digest
        guard context.transactionID != nil, context.senderNonce != nil else {
            throw Failure(info: .badRequest, reason: "transactionID or senderNonce missing")
        }
        guard let type = context.type else { throw Failure(info: .badRequest, reason: "unsupported messageType \(context.typeText)") }

        // Signer certificate and signature
        guard let signerDER = signed.certificates.first(where: { der in
            (try? Certificate(derEncoded: der)).map { signer.sid.matches($0, der: der) } ?? false
        }), let signerCert = try? Certificate(derEncoded: signerDER) else {
            throw Failure(info: .badMessageCheck, reason: "the signer certificate is not in the message")
        }
        context.signerDER = signerDER
        context.signer = signerCert
        context.device = CAService.deviceNames(ofSubject: signerCert.subject).first ?? context.device
        guard let signedAttributes = signer.signedAttributesDER,
              let contentType = signer.attribute(CMSOID.contentType), (try? contentType.oid()) == CMSOID.data,
              let md = signer.attribute(CMSOID.messageDigest), let mdBytes = try? md.octets() else {
            throw Failure(info: .badMessageCheck, reason: "contentType / messageDigest attributes missing")
        }
        guard let content = signed.content, digest.hash(content) == mdBytes else {
            throw Failure(info: .badMessageCheck, reason: "messageDigest does not match the content")
        }
        guard let rsa = _RSA.Signing.PublicKey(signerCert.publicKey) ?? (try? _RSA.Signing.PublicKey(
            unsafeDERRepresentation: Array(signerCert.publicKey.subjectPublicKeyInfoBytes))) else {
            throw Failure(info: .badAlg, reason: "the signer key is \(SubjectKeyKind(signerCert.publicKey)); SCEP replies need RSA")
        }
        guard digest.isValidRSASignature(signer.signature, for: signedAttributes, key: rsa) else {
            throw Failure(info: .badMessageCheck, reason: "the signature does not verify")
        }

        // The envelope
        let envelope: CMSEnvelopedMessage
        let plaintext: [UInt8]
        do {
            envelope = try CMSEnvelopedMessage.parse(content)
            let opened = try envelope.decrypt(certificate: ra.certificate, certificateDER: ra.der, key: try ra.decryptionKey())
            plaintext = opened.plaintext
            context.cipher = opened.cipher
            context.keyTransport = opened.keyTransport
        } catch {
            throw Failure(info: .badMessageCheck, reason: "\(error)")
        }

        switch type {
        case .pkcsReq, .renewalReq:
            let csr: CertificateSigningRequest
            do { csr = try CertificateSigningRequest(derEncoded: plaintext) } catch {
                throw Failure(info: .badRequest, reason: "not a PKCS#10 request (or an RSA key under 2048 bits): \(error)")
            }
            if let name = CAService.deviceNames(of: csr).first { context.device = name }
            let transactionID = context.transactionID ?? ""
            let spki = Array(csr.publicKey.subjectPublicKeyInfoBytes)
            if let done = transactions[transactionID], done.publicKey == spki {
                context.device = done.device
                return (CMS.certsOnly(certificates: [done.certificate]), " serial=\(done.serial) (repeated transaction)")
            }
            let challenge = CAService.challengePassword(of: csr)
            var signerProblem = ""
            var signerIsOurs = false
            if !signerCert.issuer.isEmpty, signerCert.issuer != signerCert.subject || type == .renewalReq {
                do {
                    _ = try await ca.validIssued(signerCert)
                    signerIsOurs = true
                } catch {
                    signerProblem = "\(error)"
                }
            }
            let result: DeviceEnrollmentResult
            do {
                if type == .renewalReq || (challenge == nil && signerIsOurs) {
                    guard signerIsOurs else {
                        throw Failure(info: .badRequest,
                                      reason: "RenewalReq must be signed with a valid certificate issued by this CA (\(signerProblem))")
                    }
                    context.typeText = type == .renewalReq ? "RenewalReq" : "PKCSReq (renewal)"
                    result = try await ca.renewDevice(csr: csr, existing: signerCert)
                } else {
                    result = try await ca.enrolDevice(csr: csr, challenge: challenge, deviceNames: CAService.deviceNames(of: csr),
                                                      template: nil)
                }
            } catch let e as DeviceEnrollmentError {
                throw Failure(info: .badRequest, reason: "\(e)")
            }
            context.device = result.device
            transactions[transactionID] = Transaction(publicKey: spki, certificate: result.der, serial: result.serial,
                                                      device: result.device, at: ca.clock())
            pruneTransactions()
            return (CMS.certsOnly(certificates: [result.der]), " serial=\(result.serial) template=\(result.template)")

        case .certPoll:
            guard let done = transactions[context.transactionID ?? ""] else {
                throw Failure(info: .badCertId, reason: "no issued certificate for transaction \(context.transactionID ?? "?")")
            }
            context.device = done.device
            return (CMS.certsOnly(certificates: [done.certificate]), " serial=\(done.serial)")

        case .getCert:
            let (issuer, serial) = try Self.issuerAndSerial(plaintext)
            guard let row = try await ca.store.issuedCertificate(serial: serial),
                  let cert = try? row.certificate(), Self.nameDER(cert.issuer) == issuer else {
                throw Failure(info: .badCertId, reason: "no certificate \(serial) from that issuer")
            }
            return (CMS.certsOnly(certificates: [row.der]), " serial=\(serial)")

        case .getCRL:
            let (issuer, serial) = try Self.issuerAndSerial(plaintext)
            var found: CertificateAuthority?
            for authority in (try? await ca.pki.authorities()) ?? [] where Self.nameDER(authority.certificate.subject) == issuer {
                found = authority
            }
            guard let authority = found else { throw Failure(info: .badCertId, reason: "unknown issuer (serial \(serial))") }
            let crl = try await ca.currentCRL(caName: authority.name)
            return (CMS.certsOnly(certificates: [], crls: [crl.der]), " CRL #\(crl.crlNumber ?? 0) of CA \(authority.name)")

        case .certRep:
            throw Failure(info: .badRequest, reason: "CertRep is a reply")
        }
    }

    static func issuerAndSerial(_ der: [UInt8]) throws -> (issuer: [UInt8], serial: String) {
        do {
            let node = try ASNReader.parse(der)
            let issuer = try node.child(0).encoded
            let serial = try node.child(1).unsignedInteger().map { String(format: "%02x", $0) }.joined()
            return (issuer, serial)
        } catch {
            throw Failure(info: .badRequest, reason: "not an IssuerAndSerialNumber: \(error)")
        }
    }

    static func nameDER(_ name: DistinguishedName) -> [UInt8]? {
        var s = DER.Serializer()
        guard (try? s.serialize(name)) != nil else { return nil }
        return s.serializedBytes
    }

    private func pruneTransactions() {
        let cutoff = ca.clock().addingTimeInterval(-86400)
        transactions = transactions.filter { $0.value.at > cutoff }
        if transactions.count > 2000 {
            for key in transactions.sorted(by: { $0.value.at < $1.value.at }).prefix(transactions.count - 2000).map(\.key) {
                transactions[key] = nil
            }
        }
    }

    // MARK: - Replies

    private func reply(ra: SCEPRegistrationAuthority, context: RequestContext, success payload: [UInt8]) throws -> [UInt8] {
        guard let signerDER = context.signerDER, let signer = context.signer,
              let key = try? _RSA.Encryption.PublicKey(unsafeDERRepresentation: Array(signer.publicKey.subjectPublicKeyInfoBytes)) else {
            throw Failure(info: .badAlg, reason: "cannot encrypt to the requester")
        }
        let envelope = try CMS.envelope(payload, recipientDER: signerDER, recipientKey: key, cipher: context.cipher,
                                        keyTransport: context.keyTransport)
        return try CMS.signed(content: envelope, signerDER: ra.der, signerKey: ra.signingKey, digest: context.digest,
                              attributes: attributes(context, status: 0, failure: nil), certificates: [ra.der])
    }

    private func reply(ra: SCEPRegistrationAuthority, context: RequestContext, failure: Failure) throws -> [UInt8] {
        try CMS.signed(content: nil, signerDER: ra.der, signerKey: ra.signingKey, digest: context.digest,
                       attributes: attributes(context, status: 2, failure: failure), certificates: [ra.der])
    }

    private func attributes(_ context: RequestContext, status: Int, failure: Failure?) -> [[UInt8]] {
        var list = [
            CMS.attribute(OID.messageType, [DERWriter.printableString(String(MessageType.certRep.rawValue))]),
            CMS.attribute(OID.pkiStatus, [DERWriter.printableString(String(status))]),
            CMS.attribute(OID.senderNonce, [DERWriter.octetString(CMS.randomBytes(16))]),
            CMS.attribute(CMSOID.signingTime, [DERWriter.time(ca.clock())]),
        ]
        if let t = context.transactionID { list.append(CMS.attribute(OID.transactionID, [DERWriter.printableString(t)])) }
        if let n = context.senderNonce { list.append(CMS.attribute(OID.recipientNonce, [DERWriter.octetString(n)])) }
        if let failure {
            list.append(CMS.attribute(OID.failInfo, [DERWriter.printableString(String(failure.info.rawValue))]))
            list.append(CMS.attribute(OID.failInfoText, [DERWriter.tlv(0x0C, Array(String(failure.reason.prefix(200)).utf8))]))
        }
        return list
    }

    private func emit(_ line: String) {
        logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }
}

extension CAService {
    /// CN(s) of a subject.
    public static func deviceNames(ofSubject subject: DistinguishedName) -> [String] {
        var names: [String] = []
        for rdn in subject {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                if let text = ASNReaderString.of(attribute.value) { names.append(text) }
            }
        }
        return names
    }
}
