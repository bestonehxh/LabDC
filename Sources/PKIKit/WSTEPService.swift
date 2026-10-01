import Foundation
import MSPAC
import os
import Store
import X509

/// PK-6: the MS-WSTEP enrollment service (`/<CA>_CES_Kerberos/service.svc/CES`), what an AD CS
/// "Certificate Enrollment Web Service" with Kerberos authentication answers.
///
/// A `wst:RequestSecurityToken` with RequestType Issue carries the request in
/// `wsse:BinarySecurityToken` (PKCS#10, PKCS#7 or CMC — MS-WCCE §2.2.2.6). The template comes
/// from the request (`szOID_CERTIFICATE_TEMPLATE` extension, the v1 template-name extension, a
/// `CertificateTemplate` name/value pair) or `auth:AdditionalContext`. The certificate is issued
/// by `CAService.issue` for the Kerberos identity (PAC SID + groups), so PK-1's template ACL and
/// SAN policy decide; certificates of account-bound templates (dNSHostName / UPN, PK-5's
/// CT_FLAG_PUBLISH_TO_DS) are appended to the account's `userCertificate`.
///
/// Issued: `RequestSecurityTokenResponseCollection` with DispositionMessage "Issued", the CMC
/// full PKI response signed by the CA (`#PKCS7`), the certificate (`#X509v3`) and the RequestID.
/// Refused: a SOAP fault whose `CertificateEnrollmentWSDetail` carries the HRESULT Windows shows
/// (`CERTSRV_E_TEMPLATE_DENIED` 0x80094012, …) and InvalidRequest true.
public actor WSTEPService {
    public let ca: CAService
    private let onEvent: (@Sendable (String) -> Void)?
    private let logger = Logger(subsystem: "dev.labdc.app", category: "wstep")

    /// MS-WSTEP §3.1.4.2 (what Windows sends).
    public static let action = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
    /// The plain WS-Trust Issue action, accepted as well.
    public static let wsTrustIssueAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
    public static let responseAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
    public static let issueRequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
    public static let queryTokenStatusRequestType = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus"
    public static let ketRequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET"
    public static let x509v3TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    public static let pkcs7ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"
    public static let base64EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
    /// `domain` table key of the request ID counter (the CES `RequestID`).
    public static let requestIDKey = "pki.wstepRequestID"

    public init(ca: CAService, onEvent: (@Sendable (String) -> Void)? = nil) {
        self.ca = ca
        self.onEvent = onEvent
    }

    /// `/<CA>_CES_Kerberos/service.svc/CES` → the CA name (nil for other paths).
    public static func caName(forPath path: String) -> String? {
        let suffix = "_CES_Kerberos/service.svc/CES"
        guard path.hasPrefix("/"), path.lowercased().hasSuffix(suffix.lowercased()) else { return nil }
        let name = String(path.dropFirst().dropLast(suffix.count))
        return LabPKI.isValidCAName(name) ? name : nil
    }

    /// Why a request was refused: the HRESULT and text Windows shows (certenroll puts them in the
    /// CertificateServicesClient event and in `certreq`'s output).
    public struct Refusal: Error, CustomStringConvertible {
        public var errorCode: UInt32
        public var message: String
        /// true when the CA denied the request (policy), false for a malformed request.
        public var denied: Bool
        /// The template concerned, when known (for the log).
        public var templateName: String? = nil
        public var description: String { String(format: "0x%08X ", errorCode) + message }
    }

    // HRESULTs (winerror.h).
    public static let templateDenied: UInt32 = 0x8009_4012        // CERTSRV_E_TEMPLATE_DENIED
    public static let unsupportedCertType: UInt32 = 0x8009_4800   // CERTSRV_E_UNSUPPORTED_CERT_TYPE
    public static let noCertType: UInt32 = 0x8009_4801            // CERTSRV_E_NO_CERT_TYPE
    public static let badRequestSubject: UInt32 = 0x8009_4001     // CERTSRV_E_BAD_REQUESTSUBJECT
    public static let badRequestStatus: UInt32 = 0x8009_4003      // CERTSRV_E_BAD_REQUESTSTATUS
    public static let keyLength: UInt32 = 0x8009_4811             // CERTSRV_E_KEY_LENGTH
    public static let subjectDNSRequired: UInt32 = 0x8009_480F    // CERTSRV_E_SUBJECT_DNS_REQUIRED
    public static let subjectUPNRequired: UInt32 = 0x8009_480D    // CERTSRV_E_SUBJECT_UPN_REQUIRED
    public static let badSignature: UInt32 = 0x8009_0006          // NTE_BAD_SIGNATURE
    public static let invalidArgument: UInt32 = 0x8007_0057       // E_INVALIDARG
    public static let notSupported: UInt32 = 0x8007_0032          // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
    public static let failure: UInt32 = 0x8000_4005               // E_FAIL

    static func refusal(for error: IssuanceError) -> Refusal {
        let code: UInt32 = switch error {
        case .notAllowedToEnrol, .adminRequired, .overrideRequiresAdmin: templateDenied
        case .unknownTemplate, .templateDisabled: unsupportedCertType
        case .invalidCSRSignature: badSignature
        case .malformedCSR: invalidArgument
        case .keyTypeNotAllowed, .keyTooSmall: keyLength
        case .requesterHasNoDNSHostName: subjectDNSRequired
        case .requesterHasNoSID, .requesterUnknown: badRequestSubject
        case .subjectAltNameNotAllowed, .unsupportedSubjectAltName, .missingSubjectAltName, .emptySubject,
             .overrideNotApplicable: badRequestSubject
        default: failure
        }
        return Refusal(errorCode: code, message: error.description, denied: true)
    }

    // MARK: - Handling

    /// Handles one authenticated POST to the CES of `caName`: (HTTP status, SOAP body).
    public func handle(_ body: [UInt8], caName: String, caller: EnrollmentCaller) async -> (status: Int, body: [UInt8]) {
        let request: SOAPRequest
        do { request = try SOAPRequest(bytes: body) } catch {
            emit("WSTEP request from \(caller.logName) -> fault (\(error))")
            return (400, SOAP.fault(code: "s:Sender", reason: "\(error)", relatesTo: nil))
        }
        let relatesTo = request.messageID
        guard request.action == Self.action || request.action == Self.wsTrustIssueAction,
              request.body.localName == "RequestSecurityToken", request.body.uri == SOAPNS.wsTrust else {
            emit("WSTEP \(request.action ?? "?") from \(caller.logName) -> fault (unsupported action)")
            return (500, SOAP.fault(code: "s:Sender",
                                    subcode: ("http://www.w3.org/2005/08/addressing", "ActionNotSupported"),
                                    reason: "The message with Action '\(request.action ?? "")' cannot be processed at the receiver.",
                                    relatesTo: relatesTo))
        }
        let rst = request.body
        let requestType = rst.child(SOAPNS.wsTrust, "RequestType")?.trimmedText ?? ""
        switch requestType {
        case Self.issueRequestType:
            break
        case Self.queryTokenStatusRequestType:
            // Nothing is ever held pending, so there is nothing to retrieve.
            let id = rst.child(SOAPNS.wstep, "RequestID")?.trimmedText ?? ""
            emit("WSTEP QueryTokenStatus RequestID=\(id) from \(caller.logName) -> fault (no pending requests)")
            return (500, fault(Refusal(errorCode: Self.badRequestStatus,
                                       message: "request \(id) is not pending (this CA never holds requests)", denied: false),
                               requestID: id.isEmpty ? nil : id, relatesTo: relatesTo))
        case Self.ketRequestType:
            emit("WSTEP KET from \(caller.logName) -> fault (no key archival)")
            return (500, fault(Refusal(errorCode: Self.notSupported, message: "key archival (KET) is not supported",
                                       denied: false), requestID: nil, relatesTo: relatesTo))
        default:
            emit("WSTEP RequestType \(requestType) from \(caller.logName) -> fault")
            return (500, fault(Refusal(errorCode: Self.invalidArgument, message: "unsupported RequestType '\(requestType)'",
                                       denied: false), requestID: nil, relatesTo: relatesTo))
        }

        var context: [String: String] = [:]
        if let additional = rst.child(SOAPNS.authorization, "AdditionalContext") {
            for item in additional.children(SOAPNS.authorization, "ContextItem") {
                guard let name = item.attributeValue("Name") else { continue }
                context[name.lowercased()] = item.child(SOAPNS.authorization, "Value")?.trimmedText ?? item.trimmedText
            }
        }

        let requestID = await nextRequestID()
        do {
            guard let token = rst.child(SOAPNS.wsse, "BinarySecurityToken"),
                  let der = Data(base64Encoded: token.trimmedText.filter { !$0.isWhitespace }).map({ [UInt8]($0) }),
                  !der.isEmpty else {
                throw Refusal(errorCode: Self.invalidArgument, message: "no BinarySecurityToken with a base64 request", denied: false)
            }
            let issued = try await issue(der: der, context: context, caName: caName, caller: caller, requestID: requestID)
            emit("WSTEP RequestSecurityToken from \(caller.logName) template=\(issued.template) -> Issued serial=\(issued.serial)"
                 + " RequestID=\(requestID) (\(issued.format))" + (issued.published ? ", userCertificate updated" : ""))
            return (200, SOAP.envelope(action: Self.responseAction, relatesTo: relatesTo,
                                       payload: Self.responseXML(cmc: issued.cmc, leaf: issued.der, requestID: requestID)))
        } catch let refusal as Refusal {
            emit("WSTEP RequestSecurityToken from \(caller.logName) template=\(refusal.template ?? "?") -> "
                 + (refusal.denied ? "Denied" : "fault") + " (\(refusal))")
            return (500, fault(refusal, requestID: String(requestID), relatesTo: relatesTo))
        } catch {
            emit("WSTEP RequestSecurityToken from \(caller.logName) -> fault (\(error))")
            return (500, fault(Refusal(errorCode: Self.failure, message: "\(error)", denied: false),
                               requestID: String(requestID), relatesTo: relatesTo))
        }
    }

    struct Issued {
        var template: String
        var serial: String
        var der: [UInt8]
        var cmc: [UInt8]
        var format: String
        var published: Bool
    }

    func issue(der: [UInt8], context: [String: String], caName: String, caller: EnrollmentCaller,
               requestID: Int) async throws -> Issued {
        let wrapped: WrappedEnrollmentRequest
        do { wrapped = try WrappedEnrollmentRequest.parse(der) } catch {
            throw Refusal(errorCode: Self.invalidArgument, message: "not a PKCS#10, PKCS#7 or CMC request: \(error)", denied: false)
        }
        let csr: CertificateSigningRequest
        do { csr = try CertificateSigningRequest(derEncoded: wrapped.csrDER) } catch {
            throw Refusal(errorCode: Self.invalidArgument, message: "the PKCS#10 request does not parse: \(error)", denied: false)
        }
        let template = try await resolveTemplate(csr: csr, pairs: wrapped.nameValuePairs, context: context)
        let authority: CertificateAuthority
        do { authority = try await ca.pki.authority(named: caName) } catch {
            throw Refusal(errorCode: Self.failure, message: "no CA named \(caName)", denied: false).with(template: template.name)
        }
        let certificate: Certificate
        do {
            certificate = try await ca.issue(csr: csr, template: template, requester: caller.requester,
                                             overrides: IssuanceOverrides(caName: authority.name))
        } catch let e as IssuanceError {
            throw Self.refusal(for: e).with(template: template.name)
        }
        let leaf = try LabPKI.der(certificate)
        let cmc = try CMCResponse.issued(leafDER: leaf, chain: [try authority.der()], bodyPartID: wrapped.bodyPartID,
                                         authority: authority)
        var published = false
        if TemplateDirectory.enrollmentFlag(template) & TemplateDirectory.enrollPublishToDS != 0 {
            published = await publish(leaf, forSID: caller.sid)
        }
        return Issued(template: template.name, serial: LabPKI.hex(certificate.serialNumber), der: leaf, cmc: cmc,
                      format: wrapped.format.rawValue, published: published)
    }

    /// The template the request names; the first form found wins (extension OID, extension name,
    /// name/value pair, AdditionalContext).
    func resolveTemplate(csr: CertificateSigningRequest, pairs: [String: String],
                         context: [String: String]) async throws -> CertificateTemplate {
        var wanted = RequestedTemplate.from(csr: csr)
        for key in ["certificatetemplate", "certificatetemplatename"] {
            if let v = pairs[key], !v.isEmpty { wanted.append(.name(v)) }
            if let v = context[key], !v.isEmpty { wanted.append(.name(v)) }
        }
        guard let first = wanted.first else {
            throw Refusal(errorCode: Self.noCertType, message: "the request names no certificate template", denied: true)
        }
        let templates = try await ca.templates()
        switch first {
        case .oid(let oid):
            guard let t = templates.first(where: { $0.oid == oid }) else {
                throw Refusal(errorCode: Self.unsupportedCertType, message: "no certificate template with OID \(oid)", denied: true)
            }
            return t
        case .name(let name):
            guard let t = templates.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame
                                                   || $0.displayName.caseInsensitiveCompare(name) == .orderedSame }) else {
                throw Refusal(errorCode: Self.unsupportedCertType, message: "no certificate template named '\(name)'",
                              denied: true).with(template: name)
            }
            return t
        }
    }

    /// Appends the certificate to the requester's `userCertificate` (CT_FLAG_PUBLISH_TO_DS).
    func publish(_ der: [UInt8], forSID sidText: String) async -> Bool {
        guard let sid = try? SID(string: sidText) else { return false }
        do {
            guard let entry = try await ca.store.read(sid: sid, attrs: ["userCertificate"]) else { return false }
            if entry.values("userCertificate").contains(der) { return true }
            try await ca.store.update(id: entry.id, ops: [.add("userCertificate", [der])])
            return true
        } catch {
            logger.error("userCertificate of \(sidText, privacy: .public) not updated: \(String(describing: error), privacy: .public)")
            return false
        }
    }

    /// A new request ID (a counter kept in the store, like the CA database's RequestID).
    func nextRequestID() async -> Int {
        let stored: String? = (try? await ca.store.domainValue(forKey: Self.requestIDKey)) ?? nil
        let current = stored.flatMap { Int($0) } ?? 0
        let next = current + 1
        try? await ca.store.setDomainValue(String(next), forKey: Self.requestIDKey)
        return next
    }

    // MARK: - XML

    static func responseXML(cmc: [UInt8], leaf: [UInt8], requestID: Int) -> String {
        "<RequestSecurityTokenResponseCollection xmlns=\"\(SOAPNS.wsTrust)\"><RequestSecurityTokenResponse>"
            + SOAP.element("TokenType", x509v3TokenType)
            + "<DispositionMessage xml:lang=\"en-US\" xmlns=\"\(SOAPNS.wstep)\">Issued</DispositionMessage>"
            + "<BinarySecurityToken ValueType=\"\(pkcs7ValueType)\" EncodingType=\"\(base64EncodingType)\" xmlns=\"\(SOAPNS.wsse)\">"
            + Data(cmc).base64EncodedString() + "</BinarySecurityToken>"
            + "<RequestedSecurityToken><BinarySecurityToken ValueType=\"\(x509v3TokenType)\" EncodingType=\"\(base64EncodingType)\" xmlns=\"\(SOAPNS.wsse)\">"
            + Data(leaf).base64EncodedString() + "</BinarySecurityToken></RequestedSecurityToken>"
            + "<RequestID xmlns=\"\(SOAPNS.wstep)\">\(requestID)</RequestID>"
            + "</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>"
    }

    /// The fault AD CS returns for a refused request: s:Receiver, the reason text
    /// (`Denied by Policy Module 0x80094012, …` for a policy refusal) and CertificateEnrollmentWSDetail.
    func fault(_ refusal: Refusal, requestID: String?, relatesTo: String?) -> [UInt8] {
        let hex = String(format: "0x%08x", refusal.errorCode)
        let reason = refusal.denied ? "Denied by Policy Module  \(hex), \(refusal.message)" : "\(hex), \(refusal.message)"
        var detail = "<CertificateEnrollmentWSDetail xmlns=\"\(SOAPNS.wstep)\" xmlns:xsi=\"\(SOAPNS.xsi)\">"
        detail += SOAP.nilElement("BinaryResponse")
        detail += SOAP.element("ErrorCode", String(Int32(bitPattern: refusal.errorCode)))
        detail += SOAP.element("InvalidRequest", refusal.denied ? "true" : "false")
        detail += requestID.map { SOAP.element("RequestID", $0) } ?? SOAP.nilElement("RequestID")
        detail += "</CertificateEnrollmentWSDetail>"
        return SOAP.fault(code: "s:Receiver", reason: reason, detail: detail, relatesTo: relatesTo)
    }

    private func emit(_ line: String) {
        logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }
}

extension WSTEPService.Refusal {
    var template: String? { templateName }

    func with(template: String) -> WSTEPService.Refusal {
        var r = self
        r.templateName = template
        return r
    }
}
