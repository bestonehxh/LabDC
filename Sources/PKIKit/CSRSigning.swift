import CertConvert
import Foundation
import SwiftASN1
import X509

// PK-2: signing external CSRs (CLI `labdc ca sign`, the UI's "Sign CSR" page).
//
//   let request = SignRequest(csr: bytes, templateName: "WebServer")      // PEM, DER or bare base64
//   let review = try await service.review(request)                        // decoded CSR + verdict + warnings
//   if review.canSign { let result = try await service.sign(request) }    // issues, records, returns chain

/// How the operator's SANs combine with the CSR's.
public enum SANOverride: Sendable, Equatable {
    /// The CSR's SANs as they are.
    case fromRequest
    /// The CSR's SANs plus these (duplicates dropped).
    case add([GeneralName])
    /// Only these; the CSR's are ignored.
    case replace([GeneralName])
}

/// What the operator asks for: the CSR plus the choices of the "Sign CSR" page / `ca sign` flags.
public struct SignRequest: Sendable {
    /// The request as given: PEM (`CERTIFICATE REQUEST` / `NEW CERTIFICATE REQUEST`), DER or bare base64.
    public var csr: [UInt8]
    /// A name for messages (the file name or "pasted request").
    public var sourceName: String
    public var templateName: String
    public var subjectAltNames: SANOverride
    /// Validity in days instead of the template's (an operator may lengthen it, capped at the CA's expiry).
    public var validityDays: Int?
    /// Replaces the CN of the CSR's subject (other RDNs are kept; a CN is added when there is none).
    public var commonName: String?
    /// Issue from this CA instead of the current one.
    public var caName: String?
    /// For templates that take the SAN from a directory account (Computer: dNSHostName, User: UPN):
    /// the `sAMAccountName` (or `NAME$`, UPN, SID) the certificate is for. Required there, refused elsewhere.
    public var account: String?
    /// Recorded as the requester in `pki_issued` (`ca issued` shows it).
    public var operatorName: String

    public init(csr: [UInt8], sourceName: String = "request", templateName: String,
                subjectAltNames: SANOverride = .fromRequest, validityDays: Int? = nil, commonName: String? = nil,
                caName: String? = nil, account: String? = nil, operatorName: String = "operator") {
        self.csr = csr
        self.sourceName = sourceName
        self.templateName = templateName
        self.subjectAltNames = subjectAltNames
        self.validityDays = validityDays
        self.commonName = commonName
        self.caName = caName
        self.account = account
        self.operatorName = operatorName
    }
}

/// Why a `SignRequest` could not even be reviewed (bad input), or why `sign` refused.
public enum SignRequestError: Error, Sendable, CustomStringConvertible {
    case notACSR(String)
    case severalCSRs(source: String, count: Int)
    case accountRequired(template: String, policy: SANPolicy)
    case accountNotApplicable(template: String)
    case invalidSubjectAltName(String)
    case invalidCommonName(String)
    case refused(IssuanceError)

    public var description: String {
        switch self {
        case .notACSR(let s): s
        case .severalCSRs(let source, let count): "\(source) holds \(count) certificate requests; give one at a time"
        case .accountRequired(let t, let policy):
            "template '\(t)' takes the \(policy == .upn ? "UPN" : "DNS name") from a directory account: give the account (--account <sAMAccountName>)"
        case .accountNotApplicable(let t):
            "template '\(t)' takes the names from the CSR (or --san), not from an account; leave out --account"
        case .invalidSubjectAltName(let s): "invalid SAN \(s): use dns:<host>, ip:<address>, upn:<user@realm>, email:<address> or uri:<uri>"
        case .invalidCommonName(let s): "invalid common name '\(s)'"
        case .refused(let e): "not signed: \(e)"
        }
    }
}

/// A decoded CSR, what the chosen template would make of it, and whether it may be signed.
public struct CSRReview: Sendable {
    public enum Verdict: Sendable, Equatable {
        case willIssue
        case refused(IssuanceError)
    }

    /// An extension the CSR asks for (extensionRequest).
    public struct RequestedExtension: Sendable, Equatable {
        public var oid: String
        /// `subjectAltName`, `keyUsage`, … or the dotted OID.
        public var name: String
        public var critical: Bool
        /// Decoded value (`DNS:a, IP:b`, `digitalSignature, keyEncipherment`, …), or a byte count.
        public var value: String
        /// The CA copies it (only subjectAltName, subject to the template's SAN policy); the
        /// others come from the template.
        public var honoured: Bool
    }

    /// Where the request came from.
    public let sourceName: String
    public let sourceFormat: String
    /// The CSR's DER.
    public let der: [UInt8]
    /// Nil when swift-certificates cannot load the CSR's key (RSA under 2048 bits); such a
    /// request is reviewed from its DER and always refused.
    public let csr: CertificateSigningRequest?
    public let subject: String
    /// `P-256`, `RSA-2048`, …
    public let keyType: String
    public let keyKind: SubjectKeyKind
    public let signatureAlgorithm: String
    public let signatureValid: Bool
    /// False only for RSA keys too small to load at all (< 1024 bits).
    public let signatureChecked: Bool
    /// `DNS:…`, `IP:…`, `UPN:…` as requested.
    public let requestedSubjectAltNames: [String]
    public let requestedExtensions: [RequestedExtension]
    /// Other CSR attributes (challengePassword, …), ignored by the CA.
    public let otherAttributes: [String]

    public let template: CertificateTemplate
    public let requester: RequesterIdentity
    /// The account the certificate is bound to (Computer/User templates).
    public let account: String?
    /// What would be issued; nil when refused.
    public let plan: IssuancePlan?
    public let verdict: Verdict
    public let warnings: [String]
    /// What `sign` passes to `issue`.
    let overrides: IssuanceOverrides

    public var canSign: Bool { verdict == .willIssue }

    /// The review as text (CLI output; the UI shows the fields).
    public func lines() -> [String] {
        var l = ["CSR (\(sourceName), \(sourceFormat))",
                 "  subject          \(subject.isEmpty ? "(empty)" : subject)",
                 "  public key       \(keyType)",
                 "  signature        \(signatureAlgorithm) (\(!signatureChecked ? "not checked" : signatureValid ? "valid" : "INVALID"))"]
        l.append("  requested SANs   \(requestedSubjectAltNames.isEmpty ? "none" : requestedSubjectAltNames.joined(separator: ", "))")
        if requestedExtensions.isEmpty {
            l.append("  requested ext.   none")
        }
        for (i, e) in requestedExtensions.enumerated() {
            let head = i == 0 ? "  requested ext.   " : "                   "
            l.append(head + "\(e.name)\(e.critical ? " (critical)" : ""): \(e.value)\(e.honoured ? "" : " [template decides]")")
        }
        if !otherAttributes.isEmpty { l.append("  attributes       \(otherAttributes.joined(separator: ", ")) (ignored)") }

        var flags = [template.sanPolicy == .fromRequest ? "SAN from request" : "SAN \(template.sanPolicy.rawValue)",
                     "\(template.validityDays) days"]
        if template.manualApproval { flags.append("manual") }
        if template.autoEnroll { flags.append("auto-enroll") }
        l.append("policy")
        l.append("  template         \(template.name) (\(template.displayName)): EKU \(Self.ekuNames(template.ekus)); \(flags.joined(separator: ", "))")
        l.append("  requester        \(requester.name)\(requester.isAdmin ? " [admin]" : "")\(account.map { ", account \($0)" } ?? "")")
        if let plan {
            l.append("  CA               \(plan.ca.name) (\(plan.ca.certificate.subject))")
            l.append("  will issue       subject \(plan.subject.isEmpty ? "(empty)" : plan.subject.description)")
            l.append("                   SANs \(plan.subjectAltNames.isEmpty ? "none" : plan.subjectAltNames.map(CAService.describe).joined(separator: ", "))")
            let f = Date.ISO8601FormatStyle().year().month().day()
            let days = Int((plan.notAfter.timeIntervalSince(plan.notBefore) / 86400).rounded())
            l.append("                   valid \(days) days, \(plan.notBefore.formatted(f)) to \(plan.notAfter.formatted(f))")
            l.append("                   CDP \(plan.crlURL)")
        }
        for w in warnings { l.append("  warning          \(w)") }
        switch verdict {
        case .willIssue: l.append("verdict            OK: can be signed")
        case .refused(let e): l.append("verdict            REFUSED: \(e)")
        }
        return l
    }

    static func ekuNames(_ oids: [String]) -> String {
        oids.isEmpty ? "-" : oids.map { CSRReview.ekuNames[$0] ?? $0 }.joined(separator: ", ")
    }

    static let ekuNames: [String: String] = [
        "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning",
        "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
        "1.3.6.1.5.5.7.3.17": "ipsecIKE", "1.3.6.1.5.2.3.5": "pkinitKDC", "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
        "2.5.29.37.0": "anyExtendedKeyUsage",
    ]

    static let extensionNames: [String: String] = [
        "2.5.29.17": "subjectAltName", "2.5.29.15": "keyUsage", "2.5.29.37": "extendedKeyUsage",
        "2.5.29.19": "basicConstraints", "2.5.29.14": "subjectKeyIdentifier", "2.5.29.35": "authorityKeyIdentifier",
        "2.5.29.31": "cRLDistributionPoints", "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
        "1.3.6.1.5.5.7.1.24": "tlsFeature (OCSP must-staple)", "2.5.29.32": "certificatePolicies",
        "1.3.6.1.4.1.311.20.2": "certificateTemplateName (Microsoft)", "1.3.6.1.4.1.311.21.7": "certificateTemplate (Microsoft)",
        "1.3.6.1.4.1.311.21.10": "applicationPolicies (Microsoft)", "1.2.840.113549.1.9.15": "smimeCapabilities",
        "2.16.840.1.113730.1.1": "netscapeCertType", "2.16.840.1.113730.1.13": "netscapeComment",
    ]

    static let attributeNames: [String: String] = [
        "1.2.840.113549.1.9.7": "challengePassword", "1.2.840.113549.1.9.2": "unstructuredName",
        "1.3.6.1.4.1.311.13.2.3": "osVersion (Microsoft)", "1.3.6.1.4.1.311.21.20": "requestClientInfo (Microsoft)",
        "1.3.6.1.4.1.311.13.2.2": "enrollmentCSP (Microsoft)", "1.3.6.1.4.1.311.13.2.1": "enrollmentNameValuePair (Microsoft)",
    ]
}

/// A signed CSR: the certificate, its chain and the facts the operator should see.
public struct SignResult: Sendable {
    public enum Format: String, Sendable, CaseIterable {
        /// PEM: the certificate, followed by the CA certificate when the chain is asked for.
        case pem
        /// DER: the certificate only.
        case der
        /// PKCS#7 (P7B, DER): always the certificate and the CA certificate.
        case p7b
    }

    public let review: CSRReview
    public let certificate: Certificate
    public let der: [UInt8]
    /// The issuing CA (our CAs are roots, so the chain is certificate + CA).
    public let caName: String
    public let caCertificate: Certificate
    public let caDER: [UInt8]
    /// Lower-case hex, as in `pki_issued`.
    public let serial: String
    /// Read back from the issued certificate.
    public let crlDistributionPoints: [String]
    public let caIssuers: [String]

    public var chain: [Certificate] { [certificate, caCertificate] }

    public func encoded(_ format: Format, includeChain: Bool = false) -> [UInt8] {
        switch format {
        case .der: return der
        case .p7b: return PKCS7.write(certificates: [der, caDER])
        case .pem:
            var text = PEMBlock(label: "CERTIFICATE", der: der).text
            if includeChain { text += PEMBlock(label: "CERTIFICATE", der: caDER).text }
            return Array(text.utf8)
        }
    }

    /// The certificate summary (serial, validity, SANs, CDP, …).
    public func lines(now: Date = Date()) -> [String] {
        var l = ["certificate"]
        if let item = try? CertificateItem(der: der) {
            l += CertificateSummary(item).lines(now: now).map { "  " + $0 }
        }
        l.append("  CRL (CDP)        \(crlDistributionPoints.joined(separator: ", "))")
        l.append("  CA issuers (AIA) \(caIssuers.joined(separator: ", "))")
        l.append("  template         \(review.template.name), CA \(caName), requester \(review.requester.name)")
        return l
    }
}

extension CAService {
    /// Decodes the CSR, resolves the template (and account), and runs every policy check
    /// `issue` runs, without issuing. Throws only for input problems (not a CSR, unknown
    /// template or account, a bad `--san`/`--cn`); policy refusals are in `verdict`.
    public func review(_ request: SignRequest) async throws -> CSRReview {
        // The CSR
        let decoded = try DecodedRequest.decode(request.csr, name: request.sourceName)
        let keyKind = decoded.keyKind

        // Template and requester
        let template = try await template(named: request.templateName)
        var requester = RequesterIdentity(name: request.operatorName, isAdmin: true)
        let accountBound = template.sanPolicy == .dnsHostName || template.sanPolicy == .upn
        var accountName: String?
        if let account = request.account {
            guard accountBound else { throw SignRequestError.accountNotApplicable(template: template.name) }
            let resolved = try await self.requester(account: account)
            accountName = resolved.name
            requester = RequesterIdentity(name: "\(request.operatorName) for \(resolved.name)", sid: resolved.sid,
                                          groupSIDs: resolved.groupSIDs, isAdmin: true)
        } else if accountBound {
            throw SignRequestError.accountRequired(template: template.name, policy: template.sanPolicy)
        }

        // Overrides
        var overrides = IssuanceOverrides(caName: request.caName, validityDays: request.validityDays)
        let requestedNames = (try? decoded.attributes.extensionRequest?.extensions.subjectAlternativeNames).flatMap { $0 }.map(Array.init) ?? []
        switch request.subjectAltNames {
        case .fromRequest: break
        case .add(let extra):
            var names = requestedNames
            for n in extra where !names.contains(where: { Self.describe($0).lowercased() == Self.describe(n).lowercased() }) {
                names.append(n)
            }
            overrides.subjectAltNames = names
        case .replace(let names):
            overrides.subjectAltNames = names
        }
        if let cn = request.commonName {
            let trimmed = cn.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, trimmed.count <= 64 else { throw SignRequestError.invalidCommonName(cn) }
            overrides.subject = Self.replacingCommonName(in: decoded.subject, with: trimmed)
        }

        // Verdict: the checks `issue` runs; for an account-bound template also the template's
        // enrolment ACL for that account, exactly as auto-enrollment applies it.
        var verdict = CSRReview.Verdict.willIssue
        var plan: IssuancePlan?
        do {
            if accountBound, let accountName, !Self.mayEnrol(groupSIDs: requester.groupSIDs, sid: requester.sid, template: template) {
                throw IssuanceError.notAllowedToEnrol(requester: accountName, template: template.name)
            }
            if let csr = decoded.csr {
                plan = try await self.plan(csr: csr, template: template, requester: requester, overrides: overrides)
            } else {
                // A key swift-certificates cannot load (RSA under 2048 bits): always refused, for
                // the key (the review still shows whether its signature verifies).
                guard template.enabled else { throw IssuanceError.templateDisabled(template.name) }
                guard template.allowedKeyTypes.map({ $0.lowercased() }).contains(keyKind.token) else {
                    throw IssuanceError.keyTypeNotAllowed(found: keyKind.description, allowed: template.allowedKeyTypes,
                                                          template: template.name)
                }
                if case .rsa(let bits) = keyKind {
                    throw IssuanceError.keyTooSmall(bits: bits, minimum: max(template.minKeyBits, 2048), template: template.name)
                }
                throw IssuanceError.malformedCSR("unsupported public key")
            }
        } catch let e as IssuanceError {
            verdict = .refused(e)
        }

        let extensions = Self.requestedExtensions(decoded.attributes)
        let others = decoded.attributes.map(\.oid.description).filter { $0 != "1.2.840.113549.1.9.14" }
            .map { CSRReview.attributeNames[$0] ?? $0 }
        return CSRReview(
            sourceName: request.sourceName, sourceFormat: decoded.format, der: decoded.der, csr: decoded.csr,
            subject: decoded.subject.description, keyType: keyKind.description, keyKind: keyKind,
            signatureAlgorithm: decoded.signatureAlgorithm, signatureValid: decoded.signatureValid,
            signatureChecked: decoded.signatureChecked, requestedSubjectAltNames: requestedNames.map(Self.describe),
            requestedExtensions: extensions, otherAttributes: others, template: template, requester: requester,
            account: accountName, plan: plan, verdict: verdict,
            warnings: Self.warnings(subject: decoded.subject, requestedNames: requestedNames, extensions: extensions,
                                    template: template, plan: plan, signatureAlgorithm: decoded.signatureAlgorithm),
            overrides: overrides)
    }

    /// Reviews the request again and, when the verdict allows it, issues and records the
    /// certificate (requester = the operator). Throws `SignRequestError.refused` otherwise.
    public func sign(_ request: SignRequest) async throws -> SignResult {
        let review = try await review(request)
        guard review.canSign, let plan = review.plan, let csr = review.csr else {
            if case .refused(let e) = review.verdict { throw SignRequestError.refused(e) }
            throw SignRequestError.refused(.malformedCSR("no plan"))
        }
        var overrides = review.overrides
        overrides.caName = plan.ca.name
        let certificate: Certificate
        do {
            certificate = try await issue(csr: csr, template: review.template, requester: review.requester,
                                          overrides: overrides)
        } catch let e as IssuanceError {
            throw SignRequestError.refused(e)
        }
        let der = try LabPKI.der(certificate)
        return SignResult(review: review, certificate: certificate, der: der, caName: plan.ca.name,
                          caCertificate: plan.ca.certificate, caDER: try plan.ca.der(),
                          serial: LabPKI.hex(certificate.serialNumber),
                          crlDistributionPoints: Self.extensionURIs(certificate, oid: PKIOID.crlDistributionPoints),
                          caIssuers: Self.extensionURIs(certificate, oid: PKIOID.authorityInfoAccess))
    }

    // MARK: - SAN text

    /// Parses `dns:<host>`, `ip:<v4|v6>`, `upn:<user@realm>`, `email:<address>` or `uri:<uri>`
    /// (prefix case-insensitive; `DNS:`/`IP:` as openssl prints them work too).
    public static func parseSubjectAltName(_ text: String) throws -> GeneralName {
        guard let colon = text.firstIndex(of: ":") else { throw SignRequestError.invalidSubjectAltName(text) }
        let kind = text[..<colon].lowercased()
        let value = String(text[text.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { throw SignRequestError.invalidSubjectAltName(text) }
        let name: GeneralName
        switch kind {
        case "dns": name = .dnsName(value.lowercased())
        case "ip", "ip address":
            guard let bytes = NetworkAddresses.parse(value) else { throw SignRequestError.invalidSubjectAltName(text) }
            name = .ipAddress(ASN1OctetString(contentBytes: bytes[...]))
        case "upn": name = try upnName(value)
        case "email", "rfc822": name = .rfc822Name(value)
        case "uri": name = .uniformResourceIdentifier(value)
        default: throw SignRequestError.invalidSubjectAltName(text)
        }
        do { try validate(name) } catch { throw SignRequestError.invalidSubjectAltName(text) }
        if case .otherName = name, !value.contains("@") { throw SignRequestError.invalidSubjectAltName(text) }
        return name
    }

    // MARK: - Helpers

    static func mayEnrol(groupSIDs: [String], sid: String?, template: CertificateTemplate) -> Bool {
        let mine = Set((groupSIDs + [sid].compactMap { $0 }).map { $0.uppercased() })
        return template.enrolAllowedGroupSIDs.contains { mine.contains($0.uppercased()) }
    }

    /// `dn` with its CN attribute(s) set to `cn` (appended as the last RDN when it has none).
    static func replacingCommonName(in dn: DistinguishedName, with cn: String) -> DistinguishedName {
        var replaced = false
        var rdns: [RelativeDistinguishedName] = dn.map { rdn in
            RelativeDistinguishedName(rdn.map { attribute in
                guard attribute.type == .RDNAttributeType.commonName else { return attribute }
                replaced = true
                return RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: cn)
            })
        }
        if !replaced {
            rdns.append(RelativeDistinguishedName(RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName,
                                                                                      utf8String: cn)))
        }
        return DistinguishedName(rdns)
    }

    static func commonNames(_ dn: DistinguishedName) -> [String] {
        dn.flatMap { $0 }.filter { $0.type == .RDNAttributeType.commonName }.compactMap { attribute in
            String(attribute.value)
        }
    }

    static func requestedExtensions(_ attributes: CertificateSigningRequest.Attributes) -> [CSRReview.RequestedExtension] {
        guard let request = try? attributes.extensionRequest else { return [] }
        return request.extensions.map { ext in
            let oid = ext.oid.description
            var value = "\(ext.value.count) bytes"
            switch oid {
            case "2.5.29.17":
                if let names = try? SubjectAlternativeNames(ext) { value = names.map(describe).joined(separator: ", ") }
            case "2.5.29.15":
                if let ku = try? KeyUsage(ext) {
                    let flags: [(Bool, String)] = [
                        (ku.digitalSignature, "digitalSignature"), (ku.nonRepudiation, "nonRepudiation"),
                        (ku.keyEncipherment, "keyEncipherment"), (ku.dataEncipherment, "dataEncipherment"),
                        (ku.keyAgreement, "keyAgreement"), (ku.keyCertSign, "keyCertSign"), (ku.cRLSign, "cRLSign"),
                    ]
                    value = flags.filter(\.0).map(\.1).joined(separator: ", ")
                }
            case "2.5.29.37":
                if let eku = try? ExtendedKeyUsage(ext) {
                    value = CSRReview.ekuNames(eku.map { ASN1ObjectIdentifier($0).description })
                }
            case "2.5.29.19":
                if let bc = try? BasicConstraints(ext) {
                    switch bc {
                    case .isCertificateAuthority(let len): value = "CA:TRUE" + (len.map { ", pathlen:\($0)" } ?? "")
                    case .notCertificateAuthority: value = "CA:FALSE"
                    }
                }
            default: break
            }
            return CSRReview.RequestedExtension(oid: oid, name: CSRReview.extensionNames[oid] ?? oid, critical: ext.critical,
                                                value: value, honoured: oid == "2.5.29.17")
        }
    }

    static func warnings(subject: DistinguishedName, requestedNames: [GeneralName],
                         extensions: [CSRReview.RequestedExtension], template: CertificateTemplate,
                         plan: IssuancePlan?, signatureAlgorithm: String) -> [String] {
        var w: [String] = []
        if signatureAlgorithm.lowercased().contains("sha1") {
            w.append("the CSR is signed with SHA-1 (the certificate itself is signed with SHA-256)")
        }
        if let bc = extensions.first(where: { $0.oid == "2.5.29.19" }), bc.value.hasPrefix("CA:TRUE"), !template.isCA {
            w.append("the CSR asks to be a CA (\(bc.value)); the certificate will be CA:FALSE")
        }
        let ignored = extensions.filter { !$0.honoured && $0.oid != "2.5.29.14" }.map(\.name)
        if !ignored.isEmpty {
            w.append("requested \(ignored.joined(separator: ", ")) not copied: template \(template.name) sets usages and extensions")
        }
        guard let plan else { return w }
        let requestedText = requestedNames.map(describe)
        let issuedText = plan.subjectAltNames.map(describe)
        if requestedText.map({ $0.lowercased() }) != issuedText.map({ $0.lowercased() }) {
            let asked = requestedText.isEmpty ? "none" : requestedText.joined(separator: ", ")
            let will = issuedText.isEmpty ? "none" : issuedText.joined(separator: ", ")
            let why = switch template.sanPolicy {
            case .dnsHostName: " (from the account's dNSHostName)"
            case .upn: " (from the account's UPN)"
            case .none: " (template issues no SAN)"
            case .fromRequest: " (operator --san)"
            }
            w.append("SANs will be \(will)\(why); the CSR asks for \(asked)")
        }
        if plan.subject != subject {
            w.append("subject will be \(plan.subject.isEmpty ? "(empty)" : plan.subject.description); the CSR asks for \(subject.isEmpty ? "(empty)" : subject.description)")
        }
        if template.ekus.contains(PKIOID.serverAuth) {
            let names = Set(plan.subjectAltNames.compactMap { n -> String? in
                switch n {
                case .dnsName(let h): return normalizedHost(h)
                case .ipAddress(let o): return NetworkAddresses.format(Array(o.bytes))
                default: return nil
                }
            })
            for cn in commonNames(plan.subject) where !names.contains(normalizedHost(cn)) {
                w.append("the subject CN \(cn) is not among the SANs; TLS clients match the SANs only")
            }
        }
        for case .dnsName(let h) in plan.subjectAltNames where h.hasPrefix("*.") {
            w.append("wildcard name \(h)")
        }
        if plan.cappedByCA {
            w.append("validity cut to the CA's expiry \(plan.notAfter.formatted(Date.ISO8601FormatStyle().year().month().day())) (asked for \(plan.validityDays) days)")
        }
        if plan.validityDays > template.validityDays {
            w.append("validity \(plan.validityDays) days is longer than the template's \(template.validityDays)")
        }
        return w
    }

    /// The URIs inside an issued certificate's extension (`[6] uniformResourceIdentifier` anywhere
    /// in it): the CDP full names, or the AIA access locations.
    static func extensionURIs(_ certificate: Certificate, oid: String) -> [String] {
        guard let ext = certificate.extensions.first(where: { $0.oid.description == oid }),
              let root = try? DER.parse(Array(ext.value)) else { return [] }
        var out: [String] = []
        func walk(_ node: ASN1Node) {
            switch node.content {
            case .constructed(let children): for c in children { walk(c) }
            case .primitive(let bytes):
                if node.identifier.tagClass == .contextSpecific, node.identifier.tagNumber == 6 {
                    out.append(String(decoding: bytes, as: UTF8.self))
                }
            }
        }
        walk(root)
        return out
    }
}
