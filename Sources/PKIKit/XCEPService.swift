import Foundation
import MSPAC
import os
import Store

/// PK-6: the MS-XCEP policy service (`/ADPolicyProvider_CEP_Kerberos/service.svc/CEP`), what an AD CS
/// "Certificate Enrollment Policy Web Service" in AD mode answers: every enabled template the
/// current CA publishes, with the caller's Enroll / AutoEnroll permission evaluated against the
/// template's security descriptor as published in the Configuration NC (PK-5), the current CA
/// with its MS-WSTEP (CES) URL, and every OID the policies reference.
///
/// Values and their sources are listed in docs/notes/pk-6.md. The policy ID is the one PK-4 writes
/// into the Group Policy (`{<domain objectGUID>}` unless `gpo autoenroll --policy-id` chose
/// another; `policyID` supplies it).
public actor XCEPService {
    public let ca: CAService
    /// The policy ID the GPO names (`PolicyServers\<id>\PolicyID`).
    private let policyID: @Sendable () async -> String
    /// `https://<dc fqdn>[:port]` — the base of the CES URL handed out in `<cAs>`.
    private let baseURL: @Sendable () async -> String
    private let onEvent: (@Sendable (String) -> Void)?
    private let logger = Logger(subsystem: "dev.labdc.app", category: "xcep")

    public static let getPoliciesAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
    public static let getPoliciesResponseAction = getPoliciesAction + "Response"
    /// MS-XCEP §3.1.4.1.3.23 note <6>: AD CS's default.
    public static let nextUpdateHours = 8
    public static let friendlyName = "Active Directory Enrollment Policy"
    /// The CEP path of the Kerberos-authenticated AD policy provider (compared case-insensitively).
    public static let path = "/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"

    public init(ca: CAService, policyID: @escaping @Sendable () async -> String,
                baseURL: @escaping @Sendable () async -> String, onEvent: (@Sendable (String) -> Void)? = nil) {
        self.ca = ca
        self.policyID = policyID
        self.baseURL = baseURL
        self.onEvent = onEvent
    }

    /// Handles one authenticated POST: returns (HTTP status, SOAP body).
    public func handle(_ body: [UInt8], caller: EnrollmentCaller) async -> (status: Int, body: [UInt8]) {
        let request: SOAPRequest
        do { request = try SOAPRequest(bytes: body) } catch {
            emit("XCEP GetPolicies from \(caller.logName) -> fault (\(error))")
            return (400, SOAP.fault(code: "s:Sender", reason: "\(error)", relatesTo: nil))
        }
        guard request.action == Self.getPoliciesAction,
              request.body.localName == "GetPolicies", request.body.uri == SOAPNS.xcep else {
            let what = request.action ?? "{\(request.body.uri ?? "")}\(request.body.localName ?? "")"
            emit("XCEP \(what) from \(caller.logName) -> fault (unsupported action)")
            return (500, SOAP.fault(code: "s:Sender",
                                    subcode: ("http://www.w3.org/2005/08/addressing", "ActionNotSupported"),
                                    reason: "The message with Action '\(request.action ?? "")' cannot be processed at the receiver.",
                                    relatesTo: request.messageID))
        }
        // §3.1.4.1.2.1: a missing / nil client element is a fault.
        guard let client = request.body.child(SOAPNS.xcep, "client"), !client.isNil else {
            emit("XCEP GetPolicies from \(caller.logName) -> fault (no client element)")
            return (500, SOAP.fault(code: "s:Receiver", reason: "GetPolicies: the client element is missing or nil",
                                    relatesTo: request.messageID))
        }
        let filter = Self.RequestFilter(request.body.child(SOAPNS.xcep, "requestFilter"))
        do {
            let policy = try await build(caller: caller, filter: filter)
            let summary = policy.policies.map { p in
                p.template.name + (p.autoEnroll ? " autoenroll" : p.enroll ? " enroll" : " no-permission")
            }
            emit("XCEP GetPolicies from \(caller.logName) -> \(policy.policies.count) \(policy.policies.count == 1 ? "policy" : "policies")"
                 + (summary.isEmpty ? "" : " (\(summary.joined(separator: ", ")))"))
            return (200, SOAP.envelope(action: Self.getPoliciesResponseAction, relatesTo: request.messageID,
                                       payload: policy.xml))
        } catch {
            emit("XCEP GetPolicies from \(caller.logName) -> fault (\(error))")
            return (500, SOAP.fault(code: "s:Receiver", reason: "\(error)", relatesTo: request.messageID))
        }
    }

    // MARK: - Request filter (§3.1.4.1.3.22)

    struct RequestFilter {
        var policyOIDs: Set<String> = []
        /// Z and Y of §3.1.4.1.3.22 (3 when absent / nil; 0 = our maximum).
        var clientVersion = 3
        var serverVersion = 3

        init(_ element: XMLElement?) {
            guard let element, !element.isNil else { return }
            if let oids = element.child(SOAPNS.xcep, "policyOIDs"), !oids.isNil {
                policyOIDs = Set(oids.children(SOAPNS.xcep, "oid").map(\.trimmedText).filter { !$0.isEmpty })
            }
            func version(_ name: String) -> Int {
                guard let e = element.child(SOAPNS.xcep, name), !e.isNil, let v = Int(e.trimmedText) else { return 3 }
                return v == 0 || v > 5 ? 5 : v
            }
            clientVersion = version("clientVersion")
            serverVersion = version("serverVersion")
        }

        init() {}

        func admits(_ t: CertificateTemplate) -> Bool {
            if !policyOIDs.isEmpty && !policyOIDs.contains(t.oid) { return false }
            let flag = TemplateDirectory.privateKeyFlag(schemaVersion: TemplateDirectory.schemaVersion(t))
            return Int((flag >> 24) & 0xF) <= clientVersion && Int((flag >> 16) & 0xF) <= serverVersion
        }
    }

    // MARK: - Response model

    struct PolicyEntry {
        var template: CertificateTemplate
        var enroll: Bool
        var autoEnroll: Bool
    }

    struct Policy {
        var policies: [PolicyEntry]
        var xml: String
    }

    /// OID table of one response: one `oIDReferenceID` per distinct (value, group).
    struct OIDTable {
        struct Entry { var value: String; var group: Int; var id: Int; var name: String }
        private(set) var entries: [Entry] = []

        mutating func reference(_ value: String, group: Int, name: String) -> Int {
            if let e = entries.first(where: { $0.value == value && $0.group == group }) { return e.id }
            let id = entries.count + 1
            entries.append(Entry(value: value, group: group, id: id, name: name))
            return id
        }
    }

    /// MS-XCEP §3.1.4.1.3.16 groups.
    enum OIDGroup {
        static let hashAlgorithm = 1
        static let publicKey = 3
        static let extensionOrAttribute = 6
        static let extendedKeyUsage = 7
        static let enrollmentObject = 9
    }

    static let ekuNames: [String: String] = [
        PKIOID.serverAuth: "Server Authentication", PKIOID.clientAuth: "Client Authentication",
        PKIOID.emailProtection: "Secure Email", "1.3.6.1.5.5.7.3.3": "Code Signing",
        "1.3.6.1.4.1.311.10.3.4": "Encrypting File System", "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
        "1.3.6.1.5.5.7.3.8": "Time Stamping", "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    ]

    static let applicationPoliciesOID = "1.3.6.1.4.1.311.21.10"

    /// Builds the response for `caller`.
    func build(caller: EnrollmentCaller, filter: RequestFilter = RequestFilter()) async throws -> Policy {
        let store = ca.store
        let info = try await store.domainInfo()
        let authority = try await ca.pki.currentAuthority()
        let templates = try await ca.templates().filter { $0.enabled && filter.admits($0) }
            .sorted { $0.name.lowercased() < $1.name.lowercased() }
        let sids = caller.tokenSIDs.compactMap { try? SID(string: $0) }
        guard let enrollRight = GUID(string: TemplateDirectory.enrollRight),
              let autoEnrollRight = GUID(string: TemplateDirectory.autoEnrollRight) else {
            throw PKIKitError.encoding("extended-right GUIDs")
        }

        var oids = OIDTable()
        var entries: [PolicyEntry] = []
        var policiesXML = ""
        for t in templates {
            let sd = try await Self.templateSecurityDescriptor(t, store: store, info: info)
            let enroll = EnrollmentAccess.allows(sd, right: enrollRight, sids: sids)
            let autoEnroll = enroll && EnrollmentAccess.allows(sd, right: autoEnrollRight, sids: sids)
            entries.append(PolicyEntry(template: t, enroll: enroll, autoEnroll: autoEnroll))
            policiesXML += Self.policyXML(t, enroll: enroll, autoEnroll: autoEnroll, oids: &oids)
        }

        // The CA: enrollPermission from the enrollment service object's SD (Authenticated Users: Enroll).
        var caEnroll = true
        if let object = try? await Self.enrollmentServiceObject(authority, store: store, info: info),
           let raw = object.values("nTSecurityDescriptor").first, let sd = try? SecurityDescriptor.decode(raw) {
            caEnroll = EnrollmentAccess.allows(sd, right: enrollRight, sids: sids)
        }
        let cesURL = await baseURL() + "/\(authority.name)_CES_Kerberos/service.svc/CES"
        let caXML = "<cAs><cA><uris><cAURI>"
            + SOAP.element("clientAuthentication", "2")          // Transport Kerberos
            + SOAP.element("uri", cesURL)
            + SOAP.element("priority", "1")
            + SOAP.element("renewalOnly", "false")
            + "</cAURI></uris>"
            + SOAP.element("certificate", Data(try authority.der()).base64EncodedString())
            + SOAP.element("enrollPermission", caEnroll ? "true" : "false")
            + SOAP.element("cAReferenceID", "0")
            + "</cA></cAs>"

        var oidXML = ""
        for e in oids.entries {
            oidXML += "<oID>" + SOAP.element("value", e.value) + SOAP.element("group", String(e.group))
                + SOAP.element("oIDReferenceID", String(e.id)) + SOAP.element("defaultName", e.name) + "</oID>"
        }

        var xml = "<GetPoliciesResponse xmlns=\"\(SOAPNS.xcep)\"><response>"
        xml += SOAP.element("policyID", await policyID())
        xml += SOAP.element("policyFriendlyName", Self.friendlyName)
        xml += SOAP.element("nextUpdateHours", String(Self.nextUpdateHours))
        // Always a full answer (the caller's permissions are evaluated each time).
        xml += SOAP.nilElement("policiesNotChanged")
        xml += entries.isEmpty ? SOAP.nilElement("policies") : "<policies>\(policiesXML)</policies>"
        xml += "</response>"
        xml += caXML
        xml += oids.entries.isEmpty ? SOAP.nilElement("oIDs") : "<oIDs>\(oidXML)</oIDs>"
        xml += "</GetPoliciesResponse>"
        return Policy(policies: entries, xml: xml)
    }

    /// One `<policy>`: the attribute values are those PK-5 publishes on the template object.
    static func policyXML(_ t: CertificateTemplate, enroll: Bool, autoEnroll: Bool, oids: inout OIDTable) -> String {
        let schema = TemplateDirectory.schemaVersion(t)
        let policyRef = oids.reference(t.oid, group: OIDGroup.enrollmentObject, name: t.displayName)

        var a = "<attributes>"
        a += SOAP.element("commonName", t.name)
        a += SOAP.element("policySchema", String(schema))
        a += "<certificateValidity>"
            + SOAP.element("validityPeriodSeconds", String(UInt64(t.validityDays) * 86_400))
            + SOAP.element("renewalPeriodSeconds", String(UInt64(t.renewalDays) * 86_400))
            + "</certificateValidity>"
        a += "<permission>" + SOAP.element("enroll", enroll ? "true" : "false")
            + SOAP.element("autoEnroll", autoEnroll ? "true" : "false") + "</permission>"

        // privateKeyAttributes (§3.1.4.1.3.20)
        a += "<privateKeyAttributes>"
        a += SOAP.element("minimalKeyLength", String(TemplateDirectory.minimalKeySize(t)))
        a += SOAP.element("keySpec", String(TemplateDirectory.defaultKeySpec(t)))
        if schema >= 3 {
            a += SOAP.element("keyUsageProperty", "16777215")      // msPKI-Key-Usage (NCRYPT_ALLOW_ALL_USAGES)
        } else {
            a += SOAP.nilElement("keyUsageProperty")
        }
        a += SOAP.nilElement("permissions")
        if schema >= 3, let curve = TemplateDirectory.curveBits(t).first {
            let (oid, name) = curveOID(curve)
            a += SOAP.element("algorithmOIDReference", String(oids.reference(oid, group: OIDGroup.publicKey, name: name)))
        } else {
            a += SOAP.nilElement("algorithmOIDReference")
        }
        let providers = TemplateDirectory.defaultCSPs(t).map(providerName)
        a += providers.isEmpty ? SOAP.nilElement("cryptoProviders")
            : "<cryptoProviders>" + providers.map { SOAP.element("provider", $0) }.joined() + "</cryptoProviders>"
        a += "</privateKeyAttributes>"

        a += "<revision>" + SOAP.element("majorRevision", String(t.majorRevision))
            + SOAP.element("minorRevision", String(CertificateTemplate.minorVersion)) + "</revision>"
        a += SOAP.nilElement("supersededPolicies")
        a += SOAP.element("privateKeyFlags", String(UInt32(truncatingIfNeeded: TemplateDirectory.privateKeyFlag(schemaVersion: schema))))
        a += SOAP.element("subjectNameFlags", String(TemplateDirectory.certificateNameFlag(t)))
        a += SOAP.element("enrollmentFlags", String(UInt32(truncatingIfNeeded: TemplateDirectory.enrollmentFlag(t))))
        a += SOAP.element("generalFlags", String(UInt32(truncatingIfNeeded: TemplateDirectory.generalFlags(t))))
        if schema >= 3 {
            let bits = TemplateDirectory.curveBits(t).first ?? 256
            let (oid, name) = bits >= 521 ? ("2.16.840.1.101.3.4.2.3", "sha512")
                : bits >= 384 ? ("2.16.840.1.101.3.4.2.2", "sha384") : ("2.16.840.1.101.3.4.2.1", "sha256")
            a += SOAP.element("hashAlgorithmOIDReference", String(oids.reference(oid, group: OIDGroup.hashAlgorithm, name: name)))
        } else {
            a += SOAP.nilElement("hashAlgorithmOIDReference")         // §3.1.4.1.3.1: nil for schema 1/2
        }
        a += SOAP.nilElement("rARequirements")                       // msPKI-RA-Signature 0
        a += SOAP.nilElement("keyArchivalAttributes")                // no key archival

        // extensions: what the client puts in its request (the CA builds the certificate itself).
        var ext = ""
        func add(_ oid: String, _ name: String, critical: Bool, _ value: [UInt8]) {
            let ref = oids.reference(oid, group: OIDGroup.extensionOrAttribute, name: name)
            ext += "<extension>" + SOAP.element("oIDReference", String(ref))
                + SOAP.element("critical", critical ? "true" : "false")
                + SOAP.element("value", Data(value).base64EncodedString()) + "</extension>"
        }
        add(PKIOID.certificateTemplateExtension, "Certificate Template Information", critical: false,
            templateExtensionValue(t))
        if !t.ekus.isEmpty {
            for eku in t.ekus { _ = oids.reference(eku, group: OIDGroup.extendedKeyUsage, name: ekuNames[eku] ?? eku) }
            add("2.5.29.37", "Enhanced Key Usage", critical: false, DERWriter.sequence(t.ekus.map(DERWriter.oid)))
            add(applicationPoliciesOID, "Application Policies", critical: false,
                DERWriter.sequence(t.ekus.map { DERWriter.sequence([DERWriter.oid($0)]) }))
        }
        add("2.5.29.15", "Key Usage", critical: true, keyUsageExtensionValue(t.keyUsage))
        a += "<extensions>\(ext)</extensions>"
        a += "</attributes>"

        return "<policy>" + SOAP.element("policyOIDReference", String(policyRef))
            + "<cAs>" + SOAP.element("cAReference", "0") + "</cAs>" + a + "</policy>"
    }

    /// `szOID_CERTIFICATE_TEMPLATE`: SEQUENCE { templateID, majorVersion, minorVersion } — the value
    /// PK-1 issues.
    static func templateExtensionValue(_ t: CertificateTemplate) -> [UInt8] {
        DERWriter.sequence([DERWriter.oid(t.oid), DERWriter.integer(Int64(t.majorRevision)),
                            DERWriter.integer(Int64(CertificateTemplate.minorVersion))])
    }

    /// KeyUsage BIT STRING in DER (trailing zero bits dropped): digitalSignature | keyEncipherment
    /// → `03 02 05 a0` (the MS-XCEP §4.1.1.2 example value `AwIFoA==`).
    static func keyUsageExtensionValue(_ usage: TemplateKeyUsage) -> [UInt8] {
        var bytes = TemplateDirectory.keyUsageBytes(usage)
        while let last = bytes.last, last == 0 { bytes.removeLast() }
        guard let last = bytes.last else { return [0x03, 0x01, 0x00] }
        let unused = UInt8(last.trailingZeroBitCount)
        return [0x03, UInt8(bytes.count + 1), unused] + bytes
    }

    /// `pKIDefaultCSPs` values are `<priority>,<name>`; the policy lists the names.
    static func providerName(_ value: String) -> String {
        guard let comma = value.firstIndex(of: ","), Int(value[..<comma]) != nil else { return value }
        return String(value[value.index(after: comma)...])
    }

    /// The CNG public-key algorithm OID of a curve (CryptoAPI's OID info for ECDSA_P256 & co.).
    static func curveOID(_ bits: Int) -> (String, String) {
        switch bits {
        case 384: ("1.3.132.0.34", "ECDSA_P384")
        case 521: ("1.3.132.0.35", "ECDSA_P521")
        default: ("1.2.840.10045.3.1.7", "ECDSA_P256")
        }
    }

    // MARK: - Directory lookups

    /// The template's SD as published (an administrator may have edited it in AD); PK-5's SDDL
    /// when the object is missing.
    static func templateSecurityDescriptor(_ t: CertificateTemplate, store: DirectoryStore,
                                           info: DomainInfo) async throws -> DecodedSecurityDescriptor {
        let dn = PKIDirectory.certificateTemplatesDN(configurationDN: info.configurationDN).child(RDN("CN", t.name))
        if let entry = try? await store.read(dn: dn, attrs: ["nTSecurityDescriptor"]),
           let raw = entry.values("nTSecurityDescriptor").first, let sd = try? SecurityDescriptor.decode(raw) {
            return sd
        }
        return try SecurityDescriptor.decode(try SecurityDescriptor.fromSDDL(TemplateDirectory.securityDescriptorSDDL(t),
                                                                             domainSID: info.domainSID))
    }

    static func enrollmentServiceObject(_ authority: CertificateAuthority, store: DirectoryStore,
                                        info: DomainInfo) async throws -> DirectoryEntry? {
        let dn = PKIDirectory.enrollmentServicesDN(configurationDN: info.configurationDN)
            .child(RDN("CN", try PKIDirectory.objectName(authority)))
        return try await store.read(dn: dn, attrs: ["nTSecurityDescriptor"])
    }

    private func emit(_ line: String) {
        logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }
}
