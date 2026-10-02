import _CryptoExtras
import CryptoKit
import Foundation
import Store
import SwiftASN1
import X509

// PK-7: enrollment challenges and the issuance policy shared by SCEP and EST.
//
// A challenge is created by an administrator (`labdc scep challenge new`), shown once, and
// kept only as a SHA-256. It authorises one enrollment (or, `reusable`, any number until it
// expires or is revoked) for one template, optionally for one named device. A device that
// presents a valid challenge is issued a certificate as if an administrator had signed its
// CSR with that template (manual-approval templates are refused: there is no pending queue).

/// Why a challenge was not accepted. The challenge text itself never appears here.
public enum ChallengeError: Error, Sendable, Equatable, CustomStringConvertible {
    case missing
    case invalid
    case expired(id: String)
    case alreadyUsed(id: String, by: String?)
    case revoked(id: String)
    case wrongDevice(id: String, expected: String, got: [String])
    case wrongTemplate(id: String, expected: String, requested: String)
    case unknownID(String)
    case invalidTTL(String)

    public var description: String {
        switch self {
        case .missing: "no challenge password"
        case .invalid: "unknown challenge password"
        case .expired(let id): "challenge \(id) has expired"
        case .alreadyUsed(let id, let by): "one-time challenge \(id) was already used\(by.map { " by \($0)" } ?? "")"
        case .revoked(let id): "challenge \(id) was revoked"
        case .wrongDevice(let id, let expected, let got):
            "challenge \(id) is for device \(expected), the request names \(got.isEmpty ? "no device" : got.joined(separator: ", "))"
        case .wrongTemplate(let id, let expected, let requested):
            "challenge \(id) enrols for template \(expected), not \(requested)"
        case .unknownID(let id): "no challenge with id \(id)"
        case .invalidTTL(let s): "invalid lifetime \(s) (1 minute to 3650 days, e.g. 30m, 24h, 7d)"
        }
    }
}

/// A refused SCEP / EST enrollment.
public enum DeviceEnrollmentError: Error, Sendable, CustomStringConvertible {
    case challenge(ChallengeError)
    case refused(IssuanceError)
    /// The template needs manual approval (no pending queue for devices).
    case manualApproval(template: String)
    /// Renewal: the existing certificate is not a valid certificate of ours.
    case notRenewable(String)
    case badRequest(String)

    public var description: String {
        switch self {
        case .challenge(let e): "\(e)"
        case .refused(let e): "\(e)"
        case .manualApproval(let t): "template '\(t)' needs manual approval; sign the CSR with `labdc ca sign` instead"
        case .notRenewable(let s): s
        case .badRequest(let s): s
        }
    }
}

/// What a device enrollment produced.
public struct DeviceEnrollmentResult: Sendable {
    public let certificate: Certificate
    public let der: [UInt8]
    public let serial: String
    /// The requester name recorded in `pki_issued` (the device).
    public let device: String
    public let template: String
    public let caName: String
}

extension PKIChallengeRow {
    public enum State: String, Sendable { case active, used, expired, revoked }

    public func state(at now: Date) -> State {
        if revoked { return .revoked }
        if !reusable && usedAt != nil { return .used }
        if expiresAt <= now { return .expired }
        return .active
    }
}

extension CAService {
    /// The template a challenge enrols for when none is named.
    public static let defaultDeviceTemplate = "Device"
    public static let defaultChallengeTTL: TimeInterval = 86400

    /// Parses `30m`, `24h`, `7d`, `3600s` (a bare number is hours).
    public static func parseTTL(_ text: String) throws -> TimeInterval {
        let t = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard let last = t.last else { throw ChallengeError.invalidTTL(text) }
        let (digits, unit): (Substring, Double) = switch last {
        case "s": (t.dropLast(), 1)
        case "m": (t.dropLast(), 60)
        case "h": (t.dropLast(), 3600)
        case "d": (t.dropLast(), 86400)
        default: (Substring(t), 3600)
        }
        guard let n = Double(digits), n > 0 else { throw ChallengeError.invalidTTL(text) }
        let seconds = n * unit
        guard (60...(3650 * 86400)).contains(seconds) else { throw ChallengeError.invalidTTL(text) }
        return seconds
    }

    /// Creates a challenge and returns it with its text (shown once; only its hash is stored).
    public func newChallenge(device: String? = nil, template templateName: String = CAService.defaultDeviceTemplate,
                             ttl: TimeInterval = CAService.defaultChallengeTTL,
                             reusable: Bool = false) async throws -> (challenge: PKIChallengeRow, secret: String) {
        let template = try await template(named: templateName)
        guard template.enabled else { throw IssuanceError.templateDisabled(template.name) }
        if template.manualApproval { throw DeviceEnrollmentError.manualApproval(template: template.name) }
        guard (60...(3650 * 86400)).contains(ttl) else { throw ChallengeError.invalidTTL("\(Int(ttl))s") }
        let device = device?.trimmingCharacters(in: .whitespaces)
        let now = clock()
        for _ in 0..<5 {
            let secret = Self.randomChallengeText()
            var id = CMS.randomBytes(4).map { String(format: "%02x", $0) }.joined()
            if try await store.pkiChallenge(id: id) != nil { id = CMS.randomBytes(6).map { String(format: "%02x", $0) }.joined() }
            let row = PKIChallengeRow(id: id, device: (device?.isEmpty ?? true) ? nil : device, template: template.name,
                                      hash: Self.challengeHash(secret), reusable: reusable, createdAt: now,
                                      expiresAt: now.addingTimeInterval(ttl))
            do {
                try await store.insertPKIChallenge(row)
                return (row, secret)
            } catch {
                continue
            }
        }
        throw PKIKitError.encoding("could not store a new challenge")
    }

    public func challenges() async throws -> [PKIChallengeRow] { try await store.pkiChallenges() }

    @discardableResult
    public func revokeChallenge(id: String) async throws -> PKIChallengeRow {
        guard try await store.revokePKIChallenge(id: id), let row = try await store.pkiChallenge(id: id) else {
            throw ChallengeError.unknownID(id)
        }
        return row
    }

    /// Checks a presented challenge and records its use (atomically for one-time challenges).
    /// `deviceNames` are the names the request carries (EST: the user name; SCEP: the CSR's CN
    /// and DNS SANs); a device-bound challenge must match one of them (also by first label).
    /// `template` is the one the request asks for (an EST label), nil = the challenge's.
    public func claimChallenge(_ secret: String?, deviceNames: [String], template: String?,
                               user: String) async throws -> PKIChallengeRow {
        guard let secret, !secret.isEmpty else { throw ChallengeError.missing }
        guard let row = try await store.pkiChallenge(hash: Self.challengeHash(secret)) else { throw ChallengeError.invalid }
        switch row.state(at: clock()) {
        case .revoked: throw ChallengeError.revoked(id: row.id)
        case .used: throw ChallengeError.alreadyUsed(id: row.id, by: row.usedBy)
        case .expired: throw ChallengeError.expired(id: row.id)
        case .active: break
        }
        if let device = row.device {
            let wanted = device.lowercased()
            let ok = deviceNames.contains { name in
                let n = Self.normalizedHost(name)
                return n == wanted || n.split(separator: ".").first.map(String.init) == wanted
                    || wanted.split(separator: ".").first.map(String.init) == n
            }
            guard ok else { throw ChallengeError.wrongDevice(id: row.id, expected: device, got: deviceNames) }
        }
        if let template, template.lowercased() != row.template.lowercased() {
            throw ChallengeError.wrongTemplate(id: row.id, expected: row.template, requested: template)
        }
        guard try await store.claimPKIChallenge(id: row.id, by: user, at: clock()) else {
            throw ChallengeError.alreadyUsed(id: row.id, by: try await store.pkiChallenge(id: row.id)?.usedBy)
        }
        return row
    }

    /// Issues a certificate for a device that presented a challenge (SCEP PKCSReq, EST
    /// simpleenroll). A one-time challenge is given back when the issuance fails.
    public func enrolDevice(csr: CertificateSigningRequest, challenge secret: String?, deviceNames: [String],
                            template requestedTemplate: String?) async throws -> DeviceEnrollmentResult {
        let names = deviceNames.filter { !$0.isEmpty }
        let user = names.first ?? "device"
        let row: PKIChallengeRow
        do {
            row = try await claimChallenge(secret, deviceNames: names, template: requestedTemplate, user: user)
        } catch let e as ChallengeError {
            throw DeviceEnrollmentError.challenge(e)
        }
        let device = row.device ?? user
        do {
            let template = try await template(named: row.template)
            if template.manualApproval { throw DeviceEnrollmentError.manualApproval(template: template.name) }
            try await checkDeviceNames(csr: csr, device: device, boundByAdmin: row.device != nil)
            return try await issueForDevice(csr: csr, template: template, device: device)
        } catch {
            if !row.reusable { try? await store.releasePKIChallenge(id: row.id) }
            throw error
        }
    }

    /// Renews a certificate this CA issued (SCEP RenewalReq signed with it, EST simplereenroll
    /// over TLS client authentication): same template, same requester; the CSR must keep the
    /// subject. Manual-approval and account-bound templates are not renewable this way.
    public func renewDevice(csr: CertificateSigningRequest, existing: Certificate) async throws -> DeviceEnrollmentResult {
        let row = try await validIssued(existing)
        guard csr.subject == existing.subject else {
            throw DeviceEnrollmentError.notRenewable("the renewal CSR's subject \(csr.subject) differs from the certificate's \(existing.subject)")
        }
        let template = try await template(named: row.templateName)
        if template.manualApproval { throw DeviceEnrollmentError.manualApproval(template: template.name) }
        guard template.sanPolicy == .fromRequest || template.sanPolicy == .none else {
            throw DeviceEnrollmentError.notRenewable("template '\(template.name)' certificates are renewed by auto-enrollment, not SCEP/EST")
        }
        // A renewal keeps the names it had: no new DNS names or addresses, no other kinds of name.
        let had = Set(((try? existing.extensions.subjectAlternativeNames).map(Array.init) ?? []).compactMap(Self.deviceNameKey))
        for name in Self.requestedSANs(of: csr) {
            guard let key = Self.deviceNameKey(name), had.contains(key) else {
                throw DeviceEnrollmentError.notRenewable("the renewal asks for \(Self.describe(name)), which the certificate does not have")
            }
        }
        return try await issueForDevice(csr: csr, template: template, device: row.requesterName)
    }

    /// The `pki_issued` row of `certificate` when it is ours, unrevoked, unexpired and verifies.
    public func validIssued(_ certificate: Certificate) async throws -> IssuedCertificate {
        let serial = LabPKI.hex(certificate.serialNumber)
        guard let row = try await store.issuedCertificate(serial: serial),
              row.der == (try? LabPKI.der(certificate)) else {
            throw DeviceEnrollmentError.notRenewable("certificate \(serial) was not issued by this CA")
        }
        guard !row.revoked else { throw DeviceEnrollmentError.notRenewable("certificate \(serial) is revoked") }
        let now = clock()
        guard certificate.notValidAfter > now, certificate.notValidBefore <= now.addingTimeInterval(Self.backdate) else {
            throw DeviceEnrollmentError.notRenewable("certificate \(serial) is not valid now")
        }
        guard let ca = try? await pki.authority(named: row.caName), LabPKI.isIssued(certificate, by: ca.certificate) else {
            throw DeviceEnrollmentError.notRenewable("certificate \(serial) does not verify with CA \(row.caName)")
        }
        return row
    }

    private func issueForDevice(csr: CertificateSigningRequest, template: CertificateTemplate,
                                device: String) async throws -> DeviceEnrollmentResult {
        // The challenge (or the certificate being renewed) is the administrator's authorisation.
        let requester = RequesterIdentity(name: device, isAdmin: true)
        let certificate: Certificate
        do {
            certificate = try await issue(csr: csr, template: template, requester: requester)
        } catch let e as IssuanceError {
            throw DeviceEnrollmentError.refused(e)
        }
        let ca = try await store.issuedCertificate(serial: LabPKI.hex(certificate.serialNumber))?.caName ?? "?"
        return DeviceEnrollmentResult(certificate: certificate, der: try LabPKI.der(certificate),
                                      serial: LabPKI.hex(certificate.serialNumber), device: device,
                                      template: template.name, caName: ca)
    }

    // MARK: - Helpers

    static func challengeHash(_ secret: String) -> String {
        SHA256.hash(data: Array(secret.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// 20 characters of an unambiguous upper-case alphabet (100 bits).
    static func randomChallengeText() -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        return String(CMS.randomBytes(20).map { alphabet[Int($0) % alphabet.count] })
    }

    /// The `challengePassword` attribute of a PKCS#10 (any DirectoryString form).
    public static func challengePassword(of csr: CertificateSigningRequest) -> String? {
        for attribute in csr.attributes where attribute.oid.description == CMSOID.challengePassword {
            for value in attribute.values {
                var serializer = DER.Serializer()
                guard (try? serializer.serialize(value)) != nil,
                      let node = try? ASNReader.parse(serializer.serializedBytes),
                      let text = try? node.string() else { continue }
                return text
            }
        }
        return nil
    }

    /// Audit 27 Sep 2026: a device (SCEP/EST) certificate may only name that device.
    /// - DNS names and subject CNs must be the device or `<device>.<anything>` (same first label);
    /// - IP addresses are allowed;
    /// - UPNs, e-mail addresses, URIs and other names are refused (a challenge must never yield a
    ///   certificate that signs someone in as a user);
    /// - the DC's own names and the domain name are refused;
    /// - with a challenge not bound to a device, a name that is an existing user or group's
    ///   sAMAccountName is refused (bind the challenge to that name if it really is a device).
    func checkDeviceNames(csr: CertificateSigningRequest, device: String, boundByAdmin: Bool) async throws {
        let info = try await store.domainInfo()
        let deviceLabel = Self.firstLabel(Self.normalizedHost(device))
        let forbidden: Set<String> = [Self.normalizedHost(info.dcDNSName), Self.normalizedHost(info.dnsDomain)]
        let forbiddenLabels: Set<String> = [Self.firstLabel(Self.normalizedHost(info.dcDNSName)), info.dcName.lowercased()]
        func check(_ host: String, as what: String) async throws {
            let n = Self.normalizedHost(host)
            let label = Self.firstLabel(n)
            guard !forbidden.contains(n), !forbiddenLabels.contains(label) else {
                throw DeviceEnrollmentError.badRequest("\(what) \(host) is the domain controller's name; a device certificate cannot carry it")
            }
            guard label == deviceLabel else {
                throw DeviceEnrollmentError.badRequest("\(what) \(host) is not the device \(device); a device certificate names only its device")
            }
            // A user, group or computer (`NAME$`) account's name: the certificate could sign in
            // as that account through a name mapping (resolveSignInName tries both).
            let asAccount = (try? await store.read(sam: label)) ?? nil
            let asComputer = (try? await store.read(sam: label + "$")) ?? nil
            if !boundByAdmin, asAccount != nil || asComputer != nil {
                throw DeviceEnrollmentError.badRequest("\(what) \(host) is an existing account's name; create a challenge bound to this device to allow it")
            }
        }
        for name in Self.requestedSANs(of: csr) {
            switch name {
            case .dnsName(let host): try await check(host, as: "DNS name")
            case .ipAddress: break
            default:
                throw DeviceEnrollmentError.badRequest("a device certificate cannot carry \(Self.describe(name))")
            }
        }
        for rdn in csr.subject {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                if let text = ASNReaderString.of(attribute.value) { try await check(text, as: "common name") }
            }
        }
    }

    static func requestedSANs(of csr: CertificateSigningRequest) -> [GeneralName] {
        (try? csr.attributes.extensionRequest?.extensions.subjectAlternativeNames).flatMap { $0 }.map(Array.init) ?? []
    }

    /// `dns:host` / `ip:bytes` for the names a renewal may keep; nil for any other kind.
    static func deviceNameKey(_ name: GeneralName) -> String? {
        switch name {
        case .dnsName(let host): "dns:" + normalizedHost(host)
        case .ipAddress(let octets): "ip:" + octets.bytes.map { String($0) }.joined(separator: ".")
        default: nil
        }
    }

    static func firstLabel(_ host: String) -> String {
        host.split(separator: ".").first.map(String.init) ?? host
    }

    /// The names a CSR gives its device: subject CN(s) then DNS SANs.
    public static func deviceNames(of csr: CertificateSigningRequest) -> [String] {
        var names: [String] = []
        for rdn in csr.subject {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                if let text = ASNReaderString.of(attribute.value) { names.append(text) }
            }
        }
        if let sans = try? csr.attributes.extensionRequest?.extensions.subjectAlternativeNames {
            for case .dnsName(let host) in sans { names.append(host) }
        }
        return names
    }
}

/// Reads an RDN attribute value as text.
enum ASNReaderString {
    static func of(_ value: RelativeDistinguishedName.Attribute.Value) -> String? {
        guard let text = String(value), !text.isEmpty else { return nil }
        return text
    }
}
