import CertConvert
import Foundation
import SYSVOL
import X509

/// A certificate an 802.1X profile can trust for another RADIUS server (owner, 1 Oct 2026:
/// ClearPass): one of the Default Domain Policy's trusted roots, or one added with "Add a
/// certificate…" that joins them at the next publish. Like GPMC's Trusted Root import, any
/// certificate goes: a root CA, a self-signed server certificate, or the server's own
/// certificate issued by another CA.
public struct Dot1XTrustCertificate: Equatable, Sendable, Identifiable {
    /// Upper-case hex SHA-1.
    public var thumbprint: String
    /// The friendly name, else the subject CN.
    public var name: String
    public var der: [UInt8]
    public var selfSigned: Bool
    /// A CA certificate (basicConstraints cA): a root that issued the server's certificate, not
    /// the server's own — its names are not server names.
    public var isCA: Bool
    /// ECDSA P-384: allowed for a WPA3-Enterprise 192-bit profile.
    public var p384: Bool
    /// The DNS names in its subjectAltName (IP literals left out when a real name is there),
    /// else its CN: what "Use the certificate's names" fills in.
    public var serverNames: [String]
    /// IP-address SANs and DNS SANs that are IP literals: Windows matches `ServerNames` against
    /// DNS names, so these may not match.
    public var ipNames: [String]
    /// The full subject and issuer (the pick sheet).
    public var subject: String
    public var issuer: String
    /// The issuer's CN, else the full issuer.
    public var issuerName: String
    /// The subject CN: what Windows compares `ServerNames` with (RasTls event 107 shows it as
    /// the server's "Fully Qualified Domain Name"; 2 Oct 2026, ClearPass with an IP in its SAN).
    public var commonName: String?
    /// Not in the trusted roots yet (added with the next publish).
    public var pending = false

    public var id: String { thumbprint }

    public init(der: [UInt8], friendlyName: String? = nil) throws {
        let item = try CertificateItem(der: der)
        self.der = der
        thumbprint = CertificateBlob.thumbprint(der)
        let cn = ServerController.commonName(item.certificate.subject)
        name = friendlyName.flatMap { $0.isEmpty ? nil : $0 } ?? cn ?? item.certificate.subject.description
        selfSigned = item.isSelfIssued
        if case .isCertificateAuthority = (try? item.certificate.extensions.basicConstraints) ?? .notCertificateAuthority {
            isCA = true
        } else {
            isCA = false
        }
        p384 = CertificateSummary(item).publicKey == .ec(.p384)
        serverNames = Self.names(item.certificate, cn: cn)
        ipNames = Self.ipNames(item.certificate, cn: cn)
        subject = item.certificate.subject.description
        issuer = item.certificate.issuer.description
        issuerName = ServerController.commonName(item.certificate.issuer) ?? issuer
        commonName = cn
    }

    static func names(_ certificate: Certificate, cn: String?) -> [String] {
        let dns = ((try? certificate.extensions.subjectAlternativeNames) ?? nil)?.compactMap { name -> String? in
            if case .dnsName(let s) = name { return s }
            return nil
        } ?? []
        // Windows compares ServerNames with the subject CN (2 Oct 2026: RasTls reported
        // "ClearPass-Entry" for a certificate whose only SAN was DNS:192.0.2.39, and the
        // profile worked once ServerNames said ClearPass-Entry). The CN first, then other DNS names.
        let real = dns.filter { !isIPLiteral($0) }
        if let cn, !isIPLiteral(cn) { return [cn] + real.filter { $0.caseInsensitiveCompare(cn) != .orderedSame } }
        if !real.isEmpty { return real }
        return dns.isEmpty ? cn.map { [$0] } ?? [] : dns
    }

    static func ipNames(_ certificate: Certificate, cn: String?) -> [String] {
        let sans = ((try? certificate.extensions.subjectAlternativeNames) ?? nil).map(Array.init) ?? []
        var out: [String] = []
        for name in sans {
            switch name {
            case .ipAddress(let octets): out.append(formatIP(Array(octets.bytes)))
            case .dnsName(let s) where isIPLiteral(s): out.append(s)
            default: break
            }
        }
        if sans.isEmpty, let cn, isIPLiteral(cn) { out.append(cn) }
        return out
    }

    static func formatIP(_ bytes: [UInt8]) -> String {
        if bytes.count == 4 { return bytes.map(String.init).joined(separator: ".") }
        if bytes.count == 16 {
            return stride(from: 0, to: 16, by: 2).map { String(UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]), radix: 16) }
                .joined(separator: ":")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// "10.0.0.5", "fe80::1", "[::1]".
    public static func isIPLiteral(_ text: String) -> Bool {
        let s = text.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        guard !s.isEmpty else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
    }

    /// "root CA", "self-signed server certificate", "server certificate issued by ClearPass CA".
    public var role: String {
        if selfSigned { return isCA ? "root CA" : "self-signed server certificate" }
        return (isCA ? "intermediate CA issued by " : "server certificate issued by ") + issuerName
    }

    /// Which certificates of a file to add (`--pick leaf|root|all`, `--thumbprint`, the pick sheet).
    public enum Pick: Equatable, Sendable {
        /// The certificates that are not CAs (the server's own).
        case leaf
        /// The self-signed ones.
        case root
        case all
        case thumbprints([String])

        public static func parse(_ text: String) throws -> Pick {
            switch text.lowercased() {
            case "leaf", "server": return .leaf
            case "root": return .root
            case "all": return .all
            default: throw CLIError.usage("--pick is leaf, root or all, not \(text)")
            }
        }
    }

    /// Every certificate in a PEM / DER / P7B file, in file order, and the names of the server
    /// certificate in it (the first one that is neither a CA nor self-signed, else the first
    /// that is not a CA, else the first).
    public static func candidates(_ bytes: [UInt8], fileName: String) throws -> (certificates: [Dot1XTrustCertificate], serverNames: [String]) {
        let bundle: CertBundle
        do { bundle = try CertConvert.load(bytes, name: fileName) } catch { throw CLIError.failure("\(fileName): \(error)") }
        guard !bundle.certificates.isEmpty else { throw CLIError.failure("\(fileName) holds no certificate") }
        var certificates: [Dot1XTrustCertificate] = []
        for item in bundle.certificates {
            let c = try Dot1XTrustCertificate(der: item.der, friendlyName: item.friendlyName)
            if !certificates.contains(where: { $0.thumbprint == c.thumbprint }) { certificates.append(c) }
        }
        let server = certificates.first { !$0.isCA && !$0.selfSigned } ?? certificates.first { !$0.isCA } ?? certificates[0]
        return (certificates, server.serverNames)
    }

    /// What the pick sheet ticks first: the self-signed root(s) if there are any, else the
    /// server's own certificate, else the first.
    public static func defaultPick(_ certificates: [Dot1XTrustCertificate]) -> [String] {
        let roots = certificates.filter(\.selfSigned)
        if !roots.isEmpty { return roots.map(\.thumbprint) }
        return (certificates.first { !$0.isCA } ?? certificates.first).map { [$0.thumbprint] } ?? []
    }

    /// The certificates `pick` chooses (nil: the default pick), in file order.
    public static func pick(_ pick: Pick?, from certificates: [Dot1XTrustCertificate], fileName: String) throws -> [Dot1XTrustCertificate] {
        let chosen: [Dot1XTrustCertificate]
        switch pick {
        case nil:
            let t = defaultPick(certificates)
            chosen = certificates.filter { t.contains($0.thumbprint) }
        case .leaf?:
            chosen = certificates.filter { !$0.isCA }
            if chosen.isEmpty { throw CLIError.failure("\(fileName) holds only CA certificates; use --pick root or --pick all") }
        case .root?:
            chosen = certificates.filter(\.selfSigned)
            if chosen.isEmpty { throw CLIError.failure("\(fileName) holds no self-signed (root) certificate; use --pick leaf or --pick all") }
        case .all?:
            chosen = certificates
        case .thumbprints(let list)?:
            var wanted: [String] = []
            for text in list {
                guard let t = TrustedRoot.normalizedThumbprint(text) else {
                    throw CLIError.usage("--thumbprint \(text) is not a 40-digit hex SHA-1 thumbprint")
                }
                guard certificates.contains(where: { $0.thumbprint == t }) else {
                    throw CLIError.failure("\(fileName) holds no certificate \(t); it holds "
                        + certificates.map { "\($0.thumbprint) \($0.name)" }.joined(separator: ", "))
                }
                wanted.append(t)
            }
            chosen = certificates.filter { wanted.contains($0.thumbprint) }
        }
        guard !chosen.isEmpty else { throw CLIError.failure("choose at least one certificate of \(fileName)") }
        return chosen
    }

    /// Of several chosen certificates, the one a profile names first: a self-signed one, else
    /// the first.
    public static func primary(_ chosen: [Dot1XTrustCertificate]) -> Dot1XTrustCertificate? {
        chosen.first(where: \.selfSigned) ?? chosen.first
    }

    /// "Add a certificate…" / `--trusted-root <file>`: the chosen certificate(s) of a PEM / DER /
    /// P7B file — the one the profile names first, the others it trusts as well — and the names
    /// of the server certificate in it.
    public static func load(_ bytes: [UInt8], fileName: String, pick: Pick? = nil) throws
        -> (certificate: Dot1XTrustCertificate, others: [Dot1XTrustCertificate], serverNames: [String]) {
        let file = try candidates(bytes, fileName: fileName)
        let chosen = try self.pick(pick, from: file.certificates, fileName: fileName)
        guard let first = primary(chosen) else { throw CLIError.failure("choose at least one certificate of \(fileName)") }
        return (first, chosen.filter { $0.thumbprint != first.thumbprint }, file.serverNames)
    }

    /// "cppm.lab.sheep — self-signed certificate ClearPass".
    public func describe(serverNames: [String]) -> String {
        "\(serverNames.joined(separator: "; ")) — "
            + (isCA ? "certificate issued by \(name)" : selfSigned ? "self-signed certificate \(name)"
                : "certificate \(name) issued by \(issuerName)")
    }
}
