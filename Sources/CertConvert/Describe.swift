import Foundation
import SwiftASN1
import X509

/// Human-readable facts about a certificate (the "decode" tool).
public struct CertificateSummary: Equatable, Sendable {
    public var subject: String
    public var issuer: String
    /// Serial number, upper-case hex with colons.
    public var serial: String
    public var notBefore: Date
    public var notAfter: Date
    public var publicKey: KeyAlgorithm
    public var signatureAlgorithm: String
    /// `DNS:host`, `IP:1.2.3.4`, `email:a@b`, `URI:...`, `UPN:user@realm`, `DirName:...`.
    public var subjectAlternativeNames: [String]
    /// Names (`serverAuth`, `clientAuth`, ...) or dotted OIDs.
    public var extendedKeyUsage: [String]
    public var keyUsage: [String]
    /// `CA:TRUE, pathlen:0`, `CA:FALSE`, or nil when the extension is absent.
    public var basicConstraints: String?
    public var subjectKeyIdentifier: String?
    public var authorityKeyIdentifier: String?
    public var sha1Fingerprint: String
    public var sha256Fingerprint: String
    public var isSelfIssued: Bool

    public init(_ item: CertificateItem) {
        let c = item.certificate
        subject = c.subject.description
        issuer = c.issuer.description
        serial = Array(c.serialNumber.bytes).colonHex
        notBefore = c.notValidBefore
        notAfter = c.notValidAfter
        publicKey = (try? KeyAlgorithm.fromSPKI(item.subjectPublicKeyInfo())) ?? .other(oid: "?")
        signatureAlgorithm = c.signatureAlgorithm.description.replacingOccurrences(of: "SignatureAlgorithm.", with: "")
        sha1Fingerprint = item.sha1Fingerprint.colonHex
        sha256Fingerprint = item.sha256Fingerprint.colonHex
        isSelfIssued = item.isSelfIssued

        subjectAlternativeNames = ((try? c.extensions.subjectAlternativeNames) ?? nil).map { names in
            names.map(Self.describe)
        } ?? []

        extendedKeyUsage = []
        if let ext = c.extensions[oid: .X509ExtensionID.extendedKeyUsage],
           let seq = try? ASN.parse(Array(ext.value)) {
            extendedKeyUsage = seq.children.compactMap { try? $0.oid() }.map { Self.ekuNames[$0] ?? $0 }
        }

        keyUsage = []
        if let ku = (try? c.extensions.keyUsage) ?? nil {
            let flags: [(Bool, String)] = [
                (ku.digitalSignature, "digitalSignature"), (ku.nonRepudiation, "nonRepudiation"),
                (ku.keyEncipherment, "keyEncipherment"), (ku.dataEncipherment, "dataEncipherment"),
                (ku.keyAgreement, "keyAgreement"), (ku.keyCertSign, "keyCertSign"), (ku.cRLSign, "cRLSign"),
                (ku.encipherOnly, "encipherOnly"), (ku.decipherOnly, "decipherOnly"),
            ]
            keyUsage = flags.filter(\.0).map(\.1)
        }

        switch (try? c.extensions.basicConstraints) ?? nil {
        case .isCertificateAuthority(let maxPathLength)?:
            basicConstraints = "CA:TRUE" + (maxPathLength.map { ", pathlen:\($0)" } ?? "")
        case .notCertificateAuthority?:
            basicConstraints = "CA:FALSE"
        case nil:
            basicConstraints = nil
        }
        subjectKeyIdentifier = ((try? c.extensions.subjectKeyIdentifier) ?? nil).map { Array($0.keyIdentifier).colonHex }
        authorityKeyIdentifier = ((try? c.extensions.authorityKeyIdentifier) ?? nil)?.keyIdentifier.map { Array($0).colonHex }
    }

    static let ekuNames: [String: String] = [
        "1.3.6.1.5.5.7.3.1": "serverAuth",
        "1.3.6.1.5.5.7.3.2": "clientAuth",
        "1.3.6.1.5.5.7.3.3": "codeSigning",
        "1.3.6.1.5.5.7.3.4": "emailProtection",
        "1.3.6.1.5.5.7.3.8": "timeStamping",
        "1.3.6.1.5.5.7.3.9": "OCSPSigning",
        "1.3.6.1.5.5.7.3.17": "ipsecIKE",
        "1.3.6.1.5.2.3.5": "pkinitKDC",
        "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
        "1.3.6.1.4.1.311.10.3.4": "msEFS",
        "2.5.29.37.0": "anyExtendedKeyUsage",
    ]

    static func describe(_ name: GeneralName) -> String {
        switch name {
        case .dnsName(let s): return "DNS:\(s)"
        case .rfc822Name(let s): return "email:\(s)"
        case .uniformResourceIdentifier(let s): return "URI:\(s)"
        case .directoryName(let dn): return "DirName:\(dn)"
        case .registeredID(let oid): return "RID:\(oid)"
        case .ipAddress(let octets):
            let b = Array(octets.bytes)
            if b.count == 4 { return "IP:" + b.map(String.init).joined(separator: ".") }
            if b.count == 16 {
                var addr = in6_addr()
                withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b) }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil {
                    return "IP:" + String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                }
            }
            return "IP:\(b.hex)"
        case .otherName(let other):
            if other.typeID.description == "1.3.6.1.4.1.311.20.2.3", let v = other.value,
               let s = try? ASN1UTF8String(asn1Any: v) {
                return "UPN:\(String(s))"
            }
            return "othername:\(other.typeID)"
        default:
            return "\(name)"
        }
    }

    /// Multi-line text (the CLI `inspect` output).
    public func lines(now: Date = Date()) -> [String] {
        let f = ISO8601DateFormatter()
        var l = [
            "subject          \(subject)",
            "issuer           \(issuer)\(isSelfIssued ? " (self-issued)" : "")",
            "serial           \(serial)",
            "valid            \(f.string(from: notBefore)) to \(f.string(from: notAfter))\(validityNote(now))",
            "public key       \(publicKey)",
            "signature        \(signatureAlgorithm)",
        ]
        if !subjectAlternativeNames.isEmpty { l.append("SANs             \(subjectAlternativeNames.joined(separator: ", "))") }
        if !keyUsage.isEmpty { l.append("key usage        \(keyUsage.joined(separator: ", "))") }
        if !extendedKeyUsage.isEmpty { l.append("extended usage   \(extendedKeyUsage.joined(separator: ", "))") }
        if let basicConstraints { l.append("basic constr.    \(basicConstraints)") }
        if let subjectKeyIdentifier { l.append("subject key id   \(subjectKeyIdentifier)") }
        if let authorityKeyIdentifier { l.append("authority key id \(authorityKeyIdentifier)") }
        l.append("SHA-1            \(sha1Fingerprint)")
        l.append("SHA-256          \(sha256Fingerprint)")
        return l
    }

    private func validityNote(_ now: Date) -> String {
        if now < notBefore { return " (NOT YET VALID)" }
        if now > notAfter { return " (EXPIRED)" }
        let days = Int(notAfter.timeIntervalSince(now) / 86400)
        return " (\(days) day\(days == 1 ? "" : "s") left)"
    }
}

/// Facts about a PKCS#10 request.
public struct RequestSummary: Equatable, Sendable {
    public var subject: String
    public var publicKey: KeyAlgorithm
    public var signatureAlgorithm: String
    public var signatureValid: Bool
    public var requestedSubjectAlternativeNames: [String]

    public init(_ item: CSRItem) {
        let r = item.request
        subject = r.subject.description
        publicKey = (try? KeyAlgorithm.fromSPKI(item.subjectPublicKeyInfo())) ?? .other(oid: "?")
        signatureAlgorithm = r.signatureAlgorithm.description.replacingOccurrences(of: "SignatureAlgorithm.", with: "")
        signatureValid = r.publicKey.isValidSignature(r.signature, for: r)
        var sans: [String] = []
        if let ext = try? r.attributes.extensionRequest, let names = try? ext.extensions.subjectAlternativeNames {
            sans = names.map(CertificateSummary.describe)
        }
        requestedSubjectAlternativeNames = sans
    }

    public func lines() -> [String] {
        var l = [
            "subject          \(subject)",
            "public key       \(publicKey)",
            "signature        \(signatureAlgorithm) (\(signatureValid ? "valid" : "INVALID"))",
        ]
        if !requestedSubjectAlternativeNames.isEmpty {
            l.append("requested SANs   \(requestedSubjectAlternativeNames.joined(separator: ", "))")
        }
        return l
    }
}

extension CertConvert {
    /// The `inspect` report for a whole bundle: sources, keys (and which certificate each
    /// matches), certificates in chain order, requests.
    public static func report(_ bundle: CertBundle, now: Date = Date()) -> [String] {
        var out: [String] = []
        for s in bundle.sources {
            out.append("\(s.name): \(s.format.rawValue)")
            for p in s.protection { out.append("  protection  \(p)") }
            for n in s.notes { out.append("  note        \(n)") }
        }
        let certs = bundle.orderedCertificates
        let k = bundle.keys.count, c = certs.count, r = bundle.requests.count
        var found: [String] = []
        if k > 0 { found.append("\(k) private key\(k == 1 ? "" : "s")") }
        if c > 0 { found.append("\(c) certificate\(c == 1 ? "" : "s")") }
        if r > 0 { found.append("\(r) certificate request\(r == 1 ? "" : "s")") }
        var summary = "found: " + (found.isEmpty ? "nothing" : found.joined(separator: ", "))
        if c > 0 {
            let chainLength = bundle.leaf.map { bundle.chain(for: $0).count } ?? 0
            summary += bundle.chainIsComplete
                ? " (chain of \(chainLength) ends at a self-signed root)"
                : " (chain of \(chainLength) does not reach a root in this input)"
        }
        out.append(summary)
        for (i, key) in bundle.keys.enumerated() {
            var line = "key \(i + 1)            \(key.algorithm)"
            if let n = key.friendlyName { line += ", name \(n)" }
            if let idx = certs.firstIndex(where: { key.matches($0) }) {
                line += ", matches certificate \(idx + 1)"
            } else if c > 0 {
                line += ", matches NO certificate here"
            }
            if let p = key.protection { line += " [was \(p)]" }
            out.append(line)
        }
        for (i, cert) in certs.enumerated() {
            let role = i == 0 && bundle.primaryKey.map({ $0.matches(cert) }) == true ? "leaf"
                : cert.isSelfIssued ? "root" : cert.isCA ? "CA" : i == 0 ? "leaf" : "other"
            out.append("certificate \(i + 1) (\(role))\(cert.friendlyName.map { ", name \($0)" } ?? "")")
            out += CertificateSummary(cert).lines(now: now).map { "  " + $0 }
        }
        for (i, req) in bundle.requests.enumerated() {
            out.append("request \(i + 1)")
            out += RequestSummary(req).lines().map { "  " + $0 }
        }
        return out
    }
}
