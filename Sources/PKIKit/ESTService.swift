import Foundation
import NIOSSL
import os
import SwiftASN1
import X509

/// EST (RFC 7030) over HTTPS: `/.well-known/est/[<template>/]cacerts | simpleenroll |
/// simplereenroll | csrattrs`. The optional label names the certificate template (default: the
/// challenge's, normally `Device`).
///
/// Authentication: HTTP Basic with the device name as user and an enrollment challenge (the
/// same store as SCEP) as password; `simplereenroll` also accepts TLS client authentication with
/// a valid certificate this CA issued (the renewal keeps its template and requester). Bodies
/// are base64 (the RFC) or raw DER / PEM; replies are base64 with
/// `Content-Transfer-Encoding: base64`.
///
/// `cacerts` returns the CA that issues the template in the path (else the default device
/// template). TLS is the DC certificate (EC, from the current CA): an RSA-only device that
/// cannot do ECDHE-ECDSA cannot use EST — it enrols for `Computer-RSA` / `User-RSA` over SCEP,
/// whose RA for those templates is RSA and issued by the RSA compatibility root.
public actor ESTService {
    public let ca: CAService
    private let onEvent: (@Sendable (String) -> Void)?
    private let logger = Logger(subsystem: "dev.labdc.app", category: "est")

    public static let prefix = "/.well-known/est/"
    public static let realm = "LabDC EST"

    public init(ca: CAService, onEvent: (@Sendable (String) -> Void)? = nil) {
        self.ca = ca
        self.onEvent = onEvent
    }

    /// The server configuration for the EST listener: the DC certificate, and client
    /// certificates requested (optional) and validated against every CA of this PKI.
    public static func tlsConfiguration(pki: LabPKI) async throws -> TLSConfiguration {
        var configuration = try await pki.serverTLSConfiguration()
        var roots: [NIOSSLCertificate] = []
        for authority in try await pki.authorities() {
            do { roots.append(try NIOSSLCertificate(bytes: try authority.der(), format: .der)) } catch {
                throw PKIKitError.encoding("NIOSSL certificate: \(error)")
            }
        }
        configuration.trustRoots = .certificates(roots)
        configuration.certificateVerification = .optionalVerification
        return configuration
    }

    public func handle(_ request: PKIHTTPServer.Request) async -> PKIHTTPServer.Response {
        guard request.path.hasPrefix(Self.prefix) else { return .notFound }
        let parts = request.path.dropFirst(Self.prefix.count).split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard (1...2).contains(parts.count) else { return .notFound }
        let operation = parts.last!.lowercased()
        var template: String?
        if parts.count == 2 {
            guard let t = try? await ca.template(named: parts[0]) else {
                emit("EST \(request.path) from \(request.remoteAddress) -> 404 (no template \(parts[0]))")
                return text(404, "no certificate template named \(parts[0])")
            }
            template = t.name
        }
        switch operation {
        case "cacerts":
            guard request.method == "GET" || request.method == "HEAD" else { return text(405, "use GET") }
            do {
                // The CA that issues the template in the path (else the default device template),
                // so a client checks what it enrols for against the right root.
                let t = try await ca.template(named: template ?? CAService.defaultDeviceTemplate)
                let authority = try await ca.issuingAuthority(for: t)
                emit("EST cacerts (\(t.name)) -> CA \(authority.name) from \(request.remoteAddress)")
                return base64(CMS.certsOnly(certificates: [try authority.der()]), type: "application/pkcs7-mime")
            } catch {
                return text(500, "no CA: \(error)")
            }
        case "csrattrs":
            guard request.method == "GET" || request.method == "HEAD" else { return text(405, "use GET") }
            let t = try? await ca.template(named: template ?? CAService.defaultDeviceTemplate)
            // CsrAttrs ::= SEQUENCE OF AttrOrOID: the signature algorithm the template prefers.
            let preferRSA = t?.allowedKeyTypes.contains("rsa") ?? true
            let body = DERWriter.sequence([DERWriter.oid(preferRSA ? CMSOID.sha256WithRSA : CMSOID.ecdsaWithSHA256)])
            return base64(body, type: "application/csrattrs")
        case "simpleenroll", "simplereenroll":
            guard request.method == "POST" else { return text(405, "use POST") }
            return await enroll(request, renew: operation == "simplereenroll", template: template)
        case "serverkeygen", "fullcmc":
            return text(501, "\(operation) is not supported")
        default:
            return .notFound
        }
    }

    private func enroll(_ request: PKIHTTPServer.Request, renew: Bool, template: String?) async -> PKIHTTPServer.Response {
        let op = renew ? "simplereenroll" : "simpleenroll"
        let remote = request.remoteAddress
        guard let der = Self.requestDER(request.body),
              let csr = try? CertificateSigningRequest(derEncoded: der) else {
            emit("EST \(op) from \(remote) -> 400 (not a PKCS#10 request)")
            return text(400, "the body is not a PKCS#10 certificate request (base64, DER or PEM)")
        }
        let basic = Self.basicCredentials(request.header("authorization"))
        let result: DeviceEnrollmentResult
        do {
            if renew, basic == nil, let peer = request.peerCertificateDER {
                guard let existing = try? Certificate(derEncoded: peer) else {
                    return text(401, "unreadable client certificate")
                }
                result = try await ca.renewDevice(csr: csr, existing: existing)
            } else {
                guard let (user, password) = basic else {
                    emit("EST \(op) from \(remote) -> 401 (no credentials)")
                    return challengeResponse("authentication required: HTTP Basic (device name + enrollment challenge)"
                                             + (renew ? " or a TLS client certificate issued by this CA" : ""))
                }
                result = try await ca.enrolDevice(csr: csr, challenge: password, deviceNames: [user], template: template)
            }
        } catch DeviceEnrollmentError.challenge(let e) {
            let who = basic?.user ?? "?"
            emit("EST \(op) device=\(who) -> 401 (\(e)) from \(remote)")
            return challengeResponse("\(e)")
        } catch let e as DeviceEnrollmentError {
            let who = basic?.user ?? CAService.deviceNames(ofSubject: csr.subject).first ?? "?"
            emit("EST \(op) device=\(who) -> 400 (\(e)) from \(remote)")
            return text(400, "\(e)")
        } catch {
            emit("EST \(op) from \(remote) -> 500 (\(error))")
            return text(500, "\(error)")
        }
        emit("EST \(op) device=\(result.device) template=\(result.template) -> OK serial=\(result.serial) from \(remote)")
        // RFC 7030 §4.2.3: a certs-only PKCS#7 holding the issued certificate.
        return base64(CMS.certsOnly(certificates: [result.der]), type: "application/pkcs7-mime; smime-type=certs-only")
    }

    // MARK: - Helpers

    /// base64 (RFC 7030), raw DER, or PEM.
    static func requestDER(_ body: [UInt8]) -> [UInt8]? {
        if body.first == 0x30 { return body }
        let text = String(decoding: body, as: UTF8.self)
        if text.contains("-----BEGIN") {
            let lines = text.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") }
            return Data(base64Encoded: lines.joined()).map { [UInt8]($0) }
        }
        return Data(base64Encoded: text.filter { !$0.isWhitespace }).map { [UInt8]($0) }
    }

    static func basicCredentials(_ header: String?) -> (user: String, password: String)? {
        guard let header else { return nil }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "basic",
              let data = Data(base64Encoded: String(parts[1]).trimmingCharacters(in: .whitespaces)),
              let text = String(data: data, encoding: .utf8), let colon = text.firstIndex(of: ":") else { return nil }
        return (String(text[..<colon]), String(text[text.index(after: colon)...]))
    }

    private func base64(_ der: [UInt8], type: String) -> PKIHTTPServer.Response {
        let text = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n"
        return .init(status: 200, contentType: type, body: Array(text.utf8), headers: ["Content-Transfer-Encoding": "base64"])
    }

    private func text(_ status: Int, _ message: String) -> PKIHTTPServer.Response {
        .init(status: status, contentType: "text/plain", body: Array((message + "\n").utf8))
    }

    private func challengeResponse(_ message: String) -> PKIHTTPServer.Response {
        .init(status: 401, contentType: "text/plain", body: Array((message + "\n").utf8),
              headers: ["WWW-Authenticate": "Basic realm=\"\(Self.realm)\""])
    }

    private func emit(_ line: String) {
        logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }
}
