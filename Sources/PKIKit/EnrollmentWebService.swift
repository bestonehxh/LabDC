import Foundation
import NIOSSL
import os

/// PK-6: the HTTPS host of the enrollment web services (tcp 443 in `serve`, the DC certificate):
///
/// - `POST /ADPolicyProvider_CEP_Kerberos/service.svc/CEP` → `XCEPService` (MS-XCEP GetPolicies)
/// - `POST /<CA>_CES_Kerberos/service.svc/CES` → `WSTEPService` (MS-WSTEP RequestSecurityToken)
///
/// Both require HTTP Negotiate (`HTTPNegotiateAuthenticator`). Paths are matched without regard
/// to case (IIS). A GET on either path answers a one-line text page without authentication
/// (Windows never fetches the WSDL); other paths 404.
public final class EnrollmentWebService: Sendable {
    public let xcep: XCEPService
    public let wstep: WSTEPService
    public let authenticator: HTTPNegotiateAuthenticator
    private let onEvent: (@Sendable (String) -> Void)?
    private let logger = Logger(subsystem: "dev.labdc.app", category: "enrollment-web")

    public init(xcep: XCEPService, wstep: WSTEPService, authenticator: HTTPNegotiateAuthenticator,
                onEvent: (@Sendable (String) -> Void)? = nil) {
        self.xcep = xcep
        self.wstep = wstep
        self.authenticator = authenticator
        self.onEvent = onEvent
    }

    enum Route: Equatable {
        case cep
        case ces(caName: String)
    }

    static func route(_ path: String) -> Route? {
        if path.caseInsensitiveCompare(XCEPService.path) == .orderedSame { return .cep }
        if let name = WSTEPService.caName(forPath: path) { return .ces(caName: name) }
        return nil
    }

    /// The server configuration: the DC certificate; no client certificates (Kerberos only).
    public static func tlsConfiguration(pki: LabPKI) async throws -> TLSConfiguration {
        try await pki.serverTLSConfiguration()
    }

    /// The HTTPS listener (not started) for this service, with the DC certificate.
    public func makeServer(port: Int, pki: LabPKI, bindAddresses: [String] = ["0.0.0.0", "::"],
                           onRequest: (@Sendable (String) -> Void)? = nil) async throws -> PKIHTTPServer {
        let tls = try await Self.tlsConfiguration(pki: pki)
        let onClosed: @Sendable (UInt64) -> Void = { [authenticator] id in authenticator.connectionClosed(id) }
        let handler: PKIHTTPServer.RequestHandler = { [self] request in await self.handle(request) }
        return PKIHTTPServer(port: port, bindAddresses: bindAddresses, tls: tls, onRequest: onRequest,
                             onConnectionClosed: onClosed, requestHandler: handler)
    }

    public func handle(_ request: PKIHTTPServer.Request) async -> PKIHTTPServer.Response {
        guard let route = Self.route(request.path) else { return .notFound }
        switch request.method {
        case "GET", "HEAD":
            let what = route == .cep ? "LabDC certificate enrollment policy service (MS-XCEP, Kerberos)"
                : "LabDC certificate enrollment service (MS-WSTEP, Kerberos)"
            return .init(status: 200, contentType: "text/plain; charset=utf-8", body: Array((what + "\n").utf8))
        case "POST":
            break
        default:
            return .init(status: 405, contentType: "text/plain", body: Array("use POST\n".utf8), headers: ["Allow": "POST"])
        }

        let caller: EnrollmentCaller
        var authHeader: String?
        switch await authenticator.authenticate(request) {
        case .challenge(let header, let reason):
            let service = route == .cep ? "XCEP" : "WSTEP"
            if let reason { emit("\(service) from \(request.remoteAddress) -> 401 (\(reason))") }
            return .init(status: 401, contentType: "text/plain", body: Array("authentication required (Negotiate)\n".utf8),
                         headers: ["WWW-Authenticate": header])
        case .authenticated(let c, let header):
            caller = c
            authHeader = header
        }

        let result: (status: Int, body: [UInt8])
        switch route {
        case .cep: result = await xcep.handle(request.body, caller: caller)
        case .ces(let caName): result = await wstep.handle(request.body, caName: caName, caller: caller)
        }
        var headers: [String: String] = [:]
        if let authHeader { headers["WWW-Authenticate"] = authHeader }
        return .init(status: result.status, contentType: SOAP.contentType, body: result.body, headers: headers)
    }

    public func connectionClosed(_ id: UInt64) { authenticator.connectionClosed(id) }

    private func emit(_ line: String) {
        logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }
}
