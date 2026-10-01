import AuthKit
import Foundation
import MSPAC
import NIOConcurrencyHelpers
import os

/// PK-6: HTTP `Negotiate` authentication (RFC 4559) for the CEP / CES, as IIS does it for AD CS's
/// `*_Kerberos` endpoints ("Windows authentication" at the transport layer: MS-WSTEP §3.1.1.1.1;
/// WCF `wsHttpBinding` with `security mode="Transport"`, `clientCredentialType="Windows"`).
///
/// - No `Authorization` on an unauthenticated connection → 401 `WWW-Authenticate: Negotiate`.
/// - `Authorization: Negotiate <base64>`: a SPNEGO NegTokenInit (Kerberos, NTLM fallback) runs
///   through AuthKit's `SPNEGOAcceptor`; a bare Kerberos GSS token (`60 … krb5 OID`) through the
///   `KerberosAcceptor`; a raw NTLMSSP message through the `NTLMServer`. `Authorization: NTLM`
///   is accepted too. Multi-leg exchanges (NTLM) keep their state per TCP connection; an
///   unfinished leg is answered 401 `WWW-Authenticate: Negotiate <token>`.
/// - Success: the identity is remembered for the connection (IIS' default for Kerberos and
///   NTLM), and the final token (Kerberos AP-REP: mutual authentication) goes back in the
///   `WWW-Authenticate` header of the real response.
public final class HTTPNegotiateAuthenticator: Sendable {
    public enum Outcome: Sendable {
        /// Authenticated: `responseHeader` (if any) is the `WWW-Authenticate` value for the reply.
        case authenticated(EnrollmentCaller, responseHeader: String?)
        /// Answer 401 with this `WWW-Authenticate` value (`reason` for the log).
        case challenge(header: String, reason: String?)
    }

    private let makeKerberos: @Sendable () -> KerberosAcceptor
    private let makeNTLM: (@Sendable () -> NTLMServer)?

    private enum Pending: Sendable {
        case spnego(SPNEGOAcceptor)
        case ntlm(NTLMServer, scheme: String)
    }

    private struct Connection: Sendable {
        var caller: EnrollmentCaller?
        var pending: Pending?
        var touched: Date
    }

    private let connections = NIOLockedValueBox<[UInt64: Connection]>([:])
    private let logger = Logger(subsystem: "dev.labdc.app", category: "negotiate")

    /// - Parameters: `makeNTLM` nil turns the NTLM fallback off.
    public init(kerberos: @escaping @Sendable () -> KerberosAcceptor, ntlm: (@Sendable () -> NTLMServer)?) {
        makeKerberos = kerberos
        makeNTLM = ntlm
    }

    /// Convenience over one secret source (serve: `StoreSecretSource`).
    public convenience init(source: any AuthSecretSource, allowNTLM: Bool = true) {
        let replay = ReplayCache()
        let kerberos: @Sendable () -> KerberosAcceptor = { KerberosAcceptor(source: source, replayCache: replay) }
        var ntlm: (@Sendable () -> NTLMServer)?
        if allowNTLM { ntlm = { NTLMServer(source: source, allowAnonymous: false) } }
        self.init(kerberos: kerberos, ntlm: ntlm)
    }

    public func connectionClosed(_ id: UInt64) {
        _ = connections.withLockedValue { $0.removeValue(forKey: id) }
    }

    /// Number of connections with state (tests).
    public var trackedConnections: Int { connections.withLockedValue { $0.count } }

    public func authenticate(_ request: PKIHTTPServer.Request) async -> Outcome {
        let id = request.connectionID
        let now = Date()
        prune(now)
        let state = connections.withLockedValue { $0[id] }
        guard let header = request.header("authorization") else {
            if let caller = state?.caller {
                var c = caller
                c.remoteAddress = request.remoteAddress
                return .authenticated(c, responseHeader: nil)
            }
            return .challenge(header: "Negotiate", reason: nil)
        }
        let parts = header.split(separator: " ", maxSplits: 1)
        let scheme = parts.first.map(String.init) ?? ""
        guard ["negotiate", "ntlm", "kerberos"].contains(scheme.lowercased()), parts.count == 2,
              let token = Data(base64Encoded: String(parts[1]).trimmingCharacters(in: .whitespaces)).map({ [UInt8]($0) }),
              !token.isEmpty else {
            return .challenge(header: "Negotiate", reason: "unsupported Authorization scheme '\(scheme)'")
        }
        let replyScheme = scheme.lowercased() == "ntlm" ? "NTLM" : "Negotiate"
        do {
            // A new exchange starts with an initial token; otherwise continue the pending one.
            let pending = Self.isInitialToken(token) ? nil : state?.pending
            let step: Step
            switch pending {
            case .spnego(var acceptor)?:
                step = try await Self.spnegoStep(&acceptor, token)
                store(id, pending: step.done ? nil : .spnego(acceptor), now: now)
            case .ntlm(let server, _)?:
                let r = try await server.authenticate(token)
                step = Step(done: true, output: nil, identity: r.identity, mechanism: "NTLM")
                store(id, pending: nil, now: now)
            case nil:
                if token.first == 0x60, let (mech, _) = try? GSSFraming.unwrap(token), mech.isKerberos {
                    let r = try await makeKerberos().accept(token)
                    step = Step(done: true, output: r.outputToken, identity: r.identity, mechanism: "Kerberos")
                } else if token.starts(with: Array("NTLMSSP\0".utf8)) {
                    guard let makeNTLM else { throw AuthKitError.unsupported("NTLM is disabled") }
                    var server = makeNTLM()
                    let challenge = try server.challenge(for: token)
                    store(id, pending: .ntlm(server, scheme: replyScheme), now: now)
                    return .challenge(header: "\(replyScheme) " + Data(challenge).base64EncodedString(), reason: nil)
                } else {
                    var acceptor = SPNEGOAcceptor(kerberos: makeKerberos(), ntlm: makeNTLM?())
                    step = try await Self.spnegoStep(&acceptor, token)
                    store(id, pending: step.done ? nil : .spnego(acceptor), now: now)
                }
            }
            let outputHeader = step.output.map { "\(replyScheme) " + Data($0).base64EncodedString() }
            guard step.done, let identity = step.identity else {
                return .challenge(header: outputHeader ?? replyScheme, reason: nil)
            }
            guard !identity.isAnonymous else {
                store(id, pending: nil, now: now)
                return .challenge(header: "Negotiate", reason: "anonymous logons are not accepted")
            }
            let caller = EnrollmentCaller(
                name: identity.downLevelName, sam: identity.sam, sid: identity.sid.description,
                groupSIDs: identity.groups.map(\.description), principal: identity.principal,
                mechanism: step.mechanism, remoteAddress: request.remoteAddress)
            connections.withLockedValue { $0[id] = Connection(caller: caller, pending: nil, touched: now) }
            return .authenticated(caller, responseHeader: outputHeader)
        } catch {
            connections.withLockedValue { $0[id] = nil }
            logger.info("Negotiate from \(request.remoteAddress, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return .challenge(header: "Negotiate", reason: "\(error)")
        }
    }

    private struct Step {
        var done: Bool
        var output: [UInt8]?
        var identity: AuthenticatedIdentity?
        var mechanism: String
    }

    private static func spnegoStep(_ acceptor: inout SPNEGOAcceptor, _ token: [UInt8]) async throws -> Step {
        switch try await acceptor.step(token) {
        case .continue(let out):
            return Step(done: false, output: out, identity: nil, mechanism: "SPNEGO")
        case .complete(let out, let identity, _):
            let mech = acceptor.negotiatedMechanism.map { $0.isKerberos ? "Kerberos" : "NTLM" } ?? "SPNEGO"
            return Step(done: true, output: out, identity: identity, mechanism: mech)
        }
    }

    /// A token that starts an exchange: GSS-framed (SPNEGO NegTokenInit or Kerberos AP-REQ) or
    /// an NTLM NEGOTIATE_MESSAGE.
    static func isInitialToken(_ token: [UInt8]) -> Bool {
        if token.first == 0x60 { return true }
        let ntlm = Array("NTLMSSP\0".utf8)
        return token.count >= 12 && token.starts(with: ntlm) && token[8] == 1
    }

    private func store(_ id: UInt64, pending: Pending?, now: Date) {
        connections.withLockedValue { $0[id] = Connection(caller: nil, pending: pending, touched: now) }
    }

    /// Forgets connections idle for an hour (their close callback is the normal path).
    private func prune(_ now: Date) {
        connections.withLockedValue { c in
            guard c.count > 256 else { return }
            c = c.filter { now.timeIntervalSince($0.value.touched) < 3600 }
        }
    }
}
