import CryptoKit
import Foundation
import RADIUSKit
import SwiftASN1
import X509

/// What the RADIUS side must decide for the EAP server: the directory checks.
public protocol EAPBackend: Sendable {
    /// EAP-TLS: map the client certificate to an account and check it (chain to the lab CA,
    /// validity, revocation, account state). `identity` is the EAP-Response/Identity. Called on
    /// a resumed session too, with the chain the session was established with.
    func verifyCertificate(chain: [[UInt8]], identity: String) async -> EAPAuthResult
    /// TTLS-PAP / EAP-GTC: the LDAP simple-bind check.
    func verifyPassword(user: String, password: String) async -> EAPAuthResult
    /// PEAP / TTLS MS-CHAPv2 against the stored NT hash, with the account checks.
    func verifyMSCHAPv2(user: String, challenge: [UInt8], response: MSCHAPv2.Response) async -> EAPAuthResult
    /// MS-CHAPv2 Change-Password after E=648 (RFC 2759 §7): verify against the old hash, set the
    /// new password through the domain policy, answer like `verifyMSCHAPv2` with the new one.
    func changePassword(user: String, challenge: [UInt8], change: MSCHAPv2.ChangePassword) async -> EAPAuthResult
    /// Fast reconnect: may `account`, authenticated at `authenticatedAt`, still sign in without
    /// a password (not disabled/locked/expired, password not changed or expired since)?
    func revalidate(account: String, authenticatedAt: Date) async -> EAPAuthResult
}

extension EAPBackend {
    public func changePassword(user: String, challenge: [UInt8], change: MSCHAPv2.ChangePassword) async -> EAPAuthResult {
        .failure("password change is not available")
    }
    public func revalidate(account: String, authenticatedAt: Date) async -> EAPAuthResult {
        .success(account: account, mschap: nil)
    }
}

public enum EAPAuthResult: Sendable, Equatable {
    case success(account: String, mschap: MSCHAPv2.Success?)
    /// Wrong password, unknown account, bad certificate… (MS-CHAPv2 E=691).
    case failure(String)
    /// The account may not sign in: disabled (E=647), outside its logon hours (E=646)…
    case denied(String, MSCHAPv2.ErrorCode)
    /// The password was right but has expired / must be changed (E=648): MS-CHAPv2 peers may
    /// change it in the same exchange.
    case passwordExpired(account: String, reason: String)
}

/// The server certificate (leaf first, then the issuing CA) and its PKCS#8 key, plus the P-384
/// credential WPA3-Enterprise 192-bit clients get.
public struct EAPCredentials: Sendable, Equatable {
    public var chain: [[UInt8]]
    public var keyDER: [UInt8]
    public var suiteB: TLSContext.Credential?
    /// The RSA compatibility chain for RSA-only devices ("Allow RSA-only devices"); nil: off.
    public var rsa: TLSContext.Credential?
    public init(chain: [[UInt8]], keyDER: [UInt8], suiteB: TLSContext.Credential? = nil, rsa: TLSContext.Credential? = nil) {
        self.chain = chain; self.keyDER = keyDER; self.suiteB = suiteB; self.rsa = rsa
    }
}

/// Facts about a finished EAP exchange for the policy engine and the Activity line.
public struct EAPFacts: Sendable, Equatable {
    /// `EAP-TLS`, `PEAP`, `EAP-TTLS`.
    public var method: String
    /// `EAP-MSCHAPv2` / `EAP-GTC` (PEAP, TTLS inner EAP), `PAP` / `MSCHAPv2` (TTLS); nil for EAP-TLS.
    public var innerMethod: String?
    /// The EAP-Response/Identity (outer, may be `anonymous`).
    public var outerIdentity: String
    public var tlsVersion: String?
    public var certificateSubject: String?
    public var certificateIssuer: String?
    /// Fast reconnect: the TLS session was resumed (phase 2 skipped for PEAP/TTLS).
    public var resumed = false
    /// PEAP: the peer answered the Crypto-Binding TLV (the MSK is the compound session key).
    public var cryptoBinding = false
    /// The 192-bit credential and policy were used (WPA3-Enterprise 192-bit).
    public var suiteB = false
    /// The RSA compatibility chain was used (an RSA-only device).
    public var rsaCompatibility = false
    /// MS-CHAPv2 changed an expired password in this exchange.
    public var passwordChanged = false

    public init(method: String, innerMethod: String? = nil, outerIdentity: String, tlsVersion: String? = nil,
                certificateSubject: String? = nil, certificateIssuer: String? = nil) {
        self.method = method; self.innerMethod = innerMethod; self.outerIdentity = outerIdentity
        self.tlsVersion = tlsVersion; self.certificateSubject = certificateSubject; self.certificateIssuer = certificateIssuer
    }
}

public enum EAPResult: Sendable {
    /// Access-Challenge with this EAP-Message and State.
    case challenge(eap: [UInt8], state: [UInt8])
    /// Access-Accept: EAP-Success + the MSK (MS-MPPE-Recv-Key = first 32, Send-Key = next 32).
    case accept(eap: [UInt8], msk: [UInt8], account: String, facts: EAPFacts)
    /// Access-Reject with EAP-Failure.
    case reject(eap: [UInt8], reason: String, account: String?, facts: EAPFacts?)
    /// No reply (malformed, unknown session, wrong identifier).
    case drop(String)
}

public struct EAPSettings: Sendable {
    /// Methods offered, in order; a NAK picks another from this list.
    public var methods: [EAPType] = [.tls, .peap, .ttls]
    /// Inner EAP methods (PEAP, TTLS/EAP), in order; a NAK picks another.
    public var innerMethods: [EAPType] = [.mschapv2, .gtc]
    /// TLS data per EAP fragment (lowered by Framed-MTU).
    public var fragmentSize = 1000
    /// An exchange idle longer than this is forgotten.
    public var sessionTimeout: TimeInterval = 60
    public var maxSessions = 4096
    /// TLS 1.3 for every method: EAP-TLS (RFC 9190), PEAP and TTLS (RFC 9427). TLS 1.2 stays
    /// available for older peers.
    public var allowTLS13 = true
    /// Fast reconnect (TLS session resumption) and how long a full authentication stays
    /// resumable (typical PMK cache lifetime).
    public var resumption = true
    public var resumptionLifetime: TimeInterval = 8 * 3600
    /// The name in the MS-CHAPv2 challenge.
    public var serverName = "LabDC"
    /// PEAP: reject a client that does not return a valid Crypto-Binding TLV ([MS-PEAP]
    /// §3.1.5.5). Without it the outer TLS tunnel is not bound to the inner MS-CHAPv2, so a rogue
    /// AP can relay the inner exchange. Off by default (some old supplicants never send it);
    /// on is recommended. Changed at run time with `EAPServer.setRequirePEAPCryptoBinding`.
    public var requirePEAPCryptoBinding = false

    public init() {}
}

/// Phase 4b/4c: the EAP server behind RADIUS (RFC 3579): EAP-Identity, NAK negotiation,
/// EAP-TLS (RFC 5216 / RFC 9190), PEAPv0 ([MS-PEAP]: inner EAP-MSCHAPv2 or EAP-GTC, the
/// Crypto-Binding TLV, fast reconnect), TTLSv0 (RFC 5281: inner PAP, MS-CHAPv2, EAP-MSCHAPv2,
/// EAP-GTC) — over TLS 1.2 or TLS 1.3 (RFC 9427 key derivation). One session per exchange, keyed
/// by the RADIUS State attribute, with an idle timeout and a cap. The TLS records are framed and
/// fragmented here; BoringSSL does TLS.
public actor EAPServer {
    let backend: EAPBackend
    let credentials: @Sendable () async -> EAPCredentials?
    public let settings: EAPSettings
    /// Fast reconnect state (nil when resumption is off).
    public nonisolated let resumption: EAPResumptionCache?
    private var sessions: [[UInt8]: EAPSession] = [:]
    private var contexts: (credentials: EAPCredentials, tls: TLSContext, peap: TLSContext, ttls: TLSContext)?

    public init(backend: EAPBackend, settings: EAPSettings = EAPSettings(), credentials: @escaping @Sendable () async -> EAPCredentials?) {
        self.backend = backend
        self.settings = settings
        self.credentials = credentials
        self.requirePEAPCryptoBinding = settings.requirePEAPCryptoBinding
        resumption = settings.resumption ? EAPResumptionCache(lifetime: settings.resumptionLifetime) : nil
    }

    /// "Require PEAP crypto binding" now (the RADIUS server follows its setting).
    public private(set) var requirePEAPCryptoBinding: Bool

    public func setRequirePEAPCryptoBinding(_ on: Bool) { requirePEAPCryptoBinding = on }

    public var sessionCount: Int { sessions.count }

    /// One EAP-Message (reassembled from the RADIUS attributes) with its State (if any).
    public func handle(eap bytes: [UInt8], state: [UInt8]?, framedMTU: Int? = nil, now: Date = Date()) async -> EAPResult {
        prune(now: now)
        // RFC 3579 §2.1 EAP-Start: an empty EAP-Message asks the server to begin.
        if bytes.isEmpty {
            let session = newSession(identity: "", now: now, mtu: framedMTU)
            return session.remember(session.request(type: .identity, data: []))
        }
        guard let packet = EAPPacket(bytes), packet.code == .response, let type = packet.type else {
            return .drop("malformed EAP-Message")
        }
        let session: EAPSession
        if let state, let known = sessions[state] {
            session = known
            guard packet.id == session.lastID else {
                // A retransmitted response (the peer or the NAS resent it with a new RADIUS
                // packet): the challenge it answered went missing — send it again.
                if bytes == session.lastResponse, let again = session.lastReply {
                    session.touched = now
                    return again
                }
                return .drop("EAP identifier \(packet.id) does not answer request \(session.lastID)")
            }
        } else if type == EAPType.identity.rawValue {
            session = newSession(identity: String(decoding: packet.data, as: UTF8.self), now: now, mtu: framedMTU)
            session.lastID = packet.id
        } else {
            return .drop(state == nil ? "EAP \(EAPType(rawValue: type)?.title ?? "type \(type)") without a session" : "unknown or expired EAP session")
        }
        guard !session.busy else { return .drop("EAP exchange busy (retransmission)") }
        session.busy = true
        session.touched = now
        let result = await process(session, packet)
        session.busy = false
        switch result {
        case .accept, .reject: sessions[session.state] = nil
        case .drop: break
        case .challenge:
            session.lastResponse = bytes
            session.lastReply = result
        }
        return result
    }

    private func newSession(identity: String, now: Date, mtu: Int?) -> EAPSession {
        if sessions.count >= settings.maxSessions, let oldest = sessions.min(by: { $0.value.touched < $1.value.touched })?.key {
            sessions[oldest] = nil
        }
        var fragment = settings.fragmentSize
        if let mtu, mtu > 0 { fragment = min(fragment, max(200, mtu - 60)) }
        let s = EAPSession(identity: identity, fragmentSize: fragment, now: now)
        sessions[s.state] = s
        return s
    }

    private func prune(now: Date) {
        sessions = sessions.filter { now.timeIntervalSince($0.value.touched) < settings.sessionTimeout }
    }

    private func tlsContext(for method: EAPType) async -> TLSContext? {
        guard let creds = await credentials() else { return nil }
        if contexts == nil || contexts?.credentials != creds {
            let max: UInt16 = settings.allowTLS13 ? 0x0304 : 0x0303
            guard let tls = try? TLSContext(isServer: true, chain: creds.chain, privateKeyDER: creds.keyDER, requireClientCertificate: true,
                                            maxVersion: max, suiteB: creds.suiteB, resumption: resumption, sessionContext: "EAP-TLS",
                                            deferClientVerification: true, rsa: creds.rsa),
                  let peap = try? TLSContext(isServer: true, chain: creds.chain, privateKeyDER: creds.keyDER, maxVersion: max,
                                             resumption: resumption, sessionContext: "PEAP", rsa: creds.rsa),
                  let ttls = try? TLSContext(isServer: true, chain: creds.chain, privateKeyDER: creds.keyDER, maxVersion: max,
                                             resumption: resumption, sessionContext: "EAP-TTLS", rsa: creds.rsa) else {
                return nil
            }
            contexts = (creds, tls, peap, ttls)
        }
        switch method {
        case .tls: return contexts?.tls
        case .peap: return contexts?.peap
        default: return contexts?.ttls
        }
    }

    // MARK: The state machine

    private func process(_ s: EAPSession, _ packet: EAPPacket) async -> EAPResult {
        let type = packet.type ?? 0
        switch s.stage {
        case .identity:
            guard type == EAPType.identity.rawValue else { return s.fail("expected EAP-Response/Identity") }
            s.identity = String(decoding: packet.data, as: UTF8.self)
            return await offer(s, settings.methods.first ?? .peap)
        case .offered(let method):
            if type == EAPType.nak.rawValue {
                s.tried.insert(method)
                // The client's preferred types, in its order, that we serve and have not tried.
                guard let next = packet.data.compactMap(EAPType.init(rawValue:))
                        .first(where: { settings.methods.contains($0) && !s.tried.contains($0) }) else {
                    return s.fail("the client wants \(packet.data.map { EAPType(rawValue: $0)?.title ?? "type \($0)" }.joined(separator: ", ")), none of which is offered")
                }
                return await offer(s, next)
            }
            guard type == method.rawValue else { return s.fail("answered \(method.title) with type \(type)") }
            s.stage = .handshake
            return await tlsMessage(s, packet.data)
        case .handshake, .awaitAck, .tunnel:
            guard type == s.method?.rawValue else { return s.fail("unexpected EAP type \(type) inside \(s.method?.title ?? "?")") }
            return await tlsMessage(s, packet.data)
        }
    }

    private func offer(_ s: EAPSession, _ method: EAPType) async -> EAPResult {
        guard let context = await tlsContext(for: method) else { return s.fail("no server certificate for EAP") }
        guard let engine = try? TLSEngine(context: context, isServer: true, eapType: method.rawValue) else {
            return s.fail("TLS setup failed")
        }
        s.method = method
        s.engine = engine
        s.stage = .offered(method)
        s.inbound = []
        s.pending = []
        return s.request(type: method, data: [TLSMethodMessage.start | s.version])
    }

    private func tlsMessage(_ s: EAPSession, _ typeData: [UInt8]) async -> EAPResult {
        guard let message = TLSMethodMessage(typeData), let engine = s.engine, let method = s.method else {
            return s.fail("malformed \(s.method?.title ?? "EAP") message")
        }
        // An empty response while fragments wait = "send the next one".
        if !s.pending.isEmpty {
            guard message.data.isEmpty else { return s.fail("data while server fragments were pending") }
            return s.nextFragment()
        }
        if let total = message.totalLength, total > 65536 { return s.fail("TLS message of \(total) bytes refused") }
        s.inbound += message.data
        guard s.inbound.count <= 65536 else { return s.fail("TLS message too long") }
        if message.more { return s.ack() }
        let records = s.inbound
        s.inbound = []

        switch s.stage {
        case .handshake:
            engine.feed(records)
            guard engine.advance() else { return s.fail(engine.failure ?? "TLS handshake failed") }
            if engine.certificatePending {
                // EAP-TLS: the client certificate is checked inside the handshake, so a refusal
                // is a TLS alert in an EAP-TLS request before the EAP-Failure (RFC 5216 §2.1.3,
                // RFC 9190 §2.1.1 / §2.5), for TLS 1.2 and 1.3 alike.
                let chain = engine.peerCertificates
                let result = await backend.verifyCertificate(chain: chain, identity: s.identity)
                s.certificateResult = result
                let alert = Self.certificateAlert(result, leaf: chain.first)
                engine.resolveCertificate(alert: alert)
                if !engine.advance() || alert != nil {
                    let reason: String
                    if case .failure(let why) = result { reason = why }
                    else if case .denied(let why, _) = result { reason = why }
                    else if case .passwordExpired(_, let why) = result { reason = why }
                    else { reason = engine.failure ?? "TLS handshake failed" }
                    return refuse(s, method, engine, reason: reason, facts: certificateFacts(s, engine, chain))
                }
            }
            guard engine.established else {
                let out = engine.drain()
                return out.isEmpty ? s.fail("TLS handshake stalled") : s.send(out)
            }
            return await established(s, method, engine)
        case .awaitAck(let next):
            // A TLS alert went out: whatever the peer answers, the exchange ends in EAP-Failure.
            if case .reject = next { return await complete(s, method, engine, next) }
            // The peer acknowledged the last flight (TLS 1.3 may carry a post-handshake record).
            if !records.isEmpty { engine.feed(records); _ = engine.read() }
            if let failure = engine.failure { return s.fail(failure) }
            return await complete(s, method, engine, next)
        case .tunnel(let phase):
            engine.feed(records)
            let app = engine.read()
            if let failure = engine.failure { return s.fail(failure) }
            return await finish(s, method, engine, await tunnel(s, method, engine, phase, app))
        default:
            return s.fail("TLS data in the wrong stage")
        }
    }

    /// The handshake just completed (full or resumed).
    private func established(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine) async -> EAPResult {
        engine.flush()   // TLS 1.3: the ticket goes with this flight (RFC 9190 §2.1.2 order)
        var out = engine.drain()
        switch method {
        case .tls:
            let next = await tlsVerdict(s, engine)
            if case .reject(let reason, _, let facts) = next {
                // A resumed session refused now (revoked since, account disabled…): the alert
                // goes out encrypted under the new keys, then EAP-Failure.
                engine.sendAlert(s.alert ?? TLSEngine.Alert.badCertificate)
                return refuse(s, method, engine, reason: reason, facts: facts, prefix: out)
            }
            // RFC 9190 §2.1.1 / §2.5: one encrypted 0x00 commits to no further handshake messages.
            if engine.isTLS13 { engine.write([0]); out += engine.drain() }
            if out.isEmpty { return await complete(s, method, engine, next) }
            s.stage = .awaitAck(next)
            return s.send(out)
        case .peap:
            // Like hostapd: the last handshake flight (or TLS 1.3 tickets) goes alone; phase 2
            // starts when the peer acknowledges it.
            if !out.isEmpty {
                s.stage = .awaitAck(.peapStart)
                return s.send(out)
            }
            return await complete(s, method, engine, .peapStart)
        case .ttls:
            if engine.resumed, let next = await resumeTTLS(s, engine) {
                if case .reject = next { return await complete(s, method, engine, next) }
                // RFC 9427 §2.1.2: a resumed TLS 1.3 TTLS session ends with the protected
                // success indication (0x00) instead of phase 2.
                if engine.isTLS13 { engine.write([0]); out += engine.drain() }
                if out.isEmpty { return await complete(s, method, engine, next) }
                s.stage = .awaitAck(next)
                return s.send(out)
            }
            s.stage = .tunnel(.ttlsCredentials)
            let app = engine.read()   // TLS 1.3: the AVPs may come with the client's Finished
            if app.isEmpty { return out.isEmpty ? s.ack() : s.send(out) }
            return await finish(s, method, engine, await tunnel(s, method, engine, .ttlsCredentials, app), prefix: out)
        default:
            return s.fail("\(method.title) is not served")
        }
    }

    /// Where an acknowledged flight leads.
    private func complete(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, _ next: Next) async -> EAPResult {
        switch next {
        case .accept(let account, let facts, let msk):
            return accepted(s, method, engine, account: account, facts: facts, msk: msk)
        case .reject(let reason, let account, let facts):
            resumption?.invalidate(engine.sessionHandle)
            return s.fail(reason, account: account, facts: facts)
        case .peapStart:
            return await finish(s, method, engine, await startPEAP(s, engine))
        }
    }

    private func accepted(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, account: String, facts: EAPFacts, msk: [UInt8]?) -> EAPResult {
        let key = msk ?? Self.msk(method, engine)
        if key.count == 64 {
            resumption?.authenticated(engine.sessionHandle, method: method.rawValue, account: account, inner: facts.innerMethod)
        }
        return s.succeed(account: account, msk: key, facts: facts)
    }

    /// A tunnel step's result on the wire. `prefix`: records still to send (TLS 1.3 tickets).
    private func finish(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, _ step: TunnelStep, prefix: [UInt8] = []) async -> EAPResult {
        switch step {
        case .reply:
            if let failure = engine.failure { return s.fail(failure) }
            let out = prefix + engine.drain()
            return out.isEmpty ? s.ack() : s.send(out)
        case .accept(let account, let facts, let msk):
            let pending = prefix + engine.drain()   // TLS 1.3 tickets BoringSSL wrote on the way
            if !pending.isEmpty {   // deliver them first; accept on the acknowledgement
                s.stage = .awaitAck(.accept(account: account, facts: facts, msk: msk))
                return s.send(pending)
            }
            return accepted(s, method, engine, account: account, facts: facts, msk: msk)
        case .reject(let reason, let account, let facts):
            resumption?.invalidate(engine.sessionHandle)
            return s.fail(reason, account: account, facts: facts)
        }
    }

    // MARK: EAP-TLS

    private func tlsVerdict(_ s: EAPSession, _ engine: TLSEngine) async -> Next {
        let chain = engine.peerCertificates
        let facts = certificateFacts(s, engine, chain)
        let result: EAPAuthResult
        if engine.resumed {
            // A resumed session proves the certificate it was established with: that chain is
            // verified again now (chain, validity, revocation, account), never trusted from the
            // cache — also when the cache has no account for it (the full exchange's last
            // reply was lost), which is then mapped here like a full handshake.
            guard engine.resumedHandle != nil, !chain.isEmpty else {
                s.alert = TLSEngine.Alert.badCertificate
                return .reject(reason: "resumed EAP-TLS session without a client certificate", account: nil, facts: facts)
            }
            result = await backend.verifyCertificate(chain: chain, identity: s.identity)
        } else if let checked = s.certificateResult {
            result = checked   // verified during the handshake
        } else {
            result = await backend.verifyCertificate(chain: chain, identity: s.identity)
        }
        s.alert = Self.certificateAlert(result, leaf: chain.first)
        switch result {
        case .success(let account, _):
            return .accept(account: account, facts: facts, msk: nil)
        case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
            return .reject(reason: why, account: nil, facts: facts)
        }
    }

    private func certificateFacts(_ s: EAPSession, _ engine: TLSEngine, _ chain: [[UInt8]]) -> EAPFacts {
        var facts = baseFacts(s, .tls, engine)
        if let leaf = chain.first, let cert = try? Certificate(derEncoded: leaf) {
            facts.certificateSubject = cert.subject.description
            facts.certificateIssuer = cert.issuer.description
        }
        return facts
    }

    /// Sends the TLS alert the engine holds (with `prefix` records) in an EAP-TLS request; the
    /// peer's answer gets the EAP-Failure. Without records to send, EAP-Failure at once.
    private func refuse(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, reason: String, facts: EAPFacts?,
                        prefix: [UInt8] = []) -> EAPResult {
        resumption?.invalidate(engine.sessionHandle)
        let out = prefix + engine.drain()
        guard !out.isEmpty else { return s.fail(reason, facts: facts) }
        s.stage = .awaitAck(.reject(reason: reason, account: nil, facts: facts))
        return s.send(out)
    }

    /// The TLS alert for a refused client certificate: nil when it is accepted.
    static func certificateAlert(_ result: EAPAuthResult, leaf: [UInt8]?, now: Date = Date()) -> UInt8? {
        switch result {
        case .success: return nil
        case .denied, .passwordExpired: return TLSEngine.Alert.accessDenied
        case .failure(let why):
            let text = why.lowercased()
            if text.contains("revoked") { return TLSEngine.Alert.certificateRevoked }
            if let leaf, let cert = try? Certificate(derEncoded: leaf), now < cert.notValidBefore || now > cert.notValidAfter {
                return TLSEngine.Alert.certificateExpired
            }
            if text.contains("not issued by") || text.contains("lab ca") || text.contains("chain") {
                return TLSEngine.Alert.unknownCA
            }
            return TLSEngine.Alert.badCertificate
        }
    }

    private func baseFacts(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, inner: String? = nil) -> EAPFacts {
        var f = EAPFacts(method: method.title, innerMethod: inner, outerIdentity: s.identity, tlsVersion: engine.versionName)
        f.resumed = engine.resumed
        f.suiteB = engine.suiteB
        f.rsaCompatibility = engine.rsaCompatibility
        return f
    }

    /// Fast reconnect for PEAP/TTLS: the cached, phase-2-authenticated account, revalidated.
    /// nil = no usable record (run phase 2).
    private func resumed(_ s: EAPSession, _ engine: TLSEngine) async -> (account: String, inner: String?, result: EAPAuthResult)? {
        guard let handle = engine.resumedHandle, let entry = resumption?.entry(handle), let account = entry.account,
              let at = entry.authenticatedAt else { return nil }
        return (account, entry.innerMethod, await backend.revalidate(account: account, authenticatedAt: at))
    }

    // MARK: TTLS

    private func resumeTTLS(_ s: EAPSession, _ engine: TLSEngine) async -> Next? {
        guard let (account, inner, result) = await resumed(s, engine) else { return nil }
        let facts = baseFacts(s, .ttls, engine, inner: inner)
        switch result {
        case .success: return .accept(account: account, facts: facts, msk: nil)
        case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
            return .reject(reason: "fast reconnect refused: \(why)", account: account, facts: facts)
        }
    }

    // MARK: PEAP

    /// Phase 2 begins: the inner Identity request — or, for a resumed session with an
    /// authenticated record, straight to the Result TLV ([MS-PEAP] fast reconnect).
    private func startPEAP(_ s: EAPSession, _ engine: TLSEngine) async -> TunnelStep {
        let inner = InnerEAP(firstID: s.lastID, serverName: settings.serverName, methods: settings.innerMethods)
        if engine.resumed, let (account, method, result) = await resumed(s, engine) {
            let facts = baseFacts(s, .peap, engine, inner: method)
            let tk = Array((Self.keyMaterial(.peap, engine) ?? []).prefix(60))
            switch result {
            case .success:
                let binding = tk.count == 60 ? PEAPCrypto.binding(tk: tk, isk: nil) : nil
                return sendResult(s, engine, inner: inner, PEAPPending(success: true, reason: "", account: account, facts: facts, binding: binding))
            case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
                return sendResult(s, engine, inner: inner,
                                  PEAPPending(success: false, reason: "fast reconnect refused: \(why)", account: account, facts: facts, binding: nil))
            }
        }
        s.stage = .tunnel(.peapInner(inner))
        engine.write(Self.peapCompress(inner.start()))
        return .reply
    }

    private func sendResult(_ s: EAPSession, _ engine: TLSEngine, inner: InnerEAP, _ pending: PEAPPending) -> TunnelStep {
        var p = pending
        var tlvs = PEAPCrypto.resultTLV(success: p.success)
        if p.success, let binding = p.binding {
            var nonce = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &nonce)
            p.nonce = nonce
            tlvs += PEAPCrypto.cryptoBindingTLV(nonce: nonce, cmk: binding.cmk, subType: 0)
        }
        s.stage = .tunnel(.peapResult(p))
        engine.write(EAPPacket(code: .request, id: inner.nextID(), type: EAPType.tlv.rawValue, data: tlvs).bytes)
        return .reply
    }

    // MARK: Phase 2

    private func tunnel(_ s: EAPSession, _ method: EAPType, _ engine: TLSEngine, _ phase: TunnelPhase, _ app: [UInt8]) async -> TunnelStep {
        switch phase {
        case .peapInner(let inner):
            guard let (type, data) = Self.peapInner(app) else {
                return app.isEmpty ? .reply : .reject(reason: "PEAP: malformed inner packet", account: nil, facts: baseFacts(s, .peap, engine))
            }
            switch await inner.handle(type: type, data: data, backend: backend) {
            case .send(let packet):
                engine.write(Self.peapCompress(packet))
                return .reply
            case .success(let account, let isk, let name, let changed):
                var facts = baseFacts(s, .peap, engine, inner: name)
                facts.passwordChanged = changed
                if changed { resumption?.invalidate(account: account) }
                let tk = Array((Self.keyMaterial(.peap, engine) ?? []).prefix(60))
                let binding = tk.count == 60 ? PEAPCrypto.binding(tk: tk, isk: isk ?? []) : nil
                return sendResult(s, engine, inner: inner, PEAPPending(success: true, reason: "", account: account, facts: facts, binding: binding))
            case .failure(let reason, let account, let name):
                return sendResult(s, engine, inner: inner,
                                  PEAPPending(success: false, reason: reason, account: account, facts: baseFacts(s, .peap, engine, inner: name), binding: nil))
            }
        case .peapResult(let p):
            // The client's EAP-TLV answer: Result (must be success too) and, when it supports it,
            // its Crypto-Binding TLV (SubType 1) over the same CMK.
            guard let (type, data) = Self.peapInner(app), type == EAPType.tlv.rawValue else {
                return .reject(reason: p.success ? "PEAP: the client did not confirm the result" : p.reason, account: p.account, facts: p.facts)
            }
            let tlvs = PEAPCrypto.parseTLVs(data)
            guard p.success else { return .reject(reason: p.reason, account: p.account, facts: p.facts) }
            guard tlvs.result == 1, let account = p.account else {
                return .reject(reason: "PEAP: the client did not confirm the result", account: p.account, facts: p.facts)
            }
            var facts = p.facts
            var msk: [UInt8]?
            if let cb = tlvs.cryptoBinding {
                guard let binding = p.binding, PEAPCrypto.verifyCryptoBinding(cb, cmk: binding.cmk) else {
                    return .reject(reason: "PEAP: crypto binding does not verify (tunnel not bound to the inner method)",
                                   account: account, facts: facts)
                }
                facts.cryptoBinding = true
                msk = Array(PEAPCrypto.compoundSessionKey(ipmk: binding.ipmk).prefix(64))
            } else if requirePEAPCryptoBinding {
                return .reject(reason: "PEAP: the client returned no Crypto-Binding TLV (Require PEAP crypto binding is on)",
                               account: account, facts: facts)
            }
            return .accept(account: account, facts: facts, msk: msk)

        case .ttlsCredentials:
            guard let avps = TTLSAVP.parse(app), !avps.isEmpty else {
                if app.isEmpty { return .reply }
                return .reject(reason: "TTLS: malformed AVPs", account: nil, facts: baseFacts(s, .ttls, engine))
            }
            let user = avps.first { $0.code == 1 && $0.vendor == nil }.map { String(decoding: $0.data, as: UTF8.self) } ?? s.identity
            let facts = { (inner: String) in self.baseFacts(s, .ttls, engine, inner: inner) }
            if let eap = avps.first(where: { $0.code == 79 && $0.vendor == nil }) {
                // Inner EAP (RFC 5281 §11.1): the peer starts with its EAP-Response/Identity.
                let inner = InnerEAP(firstID: 0, serverName: settings.serverName, methods: settings.innerMethods)
                s.stage = .tunnel(.ttlsInner(inner))
                return await ttlsInner(s, engine, inner, eap.data)
            }
            if let password = avps.first(where: { $0.code == 2 && $0.vendor == nil }) {
                var pw = password.data
                while pw.last == 0 { pw.removeLast() }
                switch await backend.verifyPassword(user: user, password: String(decoding: pw, as: UTF8.self)) {
                case .success(let account, _): return .accept(account: account, facts: facts("PAP"), msk: nil)
                case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
                    return .reject(reason: why, account: user, facts: facts("PAP"))
                }
            }
            if let challenge = avps.first(where: { $0.vendor == VendorSpecific.microsoft && $0.code == 11 })?.data,
               let raw = avps.first(where: { $0.vendor == VendorSpecific.microsoft && $0.code == 25 })?.data {
                // RFC 5281 §11.2.4 (and RFC 9427 for TLS 1.3): the challenge and ident come from
                // the TLS exporter, not the client.
                guard let expected = engine.export(label: "ttls challenge", length: 17),
                      challenge == Array(expected.prefix(16)), let response = MSCHAPv2.Response(raw), response.ident == expected[16] else {
                    return .reject(reason: "TTLS: MS-CHAPv2 challenge not bound to the tunnel", account: user, facts: facts("MSCHAPv2"))
                }
                switch await backend.verifyMSCHAPv2(user: user, challenge: challenge, response: response) {
                case .success(let account, let mschap):
                    s.stage = .tunnel(.ttlsMSCHAPv2Sent(account: account))
                    engine.write(TTLSAVP(code: 26, vendor: VendorSpecific.microsoft, data: mschap?.successValue ?? [response.ident]).bytes)
                    return .reply
                case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
                    return .reject(reason: why, account: user, facts: facts("MSCHAPv2"))
                }
            }
            return .reject(reason: "TTLS: no credentials in the tunnel", account: user, facts: facts("none"))
        case .ttlsInner(let inner):
            guard let avps = TTLSAVP.parse(app), let eap = avps.first(where: { $0.code == 79 && $0.vendor == nil }) else {
                if app.isEmpty { return .reply }
                return .reject(reason: "TTLS: expected an EAP-Message AVP", account: inner.user, facts: baseFacts(s, .ttls, engine, inner: "EAP"))
            }
            return await ttlsInner(s, engine, inner, eap.data)
        case .ttlsMSCHAPv2Sent(let account):
            return .accept(account: account, facts: baseFacts(s, .ttls, engine, inner: "MSCHAPv2"), msk: nil)
        }
    }

    private func ttlsInner(_ s: EAPSession, _ engine: TLSEngine, _ inner: InnerEAP, _ bytes: [UInt8]) async -> TunnelStep {
        guard let packet = EAPPacket(bytes), packet.code == .response, let type = packet.type else {
            return .reject(reason: "TTLS: malformed inner EAP packet", account: inner.user, facts: baseFacts(s, .ttls, engine, inner: "EAP"))
        }
        switch await inner.handle(type: type, data: packet.data, backend: backend) {
        case .send(let request):
            engine.write(TTLSAVP(code: 79, data: request).bytes)
            return .reply
        case .success(let account, _, let name, let changed):
            var facts = baseFacts(s, .ttls, engine, inner: name)
            facts.passwordChanged = changed
            if changed { resumption?.invalidate(account: account) }
            return .accept(account: account, facts: facts, msk: nil)
        case .failure(let reason, let account, let name):
            return .reject(reason: reason, account: account, facts: baseFacts(s, .ttls, engine, inner: name))
        }
    }

    // MARK: Helpers

    /// PEAPv0 inner packets travel without the EAP header ("compressed"), except EAP-TLV which
    /// has it: returns (type, data) either way.
    static func peapInner(_ app: [UInt8]) -> (UInt8, [UInt8])? {
        if app.count >= 5, app[0] == EAPPacket.Code.response.rawValue || app[0] == EAPPacket.Code.request.rawValue,
           Int(app[2]) << 8 | Int(app[3]) == app.count {
            return (app[4], Array(app[5...]))
        }
        guard let type = app.first else { return nil }
        return (type, Array(app.dropFirst()))
    }

    /// PEAPv0 sends inner EAP requests without their 4-byte header, EAP-TLV with it.
    static func peapCompress(_ packet: [UInt8]) -> [UInt8] {
        packet.count > 4 && packet[4] != EAPType.tlv.rawValue ? Array(packet.dropFirst(4)) : packet
    }

    /// Fills MS-Length (bytes 2–3: the EAP-MSCHAPv2 data from OpCode on).
    static func withMSLength(_ body: [UInt8]) -> [UInt8] { InnerEAP.withMSLength(body) }

    /// EAP-TLV Result (type 33, mandatory TLV 3, value 1 = success, 2 = failure) as a full EAP-Request.
    static func resultTLV(id: UInt8, success: Bool) -> [UInt8] {
        EAPPacket(code: .request, id: id, type: EAPType.tlv.rawValue, data: PEAPCrypto.resultTLV(success: success)).bytes
    }

    static func tlvResult(_ data: [UInt8]) -> UInt16? { PEAPCrypto.parseTLVs(data).result }

    /// The 128-byte key material: TLS 1.3 per RFC 9190 §2.3 / RFC 9427 §2.1
    /// (`EXPORTER_EAP_TLS_Key_Material`, context = the EAP type); TLS 1.2 per RFC 5216
    /// (`client EAP encryption`, EAP-TLS and PEAPv0) and RFC 5281 §8 (`ttls keying material`).
    static func keyMaterial(_ method: EAPType, _ engine: TLSEngine) -> [UInt8]? {
        if engine.isTLS13 {
            return engine.export(label: "EXPORTER_EAP_TLS_Key_Material", context: [method.rawValue], length: 128)
        }
        return engine.export(label: method == .ttls ? "ttls keying material" : "client EAP encryption", length: 128)
    }

    /// The MSK (first 64 bytes of the key material; the EMSK is the rest).
    static func msk(_ method: EAPType, _ engine: TLSEngine) -> [UInt8] {
        Array((keyMaterial(method, engine) ?? []).prefix(64))
    }
}

/// Where the exchange goes after the peer acknowledges the last flight.
enum Next {
    case accept(account: String, facts: EAPFacts, msk: [UInt8]?)
    case reject(reason: String, account: String?, facts: EAPFacts?)
    case peapStart
}

/// What one tunnel step did.
enum TunnelStep {
    /// Plaintext (or nothing) was written into the engine: send its records (or an ack).
    case reply
    case accept(account: String, facts: EAPFacts, msk: [UInt8]?)
    case reject(reason: String, account: String?, facts: EAPFacts?)
}

struct PEAPPending {
    var success: Bool
    var reason: String
    var account: String?
    var facts: EAPFacts
    var binding: (ipmk: [UInt8], cmk: [UInt8])?
    var nonce: [UInt8] = []
}

enum TunnelPhase {
    case peapInner(InnerEAP)
    case peapResult(PEAPPending)
    case ttlsCredentials
    case ttlsInner(InnerEAP)
    case ttlsMSCHAPv2Sent(account: String)
}

/// [MS-PEAP] §3.1.5.5–3.1.5.7 (hostapd `eap_server_peap.c`): the Result and Crypto-Binding
/// TLVs, the intermediate compound key (IPMK/CMK from TK and the inner method's ISK) and the
/// compound session key that replaces the MSK when the peer binds.
enum PEAPCrypto {
    static func resultTLV(success: Bool) -> [UInt8] { [0x80, 0x03, 0x00, 0x02, 0x00, success ? 1 : 2] }

    /// PRF+ of PEAPv0: T1 = HMAC-SHA1(K, S | 0x01 | 0x00 | 0x00), Tn = HMAC-SHA1(K, Tn-1 | S | n | 0x00 | 0x00).
    static func prfPlus(key: [UInt8], label: String, seed: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = []
        var last: [UInt8] = []
        var counter: UInt8 = 0
        let s = Array(label.utf8) + seed
        while out.count < length {
            counter &+= 1
            var mac = HMAC<Insecure.SHA1>(key: SymmetricKey(data: key))
            mac.update(data: last + s + [counter, 0, 0])
            last = Array(mac.finalize())
            out += last
        }
        return Array(out.prefix(length))
    }

    /// IPMK (40) and CMK (20): from TK alone on fast reconnect, else
    /// PRF+(TK[0..40], "Inner Methods Compound Keys", ISK (32, zero-padded), 60).
    static func binding(tk: [UInt8], isk: [UInt8]?) -> (ipmk: [UInt8], cmk: [UInt8]) {
        guard let isk else { return (Array(tk[0..<40]), Array(tk[40..<60])) }
        let padded = Array((isk + [UInt8](repeating: 0, count: 32)).prefix(32))
        let imck = prfPlus(key: Array(tk[0..<40]), label: "Inner Methods Compound Keys", seed: padded, length: 60)
        return (Array(imck[0..<40]), Array(imck[40..<60]))
    }

    /// The Crypto-Binding TLV (type 12, 56 bytes): reserved, version 0, received version 0,
    /// SubType (0 request, 1 response), Nonce 32, Compound_MAC = HMAC-SHA1(CMK, TLV with a
    /// zero MAC | EAP type 25).
    static func cryptoBindingTLV(nonce: [UInt8], cmk: [UInt8], subType: UInt8) -> [UInt8] {
        var tlv: [UInt8] = [0x00, 0x0C, 0x00, 0x38, 0, 0, 0, subType] + nonce + [UInt8](repeating: 0, count: 20)
        tlv.replaceSubrange(40..<60, with: compoundMAC(tlv, cmk: cmk))
        return tlv
    }

    static func compoundMAC(_ tlv: [UInt8], cmk: [UInt8]) -> [UInt8] {
        var zeroed = Array(tlv.prefix(60))
        zeroed.replaceSubrange(40..<60, with: [UInt8](repeating: 0, count: 20))
        var mac = HMAC<Insecure.SHA1>(key: SymmetricKey(data: cmk))
        mac.update(data: zeroed + [EAPType.peap.rawValue])
        return Array(mac.finalize())
    }

    /// A peer's Crypto-Binding TLV (header included): SubType 1, version 0, MAC over our CMK.
    static func verifyCryptoBinding(_ tlv: [UInt8], cmk: [UInt8]) -> Bool {
        guard tlv.count == 60, tlv[5] == 0, tlv[7] == 1 else { return false }
        let expected = compoundMAC(tlv, cmk: cmk)
        return zip(expected, tlv[40..<60]).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// CSK = PRF+(IPMK, "Session Key Generating Function", 0x00, 128); MSK = CSK[0..64].
    static func compoundSessionKey(ipmk: [UInt8]) -> [UInt8] {
        prfPlus(key: ipmk, label: "Session Key Generating Function", seed: [0], length: 128)
    }

    /// Result status and the Crypto-Binding TLV (with its 4-byte header) of an EAP-TLV payload.
    static func parseTLVs(_ data: [UInt8]) -> (result: UInt16?, cryptoBinding: [UInt8]?) {
        var result: UInt16?
        var binding: [UInt8]?
        var i = 0
        while i + 4 <= data.count {
            let type = UInt16(data[i] & 0x3F) << 8 | UInt16(data[i + 1])
            let length = Int(data[i + 2]) << 8 | Int(data[i + 3])
            guard i + 4 + length <= data.count else { break }
            if type == 3, length == 2 { result = UInt16(data[i + 4]) << 8 | UInt16(data[i + 5]) }
            if type == 12 { binding = Array(data[i..<(i + 4 + length)]) }
            i += 4 + length
        }
        return (result, binding)
    }
}

/// One EAP exchange (all its Access-Requests share the State).
final class EAPSession {
    enum Stage {
        case identity, offered(EAPType), handshake, awaitAck(Next), tunnel(TunnelPhase)
    }

    let state: [UInt8]
    var identity: String
    var stage: Stage
    var method: EAPType?
    var tried: Set<EAPType> = []
    var engine: TLSEngine?
    var inbound: [UInt8] = []
    var pending: [TLSMethodMessage] = []
    var lastID: UInt8 = 0
    var touched: Date
    var busy = false
    let fragmentSize: Int
    /// The last response handled and the challenge it got (a retransmission gets it again).
    var lastResponse: [UInt8]?
    var lastReply: EAPResult?
    /// EAP-TLS: the client certificate's verdict from inside the handshake, and the alert a
    /// refusal sends.
    var certificateResult: EAPAuthResult?
    var alert: UInt8?

    init(identity: String, fragmentSize: Int, now: Date) {
        var s = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &s)
        state = s
        self.identity = identity
        self.fragmentSize = fragmentSize
        touched = now
        stage = .identity
    }

    /// PEAPv0 / TTLSv0: version bits 0.
    var version: UInt8 { 0 }

    func remember(_ r: EAPResult) -> EAPResult { lastReply = r; return r }

    func request(type: EAPType, data: [UInt8]) -> EAPResult {
        lastID &+= 1
        return .challenge(eap: EAPPacket(code: .request, id: lastID, type: type.rawValue, data: data).bytes, state: state)
    }

    /// An empty method request: "got your fragment, go on".
    func ack() -> EAPResult { request(type: method ?? .tls, data: [version]) }

    func send(_ records: [UInt8]) -> EAPResult {
        pending = TLSMethodMessage.fragments(records, size: fragmentSize, version: version)
        return nextFragment()
    }

    func nextFragment() -> EAPResult {
        guard !pending.isEmpty else { return ack() }
        let next = pending.removeFirst()
        return request(type: method ?? .tls, data: next.bytes)
    }

    func succeed(account: String, msk: [UInt8], facts: EAPFacts) -> EAPResult {
        guard msk.count == 64 else { return fail("no keying material from the TLS session", account: account, facts: facts) }
        return .accept(eap: EAPPacket.success(id: lastID).bytes, msk: msk, account: account, facts: facts)
    }

    func fail(_ reason: String, account: String? = nil, facts: EAPFacts? = nil) -> EAPResult {
        .reject(eap: EAPPacket.failure(id: lastID).bytes, reason: reason, account: account ?? (identity.isEmpty ? nil : identity),
                facts: facts ?? method.map { EAPFacts(method: $0.title, outerIdentity: identity, tlsVersion: engine?.established == true ? engine?.versionName : nil) })
    }
}
