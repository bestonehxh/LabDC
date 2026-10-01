import EAPKit
import Foundation
import MSPAC
import Network
import Synchronization
import RADIUSKit
import Store
import SwiftASN1
@_spi(FixedExpiryValidationTime) import X509
import os

/// One UDP listener (auth or accounting). Network.framework hands out one `NWConnection` per
/// remote endpoint; each is tracked, cancelled on error, after `idleTimeout` without a datagram,
/// and when more than `maxConnections` are open (the oldest goes). Packets are handled off the
/// MainActor; replies go back on the same flow. Mirrors `DNSServer`'s structure.
final class RadiusListener: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "dev.labdc.app.radius")
    /// (datagram, source address, source port) → reply bytes or nil (drop).
    let handle: @Sendable ([UInt8], String, UInt16) async -> [UInt8]?
    static let idleTimeout: TimeInterval = 60
    static let maxConnections = 1024
    private let connections = Mutex<[ObjectIdentifier: (conn: NWConnection, last: Date)]>([:])
    private var sweeper: DispatchSourceTimer?

    init(port: UInt16, handle: @escaping @Sendable ([UInt8], String, UInt16) async -> [UInt8]?) throws {
        self.handle = handle
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = false
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw CLIError.failure("bad RADIUS port \(port)") }
        listener = try NWListener(using: params, on: nwPort)
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        let failure = Mutex<Error?>(nil)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let e), .waiting(let e): failure.withLock { $0 = e }; ready.signal()
            default: break
            }
        }
        listener.start(queue: queue)
        if ready.wait(timeout: .now() + 5) == .timedOut { failure.withLock { $0 = $0 ?? CLIError.failure("udp \(port): not ready") } }
        if let startError = failure.withLock({ $0 }) {
            listener.cancel()
            throw startError
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 15, repeating: 15)
        timer.setEventHandler { [weak self] in self?.sweep() }
        timer.resume()
        sweeper = timer
    }

    var port: UInt16? { listener.port?.rawValue }

    private func accept(_ conn: NWConnection) {
        let id = ObjectIdentifier(conn)
        let evicted: NWConnection? = connections.withLock { all in
            all[id] = (conn, Date())
            guard all.count > Self.maxConnections, let oldest = all.min(by: { $0.value.last < $1.value.last }) else { return nil }
            all[oldest.key] = nil
            return oldest.value.conn
        }
        evicted?.cancel()
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed: conn.cancel()
            case .cancelled: self?.connections.withLock { $0[id] = nil }
            default: break
            }
        }
        conn.start(queue: queue)
        let (source, port) = Self.describe(conn.endpoint)
        receive(conn, source: source, port: port)
    }

    private func receive(_ conn: NWConnection, source: String, port: UInt16) {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let id = ObjectIdentifier(conn)
                self.connections.withLock { if $0[id] != nil { $0[id]?.last = Date() } }
                let bytes = [UInt8](data)
                let handle = self.handle
                Task {
                    if let reply = await handle(bytes, source, port) {
                        conn.send(content: Data(reply), completion: .contentProcessed { _ in })
                    }
                }
            }
            if error == nil { self.receive(conn, source: source, port: port) } else { conn.cancel() }
        }
    }

    private func sweep() {
        let now = Date()
        let idle = connections.withLock { all in
            all.values.filter { now.timeIntervalSince($0.last) > Self.idleTimeout }.map(\.conn)
        }
        for conn in idle { conn.cancel() }
    }

    /// The source address (IPv4, or IPv6 without its `%scope`; IPv4-mapped folded) and port.
    static func describe(_ endpoint: NWEndpoint) -> (String, UInt16) {
        guard case let .hostPort(host, port) = endpoint else { return ("\(endpoint)", 0) }
        let text: String
        switch host {
        case .ipv4(let a): text = RADIUSAddress.format([UInt8](a.rawValue))
        case .ipv6(let a): text = RADIUSAddress.normalize(RADIUSAddress.format([UInt8](a.rawValue))) ?? "\(a)"
        case .name(let n, _): text = RADIUSAddress.normalize(n) ?? n
        @unknown default: text = RADIUSAddress.normalize("\(host)") ?? "\(host)"
        }
        return (text, port.rawValue)
    }

    func cancel() {
        sweeper?.cancel()
        sweeper = nil
        listener.cancel()
        let open = connections.withLock { all in
            defer { all = [:] }
            return all.values.map(\.conn)
        }
        for conn in open { conn.cancel() }
    }
}

/// Phase 4a: the RADIUS server (docs/specs/phase4-radius.md). UDP 1812 auth + 1813 accounting;
/// requests must come from a configured NAS; Access-Requests must carry a valid
/// Message-Authenticator, Accounting-Requests a valid RFC 2866 Request Authenticator. Users are
/// the directory's own accounts (PAP = the LDAP simple-bind check, MS-CHAPv2 = RFC 2759); the
/// policy engine picks the rule and the attributes that go back. Phase 4b/4c: EAP-Message
/// requests go to the `EAPServer` (EAP-TLS, PEAP-MSCHAPv2, TTLS), whose MSK becomes the
/// MS-MPPE keys (WPA2/WPA3-Enterprise).
///
/// Not actor-isolated: packet handling runs on the listener's tasks, the config (NAS list,
/// policies, default action) is cached behind a lock and reloaded after `configChanged()` or
/// at most 30 s later (a CLI edit from another process).
public final class RadiusServer: @unchecked Sendable {
    private let store: DirectoryStore
    private let log: @Sendable (String) -> Void
    private let clock: @Sendable () -> Date
    private var authListener: RadiusListener?
    private var acctListener: RadiusListener?
    public private(set) var authPort: UInt16 = 0
    public private(set) var acctPort: UInt16 = 0

    /// Config snapshot, duplicate cache, rate limiters.
    private struct State {
        var config: RadiusConfig?
        /// The last config that loaded completely (kept when a reload fails).
        var lastGood: RadiusConfig?
        var loadedAt = Date.distantPast
        /// RFC 5080 §2.2.2: a NAS retries for up to ~30 s; the same reply goes back that long.
        var duplicates = RADIUSDuplicateCache(lifetime: 30, capacity: 8192)
        var limiter = RADIUSLogLimiter(interval: 60)
        /// Interim-Update floods: one summary line per NAS every 15 minutes.
        var interim = RADIUSLogLimiter(interval: 900)
        var configProblem: String?
    }
    private let state = Mutex(State())
    /// Wrong RADIUS passwords (PAP and MS-CHAPv2) lock an account for a while, as Netlogon does.
    let badPasswords = BadPasswordTracker()
    static let lockoutThreshold = 20
    static let lockoutWindow: TimeInterval = 900
    static let lockoutDuration: TimeInterval = 900
    static let configTTL: TimeInterval = 30

    /// Phase 4b: the EAP server (nil without a server certificate — EAP requests are then refused).
    private(set) var eap: EAPServer?
    /// The lab CAs (DER) a client certificate must chain to.
    private let trustRoots: @Sendable () async -> [[UInt8]]

    public init(store: DirectoryStore, clock: @escaping @Sendable () -> Date = { Date() },
                eapCredentials: (@Sendable () async -> EAPCredentials?)? = nil,
                trustRoots: @escaping @Sendable () async -> [[UInt8]] = { [] },
                log: @escaping @Sendable (String) -> Void) {
        self.store = store
        self.clock = clock
        self.log = log
        self.trustRoots = trustRoots
        if let eapCredentials {
            let backend = RadiusEAPBackend()
            eap = EAPServer(backend: backend, credentials: eapCredentials)
            backend.server = self
        }
    }

    /// Binds both ports (0 = an ephemeral one, for tests).
    public func start(authPort: UInt16, acctPort: UInt16) throws {
        let auth = try RadiusListener(port: authPort) { [weak self] data, source, port in
            await self?.handle(data, source: source, port: port, accounting: false)
        }
        do {
            let acct = try RadiusListener(port: acctPort) { [weak self] data, source, port in
                await self?.handle(data, source: source, port: port, accounting: true)
            }
            acctListener = acct
            self.acctPort = acct.port ?? acctPort
        } catch {
            auth.cancel()
            throw error
        }
        authListener = auth
        self.authPort = auth.port ?? authPort
        log("udp \(self.authPort) (auth) + udp \(self.acctPort) (accounting): listening")
    }

    public func stop() {
        authListener?.cancel(); acctListener?.cancel()
        authListener = nil; acctListener = nil
        authPort = 0; acctPort = 0
    }

    /// A NAS or policy was edited: the next packet reloads the config.
    public func configChanged() {
        state.withLock { $0.config = nil }
    }

    private func config() async -> RadiusConfig {
        let now = clock()
        if let cached = state.withLock({ s -> RadiusConfig? in
            guard let c = s.config, now.timeIntervalSince(s.loadedAt) < Self.configTTL else { return nil }
            return c
        }) { return cached }
        let loaded = await RadiusConfig.loadReporting(store)
        // A failed read keeps the last good config (a locked or damaged table must not turn the
        // server into "reject everything"); the problem is logged once until it changes.
        let (config, line): (RadiusConfig, String?) = state.withLock { st in
            var line: String?
            let problem = loaded.problems.isEmpty ? nil : loaded.problems.joined(separator: "; ")
            if problem != st.configProblem {
                if let problem {
                    line = "RADIUS config: \(problem)" + (!loaded.complete && st.lastGood != nil ? " — keeping the last good config" : "")
                } else {
                    line = "RADIUS config reads cleanly again"
                }
                st.configProblem = problem
            }
            if loaded.complete || st.lastGood == nil {
                st.lastGood = loaded.config
                st.config = loaded.config
            } else {
                st.config = st.lastGood
            }
            st.loadedAt = now
            return (st.config ?? loaded.config, line)
        }
        if let line { log(line) }
        return config
    }

    /// A log line that a flood could repeat (unknown NAS, malformed): at most one per minute per key.
    private func limitedLog(_ key: String, _ line: String) {
        let now = clock()
        guard let held = state.withLock({ $0.limiter.admit(key, now: now) }) else { return }
        log(held > 0 ? "\(line) (\(held) more since the last line)" : line)
    }

    // MARK: Packet handling

    /// Handles one datagram; returns the reply bytes or nil (drop). Retransmissions (same source,
    /// port, Identifier and Request Authenticator) get the first answer again (RFC 5080 §2.2.2).
    func handle(_ data: [UInt8], source: String, port: UInt16, accounting: Bool) async -> [UInt8]? {
        let packet: RADIUSPacket
        do { packet = try RADIUSPacket(bytes: data) } catch {
            limitedLog("malformed \(source)", "malformed datagram from \(source) dropped (\(error))")
            return nil
        }
        // The auth port takes only Access-Request, the accounting port only Accounting-Request.
        let expected: RADIUSPacket.Code = accounting ? .accountingRequest : .accessRequest
        guard packet.code == expected else {
            limitedLog("wrong port \(source) \(packet.code.rawValue)",
                       "\(packet.code.title) from \(source) on the \(accounting ? "accounting" : "authentication") port dropped")
            return nil
        }
        let config = await config()
        guard let nas = config.nas(for: source) else {
            limitedLog("unknown \(source)", "unknown NAS \(source) dropped")
            return nil
        }
        let key = RADIUSDuplicateCache.Key(source: (accounting ? "acct " : "auth ") + source, port: port, id: packet.id,
                                           authenticator: packet.authenticator)
        let started = ContinuousClock.now
        switch state.withLock({ $0.duplicates.begin(key, now: clock()) }) {
        case .new: break
        case .replay(let bytes): return bytes
        case .inProgress, .dropped: return nil
        }
        let reply = await answer(packet, nas: nas, config: config, source: source, started: started)
        state.withLock { $0.duplicates.finish(key, reply: reply, now: clock()) }
        return reply
    }

    private func answer(_ packet: RADIUSPacket, nas: DirectoryStore.NASClient, config: RadiusConfig, source: String,
                        started: ContinuousClock.Instant) async -> [UInt8]? {
        let secret = Array(nas.secret.utf8)
        if packet.code == .accountingRequest {
            guard packet.verifyAccountingRequestAuthenticator(secret: secret),
                  packet.messageAuthenticator == nil || packet.verifyMessageAuthenticator(secret: secret) else {
                limitedLog("bad auth \(nas.name)", "Accounting-Request from \(nas.name): bad Request Authenticator, dropped")
                return nil
            }
            logAccounting(packet, nas: nas)
            var reply = RADIUSPacket(code: .accountingResponse, id: packet.id, authenticator: packet.authenticator)
            reply.echoProxyState(from: packet)
            try? reply.signResponse(requestAuthenticator: packet.authenticator, secret: secret,
                                    messageAuthenticator: packet.messageAuthenticator != nil)
            return try? reply.encode()
        }

        // Access-Request: a Message-Authenticator that is present must verify; it is REQUIRED with
        // EAP (RFC 3579) and, unless the NAS is marked as unable to send it, for everything else
        // (Blast-RADIUS, CVE-2024-3596).
        let isEAP = packet.first(.eapMessage) != nil
        if packet.messageAuthenticator == nil {
            if isEAP || nas.requireMessageAuthenticator {
                limitedLog("no MA \(isEAP ? "eap " : "")\(nas.name)", "Access-Request from \(nas.name) without Message-Authenticator dropped"
                           + (isEAP ? " (EAP requires it, RFC 3579)" : " (Require Message-Authenticator is on for this client — Blast-RADIUS)"))
                return nil
            }
        } else if !packet.verifyMessageAuthenticator(secret: secret) {
            limitedLog("bad MA \(nas.name)", "Access-Request from \(nas.name): Message-Authenticator does not verify (wrong shared secret?), dropped")
            return nil
        }
        let now = clock()
        if packet.first(.eapMessage) != nil, let eap {
            return await answerEAP(packet, eap: eap, nas: nas, config: config, source: source, started: started, now: now)
        }
        var request = RequestContext(packet: packet, sourceIP: source, date: now)
        let user = request.userName ?? ""
        let outcome = await authenticate(packet, user: user, secret: secret, now: now)

        var decision = RADIUSDecision(accept: false, rule: nil, attributes: [])
        var reason: String
        switch outcome.result {
        case .success(let entry):
            let facts = try? await store.radiusFacts(entry: entry, now: now)
            decision = Self.decide(request: &request, facts: facts, config: config)
            reason = decision.ruleText
        case .failure(let why), .denied(let why, _), .expired(_, let why):
            reason = why
        }

        let code: RADIUSPacket.Code = decision.accept ? .accessAccept : .accessReject
        var reply = RADIUSPacket(code: code, id: packet.id, authenticator: packet.authenticator)
        if decision.accept {
            reply.attributes += decision.attributes
            reply.attributes += outcome.acceptAttributes(secret: secret, requestAuthenticator: packet.authenticator)
        } else {
            // Never say why on the wire beyond the MS-CHAP error code; Activity has the reason.
            reply.attributes += outcome.rejectAttributes
        }
        reply.echoProxyState(from: packet)
        do {
            try reply.signResponse(requestAuthenticator: packet.authenticator, secret: secret, messageAuthenticator: true)
        } catch {
            log("Access-Request \(user) from \(nas.name): reply does not fit (\(error)), dropped")
            return nil
        }
        let elapsed = Self.elapsedText(ContinuousClock.now - started)
        log("Access-Request \(user.isEmpty ? "-" : user) from \(nas.name) → \(reason), "
            + "\(decision.accept ? "Accept" : "Reject") (\(outcome.method), \(elapsed))")
        return try? reply.encode()
    }

    // MARK: EAP (phase 4b/4c)

    /// One step of an EAP exchange: Access-Challenge (EAP-Request + State), or the end —
    /// Access-Accept with EAP-Success, the policy's attributes and the MPPE keys from the MSK, or
    /// Access-Reject with EAP-Failure. One Activity line per finished exchange.
    private func answerEAP(_ packet: RADIUSPacket, eap: EAPServer, nas: DirectoryStore.NASClient, config: RadiusConfig,
                           source: String, started: ContinuousClock.Instant, now: Date) async -> [UInt8]? {
        let secret = Array(nas.secret.utf8)
        let message = packet.all(.eapMessage).flatMap(\.value)
        let result = await eap.handle(eap: message, state: packet.first(.state)?.value,
                                      framedMTU: packet.integer(.framedMTU).map(Int.init), now: now)
        var request = RequestContext(packet: packet, sourceIP: source, date: now)
        let outer = request.userName ?? "-"
        var reply: RADIUSPacket
        var line: String?
        switch result {
        case .drop(let why):
            limitedLog("eap \(nas.name) \(why)", "EAP from \(nas.name): \(why), dropped")
            return nil
        case .challenge(let bytes, let state):
            reply = RADIUSPacket(code: .accessChallenge, id: packet.id, authenticator: packet.authenticator,
                                 attributes: Self.eapAttributes(bytes) + [.init(.state, state)])
            // RFC 3579 §2.6.1: Session-Timeout on a challenge = how long the NAS waits for the peer.
            reply.attributes.append(RADIUSPacket.integer(.sessionTimeout, 30))
        case .accept(let bytes, let msk, let account, let facts):
            request.eapMethod = facts.method
            request.innerMethod = facts.innerMethod
            request.certificateSubject = facts.certificateSubject
            request.certificateIssuer = facts.certificateIssuer
            var dirFacts: DirectoryFacts?
            if let entry = try? await store.resolveSignInName(account) { dirFacts = try? await store.radiusFacts(entry: entry, now: now) }
            // The policy's "account" is the authenticated one (inner identity / certificate);
            // User-Name stays the outer identity the NAS sent.
            request.account = account
            let decision = Self.decide(request: &request, facts: dirFacts, config: config)
            let how = Self.eapText(facts, account: account)
            if decision.accept {
                reply = RADIUSPacket(code: .accessAccept, id: packet.id, authenticator: packet.authenticator,
                                     attributes: Self.eapAttributes(bytes) + decision.attributes + [.init(.userName, Array(account.utf8))]
                                        + Self.mppeAttributes(msk: msk, secret: secret, requestAuthenticator: packet.authenticator))
            } else {
                let failure = EAPPacket.failure(id: EAPPacket(bytes)?.id ?? 0).bytes
                reply = RADIUSPacket(code: .accessReject, id: packet.id, authenticator: packet.authenticator,
                                     attributes: Self.eapAttributes(failure))
            }
            line = "Access-Request \(outer) from \(nas.name) → \(decision.ruleText), \(decision.accept ? "Accept" : "Reject") (\(how)"
        case .reject(let bytes, let reason, let account, let facts):
            reply = RADIUSPacket(code: .accessReject, id: packet.id, authenticator: packet.authenticator, attributes: Self.eapAttributes(bytes))
            let how = facts.map { Self.eapText($0, account: account) } ?? "EAP"
            line = "Access-Request \(outer) from \(nas.name) → \(reason), Reject (\(how)"
        }
        reply.echoProxyState(from: packet)
        do {
            try reply.signResponse(requestAuthenticator: packet.authenticator, secret: secret, messageAuthenticator: true)
        } catch {
            log("Access-Request \(outer) from \(nas.name): reply does not fit (\(error)), dropped")
            return nil
        }
        if let line { log(line + ", \(Self.elapsedText(ContinuousClock.now - started)))") }
        return try? reply.encode()
    }

    /// `PEAP/EAP-MSCHAPv2 as alice, TLS 1.3, fast reconnect, crypto binding`.
    static func eapText(_ facts: EAPFacts, account: String?) -> String {
        var text = facts.method + (facts.innerMethod.map { "/\($0)" } ?? "")
        if let account, account.caseInsensitiveCompare(facts.outerIdentity) != .orderedSame { text += " as \(account)" }
        if let v = facts.tlsVersion { text += ", \(v)" }
        if facts.suiteB { text += ", 192-bit" }
        if facts.resumed { text += ", fast reconnect" }
        if facts.cryptoBinding { text += ", crypto binding" }
        if facts.passwordChanged { text += ", password changed" }
        return text
    }

    /// Accounting: Start/Stop (and On/Off) are logged; Interim-Update is counted and summarised
    /// at most once per NAS every 15 minutes, so a network of APs cannot flood Activity.
    private func logAccounting(_ packet: RADIUSPacket, nas: DirectoryStore.NASClient) {
        let type = packet.integer(.acctStatusType)
        let status = type.map(RADIUSNames.acctStatusType) ?? "without Acct-Status-Type"
        let user = packet.string(.userName) ?? "-"
        guard type == 3 else {
            log("Accounting-Request \(status) \(user) from \(nas.name)")
            return
        }
        let now = clock()
        guard let held = state.withLock({ $0.interim.admit("interim \(nas.name)", now: now) }) else { return }
        log("Accounting-Request Interim-Update \(user) from \(nas.name)"
            + (held > 0 ? " (\(held) more Interim-Updates from this NAS in the last 15 min)" : ""))
    }

    /// An EAP packet split over EAP-Message attributes of at most 253 bytes (RFC 3579 §3.1).
    static func eapAttributes(_ bytes: [UInt8]) -> [RADIUSPacket.Attribute] {
        stride(from: 0, to: max(bytes.count, 1), by: 253).map { RADIUSPacket.Attribute(.eapMessage, Array(bytes[$0..<min(bytes.count, $0 + 253)])) }
    }

    /// MS-MPPE-Recv-Key = MSK[0..<32], MS-MPPE-Send-Key = MSK[32..<64] (RFC 5216 §2.3 / RFC 2548),
    /// each salted and encrypted with the shared secret.
    static func mppeAttributes(msk: [UInt8], secret: [UInt8], requestAuthenticator: [UInt8]) -> [RADIUSPacket.Attribute] {
        guard msk.count >= 64 else { return [] }
        var salt = [UInt8](repeating: 0, count: 2)
        _ = SecRandomCopyBytes(kSecRandomDefault, 2, &salt)
        let ms = VendorSpecific.microsoft
        return [
            VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeRecvKey.rawValue,
                                     value: MPPEKeyAttribute.encrypt(key: Array(msk[0..<32]), secret: secret,
                                                                     requestAuthenticator: requestAuthenticator, salt: [salt[0] | 0x80, salt[1]])),
            VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeSendKey.rawValue,
                                     value: MPPEKeyAttribute.encrypt(key: Array(msk[32..<64]), secret: secret,
                                                                     requestAuthenticator: requestAuthenticator, salt: [salt[0] | 0x80, salt[1] ^ 1])),
        ].compactMap { $0 }
    }

    /// Templates whose certificates never sign anyone in over 802.1X: servers, the SCEP RA,
    /// CAs — a stolen DC or RA key must not become a network credential.
    static let nonClientTemplates: Set<String> = ["domaincontrollertls", "scepra", "webserver", "subca",
                                                   "radiusserver", "radiusserversuiteb", "dot1xsuitebca"]

    /// EAP-TLS: the client certificate must chain to a lab CA (RFC 5280 path validation at
    /// `now`), carry the clientAuth EKU, not be revoked, and map to a live account:
    /// - issued by this DC (in `pki_issued`): an account-bound template (Computer, User, any
    ///   template whose SAN comes from the account) maps to the requester's SID; other templates
    ///   map by the UPN / dNSName SAN, then the CN. Server/RA/CA templates are refused.
    /// - not in `pki_issued` (signed by a lab CA key elsewhere): only a UPN or dNSName SAN maps —
    ///   a bare CN never does.
    /// Domain controllers never sign in with a certificate here.
    func certificateAuth(chain: [[UInt8]], identity: String) async -> EAPAuthResult {
        let now = clock()
        guard let leafDER = chain.first, let leaf = try? Certificate(derEncoded: leafDER) else {
            return .failure("no client certificate")
        }
        let roots = await trustRoots().compactMap { try? Certificate(derEncoded: $0) }
        guard !roots.isEmpty else { return .failure("no lab CA to check the certificate against") }
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) { RFC5280Policy(fixedExpiryValidationTime: now) }
        let intermediates = chain.dropFirst().compactMap { try? Certificate(derEncoded: $0) }
        guard case .validCertificate = await verifier.validate(leaf: leaf, intermediates: CertificateStore(intermediates)) else {
            return .failure("certificate not issued by the lab CA, or expired (\(leaf.subject))")
        }
        guard let eku = try? leaf.extensions.extendedKeyUsage, eku.contains(.clientAuth) else {
            return .failure("certificate has no Client Authentication EKU (\(leaf.subject))")
        }
        let serial = leaf.serialNumber.bytes.map { String(format: "%02x", $0) }.joined()
        let record = try? await store.issuedCertificate(serial: serial)
        if let record, record.der != leafDER { return .failure("certificate serial \(serial) belongs to another certificate") }
        if let record, record.revoked { return .failure("certificate revoked (serial \(serial))") }
        if let record, Self.nonClientTemplates.contains(record.templateName.lowercased()) {
            return .failure("a \(record.templateName) certificate cannot sign in over 802.1X (serial \(serial))")
        }

        var entry: DirectoryEntry?
        if let record, let sidText = record.requesterSID, let sid = try? SID(string: sidText),
           let template = try? await store.pkiTemplate(named: record.templateName),
           template.sanPolicy == "dnsHostName" || template.sanPolicy == "upn" {
            // The subject came from this account at issuance: the SID is the mapping.
            entry = try? await store.read(sid: sid)
            if entry == nil { return .failure("the account certificate \(serial) was issued to no longer exists") }
        } else {
            var names: [String] = []
            for name in (try? leaf.extensions.subjectAlternativeNames) ?? SubjectAlternativeNames() {
                switch name {
                case .otherName(let other) where other.typeID == [1, 3, 6, 1, 4, 1, 311, 20, 2, 3]:
                    if let value = other.value, let upn = try? ASN1UTF8String(asn1Any: value) { names.append(String(upn)) }
                case .dnsName(let dns): names.append("host/" + dns)
                default: break
                }
            }
            if record != nil {   // issued here on purpose: the CN may name the account
                for rdn in leaf.subject { for attr in rdn where attr.type == .RDNAttributeType.commonName { names.append(attr.value.description) } }
            }
            for name in names {
                if let found = try? await store.resolveSignInName(name) { entry = found; break }
            }
        }
        guard let entry else {
            return .failure("no account for certificate \(leaf.subject)" + (record == nil ? " (not issued by this DC: only a UPN or DNS name maps)" : ""))
        }
        let sam = entry.samAccountName ?? entry.dn.description
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & UserAccountControl.serverTrustAccount != 0 {
            return .failure("a domain controller account (\(sam)) cannot sign in with a certificate")
        }
        if let until = badPasswords.lockedUntil(sam, now: now) {
            return .denied(AccountRefusal.lockedOut(until: until).description + " (RADIUS) (\(sam))", .accountDisabled)
        }
        if let refusal = store.accountRefusal(entry, now: now) { return .denied("\(refusal.description) (\(sam))", .accountDisabled) }
        if !store.logonHoursAllow(entry, now: now) { return .denied("outside the logon hours (\(sam))", .restrictedLogonHours) }
        return .success(account: sam, mschap: nil)
    }

    /// `812 µs` / `4.1 ms` from a Duration (seconds and attoseconds both count).
    static func elapsedText(_ d: Duration) -> String {
        let micros = Double(d.components.seconds) * 1e6 + Double(d.components.attoseconds) / 1e12
        return micros < 1000 ? String(format: "%.0f µs", micros) : String(format: "%.1f ms", micros / 1000)
    }

    // MARK: Decision (shared with the Test box)

    /// Adds the directory facts to the request context (merge, never replace) and runs the
    /// policies. The live server and `ServerController.testRadius` both come through here.
    public static func decide(request: inout RequestContext, facts: DirectoryFacts?, config: RadiusConfig) -> RADIUSDecision {
        if let facts { request.merge(facts) }
        return RADIUSEvaluator.decide(policies: config.policies, defaultAction: config.defaultAction, request)
    }

    // MARK: Authentication

    struct AuthOutcome {
        enum Result {
            case success(DirectoryEntry)
            /// Wrong password, unknown account… (MS-CHAP E=691).
            case failure(String)
            /// The account may not sign in (E=647 disabled/locked/expired, E=646 logon hours).
            case denied(String, MSCHAPv2.ErrorCode)
            /// Right password, but it must be changed first (E=648) — Netlogon's rule.
            case expired(DirectoryEntry, String)
        }
        var result: Result
        var method: String
        var mschap: MSCHAPv2.Success?
        var identForError: UInt8?

        /// MS-CHAP-Error for an MS-CHAPv2 refusal: `E=648` (password must change, with a new
        /// challenge for MS-CHAP2-CPW), `E=647`, `E=646`, else `E=691`.
        var rejectAttributes: [RADIUSPacket.Attribute] {
            guard method == "MS-CHAPv2", let ident = identForError else { return [] }
            let code: MSCHAPv2.ErrorCode
            switch result {
            case .success, .failure: code = .authenticationFailure
            case .denied(_, let c): code = c
            case .expired: code = .passwordExpired
            }
            var challenge = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, &challenge)
            return VendorSpecific.attribute(vendor: VendorSpecific.microsoft, type: VendorSpecific.MS.chapError.rawValue,
                                            value: [ident] + Array(MSCHAPv2.failureMessage(code, challenge: challenge).utf8)).map { [$0] } ?? []
        }

        /// MS-CHAP2-Success + the MPPE keys (RFC 2548 §2.4.2/§2.4.3, salted and encrypted).
        func acceptAttributes(secret: [UInt8], requestAuthenticator: [UInt8]) -> [RADIUSPacket.Attribute] {
            guard let mschap else { return [] }
            var salt = [UInt8](repeating: 0, count: 2)
            _ = SecRandomCopyBytes(kSecRandomDefault, 2, &salt)
            let sendSalt = [salt[0] | 0x80, salt[1]]
            let recvSalt = [salt[0] | 0x80, salt[1] ^ 0x01]    // unique within the reply
            let ms = VendorSpecific.microsoft
            return [
                VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.chap2Success.rawValue, value: mschap.successValue),
                VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeSendKey.rawValue,
                                         value: MPPEKeyAttribute.encrypt(key: mschap.sendKey, secret: secret,
                                                                         requestAuthenticator: requestAuthenticator, salt: sendSalt)),
                VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeRecvKey.rawValue,
                                         value: MPPEKeyAttribute.encrypt(key: mschap.recvKey, secret: secret,
                                                                         requestAuthenticator: requestAuthenticator, salt: recvSalt)),
                VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeEncryptionPolicy.rawValue, value: [0, 0, 0, 1]),
                VendorSpecific.attribute(vendor: ms, type: VendorSpecific.MS.mppeEncryptionTypes.rawValue, value: [0, 0, 0, 6]),
            ].compactMap { $0 }
        }
    }

    private func authenticate(_ packet: RADIUSPacket, user: String, secret: [UInt8], now: Date) async -> AuthOutcome {
        if let hidden = packet.first(.userPassword) {
            guard let password = RADIUSPacket.userPassword(hidden.value, secret: secret, authenticator: packet.authenticator) else {
                return AuthOutcome(result: .failure("malformed User-Password"), method: "PAP")
            }
            return await pap(user: user, password: String(decoding: password, as: UTF8.self), now: now)
        }
        // RFC 2548 §2.3.3: MS-CHAP2-CPW (+ MS-CHAP-NT-Enc-PW) changes an expired password.
        if let cpw = packet.microsoft(.chap2CPW) {
            let ident = cpw.count > 1 ? cpw[1] : nil
            let chunks = packet.all(.vendorSpecific).compactMap { VendorSpecific($0.value) }
                .filter { $0.vendor == VendorSpecific.microsoft }
                .flatMap(\.subAttributes).filter { $0.type == VendorSpecific.MS.chapNTEncPW.rawValue }.map(\.value)
            guard let challenge = packet.microsoft(.chapChallenge), challenge.count == 16,
                  let change = MSCHAPv2.ChangePassword(cpw: cpw, encPW: chunks) else {
                var o = AuthOutcome(result: .failure("malformed MS-CHAP2-CPW"), method: "MS-CHAPv2")
                o.identForError = ident
                return o
            }
            var o = await changePasswordOutcome(user: user, challenge: challenge, change: change, ident: ident ?? 0, now: now)
            o.identForError = ident
            return o
        }
        if let response = packet.microsoft(.chap2Response) {
            let ident = response.first
            guard let challenge = packet.microsoft(.chapChallenge), challenge.count == 16,
                  let parsed = MSCHAPv2.Response(response) else {
                var o = AuthOutcome(result: .failure("malformed MS-CHAPv2"), method: "MS-CHAPv2")
                o.identForError = ident
                return o
            }
            var o = await mschapv2(user: user, challenge: challenge, response: parsed, now: now)
            o.identForError = parsed.ident
            return o
        }
        if packet.first(.eapMessage) != nil {
            return AuthOutcome(result: .failure("EAP needs a server certificate"), method: "EAP")
        }
        return AuthOutcome(result: .failure("no User-Password, MS-CHAPv2 or EAP"), method: "none")
    }

    /// The account, unless it is locked by earlier RADIUS failures.
    private func account(_ user: String, now: Date) async -> (DirectoryEntry?, String?) {
        guard !user.isEmpty, let entry = try? await store.resolveSignInName(user) else { return (nil, "no such account") }
        let sam = entry.samAccountName ?? user
        if let until = badPasswords.lockedUntil(sam, now: now) {
            return (nil, AccountRefusal.lockedOut(until: until).description + " (RADIUS)")
        }
        return (entry, nil)
    }

    private func wrongPassword(_ entry: DirectoryEntry, now: Date) -> String {
        let locked = badPasswords.recordFailure(entry.samAccountName ?? "?", now: now, threshold: Self.lockoutThreshold,
                                                window: Self.lockoutWindow, duration: Self.lockoutDuration)
        return locked ? "wrong password; account now locked out" : "wrong password"
    }

    /// After a correct password: the account-state checks every path shares — disabled, locked,
    /// expired (E=647), logon hours (E=646), must change password (E=648, Netlogon's rule:
    /// pwdLastSet 0 or UF_PASSWORD_EXPIRED unless DONT_EXPIRE_PASSWORD).
    private func accountState(_ entry: DirectoryEntry, now: Date) async -> AuthOutcome.Result {
        if let refusal = store.accountRefusal(entry, now: now) { return .denied(refusal.description, .accountDisabled) }
        if !store.logonHoursAllow(entry, now: now) { return .denied("outside the account's logon hours", .restrictedLogonHours) }
        if (try? await store.passwordMustChange(entry)) == true { return .expired(entry, "the password must be changed first") }
        return .success(entry)
    }

    /// PAP: the LDAP simple-bind password check, then the shared account-state checks (a PAP
    /// client cannot change an expired password: refused).
    func pap(user: String, password: String, now: Date) async -> AuthOutcome {
        let (found, refused) = await account(user, now: now)
        guard let entry = found else {
            return AuthOutcome(result: refused.map { .denied($0, .accountDisabled) } ?? .failure("no such account"), method: "PAP")
        }
        do {
            switch try await store.checkPassword(entry, password: password, now: now) {
            case nil:
                badPasswords.recordSuccess(entry.samAccountName ?? user)
                return AuthOutcome(result: await accountState(entry, now: now), method: "PAP")
            case .wrongPassword:
                return AuthOutcome(result: .failure(wrongPassword(entry, now: now)), method: "PAP")
            case .noPassword?, .noSuchAccount?:
                return AuthOutcome(result: .failure(AccountRefusal.noPassword.description), method: "PAP")
            case let refusal?:
                return AuthOutcome(result: .denied(refusal.description, .accountDisabled), method: "PAP")
            }
        } catch {
            return AuthOutcome(result: .failure("directory error: \(error)"), method: "PAP")
        }
    }

    /// MS-CHAPv2 (RFC 2759) against the stored NT hash, with the same account checks as PAP.
    func mschapv2(user: String, challenge: [UInt8], response: MSCHAPv2.Response, now: Date) async -> AuthOutcome {
        let (found, refused) = await account(user, now: now)
        guard let entry = found else {
            return AuthOutcome(result: refused.map { .denied($0, .accountDisabled) } ?? .failure("no such account"), method: "MS-CHAPv2")
        }
        guard let hash = try? await store.secrets(id: entry.id)?.ntHash else {
            return AuthOutcome(result: .failure(AccountRefusal.noPassword.description), method: "MS-CHAPv2")
        }
        // ChallengeHash uses the name exactly as the peer sent it, domain stripped (RFC 2759 §4).
        guard let success = MSCHAPv2.verify(challenge: challenge, response: response, username: user, ntHash: hash) else {
            return AuthOutcome(result: .failure(wrongPassword(entry, now: now)), method: "MS-CHAPv2")
        }
        badPasswords.recordSuccess(entry.samAccountName ?? user)
        return AuthOutcome(result: await accountState(entry, now: now), method: "MS-CHAPv2", mschap: success)
    }

    /// MS-CHAPv2 Change-Password (RFC 2759 §7; RADIUS MS-CHAP2-CPW or EAP-MSCHAPv2 OpCode 7):
    /// the old password proves itself through the encrypted hash, the new one goes through the
    /// domain password policy (`setPassword`, as SAMR/kpasswd changes do), and the answer is an
    /// MS-CHAPv2 success computed with the new password.
    func changePasswordOutcome(user: String, challenge: [UInt8], change: MSCHAPv2.ChangePassword, ident: UInt8, now: Date) async -> AuthOutcome {
        let (found, refused) = await account(user, now: now)
        guard let entry = found else {
            return AuthOutcome(result: refused.map { .denied($0, .accountDisabled) } ?? .failure("no such account"), method: "MS-CHAPv2")
        }
        guard let oldHash = try? await store.secrets(id: entry.id)?.ntHash else {
            return AuthOutcome(result: .failure(AccountRefusal.noPassword.description), method: "MS-CHAPv2")
        }
        guard let newPassword = MSCHAPv2.verifyChange(change, username: user, challenge: challenge, oldHash: oldHash) else {
            return AuthOutcome(result: .failure(wrongPassword(entry, now: now) + " (password change)"), method: "MS-CHAPv2")
        }
        if let refusal = store.accountRefusal(entry, now: now) {
            return AuthOutcome(result: .denied(refusal.description, .accountDisabled), method: "MS-CHAPv2")
        }
        let sam = entry.samAccountName ?? user
        do {
            // One transaction: the new password and UF_PASSWORD_EXPIRED cleared together.
            try await store.changePassword(id: entry.id, password: newPassword, enforcePolicy: true)
        } catch {
            return AuthOutcome(result: .failure("new password refused: \(error)"), method: "MS-CHAPv2")
        }
        badPasswords.recordSuccess(sam)
        eap?.resumption?.invalidate(account: sam)
        log("password of \(sam) changed through MS-CHAPv2 (RADIUS)")
        let response = MSCHAPv2.Response(ident: ident, peerChallenge: change.peerChallenge, ntResponse: change.ntResponse)
        guard let success = MSCHAPv2.verify(challenge: challenge, response: response, username: user,
                                            ntHash: DirectoryStore.ntHash(newPassword)),
              let fresh = try? await store.read(id: entry.id) else {
            return AuthOutcome(result: .failure("the new password does not verify"), method: "MS-CHAPv2")
        }
        return AuthOutcome(result: await accountState(fresh, now: now), method: "MS-CHAPv2", mschap: success)
    }

    /// Fast reconnect: the account behind a cached session may still sign in — the account
    /// checks as for a password, no RADIUS lockout, and no password change or expiry since the
    /// session was authenticated.
    func revalidate(account name: String, authenticatedAt: Date) async -> EAPAuthResult {
        let now = clock()
        guard let entry = try? await store.resolveSignInName(name) else { return .failure("no such account \(name)") }
        let sam = entry.samAccountName ?? name
        if let until = badPasswords.lockedUntil(sam, now: now) {
            return .denied(AccountRefusal.lockedOut(until: until).description + " (RADIUS)", .accountDisabled)
        }
        switch await accountState(entry, now: now) {
        case .success: break
        case .failure(let why): return .failure(why)
        case .denied(let why, let code): return .denied(why, code)
        case .expired(_, let why): return .passwordExpired(account: sam, reason: why)
        }
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        let isMachine = uac & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount) != 0
        if !isMachine, let set = try? await store.passwordLastSet(entry), set > authenticatedAt.addingTimeInterval(1) {
            return .failure("the password changed since the session was authenticated")
        }
        return .success(account: sam, mschap: nil)
    }
}

/// The RADIUS config the server works from: NAS clients, ordered policies, default action.
public struct RadiusConfig: Sendable {
    public var clients: [DirectoryStore.NASClient]
    public var policies: [RADIUSPolicy]
    public var defaultAction: RADIUSDefaultAction

    public init(clients: [DirectoryStore.NASClient] = [], policies: [RADIUSPolicy] = [], defaultAction: RADIUSDefaultAction = .reject) {
        self.clients = clients; self.policies = policies; self.defaultAction = defaultAction
    }

    public static func load(_ store: DirectoryStore) async -> RadiusConfig {
        await loadReporting(store).config
    }

    /// The config plus what went wrong reading it. `complete` is false when a table could not be
    /// read at all (the caller keeps its last good config); a client whose secret does not open
    /// is skipped and named, the others still load.
    public static func loadReporting(_ store: DirectoryStore) async -> (config: RadiusConfig, complete: Bool, problems: [String]) {
        var problems: [String] = []
        var complete = true
        var clients: [DirectoryStore.NASClient] = []
        do {
            let listed = try await store.listNASSkippingUnreadable()
            clients = listed.clients
            if !listed.unreadable.isEmpty {
                problems.append("client\(listed.unreadable.count == 1 ? "" : "s") \(listed.unreadable.joined(separator: ", ")) skipped: the shared secret cannot be decrypted (re-enter it)")
            }
        } catch {
            complete = false
            problems.append("cannot read the clients (\(error))")
        }
        var policies: [RADIUSPolicy] = []
        do { policies = try await store.listRadiusPolicies() } catch {
            complete = false
            problems.append("cannot read the policies (\(error))")
        }
        var action = RADIUSDefaultAction.reject
        do { action = try await store.radiusDefaultAction() } catch {
            complete = false
            problems.append("cannot read the default action (\(error))")
        }
        return (RadiusConfig(clients: clients, policies: policies, defaultAction: action), complete, problems)
    }

    /// The enabled client whose address/CIDR/range covers `source`.
    public func nas(for source: String) -> DirectoryStore.NASClient? {
        clients.first { $0.enabled && $0.matches(source) }
    }
}

/// The EAP server's view of the directory: the same account checks, lockout and name forms as
/// PAP/MS-CHAPv2 (RadiusServer), plus the certificate mapping for EAP-TLS, password change and
/// fast-reconnect revalidation.
final class RadiusEAPBackend: EAPBackend, @unchecked Sendable {
    weak var server: RadiusServer?

    func verifyCertificate(chain: [[UInt8]], identity: String) async -> EAPAuthResult {
        guard let server else { return .failure("server stopped") }
        return await server.certificateAuth(chain: chain, identity: identity)
    }

    func verifyPassword(user: String, password: String) async -> EAPAuthResult {
        guard let server else { return .failure("server stopped") }
        return Self.map(await server.pap(user: user, password: password, now: Date()))
    }

    func verifyMSCHAPv2(user: String, challenge: [UInt8], response: MSCHAPv2.Response) async -> EAPAuthResult {
        guard let server else { return .failure("server stopped") }
        return Self.map(await server.mschapv2(user: user, challenge: challenge, response: response, now: Date()))
    }

    func changePassword(user: String, challenge: [UInt8], change: MSCHAPv2.ChangePassword) async -> EAPAuthResult {
        guard let server else { return .failure("server stopped") }
        return Self.map(await server.changePasswordOutcome(user: user, challenge: challenge, change: change, ident: 0, now: Date()))
    }

    func revalidate(account: String, authenticatedAt: Date) async -> EAPAuthResult {
        guard let server else { return .failure("server stopped") }
        return await server.revalidate(account: account, authenticatedAt: authenticatedAt)
    }

    static func map(_ outcome: RadiusServer.AuthOutcome) -> EAPAuthResult {
        switch outcome.result {
        case .success(let entry): .success(account: entry.samAccountName ?? "?", mschap: outcome.mschap)
        case .failure(let why): .failure(why)
        case .denied(let why, let code): .denied(why, code)
        case .expired(let entry, let why): .passwordExpired(account: entry.samAccountName ?? "?", reason: why)
        }
    }
}
