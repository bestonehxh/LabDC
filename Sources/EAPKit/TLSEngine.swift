import CNIOBoringSSL
import CryptoKit
import Foundation

/// Phase 4b: TLS for EAP (30 Sep 2026). EAP carries TLS records inside EAP packets, so the
/// handshake cannot run over a socket: BoringSSL (the copy swift-nio-ssl builds) runs on two
/// memory BIOs — records in, records out — and we frame them into EAP ourselves. It also gives
/// what EAP needs and NIOSSLHandler does not expose: RFC 5705 keying-material export (the MSK)
/// and the raw peer certificate chain.
///
/// 1 Oct 2026 — fast reconnect and 192-bit mode:
/// - Resumption (TLS 1.2 session IDs and tickets, TLS 1.3 tickets) goes through our own
///   `EAPResumptionCache`: a ticket is `handle ‖ AES-GCM(serialized session)`, and the handle
///   keys the authenticated identity the EAP layer recorded for that session. BoringSSL's own
///   default cache (which knows nothing about phase 2) is never used.
/// - WPA3-Enterprise 192-bit: a server context may carry a second, P-384 credential. A
///   ClientHello that asks only for Suite-B parameters (P-384 groups, ECDSA-P-384 signatures or
///   AES-256-GCM-SHA384 suites only) gets that credential and BoringSSL's
///   `ssl_compliance_policy_wpa3_192_202304` (TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 /
///   TLS_AES_256_GCM_SHA384, P-384, SHA-384 signatures).
///
/// 1 Oct 2026 — RSA-only devices: a server context may also carry an RSA credential (the RSA
/// compatibility root's RADIUS certificate). A ClientHello that cannot use an ECDSA certificate
/// (`isRSAOnlyHello`: no ECDSA signature scheme, no ECDSA suite, no NIST curve, or a pre-TLS 1.2
/// client) gets it, with the ECDHE-RSA suites old supplicants know (GCM and CBC; no RSA key transport) and
/// TLS 1.0–1.2 allowed for that connection only. Everyone else keeps the ECDSA chain.
public final class TLSContext: @unchecked Sendable {
    let ctx: OpaquePointer
    /// The P-384 credential served to 192-bit clients (nil: none configured).
    private(set) var suiteBCredential: OpaquePointer?
    /// The RSA credential served to RSA-only clients (nil: none configured).
    private(set) var rsaCredential: OpaquePointer?
    /// The TLS 1.0–1.2 suites an RSA-only client may use (`rsaCredential` only, i.e. only while
    /// "Allow RSA-only devices" is on): ECDHE-RSA with AES-GCM, ChaCha20 or AES-CBC. RSA key
    /// transport (`AES128-SHA` & co.) is not offered (CVE audit 1 Oct 2026): it has no forward
    /// secrecy — the RADIUS key decrypts every recorded session — and is the Bleichenbacher/ROBOT
    /// oracle surface. A supplicant that knows nothing but RSA key transport fails the handshake.
    static let rsaCompatibilityCiphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:"
        + "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA"
    let resumption: EAPResumptionCache?

    public enum Failure: Error, CustomStringConvertible {
        case boringSSL(String)
        public var description: String {
            switch self { case .boringSSL(let why): "TLS: \(why)" }
        }
    }

    /// The certificate chain (DER, leaf first) and PKCS#8 key of one credential.
    public struct Credential: Sendable, Equatable {
        public var chain: [[UInt8]]
        public var keyDER: [UInt8]
        public init(chain: [[UInt8]], keyDER: [UInt8]) { self.chain = chain; self.keyDER = keyDER }
    }

    /// - Parameters:
    ///   - chain: DER certificates, leaf first (the issuing CA may follow).
    ///   - privateKeyDER: the leaf key as PKCS#8 DER (nil for a client without a certificate).
    ///   - requireClientCertificate: EAP-TLS asks for and requires a client certificate; it is
    ///     accepted at the TLS layer and verified by the EAP layer afterwards (chain to the lab
    ///     CA, revocation, account) — on a resumption too.
    ///   - maxVersion: TLS 1.3 for every method (RFC 9190 / RFC 9427) unless capped.
    ///   - suiteB: server: the P-384 credential for WPA3-Enterprise 192-bit clients; client:
    ///     `suiteBClient` restricts this peer to the 192-bit parameters.
    ///   - resumption: server: the cache that makes tickets and session IDs resumable; nil turns
    ///     resumption off explicitly (no tickets, SSL_SESS_CACHE_OFF).
    ///   - sessionContext: server: the session ID context — a session of one EAP method never
    ///     resumes under another.
    ///   - rsa: server: the RSA credential for RSA-only clients (old devices); nil: none.
    ///   - rsaOnlyClient: client (tests): behave like an RSA-only device — RSA suites and RSA
    ///     signature schemes only (`cipherList` still overrides the suites).
    ///   - minVersion: client: the lowest TLS version (legacy-device tests). The server keeps
    ///     TLS 1.2 except on the RSA path.
    ///   - cipherList: the TLS 1.2 suites instead of the default list (test peers).
    ///   - deferClientVerification: server with `requireClientCertificate`: the handshake pauses
    ///     at the client certificate (`TLSEngine.certificatePending`) until the caller decides
    ///     (`resolveCertificate`), so a refused certificate ends the handshake with a TLS alert
    ///     (RFC 5216 §2.1.3, RFC 9190 §2.1.1) instead of completing it.
    public init(isServer: Bool, chain: [[UInt8]], privateKeyDER: [UInt8]?, requireClientCertificate: Bool = false,
                maxVersion: UInt16 = UInt16(TLS1_3_VERSION), suiteB: Credential? = nil, suiteBClient: Bool = false,
                resumption: EAPResumptionCache? = nil, sessionContext: String = "EAP", deferClientVerification: Bool = false,
                rsa: Credential? = nil, rsaOnlyClient: Bool = false, minVersion: UInt16 = UInt16(TLS1_2_VERSION),
                cipherList: String? = nil) throws {
        guard let ctx = CNIOBoringSSL_SSL_CTX_new(CNIOBoringSSL_TLS_with_buffers_method()) else {
            throw Failure.boringSSL("cannot create a context")
        }
        self.ctx = ctx
        self.resumption = isServer ? resumption : nil
        CNIOBoringSSL_SSL_CTX_set_min_proto_version(ctx, isServer ? UInt16(TLS1_2_VERSION) : minVersion)
        CNIOBoringSSL_SSL_CTX_set_max_proto_version(ctx, maxVersion)
        // TLS 1.2 suites: ECDHE + AEAD only; AES-256-GCM-SHA384 and P-384 for WPA3-Enterprise
        // 192-bit clients (TLS 1.3 always offers AES-256-GCM).
        let ciphers = cipherList ?? (rsaOnlyClient ? Self.rsaCompatibilityCiphers : nil) ?? "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
            + "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
        guard CNIOBoringSSL_SSL_CTX_set_strict_cipher_list(ctx, ciphers) == 1,
              CNIOBoringSSL_SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384") == 1 else {
            CNIOBoringSSL_SSL_CTX_free(ctx)
            throw Failure.boringSSL("cipher/group configuration refused: \(Self.errors())")
        }
        if !chain.isEmpty, let privateKeyDER {
            do { try Self.setChain(ctx, chain: chain, keyDER: privateKeyDER) } catch {
                CNIOBoringSSL_SSL_CTX_free(ctx)
                throw error
            }
        }
        // With the buffers method BoringSSL builds no X509 objects and verifies nothing by itself:
        // the custom callback accepts the chain and the EAP layer verifies it (server side:
        // `EAPBackend.verifyCertificate`; a test client checks the server chain itself).
        let mode = isServer
            ? (requireClientCertificate ? Int32(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : Int32(SSL_VERIFY_NONE))
            : Int32(SSL_VERIFY_PEER)
        if isServer, requireClientCertificate, deferClientVerification {
            CNIOBoringSSL_SSL_CTX_set_custom_verify(ctx, mode, deferredVerify)
        } else {
            CNIOBoringSSL_SSL_CTX_set_custom_verify(ctx, mode) { _, _ in ssl_verify_ok }
        }
        CNIOBoringSSL_SSL_CTX_set_info_callback(ctx, alertObserver)

        if isServer {
            let sid = Array(sessionContext.utf8.prefix(32))
            _ = sid.withUnsafeBufferPointer { CNIOBoringSSL_SSL_CTX_set_session_id_context(ctx, $0.baseAddress, $0.count) }
            if let resumption {
                // Our cache only: tickets sealed by `ticketMethod`, session IDs through the
                // external callbacks; BoringSSL's internal store stays empty.
                CNIOBoringSSL_SSL_CTX_set_session_cache_mode(ctx, Int32(SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL))
                CNIOBoringSSL_SSL_CTX_set_ticket_aead_method(ctx, ticketMethod)
                CNIOBoringSSL_SSL_CTX_sess_set_new_cb(ctx, serverNewSession)
                CNIOBoringSSL_SSL_CTX_sess_set_get_cb(ctx, serverGetSession)
                _ = CNIOBoringSSL_SSL_CTX_set_num_tickets(ctx, 1)
                let lifetime = UInt32(min(resumption.lifetime, 7 * 86400))
                _ = CNIOBoringSSL_SSL_CTX_set_timeout(ctx, lifetime)
                CNIOBoringSSL_SSL_CTX_set_session_psk_dhe_timeout(ctx, lifetime)
            } else {
                // Resumption off, explicitly: no tickets (1.2 or 1.3), no session cache.
                CNIOBoringSSL_SSL_CTX_set_session_cache_mode(ctx, Int32(SSL_SESS_CACHE_OFF))
                CNIOBoringSSL_SSL_CTX_set_options(ctx, UInt32(SSL_OP_NO_TICKET))
                _ = CNIOBoringSSL_SSL_CTX_set_num_tickets(ctx, 0)
            }
            if let suiteB {
                guard let credential = CNIOBoringSSL_SSL_CREDENTIAL_new_x509() else {
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw Failure.boringSSL("cannot create the 192-bit credential")
                }
                do { try Self.setCredential(credential, chain: suiteB.chain, keyDER: suiteB.keyDER) } catch {
                    CNIOBoringSSL_SSL_CREDENTIAL_free(credential)
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw error
                }
                suiteBCredential = credential
            }
            if let rsa {
                guard let credential = CNIOBoringSSL_SSL_CREDENTIAL_new_x509() else {
                    if let suiteBCredential { CNIOBoringSSL_SSL_CREDENTIAL_free(suiteBCredential) }
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw Failure.boringSSL("cannot create the RSA credential")
                }
                do { try Self.setCredential(credential, chain: rsa.chain, keyDER: rsa.keyDER) } catch {
                    CNIOBoringSSL_SSL_CREDENTIAL_free(credential)
                    if let suiteBCredential { CNIOBoringSSL_SSL_CREDENTIAL_free(suiteBCredential) }
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw error
                }
                rsaCredential = credential
            }
            if suiteBCredential != nil || rsaCredential != nil {
                CNIOBoringSSL_SSL_CTX_set_select_certificate_cb(ctx, selectCertificate)
            }
        } else {
            // A client (tests, the check harness) remembers the session it was given, for `-r`.
            CNIOBoringSSL_SSL_CTX_set_session_cache_mode(ctx, Int32(SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL))
            CNIOBoringSSL_SSL_CTX_sess_set_new_cb(ctx, clientNewSession)
            if rsaOnlyClient {
                // RSA-PSS and PKCS#1 only: what a device without ECDSA support announces.
                let prefs: [UInt16] = [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201]
                let ok = prefs.withUnsafeBufferPointer { CNIOBoringSSL_SSL_CTX_set_verify_algorithm_prefs(ctx, $0.baseAddress, $0.count) }
                guard ok == 1 else {
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw Failure.boringSSL("RSA-only signature schemes refused: \(Self.errors())")
                }
            }
            if suiteBClient {
                guard CNIOBoringSSL_SSL_CTX_set_compliance_policy(ctx, ssl_compliance_policy_wpa3_192_202304) == 1 else {
                    CNIOBoringSSL_SSL_CTX_free(ctx)
                    throw Failure.boringSSL("192-bit policy refused: \(Self.errors())")
                }
                // The policy sets TLS 1.2–1.3; keep the caller's cap.
                CNIOBoringSSL_SSL_CTX_set_max_proto_version(ctx, maxVersion)
            }
        }
    }

    deinit {
        if let suiteBCredential { CNIOBoringSSL_SSL_CREDENTIAL_free(suiteBCredential) }
        if let rsaCredential { CNIOBoringSSL_SSL_CREDENTIAL_free(rsaCredential) }
        CNIOBoringSSL_SSL_CTX_free(ctx)
    }

    private static func buffers(_ chain: [[UInt8]]) -> [OpaquePointer?] {
        chain.map { der in der.withUnsafeBufferPointer { CNIOBoringSSL_CRYPTO_BUFFER_new($0.baseAddress, $0.count, nil) } }
    }

    private static func parseKey(_ keyDER: [UInt8]) throws -> OpaquePointer {
        let key: OpaquePointer? = keyDER.withUnsafeBufferPointer { p in
            var cbs = CBS()
            CNIOBoringSSL_CBS_init(&cbs, p.baseAddress, p.count)
            return CNIOBoringSSL_EVP_parse_private_key(&cbs)
        }
        guard let key else { throw Failure.boringSSL("the private key is not PKCS#8 DER") }
        return key
    }

    private static func setChain(_ ctx: OpaquePointer, chain: [[UInt8]], keyDER: [UInt8]) throws {
        var buffers = buffers(chain)
        defer { for b in buffers { CNIOBoringSSL_CRYPTO_BUFFER_free(b) } }
        let key = try parseKey(keyDER)
        defer { CNIOBoringSSL_EVP_PKEY_free(key) }
        let ok = buffers.withUnsafeMutableBufferPointer {
            CNIOBoringSSL_SSL_CTX_set_chain_and_key(ctx, $0.baseAddress, $0.count, key, nil)
        }
        guard ok == 1 else { throw Failure.boringSSL("certificate/key refused: \(errors())") }
    }

    private static func setCredential(_ credential: OpaquePointer, chain: [[UInt8]], keyDER: [UInt8]) throws {
        var buffers = buffers(chain)
        defer { for b in buffers { CNIOBoringSSL_CRYPTO_BUFFER_free(b) } }
        let key = try parseKey(keyDER)
        defer { CNIOBoringSSL_EVP_PKEY_free(key) }
        let chainOK = buffers.withUnsafeMutableBufferPointer {
            CNIOBoringSSL_SSL_CREDENTIAL_set1_cert_chain(credential, $0.baseAddress, $0.count)
        }
        guard chainOK == 1, CNIOBoringSSL_SSL_CREDENTIAL_set1_private_key(credential, key) == 1 else {
            throw Failure.boringSSL("192-bit certificate/key refused: \(errors())")
        }
    }

    /// The queued BoringSSL errors as text (cleared).
    static func errors() -> String {
        var parts: [String] = []
        while true {
            let code = CNIOBoringSSL_ERR_get_error()
            if code == 0 { break }
            var buf = [CChar](repeating: 0, count: 256)
            CNIOBoringSSL_ERR_error_string_n(code, &buf, buf.count)
            parts.append(String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
        }
        return parts.isEmpty ? "no detail" : parts.joined(separator: "; ")
    }

    // MARK: 192-bit detection

    /// Whether a ClientHello asks for WPA3-Enterprise 192-bit parameters only. When it lists
    /// supported_groups, that decides: P-384 offered and no smaller curve (X25519, P-256, the
    /// hybrid X25519 groups) — a client that also offers X25519/P-256 is an ordinary one, even
    /// with AES-256-only suites, and gets the normal chain. Without the extension: signature
    /// algorithms with ECDSA-P-384 but none of the usual P-256/RSA-PSS-SHA256 ones, or every
    /// TLS 1.2 suite AES-256-GCM-SHA384.
    public static func isSuiteBHello(groups: [UInt16]?, signatureAlgorithms: [UInt16]?, cipherSuites: [UInt16]) -> Bool {
        if let groups {
            let small: Set<UInt16> = [0x001d, 0x0017, 0x11ec, 0x6399]   // X25519, P-256, X25519MLKEM768, Kyber
            return groups.contains(0x0018) && !groups.contains(where: small.contains)
        }
        if let sigalgs = signatureAlgorithms, !sigalgs.isEmpty {
            let weak: Set<UInt16> = [0x0403, 0x0804, 0x0401, 0x0807]      // ECDSA-P256, PSS-SHA256, PKCS1-SHA256, Ed25519
            if sigalgs.contains(0x0503), !sigalgs.contains(where: weak.contains) { return true }
        }
        let tls12 = cipherSuites.filter { $0 != 0x00ff && $0 != 0x5600 && ($0 >> 8) != 0x13 && ($0 & 0x0f0f) != 0x0a0a }
        let suiteB: Set<UInt16> = [0xc02c, 0xc030, 0x009f]
        return !tls12.isEmpty && tls12.allSatisfy(suiteB.contains)
    }

    /// Whether a ClientHello cannot use an ECDSA server certificate — an RSA-only device:
    /// - a pre-TLS 1.2 client (legacy_version below 1.2 and no supported_versions, or only
    ///   versions below 1.2), which the ECDSA path (TLS 1.2+) would refuse anyway;
    /// - signature_algorithms without any ECDSA scheme;
    /// - no TLS 1.3 suite and no ECDHE-ECDSA suite (only RSA key transport / ECDHE-RSA);
    /// - no TLS 1.3 suite and supported_groups without a NIST curve (the ECDSA key's curve).
    /// Windows 10/11, macOS/iOS and Android offer ECDSA and keep the ECDSA chain.
    public static func isRSAOnlyHello(version: UInt16, supportedVersions: [UInt16]?, groups: [UInt16]?,
                                      signatureAlgorithms: [UInt16]?, cipherSuites: [UInt16]) -> Bool {
        let versions = (supportedVersions ?? []).filter { ($0 & 0x0f0f) != 0x0a0a }
        if versions.isEmpty, version < 0x0303 { return true }
        if !versions.isEmpty, versions.allSatisfy({ $0 < 0x0303 }) { return true }
        if let sigalgs = signatureAlgorithms, !sigalgs.isEmpty {
            let ecdsa: Set<UInt16> = [0x0403, 0x0503, 0x0603, 0x0203]
            if !sigalgs.contains(where: ecdsa.contains) { return true }
        }
        if cipherSuites.contains(where: { ($0 >> 8) == 0x13 }) { return false }
        let ecdsaSuites: Set<UInt16> = [0xc006, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc02b, 0xc02c, 0xcca9,
                                        0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xc072, 0xc073]
        if !cipherSuites.contains(where: ecdsaSuites.contains) { return true }
        if let groups, !groups.isEmpty, !groups.contains(where: { [0x0017, 0x0018, 0x0019].contains($0) }) { return true }
        return false
    }

    static func u16List(_ p: UnsafePointer<UInt8>?, _ len: Int, lengthPrefixed: Bool) -> [UInt16]? {
        guard let p else { return nil }
        let bytes = Array(UnsafeBufferPointer(start: p, count: len))
        var body = bytes[...]
        if lengthPrefixed {
            guard bytes.count >= 2 else { return nil }
            body = bytes[2...]
        }
        return stride(from: body.startIndex, to: body.endIndex - 1, by: 2).map { UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]) }
    }
}

/// The early callback: a 192-bit ClientHello gets the P-384 credential and the WPA3-192 policy;
/// an RSA-only one (when an RSA credential is configured) the RSA credential, its suites and
/// TLS 1.0–1.2 for that connection. Anything else keeps the context's (ECDSA) chain.
private let selectCertificate: @convention(c) (UnsafePointer<SSL_CLIENT_HELLO>?) -> ssl_select_cert_result_t = { hello in
    guard let hello, let ssl = hello.pointee.ssl, let engine = TLSEngine.engine(for: ssl) else { return ssl_select_cert_success }
    func ext(_ type: UInt16) -> [UInt16]? {
        var data: UnsafePointer<UInt8>?
        var len = 0
        guard CNIOBoringSSL_SSL_early_callback_ctx_extension_get(hello, type, &data, &len) == 1 else { return nil }
        return TLSContext.u16List(data, len, lengthPrefixed: true)
    }
    /// supported_versions (43): a one-byte length, then two-byte versions.
    func supportedVersions() -> [UInt16]? {
        var data: UnsafePointer<UInt8>?
        var len = 0
        guard CNIOBoringSSL_SSL_early_callback_ctx_extension_get(hello, 43, &data, &len) == 1, let data, len >= 1 else { return nil }
        let bytes = Array(UnsafeBufferPointer(start: data, count: len))
        let end = min(bytes.count, 1 + Int(bytes[0]))
        return stride(from: 1, to: end - 1, by: 2).map { UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]) }
    }
    let suites = TLSContext.u16List(hello.pointee.cipher_suites, hello.pointee.cipher_suites_len, lengthPrefixed: false) ?? []
    if let rsa = engine.context.rsaCredential,
       TLSContext.isRSAOnlyHello(version: hello.pointee.version, supportedVersions: supportedVersions(), groups: ext(10),
                                 signatureAlgorithms: ext(13), cipherSuites: suites) {
        CNIOBoringSSL_SSL_certs_clear(ssl)
        guard CNIOBoringSSL_SSL_add1_credential(ssl, rsa) == 1,
              CNIOBoringSSL_SSL_set_strict_cipher_list(ssl, TLSContext.rsaCompatibilityCiphers) == 1,
              CNIOBoringSSL_SSL_set_min_proto_version(ssl, UInt16(TLS1_VERSION)) == 1 else {
            return ssl_select_cert_error
        }
        engine.rsaCompatibility = true
        return ssl_select_cert_success
    }
    guard let credential = engine.context.suiteBCredential,
          TLSContext.isSuiteBHello(groups: ext(10), signatureAlgorithms: ext(13), cipherSuites: suites) else {
        return ssl_select_cert_success
    }
    CNIOBoringSSL_SSL_certs_clear(ssl)
    guard CNIOBoringSSL_SSL_add1_credential(ssl, credential) == 1,
          CNIOBoringSSL_SSL_set_compliance_policy(ssl, ssl_compliance_policy_wpa3_192_202304) == 1 else {
        return ssl_select_cert_error
    }
    // The policy allows TLS 1.2–1.3; keep the context's cap (TLS 1.3 may be switched off).
    _ = CNIOBoringSSL_SSL_set_max_proto_version(ssl, CNIOBoringSSL_SSL_CTX_get_max_proto_version(engine.context.ctx))
    engine.suiteB = true
    return ssl_select_cert_success
}

/// Deferred client-certificate check: the first call pauses the handshake (the EAP layer checks
/// the chain against the directory, asynchronously); the retry returns its verdict, and a
/// refusal makes BoringSSL send the chosen alert.
private let deferredVerify: @convention(c) (OpaquePointer?, UnsafeMutablePointer<UInt8>?) -> ssl_verify_result_t = { ssl, alert in
    guard let ssl, let engine = TLSEngine.engine(for: ssl) else { return ssl_verify_invalid }
    guard engine.certificateChecked else {
        engine.certificatePending = true
        return ssl_verify_retry
    }
    if let refusal = engine.certificateAlert {
        alert?.pointee = refusal
        return ssl_verify_invalid
    }
    return ssl_verify_ok
}

/// Records the alert the peer sent (either side), for the caller to report.
private let alertObserver: @convention(c) (OpaquePointer?, Int32, Int32) -> Void = { ssl, type, value in
    guard type & Int32(SSL_CB_READ_ALERT) == Int32(SSL_CB_READ_ALERT), let ssl, let engine = TLSEngine.engine(for: ssl) else { return }
    engine.peerAlert = UInt8(truncatingIfNeeded: value & 0xff)
}

/// Tickets: `handle ‖ nonce ‖ AES-GCM(session)`; the handle names the cache entry.
nonisolated(unsafe) private let ticketMethod: UnsafeMutablePointer<SSL_TICKET_AEAD_METHOD> = {
    let method = UnsafeMutablePointer<SSL_TICKET_AEAD_METHOD>.allocate(capacity: 1)
    method.initialize(to: SSL_TICKET_AEAD_METHOD(
        max_overhead: { _ in EAPResumptionCache.ticketOverhead },
        seal: { ssl, out, outLen, maxOut, input, inLen in
            outLen?.pointee = 0
            guard let ssl, let out, let input, let engine = TLSEngine.engine(for: ssl), let cache = engine.context.resumption else { return 1 }
            let handle = engine.currentHandle
            guard let sealed = cache.seal(handle: handle, method: engine.eapType,
                                          Array(UnsafeBufferPointer(start: input, count: inLen))),
                  sealed.count <= maxOut else { return 1 }   // no ticket rather than an error
            sealed.withUnsafeBufferPointer { out.update(from: $0.baseAddress!, count: sealed.count) }
            outLen?.pointee = sealed.count
            return 1
        },
        open: { ssl, out, outLen, maxOut, input, inLen in
            guard let ssl, let out, let input, let engine = TLSEngine.engine(for: ssl), let cache = engine.context.resumption,
                  let (handle, plain) = cache.open(Array(UnsafeBufferPointer(start: input, count: inLen)), method: engine.eapType),
                  plain.count <= maxOut else { return ssl_ticket_aead_ignore_ticket }
            plain.withUnsafeBufferPointer { out.update(from: $0.baseAddress!, count: plain.count) }
            outLen?.pointee = plain.count
            engine.offeredHandle = handle
            return ssl_ticket_aead_success
        }))
    return method
}()

/// TLS 1.2 session IDs: stored serialized in our cache, keyed by the ID.
private let serverNewSession: @convention(c) (OpaquePointer?, OpaquePointer?) -> Int32 = { ssl, session in
    guard let ssl, let session, let engine = TLSEngine.engine(for: ssl), let cache = engine.context.resumption else { return 0 }
    var idLen: UInt32 = 0
    guard let idPtr = CNIOBoringSSL_SSL_SESSION_get_id(session, &idLen), idLen > 0 else { return 0 }
    var data: UnsafeMutablePointer<UInt8>?
    var len = 0
    guard CNIOBoringSSL_SSL_SESSION_to_bytes(session, &data, &len) == 1, let data else { return 0 }
    defer { CNIOBoringSSL_OPENSSL_free(data) }
    cache.storeSession(id: Array(UnsafeBufferPointer(start: idPtr, count: Int(idLen))), handle: engine.currentHandle,
                       method: engine.eapType, bytes: Array(UnsafeBufferPointer(start: data, count: len)))
    return 0
}

private let serverGetSession: @convention(c) (OpaquePointer?, UnsafePointer<UInt8>?, Int32, UnsafeMutablePointer<Int32>?) -> OpaquePointer? = { ssl, id, idLen, outCopy in
    outCopy?.pointee = 0
    guard let ssl, let id, idLen > 0, let engine = TLSEngine.engine(for: ssl), let cache = engine.context.resumption,
          let (handle, bytes) = cache.session(id: Array(UnsafeBufferPointer(start: id, count: Int(idLen))), method: engine.eapType)
    else { return nil }
    let session = bytes.withUnsafeBufferPointer { CNIOBoringSSL_SSL_SESSION_from_bytes($0.baseAddress, $0.count, CNIOBoringSSL_SSL_get_SSL_CTX(ssl)) }
    if session != nil { engine.offeredHandle = handle }
    return session
}

/// Client side: the newest resumable session, serialized, for the next connection.
private let clientNewSession: @convention(c) (OpaquePointer?, OpaquePointer?) -> Int32 = { ssl, session in
    guard let ssl, let session, let engine = TLSEngine.engine(for: ssl) else { return 0 }
    var data: UnsafeMutablePointer<UInt8>?
    var len = 0
    guard CNIOBoringSSL_SSL_SESSION_to_bytes(session, &data, &len) == 1, let data else { return 0 }
    defer { CNIOBoringSSL_OPENSSL_free(data) }
    engine.savedSession = Array(UnsafeBufferPointer(start: data, count: len))
    return 0
}

/// One TLS connection on memory BIOs: `feed` records received, `advance` the handshake,
/// `drain` the records to send; `read`/`write` application data once established.
public final class TLSEngine: @unchecked Sendable {
    let ssl: OpaquePointer
    private let rbio: UnsafeMutablePointer<BIO>
    private let wbio: UnsafeMutablePointer<BIO>
    let context: TLSContext
    /// The EAP type this connection serves (a resumption cache entry belongs to one type).
    let eapType: UInt8
    public private(set) var established = false
    public private(set) var failure: String?
    /// This connection's resumption handle (the cache key its tickets and session ID carry).
    public private(set) var sessionHandle: [UInt8]
    /// The handle of the ticket or session ID the client offered (it counts once `resumed`).
    var offeredHandle: [UInt8]?
    /// The server served the 192-bit credential and policy.
    public internal(set) var suiteB = false
    /// The server served the RSA compatibility credential (an RSA-only client).
    public internal(set) var rsaCompatibility = false
    /// Client side: the last session the server gave us (serialized), to offer next time.
    public internal(set) var savedSession: [UInt8]?
    /// Deferred verification: the handshake waits for `resolveCertificate`.
    public internal(set) var certificatePending = false
    var certificateChecked = false
    var certificateAlert: UInt8?
    /// The alert description the peer sent (e.g. 42 bad_certificate, 44 certificate_revoked).
    public internal(set) var peerAlert: UInt8?

    /// TLS alert descriptions used for refused client certificates (RFC 8446 §6.2).
    public enum Alert {
        public static let badCertificate: UInt8 = 42
        public static let certificateRevoked: UInt8 = 44
        public static let certificateExpired: UInt8 = 45
        public static let unknownCA: UInt8 = 48
        public static let accessDenied: UInt8 = 49
    }

    static let exIndex: Int32 = CNIOBoringSSL_SSL_get_ex_new_index(0, nil, nil, nil, nil)

    static func engine(for ssl: OpaquePointer) -> TLSEngine? {
        guard let p = CNIOBoringSSL_SSL_get_ex_data(ssl, exIndex) else { return nil }
        return Unmanaged<TLSEngine>.fromOpaque(p).takeUnretainedValue()
    }

    /// - Parameters:
    ///   - resume: client side: a session from an earlier connection's `savedSession`.
    public init(context: TLSContext, isServer: Bool, eapType: UInt8 = 0, resume: [UInt8]? = nil) throws {
        self.context = context
        self.eapType = eapType
        var handle = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &handle)
        sessionHandle = handle
        guard let ssl = CNIOBoringSSL_SSL_new(context.ctx),
              let rbio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()),
              let wbio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
            throw TLSContext.Failure.boringSSL("cannot create a connection")
        }
        self.ssl = ssl; self.rbio = rbio; self.wbio = wbio
        CNIOBoringSSL_SSL_set_bio(ssl, rbio, wbio)    // the SSL owns both BIOs now
        CNIOBoringSSL_SSL_set_ex_data(ssl, Self.exIndex, Unmanaged.passUnretained(self).toOpaque())
        if isServer { CNIOBoringSSL_SSL_set_accept_state(ssl) } else { CNIOBoringSSL_SSL_set_connect_state(ssl) }
        if !isServer, let resume,
           let session = resume.withUnsafeBufferPointer({ CNIOBoringSSL_SSL_SESSION_from_bytes($0.baseAddress, $0.count, context.ctx) }) {
            CNIOBoringSSL_SSL_set_session(ssl, session)
            CNIOBoringSSL_SSL_SESSION_free(session)
        }
    }

    deinit { CNIOBoringSSL_SSL_free(ssl) }

    /// The handle new tickets / session IDs carry: the resumed one on an abbreviated handshake
    /// (the identity recorded for it stays reachable), else this connection's own.
    var currentHandle: [UInt8] {
        if CNIOBoringSSL_SSL_session_reused(ssl) == 1, let offeredHandle { return offeredHandle }
        return sessionHandle
    }

    /// BoringSSL resumed a session (either side).
    public var sessionReused: Bool { CNIOBoringSSL_SSL_session_reused(ssl) == 1 }

    /// The handshake resumed a session from our cache.
    public var resumed: Bool { CNIOBoringSSL_SSL_session_reused(ssl) == 1 && offeredHandle != nil }
    /// The resumed session's cache handle.
    public var resumedHandle: [UInt8]? { resumed ? offeredHandle : nil }

    /// Records from the peer.
    public func feed(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        _ = bytes.withUnsafeBufferPointer { CNIOBoringSSL_BIO_write(rbio, $0.baseAddress, Int32($0.count)) }
    }

    /// Runs the handshake as far as the received records allow. Returns false on failure.
    @discardableResult
    public func advance() -> Bool {
        guard failure == nil else { return false }
        guard !established else { return true }
        let rc = CNIOBoringSSL_SSL_do_handshake(ssl)
        if rc == 1 {
            established = true
            if resumed, let offeredHandle { sessionHandle = offeredHandle }
            return true
        }
        let err = CNIOBoringSSL_SSL_get_error(ssl, rc)
        if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_CERTIFICATE_VERIFY { return true }
        failure = "handshake failed (\(err)): \(TLSContext.errors())"
        return false
    }

    /// The caller's verdict on the paused client certificate: nil accepts it, an alert refuses
    /// it (the next `advance` fails and `drain` holds the alert record).
    public func resolveCertificate(alert: UInt8?) {
        certificateChecked = true
        certificateAlert = alert
        certificatePending = false
    }

    /// Sends a fatal alert now (after the handshake: encrypted under the traffic keys); its
    /// record appears in `drain()`. Nothing more can be sent or read afterwards.
    public func sendAlert(_ alert: UInt8) {
        _ = CNIOBoringSSL_SSL_send_fatal_alert(ssl, alert)
        if failure == nil { failure = "alert \(alert) sent" }
        _ = TLSContext.errors()
    }

    /// Everything BoringSSL wants to send (records), removed from the BIO.
    public func drain() -> [UInt8] {
        var out: [UInt8] = []
        var buf = [UInt8](repeating: 0, count: 16384)
        while CNIOBoringSSL_BIO_pending(wbio) > 0 {
            let n = CNIOBoringSSL_BIO_read(wbio, &buf, Int32(buf.count))
            if n <= 0 { break }
            out += buf.prefix(Int(n))
        }
        return out
    }

    /// Decrypted application data available now (empty when none). Post-handshake messages
    /// (TLS 1.3 NewSessionTicket) are processed on the way.
    public func read() -> [UInt8] {
        var out: [UInt8] = []
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = CNIOBoringSSL_SSL_read(ssl, &buf, Int32(buf.count))
            if n <= 0 {
                let err = CNIOBoringSSL_SSL_get_error(ssl, n)
                if err != SSL_ERROR_WANT_READ, err != SSL_ERROR_ZERO_RETURN { failure = "read failed (\(err)): \(TLSContext.errors())" }
                break
            }
            out += buf.prefix(Int(n))
        }
        return out
    }

    /// A zero-byte write: BoringSSL flushes what it holds back until the server writes —
    /// the TLS 1.3 NewSessionTicket(s) — into `drain()`.
    public func flush() {
        guard established else { return }
        var none: UInt8 = 0
        _ = CNIOBoringSSL_SSL_write(ssl, &none, 0)
    }

    /// Encrypts application data; the records appear in `drain()`.
    public func write(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        let n = bytes.withUnsafeBufferPointer { CNIOBoringSSL_SSL_write(ssl, $0.baseAddress, Int32($0.count)) }
        if n <= 0 { failure = "write failed: \(TLSContext.errors())" }
    }

    /// RFC 5705 / RFC 8446 §7.5 exporter; nil before the handshake completes.
    public func export(label: String, context: [UInt8]? = nil, length: Int) -> [UInt8]? {
        guard established else { return nil }
        var out = [UInt8](repeating: 0, count: length)
        let label = Array(label.utf8)
        let ok = label.withUnsafeBufferPointer { l in
            (context ?? []).withUnsafeBufferPointer { c in
                l.withMemoryRebound(to: CChar.self) { lc in
                    CNIOBoringSSL_SSL_export_keying_material(ssl, &out, out.count, lc.baseAddress, lc.count,
                                                             c.baseAddress, c.count, context == nil ? 0 : 1)
                }
            }
        }
        return ok == 1 ? out : nil
    }

    /// 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3).
    public var version: UInt16 { UInt16(truncatingIfNeeded: CNIOBoringSSL_SSL_version(ssl)) }
    public var isTLS13: Bool { version == UInt16(TLS1_3_VERSION) }

    public var versionName: String { isTLS13 ? "TLS 1.3" : version == UInt16(TLS1_2_VERSION) ? "TLS 1.2" : "TLS 0x\(String(version, radix: 16))" }

    public var cipherName: String {
        guard let cipher = CNIOBoringSSL_SSL_get_current_cipher(ssl), let name = CNIOBoringSSL_SSL_CIPHER_get_name(cipher) else { return "?" }
        return String(cString: name)
    }

    /// The negotiated key-exchange group (`P-384`, `X25519`, …).
    public var groupName: String {
        let id = CNIOBoringSSL_SSL_get_group_id(ssl)
        guard id != 0, let name = CNIOBoringSSL_SSL_get_group_name(id) else { return "?" }
        return String(cString: name)
    }

    /// The peer's certificates as sent (leaf first), DER — on a resumed session, the ones the
    /// session was established with.
    public var peerCertificates: [[UInt8]] {
        guard let stack = CNIOBoringSSL_SSL_get0_peer_certificates(ssl) else { return [] }
        return (0..<CNIOBoringSSL_sk_CRYPTO_BUFFER_num(stack)).compactMap { i in
            guard let buf = CNIOBoringSSL_sk_CRYPTO_BUFFER_value(stack, i),
                  let data = CNIOBoringSSL_CRYPTO_BUFFER_data(buf) else { return nil }
            return Array(UnsafeBufferPointer(start: data, count: CNIOBoringSSL_CRYPTO_BUFFER_len(buf)))
        }
    }
}

/// Fast reconnect (1 Oct 2026): what a resumable TLS session proved. Keyed by a random handle
/// that the session's ticket (sealed here with a per-process AES-256-GCM key) or its TLS 1.2
/// session ID leads back to. An entry records the EAP type and — once phase 2 (PEAP/TTLS) or
/// the certificate check (EAP-TLS) succeeded — the account and when; resumption without that
/// record runs the full authentication again. Bounded (`capacity`), expiring `lifetime` after the
/// full authentication (8 h, typical PMK caching), and dropped when the account changes.
///
/// An entry is created when the ticket or session ID is issued — before phase 2, so anyone who
/// completes a TLS handshake makes one. Those account-less entries live `pendingLifetime` (60 s)
/// and are evicted first; authenticated entries go least-recently-used only when every entry is
/// authenticated, so a flood of unauthenticated handshakes cannot flush the cache.
public final class EAPResumptionCache: @unchecked Sendable {
    public struct Entry: Sendable, Equatable {
        public var method: UInt8
        public var account: String?
        /// PEAP/TTLS: the inner method that authenticated (`EAP-MSCHAPv2`, `PAP`…).
        public var innerMethod: String?
        public var authenticatedAt: Date?
        public var created: Date
        /// Last issued, resumed or authenticated (LRU order among authenticated entries).
        public var used: Date
    }

    public let lifetime: TimeInterval
    /// How long an entry without an authenticated account stays (phase 2 has this long to finish).
    public let pendingLifetime: TimeInterval
    public let capacity: Int
    private let lock = NSLock()
    private var entries: [[UInt8]: Entry] = [:]
    private var sessions: [[UInt8]: (handle: [UInt8], bytes: [UInt8])] = [:]
    private let key = SymmetricKey(size: .bits256)
    private let clock: @Sendable () -> Date

    static let handleLength = 16
    static let ticketOverhead = handleLength + 12 + 16

    public init(lifetime: TimeInterval = 8 * 3600, pendingLifetime: TimeInterval = 60, capacity: Int = 10_000,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.lifetime = lifetime
        self.pendingLifetime = min(pendingLifetime, lifetime)
        self.capacity = capacity
        self.clock = clock
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

    public func entry(_ handle: [UInt8]) -> Entry? {
        lock.lock(); defer { lock.unlock() }
        return live(handle)
    }

    private func expired(_ e: Entry, now: Date) -> Bool {
        e.account == nil ? now.timeIntervalSince(e.created) >= pendingLifetime
                         : now.timeIntervalSince(e.authenticatedAt ?? e.created) >= lifetime
    }

    private func live(_ handle: [UInt8], touch: Bool = false) -> Entry? {
        guard var e = entries[handle] else { return nil }
        let now = clock()
        guard !expired(e, now: now) else {
            entries[handle] = nil
            return nil
        }
        if touch { e.used = now; entries[handle] = e }
        return e
    }

    /// Makes room for one more entry: expired ones go, then the oldest account-less one, and
    /// only when every entry is authenticated the least recently used.
    private func makeRoom(now: Date) {
        guard entries.count >= capacity else { return }
        entries = entries.filter { !expired($0.value, now: now) }
        if entries.count >= capacity {
            let victim = entries.filter { $0.value.account == nil }.min(by: { $0.value.created < $1.value.created })?.key
                ?? entries.min(by: { $0.value.used < $1.value.used })?.key
            if let victim { entries[victim] = nil }
        }
        let keep = Set(entries.keys)
        sessions = sessions.filter { keep.contains($0.value.handle) }
    }

    /// A ticket or session ID is being issued for `handle`: make sure it has an entry.
    private func issued(_ handle: [UInt8], method: UInt8) -> Bool {
        if let e = live(handle, touch: true) { return e.method == method }
        let now = clock()
        makeRoom(now: now)
        entries[handle] = Entry(method: method, account: nil, innerMethod: nil, authenticatedAt: nil, created: now, used: now)
        return true
    }

    /// The full authentication (or a revalidated resumption) of `handle` succeeded as `account`.
    public func authenticated(_ handle: [UInt8], method: UInt8, account: String, inner: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        if var e = live(handle), e.method == method {
            if e.account == nil { e.authenticatedAt = now }
            e.account = account
            if let inner { e.innerMethod = inner }
            e.used = now
            entries[handle] = e
        } else {
            makeRoom(now: now)
            entries[handle] = Entry(method: method, account: account, innerMethod: inner, authenticatedAt: now, created: now, used: now)
        }
    }

    /// Forgets a session (a failed exchange must never be resumed).
    public func invalidate(_ handle: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        entries[handle] = nil
        sessions = sessions.filter { $0.value.handle != handle }
    }

    /// Forgets every session of `account` (disabled, password changed).
    public func invalidate(account: String) {
        lock.lock(); defer { lock.unlock() }
        let gone = Set(entries.filter { $0.value.account?.caseInsensitiveCompare(account) == .orderedSame }.keys)
        for h in gone { entries[h] = nil }
        sessions = sessions.filter { !gone.contains($0.value.handle) }
    }

    func seal(handle: [UInt8], method: UInt8, _ plaintext: [UInt8]) -> [UInt8]? {
        lock.lock()
        let ok = issued(handle, method: method)
        lock.unlock()
        guard ok, let box = try? AES.GCM.seal(plaintext, using: key, authenticating: handle) else { return nil }
        return handle + Array(box.nonce) + Array(box.ciphertext) + Array(box.tag)
    }

    func open(_ ticket: [UInt8], method: UInt8) -> (handle: [UInt8], plaintext: [UInt8])? {
        guard ticket.count > Self.ticketOverhead else { return nil }
        let handle = Array(ticket[0..<Self.handleLength])
        lock.lock()
        let e = live(handle, touch: true)
        lock.unlock()
        guard let e, e.method == method,
              let nonce = try? AES.GCM.Nonce(data: ticket[Self.handleLength..<(Self.handleLength + 12)]),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ticket[(Self.handleLength + 12)..<(ticket.count - 16)],
                                               tag: ticket[(ticket.count - 16)...]),
              let plain = try? AES.GCM.open(box, using: key, authenticating: handle) else { return nil }
        return (handle, Array(plain))
    }

    func storeSession(id: [UInt8], handle: [UInt8], method: UInt8, bytes: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        guard issued(handle, method: method) else { return }
        if sessions.count >= capacity {
            let keep = Set(entries.keys)
            sessions = sessions.filter { keep.contains($0.value.handle) }
            if sessions.count >= capacity, let any = sessions.keys.first { sessions[any] = nil }
        }
        sessions[id] = (handle, bytes)
    }

    func session(id: [UInt8], method: UInt8) -> (handle: [UInt8], bytes: [UInt8])? {
        lock.lock(); defer { lock.unlock() }
        guard let s = sessions[id] else { return nil }
        guard let e = live(s.handle, touch: true), e.method == method else { sessions[id] = nil; return nil }
        return s
    }
}
