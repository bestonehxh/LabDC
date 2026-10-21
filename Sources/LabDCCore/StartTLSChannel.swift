import EAPKit
import Foundation
import LDAPCore
import Security

/// Test login's LDAP stream: plain or LDAPS (`LoopbackConnection` does the TLS), or LDAP with
/// StartTLS (owner, 22 Oct 2026) — a plain connection on the LDAP port that asks for StartTLS
/// (RFC 4511 §4.14) and then runs the TLS handshake over the same socket. NWConnection cannot
/// add TLS to an open connection, so the TLS layer is EAPKit's BoringSSL engine on memory BIOs.
/// As with LDAPS, the server chain must lead to the lab CA and nothing else (no host-name check).
final class LDAPTestChannel: @unchecked Sendable {
    private let connection: LoopbackConnection
    private var engine: TLSEngine?
    private var plaintext: [UInt8] = []
    /// "TLS 1.3, TLS_AES_128_GCM_SHA256" once StartTLS is up.
    private(set) var tlsSummary: String?

    init(_ connection: LoopbackConnection) {
        self.connection = connection
    }

    func open() async throws {
        try await connection.open()
    }

    func close() {
        connection.close()
    }

    /// Sends the StartTLS request and, on success, completes the handshake trusting only `caDER`.
    func startTLS(caDER: [UInt8], messageID: Int32) async throws {
        let request = LDAPMessage(messageID: messageID, .extendedRequest(ExtendedRequest(name: LDAPExtendedOID.startTLS)))
        try await connection.send(request.encoded())
        let reply = try LDAPMessage(bytes: try await connection.receive(frame: LoginTester.ldapFrame))
        guard case .extendedResponse(let ext) = reply.operation else { throw LoginTestError.protocolError("no StartTLS response") }
        guard ext.result.resultCode == .success else {
            let why = ext.result.diagnosticMessage.isEmpty ? "\(ext.result.resultCode)" : ext.result.diagnosticMessage
            throw LoginTestError.protocolError("StartTLS refused: \(why)")
        }
        let context = try TLSContext(isServer: false, chain: [], privateKeyDER: nil)
        let e = try TLSEngine(context: context, isServer: false)
        e.advance()
        try await connection.send(e.drain())
        while !e.established {
            e.feed(try await connection.receive(frame: Self.recordFrame))
            guard e.advance() else { throw LoginTestError.connection("TLS: \(e.failure ?? "handshake failed")") }
            let out = e.drain()
            if !out.isEmpty { try await connection.send(out) }
        }
        guard Self.trusted(e.peerCertificates, caDER: caDER) else {
            throw LoginTestError.connection("TLS: the DC certificate does not chain to the lab CA")
        }
        engine = e
        tlsSummary = "\(e.versionName), \(e.cipherName)"
    }

    func send(_ bytes: [UInt8]) async throws {
        guard let engine else { return try await connection.send(bytes) }
        engine.write(bytes)
        try await connection.send(engine.drain())
    }

    func receive(frame: @escaping @Sendable ([UInt8]) -> Int?) async throws -> [UInt8] {
        guard let engine else { return try await connection.receive(frame: frame) }
        while true {
            if let n = frame(plaintext), plaintext.count >= n {
                let out = Array(plaintext.prefix(n))
                plaintext.removeFirst(n)
                return out
            }
            engine.feed(try await connection.receive(frame: Self.recordFrame))
            plaintext += engine.read()
            if let failure = engine.failure { throw LoginTestError.connection("TLS: \(failure)") }
            let out = engine.drain()    // TLS 1.3 post-handshake messages (key updates) answer here
            if !out.isEmpty { try await connection.send(out) }
        }
    }

    /// One TLS record: a 5-byte header whose last two bytes are the body length.
    static func recordFrame(_ b: [UInt8]) -> Int? {
        b.count >= 5 ? 5 + (Int(b[3]) << 8 | Int(b[4])) : nil
    }

    static func trusted(_ chain: [[UInt8]], caDER: [UInt8]) -> Bool {
        let certs = chain.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard !certs.isEmpty, let ca = SecCertificateCreateWithData(nil, Data(caDER) as CFData) else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }
}
