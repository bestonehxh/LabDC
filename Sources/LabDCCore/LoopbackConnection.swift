import Foundation
import Network
import Security
import Synchronization

/// A TCP (optionally TLS) connection to one of the app's own listeners on 127.0.0.1, for Test
/// login. Async, cancellable: cancelling the calling task cancels the connection, and every wait
/// ends when the connection fails or is closed.
///
/// With `trustAnchorDER` the TLS server certificate must chain to that certificate (the lab CA)
/// and nothing else; the host name is not checked (the DC certificate names the DC, not 127.0.0.1).
final class LoopbackConnection: Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.labdc.app.login-test")
    private let buffer = Mutex<[UInt8]>([])

    init(port: Int, trustAnchorDER: [UInt8]? = nil) {
        let parameters: NWParameters
        if let anchor = trustAnchorDER {
            let tls = NWProtocolTLS.Options()
            let verifyQueue = DispatchQueue(label: "dev.labdc.app.login-test.verify")
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
                let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
                guard let ca = SecCertificateCreateWithData(nil, Data(anchor) as CFData) else { return complete(false) }
                SecTrustSetPolicies(trust, SecPolicyCreateBasicX509())
                SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, true)
                complete(SecTrustEvaluateWithError(trust, nil))
            }, verifyQueue)
            parameters = NWParameters(tls: tls)
        } else {
            parameters = .tcp
        }
        connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any,
                                  using: parameters)
    }

    /// Waits until the connection (and the TLS handshake) is ready.
    func open() async throws {
        let once = ResumeOnce()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let finish: @Sendable (Result<Void, Error>) -> Void = { result in
                    if once.claim() { continuation.resume(with: result) }
                }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: finish(.success(()))
                    case .failed(let e): finish(.failure(LoginTestError.connection(Self.describe(e))))
                    case .waiting(let e): finish(.failure(LoginTestError.connection(Self.describe(e))))
                    case .cancelled: finish(.failure(CancellationError()))
                    default: break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func send(_ bytes: [UInt8]) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: Data(bytes), completion: .contentProcessed { error in
                    if let error { continuation.resume(throwing: LoginTestError.connection(Self.describe(error))) } else {
                        continuation.resume()
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// Reads until `frame(buffer)` returns a length the buffer has reached; returns that many
    /// bytes (the rest stays buffered).
    func receive(frame: @escaping @Sendable ([UInt8]) -> Int?) async throws -> [UInt8] {
        while true {
            let ready: [UInt8]? = buffer.withLock { b in
                guard let n = frame(b), b.count >= n else { return nil }
                let out = Array(b.prefix(n))
                b.removeFirst(n)
                return out
            }
            if let ready { return ready }
            let chunk = try await receiveChunk()
            buffer.withLock { $0 += chunk }
        }
    }

    private func receiveChunk() async throws -> [UInt8] {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                    if let data, !data.isEmpty { return continuation.resume(returning: [UInt8](data)) }
                    if let error { return continuation.resume(throwing: LoginTestError.connection(Self.describe(error))) }
                    if isComplete { return continuation.resume(throwing: LoginTestError.connection("closed by the server")) }
                    continuation.resume(throwing: LoginTestError.connection("no data"))
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func close() {
        connection.cancel()
    }

    static func describe(_ error: NWError) -> String {
        switch error {
        case .posix(let code) where code == .ECONNREFUSED: "connection refused"
        case .posix(let code): String(cString: strerror(code.rawValue)).lowercased()
        case .tls(let status): "TLS error \(status)"
        default: "\(error)"
        }
    }
}

/// True exactly once (a continuation resumed from several callbacks).
private final class ResumeOnce: Sendable {
    private let done = Mutex(false)

    func claim() -> Bool {
        done.withLock { d in
            if d { return false }
            d = true
            return true
        }
    }
}
