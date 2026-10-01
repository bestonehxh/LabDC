import Foundation
import KerberosASN1
import Network
import Synchronization
import os

/// RFC 4120 §7.2.2 TCP framing: each message is preceded by its length as a 4-byte
/// big-endian integer. The high bit is reserved (RFC 5021); a set bit is answered with
/// KRB_ERR_FIELD_TOOLONG.
public enum TCPFraming {
    /// Largest request accepted over TCP.
    public static let maxMessageSize = 256 * 1024

    public static func frame(_ message: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(message.count + 4)
        out.appendBE(UInt32(message.count))
        return out + message
    }

    /// Accumulates stream bytes and yields complete messages.
    public struct Deframer: Sendable {
        private var buffer: [UInt8] = []

        public init() {}

        public mutating func append(_ bytes: some Sequence<UInt8>) { buffer.append(contentsOf: bytes) }

        /// The next complete message, or nil if more bytes are needed.
        /// - Throws: `KDCError.protocolError(KRB_ERR_FIELD_TOOLONG)` for a reserved-bit or oversized length.
        public mutating func next() throws -> [UInt8]? {
            guard buffer.count >= 4 else { return nil }
            let length = buffer[0..<4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            guard length & 0x8000_0000 == 0, Int(length) <= TCPFraming.maxMessageSize else {
                throw KDCError.krb(KerberosErrorCode.krbErrFieldToolong, "TCP length prefix \(length) refused")
            }
            guard buffer.count >= 4 + Int(length) else { return nil }
            let message = Array(buffer[4..<(4 + Int(length))])
            buffer.removeFirst(4 + Int(length))
            return message
        }

        /// Bytes received but not yet returned.
        public var pendingCount: Int { buffer.count }
    }
}

/// UDP and TCP listeners (Network.framework) in front of a `KDC`.
///
/// Binds to `0.0.0.0` by default: macOS lets a normal user bind ports below 1024 on the
/// wildcard address, but binding them to a specific address (127.0.0.1, ::1) fails with
/// EACCES. UDP: one datagram in, one out, replies over 1465 bytes become
/// KRB_ERR_RESPONSE_TOO_BIG. TCP: 4-byte length framing; the connection stays open while
/// the client keeps sending and is closed when it closes its side or after 30 s idle.
public final class KDCServer: Sendable {
    public let kdc: KDC
    private let listener: DualListener

    public init(kdc: KDC, port: UInt16 = 88, bindAddress: String = "0.0.0.0") {
        self.kdc = kdc
        listener = DualListener(name: "kdc", port: port, bindAddress: bindAddress,
                                udp: { request, peer in await kdc.handleUDP(request, from: peer.from) },
                                tcp: { request, peer in await kdc.handleTCP(request, from: peer.from) },
                                tooLong: { await kdc.errorMessage(KerberosErrorCode.krbErrFieldToolong) })
    }

    public var bindAddress: String { listener.bindAddress }

    /// The bound port (useful when 0 was requested). Valid after `start()`.
    public var port: UInt16 { listener.port }

    /// Starts UDP then TCP on the same port; returns when both are ready.
    public func start() async throws { try await listener.start() }

    public func stop() { listener.stop() }
}

/// Who sent a request, and the local address it arrived on (kpasswd puts that address in
/// the KRB-PRIV `s-address`).
public struct PeerInfo: Sendable {
    /// Printable remote address (`::1`, `127.0.0.1`).
    public var from: String
    /// The local address the request arrived on, as a Kerberos HostAddress (IPv4-mapped IPv6
    /// is reported as IPv4); nil when unknown.
    public var localAddress: HostAddress?
    /// "udp" or "tcp"; nil when driven directly.
    public var transport: String?

    public init(from: String, localAddress: HostAddress? = nil, transport: String? = nil) {
        self.from = from
        self.localAddress = localAddress
        self.transport = transport
    }
}

/// UDP + TCP listeners on one port (Network.framework) with RFC 4120 §7.2.2 TCP framing,
/// shared by the KDC (88) and kpasswd (464, which frames TCP the same way).
final class DualListener: @unchecked Sendable {
    typealias Handler = @Sendable ([UInt8], PeerInfo) async -> [UInt8]

    let name: String
    let bindAddress: String
    private let requestedPort: UInt16
    private let udpHandler: Handler
    private let tcpHandler: Handler
    private let tooLong: @Sendable () async -> [UInt8]
    private let queue: DispatchQueue
    private let listeners = Mutex<(udp: NWListener?, tcp: NWListener?)>((nil, nil))
    private static let idleTimeout: TimeInterval = 30

    init(name: String, port: UInt16, bindAddress: String, udp: @escaping Handler, tcp: @escaping Handler,
         tooLong: @escaping @Sendable () async -> [UInt8]) {
        self.name = name
        self.requestedPort = port
        self.bindAddress = bindAddress
        self.udpHandler = udp
        self.tcpHandler = tcp
        self.tooLong = tooLong
        queue = DispatchQueue(label: "dev.labdc.app.\(name)-server")
    }

    var port: UInt16 {
        listeners.withLock { $0.udp?.port?.rawValue } ?? requestedPort
    }

    func start() async throws {
        // An ephemeral request (port 0) takes the port the UDP listener got for TCP too; that port
        // can already be held by some TCP socket (EADDRINUSE). Try another ephemeral pair then.
        var attempt = 0
        while true {
            do {
                try await startPair()
                return
            } catch {
                stop()
                attempt += 1
                guard requestedPort == 0, attempt < 8 else { throw error }
            }
        }
    }

    private func startPair() async throws {
        let udp = try makeListener(.udp, port: requestedPort)
        udp.newConnectionHandler = { [weak self] conn in self?.acceptUDP(conn) }
        listeners.withLock { $0.udp = udp }
        try await Self.waitReady(udp, queue: queue, what: "\(name) udp")
        guard let bound = udp.port?.rawValue else { throw KDCError.listener("\(name) udp listener has no port") }

        let tcp = try makeListener(.tcp, port: bound)
        tcp.newConnectionHandler = { [weak self] conn in self?.acceptTCP(conn) }
        listeners.withLock { $0.tcp = tcp }
        try await Self.waitReady(tcp, queue: queue, what: "\(name) tcp")
    }

    func stop() {
        listeners.withLock {
            $0.udp?.cancel()
            $0.tcp?.cancel()
            $0 = (nil, nil)
        }
    }

    private func makeListener(_ base: NWParameters, port: UInt16) throws -> NWListener {
        let params = base.copy()
        params.allowLocalEndpointReuse = true
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw KDCError.listener("bad port \(port)") }
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(bindAddress), port: nwPort)
        do { return try NWListener(using: params) } catch {
            throw KDCError.listener("cannot create listener on \(bindAddress):\(port): \(error)")
        }
    }

    private static func waitReady(_ listener: NWListener, queue: DispatchQueue, what: String) async throws {
        let resumed = Mutex(false)
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            let finish: @Sendable (Result<Void, KDCError>) -> Void = { result in
                let first = resumed.withLock { done in
                    defer { done = true }
                    return !done
                }
                if first { c.resume(with: result.mapError { $0 as any Error }) }
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
                case .failed(let e): finish(.failure(.listener("\(what): \(e)")))
                case .waiting(let e): finish(.failure(.listener("\(what): \(e)")))
                case .cancelled: finish(.failure(.listener("\(what): cancelled")))
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    private static func describe(_ endpoint: NWEndpoint) -> String {
        if case let .hostPort(host, _) = endpoint {
            switch host {
            case .ipv4(let a): return "\(a)"
            case .ipv6(let a): return "\(a)"
            case .name(let n, _): return n
            @unknown default: return "\(host)"
            }
        }
        return "\(endpoint)"
    }

    /// The connection's local address as a HostAddress (IPv4-mapped IPv6 as IPv4).
    static func localAddress(_ conn: NWConnection) -> HostAddress? {
        guard case let .hostPort(host, _)? = conn.currentPath?.localEndpoint else { return nil }
        switch host {
        case .ipv4(let a):
            return HostAddress(addrType: AddressType.ipv4, address: [UInt8](a.rawValue))
        case .ipv6(let a):
            let raw = [UInt8](a.rawValue)
            if raw.count == 16, raw[0..<10].allSatisfy({ $0 == 0 }), raw[10] == 0xFF, raw[11] == 0xFF {
                return HostAddress(addrType: AddressType.ipv4, address: Array(raw[12..<16]))
            }
            return HostAddress(addrType: AddressType.ipv6, address: raw)
        default:
            return nil
        }
    }

    private func peer(_ conn: NWConnection, _ transport: String) -> PeerInfo {
        PeerInfo(from: Self.describe(conn.endpoint), localAddress: Self.localAddress(conn), transport: transport)
    }

    // MARK: UDP

    private func acceptUDP(_ conn: NWConnection) {
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.idleTimeout) { conn.cancel() }
        receiveUDP(conn)
    }

    private func receiveUDP(_ conn: NWConnection) {
        conn.receiveMessage { [udpHandler] data, _, _, error in
            if let data, !data.isEmpty {
                let request = [UInt8](data)
                let peer = self.peer(conn, "udp")
                Task {
                    let reply = await udpHandler(request, peer)
                    conn.send(content: Data(reply), completion: .contentProcessed { _ in })
                }
            }
            if error == nil {
                self.receiveUDP(conn)
            } else {
                conn.cancel()
            }
        }
    }

    // MARK: TCP

    private func acceptTCP(_ conn: NWConnection) {
        conn.start(queue: queue)
        readTCP(conn, buffer: TCPFraming.Deframer())
    }

    private func readTCP(_ conn: NWConnection, buffer: TCPFraming.Deframer) {
        var buffer = buffer
        do {
            if let request = try buffer.next() {
                let pending = buffer
                let peer = peer(conn, "tcp")
                Task { [tcpHandler] in
                    let reply = await tcpHandler(request, peer)
                    conn.send(content: Data(TCPFraming.frame(reply)), completion: .contentProcessed { error in
                        if error != nil { conn.cancel() } else { self.readTCP(conn, buffer: pending) }
                    })
                }
                return
            }
        } catch {
            Task { [tooLong] in
                let reply = await tooLong()
                conn.send(content: Data(TCPFraming.frame(reply)), completion: .contentProcessed { _ in conn.cancel() })
            }
            return
        }
        let received = Mutex(false)
        queue.asyncAfter(deadline: .now() + Self.idleTimeout) {
            if !received.withLock({ $0 }) { conn.cancel() }
        }
        let current = buffer
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            received.withLock { $0 = true }
            if let data, !data.isEmpty {
                var next = current
                next.append(data)
                self.readTCP(conn, buffer: next)
            } else if isComplete || error != nil {
                conn.cancel()
            } else {
                self.readTCP(conn, buffer: current)
            }
        }
    }
}

extension KDC {
    /// A bare KRB-ERROR with `code` (realm and krbtgt as sname), for transport-level failures.
    public func errorMessage(_ code: Int32) -> [UInt8] {
        KRBError(stime: KerberosTime(Date()), errorCode: code, realm: store.realm,
                 sname: .krbtgt(realm: store.realm)).encode()
    }
}
