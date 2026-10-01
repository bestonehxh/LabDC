import Darwin
import Foundation
import Network
import Synchronization
import os

/// UDP and TCP listeners (Network.framework) on one port in front of a `DNSResponder`.
///
/// Binds the wildcard address only; Network.framework's wildcard listener is dual-stack,
/// so `0.0.0.0` and `::` are both served (wp-e.md). Before binding, the port is probed with
/// BSD sockets on `0.0.0.0` and `::` (UDP exclusive; TCP with SO_REUSEADDR so a TIME_WAIT
/// does not count); if anything holds it the server refuses to start and reports the holder
/// from `lsof`.
///
/// UDP: one datagram in, one out, 512-byte limit without EDNS (TC bit), EDNS clients up to
/// 4096. TCP: 2-byte length framing, several queries per connection, 10 s idle close.
/// `stop()` closes the listeners and every open connection.
public final class DNSServer: @unchecked Sendable {
    public let responder: DNSResponder
    private let requestedPort: UInt16
    private let queue = DispatchQueue(label: "dev.labdc.app.dns-server")
    private let listeners = Mutex<(udp: NWListener?, tcp: NWListener?)>((nil, nil))
    /// Live UDP flows and TCP connections, cancelled by `stop()`.
    private let connections = Mutex<[ObjectIdentifier: NWConnection]>([:])
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "DNS")
    static let udpIdleTimeout: TimeInterval = 30
    static let tcpIdleTimeout: TimeInterval = 10

    /// - Parameters:
    ///   - source: domain facts and stored records (Store adapter in WP-P, `InMemoryZoneSource` in tests).
    ///   - port: 53 by default; 0 picks an ephemeral port (tests).
    ///   - forwarder: resolver for foreign names; nil answers them REFUSED.
    public convenience init(source: any DNSZoneSource, port: UInt16 = 53, forwarder: DNSForwarder? = DNSForwarder()) {
        self.init(responder: DNSResponder(source: source, forwarder: forwarder), port: port)
    }

    public init(responder: DNSResponder, port: UInt16 = 53) {
        self.responder = responder
        self.requestedPort = port
    }

    /// The bound port (useful when 0 was requested). Valid after `start()`.
    public var port: UInt16 {
        listeners.withLock { $0.udp?.port?.rawValue } ?? requestedPort
    }

    /// Starts UDP then TCP on the same port; returns when both are ready.
    /// - Throws: `DNSKitError.portInUse` (with `lsof` output) or `.listener`.
    public func start() async throws {
        if requestedPort != 0 { try Self.ensurePortFree(requestedPort) }
        // An ephemeral UDP port may be taken for TCP by someone else: try a few.
        let attempts = requestedPort == 0 ? 5 : 1
        for attempt in 1...attempts {
            do {
                try await startOnce()
                return
            } catch {
                stop()
                if attempt == attempts { throw error }
            }
        }
    }

    private func startOnce() async throws {
        let udp = try makeListener(.udp, port: requestedPort)
        udp.newConnectionHandler = { [weak self] conn in self?.acceptUDP(conn) }
        listeners.withLock { $0.udp = udp }
        try await Self.waitReady(udp, queue: queue, what: "udp")
        guard let bound = udp.port?.rawValue else { throw DNSKitError.listener("udp listener has no port") }
        let tcp = try makeListener(.tcp, port: bound)
        tcp.newConnectionHandler = { [weak self] conn in self?.acceptTCP(conn) }
        listeners.withLock { $0.tcp = tcp }
        try await Self.waitReady(tcp, queue: queue, what: "tcp")
        Self.logger.notice("DNS listening on udp+tcp port \(bound)")
    }

    /// Cancels the listeners and every open connection.
    public func stop() {
        listeners.withLock {
            $0.udp?.cancel()
            $0.tcp?.cancel()
            $0 = (nil, nil)
        }
        let open = connections.withLock { all in
            defer { all = [:] }
            return Array(all.values)
        }
        for conn in open { conn.cancel() }
    }

    /// Starts `conn` and remembers it until it ends.
    private func track(_ conn: NWConnection) {
        let id = ObjectIdentifier(conn)
        connections.withLock { $0[id] = conn }
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed:
                conn.cancel()
            case .cancelled:
                self?.connections.withLock { $0[id] = nil }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func makeListener(_ base: NWParameters, port: UInt16) throws -> NWListener {
        let params = base.copy()
        // Exclusive (no SO_REUSEPORT): never share the port with another listener. A TCP
        // TIME_WAIT on the port does not block the bind (tested by a restart test).
        params.allowLocalEndpointReuse = false
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw DNSKitError.listener("bad port \(port)") }
        do { return try NWListener(using: params, on: nwPort) } catch {
            throw DNSKitError.listener("cannot create listener on port \(port): \(error)")
        }
    }

    private static func waitReady(_ listener: NWListener, queue: DispatchQueue, what: String) async throws {
        let resumed = Mutex(false)
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            let finish: @Sendable (Result<Void, DNSKitError>) -> Void = { result in
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

    // MARK: Port probe

    /// Throws `.portInUse` when UDP on 0.0.0.0/:: cannot be bound exclusively, or TCP cannot
    /// be bound with SO_REUSEADDR (which ignores TIME_WAIT but not a live listener).
    static func ensurePortFree(_ port: UInt16) throws {
        for (family, type) in [(AF_INET, SOCK_DGRAM), (AF_INET6, SOCK_DGRAM), (AF_INET, SOCK_STREAM), (AF_INET6, SOCK_STREAM)] {
            let result = probeBind(family: family, type: type, port: port)
            if result == EADDRINUSE {
                let holder = lsof(port)
                logger.error("port \(port) is in use; holder: \(holder, privacy: .public)")
                throw DNSKitError.portInUse(port: port, holder: holder)
            }
            if result == EACCES {
                throw DNSKitError.listener("binding port \(port) is not permitted (EACCES)")
            }
        }
    }

    /// 0 when a wildcard bind of (family, type, port) succeeds, else errno.
    static func probeBind(family: Int32, type: Int32, port: UInt16) -> Int32 {
        let fd = socket(family, type, 0)
        guard fd >= 0 else { return 0 }                  // family unavailable: nothing to probe
        defer { close(fd) }
        if type == SOCK_STREAM {
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        }
        var rc: Int32
        if family == AF_INET {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr = in_addr(s_addr: INADDR_ANY)
            rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        } else {
            var one: Int32 = 1
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            addr.sin6_addr = in6addr_any
            rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        return rc == 0 ? 0 : errno
    }

    /// `lsof -nP -iUDP:<port> -iTCP:<port>` output (only processes visible to this user).
    static func lsof(_ port: UInt16) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-iUDP:\(port)", "-iTCP:\(port)"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? "(lsof shows no holder visible to this user; try `sudo lsof -nP -iUDP:\(port)`)" : text
        } catch {
            return "(lsof failed: \(error))"
        }
    }

    // MARK: Connections

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

    private func acceptUDP(_ conn: NWConnection) {
        track(conn)
        queue.asyncAfter(deadline: .now() + Self.udpIdleTimeout) { conn.cancel() }
        receiveUDP(conn, from: Self.describe(conn.endpoint))
    }

    private func receiveUDP(_ conn: NWConnection, from: String) {
        conn.receiveMessage { [responder] data, _, _, error in
            if let data, !data.isEmpty {
                let request = [UInt8](data)
                Task {
                    if let reply = await responder.handle(request, transport: .udp, from: from) {
                        conn.send(content: Data(reply), completion: .contentProcessed { _ in })
                    }
                }
            }
            if error == nil {
                self.receiveUDP(conn, from: from)
            } else {
                conn.cancel()
            }
        }
    }

    private func acceptTCP(_ conn: NWConnection) {
        track(conn)
        readTCP(conn, from: Self.describe(conn.endpoint), buffer: DNSTCPFraming.Deframer())
    }

    private func readTCP(_ conn: NWConnection, from: String, buffer: DNSTCPFraming.Deframer) {
        var buffer = buffer
        if let request = buffer.next() {
            let pending = buffer
            Task { [responder] in
                guard let reply = await responder.handle(request, transport: .tcp, from: from) else {
                    self.readTCP(conn, from: from, buffer: pending)
                    return
                }
                conn.send(content: Data(DNSTCPFraming.frame(reply)), completion: .contentProcessed { error in
                    if error != nil { conn.cancel() } else { self.readTCP(conn, from: from, buffer: pending) }
                })
            }
            return
        }
        let received = Mutex(false)
        queue.asyncAfter(deadline: .now() + Self.tcpIdleTimeout) {
            if !received.withLock({ $0 }) { conn.cancel() }
        }
        let current = buffer
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65537) { data, _, isComplete, error in
            received.withLock { $0 = true }
            if let data, !data.isEmpty {
                var next = current
                next.append(data)
                self.readTCP(conn, from: from, buffer: next)
            } else if isComplete || error != nil {
                conn.cancel()
            } else {
                self.readTCP(conn, from: from, buffer: current)
            }
        }
    }
}
