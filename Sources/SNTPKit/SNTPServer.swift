import Darwin
import Foundation
import Network
import Synchronization
import os

/// SNTP server on UDP (Network.framework), the DNSKit `DNSServer` pattern (wp-h.md): one
/// wildcard listener, which Network.framework makes dual-stack (0.0.0.0 and ::). Before binding a
/// fixed port it probes 0.0.0.0 and :: with exclusive BSD binds and refuses to start, naming the
/// holder from `lsof`, when anything (for example `timed`/`ntpd`) has the port.
public final class SNTPServer: @unchecked Sendable {
    public let responder: SNTPResponder
    private let requestedPort: UInt16
    private let queue = DispatchQueue(label: "dev.labdc.app.sntp-server")
    private let listener = Mutex<NWListener?>(nil)
    private let flows = Mutex<[ObjectIdentifier: NWConnection]>([:])
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "SNTP")
    static let flowIdleTimeout: TimeInterval = 30

    /// - Parameters:
    ///   - port: 123 by default; 0 picks an ephemeral port (tests).
    ///   - stratum: advertised stratum (2: "synchronised to something", which Windows requires).
    ///   - referenceID: 4 ASCII characters.
    ///   - clock: time source (injected by tests).
    ///   - keyProvider: NT hash by RID for MS-SNTP signed replies (nil: never sign).
    ///   - answerUnauthenticated: answer MS-SNTP requests without a key with a plain 48-byte reply.
    public convenience init(port: UInt16 = 123, stratum: UInt8 = 2, referenceID: String = "LOCL",
                            clock: @escaping @Sendable () -> Date = { Date() },
                            keyProvider: SNTPKeyProvider? = nil, answerUnauthenticated: Bool = true) {
        self.init(responder: SNTPResponder(stratum: stratum, referenceID: referenceID,
                                           answerUnauthenticated: answerUnauthenticated,
                                           keyProvider: keyProvider, clock: clock), port: port)
    }

    public init(responder: SNTPResponder, port: UInt16 = 123) {
        self.responder = responder
        self.requestedPort = port
    }

    /// The bound port (useful when 0 was requested). Valid after `start()`.
    public var port: UInt16 { listener.withLock { $0?.port?.rawValue } ?? requestedPort }

    /// Starts the UDP listener; returns when it is ready.
    /// - Throws: `SNTPKitError.portInUse` (with `lsof` output) or `.listener`.
    public func start() async throws {
        if requestedPort != 0 { try Self.ensurePortFree(requestedPort) }
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = false
        guard let nwPort = NWEndpoint.Port(rawValue: requestedPort) else {
            throw SNTPKitError.listener("bad port \(requestedPort)")
        }
        let l: NWListener
        do { l = try NWListener(using: params, on: nwPort) } catch {
            throw SNTPKitError.listener("cannot create listener on port \(requestedPort): \(error)")
        }
        l.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        listener.withLock { $0 = l }
        do {
            try await Self.waitReady(l, queue: queue)
        } catch {
            stop()
            throw error
        }
        Self.logger.notice("SNTP listening on udp port \(self.port)")
    }

    /// Cancels the listener and every open flow.
    public func stop() {
        listener.withLock {
            $0?.cancel()
            $0 = nil
        }
        let open = flows.withLock { all in
            defer { all = [:] }
            return Array(all.values)
        }
        for conn in open { conn.cancel() }
    }

    private static func waitReady(_ listener: NWListener, queue: DispatchQueue) async throws {
        let resumed = Mutex(false)
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            let finish: @Sendable (Result<Void, SNTPKitError>) -> Void = { result in
                let first = resumed.withLock { done in
                    defer { done = true }
                    return !done
                }
                if first { c.resume(with: result.mapError { $0 as any Error }) }
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
                case .failed(let e): finish(.failure(.listener("udp: \(e)")))
                case .waiting(let e): finish(.failure(.listener("udp: \(e)")))
                case .cancelled: finish(.failure(.listener("udp: cancelled")))
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    // MARK: Flows

    private func accept(_ conn: NWConnection) {
        let id = ObjectIdentifier(conn)
        flows.withLock { $0[id] = conn }
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed: conn.cancel()
            case .cancelled: self?.flows.withLock { $0[id] = nil }
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.flowIdleTimeout) { conn.cancel() }
        receive(conn)
    }

    private func receive(_ conn: NWConnection) {
        conn.receiveMessage { [responder] data, _, _, error in
            let receivedAt = responder.clock()
            if let data, !data.isEmpty {
                let request = [UInt8](data)
                Task {
                    if let reply = await responder.reply(to: request, receivedAt: receivedAt) {
                        conn.send(content: Data(reply), completion: .contentProcessed { _ in })
                    }
                }
            }
            if error == nil { self.receive(conn) } else { conn.cancel() }
        }
    }

    // MARK: Port probe

    /// Throws `.portInUse` when UDP on 0.0.0.0 or :: cannot be bound exclusively.
    static func ensurePortFree(_ port: UInt16) throws {
        for family in [AF_INET, AF_INET6] {
            let rc = probeBind(family: family, port: port)
            if rc == EADDRINUSE {
                let holder = lsof(port)
                logger.error("udp port \(port) is in use; holder: \(holder, privacy: .public)")
                throw SNTPKitError.portInUse(port: port, holder: holder)
            }
            if rc == EACCES { throw SNTPKitError.listener("binding udp port \(port) is not permitted (EACCES)") }
        }
    }

    /// 0 when a wildcard UDP bind of (family, port) succeeds, else errno.
    static func probeBind(family: Int32, port: UInt16) -> Int32 {
        let fd = socket(family, SOCK_DGRAM, 0)
        guard fd >= 0 else { return 0 }
        defer { close(fd) }
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

    /// `lsof -nP -iUDP:<port>` output (only processes visible to this user).
    static func lsof(_ port: UInt16) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-iUDP:\(port)"]
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
}
