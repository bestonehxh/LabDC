import Darwin
import Foundation
import Network
import Store
import Synchronization
import os

/// Settings of a `CLDAPServer`.
public struct CLDAPServerConfig: Sendable {
    /// UDP port; 389 by default, 0 picks an ephemeral port (tests).
    public var port: UInt16
    /// IPv4 address for `DcSockAddr` (`V5EX_WITH_IP`) and `DcIpAddress` (V5). nil uses the
    /// address the ping arrived on, else the first non-loopback IPv4 (`NetlogonAddress.select`).
    public var advertisedIPv4: String?
    /// `DS_FLAG` bits announced in every ping answer.
    public var flags: NetlogonDSFlags
    /// `vendorVersion` of the RootDSE (keep it equal to `DirectoryServerConfig.vendorVersion`).
    public var vendorVersion: String
    /// `currentTime` of the RootDSE.
    public var clock: @Sendable () -> Date

    public init(port: UInt16 = 389, advertisedIPv4: String? = nil, flags: NetlogonDSFlags = .sheepDC,
                vendorVersion: String = DirectoryServerConfig().vendorVersion,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.port = port
        self.advertisedIPv4 = advertisedIPv4
        self.flags = flags
        self.vendorVersion = vendorVersion
        self.clock = clock
    }
}

/// Connectionless LDAP (CLDAP) on UDP 389: LDAP pings (`Netlogon`, MS-ADTS §6.3.3) and
/// RootDSE searches, one request and one reply datagram each (see `CLDAPResponder`).
///
/// It uses a Network.framework UDP listener on the wildcard address. The listener is
/// dual-stack, so it serves both `0.0.0.0` and `::` (see wp-e.md). `DirectoryServer` binds
/// only TCP 389, so the two servers do not collide.
public final class CLDAPServer: Sendable {
    public let store: DirectoryStore
    public let config: CLDAPServerConfig

    private struct State {
        var listener: NWListener?
        var flows: [ObjectIdentifier: NWConnection] = [:]
        var responder: CLDAPResponder?
    }

    private let state = Mutex(State())
    private let queue = DispatchQueue(label: "dev.labdc.app.cldap")
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "CLDAP")
    /// A client's UDP flow is dropped after this long without datagrams.
    static let flowIdleTimeout: TimeInterval = 30

    public init(store: DirectoryStore, config: CLDAPServerConfig = CLDAPServerConfig()) {
        self.store = store
        self.config = config
    }

    /// The bound port (useful when 0 was requested); nil before `start()`.
    public var port: UInt16? { state.withLock { $0.listener?.port?.rawValue } }

    /// Binds the UDP listener and returns once it is ready.
    /// - Throws: `DirectoryKitError.notProvisioned`, `.alreadyStarted`, or `.listener` (the
    ///   port is held, or binding is not permitted).
    public func start() async throws {
        guard await store.isProvisioned else { throw DirectoryKitError.notProvisioned }
        let info = try await store.domainInfo()
        let responder = CLDAPResponder(store: store, info: info, config: config)
        if config.port != 0, let problem = Self.probeUDP(config.port) {
            throw DirectoryKitError.listener("CLDAP udp/\(config.port): \(problem)")
        }
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = false
        guard let nwPort = NWEndpoint.Port(rawValue: config.port) else {
            throw DirectoryKitError.listener("CLDAP: bad port \(config.port)")
        }
        let listener: NWListener
        do { listener = try NWListener(using: params, on: nwPort) } catch {
            throw DirectoryKitError.listener("CLDAP udp/\(config.port): \(error)")
        }
        let already = state.withLock { s -> Bool in
            if s.listener != nil { return true }
            s.listener = listener
            s.responder = responder
            return false
        }
        if already { throw DirectoryKitError.alreadyStarted }
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        do {
            try await waitReady(listener)
        } catch {
            stop()
            throw error
        }
        Self.logger.notice("CLDAP listening on udp port \(listener.port?.rawValue ?? 0)")
    }

    /// Cancels the listener and every client flow.
    public func stop() {
        let (listener, flows) = state.withLock { s -> (NWListener?, [NWConnection]) in
            defer {
                s.listener = nil
                s.flows = [:]
                s.responder = nil
            }
            return (s.listener, Array(s.flows.values))
        }
        listener?.cancel()
        for f in flows { f.cancel() }
    }

    private func waitReady(_ listener: NWListener) async throws {
        let resumed = Mutex(false)
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            let finish: @Sendable (Result<Void, DirectoryKitError>) -> Void = { result in
                let first = resumed.withLock { done in
                    defer { done = true }
                    return !done
                }
                if first { c.resume(with: result.mapError { $0 as any Error }) }
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
                case .failed(let e), .waiting(let e): finish(.failure(.listener("CLDAP: \(e)")))
                case .cancelled: finish(.failure(.listener("CLDAP: cancelled")))
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    // MARK: Flows

    private func accept(_ conn: NWConnection) {
        let id = ObjectIdentifier(conn)
        guard let responder = state.withLock({ s -> CLDAPResponder? in
            guard let r = s.responder else { return nil }
            s.flows[id] = conn
            return r
        }) else {
            conn.cancel()
            return
        }
        conn.stateUpdateHandler = { [weak self] st in
            switch st {
            case .failed: conn.cancel()
            case .cancelled: self?.state.withLock { _ = $0.flows.removeValue(forKey: id) }
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.flowIdleTimeout) { conn.cancel() }
        receive(conn, responder: responder)
    }

    private func receive(_ conn: NWConnection, responder: CLDAPResponder) {
        conn.receiveMessage { [weak self] data, _, _, error in
            if let data, !data.isEmpty {
                let request = [UInt8](data)
                let local = Self.host(conn.currentPath?.localEndpoint)
                let peer = Self.host(conn.endpoint) ?? "?"
                Task {
                    guard let reply = await responder.handle(request, localAddress: local) else {
                        Self.logger.debug("CLDAP from \(peer, privacy: .public): no reply to \(request.count) bytes")
                        return
                    }
                    Self.logger.info("CLDAP \(peer, privacy: .public) -> \(local ?? "?", privacy: .public): \(request.count) in, \(reply.count) out")
                    conn.send(content: Data(reply), completion: .contentProcessed { _ in })
                }
            }
            if error == nil {
                self?.receive(conn, responder: responder)
            } else {
                conn.cancel()
            }
        }
    }

    static func host(_ endpoint: NWEndpoint?) -> String? {
        guard case let .hostPort(host, _)? = endpoint else { return nil }
        switch host {
        case .ipv4(let a): return "\(a)"
        case .ipv6(let a): return "\(a)"
        case .name(let n, _): return n
        @unknown default: return nil
        }
    }

    /// nil when UDP `port` can be bound exclusively on `0.0.0.0` and `::`, else the problem.
    static func probeUDP(_ port: UInt16) -> String? {
        for family in [AF_INET, AF_INET6] {
            let fd = socket(family, SOCK_DGRAM, 0)
            guard fd >= 0 else { continue }
            defer { close(fd) }
            var rc: Int32
            if family == AF_INET {
                var addr = sockaddr_in()
                addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = port.bigEndian
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
            if rc != 0 {
                let e = errno
                if e == EADDRINUSE { return "port in use (see `lsof -nP -iUDP:\(port)`)" }
                if e == EACCES { return "binding is not permitted (EACCES)" }
                if e == EADDRNOTAVAIL, family == AF_INET6 { continue }
                return String(cString: strerror(e))
            }
        }
        return nil
    }
}
