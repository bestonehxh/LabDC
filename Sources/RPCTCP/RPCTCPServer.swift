import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import RPCKit

/// The interfaces and per-connection auth provider a `ncacn_ip_tcp` endpoint presents. The
/// interfaces are shared across connections (their per-call state lives in each connection's handle
/// table, exactly as the SMB pipes share them); the auth provider is built fresh per connection.
public struct RPCTCPEndpointSetup: Sendable {
    public var interfaces: [any RPCInterface]
    public var makeAuthProvider: @Sendable () -> any RPCAuthProvider
    /// WP-AJ: a connection with no traffic in either direction for this long is closed. Nil (the
    /// default) disables the timeout: a Windows member keeps its Netlogon secure-channel connection
    /// open and reuses it for hours; when the DC closed it after 30 s (26 Sep 2026 capture) the next
    /// call found a dead socket, Netlogon reported ERROR_NO_LOGON_SERVERS, SID lookups came back
    /// "Unknown SID type" and the member re-authenticated every minute. A real DC never closes them.
    public var idleTimeout: TimeAmount?

    /// The default idle timeout: none.
    public static let defaultIdleTimeout: TimeAmount? = nil

    public init(interfaces: [any RPCInterface],
                makeAuthProvider: @escaping @Sendable () -> any RPCAuthProvider = { NoAuthProvider() },
                idleTimeout: TimeAmount? = RPCTCPEndpointSetup.defaultIdleTimeout) {
        self.interfaces = interfaces
        self.makeAuthProvider = makeAuthProvider
        self.idleTimeout = idleTimeout
    }
}

/// A DCERPC connection-oriented server over `ncacn_ip_tcp` (MS-RPCE). Each accepted TCP connection
/// gets its own `RPCServerConnection` driven over a `NIORPCTransport`; the identity comes solely from
/// the RPC auth provider (there is no SMB session here). Raw PDU bytes stream in and out with no
/// intermediate framing — `RPCServerConnection` frames by `frag_length` itself.
///
/// One server instance hosts one endpoint (one port, one interface set). The endpoint mapper on
/// port 135 and the shared dynamic port for LSARPC/SAMR/NETLOGON are two instances.
public final class RPCTCPServer: @unchecked Sendable {
    public let requestedPort: Int
    private let bindAddresses: [String]
    private let setup: RPCTCPEndpointSetup

    private struct State {
        var group: MultiThreadedEventLoopGroup?
        var listeners: [Channel] = []
        var boundPort: Int?
    }
    private let state = NIOLockedValueBox(State())

    /// - Parameters:
    ///   - port: the TCP port to bind; 0 asks the OS for an ephemeral port (read back via `boundPort`).
    ///   - bindAddresses: the addresses to bind (default IPv4 + IPv6 wildcard).
    public init(port: Int, bindAddresses: [String] = ["0.0.0.0", "::"], setup: RPCTCPEndpointSetup) {
        self.requestedPort = port
        self.bindAddresses = bindAddresses
        self.setup = setup
    }

    /// The port actually bound (equals `requestedPort` unless it was 0).
    public var boundPort: Int? { state.withLockedValue { $0.boundPort } }

    public func start() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        state.withLockedValue { $0.group = group }
        let setup = self.setup
        var bound = requestedPort
        var boundAny = false
        for address in bindAddresses {
            let isV6 = address.contains(":")
            var bootstrap = ServerBootstrap(group: group)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .serverChannelOption(.backlog, value: 128)
                .childChannelOption(.socketOption(.so_keepalive), value: 1)
                .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
                .childChannelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        let remote = channel.remoteAddress?.ipAddress ?? "tcp:peer"
                        let inbox = RPCByteInbox()
                        let transport = NIORPCTransport(channel: channel, inbox: inbox, remoteAddress: remote)
                        let connection = RPCServerConnection(transport: transport,
                                                             authProvider: setup.makeAuthProvider())
                        for iface in setup.interfaces { connection.register(iface) }
                        if let idle = setup.idleTimeout {
                            try channel.pipeline.syncOperations.addHandler(IdleStateHandler(allTimeout: idle))
                        }
                        try channel.pipeline.syncOperations.addHandler(RPCInboundHandler(inbox: inbox))
                        // Drive the connection until the transport closes, then close the socket.
                        // WP-AJ: `run()` ending (shutdown PDU, an auth error, a malformed PDU) used to
                        // leave the TCP connection open with nobody reading it, so the client waited
                        // for its own timeout; now it sees the close at once.
                        Task {
                            try? await connection.run()
                            inbox.close()
                            if channel.isActive { channel.close(promise: nil) }
                        }
                    }
                }
            if isV6 {
                bootstrap = bootstrap.serverChannelOption(
                    ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only), value: 1)
            }
            do {
                let channel = try await bootstrap.bind(host: address, port: bound).get()
                state.withLockedValue { $0.listeners.append(channel) }
                if bound == 0, let p = channel.localAddress?.port { bound = p }
                boundAny = true
            } catch {
                // If IPv4 already bound, tolerate an IPv6 failure (dual-stack hosts vary); otherwise fail.
                if boundAny { continue }
                if isV6 && bindAddresses.count > 1 && address != bindAddresses.first { continue }
                try? await group.shutdownGracefully()
                state.withLockedValue { $0.group = nil }
                throw RPCTCPError.listener("\(address):\(bound): \(error)")
            }
        }
        guard boundAny else {
            try? await group.shutdownGracefully()
            throw RPCTCPError.listener("no address could be bound for port \(requestedPort)")
        }
        state.withLockedValue { $0.boundPort = bound }
    }

    public func stop() async {
        let (chans, g): ([Channel], MultiThreadedEventLoopGroup?) = state.withLockedValue {
            let c = $0.listeners; $0.listeners = []
            let group = $0.group; $0.group = nil
            return (c, group)
        }
        for c in chans { try? await c.close() }
        if let g { try? await g.shutdownGracefully() }
    }
}

public enum RPCTCPError: Error, CustomStringConvertible, Sendable {
    case listener(String)
    public var description: String {
        switch self { case .listener(let s): return "RPC TCP listener: \(s)" }
    }
}
