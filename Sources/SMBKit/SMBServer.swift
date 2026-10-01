import AuthKit
import Foundation
import NIOCore
import NIOPosix
import SheepCrypto
import Store
import Synchronization
import os

/// Protocol limits and identity of an `SMBServer`.
public struct SMBServerConfig: Sendable {
    /// ServerGuid of NEGOTIATE / VALIDATE_NEGOTIATE_INFO (16 bytes, wire order). Stable per DC:
    /// `from(store:)` uses the domain GUID.
    public var serverGUID: [UInt8]
    /// Dialects offered, a subset of `SMB2Dialect.all`.
    public var dialects: [UInt16]
    /// NEGOTIATE SecurityMode SIGNING_REQUIRED, and every authenticated request must be signed.
    public var requireSigning: Bool
    /// MaxTransactSize/MaxReadSize/MaxWriteSize for 2.1+ (2.0.2 always gets 64 KiB).
    public var maxIOSize: UInt32
    /// Upper bound of the credits a client holds.
    public var maxCredits: UInt16
    /// The IPv4 FSCTL_QUERY_NETWORK_INTERFACE_INFO reports; nil uses the connection's local address.
    public var advertisedIPv4: String?
    /// Link speed reported per interface (bits per second).
    public var linkSpeed: UInt64
    /// How long a READ on an empty pipe waits for the service to produce data.
    public var pipeReadTimeout: Duration
    public var eventLoopThreads: Int
    public var clock: @Sendable () -> Date
    public var rng: RandomBytes

    public init(serverGUID: [UInt8], dialects: [UInt16] = SMB2Dialect.all, requireSigning: Bool = true,
                maxIOSize: UInt32 = 1 << 20, maxCredits: UInt16 = 128, advertisedIPv4: String? = nil,
                linkSpeed: UInt64 = 1_000_000_000, pipeReadTimeout: Duration = .seconds(5), eventLoopThreads: Int = 2,
                clock: @escaping @Sendable () -> Date = { Date() }, rng: RandomBytes = RandomBytes()) {
        precondition(serverGUID.count == 16, "serverGUID must be 16 bytes")
        self.serverGUID = serverGUID
        self.dialects = dialects
        self.requireSigning = requireSigning
        self.maxIOSize = maxIOSize
        self.maxCredits = maxCredits
        self.advertisedIPv4 = advertisedIPv4
        self.linkSpeed = linkSpeed
        self.pipeReadTimeout = pipeReadTimeout
        self.eventLoopThreads = eventLoopThreads
        self.clock = clock
        self.rng = rng
    }

    /// The configuration of a DC over a provisioned store (server GUID = domain GUID).
    public static func from(store: DirectoryStore) async throws -> SMBServerConfig {
        let info = try await store.domainInfo()
        return SMBServerConfig(serverGUID: info.domainGUID.bytes)
    }
}

/// Which authentication SESSION_SETUP accepts.
public struct SMBAuthPolicy: Sendable {
    /// Kerberos (and MS-KRB5) through SPNEGO.
    public var kerberos: Bool
    /// NTLMv2 through SPNEGO (and raw NTLMSSP).
    public var ntlm: Bool
    /// NTLM anonymous (null) sessions, which may then only use IPC$. Off by default.
    public var allowAnonymousIPC: Bool
    /// Kerberos authenticator replay cache (share it with other acceptors of the same keys).
    public var replayCache: ReplayCache

    public init(kerberos: Bool = true, ntlm: Bool = true, allowAnonymousIPC: Bool = false,
                replayCache: ReplayCache = ReplayCache()) {
        self.kerberos = kerberos
        self.ntlm = ntlm
        self.allowAnonymousIPC = allowAnonymousIPC
        self.replayCache = replayCache
    }
}

/// Everything a connection shares with the others.
final class SMBServerContext: Sendable {
    let shares: [SMBShare]
    let auth: SMBAuthPolicy
    let secrets: any AuthSecretSource
    let config: SMBServerConfig
    let logger = Logger(subsystem: "dev.labdc.app", category: "smb")
    private let pipes: Mutex<[String: any NamedPipeService]>
    /// Test hook (never set in production, never logged): the SessionId and keys of each
    /// established session, so a test can hand them to Wireshark.
    let sessionKeyObserver = Mutex<(@Sendable (UInt64, SMBCrypto.SessionKeys) -> Void)?>(nil)
    private let nextSession = Atomic<UInt64>(0)

    init(shares: [SMBShare], pipes: [any NamedPipeService], auth: SMBAuthPolicy, secrets: any AuthSecretSource,
         config: SMBServerConfig) {
        self.shares = shares
        self.auth = auth
        self.secrets = secrets
        self.config = config
        var map: [String: any NamedPipeService] = [:]
        for p in pipes { map[PipeName.normalize(p.pipeName)] = p }
        self.pipes = Mutex(map)
        // Session ids: a random high half, a counter low half (never 0, never all ones).
        let seed = config.rng.next(4).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } & 0x7FFF_FFFF
        nextSession.store((seed | 1) << 32, ordering: .relaxed)
    }

    func register(_ pipe: any NamedPipeService) {
        pipes.withLock { $0[PipeName.normalize(pipe.pipeName)] = pipe }
    }

    func pipe(named name: String) -> (any NamedPipeService)? {
        pipes.withLock { $0[PipeName.normalize(name)] }
    }

    var pipeNames: [String] { pipes.withLock { Array($0.keys) } }

    func share(named name: String) -> SMBShare? {
        shares.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }

    func newSessionID() -> UInt64 { nextSession.wrappingAdd(1, ordering: .relaxed).newValue }

    func spnego() -> SPNEGOAcceptor {
        SPNEGOAcceptor(kerberos: auth.kerberos ? kerberosAcceptor() : nil, ntlm: auth.ntlm ? ntlmServer() : nil)
    }

    func kerberosAcceptor() -> KerberosAcceptor {
        KerberosAcceptor(source: secrets, replayCache: auth.replayCache, clock: config.clock)
    }

    func ntlmServer() -> NTLMServer {
        NTLMServer(source: secrets, allowAnonymous: auth.allowAnonymousIPC, clock: config.clock, rng: config.rng)
    }
}

/// The SMB2/3 server: NetBIOS-framed TCP (445 by default) on SwiftNIO, SESSION_SETUP through
/// AuthKit SPNEGO, signing, IPC$ named pipes bound to `NamedPipeService`s and read-only
/// folder shares.
public final class SMBServer: Sendable {
    public let port: Int
    /// WP-AR2: an optional second listener for the NetBIOS session service (tcp 139). It shares this
    /// server's context (shares, pipes, sessions); `NetBIOSFrameDecoder` answers its 0x81 session
    /// request with 0x82 and then carries SMB exactly as on 445. nil: 445 only.
    public let netbiosPort: Int?
    public let bindAddresses: [String]
    let context: SMBServerContext
    private let logger = Logger(subsystem: "dev.labdc.app", category: "smb")

    private struct State {
        var group: MultiThreadedEventLoopGroup?
        var listeners: [Channel] = []
        var port: Int?
        var netbiosPort: Int?
    }

    private let state = Mutex(State())

    /// - Parameters:
    ///   - port: 445; 0 picks an ephemeral port (see `boundPort`).
    ///   - netbiosPort: 139 for the NetBIOS session service, 0 ephemeral, nil none (see `boundNetbiosPort`).
    ///   - bindAddresses: `0.0.0.0` and `::` (V6ONLY) by default.
    ///   - shares: typically `SMBShare.domainController(sysvol:dnsDomain:)`.
    ///   - pipes: named pipe services (more can be added with `register(pipe:)`).
    public init(port: Int = 445, netbiosPort: Int? = nil, bindAddresses: [String] = ["0.0.0.0", "::"], shares: [SMBShare],
                pipes: [any NamedPipeService] = [], auth: SMBAuthPolicy = SMBAuthPolicy(), secrets: any AuthSecretSource,
                config: SMBServerConfig) {
        self.port = port
        self.netbiosPort = netbiosPort
        self.bindAddresses = bindAddresses
        context = SMBServerContext(shares: shares, pipes: pipes, auth: auth, secrets: secrets, config: config)
    }

    /// Adds (or replaces) the service for `pipe.pipeName`; takes effect for later CREATEs.
    public func register(pipe: any NamedPipeService) {
        context.register(pipe)
    }

    /// The port actually bound (after `start()`).
    public var boundPort: Int? { state.withLock { $0.port } }

    /// The NetBIOS session port actually bound (after `start()`), nil when not requested.
    public var boundNetbiosPort: Int? { state.withLock { $0.netbiosPort } }

    public func start() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: max(1, context.config.eventLoopThreads))
        let started = state.withLock { s -> Bool in
            if s.group != nil { return true }
            s.group = group
            return false
        }
        if started {
            try? await group.shutdownGracefully()
            throw SMBKitError.alreadyStarted
        }
        do {
            let bound = try await bind(port, group: group)
            state.withLock { $0.port = bound }
            logger.info("SMB listening on port \(bound)")
            if let netbiosPort {
                let nb = try await bind(netbiosPort, group: group)
                state.withLock { $0.netbiosPort = nb }
                logger.info("SMB (NetBIOS session) listening on port \(nb)")
            }
        } catch {
            await stop()
            throw error
        }
    }

    /// Binds `port` on every bind address (all sharing `context`); returns the bound port.
    private func bind(_ port: Int, group: MultiThreadedEventLoopGroup) async throws -> Int {
        var bound = port
        var boundAny = false
        let context = context
        do {
            for address in bindAddresses {
                let isV6 = address.contains(":")
                var bootstrap = ServerBootstrap(group: group)
                    .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                    .serverChannelOption(.backlog, value: 256)
                    .childChannelOption(.socketOption(.so_keepalive), value: 1)
                    .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
                    .childChannelInitializer { channel in
                        channel.eventLoop.makeCompletedFuture {
                            let sync = channel.pipeline.syncOperations
                            try sync.addHandler(ByteToMessageHandler(NetBIOSFrameDecoder()))
                            try sync.addHandler(SMBChannelHandler(context: context))
                        }
                    }
                if isV6 {
                    bootstrap = bootstrap.serverChannelOption(
                        ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only), value: 1)
                }
                do {
                    let channel = try await bootstrap.bind(host: address, port: bound).get()
                    state.withLock { $0.listeners.append(channel) }
                    if bound == 0, let p = channel.localAddress?.port { bound = p }
                    boundAny = true
                } catch {
                    if boundAny || (isV6 && bindAddresses.count > 1 && address != bindAddresses.first) {
                        logger.warning("SMB on [\(address, privacy: .public)]:\(bound): \(String(describing: error), privacy: .public)")
                        continue
                    }
                    throw SMBKitError.listener("\(address):\(port): \(error)")
                }
            }
            guard boundAny else { throw SMBKitError.listener("no address could be bound") }
        }
        return bound
    }

    /// Closes the listeners and every connection (open pipes are closed).
    public func stop() async {
        let (group, listeners) = state.withLock { s -> (MultiThreadedEventLoopGroup?, [Channel]) in
            defer {
                s.group = nil
                s.listeners = []
                s.port = nil
                s.netbiosPort = nil
            }
            return (s.group, s.listeners)
        }
        for l in listeners { try? await l.close() }
        try? await group?.shutdownGracefully()
    }
}

/// Direct-TCP / NetBIOS session framing (MS-SMB2 §2.1, RFC 1002 §4.3): a 4-byte header
/// `type(1) | length(3, big endian)`. Type 0x00 carries an SMB message; 0x85 keepalives are
/// dropped; a 0x81 session request (port 139 style) gets a positive response 0x82.
struct NetBIOSFrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = [UInt8]
    static let maxFrame = 0x00FF_FFFF

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard buffer.readableBytes >= 4, let head = buffer.getBytes(at: buffer.readerIndex, length: 4) else {
            return .needMoreData
        }
        let length = Int(head[1]) << 16 | Int(head[2]) << 8 | Int(head[3])
        guard buffer.readableBytes >= 4 + length else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 4)
        let payload = buffer.readBytes(length: length) ?? []
        switch head[0] {
        case 0x00:
            context.fireChannelRead(wrapInboundOut(payload))
        case 0x81:
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: [0x82, 0, 0, 0])), promise: nil)
        case 0x85:
            break
        default:
            throw SMBKitError.protocolViolation("NetBIOS session packet type 0x\(String(head[0], radix: 16))")
        }
        return .continue
    }

    mutating func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        while try decode(context: context, buffer: &buffer) == .continue {}
        return .needMoreData
    }

    static func frame(_ pdu: [UInt8]) -> [UInt8] {
        [0, UInt8((pdu.count >> 16) & 0xFF), UInt8((pdu.count >> 8) & 0xFF), UInt8(pdu.count & 0xFF)] + pdu
    }
}

/// Feeds frames to the connection's serial processing task and writes its answers.
final class SMBChannelHandler: ChannelInboundHandler {
    typealias InboundIn = [UInt8]

    private let server: SMBServerContext
    private var continuation: AsyncStream<[UInt8]>.Continuation?

    init(context: SMBServerContext) { server = context }

    func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive { start(context) }
    }

    func channelActive(context: ChannelHandlerContext) {
        start(context)
        context.fireChannelActive()
    }

    private func start(_ ctx: ChannelHandlerContext) {
        guard continuation == nil else { return }
        let (stream, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        self.continuation = continuation
        let channel = ctx.channel
        let connection = SMBConnection(server: server, clientAddress: Self.describe(ctx.remoteAddress),
                                       localAddress: ctx.localAddress)
        Task {
            for await frame in stream {
                let out = await connection.process(frame)
                if let pdu = out.response {
                    let framed = NetBIOSFrameDecoder.frame(pdu)
                    channel.writeAndFlush(channel.allocator.buffer(bytes: framed), promise: nil)
                }
                if out.close {
                    channel.close(promise: nil)
                    break
                }
            }
            await connection.shutdown()
        }
    }

    static func describe(_ a: SocketAddress?) -> String {
        guard let a else { return "?" }
        if let ip = a.ipAddress, let port = a.port { return a.protocol == .inet6 ? "[\(ip)]:\(port)" : "\(ip):\(port)" }
        return "\(a)"
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        continuation?.yield(unwrapInboundIn(data))
    }

    func channelInactive(context: ChannelHandlerContext) {
        continuation?.finish()
        continuation = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        server.logger.info("SMB connection \(String(describing: context.remoteAddress), privacy: .public): \(String(describing: error), privacy: .public)")
        continuation?.finish()
        continuation = nil
        context.close(promise: nil)
    }
}
