import AuthKit
import Foundation
import LDAPCore
import NIOCore
import NIOPosix
import NIOSSL
import PKIKit
import Store
import Synchronization
import os

/// Listener and protocol limits of a `DirectoryServer`.
public struct DirectoryServerConfig: Sendable {
    /// Plain LDAP (StartTLS available). nil disables; 0 picks an ephemeral port.
    public var ldapPort: Int?
    /// LDAPS.
    public var ldapsPort: Int?
    /// Global catalog (phase 1: the same data as `ldapPort`).
    public var globalCatalogPort: Int?
    /// Global catalog over TLS.
    public var globalCatalogTLSPort: Int?
    /// Addresses every listener binds (wildcards `0.0.0.0` and `::` by default). The first one
    /// fixes an ephemeral port; the others reuse it.
    public var bindAddresses: [String]
    /// `MaxReceiveBuffer`: largest LDAP message accepted (10 MB, as AD).
    public var maxMessageSize: Int
    /// `MaxPageSize`: page size cap and the size limit of unpaged searches (1000, as AD).
    public var maxPageSize: Int
    /// `MaxValRange`: values per attribute before ranged retrieval kicks in (1500, as AD).
    public var maxValRange: Int
    /// `vendorVersion` in the RootDSE.
    public var vendorVersion: String
    /// Event loop threads of the server's own group.
    public var eventLoopThreads: Int
    /// The server's notion of now (`currentTime`, Kerberos authenticators).
    public var clock: @Sendable () -> Date
    /// `DS_FLAG` bits of LDAP ping answers over TCP (see `CLDAPServerConfig.flags`).
    public var netlogonFlags: NetlogonDSFlags = .sheepDC
    /// IPv4 address LDAP ping answers advertise; nil uses the connection's local address
    /// (see `NetlogonAddress.select`).
    public var advertisedIPv4: String?
    /// UI-1: one line per bind that names an account (`simple LABSHEEP\\alice from 192.0.2.7/ldaps -> OK as alice`,
    /// `GSS-SPNEGO ... -> invalidCredentials (52e)`) for the serve log and the app's activity list.
    public var onBind: (@Sendable (String) -> Void)?
    /// UI-1 ("Allow plain LDAP"): false refuses a simple bind with a password on a connection that is
    /// neither TLS nor SASL-sealed (strongerAuthRequired, like AD's LDAP signing requirement).
    public var allowPlainSimpleBind: Bool = true
    /// "Require LDAP signing" (AD's `LDAPServerIntegrity` = 2): a SASL bind on a connection without
    /// TLS must negotiate integrity (sign) or confidentiality (seal); one that completes without a
    /// layer is answered strongerAuthRequired. Simple binds stay governed by `allowPlainSimpleBind`.
    public var requireLDAPSigning: Bool = true
    /// "LDAP channel binding" (AD's `LdapEnforceChannelBinding`): how NTLM and Kerberos SASL binds
    /// over LDAPS / StartTLS must be bound to the TLS channel (EPA).
    public var ldapChannelBinding: ChannelBindingPolicy = .whenSupported

    public init(ldapPort: Int? = 389, ldapsPort: Int? = 636, globalCatalogPort: Int? = 3268,
                globalCatalogTLSPort: Int? = 3269, bindAddresses: [String] = ["0.0.0.0", "::"],
                maxMessageSize: Int = 10 * 1024 * 1024, maxPageSize: Int = 1000, maxValRange: Int = 1500,
                vendorVersion: String = "LabDC 1.0 (phase 1)", eventLoopThreads: Int = 2,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.ldapPort = ldapPort
        self.ldapsPort = ldapsPort
        self.globalCatalogPort = globalCatalogPort
        self.globalCatalogTLSPort = globalCatalogTLSPort
        self.bindAddresses = bindAddresses
        self.maxMessageSize = maxMessageSize
        self.maxPageSize = maxPageSize
        self.maxValRange = maxValRange
        self.vendorVersion = vendorVersion
        self.eventLoopThreads = eventLoopThreads
        self.clock = clock
    }

    /// Every listener on an ephemeral port, loopback only (tests).
    public static func ephemeralLoopback() -> DirectoryServerConfig {
        DirectoryServerConfig(ldapPort: 0, ldapsPort: 0, globalCatalogPort: 0, globalCatalogTLSPort: 0,
                              bindAddresses: ["127.0.0.1", "::1"])
    }
}

/// The ports the listeners actually bound (after `start()`).
public struct BoundPorts: Sendable, Hashable {
    public var ldap: Int?
    public var ldaps: Int?
    public var globalCatalog: Int?
    public var globalCatalogTLS: Int?
}

/// Which listener a connection arrived on.
enum ListenerKind: Sendable, Hashable, CaseIterable {
    case ldap, ldaps, globalCatalog, globalCatalogTLS

    var usesTLS: Bool { self == .ldaps || self == .globalCatalogTLS }
    var isGlobalCatalog: Bool { self == .globalCatalog || self == .globalCatalogTLS }
}

/// Everything a connection needs, shared by all connections.
final class ServerContext: Sendable {
    let store: DirectoryStore
    let info: DomainInfo
    let config: DirectoryServerConfig
    let secrets: StoreSecretSource
    let tls: NIOSSLContext?
    /// `tls-server-end-point` of the certificate `tls` presents (EPA).
    let channelBindings: ChannelBindings?
    let replayCache = ReplayCache()
    let logger = Logger(subsystem: "dev.labdc.app", category: "LDAP")

    init(store: DirectoryStore, info: DomainInfo, config: DirectoryServerConfig, secrets: StoreSecretSource, tls: NIOSSLContext?,
         channelBindings: ChannelBindings? = nil) {
        self.store = store
        self.info = info
        self.config = config
        self.secrets = secrets
        self.tls = tls
        self.channelBindings = channelBindings
    }

    var kerberosAcceptor: KerberosAcceptor { KerberosAcceptor(source: secrets, replayCache: replayCache, clock: config.clock) }

    /// The EPA check of a bind on a connection that is (`tls`) or is not on TLS.
    func channelBindingCheck(tls: Bool) -> ChannelBindingCheck {
        tls ? ChannelBindingCheck(policy: config.ldapChannelBinding, expected: channelBindings) : .none
    }
}

/// The AD-shaped LDAP server: SwiftNIO listeners for LDAP (389, StartTLS), LDAPS (636) and
/// the global catalog (3268/3269) over one `DirectoryStore`, with simple and SASL
/// (`GSSAPI`, `GSS-SPNEGO`) binds and the SASL security layer.
public final class DirectoryServer: Sendable {
    public let store: DirectoryStore
    /// Source of the TLS identity; without it LDAPS/GC-TLS listeners are skipped and StartTLS
    /// answers `unavailable`.
    public let pki: LabPKI?
    public let config: DirectoryServerConfig

    private struct State {
        var group: MultiThreadedEventLoopGroup?
        var listeners: [Channel] = []
        var ports = BoundPorts()
    }

    private let state = Mutex(State())
    private let logger = Logger(subsystem: "dev.labdc.app", category: "LDAP")

    public init(store: DirectoryStore, pki: LabPKI?, config: DirectoryServerConfig = DirectoryServerConfig()) {
        self.store = store
        self.pki = pki
        self.config = config
    }

    /// Bound ports; nil entries are disabled listeners.
    public var boundPorts: BoundPorts { state.withLock { $0.ports } }

    /// Binds every configured listener. On failure nothing stays bound.
    public func start() async throws {
        guard await store.isProvisioned else { throw DirectoryKitError.notProvisioned }
        let info = try await store.domainInfo()
        let secrets = try await StoreSecretSource(store: store)
        var tls: NIOSSLContext?
        var bindings: ChannelBindings?
        if let pki {
            do {
                let configuration = try await pki.serverTLSConfiguration()
                tls = try NIOSSLContext(configuration: configuration)
                bindings = configuration.tlsServerEndPoint
            } catch {
                throw DirectoryKitError.tls("\(error)")
            }
        }
        let context = ServerContext(store: store, info: info, config: config, secrets: secrets, tls: tls,
                                    channelBindings: bindings)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: max(1, config.eventLoopThreads))
        let started = state.withLock { s -> Bool in
            if s.group != nil { return true }
            s.group = group
            return false
        }
        if started {
            try? await group.shutdownGracefully()
            throw DirectoryKitError.alreadyStarted
        }

        do {
            var ports = BoundPorts()
            let plan: [(ListenerKind, Int?)] = [(.ldap, config.ldapPort), (.ldaps, config.ldapsPort),
                                                (.globalCatalog, config.globalCatalogPort),
                                                (.globalCatalogTLS, config.globalCatalogTLSPort)]
            for (kind, requested) in plan {
                guard let requested else { continue }
                if kind.usesTLS, tls == nil {
                    logger.notice("no PKI: \(String(describing: kind), privacy: .public) listener disabled")
                    continue
                }
                let port = try await bind(kind: kind, port: requested, group: group, context: context)
                switch kind {
                case .ldap: ports.ldap = port
                case .ldaps: ports.ldaps = port
                case .globalCatalog: ports.globalCatalog = port
                case .globalCatalogTLS: ports.globalCatalogTLS = port
                }
            }
            state.withLock { $0.ports = ports }
            logger.info("LDAP listening: \(String(describing: ports), privacy: .public)")
        } catch {
            await stop()
            throw error
        }
    }

    /// Binds `kind` on every address; the first address decides an ephemeral port.
    private func bind(kind: ListenerKind, port requested: Int, group: EventLoopGroup, context: ServerContext) async throws -> Int {
        var port = requested
        var boundAny = false
        for address in config.bindAddresses {
            let isV6 = address.contains(":")
            var bootstrap = ServerBootstrap(group: group)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .serverChannelOption(.backlog, value: 256)
                .childChannelOption(.socketOption(.so_keepalive), value: 1)
                .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
                .childChannelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try Self.initializeConnection(channel, kind: kind, context: context)
                    }
                }
            if isV6 {
                bootstrap = bootstrap.serverChannelOption(ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only), value: 1)
            }
            do {
                let channel = try await bootstrap.bind(host: address, port: port).get()
                state.withLock { $0.listeners.append(channel) }
                if port == 0, let p = channel.localAddress?.port { port = p }
                boundAny = true
            } catch {
                // A missing address family (no IPv6) is not fatal once one address is bound.
                if boundAny || (isV6 && config.bindAddresses.count > 1 && address != config.bindAddresses.first) {
                    logger.warning("LDAP \(String(describing: kind), privacy: .public) on [\(address, privacy: .public)]:\(port): \(String(describing: error), privacy: .public)")
                    continue
                }
                throw DirectoryKitError.listener("\(kind) on \(address):\(requested): \(error)")
            }
        }
        guard boundAny else { throw DirectoryKitError.listener("\(kind): no address could be bound") }
        return port
    }

    private static func initializeConnection(_ channel: Channel, kind: ListenerKind, context: ServerContext) throws {
        let sync = channel.pipeline.syncOperations
        if kind.usesTLS, let tls = context.tls {
            try sync.addHandler(NIOSSLServerHandler(context: tls), name: LDAPPipeline.tls)
        }
        try sync.addHandler(ByteToMessageHandler(LDAPFrameDecoder(maxMessageSize: context.config.maxMessageSize)),
                            name: LDAPPipeline.frameDecoder)
        try sync.addHandler(LDAPConnectionHandler(context: context, kind: kind), name: LDAPPipeline.connection)
    }

    /// Closes the listeners and every connection.
    public func stop() async {
        let (group, listeners) = state.withLock { s -> (MultiThreadedEventLoopGroup?, [Channel]) in
            defer {
                s.group = nil
                s.listeners = []
                s.ports = BoundPorts()
            }
            return (s.group, s.listeners)
        }
        for l in listeners { try? await l.close() }
        try? await group?.shutdownGracefully()
    }
}

enum LDAPPipeline {
    static let tls = "tls"
    static let saslLayer = "sasl-layer"
    static let frameDecoder = "ldap-frame"
    static let connection = "ldap-connection"
}
