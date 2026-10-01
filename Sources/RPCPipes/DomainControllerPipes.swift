import Foundation
import DRSService
import LSAService
import NetlogonService
import RPCKit
import SAMService
import SMBKit
import Store

/// The RPC interfaces and auth provider a pipe presents on each CREATE.
public struct RPCPipeSetup: Sendable {
    public var interfaces: [any RPCInterface]
    public var authProvider: any RPCAuthProvider

    public init(interfaces: [any RPCInterface], authProvider: any RPCAuthProvider = NoAuthProvider()) {
        self.interfaces = interfaces
        self.authProvider = authProvider
    }
}

/// A `NamedPipeService` that stands up a fresh `RPCServerConnection` per open, from a per-session
/// setup closure. The interfaces are shared across connections (their per-call state lives in the
/// connection's handle table); the auth provider is per connection.
public struct RPCPipeService: NamedPipeService {
    public let pipeName: String
    private let make: @Sendable (SMBSessionInfo) -> RPCPipeSetup

    public init(pipeName: String, setup: @escaping @Sendable (SMBSessionInfo) -> RPCPipeSetup) {
        self.pipeName = pipeName
        self.make = setup
    }

    public func open(session: SMBSessionInfo) async -> any NamedPipeHandle {
        RPCPipeHandle(session: session, setup: make(session))
    }
}

/// The DC's RPC service instances built once over one Store, so both the SMB named pipes (WP-X) and
/// the `ncacn_ip_tcp` endpoint (WP-AE) share them. The services are stateless dispatchers (per-call
/// state lives in each connection's handle table), and the `NetlogonStateStore` — the shared
/// secure-channel state — is the same object across transports, so a channel established over a pipe
/// is visible to a TCP caller and vice versa.
public struct DomainControllerServices: Sendable {
    public let samr: SAMRService
    public let lsa: LSARPCService
    public let srvsvc: SrvsvcService
    public let wkssvc: WkssvcService
    public let dssetup: DSSetupService
    public let netlogon: NetlogonService
    public let drs: DRSService
    public let netlogonState: NetlogonStateStore
    /// The Store the services read (WP-AJ: the TCP schannel provider resolves the computer
    /// account's identity from it).
    public let store: DirectoryStore

    public init(store: DirectoryStore,
                netlogonState: NetlogonStateStore,
                dcInfo: any NetlogonDCInfoProvider,
                shareProvider: (any ShareProvider)? = nil,
                allowAnonymousLSA: Bool = false,
                netlogonConfig: NetlogonServiceConfig = NetlogonServiceConfig(),
                drsOnEvent: (@Sendable (String) -> Void)? = nil) {
        self.samr = SAMRService(directory: store)
        self.lsa = LSARPCService(store: store, allowAnonymous: allowAnonymousLSA)
        self.srvsvc = SrvsvcService(store: store, shares: shareProvider)
        self.wkssvc = WkssvcService(store: store)
        self.dssetup = DSSetupService(store: store)
        self.netlogon = NetlogonService(store: store, state: netlogonState, dcInfo: dcInfo, config: netlogonConfig)
        self.drs = DRSService(store: store, onEvent: drsOnEvent)
        self.netlogonState = netlogonState
        self.store = store
    }

    /// WP-AJ: a fresh Netlogon schannel provider (auth type 68) for one `ncacn_ip_tcp` connection,
    /// over the same `NetlogonStateStore` the pipes use — pass it as
    /// `RPCServerAuthConfig.makeSchannel`. On TCP there is no SMB session, so the provider also
    /// supplies the identity: the secure channel's computer account.
    public func makeTCPSchannelProvider() -> any RPCAuthProvider {
        NetlogonSchannelProvider(store: netlogonState, identityDirectory: store)
    }

    /// The five DC named pipes: `\samr`, `\lsarpc`, `\srvsvc`, `\wkssvc`, `\netlogon`.
    public func pipeServices() -> [any NamedPipeService] {
        let samr = self.samr, lsa = self.lsa, srvsvc = self.srvsvc, wkssvc = self.wkssvc
        let dssetup = self.dssetup, netlogon = self.netlogon, netlogonState = self.netlogonState
        return [
            // WP-Z: a Samba/winbind member *requires* schannel (auth type 68) on \samr and \lsarpc
            // (winbindd_cm.c `cm_connect_sam`/`cm_connect_lsa`: require_schannel for its own domain).
            // Binds without an auth trailer never reach the provider, so rpcclient/impacket/Windows
            // no-auth binds are unchanged.
            RPCPipeService(pipeName: "samr") { _ in
                RPCPipeSetup(interfaces: [samr], authProvider: NetlogonSchannelProvider(store: netlogonState))
            },
            // `dssetup` shares the `\lsarpc` pipe with LSA, as on Windows (WP-Z).
            RPCPipeService(pipeName: "lsarpc") { _ in
                RPCPipeSetup(interfaces: [lsa, dssetup], authProvider: NetlogonSchannelProvider(store: netlogonState))
            },
            RPCPipeService(pipeName: "srvsvc") { _ in RPCPipeSetup(interfaces: [srvsvc]) },
            RPCPipeService(pipeName: "wkssvc") { _ in RPCPipeSetup(interfaces: [wkssvc]) },
            RPCPipeService(pipeName: "netlogon") { _ in
                RPCPipeSetup(interfaces: [netlogon], authProvider: NetlogonSchannelProvider(store: netlogonState))
            },
        ]
    }

    /// The interfaces published on the shared dynamic `ncacn_ip_tcp` port: LSARPC (+ dssetup), SAMR
    /// and NETLOGON — the interfaces Windows reaches over TCP after a join and at logon. Identity
    /// comes from the RPC auth provider on that connection (no SMB session): NTLM/SPNEGO/Kerberos,
    /// or Netlogon schannel via `makeTCPSchannelProvider()` (WP-AJ).
    public var tcpInterfaces: [any RPCInterface] { [lsa, dssetup, samr, netlogon, drs] }

    /// Endpoint-mapper registrations for the TCP interfaces: each advertised on
    /// `ncacn_ip_tcp:<advertise>[tcpPort]` and its named pipe (`ncacn_np:\\host[\pipe\…]`).
    public func epmRegistrations(advertiseIPv4: String, tcpPort: UInt16, dcHostName: String) -> [EPMRegistration] {
        func reg(_ iface: any RPCInterface, pipe: String, _ annotation: String) -> EPMRegistration {
            EPMRegistration(interface: iface.abstractSyntax, annotation: annotation,
                            endpoints: [.tcp(ipv4: advertiseIPv4, port: tcpPort),
                                        .namedPipe(pipe: pipe, host: dcHostName)])
        }
        return [
            reg(lsa, pipe: "\\pipe\\lsarpc", "LabDC LSA RPC"),
            reg(dssetup, pipe: "\\pipe\\lsarpc", "LabDC Directory Setup"),
            reg(samr, pipe: "\\pipe\\samr", "LabDC SAM"),
            reg(netlogon, pipe: "\\pipe\\netlogon", "LabDC Netlogon"),
            // DRSUAPI is TCP-only on Windows: advertise just the ncacn_ip_tcp endpoint.
            EPMRegistration(interface: drs.abstractSyntax, annotation: "LabDC Directory Replication",
                            endpoints: [.tcp(ipv4: advertiseIPv4, port: tcpPort)]),
        ]
    }
}

/// Builds the five DC named pipes over one Store: `\samr`, `\lsarpc`, `\srvsvc`, `\wkssvc`, and
/// `\netlogon` (the last with a `NetlogonSchannelProvider` available for the type-68 schannel bind
/// Windows makes after `NetrServerAuthenticate3`). A thin wrapper over `DomainControllerServices` for
/// existing callers; new code that also wants the TCP endpoint should build `DomainControllerServices`
/// once and use both `pipeServices()` and `tcpInterfaces`.
public enum DomainControllerPipes {
    public static func services(store: DirectoryStore,
                                netlogonState: NetlogonStateStore,
                                dcInfo: any NetlogonDCInfoProvider,
                                shareProvider: (any ShareProvider)? = nil,
                                allowAnonymousLSA: Bool = false,
                                netlogonConfig: NetlogonServiceConfig = NetlogonServiceConfig()) -> [any NamedPipeService] {
        DomainControllerServices(store: store, netlogonState: netlogonState, dcInfo: dcInfo,
                                 shareProvider: shareProvider, allowAnonymousLSA: allowAnonymousLSA,
                                 netlogonConfig: netlogonConfig).pipeServices()
    }
}
