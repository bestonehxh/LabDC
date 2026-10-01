import AuthKit
import DNSKit
import EAPKit
import DirectoryKit
import Foundation
import KDC
import LSAService
import NetlogonService
import PKIKit
import RPCKit
import RPCPipes
import RPCTCP
import SMBKit
import SNTPKit
import SYSVOL
import Store
import Synchronization

/// The HTTPS port the CEP hands out in its CES URL (known only once the listener is bound).
final class HTTPSPortBox: Sendable {
    private let value = Mutex<Int>(443)
    var port: Int {
        get { value.withLock { $0 } }
        set { value.withLock { $0 = newValue } }
    }
}

/// This Mac's IPv4 addresses as the DC publishes them (interfaces up, no loopback/link-local).
public enum ServeAddresses {
    public static func current() -> [String] { LabPKI.currentAddresses() }
}

/// The ports `serve` actually bound (nil: not running).
public struct ServeBoundPorts: Sendable, Equatable {
    public var dns: UInt16?
    public var kdc: UInt16?
    public var kpasswd: UInt16?
    public var ldap: Int?
    public var ldaps: Int?
    public var gc: Int?
    public var gcs: Int?
    public var cldap: UInt16?
    public var smb: Int?
    public var sntp: UInt16?
    /// The RPC endpoint mapper port (135).
    public var epm: Int?
    /// The shared dynamic `ncacn_ip_tcp` port.
    public var rpc: Int?
    /// PK-1: the CDP/AIA HTTP listener (80).
    public var http: Int?
    /// PK-7: EST over HTTPS (8443).
    public var est: Int?
    /// PK-6: the CEP / CES enrollment web services over HTTPS (443).
    public var https: Int?
    /// WP-AR2: the NetBIOS name service (udp 137).
    public var nbns: Int?
    /// Phase 4a: RADIUS auth (udp 1812) and accounting (udp 1813).
    public var radius: Int?
    public var radacct: Int?
    /// WP-AR2: the NetBIOS session service (tcp 139, the SMB server's second port).
    public var nbss: Int?

    public init() {}
}

/// `labdc serve`: everything from one Store, started in dependency order and stopped in
/// reverse.
///
/// 1. Store (`<data>/lab.sqlite`, provisioned on request, never twice)
/// 2. LabPKI (`<data>/pki`): the lab CA and the DC certificate for `defaultServerNames`
///    (+ `--advertise`); reissued when the SAN set changes, at start and while running
/// 3. DNS (udp+tcp 53) over `StoreZoneSource`
/// 4. KDC (udp+tcp 88) and kpasswd (udp+tcp 464) over `DirectoryPrincipalStore`
/// 5. LDAP 389 / LDAPS 636 / GC 3268 / GC-TLS 3269 (`DirectoryServer`)
/// 6. CLDAP (udp 389, `CLDAPServer`) with the same `advertisedIPv4`, flags and vendor version
/// 7–9. SYSVOL + SMB, SNTP, RPC endpoint mapper + ncacn_ip_tcp
/// 10. PK-1: HTTP (tcp 80) serving `/pki/<ca>.crl` and `/pki/<ca>.crt` (`CAService`), with an
///     hourly check that regenerates CRLs older than a day; PK-7: SCEP (`/scep`,
///     `/certsrv/mscep/mscep.dll`) on the same listener
/// 11. PK-7: EST (HTTPS, tcp 8443) with the DC certificate
/// 12. PK-6: the enrollment web services (HTTPS, tcp 443, DC certificate, HTTP Negotiate):
///     MS-XCEP `/ADPolicyProvider_CEP_Kerberos/service.svc/CEP` and MS-WSTEP
///     `/<CA>_CES_Kerberos/service.svc/CES` (Windows certificate auto-enrollment)
/// 13. Phase 4a: RADIUS (udp 1812 auth + 1813 accounting), always with the directory
public actor ServeRuntime {
    public static let vendorVersion = "LabDC 1.0 (phase 1)"

    /// UI-1: `var` so `restart(_:port:)` can move one listener in place.
    public private(set) var options: ServeOptions
    public let log: ServeLog
    public let data: DataDirectory
    public private(set) var store: DirectoryStore?
    public private(set) var pki: LabPKI?
    /// PK-1: templates, issuance database, revocation and CRLs.
    public private(set) var caService: CAService?
    private var http: PKIHTTPServer?
    /// PK-7: SCEP (on `http`) and EST (its own HTTPS listener).
    public private(set) var scepService: SCEPService?
    public private(set) var estService: ESTService?
    private var est: PKIHTTPServer?
    /// PK-6: CEP + CES over HTTPS.
    public private(set) var enrollmentWeb: EnrollmentWebService?
    private var https: PKIHTTPServer?
    private var httpsPortBox: HTTPSPortBox?
    private var crlTimer: Task<Void, Never>?
    private var dns: DNSServer?
    /// Where names outside the domain go (Settings ▸ Directory ▸ Other names, `--forwarders`).
    private var dnsForwarder: DNSForwarder?
    private let forwardingState = DNSForwardingState()
    private var kdc: KDCServer?
    private var kpasswd: KPasswdServer?
    private var ldap: DirectoryServer?
    private var cldap: CLDAPServer?
    private var smb: SMBServer?
    private var sntp: SNTPServer?
    /// WP-AR2: the NetBIOS name service (udp 137).
    private var nbns: NBNSServer?
    /// Phase 4a: the RADIUS server (auth + accounting listeners live inside it).
    private var radius: RadiusServer?
    /// Why RADIUS did not start with the rest (a held udp 1812/1813). RADIUS never stops the
    /// directory from starting; the Services row shows the problem and offers Restart.
    public private(set) var radiusStartFailure: String?
    /// On-demand issuance of the 192-bit RADIUS certificate (`eapCredentials`): after a failure
    /// it is tried again at most every 10 minutes, with one log line per attempt.
    var suiteBIssuance = RetryWindow(interval: .seconds(600))
    /// The shared dynamic `ncacn_ip_tcp` endpoint (LSARPC/SAMR/NETLOGON) and the endpoint mapper (135).
    private var rpcTCP: RPCTCPServer?
    private var epm: RPCTCPServer?
    /// The DC RPC services, built once and shared by the SMB pipes and the TCP endpoint.
    private var dcServices: DomainControllerServices?
    /// Shared NETLOGON secure-channel state (kept alive for the `\netlogon` pipe + schannel auth).
    private var netlogonState: NetlogonStateStore?
    private var watcher: Task<Void, Never>?
    private var lastAddresses: Set<String> = []
    public private(set) var bound = ServeBoundPorts()

    public init(options: ServeOptions, log: ServeLog) {
        self.options = options
        self.log = log
        self.data = DataDirectory(options.dataDirectory)
    }

    /// Opens (and, with `--provision`, provisions) the store. Refuses to provision a store that
    /// already holds a domain, and refuses to serve an empty one.
    public static func openStore(_ data: DataDirectory, provision: ProvisionSpec?, log: ServeLog) async throws -> DirectoryStore {
        try data.prepare()
        let store: DirectoryStore
        do { store = try DirectoryStore(path: data.storeURL.path) } catch {
            throw CLIError.failure("cannot open \(data.storeURL.path): \(error)")
        }
        // WP-AN: one line per object the open-time fixups repaired (raw SAMR ACB userAccountControl).
        for fix in store.openFixups { log.event("Store", "fixup: \(fix)") }
        let provisioned = await store.isProvisioned
        if let provision {
            if provisioned {
                let realm = (try? await store.domainInfo().realm) ?? "?"
                throw CLIError.failure("the store at \(data.storeURL.path) is already provisioned (realm \(realm)); "
                                       + "refusing to re-provision. Drop --provision to serve it, or use a new --data folder.")
            }
            do {
                try await store.provision(realm: provision.realm, dnsDomain: provision.dnsDomain, netbios: provision.netbios,
                                          dcName: provision.dcName, adminPassword: provision.adminPassword)
            } catch {
                throw CLIError.failure("provisioning failed: \(error)")
            }
            let info = try await store.domainInfo()
            log.event("Store", "provisioned \(info.realm) (DNS \(info.dnsDomain), NetBIOS \(info.netbiosDomain), DC \(info.dcDNSName), SID \(info.domainSID))")
        } else if !provisioned {
            throw CLIError.failure("the store at \(data.storeURL.path) is not provisioned; start once with "
                                   + "--provision realm=LAB.SHEEP dns=lab.sheep netbios=LABSHEEP dc=dc1 admin-password=<pw>")
        }
        return store
    }

    /// Starts every component; on any failure the ones already started are stopped again.
    @discardableResult
    public func start() async throws -> ServeBoundPorts {
        do {
            return try await startAll()
        } catch {
            await stop()
            throw error
        }
    }

    private func startAll() async throws -> ServeBoundPorts {
        let ports = options.ports
        // 1. Store
        let store = try await Self.openStore(data, provision: options.provision, log: log)
        self.store = store
        let info = try await store.domainInfo()
        log.event("Store", "\(data.storeURL.path): realm \(info.realm), DC \(info.dcDNSName)")

        // 2. PKI
        let pki: LabPKI
        let caService: CAService
        do {
            pki = try await LabPKI.open(directory: data.pkiURL)
            let ca = try await pki.ensureCA(name: "LabDC Lab CA (\(info.realm))",
                                            alsoAccepting: ["SheepAuth Lab CA (\(info.realm))"])  // never re-key a live CA
            let current = try await pki.currentAuthority()
            let previous = try? await pki.serverCertificate()
            let names = serverNames(info)
            let cert = try await pki.ensureServerCertificate(hostnames: names.hostnames, ips: names.ips)
            log.event("PKI", "lab CA \(ca == .issued ? "issued" : "loaded"), current CA \(current.name) (\(current.keyType.displayName), "
                      + "\(current.certificate.subject)), DC certificate \(cert == .issued ? "issued" : "unchanged") "
                      + "for \((names.hostnames + names.ips).joined(separator: ", "))")
            if cert == .issued, let previous, previous.issuer != current.certificate.subject {
                log.event("PKI", "DC certificate reissued from CA \(current.name) (was issued by \(previous.issuer))")
            }
            caService = try await CAService.open(pki: pki, store: store)
            await prepareSuiteB(caService: caService, pki: pki, info: info)
            if options.httpEnabled, options.ports.http != 0 { try? await caService.setPublicationPort(Int(options.ports.http)) }
            await recordServerCertificate(caService, pki: pki, info: info)
            let refreshed = try await caService.refreshCRLs()
            if !refreshed.isEmpty { log.event("PKI", "CRL regenerated for \(refreshed.joined(separator: ", "))") }
        } catch {
            throw CLIError.failure("PKI in \(data.pkiURL.path): \(error)")
        }
        // PK-5: NTAuth, Enrollment Services, templates, AIA/CDP/OID in the Configuration NC.
        do {
            let report = try await caService.publishToDirectory()
            log.event("PKI", report.isNoOp ? "directory objects up to date (Public Key Services)"
                      : "directory objects: \(report.created.count) created, \(report.modified.count) updated, "
                        + "\(report.deleted.count) removed (Public Key Services)")
        } catch {
            log.warning("PKI", "publishing the PKI objects in the Configuration NC failed: \(error)")
        }
        self.pki = pki
        self.caService = caService
        lastAddresses = Set(ServeAddresses.current())

        // 3. DNS
        if options.dnsEnabled {
            let log = self.log
            let source = StoreZoneSource(store: store, advertise: options.advertise,
                                         onChange: { line in log.event("DNS", line) })
            let server = makeDNSServer(source: source, port: ports.dns)
            do { try await server.start() } catch {
                throw CLIError.failure("DNS udp+tcp \(ports.dns): \(error)")
            }
            dns = server
            bound.dns = server.port
            await dnsServerStarted(server)
        }

        // 4. KDC + kpasswd
        let principals = try await DirectoryPrincipalStore(directory: store)
        let verbose = options.verbose
        let log = self.log
        let onExchange: @Sendable (ExchangeRecord) -> Void = { record in
            var line = record.description
            if verbose {
                line += " [\(record.replySize) bytes]"
                if let reason = record.reason { line += " (\(reason))" }
            }
            log.event(record.kind == .kpasswd ? "kpasswd" : "KDC", line)
        }
        for (name, port) in [("KDC", ports.kdc), ("kpasswd", ports.kpasswd)] {
            if let problem = PortProbe.problem(port: port, protos: [.udp, .tcp]) {
                throw CLIError.failure("\(name) udp+tcp \(port): \(problem)")
            }
        }
        let kdcServer = KDCServer(kdc: KDC(store: principals, onExchange: onExchange), port: ports.kdc, bindAddress: "0.0.0.0")
        do { try await kdcServer.start() } catch { throw CLIError.failure("KDC udp+tcp \(ports.kdc): \(error)") }
        kdc = kdcServer
        bound.kdc = kdcServer.port
        let kpw = KPasswdServer(service: KPasswdService(store: principals, onExchange: onExchange), port: ports.kpasswd,
                                bindAddress: "0.0.0.0")
        do { try await kpw.start() } catch { throw CLIError.failure("kpasswd udp+tcp \(ports.kpasswd): \(error)") }
        kpasswd = kpw
        bound.kpasswd = kpw.port

        // 5. LDAP / LDAPS / GC
        try await startLDAP(store: store, pki: pki)

        // 6. CLDAP
        let cldapServer = CLDAPServer(store: store, config: CLDAPServerConfig(
            port: ports.cldap, advertisedIPv4: options.advertise, vendorVersion: Self.vendorVersion))
        do { try await cldapServer.start() } catch { throw CLIError.failure("CLDAP udp \(ports.cldap): \(error)") }
        cldap = cldapServer
        bound.cldap = cldapServer.port

        // 7. SYSVOL + SMB (445) and 8. SNTP (123)
        try await startSMBAndSNTP(store: store, info: info)

        // 9. RPC endpoint mapper (135) + shared dynamic ncacn_ip_tcp port
        try await startRPCTCP(store: store, info: info)

        // 10. HTTP (80): CRL distribution point + AIA, SCEP
        try await startHTTP(caService: caService, info: info)
        // 11. EST (8443, HTTPS)
        try await startEST(caService: caService, pki: pki, info: info)
        // 12. CEP + CES (443, HTTPS, Negotiate)
        try await startHTTPS(caService: caService, pki: pki, store: store, info: info)
        // 13. RADIUS (owner, 30 Sep 2026: starts with the directory, no switch). A held port is a
        // problem on its Services row, not a failed start of the whole DC.
        if options.radiusEnabled {
            do { try await startRadius(store: store) } catch {
                radiusStartFailure = "\(error)"
                log.warning("RADIUS", "\(error)")
            }
        }

        if options.addressCheckInterval > 0 {
            let interval = options.addressCheckInterval
            watcher = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(interval))
                    if Task.isCancelled { return }
                    await self?.checkAddresses()
                }
            }
        }
        return bound
    }

    /// Ensures the SYSVOL tree, then starts the SMB server (445, IPC$ + the five RPC pipes +
    /// SYSVOL/NETLOGON folder shares) and the SNTP server (123, MS-SNTP signing keyed on computer
    /// NT hashes). Both refuse to start if the port is held (the holder is named).
    private func startSMBAndSNTP(store: DirectoryStore, info: DomainInfo) async throws {
        let ports = options.ports

        if options.smbEnabled {
            // SYSVOL folder tree + default GPO objects (idempotent).
            do {
                let result = try await SysvolLayout.ensure(root: data.sysvolURL, store: store)
                log.event("SYSVOL", result.isNoOp ? "\(data.sysvolURL.path): already present"
                          : "\(data.sysvolURL.path): \(result.createdPaths.count) paths, "
                            + "\(result.createdObjects.count) objects created, \(result.modifiedObjects.count) modified")
                for gpo in result.createdGPOs {
                    log.event("GPO", "created \(gpo.displayName) \(gpo.guid), linked on "
                              + gpo.linkedDN(domainDN: info.domainDN).description)
                }
            } catch {
                throw CLIError.failure("SYSVOL \(data.sysvolURL.path): \(error)")
            }

            if let problem = PortProbe.problem(port: ports.smb, protos: [.tcp]) {
                throw CLIError.failure("SMB tcp \(ports.smb): \(problem)")
            }
            // WP-AR2: the NetBIOS session service (tcp 139) is a second port of the same SMB server
            // (one share/pipe/session state). A held port is a warning, not a startup failure:
            // NetBIOS is a fallback for clients that do not use 445.
            var netbiosPort: Int?
            if options.netbiosEnabled {
                if let problem = PortProbe.problem(port: ports.nbss, protos: [.tcp]) {
                    log.warning("NBSS", "tcp \(ports.nbss): \(problem); SMB runs on \(ports.smb) only")
                } else {
                    netbiosPort = Int(ports.nbss)
                }
            }
            let pipes = dcServicesShared(store: store, info: info).pipeServices()
            var config: SMBServerConfig
            do { config = try await SMBServerConfig.from(store: store) } catch {
                throw CLIError.failure("SMB config from store: \(error)")
            }
            config.advertisedIPv4 = options.advertise
            let secrets: StoreSecretSource
            do { secrets = try await StoreSecretSource(store: store) } catch {
                throw CLIError.failure("SMB secret source: \(error)")
            }
            let server = SMBServer(port: Int(ports.smb), netbiosPort: netbiosPort,
                                   shares: SMBShare.domainController(sysvol: data.sysvolURL.path, dnsDomain: info.dnsDomain),
                                   pipes: pipes, auth: SMBAuthPolicy(), secrets: secrets, config: config)
            do { try await server.start() } catch {
                throw CLIError.failure("SMB tcp \(ports.smb)" + (netbiosPort.map { "+\($0)" } ?? "") + ": \(error)")
            }
            smb = server
            bound.smb = server.boundPort
            bound.nbss = server.boundNetbiosPort
            log.event("SMB", "tcp \(server.boundPort ?? Int(ports.smb)): IPC$, SYSVOL, NETLOGON; "
                      + "pipes \\samr \\lsarpc \\netlogon \\srvsvc \\wkssvc")
            if let nb = server.boundNetbiosPort {
                log.event("NBSS", "tcp \(nb): NetBIOS session service (SMB over NetBIOS)")
            }
        }

        try await startNBNS(info: info)

        if options.sntpEnabled {
            let domainSID = info.domainSID
            let keyStore = store
            let keyProvider: SNTPKeyProvider = { rid, _ in
                guard let sid = try? domainSID.appending(rid: rid),
                      let entry = try? await keyStore.read(sid: sid, attrs: ["sAMAccountType", "sAMAccountName"]),
                      Self.isComputer(entry) else { return nil }
                // Machine accounts keep no password history, so `previous` returns the current hash too.
                return try? await keyStore.secrets(id: entry.id)?.ntHash
            }
            let server = SNTPServer(port: ports.sntp, keyProvider: keyProvider)
            do { try await server.start() } catch {
                throw CLIError.failure("SNTP udp \(ports.sntp): \(error)")
            }
            sntp = server
            bound.sntp = server.port
            log.event("SNTP", "udp \(server.port): stratum 2, MS-SNTP signing for computer accounts")
        }
    }

    /// WP-AR2: the NetBIOS name service (udp 137): answers `<DC><00>`/`<DC><20>`, `<DOMAIN><1B>`,
    /// `<DOMAIN><1C>` and NBSTAT with the advertised IPv4. Skipped (with a log line) when NetBIOS is
    /// off, when no IPv4 is known, or when the port is held (macOS `netbiosd` may own 137) — NetBIOS
    /// is a fallback, so it never stops `serve` from starting.
    private func startNBNS(info: DomainInfo) async throws {
        guard options.netbiosEnabled else { return }
        let port = options.ports.nbns
        guard let address = advertisedIPv4,
              let responder = NBNSResponder(dcName: info.dcName, netbiosDomain: info.netbiosDomain, advertisedIPv4: address) else {
            log.event("NBNS", "udp \(port): not started, no IPv4 address to answer with (pass --advertise <ipv4>)")
            return
        }
        if let problem = PortProbe.problem(port: port, protos: [.udp]) {
            log.warning("NBNS", "udp \(port): \(problem); NetBIOS name service not started")
            return
        }
        let server = NBNSServer(responder: responder, port: Int(port))
        do { try await server.start() } catch {
            log.warning("NBNS", "udp \(port): \(error); NetBIOS name service not started")
            return
        }
        nbns = server
        bound.nbns = server.port
        log.event("NBNS", "udp \(server.port): \(responder.dcName)<00>/<20>, \(responder.netbiosDomain)<1B>/<1C> -> \(address)")
    }

    /// Builds the shared DC RPC services once (SMB pipes and the TCP endpoint reuse them and the same
    /// NETLOGON secure-channel state).
    private func dcServicesShared(store: DirectoryStore, info: DomainInfo) -> DomainControllerServices {
        if let s = dcServices { return s }
        // UI-1c: a rebuild (new advertised address) keeps the secure channels of joined machines.
        let state = netlogonState ?? NetlogonStateStore()
        netlogonState = state
        let dcInfo = StaticNetlogonDCInfoProvider(advertisedIPv4: options.advertise)
        // WP-AK: secure-channel setup, password rotation and SamLogon outcomes on stdout, like the
        // KDC's `AS ... -> OK` lines (`NETLOGON SamLogon Network LABSHEEP\alice ... -> OK as alice`).
        let log = self.log
        let s = DomainControllerServices(
            store: store, netlogonState: state, dcInfo: dcInfo,
            shareProvider: StaticShareProvider.domainController(dnsDomain: info.dnsDomain),
            netlogonConfig: NetlogonServiceConfig(ntlmAuth: options.ntlmAuth,
                                                  onEvent: { line in log.event("NETLOGON", line) }),
            // WP-AM: DsBind / DsCrackNames / DsUnbind outcomes (`DRSUAPI DsCrackNames offered=7(CANONICAL) ...`).
            drsOnEvent: { line in log.event("DRSUAPI", line) })
        dcServices = s
        return s
    }

    /// Starts the shared dynamic `ncacn_ip_tcp` endpoint (LSARPC/dssetup, SAMR, NETLOGON) and the RPC
    /// endpoint mapper on TCP 135. The dynamic endpoint binds first so its port is known before the
    /// endpoint mapper advertises it. Identity on TCP comes from the RPC auth verifier (NTLMSSP type
    /// 10, SPNEGO type 9; Kerberos DCE-style is a documented gap). The endpoint mapper refuses to
    /// start if 135 is held and names the holder.
    private func startRPCTCP(store: DirectoryStore, info: DomainInfo) async throws {
        guard options.rpcTcpEnabled else { return }
        let ports = options.ports
        let services = dcServicesShared(store: store, info: info)

        // Per-connection auth negotiator for the dynamic endpoint.
        let secrets: StoreSecretSource
        do { secrets = try await StoreSecretSource(store: store) } catch {
            throw CLIError.failure("RPC secret source: \(error)")
        }
        // WP-AJ: Netlogon schannel (type 68) over the shared NetlogonStateStore, so winbind/Windows
        // can use the NETLOGON tower the endpoint mapper advertises with the channel they set up.
        let authConfig = RPCServerAuthConfig(
            makeNTLMServer: { NTLMServer(source: secrets, allowAnonymous: false) },
            makeKerberosAcceptor: { KerberosAcceptor(source: secrets) },
            makeSchannel: { services.makeTCPSchannelProvider() })
        let dynSetup = RPCTCPEndpointSetup(interfaces: services.tcpInterfaces,
                                           makeAuthProvider: { RPCServerAuthNegotiator(config: authConfig) })
        let dyn = RPCTCPServer(port: Int(ports.rpc), setup: dynSetup)
        do { try await dyn.start() } catch { throw CLIError.failure("RPC ncacn_ip_tcp: \(error)") }
        rpcTCP = dyn
        let dynPort = dyn.boundPort ?? Int(ports.rpc)
        bound.rpc = dynPort

        // Endpoint mapper on 135, advertising the dynamic port for each interface.
        if let problem = PortProbe.problem(port: ports.epm, protos: [.tcp]) {
            throw CLIError.failure("EPM tcp \(ports.epm): \(problem)")
        }
        let advertiseIP = options.advertise ?? ServeAddresses.current().first ?? "127.0.0.1"
        var registrations = services.epmRegistrations(advertiseIPv4: advertiseIP,
                                                      tcpPort: UInt16(truncatingIfNeeded: dynPort),
                                                      dcHostName: info.dcDNSName)
        registrations.append(EPMRegistration(
            interface: EndpointMapperService.interfaceID, annotation: "LabDC Endpoint Mapper",
            endpoints: [.tcp(ipv4: advertiseIP, port: ports.epm), .namedPipe(pipe: "\\pipe\\epmapper", host: info.dcDNSName)]))
        let epmService = EndpointMapperService(registrations: registrations)
        let epmSetup = RPCTCPEndpointSetup(interfaces: [epmService])
        let epmServer = RPCTCPServer(port: Int(ports.epm), setup: epmSetup)
        do { try await epmServer.start() } catch {
            await dyn.stop(); rpcTCP = nil
            throw CLIError.failure("EPM tcp \(ports.epm): \(error)")
        }
        epm = epmServer
        bound.epm = epmServer.boundPort
        log.event("RPC", "ncacn_ip_tcp \(dynPort): lsarpc, dssetup, samr, netlogon, drsuapi "
                  + "(NTLMSSP / SPNEGO / Kerberos DCE-style / Netlogon schannel auth); "
                  + "endpoint mapper tcp \(epmServer.boundPort ?? Int(ports.epm))")
    }

    /// PK-1: the plain-HTTP listener for `/pki/<ca>.crl` and `/pki/<ca>.crt` (the CDP / AIA URLs in
    /// every issued certificate, `http://<dc fqdn>/pki/…`), and the CRL refresh timer.
    private func startHTTP(caService: CAService, info: DomainInfo) async throws {
        let log = self.log
        if options.crlCheckInterval > 0 {
            let interval = options.crlCheckInterval
            crlTimer = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(interval))
                    if Task.isCancelled { return }
                    do {
                        let refreshed = try await caService.refreshCRLs()
                        if !refreshed.isEmpty { log.event("PKI", "CRL regenerated for \(refreshed.joined(separator: ", ")) (daily)") }
                    } catch {
                        log.warning("PKI", "CRL refresh failed: \(error)")
                    }
                }
            }
        }
        guard options.httpEnabled else { return }
        let port = options.ports.http
        if let problem = PortProbe.problem(port: port, protos: [.tcp]) {
            throw CLIError.failure("HTTP tcp \(port): \(problem)")
        }
        // PK-7: SCEP needs its RA certificate (RSA, issued by the current CA) before it answers.
        let scep = SCEPService(ca: caService, onEvent: { line in log.event("SCEP", Self.dropPrefix(line, "SCEP ")) })
        do {
            let (ra, issued) = try await scep.prepare()
            log.event("SCEP", "RA certificate \(issued ? "issued" : "loaded"): \(ra.certificate.subject), serial \(ra.certificate.serialNumber), "
                      + "until \(ra.certificate.notValidAfter.formatted(Date.ISO8601FormatStyle().year().month().day()))")
        } catch {
            throw CLIError.failure("SCEP RA certificate: \(error)")
        }
        scepService = scep
        let server = PKIHTTPServer(port: Int(port), tls: nil, onRequest: { line in log.event("HTTP", line) },
                                   requestHandler: { request in
                                       if SCEPService.handles(path: request.path) { return await scep.handle(request) }
                                       return await caService.httpResponse(method: request.method, path: request.uri)
                                   })
        do { try await server.start() } catch { throw CLIError.failure("HTTP tcp \(port): \(error)") }
        http = server
        bound.http = server.boundPort
        let current = (try? await caService.pki.currentAuthority().name) ?? LabPKI.labCAName
        let httpPort = server.boundPort ?? Int(port)
        do { try await caService.setPublicationPort(httpPort) } catch {
            log.event("PKI", "WARNING could not record the CRL port \(httpPort): \(error)")
        }
        let hostPort = "\(info.dcDNSName)\(httpPort == 80 ? "" : ":\(httpPort)")"
        log.event("HTTP", "tcp \(httpPort): CRL http://\(hostPort)\(CAService.crlPath(caName: current)), "
                  + "CA certificate http://\(hostPort)\(CAService.caCertificatePath(caName: current)), "
                  + "SCEP http://\(info.dcDNSName)\(httpPort == 80 ? "" : ":\(httpPort)")/scep (and /certsrv/mscep/mscep.dll)")
    }

    /// PK-7: EST (RFC 7030) over HTTPS with the DC certificate; client certificates are
    /// requested (optional) for `simplereenroll`.
    private func startEST(caService: CAService, pki: LabPKI, info: DomainInfo, port requested: UInt16? = nil) async throws {
        guard options.estEnabled else { return }
        let port = requested ?? options.ports.est
        if let problem = PortProbe.problem(port: port, protos: [.tcp]) {
            throw CLIError.failure("EST tcp \(port): \(problem)")
        }
        let log = self.log
        let service = estService ?? ESTService(ca: caService, onEvent: { line in log.event("EST", Self.dropPrefix(line, "EST ")) })
        estService = service
        let server: PKIHTTPServer
        do {
            server = PKIHTTPServer(port: Int(port), tls: try await ESTService.tlsConfiguration(pki: pki), onRequest: { line in log.event("EST", line) },
                                   requestHandler: { request in await service.handle(request) })
        } catch {
            throw CLIError.failure("EST TLS: \(error)")
        }
        do { try await server.start() } catch { throw CLIError.failure("EST tcp \(port): \(error)") }
        est = server
        bound.est = server.boundPort
        let estPort = server.boundPort ?? Int(port)
        log.event("EST", "tcp \(estPort): https://\(info.dcDNSName)\(estPort == 443 ? "" : ":\(estPort)")/.well-known/est "
                  + "(cacerts, simpleenroll, simplereenroll, csrattrs; Basic = device + challenge)")
    }

    /// PK-6: the MS-XCEP policy service and the MS-WSTEP enrollment service over HTTPS with the DC
    /// certificate, authenticated with HTTP Negotiate against the store (Kerberos
    /// `HTTP/<dc fqdn>` — resolved to the DC account through the `http` sPNMappings alias —
    /// with NTLM fallback). The policy ID is the one the Default Domain Policy gives the client.
    private func startHTTPS(caService: CAService, pki: LabPKI, store: DirectoryStore, info: DomainInfo,
                            port requested: UInt16? = nil) async throws {
        guard options.httpsEnabled else { return }
        let port = requested ?? options.ports.https
        if let problem = PortProbe.problem(port: port, protos: [.tcp]) {
            throw CLIError.failure("HTTPS tcp \(port): \(problem)")
        }
        let log = self.log
        let service: EnrollmentWebService
        if let existing = enrollmentWeb {
            service = existing
        } else {
            let secrets: StoreSecretSource
            do { secrets = try await StoreSecretSource(store: store) } catch {
                throw CLIError.failure("HTTPS secret source: \(error)")
            }
            let sysvol = data.sysvolURL
            let policyID: @Sendable () async -> String = {
                let editor = GroupPolicyEditor(root: sysvol, store: store)
                if let id = try? await editor.autoEnrollmentPolicyID() { return id }
                return (try? await AutoEnrollmentSettings.defaultPolicyID(store: store)) ?? ""
            }
            let host = info.dcDNSName
            let portBox = HTTPSPortBox()
            let baseURL: @Sendable () async -> String = {
                let p = portBox.port
                return "https://\(host)" + (p == 443 || p == 0 ? "" : ":\(p)")
            }
            let xcep = XCEPService(ca: caService, policyID: policyID, baseURL: baseURL,
                                   onEvent: { line in log.event("XCEP", Self.dropPrefix(line, "XCEP ")) })
            let wstep = WSTEPService(ca: caService, onEvent: { line in log.event("WSTEP", Self.dropPrefix(line, "WSTEP ")) })
            service = EnrollmentWebService(xcep: xcep, wstep: wstep,
                                           authenticator: HTTPNegotiateAuthenticator(source: secrets),
                                           onEvent: { line in log.event("HTTPS", line) })
            enrollmentWeb = service
            httpsPortBox = portBox
        }
        var onRequest: (@Sendable (String) -> Void)?
        if options.verbose { onRequest = { line in log.event("HTTPS", line) } }
        let server: PKIHTTPServer
        do { server = try await service.makeServer(port: Int(port), pki: pki, onRequest: onRequest) } catch {
            throw CLIError.failure("HTTPS TLS: \(error)")
        }
        do { try await server.start() } catch { throw CLIError.failure("HTTPS tcp \(port): \(error)") }
        https = server
        bound.https = server.boundPort
        let httpsPort = server.boundPort ?? Int(port)
        httpsPortBox?.port = httpsPort
        let base = "https://\(info.dcDNSName)\(httpsPort == 443 ? "" : ":\(httpsPort)")"
        let ca = (try? await pki.currentAuthority().name) ?? LabPKI.labCAName
        log.event("HTTPS", "tcp \(httpsPort): CEP \(base)\(XCEPService.path), CES \(base)/\(ca)_CES_Kerberos/service.svc/CES "
                  + "(Negotiate: Kerberos HTTP/\(info.dcDNSName), NTLM)")
    }

    static func dropPrefix(_ line: String, _ prefix: String) -> String {
        line.hasPrefix(prefix) ? String(line.dropFirst(prefix.count)) : line
    }

    /// WPA3-Enterprise 192-bit at start: an existing P-384 802.1X CA is kept and its RADIUS
    /// certificate renewed; a missing one is created only when a 192-bit template is enabled
    /// (e.g. from the CLI while the server was stopped). Otherwise nothing — the CA appears when
    /// a 192-bit profile is published or a 192-bit template enabled.
    private func prepareSuiteB(caService: CAService, pki: LabPKI, info: DomainInfo) async {
        do {
            var created = false
            if try await !pki.hasSuiteBCA() {
                let wanted = (try? await caService.templates())?.contains { $0.enabled && $0.issuingCA == LabPKI.suiteBCAName } ?? false
                guard wanted else { return }
                created = try await caService.ensureSuiteBAuthority()
            }
            let leaf = try await pki.ensureSuiteBServerCertificate(hostname: info.dcDNSName)
            if created || leaf == .issued {
                log.event("PKI", "802.1X 192-bit CA (P-384) \(created ? "created" : "loaded"), "
                          + "RADIUS certificate \(leaf == .issued ? "issued" : "unchanged") for \(info.dcDNSName)")
            }
        } catch {
            log.warning("PKI", "802.1X 192-bit CA / RADIUS certificate: \(error) — WPA3-Enterprise 192-bit clients cannot connect")
        }
    }

    /// The EAP credentials, read per use: the DC certificate and, once the 802.1X 192-bit CA
    /// exists (created while running: a 192-bit profile or template), its P-384 RADIUS
    /// certificate — issued here on first need and recorded in the issuance database.
    func eapCredentials() async -> EAPCredentials? {
        guard let pki, let c = try? await pki.eapServerCredentials() else { return nil }
        var suiteB = (try? await pki.eapSuiteBCredentials()).flatMap { $0 }
        if suiteB == nil, suiteBIssuance.allows(), (try? await pki.hasSuiteBCA()) == true, let store,
           let info = try? await store.domainInfo(), suiteBIssuance.begin() {
            // `begin` holds the window while this attempt runs, so concurrent EAP exchanges do
            // not issue (or fail and log) in parallel.
            do {
                if try await pki.ensureSuiteBServerCertificate(hostname: info.dcDNSName) == .issued {
                    log.event("PKI", "802.1X 192-bit RADIUS certificate issued for \(info.dcDNSName)")
                    if let caService { await recordSuiteBServerCertificate(caService, pki: pki, info: info) }
                }
                suiteBIssuance.succeeded()
                suiteB = (try? await pki.eapSuiteBCredentials()).flatMap { $0 }
            } catch {
                suiteBIssuance.failed()
                log.warning("PKI", "802.1X 192-bit RADIUS certificate: \(error) — WPA3-Enterprise 192-bit clients cannot connect; "
                            + "next try in \(suiteBIssuance.intervalText)")
            }
        }
        return EAPCredentials(chain: c.chain, keyDER: c.keyDER,
                              suiteB: suiteB.map { TLSContext.Credential(chain: $0.chain, keyDER: $0.keyDER) })
    }

    private func recordSuiteBServerCertificate(_ service: CAService, pki: LabPKI, info: DomainInfo) async {
        guard let radius = await pki.suiteBServerCertificate() else { return }
        let dcSID = try? await store?.read(dn: info.dcComputerDN)?.sid?.description
        do {
            try await service.record(radius, caName: LabPKI.suiteBCAName, templateName: "RadiusServerSuiteB",
                                     requester: RequesterIdentity(name: info.dcName.uppercased() + "$", sid: dcSID))
        } catch {
            log.warning("PKI", "cannot record the 192-bit RADIUS certificate: \(error)")
        }
    }

    /// Records the DC certificate in the issuance database (template `DomainControllerTLS`).
    private func recordServerCertificate(_ service: CAService, pki: LabPKI, info: DomainInfo) async {
        guard let certificate = try? await pki.serverCertificate(), let ca = try? await pki.currentAuthority() else { return }
        let dcSID = try? await store?.read(dn: info.dcComputerDN)?.sid?.description
        do {
            try await service.record(certificate, caName: ca.name, templateName: "DomainControllerTLS",
                                     requester: RequesterIdentity(name: info.dcName.uppercased() + "$", sid: dcSID))
        } catch {
            log.warning("PKI", "cannot record the DC certificate: \(error)")
        }
        await recordSuiteBServerCertificate(service, pki: pki, info: info)
    }

    /// True for a machine account (`sAMAccountType` SAM_MACHINE_ACCOUNT, or a `NAME$` sAMAccountName).
    private static func isComputer(_ entry: DirectoryEntry) -> Bool {
        if let t = entry.int("sAMAccountType"), UInt32(truncatingIfNeeded: t) == SAMAccountType.machineAccount { return true }
        return entry.string("sAMAccountName")?.hasSuffix("$") ?? false
    }

    private func startLDAP(store: DirectoryStore, pki: LabPKI) async throws {
        let p = options.ports
        var config = DirectoryServerConfig(ldapPort: Int(p.ldap), ldapsPort: Int(p.ldaps), globalCatalogPort: Int(p.gc),
                                           globalCatalogTLSPort: Int(p.gcs), vendorVersion: Self.vendorVersion)
        config.advertisedIPv4 = options.advertise
        // UI-1: bind outcomes on the serve log (the app's activity list) and "Allow plain LDAP".
        let log = self.log
        config.onBind = { line in log.event("LDAP", "bind " + line) }
        config.allowPlainSimpleBind = options.allowPlainLDAP
        let server = DirectoryServer(store: store, pki: pki, config: config)
        do { try await server.start() } catch {
            throw CLIError.failure("LDAP tcp \(p.ldap)/\(p.ldaps)/\(p.gc)/\(p.gcs): \(error)")
        }
        ldap = server
        let ports = server.boundPorts
        bound.ldap = ports.ldap
        bound.ldaps = ports.ldaps
        bound.gc = ports.globalCatalog
        bound.gcs = ports.globalCatalogTLS
    }

    /// The certificate's SAN set: DC name, domain, localhost, every IPv4, 127.0.0.1, `--advertise`.
    private func serverNames(_ info: DomainInfo) -> LabPKI.SubjectAltNames {
        var names = LabPKI.defaultServerNames(dcHostname: info.dcDNSName, dnsDomain: info.dnsDomain)
        if let advertise = options.advertise, !names.ips.contains(advertise) { names.ips.insert(advertise, at: 0) }
        return names
    }

    /// Re-reads the interface addresses; on a change, reissues the DC certificate and restarts
    /// the LDAP listeners (their TLS context is built once at start). DNS reads addresses per
    /// query and CLDAP per datagram, so they follow by themselves.
    func checkAddresses() async {
        let now = Set(ServeAddresses.current())
        guard now != lastAddresses else { return }
        log.event("PKI", "IPv4 addresses changed: \(lastAddresses.sorted().joined(separator: ", ")) -> \(now.sorted().joined(separator: ", "))")
        lastAddresses = now
        await addressesChanged(now)
        guard let pki, let store, let info = try? await store.domainInfo() else { return }
        let names = serverNames(info)
        do {
            let outcome = try await pki.ensureServerCertificate(hostnames: names.hostnames, ips: names.ips)
            guard outcome == .issued else { return }
            log.event("PKI", "DC certificate reissued for \((names.hostnames + names.ips).joined(separator: ", ")); restarting LDAP"
                      + (est == nil ? "" : ", EST") + (https == nil ? "" : ", HTTPS"))
            if let caService { await recordServerCertificate(caService, pki: pki, info: info) }
            await ldap?.stop()
            ldap = nil
            try await startLDAP(store: store, pki: pki)
            if let server = est, let caService {
                await server.stop()
                est = nil
                bound.est = nil
                try await startEST(caService: caService, pki: pki, info: info,
                                   port: server.boundPort.map { UInt16($0) } ?? options.ports.est)
            }
            if let server = https, let caService {
                await server.stop()
                https = nil
                bound.https = nil
                try await startHTTPS(caService: caService, pki: pki, store: store, info: info,
                                     port: server.boundPort.map { UInt16($0) } ?? options.ports.https)
            }
        } catch {
            log.warning("PKI", "certificate reissue / LDAP restart failed: \(error)")
        }
        if now.count > 1, options.advertise == nil { log.warning("serve", Self.multipleAddressWarning(Array(now))) }
    }

    /// Stops everything, in reverse order. Safe to call twice.
    public func stop() async {
        watcher?.cancel()
        watcher = nil
        crlTimer?.cancel()
        crlTimer = nil
        await https?.stop()
        https = nil
        enrollmentWeb = nil
        httpsPortBox = nil
        await est?.stop()
        est = nil
        estService = nil
        await http?.stop()
        http = nil
        scepService = nil
        caService = nil
        await epm?.stop()
        epm = nil
        await rpcTCP?.stop()
        rpcTCP = nil
        dcServices = nil
        await nbns?.stop()
        nbns = nil
        radius?.stop()
        radius = nil
        radiusStartFailure = nil
        sntp?.stop()
        sntp = nil
        await smb?.stop()
        smb = nil
        netlogonState = nil
        cldap?.stop()
        cldap = nil
        await ldap?.stop()
        ldap = nil
        kpasswd?.stop()
        kpasswd = nil
        kdc?.stop()
        kdc = nil
        dns?.stop()
        dns = nil
        bound = ServeBoundPorts()
    }

    public static func multipleAddressWarning(_ addresses: [String]) -> String {
        "this Mac has \(addresses.count) LAN IPv4 addresses (\(addresses.sorted().joined(separator: ", "))); DNS publishes all of them "
            + "and CLDAP answers with the address a ping arrived on. Pass --advertise <ipv4> to pin the one Windows clients should use."
    }

    /// The startup banner: realm, every bound port, the store and the CA.
    public func banner() async -> String {
        var lines: [String] = []
        let info = try? await store?.domainInfo()
        lines.append("labdc serve: realm \(info?.realm ?? "?"), domain \(info?.dnsDomain ?? "?"), "
                     + "NetBIOS \(info?.netbiosDomain ?? "?"), DC \(info?.dcDNSName ?? "?")")
        func row(_ name: String, _ proto: String, _ port: CustomStringConvertible?) {
            let value = port.map { "\($0)" } ?? "off"
            lines.append("  " + name.padding(toLength: 10, withPad: " ", startingAt: 0) + proto.padding(toLength: 9, withPad: " ", startingAt: 0) + value)
        }
        row("DNS", "udp+tcp", bound.dns)
        row("Kerberos", "udp+tcp", bound.kdc)
        row("kpasswd", "udp+tcp", bound.kpasswd)
        row("LDAP", "tcp", bound.ldap)
        row("LDAPS", "tcp", bound.ldaps)
        row("GC", "tcp", bound.gc)
        row("GC-TLS", "tcp", bound.gcs)
        row("CLDAP", "udp", bound.cldap)
        row("SMB", "tcp", bound.smb)
        row("NBSS", "tcp", bound.nbss)
        row("NBNS", "udp", bound.nbns)
        row("SNTP", "udp", bound.sntp)
        row("EPM", "tcp", bound.epm)
        row("RPC", "tcp", bound.rpc)
        row("HTTP", "tcp", bound.http)
        row("EST", "tcp", bound.est)
        row("HTTPS", "tcp", bound.https)
        lines.append("  store     \(data.storeURL.path)")
        lines.append("  lab CA    \(data.caURL.path)")
        let current = try? await pki?.currentAuthority()
        let caPath = current?.certificateURL.path ?? data.caURL.path
        if let current, let info {
            lines.append("  CA        \(current.name) (\(current.keyType.displayName), \(current.certificate.subject)), "
                         + "CRL http://\(info.dcDNSName)\(CAService.crlPath(caName: current.name))")
        }
        lines.append("  trust it: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '\(caPath)'")
        let addresses = ServeAddresses.current()
        lines.append("  address   " + (options.advertise.map { "\($0) (--advertise)" } ?? (addresses.isEmpty ? "none (127.0.0.1)" : addresses.joined(separator: ", "))))
        return lines.joined(separator: "\n")
    }
}

// MARK: - UI-1: in-place listener restart and the advertised address (LabDCCore.ServerController)
//
// Kept in this file so it can reach the private listener properties; the start code of the
// listeners that `startAll` builds inline (DNS, KDC, kpasswd, CLDAP) is repeated here rather than
// moved, so `startAll` stays as it was.

extension ServeRuntime {
    /// The IPv4 DNS/CLDAP/the endpoint mapper hand out: `--advertise`, else the first interface address.
    public var advertisedIPv4: String? { options.advertise ?? ServeAddresses.current().first }

    /// Moves one listener to `port` while everything else keeps running. LDAP/LDAPS/GC/GC-TLS share
    /// one server, SMB+SNTP and EPM+RPC restart together. When the new port cannot be bound the old
    /// one is bound again and the error is rethrown. A disabled listener only records the port.
    public func restart(_ listener: ServeListener, port: UInt16) async throws {
        let old = options.ports[listener]
        options.ports[listener] = port
        do {
            try await restartListener(listener)
            log.event("serve", "\(listener.displayName) moved to \(listener.transport) \(port) (was \(old))")
        } catch {
            options.ports[listener] = old
            log.warning("serve", "\(listener.displayName) could not move to \(listener.transport) \(port): \(error); back on \(old)")
            try? await restartListener(listener)
            throw error
        }
    }

    /// UI-1c (the network interface picker): pins the address devices are told (`--advertise`;
    /// nil = automatic, the first interface address) while everything keeps running. DNS, CLDAP,
    /// LDAP pings, SMB/NetBIOS, the NETLOGON DC locator and the endpoint mapper take the address
    /// when they start, so those listeners restart in place on their ports (the NETLOGON secure
    /// channels survive). Logs `advertising <ip> (<label>)` and reports the change to the observer.
    public func setAdvertise(_ address: String?, label: String? = nil) async throws {
        guard address != options.advertise else { return }
        options.advertise = address
        let advertised = advertisedIPv4
        let how = address == nil ? "automatic, first address" : "pinned in Settings"
        log.event("serve", "advertising \(advertised ?? "no address (127.0.0.1)")" + (label.map { " on \($0)" } ?? "") + " (\(how))")
        log.runtimeEvent(.addressesChanged(advertised: advertised, addresses: ServeAddresses.current(), pinned: address != nil))
        guard store != nil else { return }
        dcServices = nil  // rebuilt with the new StaticNetlogonDCInfoProvider (same NetlogonStateStore)
        try await restartInPlace([.dns, .cldap, .ldap, .smb, .nbns, .epm], name: "advertised address")
    }

    // MARK: DNS forwarding

    /// A DNS server whose forwarder follows `forwardingState` (the setting, this Mac's addresses
    /// and the bound port, so it never forwards to itself).
    private func makeDNSServer(source: StoreZoneSource, port: UInt16) -> DNSServer {
        forwardingState.update(forwarding: options.dnsForwarding, port: port, advertise: options.advertise)
        let state = forwardingState
        let forwarder = DNSForwarder(plan: { state.plan() })
        dnsForwarder = forwarder
        return DNSServer(source: source, port: port, forwarder: forwarder)
    }

    private func dnsServerStarted(_ server: DNSServer) async {
        forwardingState.update(forwarding: options.dnsForwarding, port: server.port, advertise: options.advertise)
        guard let plan = await dnsForwarder?.refreshPlan() else { return }
        await logForwarding(plan)
    }

    private func logForwarding(_ plan: DNSResolverPlan) async {
        let domain = (try? await store?.domainInfo().dnsDomain) ?? "the domain"
        log.event("DNS", "names outside \(domain) go to \(plan.summary) (\(plan.originText))")
        if !plan.skipped.isEmpty {
            log.warning("DNS", "not forwarding to \(plan.skipped.map(\.settingsText).joined(separator: ", ")): that is this DNS server itself")
        }
    }

    /// Where names outside the domain go now; nil while DNS is not running.
    public func dnsForwardingPlan() async -> DNSResolverPlan? {
        guard dns != nil, let dnsForwarder else { return nil }
        return await dnsForwarder.currentPlan()
    }

    /// Settings ▸ Directory ▸ Other names: applied live, DNS keeps running.
    @discardableResult
    public func setDNSForwarding(_ forwarding: DNSForwarding) async -> DNSResolverPlan? {
        guard forwarding != options.dnsForwarding else { return await dnsForwardingPlan() }
        options.dnsForwarding = forwarding
        forwardingState.update(forwarding: forwarding, port: forwardingState.port, advertise: options.advertise)
        guard dns != nil, let plan = await dnsForwarder?.refreshPlan() else { return nil }
        await logForwarding(plan)
        return plan
    }

    /// UI-1b (Overview ▸ Restart on a service row): stops and starts `listeners` on the ports they
    /// have now (an ephemeral or dynamic port is kept), everything else keeps running. Listeners
    /// that share a server restart together (see `ServeListener.restartsWith`); disabled ones are
    /// skipped. Logs one `serve restart …` line with the outcome; rethrows the first failure after
    /// trying every group.
    public func restartInPlace(_ listeners: [ServeListener], name: String) async throws {
        var groups: [ServeListener] = []
        for l in listeners where l.isEnabled(in: options) {
            let head = l.restartsWith.first ?? l
            if !groups.contains(head) { groups.append(head) }
        }
        for group in groups {
            for l in group.restartsWith where options.ports[l] == 0 {
                if let p = l.bound(in: bound) { options.ports[l] = UInt16(truncatingIfNeeded: p) }
            }
        }
        // The SMB group already restarts NBNS.
        if groups.contains(.smb) { groups.removeAll { $0 == .nbns } }
        var firstError: Error?
        for group in groups {
            do { try await restartListener(group) } catch { if firstError == nil { firstError = error } }
        }
        let ports = listeners.compactMap { l in l.bound(in: bound).map { "\(l.shortName) \($0)" } }.joined(separator: ", ")
        if let firstError {
            log.warning("serve", "restart \(name): \(firstError)")
            throw firstError
        }
        log.event("serve", "restart \(name) -> OK" + (ports.isEmpty ? "" : " (\(ports))"))
    }

    private func restartListener(_ listener: ServeListener) async throws {
        guard let store, let pki, let info = try? await store.domainInfo() else { return }
        let ports = options.ports
        let log = self.log
        switch listener {
        case .dns:
            guard options.dnsEnabled else { return }
            dns?.stop(); dns = nil; bound.dns = nil
            await Self.waitUntilFree(ports.dns, [.udp, .tcp])
            let source = StoreZoneSource(store: store, advertise: options.advertise, onChange: { line in log.event("DNS", line) })
            let server = makeDNSServer(source: source, port: ports.dns)
            do { try await server.start() } catch { throw CLIError.failure("DNS udp+tcp \(ports.dns): \(error)") }
            dns = server
            bound.dns = server.port
            await dnsServerStarted(server)
        case .kdc, .kpasswd:
            let port = listener == .kdc ? ports.kdc : ports.kpasswd
            if listener == .kdc { kdc?.stop(); kdc = nil; bound.kdc = nil } else { kpasswd?.stop(); kpasswd = nil; bound.kpasswd = nil }
            await Self.waitUntilFree(port, [.udp, .tcp])
            if let problem = PortProbe.problem(port: port, protos: [.udp, .tcp]) {
                throw CLIError.failure("\(listener == .kdc ? "KDC" : "kpasswd") udp+tcp \(port): \(problem)")
            }
            let principals = try await DirectoryPrincipalStore(directory: store)
            let verbose = options.verbose
            let onExchange: @Sendable (ExchangeRecord) -> Void = { record in
                var line = record.description
                if verbose {
                    line += " [\(record.replySize) bytes]"
                    if let reason = record.reason { line += " (\(reason))" }
                }
                log.event(record.kind == .kpasswd ? "kpasswd" : "KDC", line)
            }
            if listener == .kdc {
                let server = KDCServer(kdc: KDC(store: principals, onExchange: onExchange), port: port, bindAddress: "0.0.0.0")
                do { try await server.start() } catch { throw CLIError.failure("KDC udp+tcp \(port): \(error)") }
                kdc = server
                bound.kdc = server.port
            } else {
                let server = KPasswdServer(service: KPasswdService(store: principals, onExchange: onExchange), port: port,
                                           bindAddress: "0.0.0.0")
                do { try await server.start() } catch { throw CLIError.failure("kpasswd udp+tcp \(port): \(error)") }
                kpasswd = server
                bound.kpasswd = server.port
            }
        case .ldap, .ldaps, .gc, .gcs:
            await ldap?.stop(); ldap = nil
            bound.ldap = nil; bound.ldaps = nil; bound.gc = nil; bound.gcs = nil
            try await startLDAP(store: store, pki: pki)
        case .cldap:
            cldap?.stop(); cldap = nil; bound.cldap = nil
            await Self.waitUntilFree(ports.cldap, [.udp])
            let server = CLDAPServer(store: store, config: CLDAPServerConfig(
                port: ports.cldap, advertisedIPv4: options.advertise, vendorVersion: Self.vendorVersion))
            do { try await server.start() } catch { throw CLIError.failure("CLDAP udp \(ports.cldap): \(error)") }
            cldap = server
            bound.cldap = server.port
        case .smb, .sntp, .nbss:
            // startSMBAndSNTP also (re)starts NBNS, so stop it here too.
            await smb?.stop(); smb = nil; bound.smb = nil; bound.nbss = nil
            sntp?.stop(); sntp = nil; bound.sntp = nil
            await nbns?.stop(); nbns = nil; bound.nbns = nil
            await Self.waitUntilFree(ports.sntp, [.udp])
            if options.netbiosEnabled { await Self.waitUntilFree(ports.nbns, [.udp]) }
            try await startSMBAndSNTP(store: store, info: info)
        case .nbns:
            await nbns?.stop(); nbns = nil; bound.nbns = nil
            await Self.waitUntilFree(ports.nbns, [.udp])
            try await startNBNS(info: info)
        case .radius, .radacct:
            radius?.stop(); radius = nil
            bound.radius = nil; bound.radacct = nil
            radiusStartFailure = nil
            guard options.radiusEnabled else { return }
            await Self.waitUntilFree(ports.radius, [.udp])
            await Self.waitUntilFree(ports.radacct, [.udp])
            try await startRadius(store: store)
        case .epm, .rpc:
            try await restartRPC(store: store, info: info)
        case .http:
            guard let caService else { return }
            crlTimer?.cancel(); crlTimer = nil
            await http?.stop(); http = nil; bound.http = nil
            scepService = nil
            try await startHTTP(caService: caService, info: info)
        case .est:
            guard let caService else { return }
            await est?.stop(); est = nil; bound.est = nil
            try await startEST(caService: caService, pki: pki, info: info)
        case .https:
            guard let caService else { return }
            await https?.stop(); https = nil; bound.https = nil; enrollmentWeb = nil
            try await startHTTPS(caService: caService, pki: pki, store: store, info: info)
        }
    }

    /// Network.framework listeners (DNS, KDC/kpasswd, CLDAP, SNTP) release their port a moment
    /// after `cancel()`; a restart on the same port waits for that (at most 5 s) instead of
    /// failing with "port in use" against itself.
    static func waitUntilFree(_ port: UInt16, _ protos: [PortProbe.Proto]) async {
        guard port != 0 else { return }
        for _ in 0..<100 {
            if PortProbe.problem(port: port, protos: protos) == nil { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Phase 4a: binds RADIUS auth + accounting (`RadiusServer`); errors name the service
    /// (`RADIUS udp 1812: …`) so the Services row picks them up.
    private func startRadius(store: DirectoryStore) async throws {
        let ports = options.ports
        for port in [ports.radius, ports.radacct] where port != 0 {
            if let problem = PortProbe.problem(port: port, protos: [.udp]) {
                throw CLIError.failure("RADIUS udp \(port): \(problem)")
            }
        }
        let log = self.log
        // Phase 4b: EAP (TLS, PEAP, TTLS) with the DC certificate; client certificates must
        // chain to one of this DC's CAs. Read per use, so a reissued certificate (or a 192-bit
        // CA created while running) is picked up.
        let pki = self.pki
        let server = RadiusServer(store: store,
                                  eapCredentials: { [weak self] in await self?.eapCredentials() },
                                  trustRoots: { (try? await pki?.authorityCertificatesDER()) ?? [] },
                                  log: { line in log.event("RADIUS", line) })
        do { try server.start(authPort: ports.radius, acctPort: ports.radacct) } catch {
            throw CLIError.failure("RADIUS udp \(ports.radius)+\(ports.radacct): \(error)")
        }
        radius = server
        bound.radius = Int(server.authPort)
        bound.radacct = Int(server.acctPort)
    }

    /// A RADIUS client or policy changed (app, CLI through the app): the server reloads its config.
    public func radiusConfigChanged() {
        radius?.configChanged()
    }

    private func restartRPC(store: DirectoryStore, info: DomainInfo) async throws {
        await epm?.stop(); epm = nil; bound.epm = nil
        await rpcTCP?.stop(); rpcTCP = nil; bound.rpc = nil
        try await startRPCTCP(store: store, info: info)
    }

    /// Called by `checkAddresses` on every change of the interface list: tells the observer
    /// (`ServeLog.onRuntimeEvent`) and, when `--advertise` is not pinned, re-registers the endpoint
    /// mapper, whose towers carry the advertised address. DNS, CLDAP and LDAP pings pick the new
    /// address per request by themselves.
    func addressesChanged(_ now: Set<String>) async {
        let advertised = advertisedIPv4
        log.runtimeEvent(.addressesChanged(advertised: advertised, addresses: now.sorted(), pinned: options.advertise != nil))
        guard options.advertise == nil else { return }
        log.event("serve", "advertising \(advertised ?? "no address (127.0.0.1)") (automatic; --advertise not pinned)")
        // UI-1c: NBNS answers with the address it started with.
        if nbns != nil, options.netbiosEnabled {
            if let p = bound.nbns, options.ports.nbns == 0 { options.ports.nbns = UInt16(truncatingIfNeeded: p) }
            try? await restartListener(.nbns)
        }
        guard epm != nil, let store, let info = try? await store.domainInfo() else { return }
        // Same ports again (an ephemeral 0 would move them).
        if let p = bound.rpc, options.ports.rpc == 0 { options.ports.rpc = UInt16(truncatingIfNeeded: p) }
        if let p = bound.epm, options.ports.epm == 0 { options.ports.epm = UInt16(truncatingIfNeeded: p) }
        do {
            try await restartRPC(store: store, info: info)
            log.event("RPC", "endpoint mapper re-registered for \(advertised ?? "127.0.0.1")")
        } catch {
            log.warning("RPC", "endpoint mapper re-registration failed: \(error)")
        }
    }
}

/// A retry gate for work that may keep failing on a hot path (the 192-bit RADIUS certificate
/// issued on first EAP use): after a failure, `allows()` is false for `interval`; `begin()`
/// also closes it while an attempt runs, so concurrent callers do not repeat it.
struct RetryWindow: Sendable {
    let interval: Duration
    private(set) var notBefore: ContinuousClock.Instant?
    private(set) var inFlight = false

    init(interval: Duration) { self.interval = interval }

    func allows(at now: ContinuousClock.Instant = .now) -> Bool {
        !inFlight && (notBefore.map { now >= $0 } ?? true)
    }

    /// Starts an attempt; false when one runs already or the window is closed.
    mutating func begin(at now: ContinuousClock.Instant = .now) -> Bool {
        guard allows(at: now) else { return false }
        inFlight = true
        return true
    }

    mutating func succeeded() {
        inFlight = false
        notBefore = nil
    }

    mutating func failed(at now: ContinuousClock.Instant = .now) {
        inFlight = false
        notBefore = now + interval
    }

    var intervalText: String {
        let minutes = Int(interval.components.seconds / 60)
        return minutes >= 1 ? "\(minutes) min" : "\(interval.components.seconds) s"
    }
}
