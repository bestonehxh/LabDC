import AuthKit
import DNSKit
import EAPKit
import DirectoryKit
import Foundation
import KDC
import LSAService
import NetlogonService
import PKIKit
import RADIUSKit
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
    /// Phase 5: DHCPv4 (udp 67) and DHCPv6 (udp 547); nil until a scope exists.
    public var dhcp: Int?
    public var dhcpv6: Int?

    public init() {}

    /// Every bound port with its listener and protocols (NBSS shares the SMB server; each
    /// port is listed once per listener).
    public var held: [ServeHeldPort] {
        ServeListener.allCases.compactMap { l in
            guard let p = l.bound(in: self), p > 0, p <= Int(UInt16.max) else { return nil }
            return ServeHeldPort(listener: l, port: UInt16(p), protos: ServeHeldPort.protos(l))
        }
    }
}

/// A port a runtime held, kept across a stop so the next start can wait until it is free.
public struct ServeHeldPort: Sendable, Equatable {
    public var listener: ServeListener
    public var port: UInt16
    public var protos: [PortProbe.Proto]

    public static func protos(_ l: ServeListener) -> [PortProbe.Proto] {
        switch l.transport {
        case "udp+tcp": [.udp, .tcp]
        case "udp": [.udp]
        default: [.tcp]
        }
    }

    /// Waits until every port is free (at most 5 s each; `ServeRuntime.waitUntilFree`).
    public static func waitUntilFree(_ ports: [ServeHeldPort]) async {
        for h in ports { await ServeRuntime.waitUntilFree(h.port, h.protos) }
    }
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
/// 14. Phase 5: DHCP (udp 67 + 547), once at least one scope exists
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
    /// The running DNS server's responder (Settings ▸ DNS "Dynamic updates" is applied to it live).
    private var dnsResponder: DNSResponder?
    /// Where names outside the domain go (Settings ▸ Directory ▸ Other names, `--forwarders`).
    private var dnsForwarder: DNSForwarder?
    private let forwardingState = DNSForwardingState()
    /// Who may use DNS as a resolver (this Mac's networks, the DHCP scopes, `--dns-allow`).
    private var dnsRecursionACL: DNSRecursionACL?
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
    /// Phase 5: where RADIUS reads device profiles (policy facts) and their change feed (CoA).
    /// `NoDeviceProfiles` until the DHCP side's store profiles are wired in.
    public private(set) var deviceProfiles: DeviceProfileSource = NoDeviceProfiles()
    /// Why RADIUS did not start with the rest (a held udp 1812/1813). RADIUS never stops the
    /// directory from starting; the Services row shows the problem and offers Restart.
    public private(set) var radiusStartFailure: String?
    /// Phase 5: the DHCP server (nil while no scope exists).
    public private(set) var dhcp: DHCPServer?
    /// Why DHCPv4 did not start (udp 67 held, e.g. by bootpd for Internet Sharing). Like
    /// RADIUS, it never stops the directory from starting.
    public private(set) var dhcpStartFailure: String?
    /// The pinned advertised address the DHCP server hands out (nil = first interface address).
    private let dhcpAdvertise = AdvertisedAddressBox()
    /// Why DHCPv6 did not start (udp 547 held, e.g. by InternetSharing). v4 and v6 are
    /// independent listeners: either runs without the other.
    public private(set) var dhcpv6StartFailure: String?
    /// While a DHCP family failed only because its port is busy, binding is retried this often
    /// in the background (it comes up by itself once Internet Sharing exits).
    public private(set) var dhcpRetryInterval: Duration = .seconds(30)
    private var dhcpRetryTask: Task<Void, Never>?
    /// `withDHCPLock`: one DHCP lifecycle operation at a time.
    private var dhcpLocked = false
    private var dhcpLockWaiters: [CheckedContinuation<Void, Never>] = []
    /// Services ▸ Stop on DHCP: a new scope does not start it again until Start.
    public var dhcpStoppedByOwner: Bool { options.ownerStopped.contains(.dhcp) }
    /// On-demand issuance of the 192-bit RADIUS certificate (`eapCredentials`): after a failure
    /// it is tried again at most every 10 minutes, with one log line per attempt.
    var suiteBIssuance = RetryWindow(interval: .seconds(600))
    /// The same for the RSA RADIUS certificate ("Allow RSA-only devices").
    var rsaIssuance = RetryWindow(interval: .seconds(600))
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
    /// Set by `stop()` (cleared by `start()`): every path that suspends and then binds checks it
    /// after its awaits, so a restart, a DHCP retry or an address change that was in flight when
    /// the runtime stopped never leaves a port bound in a stopped runtime (and if a bind raced
    /// the stop anyway, the listener is stopped again right away).
    public private(set) var stopped = false
    /// Every port this runtime had bound when it stopped (or released a late bind): the
    /// controller waits for them to come free before the next start on the same ports.
    public private(set) var releasedPorts: [ServeHeldPort] = []

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
            // The lab CA is made at the first start (`ensureCA`) with this key.
            try await store.setDomainValue(provision.caKeyType.rawValue, forKey: CAService.labCAKeyTypeKey)
            log.event("Store", "provisioned \(info.realm) (DNS \(info.dnsDomain), NetBIOS \(info.netbiosDomain), DC \(info.dcDNSName), SID \(info.domainSID), "
                      + "lab CA \(provision.caKeyType.displayName))")
        } else if !provisioned {
            throw CLIError.failure("the store at \(data.storeURL.path) is not provisioned; start once with "
                                   + "--provision realm=LAB.SHEEP dns=lab.sheep netbios=LABSHEEP dc=dc1 admin-password=<pw>")
        }
        return store
    }

    /// Starts every component; on any failure the ones already started are stopped again.
    @discardableResult
    public func start() async throws -> ServeBoundPorts {
        stopped = false
        do {
            let ports = try await startAll()
            // A stop() while the last listeners bound: nothing stays up.
            try checkRunning()
            return ports
        } catch {
            await stop()
            throw error
        }
    }

    /// Thrown by a bind path that finds the runtime stopped after one of its awaits.
    public struct Stopped: Error, CustomStringConvertible {
        public var description: String { "the server stopped" }
    }

    /// Call after an await, before binding: throws once `stop()` ran.
    func checkRunning() throws {
        if stopped { throw Stopped() }
    }

    /// Whether the owner left `service` running (Services ▸ Stop keeps it down until Start).
    func wants(_ service: ServeService) -> Bool { !options.ownerStopped.contains(service) }

    /// The end of a path that may have bound after suspending: when `stop()` ran meanwhile,
    /// whatever got bound is stopped again (and its ports recorded for the controller).
    func releaseIfStopped() async {
        guard stopped, anyListenerUp else { return }
        let late = bound.held
        log.event("serve", "stopping what was bound after the stop"
                  + (late.isEmpty ? "" : ": " + late.map { "\($0.listener.shortName) \($0.port)" }.joined(separator: ", ")))
        await stopAllListeners()
    }

    private func startAll() async throws -> ServeBoundPorts {
        let ports = options.ports
        // 1. Store
        let store = try await Self.openStore(data, provision: options.provision, log: log)
        self.store = store
        // Phase 5: RADIUS reads the DHCP side's device profiles (policy facts, auto-CoA) unless
        // a test or the app handed in another source.
        if deviceProfiles is NoDeviceProfiles { deviceProfiles = StoreDeviceProfileSource(store: store) }
        let info = try await store.domainInfo()
        log.event("Store", "\(data.storeURL.path): realm \(info.realm), DC \(info.dcDNSName)")

        // 2. PKI
        let pki: LabPKI
        let caService: CAService
        do {
            pki = try await LabPKI.open(directory: data.pkiURL)
            // A new domain's lab CA gets the key chosen at provisioning (P-384 by default); an
            // existing lab CA is kept as it is (never re-keyed: `labdc ca migrate` changes roots).
            let keyType = ((try? await store.domainValue(forKey: CAService.labCAKeyTypeKey)) ?? nil)
                .flatMap(CAKeyType.init(rawValue:)) ?? LabPKI.defaultLabCAKeyType
            let ca = try await pki.ensureCA(name: "LabDC Lab CA (\(info.realm))",
                                            alsoAccepting: ["SheepAuth Lab CA (\(info.realm))"], keyType: keyType)
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
            await prepareRSACompatibility(caService: caService, pki: pki, info: info)
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

        try checkRunning()
        // 3. DNS
        if options.dnsEnabled, wants(.dns) {
            let log = self.log
            // GSS-TSIG: members ask for a ticket to DNS/<dc fqdn> before a secure update.
            do {
                let added = try await store.ensureDNSServicePrincipalNames()
                if !added.isEmpty { log.event("DNS", "service principal names added to the DC account: \(added.joined(separator: ", "))") }
            } catch {
                log.warning("DNS", "cannot add the DNS service principal names to the DC account: \(error)")
            }
            let source = StoreZoneSource(store: store, advertise: options.advertise,
                                         onChange: { line in log.event("DNS", line) })
            let server = await makeDNSServer(source: source, port: ports.dns)
            do { try await server.start() } catch {
                throw CLIError.failure("DNS udp+tcp \(ports.dns): \(error)")
            }
            dns = server
            bound.dns = server.port
            await dnsServerStarted(server)
        }

        // 4. KDC + kpasswd
        if wants(.kerberos) {
            try checkRunning()
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
            try checkRunning()
            let kdcServer = KDCServer(kdc: KDC(store: principals, onExchange: onExchange), port: ports.kdc, bindAddress: "0.0.0.0")
            do { try await kdcServer.start() } catch { throw CLIError.failure("KDC udp+tcp \(ports.kdc): \(error)") }
            kdc = kdcServer
            bound.kdc = kdcServer.port
            try checkRunning()
            let kpw = KPasswdServer(service: KPasswdService(store: principals, onExchange: onExchange), port: ports.kpasswd,
                                    bindAddress: "0.0.0.0")
            do { try await kpw.start() } catch { throw CLIError.failure("kpasswd udp+tcp \(ports.kpasswd): \(error)") }
            kpasswd = kpw
            bound.kpasswd = kpw.port
        }

        if wants(.directory) {
            // 5. LDAP / LDAPS / GC
            try await startLDAP(store: store, pki: pki)

            // 6. CLDAP
            try checkRunning()
            let cldapServer = CLDAPServer(store: store, config: CLDAPServerConfig(
                port: ports.cldap, advertisedIPv4: options.advertise, vendorVersion: Self.vendorVersion))
            do { try await cldapServer.start() } catch { throw CLIError.failure("CLDAP udp \(ports.cldap): \(error)") }
            cldap = cldapServer
            bound.cldap = cldapServer.port
        }

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
        try checkRunning()
        if options.radiusEnabled, wants(.radius) {
            do { try await startRadius(store: store) } catch {
                radiusStartFailure = "\(error)"
                log.warning("RADIUS", "\(error)")
            }
        }

        // 14. DHCP (phase 5): with the directory once a scope exists; a held port is a problem
        // on its Services row.
        try checkRunning()
        if options.dhcpEnabled, wants(.dhcp) {
            do { try await withDHCPLock { try await startDHCPIfNeeded(store: store) } } catch {
                recordDHCPError(error)
                log.warning("DHCP", "\(error)")
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

        if options.smbEnabled, wants(.fileAndRPC) {
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
            do {
                let dropped = try await GroupPolicyEditor(root: data.sysvolURL, store: store).dropOrphanDot1XExtensions()
                if !dropped.isEmpty {
                    log.event("GPO", "802.1X: removed \(dropped.count == 2 ? "the wireless and wired" : dropped[0] == GPOExtensionNames.wirelessCSE ? "the wireless" : "the wired") "
                              + "extension left without a policy (gpupdate reported it failed); PCs drop the old profiles at their next gpupdate")
                }
            } catch {
                log.warning("GPO", "cannot check the 802.1X extensions: \(error)")
            }

            try checkRunning()
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
            var config: SMBServerConfig
            do { config = try await SMBServerConfig.from(store: store) } catch {
                throw CLIError.failure("SMB config from store: \(error)")
            }
            config.advertisedIPv4 = options.advertise
            let secrets: StoreSecretSource
            do { secrets = try await StoreSecretSource(store: store) } catch {
                throw CLIError.failure("SMB secret source: \(error)")
            }
            // MS-BKRP: `\protected_storage` needs RPC-level NTLMSSP / SPNEGO / Kerberos at packet
            // privacy (DPAPI binds that way), so that pipe gets the same negotiator as the TCP endpoint.
            let pipes = dcServicesShared(store: store, info: info).pipeServices(rpcAuth: RPCServerAuthConfig(
                makeNTLMServer: { NTLMServer(source: secrets, allowAnonymous: false) },
                makeKerberosAcceptor: { KerberosAcceptor(source: secrets) }))
            try checkRunning()
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
                      + "pipes \\samr \\lsarpc \\netlogon \\srvsvc \\wkssvc \\protected_storage")
            if let nb = server.boundNetbiosPort {
                log.event("NBSS", "tcp \(nb): NetBIOS session service (SMB over NetBIOS)")
            }
        }

        try await startNBNS(info: info)

        if options.sntpEnabled, wants(.time) {
            try checkRunning()
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
        guard options.netbiosEnabled, wants(.fileAndRPC) else { return }
        try checkRunning()
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
            drsOnEvent: { line in log.event("DRSUAPI", line) },
            // MS-BKRP: `BKRP RetrieveBackupKey from best@192.0.2.10 -> OK key {…}`.
            backupKeyOnEvent: { line in log.event("BKRP", line) })
        dcServices = s
        return s
    }

    /// Starts the shared dynamic `ncacn_ip_tcp` endpoint (LSARPC/dssetup, SAMR, NETLOGON) and the RPC
    /// endpoint mapper on TCP 135. The dynamic endpoint binds first so its port is known before the
    /// endpoint mapper advertises it. Identity on TCP comes from the RPC auth verifier (NTLMSSP type
    /// 10, SPNEGO type 9; Kerberos DCE-style is a documented gap). The endpoint mapper refuses to
    /// start if 135 is held and names the holder.
    private func startRPCTCP(store: DirectoryStore, info: DomainInfo) async throws {
        guard options.rpcTcpEnabled, wants(.fileAndRPC) else { return }
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
        try checkRunning()
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
        if stopped { await dyn.stop(); rpcTCP = nil; bound.rpc = nil; throw Stopped() }
        let epmServer = RPCTCPServer(port: Int(ports.epm), setup: epmSetup)
        do { try await epmServer.start() } catch {
            await dyn.stop(); rpcTCP = nil
            throw CLIError.failure("EPM tcp \(ports.epm): \(error)")
        }
        epm = epmServer
        bound.epm = epmServer.boundPort
        log.event("RPC", "ncacn_ip_tcp \(dynPort): lsarpc, dssetup, samr, netlogon, drsuapi, backupkey "
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
        guard options.httpEnabled, wants(.webPKI) else { return }
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
        try checkRunning()
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
        guard options.estEnabled, wants(.webPKI) else { return }
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
        try checkRunning()
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
        guard options.httpsEnabled, wants(.webPKI) else { return }
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
                                           authenticator: HTTPNegotiateAuthenticator(source: secrets, allowNTLM: options.cesAllowNTLM,
                                                                                     channelBinding: options.cesChannelBinding),
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
        try checkRunning()
        do { try await server.start() } catch { throw CLIError.failure("HTTPS tcp \(port): \(error)") }
        https = server
        bound.https = server.boundPort
        let httpsPort = server.boundPort ?? Int(port)
        httpsPortBox?.port = httpsPort
        let base = "https://\(info.dcDNSName)\(httpsPort == 443 ? "" : ":\(httpsPort)")"
        let ca = (try? await pki.currentAuthority().name) ?? LabPKI.labCAName
        log.event("HTTPS", "tcp \(httpsPort): CEP \(base)\(XCEPService.path), CES \(base)/\(ca)_CES_Kerberos/service.svc/CES "
                  + "(Negotiate: Kerberos HTTP/\(info.dcDNSName)\(options.cesAllowNTLM ? ", NTLM with channel binding" : ", NTLM off"))")
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
            // A P-384 current CA (new domains) serves 192-bit with the DC certificate itself.
            if try await pki.mainCAServesSuiteB() { return }
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

    /// "Allow RSA-only devices" at start: the RSA compatibility root (made when the toggle was
    /// switched on) gets its RSA RADIUS certificate renewed. Nothing while the toggle is off.
    private func prepareRSACompatibility(caService: CAService, pki: LabPKI, info: DomainInfo) async {
        guard await caService.rsaCompatibilityEnabled() else { return }
        do {
            let created = try await caService.ensureRSACompatAuthority()
            if try await pki.ensureRSAServerCertificate(hostname: info.dcDNSName) == .issued || created {
                log.event("PKI", "RSA compatibility CA (RSA-3072) \(created ? "created" : "loaded"), RSA RADIUS certificate issued for \(info.dcDNSName)")
                await recordRSAServerCertificate(caService, pki: pki, info: info)
            }
        } catch {
            log.warning("PKI", "RSA compatibility CA / RADIUS certificate: \(error) — RSA-only devices cannot connect")
        }
    }

    private func recordRSAServerCertificate(_ service: CAService, pki: LabPKI, info: DomainInfo) async {
        guard let certificate = await pki.rsaServerCertificate() else { return }
        let dcSID = try? await store?.read(dn: info.dcComputerDN)?.sid?.description
        do {
            try await service.record(certificate, caName: LabPKI.rsaCompatCAName, templateName: "RadiusServerRSA",
                                     requester: RequesterIdentity(name: info.dcName.uppercased() + "$", sid: dcSID))
        } catch {
            log.warning("PKI", "cannot record the RSA RADIUS certificate: \(error)")
        }
    }

    /// The RSA credential while "Allow RSA-only devices" is on, its certificate issued here on
    /// first need (the toggle switched on while running).
    private func rsaCredential() async -> TLSContext.Credential? {
        guard let pki, let caService, await caService.rsaCompatibilityEnabled() else { return nil }
        if let c = (try? await pki.eapRSACredentials()) ?? nil { return TLSContext.Credential(chain: c.chain, keyDER: c.keyDER) }
        guard rsaIssuance.allows(), let store, let info = try? await store.domainInfo(), rsaIssuance.begin() else { return nil }
        do {
            try await caService.ensureRSACompatAuthority()
            if try await pki.ensureRSAServerCertificate(hostname: info.dcDNSName) == .issued {
                log.event("PKI", "RSA RADIUS certificate issued for \(info.dcDNSName)")
                await recordRSAServerCertificate(caService, pki: pki, info: info)
            }
            rsaIssuance.succeeded()
        } catch {
            rsaIssuance.failed()
            log.warning("PKI", "RSA RADIUS certificate: \(error) — RSA-only devices cannot connect; next try in \(rsaIssuance.intervalText)")
            return nil
        }
        return ((try? await pki.eapRSACredentials()) ?? nil).map { TLSContext.Credential(chain: $0.chain, keyDER: $0.keyDER) }
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
                              suiteB: suiteB.map { TLSContext.Credential(chain: $0.chain, keyDER: $0.keyDER) },
                              rsa: await rsaCredential())
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
        config.requireLDAPSigning = options.requireLDAPSigning
        config.ldapChannelBinding = options.ldapChannelBinding
        try checkRunning()
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
        guard !stopped, let pki, let store, let info = try? await store.domainInfo() else { return }
        let names = serverNames(info)
        // Each listener restarts on its own: one that fails does not keep the others down, and
        // the failure reaches the controller (`.listenersChanged`), which shows it on the row
        // instead of "Running" over a dead port.
        var failures: [String] = []
        do {
            let outcome = try await pki.ensureServerCertificate(hostnames: names.hostnames, ips: names.ips)
            guard outcome == .issued, !stopped else { return }
            log.event("PKI", "DC certificate reissued for \((names.hostnames + names.ips).joined(separator: ", ")); restarting LDAP"
                      + (est == nil ? "" : ", EST") + (https == nil ? "" : ", HTTPS"))
            if let caService { await recordServerCertificate(caService, pki: pki, info: info) }
        } catch {
            log.warning("PKI", "certificate reissue failed: \(error)")
            return
        }
        if ldap != nil {
            await ldap?.stop()
            ldap = nil
            bound.ldap = nil; bound.ldaps = nil; bound.gc = nil; bound.gcs = nil
            do { try await startLDAP(store: store, pki: pki) } catch { failures.append("\(error)") }
        }
        if let server = est, let caService = self.caService {
            await server.stop()
            est = nil
            bound.est = nil
            do {
                try await startEST(caService: caService, pki: pki, info: info,
                                   port: server.boundPort.map { UInt16($0) } ?? options.ports.est)
            } catch { failures.append("\(error)") }
        }
        if let server = https, let caService = self.caService {
            await server.stop()
            https = nil
            bound.https = nil
            do {
                try await startHTTPS(caService: caService, pki: pki, store: store, info: info,
                                     port: server.boundPort.map { UInt16($0) } ?? options.ports.https)
            } catch { failures.append("\(error)") }
        }
        await releaseIfStopped()
        if stopped { return }
        for why in failures { log.warning("PKI", "restart after the certificate reissue failed: \(why)") }
        log.runtimeEvent(.listenersChanged(failures: failures))
        if now.count > 1, options.advertise == nil {
            log.warning("serve", Self.multipleAddressWarning(Array(now), app: options.inApp))
        }
    }

    /// Stops everything, in reverse order. Safe to call twice. Marks the runtime stopped (every
    /// bind path still in flight gives up, see `stopped`) and lets go of the store and the PKI.
    public func stop() async {
        stopped = true
        await stopAllListeners()
        store = nil
        pki = nil
        caService = nil
    }

    /// True while any listener object is still held.
    var anyListenerUp: Bool {
        dns != nil || kdc != nil || kpasswd != nil || ldap != nil || cldap != nil || smb != nil || sntp != nil
            || nbns != nil || radius != nil || dhcp != nil || rpcTCP != nil || epm != nil || http != nil || est != nil
            || https != nil
    }

    /// Stops every listener and timer, in reverse start order, recording the bound ports in
    /// `releasedPorts` first.
    private func stopAllListeners() async {
        for h in bound.held where !releasedPorts.contains(h) { releasedPorts.append(h) }
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
        dhcpRetryTask?.cancel()
        dhcpRetryTask = nil
        await dhcp?.stop()
        dhcp = nil
        dhcpStartFailure = nil
        dhcpv6StartFailure = nil
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
        // A listener bound while this stop was suspended above: its port joins the list too.
        for h in bound.held where !releasedPorts.contains(h) { releasedPorts.append(h) }
        bound = ServeBoundPorts()
    }

    /// `app`: the LabDC app says where its setting is instead of the CLI flag (owner, 2 Oct 2026).
    public static func multipleAddressWarning(_ addresses: [String], app: Bool = false) -> String {
        "this Mac has \(addresses.count) LAN IPv4 addresses (\(addresses.sorted().joined(separator: ", "))); DNS publishes all of them "
            + "and CLDAP answers with the address a ping arrived on. "
            + (app ? "Choose the one Windows clients should use in Settings ▸ System ▸ Network."
                   : "Pass --advertise <ipv4> to pin the one Windows clients should use.")
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
        row("DHCP", "udp", bound.dhcp)
        row("DHCPv6", "udp", bound.dhcpv6)
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
        dhcpAdvertise.set(address)
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
    private func makeDNSServer(source: StoreZoneSource, port: UInt16) async -> DNSServer {
        forwardingState.update(forwarding: options.dnsForwarding, port: port, advertise: options.advertise)
        let state = forwardingState
        let forwarder = DNSForwarder(plan: { state.plan() })
        dnsForwarder = forwarder
        let acl = DNSRecursionACL(store: source.store, extra: options.dnsAllowedClients)
        dnsRecursionACL = acl
        // GSS-TSIG secure updates: TKEY contexts from DNS/<dc> tickets (one replay cache).
        var secure: DNSSecureUpdateConfig?
        if let secrets = try? await StoreSecretSource(store: source.store) {
            let replay = ReplayCache()
            secure = DNSSecureUpdateConfig(kerberos: { KerberosAcceptor(source: secrets, replayCache: replay) },
                                           directory: StoreDNSUpdateDirectory(store: source.store))
        } else {
            log.warning("DNS", "secure dynamic updates (GSS-TSIG) are unavailable: the directory has no Kerberos secrets")
        }
        // Recursion only for this Mac's networks, the DHCP scopes and `--dns-allow`; UDP response
        // rate limiting on (DNSRateLimit defaults); unsigned updates under `.ownAddress` (or none,
        // per Settings ▸ DNS "Dynamic updates").
        let log = self.log
        let responder = DNSResponder(source: source, forwarder: forwarder, recursion: acl.policy, rateLimit: DNSRateLimit(),
                                     updateMode: options.dnsUpdateMode, secure: secure,
                                     onEvent: { line in log.event("DNS", line) })
        dnsResponder = responder
        return DNSServer(responder: responder, port: port)
    }

    /// Settings ▸ DNS "Dynamic updates": applied live, DNS keeps running.
    public func setDNSUpdateMode(_ mode: DNSDynamicUpdateMode) async {
        guard mode != options.dnsUpdateMode else { return }
        options.dnsUpdateMode = mode
        await dnsResponder?.setUpdateMode(mode)
        log.event("DNS", "dynamic updates: \(mode.settingsLabel.lowercased())")
    }

    /// Settings ▸ the networks allowed to resolve names outside the domain: applied live.
    public func setDNSAllowedClients(_ networks: [DNSNetwork]) {
        options.dnsAllowedClients = networks
        dnsRecursionACL?.setExtra(networks)
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

    /// Services ▸ Stop (owner, 1 Oct 2026): stops the listeners of one service and leaves the
    /// others running; `restartInPlace` starts them again.
    public func stopInPlace(_ listeners: [ServeListener], name: String) async {
        var groups: [ServeListener] = []
        for l in listeners {
            let head = l.restartsWith.first ?? l
            if !groups.contains(head) { groups.append(head) }
        }
        // Ephemeral ports are pinned first, so Start brings the service back on the same port.
        for group in groups {
            for l in group.restartsWith where options.ports[l] == 0 {
                if let p = l.bound(in: bound) { options.ports[l] = UInt16(truncatingIfNeeded: p) }
            }
        }
        // Marked stopped before the first await: a reconcile running meanwhile (a DHCP scope
        // change, a retry) must not start the service again while its listeners go down.
        for l in listeners { options.ownerStopped.insert(ServeService.of(l)) }
        for group in groups { await stopListener(group) }
        log.event("serve", "stop \(name) -> OK")
    }

    /// Services ▸ Start on a row the owner stopped: forgets the stop and starts its listeners
    /// again (`restartInPlace`).
    public func startInPlace(_ listeners: [ServeListener], name: String) async throws {
        for l in listeners { options.ownerStopped.remove(ServeService.of(l)) }
        try await restartInPlace(listeners, name: name)
    }

    private func stopListener(_ listener: ServeListener) async {
        switch listener {
        case .dns:
            dns?.stop(); dns = nil; bound.dns = nil
        case .kdc:
            kdc?.stop(); kdc = nil; bound.kdc = nil
        case .kpasswd:
            kpasswd?.stop(); kpasswd = nil; bound.kpasswd = nil
        case .ldap, .ldaps, .gc, .gcs:
            await ldap?.stop(); ldap = nil
            bound.ldap = nil; bound.ldaps = nil; bound.gc = nil; bound.gcs = nil
        case .cldap:
            cldap?.stop(); cldap = nil; bound.cldap = nil
        case .smb, .sntp, .nbss:
            await smb?.stop(); smb = nil; bound.smb = nil; bound.nbss = nil
            sntp?.stop(); sntp = nil; bound.sntp = nil
            await nbns?.stop(); nbns = nil; bound.nbns = nil
        case .nbns:
            await nbns?.stop(); nbns = nil; bound.nbns = nil
        case .radius, .radacct:
            radius?.stop(); radius = nil
            bound.radius = nil; bound.radacct = nil
            radiusStartFailure = nil
        case .dhcp, .dhcpv6:
            await withDHCPLock {
                dhcpRetryTask?.cancel(); dhcpRetryTask = nil
                let old = dhcp
                dhcp = nil
                bound.dhcp = nil; bound.dhcpv6 = nil
                dhcpStartFailure = nil
                dhcpv6StartFailure = nil
                await old?.stop()
            }
        case .epm, .rpc:
            await epm?.stop(); epm = nil; bound.epm = nil
            await rpcTCP?.stop(); rpcTCP = nil; bound.rpc = nil
        case .http:
            crlTimer?.cancel(); crlTimer = nil
            await http?.stop(); http = nil; bound.http = nil
            scepService = nil
        case .est:
            await est?.stop(); est = nil; bound.est = nil
        case .https:
            await https?.stop(); https = nil; bound.https = nil; enrollmentWeb = nil
        }
    }

    /// Restarts one listener group, unless the runtime is stopped or the owner stopped its
    /// service (then it stays down: a port move only records the port). Anything bound after a
    /// `stop()` that came while this was suspended is stopped again.
    private func restartListener(_ listener: ServeListener) async throws {
        guard !stopped else { throw Stopped() }
        do {
            try await restartListenerBody(listener)
        } catch {
            await releaseIfStopped()
            throw error
        }
        await releaseIfStopped()
        try checkRunning()
    }

    private func restartListenerBody(_ listener: ServeListener) async throws {
        // SMB+SNTP restart together and check each service themselves (`startSMBAndSNTP`).
        if ![.smb, .sntp, .nbss].contains(listener), !wants(ServeService.of(listener)) { return }
        guard let store, let pki, let info = try? await store.domainInfo() else { return }
        try checkRunning()
        let ports = options.ports
        let log = self.log
        switch listener {
        case .dns:
            guard options.dnsEnabled else { return }
            dns?.stop(); dns = nil; bound.dns = nil
            await Self.waitUntilFree(ports.dns, [.udp, .tcp])
            try checkRunning()
            let source = StoreZoneSource(store: store, advertise: options.advertise, onChange: { line in log.event("DNS", line) })
            let server = await makeDNSServer(source: source, port: ports.dns)
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
            try checkRunning()
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
            try checkRunning()
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
            try checkRunning()
            try await startRadius(store: store)
        case .dhcp, .dhcpv6:
            try await withDHCPLock {
                // Wait only for ports this server held: a port someone else holds (Internet
                // Sharing) does not come free by waiting here, and the start reports it at once.
                let had4 = bound.dhcp != nil, had6 = bound.dhcpv6 != nil
                dhcpRetryTask?.cancel(); dhcpRetryTask = nil
                let old = dhcp
                dhcp = nil
                bound.dhcp = nil; bound.dhcpv6 = nil
                dhcpStartFailure = nil
                dhcpv6StartFailure = nil
                await old?.stop()
                guard options.dhcpEnabled, wants(.dhcp) else { return }
                if had4 { await Self.waitUntilFree(ports.dhcp, [.udp]) }
                if had6 { await Self.waitUntilFree(ports.dhcpv6, [.udp]) }
                try checkRunning()
                try await startDHCPIfNeeded(store: store)
            }
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
            // `isFree`, not `problem`: the latter runs lsof/pgrep for the holder on every try.
            if PortProbe.isFree(port: port, protos: protos) { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Phase 4a: binds RADIUS auth + accounting (`RadiusServer`); errors name the service
    /// (`RADIUS udp 1812: …`) so the Services row picks them up.
    private func startRadius(store: DirectoryStore) async throws {
        let ports = options.ports
        try checkRunning()
        for port in [ports.radius, ports.radacct] where port != 0 {
            if let problem = PortProbe.problem(port: port, protos: [.udp]) {
                throw CLIError.failure("RADIUS udp \(port): \(problem)")
            }
        }
        let log = self.log
        // Phase 4b: EAP (TLS, PEAP, TTLS) with the DC certificate; client certificates must
        // chain to one of this DC's CAs. Read per use, so a reissued certificate (or a 192-bit
        // CA created while running) is picked up. Trusted: every CA except a retired root and the
        // RSA compatibility root while RSA-only devices are not allowed.
        let caService = self.caService
        let server = RadiusServer(store: store,
                                  eapCredentials: { [weak self] in await self?.eapCredentials() },
                                  trustRoots: { (try? await caService?.eapTrustedRootsDER()) ?? [] },
                                  profiles: deviceProfiles,
                                  log: { line in log.event("RADIUS", line) })
        do { try server.start(authPort: ports.radius, acctPort: ports.radacct) } catch {
            throw CLIError.failure("RADIUS udp \(ports.radius)+\(ports.radacct): \(error)")
        }
        server.watchDeviceProfiles()
        radius = server
        bound.radius = Int(server.authPort)
        bound.radacct = Int(server.acctPort)
    }

    /// A RADIUS client or policy changed (app, CLI through the app): the server reloads its config.
    public func radiusConfigChanged() {
        radius?.configChanged()
    }

    /// Phase 5: binds DHCP when at least one scope exists (errors name `DHCP udp 67` /
    /// `DHCPv6 udp 547` for the Services row). v4 and v6 are independent listeners: v4 binds
    /// once any scope exists, v6 only when DHCPv6 is on AND a v6 scope exists (the same rule at
    /// start, on a scope change and on Restart). A busy port of one family leaves the other
    /// running and is recorded in `dhcpStartFailure` / `dhcpv6StartFailure` (logged unless
    /// `quiet`); this throws only when no family could bind. A busy port is retried in the
    /// background (`dhcpRetryInterval`).
    private func startDHCPIfNeeded(store: DirectoryStore, quiet: Bool = false) async throws {
        guard dhcp == nil else { return }
        dhcpStartFailure = nil
        dhcpv6StartFailure = nil
        let scopes = try await store.dhcpScopes()
        guard !scopes.isEmpty else { return }
        defer { scheduleDHCPRetryIfNeeded() }
        let ports = options.ports
        let v6Setting = (try? await store.dhcpSettings())?.enableV6 ?? false
        let wantV6 = options.dhcpV6Enabled && v6Setting && scopes.contains { $0.family == .v6 }
        // The scopes were read with a suspension: a stop (runtime or the owner's) wins.
        try checkRunning()
        guard wants(.dhcp), dhcp == nil else { return }
        if ports.dhcp != 0, let problem = PortProbe.problem(port: ports.dhcp, protos: [.udp]) {
            dhcpStartFailure = "DHCP udp \(ports.dhcp): \(problem)"
        }
        if wantV6, ports.dhcpv6 != 0, let problem = PortProbe.problem(port: ports.dhcpv6, protos: [.udp]) {
            dhcpv6StartFailure = "DHCPv6 udp \(ports.dhcpv6): \(problem)"
        }
        let use4 = dhcpStartFailure == nil, use6 = wantV6 && dhcpv6StartFailure == nil
        guard use4 || use6 else {
            // Nothing binds: the caller logs (and Restart reports) the v4 problem; v6's here.
            if let why6 = dhcpv6StartFailure, !quiet { log.warning("DHCP", why6) }
            throw CLIError.failure(dhcpStartFailure ?? "DHCP: nothing to bind")
        }
        let log = self.log
        // Read at every reply, not captured at start: a new address in Settings (owner, 1 Oct
        // 2026: DNS/NTP options kept the old Tailscale address) applies without a DHCP restart.
        let advertise = dhcpAdvertise
        advertise.set(options.advertise)
        let server = DHCPServer(store: store,
                                options: DHCPServer.Options(v4Port: ports.dhcp, v6Port: ports.dhcpv6, enableV4: use4, enableV6: use6),
                                advertised: { advertise.get() ?? ServeAddresses.current().first },
                                log: { line in log.event("DHCP", line) }, warn: { line in log.warning("DHCP", line) })
        do {
            try await server.start()
        } catch {
            recordDHCPError(error)
            throw error
        }
        if stopped || !wants(.dhcp) {
            await server.stop()
            throw Stopped()
        }
        dhcp = server
        bound.dhcp = use4 ? Int(server.v4Port) : nil
        bound.dhcpv6 = use6 ? Int(server.v6Port) : nil
        if !quiet {
            for why in [dhcpStartFailure, dhcpv6StartFailure].compactMap({ $0 }) { log.warning("DHCP", why) }
        }
    }

    /// Records a DHCP start error on the family it names.
    private func recordDHCPError(_ error: Error) {
        let message = "\(error)"
        if message.hasPrefix("DHCPv6 ") { dhcpv6StartFailure = message } else { dhcpStartFailure = message }
    }

    /// Whether a recorded DHCP failure is only a busy port (worth retrying in the background).
    static func isBusyPort(_ failure: String?) -> Bool { failure?.contains("is in use") ?? false }

    /// Whether the background DHCP retry is scheduled.
    var dhcpRetryActive: Bool { dhcpRetryTask != nil }

    /// Tests: a shorter background retry.
    func setDHCPRetryInterval(_ interval: Duration) {
        dhcpRetryInterval = interval
    }

    /// Starts the background retry while a family failed on a busy port; stops it otherwise.
    private func scheduleDHCPRetryIfNeeded() {
        let busy = Self.isBusyPort(dhcpStartFailure) || Self.isBusyPort(dhcpv6StartFailure)
        guard busy else {
            dhcpRetryTask?.cancel()
            dhcpRetryTask = nil
            return
        }
        guard dhcpRetryTask == nil else { return }
        dhcpRetryTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let interval = await self?.dhcpRetryInterval else { return }
                try? await Task.sleep(for: interval)
                guard !Task.isCancelled, let self, await self.retryDHCPBind() else { return }
            }
        }
    }

    /// One background retry: when a port that was busy is free now, DHCP binds again with every
    /// family it wants. Logs only when a family comes up (once per change); true while the
    /// caller should keep retrying. Runs under the DHCP lock (`withDHCPLock`).
    func retryDHCPBind() async -> Bool {
        await withDHCPLock { await retryDHCPBindLocked() }
    }

    private func retryDHCPBindLocked() async -> Bool {
        // This task stays the retry task through the rebind (startDHCPIfNeeded keeps it).
        let me = dhcpRetryTask
        guard !Task.isCancelled, !stopped, options.dhcpEnabled, !dhcpStoppedByOwner, let store else {
            if dhcpRetryTask == me { dhcpRetryTask = nil }
            return false
        }
        let busy4 = Self.isBusyPort(dhcpStartFailure), busy6 = Self.isBusyPort(dhcpv6StartFailure)
        guard busy4 || busy6 else { if dhcpRetryTask == me { dhcpRetryTask = nil }; return false }
        let ports = options.ports
        let free4 = busy4 && PortProbe.isFree(port: ports.dhcp, protos: [.udp])
        let free6 = busy6 && PortProbe.isFree(port: ports.dhcpv6, protos: [.udp])
        guard free4 || free6 else { return true }
        let before4 = dhcpStartFailure, before6 = dhcpv6StartFailure
        let had4 = bound.dhcp != nil, had6 = bound.dhcpv6 != nil
        let old = dhcp
        dhcp = nil
        bound.dhcp = nil; bound.dhcpv6 = nil
        await old?.stop()
        if had4 { await Self.waitUntilFree(ports.dhcp, [.udp]) }
        if had6 { await Self.waitUntilFree(ports.dhcpv6, [.udp]) }
        // Cancelled (a Stop, a restart, the scopes removed) or stopped while waiting: no bind.
        guard !Task.isCancelled, !stopped, wants(.dhcp) else {
            if dhcpRetryTask == me { dhcpRetryTask = nil }
            log.runtimeEvent(.dhcpChanged)
            return false
        }
        do { try await startDHCPIfNeeded(store: store, quiet: true) } catch {
            if !(error is Stopped) { recordDHCPError(error) }
        }
        await releaseIfStopped()
        if stopped { return false }
        if before4 != nil, dhcpStartFailure == nil, bound.dhcp != nil {
            log.event("DHCP", "udp \(ports.dhcp) is free again: DHCP (IPv4) started")
        }
        if before6 != nil, dhcpv6StartFailure == nil, bound.dhcpv6 != nil {
            log.event("DHCP", "udp \(ports.dhcpv6) is free again: DHCPv6 started")
        }
        log.runtimeEvent(.dhcpChanged)
        return dhcpRetryTask != nil && dhcpRetryTask == me
    }

    /// Runs one DHCP lifecycle operation at a time: config changes, the background retry and
    /// Stop/Start of the DHCP row each suspend between deciding to bind and binding, and two of
    /// them overlapping used to build two servers (the second bind failed, its "port in use"
    /// stayed recorded while the first ran, and the retry looped on it forever). Later callers
    /// wait their turn; each re-reads the state once it runs.
    private func withDHCPLock<T>(_ body: () async -> T) async -> T {
        while dhcpLocked { await withCheckedContinuation { dhcpLockWaiters.append($0) } }
        dhcpLocked = true
        defer {
            dhcpLocked = false
            if !dhcpLockWaiters.isEmpty { dhcpLockWaiters.removeFirst().resume() }
        }
        return await body()
    }

    private func withDHCPLock<T>(_ body: () async throws -> T) async throws -> T {
        while dhcpLocked { await withCheckedContinuation { dhcpLockWaiters.append($0) } }
        dhcpLocked = true
        defer {
            dhcpLocked = false
            if !dhcpLockWaiters.isEmpty { dhcpLockWaiters.removeFirst().resume() }
        }
        return try await body()
    }

    /// A scope, reservation or DHCP setting changed: the running server reloads; the first
    /// scope starts it, removing the last one stops it. Serialised with the other DHCP
    /// operations (`withDHCPLock`).
    public func dhcpConfigChanged() async {
        await withDHCPLock { await dhcpConfigChangedLocked() }
    }

    private func dhcpConfigChangedLocked() async {
        guard options.dhcpEnabled, !stopped, let store else { return }
        let scopes = (try? await store.dhcpScopes()) ?? []
        let v6Setting = (try? await store.dhcpSettings())?.enableV6 ?? false
        guard !stopped else { return }
        if let running = dhcp {
            let wantV6 = options.dhcpV6Enabled && v6Setting && scopes.contains { $0.family == .v6 }
            if scopes.isEmpty {
                dhcpRetryTask?.cancel(); dhcpRetryTask = nil
                dhcp = nil
                bound.dhcp = nil; bound.dhcpv6 = nil
                dhcpStartFailure = nil
                dhcpv6StartFailure = nil
                await running.stop()
                log.event("DHCP", "stopped: no scope left")
            } else if wantV6 != (bound.dhcpv6 != nil || dhcpv6StartFailure != nil) {
                // The first v6 scope (or the last one gone): v6 binds (or unbinds) by the same
                // rule as at start.
                let had4 = bound.dhcp != nil, had6 = bound.dhcpv6 != nil
                dhcp = nil
                bound.dhcp = nil; bound.dhcpv6 = nil
                await running.stop()
                if had4 { await Self.waitUntilFree(options.ports.dhcp, [.udp]) }
                if had6 { await Self.waitUntilFree(options.ports.dhcpv6, [.udp]) }
                do { try await startDHCPIfNeeded(store: store) } catch {
                    if !(error is Stopped) {
                        recordDHCPError(error)
                        log.warning("DHCP", "\(error)")
                    }
                }
                await releaseIfStopped()
            } else {
                await running.configChanged()
            }
            return
        }
        guard !scopes.isEmpty else {
            dhcpRetryTask?.cancel(); dhcpRetryTask = nil
            dhcpStartFailure = nil
            dhcpv6StartFailure = nil
            return
        }
        guard !dhcpStoppedByOwner, !stopped else { return }
        do {
            try await startDHCPIfNeeded(store: store)
        } catch {
            if !(error is Stopped) {
                recordDHCPError(error)
                log.warning("DHCP", "\(error)")
            }
        }
        await releaseIfStopped()
    }

    /// Uses `source` for device facts and profile-change CoA from the next RADIUS start on
    /// (call before `start`, or restart RADIUS).
    public func setDeviceProfiles(_ source: DeviceProfileSource) {
        deviceProfiles = source
    }

    /// RADIUS ▸ Sessions: Reauthenticate / Disconnect one stored session (RFC 5176).
    public func radiusCoA(_ action: CoAAction, session: DirectoryStore.RadiusSession) async -> CoAResult {
        guard let radius else {
            return CoAResult(request: action.title, outcome: nil, problem: "RADIUS is not running", attempts: 0)
        }
        return await radius.sendCoA(action, session: session, reason: "manual (app)")
    }

    private func restartRPC(store: DirectoryStore, info: DomainInfo) async throws {
        await epm?.stop(); epm = nil; bound.epm = nil
        await rpcTCP?.stop(); rpcTCP = nil; bound.rpc = nil
        try checkRunning()
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
        if nbns != nil, options.netbiosEnabled, !stopped {
            if let p = bound.nbns, options.ports.nbns == 0 { options.ports.nbns = UInt16(truncatingIfNeeded: p) }
            try? await restartListener(.nbns)
        }
        guard !stopped, epm != nil, let store, let info = try? await store.domainInfo(), !stopped, epm != nil else { return }
        // Same ports again (an ephemeral 0 would move them).
        if let p = bound.rpc, options.ports.rpc == 0 { options.ports.rpc = UInt16(truncatingIfNeeded: p) }
        if let p = bound.epm, options.ports.epm == 0 { options.ports.epm = UInt16(truncatingIfNeeded: p) }
        do {
            try await restartRPC(store: store, info: info)
            await releaseIfStopped()
            try checkRunning()
            log.event("RPC", "endpoint mapper re-registered for \(advertised ?? "127.0.0.1")")
        } catch is Stopped {
            await releaseIfStopped()
        } catch {
            await releaseIfStopped()
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


/// The address the DHCP server hands out as DNS/NTP, shared with its reply path so a change in
/// Settings applies without a restart.
final class AdvertisedAddressBox: Sendable {
    private let value = Mutex<String?>(nil)
    func get() -> String? { value.withLock { $0 } }
    func set(_ address: String?) { value.withLock { $0 = address } }
}
