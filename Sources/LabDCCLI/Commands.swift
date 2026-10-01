import DNSKit
import Foundation
import KDC
import PKIKit
import Store

/// The offline commands: they open `<data>/lab.sqlite` directly (their own `DirectoryStore`
/// connection) and may run while `serve` runs.
///
/// Concurrency rule: the store is SQLite in WAL mode, so readers never block and never see a
/// half-written change. Writers are serialised by SQLite's file lock (5 s busy timeout, every
/// Store mutation is one transaction); if a CLI write still collides with a server write it
/// fails as a whole with "database is locked" and can simply be re-run. `serve` caches only the
/// realm-wide `domain` values (fixed after provisioning) and reads objects, secrets and DNS
/// records from SQLite on every request, so a user added or a password set from the CLI is
/// visible to the running KDC/LDAP/DNS immediately, without a restart.
public enum CLICommands {
    /// Runs an offline command; `out` receives the output lines.
    public static func run(_ command: CLICommand, out: (String) -> Void) async throws {
        switch command {
        case .serve, .help:
            throw CLIError.usage("not an offline command")
        case let .userAdd(data, options):
            let store = try DataDirectory(data).openExistingStore()
            let entry = try await addUser(store, options)
            out("added \(entry.samAccountName ?? options.sam) (\(entry.dn)), SID \(entry.sid?.description ?? "?")"
                + (options.groups.isEmpty ? "" : ", member of \(options.groups.joined(separator: ", "))"))
        case let .userPasswd(data, sam, password):
            let store = try DataDirectory(data).openExistingStore()
            try await setPassword(store, sam: sam, password: password)
            out("password of \(sam) set")
        case .userList(let data):
            let store = try DataDirectory(data).openExistingStore()
            for line in try await listUsers(store) { out(line) }
        case .computerList(let data):
            let store = try DataDirectory(data).openExistingStore()
            for line in try await listComputers(store) { out(line) }
        case let .computerAddSPN(data, account, spn):
            let store = try DataDirectory(data).openExistingStore()
            out(try await addSPN(store, account: account, spn: spn))
        case .dnsList(let data):
            let store = try DataDirectory(data).openExistingStore()
            for line in try await listDNS(store) { out(line) }
        case let .exportKeytab(data, path):
            let store = try DataDirectory(data).openExistingStore()
            _ = try await store.requireInfo()
            let principals = try await DirectoryPrincipalStore(directory: store).allPrincipals()
            let entries = Keytab.entries(for: principals)
            try Keytab.write(entries, to: URL(fileURLWithPath: path))
            out("wrote \(entries.count) keys of \(principals.count) principals to \(path) (mode 0600)")
        case let .ca(data, sub):
            try await CACommands.run(data: data, sub, out: out)
        case .cert(let command):
            try await CertCLI.run(command, out: out)
        case let .gpo(data, sub):
            try await GPOCommands.run(data: data, sub, out: out)
        case let .pki(data, sub):
            try await PKICommands.run(data: data, sub, out: out)
        case let .enrollment(data, protocolName, sub):
            try await EnrollmentCommands.run(data: data, protocolName: protocolName, sub, out: out)
        case let .radius(data, sub):
            try await RadiusCommands.run(data: data, sub, out: out)
        case .status(let data):
            let dir = DataDirectory(data)
            let store = try dir.openExistingStore()
            for line in try await status(store, data: dir) { out(line) }
        }
    }

    // MARK: Users

    /// Creates a user under `CN=Users` (or `--ou`), sets the password (policy enforced; the user
    /// is removed again when the password is refused) and adds it to the groups.
    @discardableResult
    public static func addUser(_ store: DirectoryStore, _ o: UserAddOptions) async throws -> DirectoryEntry {
        var parent: DN?
        if let ou = o.ou {
            do { parent = try DN(string: ou) } catch { throw CLIError.failure("bad --ou DN \(ou): \(error)") }
        }
        // UI-2: the same code path as the app's Users page (LabDCCore `DirectoryAccounts`).
        return try await DirectoryAccounts.addUser(store, sam: o.sam, password: o.password, upn: o.upn, parent: parent,
                                                   groups: o.groups)
    }

    public static func setPassword(_ store: DirectoryStore, sam: String, password: String) async throws {
        try await DirectoryAccounts.setPassword(store, sam: sam, password: password)
    }

    public static func listUsers(_ store: DirectoryStore) async throws -> [String] {
        let info = try await store.requireInfo()
        let filter = FilterAST.and([.equality(attribute: "objectClass", value: Array("user".utf8)),
                                    .not(.equality(attribute: "objectClass", value: Array("computer".utf8)))])
        let users = try await store.search(base: info.domainDN, scope: .subtree, filter: filter)
        return users.map { u in
            let uac = UInt32(truncatingIfNeeded: u.int("userAccountControl") ?? 0)
            let state = uac & UserAccountControl.accountDisable != 0 ? "disabled" : "enabled"
            return [u.samAccountName ?? "?", u.string("userPrincipalName") ?? "-", state, u.dn.description]
                .joined(separator: "\t")
        }
    }

    // MARK: Computers

    public static func listComputers(_ store: DirectoryStore) async throws -> [String] {
        let info = try await store.requireInfo()
        let computers = try await store.search(base: info.domainDN, scope: .subtree,
                                               filter: .equality(attribute: "objectClass", value: Array("computer".utf8)))
        return computers.map { c in
            let uac = UInt32(truncatingIfNeeded: c.int("userAccountControl") ?? 0)
            let kind = uac & UserAccountControl.serverTrustAccount != 0 ? "DC" : "workstation"
            return [c.samAccountName ?? "?", c.string("dNSHostName") ?? "-", kind,
                    "\(c.values("servicePrincipalName").count) SPNs", c.dn.description].joined(separator: "\t")
        }
    }

    /// Adds `spn` to the account's `servicePrincipalName` (`DC1$` or `DC1`).
    public static func addSPN(_ store: DirectoryStore, account: String, spn: String) async throws -> String {
        _ = try await store.requireInfo()
        guard spn.contains("/") else { throw CLIError.failure("an SPN looks like service/host, not \(spn)") }
        let entry: DirectoryEntry
        if let e = try await store.read(sam: account) {
            entry = e
        } else if !account.hasSuffix("$"), let e = try await store.read(sam: account + "$") {
            entry = e
        } else {
            throw CLIError.failure("no account \(account)")
        }
        if entry.strings("servicePrincipalName").contains(where: { $0.caseInsensitiveCompare(spn) == .orderedSame }) {
            return "\(entry.samAccountName ?? account) already has \(spn)"
        }
        try await store.update(id: entry.id, ops: [.add("servicePrincipalName", strings: [spn])])
        return "added \(spn) to \(entry.samAccountName ?? account)"
    }

    // MARK: DNS

    /// Generated records (from the domain values and this Mac's addresses) and stored ones.
    public static func listDNS(_ store: DirectoryStore) async throws -> [String] {
        _ = try await store.requireInfo()
        let source = StoreZoneSource(store: store)
        let info = await source.domainInfo()
        let generated = ADZoneGenerator.records(for: info, serial: 0)
        var lines: [String] = []
        for zone in info.zones {
            lines.append("; zone \(zone)")
            for r in generated[zone] ?? [] where r.type != .soa { lines.append("generated\t\(r)") }
            let rows = try await store.dnsRecords(zone: zone.canonicalText)
            for row in rows {
                guard let r = StoreZoneSource.record(from: row, zone: zone) else { continue }
                lines.append("\(row.dynamic ? "dynamic" : "stored")\t\(r)")
            }
        }
        return lines
    }

    // MARK: Status

    public static func status(_ store: DirectoryStore, data: DataDirectory) async throws -> [String] {
        let info = try await store.requireInfo()
        func count(_ filter: FilterAST) async throws -> Int {
            try await store.count(base: info.domainDN, scope: .subtree, filter: filter)
        }
        let oc = { (v: String) in FilterAST.equality(attribute: "objectClass", value: Array(v.utf8)) }
        let users = try await count(.and([oc("user"), .not(oc("computer"))]))
        let computers = try await count(oc("computer"))
        let groups = try await count(oc("group"))
        var dynamic = 0, stored = 0
        for zone in try await store.dnsZones() {
            for row in try await store.dnsRecords(zone: zone) {
                if row.dynamic { dynamic += 1 } else { stored += 1 }
            }
        }
        let caExists = FileManager.default.fileExists(atPath: data.caURL.path)
        // PK-1: `current-ca.json` names the issuing CA when it is not the lab CA.
        let currentFile = data.pkiURL.appendingPathComponent(LabPKI.currentCAFileName)
        let currentCA = (try? Data(contentsOf: currentFile))
            .flatMap { try? JSONDecoder().decode([String: String].self, from: $0) }?["current"] ?? LabPKI.labCAName
        let issued = try await store.issuedCertificates()
        return [
            "realm           \(info.realm)",
            "DNS domain      \(info.dnsDomain)",
            "NetBIOS domain  \(info.netbiosDomain)",
            "DC              \(info.dcDNSName) (\(info.dcName))",
            "domain SID      \(info.domainSID)",
            "domain GUID     \(info.domainGUID)",
            "DSA GUID        \(info.dsaGUID)",
            "site            \(info.site)",
            "users           \(users)",
            "computers       \(computers)",
            "groups          \(groups)",
            "DNS records     \(dynamic) dynamic, \(stored) other stored",
            "highest USN     \(try await store.highestCommittedUSN())",
            "store           \(data.storeURL.path)",
            "lab CA          \(caExists ? data.caURL.path : "not created yet (serve creates it)")",
            "current CA      \(currentCA)",
            "certificates    \(issued.count) issued, \(issued.filter(\.revoked).count) revoked",
        ]
    }
}
