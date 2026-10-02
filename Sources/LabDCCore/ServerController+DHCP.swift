import DHCPKit
import Foundation
import Store

/// The DHCP page's controller API (phase 5): scopes, reservations, leases, settings, the
/// direct-mode probe and the dry-run Test — the same store calls `labdc dhcp` makes, plus a
/// reload of the running server after every change.
extension ServerController {
    private func dhcpStore() throws -> DirectoryStore {
        guard let store else { throw CLIError.failure("the server is not running") }
        return store
    }

    // MARK: Scopes

    public func dhcpScopes() async -> [DHCPScope] { (try? await store?.dhcpScopes()) ?? [] }

    /// Returns notes on what the save changed by itself (server-set custom options saved by an
    /// earlier build, dropped: `DirectoryStore.updateDHCPScope`); they are logged as well.
    @discardableResult
    public func saveDHCPScope(_ scope: DHCPScope) async throws -> [String] {
        let store = try dhcpStore()
        var notes: [String] = []
        if scope.id == 0 {
            try await store.addDHCPScope(scope)
            serveLog.event("DHCP", "scope \(scope.name) (\(scope.subnet)\(scope.vlan.map { ", VLAN \($0)" } ?? "")) added (app)")
        } else {
            notes = try await store.updateDHCPScope(scope)
            for note in notes { serveLog.event("DHCP", note + " (app)") }
            serveLog.event("DHCP", "scope \(scope.name) (\(scope.subnet)) updated (app)")
        }
        await dhcpChanged()
        return notes
    }

    public func deleteDHCPScope(_ scope: DHCPScope) async throws {
        let store = try dhcpStore()
        // Leases of the scope lose their DNS records first; the running server forgets them
        // (its sweeper would otherwise write them back under the dead scope id).
        if let server = await runtime?.dhcp {
            for l in await server.leases() where l.scopeID == scope.id && l.state == .active {
                try? await server.release(family: l.family, address: l.address)
            }
            await server.flush()
            try await DHCPOffline.deleteScope(id: scope.id, store: store)
            await server.scopeDeleted(id: scope.id)
            await server.flush()
        } else {
            try await DHCPOffline.deleteScope(id: scope.id, store: store)
        }
        serveLog.event("DHCP", "scope \(scope.name) (\(scope.subnet)) deleted with its reservations and leases (app)")
        await dhcpChanged()
    }

    // MARK: Reservations

    public func dhcpReservations() async -> [DHCPReservation] { (try? await store?.dhcpReservations()) ?? [] }

    /// Returns notes as `saveDHCPScope`.
    @discardableResult
    public func saveDHCPReservation(_ r: DHCPReservation) async throws -> [String] {
        let store = try dhcpStore()
        var notes: [String] = []
        if r.id == 0 { try await store.addDHCPReservation(r) } else { notes = try await store.updateDHCPReservation(r) }
        for note in notes { serveLog.event("DHCP", note + " (app)") }
        serveLog.event("DHCP", "reservation \(r.name) → \(r.address) (\(r.identifierText)) saved (app)")
        await dhcpChanged()
        return notes
    }

    public func deleteDHCPReservation(_ r: DHCPReservation) async throws {
        try await dhcpStore().deleteDHCPReservation(id: r.id)
        serveLog.event("DHCP", "reservation \(r.name) (\(r.address)) deleted (app)")
        await dhcpChanged()
    }

    // MARK: Leases

    /// Current and recent leases: the running server's memory (offers included), else the store.
    public func dhcpLeases() async -> [DHCPLease] {
        if let server = await runtime?.dhcp { return await server.leases() }
        return (try? await store?.dhcpLeases()) ?? []
    }

    public func releaseDHCPLease(_ lease: DHCPLease) async throws {
        if let server = await runtime?.dhcp {
            try await server.release(family: lease.family, address: lease.address)
        } else {
            // Not running: the lease's DNS records go now (no sweeper would remove them later).
            let store = try dhcpStore()
            let current = try await store.dhcpLease(family: lease.family, address: lease.address) ?? lease
            try await DHCPOffline.release(current, store: store)
        }
        await dhcpChanged()
    }

    public func dhcpHistory(_ lease: DHCPLease) async -> [DHCPEvent] {
        (try? await store?.dhcpEvents(family: lease.family, address: lease.address, limit: 100)) ?? []
    }

    public func deviceProfile(mac: String) async -> DeviceProfile? { try? await store?.deviceProfile(mac: mac) }

    // MARK: Device profiles

    /// Every profiled device, most recently seen first (DHCP ▸ Devices).
    public func deviceProfiles() async -> [DeviceProfile] { (try? await store?.deviceProfiles()) ?? [] }

    /// Sets a device's category (and OS) by hand: DHCP fingerprints no longer change it. A
    /// changed category reaches RADIUS like a DHCP one (policy facts, automatic CoA).
    public func setDeviceCategory(mac: String, category: DeviceCategory, os: String?) async throws {
        let store = try dhcpStore()
        let now = Date()
        var p = try await store.deviceProfile(mac: mac)
            ?? DeviceProfile(mac: mac, firstSeen: now, lastSeen: now, source: .manual, category: category)
        p.source = .manual; p.category = category; p.os = os; p.confidence = 100; p.manualOverride = true
        try await store.upsertDeviceProfile(p)
        serveLog.event("DHCP", "device \(p.mac) set by hand to \(category.title)\(os.map { " — \($0)" } ?? "")")
    }

    /// Lets DHCP fingerprints decide again (the next request re-profiles the device).
    public func clearDeviceOverride(mac: String) async throws {
        let store = try dhcpStore()
        guard var p = try await store.deviceProfile(mac: mac), p.manualOverride else { return }
        p.source = .manual; p.manualOverride = false; p.confidence = 0
        try await store.upsertDeviceProfile(p)
    }

    /// Forgets a device: RADIUS sees it as `unknown` until DHCP profiles it again.
    public func deleteDeviceProfile(mac: String) async throws {
        try await dhcpStore().deleteDeviceProfile(mac: mac)
    }

    public func dhcpStatus() async -> DHCPRuntimeStatus? { await runtime?.dhcp?.status() }

    // MARK: Settings

    public func dhcpSettings() async -> DHCPSettings { (try? await store?.dhcpSettings()) ?? DHCPSettings() }

    /// Saves everything except the direct-mode interfaces (those go through the probe).
    public func saveDHCPSettings(_ settings: DHCPSettings) async throws {
        let store = try dhcpStore()
        var s = settings
        s.directInterfaces = try await store.dhcpSettings().directInterfaces
        try await store.setDHCPSettings(s)
        serveLog.event("DHCP", "settings saved: \(s.modeText)"
                       + (s.allowedRelays.isEmpty ? ", relays with giaddr in a scope" : ", relays \(s.allowedRelays.joined(separator: ", "))")
                       + (s.profilers.isEmpty ? "" : ", profilers \(s.profilers.joined(separator: ", "))") + " (app)")
        await dhcpChanged()
    }

    /// Direct mode on `interface`: probes first (a DISCOVER broadcast) and refuses when any DHCP
    /// server answers — the production server must never have to compete with LabDC.
    @discardableResult
    public func enableDHCPDirect(interface: String, probe: @escaping @Sendable (String) -> DHCPProbe.Result = { DHCPProbe.run(interface: $0) }) async throws -> String {
        let store = try dhcpStore()
        serveLog.event("DHCP", "probing \(interface) for other DHCP servers before direct mode (app)")
        let result = await Task.detached { probe(interface) }.value
        if let problem = result.problem {
            serveLog.warning("DHCP", "direct mode on \(interface) refused: \(problem)")
            throw CLIError.failure("Direct mode stays off: \(problem)")
        }
        guard result.servers.isEmpty else {
            let list = result.servers.joined(separator: ", ")
            serveLog.warning("DHCP", "direct mode on \(interface) refused: DHCP server \(list) answered the probe")
            throw CLIError.failure("Direct mode stays off: another DHCP server (\(list)) answers on \(interface). Use relay-only, or ask the network team for a VLAN without one.")
        }
        var s = try await store.dhcpSettings()
        if !s.directInterfaces.contains(interface) { s.directInterfaces.append(interface) }
        try await store.setDHCPSettings(s)
        serveLog.event("DHCP", "direct mode on \(interface): no other DHCP server answered; LabDC now answers local broadcasts there (app)")
        await dhcpChanged()
        return "No other DHCP server answered on \(interface). LabDC now answers DHCP broadcasts there."
    }

    public func disableDHCPDirect(interface: String) async throws {
        let store = try dhcpStore()
        var s = try await store.dhcpSettings()
        s.directInterfaces.removeAll { $0 == interface }
        try await store.setDHCPSettings(s)
        serveLog.event("DHCP", "direct mode off on \(interface): relay-only there again (app)")
        await dhcpChanged()
    }

    // MARK: Test, export

    public func dhcpTest(v4 request: DHCPDryRun.V4) async -> (ok: Bool, text: String) {
        guard let store else { return (false, "The server is not running.") }
        do {
            let r = try await DHCPDryRun.offer(store: store, request, advertised: status.advertisedIPv4)
            return (r.ok, r.lines.joined(separator: "\n"))
        } catch { return (false, "\(error)") }
    }

    public func dhcpTest(v6 request: DHCPDryRun.V6) async -> (ok: Bool, text: String) {
        guard let store else { return (false, "The server is not running.") }
        do {
            let r = try await DHCPDryRun.advertise(store: store, request, advertised: status.advertisedIPv4)
            return (r.ok, r.lines.joined(separator: "\n"))
        } catch { return (false, "\(error)") }
    }

    public func exportDHCPConfig() async throws -> Data { try await dhcpStore().exportDHCPConfig() }

    public func importDHCPConfig(_ data: Data) async throws -> String {
        let r = try await dhcpStore().importDHCPConfig(data)
        serveLog.event("DHCP", "imported \(r.scopes) scopes and \(r.reservations) reservations (app)"
                       + (r.ignoredDirect.isEmpty ? "" : "; direct interfaces \(r.ignoredDirect.joined(separator: ", ")) ignored"))
        await dhcpChanged()
        var text = "Imported \(r.scopes) scope\(r.scopes == 1 ? "" : "s") and \(r.reservations) reservation\(r.reservations == 1 ? "" : "s")."
        if !r.ignoredDirect.isEmpty {
            text += " Direct interfaces in the file (\(r.ignoredDirect.joined(separator: ", "))) were ignored: an import never "
                + "switches direct mode on — turn it on in Settings, which probes for another DHCP server first."
        }
        return text
    }
}
