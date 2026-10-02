import DHCPKit
import DNSKit
import Foundation
import Store

/// Lease changes made while the DHCP server is not running (the app with Services stopped,
/// `labdc dhcp`): the DNS records a lease registered go with it, as the running server would
/// remove them.
public enum DHCPOffline {
    /// Ends `lease` now: its A/AAAA/DHCID/PTR are removed and it is saved as released.
    @discardableResult
    public static func release(_ lease: DHCPLease, store: DirectoryStore, now: Date = Date(),
                               log: @escaping @Sendable (String) -> Void = { _ in }) async throws -> DHCPLease {
        var l = await unregister(lease, store: store, log: log)
        l.state = .released
        l.expires = now
        l.updated = now
        try await store.saveDHCPLeases([l])
        return l
    }

    /// Deletes scope `id` with its reservations and leases, removing the leases' DNS records first.
    public static func deleteScope(id: Int64, store: DirectoryStore, log: @escaping @Sendable (String) -> Void = { _ in }) async throws {
        for l in try await store.dhcpLeases() where l.scopeID == id && (l.dnsName != nil || l.dnsPTR != nil) {
            _ = await unregister(l, store: store, log: log)
        }
        try await store.deleteDHCPScope(id: id)
    }

    static func unregister(_ lease: DHCPLease, store: DirectoryStore, log: @escaping @Sendable (String) -> Void) async -> DHCPLease {
        guard lease.dnsName != nil || lease.dnsPTR != nil else { return lease }
        let domain = (try? await store.domainInfo().dnsDomain) ?? ""
        return await DHCPDNSUpdater(store: store, log: log).apply(DHCPv4Engine.unregisterAction(lease), domain: domain)
    }
}

/// Dynamic DNS for leases (spec §2 / rev 2): A/AAAA + DHCID in the AD zone, PTR in the scope's
/// reverse zone, written straight into the store's `dns_records` (the DNS server reads them per
/// query). A name that holds another client's DHCID — or records with no DHCID at all (AD
/// computer accounts, the DC's own names, static records) — is never overwritten; deletes only
/// touch what this lease wrote while the DHCID is still ours. Names the DC answers for itself
/// (its host name and former names, the apex, `_` names, everything `ADZoneGenerator` makes) are
/// refused outright through `DNSResponder.reservedNameReason`, the check unsigned updates use:
/// a stored A there would shadow the generated one.
struct DHCPDNSUpdater: Sendable {
    let store: DirectoryStore
    let log: @Sendable (String) -> Void
    /// Windows' DHCP server registers with a 20-minute TTL.
    static let ttl: UInt32 = 1200

    /// Performs `action` and returns the lease with its DNS fields updated.
    func apply(_ action: DHCPDNSAction, domain: String) async -> DHCPLease {
        switch action.kind {
        case .register: return await register(action, domain: domain)
        case .unregister: return await unregister(action.lease, domain: domain)
        }
    }

    private func register(_ action: DHCPDNSAction, domain: String) async -> DHCPLease {
        var lease = action.lease
        guard let fqdn = action.fqdn?.lowercased() else { return lease }
        if let old = lease.dnsName, old != fqdn {
            lease = await unregister(lease, domain: domain)
        }
        let v4 = lease.family == .v4
        let addressBytes: [UInt8] = v4 ? (IPv4Address(lease.address)?.bytes ?? []) : (IPv6Address(lease.address)?.bytes ?? [])
        guard !addressBytes.isEmpty else { return lease }
        if let reason = await reservedReason(fqdn, domain: domain) {
            log("DNS: \(fqdn) not registered for \(lease.address): name in use by the DC (\(reason))")
            return lease
        }
        var did: [String] = []
        if action.forward {
            let zone = domain.lowercased()
            if DHCPDNS.zone(for: fqdn, in: [zone]) == nil || fqdn == zone {
                log("DNS: \(fqdn) is outside \(zone); \(v4 ? "A" : "AAAA") not registered for \(lease.address)")
            } else {
                let owner = DHCPDNS.relative(fqdn, zone: zone)
                let dhcid = DHCPDNS.dhcid(type: action.identifierType, identifier: action.identifier, fqdn: fqdn)
                let rows = (try? await store.dnsRecords(zone: zone, name: owner)) ?? []
                let held = rows.filter { $0.type == DHCPDNS.dhcidType }
                if !held.isEmpty, !held.contains(where: { $0.rdata == dhcid }) {
                    log("DNS: \(fqdn) not registered for \(lease.address): name in use by another host (its DHCID differs)")
                } else if held.isEmpty, rows.contains(where: { $0.type != DHCPDNS.dhcidType }) {
                    log("DNS: \(fqdn) not registered for \(lease.address): name in use by another host (records without a DHCID)")
                } else {
                    let type: UInt16 = v4 ? 1 : 28
                    for r in rows where r.type == type && r.rdata != addressBytes {
                        _ = try? await store.deleteDNSRecords(zone: zone, name: owner, type: type, rdata: r.rdata)
                    }
                    do {
                        try await store.addDNSRecord(zone: zone, name: owner, type: type, ttl: Self.ttl, rdata: addressBytes, dynamic: true)
                        try await store.addDNSRecord(zone: zone, name: owner, type: DHCPDNS.dhcidType, ttl: Self.ttl, rdata: dhcid, dynamic: true)
                        lease.dnsName = fqdn
                        lease.dnsForward = true
                        lease.dnsDHCID = DHCPHex.string(dhcid)
                        did.append("\(v4 ? "A" : "AAAA") + DHCID")
                    } catch {
                        log("DNS: cannot register \(fqdn): \(error)")
                    }
                }
            }
        }
        if action.ptr {
            let ptrName = v4 ? DHCPDNS.ptrName(v4: IPv4Address(lease.address)!) : DHCPDNS.ptrName(v6: IPv6Address(lease.address)!)
            let zones = (try? await store.dhcpReverseZones()) ?? []
            if let rz = DHCPDNS.zone(for: ptrName, in: zones), let target = try? DHCPDNSWire.encode(fqdn) {
                let owner = DHCPDNS.relative(ptrName, zone: rz)
                let existing = (try? await store.dnsRecords(zone: rz, name: owner, type: 12)) ?? []
                for r in existing where r.dynamic && r.rdata != target {
                    _ = try? await store.deleteDNSRecords(zone: rz, name: owner, type: 12, rdata: r.rdata)
                }
                if existing.contains(where: { !$0.dynamic && $0.rdata != target }) {
                    log("DNS: \(ptrName) has a static PTR; not changed for \(fqdn)")
                } else if (try? await store.addDNSRecord(zone: rz, name: owner, type: 12, ttl: Self.ttl, rdata: target, dynamic: true)) != nil {
                    lease.dnsPTR = ptrName
                    if lease.dnsName == nil { lease.dnsName = fqdn }
                    did.append("PTR")
                }
            }
        }
        if !did.isEmpty { log("DNS: \(fqdn) → \(lease.address) (\(did.joined(separator: ", ")))") }
        return lease
    }

    /// Why `fqdn` belongs to the DC (nil: a client may have it).
    private func reservedReason(_ fqdn: String, domain: String) async -> String? {
        guard let name = try? DNSName(parsing: fqdn) else { return "not a DNS name" }
        let zone = (try? DNSName(parsing: domain.lowercased())) ?? name
        guard let info = try? await StoreZoneSource.baseInfo(store) else {
            return DNSResponder.reservedNameReason(name, zone: zone,
                                                   info: DNSDomainInfo(dnsDomain: zone, dcHostName: .root, domainGUID: UUID(), addresses: []),
                                                   generated: [])
        }
        return DNSResponder.reservedNameReason(name, zone: zone, info: info)
    }

    private func unregister(_ lease: DHCPLease, domain: String) async -> DHCPLease {
        var l = lease
        var did: [String] = []
        let v4 = l.family == .v4
        if l.dnsForward, let fqdn = l.dnsName {
            let zone = domain.lowercased()
            if DHCPDNS.zone(for: fqdn, in: [zone]) != nil {
                let owner = DHCPDNS.relative(fqdn, zone: zone)
                let rows = (try? await store.dnsRecords(zone: zone, name: owner)) ?? []
                let ours = rows.contains { $0.type == DHCPDNS.dhcidType && DHCPHex.string($0.rdata) == l.dnsDHCID }
                if ours {
                    let type: UInt16 = v4 ? 1 : 28
                    let bytes: [UInt8] = v4 ? (IPv4Address(l.address)?.bytes ?? []) : (IPv6Address(l.address)?.bytes ?? [])
                    _ = try? await store.deleteDNSRecords(zone: zone, name: owner, type: type, rdata: bytes)
                    let left = rows.filter { ($0.type == 1 || $0.type == 28) && $0.rdata != bytes }
                    if left.isEmpty, let dhcid = l.dnsDHCID.flatMap(DHCPHex.bytes) {
                        _ = try? await store.deleteDNSRecords(zone: zone, name: owner, type: DHCPDNS.dhcidType, rdata: dhcid)
                    }
                    did.append(v4 ? "A" : "AAAA")
                } else {
                    log("DNS: \(fqdn) kept: its DHCID is no longer this lease's")
                }
            }
        }
        if let ptrName = l.dnsPTR, let fqdn = l.dnsName, let target = try? DHCPDNSWire.encode(fqdn) {
            let zones = (try? await store.dhcpReverseZones()) ?? []
            if let rz = DHCPDNS.zone(for: ptrName, in: zones) {
                let owner = DHCPDNS.relative(ptrName, zone: rz)
                if let n = try? await store.deleteDNSRecords(zone: rz, name: owner, type: 12, rdata: target), n > 0 { did.append("PTR") }
            }
        }
        if !did.isEmpty, let fqdn = l.dnsName { log("DNS: \(fqdn) / \(l.address) removed (\(did.joined(separator: ", ")))") }
        l.dnsName = nil
        l.dnsPTR = nil
        l.dnsForward = false
        l.dnsDHCID = nil
        return l
    }
}
