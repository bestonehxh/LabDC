import DNSKit
import MSPAC
import Foundation
import Store

/// DNSKit's `DNSZoneSource` over a `DirectoryStore`.
///
/// - `domainInfo()`: the Store's `domain` values (DNS domain, DC host name, domain GUID, the
///   NTDS Settings objectGUID as `dsaGUID`, site) plus the addresses to publish for the DC:
///   `advertise` when given, else every IPv4 of this Mac (`LabPKI.currentAddresses()`, re-read
///   at most every `addressCacheSeconds`), else `127.0.0.1`.
/// - Stored records live in the Store's `dns_records` table: zone text lower-case (`lab.sheep`,
///   `_msdcs.lab.sheep`), owner relative to the zone (`test1`, `@` for the apex), RDATA in
///   uncompressed wire form. Records added by RFC 2136 updates are `dynamic = 1`, so they
///   survive a restart of `serve`.
public actor StoreZoneSource: DNSZoneSource {
    public let store: DirectoryStore
    private let addressProvider: @Sendable () -> [String]
    private let onChange: (@Sendable (String) -> Void)?
    private let addressCacheSeconds: TimeInterval
    private var base: DNSDomainInfo?
    private var cachedAddresses: (at: Date, list: [DNSAddress])?
    /// Phase 5: the DHCP scopes' reverse zones, re-read at most every `addressCacheSeconds`.
    private var cachedReverse: (at: Date, list: [DNSName])?

    /// - Parameters:
    ///   - advertise: the one IPv4 to publish for the DC (overrides the interface list).
    ///   - addresses: the interface IPv4 list (injected by tests).
    ///   - onChange: called with a log line for every stored or removed dynamic record.
    public init(store: DirectoryStore, advertise: String? = nil,
                addresses: @escaping @Sendable () -> [String] = { ServeAddresses.current() },
                addressCacheSeconds: TimeInterval = 10,
                onChange: (@Sendable (String) -> Void)? = nil) {
        self.store = store
        if let advertise {
            self.addressProvider = { [advertise] }
        } else {
            self.addressProvider = addresses
        }
        self.addressCacheSeconds = addressCacheSeconds
        self.onChange = onChange
    }

    // MARK: DNSZoneSource

    public func domainInfo() async -> DNSDomainInfo {
        var info: DNSDomainInfo
        if let base {
            info = base
        } else {
            do {
                info = try await Self.baseInfo(store)
                base = info
            } catch {
                // Not provisioned: serve an empty `invalid` zone rather than crash.
                return DNSDomainInfo(dnsDomain: "invalid", dcHostName: "dc.invalid", domainGUID: UUID(), addresses: [])
            }
        }
        info.addresses = currentAddresses()
        info.reverseZones = await reverseZones()
        return info
    }

    private func reverseZones() async -> [DNSName] {
        let now = Date()
        if let cached = cachedReverse, now.timeIntervalSince(cached.at) < addressCacheSeconds { return cached.list }
        let list = ((try? await store.dhcpReverseZones()) ?? []).compactMap { try? DNSName(parsing: $0) }
        cachedReverse = (now, list)
        return list
    }

    /// Forget the cached reverse zones (a scope was added or removed in this process).
    public func reverseZonesChanged() { cachedReverse = nil }

    public func records(zone: DNSName) async -> [DNSRecord] {
        let zoneText = zone.canonicalText
        guard let rows = try? await store.dnsRecords(zone: zoneText) else { return [] }
        return rows.compactMap { Self.record(from: $0, zone: zone) }
    }

    public func addDynamic(_ record: DNSRecord, zone: DNSName) async throws {
        let rdata = try DNSRDataCoding.encode(record)
        try await store.addDNSRecord(zone: zone.canonicalText, name: Self.relativeName(record.name, zone: zone),
                                     type: record.type.rawValue, ttl: record.ttl, rdata: rdata, dynamic: true)
        onChange?("stored \(record) (zone \(zone.canonicalText))")
    }

    public func removeDynamic(_ record: DNSRecord, zone: DNSName) async throws {
        let name = Self.relativeName(record.name, zone: zone)
        let rows = try await store.dnsRecords(zone: zone.canonicalText, name: name, type: record.type.rawValue)
        var removed = 0
        for row in rows {
            // RDATA names compare case-insensitively; delete by the stored bytes.
            guard let stored = Self.record(from: row, zone: zone), stored.sameData(as: record) else { continue }
            removed += try await store.deleteDNSRecords(zone: row.zone, name: row.name, type: row.type, rdata: row.rdata)
        }
        if removed > 0 { onChange?("removed \(record) (zone \(zone.canonicalText))") }
    }

    public func hasStaticRecords(name: DNSName, zone: DNSName) async -> Bool {
        // A read error counts as static: the name is then left alone rather than handed over.
        (try? await store.hasStaticDNSRecords(zone: zone.canonicalText, name: Self.relativeName(name, zone: zone))) ?? true
    }

    public func dynamicOwner(name: DNSName, zone: DNSName) async -> DNSRecordOwner? {
        guard let row = try? await store.dnsOwner(zone: zone.canonicalText, name: Self.relativeName(name, zone: zone)),
              let holder = DNSRecordOwner.Holder(storageText: row.owner) else { return nil }
        return DNSRecordOwner(holder: holder, updated: row.updated)
    }

    public func setDynamicOwner(_ owner: DNSRecordOwner.Holder?, name: DNSName, zone: DNSName) async throws {
        try await store.setDNSOwner(zone: zone.canonicalText, name: Self.relativeName(name, zone: zone), owner: owner?.storageText)
    }

    // MARK: Helpers

    /// Domain facts from the Store, without addresses.
    static func baseInfo(_ store: DirectoryStore) async throws -> DNSDomainInfo {
        let info = try await store.domainInfo()
        let domain = try DNSName(parsing: info.dnsDomain)
        let host = try DNSName(parsing: info.dcDNSName)
        guard let domainGUID = UUID(uuidString: info.domainGUID.description) else {
            throw CLIError.failure("bad domain GUID \(info.domainGUID)")
        }
        let former = try await store.formerDCHostNames().compactMap { try? DNSName(parsing: $0) }
        return DNSDomainInfo(dnsDomain: domain, dcHostName: host, domainGUID: domainGUID,
                             dsaGUID: UUID(uuidString: info.dsaGUID.description), site: info.site, addresses: [],
                             formerHostNames: former)
    }

    private func currentAddresses() -> [DNSAddress] {
        let now = Date()
        if let cached = cachedAddresses, now.timeIntervalSince(cached.at) < addressCacheSeconds { return cached.list }
        var list = addressProvider().compactMap(DNSAddress.init)
        if list.isEmpty { list = [DNSAddress("127.0.0.1")!] }
        cachedAddresses = (now, list)
        return list
    }

    /// `test1` for `test1.lab.sheep` in `lab.sheep`, `@` for the apex; an owner outside the
    /// zone is stored absolute with a trailing dot.
    static func relativeName(_ name: DNSName, zone: DNSName) -> String {
        if name == zone { return "@" }
        guard name.isSubdomain(of: zone) else { return name.canonicalText + "." }
        let prefix = DNSName(labels: Array(name.canonicalLabels.dropLast(zone.labels.count)))
        return prefix.description
    }

    static func absoluteName(_ stored: String, zone: DNSName) -> DNSName? {
        if stored == "@" || stored.isEmpty { return zone }
        if stored.hasSuffix(".") { return try? DNSName(parsing: stored) }
        return (try? DNSName(parsing: stored))?.appending(zone)
    }

    public static func record(from row: DNSRecordRow, zone: DNSName) -> DNSRecord? {
        guard let owner = absoluteName(row.name, zone: zone),
              let rdata = try? DNSRDataCoding.decode(type: DNSRecordType(rawValue: row.type), rdata: row.rdata) else { return nil }
        return DNSRecord(name: owner, type: DNSRecordType(rawValue: row.type), ttl: row.ttl, rdata: rdata)
    }
}

/// RDATA to and from the uncompressed wire form stored in `dns_records.rdata`, through DNSKit's
/// own message codec (a one-record message with the root as owner).
public enum DNSRDataCoding {
    /// Header (12) + root owner (1) + type, class, TTL, RDLENGTH (10).
    private static let rdataOffset = 23

    public static func encode(_ record: DNSRecord) throws -> [UInt8] {
        var r = record
        r.name = .root
        let bytes = try DNSMessage(isResponse: true, answers: [r]).encode(compress: false)
        return Array(bytes[rdataOffset...])
    }

    public static func decode(type: DNSRecordType, rdata: [UInt8]) throws -> DNSRData {
        guard rdata.count <= 0xFFFF else { throw CLIError.failure("RDATA too long") }
        var bytes: [UInt8] = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
        bytes += [UInt8(type.rawValue >> 8), UInt8(type.rawValue & 0xFF), 0, 1, 0, 0, 0, 0]
        bytes += [UInt8(rdata.count >> 8), UInt8(rdata.count & 0xFF)] + rdata
        let message = try DNSMessage(bytes: bytes)
        guard let answer = message.answers.first else { throw CLIError.failure("undecodable RDATA") }
        return answer.rdata
    }
}

/// DNSKit's `DNSUpdateDirectory` over a `DirectoryStore`: the signer's `dNSHostName`, and whether
/// it is in Domain Admins / Enterprise Admins / DnsAdmins (nested groups included).
public struct StoreDNSUpdateDirectory: DNSUpdateDirectory {
    public let store: DirectoryStore

    public init(store: DirectoryStore) { self.store = store }

    public func dnsHostName(accountSID: SID) async -> String? {
        (try? await store.dnsHostName(sid: accountSID)) ?? nil
    }

    public func isDNSAdministrator(accountSID: SID) async -> Bool {
        (try? await store.isDNSAdministrator(sid: accountSID)) ?? false
    }
}
