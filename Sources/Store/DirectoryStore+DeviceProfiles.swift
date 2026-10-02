import Foundation
import Synchronization

/// Broadcasts the MACs whose device profile changed (category or OS): the RADIUS side
/// subscribes to send CoA. Each `stream()` is its own subscriber.
public final class DeviceProfileEvents: Sendable {
    private let observers = Mutex<[UUID: AsyncStream<String>.Continuation]>([:])

    public init() {}

    public func stream() -> AsyncStream<String> {
        let (stream, continuation) = AsyncStream.makeStream(of: String.self, bufferingPolicy: .bufferingNewest(256))
        let key = UUID()
        observers.withLock { $0[key] = continuation }
        continuation.onTermination = { [weak self] _ in
            self?.observers.withLock { _ = $0.removeValue(forKey: key) }
        }
        return stream
    }

    public func publish(_ mac: String) {
        for o in observers.withLock({ Array($0.values) }) { o.yield(mac) }
    }
}

/// `DeviceProfileSource` over a store (what RADIUS is handed).
public struct StoreDeviceProfileSource: DeviceProfileSource {
    public let store: DirectoryStore

    public init(store: DirectoryStore) { self.store = store }

    public func deviceProfile(mac: String) async throws -> DeviceProfile? { try await store.deviceProfile(mac: mac) }
    public var changes: AsyncStream<String> { store.deviceProfileEvents.stream() }
}

extension DirectoryStore {
    static func createDeviceProfileSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS device_profiles(
              mac TEXT PRIMARY KEY,
              first_seen INTEGER NOT NULL,
              last_seen INTEGER NOT NULL,
              source TEXT NOT NULL,
              category TEXT NOT NULL,
              os TEXT NULL,
              vendor_class TEXT NULL,
              hostname TEXT NULL,
              confidence INTEGER NOT NULL DEFAULT 0,
              manual_override INTEGER NOT NULL DEFAULT 0);
            """)
    }

    /// Any spelling of a MAC → `aa:bb:cc:dd:ee:ff` (RADIUS Calling-Station-Id is `AA-BB-…`).
    public nonisolated static func canonicalMAC(_ text: String) -> String? {
        let hex = text.lowercased().filter(\.isHexDigit)
        guard hex.count == 12 else { return nil }
        var out = ""
        for (i, ch) in hex.enumerated() {
            if i > 0, i % 2 == 0 { out.append(":") }
            out.append(ch)
        }
        return out
    }

    public func deviceProfile(mac: String) throws -> DeviceProfile? {
        guard let key = Self.canonicalMAC(mac) else { return nil }
        return try db.query("SELECT mac, first_seen, last_seen, source, category, os, vendor_class, hostname, confidence, manual_override "
                            + "FROM device_profiles WHERE mac = ?", [.text(key)]).first.map(Self.profileRow)
    }

    public func deviceProfiles(limit: Int = 10_000) throws -> [DeviceProfile] {
        try db.query("SELECT mac, first_seen, last_seen, source, category, os, vendor_class, hostname, confidence, manual_override "
                     + "FROM device_profiles ORDER BY last_seen DESC LIMIT ?", [.int(Int64(limit))]).map(Self.profileRow)
    }

    static func profileRow(_ r: [SQLValue]) -> DeviceProfile {
        return DeviceProfile(mac: r[0].text ?? "", firstSeen: Self.realDate(r[1]), lastSeen: Self.realDate(r[2]),
                             source: DeviceProfile.Source(rawValue: r[3].text ?? "") ?? .dhcp4,
                             category: DeviceCategory(rawValue: r[4].text ?? "") ?? .unknown, os: r[5].text,
                             vendorClass: r[6].text, hostname: r[7].text, confidence: Int(r[8].int ?? 0),
                             manualOverride: (r[9].int ?? 0) != 0)
    }

    /// How far a DHCP update may move an existing profile's category (anti-poisoning: a host
    /// that already authenticated by 802.1X should not be re-profiled by forged DHCP).
    public enum CategoryGuard: Sendable, Equatable {
        /// The usual rules (manual override kept, never down to a lower-confidence guess).
        case open
        /// Category/OS change only on a strictly higher confidence.
        case strictlyHigher
        /// Category/OS never change (last-seen, host name and vendor class still move).
        case frozen
    }

    /// Inserts or updates a profile. A manual override is kept against DHCP updates (only
    /// last-seen, host name and vendor class move); a profile never drops to a lower
    /// confidence guess; `guard` restricts category changes further. Returns true when the
    /// category or OS changed (a new profile counts), and then publishes the MAC on
    /// `deviceProfileEvents`.
    @discardableResult
    public func upsertDeviceProfile(_ profile: DeviceProfile, guard categoryGuard: CategoryGuard = .open) throws -> Bool {
        guard let key = Self.canonicalMAC(profile.mac) else { throw StoreError.constraintViolation("\(profile.mac) is not a MAC address") }
        var next = profile
        next.mac = key
        let changed: Bool = try transaction {
            let existing = try db.query("SELECT mac, first_seen, last_seen, source, category, os, vendor_class, hostname, confidence, manual_override "
                                        + "FROM device_profiles WHERE mac = ?", [.text(key)]).first.map(Self.profileRow)
            if let old = existing {
                next.firstSeen = min(old.firstSeen, next.firstSeen)
                next.lastSeen = max(old.lastSeen, next.lastSeen)
                if old.manualOverride, profile.source != .manual {
                    next.category = old.category; next.os = old.os; next.confidence = old.confidence
                    next.manualOverride = true; next.source = old.source
                } else if profile.source != .manual, next.confidence < old.confidence, old.category != .unknown {
                    next.category = old.category; next.os = old.os; next.confidence = old.confidence
                } else if profile.source != .manual, next.category != old.category,
                          categoryGuard == .frozen || (categoryGuard == .strictlyHigher && next.confidence <= old.confidence) {
                    next.category = old.category; next.os = old.os; next.confidence = old.confidence; next.source = old.source
                }
                next.vendorClass = next.vendorClass ?? old.vendorClass
                next.hostname = next.hostname ?? old.hostname
            }
            try db.run("""
                INSERT INTO device_profiles(mac, first_seen, last_seen, source, category, os, vendor_class, hostname, confidence, manual_override)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                source=excluded.source, category=excluded.category, os=excluded.os, vendor_class=excluded.vendor_class,
                hostname=excluded.hostname, confidence=excluded.confidence, manual_override=excluded.manual_override
                """, [.text(key), .int(Self.epochSeconds(next.firstSeen)), .int(Self.epochSeconds(next.lastSeen)),
                      .text(next.source.rawValue), .text(next.category.rawValue), .optional(next.os), .optional(next.vendorClass),
                      .optional(next.hostname), .int(Int64(next.confidence)), .int(next.manualOverride ? 1 : 0)])
            guard let old = existing else { return true }
            return old.category != next.category || old.os != next.os
        }
        if changed { deviceProfileEvents.publish(key) }
        return changed
    }

    /// Drops DHCP-made profiles that never got a category (`unknown`, not manual) and were last
    /// seen before `cutoff`; returns how many. Scanners and MAC-randomising phones would
    /// otherwise grow the table without bound.
    @discardableResult
    public func purgeUnknownDeviceProfiles(lastSeenBefore cutoff: Date) throws -> Int {
        try transaction {
            try db.run("DELETE FROM device_profiles WHERE category = ? AND manual_override = 0 AND source != ? AND last_seen < ?",
                       [.text(DeviceCategory.unknown.rawValue), .text(DeviceProfile.Source.manual.rawValue), .int(Self.epochSeconds(cutoff))])
            return db.changes
        }
    }

    public func deleteDeviceProfile(mac: String) throws {
        guard let key = Self.canonicalMAC(mac) else { return }
        try db.run("DELETE FROM device_profiles WHERE mac = ?", [.text(key)])
    }

    /// Dates are stored as whole seconds since 1970 (`SQLValue` has no REAL).
    static func realDate(_ v: SQLValue) -> Date { Date(timeIntervalSince1970: TimeInterval(v.int ?? 0)) }
    static func epochSeconds(_ d: Date) -> Int64 { Int64(d.timeIntervalSince1970.rounded(.down)) }
}
