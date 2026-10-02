import Foundation
import RADIUSKit

/// Phase 4c / 5: RADIUS accounting sessions (Start / Interim-Update / Stop kept, 30-day
/// retention), the per-NAS CoA settings, and the registered-devices list MAB policies use.
/// Like the other RADIUS tables: the server's own config and records, not directory data.
extension DirectoryStore {
    /// Sessions whose last word (Stop, or the last Start/Interim) is older than this are purged.
    public static let radiusSessionRetention: TimeInterval = 30 * 86400

    static func createRadiusSessionSchema(_ db: SQLiteConnection) throws {
        try db.exec("""
            CREATE TABLE IF NOT EXISTS radius_sessions(
              id INTEGER PRIMARY KEY,
              session_id TEXT NOT NULL,
              nas_source TEXT NOT NULL,
              nas_name TEXT NULL,
              nas_ip TEXT NULL,
              nas_identifier TEXT NULL,
              nas_port INTEGER NULL,
              nas_port_id TEXT NULL,
              called_station_id TEXT NULL,
              calling_station_id TEXT NULL,
              mac TEXT NULL,
              user_name TEXT NULL,
              framed_ip TEXT NULL,
              started_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              stopped_at INTEGER NULL,
              session_time INTEGER NULL,
              input_octets INTEGER NOT NULL DEFAULT 0,
              output_octets INTEGER NOT NULL DEFAULT 0,
              input_packets INTEGER NOT NULL DEFAULT 0,
              output_packets INTEGER NOT NULL DEFAULT 0,
              terminate_cause INTEGER NULL,
              UNIQUE(nas_source, session_id));
            CREATE INDEX IF NOT EXISTS radius_sessions_mac ON radius_sessions(mac, stopped_at);
            CREATE INDEX IF NOT EXISTS radius_sessions_updated ON radius_sessions(updated_at);
            CREATE TABLE IF NOT EXISTS radius_devices(
              mac TEXT PRIMARY KEY,
              description TEXT NOT NULL DEFAULT '',
              grp TEXT NULL,
              added_at INTEGER NOT NULL);
            """)
        let nasColumns = try db.query("PRAGMA table_info(radius_nas)").compactMap { $0[1].text }
        if !nasColumns.contains("coa_port") {
            try db.exec("ALTER TABLE radius_nas ADD COLUMN coa_port INTEGER NOT NULL DEFAULT 3799")
        }
        if !nasColumns.contains("coa_vendor") {
            try db.exec("ALTER TABLE radius_nas ADD COLUMN coa_vendor TEXT NOT NULL DEFAULT 'generic'")
        }
        let policyColumns = try db.query("PRAGMA table_info(radius_policies)").compactMap { $0[1].text }
        if !policyColumns.contains("allow_mab") {
            try db.exec("ALTER TABLE radius_policies ADD COLUMN allow_mab INTEGER NOT NULL DEFAULT 0")
        }
    }

    // MARK: Sessions

    public struct RadiusSession: Sendable, Equatable, Identifiable {
        public var id: Int64
        public var sessionId: String
        /// The address the accounting came from; CoA goes back to it.
        public var nasSource: String
        public var nasName: String?
        public var nasIP: String?
        public var nasIdentifier: String?
        public var nasPort: UInt32?
        public var nasPortId: String?
        public var calledStationId: String?
        /// As the NAS sent it.
        public var callingStationId: String?
        /// Canonical MAC of the Calling-Station-Id.
        public var mac: String?
        public var userName: String?
        public var framedIP: String?
        public var startedAt: Date
        public var updatedAt: Date
        public var stoppedAt: Date?
        public var sessionTime: UInt32?
        public var inputOctets: UInt64
        public var outputOctets: UInt64
        public var inputPackets: UInt64
        public var outputPackets: UInt64
        public var terminateCause: UInt32?

        public var active: Bool { stoppedAt == nil }

        /// The session as a CoA/Disconnect names it.
        public var coaSession: CoASession {
            CoASession(nasIP: nasIP, nasIdentifier: nasIP == nil ? nasIdentifier : nil, acctSessionId: sessionId,
                       userName: userName, callingStationId: callingStationId, framedIP: framedIP)
        }
    }

    private static let sessionColumns = """
        id, session_id, nas_source, nas_name, nas_ip, nas_identifier, nas_port, nas_port_id, called_station_id,
        calling_station_id, mac, user_name, framed_ip, started_at, updated_at, stopped_at, session_time,
        input_octets, output_octets, input_packets, output_packets, terminate_cause
        """

    private static func session(_ r: [SQLValue]) -> RadiusSession {
        func date(_ v: SQLValue) -> Date? { v.int.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
        func u32(_ v: SQLValue) -> UInt32? { v.int.map { UInt32(clamping: $0) } }
        return RadiusSession(id: r[0].int ?? 0, sessionId: r[1].text ?? "", nasSource: r[2].text ?? "",
                             nasName: r[3].text, nasIP: r[4].text, nasIdentifier: r[5].text, nasPort: u32(r[6]),
                             nasPortId: r[7].text, calledStationId: r[8].text, callingStationId: r[9].text, mac: r[10].text,
                             userName: r[11].text, framedIP: r[12].text, startedAt: date(r[13]) ?? .distantPast,
                             updatedAt: date(r[14]) ?? .distantPast, stoppedAt: date(r[15]), sessionTime: u32(r[16]),
                             inputOctets: UInt64(clamping: r[17].int ?? 0), outputOctets: UInt64(clamping: r[18].int ?? 0),
                             inputPackets: UInt64(clamping: r[19].int ?? 0), outputPackets: UInt64(clamping: r[20].int ?? 0),
                             terminateCause: u32(r[21]))
    }

    /// Stores one Accounting-Request. Start opens (or reopens — a NAS that reuses an
    /// Acct-Session-Id after a reboot) the session; Interim-Update refreshes it (creating it when
    /// the Start was lost); Stop closes it with the counters and Terminate-Cause.
    /// Accounting-On/Off closes every open session of that NAS (Terminate-Cause NAS-Reboot).
    /// Returns the session written (nil for On/Off) and how many sessions On/Off closed.
    @discardableResult
    public func recordAccounting(_ record: AccountingRecord, nasName: String?, now: Date) throws -> (session: RadiusSession?, closed: Int) {
        let t = Int64(now.timeIntervalSince1970)
        let sent = t - Int64(record.delay)
        return try transaction {
            switch record.status {
            case .nasOn, .nasOff:
                try db.run("UPDATE radius_sessions SET stopped_at=?, updated_at=?, terminate_cause=COALESCE(terminate_cause, 11) " +
                           "WHERE nas_source=? AND stopped_at IS NULL", [.int(sent), .int(t), .text(record.nasSource)])
                return (nil, db.changes)
            case .start, .interim, .stop:
                break
            }
            let existing = try db.query("SELECT \(Self.sessionColumns) FROM radius_sessions WHERE nas_source=? AND session_id=?",
                                        [.text(record.nasSource), .text(record.sessionId)]).first.map(Self.session)
            // A late Interim-Update (or a repeated Stop) never reopens a session that ended.
            if let existing, !existing.active, record.status != .start { return (existing, 0) }
            // A Start for a session that already ended is a new session under a reused id.
            let fresh = existing == nil || (record.status == .start && existing?.active == false)
            let startedAt: Int64
            if fresh {
                startedAt = record.status == .start ? sent : sent - Int64(record.sessionTime ?? 0)
            } else {
                startedAt = Int64(existing!.startedAt.timeIntervalSince1970)
            }
            let stoppedAt: SQLValue = record.status == .stop ? .int(sent) : .null
            func keep<T>(_ new: T?, _ old: T?) -> T? { new ?? (fresh ? nil : old) }
            let values: [SQLValue] = [
                .text(record.sessionId), .text(record.nasSource), .optional(nasName ?? existing?.nasName),
                .optional(keep(record.nasIP, existing?.nasIP)), .optional(keep(record.nasIdentifier, existing?.nasIdentifier)),
                keep(record.nasPort, existing?.nasPort).map { .int(Int64($0)) } ?? .null,
                .optional(keep(record.nasPortId, existing?.nasPortId)),
                .optional(keep(record.calledStationId, existing?.calledStationId)),
                .optional(keep(record.callingStationId, existing?.callingStationId)),
                .optional(keep(record.mac, existing?.mac)),
                .optional(keep(record.userName, existing?.userName)),
                .optional(keep(record.framedIP, existing?.framedIP)),
                .int(startedAt), .int(t), stoppedAt,
                keep(record.sessionTime, existing?.sessionTime).map { .int(Int64($0)) } ?? .null,
                .int(Int64(clamping: keep(record.inputOctets, existing?.inputOctets) ?? 0)),
                .int(Int64(clamping: keep(record.outputOctets, existing?.outputOctets) ?? 0)),
                .int(Int64(clamping: keep(record.inputPackets.map(UInt64.init), existing?.inputPackets) ?? 0)),
                .int(Int64(clamping: keep(record.outputPackets.map(UInt64.init), existing?.outputPackets) ?? 0)),
                record.status == .stop ? (record.terminateCause.map { .int(Int64($0)) } ?? .null) : .null,
            ]
            try db.run("""
                INSERT INTO radius_sessions(session_id, nas_source, nas_name, nas_ip, nas_identifier, nas_port, nas_port_id,
                  called_station_id, calling_station_id, mac, user_name, framed_ip, started_at, updated_at, stopped_at,
                  session_time, input_octets, output_octets, input_packets, output_packets, terminate_cause)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(nas_source, session_id) DO UPDATE SET nas_name=excluded.nas_name, nas_ip=excluded.nas_ip,
                  nas_identifier=excluded.nas_identifier, nas_port=excluded.nas_port, nas_port_id=excluded.nas_port_id,
                  called_station_id=excluded.called_station_id, calling_station_id=excluded.calling_station_id,
                  mac=excluded.mac, user_name=excluded.user_name, framed_ip=excluded.framed_ip,
                  started_at=excluded.started_at, updated_at=excluded.updated_at, stopped_at=excluded.stopped_at,
                  session_time=excluded.session_time, input_octets=excluded.input_octets,
                  output_octets=excluded.output_octets, input_packets=excluded.input_packets,
                  output_packets=excluded.output_packets, terminate_cause=excluded.terminate_cause
                """, values)
            let row = try db.query("SELECT \(Self.sessionColumns) FROM radius_sessions WHERE nas_source=? AND session_id=?",
                                   [.text(record.nasSource), .text(record.sessionId)]).first.map(Self.session)
            return (row, 0)
        }
    }

    /// Newest first. `activeOnly`: sessions without a Stop.
    public func radiusSessions(activeOnly: Bool, limit: Int = 500) throws -> [RadiusSession] {
        try db.query("SELECT \(Self.sessionColumns) FROM radius_sessions " + (activeOnly ? "WHERE stopped_at IS NULL " : "")
                     + "ORDER BY updated_at DESC, id DESC LIMIT ?", [.int(Int64(max(1, limit)))]).map(Self.session)
    }

    public func radiusSession(id: Int64) throws -> RadiusSession? {
        try db.query("SELECT \(Self.sessionColumns) FROM radius_sessions WHERE id=?", [.int(id)]).first.map(Self.session)
    }

    /// Open sessions of `mac` (any spelling), newest first.
    public func activeRadiusSessions(mac: String) throws -> [RadiusSession] {
        guard let key = RADIUSMAC.normalize(mac) else { return [] }
        return try db.query("SELECT \(Self.sessionColumns) FROM radius_sessions WHERE mac=? AND stopped_at IS NULL " +
                            "ORDER BY updated_at DESC", [.text(key)]).map(Self.session)
    }

    /// Drops sessions whose last record is older than `cutoff`; returns how many.
    @discardableResult
    public func purgeRadiusSessions(before cutoff: Date) throws -> Int {
        try transaction {
            try db.run("DELETE FROM radius_sessions WHERE COALESCE(stopped_at, updated_at) < ?",
                       [.int(Int64(cutoff.timeIntervalSince1970))])
            return db.changes
        }
    }

    // MARK: Registered devices (MAB allow-list)

    public struct RegisteredDevice: Sendable, Equatable, Identifiable {
        /// Canonical `aa:bb:cc:dd:ee:ff`.
        public var mac: String
        public var description: String
        /// Matched by `device_group` in policies.
        public var group: String?
        public var addedAt: Date
        public var id: String { mac }

        public init(mac: String, description: String = "", group: String? = nil, addedAt: Date = Date()) {
            self.mac = RADIUSMAC.normalize(mac) ?? mac
            self.description = description
            let g = group?.trimmingCharacters(in: .whitespaces)
            self.group = g?.isEmpty == false ? g : nil
            self.addedAt = addedAt
        }
    }

    public func registeredDevices() throws -> [RegisteredDevice] {
        try db.query("SELECT mac, description, grp, added_at FROM radius_devices ORDER BY mac").map {
            RegisteredDevice(mac: $0[0].text ?? "", description: $0[1].text ?? "", group: $0[2].text,
                             addedAt: Date(timeIntervalSince1970: TimeInterval($0[3].int ?? 0)))
        }
    }

    public func registeredDevice(mac: String) throws -> RegisteredDevice? {
        guard let key = RADIUSMAC.normalize(mac) else { return nil }
        return try db.query("SELECT mac, description, grp, added_at FROM radius_devices WHERE mac=?", [.text(key)]).first.map {
            RegisteredDevice(mac: $0[0].text ?? "", description: $0[1].text ?? "", group: $0[2].text,
                             addedAt: Date(timeIntervalSince1970: TimeInterval($0[3].int ?? 0)))
        }
    }

    /// Adds or replaces (by MAC) a registered device.
    public func saveRegisteredDevice(_ device: RegisteredDevice) throws {
        guard let key = RADIUSMAC.normalize(device.mac) else {
            throw StoreError.constraintViolation("\(device.mac) is not a MAC address")
        }
        try transaction {
            try db.run("INSERT INTO radius_devices(mac, description, grp, added_at) VALUES(?,?,?,?) " +
                       "ON CONFLICT(mac) DO UPDATE SET description=excluded.description, grp=excluded.grp",
                       [.text(key), .text(device.description), .optional(device.group),
                        .int(Int64(device.addedAt.timeIntervalSince1970))])
        }
    }

    /// True when a device was removed.
    @discardableResult
    public func deleteRegisteredDevice(mac: String) throws -> Bool {
        guard let key = RADIUSMAC.normalize(mac) else { return false }
        return try transaction {
            try db.run("DELETE FROM radius_devices WHERE mac=?", [.text(key)])
            return db.changes > 0
        }
    }
}
