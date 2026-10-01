import Foundation
import RPCKit

// MARK: - Shares

/// Share type bits (MS-SRVS §2.2.2.4).
public enum ShareType {
    public static let diskTree: UInt32 = 0x0000_0000
    public static let printQueue: UInt32 = 0x0000_0001
    public static let device: UInt32 = 0x0000_0002
    public static let ipc: UInt32 = 0x0000_0003
    public static let special: UInt32 = 0x8000_0000
    public static let temporary: UInt32 = 0x4000_0000
}

/// A share as srvsvc reports it (the union of the SHARE_INFO_0/1/2 fields).
public struct ShareDescriptor: Sendable, Hashable {
    public var name: String
    public var type: UInt32
    public var remark: String
    /// Local path shown by level 2 (`C:\Windows\SYSVOL\sysvol` on a Windows DC).
    public var path: String

    public init(name: String, type: UInt32, remark: String, path: String = "") {
        self.name = name
        self.type = type
        self.remark = remark
        self.path = path
    }
}

/// Supplies the share list to srvsvc. WP-X passes SMBKit's configured shares; tests and the
/// default use `StaticShareProvider.domainController(dnsDomain:)`.
public protocol ShareProvider: Sendable {
    func shares() async -> [ShareDescriptor]
}

/// A fixed share list.
public struct StaticShareProvider: ShareProvider {
    public let list: [ShareDescriptor]

    public init(_ list: [ShareDescriptor]) { self.list = list }

    public func shares() async -> [ShareDescriptor] { list }

    /// `IPC$`, `NETLOGON`, `SYSVOL` with the remarks and paths a Windows DC reports.
    public static func domainController(dnsDomain: String) -> StaticShareProvider {
        StaticShareProvider([
            ShareDescriptor(name: "IPC$", type: ShareType.ipc | ShareType.special, remark: "Remote IPC"),
            ShareDescriptor(name: "NETLOGON", type: ShareType.diskTree, remark: "Logon server share ",
                            path: "C:\\Windows\\SYSVOL\\sysvol\\\(dnsDomain)\\SCRIPTS"),
            ShareDescriptor(name: "SYSVOL", type: ShareType.diskTree, remark: "Logon server share ",
                            path: "C:\\Windows\\SYSVOL\\sysvol"),
        ])
    }
}

/// `SHARE_INFO_0/1/2` marshalling (MS-SRVS §2.2.4.22–24). Level 2's `shi2_passwd` is always NULL.
public enum ShareInfoCodec {
    public static let levels: Set<UInt32> = [0, 1, 2]

    /// Flat part; the `[string] wchar_t*` bodies are deferred.
    static func encodeFlat(_ s: ShareDescriptor, level: UInt32, _ w: NDRWriter) {
        w.stringPointer(s.name)
        guard level >= 1 else { return }
        w.u32(s.type)
        w.stringPointer(s.remark)
        guard level >= 2 else { return }
        w.u32(0)              // shi2_permissions (ACCESS_NONE: share-level security not used)
        w.u32(0xFFFF_FFFF)    // shi2_max_uses (unlimited)
        w.u32(0)              // shi2_current_uses
        w.stringPointer(s.path)
        w.stringPointer(nil)  // shi2_passwd
    }

    struct Flat { var name: Bool; var type: UInt32; var remark: Bool; var path: Bool; var passwd: Bool }

    static func decodeFlat(level: UInt32, _ r: NDRReader) throws -> Flat {
        var f = Flat(name: try r.pointer() != nil, type: 0, remark: false, path: false, passwd: false)
        guard level >= 1 else { return f }
        f.type = try r.u32()
        f.remark = try r.pointer() != nil
        guard level >= 2 else { return f }
        _ = try r.u32(); _ = try r.u32(); _ = try r.u32()
        f.path = try r.pointer() != nil
        f.passwd = try r.pointer() != nil
        return f
    }

    static func decodeBodies(_ f: Flat, _ r: NDRReader) throws -> ShareDescriptor {
        let name = f.name ? try r.refStringInline() : ""
        let remark = f.remark ? try r.refStringInline() : ""
        let path = f.path ? try r.refStringInline() : ""
        if f.passwd { _ = try r.refStringInline() }
        return ShareDescriptor(name: name, type: f.type, remark: remark, path: path)
    }

    /// `SHARE_ENUM_STRUCT` (top-level `[in, out] LPSHARE_ENUM_STRUCT`): `Level`, then the
    /// `SHARE_ENUM_UNION` (32-bit discriminant, pointer to `SHARE_INFO_n_CONTAINER` =
    /// `{ EntriesRead; [size_is(EntriesRead)] LPSHARE_INFO_n Buffer; }`).
    public static func encodeEnumStruct(level: UInt32, shares: [ShareDescriptor]?, _ w: NDRWriter) {
        w.u32(level)
        w.u32(level)
        guard let shares, levels.contains(level) else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.deferPointee { [weak w] in
            guard let w else { return }
            w.u32(UInt32(shares.count))
            if w.uniquePointer(!shares.isEmpty) {
                w.deferPointee { [weak w] in
                    guard let w else { return }
                    w.u32(UInt32(shares.count))
                    for s in shares { encodeFlat(s, level: level, w) }
                }
            }
        }
        w.flushDeferred()
    }

    public static func decodeEnumStruct(_ r: NDRReader) throws -> (level: UInt32, shares: [ShareDescriptor]?) {
        let level = try r.u32()
        let tag = try r.u32()
        guard tag == level else { throw NDRError(offset: r.offset, reason: "union tag \(tag) != Level \(level)") }
        guard try r.pointer() != nil else { return (level, nil) }
        // Every SHARE_INFO_n_CONTAINER starts { EntriesRead; Buffer* }, so an (empty) request
        // container parses whatever the level.
        let entries = Int(try r.u32())
        guard try r.pointer() != nil else { return (level, []) }
        guard levels.contains(level) else { throw NDRError(offset: r.offset, reason: "unsupported share level \(level)") }
        let n = try r.boundedCount(max: 65536)
        guard n == entries else { throw NDRError(offset: r.offset, reason: "share array \(n) != EntriesRead \(entries)") }
        var flats: [Flat] = []
        for _ in 0..<n { flats.append(try decodeFlat(level: level, r)) }
        return (level, try flats.map { try decodeBodies($0, r) })
    }

    /// `[out, switch_is(Level)] LPSHARE_INFO InfoStruct` of `NetrShareGetInfo`: a 32-bit
    /// discriminant then a pointer to the `SHARE_INFO_n`.
    public static func encodeShareInfo(level: UInt32, share: ShareDescriptor?, _ w: NDRWriter) {
        w.u32(level)
        guard let share, levels.contains(level) else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.deferPointee { [weak w] in
            guard let w else { return }
            encodeFlat(share, level: level, w)
        }
        w.flushDeferred()
    }

    public static func decodeShareInfo(_ r: NDRReader) throws -> (level: UInt32, share: ShareDescriptor?) {
        let level = try r.u32()
        guard try r.pointer() != nil else { return (level, nil) }
        guard levels.contains(level) else { throw NDRError(offset: r.offset, reason: "unsupported share level \(level)") }
        let f = try decodeFlat(level: level, r)
        return (level, try decodeBodies(f, r))
    }
}

// MARK: - Server info

/// Server type bits (MS-SRVS §2.2.2.7).
public enum ServerType {
    public static let workstation: UInt32 = 0x0000_0001
    public static let server: UInt32 = 0x0000_0002
    public static let domainController: UInt32 = 0x0000_0008
    public static let nt: UInt32 = 0x0000_1000
    /// What this DC advertises: workstation, server, domain controller, NT (no DFS root).
    public static let dc: UInt32 = workstation | server | domainController | nt
}

/// `SERVER_INFO_100/101/102` (MS-SRVS §2.2.4.40–42).
public struct ServerInfo: Sendable, Hashable {
    public var platformID: UInt32
    public var name: String
    public var versionMajor: UInt32
    public var versionMinor: UInt32
    public var type: UInt32
    public var comment: String
    public var users: UInt32
    public var disc: Int32
    public var hidden: UInt32
    public var announce: UInt32
    public var anndelta: UInt32
    public var licenses: UInt32
    public var userPath: String

    public init(platformID: UInt32 = 500, name: String, versionMajor: UInt32 = 10, versionMinor: UInt32 = 0,
                type: UInt32 = ServerType.dc, comment: String = "", users: UInt32 = 0xFFFF_FFFF, disc: Int32 = 15,
                hidden: UInt32 = 0, announce: UInt32 = 240, anndelta: UInt32 = 3000, licenses: UInt32 = 0,
                userPath: String = "c:\\") {
        self.platformID = platformID
        self.name = name
        self.versionMajor = versionMajor
        self.versionMinor = versionMinor
        self.type = type
        self.comment = comment
        self.users = users
        self.disc = disc
        self.hidden = hidden
        self.announce = announce
        self.anndelta = anndelta
        self.licenses = licenses
        self.userPath = userPath
    }

    public static let levels: Set<UInt32> = [100, 101, 102]

    /// `[out, switch_is(Level)] LPSERVER_INFO InfoStruct`: discriminant, pointer, struct, strings.
    /// Fields not carried by a lower level decode as this type's defaults.
    public static func encode(level: UInt32, info: ServerInfo?, _ w: NDRWriter) {
        w.u32(level)
        guard let info, levels.contains(level) else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.deferPointee { [weak w] in
            guard let w else { return }
            w.u32(info.platformID)
            w.stringPointer(info.name)
            guard level >= 101 else { return }
            w.u32(info.versionMajor)
            w.u32(info.versionMinor)
            w.u32(info.type)
            w.stringPointer(info.comment)
            guard level >= 102 else { return }
            w.u32(info.users)
            w.i32(info.disc)
            w.u32(info.hidden)
            w.u32(info.announce)
            w.u32(info.anndelta)
            w.u32(info.licenses)
            w.stringPointer(info.userPath)
        }
        w.flushDeferred()
    }

    public static func decode(_ r: NDRReader) throws -> (level: UInt32, info: ServerInfo?) {
        let level = try r.u32()
        guard try r.pointer() != nil else { return (level, nil) }
        guard levels.contains(level) else { throw NDRError(offset: r.offset, reason: "unsupported server level \(level)") }
        var info = ServerInfo(name: "")
        info.platformID = try r.u32()
        let hasName = try r.pointer() != nil
        var hasComment = false, hasPath = false
        if level >= 101 {
            info.versionMajor = try r.u32()
            info.versionMinor = try r.u32()
            info.type = try r.u32()
            hasComment = try r.pointer() != nil
        }
        if level >= 102 {
            info.users = try r.u32()
            info.disc = try r.i32()
            info.hidden = try r.u32()
            info.announce = try r.u32()
            info.anndelta = try r.u32()
            info.licenses = try r.u32()
            hasPath = try r.pointer() != nil
        }
        if hasName { info.name = try r.refStringInline() }
        if hasComment { info.comment = try r.refStringInline() }
        if hasPath { info.userPath = try r.refStringInline() }
        return (level, info)
    }
}

/// `TIME_OF_DAY_INFO` (MS-SRVS §2.2.4.105), returned by `NetrRemoteTOD`.
public struct TimeOfDayInfo: Sendable, Hashable {
    public var elapsedt: UInt32
    public var msecs: UInt32
    public var hours: UInt32
    public var mins: UInt32
    public var secs: UInt32
    public var hunds: UInt32
    /// Minutes west of UTC; this server reports UTC (0).
    public var timezone: Int32
    /// Clock tick interval in 0.0001 s units.
    public var tinterval: UInt32
    public var day: UInt32
    public var month: UInt32
    public var year: UInt32
    public var weekday: UInt32

    public init(date: Date, msecsSinceBoot: UInt32 = 0) {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second, .nanosecond, .weekday], from: date)
        elapsedt = UInt32(clamping: Int64(date.timeIntervalSince1970))
        msecs = msecsSinceBoot
        hours = UInt32(c.hour ?? 0)
        mins = UInt32(c.minute ?? 0)
        secs = UInt32(c.second ?? 0)
        hunds = UInt32((c.nanosecond ?? 0) / 10_000_000)
        timezone = 0
        tinterval = 310
        day = UInt32(c.day ?? 1)
        month = UInt32(c.month ?? 1)
        year = UInt32(c.year ?? 1970)
        weekday = UInt32((c.weekday ?? 1) - 1)   // 0 = Sunday
    }

    /// `[out] LPTIME_OF_DAY_INFO* BufferPtr`: unique pointer then the 12 DWORDs.
    public static func encodeTopLevel(_ t: TimeOfDayInfo, _ w: NDRWriter) {
        _ = w.uniquePointer(true)
        for v in [t.elapsedt, t.msecs, t.hours, t.mins, t.secs, t.hunds, UInt32(bitPattern: t.timezone),
                  t.tinterval, t.day, t.month, t.year, t.weekday] { w.u32(v) }
    }

    public static func decodeTopLevel(_ r: NDRReader) throws -> TimeOfDayInfo? {
        guard try r.pointer() != nil else { return nil }
        var v: [UInt32] = []
        for _ in 0..<12 { v.append(try r.u32()) }
        var t = TimeOfDayInfo(date: Date(timeIntervalSince1970: 0))
        t.elapsedt = v[0]; t.msecs = v[1]; t.hours = v[2]; t.mins = v[3]; t.secs = v[4]; t.hunds = v[5]
        t.timezone = Int32(bitPattern: v[6]); t.tinterval = v[7]; t.day = v[8]; t.month = v[9]; t.year = v[10]
        t.weekday = v[11]
        return t
    }
}

// MARK: - Workstation info

/// `WKSTA_INFO_100/101/102` (MS-WKST §2.2.5.1–3).
public struct WorkstationInfo: Sendable, Hashable {
    public var platformID: UInt32
    public var computerName: String
    public var lanGroup: String
    public var versionMajor: UInt32
    public var versionMinor: UInt32
    public var lanRoot: String
    public var loggedOnUsers: UInt32

    public init(platformID: UInt32 = 500, computerName: String, lanGroup: String, versionMajor: UInt32 = 10,
                versionMinor: UInt32 = 0, lanRoot: String = "C:\\Windows", loggedOnUsers: UInt32 = 0) {
        self.platformID = platformID
        self.computerName = computerName
        self.lanGroup = lanGroup
        self.versionMajor = versionMajor
        self.versionMinor = versionMinor
        self.lanRoot = lanRoot
        self.loggedOnUsers = loggedOnUsers
    }

    public static let levels: Set<UInt32> = [100, 101, 102]

    /// `[out, switch_is(Level)] LPWKSTA_INFO WkstaInfo`: discriminant, pointer, struct, strings.
    public static func encode(level: UInt32, info: WorkstationInfo?, _ w: NDRWriter) {
        w.u32(level)
        guard let info, levels.contains(level) else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.deferPointee { [weak w] in
            guard let w else { return }
            w.u32(info.platformID)
            w.stringPointer(info.computerName)
            w.stringPointer(info.lanGroup)
            w.u32(info.versionMajor)
            w.u32(info.versionMinor)
            guard level >= 101 else { return }
            w.stringPointer(info.lanRoot)
            guard level >= 102 else { return }
            w.u32(info.loggedOnUsers)
        }
        w.flushDeferred()
    }

    public static func decode(_ r: NDRReader) throws -> (level: UInt32, info: WorkstationInfo?) {
        let level = try r.u32()
        guard try r.pointer() != nil else { return (level, nil) }
        guard levels.contains(level) else { throw NDRError(offset: r.offset, reason: "unsupported wksta level \(level)") }
        var info = WorkstationInfo(computerName: "", lanGroup: "")
        info.platformID = try r.u32()
        let hasName = try r.pointer() != nil
        let hasGroup = try r.pointer() != nil
        info.versionMajor = try r.u32()
        info.versionMinor = try r.u32()
        var hasRoot = false
        if level >= 101 { hasRoot = try r.pointer() != nil }
        if level >= 102 { info.loggedOnUsers = try r.u32() }
        if hasName { info.computerName = try r.refStringInline() }
        if hasGroup { info.lanGroup = try r.refStringInline() }
        if hasRoot { info.lanRoot = try r.refStringInline() }
        return (level, info)
    }
}
