import Foundation
import RPCKit
import Store

/// The `srvsvc` interface (MS-SRVS, UUID 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0): enough for
/// `net view`, `smbutil view` and impacket's share/server queries.
///
/// Opnums: `NetrShareEnum` 15 (levels 0/1/2), `NetrShareGetInfo` 16 (levels 0/1/2),
/// `NetrServerGetInfo` 21 (levels 100/101/102), `NetrRemoteTOD` 28. Anything else faults with
/// `nca_op_rng_error`.
public struct SrvsvcService: RPCInterface {
    public static let uuid = DCEUUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")
    public static let pipeName = "srvsvc"

    public enum Opnum {
        public static let shareEnum: UInt16 = 15
        public static let shareGetInfo: UInt16 = 16
        public static let serverGetInfo: UInt16 = 21
        public static let remoteTOD: UInt16 = 28
        /// NetrShareEnumSticky — Samba's IDL calls it `srvsvc_NetShareEnum`, and `rpcclient
        /// netshareenum` uses it (WP-Z). Same signature as NetrShareEnum (15).
        public static let shareEnumSticky: UInt16 = 36
    }

    public let store: DirectoryStore
    /// The share list; nil means the DC default (`IPC$`, `NETLOGON`, `SYSVOL`).
    public let shareProvider: (any ShareProvider)?
    let clock: @Sendable () -> Date

    public init(store: DirectoryStore, shares: (any ShareProvider)? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.shareProvider = shares
        self.clock = clock
    }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (3, 0) }

    func shares() async throws -> [ShareDescriptor] {
        if let shareProvider { return await shareProvider.shares() }
        return await StaticShareProvider.domainController(dnsDomain: try await store.domainInfo().dnsDomain).shares()
    }

    /// The `SERVER_INFO` this DC reports: platform 500 (NT), its NetBIOS name, version 10.0,
    /// `SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_DOMAIN_CTRL | SV_TYPE_NT`.
    public func serverInfo() async throws -> ServerInfo {
        ServerInfo(name: try await store.domainInfo().dcName)
    }

    public func dispatch(opnum: UInt16, input r: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        let w = NDRWriter()
        switch opnum {
        case Opnum.shareEnum, Opnum.shareEnumSticky:
            // NetrShareEnum([in,string,unique] SRVSVC_HANDLE ServerName, [in,out] LPSHARE_ENUM_STRUCT
            //   InfoStruct, [in] DWORD PreferedMaximumLength, [out] DWORD* TotalEntries,
            //   [in,out,unique] DWORD* ResumeHandle)
            _ = try r.stringPointerInline()
            let (level, _) = try ShareInfoCodec.decodeEnumStruct(r)
            _ = try r.u32()
            let hasResume = try r.pointer() != nil
            if hasResume { _ = try r.u32() }
            let list = try await shares()
            let ok = ShareInfoCodec.levels.contains(level)
            ShareInfoCodec.encodeEnumStruct(level: level, shares: ok ? list : nil, w)
            w.u32(ok ? UInt32(list.count) : 0)
            if w.uniquePointer(hasResume) { w.u32(0) }
            w.u32(ok ? NetAPIStatus.success : NetAPIStatus.invalidLevel)

        case Opnum.shareGetInfo:
            // NetrShareGetInfo([in,string,unique] SRVSVC_HANDLE ServerName, [in,string] WCHAR* NetName,
            //   [in] DWORD Level, [out, switch_is(Level)] LPSHARE_INFO InfoStruct)
            _ = try r.stringPointerInline()
            let name = try r.refStringInline()
            let level = try r.u32()
            let share = try await shares().first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            let status: UInt32 = !ShareInfoCodec.levels.contains(level) ? NetAPIStatus.invalidLevel
                : share == nil ? NetAPIStatus.netNameNotFound : NetAPIStatus.success
            ShareInfoCodec.encodeShareInfo(level: level, share: status == NetAPIStatus.success ? share : nil, w)
            w.u32(status)

        case Opnum.serverGetInfo:
            // NetrServerGetInfo([in,string,unique] SRVSVC_HANDLE ServerName, [in] DWORD Level,
            //   [out, switch_is(Level)] LPSERVER_INFO InfoStruct)
            _ = try r.stringPointerInline()
            let level = try r.u32()
            let ok = ServerInfo.levels.contains(level)
            ServerInfo.encode(level: level, info: ok ? try await serverInfo() : nil, w)
            w.u32(ok ? NetAPIStatus.success : NetAPIStatus.invalidLevel)

        case Opnum.remoteTOD:
            // NetrRemoteTOD([in,string,unique] SRVSVC_HANDLE ServerName, [out] LPTIME_OF_DAY_INFO* BufferPtr)
            _ = try r.stringPointerInline()
            let uptime = UInt32(truncatingIfNeeded: Int(ProcessInfo.processInfo.systemUptime * 1000))
            TimeOfDayInfo.encodeTopLevel(TimeOfDayInfo(date: clock(), msecsSinceBoot: uptime), w)
            w.u32(NetAPIStatus.success)

        default:
            throw RPCError.fault(.opRangeError)
        }
        return w
    }
}

/// The `wkssvc` interface (MS-WKST, UUID 6bffd098-a112-3610-9833-46c3f87e345a v1.0):
/// `NetrWkstaGetInfo` (0) levels 100/101/102. Anything else faults with `nca_op_rng_error`.
public struct WkssvcService: RPCInterface {
    public static let uuid = DCEUUID("6bffd098-a112-3610-9833-46c3f87e345a")
    public static let pipeName = "wkssvc"

    public enum Opnum {
        public static let wkstaGetInfo: UInt16 = 0
    }

    public let store: DirectoryStore

    public init(store: DirectoryStore) { self.store = store }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (1, 0) }

    /// Platform 500, computer `DC1`, LAN group `LABSHEEP`, version 10.0.
    public func workstationInfo() async throws -> WorkstationInfo {
        let info = try await store.domainInfo()
        return WorkstationInfo(computerName: info.dcName, lanGroup: info.netbiosDomain)
    }

    public func dispatch(opnum: UInt16, input r: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        guard opnum == Opnum.wkstaGetInfo else { throw RPCError.fault(.opRangeError) }
        // NetrWkstaGetInfo([in,string,unique] WKSSVC_IDENTIFY_HANDLE ServerName, [in] unsigned long
        //   Level, [out, switch_is(Level)] LPWKSTA_INFO WkstaInfo)
        let w = NDRWriter()
        _ = try r.stringPointerInline()
        let level = try r.u32()
        let ok = WorkstationInfo.levels.contains(level)
        WorkstationInfo.encode(level: level, info: ok ? try await workstationInfo() : nil, w)
        w.u32(ok ? NetAPIStatus.success : NetAPIStatus.invalidLevel)
        return w
    }
}
