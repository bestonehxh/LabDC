import Foundation
import RPCKit
import Store
import MSPAC

/// The Directory Replication Service (MS-DRSR) interface `drsuapi`
/// (`e3514235-4b06-11d1-ab04-00c04fc2dcd2` v4.0), a minimal subset Windows uses at logon and that
/// `nltest`/`dsquery`/impacket call: `IDL_DRSBind` (opnum 0), `IDL_DRSUnbind` (1),
/// `IDL_DRSCrackNames` (12) and `IDL_DRSDomainControllerInfo` (16). Everything else faults with
/// `nca_op_rng_error`.
///
/// DRSUAPI is served over `ncacn_ip_tcp` only (Windows never uses the named pipe for it) and
/// **requires `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`** — a call at a lower protection level faults with
/// `nca_s_access_denied`, matching a real DC. The privacy check reads the call's negotiated auth
/// level, which the connection exposes on `RPCCallContext` (WP-AG adds `authLevel`).
public struct DRSService: RPCInterface {
    public static let uuid = DCEUUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2")
    static let handleType = "DRS_HANDLE"

    public enum Opnum {
        public static let bind: UInt16 = 0
        public static let unbind: UInt16 = 1
        public static let crackNames: UInt16 = 12
        public static let domainControllerInfo: UInt16 = 16
    }

    public let store: DirectoryStore
    /// When true (the default) a call below PKT_PRIVACY faults `nca_s_access_denied`, as Windows'
    /// DRSUAPI does. Tests that exercise the NDR without an auth layer can disable it.
    public let requirePrivacy: Bool
    /// WP-AM: receives one operational line per DsBind / DsUnbind / DsDomainControllerInfo call and
    /// per cracked name (`labdc serve` prints them as the `DRSUAPI` component). Also logged to
    /// `os.Logger` category `DRSUAPI`.
    public let onEvent: (@Sendable (String) -> Void)?

    public init(store: DirectoryStore, requirePrivacy: Bool = true,
                onEvent: (@Sendable (String) -> Void)? = nil) {
        self.store = store
        self.requirePrivacy = requirePrivacy
        self.onEvent = onEvent
    }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (4, 0) }

    public func dispatch(opnum: UInt16, input r: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        if requirePrivacy && context.authLevel != .pktPrivacy {
            // MS-DRSR 5.40: the DC rejects DRSUAPI calls that are not privacy-protected.
            logEvent("opnum \(opnum) from \(Self.caller(context)) -> access denied (auth level below PKT_PRIVACY)")
            throw RPCError.fault(.accessDenied)
        }
        switch opnum {
        case Opnum.bind: return try dsBind(r, context)
        case Opnum.unbind: return try dsUnbind(r, context)
        case Opnum.crackNames: return try await dsCrackNames(r, context)
        case Opnum.domainControllerInfo: return try await dsDomainControllerInfo(r, context)
        default: throw RPCError.fault(.opRangeError)
        }
    }

    // MARK: IDL_DRSBind / IDL_DRSUnbind

    private func dsBind(_ r: NDRReader, _ context: RPCCallContext) throws -> NDRWriter {
        // ([in] UUID* puuidClientDsa, [in] DRS_EXTENSIONS* pextClient,
        //  [out] DRS_EXTENSIONS** ppextServer, [out] DRS_HANDLE* phDrs)
        var clientDsa: DCEUUID?
        if try r.pointer() != nil { clientDsa = try r.guid() }  // puuidClientDsa
        if try r.pointer() != nil { _ = try readExtensions(r) } // pextClient (contents ignored)

        let handle = context.handles.allocate(type: Self.handleType, state: DRSBindState())
        logEvent("DsBind client=\(clientDsa.map { "\($0)" } ?? "-") from \(Self.caller(context)) -> OK")
        let w = NDRWriter()
        // ppextServer: a unique pointer to DRS_EXTENSIONS { cb, rgb[] }.
        _ = w.uniquePointer(true)
        w.deferPointee { writeExtensions(w, Self.serverExtensions) }
        w.flushDeferred()
        w.contextHandle(handle)                                  // phDrs
        w.u32(0)                                                 // ErrorCode = 0
        return w
    }

    private func dsUnbind(_ r: NDRReader, _ context: RPCCallContext) throws -> NDRWriter {
        let handle = try r.contextHandle()                       // [in, out] DRS_HANDLE* phDrs
        context.handles.close(handle)
        logEvent("DsUnbind from \(Self.caller(context)) -> OK")
        let w = NDRWriter()
        w.contextHandle(.null)                                   // nulled [out] handle
        w.u32(0)                                                 // ErrorCode
        return w
    }

    /// A DRS_EXTENSIONS_INT (MS-DRSR §5.39) advertising the base capability set. `dwExtCaps`
    /// 0xffffffff mirrors what Windows/impacket send; the concrete flags are not load-bearing for
    /// the calls we implement.
    static let serverExtensions: [UInt8] = {
        var b = [UInt8]()
        func le32(_ v: UInt32) { for i in 0..<4 { b.append(UInt8(truncatingIfNeeded: v >> (8 * i))) } }
        le32(0x0000_0004 | 0x0000_0100)   // dwFlags: DRS_EXT_GETCHGREQ_V6 | DRS_EXT_GETCHGREPLY_V6
        b += [UInt8](repeating: 0, count: 16)  // SiteObjGuid
        le32(0)                            // Pid
        le32(0)                            // dwReplEpoch
        le32(0)                            // dwFlagsExt
        b += [UInt8](repeating: 0, count: 16)  // ConfigObjGUID
        le32(0xffff_ffff)                  // dwExtCaps
        return b
    }()

    private func readExtensions(_ r: NDRReader) throws -> [UInt8] {
        // DRS_EXTENSIONS { cb DWORD, rgb BYTE_ARRAY }: the conformant array size is hoisted to the
        // front of the struct.
        let maxCount = Int(try r.u32())
        _ = try r.u32()                    // cb
        return try r.take(maxCount)        // rgb
    }

    private func writeExtensions(_ w: NDRWriter, _ rgb: [UInt8]) {
        w.align(4)
        w.u32(UInt32(rgb.count))           // max_count (hoisted)
        w.u32(UInt32(rgb.count))           // cb
        w.raw(rgb)                         // rgb
    }
}

/// Opaque state behind a DRS bind handle (no per-bind replication state is kept for this subset).
struct DRSBindState: Sendable {}
