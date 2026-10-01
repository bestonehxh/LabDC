import Foundation
import RPCKit
import Store

/// The `dssetup` interface (MS-DSSP, UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0), which
/// Windows serves on the `\lsarpc` pipe next to LSA: `DsRolerGetPrimaryDomainInformation` (0)
/// levels 1 (basic), 2 (upgrade status) and 3 (operation state). Anything else faults with
/// `nca_op_rng_error`.
///
/// WP-Z: `rpcclient dsroledominfo` binds it on `\lsarpc`; without it the bind failed with
/// "transfer syntax differs". Older winbindd releases also probed it to detect an AD domain.
public struct DSSetupService: RPCInterface {
    public static let uuid = DCEUUID("3919286a-b10c-11d0-9ba8-00c04fd92ef5")

    public enum Opnum {
        public static let getPrimaryDomainInformation: UInt16 = 0
    }

    /// `DSROLE_MACHINE_ROLE` DsRole_RolePrimaryDomainController.
    static let rolePrimaryDC: UInt16 = 5
    /// `DSROLE_PRIMARY_DS_RUNNING | DSROLE_PRIMARY_DOMAIN_GUID_PRESENT` (not mixed mode).
    static let basicFlags: UInt32 = 0x0000_0001 | 0x0100_0000
    /// WERROR `ERROR_INVALID_PARAMETER`.
    static let errorInvalidParameter: UInt32 = 87

    public let store: DirectoryStore

    public init(store: DirectoryStore) { self.store = store }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (0, 0) }

    public func dispatch(opnum: UInt16, input r: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        guard opnum == Opnum.getPrimaryDomainInformation else { throw RPCError.fault(.opRangeError) }
        // DsRolerGetPrimaryDomainInformation([in] handle_t, [in] DSROLE_PRIMARY_DOMAIN_INFO_LEVEL
        //   InfoLevel, [out, switch_is(InfoLevel)] PDSROLER_PRIMARY_DOMAIN_INFORMATION* DomainInfo)
        let level = try r.enum16()
        let w = NDRWriter()
        switch level {
        case 1:
            let info = try await store.domainInfo()
            _ = w.uniquePointer(true)
            w.unionDiscriminant16(level)
            // DSROLER_PRIMARY_DOMAIN_INFO_BASIC
            w.enum16(Self.rolePrimaryDC)                     // MachineRole
            w.align(4)
            w.u32(Self.basicFlags)                           // Flags
            _ = w.uniquePointer(true)                        // DomainNameFlat
            _ = w.uniquePointer(true)                        // DomainNameDns
            _ = w.uniquePointer(true)                        // DomainForestName
            w.guid(DCEUUID(bytes: info.domainGUID.bytes))    // DomainGuid
            for s in [info.netbiosDomain, info.dnsDomain.lowercased(), info.dnsDomain.lowercased()] {
                w.align(4)
                w.varyingWCharBody(s, includeNUL: true)
            }
        case 2:
            _ = w.uniquePointer(true)
            w.unionDiscriminant16(level)
            w.u32(0)                                         // OperationState: not upgrading
            w.enum16(0)                                      // PreviousServerState: unknown
        case 3:
            _ = w.uniquePointer(true)
            w.unionDiscriminant16(level)
            w.enum16(0)                                      // OperationState: idle
        default:
            w.u32(0)                                         // NULL DomainInfo
            w.align(4)
            w.u32(Self.errorInvalidParameter)
            return w
        }
        w.align(4)
        w.u32(0)                                             // WERR_OK
        return w
    }
}
