import Foundation
import RPCKit
import MSPAC

/// The fields NETLOGON returns in `NETLOGON_VALIDATION_SAM_INFO2` (level 3) and `_INFO4` (level 6).
/// These share the whole `KERB_VALIDATION_INFO` prefix (MS-PAC §2.5); INFO4 adds LM key, UAC, the
/// interactive-logon counters, extra SIDs, DnsLogonDomainName and Upn (MS-NRPC §2.2.1.4.13).
public struct SamValidationInfo: Sendable {
    public var logonTime: UInt64 = 0
    public var passwordLastSet: UInt64 = 0
    public var effectiveName: String
    public var fullName: String = ""
    public var logonScript: String = ""
    public var profilePath: String = ""
    public var homeDirectory: String = ""
    public var homeDirectoryDrive: String = ""
    public var logonCount: UInt16 = 0
    public var badPasswordCount: UInt16 = 0
    public var userId: UInt32
    public var primaryGroupId: UInt32
    public var groupRIDs: [UInt32]
    public var userFlags: UInt32 = 0
    /// 16 bytes, already sealed with the schannel session key when a channel exists.
    public var userSessionKey: [UInt8]
    public var logonServer: String
    public var logonDomainName: String
    public var logonDomainId: SID
    public var userAccountControl: UInt32 = 0x0000_0010   // USER_NORMAL_ACCOUNT
    public var dnsLogonDomainName: String = ""
    public var upn: String = ""

    public init(effectiveName: String, userId: UInt32, primaryGroupId: UInt32, groupRIDs: [UInt32],
                userSessionKey: [UInt8], logonServer: String, logonDomainName: String, logonDomainId: SID) {
        self.effectiveName = effectiveName
        self.userId = userId
        self.primaryGroupId = primaryGroupId
        self.groupRIDs = groupRIDs
        self.userSessionKey = userSessionKey
        self.logonServer = logonServer
        self.logonDomainName = logonDomainName
        self.logonDomainId = logonDomainId
    }

    static let never: UInt64 = 0x7FFF_FFFF_FFFF_FFFF

    /// The GroupIds actually sent: `primaryGroupId` first, then `groupRIDs` without duplicates,
    /// each with attributes 7 (WP-AO; the PAC's rule, `GroupMembership.accountGroupRIDs`).
    public var wireGroupRIDs: [UInt32] { GroupMembership.accountGroupRIDs(primary: primaryGroupId, rids: groupRIDs) }

    /// Marshals the `NETLOGON_VALIDATION` union (`level` 3 = SAM_INFO2, 6 = SAM_INFO4) into `w`,
    /// including the union discriminant, the arm pointer, the struct, its deferred bodies, and then
    /// the `Authoritative`/`ExtraFlags`/`ErrorCode` trailer that `NetrLogonSamLogonEx` returns.
    func writeSamLogonExResponse(_ w: NDRWriter, level: UInt16, authoritative: Bool, errorCode: UInt32) {
        // NETLOGON_VALIDATION: 16-bit discriminant, then align(4) before the arm pointer.
        w.enum16(level)
        w.align(4)
        NLNDR.writeReferent(w)                     // PNETLOGON_VALIDATION_SAM_INFO*
        writeStruct(w, info4: level == 6)
        w.flushDeferred()
        w.u8(authoritative ? 1 : 0)
        w.u32(0)                                   // ExtraFlags
        w.u32(errorCode)
    }

    /// Marshals just the `NETLOGON_VALIDATION` union + struct + deferred bodies (no trailer), for
    /// `NetrLogonSamLogon`/`WithFlags` which carry a `ReturnAuthenticator` before the validation and
    /// the `Authoritative`/`ErrorCode` after it.
    func writeValidationUnion(_ w: NDRWriter, level: UInt16) {
        w.enum16(level)
        w.align(4)
        NLNDR.writeReferent(w)
        writeStruct(w, info4: level == 6)
        w.flushDeferred()
    }

    private func writeStruct(_ w: NDRWriter, info4: Bool) {
        w.oldLargeInteger(Int64(bitPattern: logonTime))
        w.oldLargeInteger(Int64(bitPattern: Self.never))     // LogoffTime
        w.oldLargeInteger(Int64(bitPattern: Self.never))     // KickOffTime
        w.oldLargeInteger(Int64(bitPattern: passwordLastSet))
        w.oldLargeInteger(0)                                 // PasswordCanChange
        w.oldLargeInteger(Int64(bitPattern: Self.never))     // PasswordMustChange
        NLNDR.writeUnicodeString(w, effectiveName)
        NLNDR.writeUnicodeString(w, fullName)
        NLNDR.writeUnicodeString(w, logonScript)
        NLNDR.writeUnicodeString(w, profilePath)
        NLNDR.writeUnicodeString(w, homeDirectory)
        NLNDR.writeUnicodeString(w, homeDirectoryDrive)
        w.u16(logonCount)
        w.u16(badPasswordCount)
        w.u32(userId)
        w.u32(primaryGroupId)
        let rids = wireGroupRIDs
        w.u32(UInt32(rids.count))
        if rids.isEmpty {
            w.u32(0)                                         // NULL GroupIds
        } else {
            NLNDR.writeReferent(w)
            w.deferPointee {
                w.u32(UInt32(rids.count))                    // conformant MaximumCount
                for rid in rids { w.u32(rid); w.u32(0x0000_0007) }
            }
        }
        w.u32(userFlags)
        w.raw(Array(userSessionKey.prefix(16)) + [UInt8](repeating: 0, count: max(0, 16 - userSessionKey.count)))
        NLNDR.writeUnicodeString(w, logonServer)
        NLNDR.writeUnicodeString(w, logonDomainName)
        let sid = logonDomainId
        NLNDR.writeReferent(w)                               // LogonDomainId PRPC_SID
        w.deferPointee { w.sid(sid) }

        if info4 {
            w.raw([UInt8](repeating: 0, count: 8))           // LMKey
            w.u32(userAccountControl)
            w.u32(0)                                         // SubAuthStatus
            w.oldLargeInteger(0)                             // LastSuccessfulILogon
            w.oldLargeInteger(0)                             // LastFailedILogon
            w.u32(0)                                         // FailedILogonCount
            w.u32(0)                                         // Reserved4
            w.u32(0)                                         // SidCount
            w.u32(0)                                         // ExtraSids NULL
            NLNDR.writeUnicodeString(w, dnsLogonDomainName)
            NLNDR.writeUnicodeString(w, upn)
            for _ in 0..<10 { NLNDR.writeUnicodeString(w, "") }  // ExpansionString1..10
        } else {
            for _ in 0..<10 { w.u32(0) }                     // ExpansionRoom LONG[10]
            w.u32(0)                                         // SidCount
            w.u32(0)                                         // ExtraSids NULL
        }
    }
}
