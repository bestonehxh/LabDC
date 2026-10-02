import Foundation
import os
import RPCKit
import Store
import MSPAC
import AuthKit

/// MS-SAMR (`samr`, `12345778-1234-abcd-ef00-0123456789ac` v1.0) over RPCKit, backed by the
/// directory `Store`. Implements the calls a Windows domain join and `net`/`samrdump` use: connect,
/// enumerate/open the account and BUILTIN domains, look names and RIDs up, create a computer or
/// user account, set its `userAccountControl` and password (levels 16/18/21/23/24/25/26 with the
/// session-key blob cryptography), query users/groups/aliases, and change a user's password.
///
/// SAMR reports business errors in each reply's `ErrorCode` field, never as an RPC fault, so every
/// handler returns a well-formed NDR response; a `SAMRError` thrown inside a handler is turned into
/// the empty/nulled out-parameters plus that status.
public final class SAMRService: RPCInterface, @unchecked Sendable {
    /// The abstract syntax id Windows binds.
    public static let interfaceID = RPCSyntaxID("12345778-1234-abcd-ef00-0123456789ac", 1, 0)
    public var interfaceUUID: DCEUUID { Self.interfaceID.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (1, 0) }

    let directory: DirectoryStore
    let builtinSID = try! SID(string: "S-1-5-32")
    static let logger = Logger(subsystem: "dev.labdc.app", category: "samr")

    /// Wrong old-password counts for SamrUnicodeChangePasswordUser2 (an online password oracle
    /// otherwise). The DC passes Netlogon's tracker so both paths count towards one lockout.
    let badPasswords: BadPasswordTracker
    let lockoutThreshold: Int
    let lockoutWindow: TimeInterval
    let lockoutDuration: TimeInterval
    let clock: @Sendable () -> Date

    public init(directory: DirectoryStore, badPasswords: BadPasswordTracker = BadPasswordTracker(),
                lockoutThreshold: Int = 20, lockoutWindow: TimeInterval = 900, lockoutDuration: TimeInterval = 900,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.directory = directory
        self.badPasswords = badPasswords
        self.lockoutThreshold = lockoutThreshold
        self.lockoutWindow = lockoutWindow
        self.lockoutDuration = lockoutDuration
        self.clock = clock
    }

    /// Opnums an anonymous caller may still use: the password change itself proves the old
    /// password (Windows' "change password" at the logon screen and `smbpasswd -r` make it over a
    /// null session), and the domain password policy it needs.
    static let anonymousOpnums: Set<UInt16> = [SAMROpnum.unicodeChangePasswordUser2,
                                               SAMROpnum.getDomainPasswordInformation]

    /// Null-session SAMR (security audit, 1 Oct 2026): an anonymous identity — a null SMB session,
    /// or an unauthenticated `ncacn_ip_tcp` bind — may not connect, enumerate or look anything up
    /// (RestrictAnonymousSAM). A Netlogon schannel binding at integrity/privacy counts as
    /// authenticated: winbind falls back to schannel over an anonymous SMB session.
    static func refusesAnonymous(_ context: RPCCallContext, opnum: UInt16) -> Bool {
        guard context.identity.isAnonymous, !anonymousOpnums.contains(opnum) else { return false }
        let schannel = context.authType == .schannel
            && (context.authLevel == .pktIntegrity || context.authLevel == .pktPrivacy)
        return !schannel
    }

    public func dispatch(opnum: UInt16, input: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        if Self.refusesAnonymous(context, opnum: opnum) {
            Self.logger.info("SAMR opnum \(opnum) denied to anonymous caller from \(context.clientAddress, privacy: .public)")
            throw RPCError.fault(.accessDenied)
        }
        switch opnum {
        case SAMROpnum.connect:                 return try await connect(input, ctx: context, variant: .connect)
        case SAMROpnum.connect2:                return try await connect(input, ctx: context, variant: .connect2)
        case SAMROpnum.connect4:                return try await connect(input, ctx: context, variant: .connect4)
        case SAMROpnum.connect5:                return try await connect(input, ctx: context, variant: .connect5)
        case SAMROpnum.closeHandle:             return try await closeHandle(input, ctx: context)
        case SAMROpnum.lookupDomainInSamServer: return try await lookupDomain(input, ctx: context)
        case SAMROpnum.enumerateDomains:        return try await enumerateDomains(input, ctx: context)
        case SAMROpnum.openDomain:              return try await openDomain(input, ctx: context)
        case SAMROpnum.queryInformationDomain,
             SAMROpnum.queryInformationDomain2: return try await queryInformationDomain(input, ctx: context)
        case SAMROpnum.enumerateUsers:          return try await enumerateUsers(input, ctx: context)
        case SAMROpnum.enumerateGroups:         return try await enumerateGroupsOrAliases(input, ctx: context, aliases: false)
        case SAMROpnum.enumerateAliases:        return try await enumerateGroupsOrAliases(input, ctx: context, aliases: true)
        case SAMROpnum.lookupNamesInDomain:     return try await lookupNames(input, ctx: context)
        case SAMROpnum.lookupIdsInDomain:       return try await lookupIds(input, ctx: context)
        case SAMROpnum.getAliasMembership:      return try await getAliasMembership(input, ctx: context)
        case SAMROpnum.openGroup:               return try await openGroup(input, ctx: context)
        case SAMROpnum.queryInformationGroup:   return try await queryInformationGroup(input, ctx: context)
        case SAMROpnum.getMembersInGroup:       return try await getMembersInGroup(input, ctx: context)
        case SAMROpnum.openAlias:               return try await openAlias(input, ctx: context)
        case SAMROpnum.queryInformationAlias:   return try await queryInformationAlias(input, ctx: context)
        case SAMROpnum.getMembersInAlias:       return try await getMembersInAlias(input, ctx: context)
        case SAMROpnum.openUser:                return try await openUser(input, ctx: context)
        case SAMROpnum.deleteUser:              return try await deleteUser(input, ctx: context)
        case SAMROpnum.queryInformationUser,
             SAMROpnum.queryInformationUser2:   return try await queryInformationUser(input, ctx: context)
        case SAMROpnum.setInformationUser,
             SAMROpnum.setInformationUser2:     return try await setInformationUser(input, ctx: context)
        case SAMROpnum.changePasswordUser:      return try await changePasswordUser(input, ctx: context)
        case SAMROpnum.unicodeChangePasswordUser2: return try await unicodeChangePasswordUser2(input, ctx: context)
        case SAMROpnum.getGroupsForUser:        return try await getGroupsForUser(input, ctx: context)
        case SAMROpnum.getUserDomainPasswordInfo: return try await getUserDomainPasswordInformation(input, ctx: context)
        case SAMROpnum.getDomainPasswordInformation: return try await getDomainPasswordInformation(input, ctx: context)
        case SAMROpnum.createUser2InDomain:     return try await createUser2(input, ctx: context)
        case SAMROpnum.createUserInDomain:      return try await createUser(input, ctx: context)
        case SAMROpnum.ridToSid:                return try await ridToSid(input, ctx: context)
        case SAMROpnum.validatePassword:        return try validatePassword(input, ctx: context)
        default:
            throw RPCError.fault(.opRangeError)
        }
    }

    // MARK: - Connect (0/57/62/64)

    enum ConnectVariant { case connect, connect2, connect4, connect5 }

    func connect(_ r: NDRReader, ctx: RPCCallContext, variant: ConnectVariant) async throws -> NDRWriter {
        // All variants begin with a server-name pointer we ignore; the trailing fields differ.
        // ServerName is a top-level pointer param: its referent is marshalled inline (read it
        // before the following scalars, per MS-RPCE top-level-pointer rules).
        switch variant {
        case .connect:
            // SamrConnect (opnum 0): ServerName is PSAMPR_SERVER_NAME, a `[handle] wchar_t*` —
            // a unique pointer to a SINGLE `unsigned short`, not a conformant string (MS-SAMR
            // §3.1.5.1.6; confirmed against impacket `SamrConnect`: referent + one WCHAR + pad).
            if try r.pointer() != nil { r.align(2); _ = try r.u16() }
            r.align(4)
            _ = try r.u32()            // DesiredAccess
        case .connect2:
            try r.readWideStringPointerInline(); _ = try r.u32()
        case .connect4:
            try r.readWideStringPointerInline(); _ = try r.u32(); _ = try r.u32()
        case .connect5:
            try r.readWideStringPointerInline()
            _ = try r.u32()            // DesiredAccess
            _ = try r.u32()            // InVersion
            _ = try r.u32()            // InRevisionInfo.tag
            _ = try r.u32()            // V1.Revision
            _ = try r.u32()            // V1.SupportedFeatures
        }

        let handle = ctx.handles.allocate(type: SAMRHandleType.server,
                                          state: ServerState(grantedAccess: SAMRAccess.serverAllAccess))
        let w = NDRWriter()
        if variant == .connect5 {
            w.u32(1)                   // OutVersion
            w.u32(1)                   // OutRevisionInfo.tag = 1
            w.u32(3)                   // V1.Revision = 3
            w.u32(0)                   // V1.SupportedFeatures
        }
        w.contextHandle(handle)
        w.u32(NTStatus.success.rawValue)
        w.flushDeferred()
        return w
    }

    // MARK: - CloseHandle (1)

    func closeHandle(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        ctx.handles.close(handle)
        let w = NDRWriter()
        w.contextHandle(.null)         // [out] nulled handle
        w.u32(NTStatus.success.rawValue)
        return w
    }

    // MARK: - LookupDomainInSamServer (5)

    func lookupDomain(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        _ = try r.contextHandle()
        let nameValue = try r.readUnicodeStringInline()
        let w = NDRWriter()
        do {
            let name = nameValue ?? ""
            let info = try await directory.domainInfo()
            let sid: SID
            if name.caseInsensitiveCompare("Builtin") == .orderedSame {
                sid = builtinSID
            } else if name.caseInsensitiveCompare(info.netbiosDomain) == .orderedSame
                        || name.caseInsensitiveCompare(info.dnsDomain) == .orderedSame {
                sid = info.domainSID
            } else {
                throw SAMRError(.noSuchDomain)
            }
            w.samrSidPointer(sid)
            w.flushDeferred()                          // DomainId param referent (before ErrorCode)
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.samrSidPointer(nil)
            w.flushDeferred()
            w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - EnumerateDomainsInSamServer (6)

    func enumerateDomains(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        _ = try r.contextHandle()
        _ = try r.u32()                // EnumerationContext
        _ = try r.u32()                // PreferedMaximumLength
        let info = try await directory.domainInfo()
        let names = [info.netbiosDomain, "Builtin"]
        let w = NDRWriter()
        w.u32(UInt32(names.count))      // EnumerationContext (return)
        writeRidEnumeration(w, entries: names.map { (rid: UInt32(0), name: $0) })
        w.flushDeferred()               // Buffer param referent (before CountReturned/ErrorCode)
        w.u32(UInt32(names.count))      // CountReturned
        w.u32(NTStatus.success.rawValue)
        return w
    }

    // MARK: - OpenDomain (7)

    func openDomain(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        _ = try r.contextHandle()      // ServerHandle
        _ = try r.u32()                // DesiredAccess
        let sid = try r.sid()          // DomainId (RPC_SID, inline)
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let info = try await directory.domainInfo()
            let isBuiltin: Bool
            if sid == builtinSID { isBuiltin = true }
            else if sid == info.domainSID { isBuiltin = false }
            else { throw SAMRError(.noSuchDomain) }
            let handle = ctx.handles.allocate(type: SAMRHandleType.domain,
                state: DomainState(sid: sid, isBuiltin: isBuiltin, grantedAccess: SAMRAccess.domainAllAccess))
            w.contextHandle(handle)
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null)
            w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - RidToSid (65)

    func ridToSid(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let rid = try r.u32()
        try r.flushDeferred()
        let w = NDRWriter()
        // The object handle may be a domain/user/group/alias handle; derive its domain SID.
        let domainSID = ctx.domainSIDForAnyHandle(handle)
        if let domainSID, let sid = try? domainSID.appending(rid: rid) {
            w.samrSidPointer(sid)
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } else {
            w.samrSidPointer(nil)
            w.flushDeferred()
            w.u32(NTStatus.invalidHandle.rawValue)
        }
        return w
    }

    // MARK: - shared marshalling helpers

    /// Writes a `PSAMPR_ENUMERATION_BUFFER` (a unique pointer to {EntriesRead, RID-enumeration
    /// array}). Used by the four Enumerate* replies.
    func writeRidEnumeration(_ w: NDRWriter, entries: [(rid: UInt32, name: String)]) {
        _ = w.uniquePointer(true)
        w.deferPointee {
            w.u32(UInt32(entries.count))          // EntriesRead
            _ = w.uniquePointer(true)             // Buffer (RID enumeration array)
            w.deferPointee {
                w.u32(UInt32(entries.count))      // conformant MaximumCount
                for e in entries {
                    w.u32(e.rid)
                    w.samrUnicodeString(e.name)
                }
            }
        }
    }
}
