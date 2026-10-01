import Foundation
import RPCKit
import Store
import MSPAC
import KerberosCrypto

extension SAMRService {
    // MARK: - OpenUser (34)

    func openUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32()                    // DesiredAccess
        let rid = try r.u32()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            guard let sid = try? dom.sid.appending(rid: rid),
                  let entry = try await directory.read(sid: sid),
                  entry.strings("objectClass").contains(where: { $0.caseInsensitiveCompare("user") == .orderedSame })
            else { throw SAMRError(.noSuchUser) }
            let h = ctx.handles.allocate(type: SAMRHandleType.user,
                state: UserState(objectID: entry.id, rid: rid, domainSID: dom.sid, grantedAccess: SAMRAccess.userAllAccess))
            w.contextHandle(h); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - DeleteUser (35)

    func deleteUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let user = try ctx.userState(handle)
            guard let entry = try await directory.read(id: user.objectID) else { throw SAMRError(.noSuchUser) }
            try await authorizePasswordSet(ctx, target: entry)     // delete requires the same write right
            try await directory.delete(id: user.objectID)
            ctx.handles.close(handle)
            w.contextHandle(.null); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(handle); w.u32(e.status.rawValue)
        } catch {
            w.contextHandle(handle); w.u32(NTStatus.accessDenied.rawValue)
        }
        return w
    }

    // MARK: - QueryInformationUser / 2 (36/47)

    func queryInformationUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let level = try r.u16()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let user = try ctx.userState(handle)
            guard let entry = try await directory.read(id: user.objectID) else { throw SAMRError(.noSuchUser) }
            // SAMR carries ACB flags; the directory stores UF bits (MS-SAMR §3.1.5.14.3, ds_uf2acb).
            let acb = UserAccountControl.toACB(UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0))
            guard [16, 20, 21].contains(level) else { throw SAMRError(.invalidInfoClass) }
            _ = w.uniquePointer(true)          // Buffer
            w.deferPointee {
                w.align(4)                     // referent alignment
                w.u16(level)                   // union tag
                switch level {
                case 16:
                    w.u32(acb)
                case 20:
                    w.samrUnicodeString(nil)   // Parameters
                case 21:
                    self.writeUserAll(w, entry: entry, rid: user.rid, acb: acb)
                default:
                    break
                }
            }
            w.flushDeferred()                  // Buffer param referent
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    /// Marshals `SAMPR_USER_ALL_INFORMATION` (§2.2.7.6) with the populated fields flagged in
    /// `WhichFields`; all strings but the account name are empty and the password blobs absent.
    func writeUserAll(_ w: NDRWriter, entry: DirectoryEntry, rid: UInt32, acb: UInt32) {
        let pwdLastSet = entry.int("pwdLastSet") ?? 0
        let accountExpires = entry.int("accountExpires") ?? Int64.max
        let primaryGroup = UInt32(truncatingIfNeeded: entry.int("primaryGroupID") ?? 513)
        w.oldLargeInteger(0)                                 // LastLogon
        w.oldLargeInteger(0)                                 // LastLogoff
        w.oldLargeInteger(pwdLastSet)                        // PasswordLastSet
        w.oldLargeInteger(accountExpires)                    // AccountExpires
        w.oldLargeInteger(0)                                 // PasswordCanChange
        w.oldLargeInteger(Int64.max)                         // PasswordMustChange (never)
        w.samrUnicodeString(entry.samAccountName)            // UserName
        for _ in 0..<9 { w.samrUnicodeString(nil) }          // FullName..Parameters
        shortBlob(w)                                         // LmOwfPassword
        shortBlob(w)                                         // NtOwfPassword
        w.samrUnicodeString(nil)                             // PrivateData
        w.u32(0); w.u32(0)                                   // SecurityDescriptor {Length, NULL ptr}
        w.u32(rid)                                           // UserId
        w.u32(primaryGroup)                                  // PrimaryGroupId
        w.u32(acb)                                           // UserAccountControl (ACB flags)
        w.u32(UserAllFields.userName | UserAllFields.userId | UserAllFields.primaryGroupId
              | UserAllFields.passwordLastSet | UserAllFields.accountExpires | UserAllFields.userAccountControl)
        w.u32(0); w.u32(0)                                   // LogonHours {UnitsPerWeek, NULL ptr}
        w.u16(0); w.u16(0); w.u16(0); w.u16(0)              // Bad/Logon count, Country, CodePage
        w.u8(0); w.u8(0); w.u8(0); w.u8(0)                  // Lm/Nt present, PasswordExpired, PrivateDataSensitive
    }

    private func shortBlob(_ w: NDRWriter) {
        w.u16(0); w.u16(0); w.u32(0)   // Length, MaximumLength, NULL Buffer pointer
    }

    // MARK: - GetGroupsForUser (39)

    func getGroupsForUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let user = try ctx.userState(handle)
            guard let entry = try await directory.read(id: user.objectID) else { throw SAMRError(.noSuchUser) }
            let info = try await directory.domainInfo()
            var rids = [UInt32(truncatingIfNeeded: entry.int("primaryGroupID") ?? 513)]
            for gid in try await directory.transitiveGroups(of: user.objectID) {
                guard let g = try await directory.read(id: gid), let sid = g.sid,
                      sid.domain == info.domainSID, let rid = sid.rid, !rids.contains(rid) else { continue }
                let gt = Int32(truncatingIfNeeded: g.int("groupType") ?? Int64(GroupType.globalSecurity))
                if gt & (GroupType.resourceGroup | GroupType.builtinLocal) != 0 { continue }
                rids.append(rid)
            }
            w.samrGroupMembershipBuffer(rids, attributes: 7)   // MANDATORY|ENABLED_BY_DEFAULT|ENABLED
            w.flushDeferred()                                  // Groups param referent
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - GetUserDomainPasswordInformation (44)

    func getUserDomainPasswordInformation(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        _ = try r.contextHandle()
        try r.flushDeferred()
        let w = NDRWriter()
        let policy = try await directory.passwordPolicy()
        w.u16(UInt16(policy.minLength))                    // MinPasswordLength
        w.u32(policy.complexity ? 1 : 0)                   // PasswordProperties
        w.u32(NTStatus.success.rawValue)
        return w
    }

    // MARK: - GetDomainPasswordInformation (56)

    /// `SamrGetDomainPasswordInformation` (MS-SAMR §3.1.5.13.3): no handle; the `[in, unique]
    /// PRPC_UNICODE_STRING Unused` server name is ignored. WP-Z: `rpcclient getdompwinfo` and
    /// Samba's password-change paths call it (it faulted `op_rng_error` before).
    func getDomainPasswordInformation(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let w = NDRWriter()
        let policy = try await directory.passwordPolicy()
        w.u16(UInt16(policy.minLength))                    // MinPasswordLength
        w.u32(policy.complexity ? 1 : 0)                   // PasswordProperties (DOMAIN_PASSWORD_COMPLEX)
        w.u32(NTStatus.success.rawValue)
        return w
    }

    // MARK: - ValidatePassword (67) — not supported

    func validatePassword(_ r: NDRReader, ctx: RPCCallContext) throws -> NDRWriter {
        let w = NDRWriter()
        w.u32(0)                                           // NULL OutputArg pointer
        w.u32(NTStatus.notSupported.rawValue)
        return w
    }

    // MARK: - CreateUser2InDomain (50) / CreateUserInDomain (12)

    func createUser2(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let name = try r.readUnicodeStringInline() ?? ""    // top-level param: referent inline
        let accountType = try r.u32()
        _ = try r.u32()                    // DesiredAccess
        let w = NDRWriter()
        do {
            let (h, granted, rid) = try await createAccount(ctx, handle: handle, name: name,
                                                            accountType: accountType)
            w.contextHandle(h); w.u32(granted); w.u32(rid); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null); w.u32(0); w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    func createUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let name = try r.readUnicodeStringInline() ?? ""    // top-level param: referent inline
        _ = try r.u32()                    // DesiredAccess
        let w = NDRWriter()
        do {
            let (h, _, rid) = try await createAccount(ctx, handle: handle, name: name,
                                                      accountType: SAMRAccountType.normalAccount)
            w.contextHandle(h); w.u32(rid); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null); w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    /// The shared create path (MS-SAMR §3.1.5.4.4): a normal user under `CN=Users` or a computer
    /// (workstation/server trust) under `CN=Computers`, created disabled with `PASSWD_NOTREQD`
    /// cleared; the RID comes from the Store's pool. Returns the new handle, granted access and RID.
    private func createAccount(_ ctx: RPCCallContext, handle: RPCKit.ContextHandle, name: String,
                               accountType: UInt32) async throws -> (RPCKit.ContextHandle, UInt32, UInt32) {
        let dom = try ctx.domainState(handle)
        guard !dom.isBuiltin else { throw SAMRError(.invalidParameter) }
        guard !name.isEmpty else { throw SAMRError(.invalidParameter) }

        // AccountType is a SAMR ACB account-type code (MS-SAMR §3.1.5.4.4; Samba `dsdb_add_user`):
        // exactly one of USER_NORMAL / USER_WORKSTATION_TRUST / USER_SERVER_TRUST. Interdomain
        // trust accounts are LSA's (CreateTrustedDomain), as in Samba → STATUS_INVALID_PARAMETER.
        let type = accountType & ACB.accountTypeMask
        guard [ACB.normal, ACB.workstationTrust, ACB.serverTrust].contains(type) else {
            throw SAMRError(.invalidParameter)
        }

        // Authorization: administrators and Account Operators create any of the three account
        // types. Any other authenticated caller may create only a workstation trust account, and
        // only up to ms-DS-MachineAccountQuota (Samba `dsdb_add_user`); the created object is
        // stamped with mS-DS-CreatorSID = the caller's SID, which counts against the quota.
        let priv = try await privileges(ctx)
        var creatorSID: SID?
        if !(priv.admin || priv.accountOperator) {
            guard type == ACB.workstationTrust else { throw SAMRError(.accessDenied) }
            try await enforceMachineAccountQuota(creator: ctx.identity.sid)
            creatorSID = ctx.identity.sid
        }

        if try await directory.read(sam: name) != nil { throw SAMRError(.userExists) }
        let info = try await directory.domainInfo()

        let isComputer = type != ACB.normal
        let objectClass = isComputer ? "computer" : "user"
        let cn = name.hasSuffix("$") ? String(name.dropLast()) : name
        let parent: DN = isComputer ? info.domainDN.child(RDN("CN", "Computers"))
                                    : info.domainDN.child(RDN("CN", "Users"))
        // Stored as UF bits (ds_acb2uf), created disabled: ACB_WSTRUST → 0x1002, ACB_NORMAL → 0x202.
        let uac = UserAccountControl.fromACB(type) | UserAccountControl.accountDisable

        var attributes: [String: [[UInt8]]] = [
            "sAMAccountName": [Array(name.utf8)],
            "userAccountControl": [Array(String(uac).utf8)],
        ]
        if let creatorSID { attributes["mS-DS-CreatorSID"] = [creatorSID.bytes] }

        let id: ObjectID
        do {
            id = try await directory.create(parent: parent, rdn: RDN("CN", cn), objectClass: objectClass,
                                            attributes: attributes)
        } catch let e as StoreError {
            switch e {
            case .entryAlreadyExists, .samAccountNameExists: throw SAMRError(.userExists)
            default: throw SAMRError(.accessDenied)
            }
        }
        guard let entry = try await directory.read(id: id), let rid = entry.sid?.rid else {
            throw SAMRError(.internalError)
        }
        Self.logger.notice("SAMR create \(name, privacy: .public) rid \(rid) uac 0x\(String(uac, radix: 16), privacy: .public)")
        let h = ctx.handles.allocate(type: SAMRHandleType.user,
            state: UserState(objectID: id, rid: rid, domainSID: dom.sid, grantedAccess: SAMRAccess.userAllAccess))
        return (h, SAMRAccess.userAllAccess, rid)
    }
}
