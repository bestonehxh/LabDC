import Foundation
import RPCKit
import Store
import MSPAC

/// Authorization for the write operations, reusing WP-Q's kpasswd set-password rule: administrators
/// (RID 500, or a transitive member of Domain Admins 512 / Enterprise Admins 519 / BUILTIN
/// Administrators 544) may set any account's password and create accounts; Account Operators
/// (S-1-5-32-548) may do so for accounts that are not protected; a user may always change their own
/// password. Reads/enumerations are open to any authenticated caller (lab posture).
extension SAMRService {
    struct Privileges { let admin: Bool; let accountOperator: Bool }

    static let builtinAdministrators = try! SID(string: "S-1-5-32-544")
    static let accountOperators = try! SID(string: "S-1-5-32-548")
    static let protectedDomainRIDs: Set<UInt32> = [500, 502, 512, 516, 518, 519, 521]
    static let protectedBuiltinRIDs: Set<UInt32> = [544, 548, 549, 550, 551, 552]

    func privileges(_ ctx: RPCCallContext) async throws -> Privileges {
        let info = try await directory.domainInfo()
        // Resolve the caller in the directory for accurate transitive membership; fall back to the
        // group SIDs carried on the token when the caller is not a local account.
        var groups: Set<SID>
        if let caller = try await directory.read(sid: ctx.identity.sid) {
            groups = Set(try await directory.groupSIDs(of: caller.id))
        } else {
            groups = Set(ctx.identity.groups)
        }
        groups.insert(ctx.identity.sid)
        let da = try? info.domainSID.appending(rid: 512)
        let ea = try? info.domainSID.appending(rid: 519)
        let admin500 = try? info.domainSID.appending(rid: 500)
        let admin = (admin500 != nil && ctx.identity.sid == admin500)
            || [da, ea, Self.builtinAdministrators].compactMap { $0 }.contains(where: groups.contains)
        let accountOperator = groups.contains(Self.accountOperators)
        return Privileges(admin: admin, accountOperator: accountOperator)
    }

    /// Throws `accessDenied` unless the caller may set `target`'s password.
    func authorizePasswordSet(_ ctx: RPCCallContext, target: DirectoryEntry) async throws {
        if let tsid = target.sid, tsid == ctx.identity.sid { return }        // own account
        let p = try await privileges(ctx)
        if p.admin { return }
        if p.accountOperator, !(try await isProtected(target)) { return }
        throw SAMRError(.accessDenied)
    }

    /// Throws `accessDenied` unless the caller may create accounts.
    func authorizeCreate(_ ctx: RPCCallContext) async throws {
        let p = try await privileges(ctx)
        guard p.admin || p.accountOperator else { throw SAMRError(.accessDenied) }
    }

    /// Throws `STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED` when `creator` already owns
    /// `ms-DS-MachineAccountQuota` computer objects (counted by `mS-DS-CreatorSID`, as AD and
    /// Samba do). Used to gate machine-account creation by non-privileged callers.
    func enforceMachineAccountQuota(creator sid: SID) async throws {
        let info = try await directory.domainInfo()
        let quota = Int(try await directory.read(dn: info.domainDN)?.int("ms-DS-MachineAccountQuota") ?? 0)
        let used = try await directory.count(base: info.domainDN, scope: .subtree,
            filter: .and([.eq("objectClass", "computer"),
                          .equality(attribute: "mS-DS-CreatorSID", value: sid.bytes)]))
        guard used < quota else { throw SAMRError(.machineAccountQuotaExceeded) }
    }

    func isProtected(_ target: DirectoryEntry) async throws -> Bool {
        let uac = UInt32(truncatingIfNeeded: target.int("userAccountControl") ?? 0)
        if uac & UserAccountControl.serverTrustAccount != 0 { return true }
        let info = try await directory.domainInfo()
        var sids: [SID] = []
        if let s = target.sid { sids.append(s) }
        sids += (try? await directory.groupSIDs(of: target.id)) ?? []
        for sid in sids {
            guard let rid = sid.rid, let parent = sid.domain else { continue }
            if parent == info.domainSID, Self.protectedDomainRIDs.contains(rid) { return true }
            if parent == builtinSID, Self.protectedBuiltinRIDs.contains(rid) { return true }
        }
        return false
    }
}
