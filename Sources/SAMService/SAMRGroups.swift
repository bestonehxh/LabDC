import Foundation
import RPCKit
import Store
import MSPAC

extension SAMRService {
    // MARK: - OpenGroup (19) / OpenAlias (27)

    func openGroup(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32()                    // DesiredAccess
        let rid = try r.u32()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            guard let sid = try? dom.sid.appending(rid: rid), let entry = try await directory.read(sid: sid),
                  entry.strings("objectClass").contains(where: { $0.caseInsensitiveCompare("group") == .orderedSame })
            else { throw SAMRError(.noSuchGroup) }
            let h = ctx.handles.allocate(type: SAMRHandleType.group,
                state: GroupState(objectID: entry.id, rid: rid, domainSID: dom.sid, grantedAccess: SAMRAccess.groupAllAccess))
            w.contextHandle(h); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null); w.u32(e.status.rawValue)
        }
        return w
    }

    func openAlias(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32()                    // DesiredAccess
        let rid = try r.u32()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            guard let sid = try? dom.sid.appending(rid: rid), let entry = try await directory.read(sid: sid),
                  entry.strings("objectClass").contains(where: { $0.caseInsensitiveCompare("group") == .orderedSame })
            else { throw SAMRError(.noSuchAlias) }
            let h = ctx.handles.allocate(type: SAMRHandleType.alias,
                state: AliasState(objectID: entry.id, rid: rid, domainSID: dom.sid,
                                  isBuiltin: dom.isBuiltin, grantedAccess: SAMRAccess.aliasAllAccess))
            w.contextHandle(h); w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.contextHandle(.null); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - QueryInformationGroup (20)

    func queryInformationGroup(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let level = try r.u16()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let g = try ctx.groupState(handle)
            guard let entry = try await directory.read(id: g.objectID) else { throw SAMRError(.noSuchGroup) }
            let name = entry.samAccountName ?? entry.string("name") ?? ""
            let members = try await memberRIDs(of: entry, domainSID: g.domainSID)
            guard [1, 2, 3].contains(level) else { throw SAMRError(.invalidInfoClass) }
            _ = w.uniquePointer(true)
            w.deferPointee {
                w.align(4)
                w.u16(level)
                switch level {
                case 1:   // General
                    w.samrUnicodeString(name)
                    w.u32(7)                       // Attributes
                    w.u32(UInt32(members.count))   // MemberCount
                    w.samrUnicodeString(nil)       // AdminComment
                case 2:   // Name
                    w.samrUnicodeString(name)
                case 3:   // Attribute
                    w.u32(7)
                default:
                    break
                }
            }
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - GetMembersInGroup (25)

    func getMembersInGroup(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let g = try ctx.groupState(handle)
            guard let entry = try await directory.read(id: g.objectID) else { throw SAMRError(.noSuchGroup) }
            let rids = try await memberRIDs(of: entry, domainSID: g.domainSID)
            w.samrGetMembersBuffer(rids: rids, attributes: [UInt32](repeating: 7, count: rids.count))
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - QueryInformationAlias (28)

    func queryInformationAlias(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let level = try r.u16()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let a = try ctx.aliasState(handle)
            guard let entry = try await directory.read(id: a.objectID) else { throw SAMRError(.noSuchAlias) }
            let name = entry.samAccountName ?? entry.string("name") ?? ""
            let members = try await memberSIDs(of: entry)
            guard [1, 2, 3].contains(level) else { throw SAMRError(.invalidInfoClass) }
            _ = w.uniquePointer(true)
            w.deferPointee {
                w.align(4)
                w.u16(level)
                switch level {
                case 1:   // General
                    w.samrUnicodeString(name)
                    w.u32(UInt32(members.count))   // MemberCount
                    w.samrUnicodeString(nil)       // AdminComment
                case 2:
                    w.samrUnicodeString(name)
                case 3:
                    w.samrUnicodeString(nil)
                default:
                    break
                }
            }
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - GetMembersInAlias (33)

    func getMembersInAlias(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let a = try ctx.aliasState(handle)
            guard let entry = try await directory.read(id: a.objectID) else { throw SAMRError(.noSuchAlias) }
            let sids = try await memberSIDs(of: entry)
            w.samrSidArrayOut(sids)
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.samrSidArrayOut([]); w.flushDeferred(); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - GetAliasMembership (16)

    func getAliasMembership(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        // SAMPR_PSID_ARRAY: Count, then a pointer to a conformant array of PSAMPR_SID_INFORMATION.
        _ = try r.u32()                    // Count
        let sids = Ref<[SID]>([])
        if try r.pointer() != nil {
            r.deferPointee {
                let maxc = Int(try r.u32())
                var present = 0
                for _ in 0..<maxc { if try r.pointer() != nil { present += 1 } }
                for _ in 0..<present { r.deferPointee { sids.value.append(try r.sid()) } }
            }
        }
        try r.flushDeferred()

        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            var rids = Set<UInt32>()
            for principal in sids.value {
                guard let entry = try await directory.read(sid: principal) else { continue }
                for gsid in try await directory.groupSIDs(of: entry.id) {
                    if gsid.domain == dom.sid, let rid = gsid.rid { rids.insert(rid) }
                }
            }
            w.samrULongArray(rids.sorted())
            w.flushDeferred()
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.samrULongArray([]); w.flushDeferred(); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - member helpers

    /// RIDs of a group/alias's direct members whose SID is in `domainSID`.
    private func memberRIDs(of group: DirectoryEntry, domainSID: SID) async throws -> [UInt32] {
        var rids = [UInt32]()
        for dn in group.strings("member") {
            guard let member = try await directory.read(dn: try DN(string: dn)),
                  let sid = member.sid, sid.domain == domainSID, let rid = sid.rid else { continue }
            rids.append(rid)
        }
        return rids
    }

    /// SIDs of a group/alias's direct members (any domain).
    private func memberSIDs(of group: DirectoryEntry) async throws -> [SID] {
        var sids = [SID]()
        for dn in group.strings("member") {
            if let member = try await directory.read(dn: try DN(string: dn)), let sid = member.sid { sids.append(sid) }
        }
        return sids
    }
}
