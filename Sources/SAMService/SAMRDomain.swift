import Foundation
import RPCKit
import Store
import MSPAC

extension SAMRService {
    // MARK: - object listing helpers

    /// Live user-class objects (users and computers) whose SID is in the account domain.
    func accountUsers() async throws -> [DirectoryEntry] {
        let info = try await directory.domainInfo()
        let all = try await directory.search(base: info.domainDN, scope: .subtree,
                                             filter: .equality(attribute: "objectClass", value: Array("user".utf8)))
        return all.filter { $0.sid?.domain == info.domainSID }
    }

    /// Live group-class objects. `builtin` selects the S-1-5-32 domain; otherwise the account domain.
    func groupObjects(builtin: Bool) async throws -> [DirectoryEntry] {
        let info = try await directory.domainInfo()
        let all = try await directory.search(base: info.domainDN, scope: .subtree,
                                             filter: .equality(attribute: "objectClass", value: Array("group".utf8)))
        let wanted = builtin ? builtinSID : info.domainSID
        return all.filter { $0.sid?.domain == wanted }
    }

    /// Splits account-domain groups into "groups" (global/universal) and "aliases" (domain-local).
    func isAlias(_ e: DirectoryEntry) -> Bool {
        let gt = Int32(truncatingIfNeeded: e.int("groupType") ?? Int64(GroupType.globalSecurity))
        return gt & (GroupType.resourceGroup | GroupType.builtinLocal) != 0
    }

    // MARK: - QueryInformationDomain / 2 (8/46)

    func queryInformationDomain(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let level = try r.u16()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            let info = try await directory.domainInfo()
            let domainEntry = try await directory.read(dn: info.domainDN)
            let policy = try await directory.passwordPolicy()
            guard [1, 2, 3, 5, 8, 12, 13].contains(level) else { throw SAMRError(.invalidInfoClass) }

            // Counts for the general level (computed up front; the union body is deferred).
            var userCount = 0, groupCount = 0, aliasCount = 0
            if level == 2 {
                userCount = try await accountUsers().count
                let groups = try await groupObjects(builtin: dom.isBuiltin)
                groupCount = dom.isBuiltin ? 0 : groups.filter { !isAlias($0) }.count
                aliasCount = groups.filter { isAlias($0) }.count
            }

            _ = w.uniquePointer(true)                 // Buffer (PSAMPR_DOMAIN_INFO_BUFFER)
            w.deferPointee {
                w.align(4)                            // referent alignment
                w.u16(level)                          // union tag
                switch level {
                case 1:
                    w.u16(UInt16(policy.minLength))
                    w.u16(UInt16(policy.historyLength))
                    w.u32(policy.complexity ? 1 : 0)
                    w.oldLargeInteger(domainEntry?.int("maxPwdAge") ?? -37_108_517_437_440)
                    w.oldLargeInteger(domainEntry?.int("minPwdAge") ?? 0)
                case 2:
                    w.oldLargeInteger(-9_223_372_036_854_775_808)   // ForceLogoff = never
                    w.samrUnicodeString(nil)                        // OemInformation
                    w.samrUnicodeString(dom.isBuiltin ? "Builtin" : info.netbiosDomain)
                    w.samrUnicodeString(nil)                        // ReplicaSourceNodeName
                    w.oldLargeInteger(0)                            // DomainModifiedCount
                    w.u32(1)                                        // DomainServerState = enabled
                    w.u32(dom.isBuiltin ? 2 : 3)                    // role (primary for account domain)
                    w.u8(0)                                         // UasCompatibilityRequired
                    w.u32(UInt32(userCount))
                    w.u32(UInt32(groupCount))
                    w.u32(UInt32(aliasCount))
                case 3:
                    w.oldLargeInteger(-9_223_372_036_854_775_808)   // ForceLogoff
                case 5:
                    w.samrUnicodeString(dom.isBuiltin ? "Builtin" : info.netbiosDomain)
                case 8:
                    w.oldLargeInteger(0)                            // DomainModifiedCount
                    w.oldLargeInteger(Int64(bitPattern: FileTime(Date()).rawValue))
                case 12:
                    w.i64(domainEntry?.int("lockoutDuration") ?? 0)
                    w.i64(domainEntry?.int("lockOutObservationWindow") ?? 0)
                    w.u16(UInt16(truncatingIfNeeded: domainEntry?.int("lockoutThreshold") ?? 0))
                case 13:
                    w.oldLargeInteger(0)
                    w.oldLargeInteger(Int64(bitPattern: FileTime(Date()).rawValue))
                    w.oldLargeInteger(0)
                default:
                    break
                }
            }
            w.flushDeferred()                          // Buffer param referent (before ErrorCode)
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0)                                   // NULL Buffer pointer
            w.flushDeferred()
            w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - EnumerateUsersInDomain (13)

    func enumerateUsers(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32()                    // EnumerationContext
        let acbFilter = try r.u32()        // UserAccountControl ACB filter
        _ = try r.u32()                    // PreferedMaximumLength
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            var entries: [(rid: UInt32, name: String)] = []
            if !dom.isBuiltin {
                for e in try await accountUsers() {
                    guard let rid = e.sid?.rid, let sam = e.samAccountName else { continue }
                    if acbFilter != 0, !matchesACB(e, filter: acbFilter) { continue }
                    entries.append((rid, sam))
                }
                entries.sort { $0.rid < $1.rid }
            }
            w.u32(UInt32(entries.count))    // EnumerationContext (return)
            writeRidEnumeration(w, entries: entries)
            w.flushDeferred()               // Buffer param referent
            w.u32(UInt32(entries.count))    // CountReturned
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(0); w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    private func matchesACB(_ e: DirectoryEntry, filter: UInt32) -> Bool {
        // Samba `dcesrv_samr_EnumDomainUsers`: the account's ACB flags (ds_uf2acb) & the filter.
        let acb = UserAccountControl.toACB(UInt32(truncatingIfNeeded: e.int("userAccountControl") ?? 0))
        return acb & filter != 0
    }

    // MARK: - EnumerateGroups/Aliases (11/15)

    func enumerateGroupsOrAliases(_ r: NDRReader, ctx: RPCCallContext, aliases: Bool) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32(); _ = try r.u32()
        try r.flushDeferred()
        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            var entries: [(rid: UInt32, name: String)] = []
            for e in try await groupObjects(builtin: dom.isBuiltin) {
                guard let rid = e.sid?.rid, let sam = e.samAccountName ?? e.string("name") else { continue }
                let alias = dom.isBuiltin ? true : isAlias(e)
                if alias == aliases { entries.append((rid, sam)) }
            }
            entries.sort { $0.rid < $1.rid }
            w.u32(UInt32(entries.count))
            writeRidEnumeration(w, entries: entries)
            w.flushDeferred()               // Buffer param referent
            w.u32(UInt32(entries.count))
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(0); w.u32(0); w.u32(0); w.u32(e.status.rawValue)
        }
        return w
    }

    // MARK: - LookupNamesInDomain (17)

    func lookupNames(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let count = Int(try r.u32())
        // Names: RPC_UNICODE_STRING_ARRAY (conformant+varying of RPC_UNICODE_STRING).
        let maxCount = Int(try r.u32())
        let offset = Int(try r.u32())
        let actual = Int(try r.u32())
        guard offset == 0, actual <= maxCount, actual <= 4096 else { throw RPCError.fault(.ndr) }
        var boxes: [Ref<String?>] = []
        for _ in 0..<actual { boxes.append(try r.samrUnicodeString()) }
        try r.flushDeferred()
        _ = count

        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            let domainSID = dom.sid
            var rids = [UInt32](); var uses = [UInt32]()
            var mapped = 0
            for box in boxes {
                let name = box.value ?? ""
                if let (rid, use) = try await resolveName(name, domainSID: domainSID) {
                    rids.append(rid); uses.append(use); mapped += 1
                } else {
                    rids.append(0); uses.append(SIDNameUse.unknown)
                }
            }
            w.samrULongArray(rids); w.flushDeferred()      // RelativeIds param
            w.samrULongArray(uses); w.flushDeferred()      // Use param
            let status: NTStatus = mapped == boxes.count ? .success : (mapped == 0 ? .noneMapped : .someNotMapped)
            w.u32(status.rawValue)
        } catch let e as SAMRError {
            w.samrULongArray([]); w.flushDeferred(); w.samrULongArray([]); w.flushDeferred(); w.u32(e.status.rawValue)
        }
        return w
    }

    private func resolveName(_ name: String, domainSID: SID) async throws -> (UInt32, UInt32)? {
        guard !name.isEmpty else { return nil }
        var found = try await directory.read(sam: name)
        if found == nil { found = try await directory.read(sam: name + "$") }
        guard let entry = found, let sid = entry.sid, sid.domain == domainSID, let rid = sid.rid else { return nil }
        let chain = entry.strings("objectClass")
        let use: UInt32
        if chain.contains(where: { $0.caseInsensitiveCompare("computer") == .orderedSame }) {
            use = SIDNameUse.user
        } else if chain.contains(where: { $0.caseInsensitiveCompare("user") == .orderedSame }) {
            use = SIDNameUse.user
        } else if chain.contains(where: { $0.caseInsensitiveCompare("group") == .orderedSame }) {
            use = isAlias(entry) ? SIDNameUse.alias : SIDNameUse.group
        } else {
            use = SIDNameUse.unknown
        }
        return (rid, use)
    }

    // MARK: - LookupIdsInDomain (18)

    func lookupIds(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        _ = try r.u32()                    // Count
        // RelativeIds is a conformant+varying ULONG array: MaximumCount, Offset, ActualCount, elements.
        let maxCount = Int(try r.u32())
        _ = try r.u32()                    // Offset
        let actual = Int(try r.u32())
        guard actual <= maxCount, maxCount <= 4096 else { throw RPCError.fault(.ndr) }
        var ids = [UInt32]()
        for _ in 0..<actual { ids.append(try r.u32()) }

        let w = NDRWriter()
        do {
            let dom = try ctx.domainState(handle)
            var names = [String?](); var uses = [UInt32](); var mapped = 0
            for rid in ids {
                if let sid = try? dom.sid.appending(rid: rid), let entry = try await directory.read(sid: sid) {
                    names.append(entry.samAccountName ?? entry.string("name") ?? "")
                    let chain = entry.strings("objectClass")
                    if chain.contains(where: { $0.caseInsensitiveCompare("group") == .orderedSame }) {
                        uses.append(isAlias(entry) ? SIDNameUse.alias : SIDNameUse.group)
                    } else { uses.append(SIDNameUse.user) }
                    mapped += 1
                } else {
                    names.append(nil); uses.append(SIDNameUse.unknown)
                }
            }
            w.samrReturnedUStringArray(names); w.flushDeferred()   // Names param
            w.samrULongArray(uses); w.flushDeferred()              // Use param
            let status: NTStatus = mapped == ids.count ? .success : (mapped == 0 ? .noneMapped : .someNotMapped)
            w.u32(status.rawValue)
        } catch let e as SAMRError {
            w.samrReturnedUStringArray([]); w.flushDeferred(); w.samrULongArray([]); w.flushDeferred(); w.u32(e.status.rawValue)
        }
        return w
    }
}
