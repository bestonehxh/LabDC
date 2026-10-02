import Foundation
import MSPAC

extension DirectoryStore {
    /// Attributes callers may send but the store computes: dropped silently on create.
    static let droppedOnCreate: Set<String> = [
        "distinguishedname", "name", "whencreated", "whenchanged", "usncreated", "usnchanged", "samaccounttype",
        "memberof", "directreports", "managedobjects", "serverreferencebl", "objectcategory", "instancetype",
        "isdeleted",
    ]

    /// Attributes no client may modify.
    static let readOnlyAttributes: Set<String> = [
        "objectguid", "objectsid", "distinguishedname", "name", "whencreated", "whenchanged", "usncreated",
        "usnchanged", "samaccounttype", "objectcategory", "instancetype", "isdeleted", "memberof",
        "directreports", "managedobjects", "serverreferencebl",
    ]

    /// Creates an object below `parent` (AD add semantics for security principals).
    ///
    /// - `user`/`computer`/`group` (and subclasses) get a SID from the RID pool.
    /// - `user` requires `sAMAccountName`; `computer` defaults it to `RDN$` upper case; `group`
    ///   to the RDN value.
    /// - Defaults: `userAccountControl` 0x10200 (users) / 0x1000 (computers), `primaryGroupID`
    ///   513/515/516, `groupType` global security.
    /// - `member`, `manager`, ... become links; `objectClass` values beyond the class chain are
    ///   kept as auxiliary classes; computed attributes are ignored.
    /// - Throws: `entryAlreadyExists`, `samAccountNameExists`, `upnExists`, `noSuchObject`
    ///   (parent or link target), `objectClassViolation`, `constraintViolation`.
    @discardableResult
    public func create(parent: DN, rdn: RDN, objectClass: String,
                       attributes: [String: [[UInt8]]] = [:]) throws -> ObjectID {
        for key in attributes.keys {
            switch key.lowercased() {
            case "objectsid", "objectguid":
                throw StoreError.constraintViolation("\(key) is system-only")
            case "unicodepwd":
                throw StoreError.unwillingToPerform("set unicodePwd with setPassword")
            default: break
            }
        }
        return try createObject(parent: parent, rdn: rdn, objectClass: objectClass, attributes: attributes)
    }

    /// Convenience: attribute values as strings.
    @discardableResult
    public func create(parent: DN, rdn: RDN, objectClass: String, strings: [String: [String]]) throws -> ObjectID {
        try create(parent: parent, rdn: rdn, objectClass: objectClass,
                   attributes: strings.mapValues { $0.map { Array($0.utf8) } })
    }

    /// `create` without the system-only checks; `sid` and `guid` may be forced (provisioning).
    @discardableResult
    func createObject(parent: DN, rdn: RDN, objectClass: String, attributes: [String: [[UInt8]]],
                      sid forcedSID: SID? = nil, guid: GUID? = nil) throws -> ObjectID {
        try transaction {
            let parentRow = try requireRow(dn: parent)
            let dn = parent.child(rdn)
            let cls = DirectorySchema.canonicalClassName(objectClass)
            let chain = DirectorySchema.classChain(cls)
            let isUser = chain.contains("user"), isComputer = chain.contains("computer"), isGroup = chain.contains("group")

            // Merge names case-insensitively, keeping the first spelling.
            var merged: [(String, [[UInt8]])] = []
            for (name, values) in attributes.sorted(by: { $0.key < $1.key }) {
                if let i = merged.firstIndex(where: { $0.0.caseInsensitiveCompare(name) == .orderedSame }) {
                    merged[i].1 += values
                } else {
                    merged.append((name, values))
                }
            }
            func take(_ name: String) -> [[UInt8]]? {
                guard let i = merged.firstIndex(where: { $0.0.caseInsensitiveCompare(name) == .orderedSame }) else { return nil }
                return merged.remove(at: i).1
            }
            func text(_ v: [[UInt8]]?) -> String? { v?.first.map { String(decoding: $0, as: UTF8.self) } }

            var sam = text(take("sAMAccountName"))
            let upn = text(take("userPrincipalName"))
            let pwdLastSet = text(take("pwdLastSet"))
            if isComputer, sam == nil { sam = rdn.value.uppercased() + "$" }
            if isGroup, sam == nil { sam = rdn.value }
            if isUser, sam == nil {
                throw StoreError.objectClassViolation("\(dn): sAMAccountName is required")
            }
            if let sam, sam.isEmpty || sam.count > 256 {
                throw StoreError.constraintViolation("sAMAccountName '\(sam)' is invalid")
            }

            // objectClass: keep values outside the chain as auxiliary classes.
            let aux = (take("objectClass") ?? []).map { String(decoding: $0, as: UTF8.self) }
                .filter { v in !chain.contains { $0.caseInsensitiveCompare(v) == .orderedSame } }
                .filter { $0.caseInsensitiveCompare(cls) != .orderedSame }

            // Links.
            var links: [(String, [[UInt8]])] = []
            for fwd in DirectorySchema.linkPairs.keys {
                if let v = take(fwd) { links.append((fwd, v)) }
            }
            merged.removeAll { Self.droppedOnCreate.contains($0.0.lowercased()) }

            // Naming attribute(s).
            for c in rdn.components where !merged.contains(where: { $0.0.caseInsensitiveCompare(c.type) == .orderedSame }) {
                merged.append((c.type, [Array(c.value.utf8)]))
            }

            // Defaults.
            func setDefault(_ name: String, _ value: String) {
                if !merged.contains(where: { $0.0.caseInsensitiveCompare(name) == .orderedSame }) {
                    merged.append((name, [Array(value.utf8)]))
                }
            }
            if isUser {
                setDefault("userAccountControl", String(Self.defaultUAC(computer: isComputer)))
                let uacText = merged.first { $0.0.caseInsensitiveCompare("userAccountControl") == .orderedSame }?.1.first
                let uac = DirectorySchema.int32Bits(uacText ?? []) ?? 0    // invalid → refused below
                setDefault("primaryGroupID", String(Self.defaultPrimaryGroup(uac: uac, computer: isComputer)))
            }
            if isGroup { setDefault("groupType", String(GroupType.globalSecurity)) }
            for (name, values) in merged where DirectorySchema.isSingleValued(name) && values.count > 1 {
                throw StoreError.constraintViolation("\(name) is single-valued")
            }
            for (name, values) in merged { try Self.validateInt32(name, values) }

            var sid = forcedSID
            if sid == nil, isUser || isGroup {
                let info = try domainInfo()
                sid = try info.domainSID.appending(rid: try allocateRID())
            }
            var stored = merged
            if !aux.isEmpty { stored.append(("objectClass", aux.map { Array($0.utf8) })) }
            let id = try insertObject(parentID: parentRow.id, dn: dn, objectClass: cls, guid: guid, sid: sid?.bytes,
                                      sam: sam, upn: upn, attributes: stored)
            for (fwd, values) in links {
                for v in values { try addLink(source: id, attr: fwd, targetDN: v) }
            }
            if let pwdLastSet { try setPwdLastSet(id, pwdLastSet) }
            return id
        }
    }

    func addLink(source: ObjectID, attr: String, targetDN value: [UInt8], permissive: Bool = false) throws {
        let text = String(decoding: value, as: UTF8.self)
        let dn = try DN(string: text)
        guard let target = try row(dnNorm: dn.normalized), !target.deleted else { throw StoreError.noSuchObject(text) }
        if try db.scalar("SELECT 1 FROM links WHERE source_id = ? AND attr = ? AND target_id = ?",
                         [.int(source), .text(attr), .int(target.id)]) != nil {
            if permissive { return }
            throw StoreError.attributeOrValueExists("\(attr): \(text)")
        }
        try db.run("INSERT INTO links(source_id, attr, target_id) VALUES(?, ?, ?)", [.int(source), .text(attr), .int(target.id)])
    }

    /// Adds `member` links directly (provisioning, tests).
    func link(_ source: ObjectID, _ attr: String, _ target: ObjectID) throws {
        try db.run("INSERT OR IGNORE INTO links(source_id, attr, target_id) VALUES(?, ?, ?)",
                   [.int(source), .text(attr), .int(target)])
    }

    func setPwdLastSet(_ id: ObjectID, _ text: String) throws {
        guard let v = Int64(text.trimmingSpaces) else { throw StoreError.constraintViolation("pwdLastSet '\(text)'") }
        // AD: 0 forces a change at next logon, -1 means "now".
        let value: Int64
        switch v {
        case 0: value = 0
        case -1: value = Int64(FileTime(clock()).rawValue)
        default: throw StoreError.unwillingToPerform("pwdLastSet may only be set to 0 or -1")
        }
        try db.run("""
            INSERT INTO secrets(object_id, pwd_last_set) VALUES(?, ?)
            ON CONFLICT(object_id) DO UPDATE SET pwd_last_set = excluded.pwd_last_set
            """, [.int(id), .text(String(value))])
    }

    // MARK: - Modify

    /// Applies `ops` atomically (RFC 4511 §4.6 semantics). `member` and the other forward links
    /// maintain their back links; `sAMAccountName`/`userPrincipalName` keep their unique
    /// columns; `pwdLastSet` accepts 0 and -1. With `permissive` (the AD permissive-modify
    /// control), adding an existing value or deleting a missing one is not an error.
    public func update(id: ObjectID, ops: [ModifyOp], permissive: Bool = false) throws {
        try transaction {
            let row = try requireRow(id: id)
            let rdnTypes = Set((try? DN(string: row.dn))?.rdn?.components.map { $0.type.lowercased() } ?? [row.rdnAttr.lowercased()])
            for op in ops {
                let name = DirectoryStore.canonicalName(op.attribute)
                let l = name.lowercased()
                if Self.readOnlyAttributes.contains(l) { throw StoreError.constraintViolation("\(name) is read-only") }
                if l == "unicodepwd" { throw StoreError.unwillingToPerform("set unicodePwd with setPassword") }
                if rdnTypes.contains(l) { throw StoreError.notAllowedOnRDN("\(name): use rename") }
                switch l {
                case "samaccountname": try modifyColumn(row, op, column: "sam_account_name", permissive: permissive)
                case "userprincipalname": try modifyColumn(row, op, column: "upn", permissive: permissive)
                case "pwdlastset":
                    guard case .replace(_, let values) = op, let v = values.first, values.count == 1 else {
                        throw StoreError.unwillingToPerform("pwdLastSet only supports replace with one value")
                    }
                    try setPwdLastSet(id, String(decoding: v, as: UTF8.self))
                case "objectclass": try modifyObjectClass(row, op)
                default:
                    if let fwd = DirectorySchema.forwardLink(l) {
                        try modifyLinks(id, fwd, op, permissive: permissive)
                    } else {
                        try modifyStored(id, name, op, permissive: permissive)
                    }
                }
            }
            try touch(id)
        }
    }

    /// INTEGER-syntax (2.5.5.9) attributes hold 32 bits (`userAccountControl`, `primaryGroupID`,
    /// `groupType`, `sAMAccountType`, `msDS-SupportedEncryptionTypes`, ...): every value must be
    /// the decimal text of a signed or unsigned 32-bit number (`DirectorySchema.int32Bits`).
    /// A wider value would read as one thing to a range-checking parser and another to the
    /// readers that truncate to 32 bits, so no caller may store one.
    static func validateInt32(_ name: String, _ values: [[UInt8]]) throws {
        guard DirectorySchema.syntax(of: name) == .integer else { return }
        if let bad = values.first(where: { DirectorySchema.int32Bits($0) == nil }) {
            throw StoreError.invalidAttributeSyntax("\(name): '\(String(decoding: bad, as: UTF8.self))' is not a 32-bit integer")
        }
    }

    private func matchKey(_ name: String, _ v: [UInt8]) -> [UInt8] {
        DirectorySchema.matchKey(v, syntax: DirectorySchema.syntax(of: name)) ?? v
    }

    private func modifyStored(_ id: ObjectID, _ name: String, _ op: ModifyOp, permissive: Bool) throws {
        var current = try storedValues(id, name)
        switch op {
        case .add(_, let values):
            guard !values.isEmpty else { throw StoreError.constraintViolation("add of \(name) without values") }
            for v in values {
                if current.contains(where: { matchKey(name, $0) == matchKey(name, v) }) {
                    if permissive { continue }
                    throw StoreError.attributeOrValueExists(name)
                }
                current.append(v)
            }
        case .delete(_, let values):
            if values.isEmpty {
                if current.isEmpty && !permissive { throw StoreError.noSuchAttribute(name) }
                current = []
            } else {
                for v in values {
                    guard let i = current.firstIndex(where: { matchKey(name, $0) == matchKey(name, v) }) else {
                        if permissive { continue }
                        throw StoreError.noSuchAttribute("\(name): value not present")
                    }
                    current.remove(at: i)
                }
            }
        case .replace(_, let values):
            current = values
        case .increment(_, let delta):
            guard current.count == 1, let v = Int64(String(decoding: current[0], as: UTF8.self)) else {
                throw StoreError.constraintViolation("increment of \(name) needs one integer value")
            }
            current = [Array(String(v &+ delta).utf8)]
        }
        if DirectorySchema.isSingleValued(name) && current.count > 1 {
            throw StoreError.constraintViolation("\(name) is single-valued")
        }
        try Self.validateInt32(name, current)
        let syntax = DirectorySchema.syntax(of: name)
        if syntax.isInteger || syntax == .boolean, current.contains(where: { DirectorySchema.matchKey($0, syntax: syntax) == nil }) {
            throw StoreError.constraintViolation("\(name): invalid \(syntax) value")
        }
        try replaceStored(id, name, current)
    }

    private func modifyColumn(_ row: ObjectRow, _ op: ModifyOp, column: String, permissive: Bool) throws {
        let current = column == "upn" ? row.upn : row.sam
        var new: String? = current
        switch op {
        case .add(_, let values):
            guard values.count == 1 else { throw StoreError.constraintViolation("\(column) is single-valued") }
            if current != nil {
                if permissive { return }
                throw StoreError.attributeOrValueExists(column)
            }
            new = String(decoding: values[0], as: UTF8.self)
        case .replace(_, let values):
            guard values.count <= 1 else { throw StoreError.constraintViolation("\(column) is single-valued") }
            new = values.first.map { String(decoding: $0, as: UTF8.self) }
        case .delete(_, let values):
            if current == nil {
                if permissive { return }
                throw StoreError.noSuchAttribute(column)
            }
            if let v = values.first, String(decoding: v, as: UTF8.self).lowercased() != current!.lowercased() {
                if permissive { return }
                throw StoreError.noSuchAttribute(column)
            }
            new = nil
        case .increment:
            throw StoreError.constraintViolation("\(column) is not an integer")
        }
        if column == "sam_account_name", new == nil, DirectorySchema.classChain(row.objectClass).contains("user")
            || DirectorySchema.classChain(row.objectClass).contains("group") {
            throw StoreError.objectClassViolation("sAMAccountName is required")
        }
        if let new, new.caseInsensitiveCompare(current ?? "") != .orderedSame,
           try db.scalar("SELECT id FROM objects WHERE \(column) = ? AND id <> ?", [.text(new), .int(row.id)]) != nil {
            throw column == "upn" ? StoreError.upnExists(new) : StoreError.samAccountNameExists(new)
        }
        try db.run("UPDATE objects SET \(column) = ? WHERE id = ?", [.optional(new), .int(row.id)])
    }

    private func modifyObjectClass(_ row: ObjectRow, _ op: ModifyOp) throws {
        let chain = DirectorySchema.classChain(row.objectClass)
        let values: [[UInt8]]
        switch op {
        case .add(_, let v), .delete(_, let v): values = v
        case .replace, .increment:
            throw StoreError.objectClassViolation("the structural class cannot be replaced")
        }
        let texts = values.map { String(decoding: $0, as: UTF8.self) }
        if texts.contains(where: { t in chain.contains { $0.caseInsensitiveCompare(t) == .orderedSame } }) {
            if case .delete = op { throw StoreError.objectClassViolation("cannot remove a structural class") }
            return  // adding a class already in the chain is a no-op
        }
        try modifyStored(row.id, "objectClass", op, permissive: false)
    }

    private func modifyLinks(_ id: ObjectID, _ attr: String, _ op: ModifyOp, permissive: Bool) throws {
        func targetID(_ v: [UInt8]) throws -> ObjectID? {
            let dn = try DN(string: String(decoding: v, as: UTF8.self))
            return try row(dnNorm: dn.normalized).map(\.id)
        }
        switch op {
        case .add(_, let values):
            for v in values { try addLink(source: id, attr: attr, targetDN: v, permissive: permissive) }
        case .delete(_, let values):
            if values.isEmpty {
                try db.run("DELETE FROM links WHERE source_id = ? AND attr = ?", [.int(id), .text(attr)])
                return
            }
            for v in values {
                guard let t = try targetID(v) else {
                    if permissive { continue }
                    throw StoreError.noSuchAttribute("\(attr): \(String(decoding: v, as: UTF8.self))")
                }
                try db.run("DELETE FROM links WHERE source_id = ? AND attr = ? AND target_id = ?", [.int(id), .text(attr), .int(t)])
                if db.changes == 0 && !permissive {
                    throw StoreError.noSuchAttribute("\(attr): \(String(decoding: v, as: UTF8.self))")
                }
            }
        case .replace(_, let values):
            try db.run("DELETE FROM links WHERE source_id = ? AND attr = ?", [.int(id), .text(attr)])
            for v in values { try addLink(source: id, attr: attr, targetDN: v, permissive: true) }
        case .increment:
            throw StoreError.constraintViolation("\(attr) is not an integer")
        }
        if DirectorySchema.isSingleValued(attr),
           (try db.scalar("SELECT COUNT(*) FROM links WHERE source_id = ? AND attr = ?", [.int(id), .text(attr)])?.int ?? 0) > 1 {
            throw StoreError.constraintViolation("\(attr) is single-valued")
        }
    }

    // MARK: - Rename / move

    /// Renames and/or moves an object (LDAP ModifyDN). The naming attribute is updated to the
    /// new RDN value; DNs of every descendant follow.
    public func rename(id: ObjectID, newRDN: RDN, newParent: DN? = nil) throws {
        try transaction {
            let row = try requireRow(id: id)
            guard let oldParentID = row.parentID else { throw StoreError.unwillingToPerform("cannot rename a naming context head") }
            var parentRow = try requireRow(id: oldParentID)
            if let newParent { parentRow = try requireRow(dn: newParent) }
            // Refuse moving an object below itself.
            var cursor: ObjectID? = parentRow.id
            while let c = cursor {
                if c == id { throw StoreError.unwillingToPerform("cannot move an object below itself") }
                cursor = try self.row(id: c)?.parentID
            }
            let newDN = parentRow.parsedDN.child(newRDN)
            if let existing = try self.row(dnNorm: newDN.normalized), existing.id != id {
                throw StoreError.entryAlreadyExists(newDN.description)
            }
            let oldRDN = row.parsedDN.rdn
            try db.run("UPDATE objects SET parent_id = ?, rdn_attr = ?, rdn_value = ?, dn = ?, dn_norm = ? WHERE id = ?",
                       [.int(parentRow.id), .text(newRDN.type), .text(newRDN.value), .text(newDN.description),
                        .text(newDN.normalized), .int(id)])
            if let oldRDN {
                for c in oldRDN.components where !newRDN.components.contains(where: { $0.type.caseInsensitiveCompare(c.type) == .orderedSame }) {
                    try removeStored(id, c.type)
                }
            }
            for c in newRDN.components { try replaceStored(id, c.type, [Array(c.value.utf8)]) }
            try touch(id)
            try refreshDescendantDNs(of: id, dn: newDN)
        }
    }

    private func refreshDescendantDNs(of id: ObjectID, dn: DN) throws {
        for child in try rows(where: "o.parent_id = ?", [.int(id)]) {
            guard let rdn = child.parsedDN.rdn else { continue }
            let childDN = dn.child(rdn)
            try db.run("UPDATE objects SET dn = ?, dn_norm = ? WHERE id = ?",
                       [.text(childDN.description), .text(childDN.normalized), .int(child.id)])
            try refreshDescendantDNs(of: child.id, dn: childDN)
        }
    }

    // MARK: - Delete (tombstone)

    /// Attributes a tombstone keeps (MS-ADTS §3.1.1.5.5.1.1, abridged).
    static let tombstoneKeeps: Set<String> = [
        "samaccountname", "grouptype", "useraccountcontrol", "dnshostname", "systemflags", "instancetype",
        "objectclass", "ntsecuritydescriptor", "sidhistory", "flatname", "trustpartner", "lastknownparent",
        "msds-lastknownrdn", "isdeleted",
    ]

    /// Tombstones an object: `isDeleted: TRUE`, RDN `name\0ADEL:<guid>`, moved under
    /// `CN=Deleted Objects` of its naming context, links and secrets dropped, most attributes
    /// stripped. With `recursive` (tree delete) children are tombstoned first; otherwise an
    /// object with live children is `notAllowedOnNonLeaf`.
    public func delete(id: ObjectID, recursive: Bool = false) throws {
        try transaction {
            let row = try requireRow(id: id)
            guard row.parentID != nil else { throw StoreError.unwillingToPerform("cannot delete a naming context head") }
            let critical = try storedValues(id, "isCriticalSystemObject").first.map { String(decoding: $0, as: UTF8.self).uppercased() == "TRUE" } ?? false
            if critical { throw StoreError.unwillingToPerform("\(row.dn) is a critical system object") }
            let kids = try rows(where: "o.parent_id = ? AND o.deleted = 0", [.int(id)])
            if !kids.isEmpty {
                guard recursive else { throw StoreError.notAllowedOnNonLeaf(row.dn) }
                for k in kids { try delete(id: k.id, recursive: true) }
            }
            // Find the NC head and its Deleted Objects container.
            var head = row
            while let p = head.parentID, let pr = try self.row(id: p) { head = pr }
            let deletedContainerDN = head.parsedDN.child(RDN("CN", "Deleted Objects"))
            guard let container = try self.row(dnNorm: deletedContainerDN.normalized) else {
                throw StoreError.unwillingToPerform("no \(deletedContainerDN)")
            }
            let parentDN = try requireRow(id: row.parentID!, includeDeleted: true).dn
            let newRDN = RDN(row.rdnAttr, "\(row.rdnValue)\nDEL:\(row.guid)")
            let newDN = deletedContainerDN.child(newRDN)

            // Strip attributes and links.
            let keep = Self.tombstoneKeeps.map { "'\($0)'" }.joined(separator: ",")
            try db.run("DELETE FROM attributes WHERE object_id = ? AND lower(name) NOT IN (\(keep))", [.int(id)])
            try db.run("DELETE FROM links WHERE source_id = ? OR target_id = ?", [.int(id), .int(id)])
            try db.run("DELETE FROM secrets WHERE object_id = ?", [.int(id)])
            if let sam = row.sam { try replaceStored(id, "sAMAccountName", [Array(sam.utf8)]) }
            try replaceStored(id, "isDeleted", [Array("TRUE".utf8)])
            try replaceStored(id, "lastKnownParent", [Array(parentDN.utf8)])
            try replaceStored(id, "msDS-LastKnownRDN", [Array(row.rdnValue.utf8)])
            try replaceStored(id, row.rdnAttr, [Array(newRDN.value.utf8)])
            try db.run("""
                UPDATE objects SET deleted = 1, parent_id = ?, rdn_value = ?, dn = ?, dn_norm = ?,
                  sam_account_name = NULL, upn = NULL WHERE id = ?
                """, [.int(container.id), .text(newRDN.value), .text(newDN.description), .text(newDN.normalized), .int(id)])
            try touch(id)
        }
    }

    /// Default tombstone lifetime (`tombstoneLifetime` on CN=Directory Service): 180 days.
    public static let tombstoneLifetime: TimeInterval = 180 * 24 * 3600

    /// Removes tombstones older than `lifetime` for good. Returns how many were purged.
    @discardableResult
    public func purgeTombstones(olderThan lifetime: TimeInterval = DirectoryStore.tombstoneLifetime) throws -> Int {
        try transaction {
            let cutoff = GeneralizedTime.string(clock().addingTimeInterval(-lifetime))
            let victims = try db.query("""
                SELECT o.id FROM objects o JOIN objects p ON p.id = o.parent_id
                WHERE o.deleted = 1 AND p.deleted = 1 AND lower(p.rdn_value) = 'deleted objects' AND o.when_changed < ?
                """, [.text(cutoff)]).compactMap { $0[0].int }
            for v in victims { try db.run("DELETE FROM objects WHERE id = ?", [.int(v)]) }
            return victims.count
        }
    }
}
