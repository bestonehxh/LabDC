import Foundation
import LDAPCore
import MSPAC
import Store

extension LDAPConnection {
    // MARK: Passwords (MS-ADTS §3.1.1.3.1.5)

    /// `unicodePwd` values are the UTF-16LE encoding of the password in double quotes.
    static func decodeUnicodePwd(_ value: [UInt8]) throws -> String {
        guard value.count % 2 == 0 else { throw LDAPFailure(.unwillingToPerform, ADDiagnostic.attributeConversion) }
        let units = stride(from: 0, to: value.count, by: 2).map { UInt16(value[$0]) | UInt16(value[$0 + 1]) << 8 }
        let text = String(decoding: units, as: UTF16.self)
        guard text.count >= 2, text.hasPrefix("\""), text.hasSuffix("\"") else {
            throw LDAPFailure(.unwillingToPerform, ADDiagnostic.attributeConversion)
        }
        return String(text.dropFirst().dropLast())
    }

    /// Whether `userPassword` is a password attribute: `dSHeuristics` character 9
    /// (fUserPwdSupport) is `1`. Otherwise it is an ordinary attribute, as in AD.
    func userPasswordIsPassword() async throws -> Bool {
        let dn = info.configurationDN.child(RDN("CN", "Services")).child(RDN("CN", "Windows NT")).child(RDN("CN", "Directory Service"))
        guard let h = try await store.read(dn: dn)?.string("dSHeuristics"), h.count >= 9 else { return false }
        return h[h.index(h.startIndex, offsetBy: 8)] == "1"
    }

    func isPasswordAttribute(_ name: String, userPassword: Bool) -> Bool {
        let l = name.lowercased()
        return l == "unicodepwd" || (userPassword && l == "userpassword")
    }

    func passwordText(_ attribute: String, _ value: [UInt8]) throws -> String {
        attribute.lowercased() == "unicodepwd" ? try Self.decodeUnicodePwd(value) : String(decoding: value, as: UTF8.self)
    }

    /// Checks the new password against the policy before anything is written.
    func checkPolicy(_ entry: DirectoryEntry, _ password: String) async throws {
        // Trust accounts (computers, DCs, inter-domain) carry generated secrets, not user passwords:
        // no length/complexity/history rule applies, as on the SAMR path (WP-U). WP-Z: Samba's
        // `net ads join` re-join sets the random machine password with an LDAP unicodePwd replace
        // (`ads_gen_mod` of an existing account) and got 0000052D CONSTRAINT_ATT_TYPE here.
        if Self.isTrustAccount(entry) { return }
        do {
            try await store.checkPasswordPolicy(id: entry.id, password: password)
        } catch StoreError.passwordPolicy(let v) {
            server.logger.info("LDAP password for \(entry.dn.description, privacy: .public) refused: \(v.description, privacy: .public)")
            throw LDAPFailure(.constraintViolation, ADDiagnostic.passwordPolicy())
        }
    }

    /// A computer, DC or inter-domain trust account (`userAccountControl` trust bits).
    static func isTrustAccount(_ entry: DirectoryEntry) -> Bool {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        let trust = UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount
            | UserAccountControl.interdomainTrustAccount
        return uac & trust != 0
    }

    // MARK: Modify

    func modify(_ message: LDAPMessage, _ request: ModifyRequest) async throws {
        let me = try requireBound()
        if request.object.isEmpty {
            // RootDSE modify operations (schemaUpdateNow, ...): nothing to do for us.
            guard me.isAdmin else { throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess) }
            send(LDAPMessage(messageID: message.messageID, .modifyResponse(.success)))
            return
        }
        let dn = try parseDN(request.object)
        let entry = try await requireEntry(dn)
        let userPassword = try await userPasswordIsPassword()

        var ops: [ModifyOp] = []
        var passwordChanges: [ModifyChange] = []
        for change in request.changes {
            let name = AttributeSelection.baseName(change.modification.type)
            if isPasswordAttribute(name, userPassword: userPassword) {
                passwordChanges.append(change)
                continue
            }
            let values = change.modification.values
            switch change.operation {
            case .add: ops.append(.add(name, values))
            case .delete: ops.append(.delete(name, values))
            case .replace: ops.append(.replace(name, values))
            case .increment:
                guard values.count == 1, let delta = Int64(String(decoding: values[0], as: UTF8.self)) else {
                    throw LDAPFailure(.invalidAttributeSyntax, ADDiagnostic.constraintViolation)
                }
                ops.append(.increment(name, delta))
            }
        }

        let isSelf = entry.id == me.entryID
        // A machine account the bound user created (mS-DS-CreatorSID = its SID) is self-writable
        // by that creator, exactly like its own object (WP-AD): password, host names, SPNs,
        // encryption types, OS attributes and UPN.
        let ownsAsCreator = createdByMe(me, entry)
        let selfLike = isSelf || ownsAsCreator
        // Administrators write anything; Account Operators write unprotected users, groups and
        // computers; everyone else only the self-writable attributes of their own object
        // (their password, the personal and web information, and for a computer its
        // validated host names and SPNs, encryption types, OS attributes and UPN) or of a
        // machine account they created.
        let manages = try await mayManage(me, entry)
        if !manages {
            guard selfLike else {
                server.logger.info("LDAP modify of \(dn.description, privacy: .public) by \(me.identity.downLevelName, privacy: .public) refused")
                throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
            }
            try await checkSelfWrite(entry, ops)
        } else if !me.isAdmin {
            ops = try Self.operatorModifyOps(ops, entry: entry)
            try checkOperatorWrite(ops.map { ($0.attribute, $0.values) })
        }

        var newPassword: String?
        if !passwordChanges.isEmpty {
            guard isConfidential else {
                throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unicodePwdNeedsSecureConnection)
            }
            let shape = passwordChanges.map { ($0.operation, $0.modification.values.count) }
            if shape.count == 1, shape[0] == (.replace, 1) {
                // Reset: needs the reset right (administrators, Account Operators on the
                // accounts they manage, or the creator of a machine account).
                guard manages || ownsAsCreator else { throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess) }
                let c = passwordChanges[0]
                newPassword = try passwordText(c.modification.type, c.modification.values[0])
            } else if shape.count == 2, shape[0] == (.delete, 1), shape[1] == (.add, 1) {
                // Change: delete the current value, add the new one.
                let old = try passwordText(passwordChanges[0].modification.type, passwordChanges[0].modification.values[0])
                try await verifyCurrentPassword(entry, old)
                newPassword = try passwordText(passwordChanges[1].modification.type, passwordChanges[1].modification.values[0])
            } else {
                throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unwillingToPerform)
            }
            try await checkPolicy(entry, newPassword!)
        }

        if !ops.isEmpty {
            let permissive = message.control(LDAPControlOID.permissiveModify) != nil
            try await storeCall(dn) { try await store.update(id: entry.id, ops: ops, permissive: permissive) }
        }
        if let newPassword { try await setPassword(entry, newPassword) }
        send(LDAPMessage(messageID: message.messageID, .modifyResponse(.success)))
    }

    /// Administrators, or Account Operators on an unprotected user, group or computer.
    func requireManages(_ me: BoundIdentity, _ entry: DirectoryEntry) async throws {
        guard try await mayManage(me, entry) else {
            throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
        }
    }

    // MARK: Add

    /// The structural class of an add: the known class with the longest superclass chain
    /// among the `objectClass` values (`top, person, organizationalPerson, user` → `user`).
    static func structuralClass(_ values: [String]) -> String? {
        let known = values.compactMap { DirectorySchema.objectClass($0) }.filter { $0.kind == .structural }
        if let best = known.max(by: { DirectorySchema.classChain($0.name).count < DirectorySchema.classChain($1.name).count }) {
            return best.name
        }
        return values.last { $0.lowercased() != "top" }
    }

    func add(_ message: LDAPMessage, _ request: AddRequest) async throws {
        let me = try requireBound()
        let dn = try parseDN(request.entry)
        guard let rdn = dn.rdn, let parent = dn.parent, !parent.isRoot else {
            throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unwillingToPerform)
        }
        guard try await store.read(dn: parent) != nil else { throw await noSuchObject(dn) }
        let userPassword = try await userPasswordIsPassword()

        var attributes: [String: [[UInt8]]] = [:]
        var classes: [String] = []
        var password: String?
        for a in request.attributes {
            let name = AttributeSelection.baseName(a.type)
            if isPasswordAttribute(name, userPassword: userPassword) {
                guard isConfidential else { throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unicodePwdNeedsSecureConnection) }
                guard a.values.count == 1 else { throw LDAPFailure(.constraintViolation, ADDiagnostic.constraintViolation) }
                password = try passwordText(name, a.values[0])
                continue
            }
            if name.caseInsensitiveCompare("objectClass") == .orderedSame { classes += a.strings }
            if let key = attributes.keys.first(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) {
                attributes[key]! += a.values
            } else {
                attributes[name] = a.values
            }
        }
        guard let cls = Self.structuralClass(classes) else {
            throw LDAPFailure(.objectClassViolation, ADDiagnostic.objectClassViolation)
        }
        // `mS-DS-CreatorSID` is system-managed; never honour a client-supplied value.
        attributes = attributes.filter { $0.key.caseInsensitiveCompare("mS-DS-CreatorSID") != .orderedSame }
        var creatorSID: SID?
        if !me.isAdmin {
            if me.isAccountOperator, SelfWriteRights.operatorClasses.contains(cls.lowercased()) {
                // Account Operators create users, groups and computers (the AO CCDC ACEs); they
                // are not subject to ms-DS-MachineAccountQuota.
                try checkOperatorWrite(attributes.map { ($0.key, $0.value) })
            } else {
                // Any other authenticated user may create computer (machine) accounts up to
                // ms-DS-MachineAccountQuota (Samba / MS-ADTS §6.4). The new object is stamped
                // with mS-DS-CreatorSID = the creator's SID, which the creator then self-writes.
                creatorSID = try await authorizeMachineAccountCreation(me, cls: cls, rdn: rdn, attributes: attributes)
            }
        }
        if let creatorSID {
            attributes["mS-DS-CreatorSID"] = [creatorSID.bytes]
        }
        let id = try await storeCall(parent) {
            try await store.create(parent: parent, rdn: rdn, objectClass: cls, attributes: attributes)
        }
        if let password {
            do {
                guard let entry = try await store.read(id: id) else { throw StoreError.noSuchObject(dn.description) }
                try await checkPolicy(entry, password)
                try await setPassword(entry, password)
            } catch {
                // AD refuses the whole add; undo it (a tombstone remains).
                try? await store.delete(id: id)
                throw error
            }
        }
        server.logger.info("LDAP add \(dn.description, privacy: .public) (\(cls, privacy: .public))")
        send(LDAPMessage(messageID: message.messageID, .addResponse(.success)))
    }

    // MARK: Delete

    func delete(_ message: LDAPMessage, _ text: String) async throws {
        let me = try requireBound()
        let dn = try parseDN(text)
        let entry = try await requireEntry(dn)
        try await requireManages(me, entry)
        let recursive = message.control(LDAPControlOID.treeDelete) != nil
        try await storeCall(dn) { try await store.delete(id: entry.id, recursive: recursive) }
        server.logger.info("LDAP delete \(dn.description, privacy: .public)")
        send(LDAPMessage(messageID: message.messageID, .deleteResponse(.success)))
    }

    // MARK: ModifyDN

    func modifyDN(_ message: LDAPMessage, _ request: ModifyDNRequest) async throws {
        let me = try requireBound()
        let dn = try parseDN(request.entry)
        let entry = try await requireEntry(dn)
        try await requireManages(me, entry)
        let newRDN: RDN
        do { newRDN = try RDN(string: request.newRDN) } catch {
            throw LDAPFailure(.invalidDNSyntax, ADDiagnostic.invalidDN(request.newRDN))
        }
        var newParent: DN?
        if let sup = request.newSuperior {
            let p = try parseDN(sup)
            guard try await store.read(dn: p) != nil else { throw await noSuchObject(p.child(newRDN)) }
            newParent = p
        }
        try await storeCall(dn) { try await store.rename(id: entry.id, newRDN: newRDN, newParent: newParent) }
        server.logger.info("LDAP modDN \(dn.description, privacy: .public) -> \(newRDN.description, privacy: .public)")
        send(LDAPMessage(messageID: message.messageID, .modifyDNResponse(.success)))
    }
}
