import Foundation
import LDAPCore
import MSPAC
import Store

/// The write rights AD's default security descriptors give an account over its own object
/// (the `PS`/SELF ACEs of the `user` and `computer` defaultSecurityDescriptor, MS-ADTS §5.1.3,
/// §3.1.1.5.3.1.1.4), and the rights of Account Operators (S-1-5-32-548).
///
/// Administrators keep full access; everything not listed here stays read-only for everyone else.
enum SelfWriteRights {
    /// Property set `Personal-Information` (77b5b886-944a-11d1-aebd-0000f80367c1): SELF has
    /// RPWP on users and computers.
    static let personalInformation: Set<String> = [
        "assistant", "facsimiletelephonenumber", "homephone", "homepostaladdress", "internationalisdnnumber",
        "ipphone", "mobile", "otherfacsimiletelephonenumber", "otherhomephone", "otheripphone", "othermobile",
        "otherpager", "othertelephone", "pager", "personaltitle", "physicaldeliveryofficename", "postaladdress",
        "postalcode", "postofficebox", "preferreddeliverymethod", "primaryinternationalisdnnumber",
        "primarytelexnumber", "registeredaddress", "street", "streetaddress", "telephonenumber",
        "teletexterminalidentifier", "telexnumber", "thumbnailphoto", "usercert", "usersharedfolder",
        "usersharedfolderother", "usersmimecertificate", "x121address",
    ]

    /// Property set `Web-Information` (e45795b3-9455-11d1-aebd-0000f80367c1).
    static let webInformation: Set<String> = ["wwwhomepage", "url"]

    /// What a computer may write on itself beyond the property sets: the validated writes
    /// (`dNSHostName`/`msDS-AdditionalDnsHostName` via 72e39547-7b18-11d1-adef-00c04fd8d5cd,
    /// `servicePrincipalName` via f3a64788-5306-11d1-a9c5-0000f80367c1) and the attributes
    /// Samba's `net ads join` sets as the machine account (`libnet_join_set_machine_spn`,
    /// `libnet_join_set_machine_enctypes`, `libnet_join_set_os_attributes`,
    /// `libnet_join_set_machine_upn`).
    static let computer: Set<String> = [
        "dnshostname", "msds-additionaldnshostname", "serviceprincipalname", "msds-supportedencryptiontypes",
        "operatingsystem", "operatingsystemversion", "operatingsystemservicepack", "operatingsystemhotfix",
        "userprincipalname",
    ]

    /// Attributes whose values go through a validated-write check.
    static let hostNameAttributes: Set<String> = ["dnshostname", "msds-additionaldnshostname"]

    /// Service classes a validated SPN write may not claim (the KDC resolves these specially).
    static let reservedServiceClasses: Set<String> = ["krbtgt", "kadmin"]

    /// ATTRTYP of the attributes named in constraint diagnostics.
    static let attributeIDs: [String: String] = [
        "dnshostname": "9026b (dNSHostName)", "msds-additionaldnshostname": "906b5 (msDS-AdditionalDnsHostName)",
        "serviceprincipalname": "90303 (servicePrincipalName)", "userprincipalname": "90290 (userPrincipalName)",
    ]

    /// The self-writable attributes (lower case) of an object of class `objectClass`.
    static func allowed(objectClass: String) -> Set<String> {
        let chain = DirectorySchema.classChain(objectClass).map { $0.lowercased() }
        var set = personalInformation.union(webInformation)
        if chain.contains("computer") { set.formUnion(computer) }
        return set
    }

    // MARK: Account Operators

    /// Domain RIDs Account Operators may not touch (AdminSDHolder-protected accounts and groups).
    static let protectedRIDs: Set<UInt32> = [500, 502, 498, 512, 516, 518, 519, 520, 521, 526, 527]
    /// Groups whose (transitive) members are protected.
    static let protectedGroupRIDs: Set<UInt32> = [498, 512, 516, 518, 519, 521, 526, 527]
    static let protectedBuiltinRIDs: Set<UInt32> = [544, 548, 549, 550, 551]
    /// UAC bits Account Operators may not set (DC and delegation flags need more than AO).
    static let privilegedUAC: UInt32 = UserAccountControl.serverTrustAccount | UserAccountControl.partialSecretsAccount
        | UserAccountControl.trustedForDelegation | UserAccountControl.trustedToAuthForDelegation
        | UserAccountControl.interdomainTrustAccount
    /// Attributes Account Operators may not write even on objects they manage.
    static let operatorDenied: Set<String> = [
        "admincount", "msds-allowedtodelegateto", "msds-allowedtoactonbehalfofotheridentity", "ntsecuritydescriptor",
        "issystemcriticalobject", "iscriticalsystemobject", "sidhistory",
    ]
    /// Classes Account Operators create, delete and modify (the `AO` ACEs on OUs and containers).
    static let operatorClasses: Set<String> = ["user", "group", "computer", "inetorgperson"]
}

extension LDAPConnection {
    static let builtinAccountOperators = try? SID(string: "S-1-5-32-548")

    // MARK: Validated writes and self rights

    /// Checks the non-password changes of a modify on the bound account's own object: every
    /// attribute must be self-writable, and the validated writes must hold.
    func checkSelfWrite(_ entry: DirectoryEntry, _ ops: [ModifyOp]) async throws {
        let allowed = SelfWriteRights.allowed(objectClass: entry.objectClass)
        for op in ops where !allowed.contains(op.attribute.lowercased()) {
            server.logger.info("LDAP self-write of \(op.attribute, privacy: .public) on \(entry.dn.description, privacy: .public) refused")
            throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
        }
        guard DirectorySchema.classChain(entry.objectClass).contains(where: { $0.lowercased() == "computer" }) else { return }

        let sam = entry.samAccountName ?? ""
        let computerName = sam.hasSuffix("$") ? String(sam.dropLast()) : sam
        let suffixes = try await allowedDNSSuffixes()

        // 1. Host names (validated write to DNS host name, MS-ADTS §3.1.1.5.3.1.1.2).
        var hostNames = Set([computerName.lowercased()])
        for name in SelfWriteRights.hostNameAttributes {
            hostNames.formUnion(entry.strings(name).map { $0.lowercased() })
        }
        for (name, values) in Self.writtenValues(ops) where SelfWriteRights.hostNameAttributes.contains(name) {
            for value in values {
                let host = value.lowercased()
                guard Self.isValidHostName(host, computerName: computerName, suffixes: suffixes) else {
                    throw validatedWriteFailure(name, "\(value) is not \(computerName).<domain>")
                }
                try await requireUnique(host, filter: .or([.equality(attribute: "dNSHostName", value: Array(host.utf8)),
                                                           .equality(attribute: "msDS-AdditionalDnsHostName", value: Array(host.utf8))]),
                                        entry: entry, attribute: name, code: "0000202F")
                hostNames.insert(host)
            }
        }

        // 2. SPNs (validated write to service principal name, §3.1.1.5.3.1.1.4): the instance
        //    must be one of the object's own names (current or set in this same request).
        for (name, values) in Self.writtenValues(ops) where name == "serviceprincipalname" {
            for value in values {
                guard Self.isValidSPN(value, hostNames: hostNames, domainNames: domainNames()) else {
                    throw validatedWriteFailure(name, "\(value) does not name this computer")
                }
                try await requireUnique(value, filter: .equality(attribute: "servicePrincipalName", value: Array(value.utf8)),
                                        entry: entry, attribute: name, code: "000021C7")
            }
        }

        // 3. userPrincipalName: may not shadow another account's implicit `sam@domain` name.
        for (name, values) in Self.writtenValues(ops) where name == "userprincipalname" {
            for value in values {
                guard let at = value.lastIndex(of: "@"), at != value.startIndex, value.index(after: at) != value.endIndex else {
                    throw validatedWriteFailure(name, "\(value) is not user@suffix")
                }
                let local = String(value[..<at])
                let suffix = value[value.index(after: at)...].lowercased()
                if suffix == info.dnsDomain.lowercased() || suffix == info.realm.lowercased() {
                    for candidate in [local, local + "$"] {
                        if let other = try await store.read(sam: candidate), other.id != entry.id {
                            throw validatedWriteFailure(name, "\(value) is the name of \(other.dn)", code: "000021C8")
                        }
                    }
                }
            }
        }
    }

    /// Lower-cased attribute name to the values an add or replace writes (deletes need no check:
    /// with the validated-write right AD lets the account remove its own values).
    static func writtenValues(_ ops: [ModifyOp]) -> [(String, [String])] {
        ops.compactMap { op in
            switch op {
            case .add(let n, let v), .replace(let n, let v):
                (n.lowercased(), v.map { String(decoding: $0, as: UTF8.self) })
            case .delete, .increment:
                nil
            }
        }
    }

    /// The domain's DNS name plus `msDS-AllowedDNSSuffixes` of the domain object, lower case.
    func allowedDNSSuffixes() async throws -> [String] {
        let extra = try await store.read(dn: info.domainDN)?.strings("msDS-AllowedDNSSuffixes") ?? []
        return [info.dnsDomain.lowercased()] + extra.map { $0.lowercased() }
    }

    func domainNames() -> Set<String> {
        [info.dnsDomain.lowercased(), info.netbiosDomain.lowercased(), info.realm.lowercased()]
    }

    /// `<computer name>.<allowed suffix>`, case-insensitive. The first label may also be a
    /// longer host name whose first 15 characters are the NetBIOS name (Samba and Windows
    /// truncate `sAMAccountName` there).
    static func isValidHostName(_ host: String, computerName: String, suffixes: [String]) -> Bool {
        guard let dot = host.firstIndex(of: "."), !computerName.isEmpty else { return false }
        let label = host[..<dot]
        let suffix = String(host[host.index(after: dot)...])
        guard suffixes.contains(suffix), !label.isEmpty,
              label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return false }
        let name = computerName.lowercased()
        if label == name { return true }
        return name.count == 15 && label.count > 15 && label.hasPrefix(name)
    }

    /// `serviceClass/instance[:port][/serviceName]` whose instance is one of `hostNames` and
    /// whose service name (if any) is an own host name or the domain.
    static func isValidSPN(_ spn: String, hostNames: Set<String>, domainNames: Set<String>) -> Bool {
        let parts = spn.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2 || parts.count == 3, parts.allSatisfy({ !$0.isEmpty && !$0.contains(where: \.isWhitespace) }) else {
            return false
        }
        guard !SelfWriteRights.reservedServiceClasses.contains(parts[0].lowercased()) else { return false }
        var instance = parts[1].lowercased()
        if let colon = instance.lastIndex(of: ":") {
            guard let port = Int(instance[instance.index(after: colon)...]), (1...65535).contains(port) else { return false }
            instance = String(instance[..<colon])
        }
        guard hostNames.contains(instance) else { return false }
        if parts.count == 3 {
            let service = parts[2].lowercased()
            return hostNames.contains(service) || domainNames.contains(service)
        }
        return true
    }

    /// No other live object may hold `value` (SPNs and host names are unique in AD).
    func requireUnique(_ value: String, filter: FilterAST, entry: DirectoryEntry, attribute: String, code: String) async throws {
        let others = try await store.search(base: info.domainDN, scope: .subtree, filter: filter, attrs: ["1.1"], sizeLimit: 2)
        if others.contains(where: { $0.id != entry.id }) {
            throw validatedWriteFailure(attribute, "\(value) is already used by another object", code: code)
        }
    }

    func validatedWriteFailure(_ attribute: String, _ reason: String, code: String = "0000202F") -> LDAPFailure {
        server.logger.info("LDAP validated write of \(attribute, privacy: .public) refused: \(reason, privacy: .public)")
        return LDAPFailure(.constraintViolation, ADDiagnostic.constraint(code: code, attribute: SelfWriteRights.attributeIDs[attribute] ?? attribute))
    }

    // MARK: Machine account quota (ms-DS-MachineAccountQuota)

    /// Whether `entry` is a machine account the bound user created (its `mS-DS-CreatorSID` equals
    /// the bound account's SID). Such an account is self-writable by its creator (WP-AD rights).
    func createdByMe(_ me: BoundIdentity, _ entry: DirectoryEntry) -> Bool {
        guard !me.identity.isAnonymous,
              let raw = entry.values("mS-DS-CreatorSID").first,
              let creator = try? SID(bytes: raw) else { return false }
        return creator == me.identity.sid
    }

    /// Authorises a non-admin, non-Account-Operator user to create a machine account under
    /// `ms-DS-MachineAccountQuota`, as AD and Samba do by default (any authenticated user may add
    /// up to N computer objects). The class must be `computer` and the account a workstation trust
    /// account (never a DC or trust account). Existing computer objects whose `mS-DS-CreatorSID`
    /// is the caller's SID count against the quota; over quota is `insufficientAccessRights`.
    /// Returns the SID to stamp as `mS-DS-CreatorSID`.
    func authorizeMachineAccountCreation(_ me: BoundIdentity, cls: String,
                                         attributes: [String: [[UInt8]]]) async throws -> SID {
        let chain = DirectorySchema.classChain(cls).map { $0.lowercased() }
        guard !me.identity.isAnonymous, chain.contains("computer") else {
            throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
        }
        // The account must be a plain workstation trust account. Absent an explicit
        // userAccountControl the store defaults a computer to WORKSTATION_TRUST_ACCOUNT.
        let uac = machineUAC(attributes)
        guard uac & UserAccountControl.workstationTrustAccount != 0,
              uac & SelfWriteRights.privilegedUAC == 0 else {
            throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
        }
        // A creator may not set privileged or protected attributes on the new account.
        try checkOperatorWrite(attributes.map { ($0.key, $0.value) })

        let sid = me.identity.sid
        let quota = try await machineAccountQuota()
        let used = try await store.count(base: info.domainDN, scope: .subtree,
            filter: .and([.eq("objectClass", "computer"),
                          .equality(attribute: "mS-DS-CreatorSID", value: sid.bytes)]))
        guard used < quota else {
            server.logger.info("LDAP add refused: ms-DS-MachineAccountQuota \(quota) reached for \(me.identity.downLevelName, privacy: .public)")
            throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.machineAccountQuotaExceeded)
        }
        return sid
    }

    /// The effective `userAccountControl` of an add: the value supplied, else the store's computer
    /// default (WORKSTATION_TRUST_ACCOUNT).
    func machineUAC(_ attributes: [String: [[UInt8]]]) -> UInt32 {
        for (name, values) in attributes where name.caseInsensitiveCompare("userAccountControl") == .orderedSame {
            if let text = values.first.map({ String(decoding: $0, as: UTF8.self) }), let v = UInt32(text) { return v }
        }
        return UserAccountControl.workstationTrustAccount
    }

    /// `ms-DS-MachineAccountQuota` from the domain head (provisioned 10). Absent → 0 (no quota).
    func machineAccountQuota() async throws -> Int {
        let v = try await store.read(dn: info.domainDN)?.int("ms-DS-MachineAccountQuota")
        return Int(v ?? 0)
    }

    // MARK: Account Operators

    /// Whether the bound identity may manage `entry` as an Account Operator: a user, group or
    /// computer that is not protected by AdminSDHolder (administrators, DCs, krbtgt, the
    /// privileged groups and their members, builtin groups).
    func operatorManages(_ me: BoundIdentity, _ entry: DirectoryEntry) async throws -> Bool {
        guard me.isAccountOperator else { return false }
        let chain = Set(DirectorySchema.classChain(entry.objectClass).map { $0.lowercased() })
        guard !chain.isDisjoint(with: SelfWriteRights.operatorClasses) else { return false }
        return try await !isProtected(entry)
    }

    /// Full write access to `entry`: an administrator, or an Account Operator on an unprotected
    /// user, group or computer.
    func mayManage(_ me: BoundIdentity, _ entry: DirectoryEntry) async throws -> Bool {
        if me.isAdmin { return true }
        return try await operatorManages(me, entry)
    }

    func isProtected(_ entry: DirectoryEntry) async throws -> Bool {
        if entry.int("adminCount") == 1 { return true }
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & (UserAccountControl.serverTrustAccount | UserAccountControl.partialSecretsAccount) != 0 { return true }
        let domain = info.domainSID
        let builtin = try? SID(string: "S-1-5-32")
        func protected(_ sid: SID) -> Bool {
            guard let rid = sid.rid else { return false }
            if sid.domain == domain { return SelfWriteRights.protectedRIDs.contains(rid) }
            return sid.domain == builtin
        }
        if let sid = entry.sid, protected(sid) { return true }
        for g in try await store.groupSIDs(of: entry.id) {
            guard let rid = g.rid else { continue }
            if g.domain == domain, SelfWriteRights.protectedGroupRIDs.contains(rid) { return true }
            if g.domain == builtin, SelfWriteRights.protectedBuiltinRIDs.contains(rid) { return true }
        }
        return false
    }

    /// The attribute limits of an Account Operator write (add or modify): no privileged UAC
    /// bits, no protected primary group, no delegation or security attributes.
    func checkOperatorWrite(_ attributes: [(String, [[UInt8]])]) throws {
        for (name, values) in attributes {
            let l = name.lowercased()
            if SelfWriteRights.operatorDenied.contains(l) {
                throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
            }
            if l == "useraccountcontrol",
               values.contains(where: { (UInt32(String(decoding: $0, as: UTF8.self)) ?? 0) & SelfWriteRights.privilegedUAC != 0 }) {
                throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
            }
            if l == "primarygroupid",
               values.contains(where: { SelfWriteRights.protectedRIDs.contains(UInt32(String(decoding: $0, as: UTF8.self)) ?? 0) }) {
                throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess)
            }
        }
    }
}

extension ModifyOp {
    /// The values an operation carries (an increment's delta as text).
    var values: [[UInt8]] {
        switch self {
        case .add(_, let v), .delete(_, let v), .replace(_, let v): v
        case .increment(_, let d): [Array(String(d).utf8)]
        }
    }
}
