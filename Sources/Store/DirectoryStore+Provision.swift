import Foundation
import KerberosCrypto
import MSPAC
import SheepCrypto

extension DirectoryStore {
    /// A well-known domain group created by `provision` (RID, name, groupType, description).
    struct WellKnownGroup {
        var rid: UInt32?
        var name: String
        var groupType: Int32
        var description: String
    }

    static let usersGroups: [WellKnownGroup] = [
        .init(rid: 498, name: "Enterprise Read-only Domain Controllers", groupType: GroupType.universalSecurity,
              description: "Members of this group are Read-Only Domain Controllers in the enterprise"),
        .init(rid: 512, name: "Domain Admins", groupType: GroupType.globalSecurity, description: "Designated administrators of the domain"),
        .init(rid: 513, name: "Domain Users", groupType: GroupType.globalSecurity, description: "All domain users"),
        .init(rid: 514, name: "Domain Guests", groupType: GroupType.globalSecurity, description: "All domain guests"),
        .init(rid: 515, name: "Domain Computers", groupType: GroupType.globalSecurity,
              description: "All workstations and servers joined to the domain"),
        .init(rid: 516, name: "Domain Controllers", groupType: GroupType.globalSecurity, description: "All domain controllers in the domain"),
        .init(rid: 517, name: "Cert Publishers", groupType: GroupType.domainLocalSecurity,
              description: "Members of this group are permitted to publish certificates to the directory"),
        .init(rid: 518, name: "Schema Admins", groupType: GroupType.universalSecurity, description: "Designated administrators of the schema"),
        .init(rid: 519, name: "Enterprise Admins", groupType: GroupType.universalSecurity,
              description: "Designated administrators of the enterprise"),
        .init(rid: 520, name: "Group Policy Creator Owners", groupType: GroupType.globalSecurity,
              description: "Members in this group can modify group policy for the domain"),
        .init(rid: 521, name: "Read-only Domain Controllers", groupType: GroupType.globalSecurity,
              description: "Members of this group are Read-Only Domain Controllers in the domain"),
        .init(rid: 522, name: "Cloneable Domain Controllers", groupType: GroupType.globalSecurity,
              description: "Members of this group that are domain controllers may be cloned."),
        .init(rid: 525, name: "Protected Users", groupType: GroupType.globalSecurity,
              description: "Members of this group are afforded additional protections against authentication security threats"),
        .init(rid: 526, name: "Key Admins", groupType: GroupType.globalSecurity,
              description: "Members of this group can perform administrative actions on key objects within the domain."),
        .init(rid: 527, name: "Enterprise Key Admins", groupType: GroupType.universalSecurity,
              description: "Members of this group can perform administrative actions on key objects within the forest."),
        .init(rid: 553, name: "RAS and IAS Servers", groupType: GroupType.domainLocalSecurity,
              description: "Servers in this group can access remote access properties of users"),
        .init(rid: 571, name: "Allowed RODC Password Replication Group", groupType: GroupType.domainLocalSecurity,
              description: "Members in this group can have their passwords replicated to all read-only domain controllers in the domain"),
        .init(rid: 572, name: "Denied RODC Password Replication Group", groupType: GroupType.domainLocalSecurity,
              description: "Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain"),
        .init(rid: nil, name: "DnsAdmins", groupType: GroupType.domainLocalSecurity, description: "DNS Administrators Group"),
        .init(rid: nil, name: "DnsUpdateProxy", groupType: GroupType.globalSecurity,
              description: "DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers)."),
    ]

    static let builtinGroups: [(UInt32, String)] = [
        (544, "Administrators"), (545, "Users"), (546, "Guests"), (548, "Account Operators"), (549, "Server Operators"),
        (550, "Print Operators"), (551, "Backup Operators"), (552, "Replicator"), (554, "Pre-Windows 2000 Compatible Access"),
        (555, "Remote Desktop Users"), (556, "Network Configuration Operators"), (557, "Incoming Forest Trust Builders"),
        (558, "Performance Monitor Users"), (559, "Performance Log Users"), (560, "Windows Authorization Access Group"),
        (561, "Terminal Server License Servers"), (562, "Distributed COM Users"), (568, "IIS_IUSRS"),
        (569, "Cryptographic Operators"), (573, "Event Log Readers"), (574, "Certificate Service DCOM Access"),
        (575, "RDS Remote Access Servers"), (576, "RDS Endpoint Servers"), (577, "RDS Management Servers"),
        (578, "Hyper-V Administrators"), (579, "Access Control Assistance Operators"), (580, "Remote Management Users"),
        (582, "Storage Replica Administrators"),
    ]

    /// Well-known objects GUIDs (MS-ADTS §6.1.1.4) -> container RDN below the domain.
    static let wellKnownContainers: [(String, String)] = [
        ("A9D1CA15768811D1ADED00C04FD8D5CD", "CN=Users"),
        ("AA312825768811D1ADED00C04FD8D5CD", "CN=Computers"),
        ("AB1D30F3768811D1ADED00C04FD8D5CD", "CN=System"),
        ("A361B2FFFFD211D1AA4B00C04FD7D83A", "OU=Domain Controllers"),
        ("2FBAC1870ADE11D297C400C04FD8D5CD", "CN=Infrastructure"),
        ("18E2EA80684F11D2B9AA00C04F79F805", "CN=Deleted Objects"),
        ("AB8153B7768811D1ADED00C04FD8D5CD", "CN=LostAndFound"),
        ("22B70C67D56E4EFB91E9300FCA3DC1AA", "CN=ForeignSecurityPrincipals"),
        ("09460C08AE1E4A4EA0F64AEE7DAA1E5A", "CN=Program Data"),
        ("F4BE92A4C777485E878E9421D53087DB", "CN=Microsoft,CN=Program Data"),
        ("6227F0AF1FC2410D8E3BB10615BB5B0F", "CN=NTDS Quotas"),
    ]

    /// Creates the domain: the `domain` table, the three naming contexts and the well-known
    /// objects of MS-ADTS §6.1.1 (see docs/notes/wp-f.md for the full list), the Administrator
    /// (RID 500) with `adminPassword`, Guest (501, disabled, no password), krbtgt (502, random
    /// keys), the DC computer account (`DC1$`, first allocated RID, random password, host/ldap/GC
    /// SPNs) and its Configuration-NC server/NTDS Settings objects.
    ///
    /// - Parameters:
    ///   - realm: Kerberos realm (upper-cased).
    ///   - dnsDomain: DNS domain (lower-cased); also the domain NC `DC=` components.
    ///   - netbios: NetBIOS domain name (upper-cased).
    ///   - dcName: host label of this DC (`dc1`); NetBIOS name is the upper-case form.
    ///   - domainSID: fixed domain SID (tests); random `S-1-5-21-x-y-z` otherwise.
    public func provision(realm: String, dnsDomain: String, netbios: String, dcName: String, adminPassword: String,
                          domainSID: SID? = nil, site: String = "Default-First-Site-Name") throws {
        guard cachedInfo == nil, (try db.scalar("SELECT COUNT(*) FROM objects")?.int ?? 0) == 0 else {
            throw StoreError.provisioning("the store is already provisioned")
        }
        let realm = realm.uppercased(), dns = dnsDomain.lowercased(), netbios = netbios.uppercased()
        let dcLabel = dcName.lowercased(), dcNB = dcName.uppercased()
        guard !realm.isEmpty, !dns.isEmpty, !netbios.isEmpty, !dcLabel.isEmpty, !dcLabel.contains(".") else {
            throw StoreError.provisioning("realm, dnsDomain, netbios and a single-label dcName are required")
        }
        let sid = try domainSID ?? SID(identifierAuthority: 5, subAuthorities: [21] + (0..<3).map { _ in
            rng.next(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } & 0x7FFF_FFFF | 0x1000_0000
        })
        do {
            try provisionAll(realm: realm, dns: dns, netbios: netbios, dcLabel: dcLabel, dcNB: dcNB, sid: sid,
                             site: site, adminPassword: adminPassword)
        } catch {
            sdCache = [:]
            try? reloadInfo()
            throw error
        }
        Self.logger.notice("provisioned \(realm, privacy: .public) (\(sid.description, privacy: .public))")
    }

    private func provisionAll(realm: String, dns: String, netbios: String, dcLabel: String, dcNB: String, sid: SID,
                              site: String, adminPassword: String) throws {
        try transaction {
            let domainGUID = GUID.random(rng), dsaGUID = GUID.random(rng), invocation = GUID.random(rng)
            for (k, v) in [("realm", realm), ("dnsDomain", dns), ("netbios", netbios), ("domainSID", sid.description),
                           ("domainGUID", domainGUID.description), ("dcName", dcNB), ("dcDNSName", "\(dcLabel).\(dns)"),
                           ("site", site), ("dsaGUID", dsaGUID.description), ("invocationID", invocation.description),
                           ("nextRID", "1000"), ("relaxPasswordPolicy", "0"), ("provisioned", nowString)] {
                try setDomainValue(v, forKey: k)
            }
            try reloadInfo()
            let info = try domainInfo()
            try provisionDomainNC(info, domainGUID: domainGUID, adminPassword: adminPassword)
            try provisionConfigurationNC(info)
            try provisionSchemaNC(info)
        }
    }

    private func s(_ v: String) -> [[UInt8]] { [Array(v.utf8)] }
    private func s(_ v: [String]) -> [[UInt8]] { v.map { Array($0.utf8) } }

    private func critical(_ extra: [String: [[UInt8]]] = [:]) -> [String: [[UInt8]]] {
        extra.merging(["isCriticalSystemObject": s("TRUE"), "showInAdvancedViewOnly": s("TRUE")]) { a, _ in a }
    }

    @discardableResult
    private func add(_ parent: DN, _ rdn: String, _ cls: String, _ attrs: [String: [[UInt8]]] = [:],
                     sid: SID? = nil, guid: GUID? = nil) throws -> ObjectID {
        try createObject(parent: parent, rdn: try RDN(string: rdn), objectClass: cls, attributes: attrs, sid: sid, guid: guid)
    }

    private func provisionDomainNC(_ info: DomainInfo, domainGUID: GUID, adminPassword: String) throws {
        let d = info.domainDN
        let firstLabel = info.dnsDomain.split(separator: ".").first.map(String.init) ?? info.dnsDomain
        let wko = Self.wellKnownContainers.map { "B:32:\($0.0):\($0.1),\(d)" }
        let domainID = try insertObject(
            parentID: nil, dn: d, objectClass: "domainDNS", guid: domainGUID, sid: info.domainSID.bytes,
            attributes: [("dc", s(firstLabel)), ("instanceType", s("5")), ("minPwdLength", s("7")),
                         ("pwdHistoryLength", s("24")), ("pwdProperties", s("1")), ("maxPwdAge", s("-36288000000000")),
                         ("minPwdAge", s("-864000000000")), ("lockoutThreshold", s("0")),
                         ("lockoutDuration", s("-18000000000")), ("lockOutObservationWindow", s("-18000000000")),
                         ("forceLogoff", s(String(Int64.min))), ("ms-DS-MachineAccountQuota", s("10")),
                         ("msDS-Behavior-Version", s("7")), ("nTMixedDomain", s("0")), ("isCriticalSystemObject", s("TRUE")),
                         ("wellKnownObjects", s(wko)),
                         ("otherWellKnownObjects", s("B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service Accounts,\(d)")),
                         ("fSMORoleOwner", s(info.dsServiceDN.description)),
                         ("rIDManagerReference", s("CN=RID Manager$,CN=System,\(d)")),
                         ("subRefs", s(info.configurationDN.description))])
        _ = domainID

        // Containers.
        let users = try add(d, "CN=Users", "container", critical(["description": s("Default container for upgraded user accounts")]))
        _ = users
        try add(d, "CN=Computers", "container", critical(["description": s("Default container for upgraded computer accounts")]))
        try add(d, "OU=Domain Controllers", "organizationalUnit", critical(["description": s("Default container for domain controllers")]))
        let builtinID = try add(d, "CN=Builtin", "builtinDomain", critical(), sid: try SID(string: "S-1-5-32"))
        _ = builtinID
        let system = d.child(RDN("CN", "System"))
        try add(d, "CN=System", "container", critical(["description": s("Builtin system settings")]))
        try add(system, "CN=Policies", "container", critical())
        try add(system, "CN=RID Manager$", "rIDManager",
                critical(["rIDAvailablePool": s(String(Self.ridPool(next: 1000)))]))
        try add(system, "CN=Password Settings Container", "msDS-PasswordSettingsContainer", critical())
        try add(system, "CN=AdminSDHolder", "container", critical())
        try add(d, "CN=ForeignSecurityPrincipals", "container", critical(["description": s("Default container for security identifiers (SIDs) associated with objects from external, trusted domains")]))
        try add(d, "CN=Managed Service Accounts", "container", critical(["description": s("Default container for managed service accounts")]))
        try add(d, "CN=NTDS Quotas", "msDS-QuotaContainer", critical(["description": s("Quota specifications container")]))
        try add(d, "CN=Program Data", "container", ["description": s("Default location for storage of application data.")])
        try add(d.child(RDN("CN", "Program Data")), "CN=Microsoft", "container", ["description": s("Default location for storage of Microsoft application data.")])
        try add(d, "CN=LostAndFound", "lostAndFound", critical(["description": s("Default container for orphaned objects")]))
        try add(d, "CN=Infrastructure", "infrastructureUpdate", critical(["fSMORoleOwner": s(info.dsServiceDN.description)]))
        try insertDeletedObjectsContainer(parent: d)

        // Builtin groups.
        let builtin = d.child(RDN("CN", "Builtin"))
        var builtinIDs: [UInt32: ObjectID] = [:]
        for (rid, name) in Self.builtinGroups {
            builtinIDs[rid] = try add(builtin, "CN=\(DN.escape(name))", "group",
                                      critical(["groupType": s(String(GroupType.builtinSecurity)), "sAMAccountName": s(name)]),
                                      sid: try SID(string: "S-1-5-32-\(rid)"))
        }

        // Foreign security principals for well-known SIDs used in builtin memberships.
        let fsp = d.child(RDN("CN", "ForeignSecurityPrincipals"))
        var fspIDs: [String: ObjectID] = [:]
        for w in ["S-1-5-4", "S-1-5-9", "S-1-5-11", "S-1-5-17"] {
            fspIDs[w] = try add(fsp, "CN=\(w)", "foreignSecurityPrincipal", ["showInAdvancedViewOnly": s("TRUE")],
                                sid: try SID(string: w))
        }

        // Users container: accounts and groups.
        let usersDN = d.child(RDN("CN", "Users"))
        var groupIDs: [String: ObjectID] = [:]
        func addGroup(_ g: WellKnownGroup) throws {
            let gsid = try g.rid.map { try info.domainSID.appending(rid: $0) }
            var attrs: [String: [[UInt8]]] = ["groupType": s(String(g.groupType)), "description": s(g.description),
                                              "sAMAccountName": s(g.name)]
            if g.rid != nil { attrs = critical(attrs) }
            if [512, 518, 519].contains(g.rid) { attrs["adminCount"] = s("1") }
            groupIDs[g.name] = try add(usersDN, "CN=\(DN.escape(g.name))", "group", attrs, sid: gsid)
        }
        for g in Self.usersGroups where g.rid != nil { try addGroup(g) }
        let admin = try add(usersDN, "CN=Administrator", "user", critical([
            "sAMAccountName": s("Administrator"), "userAccountControl": s(String(UserAccountControl.normalAccount | UserAccountControl.dontExpirePassword)),
            "adminCount": s("1"), "description": s("Built-in account for administering the computer/domain"),
        ]), sid: try info.domainSID.appending(rid: 500))
        let guest = try add(usersDN, "CN=Guest", "user", critical([
            "sAMAccountName": s("Guest"),
            "userAccountControl": s(String(UserAccountControl.normalAccount | UserAccountControl.dontExpirePassword
                | UserAccountControl.accountDisable | UserAccountControl.passwordNotRequired)),
            "primaryGroupID": s("514"), "description": s("Built-in account for guest access to the computer/domain"),
        ]), sid: try info.domainSID.appending(rid: 501))
        let krbtgt = try add(usersDN, "CN=krbtgt", "user", critical([
            "sAMAccountName": s("krbtgt"),
            "userAccountControl": s(String(UserAccountControl.normalAccount | UserAccountControl.accountDisable)),
            "servicePrincipalName": s("kadmin/changepw"), "adminCount": s("1"),
            "description": s("Key Distribution Center Service Account"),
        ]), sid: try info.domainSID.appending(rid: 502))
        // Lab-first: at bootstrap the character mix is advice, not a refusal (`p@ssw0rd` is
        // fine); length and "must not contain the account name" hold for every caller, the
        // wizard and `labdc serve --provision` alike (30 Sep 2026). Complexity/history
        // govern every later change and can be relaxed in Settings ▸ Password policy.
        try Self.checkBootstrapPassword(adminPassword, sam: "Administrator",
                                        minLength: (try? passwordPolicy().minLength) ?? 7)
        try setPassword(id: admin, password: adminPassword, enforcePolicy: false)
        try setRandomKeys(id: krbtgt)

        // DC computer account.
        let dcs = d.child(RDN("OU", "Domain Controllers"))
        let host = info.dcDNSName
        let dcAccount = try add(dcs, "CN=\(info.dcName)", "computer", critical([
            "sAMAccountName": s(info.dcName + "$"),
            "userAccountControl": s(String(UserAccountControl.serverTrustAccount | UserAccountControl.trustedForDelegation)),
            "dNSHostName": s(host), "operatingSystem": s("LabDC"), "operatingSystemVersion": s("1.0"),
            "msDS-SupportedEncryptionTypes": s("28"),
            "servicePrincipalName": s([
                "HOST/\(host)", "HOST/\(info.dcName)", "HOST/\(host)/\(info.dnsDomain)", "HOST/\(host)/\(info.netbiosDomain)",
                "ldap/\(host)", "ldap/\(info.dcName)", "ldap/\(host)/\(info.dnsDomain)", "ldap/\(host)/\(info.netbiosDomain)",
                "ldap/\(host)/ForestDnsZones.\(info.dnsDomain)", "ldap/\(host)/DomainDnsZones.\(info.dnsDomain)",
                "ldap/\(info.dsaGUID)._msdcs.\(info.dnsDomain)",
                "GC/\(host)/\(info.dnsDomain)", "RestrictedKrbHost/\(host)", "RestrictedKrbHost/\(info.dcName)",
                "E3514235-4B06-11D1-AB04-00C04FC2DCD2/\(info.dsaGUID)/\(info.dnsDomain)",
            ] + Self.dnsServicePrincipalNames(info)),  // GSS-TSIG: members ask for DNS/<dc fqdn>
        ]))
        let machinePassword = String(decoding: rng.next(96).map { UInt8(0x21 + Int($0) % 94) }, as: UTF8.self)
        try setPassword(id: dcAccount, password: machinePassword, enforcePolicy: false)
        // Groups without a well-known RID come from the pool after the DC account (RID 1000).
        for g in Self.usersGroups where g.rid == nil { try addGroup(g) }

        // Memberships.
        func member(_ group: ObjectID?, _ m: ObjectID?) throws {
            if let group, let m { try link(group, "member", m) }
        }
        for g in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners"] {
            try member(groupIDs[g], admin)
        }
        try member(builtinIDs[544], admin)
        try member(builtinIDs[544], groupIDs["Domain Admins"])
        try member(builtinIDs[544], groupIDs["Enterprise Admins"])
        try member(builtinIDs[545], groupIDs["Domain Users"])
        try member(builtinIDs[545], fspIDs["S-1-5-4"])
        try member(builtinIDs[545], fspIDs["S-1-5-11"])
        try member(builtinIDs[546], guest)
        try member(builtinIDs[546], groupIDs["Domain Guests"])
        try member(builtinIDs[554], fspIDs["S-1-5-11"])
        try member(builtinIDs[560], fspIDs["S-1-5-9"])
        try member(builtinIDs[568], fspIDs["S-1-5-17"])
        for g in ["Cert Publishers", "Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners",
                  "Domain Controllers", "Read-only Domain Controllers"] {
            try member(groupIDs["Denied RODC Password Replication Group"], groupIDs[g])
        }
        try member(groupIDs["Denied RODC Password Replication Group"], krbtgt)
    }

    private func insertDeletedObjectsContainer(parent: DN) throws {
        let dn = parent.child(RDN("CN", "Deleted Objects"))
        let parentRow = try requireRow(dn: parent)
        _ = try insertObject(parentID: parentRow.id, dn: dn, objectClass: "container",
                             attributes: [("cn", s("Deleted Objects")), ("isDeleted", s("TRUE")),
                                          ("isCriticalSystemObject", s("TRUE")), ("showInAdvancedViewOnly", s("TRUE")),
                                          ("description", s("Default container for deleted objects")), ("systemFlags", s("-1946157056"))],
                             deleted: true)
    }

    private func provisionConfigurationNC(_ info: DomainInfo) throws {
        let c = info.configurationDN
        _ = try insertObject(parentID: nil, dn: c, objectClass: "configuration",
                             attributes: [("cn", s("Configuration")), ("instanceType", s("13"))])
        try insertDeletedObjectsContainer(parent: c)
        let sites = c.child(RDN("CN", "Sites"))
        try add(c, "CN=Sites", "sitesContainer", ["systemFlags": s("33554432")])
        let site = sites.child(RDN("CN", info.site))
        try add(sites, "CN=\(DN.escape(info.site))", "site")
        try add(site, "CN=NTDS Site Settings", "nTDSSiteSettings")
        try add(sites, "CN=Subnets", "subnetContainer")
        try add(sites, "CN=Inter-Site Transports", "container")
        let servers = site.child(RDN("CN", "Servers"))
        try add(site, "CN=Servers", "serversContainer")
        try add(servers, "CN=\(info.dcName)", "server", [
            "dNSHostName": s(info.dcDNSName), "serverReference": s(info.dcComputerDN.description), "systemFlags": s("1375731712"),
        ])
        try add(info.serverDN, "CN=NTDS Settings", "nTDSDSA", [
            "options": s("1"), "invocationId": [info.invocationID.bytes], "msDS-Behavior-Version": s("7"),
            "hasMasterNCs": s([info.domainDN.description, c.description, info.schemaDN.description]),
            "msDS-hasMasterNCs": s([info.domainDN.description, c.description, info.schemaDN.description]),
            "msDS-HasDomainNCs": s(info.domainDN.description), "dMDLocation": s(info.schemaDN.description),
            "systemFlags": s("33554432"),
        ], guid: info.dsaGUID)
        let partitions = c.child(RDN("CN", "Partitions"))
        try add(c, "CN=Partitions", "crossRefContainer", [
            "msDS-Behavior-Version": s("7"), "fSMORoleOwner": s(info.dsServiceDN.description), "systemFlags": s("-2147483648"),
        ])
        try add(partitions, "CN=\(DN.escape(info.netbiosDomain))", "crossRef", [
            "nCName": s(info.domainDN.description), "nETBIOSName": s(info.netbiosDomain), "dnsRoot": s(info.dnsDomain),
            "systemFlags": s("3"),
        ])
        try add(partitions, "CN=Enterprise Configuration", "crossRef", [
            "nCName": s(c.description), "dnsRoot": s(info.dnsDomain), "systemFlags": s("1"),
        ])
        try add(partitions, "CN=Enterprise Schema", "crossRef", [
            "nCName": s(info.schemaDN.description), "dnsRoot": s(info.dnsDomain), "systemFlags": s("1"),
        ])
        let services = c.child(RDN("CN", "Services"))
        try add(c, "CN=Services", "container")
        try add(services, "CN=Windows NT", "container")
        try add(services.child(RDN("CN", "Windows NT")), "CN=Directory Service", "nTDSService", [
            "tombstoneLifetime": s("180"),
        ])
    }

    private func provisionSchemaNC(_ info: DomainInfo) throws {
        let schema = info.schemaDN
        _ = try insertObject(parentID: nil, dn: schema, objectClass: "dMD",
                             attributes: [("cn", s("Schema")), ("instanceType", s("13")), ("objectVersion", s("88")),
                                          ("fSMORoleOwner", s(info.dsServiceDN.description))])
        for a in DirectorySchema.attributes {
            var attrs: [String: [[UInt8]]] = [
                "lDAPDisplayName": s(a.name), "attributeID": s(a.oid), "attributeSyntax": s(a.syntax.attributeSyntaxOID),
                "oMSyntax": s(String(a.syntax.oMSyntax)), "isSingleValued": s(a.singleValued ? "TRUE" : "FALSE"),
                "adminDisplayName": s(a.cn), "showInAdvancedViewOnly": s("TRUE"),
            ]
            if let link = a.linkID { attrs["linkID"] = s(String(link)) }
            try add(schema, "CN=\(DN.escape(a.cn))", "attributeSchema", attrs)
        }
        for c in DirectorySchema.classes {
            var attrs: [String: [[UInt8]]] = [
                "lDAPDisplayName": s(c.name), "governsID": s(c.oid), "objectClassCategory": s(String(c.kind.rawValue)),
                "subClassOf": s(c.superior ?? "top"), "adminDisplayName": s(c.cn), "showInAdvancedViewOnly": s("TRUE"),
                "defaultObjectCategory": s(schema.child(RDN("CN", DirectorySchema.objectClass(c.category)?.cn ?? c.cn)).description),
            ]
            attrs["defaultSecurityDescriptor"] = s(SecurityDescriptor.defaultSDDL(for: c.name))
            try add(schema, "CN=\(DN.escape(c.cn))", "classSchema", attrs)
        }
        try add(schema, "CN=Aggregate", "subSchema", [
            "attributeTypes": s(DirectorySchema.attributes.map(Self.attributeTypeDescription)),
            "objectClasses": s(DirectorySchema.classes.map(Self.objectClassDescription)),
            "showInAdvancedViewOnly": s("TRUE"),
        ])
    }

    /// RFC 4512 §4.1.2 description of a catalog attribute.
    static func attributeTypeDescription(_ a: AttributeDefinition) -> String {
        var s = "( \(a.oid) NAME '\(a.name)' SYNTAX '\(a.syntax.ldapSyntaxOID)'"
        if a.singleValued { s += " SINGLE-VALUE" }
        if a.linkID.map({ $0 % 2 == 1 }) ?? false || readOnlyAttributes.contains(a.name.lowercased()) {
            s += " NO-USER-MODIFICATION"
        }
        return s + " )"
    }

    /// RFC 4512 §4.1.1 description of a catalog class.
    static func objectClassDescription(_ c: ClassDefinition) -> String {
        var s = "( \(c.oid) NAME '\(c.name)'"
        if let sup = c.superior { s += " SUP \(sup)" }
        s += c.kind == .abstract ? " ABSTRACT" : (c.kind == .auxiliary ? " AUXILIARY" : " STRUCTURAL")
        return s + " )"
    }

    /// The provisioning password rule (30 Sep 2026): the domain's minimum length, the 256
    /// maximum, and not containing the account name — without the character-mix rule.
    static func checkBootstrapPassword(_ password: String, sam: String, minLength: Int) throws {
        if password.count < minLength { throw StoreError.passwordPolicy(.tooShort(minimum: minLength)) }
        if password.count > PasswordPolicy.maxLength { throw StoreError.passwordPolicy(.tooLong(maximum: PasswordPolicy.maxLength)) }
        if sam.count >= 3, password.lowercased().contains(sam.lowercased()) {
            throw StoreError.passwordPolicy(.containsAccountName)
        }
    }
}
