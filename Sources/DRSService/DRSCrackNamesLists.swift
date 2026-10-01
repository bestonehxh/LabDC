import Foundation
import RPCKit
import Store

/// The list-style `DsCrackNames` formats (MS-DRSR §4.1.4.2.1 CrackNames). LabDC is a single-DC,
/// single-domain forest: one site, one server, one nTDSDSA holding every FSMO role and the GC. The
/// answers are read from the provisioned Configuration NC (`CN=Sites`, `CN=Partitions`), so they
/// stay right if the site or DC is renamed at provision time.
extension DRSService {
    private func sitesDN(_ info: DomainInfo) -> DN { info.configurationDN.child(RDN("CN", "Sites")) }
    private func partitionsDN(_ info: DomainInfo) -> DN { info.configurationDN.child(RDN("CN", "Partitions")) }

    /// Live entries of `objectClass` (any value in the class chain) at or below `base`.
    private func objects(_ objectClass: String, under base: DN, scope: SearchScope = .subtree) async throws -> [DirectoryEntry] {
        guard (try await store.read(dn: base)) != nil else { return [] }
        return try await store.search(base: base, scope: scope, filter: .everything, attrs: nil).filter { e in
            e.objectClass.caseInsensitiveCompare(objectClass) == .orderedSame
                || e.strings("objectClass").contains { $0.caseInsensitiveCompare(objectClass) == .orderedSame }
        }
    }

    private static func dnItem(_ dn: DN, domain: String? = nil) -> CrackItem {
        CrackItem(.ok, domain: domain, name: dn.description)
    }

    /// The site DN a caller passed (names[index]); nil when absent or not a DN.
    private static func dnArgument(_ names: [String], _ index: Int) -> DN? {
        guard names.count > index else { return nil }
        return try? DN(string: names[index])
    }

    /// DS_LIST_SITES: every `site` child of `CN=Sites` (pName = the site DN).
    func listSites(_ info: DomainInfo) async throws -> [CrackItem] {
        try await objects("site", under: sitesDN(info), scope: .oneLevel).map { Self.dnItem($0.dn) }
    }

    /// DS_LIST_SERVERS_IN_SITE: the `server` objects below the site DN in names[0].
    func listServersInSite(_ names: [String], _ info: DomainInfo) async throws -> [CrackItem] {
        guard let site = Self.dnArgument(names, 0) else { return [] }
        return try await objects("server", under: site).map { Self.dnItem($0.dn) }
    }

    /// DS_LIST_DOMAINS / DS_LIST_NCS: the ncName of every crossRef under `CN=Partitions` (only
    /// FLAG_CR_NTDS_DOMAIN ones for domains): here the domain, and for NCs also Configuration and
    /// Schema.
    func listNCs(_ info: DomainInfo, domainsOnly: Bool) async throws -> [CrackItem] {
        let flagCrNtdsDomain: Int64 = 0x2
        return try await objects("crossRef", under: partitionsDN(info), scope: .oneLevel).compactMap { cr in
            if domainsOnly && (cr.int("systemFlags") ?? 0) & flagCrNtdsDomain == 0 { return nil }
            guard let nc = cr.string("nCName") else { return nil }
            return CrackItem(.ok, name: nc)
        }
    }

    /// nTDSDSA objects below a site DN.
    private func dsas(inSite site: DN) async throws -> [DirectoryEntry] {
        try await objects("nTDSDSA", under: site)
    }

    /// DS_LIST_DOMAINS_IN_SITE: the hasMasterNCs of the site's DSAs, minus Schema and Configuration.
    func listDomainsInSite(_ names: [String], _ info: DomainInfo) async throws -> [CrackItem] {
        guard let site = Self.dnArgument(names, 0) else { return [] }
        var seen = Set<String>()
        var out = [CrackItem]()
        for dsa in try await dsas(inSite: site) {
            for nc in dsa.strings("hasMasterNCs") {
                guard let dn = try? DN(string: nc), dn != info.schemaDN, dn != info.configurationDN,
                      seen.insert(dn.normalized).inserted else { continue }
                out.append(Self.dnItem(dn))
            }
        }
        return out
    }

    /// DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE: servers (DSA parents) in site names[1] whose DSA masters
    /// the domain names[0] (msDS-hasMasterNCs).
    func listServersForDomainInSite(_ names: [String], _ info: DomainInfo) async throws -> [CrackItem] {
        guard let domain = Self.dnArgument(names, 0), let site = Self.dnArgument(names, 1) else { return [] }
        return try await dsas(inSite: site).compactMap { dsa in
            let masters = dsa.strings("msDS-hasMasterNCs").compactMap { try? DN(string: $0) }
            guard masters.contains(domain), let server = dsa.dn.parent else { return nil }
            return Self.dnItem(server)
        }
    }

    /// DS_LIST_SERVERS_WITH_DCS_IN_SITE: servers (DSA parents) in site names[0] whose DSA has
    /// hasMasterNCs.
    func listServersWithDCsInSite(_ names: [String], _ info: DomainInfo) async throws -> [CrackItem] {
        guard let site = Self.dnArgument(names, 0) else { return [] }
        return try await dsas(inSite: site).compactMap { dsa in
            guard dsa.has("hasMasterNCs"), let server = dsa.dn.parent else { return nil }
            return Self.dnItem(server)
        }
    }

    /// DS_LIST_INFO_FOR_SERVER, as Samba's dcesrv_drsuapi_ListInfoServer: always three items, each
    /// NOT_FOUND unless found — [0] the nTDSDSA under the server DN names[0], [1] the server's
    /// dNSHostName, [2] its serverReference.
    func listInfoForServer(_ names: [String], _ info: DomainInfo) async throws -> [CrackItem] {
        var items = [CrackItem](repeating: CrackItem(.notFound), count: 3)
        guard names.count == 1, let serverDN = Self.dnArgument(names, 0) else { return items }
        let dsas = try await objects("nTDSDSA", under: serverDN, scope: .oneLevel)
        guard dsas.count == 1 else { return items }
        items[0] = Self.dnItem(dsas[0].dn)
        guard let server = try await store.read(dn: serverDN) else { return items }
        if let host = server.string("dNSHostName") { items[1] = CrackItem(.ok, name: host) }
        if let ref = server.string("serverReference") { items[2] = CrackItem(.ok, name: ref) }
        return items
    }

    /// DS_LIST_ROLES, as Samba's dcesrv_drsuapi_ListRoles: five items (MS-DRSR order: schema,
    /// domain naming, PDC, RID, infrastructure), pName = the fSMORoleOwner (nTDSDSA DN), pDomain =
    /// the owning server's dNSHostName.
    func listRoles(_ info: DomainInfo) async throws -> [CrackItem] {
        let holders: [DN] = [
            info.schemaDN,
            partitionsDN(info),
            info.domainDN,
            info.domainDN.child(RDN("CN", "System")).child(RDN("CN", "RID Manager$")),
            info.domainDN.child(RDN("CN", "Infrastructure")),
        ]
        var out = [CrackItem]()
        for holder in holders {
            let owner = (try await store.read(dn: holder))?.string("fSMORoleOwner")
                .flatMap { try? DN(string: $0) } ?? info.dsServiceDN
            var host = info.dcDNSName
            if let serverDN = owner.parent, let server = try await store.read(dn: serverDN),
               let h = server.string("dNSHostName") {
                host = h
            }
            out.append(CrackItem(.ok, domain: host, name: owner.description))
        }
        return out
    }

    /// DS_LIST_GLOBAL_CATALOG_SERVERS: every nTDSDSA with NTDSDSA_OPT_IS_GC and an invocationId —
    /// pDomain = the server's dNSHostName, pName = the site's RDN value.
    func listGlobalCatalogServers(_ info: DomainInfo) async throws -> [CrackItem] {
        let ntdsdsaOptIsGC: Int64 = 0x1
        var out = [CrackItem]()
        for dsa in try await objects("nTDSDSA", under: sitesDN(info)) {
            guard (dsa.int("options") ?? 0) & ntdsdsaOptIsGC != 0, dsa.has("invocationId"),
                  let serverDN = dsa.dn.parent,
                  let siteDN = serverDN.parent?.parent,           // CN=<server>,CN=Servers,CN=<site>
                  let siteName = siteDN.rdn?.value else { continue }
            let host = (try await store.read(dn: serverDN))?.string("dNSHostName") ?? info.dcDNSName
            out.append(CrackItem(.ok, domain: host, name: siteName))
        }
        return out
    }
}
