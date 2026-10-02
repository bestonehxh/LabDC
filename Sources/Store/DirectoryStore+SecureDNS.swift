import Foundation
import MSPAC

// GSS-TSIG secure dynamic DNS updates: the DC's DNS service principal names, and what the DNS
// server asks about the account that signed an update.

extension DirectoryStore {
    /// The service names a member asks a ticket for before a secure update (`DNS/<SOA MNAME>`,
    /// i.e. the DC's host name, plus the short form).
    public static func dnsServicePrincipalNames(_ info: DomainInfo) -> [String] {
        ["DNS/\(info.dcDNSName)", "DNS/\(info.dcName)"]
    }

    /// Adds the DNS service principal names the DC account lacks (domains provisioned before, or
    /// renamed since); returns those added. Idempotent.
    @discardableResult
    public func ensureDNSServicePrincipalNames() throws -> [String] {
        let info = try domainInfo()
        guard let id = try id(of: info.dcComputerDN),
              let entry = try read(id: id, attrs: ["servicePrincipalName"]) else { return [] }
        let have = Set(entry.strings("servicePrincipalName").map { $0.lowercased() })
        let missing = Self.dnsServicePrincipalNames(info).filter { !have.contains($0.lowercased()) }
        guard !missing.isEmpty else { return [] }
        try update(id: id, ops: [.add("servicePrincipalName", strings: missing)])
        return missing
    }

    /// The `dNSHostName` of the live account with `sid`; nil when it has none.
    public func dnsHostName(sid: SID) throws -> String? {
        guard let e = try read(sid: sid, attrs: ["dNSHostName"]), !e.isDeleted else { return nil }
        return e.string("dNSHostName")
    }

    /// Whether the account with `sid` is, directly or nested, in Domain Admins, Enterprise Admins
    /// or DnsAdmins.
    public func isDNSAdministrator(sid: SID) throws -> Bool {
        guard let e = try read(sid: sid, attrs: ["objectSid"]), !e.isDeleted else { return false }
        let info = try domainInfo()
        var admins = Set([512, 519].compactMap { try? info.domainSID.appending(rid: $0) })
        if let dnsAdmins = try read(sam: "DnsAdmins", attrs: ["objectSid"])?.sid { admins.insert(dnsAdmins) }
        return try groupSIDs(of: e.id).contains { admins.contains($0) }
    }
}
