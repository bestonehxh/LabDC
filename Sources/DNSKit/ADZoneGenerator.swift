import Darwin
import Foundation

/// Generates the records an AD domain controller registers (MS-ADTS §6.3.2.3, the
/// `netlogon.dns` set), split into the domain zone and the `_msdcs` zone.
public enum ADZoneGenerator {
    /// TTL of every generated record.
    public static let ttl: UInt32 = 600
    /// SOA timers: refresh, retry, expire, minimum (negative-caching TTL, RFC 2308).
    public static let soaTimers: (refresh: UInt32, retry: UInt32, expire: UInt32, minimum: UInt32) = (900, 600, 86400, 600)

    public static let ldapPort: UInt16 = 389
    public static let gcPort: UInt16 = 3268
    public static let kerberosPort: UInt16 = 88
    public static let kpasswdPort: UInt16 = 464

    /// SRV owner (relative to the domain) and port, per MS-ADTS §6.3.2.3, in the domain zone.
    static func domainSRVs(site: String) -> [(String, UInt16)] {
        [
            ("_ldap._tcp", ldapPort),
            ("_ldap._tcp.\(site)._sites", ldapPort),
            ("_kerberos._tcp", kerberosPort),
            ("_kerberos._udp", kerberosPort),
            ("_kerberos._tcp.\(site)._sites", kerberosPort),
            ("_kpasswd._tcp", kpasswdPort),
            ("_kpasswd._udp", kpasswdPort),
            ("_gc._tcp", gcPort),
            ("_gc._tcp.\(site)._sites", gcPort),
        ]
    }

    /// SRV owner (relative to `_msdcs.<domain>`) and port, in the `_msdcs` zone.
    static func msdcsSRVs(site: String, domainGUID: String) -> [(String, UInt16)] {
        [
            ("_ldap._tcp.dc", ldapPort),
            ("_ldap._tcp.pdc", ldapPort),
            ("_ldap._tcp.gc", gcPort),
            ("_ldap._tcp.\(site)._sites.dc", ldapPort),
            ("_ldap._tcp.\(site)._sites.gc", gcPort),
            ("_kerberos._tcp.dc", kerberosPort),
            ("_kerberos._tcp.\(site)._sites.dc", kerberosPort),
            ("_ldap._tcp.\(domainGUID).domains", ldapPort),
        ]
    }

    /// The SOA record for `zone`: primary `dcHostName`, mailbox `hostmaster.<domain>`.
    public static func soa(zone: DNSName, info: DNSDomainInfo, serial: UInt32) -> DNSRecord {
        let t = soaTimers
        return DNSRecord(name: zone, ttl: ttl, .soa(DNSSOA(
            mname: info.dcHostName, rname: info.dnsDomain.prepending("hostmaster"), serial: serial,
            refresh: t.refresh, retry: t.retry, expire: t.expire, minimum: t.minimum)))
    }

    /// Every generated record, keyed by zone (`info.servedZones`).
    public static func records(for info: DNSDomainInfo, serial: UInt32) -> [DNSName: [DNSRecord]] {
        let domain = info.dnsDomain
        let msdcs = domain.prepending("_msdcs")
        let host = info.dcHostName
        let domainGUID = info.domainGUID.uuidString.lowercased()
        let dsaGUID = (info.dsaGUID ?? info.domainGUID).uuidString.lowercased()

        func addressRecords(_ owner: DNSName) -> [DNSRecord] {
            info.addresses.map { DNSRecord(name: owner, ttl: ttl, $0.isIPv4 ? .a($0) : .aaaa($0)) }
        }
        func srv(_ relative: String, in zone: DNSName, port: UInt16) -> DNSRecord {
            let owner = (try? DNSName(parsing: relative).appending(zone)) ?? zone
            return DNSRecord(name: owner, ttl: ttl, .srv(DNSSRV(priority: 0, weight: 100, port: port, target: host)))
        }

        var main: [DNSRecord] = [soa(zone: domain, info: info, serial: serial), DNSRecord(name: domain, ttl: ttl, .ns(host))]
        main += addressRecords(domain)
        if host.isSubdomain(of: domain), !host.isSubdomain(of: msdcs) { main += addressRecords(host) }
        main += domainSRVs(site: info.site).map { srv($0.0, in: domain, port: $0.1) }

        var underscore: [DNSRecord] = [soa(zone: msdcs, info: info, serial: serial), DNSRecord(name: msdcs, ttl: ttl, .ns(host))]
        underscore += msdcsSRVs(site: info.site, domainGUID: domainGUID).map { srv($0.0, in: msdcs, port: $0.1) }
        underscore.append(DNSRecord(name: msdcs.prepending(dsaGUID), ttl: ttl, .cname(host)))
        underscore += addressRecords(msdcs.prepending("gc"))

        var out = [domain: main, msdcs: underscore]
        // The DC's names from before a domain rename, each its own one-name zone (formerHostNames).
        for former in info.formerHostZones {
            out[former] = [soa(zone: former, info: info, serial: serial), DNSRecord(name: former, ttl: ttl, .ns(host))]
                + addressRecords(former)
        }
        return out
    }
}

/// Enumerates this Mac's interface addresses (the NetworkInfo-style list the zone publishes).
public enum DNSHostAddresses {
    /// Addresses of interfaces that are up and not loopback. IPv4 link-local (169.254/16)
    /// is skipped; IPv6 is included only when asked, and then only global/ULA addresses.
    public static func current(includeIPv6: Bool = false) -> [DNSAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var result: [DNSAddress] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0,
                  let sa = entry.pointee.ifa_addr else { continue }
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                let bytes = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                    withUnsafeBytes(of: p.pointee.sin_addr) { Array($0) }
                }
                if bytes[0] == 169 && bytes[1] == 254 { continue }
                result.append(DNSAddress(bytes: bytes))
            case AF_INET6 where includeIPv6:
                let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                    withUnsafeBytes(of: p.pointee.sin6_addr) { Array($0) }
                }
                if bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80 { continue }   // fe80::/10
                result.append(DNSAddress(bytes: bytes))
            default: continue
            }
        }
        return Array(Set(result)).sorted()
    }
}
