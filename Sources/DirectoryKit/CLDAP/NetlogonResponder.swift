import Darwin
import Foundation
import LDAPCore
import Store

/// Builds the `Netlogon` attribute value for an LDAP ping (MS-ADTS §6.3.3.2). Used by the CLDAP
/// responder and by the TCP LDAP server's RootDSE search.
public struct NetlogonResponder: Sendable {
    public let store: DirectoryStore
    public let info: DomainInfo
    public let flags: NetlogonDSFlags

    public init(store: DirectoryStore, info: DomainInfo, flags: NetlogonDSFlags = .sheepDC) {
        self.store = store
        self.info = info
        self.flags = flags
    }

    /// The netlogon structure for `ping`, or nil when the ping is not addressed to this
    /// domain (the caller then sends an entry without attributes, see `entry(for:serverIPv4:)`).
    ///
    /// Opcode: `USER_UNKNOWN(_EX)` when a `User` term names no enabled account of an `AAC`
    /// type. EX flags are `flags`; V5 flags are `PDC|DS` only (§6.3.3.2). UnicodeLogonServer
    /// of the V5 and NT40 structures is `\\DC1` (the NT form Samba sends).
    /// - Parameter serverIPv4: this DC's address (network order) for `DcSockAddr` and
    ///   `DcIpAddress`; see `NetlogonAddress.select`.
    public func response(to ping: NetlogonPing, serverIPv4: [UInt8]) async -> [UInt8]? {
        guard ping.isAddressed(to: info) else { return nil }
        let userName = ping.user ?? ""
        let known = await userKnown(ping)
        let version = ping.effectiveNtVersion
        let site = info.site
        switch ping.responseKind {
        case .ex:
            return NetlogonSamLogonResponseEx(
                opcode: known ? .samLogonResponseEx : .samUserUnknownEx, flags: flags, domainGUID: info.domainGUID.bytes,
                dnsForestName: info.dnsDomain, dnsDomainName: info.dnsDomain, dnsHostName: info.dcDNSName,
                netbiosDomainName: info.netbiosDomain, netbiosComputerName: info.dcName, userName: userName,
                dcSiteName: site, clientSiteName: site,
                dcIPv4: version.contains(.v5exWithIP) ? serverIPv4 : nil,
                nextClosestSiteName: version.contains(.withClosestSite) ? "" : nil
            ).encoded()
        case .v5:
            return NetlogonSamLogonResponse(
                opcode: known ? .samLogonResponse : .samUserUnknown, unicodeLogonServer: "\\\\" + info.dcName,
                unicodeUserName: userName, unicodeDomainName: info.netbiosDomain, domainGUID: info.domainGUID.bytes,
                dnsForestName: info.dnsDomain, dnsDomainName: info.dnsDomain, dnsHostName: info.dcDNSName,
                dcIPv4: serverIPv4, flags: flags.intersection(.pdc).union(.ds)
            ).encoded()
        case .nt40:
            return NetlogonSamLogonResponseNT40(
                opcode: known ? .samLogonResponse : .samUserUnknown, unicodeLogonServer: "\\\\" + info.dcName,
                unicodeUserName: userName, unicodeDomainName: info.netbiosDomain
            ).encoded()
        }
    }

    /// The SearchResultEntry answering a ping filter: `Netlogon` with the structure, or, for
    /// an invalid filter or one naming another domain, an entry without attributes
    /// (MS-ADTS §6.3.3.3). SearchResultDone (success) follows either way.
    public func entry(for filter: FilterAST, serverIPv4: [UInt8]) async -> SearchResultEntry {
        guard let ping = try? NetlogonPing(filter: filter),
              let value = await response(to: ping, serverIPv4: serverIPv4) else {
            return SearchResultEntry(objectName: "", attributes: [])
        }
        return SearchResultEntry(objectName: "", attributes: [LDAPAttribute(type: "Netlogon", values: [value])])
    }

    /// No `User` term: known. Otherwise an enabled account with that sAMAccountName whose
    /// `userAccountControl` has one of the account-type bits `AAC` asks for.
    func userKnown(_ ping: NetlogonPing) async -> Bool {
        guard let user = ping.user else { return true }
        guard !user.isEmpty, let entry = try? await store.read(sam: user, attrs: ["userAccountControl"]),
              let uac = entry.int("userAccountControl") else { return false }
        let bits = UInt32(truncatingIfNeeded: uac)
        if bits & 0x2 != 0 { return false }
        return bits & ping.requiredUACBits != 0
    }
}

/// Picks the IPv4 address a netlogon response advertises.
public enum NetlogonAddress {
    /// `configured` if set; else the address the request arrived on when it is IPv4
    /// (v4-mapped IPv6 counts); else the first non-loopback IPv4 of an up interface; else
    /// 127.0.0.1.
    public static func select(configured: String?, arrivedOn local: String?) -> [UInt8] {
        if let configured, let b = ipv4Bytes(configured) { return b }
        if let local, let b = ipv4Bytes(local), b != [0, 0, 0, 0] { return b }
        return firstNonLoopbackIPv4() ?? [127, 0, 0, 1]
    }

    /// `a.b.c.d` or `::ffff:a.b.c.d` (with an optional `%scope`) as 4 bytes.
    public static func ipv4Bytes(_ text: String) -> [UInt8]? {
        var s = text
        if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }
        if s.lowercased().hasPrefix("::ffff:") { s = String(s.dropFirst(7)) }
        var addr = in_addr()
        guard inet_pton(AF_INET, s, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: addr.s_addr) { Array($0) }
    }

    public static func firstNonLoopbackIPv4() -> [UInt8]? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        var candidates: [(String, [UInt8])] = []
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            defer { p = cur.pointee.ifa_next }
            let flags = Int32(cur.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0,
                  let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let bytes = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                withUnsafeBytes(of: sin.pointee.sin_addr.s_addr) { Array($0) }
            }
            if bytes[0] == 169, bytes[1] == 254 { continue }   // link-local last resort only
            candidates.append((String(cString: cur.pointee.ifa_name), bytes))
        }
        // Prefer en* (Wi-Fi/Ethernet) over VPN and bridge interfaces.
        return (candidates.first { $0.0.hasPrefix("en") } ?? candidates.first)?.1
    }
}

/// One CLDAP exchange: a datagram in, at most one datagram out.
///
/// - A SearchRequest with base `""`, scope base and `Netlogon` among the attributes is an
///   LDAP ping. The reply is a SearchResultEntry with the `Netlogon` value followed by
///   SearchResultDone, both in one datagram. If the filter is not a valid ping, or names
///   another domain, the entry has no attributes (MS-ADTS §6.3.3.3).
/// - Any other RootDSE search gets the RootDSE entry (the same attributes the TCP server
///   emits), provided the filter matches it. `(objectClass=*)` always does.
/// - A search elsewhere gets `unwillingToPerform`. Other operations and undecodable
///   datagrams are dropped (RFC 1798 defines no other replies).
///
/// Requests in the RFC 1798 format (a `user` DN between messageID and protocolOp) are
/// accepted. Replies always use the LDAPv3 message format, as AD does.
final class CLDAPResponder: Sendable {
    let store: DirectoryStore
    let info: DomainInfo
    let config: CLDAPServerConfig
    let netlogon: NetlogonResponder

    init(store: DirectoryStore, info: DomainInfo, config: CLDAPServerConfig) {
        self.store = store
        self.info = info
        self.config = config
        netlogon = NetlogonResponder(store: store, info: info, flags: config.flags)
    }

    /// The reply datagram for `datagram`, or nil to stay silent.
    /// - Parameter localAddress: the address the datagram arrived on, if known.
    func handle(_ datagram: [UInt8], localAddress: String?) async -> [UInt8]? {
        guard let message = Self.decode(datagram) else { return nil }
        guard case .searchRequest(let request) = message.operation else { return nil }
        let id = message.messageID
        guard request.baseObject.isEmpty, request.scope == .base else {
            return Self.done(id, LDAPResult(.unwillingToPerform, diagnosticMessage: "CLDAP serves the RootDSE only"))
        }
        if request.attributes.contains(where: { $0.caseInsensitiveCompare("Netlogon") == .orderedSame }) {
            let ip = NetlogonAddress.select(configured: config.advertisedIPv4, arrivedOn: localAddress)
            let entry = await netlogon.entry(for: request.filter, serverIPv4: ip)
            return LDAPMessage(messageID: id, .searchResultEntry(entry)).encoded() + Self.done(id, .success)
        }
        guard let all = try? await LDAPConnection.rootDSEAttributes(store: store, info: info, now: config.clock(),
                                                                    vendorVersion: config.vendorVersion) else {
            return Self.done(id, LDAPResult(.unavailable, diagnosticMessage: "store unavailable"))
        }
        guard Self.rootDSEMatches(request.filter, all) else { return Self.done(id, .success) }
        let selection = AttributeSelection(request.attributes)
        var attrs = all
        if !selection.allUser, !selection.allOperational { attrs = attrs.filter { selection.wants($0.type) } }
        if request.typesOnly { attrs = attrs.map { LDAPAttribute(type: $0.type, values: []) } }
        let entry = SearchResultEntry(objectName: "", attributes: attrs)
        return LDAPMessage(messageID: id, .searchResultEntry(entry)).encoded() + Self.done(id, .success)
    }

    static func done(_ id: Int32, _ result: LDAPResult) -> [UInt8] {
        LDAPMessage(messageID: id, .searchResultDone(result)).encoded()
    }

    /// LDAPv3, or RFC 1798 CLDAP with its `user` field removed.
    static func decode(_ datagram: [UInt8]) -> LDAPMessage? {
        if let m = try? LDAPMessage(bytes: datagram) { return m }
        guard let outer = try? BERElement(bytes: datagram), outer.tag == .sequence,
              var parts = try? outer.children(), parts.count >= 3, parts[1].tag == .octetString,
              parts[2].tag.tagClass == .application else { return nil }
        parts.remove(at: 1)
        return try? LDAPMessage(element: .sequence(parts))
    }

    /// Two-valued evaluation of a filter against the RootDSE, whose `objectClass` is `top`.
    static func rootDSEMatches(_ filter: FilterAST, _ attrs: [LDAPAttribute]) -> Bool {
        func values(_ name: String) -> [[UInt8]]? {
            if name.caseInsensitiveCompare("objectClass") == .orderedSame { return [Array("top".utf8)] }
            return attrs.first { $0.type.caseInsensitiveCompare(name) == .orderedSame }?.values
        }
        switch filter {
        case .and(let fs): return fs.allSatisfy { rootDSEMatches($0, attrs) }
        case .or(let fs): return fs.contains { rootDSEMatches($0, attrs) }
        case .not(let f): return !rootDSEMatches(f, attrs)
        case .present(let a): return values(a) != nil
        case .equality(let a, let v), .approx(let a, let v):
            let want = String(decoding: v, as: UTF8.self).lowercased()
            return values(a)?.contains { String(decoding: $0, as: UTF8.self).lowercased() == want } ?? false
        default: return false
        }
    }
}
