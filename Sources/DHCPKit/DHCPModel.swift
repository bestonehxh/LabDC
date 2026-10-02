import Foundation

public enum DHCPFamily: String, Codable, Sendable, CaseIterable {
    case v4, v6
    public var title: String { self == .v4 ? "IPv4" : "IPv6" }
}

/// `start`…`end`, inclusive, both in the scope's subnet.
public struct DHCPRange: Codable, Sendable, Hashable {
    public var start: String
    public var end: String

    public init(_ start: String, _ end: String) { self.start = start; self.end = end }

    public var text: String { "\(start)-\(end)" }

    /// `10.0.0.10-10.0.0.99` or a single address.
    public init?(text: String) {
        let parts = text.split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.count == 2 { self.init(parts[0], parts[1]) } else if parts.count == 1, !parts[0].isEmpty { self.init(parts[0], parts[0]) } else { return nil }
    }

    public var v4: ClosedRange<IPv4Address>? {
        guard let a = IPv4Address(start), let b = IPv4Address(end), a <= b else { return nil }
        return a...b
    }

    public var v6: ClosedRange<IPv6Address>? {
        guard let a = IPv6Address(start), let b = IPv6Address(end), a <= b else { return nil }
        return a...b
    }
}

/// A vendor/user-class policy inside a scope (option 60/77, v6 16/15): matching clients get a
/// sub-range and/or their own options.
public struct DHCPClassPolicy: Codable, Sendable, Hashable, Identifiable {
    public enum Match: String, Codable, Sendable, CaseIterable {
        case vendorClass, userClass
        public var title: String { self == .vendorClass ? "Vendor class" : "User class" }
    }

    public var id: UUID
    public var name: String
    public var match: Match
    /// Case-insensitive "contains".
    public var value: String
    /// Addresses for matching clients (empty = the scope's ranges).
    public var ranges: [DHCPRange]
    public var option43: VendorOption43?
    public var options: [DHCPCustomOption]

    public init(id: UUID = UUID(), name: String, match: Match = .vendorClass, value: String, ranges: [DHCPRange] = [],
                option43: VendorOption43? = nil, options: [DHCPCustomOption] = []) {
        self.id = id; self.name = name; self.match = match; self.value = value; self.ranges = ranges
        self.option43 = option43; self.options = options
    }

    public func matches(vendorClass: String?, userClass: String?) -> Bool {
        let want = value.trimmingCharacters(in: .whitespaces)
        guard !want.isEmpty, let have = match == .vendorClass ? vendorClass : userClass else { return false }
        return have.range(of: want, options: .caseInsensitive) != nil
    }
}

/// A DHCP scope: one subnet (usually one VLAN) and what its clients get.
public struct DHCPScope: Codable, Sendable, Equatable, Identifiable {
    public var id: Int64
    public var name: String
    public var family: DHCPFamily
    public var enabled: Bool
    public var vlan: Int?
    /// `10.20.0.0/24` or `2001:db8:20::/64`.
    public var subnet: String
    public var ranges: [DHCPRange]
    public var exclusions: [DHCPRange]
    /// Scopes with the same non-empty name share one link (several subnets behind one `giaddr`).
    public var sharedNetwork: String?
    /// v4 option 3.
    public var routers: [String]
    /// v4 lease time / v6 valid lifetime, seconds.
    public var leaseSeconds: Int
    /// v6 preferred lifetime (0 = 5/8 of the valid lifetime... see `preferredLifetime`).
    public var preferredSeconds: Int
    /// Empty = this DC.
    public var dnsServers: [String]
    /// nil = the AD domain.
    public var domainName: String?
    /// Empty = this DC.
    public var ntpServers: [String]
    /// Option 119 / v6 24 (empty = the domain name).
    public var searchList: [String]
    public var mtu: Int?
    public var staticRoutes: [DHCPOptionBuilder.StaticRoute]
    /// Option 138 CAPWAP AC addresses.
    public var capwap: [String]
    /// Option 66 / 67 / 150 (phones, zero-touch; LabDC serves no TFTP itself).
    public var tftpServer: String?
    public var bootfile: String?
    public var tftpServers150: [String]
    public var option43: VendorOption43?
    public var classPolicies: [DHCPClassPolicy]
    public var customOptions: [DHCPCustomOption]
    /// NAK requests for addresses that do not belong on this link (off: a second server stays quiet).
    public var authoritative: Bool
    /// Only reservations get addresses.
    public var knownClientsOnly: Bool
    /// Wait this long before an OFFER/ADVERTISE, so the production server answers first.
    public var offerDelayMs: Int
    /// ICMP echo the candidate address before offering it (300 ms).
    public var pingBeforeOffer: Bool
    /// Register A/AAAA and PTR for this scope's clients.
    public var dnsUpdates: Bool
    /// v6: answer a SOLICIT with Rapid Commit directly with a REPLY.
    public var rapidCommit: Bool

    public init(id: Int64 = 0, name: String, family: DHCPFamily = .v4, enabled: Bool = true, vlan: Int? = nil,
                subnet: String, ranges: [DHCPRange] = [], exclusions: [DHCPRange] = [], sharedNetwork: String? = nil,
                routers: [String] = [], leaseSeconds: Int? = nil, preferredSeconds: Int = 0,
                dnsServers: [String] = [], domainName: String? = nil, ntpServers: [String] = [], searchList: [String] = [],
                mtu: Int? = nil, staticRoutes: [DHCPOptionBuilder.StaticRoute] = [], capwap: [String] = [],
                tftpServer: String? = nil, bootfile: String? = nil, tftpServers150: [String] = [],
                option43: VendorOption43? = nil, classPolicies: [DHCPClassPolicy] = [], customOptions: [DHCPCustomOption] = [],
                authoritative: Bool = false, knownClientsOnly: Bool = false, offerDelayMs: Int = 0,
                pingBeforeOffer: Bool = false, dnsUpdates: Bool = true, rapidCommit: Bool = true) {
        self.id = id; self.name = name; self.family = family; self.enabled = enabled; self.vlan = vlan
        self.subnet = subnet; self.ranges = ranges; self.exclusions = exclusions; self.sharedNetwork = sharedNetwork
        self.routers = routers
        self.leaseSeconds = leaseSeconds ?? (family == .v4 ? 8 * 3600 : 86_400)
        self.preferredSeconds = preferredSeconds
        self.dnsServers = dnsServers; self.domainName = domainName; self.ntpServers = ntpServers
        self.searchList = searchList; self.mtu = mtu; self.staticRoutes = staticRoutes; self.capwap = capwap
        self.tftpServer = tftpServer; self.bootfile = bootfile; self.tftpServers150 = tftpServers150
        self.option43 = option43; self.classPolicies = classPolicies; self.customOptions = customOptions
        self.authoritative = authoritative; self.knownClientsOnly = knownClientsOnly; self.offerDelayMs = offerDelayMs
        self.pingBeforeOffer = pingBeforeOffer; self.dnsUpdates = dnsUpdates; self.rapidCommit = rapidCommit
    }

    // Decoding tolerates rows written by earlier builds (missing keys take the defaults).
    enum CodingKeys: String, CodingKey {
        case id, name, family, enabled, vlan, subnet, ranges, exclusions, sharedNetwork, routers, leaseSeconds, preferredSeconds
        case dnsServers, domainName, ntpServers, searchList, mtu, staticRoutes, capwap, tftpServer, bootfile, tftpServers150
        case option43, classPolicies, customOptions, authoritative, knownClientsOnly, offerDelayMs, pingBeforeOffer, dnsUpdates
        case rapidCommit
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let family = try c.decodeIfPresent(DHCPFamily.self, forKey: .family) ?? .v4
        self.init(id: try c.decodeIfPresent(Int64.self, forKey: .id) ?? 0,
                  name: try c.decodeIfPresent(String.self, forKey: .name) ?? "",
                  family: family,
                  enabled: try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true,
                  vlan: try c.decodeIfPresent(Int.self, forKey: .vlan),
                  subnet: try c.decodeIfPresent(String.self, forKey: .subnet) ?? "",
                  ranges: try c.decodeIfPresent([DHCPRange].self, forKey: .ranges) ?? [],
                  exclusions: try c.decodeIfPresent([DHCPRange].self, forKey: .exclusions) ?? [],
                  sharedNetwork: try c.decodeIfPresent(String.self, forKey: .sharedNetwork),
                  routers: try c.decodeIfPresent([String].self, forKey: .routers) ?? [],
                  leaseSeconds: try c.decodeIfPresent(Int.self, forKey: .leaseSeconds),
                  preferredSeconds: try c.decodeIfPresent(Int.self, forKey: .preferredSeconds) ?? 0,
                  dnsServers: try c.decodeIfPresent([String].self, forKey: .dnsServers) ?? [],
                  domainName: try c.decodeIfPresent(String.self, forKey: .domainName),
                  ntpServers: try c.decodeIfPresent([String].self, forKey: .ntpServers) ?? [],
                  // Rows saved before 2 Oct 2026 may hold `a.lab b.lab` as one entry.
                  searchList: DHCPScope.splitSearchList(try c.decodeIfPresent([String].self, forKey: .searchList) ?? []),
                  mtu: try c.decodeIfPresent(Int.self, forKey: .mtu),
                  staticRoutes: try c.decodeIfPresent([DHCPOptionBuilder.StaticRoute].self, forKey: .staticRoutes) ?? [],
                  capwap: try c.decodeIfPresent([String].self, forKey: .capwap) ?? [],
                  tftpServer: try c.decodeIfPresent(String.self, forKey: .tftpServer),
                  bootfile: try c.decodeIfPresent(String.self, forKey: .bootfile),
                  tftpServers150: try c.decodeIfPresent([String].self, forKey: .tftpServers150) ?? [],
                  option43: try c.decodeIfPresent(VendorOption43.self, forKey: .option43),
                  classPolicies: try c.decodeIfPresent([DHCPClassPolicy].self, forKey: .classPolicies) ?? [],
                  customOptions: try c.decodeIfPresent([DHCPCustomOption].self, forKey: .customOptions) ?? [],
                  authoritative: try c.decodeIfPresent(Bool.self, forKey: .authoritative) ?? false,
                  knownClientsOnly: try c.decodeIfPresent(Bool.self, forKey: .knownClientsOnly) ?? false,
                  offerDelayMs: try c.decodeIfPresent(Int.self, forKey: .offerDelayMs) ?? 0,
                  pingBeforeOffer: try c.decodeIfPresent(Bool.self, forKey: .pingBeforeOffer) ?? false,
                  dnsUpdates: try c.decodeIfPresent(Bool.self, forKey: .dnsUpdates) ?? true,
                  rapidCommit: try c.decodeIfPresent(Bool.self, forKey: .rapidCommit) ?? true)
    }

    public var subnetV4: IPv4Subnet? { family == .v4 ? IPv4Subnet(subnet) : nil }
    public var subnetV6: IPv6Subnet? { family == .v6 ? IPv6Subnet(subnet) : nil }

    /// `Staff VLAN 20` / `Staff`.
    public var label: String { name }

    /// v6 preferred lifetime: the configured one, else the valid lifetime × 5/8 (min 60 s).
    public var preferredLifetime: Int {
        preferredSeconds > 0 ? min(preferredSeconds, leaseSeconds) : max(60, leaseSeconds * 5 / 8)
    }

    /// Checks the scope before it is saved: subnet, ranges inside it, addresses, options.
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { throw DHCPError.invalid("a scope needs a name") }
        if let vlan, !(1...4094).contains(vlan) { throw DHCPError.invalid("VLAN \(vlan) is not 1–4094") }
        guard leaseSeconds >= 60, leaseSeconds <= 365 * 86_400 else { throw DHCPError.invalid("lease time must be 1 minute to 1 year") }
        guard (0...5000).contains(offerDelayMs) else { throw DHCPError.invalid("offer delay must be 0–5000 ms") }
        switch family {
        case .v4:
            guard let s = IPv4Subnet(subnet) else { throw DHCPError.invalid("\(subnet) is not an IPv4 subnet (10.20.0.0/24)") }
            guard s.prefix >= 8, s.prefix <= 30 else { throw DHCPError.invalid("an IPv4 scope must be /8 to /30") }
            guard !ranges.isEmpty else { throw DHCPError.invalid("add at least one address range") }
            for r in ranges + exclusions + classPolicies.flatMap(\.ranges) {
                guard let v = r.v4 else { throw DHCPError.invalid("\(r.text) is not an IPv4 range") }
                guard s.contains(v.lowerBound), s.contains(v.upperBound) else { throw DHCPError.invalid("\(r.text) is outside \(s)") }
            }
            for a in routers + dnsServers + ntpServers + capwap + tftpServers150 where IPv4Address(a) == nil {
                throw DHCPError.invalid("\(a) is not an IPv4 address")
            }
            if let mtu, !(68...65535).contains(mtu) { throw DHCPError.invalid("MTU \(mtu) is out of range") }
            _ = try DHCPOptionBuilder.classlessRoutes(staticRoutes)
            if let option43 { _ = try option43.encode() }
            for p in classPolicies { if let o = p.option43 { _ = try o.encode() } }
            for o in customOptions + classPolicies.flatMap(\.options) { try o.validate() }
        case .v6:
            guard let s = IPv6Subnet(subnet) else { throw DHCPError.invalid("\(subnet) is not an IPv6 prefix (2001:db8:20::/64)") }
            guard s.prefix >= 48, s.prefix <= 120 else { throw DHCPError.invalid("an IPv6 scope must be /48 to /120") }
            guard !ranges.isEmpty else { throw DHCPError.invalid("add at least one address range") }
            for r in ranges + exclusions + classPolicies.flatMap(\.ranges) {
                guard let v = r.v6 else { throw DHCPError.invalid("\(r.text) is not an IPv6 range") }
                guard s.contains(v.lowerBound), s.contains(v.upperBound) else { throw DHCPError.invalid("\(r.text) is outside \(s)") }
            }
            for a in dnsServers + ntpServers where IPv6Address(a) == nil { throw DHCPError.invalid("\(a) is not an IPv6 address") }
            for o in customOptions { try o.validate(v6: true) }
        }
        for d in searchList + [domainName].compactMap({ $0 }) where !d.isEmpty { _ = try DHCPDNSWire.encode(d) }
    }

    /// Whether `address` is one this scope may hand out dynamically (in a range, not excluded,
    /// not a router).
    public func isAssignable(_ address: String) -> Bool {
        switch family {
        case .v4:
            guard let a = IPv4Address(address), let s = subnetV4, s.isHost(a) else { return false }
            if routers.contains(where: { IPv4Address($0) == a }) { return false }
            if exclusions.contains(where: { $0.v4?.contains(a) ?? false }) { return false }
            return ranges.contains { $0.v4?.contains(a) ?? false }
        case .v6:
            guard let a = IPv6Address(address), let s = subnetV6, s.contains(a) else { return false }
            if exclusions.contains(where: { $0.v6?.contains(a) ?? false }) { return false }
            return ranges.contains { $0.v6?.contains(a) ?? false }
        }
    }

    /// Whether `address` lies in the scope's subnet at all (reservations may sit outside ranges).
    public func contains(_ address: String) -> Bool {
        switch family {
        case .v4: guard let a = IPv4Address(address), let s = subnetV4 else { return false }; return s.contains(a)
        case .v6: guard let a = IPv6Address(address), let s = subnetV6 else { return false }; return s.contains(a)
        }
    }

    /// Dynamic addresses in the ranges (minus exclusions), capped for a summary.
    public var poolSize: UInt64 {
        switch family {
        case .v4:
            var total: UInt64 = 0
            for r in ranges { if let v = r.v4 { total += UInt64(v.upperBound.value - v.lowerBound.value) + 1 } }
            for r in exclusions { if let v = r.v4 { total -= min(total, UInt64(v.upperBound.value - v.lowerBound.value) + 1) } }
            return total
        case .v6:
            // Saturating: a /64 range alone is 2^64 addresses.
            func count(_ v: ClosedRange<IPv6Address>) -> UInt64 {
                let span = v.upperBound.value - v.lowerBound.value
                return span >= UInt128(UInt64.max) ? .max : UInt64(span) + 1
            }
            var total: UInt64 = 0
            for r in ranges {
                guard let v = r.v6 else { continue }
                let (sum, overflow) = total.addingReportingOverflow(count(v))
                total = overflow ? .max : sum
            }
            guard total < .max else { return total }
            for r in exclusions { if let v = r.v6 { total -= min(total, count(v)) } }
            return total
        }
    }
}

/// A fixed address for one client.
public struct DHCPReservation: Codable, Sendable, Equatable, Identifiable {
    public var id: Int64
    public var scopeID: Int64
    public var name: String
    public var enabled: Bool
    /// `aa:bb:cc:dd:ee:ff` (v4 chaddr; v6 via RFC 6939 or the DUID's link-layer address).
    public var mac: String?
    /// v4 option 61 as hex.
    public var clientID: String?
    /// v6 DUID as hex.
    public var duid: String?
    /// Option 82 circuit-id / remote-id (text as decoded, printable text or hex).
    public var circuitID: String?
    public var remoteID: String?
    public var address: String
    /// Name to register in DNS (else the client's own).
    public var hostname: String?
    public var options: [DHCPCustomOption]
    public var option43: VendorOption43?

    public init(id: Int64 = 0, scopeID: Int64, name: String, enabled: Bool = true, mac: String? = nil, clientID: String? = nil,
                duid: String? = nil, circuitID: String? = nil, remoteID: String? = nil, address: String,
                hostname: String? = nil, options: [DHCPCustomOption] = [], option43: VendorOption43? = nil) {
        self.id = id; self.scopeID = scopeID; self.name = name; self.enabled = enabled
        self.mac = mac.flatMap { DHCPMAC.normalize($0) ?? $0 }
        self.clientID = clientID.map { DHCPHex.bytes($0).map(DHCPHex.string) ?? $0 }
        self.duid = duid.map { DHCPHex.bytes($0).map(DHCPHex.string) ?? $0 }
        self.circuitID = circuitID; self.remoteID = remoteID; self.address = address
        self.hostname = hostname; self.options = options; self.option43 = option43
    }

    public var identifierText: String {
        [mac.map { "MAC \($0)" }, clientID.map { "client-id \($0)" }, duid.map { "DUID \($0)" },
         circuitID.map { "circuit \($0)" }, remoteID.map { "remote \($0)" }].compactMap { $0 }.joined(separator: " · ")
    }

    public func validate(scope: DHCPScope) throws {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { throw DHCPError.invalid("a reservation needs a name") }
        guard scope.contains(address) else { throw DHCPError.invalid("\(address) is not in \(scope.subnet)") }
        if let mac, DHCPMAC.normalize(mac) == nil { throw DHCPError.invalid("\(mac) is not a MAC address") }
        if let clientID, DHCPHex.bytes(clientID) == nil { throw DHCPError.invalid("client-id \(clientID) is not hex") }
        if let duid, DHCPHex.bytes(duid) == nil { throw DHCPError.invalid("DUID \(duid) is not hex") }
        let ids = [mac, clientID, duid, circuitID, remoteID].compactMap { $0 }.filter { !$0.isEmpty }
        guard !ids.isEmpty else { throw DHCPError.invalid("a reservation needs a MAC, client-id, DUID, circuit-id or remote-id") }
        for o in options { try o.validate(v6: scope.family == .v6) }
        if let option43 { _ = try option43.encode() }
    }
}

public enum DHCPLeaseState: String, Codable, Sendable, CaseIterable {
    /// Held for a client between OFFER/ADVERTISE and REQUEST (about a minute).
    case offered
    case active
    case released
    case expired
    /// DECLINEd by a client (address conflict): quarantined.
    case declined
    /// Answered a ping before the offer, or otherwise found in use: not handed out for a while.
    case abandoned
    /// Seen in a REQUEST to another server (option 54 not ours): that server's lease.
    case foreign

    public var title: String {
        switch self {
        case .offered: "Offered"
        case .active: "Active"
        case .released: "Released"
        case .expired: "Expired"
        case .declined: "Declined"
        case .abandoned: "Abandoned"
        case .foreign: "Other server"
        }
    }

    /// The address is taken (not free for someone else) while the lease time runs.
    public var holdsAddress: Bool { [.offered, .active, .declined, .abandoned, .foreign].contains(self) }
}

/// What a client sent that identifies its OS (device profiling, spec §7).
public struct DHCPFingerprint: Codable, Sendable, Equatable {
    public var family: DHCPFamily
    /// The message the fingerprint came from (`DISCOVER`, `REQUEST`, `SOLICIT`).
    public var message: String
    /// v4 option 55 in order / v6 ORO.
    public var parameterList: [UInt16]
    /// Option codes in the order the client wrote them.
    public var optionOrder: [UInt16]
    public var vendorClass: String?
    /// v6 vendor class enterprise number.
    public var vendorEnterprise: UInt32?
    public var hostname: String?
    public var clientID: String?
    public var userClass: String?
    public var fqdn: String?
    public var architecture: String?
    public var networkInterface: String?
    public var maxMessageSize: Int?
    public var duidType: UInt16?

    public init(family: DHCPFamily, message: String, parameterList: [UInt16] = [], optionOrder: [UInt16] = [],
                vendorClass: String? = nil, vendorEnterprise: UInt32? = nil, hostname: String? = nil, clientID: String? = nil,
                userClass: String? = nil, fqdn: String? = nil, architecture: String? = nil, networkInterface: String? = nil,
                maxMessageSize: Int? = nil, duidType: UInt16? = nil) {
        self.family = family; self.message = message; self.parameterList = parameterList; self.optionOrder = optionOrder
        self.vendorClass = vendorClass; self.vendorEnterprise = vendorEnterprise; self.hostname = hostname
        self.clientID = clientID; self.userClass = userClass; self.fqdn = fqdn; self.architecture = architecture
        self.networkInterface = networkInterface; self.maxMessageSize = maxMessageSize; self.duidType = duidType
    }

    /// v4: options 55, 60, 12, 61, 77, 81, 93, 94, 57 and the option order.
    public init(v4 p: DHCPv4Packet) {
        self.init(family: .v4, message: p.messageType?.description ?? "?",
                  parameterList: p.parameterRequestList.map(UInt16.init), optionOrder: p.optionOrder.map(UInt16.init),
                  vendorClass: p.vendorClass, hostname: p.hostName, clientID: p.clientIdentifier.map(DHCPHex.string),
                  userClass: p.userClass, fqdn: p.clientFQDN?.name,
                  architecture: p[DHCPv4OptionCode.clientSystemArchitecture].map(DHCPHex.string),
                  networkInterface: p[DHCPv4OptionCode.clientNetworkInterface].map(DHCPHex.string),
                  maxMessageSize: p.maxMessageSize)
    }

    /// v6: ORO, vendor class (16), user class (15), FQDN (39), DUID type.
    public init(v6 m: DHCPv6Message) {
        let vc = m.vendorClass
        self.init(family: .v6, message: m.type.description, parameterList: m.oro, optionOrder: m.options.map(\.code),
                  vendorClass: vc?.text, vendorEnterprise: vc?.enterprise, userClass: m.userClass, fqdn: m.clientFQDN?.name,
                  duidType: m.clientDUID.flatMap(DHCPv6DUID.type))
    }

    /// `55=1,3,6,15,31,33,43,44,46,47,119,121,249,252` — the common profiler notation.
    public var parameterListText: String { parameterList.map(String.init).joined(separator: ",") }

    /// One line per fact, for the lease detail and the CLI.
    public var lines: [String] {
        var out: [String] = []
        let prl = family == .v4 ? "Option 55" : "ORO"
        if !parameterList.isEmpty { out.append("\(prl): \(parameterListText)") }
        if !optionOrder.isEmpty { out.append("Option order: \(optionOrder.map(String.init).joined(separator: ","))") }
        if let vendorClass { out.append("Vendor class: \(vendorClass)" + (vendorEnterprise.map { " (enterprise \($0))" } ?? "")) }
        if let hostname { out.append("Host name: \(hostname)") }
        if let fqdn { out.append("FQDN: \(fqdn)") }
        if let userClass { out.append("User class: \(userClass)") }
        if let clientID { out.append("Client-id: \(clientID)") }
        if let architecture { out.append("Architecture (93): \(architecture)") }
        if let networkInterface { out.append("Network interface (94): \(networkInterface)") }
        if let maxMessageSize { out.append("Max message size: \(maxMessageSize)") }
        if let duidType { out.append("DUID type: \(duidType)") }
        out.append("From: \(message)")
        return out
    }
}

/// One lease (current or historical) on one address.
public struct DHCPLease: Codable, Sendable, Equatable, Identifiable {
    public var family: DHCPFamily
    public var address: String
    public var scopeID: Int64
    public var state: DHCPLeaseState
    /// v4: `id:<client-id hex>` or `hw:<htype>:<chaddr hex>`; v6: `duid:<hex>/<iaid>`.
    public var clientKey: String
    public var mac: String?
    public var clientID: String?
    public var duid: String?
    public var iaid: UInt32?
    public var hostname: String?
    public var start: Date
    public var expires: Date
    public var updated: Date
    /// The relay the client is behind (datagram source) and the link (giaddr / link-address).
    public var relay: String?
    public var link: String?
    public var circuitID: String?
    public var remoteID: String?
    public var subscriberID: String?
    public var vss: String?
    public var vendorClass: String?
    public var userClass: String?
    public var fingerprint: DHCPFingerprint?
    public var deviceCategory: String?
    public var deviceOS: String?
    /// The FQDN LabDC registered (A/AAAA + DHCID), the PTR owner, and whether the forward
    /// record is LabDC's.
    public var dnsName: String?
    public var dnsPTR: String?
    public var dnsForward: Bool
    /// The DHCID RDATA (hex) LabDC wrote next to the forward record: deleted only while it is ours.
    public var dnsDHCID: String?
    /// For `foreign`: the other server (option 54).
    public var otherServer: String?
    public var reservationID: Int64?

    public var id: String { "\(family.rawValue)/\(address)" }

    public init(family: DHCPFamily, address: String, scopeID: Int64, state: DHCPLeaseState, clientKey: String,
                mac: String? = nil, clientID: String? = nil, duid: String? = nil, iaid: UInt32? = nil, hostname: String? = nil,
                start: Date, expires: Date, updated: Date? = nil) {
        self.family = family; self.address = address; self.scopeID = scopeID; self.state = state; self.clientKey = clientKey
        self.mac = mac; self.clientID = clientID; self.duid = duid; self.iaid = iaid; self.hostname = hostname
        self.start = start; self.expires = expires; self.updated = updated ?? start
        self.dnsForward = false
    }

    /// Holds the address at `now` (offered/active/declined/abandoned/foreign and not yet past expiry).
    public func holds(at now: Date) -> Bool { state.holdsAddress && expires > now }

    /// Who is behind the lease, shortest useful text: `LAPTOP-7 (aa:bb:…)`.
    public var whoText: String {
        let id = mac ?? duid.map { "DUID \($0.prefix(16))…" } ?? clientKey
        return hostname.map { "\($0) (\(id))" } ?? id
    }
}

/// Server-wide DHCP settings (Settings tab, `labdc dhcp settings`).
public struct DHCPSettings: Codable, Sendable, Equatable {
    public enum DDNSMode: String, Codable, Sendable, CaseIterable {
        /// Windows' default: A+PTR unless the client asks to do A itself (then PTR only).
        case windows
        /// A+PTR for every client, overriding a client that wants to do its own.
        case always
        case never

        public var title: String {
            switch self {
            case .windows: "Like Windows (client's choice)"
            case .always: "Always A + PTR"
            case .never: "Never"
            }
        }
    }

    /// BSD interface names (`en0`) where LabDC answers local broadcasts; empty = relay-only.
    public var directInterfaces: [String]
    /// Relay agent addresses/CIDRs allowed to reach the server; empty = any.
    public var allowedRelays: [String]
    /// ClearPass / ISE profiler addresses that get a relay copy of each client message.
    public var profilers: [String]
    public var forwardReplies: Bool
    public var forwardV6: Bool
    public var ddns: DDNSMode
    public var declineQuarantineSeconds: Int
    public var offerHoldSeconds: Int
    /// 0 = no cap.
    public var maxLeasesPerRelay: Int
    public var maxLeasesPerCircuit: Int
    /// Distinct client identifiers one chaddr may use per hour (0 = no cap).
    public var clientIDChurnLimit: Int
    /// The v4 server identifier to hand out (nil = this Mac's address toward the relay).
    public var serverAddress: String?
    /// DHCPv6 (udp 547). Off by default (owner, 1 Oct 2026): macOS's own dhcp6d takes 547 when
    /// Internet Sharing runs (a VM on a Shared network), and launchd restarts it.
    public var enableV6: Bool

    public init(directInterfaces: [String] = [], allowedRelays: [String] = [], profilers: [String] = [],
                forwardReplies: Bool = false, forwardV6: Bool = false, ddns: DDNSMode = .windows,
                declineQuarantineSeconds: Int = 600, offerHoldSeconds: Int = 60, maxLeasesPerRelay: Int = 0,
                maxLeasesPerCircuit: Int = 0, clientIDChurnLimit: Int = 8, serverAddress: String? = nil,
                enableV6: Bool = false) {
        self.directInterfaces = directInterfaces; self.allowedRelays = allowedRelays; self.profilers = profilers
        self.forwardReplies = forwardReplies; self.forwardV6 = forwardV6; self.ddns = ddns
        self.declineQuarantineSeconds = declineQuarantineSeconds; self.offerHoldSeconds = offerHoldSeconds
        self.maxLeasesPerRelay = maxLeasesPerRelay; self.maxLeasesPerCircuit = maxLeasesPerCircuit
        self.clientIDChurnLimit = clientIDChurnLimit; self.serverAddress = serverAddress
        self.enableV6 = enableV6
    }

    enum CodingKeys: String, CodingKey {
        case directInterfaces, allowedRelays, profilers, forwardReplies, forwardV6, ddns, declineQuarantineSeconds
        case offerHoldSeconds, maxLeasesPerRelay, maxLeasesPerCircuit, clientIDChurnLimit, serverAddress, enableV6
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = DHCPSettings()
        self.init(directInterfaces: try c.decodeIfPresent([String].self, forKey: .directInterfaces) ?? d.directInterfaces,
                  allowedRelays: try c.decodeIfPresent([String].self, forKey: .allowedRelays) ?? d.allowedRelays,
                  profilers: try c.decodeIfPresent([String].self, forKey: .profilers) ?? d.profilers,
                  forwardReplies: try c.decodeIfPresent(Bool.self, forKey: .forwardReplies) ?? d.forwardReplies,
                  forwardV6: try c.decodeIfPresent(Bool.self, forKey: .forwardV6) ?? d.forwardV6,
                  ddns: try c.decodeIfPresent(DDNSMode.self, forKey: .ddns) ?? d.ddns,
                  declineQuarantineSeconds: try c.decodeIfPresent(Int.self, forKey: .declineQuarantineSeconds) ?? d.declineQuarantineSeconds,
                  offerHoldSeconds: try c.decodeIfPresent(Int.self, forKey: .offerHoldSeconds) ?? d.offerHoldSeconds,
                  maxLeasesPerRelay: try c.decodeIfPresent(Int.self, forKey: .maxLeasesPerRelay) ?? d.maxLeasesPerRelay,
                  maxLeasesPerCircuit: try c.decodeIfPresent(Int.self, forKey: .maxLeasesPerCircuit) ?? d.maxLeasesPerCircuit,
                  clientIDChurnLimit: try c.decodeIfPresent(Int.self, forKey: .clientIDChurnLimit) ?? d.clientIDChurnLimit,
                  serverAddress: try c.decodeIfPresent(String.self, forKey: .serverAddress),
                  enableV6: try c.decodeIfPresent(Bool.self, forKey: .enableV6) ?? d.enableV6)
    }

    public var isRelayOnly: Bool { directInterfaces.isEmpty }

    /// A profiler entry: `10.0.0.5` (udp 67), `10.0.0.5:6767`, `fd00::5` (udp 547), `[fd00::5]:5547`.
    public static func endpoint(_ text: String) -> (v4: IPv4Address?, v6: IPv6Address?, port: UInt16?)? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if let a = IPv4Address(t) { return (a, nil, nil) }
        if let a = IPv6Address(t) { return (nil, a, nil) }
        if t.hasPrefix("["), let close = t.firstIndex(of: "]") {
            let host = String(t[t.index(after: t.startIndex)..<close])
            let rest = t[t.index(after: close)...]
            guard let a = IPv6Address(host), rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()) else { return nil }
            return (nil, a, port)
        }
        let parts = t.split(separator: ":")
        if parts.count == 2, let a = IPv4Address(String(parts[0])), let port = UInt16(parts[1]) { return (a, nil, port) }
        return nil
    }

    /// IPv4 profilers with their ports (67 unless given).
    public var v4Profilers: [(IPv4Address, UInt16)] {
        profilers.compactMap { Self.endpoint($0) }.compactMap { e in e.v4.map { ($0, e.port ?? 67) } }
    }

    /// IPv6 profilers with their ports (547 unless given).
    public var v6Profilers: [(IPv6Address, UInt16)] {
        profilers.compactMap { Self.endpoint($0) }.compactMap { e in e.v6.map { ($0, e.port ?? 547) } }
    }
    public var modeText: String { isRelayOnly ? "relay-only" : "direct on \(directInterfaces.joined(separator: ", "))" }

    public func validate() throws {
        for p in allowedRelays where !DHCPAddressPattern.isValid(p) { throw DHCPError.invalid("\(p) is not an address, CIDR or range") }
        for p in profilers where Self.endpoint(p) == nil { throw DHCPError.invalid("profiler \(p) is not an address (or address:port)") }
        if let serverAddress, IPv4Address(serverAddress) == nil { throw DHCPError.invalid("\(serverAddress) is not an IPv4 address") }
        guard (60...86_400).contains(declineQuarantineSeconds) else { throw DHCPError.invalid("quarantine must be 1 minute to 1 day") }
        guard (10...600).contains(offerHoldSeconds) else { throw DHCPError.invalid("offer hold must be 10–600 s") }
        guard maxLeasesPerRelay >= 0, maxLeasesPerCircuit >= 0, clientIDChurnLimit >= 0 else { throw DHCPError.invalid("caps cannot be negative") }
    }

    /// Whether a relay (datagram source or giaddr) may use this server.
    public func allowsRelay(_ addresses: [String]) -> Bool {
        guard !allowedRelays.isEmpty else { return true }
        return addresses.contains { a in allowedRelays.contains { DHCPAddressPattern.matches($0, a) } }
    }
}

/// Per-scope counters since the server started.
public struct DHCPCounters: Codable, Sendable, Equatable {
    public var discover = 0, offer = 0, request = 0, ack = 0, nak = 0, decline = 0, release = 0, inform = 0
    public var solicit = 0, advertise = 0, reply = 0, renew = 0
    public var ignoredLocal = 0, droppedRelay = 0, foreignSeen = 0, noScope = 0, capped = 0
    public init() {}

    public static func + (a: DHCPCounters, b: DHCPCounters) -> DHCPCounters {
        var c = DHCPCounters()
        c.discover = a.discover + b.discover; c.offer = a.offer + b.offer; c.request = a.request + b.request
        c.ack = a.ack + b.ack; c.nak = a.nak + b.nak; c.decline = a.decline + b.decline; c.release = a.release + b.release
        c.inform = a.inform + b.inform; c.solicit = a.solicit + b.solicit; c.advertise = a.advertise + b.advertise
        c.reply = a.reply + b.reply; c.renew = a.renew + b.renew; c.ignoredLocal = a.ignoredLocal + b.ignoredLocal
        c.droppedRelay = a.droppedRelay + b.droppedRelay; c.foreignSeen = a.foreignSeen + b.foreignSeen
        c.noScope = a.noScope + b.noScope; c.capped = a.capped + b.capped
        return c
    }

    public var summary: String {
        "DISCOVER \(discover) · OFFER \(offer) · REQUEST \(request) · ACK \(ack) · NAK \(nak) · DECLINE \(decline)"
            + (solicit + reply > 0 ? " · SOLICIT \(solicit) · REPLY \(reply)" : "")
    }
}

/// One audit row (`dhcp_events`): per-lease history in the app and the CLI.
public struct DHCPEvent: Codable, Sendable, Equatable, Identifiable {
    public var id: Int64
    public var date: Date
    public var family: DHCPFamily
    public var address: String?
    public var mac: String?
    public var clientKey: String?
    /// `ACK`, `OFFER`, `RELEASE`, `DECLINE`, `EXPIRED`, `FOREIGN`, `NAK`, `REPLY`, …
    public var kind: String
    public var detail: String

    public init(id: Int64 = 0, date: Date, family: DHCPFamily, address: String?, mac: String?, clientKey: String?,
                kind: String, detail: String) {
        self.id = id; self.date = date; self.family = family; self.address = address; self.mac = mac
        self.clientKey = clientKey; self.kind = kind; self.detail = detail
    }
}
