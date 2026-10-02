import CryptoKit
import Foundation

/// How a udp 547 datagram arrived.
public struct DHCPv6Arrival: Sendable {
    public var source: IPv6Address
    public var sourcePort: UInt16
    /// The destination (`IPV6_RECVPKTINFO`); ff02::1:2 for a client on the local link.
    public var destination: IPv6Address?
    public var interfaceName: String?
    /// This Mac's global/ULA address on the receiving interface (direct mode's link).
    public var interfaceGlobal: IPv6Address?

    public init(source: IPv6Address, sourcePort: UInt16 = 547, destination: IPv6Address? = nil, interfaceName: String? = nil,
                interfaceGlobal: IPv6Address? = nil) {
        self.source = source; self.sourcePort = sourcePort; self.destination = destination
        self.interfaceName = interfaceName; self.interfaceGlobal = interfaceGlobal
    }

    public var isMulticast: Bool { destination?.isMulticast ?? true }
}

public struct DHCPv6Outcome: Sendable {
    public enum Destination: Sendable, Equatable {
        case none
        /// The relay that sent the Relay-forward: its source address, port 547 or (RFC 8357
        /// option 135) the port it sent from.
        case relay(IPv6Address, UInt16)
        /// A client on the local link (direct mode): its link-local address :546 via the interface.
        case client(IPv6Address, String?)
    }

    /// The client-level reply (before relay wrapping).
    public var reply: DHCPv6Message?
    /// The bytes to send (wrapped in Relay-reply layers when relayed).
    public var wire: [UInt8]?
    public var destination: Destination = .none
    public var common = DHCPCommonOutcome()

    public init() {}
}

/// The DHCPv6 server (RFC 8415), stateful IA_NA, relay-first. Rapid Commit; RENEW/REBIND/
/// RELEASE/DECLINE/CONFIRM/INFORMATION-REQUEST; status codes NoAddrsAvail, NotOnLink,
/// NoBinding, UseMulticast. Never sends Server Unicast; IA_PD is out of scope.
public enum DHCPv6Engine {
    public static func handle(_ bytes: [UInt8], arrival: DHCPv6Arrival, config: DHCPConfig,
                              leases: inout DHCPLeaseTable, now: Date) -> DHCPv6Outcome {
        var out = DHCPv6Outcome()
        let env: DHCPv6Envelope
        do { env = try DHCPv6Envelope(bytes: bytes) } catch {
            out.common.quiet = ("malformed6 \(arrival.source)", "DHCPv6 datagram from \(arrival.source) dropped (\(error))")
            return out
        }
        let m = env.message
        guard [.solicit, .request, .confirm, .renew, .rebind, .release, .decline, .informationRequest].contains(m.type) else {
            out.common.quiet = ("v6type \(arrival.source)", "DHCPv6 \(m.type) from \(arrival.source) is not a client message, dropped")
            return out
        }
        let settings = config.settings
        var scopes: [DHCPScope] = []
        var linkText: String
        if env.isRelayed {
            guard settings.allowsRelay([arrival.source.description] + env.relays.map(\.linkAddress.description).filter { $0 != "::" }) else {
                out.common.counters = [.droppedRelay]
                out.common.quiet = ("relay6 \(arrival.source)", "DHCPv6 \(m.type) via relay \(arrival.source) dropped: not an allowed relay")
                return out
            }
            // RFC 8415 §13.1: the innermost non-:: link-address, else the relay's source.
            let link = env.linkAddress ?? arrival.source
            scopes = config.scopes(forLink: link)
            linkText = "link \(link)"
        } else if arrival.isMulticast {
            guard let ifname = arrival.interfaceName, settings.directInterfaces.contains(ifname), let g = arrival.interfaceGlobal else {
                out.common.counters = [.ignoredLocal]
                out.common.quiet = ("local6", "DHCPv6 \(m.type) from \(arrival.source) on the local link ignored (relay-only)")
                return out
            }
            scopes = config.scopes(forLink: g)
            linkText = "direct on \(ifname)"
        } else {
            // A client unicast to us without Server Unicast: RFC 8415 §18.3 UseMulticast.
            guard [.request, .renew, .release, .decline].contains(m.type), let cid = m.clientDUID else {
                out.common.counters = [.ignoredLocal]
                return out
            }
            var reply = DHCPv6Message(type: .reply, transactionID: m.transactionID)
            reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, cid), DHCPv6Option(DHCPv6OptionCode.serverID, config.serverDUID),
                             DHCPv6Option.status(.useMulticast, "use multicast")]
            out.reply = reply
            out.wire = reply.encode()
            out.destination = .client(arrival.source, arrival.interfaceName)
            return out
        }
        guard let primary = scopes.first else {
            out.common.counters = [.noScope]
            out.common.quiet = ("noscope6 \(linkText)", "DHCPv6 \(m.type) (\(linkText)) dropped: no scope for that link")
            return out
        }
        out.common.scopeID = primary.id
        if settings.forwardV6, [.solicit, .request, .renew, .rebind, .informationRequest, .confirm].contains(m.type) {
            out.common.forwardToProfilers = true
        }

        // RFC 8415 §16: who must carry which DUID.
        let cid = m.clientDUID
        let sid = m.serverDUID
        switch m.type {
        case .solicit, .confirm, .rebind:
            guard cid != nil, sid == nil else { return dropInvalid(m, arrival, &out) }
        case .request, .renew, .release, .decline:
            guard cid != nil, let sid else { return dropInvalid(m, arrival, &out) }
            guard sid == config.serverDUID else {
                if m.type == .request, let cid { otherServerRequest(m, cid: cid, scopes: scopes, &leases, now: now) }
                out.common.quiet = ("other6 \(DHCPHex.string(cid ?? []))", "DHCPv6 \(m.type) for another server, ignored")
                return out
            }
        case .informationRequest:
            if let sid, sid != config.serverDUID { return out }
        default: break
        }

        let mac = macAddress(env, m)
        let fp = DHCPFingerprint(v6: m)
        if let mac, [.solicit, .request, .renew, .rebind, .informationRequest].contains(m.type) {
            out.common.profile = (mac, fp, DeviceClassifier.classify(fp), m.clientFQDN?.name)
        }
        let ctx = Context(env: env, m: m, arrival: arrival, config: config, scopes: scopes, linkText: linkText,
                          clientDUID: cid ?? [], mac: mac, fingerprint: fp, now: now)
        var reply: DHCPv6Message?
        switch m.type {
        case .solicit: reply = solicit(ctx, &leases, &out)
        case .request: reply = assign(ctx, &leases, &out, rapid: false)
        case .renew, .rebind: reply = renew(ctx, &leases, &out)
        case .release: reply = release(ctx, &leases, &out)
        case .decline: reply = decline(ctx, &leases, &out)
        case .confirm: reply = confirm(ctx, &out)
        case .informationRequest: reply = information(ctx, &out)
        default: break
        }
        guard let reply else { return out }
        out.reply = reply
        out.wire = env.isRelayed ? env.wrapReply(reply) : reply.encode()
        if env.isRelayed {
            let port: UInt16 = env.relays.first?.options.first(DHCPv6OptionCode.relaySourcePort) != nil ? arrival.sourcePort : 547
            out.destination = .relay(arrival.source, port)
        } else {
            out.destination = .client(arrival.source, arrival.interfaceName)
        }
        if reply.type == .advertise { out.common.counters.append(.advertise) } else { out.common.counters.append(.reply) }
        return out
    }

    static func dropInvalid(_ m: DHCPv6Message, _ a: DHCPv6Arrival, _ out: inout DHCPv6Outcome) -> DHCPv6Outcome {
        out.common.quiet = ("invalid6 \(a.source)", "DHCPv6 \(m.type) from \(a.source) without the required client/server DUID, dropped")
        return out
    }

    /// The client's MAC: RFC 6939 option 79 (Ethernet) from the relay, else the DUID-LL/LLT's.
    static func macAddress(_ env: DHCPv6Envelope, _ m: DHCPv6Message) -> String? {
        if let ll = env.clientLinkLayer, ll.type == 1, ll.address.count == 6 { return DHCPMAC.string(ll.address) }
        return m.clientDUID.flatMap(DHCPv6DUID.mac)
    }

    public static func clientKey(duid: [UInt8], iaid: UInt32) -> String { "duid:\(DHCPHex.string(duid))/\(iaid)" }

    struct Context {
        let env: DHCPv6Envelope
        let m: DHCPv6Message
        let arrival: DHCPv6Arrival
        let config: DHCPConfig
        let scopes: [DHCPScope]
        let linkText: String
        let clientDUID: [UInt8]
        let mac: String?
        let fingerprint: DHCPFingerprint
        let now: Date

        var who: String {
            let id = mac ?? "DUID \(DHCPHex.string(clientDUID).prefix(20))"
            return m.clientFQDN.map { "\(id) (\($0.name))" } ?? id
        }
        var via: String { env.isRelayed ? "via relay \(arrival.source)" : linkText }

        func scope(containing a: IPv6Address) -> DHCPScope? { scopes.first { $0.subnetV6?.contains(a) ?? false } }

        func reservation() -> DHCPReservation? {
            let ids = Set(scopes.map(\.id))
            let duidHex = DHCPHex.string(clientDUID)
            let remote = env.relayOption(DHCPv6OptionCode.remoteID).map { Array($0.dropFirst(4)) }
            return config.reservations.first { r in
                guard r.enabled, ids.contains(r.scopeID) else { return false }
                if let d = r.duid, d.lowercased() == duidHex { return true }
                if let rm = r.mac, let mac, rm == mac { return true }
                if let rid = r.remoteID, let remote, CircuitIDDecoder.matches(rid, remote) { return true }
                return false
            }
        }

        func policy(in scope: DHCPScope) -> DHCPClassPolicy? {
            scope.classPolicies.first { $0.matches(vendorClass: m.vendorClass?.text, userClass: m.userClass) }
        }
    }

    // MARK: Messages

    static func solicit(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        out.common.counters.append(.solicit)
        let rapid = c.m.hasRapidCommit && c.scopes.first?.rapidCommit == true
        if !rapid, let delay = c.scopes.first?.offerDelayMs { out.common.delayMs = delay }
        if c.scopes.allSatisfy(\.knownClientsOnly), c.reservation() == nil {
            out.common.quiet = ("unknown6 \(DHCPHex.string(c.clientDUID))", "DHCPv6 SOLICIT from \(c.who) \(c.via): known clients only, no reservation")
            return nil
        }
        return assign(c, &leases, &out, rapid: rapid, advertise: !rapid)
    }

    /// SOLICIT (advertise), REQUEST and Rapid Commit: one address per IA_NA.
    static func assign(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv6Outcome, rapid: Bool,
                       advertise: Bool = false) -> DHCPv6Message? {
        if !advertise, c.m.type == .request { out.common.counters.append(.request) }
        var reply = DHCPv6Message(type: advertise ? .advertise : .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID)]
        if rapid { reply.options.append(DHCPv6Option(DHCPv6OptionCode.rapidCommit, [])) }
        var granted: [String] = []
        var anyAddress = false
        for ia in c.m.iaNAs {
            let key = clientKey(duid: c.clientDUID, iaid: ia.iaid)
            // A REQUEST naming addresses on the wrong link: NotOnLink for that IA.
            if c.m.type == .request, !ia.addresses.isEmpty, ia.addresses.allSatisfy({ c.scope(containing: $0.address) == nil }) {
                reply.options.append(DHCPv6IANA(iaid: ia.iaid, options: [DHCPv6Option.status(.notOnLink, "not on this link")]).option)
                continue
            }
            guard let picked = pick(c, ia: ia, key: key, &leases) else {
                reply.options.append(DHCPv6IANA(iaid: ia.iaid, options: [DHCPv6Option.status(.noAddrsAvail, "no addresses available")]).option)
                continue
            }
            anyAddress = true
            let (address, scope, reservation) = picked
            var l = leases.lease(.v6, address.description) ?? DHCPLease(family: .v6, address: address.description, scopeID: scope.id,
                                                                         state: .offered, clientKey: key, start: c.now, expires: c.now)
            if l.clientKey != key {
                l = DHCPLease(family: .v6, address: address.description, scopeID: scope.id, state: .offered, clientKey: key,
                              start: c.now, expires: c.now)
            }
            let valid = scope.leaseSeconds
            let preferred = scope.preferredLifetime
            let wasActive = l.state == .active && l.expires > c.now
            fill(&l, c, scope: scope, reservation: reservation, iaid: ia.iaid)
            if advertise {
                if !wasActive {
                    l.state = .offered
                    l.expires = c.now.addingTimeInterval(TimeInterval(c.config.settings.offerHoldSeconds))
                }
            } else {
                if !wasActive { l.start = c.now }
                l.state = .active
                l.expires = c.now.addingTimeInterval(TimeInterval(valid))
                granted.append(address.description)
                if let action = dnsAction(c, scope: scope, reservation: reservation, lease: l) { out.common.dns.append(action) }
                out.common.events.append(DHCPEvent(date: c.now, family: .v6, address: l.address, mac: l.mac, clientKey: key,
                                                   kind: "REPLY", detail: "\(rapid ? "rapid commit" : "request"), \(valid) s \(c.via) · scope \(scope.name)"))
            }
            leases.put(l)
            let t1 = UInt32(preferred / 2), t2 = UInt32(preferred * 4 / 5)
            reply.options.append(DHCPv6IANA(iaid: ia.iaid, t1: t1, t2: t2, addresses: [
                .init(address: address, preferred: UInt32(preferred), valid: UInt32(valid)),
            ]).option)
        }
        if c.m.iaNAs.isEmpty || !anyAddress {
            if c.m.iaNAs.isEmpty {
                reply.options.append(DHCPv6Option.status(.noAddrsAvail, "no IA_NA in the request"))
            } else {
                reply.options.append(DHCPv6Option.status(.noAddrsAvail, "no addresses available"))
                out.common.quiet = ("full6 \(c.scopes.first?.id ?? 0)", "DHCPv6: no free address in \(c.scopes.map(\.name).joined(separator: ", ")) for \(c.who)")
            }
        }
        addConfig(&reply, c, scope: c.scopes[0])
        if let fqdnReply = fqdnReply(c, scope: c.scopes[0]) { reply.options.append(fqdnReply) }
        if !granted.isEmpty {
            out.common.line = "DHCPv6 REPLY \(granted.joined(separator: ", ")) to \(c.who) \(c.via) · scope \(c.scopes[0].name)"
                + (rapid ? " (rapid commit)" : "")
        }
        return reply
    }

    /// The client's binding for this IA, its reservation, the address it asked for, else a
    /// hashed probe through the ranges.
    static func pick(_ c: Context, ia: DHCPv6IANA, key: String, _ leases: inout DHCPLeaseTable) -> (IPv6Address, DHCPScope, DHCPReservation?)? {
        let reserved = Set(c.config.reservations.filter(\.enabled).map(\.address))
        if let r = c.reservation(), let a = IPv6Address(r.address), let s = c.config.scope(id: r.scopeID) {
            if leases.heldByOther(.v6, a.description, client: key, now: c.now) { return nil }
            return (a, s, r)
        }
        let open = c.scopes.filter { !$0.knownClientsOnly }
        for l in leases.leases(client: key) where l.family == .v6 && [.offered, .active, .released, .expired].contains(l.state) {
            guard let a = IPv6Address(l.address), let s = open.first(where: { $0.subnetV6?.contains(a) == true }),
                  s.isAssignable(l.address), !reserved.contains(l.address),
                  !leases.heldByOther(.v6, l.address, client: key, now: c.now) else { continue }
            return (a, s, nil)
        }
        func free(_ a: IPv6Address, _ s: DHCPScope) -> Bool {
            s.isAssignable(a.description) && !reserved.contains(a.description)
                && !(leases.lease(.v6, a.description).map { $0.holds(at: c.now) } ?? false)
        }
        for hint in ia.addresses {
            if let s = open.first(where: { $0.subnetV6?.contains(hint.address) == true }), free(hint.address, s) { return (hint.address, s, nil) }
        }
        var seed = Array(SHA256.hash(data: c.clientDUID + DHCPOptionBuilder.uint32(ia.iaid)))
        for s in open {
            let ranges = c.policy(in: s).flatMap { $0.ranges.isEmpty ? nil : $0.ranges } ?? s.ranges
            for r in ranges {
                guard let span = r.v6 else { continue }
                let size = span.upperBound.value - span.lowerBound.value
                for attempt in 0..<256 {
                    let h = seed.prefix(16).reduce(UInt128(0)) { $0 << 8 | UInt128($1) }
                    let offset = size == UInt128.max ? h : h % (size + 1)
                    let a = IPv6Address(span.lowerBound.value + offset)
                    if free(a, s) { return (a, s, nil) }
                    seed = Array(SHA256.hash(data: seed + [UInt8(attempt & 0xFF)]))
                    if size < 256, attempt > Int(size) { break }
                }
                // Small ranges: a linear sweep.
                if size < 4096 {
                    var v = span.lowerBound.value
                    while v <= span.upperBound.value {
                        let a = IPv6Address(v)
                        if free(a, s) { return (a, s, nil) }
                        v += 1
                    }
                }
            }
        }
        return nil
    }

    /// RENEW / REBIND: extend the client's bindings; zero lifetimes for addresses that are not
    /// ours or not on the link; NoBinding for a RENEW we know nothing about.
    static func renew(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        out.common.counters.append(.renew)
        var reply = DHCPv6Message(type: .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID)]
        var extended: [String] = []
        var answered = false
        for ia in c.m.iaNAs {
            let key = clientKey(duid: c.clientDUID, iaid: ia.iaid)
            var addresses: [DHCPv6IANA.Address] = []
            var found = false
            for hint in ia.addresses {
                if var l = leases.lease(.v6, hint.address.description), l.clientKey == key,
                   [.active, .expired, .released].contains(l.state),
                   let scope = c.config.scope(id: l.scopeID), scope.enabled, scope.contains(l.address),
                   !leases.heldByOther(.v6, l.address, client: key, now: c.now) {
                    found = true
                    let wasActive = l.state == .active && l.expires > c.now
                    if !wasActive { l.start = c.now }
                    l.state = .active
                    l.expires = c.now.addingTimeInterval(TimeInterval(scope.leaseSeconds))
                    fill(&l, c, scope: scope, reservation: nil, iaid: ia.iaid)
                    leases.put(l)
                    addresses.append(.init(address: hint.address, preferred: UInt32(scope.preferredLifetime), valid: UInt32(scope.leaseSeconds)))
                    extended.append(l.address)
                    if !wasActive, let action = dnsAction(c, scope: scope, reservation: nil, lease: l) { out.common.dns.append(action) }
                    out.common.events.append(DHCPEvent(date: c.now, family: .v6, address: l.address, mac: l.mac, clientKey: key,
                                                       kind: "REPLY", detail: "\(c.m.type == .renew ? "renew" : "rebind") \(c.via)"))
                } else if c.scope(containing: hint.address) == nil || c.m.type == .renew {
                    // Not appropriate for the link, or a RENEW for an address that is not this client's here.
                    addresses.append(.init(address: hint.address, preferred: 0, valid: 0))
                }
            }
            if found || !addresses.isEmpty {
                answered = true
                let scope = addresses.first.flatMap { c.scope(containing: $0.address) } ?? c.scopes[0]
                let pref = scope.preferredLifetime
                reply.options.append(DHCPv6IANA(iaid: ia.iaid, t1: found ? UInt32(pref / 2) : 0, t2: found ? UInt32(pref * 4 / 5) : 0,
                                                addresses: addresses).option)
            } else if c.m.type == .renew {
                answered = true
                reply.options.append(DHCPv6IANA(iaid: ia.iaid, options: [DHCPv6Option.status(.noBinding, "no binding")]).option)
            }
        }
        // REBIND for bindings we do not know and addresses on our link: stay quiet (the
        // production server may hold them).
        guard answered else {
            out.common.quiet = ("rebind-unknown \(DHCPHex.string(c.clientDUID))", "DHCPv6 \(c.m.type) from \(c.who): no binding here, silent")
            return nil
        }
        addConfig(&reply, c, scope: c.scopes[0])
        if let f = fqdnReply(c, scope: c.scopes[0]) { reply.options.append(f) }
        if !extended.isEmpty {
            out.common.line = "DHCPv6 REPLY \(extended.joined(separator: ", ")) to \(c.who) \(c.via) · scope \(c.scopes[0].name) (\(c.m.type == .renew ? "renew" : "rebind"))"
        }
        return reply
    }

    static func release(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        out.common.counters.append(.release)
        var reply = DHCPv6Message(type: .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID)]
        var released: [String] = []
        for ia in c.m.iaNAs {
            let key = clientKey(duid: c.clientDUID, iaid: ia.iaid)
            var known = false
            for hint in ia.addresses {
                guard var l = leases.lease(.v6, hint.address.description), l.clientKey == key, l.state == .active else { continue }
                known = true
                if l.dnsName != nil || l.dnsPTR != nil { out.common.dns.append(DHCPv4Engine.unregisterAction(l)) }
                l.state = .released; l.expires = c.now; l.updated = c.now
                leases.put(l)
                released.append(l.address)
                out.common.events.append(DHCPEvent(date: c.now, family: .v6, address: l.address, mac: l.mac, clientKey: key,
                                                   kind: "RELEASE", detail: "released by the client \(c.via)"))
            }
            if !known { reply.options.append(DHCPv6IANA(iaid: ia.iaid, options: [DHCPv6Option.status(.noBinding, "no binding")]).option) }
        }
        reply.options.append(DHCPv6Option.status(.success, "released"))
        if !released.isEmpty { out.common.line = "DHCPv6 RELEASE \(released.joined(separator: ", ")) from \(c.who) \(c.via)" }
        return reply
    }

    static func decline(_ c: Context, _ leases: inout DHCPLeaseTable, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        out.common.counters.append(.decline)
        var reply = DHCPv6Message(type: .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID)]
        let quarantine = c.config.settings.declineQuarantineSeconds
        var declined: [String] = []
        for ia in c.m.iaNAs {
            let key = clientKey(duid: c.clientDUID, iaid: ia.iaid)
            for hint in ia.addresses {
                guard var l = leases.lease(.v6, hint.address.description), l.clientKey == key else { continue }
                if l.dnsName != nil || l.dnsPTR != nil { out.common.dns.append(DHCPv4Engine.unregisterAction(l)) }
                l.state = .declined; l.updated = c.now
                l.expires = c.now.addingTimeInterval(TimeInterval(quarantine))
                leases.put(l)
                declined.append(l.address)
                out.common.events.append(DHCPEvent(date: c.now, family: .v6, address: l.address, mac: l.mac, clientKey: key,
                                                   kind: "DECLINE", detail: "duplicate address; quarantined \(quarantine / 60) min"))
            }
        }
        reply.options.append(DHCPv6Option.status(.success, "declined"))
        if !declined.isEmpty {
            out.common.line = "DHCPv6 DECLINE \(declined.joined(separator: ", ")) from \(c.who) \(c.via): duplicate, quarantined \(quarantine / 60) min"
        }
        return reply
    }

    /// CONFIRM: Success when every address is on this link, NotOnLink otherwise; nothing when it
    /// names no address (RFC 8415 §18.3.3).
    static func confirm(_ c: Context, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        let addresses = c.m.iaNAs.flatMap(\.addresses).map(\.address)
        guard !addresses.isEmpty else { return nil }
        let onLink = addresses.allSatisfy { c.scope(containing: $0) != nil }
        var reply = DHCPv6Message(type: .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID),
                         DHCPv6Option.status(onLink ? .success : .notOnLink, onLink ? "on link" : "not on this link")]
        return reply
    }

    static func information(_ c: Context, _ out: inout DHCPv6Outcome) -> DHCPv6Message? {
        var reply = DHCPv6Message(type: .reply, transactionID: c.m.transactionID)
        reply.options = [DHCPv6Option(DHCPv6OptionCode.serverID, c.config.serverDUID)]
        if !c.clientDUID.isEmpty { reply.options.insert(DHCPv6Option(DHCPv6OptionCode.clientID, c.clientDUID), at: 0) }
        addConfig(&reply, c, scope: c.scopes[0])
        out.common.line = "DHCPv6 INFORMATION-REQUEST from \(c.who) \(c.via) · scope \(c.scopes[0].name)"
        return reply
    }

    /// A REQUEST to another server: our ADVERTISE lapses (the client chose the other one).
    static func otherServerRequest(_ m: DHCPv6Message, cid: [UInt8], scopes: [DHCPScope], _ leases: inout DHCPLeaseTable, now: Date) {
        for ia in m.iaNAs {
            for var l in leases.leases(client: clientKey(duid: cid, iaid: ia.iaid)) where l.family == .v6 && l.state == .offered {
                l.state = .expired; l.expires = now; l.updated = now
                leases.put(l)
            }
        }
    }

    // MARK: Options

    static func addConfig(_ r: inout DHCPv6Message, _ c: Context, scope: DHCPScope) {
        let oro = Set(c.m.oro)
        func wanted(_ code: UInt16) -> Bool { oro.isEmpty || oro.contains(code) }
        let dns = scope.dnsServers.isEmpty ? c.config.dcIPv6 : scope.dnsServers
        if !dns.isEmpty, wanted(DHCPv6OptionCode.dnsServers), let b = try? DHCPOptionBuilder.ipv6List(dns) {
            r.options.append(DHCPv6Option(DHCPv6OptionCode.dnsServers, b))
        }
        let domain = scope.domainName ?? c.config.domain
        let search = scope.searchList.isEmpty ? (domain.isEmpty ? [] : [domain]) : scope.searchList
        if !search.isEmpty, wanted(DHCPv6OptionCode.domainList), let b = try? DHCPOptionBuilder.domainSearch(search) {
            r.options.append(DHCPv6Option(DHCPv6OptionCode.domainList, b))
        }
        let ntp = scope.ntpServers.isEmpty ? c.config.dcIPv6 : scope.ntpServers
        if !ntp.isEmpty, oro.contains(DHCPv6OptionCode.ntpServer) {
            // RFC 5908: NTP_SUBOPTION_SRV_ADDR (1), 16 bytes each.
            let data: [UInt8] = ntp.compactMap { IPv6Address($0) }.flatMap { a -> [UInt8] in [0, 1, 0, 16] + a.bytes }
            if !data.isEmpty { r.options.append(DHCPv6Option(DHCPv6OptionCode.ntpServer, data)) }
        }
        for o in scope.customOptions + (c.policy(in: scope)?.options ?? []) {
            guard wanted(o.code), let b = try? o.encode(v6: true) else { continue }
            r.options.removeAll { $0.code == o.code }
            r.options.append(DHCPv6Option(o.code, b))
        }
    }

    static func fqdnReply(_ c: Context, scope: DHCPScope) -> DHCPv6Option? {
        guard let f = c.m.clientFQDN else { return nil }
        let plan = dnsPlan(c, scope: scope, reservation: nil)
        let r = ClientFQDN(s: plan.forward, o: plan.forward && !f.s, n: f.n && !plan.forward && !plan.ptr,
                           name: plan.fqdn ?? f.name, fullyQualified: plan.fqdn != nil || f.fullyQualified)
        return DHCPv6Option(DHCPv6OptionCode.clientFQDN, r.encodeV6())
    }

    static func dnsPlan(_ c: Context, scope: DHCPScope, reservation: DHCPReservation?) -> (fqdn: String?, forward: Bool, ptr: Bool) {
        let mode = c.config.settings.ddns
        let f = c.m.clientFQDN
        guard scope.dnsUpdates, mode != .never, let raw = reservation?.hostname ?? f?.name, let label = DHCPDNS.sanitizeLabel(raw) else {
            return (nil, false, false)
        }
        let fqdn = DHCPDNS.fqdn(label: label, domain: scope.domainName ?? c.config.domain)
        if let f {
            if f.n { return (fqdn, false, false) }
            if !f.s, mode == .windows { return (fqdn, false, true) }
        }
        return (fqdn, true, true)
    }

    static func dnsAction(_ c: Context, scope: DHCPScope, reservation: DHCPReservation?, lease: DHCPLease) -> DHCPDNSAction? {
        let plan = dnsPlan(c, scope: scope, reservation: reservation)
        guard let fqdn = plan.fqdn, plan.forward || plan.ptr else { return nil }
        return DHCPDNSAction(kind: .register, lease: lease, fqdn: fqdn, forward: plan.forward, ptr: plan.ptr,
                             identifierType: .duid, identifier: c.clientDUID)
    }

    static func fill(_ l: inout DHCPLease, _ c: Context, scope: DHCPScope, reservation: DHCPReservation?, iaid: UInt32) {
        l.scopeID = scope.id
        l.updated = c.now
        l.duid = DHCPHex.string(c.clientDUID)
        l.iaid = iaid
        l.mac = c.mac
        if let h = reservation?.hostname ?? c.m.clientFQDN?.name { l.hostname = h }
        l.relay = c.env.isRelayed ? c.arrival.source.description : nil
        l.link = c.env.linkAddress?.description ?? c.arrival.interfaceName
        if let iid = c.env.relays.last?.interfaceID { l.circuitID = DHCPHex.string(iid) }
        if let rid = c.env.relayOption(DHCPv6OptionCode.remoteID) { l.remoteID = DHCPHex.string(rid) }
        if let sub = c.env.relayOption(DHCPv6OptionCode.subscriberID) { l.subscriberID = DHCPHex.string(sub) }
        if let vc = c.m.vendorClass { l.vendorClass = vc.text.isEmpty ? "enterprise \(vc.enterprise)" : vc.text }
        if let uc = c.m.userClass { l.userClass = uc }
        if [.solicit, .request, .renew, .rebind].contains(c.m.type) {
            l.fingerprint = c.fingerprint
            let profile = DeviceClassifier.classify(c.fingerprint)
            l.deviceCategory = profile.category.rawValue
            l.deviceOS = profile.os
        }
        l.reservationID = reservation?.id
    }
}
