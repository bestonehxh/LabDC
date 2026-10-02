import AuthKit
import Foundation
import MSPAC
import os

/// Who may send an unsigned dynamic update (audit 27 Sep 2026: any host could replace any record,
/// e.g. point `_ldap._tcp` or another member's name at itself).
public enum DNSUpdatePolicy: Sendable {
    /// Over TCP from this Mac (loopback or one of the DC's addresses): anything outside the
    /// generated records. Everything else — every UDP update, whatever source address it claims
    /// (CVE audit 1 Oct 2026: a UDP source address is spoofable, so `127.0.0.1` on UDP proves
    /// nothing) — only A/AAAA records of the sender's own address, on an ordinary host name in
    /// the domain zone (not `_` names, not the DC, not `_msdcs`, not a static name), and only on a
    /// name the sender registered itself (`DNSRecordOwner`); deletes the same.
    case ownAddress
    /// RFC 2136 as is, for tests that exercise the protocol.
    case open
}

/// How a message arrived; decides the size limit and the ANY policy.
public enum DNSTransport: String, Sendable {
    case udp, tcp
}

/// Answers DNS messages: authoritative for the AD zones of a `DNSZoneSource`, RFC 2136
/// dynamic update for them, and forwarding (with a cache) for every other name.
///
/// Transport-independent: `DNSServer` feeds it bytes; tests can call it directly.
public actor DNSResponder {
    public let source: any DNSZoneSource
    public let forwarder: DNSForwarder?
    public let updatePolicy: DNSUpdatePolicy
    /// Settings ▸ DNS "Dynamic updates": secure and nonsecure / secure only / off.
    public private(set) var updateMode: DNSDynamicUpdateMode
    /// GSS-TSIG (RFC 3645); nil: TKEY is refused and every signed message gets BADKEY.
    public let secure: DNSSecureUpdateConfig?
    /// TKEY contexts by key name.
    var gssKeys: DNSGSSKeyTable
    /// One Activity line per applied or refused update (`UPDATE laptop-7.lab.sheep A … by LAPTOP-7$ (secure)`).
    let onEvent: (@Sendable (String) -> Void)?
    /// Who may have names outside our zones resolved (forwarded).
    public let recursion: DNSRecursionPolicy
    /// UDP response rate limiting (nil: off).
    private var rateLimiter: DNSRateLimiter?
    /// Monotonic seconds for the rate limiter (tests inject one).
    private let uptime: @Sendable () -> TimeInterval
    /// A name's owner that has not refreshed it for this long (Windows re-registers daily; this is
    /// Windows' default no-refresh + refresh interval) no longer holds it.
    public static let ownerLifetime: TimeInterval = 7 * 86400
    /// Current SOA serial of both zones; bumped by every dynamic update that changes data.
    public private(set) var serial: UInt32
    private var generated: (info: DNSDomainInfo, serial: UInt32, records: [DNSName: [DNSRecord]])?
    static let logger = Logger(subsystem: "dev.labdc.app", category: "DNS")

    /// Largest UDP reply we send to an EDNS client, and the size we advertise.
    public static let ednsUDPSize: UInt16 = 4096
    /// Longest CNAME chain followed inside our zones.
    static let maxChain = 8

    /// - Parameters:
    ///   - recursion: who may have foreign names forwarded; by default this Mac's networks.
    ///   - rateLimit: UDP response rate limiting; nil turns it off.
    public init(source: any DNSZoneSource, forwarder: DNSForwarder?, initialSerial: UInt32? = nil,
                updatePolicy: DNSUpdatePolicy = .ownAddress, recursion: DNSRecursionPolicy = .connectedNetworks,
                rateLimit: DNSRateLimit? = DNSRateLimit(),
                uptime: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
                updateMode: DNSDynamicUpdateMode = .secureAndNonsecure, secure: DNSSecureUpdateConfig? = nil,
                onEvent: (@Sendable (String) -> Void)? = nil) {
        self.source = source
        self.forwarder = forwarder
        self.updatePolicy = updatePolicy
        self.updateMode = updateMode
        self.secure = secure
        self.gssKeys = DNSGSSKeyTable(limit: secure?.maxContexts ?? 1)
        self.onEvent = onEvent
        self.recursion = recursion
        self.rateLimiter = rateLimit.map(DNSRateLimiter.init)
        self.uptime = uptime
        self.serial = initialSerial ?? UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))
    }

    /// Settings ▸ DNS "Dynamic updates", applied live.
    public func setUpdateMode(_ mode: DNSDynamicUpdateMode) {
        updateMode = mode
    }

    /// Established or pending TKEY contexts (tests, diagnostics).
    public var gssContextCount: Int { gssKeys.count }

    // MARK: Entry points

    /// Handles one wire message; nil means "send nothing" (responses, runts).
    public func handle(_ bytes: [UInt8], transport: DNSTransport, from: String) async -> [UInt8]? {
        let request: DNSMessage
        do {
            request = try DNSMessage(bytes: bytes)
        } catch {
            // FORMERR with the request's ID and opcode, if the header is there and it is a query.
            guard bytes.count >= 12, bytes[2] & 0x80 == 0 else { return nil }
            Self.logger.info("FORMERR to \(from, privacy: .public): \(String(describing: error), privacy: .public)")
            let id = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
            let reply = DNSMessage(id: id, isResponse: true, opcode: DNSOpcode(rawValue: bytes[2] >> 3 & 0x0F),
                                   recursionDesired: bytes[2] & 0x01 != 0, rcode: .formErr)
            return try? reply.encode()
        }
        guard !request.isResponse else { return nil }
        let signed: DNSWireTSIG.Signed?
        do { signed = try DNSWireTSIG.split(bytes) } catch {
            Self.logger.info("FORMERR to \(from, privacy: .public): \(String(describing: error), privacy: .public)")
            return try? request.responseSkeleton(rcode: .formErr).encode()
        }
        // RRL: UDP only (TCP cannot be spoofed and is how a slipped client retries).
        if transport == .udp, var limiter = rateLimiter, let client = DNSAddress.sender(from), !client.isLoopback,
           let name = request.questions.first?.name {
            let verdict = limiter.check(client: client, name: name, now: uptime())
            rateLimiter = limiter
            switch verdict {
            case .answer: break
            case .drop: return nil
            case .slip:
                var slipped = request.responseSkeleton()
                slipped.truncated = true
                return try? slipped.encode()
            }
        }
        let outcome = await process(request, signed: signed, transport: transport, from: from)
        return Self.finish(outcome, limit: Self.sizeLimit(for: request, transport: transport))
    }

    /// Builds the response message (before size limiting and before any TSIG is appended). A
    /// TSIG on `request` is checked against its re-encoding; `handle` checks the bytes as they
    /// travelled, which is what a real client's MAC covers.
    public func respond(to request: DNSMessage, transport: DNSTransport, from: String) async -> DNSMessage {
        let signed = request.additional.contains { $0.type == .tsig } && request.edns == nil
            ? (try? request.encode()).flatMap { try? DNSWireTSIG.split($0) } : nil
        return await process(request, signed: signed, transport: transport, from: from).message
    }

    /// A response and, for a signed exchange, how to sign it once encoded.
    struct Outcome {
        var message: DNSMessage
        var sign: SignPlan?
    }

    /// The TSIG to append to a response (RFC 8945 §5.3): signed with `context`, or (nil) an
    /// unsigned error TSIG with an empty MAC, as BADKEY and BADSIG answers are.
    struct SignPlan {
        var keyName: DNSName
        var algorithm: DNSName
        var context: (any GSSSecurityContext)?
        /// The request's MAC (RFC 8945 §4.3.1); nil for the TKEY reply, whose request is unsigned.
        var priorMAC: [UInt8]?
        var timeSigned: UInt64
        var error: DNSTSIGError = .noError
        var otherData: [UInt8] = []
    }

    private func process(_ request: DNSMessage, signed: DNSWireTSIG.Signed?, transport: DNSTransport,
                         from: String) async -> Outcome {
        var outcome: Outcome
        if let edns = request.edns, edns.version > 0 {
            outcome = Outcome(message: request.responseSkeleton(rcode: .badVers))
        } else {
            var signer: DNSUpdateSigner?
            var plan: SignPlan?
            var refusal: Outcome?
            if let signed {
                switch verify(signed, request: request, from: from) {
                case .refused(let failed): refusal = failed
                case let .verified(s, p): (signer, plan) = (s, p)
                }
            }
            if let refusal {
                outcome = refusal
            } else {
                switch request.opcode {
                case .query where request.questions.count == 1 && request.questions[0].type == .tkey:
                    outcome = await tkey(request, from: from)
                case .query:
                    outcome = Outcome(message: await query(request, transport: transport, from: from))
                case .update:
                    outcome = Outcome(message: await update(request, transport: transport, from: from, signer: signer))
                default:
                    outcome = Outcome(message: request.responseSkeleton(rcode: .notImp))
                }
                if let plan { outcome.sign = plan }
            }
        }
        outcome.message.recursionAvailable = forwarder != nil
        if let edns = request.edns {
            outcome.message.edns = DNSEDNS(udpPayloadSize: Self.ednsUDPSize, dnssecOK: edns.dnssecOK)
        } else {
            outcome.message.edns = nil
        }
        return outcome
    }

    /// Encodes `outcome` within `limit` bytes and appends its TSIG; the MAC covers the encoded
    /// response exactly as sent (RFC 8945 §4.3).
    static func finish(_ outcome: Outcome, limit: Int) -> [UInt8]? {
        guard let plan = outcome.sign else { return encode(outcome.message, limit: limit) }
        let reserve = plan.keyName.wireLength + plan.algorithm.wireLength + 10 + 16 + 64 + plan.otherData.count
        guard let bytes = encode(outcome.message, limit: max(64, limit - reserve)) else { return nil }
        var tsig = DNSTSIG(algorithm: plan.algorithm, timeSigned: plan.timeSigned, originalID: outcome.message.id,
                           error: plan.error.rawValue, otherData: plan.otherData)
        if let context = plan.context {
            let digest = tsig.digest(message: bytes, keyName: plan.keyName, priorMAC: plan.priorMAC)
            do { tsig.mac = try context.getMIC(digest) } catch {
                logger.error("cannot sign the response for \(plan.keyName, privacy: .public): \(String(describing: error), privacy: .public)")
            }
        }
        return DNSWireTSIG.append(tsig.record(keyName: plan.keyName), to: bytes)
    }

    /// The UDP reply limit: 512 without EDNS, else the client's size clamped to 512...4096.
    public static func sizeLimit(for request: DNSMessage, transport: DNSTransport) -> Int {
        if transport == .tcp { return 65535 }
        guard let edns = request.edns else { return 512 }
        return min(max(Int(edns.udpPayloadSize), 512), Int(ednsUDPSize))
    }

    /// Encodes `response` within `limit` bytes: first drop the additional section (no TC,
    /// RFC 2181 §9), then the answer and authority sections with TC set.
    public static func encode(_ response: DNSMessage, limit: Int) -> [UInt8]? {
        var r = response
        do {
            let full = try r.encode()
            if full.count <= limit { return full }
            r.additional = []
            let noAdditional = try r.encode()
            if noAdditional.count <= limit { return noAdditional }
            r.answers = []
            r.authority = []
            r.truncated = true
            return try r.encode()
        } catch {
            logger.error("cannot encode response: \(String(describing: error), privacy: .public)")
            var failure = response.responseSkeleton(rcode: .servFail)
            failure.edns = response.edns
            return try? failure.encode()
        }
    }

    // MARK: Zone view

    /// The zones we serve, most specific first.
    private func zones(_ info: DNSDomainInfo) -> [DNSName] {
        info.servedZones.sorted { $0.labels.count > $1.labels.count }
    }

    private func zone(for name: DNSName, info: DNSDomainInfo) -> DNSName? {
        zones(info).first { name.isSubdomain(of: $0) }
    }

    private func generatedRecords(_ info: DNSDomainInfo) -> [DNSName: [DNSRecord]] {
        if let g = generated, g.info == info, g.serial == serial { return g.records }
        let records = ADZoneGenerator.records(for: info, serial: serial)
        generated = (info, serial, records)
        return records
    }

    /// Generated records of `zone` plus the source's stored ones (duplicates of generated data dropped).
    func view(zone: DNSName, info: DNSDomainInfo) async -> (all: [DNSRecord], generated: [DNSRecord]) {
        let fixed = generatedRecords(info)[zone] ?? []
        let stored = await source.records(zone: zone).filter { r in
            r.name.isSubdomain(of: zone) && self.zone(for: r.name, info: info) == zone
                && !fixed.contains { $0.sameData(as: r) }
        }
        return (fixed + stored, fixed)
    }

    private func soa(of zone: DNSName, info: DNSDomainInfo) -> DNSRecord {
        ADZoneGenerator.soa(zone: zone, info: info, serial: serial)
    }

    /// The SOA for a negative answer: TTL = min(SOA TTL, MINIMUM) (RFC 2308 §5).
    private func negativeSOA(_ zone: DNSName, info: DNSDomainInfo) -> DNSRecord {
        var s = soa(of: zone, info: info)
        if case .soa(let data) = s.rdata { s.ttl = min(s.ttl, data.minimum) }
        return s
    }

    // MARK: QUERY

    private func query(_ request: DNSMessage, transport: DNSTransport, from: String) async -> DNSMessage {
        guard request.questions.count == 1, let q = request.questions.first else {
            return request.responseSkeleton(rcode: .formErr)
        }
        guard q.qclass == .in || q.qclass == .any else { return request.responseSkeleton(rcode: .refused) }
        switch q.type {
        case .axfr, .ixfr, .tkey:
            // No zone transfers. TKEY is answered by `tkey` (only a lone TKEY question gets there).
            Self.logger.info("\(q.type, privacy: .public) \(q.name, privacy: .public) from \(from, privacy: .public): refused")
            return request.responseSkeleton(rcode: .refused)
        case .maila, .mailb, .opt, .tsig:
            return request.responseSkeleton(rcode: .notImp)
        default: break
        }
        let info = await source.domainInfo()
        let zone = zone(for: q.name, info: info)
        if DNSBlockList.isBlocked(q.name) {
            // Global query block list: only an administrator's static record is answered.
            var allowed = false
            if let zone { allowed = await source.hasStaticRecords(name: q.name, zone: zone) }
            if !allowed {
                Self.logger.info("\(q.type, privacy: .public) \(q.name, privacy: .public) from \(from, privacy: .public): NXDOMAIN (global query block list)")
                var blocked = request.responseSkeleton(rcode: .nxDomain)
                if let zone {
                    blocked.authoritative = true
                    blocked.authority = [negativeSOA(zone, info: info)]
                }
                return blocked
            }
        }
        guard let zone else {
            return await forward(request, info: info, from: from)
        }

        var response = request.responseSkeleton()
        response.authoritative = true
        var name = q.name
        var currentZone = zone
        for _ in 0..<Self.maxChain {
            let records = await view(zone: currentZone, info: info).all
            let atName = records.filter { $0.name == name }
            if atName.isEmpty {
                // Empty non-terminal (e.g. `_tcp.lab.sheep`) is NODATA, anything else NXDOMAIN.
                let exists = records.contains { $0.name.isSubdomain(of: name) }
                response.rcode = exists ? .noError : .nxDomain
                response.authority = [negativeSOA(currentZone, info: info)]
                break
            }
            var matching = q.type == .any ? atName : atName.filter { $0.type == q.type }
            if q.type == .any, transport == .udp, let firstType = matching.first?.type {
                matching = matching.filter { $0.type == firstType }       // RFC 8482 §4.1: one RRset
            }
            if !matching.isEmpty {
                response.answers += matching
                break
            }
            if let cname = atName.first(where: { $0.type == .cname }), case .cname(let target) = cname.rdata {
                response.answers.append(cname)
                guard let next = self.zone(for: target, info: info) else { break }
                name = target
                currentZone = next
                continue
            }
            response.authority = [negativeSOA(currentZone, info: info)]      // NODATA
            break
        }
        response.additional = await additionalAddresses(for: response.answers, info: info)
        Self.logger.debug("\(q.type, privacy: .public) \(q.name, privacy: .public) from \(from, privacy: .public): \(response.rcode, privacy: .public) \(response.answers.count) answers")
        return response
    }

    /// A/AAAA of SRV, MX and NS targets that live in our zones (RFC 2782 "additional data").
    private func additionalAddresses(for answers: [DNSRecord], info: DNSDomainInfo) async -> [DNSRecord] {
        var targets: [DNSName] = []
        for r in answers {
            switch r.rdata {
            case .srv(let s): targets.append(s.target)
            case .mx(_, let e): targets.append(e)
            case .ns(let n): targets.append(n)
            default: break
            }
        }
        var out: [DNSRecord] = []
        for target in Set(targets).sorted() {
            guard let zone = zone(for: target, info: info) else { continue }
            out += await view(zone: zone, info: info).all.filter {
                $0.name == target && ($0.type == .a || $0.type == .aaaa)
            }
        }
        return out
    }

    private func forward(_ request: DNSMessage, info: DNSDomainInfo, from: String) async -> DNSMessage {
        guard let forwarder, request.recursionDesired else { return request.responseSkeleton(rcode: .refused) }
        guard await mayRecurse(from, info: info) else {
            Self.logger.info("recursion for \(request.questions.first?.name.description ?? "?", privacy: .public) from \(from, privacy: .public): REFUSED (not an allowed client network)")
            return request.responseSkeleton(rcode: .refused)
        }
        do {
            return try await forwarder.resolve(request)
        } catch {
            Self.logger.notice("forwarding \(request.questions.first?.name.description ?? "?", privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return request.responseSkeleton(rcode: .servFail)
        }
    }

    /// Whether `from` may have a foreign name forwarded: loopback and the DC's addresses always,
    /// else `recursion` decides.
    func mayRecurse(_ from: String, info: DNSDomainInfo) async -> Bool {
        guard case .allowed(let check) = recursion else { return true }
        guard let client = DNSAddress.sender(from) else { return false }
        if client.isLoopback || info.addresses.contains(client) { return true }
        return await check(client)
    }

    // MARK: UPDATE (RFC 2136)

    /// Whether an update may do anything RFC 2136 allows: `.open`, or TCP (the handshake proves
    /// the source address) from loopback or one of the DC's own addresses.
    static func isPrivileged(_ policy: DNSUpdatePolicy, transport: DNSTransport, from: String, info: DNSDomainInfo) -> Bool {
        if policy == .open { return true }
        guard transport == .tcp, let sender = DNSAddress.sender(from) else { return false }
        return sender.isLoopback || info.addresses.contains(sender)
    }

    private func update(_ request: DNSMessage, transport: DNSTransport, from: String,
                        signer: DNSUpdateSigner? = nil) async -> DNSMessage {
        var response = request.responseSkeleton()
        guard request.zone.count == 1, let z = request.zone.first, z.type == .soa else {
            response.rcode = .formErr
            return response
        }
        let how = signer.map { "\($0.accountName) (secure)" } ?? "\(from) (nonsecure)"
        let first = request.updates.first.map { "\($0.name)" } ?? "\(z.name)"
        func refuse(_ reason: String) -> DNSMessage {
            Self.logger.notice("update for \(z.name, privacy: .public) from \(from, privacy: .public) over \(transport.rawValue, privacy: .public) by \(how, privacy: .public): REFUSED (\(reason, privacy: .public))")
            onEvent?("UPDATE \(first) refused for \(signer == nil ? "" : "\(from) ")\(how): \(reason)")
            response.rcode = .refused
            return response
        }
        switch updateMode {
        case .off:
            return refuse("dynamic updates are off")
        case .secureOnly where signer == nil:
            return refuse("unsigned update (Dynamic updates: Secure only; Windows retries with GSS-TSIG)")
        default:
            break
        }
        let info = await source.domainInfo()
        let updatable = signer == nil ? info.zones : info.zones + info.reverseZones
        guard z.qclass == .in, updatable.contains(z.name) else {
            response.rcode = .notAuth
            return response
        }
        let zone = z.name
        if let blocked = request.updates.first(where: { $0.rrClass == .in && DNSBlockList.isBlocked($0.name) }) {
            return refuse("\(blocked.name) is on the global query block list")
        }
        let privileged = signer == nil && Self.isPrivileged(updatePolicy, transport: transport, from: from, info: info)
        if let signer {
            if let reason = await secureUpdateRefusal(request, zone: zone, info: info, signer: signer) {
                return refuse(reason)
            }
        } else if !privileged, let reason = await unsignedUpdateRefusal(request, zone: zone, info: info, from: from) {
            return refuse(reason)
        }
        response.rcode = await applyUpdate(request, zone: zone, info: info, from: from, secure: signer != nil)
        if response.rcode == .noError {
            if let signer {
                await recordOwners(request, zone: zone, info: info, owner: signer.holder)
            } else if updatePolicy == .ownAddress {
                await recordOwners(request, zone: zone, info: info, owner: privileged ? nil : DNSAddress.sender(from).map { .address($0) })
            }
            if let summary = Self.summary(request.updates) {
                onEvent?("UPDATE \(summary) \(signer == nil ? "from" : "by") \(how)")
            }
        }
        return response
    }

    /// `laptop-7.lab.sheep A 192.168.99.20` for the records an update adds (or, when it only
    /// deletes, `delete laptop-7.lab.sheep A`).
    static func summary(_ updates: [DNSRecord]) -> String? {
        let adds = updates.filter { $0.rrClass == .in }
        if !adds.isEmpty {
            return adds.map { r -> String in
                switch r.rdata {
                case .a(let a), .aaaa(let a): "\(r.name) \(r.type) \(a)"
                case .ptr(let n), .cname(let n): "\(r.name) \(r.type) \(n)"
                default: "\(r.name) \(r.type)"
                }
            }.joined(separator: ", ")
        }
        guard !updates.isEmpty else { return nil }
        return "delete " + updates.map { "\($0.name) \($0.type == .any ? "all" : $0.type.description)" }.joined(separator: ", ")
    }

    /// After an update: the sender that added records owns the name (refreshed on every
    /// registration) — its address for an unsigned update, its account for a secure one; a
    /// privileged add makes it the DC's (no owner); a name left without records has no owner.
    private func recordOwners(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo, owner: DNSRecordOwner.Holder?) async {
        let current = await view(zone: zone, info: info).all
        var seen = Set<DNSName>()
        for u in request.updates {
            let name = DNSName(labels: u.name.canonicalLabels)
            guard seen.insert(name).inserted else { continue }
            let added = request.updates.contains { $0.rrClass == .in && DNSName(labels: $0.name.canonicalLabels) == name }
            let remaining = current.contains { DNSName(labels: $0.name.canonicalLabels) == name }
            do {
                if !remaining {
                    try await source.setDynamicOwner(nil, name: name, zone: zone)
                } else if added {
                    try await source.setDynamicOwner(owner, name: name, zone: zone)
                }
            } catch {
                Self.logger.error("cannot record the owner of \(name, privacy: .public): \(String(describing: error), privacy: .public)")
            }
        }
    }

    /// Why an unprivileged update from `from` is refused under `.ownAddress`; nil when it may go
    /// ahead. Windows members register their own A/AAAA this way; everything else a member might
    /// send (SRV, CNAME, other hosts' names) is refused, which Windows logs and ignores. This
    /// applies to the DC's own addresses too when the update came over UDP (spoofable).
    func unsignedUpdateRefusal(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo, from: String,
                               now: Date = Date()) async -> String? {
        guard let sender = DNSAddress.sender(from) else { return "sender \(from) is not an address" }
        guard zone == info.dnsDomain else { return "only the DC updates \(zone)" }
        let current = await view(zone: zone, info: info)
        let pinnedNames = Set(current.generated.map { DNSName(labels: $0.name.canonicalLabels) })
        var checked = Set<DNSName>()
        for u in request.updates {
            let name = DNSName(labels: u.name.canonicalLabels)
            // Phase 5 (RFC 4703): a name the DHCP server registered (it holds a DHCID) may only
            // be changed by the host that holds the lease — the address in its A/AAAA.
            let owned = current.all.filter { DNSName(labels: $0.name.canonicalLabels) == name }
            let holders = owned.compactMap { r -> DNSAddress? in
                switch r.rdata {
                case .a(let a), .aaaa(let a): a.unmapped
                default: nil
                }
            }
            if owned.contains(where: { $0.type == .dhcid }) {
                if !holders.contains(sender) { return "\(u.name) is held by a DHCP lease of another host" }
            } else if checked.insert(name).inserted, !pinnedNames.contains(name) {
                // Per-name ownership: only the client that registered a name may replace or
                // delete it (no delete-then-replace of another host's name), never a static name.
                if await source.hasStaticRecords(name: name, zone: zone) { return "\(u.name) is a static name" }
                if let owner = await source.dynamicOwner(name: name, zone: zone) {
                    if owner.holder != .address(sender), now.timeIntervalSince(owner.updated) < Self.ownerLifetime {
                        if case .account(_, let account) = owner.holder {
                            return "\(u.name) was registered by \(account) with a secure update"
                        }
                        return "\(u.name) was registered by \(owner.holder)"
                    }
                } else if holders.contains(where: { $0 != sender }) {
                    // Registered before owners were recorded: its addresses say whose it is.
                    return "\(u.name) belongs to another host"
                }
            }
            if let reason = Self.reservedNameReason(u.name, zone: zone, info: info, generated: pinnedNames) { return reason }
            switch u.rrClass {
            case .in:
                switch u.rdata {
                case .a(let a), .aaaa(let a):
                    if a != sender { return "\(u.name) \(u.type) \(a) is not the sender's address" }
                default:
                    return "\(u.type) records are not accepted unsigned"
                }
            case .any, .none:
                guard [.a, .aaaa, .any].contains(u.type) else { return "\(u.type) records are not accepted unsigned" }
                if case .a(let a) = u.rdata, a != sender { return "deleting another address" }
                if case .aaaa(let a) = u.rdata, a != sender { return "deleting another address" }
            default:
                return "class \(u.rrClass)"
            }
        }
        return nil
    }

    /// The pin check shared by unsigned updates and the DHCP server's dynamic DNS: nil when a
    /// host may hold `name` in `zone`; otherwise why not — the zone apex, `_` service names, the
    /// DC's host name and its former names, and every name the zone generator produces
    /// (`gc._msdcs`, the DSA CNAME, …). `generated` defaults to the generator's names in every
    /// zone of `info`.
    public static func reservedNameReason(_ name: DNSName, zone: DNSName, info: DNSDomainInfo,
                                          generated: Set<DNSName>? = nil) -> String? {
        if name == zone || name == info.dnsDomain { return "the zone apex" }
        if name.labels.contains(where: { $0.first == UInt8(ascii: "_") }) { return "service name \(name)" }
        if DNSBlockList.isBlocked(name) { return "\(name) is on the global query block list (wpad, isatap)" }
        let pinned = generated ?? generatedNames(info)
        if name == info.dcHostName || info.formerHostNames.contains(name) || pinned.contains(name) {
            return "\(name) belongs to the DC"
        }
        return nil
    }

    /// Every owner name `ADZoneGenerator` produces for `info` (with a placeholder address when
    /// `info` has none, so the DC's A/AAAA owners are included).
    public static func generatedNames(_ info: DNSDomainInfo) -> Set<DNSName> {
        var i = info
        if i.addresses.isEmpty, let a = DNSAddress("127.0.0.1") { i.addresses = [a] }
        return Set(ADZoneGenerator.records(for: i, serial: 0).values.joined().map(\.name))
    }

    /// Removes `victims` from the source, except generated (pinned) records. True when any went.
    private func deleteStored(pinned: [DNSRecord], zone: DNSName, log: inout [String], _ victims: [DNSRecord]) async throws -> Bool {
        var removed = false
        for v in victims {
            if pinned.contains(where: { $0.sameData(as: v) }) {
                log.append("keep generated \(v)")
                continue
            }
            try await source.removeDynamic(v, zone: zone)
            removed = true
            log.append("delete \(v)")
        }
        return removed
    }

    private func applyUpdate(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo, from: String,
                             secure: Bool = false) async -> DNSRCode {
        let inZone: (DNSName) -> Bool = { self.zone(for: $0, info: info) == zone }

        // §3.2 prerequisites.
        var records = await view(zone: zone, info: info).all
        var valueDependent: [DNSRecord] = []
        for p in request.prerequisites {
            guard p.ttl == 0 else { return .formErr }
            guard inZone(p.name) else { return .notZone }
            let atName = records.filter { $0.name == p.name }
            switch p.rrClass {
            case .any:
                guard p.rdata == .empty else { return .formErr }
                if p.type == .any {
                    if atName.isEmpty { return .nxDomain }
                } else if !atName.contains(where: { $0.type == p.type }) {
                    return .nxRRSet
                }
            case .none:
                guard p.rdata == .empty else { return .formErr }
                if p.type == .any {
                    if !atName.isEmpty { return .yxDomain }
                } else if atName.contains(where: { $0.type == p.type }) {
                    return .yxRRSet
                }
            case .in:
                guard !p.type.isMeta else { return .formErr }
                valueDependent.append(p)
            default:
                return .formErr
            }
        }
        let groups = Dictionary(grouping: valueDependent) { DNSQuestion(name: $0.name, type: $0.type) }
        for (key, wanted) in groups {
            let have = Set(records.filter { $0.name == key.name && $0.type == key.type }.map(\.rdata))
            guard have == Set(wanted.map(\.rdata)) else { return .nxRRSet }
        }

        // §3.4.1 prescan.
        for u in request.updates {
            guard inZone(u.name) else { return .notZone }
            switch u.rrClass {
            case .in:
                guard !u.type.isMeta, u.rdata != .empty else { return .formErr }
            case .any:
                guard u.ttl == 0, u.rdata == .empty, !u.type.isMeta || u.type == .any else { return .formErr }
            case .none:
                guard u.ttl == 0, !u.type.isMeta else { return .formErr }
            default:
                return .formErr
            }
        }

        // §3.4.2 apply, in order, each against the result of the previous ones.
        var changed = false
        var log: [String] = []
        do {
            for u in request.updates {
                let current = await view(zone: zone, info: info)
                records = current.all
                let pinned = current.generated
                let atName = records.filter { $0.name == u.name }
                let isApex = u.name == zone
                switch u.rrClass {
                case .in:
                    if u.type == .soa { log.append("ignore SOA \(u.name)"); continue }
                    if u.type == .cname, atName.contains(where: { $0.type != .cname }) { log.append("ignore CNAME at \(u.name)"); continue }
                    if u.type != .cname, atName.contains(where: { $0.type == .cname }) { log.append("ignore \(u.type) at CNAME \(u.name)"); continue }
                    if pinned.contains(where: { $0.sameData(as: u) }) { continue }
                    if u.type == .cname, pinned.contains(where: { $0.name == u.name && $0.type == .cname }) {
                        log.append("keep generated CNAME \(u.name)")
                        continue
                    }
                    if u.type == .cname {
                        if try await deleteStored(pinned: pinned, zone: zone, log: &log, atName.filter { $0.type == .cname && !$0.sameData(as: u) }) { changed = true }
                    }
                    var record = u
                    record.rrClass = .in
                    try await source.addDynamic(record, zone: zone)
                    changed = true
                    log.append("add \(record)")
                case .any:
                    if u.type == .any {
                        if try await deleteStored(pinned: pinned, zone: zone, log: &log, atName.filter { !(isApex && ($0.type == .soa || $0.type == .ns)) }) { changed = true }
                    } else if !(isApex && (u.type == .soa || u.type == .ns)) {
                        if try await deleteStored(pinned: pinned, zone: zone, log: &log, atName.filter { $0.type == u.type }) { changed = true }
                    }
                case .none:
                    if u.type == .soa { continue }
                    let matches = atName.filter { $0.type == u.type && $0.rdata == u.rdata }
                    if isApex, u.type == .ns, atName.filter({ $0.type == .ns }).count <= matches.count { continue }
                    if try await deleteStored(pinned: pinned, zone: zone, log: &log, matches) { changed = true }
                default:
                    break
                }
            }
        } catch {
            Self.logger.error("update of \(zone, privacy: .public) from \(from, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return .servFail
        }
        if changed { serial &+= 1 }
        Self.logger.notice("\(secure ? "secure" : "unsecured", privacy: .public) update of \(zone, privacy: .public) from \(from, privacy: .public): \(log.isEmpty ? "no change" : log.joined(separator: "; "), privacy: .public)")
        return .noError
    }
}
