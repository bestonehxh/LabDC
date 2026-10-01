import Foundation
import os

/// Who may send an unsigned dynamic update (audit 27 Sep 2026: any host could replace any record,
/// e.g. point `_ldap._tcp` or another member's name at itself).
public enum DNSUpdatePolicy: Sendable {
    /// From this Mac (loopback or one of the DC's addresses): anything outside the generated
    /// records. From anyone else: only A/AAAA records of the sender's own address, on an ordinary
    /// host name in the domain zone (not `_` names, not the DC, not `_msdcs`); deletes the same.
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
    /// Current SOA serial of both zones; bumped by every dynamic update that changes data.
    public private(set) var serial: UInt32
    private var generated: (info: DNSDomainInfo, serial: UInt32, records: [DNSName: [DNSRecord]])?
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "DNS")

    /// Largest UDP reply we send to an EDNS client, and the size we advertise.
    public static let ednsUDPSize: UInt16 = 4096
    /// Longest CNAME chain followed inside our zones.
    static let maxChain = 8

    public init(source: any DNSZoneSource, forwarder: DNSForwarder?, initialSerial: UInt32? = nil,
                updatePolicy: DNSUpdatePolicy = .ownAddress) {
        self.source = source
        self.forwarder = forwarder
        self.updatePolicy = updatePolicy
        self.serial = initialSerial ?? UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))
    }

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
        let response = await respond(to: request, transport: transport, from: from)
        return Self.encode(response, limit: Self.sizeLimit(for: request, transport: transport))
    }

    /// Builds the response message (before size limiting).
    public func respond(to request: DNSMessage, transport: DNSTransport, from: String) async -> DNSMessage {
        var response: DNSMessage
        if let edns = request.edns, edns.version > 0 {
            response = request.responseSkeleton(rcode: .badVers)
        } else {
            switch request.opcode {
            case .query: response = await query(request, transport: transport, from: from)
            case .update: response = await update(request, from: from)
            default: response = request.responseSkeleton(rcode: .notImp)
            }
        }
        response.recursionAvailable = forwarder != nil
        if let edns = request.edns {
            response.edns = DNSEDNS(udpPayloadSize: Self.ednsUDPSize, dnssecOK: edns.dnssecOK)
        } else {
            response.edns = nil
        }
        return response
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
            // No zone transfers. TKEY (the GSS-TSIG key exchange Windows starts before a
            // secure update; its key name need not be in our zones) is refused too.
            // TODO(GSS-TSIG, RFC 3645): TKEY negotiation via AuthKit's Kerberos acceptor.
            Self.logger.info("\(q.type, privacy: .public) \(q.name, privacy: .public) from \(from, privacy: .public): refused")
            return request.responseSkeleton(rcode: .refused)
        case .maila, .mailb, .opt, .tsig:
            return request.responseSkeleton(rcode: .notImp)
        default: break
        }
        let info = await source.domainInfo()
        guard let zone = zone(for: q.name, info: info) else {
            return await forward(request, from: from)
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

    private func forward(_ request: DNSMessage, from: String) async -> DNSMessage {
        guard let forwarder, request.recursionDesired else { return request.responseSkeleton(rcode: .refused) }
        do {
            return try await forwarder.resolve(request)
        } catch {
            Self.logger.notice("forwarding \(request.questions.first?.name.description ?? "?", privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return request.responseSkeleton(rcode: .servFail)
        }
    }

    // MARK: UPDATE (RFC 2136)

    private func update(_ request: DNSMessage, from: String) async -> DNSMessage {
        var response = request.responseSkeleton()
        guard request.zone.count == 1, let z = request.zone.first, z.type == .soa else {
            response.rcode = .formErr
            return response
        }
        if request.additional.contains(where: { $0.type == .tsig }) {
            // TODO(GSS-TSIG, RFC 3645): verify the TSIG with a GSS context from TKEY. Until
            // then signed updates are REFUSED; Windows then retries unsigned.
            Self.logger.notice("signed update for \(z.name, privacy: .public) from \(from, privacy: .public): REFUSED (GSS-TSIG not implemented)")
            response.rcode = .refused
            return response
        }
        let info = await source.domainInfo()
        guard z.qclass == .in, info.zones.contains(z.name) else {
            response.rcode = .notAuth
            return response
        }
        let zone = z.name
        if updatePolicy == .ownAddress, let reason = await unsignedUpdateRefusal(request, zone: zone, info: info, from: from) {
            Self.logger.notice("unsigned update for \(zone, privacy: .public) from \(from, privacy: .public): REFUSED (\(reason, privacy: .public))")
            response.rcode = .refused
            return response
        }
        response.rcode = await applyUpdate(request, zone: zone, info: info, from: from)
        return response
    }

    /// Why an unsigned update from `from` is refused under `.ownAddress`; nil when it may go ahead.
    /// Windows members register their own A/AAAA this way; everything else a member might send
    /// (SRV, CNAME, other hosts' names) is refused, which Windows logs and ignores.
    func unsignedUpdateRefusal(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo, from: String) async -> String? {
        let host = from.split(separator: "%", maxSplits: 1).first.map(String.init) ?? from
        guard let sender = DNSAddress(host) else { return "sender \(from) is not an address" }
        if Self.isLoopback(sender) || info.addresses.contains(sender) { return nil }
        guard zone == info.dnsDomain else { return "only the DC updates \(zone)" }
        let pinnedNames = Set(await view(zone: zone, info: info).generated.map { DNSName(labels: $0.name.canonicalLabels) })
        for u in request.updates {
            let name = DNSName(labels: u.name.canonicalLabels)
            if name == DNSName(labels: zone.canonicalLabels) { return "the zone apex" }
            if name.labels.contains(where: { $0.first == UInt8(ascii: "_") }) { return "service name \(u.name)" }
            if pinnedNames.contains(name) || name == DNSName(labels: info.dcHostName.canonicalLabels) {
                return "\(u.name) belongs to the DC"
            }
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

    static func isLoopback(_ a: DNSAddress) -> Bool {
        if a.bytes.count == 4 { return a.bytes[0] == 127 }
        return a.bytes == [UInt8](repeating: 0, count: 15) + [1]
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

    private func applyUpdate(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo, from: String) async -> DNSRCode {
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
        Self.logger.notice("unsecured update of \(zone, privacy: .public) from \(from, privacy: .public): \(log.isEmpty ? "no change" : log.joined(separator: "; "), privacy: .public)")
        return .noError
    }
}
