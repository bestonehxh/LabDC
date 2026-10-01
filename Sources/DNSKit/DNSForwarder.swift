import Foundation
import Network
import Synchronization
import os

/// An upstream resolver address.
public struct DNSUpstream: Hashable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16 = 53) {
        self.host = host
        self.port = port
    }

    public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    /// Fallback when the system has no usable resolver.
    public static let cloudflare = DNSUpstream(host: "1.1.1.1")

    /// `nameserver` lines of a resolv.conf, loopback entries skipped (they would usually be
    /// us, or something that already holds port 53). Falls back to 1.1.1.1.
    public static func system(resolvConf path: String = "/etc/resolv.conf") -> [DNSUpstream] {
        let text = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        let found = parseResolvConf(text)
        return found.isEmpty ? [.cloudflare] : found
    }

    /// Parses `nameserver <address>` lines (scoped IPv6 like `fe80::1%en0` kept verbatim).
    public static func parseResolvConf(_ text: String) -> [DNSUpstream] {
        text.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 2, fields[0] == "nameserver" else { return nil }
            let host = String(fields[1])
            let bare = host.split(separator: "%").first.map(String.init) ?? host
            guard let address = DNSAddress(bare) else { return nil }
            if address.isIPv4 ? address.bytes[0] == 127 : address.bytes == [UInt8](repeating: 0, count: 15) + [1] {
                return nil
            }
            return DNSUpstream(host: host)
        }
    }
}

/// Forwards queries for foreign names to upstream resolvers and caches the answers by TTL.
///
/// UDP first (with EDNS 4096); a truncated reply is retried over TCP. Each upstream gets
/// `timeout`; on failure the next one is tried. Positive answers are cached for the
/// smallest TTL in the reply, NXDOMAIN/NODATA for the SOA's negative TTL (RFC 2308);
/// SERVFAIL and truncated replies are not cached.
public actor DNSForwarder {
    public let timeout: Duration
    public let cacheCapacity: Int
    private var cache: [CacheKey: CacheEntry] = [:]
    /// Upstream exchanges performed (cache misses), for tests and stats.
    public private(set) var upstreamQueries = 0
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "DNS")

    struct CacheKey: Hashable {
        var name: DNSName
        var type: DNSRecordType
        var qclass: DNSClass
    }

    struct CacheEntry {
        var rcode: DNSRCode
        var answers: [DNSRecord]
        var authority: [DNSRecord]
        var additional: [DNSRecord]
        var stored: ContinuousClock.Instant
        var expires: ContinuousClock.Instant
    }

    private let planProvider: @Sendable () -> DNSResolverPlan
    private let planRefresh: Duration
    private var plan: DNSResolverPlan
    private var planFetched: ContinuousClock.Instant

    /// A fixed list of upstreams.
    public init(upstreams: [DNSUpstream] = DNSUpstream.system(), timeout: Duration = .seconds(3), cacheCapacity: Int = 1000) {
        let fixed = DNSResolverPlan(defaults: upstreams)
        self.init(plan: { fixed }, refresh: .seconds(86400), timeout: timeout, cacheCapacity: cacheCapacity)
    }

    /// Upstreams from `plan`, asked again every `refresh` (the Mac's DNS changes with the network)
    /// and on `refreshPlan()`. A changed plan empties the cache.
    public init(plan: @escaping @Sendable () -> DNSResolverPlan, refresh: Duration = .seconds(10),
                timeout: Duration = .seconds(3), cacheCapacity: Int = 1000) {
        self.planProvider = plan
        self.planRefresh = refresh
        self.plan = plan()
        self.planFetched = .now
        self.timeout = timeout
        self.cacheCapacity = cacheCapacity
    }

    /// The default upstreams right now.
    public var upstreams: [DNSUpstream] { currentPlan().defaults }

    /// The plan in use, refreshed when it is older than `refresh`.
    public func currentPlan() -> DNSResolverPlan {
        if ContinuousClock.now - planFetched >= planRefresh { refreshPlan() }
        return plan
    }

    /// Asks the provider now (after a settings change); returns the plan.
    @discardableResult
    public func refreshPlan() -> DNSResolverPlan {
        let next = planProvider()
        planFetched = .now
        if next != plan {
            Self.logger.notice("forwarding to \(next.summary, privacy: .public) (was \(self.plan.summary, privacy: .public))")
            plan = next
            cache.removeAll()
        }
        return plan
    }

    public var cacheCount: Int { cache.count }

    /// Resolves `query` (one question) and returns a response carrying the query's ID.
    public func resolve(_ query: DNSMessage) async throws -> DNSMessage {
        guard query.questions.count == 1, let q = query.questions.first else {
            return query.responseSkeleton(rcode: .formErr)
        }
        let key = CacheKey(name: q.name, type: q.type, qclass: q.qclass)
        let now = ContinuousClock.now
        if let entry = cache[key] {
            if entry.expires > now {
                let elapsed = UInt32(max(0, (now - entry.stored).components.seconds))
                func age(_ records: [DNSRecord]) -> [DNSRecord] {
                    records.map { var r = $0; r.ttl = r.ttl > elapsed ? r.ttl - elapsed : 0; return r }
                }
                var response = query.responseSkeleton(rcode: entry.rcode)
                response.recursionAvailable = true
                response.answers = age(entry.answers)
                response.authority = age(entry.authority)
                response.additional = age(entry.additional)
                return response
            }
            cache[key] = nil
        }

        var outbound = DNSMessage(id: UInt16.random(in: 0...UInt16.max), recursionDesired: true,
                                  checkingDisabled: query.checkingDisabled, questions: [q],
                                  edns: DNSEDNS(udpPayloadSize: 4096))
        var lastError: any Error = DNSKitError.upstream("no upstream configured")
        for upstream in currentPlan().upstreams(for: q.name) {
            do {
                upstreamQueries += 1
                var reply = try await exchange(outbound, with: upstream)
                if reply.truncated {
                    outbound.id = UInt16.random(in: 0...UInt16.max)
                    reply = try await exchange(outbound, with: upstream, tcp: true)
                }
                store(reply, key: key)
                var response = query.responseSkeleton(rcode: reply.rcode)
                response.recursionAvailable = true
                response.authenticData = false
                response.answers = reply.answers
                response.authority = reply.authority
                response.additional = reply.additional
                return response
            } catch {
                Self.logger.notice("upstream \(upstream, privacy: .public) for \(q.name, privacy: .public): \(String(describing: error), privacy: .public)")
                lastError = error
            }
        }
        throw lastError
    }

    private func exchange(_ message: DNSMessage, with upstream: DNSUpstream, tcp: Bool = false) async throws -> DNSMessage {
        let bytes = try message.encode()
        let raw = tcp
            ? try await DNSExchange.tcp(bytes, host: upstream.host, port: upstream.port, timeout: timeout)
            : try await DNSExchange.udp(bytes, host: upstream.host, port: upstream.port, timeout: timeout)
        let reply = try DNSMessage(bytes: raw)
        guard reply.isResponse, reply.id == message.id, reply.questions == message.questions else {
            throw DNSKitError.upstream("reply from \(upstream) does not match the query")
        }
        guard reply.rcode != .servFail else { throw DNSKitError.upstream("\(upstream) answered SERVFAIL") }
        return reply
    }

    private func store(_ reply: DNSMessage, key: CacheKey) {
        guard cacheCapacity > 0, !reply.truncated else { return }
        let ttl: UInt32
        switch reply.rcode {
        case .noError where !reply.answers.isEmpty:
            ttl = reply.answers.map(\.ttl).min() ?? 0
        case .noError, .nxDomain:
            guard let soa = reply.authority.first(where: { $0.type == .soa }), case .soa(let data) = soa.rdata else { return }
            ttl = min(soa.ttl, data.minimum)
        default:
            return
        }
        guard ttl > 0 else { return }
        let now = ContinuousClock.now
        if cache.count >= cacheCapacity {
            cache = cache.filter { $0.value.expires > now }
            while cache.count >= cacheCapacity, let soonest = cache.min(by: { $0.value.expires < $1.value.expires }) {
                cache[soonest.key] = nil
            }
        }
        cache[key] = CacheEntry(rcode: reply.rcode, answers: reply.answers, authority: reply.authority,
                                additional: reply.additional, stored: now, expires: now + .seconds(Int(ttl)))
    }
}

/// One request/response exchange over Network.framework with a deadline.
enum DNSExchange {
    private static let queue = DispatchQueue(label: "dev.labdc.app.dns-exchange")

    /// Resumes a continuation once; later results are dropped. Cancels the connection.
    private final class Once: Sendable {
        private let state: Mutex<CheckedContinuation<[UInt8], any Error>?>
        private let connection: NWConnection
        init(_ c: CheckedContinuation<[UInt8], any Error>, connection: NWConnection) {
            state = Mutex(c)
            self.connection = connection
        }
        func finish(_ result: Result<[UInt8], any Error>) {
            let c = state.withLock { s -> CheckedContinuation<[UInt8], any Error>? in
                defer { s = nil }
                return s
            }
            guard let c else { return }
            connection.cancel()
            c.resume(with: result)
        }
    }

    private static func run(_ parameters: NWParameters, host: String, port: UInt16, timeout: Duration,
                            body: @escaping @Sendable (NWConnection, Once) -> Void) async throws -> [UInt8] {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw DNSKitError.upstream("bad port \(port)") }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        return try await withCheckedThrowingContinuation { c in
            let once = Once(c, connection: connection)
            let seconds = Double(timeout.components.seconds) + Double(timeout.components.attoseconds) / 1e18
            queue.asyncAfter(deadline: .now() + seconds) {
                once.finish(.failure(DNSKitError.upstream("\(host):\(port) timed out after \(timeout)")))
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: body(connection, once)
                case .failed(let e): once.finish(.failure(DNSKitError.upstream("\(host):\(port): \(e)")))
                case .waiting(let e): once.finish(.failure(DNSKitError.upstream("\(host):\(port): \(e)")))
                default: break
                }
            }
            connection.start(queue: queue)
        }
    }

    static func udp(_ bytes: [UInt8], host: String, port: UInt16, timeout: Duration) async throws -> [UInt8] {
        let id = Array(bytes.prefix(2))
        return try await run(.udp, host: host, port: port, timeout: timeout) { connection, once in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { once.finish(.failure(DNSKitError.upstream("send: \(error)"))) }
            })
            @Sendable func receive() {
                connection.receiveMessage { data, _, _, error in
                    if let data, data.count >= 12, Array(data.prefix(2)) == id {
                        once.finish(.success([UInt8](data)))
                    } else if let error {
                        once.finish(.failure(DNSKitError.upstream("receive: \(error)")))
                    } else {
                        receive()                             // stray datagram: keep waiting
                    }
                }
            }
            receive()
        }
    }

    static func tcp(_ bytes: [UInt8], host: String, port: UInt16, timeout: Duration) async throws -> [UInt8] {
        try await run(.tcp, host: host, port: port, timeout: timeout) { connection, once in
            connection.send(content: Data(DNSTCPFraming.frame(bytes)), completion: .contentProcessed { error in
                if let error { once.finish(.failure(DNSKitError.upstream("send: \(error)"))) }
            })
            @Sendable func receive(_ buffer: DNSTCPFraming.Deframer) {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65537) { data, _, isComplete, error in
                    var buffer = buffer
                    if let data { buffer.append(data) }
                    if let message = buffer.next() {
                        once.finish(.success(message))
                    } else if isComplete || error != nil {
                        once.finish(.failure(DNSKitError.upstream("connection closed before a full reply")))
                    } else {
                        receive(buffer)
                    }
                }
            }
            receive(DNSTCPFraming.Deframer())
        }
    }
}
