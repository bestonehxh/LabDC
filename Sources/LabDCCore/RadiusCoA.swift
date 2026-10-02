import Darwin
import Foundation
import RADIUSKit
import Store

/// What became of one CoA/Disconnect-Request.
public struct CoAResult: Sendable, Equatable {
    /// `CoA reauthenticate`, `CoA port bounce`, `Disconnect`.
    public var request: String
    /// nil = no valid reply (see `problem`).
    public var outcome: DynamicAuth.Outcome?
    public var problem: String?
    public var attempts: Int

    public var ok: Bool { outcome == .ack }

    /// `ACK`, `NAK (503 Session Context Not Found)`, `no reply after 3 tries`.
    public var text: String {
        if let outcome { return outcome.text }
        return problem ?? "no reply"
    }
}

/// RFC 5176 client: sends a CoA- or Disconnect-Request to a NAS's dynamic-authorization port
/// with the NAS's shared secret, retransmits the identical packet (same Identifier and
/// authenticator, RFC 5080 §2.2.1) on timeout, and accepts only a reply that verifies.
public enum RadiusCoAClient {
    public static let defaultTimeout: TimeInterval = 2
    public static let defaultAttempts = 3

    /// Sends `action` for `session` to `nas` (at the address the accounting came from).
    public static func send(_ action: CoAAction, session: DirectoryStore.RadiusSession, nas: DirectoryStore.NASClient,
                            now: Date = Date(), timeout: TimeInterval = defaultTimeout,
                            attempts: Int = defaultAttempts) async -> CoAResult {
        await send(action, session: session.coaSession, to: session.nasSource, port: nas.coaPort, vendor: nas.coaVendor,
                   secret: Array(nas.secret.utf8), now: now, timeout: timeout, attempts: attempts)
    }

    public static func send(_ action: CoAAction, session: CoASession, to host: String, port: UInt16, vendor: CoAVendor,
                            secret: [UInt8], now: Date = Date(), timeout: TimeInterval = defaultTimeout,
                            attempts: Int = defaultAttempts) async -> CoAResult {
        let plan = DynamicAuth.plan(action, vendor: vendor)
        let request: RADIUSPacket
        let bytes: [UInt8]
        do {
            request = try DynamicAuth.request(action, vendor: vendor, session: session, id: UInt8.random(in: 0...255),
                                              secret: secret, now: now)
            bytes = try request.encode()
        } catch {
            return CoAResult(request: plan.text, outcome: nil, problem: "cannot build the request (\(error))", attempts: 0)
        }
        return await withCheckedContinuation { (done: CheckedContinuation<CoAResult, Never>) in
            DispatchQueue.global(qos: .utility).async {
                done.resume(returning: exchange(bytes, request: request, host: host, port: port, secret: secret,
                                                timeout: timeout, attempts: max(1, attempts), text: plan.text))
            }
        }
    }

    /// Blocking: one UDP socket, `attempts` sends, each followed by up to `timeout` of waiting.
    private static func exchange(_ bytes: [UInt8], request: RADIUSPacket, host: String, port: UInt16, secret: [UInt8],
                                 timeout: TimeInterval, attempts: Int, text: String) -> CoAResult {
        guard let address = RADIUSAddress.bytes(host) else {
            return CoAResult(request: text, outcome: nil, problem: "\(host) is not an IP address", attempts: 0)
        }
        let v6 = address.count == 16
        let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return CoAResult(request: text, outcome: nil, problem: "socket: \(errno)", attempts: 0) }
        defer { close(fd) }
        var storage = sockaddr_storage()
        let length: socklen_t
        if v6 {
            var sa = sockaddr_in6()
            sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sa.sin6_family = sa_family_t(AF_INET6)
            sa.sin6_port = port.bigEndian
            withUnsafeMutableBytes(of: &sa.sin6_addr) { for (i, b) in address.enumerated() { $0[i] = b } }
            withUnsafeMutableBytes(of: &storage) { dst in withUnsafeBytes(of: sa) { dst.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        } else {
            var sa = sockaddr_in()
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_port = port.bigEndian
            withUnsafeMutableBytes(of: &sa.sin_addr) { for (i, b) in address.enumerated() { $0[i] = b } }
            withUnsafeMutableBytes(of: &storage) { dst in withUnsafeBytes(of: sa) { dst.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
        }
        var lastProblem: String?
        var buffer = [UInt8](repeating: 0, count: 4096)
        for attempt in 1...attempts {
            let sent = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, length) }
            }
            if sent != bytes.count { lastProblem = "send to \(host):\(port) failed (\(String(cString: strerror(errno))))" }
            let deadline = Date().addingTimeInterval(timeout)
            while true {
                let left = deadline.timeIntervalSinceNow
                if left <= 0 { break }
                var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let ready = poll(&pfd, 1, Int32(max(1, left * 1000)))
                if ready <= 0 { if ready < 0, errno != EINTR { break }; continue }
                var from = sockaddr_storage()
                var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let n = withUnsafeMutablePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &fromLength) }
                }
                if n <= 0 {
                    // ICMP port unreachable surfaces as ECONNREFUSED on some stacks: keep trying.
                    lastProblem = "\(host):\(port) refused (no CoA listener?)"
                    break
                }
                // Only the NAS address and port the request went to may answer (CVE audit
                // 1 Oct 2026): anything else on our ephemeral port is ignored unparsed.
                guard Self.endpoint(from, matches: address, port: port) else {
                    lastProblem = "reply from an address other than \(host):\(port) ignored"
                    continue
                }
                do {
                    let outcome = try DynamicAuth.outcome(of: Array(buffer.prefix(n)), for: request, secret: secret)
                    return CoAResult(request: text, outcome: outcome, problem: nil, attempts: attempt)
                } catch {
                    // A reply that does not verify is ignored (it may be forged); keep waiting.
                    lastProblem = "reply ignored: \(error)"
                }
            }
        }
        return CoAResult(request: text, outcome: nil,
                         problem: (lastProblem.map { "\($0); " } ?? "") + "no reply after \(attempts) tr\(attempts == 1 ? "y" : "ies")",
                         attempts: attempts)
    }

    /// Whether a datagram's source (`recvfrom`) is `address` (4 or 16 bytes) and `port`.
    static func endpoint(_ from: sockaddr_storage, matches address: [UInt8], port: UInt16) -> Bool {
        var from = from
        switch Int32(from.ss_family) {
        case AF_INET where address.count == 4:
            return withUnsafePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sa in
                    UInt16(bigEndian: sa.pointee.sin_port) == port
                        && withUnsafeBytes(of: sa.pointee.sin_addr) { Array($0) } == address
                }
            }
        case AF_INET6 where address.count == 16:
            return withUnsafePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sa in
                    UInt16(bigEndian: sa.pointee.sin6_port) == port
                        && withUnsafeBytes(of: sa.pointee.sin6_addr) { Array($0) } == address
                }
            }
        default:
            return false
        }
    }
}

/// Device facts for the policy engine: the DHCP profile of the MAC (via `DeviceProfileSource`)
/// plus the registered-devices list in the store.
public enum RadiusDeviceFacts {
    public static func lookup(mac: String, store: DirectoryStore, profiles: DeviceProfileSource) async -> DeviceFacts {
        var facts = DeviceFacts()
        if let profile = try? await profiles.deviceProfile(mac: mac) {
            facts.category = profile.category.rawValue
            facts.os = profile.os
            facts.vendorClass = profile.vendorClass
            facts.hostname = profile.hostname
        }
        if let device = try? await store.registeredDevice(mac: mac) {
            facts.registered = true
            facts.group = device.group
        }
        return facts
    }
}
