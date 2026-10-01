import Darwin
import Foundation

/// Checks that a port is free before a listener binds it.
///
/// The KDC and kpasswd listeners (WP-E/WP-J `DualListener`) set `allowLocalEndpointReuse`, so
/// Network.framework would happily share 88/464 with another KDC (SO_REUSEPORT) and each would
/// get a random half of the requests. `serve` therefore probes them the way DNSKit and CLDAP do:
/// a plain BSD bind on `0.0.0.0` and `::` (UDP exclusive, TCP with SO_REUSEADDR so a TIME_WAIT
/// does not count).
public enum PortProbe {
    public enum Proto: String, Sendable { case udp, tcp }

    /// nil when free, else why (with the `lsof` holder when visible).
    public static func problem(port: UInt16, protos: [Proto]) -> String? {
        guard port != 0 else { return nil }
        for proto in protos {
            for family in [AF_INET, AF_INET6] {
                if let e = bindError(port: port, proto: proto, family: family) {
                    if e == EADDRNOTAVAIL || e == EAFNOSUPPORT, family == AF_INET6 { continue }
                    if e == EADDRINUSE {
                        return "\(proto.rawValue) port \(port) is in use (holder: \(holder(port)))"
                    }
                    return "\(proto.rawValue) port \(port): \(String(cString: strerror(e)))"
                }
            }
        }
        return nil
    }

    static func bindError(port: UInt16, proto: Proto, family: Int32) -> Int32? {
        let fd = socket(family, proto == .udp ? SOCK_DGRAM : SOCK_STREAM, 0)
        guard fd >= 0 else { return errno }
        defer { close(fd) }
        var one: Int32 = 1
        if proto == .tcp { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size)) }
        let rc: Int32
        if family == AF_INET {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        } else {
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            addr.sin6_addr = in6addr_any
            rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        return rc == 0 ? nil : errno
    }

    /// `lsof -nP -i :<port>` holders, or a hint when lsof shows nothing (other users' processes).
    static func holder(_ port: UInt16) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-i", ":\(port)"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return "unknown" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let rows = String(decoding: data, as: UTF8.self).split(separator: "\n").dropFirst().map { line -> String in
            let f = line.split(separator: " ", omittingEmptySubsequences: true)
            return f.count >= 9 ? "\(f[0]) pid \(f[1]) \(f[7]) \(f[8])" : String(line)
        }
        return rows.isEmpty ? "not visible to this user; try `sudo lsof -nP -i :\(port)`" : Array(Set(rows)).sorted().joined(separator: "; ")
    }
}
