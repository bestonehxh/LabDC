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

    /// Whether every family binds (no `lsof`: cheap enough to poll while a port is released).
    public static func isFree(port: UInt16, protos: [Proto]) -> Bool {
        guard port != 0 else { return true }
        for proto in protos {
            for family in [AF_INET, AF_INET6] {
                if let e = bindError(port: port, proto: proto, family: family) {
                    if e == EADDRNOTAVAIL || e == EAFNOSUPPORT, family == AF_INET6 { continue }
                    return false
                }
            }
        }
        return true
    }

    /// `udp port 547 is in use (holder: X)` → `X` (nil for other messages).
    public static func holderName(in message: String) -> String? {
        guard let start = message.range(of: "(holder: ") else { return nil }
        var rest = message[start.upperBound...]
        if rest.hasSuffix(")") { rest = rest.dropLast() }
        return String(rest)
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
        if rows.isEmpty, let known = knownSystemHolder(port) { return known }
        return rows.isEmpty ? "not visible to this user; try sudo lsof -nP -i :\(port)" : Array(Set(rows)).sorted().joined(separator: "; ")
    }

    /// Root-owned holders lsof cannot show this user, named from the running process list
    /// (owner, 1 Oct 2026: UTM's Shared network started Internet Sharing, which holds udp 67, and
    /// udp 547 too; it kept running after UTM quit).
    static func knownSystemHolder(_ port: UInt16, running: (String) -> Bool = PortProbe.isRunning) -> String? {
        switch port {
        case 67:
            if running("InternetSharing") || running("bootpd") {
                return "macOS Internet Sharing (bootpd) — a VM on a Shared network (UTM, Parallels, VMware) or Settings ▸ General ▸ Sharing ▸ Internet Sharing turns it on; "
                    + "it may keep running after the VM quits. Switch the VM to Bridged, or turn Internet Sharing off in System Settings ▸ General ▸ Sharing (or log out) to release it"
            }
        case 547:
            if running("InternetSharing") {
                return "macOS Internet Sharing (InternetSharing, DHCPv6) — a VM on a Shared network (UTM, Parallels, VMware) or Settings ▸ General ▸ Sharing ▸ Internet Sharing turns it on; "
                    + "it may keep running after the VM quits. Turn Internet Sharing off in System Settings ▸ General ▸ Sharing (or log out) to release it"
            }
        default: break
        }
        return nil
    }

    /// `pgrep -x name` (root processes included).
    static func isRunning(_ name: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        p.arguments = ["-x", name]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }
}
