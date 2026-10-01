import Darwin

/// IPv4 enumeration (getifaddrs) and IP literal parsing.
public enum NetworkAddresses {
    /// Every IPv4 address of this Mac on an interface that is up, excluding loopback (127/8)
    /// and link-local (169.254/16). Sorted numerically, without duplicates.
    public static func currentIPv4() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return [] }
        defer { freeifaddrs(head) }
        var result = Set<UInt32>()
        var cursor = head
        while let ifa = cursor {
            cursor = ifa.pointee.ifa_next
            let flags = Int32(bitPattern: ifa.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let address = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let a = address >> 24, b = (address >> 16) & 0xFF
            if a == 127 || a == 0 { continue }
            if a == 169 && b == 254 { continue }
            result.insert(address)
        }
        return result.sorted().map { "\($0 >> 24).\(($0 >> 16) & 0xFF).\(($0 >> 8) & 0xFF).\($0 & 0xFF)" }
    }

    /// Parses an IPv4 (4 bytes) or IPv6 (16 bytes) literal. Returns nil for anything else.
    public static func parse(_ string: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, string, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, string, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }

    /// Formats 4 or 16 address bytes as text (IPv6 in the compressed form inet_ntop produces).
    public static func format(_ bytes: [UInt8]) -> String? {
        let family: Int32
        switch bytes.count {
        case 4: family = AF_INET
        case 16: family = AF_INET6
        default: return nil
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let ok = bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &buf, socklen_t(buf.count)) != nil
        }
        guard ok else { return nil }
        let end = buf.firstIndex(of: 0) ?? buf.count
        return String(decoding: buf[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
