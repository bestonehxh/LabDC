/// A domain name as a sequence of labels (RFC 1035 §3.1), without the root label.
///
/// Labels keep their original case for output; equality, hashing and zone matching are
/// ASCII case-insensitive (RFC 4343). The text form has no trailing dot; the root is ".".
public struct DNSName: Hashable, Sendable, CustomStringConvertible, ExpressibleByStringLiteral, Comparable {
    /// Labels from the leftmost (most specific) to the rightmost; each 1...63 bytes.
    public let labels: [[UInt8]]

    public static let root = DNSName(labels: [])

    public init(labels: [[UInt8]]) { self.labels = labels }

    /// Parses dotted text (named `parsing:` so that `DNSName("x")` stays the literal form). A trailing dot is optional; `\.`, `\\` and `\DDD` escapes are honoured.
    public init(parsing text: String) throws {
        if text.isEmpty || text == "." { self.init(labels: []); return }
        var labels: [[UInt8]] = []
        var current: [UInt8] = []
        let bytes = Array(text.utf8)
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == UInt8(ascii: "\\") {
                guard i + 1 < bytes.count else { throw DNSKitError.invalidText("dangling escape in \(text)") }
                let n = bytes[i + 1]
                if (0x30...0x39).contains(n), i + 3 < bytes.count,
                   (0x30...0x39).contains(bytes[i + 2]), (0x30...0x39).contains(bytes[i + 3]) {
                    let v = Int(n - 0x30) * 100 + Int(bytes[i + 2] - 0x30) * 10 + Int(bytes[i + 3] - 0x30)
                    guard v <= 255 else { throw DNSKitError.invalidText("bad escape in \(text)") }
                    current.append(UInt8(v))
                    i += 4
                } else {
                    current.append(n)
                    i += 2
                }
                continue
            }
            if b == UInt8(ascii: ".") {
                guard !current.isEmpty else { throw DNSKitError.invalidText("empty label in \(text)") }
                labels.append(current)
                current = []
                i += 1
                if i == bytes.count { break }
                continue
            }
            current.append(b)
            i += 1
        }
        if !current.isEmpty { labels.append(current) }
        guard labels.allSatisfy({ $0.count <= 63 }) else { throw DNSKitError.invalidText("label longer than 63 bytes in \(text)") }
        let name = DNSName(labels: labels)
        guard name.wireLength <= 255 else { throw DNSKitError.invalidText("name longer than 255 bytes: \(text)") }
        self = name
    }

    /// Literal names must be valid; an invalid literal is a programming error.
    public init(stringLiteral value: String) {
        do { try self.init(parsing: value) } catch { preconditionFailure("invalid DNS name literal \(value): \(error)") }
    }

    /// Length of the uncompressed wire form, including the root byte.
    public var wireLength: Int { labels.reduce(1) { $0 + 1 + $1.count } }

    public var isRoot: Bool { labels.isEmpty }

    /// The name with the leftmost label removed (root stays root).
    public var parent: DNSName { labels.isEmpty ? self : DNSName(labels: Array(labels.dropFirst())) }

    /// `label.self`.
    public func prepending(_ label: String) -> DNSName {
        DNSName(labels: [Array(label.utf8)] + labels)
    }

    /// `self` followed by `suffix` (e.g. `"_ldap._tcp".appending(zone)`).
    public func appending(_ suffix: DNSName) -> DNSName { DNSName(labels: labels + suffix.labels) }

    /// True when `self` equals `zone` or lies below it.
    public func isSubdomain(of zone: DNSName) -> Bool {
        guard labels.count >= zone.labels.count else { return false }
        return DNSName(labels: Array(labels.suffix(zone.labels.count))) == zone
    }

    /// Lower-cased labels, the canonical form used for comparison.
    public var canonicalLabels: [[UInt8]] { labels.map { $0.map(Self.lower) } }

    /// Lower-cased text form.
    public var canonicalText: String { DNSName(labels: canonicalLabels).description }

    public var description: String {
        guard !labels.isEmpty else { return "." }
        return labels.map { label in
            var s = ""
            for b in label {
                switch b {
                case UInt8(ascii: "."), UInt8(ascii: "\\"): s += "\\" + String(UnicodeScalar(b))
                case 0x21...0x7E: s.append(Character(UnicodeScalar(b)))
                default:
                    let d = String(b)
                    s += "\\" + String(repeating: "0", count: 3 - d.count) + d
                }
            }
            return s
        }.joined(separator: ".")
    }

    public static func == (a: DNSName, b: DNSName) -> Bool {
        guard a.labels.count == b.labels.count else { return false }
        for (x, y) in zip(a.labels, b.labels) {
            guard x.count == y.count else { return false }
            for (p, q) in zip(x, y) where lower(p) != lower(q) { return false }
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        for label in labels {
            hasher.combine(label.count)
            for b in label { hasher.combine(Self.lower(b)) }
        }
    }

    /// Canonical DNS ordering (RFC 4034 §6.1): compare labels from the right, case-insensitively.
    public static func < (a: DNSName, b: DNSName) -> Bool {
        let x = Array(a.canonicalLabels.reversed()), y = Array(b.canonicalLabels.reversed())
        for (p, q) in zip(x, y) where p != q { return p.lexicographicallyPrecedes(q) }
        return x.count < y.count
    }

    @inline(__always) static func lower(_ b: UInt8) -> UInt8 { (0x41...0x5A).contains(b) ? b | 0x20 : b }
}
