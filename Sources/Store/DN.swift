/// One `type=value` pair of an RDN. `value` is the unescaped string.
public struct AttributeTypeAndValue: Sendable, Hashable, CustomStringConvertible {
    public var type: String
    public var value: String

    public init(type: String, value: String) {
        self.type = type
        self.value = value
    }

    /// `CN=a\,b` (RFC 4514 escaping, the type as given).
    public var description: String { "\(type)=\(DN.escape(value))" }

    /// Lower-cased type (OIDs mapped to their short names), lower-cased escaped value.
    var normalized: String { "\(DN.normalizedType(type))=\(DN.escape(value.lowercased()))" }
}

/// A relative distinguished name: one or more `type=value` pairs joined by `+`.
public struct RDN: Sendable, CustomStringConvertible {
    public var components: [AttributeTypeAndValue]

    public init(components: [AttributeTypeAndValue]) {
        precondition(!components.isEmpty, "an RDN has at least one component")
        self.components = components
    }

    /// `RDN("CN", "alice")`.
    public init(_ type: String, _ value: String) {
        components = [AttributeTypeAndValue(type: type, value: value)]
    }

    /// Parses one RDN (`CN=alice`, `cn=a+sn=b`).
    public init(string: String) throws {
        let dn = try DN(string: string)
        guard dn.rdns.count == 1 else { throw StoreError.invalidDN("'\(string)' is not a single RDN") }
        self = dn.rdns[0]
    }

    /// The first (naming) attribute type.
    public var type: String { components[0].type }
    /// The first value.
    public var value: String { components[0].value }

    public var description: String { components.map(\.description).joined(separator: "+") }

    /// Components sorted so `cn=a+sn=b` and `sn=b+cn=a` compare equal.
    var normalized: String { components.map(\.normalized).sorted().joined(separator: "+") }
}

extension RDN: Hashable {
    public static func == (a: RDN, b: RDN) -> Bool { a.normalized == b.normalized }
    public func hash(into h: inout Hasher) { h.combine(normalized) }
}

/// A distinguished name (RFC 4514). `rdns[0]` is the leaf. Equality and hashing use the
/// normalised form (case-insensitive types and values, multi-valued RDNs sorted).
public struct DN: Sendable, CustomStringConvertible {
    public var rdns: [RDN]

    public init(rdns: [RDN]) { self.rdns = rdns }

    /// The empty DN (RootDSE).
    public static let root = DN(rdns: [])

    public var isRoot: Bool { rdns.isEmpty }

    /// RFC 4514 string with the types and value case as given.
    public var description: String { rdns.map(\.description).joined(separator: ",") }

    /// Lower-cased, canonically escaped, `cn=a,dc=lab,dc=sheep`. Used as the lookup key.
    public var normalized: String { rdns.map(\.normalized).joined(separator: ",") }

    /// The leaf RDN.
    public var rdn: RDN? { rdns.first }

    /// The DN without its leaf; nil for the root.
    public var parent: DN? { rdns.isEmpty ? nil : DN(rdns: Array(rdns.dropFirst())) }

    /// `rdn,self`.
    public func child(_ rdn: RDN) -> DN { DN(rdns: [rdn] + rdns) }

    /// True when `self` is `ancestor` or below it.
    public func isDescendant(of ancestor: DN, orSelf: Bool = true) -> Bool {
        guard rdns.count >= ancestor.rdns.count else { return false }
        if !orSelf && rdns.count == ancestor.rdns.count { return false }
        return Array(rdns.suffix(ancestor.rdns.count)) == ancestor.rdns
    }

    /// `DC=lab,DC=sheep` for `lab.sheep`.
    public init(dnsDomain: String) {
        rdns = dnsDomain.split(separator: ".").map { RDN("DC", String($0)) }
    }

    // MARK: - Parsing

    /// Parses an RFC 4514 DN. Lenient in the ways AD is: spaces around `,` `+` `=`, `;` as a
    /// separator, quoted values, `OID.` prefixes.
    public init(string: String) throws {
        var p = Parser(Array(string.utf8), original: string)
        rdns = try p.parseDN()
    }

    private struct Parser {
        let bytes: [UInt8]
        let original: String
        var i = 0

        init(_ bytes: [UInt8], original: String) {
            self.bytes = bytes
            self.original = original
        }

        func fail(_ why: String) -> StoreError { .invalidDN("'\(original)': \(why)") }

        var atEnd: Bool { i >= bytes.count }

        mutating func skipSpaces() { while !atEnd, bytes[i] == 0x20 { i += 1 } }

        mutating func parseDN() throws -> [RDN] {
            skipSpaces()
            if atEnd { return [] }
            var rdns: [RDN] = []
            while true {
                var comps: [AttributeTypeAndValue] = []
                while true {
                    comps.append(try parseATV())
                    skipSpaces()
                    if !atEnd, bytes[i] == UInt8(ascii: "+") { i += 1; continue }
                    break
                }
                rdns.append(RDN(components: comps))
                skipSpaces()
                if atEnd { return rdns }
                guard bytes[i] == UInt8(ascii: ",") || bytes[i] == UInt8(ascii: ";") else {
                    throw fail("unexpected character at \(i)")
                }
                i += 1
            }
        }

        mutating func parseATV() throws -> AttributeTypeAndValue {
            skipSpaces()
            let start = i
            while !atEnd, bytes[i] != UInt8(ascii: "="), bytes[i] != 0x20 { i += 1 }
            var type = String(decoding: bytes[start..<i], as: UTF8.self)
            if type.lowercased().hasPrefix("oid.") { type = String(type.dropFirst(4)) }
            guard DN.isValidType(type) else { throw fail("bad attribute type '\(type)'") }
            skipSpaces()
            guard !atEnd, bytes[i] == UInt8(ascii: "=") else { throw fail("missing '=' after \(type)") }
            i += 1
            skipSpaces()
            return AttributeTypeAndValue(type: type, value: try parseValue())
        }

        mutating func parseValue() throws -> String {
            if !atEnd, bytes[i] == UInt8(ascii: "#") { return try parseHexString() }
            if !atEnd, bytes[i] == UInt8(ascii: "\"") { return try parseQuoted() }
            var out: [UInt8] = []
            var lastSignificant = 0  // length of `out` up to the last escaped or non-space byte
            while !atEnd {
                let c = bytes[i]
                if c == UInt8(ascii: ",") || c == UInt8(ascii: "+") || c == UInt8(ascii: ";") { break }
                if c == UInt8(ascii: "\\") {
                    i += 1
                    guard !atEnd else { throw fail("dangling '\\'") }
                    if let h = hex(bytes[i]), i + 1 < bytes.count, let l = hex(bytes[i + 1]) {
                        out.append(h << 4 | l)
                        i += 2
                    } else {
                        out.append(bytes[i])
                        i += 1
                    }
                    lastSignificant = out.count
                    continue
                }
                out.append(c)
                i += 1
                if c != 0x20 { lastSignificant = out.count }
            }
            out.removeSubrange(lastSignificant...)
            guard let s = String(validating: out, as: UTF8.self) else { throw fail("value is not UTF-8") }
            return s
        }

        mutating func parseQuoted() throws -> String {
            i += 1
            var out: [UInt8] = []
            while true {
                guard !atEnd else { throw fail("unterminated quoted value") }
                let c = bytes[i]
                i += 1
                if c == UInt8(ascii: "\"") { break }
                if c == UInt8(ascii: "\\") {
                    guard !atEnd else { throw fail("dangling '\\'") }
                    out.append(bytes[i])
                    i += 1
                    continue
                }
                out.append(c)
            }
            guard let s = String(validating: out, as: UTF8.self) else { throw fail("value is not UTF-8") }
            return s
        }

        /// `#04056162636465` -> the BER string's contents when it is a string type, otherwise
        /// the `#hex` text itself.
        mutating func parseHexString() throws -> String {
            let start = i
            i += 1
            var raw: [UInt8] = []
            while i + 1 < bytes.count, let h = hex(bytes[i]), let l = hex(bytes[i + 1]) {
                raw.append(h << 4 | l)
                i += 2
            }
            guard !raw.isEmpty else { throw fail("empty hex value") }
            let text = String(decoding: bytes[start..<i], as: UTF8.self)
            // Tag, one short-form length byte, contents: OCTET STRING, UTF8String, PrintableString, IA5String.
            if raw.count >= 2, [0x04, 0x0C, 0x13, 0x16].contains(raw[0]), Int(raw[1]) == raw.count - 2,
               let s = String(validating: raw[2...], as: UTF8.self) {
                return s
            }
            return text
        }

        func hex(_ c: UInt8) -> UInt8? {
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
            default: nil
            }
        }
    }

    static func isValidType(_ t: String) -> Bool {
        let b = Array(t.utf8)
        guard let f = b.first else { return false }
        func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
        func isAlpha(_ c: UInt8) -> Bool { (c | 0x20) >= 0x61 && (c | 0x20) <= 0x7A }
        if isDigit(f) {
            return t.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
                !$0.isEmpty && $0.utf8.allSatisfy(isDigit)
            }
        }
        return isAlpha(f) && b.allSatisfy { isAlpha($0) || isDigit($0) || $0 == UInt8(ascii: "-") }
    }

    private static let oidNames: [String: String] = [
        "2.5.4.3": "cn", "0.9.2342.19200300.100.1.25": "dc", "2.5.4.11": "ou", "2.5.4.10": "o",
        "2.5.4.6": "c", "2.5.4.7": "l", "2.5.4.8": "st", "2.5.4.9": "street", "0.9.2342.19200300.100.1.1": "uid",
    ]

    static func normalizedType(_ t: String) -> String {
        let l = t.lowercased()
        return oidNames[l] ?? l
    }

    // MARK: - Escaping

    /// RFC 4514 §2.4 escaping: `"+,;<>\` always, `#` and space at the start, space at the end,
    /// control characters (and NUL) as `\XX` (AD writes the tombstone newline as `\0A`).
    public static func escape(_ value: String) -> String {
        let scalars = Array(value.unicodeScalars)
        var out = ""
        for (idx, s) in scalars.enumerated() {
            switch s {
            case "\"", "+", ",", ";", "<", ">", "\\":
                out += "\\" + String(s)
            case "#" where idx == 0:
                out += "\\#"
            case " " where idx == 0 || idx == scalars.count - 1:
                out += "\\ "
            default:
                if s.value < 0x20 || s.value == 0x7F {
                    out += "\\" + (s.value < 0x10 ? "0" : "") + String(s.value, radix: 16, uppercase: true)
                } else {
                    out.unicodeScalars.append(s)
                }
            }
        }
        return out
    }
}

extension DN: Hashable {
    public static func == (a: DN, b: DN) -> Bool { a.normalized == b.normalized }
    public func hash(into h: inout Hasher) { h.combine(normalized) }
}
