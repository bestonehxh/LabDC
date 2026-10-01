/// BER tag classes (X.690 §8.1.2.2).
public enum BERTagClass: UInt8, Sendable, Hashable {
    case universal = 0, application = 1, contextSpecific = 2, `private` = 3
}

/// An identifier octet(s): class, primitive/constructed, number.
public struct BERTag: Sendable, Hashable, CustomStringConvertible {
    public var tagClass: BERTagClass
    public var constructed: Bool
    public var number: UInt32

    public init(_ tagClass: BERTagClass, constructed: Bool, number: UInt32) {
        self.tagClass = tagClass
        self.constructed = constructed
        self.number = number
    }

    public static let boolean = BERTag(.universal, constructed: false, number: 1)
    public static let integer = BERTag(.universal, constructed: false, number: 2)
    public static let octetString = BERTag(.universal, constructed: false, number: 4)
    public static let null = BERTag(.universal, constructed: false, number: 5)
    public static let enumerated = BERTag(.universal, constructed: false, number: 10)
    public static let sequence = BERTag(.universal, constructed: true, number: 16)
    public static let set = BERTag(.universal, constructed: true, number: 17)

    public static func application(_ n: UInt32, constructed: Bool) -> BERTag {
        BERTag(.application, constructed: constructed, number: n)
    }

    public static func context(_ n: UInt32, constructed: Bool = false) -> BERTag {
        BERTag(.contextSpecific, constructed: constructed, number: n)
    }

    /// Same class and number, ignoring the constructed bit (strings may arrive constructed).
    public func sameType(as other: BERTag) -> Bool { tagClass == other.tagClass && number == other.number }

    public var description: String {
        let c: String
        switch tagClass {
        case .universal: c = "UNIVERSAL"
        case .application: c = "APPLICATION"
        case .contextSpecific: c = "CONTEXT"
        case .private: c = "PRIVATE"
        }
        return "[\(c) \(number)\(constructed ? " constructed" : "")]"
    }

    /// DER identifier octets.
    func encode(into out: inout [UInt8]) {
        let first = tagClass.rawValue << 6 | (constructed ? 0x20 : 0)
        if number < 31 {
            out.append(first | UInt8(number))
            return
        }
        out.append(first | 0x1F)
        var groups: [UInt8] = []
        var n = number
        repeat {
            groups.append(UInt8(n & 0x7F))
            n >>= 7
        } while n > 0
        for (i, g) in groups.reversed().enumerated() { out.append(i == groups.count - 1 ? g : g | 0x80) }
    }
}

/// One BER element: its tag and raw content octets. Constructed contents are parsed on demand
/// (`children()`), so a malformed inner element only fails the caller that looks at it.
///
/// Decoding is BER-lenient in the ways LDAP peers need (RFC 4511 §5.1): long-form and
/// non-minimal lengths, non-minimal INTEGERs, any non-zero BOOLEAN, constructed OCTET STRINGs.
/// Indefinite lengths are refused (LDAP forbids them). Encoding is always DER.
public struct BERElement: Sendable, Hashable {
    public var tag: BERTag
    public var content: [UInt8]

    public init(tag: BERTag, content: [UInt8]) {
        self.tag = tag
        self.content = content
    }

    /// Maximum nesting callers such as the filter decoder allow.
    public static let maxDepth = 64

    // MARK: Decoding

    /// Parses exactly one element; trailing bytes are an error.
    public init(bytes: [UInt8]) throws {
        var r = BERReader(bytes[...])
        self = try r.read()
        guard r.isAtEnd else { throw LDAPCoreError.malformed(what: "BER element", reason: "\(r.remaining) trailing bytes") }
    }

    /// Parses a concatenation of elements.
    public static func elements(of bytes: [UInt8]) throws -> [BERElement] {
        var r = BERReader(bytes[...])
        var out: [BERElement] = []
        while !r.isAtEnd { out.append(try r.read()) }
        return out
    }

    /// The total size (header + content) of the element at the start of `bytes`, or nil when
    /// more bytes are needed. Used by stream framers.
    /// - Throws: `tooLarge` when the element announces more than `limit` bytes; `malformed`
    ///   for indefinite or absurd lengths.
    public static func frameLength<C: Collection>(_ bytes: C, limit: Int) throws -> Int? where C.Element == UInt8 {
        var i = bytes.startIndex
        guard i != bytes.endIndex else { return nil }
        var headerLength = 1
        if bytes[i] & 0x1F == 0x1F {
            repeat {
                i = bytes.index(after: i)
                guard i != bytes.endIndex else { return nil }
                headerLength += 1
                if headerLength > 6 { throw LDAPCoreError.malformed(what: "BER tag", reason: "tag number too long") }
            } while bytes[i] & 0x80 != 0
        }
        i = bytes.index(after: i)
        guard i != bytes.endIndex else { return nil }
        let first = bytes[i]
        headerLength += 1
        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else if first == 0x80 {
            throw LDAPCoreError.malformed(what: "BER length", reason: "indefinite length")
        } else {
            let n = Int(first & 0x7F)
            guard n <= 8 else { throw LDAPCoreError.malformed(what: "BER length", reason: "\(n) length octets") }
            for _ in 0..<n {
                i = bytes.index(after: i)
                guard i != bytes.endIndex else { return nil }
                guard length <= (Int.max >> 8) else { throw LDAPCoreError.tooLarge(size: Int.max, limit: limit) }
                length = length << 8 | Int(bytes[i])
                headerLength += 1
            }
        }
        guard length <= limit, headerLength + length <= limit else {
            throw LDAPCoreError.tooLarge(size: length, limit: limit)
        }
        let total = headerLength + length
        return bytes.count >= total ? total : nil
    }

    /// The elements inside a constructed element.
    public func children() throws -> [BERElement] {
        guard tag.constructed else { throw LDAPCoreError.malformed(what: "\(tag)", reason: "primitive, expected constructed") }
        return try Self.elements(of: content)
    }

    /// The octets of a string-like element (OCTET STRING, LDAPString, context strings).
    /// A constructed string is the concatenation of its segments (X.690 §8.7.3).
    public func octets() throws -> [UInt8] { try octets(depth: 0) }

    private func octets(depth: Int) throws -> [UInt8] {
        guard tag.constructed else { return content }
        guard depth < 8 else { throw LDAPCoreError.nestingTooDeep(limit: 8) }
        var out: [UInt8] = []
        for c in try children() {
            guard c.tag.tagClass == .universal, c.tag.number == 4 else {
                throw LDAPCoreError.malformed(what: "constructed string", reason: "segment \(c.tag) is not an OCTET STRING")
            }
            out += try c.octets(depth: depth + 1)
        }
        return out
    }

    /// The content as UTF-8 text (LDAPString / LDAPOID / LDAPDN); invalid UTF-8 is replaced.
    public func string() throws -> String { String(decoding: try octets(), as: UTF8.self) }

    /// INTEGER / ENUMERATED as Int64; accepts redundant leading 00/FF octets.
    public func integer() throws -> Int64 {
        guard !tag.constructed else { throw LDAPCoreError.malformed(what: "INTEGER", reason: "constructed") }
        let minimal = try Self.minimalTwosComplement(content)
        guard minimal.count <= 8 else { throw LDAPCoreError.integerOverflow("\(minimal.count)-byte INTEGER") }
        var v: Int64 = minimal[0] & 0x80 != 0 ? -1 : 0
        for b in minimal { v = v << 8 | Int64(b) }
        return v
    }

    /// INTEGER as Int32 (message IDs, limits).
    public func int32() throws -> Int32 {
        let v = try integer()
        guard let r = Int32(exactly: v) else { throw LDAPCoreError.integerOverflow("\(v) does not fit 32 bits") }
        return r
    }

    /// INTEGER of any size: minimal big-endian two's complement.
    public func bigInteger() throws -> [UInt8] {
        guard !tag.constructed else { throw LDAPCoreError.malformed(what: "INTEGER", reason: "constructed") }
        return try Self.minimalTwosComplement(content)
    }

    /// BOOLEAN: one octet, any non-zero value is TRUE (BER).
    public func boolean() throws -> Bool {
        guard !tag.constructed, content.count == 1 else {
            throw LDAPCoreError.malformed(what: "BOOLEAN", reason: "\(content.count) content octets")
        }
        return content[0] != 0
    }

    static func minimalTwosComplement(_ bytes: [UInt8]) throws -> [UInt8] {
        guard !bytes.isEmpty else { throw LDAPCoreError.malformed(what: "INTEGER", reason: "empty") }
        var start = 0
        while start < bytes.count - 1 {
            let b = bytes[start], next = bytes[start + 1]
            if (b == 0x00 && next & 0x80 == 0) || (b == 0xFF && next & 0x80 != 0) { start += 1 } else { break }
        }
        return Array(bytes[start...])
    }

    /// Requires `expected` (string-like and context tags may arrive primitive or constructed).
    @discardableResult
    public func expect(_ expected: BERTag, _ what: String) throws -> BERElement {
        let lenient = expected == .octetString || expected.tagClass == .contextSpecific
        guard tag == expected || (lenient && tag.sameType(as: expected)) else {
            throw LDAPCoreError.unexpectedTag(expected: "\(what) \(expected)", found: tag)
        }
        return self
    }

    // MARK: Encoding (DER)

    public func encoded() -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(content.count + 6)
        encode(into: &out)
        return out
    }

    public func encode(into out: inout [UInt8]) {
        tag.encode(into: &out)
        Self.encodeLength(content.count, into: &out)
        out += content
    }

    static func encodeLength(_ n: Int, into out: inout [UInt8]) {
        if n < 0x80 {
            out.append(UInt8(n))
            return
        }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.append(UInt8(v & 0xFF))
            v >>= 8
        }
        out.append(0x80 | UInt8(bytes.count))
        out += bytes.reversed()
    }

    public static func boolean(_ v: Bool, tag: BERTag = .boolean) -> BERElement {
        BERElement(tag: tag, content: [v ? 0xFF : 0x00])
    }

    public static func integer(_ v: Int64, tag: BERTag = .integer) -> BERElement {
        var bytes: [UInt8] = []
        var x = v
        for _ in 0..<8 {
            bytes.append(UInt8(truncatingIfNeeded: x))
            x >>= 8
        }
        bytes.reverse()
        return BERElement(tag: tag, content: (try? minimalTwosComplement(bytes)) ?? [0])
    }

    /// An INTEGER from big-endian two's-complement octets (made minimal).
    public static func bigInteger(_ bytes: [UInt8], tag: BERTag = .integer) -> BERElement {
        BERElement(tag: tag, content: (try? minimalTwosComplement(bytes)) ?? [0])
    }

    public static func enumerated(_ v: Int64) -> BERElement { integer(v, tag: .enumerated) }

    public static func octetString(_ bytes: [UInt8], tag: BERTag = .octetString) -> BERElement {
        BERElement(tag: tag, content: bytes)
    }

    public static func octetString(_ s: String, tag: BERTag = .octetString) -> BERElement {
        BERElement(tag: tag, content: Array(s.utf8))
    }

    public static func null(tag: BERTag = .null) -> BERElement { BERElement(tag: tag, content: []) }

    public static func sequence(_ children: [BERElement], tag: BERTag = .sequence) -> BERElement {
        var content: [UInt8] = []
        for c in children { c.encode(into: &content) }
        return BERElement(tag: tag, content: content)
    }

    /// A SET OF: DER orders the encodings of the elements (X.690 §11.6).
    public static func set(_ children: [BERElement], tag: BERTag = .set) -> BERElement {
        let encodings = children.map { $0.encoded() }.sorted { $0.lexicographicallyPrecedes($1) }
        return BERElement(tag: tag, content: encodings.flatMap { $0 })
    }
}

/// A cursor over BER bytes.
struct BERReader {
    private var bytes: ArraySlice<UInt8>

    init(_ bytes: ArraySlice<UInt8>) { self.bytes = bytes }

    var isAtEnd: Bool { bytes.isEmpty }
    var remaining: Int { bytes.count }

    private mutating func byte(_ what: String) throws -> UInt8 {
        guard let b = bytes.first else { throw LDAPCoreError.truncated(what) }
        bytes = bytes.dropFirst()
        return b
    }

    mutating func read() throws -> BERElement {
        let first = try byte("tag")
        let cls = BERTagClass(rawValue: first >> 6)!
        var number = UInt32(first & 0x1F)
        if number == 0x1F {
            number = 0
            var count = 0
            while true {
                let b = try byte("tag number")
                count += 1
                guard count <= 5, number <= (UInt32.max >> 7) else {
                    throw LDAPCoreError.malformed(what: "tag", reason: "tag number too large")
                }
                number = number << 7 | UInt32(b & 0x7F)
                if b & 0x80 == 0 { break }
            }
        }
        let l0 = try byte("length")
        var length = 0
        if l0 < 0x80 {
            length = Int(l0)
        } else if l0 == 0x80 {
            throw LDAPCoreError.malformed(what: "length", reason: "indefinite length")
        } else {
            let n = Int(l0 & 0x7F)
            guard n <= 8 else { throw LDAPCoreError.malformed(what: "length", reason: "\(n) length octets") }
            for _ in 0..<n {
                let b = try byte("length")
                guard length <= (Int.max >> 8) else { throw LDAPCoreError.malformed(what: "length", reason: "too large") }
                length = length << 8 | Int(b)
            }
        }
        guard length <= bytes.count else {
            throw LDAPCoreError.truncated("element announces \(length) bytes, \(bytes.count) left")
        }
        let content = Array(bytes.prefix(length))
        bytes = bytes.dropFirst(length)
        return BERElement(tag: BERTag(cls, constructed: first & 0x20 != 0, number: number), content: content)
    }
}

/// Positional access to the children of a SEQUENCE with OPTIONAL/DEFAULT fields.
struct BERFields {
    let items: [BERElement]
    var index = 0
    let what: String

    init(_ element: BERElement, _ what: String) throws {
        guard element.tag.constructed else {
            throw LDAPCoreError.malformed(what: what, reason: "expected a constructed element")
        }
        items = try element.children()
        self.what = what
    }

    var isAtEnd: Bool { index >= items.count }

    mutating func next(_ field: String) throws -> BERElement {
        guard index < items.count else { throw LDAPCoreError.malformed(what: what, reason: "missing \(field)") }
        defer { index += 1 }
        return items[index]
    }

    mutating func next(_ tag: BERTag, _ field: String) throws -> BERElement {
        try next(field).expect(tag, "\(what).\(field)")
    }

    /// The next element if its class and number match `tag`.
    mutating func optional(_ tag: BERTag) -> BERElement? {
        guard index < items.count, items[index].tag.sameType(as: tag) else { return nil }
        defer { index += 1 }
        return items[index]
    }
}
