import Store

// MARK: - BER (RFC 4511 §4.5.1.7)

extension FilterAST {
    /// Decodes a BER `Filter`.
    public init(berElement: BERElement) throws {
        self = try Self.decode(berElement, depth: 0)
    }

    private static func decode(_ e: BERElement, depth: Int) throws -> FilterAST {
        guard depth < BERElement.maxDepth else { throw LDAPCoreError.nestingTooDeep(limit: BERElement.maxDepth) }
        guard e.tag.tagClass == .contextSpecific else {
            throw LDAPCoreError.unexpectedTag(expected: "Filter [CONTEXT n]", found: e.tag)
        }
        func ava(_ what: String) throws -> (String, [UInt8]) {
            var f = try BERFields(e, what)
            let attr = try f.next(.octetString, "attributeDesc").string()
            let value = try f.next(.octetString, "assertionValue").octets()
            return (attr, value)
        }
        switch e.tag.number {
        case 0: return .and(try e.children().map { try decode($0, depth: depth + 1) })
        case 1: return .or(try e.children().map { try decode($0, depth: depth + 1) })
        case 2:
            let kids = try e.children()
            guard kids.count == 1 else { throw LDAPCoreError.malformed(what: "not filter", reason: "\(kids.count) elements") }
            return .not(try decode(kids[0], depth: depth + 1))
        case 3:
            let (a, v) = try ava("equalityMatch")
            return .equality(attribute: a, value: v)
        case 4:
            var f = try BERFields(e, "SubstringFilter")
            let attr = try f.next(.octetString, "type").string()
            let parts = try f.next(.sequence, "substrings").children()
            guard !parts.isEmpty else { throw LDAPCoreError.malformed(what: "SubstringFilter", reason: "no substrings") }
            var initial: [UInt8]?, final: [UInt8]?
            var any: [[UInt8]] = []
            for (i, p) in parts.enumerated() {
                guard p.tag.tagClass == .contextSpecific else {
                    throw LDAPCoreError.unexpectedTag(expected: "substring choice", found: p.tag)
                }
                switch p.tag.number {
                case 0:
                    guard i == 0, initial == nil else { throw LDAPCoreError.malformed(what: "SubstringFilter", reason: "initial not first") }
                    initial = try p.octets()
                case 1:
                    guard final == nil else { throw LDAPCoreError.malformed(what: "SubstringFilter", reason: "any after final") }
                    any.append(try p.octets())
                case 2:
                    guard i == parts.count - 1 else { throw LDAPCoreError.malformed(what: "SubstringFilter", reason: "final not last") }
                    final = try p.octets()
                default:
                    throw LDAPCoreError.unexpectedTag(expected: "substring choice", found: p.tag)
                }
            }
            return .substrings(attribute: attr, initial: initial, any: any, final: final)
        case 5:
            let (a, v) = try ava("greaterOrEqual")
            return .greaterOrEqual(attribute: a, value: v)
        case 6:
            let (a, v) = try ava("lessOrEqual")
            return .lessOrEqual(attribute: a, value: v)
        case 7:
            return .present(attribute: try e.string())
        case 8:
            let (a, v) = try ava("approxMatch")
            return .approx(attribute: a, value: v)
        case 9:
            var f = try BERFields(e, "MatchingRuleAssertion")
            let rule = try f.optional(.context(1)).map { try $0.string() }
            let type = try f.optional(.context(2)).map { try $0.string() }
            let value = try f.next(.context(3), "matchValue").octets()
            let dnAttributes = try f.optional(.context(4)).map { try $0.boolean() } ?? false
            guard rule != nil || type != nil else {
                throw LDAPCoreError.malformed(what: "MatchingRuleAssertion", reason: "neither matchingRule nor type")
            }
            return .extensible(rule: rule, attribute: type, value: value, dnAttributes: dnAttributes)
        default:
            throw LDAPCoreError.unexpectedTag(expected: "Filter [CONTEXT 0...9]", found: e.tag)
        }
    }

    /// The DER `Filter`.
    public var berElement: BERElement {
        func ava(_ n: UInt32, _ a: String, _ v: [UInt8]) -> BERElement {
            .sequence([.octetString(a), .octetString(v)], tag: .context(n, constructed: true))
        }
        switch self {
        case .and(let fs): return .sequence(fs.map(\.berElement), tag: .context(0, constructed: true))
        case .or(let fs): return .sequence(fs.map(\.berElement), tag: .context(1, constructed: true))
        case .not(let f): return .sequence([f.berElement], tag: .context(2, constructed: true))
        case let .equality(a, v): return ava(3, a, v)
        case let .substrings(a, initial, any, final):
            var parts: [BERElement] = []
            if let initial { parts.append(.octetString(initial, tag: .context(0))) }
            parts += any.map { .octetString($0, tag: .context(1)) }
            if let final { parts.append(.octetString(final, tag: .context(2))) }
            return .sequence([.octetString(a), .sequence(parts)], tag: .context(4, constructed: true))
        case let .greaterOrEqual(a, v): return ava(5, a, v)
        case let .lessOrEqual(a, v): return ava(6, a, v)
        case .present(let a): return .octetString(a, tag: .context(7))
        case let .approx(a, v): return ava(8, a, v)
        case let .extensible(rule, attribute, value, dnAttributes):
            var items: [BERElement] = []
            if let rule { items.append(.octetString(rule, tag: .context(1))) }
            if let attribute { items.append(.octetString(attribute, tag: .context(2))) }
            items.append(.octetString(value, tag: .context(3)))
            if dnAttributes { items.append(.boolean(true, tag: .context(4))) }
            return .sequence(items, tag: .context(9, constructed: true))
        }
    }
}

// MARK: - String representation (RFC 4515)

extension FilterAST {
    /// Parses an RFC 4515 filter string. The outer parentheses may be omitted (as
    /// `ldapsearch` allows); `(&)` and `(|)` are the RFC 4526 absolute true/false filters.
    public init(ldapString: String) throws {
        var p = FilterStringParser(Array(ldapString.utf8))
        p.skipSpaces()
        if p.peek == UInt8(ascii: "(") {
            self = try p.filter(depth: 0)
        } else {
            self = try p.item(terminator: nil)
        }
        p.skipSpaces()
        guard p.isAtEnd else { throw LDAPCoreError.invalidFilter("trailing characters", position: p.position) }
    }

    /// The RFC 4515 string form. Assertion values escape `*()\`, NUL and every byte outside
    /// printable ASCII, so `FilterAST(ldapString: f.ldapString) == f`.
    public var ldapString: String {
        func esc(_ v: [UInt8]) -> String {
            var s = ""
            for b in v {
                if b < 0x20 || b >= 0x7F || b == 0x2A || b == 0x28 || b == 0x29 || b == 0x5C {
                    s += "\\" + String(b >> 4, radix: 16) + String(b & 0x0F, radix: 16)
                } else {
                    s.unicodeScalars.append(Unicode.Scalar(b))
                }
            }
            return s
        }
        switch self {
        case .and(let fs): return "(&" + fs.map(\.ldapString).joined() + ")"
        case .or(let fs): return "(|" + fs.map(\.ldapString).joined() + ")"
        case .not(let f): return "(!" + f.ldapString + ")"
        case let .equality(a, v): return "(\(a)=\(esc(v)))"
        case let .substrings(a, initial, any, final):
            return "(\(a)=" + (initial.map(esc) ?? "") + "*" + any.map { esc($0) + "*" }.joined() + (final.map(esc) ?? "") + ")"
        case let .greaterOrEqual(a, v): return "(\(a)>=\(esc(v)))"
        case let .lessOrEqual(a, v): return "(\(a)<=\(esc(v)))"
        case .present(let a): return "(\(a)=*)"
        case let .approx(a, v): return "(\(a)~=\(esc(v)))"
        case let .extensible(rule, attribute, value, dn):
            return "(" + (attribute ?? "") + (dn ? ":dn" : "") + (rule.map { ":" + $0 } ?? "") + ":=" + esc(value) + ")"
        }
    }
}

private struct FilterStringParser {
    let s: [UInt8]
    var position = 0

    init(_ s: [UInt8]) { self.s = s }

    var isAtEnd: Bool { position >= s.count }
    var peek: UInt8? { position < s.count ? s[position] : nil }

    func fail(_ reason: String) -> LDAPCoreError { .invalidFilter(reason, position: position) }

    mutating func skipSpaces() {
        while let c = peek, c == 0x20 { position += 1 }
    }

    mutating func expect(_ c: Character) throws {
        guard peek == c.asciiValue else { throw fail("expected '\(c)'") }
        position += 1
    }

    /// `filter = LPAREN filtercomp RPAREN`
    mutating func filter(depth: Int) throws -> FilterAST {
        guard depth < BERElement.maxDepth else { throw LDAPCoreError.nestingTooDeep(limit: BERElement.maxDepth) }
        try expect("(")
        let result: FilterAST
        switch peek {
        case UInt8(ascii: "&"):
            position += 1
            result = .and(try list(depth: depth))
        case UInt8(ascii: "|"):
            position += 1
            result = .or(try list(depth: depth))
        case UInt8(ascii: "!"):
            position += 1
            skipSpaces()
            result = .not(try filter(depth: depth + 1))
            skipSpaces()
        default:
            result = try item(terminator: UInt8(ascii: ")"))
        }
        try expect(")")
        return result
    }

    mutating func list(depth: Int) throws -> [FilterAST] {
        var out: [FilterAST] = []
        skipSpaces()
        while peek == UInt8(ascii: "(") {
            out.append(try filter(depth: depth + 1))
            skipSpaces()
        }
        return out
    }

    static func isDescriptorChar(_ c: UInt8) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x2D || c == 0x2E || c == 0x3B
    }

    /// Attribute description (`attr;option`), OID or name.
    mutating func attributeDescription() -> String {
        let start = position
        while let c = peek, Self.isDescriptorChar(c) || c == 0x5F { position += 1 }
        return String(decoding: s[start..<position], as: UTF8.self)
    }

    /// `item = simple / present / substring / extensible`, up to `terminator` (or the end).
    mutating func item(terminator: UInt8?) throws -> FilterAST {
        let attr = attributeDescription()
        guard let c = peek else { throw fail("missing filter type") }
        switch c {
        case UInt8(ascii: ":"):
            return try extensible(attr: attr.isEmpty ? nil : attr, terminator: terminator)
        case UInt8(ascii: "~"), UInt8(ascii: ">"), UInt8(ascii: "<"):
            guard !attr.isEmpty else { throw fail("missing attribute") }
            position += 1
            try expect("=")
            let v = try value(terminator: terminator, allowStar: false).first ?? []
            switch c {
            case UInt8(ascii: "~"): return .approx(attribute: attr, value: v)
            case UInt8(ascii: ">"): return .greaterOrEqual(attribute: attr, value: v)
            default: return .lessOrEqual(attribute: attr, value: v)
            }
        case UInt8(ascii: "="):
            guard !attr.isEmpty else { throw fail("missing attribute") }
            position += 1
            let pieces = try value(terminator: terminator, allowStar: true)
            if pieces.count == 1 { return .equality(attribute: attr, value: pieces[0]) }
            if pieces.count == 2, pieces[0].isEmpty, pieces[1].isEmpty { return .present(attribute: attr) }
            let initial = pieces.first!.isEmpty ? nil : pieces.first!
            let final = pieces.last!.isEmpty ? nil : pieces.last!
            let any = pieces.dropFirst().dropLast()
            guard !any.contains(where: \.isEmpty) else { throw fail("empty substring between '*'") }
            return .substrings(attribute: attr, initial: initial, any: Array(any), final: final)
        default:
            throw fail("unexpected character '\(Character(Unicode.Scalar(c)))'")
        }
    }

    /// `[attr] [":dn"] [":" rule] ":=" value`
    mutating func extensible(attr: String?, terminator: UInt8?) throws -> FilterAST {
        var dn = false
        var rule: String?
        while peek == UInt8(ascii: ":") {
            position += 1
            if peek == UInt8(ascii: "=") {
                position += 1
                guard attr != nil || rule != nil else { throw fail("extensible match needs a type or a rule") }
                let v = try value(terminator: terminator, allowStar: false).first ?? []
                return .extensible(rule: rule, attribute: attr, value: v, dnAttributes: dn)
            }
            let word = attributeDescription()
            guard !word.isEmpty else { throw fail("empty extensible component") }
            if word.lowercased() == "dn" {
                guard !dn, rule == nil else { throw fail("misplaced ':dn'") }
                dn = true
            } else if rule == nil {
                rule = word
            } else {
                throw fail("unexpected '\(word)'")
            }
        }
        throw fail("expected ':='")
    }

    /// The assertion value up to the terminator, split at unescaped `*` when allowed.
    mutating func value(terminator: UInt8?, allowStar: Bool) throws -> [[UInt8]] {
        var pieces: [[UInt8]] = [[]]
        while let c = peek, c != terminator {
            if terminator != nil, c == UInt8(ascii: "(") { throw fail("unescaped '(' in value") }
            if c == UInt8(ascii: "\\") {
                guard position + 2 < s.count, let hi = Self.hex(s[position + 1]), let lo = Self.hex(s[position + 2]) else {
                    throw fail("bad escape")
                }
                pieces[pieces.count - 1].append(hi << 4 | lo)
                position += 3
            } else if c == UInt8(ascii: "*") {
                guard allowStar else { throw fail("'*' not allowed here") }
                pieces.append([])
                position += 1
            } else {
                pieces[pieces.count - 1].append(c)
                position += 1
            }
        }
        if terminator != nil, peek != terminator { throw fail("unterminated value") }
        return pieces
    }

    static func hex(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: c - 0x30
        case 0x41...0x46: c - 0x41 + 10
        case 0x61...0x66: c - 0x61 + 10
        default: nil
        }
    }
}
