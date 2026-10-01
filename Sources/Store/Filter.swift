import MSPAC

/// A parsed LDAP search filter (RFC 4511 §4.5.1.7), independent of the wire format so
/// LDAPCore can map RFC 4515 strings and BER filters onto it. Assertion values are raw octet
/// strings, as they arrive on the wire.
public indirect enum FilterAST: Sendable, Hashable {
    case and([FilterAST])
    case or([FilterAST])
    case not(FilterAST)
    case equality(attribute: String, value: [UInt8])
    case substrings(attribute: String, initial: [UInt8]?, any: [[UInt8]], final: [UInt8]?)
    case greaterOrEqual(attribute: String, value: [UInt8])
    case lessOrEqual(attribute: String, value: [UInt8])
    case present(attribute: String)
    case approx(attribute: String, value: [UInt8])
    /// `attr:dn:rule:=value`. With `rule` nil the attribute's equality rule applies; with
    /// `attribute` nil every attribute is tried.
    case extensible(rule: String?, attribute: String?, value: [UInt8], dnAttributes: Bool)

    /// `(objectClass=*)`: matches every entry.
    public static let everything = FilterAST.present(attribute: "objectClass")

    /// `(attr=value)` with a text value.
    public static func eq(_ attribute: String, _ value: String) -> FilterAST {
        .equality(attribute: attribute, value: Array(value.utf8))
    }

    /// `(attr:1.2.840.113556.1.4.803:=bits)`.
    public static func bitAnd(_ attribute: String, _ bits: Int64) -> FilterAST {
        .extensible(rule: MatchingRule.bitAnd, attribute: attribute, value: Array(String(bits).utf8), dnAttributes: false)
    }

    /// `(attr:1.2.840.113556.1.4.804:=bits)`.
    public static func bitOr(_ attribute: String, _ bits: Int64) -> FilterAST {
        .extensible(rule: MatchingRule.bitOr, attribute: attribute, value: Array(String(bits).utf8), dnAttributes: false)
    }

    /// Evaluates the filter against an entry without store access: `LDAP_MATCHING_RULE_IN_CHAIN`
    /// evaluates to Undefined here (the store evaluates it in `search`).
    public func matches(_ entry: DirectoryEntry, schemaDN: DN? = nil) -> Bool {
        let evaluator = FilterEvaluator(schemaDN: schemaDN, chain: nil)
        return (try? evaluator.evaluate(self, entry)) == .true
    }
}

/// Matching rules the store implements beyond plain equality.
public enum MatchingRule {
    /// `LDAP_MATCHING_RULE_BIT_AND`: every bit of the assertion is set.
    public static let bitAnd = "1.2.840.113556.1.4.803"
    /// `LDAP_MATCHING_RULE_BIT_OR`: at least one bit of the assertion is set.
    public static let bitOr = "1.2.840.113556.1.4.804"
    /// `LDAP_MATCHING_RULE_IN_CHAIN`: transitive closure over a linked attribute.
    public static let inChain = "1.2.840.113556.1.4.1941"
    /// RFC 4517 equality rules accepted as "use equality".
    static let equalityRules: Set<String> = [
        "2.5.13.0", "2.5.13.1", "2.5.13.2", "2.5.13.5", "2.5.13.14", "2.5.13.13", "2.5.13.17",
        "objectidentifiermatch", "distinguishednamematch", "caseignorematch", "caseexactmatch",
        "integermatch", "booleanmatch", "octetstringmatch",
    ]
}

/// Three-valued filter result (RFC 4511 §4.5.1.7).
enum FilterResult: Sendable, Equatable {
    case `true`, `false`, undefined

    static prefix func ! (r: FilterResult) -> FilterResult {
        switch r {
        case .true: .false
        case .false: .true
        case .undefined: .undefined
        }
    }
}

/// Evaluates a `FilterAST` on a materialised entry. `chain` resolves
/// `LDAP_MATCHING_RULE_IN_CHAIN` (entry, attribute, target DN) -> member-of-chain.
struct FilterEvaluator {
    var schemaDN: DN?
    var chain: ((DirectoryEntry, String, DN) throws -> Bool)?

    func evaluate(_ f: FilterAST, _ e: DirectoryEntry) throws -> FilterResult {
        switch f {
        case .and(let list):
            var result = FilterResult.true
            for sub in list {
                switch try evaluate(sub, e) {
                case .false: return .false
                case .undefined: result = .undefined
                case .true: break
                }
            }
            return result
        case .or(let list):
            var result = FilterResult.false
            for sub in list {
                switch try evaluate(sub, e) {
                case .true: return .true
                case .undefined: result = .undefined
                case .false: break
                }
            }
            return result
        case .not(let sub):
            return !(try evaluate(sub, e))
        case .present(let attr):
            if attr.caseInsensitiveCompare("objectClass") == .orderedSame { return .true }
            return e.has(attr) ? .true : .false
        case let .equality(attr, value), let .approx(attr, value):
            return equality(attr, value, e)
        case let .greaterOrEqual(attr, value):
            return ordering(attr, value, e) { $0 >= 0 }
        case let .lessOrEqual(attr, value):
            return ordering(attr, value, e) { $0 <= 0 }
        case let .substrings(attr, initial, any, final):
            return substrings(attr, initial, any, final, e)
        case let .extensible(rule, attr, value, dnAttributes):
            return try extensible(rule, attr, value, dnAttributes, e)
        }
    }

    /// The assertion's match key, with AD conveniences: `objectSid=S-1-5-...`,
    /// `objectGUID={...}`, `objectCategory=person`.
    func assertionKey(_ attr: String, _ value: [UInt8]) -> [UInt8]? {
        let syntax = DirectorySchema.syntax(of: attr)
        let text = String(validating: value, as: UTF8.self)
        if syntax == .sid, let text, text.uppercased().hasPrefix("S-1-"), let sid = try? SID(string: text) {
            return sid.bytes
        }
        if attr.caseInsensitiveCompare("objectGUID") == .orderedSame, value.count != 16, let text,
           let guid = GUID(string: text) {
            return guid.bytes
        }
        if attr.caseInsensitiveCompare("objectCategory") == .orderedSame, let text, !text.contains("="),
           let schemaDN {
            let cls = DirectorySchema.objectClass(text)
            let cn = cls.flatMap { DirectorySchema.objectClass($0.category)?.cn } ?? text
            return Array(schemaDN.child(RDN("CN", cn)).normalized.utf8)
        }
        return DirectorySchema.matchKey(value, syntax: syntax)
    }

    func equality(_ attr: String, _ value: [UInt8], _ e: DirectoryEntry) -> FilterResult {
        let values = e.values(attr)
        guard !values.isEmpty else { return .false }
        guard let key = assertionKey(attr, value) else { return .undefined }
        let syntax = DirectorySchema.syntax(of: attr)
        return values.contains { DirectorySchema.matchKey($0, syntax: syntax) == key } ? .true : .false
    }

    func ordering(_ attr: String, _ value: [UInt8], _ e: DirectoryEntry, _ ok: (Int) -> Bool) -> FilterResult {
        let values = e.values(attr)
        guard !values.isEmpty else { return .false }
        let syntax = DirectorySchema.syntax(of: attr)
        if syntax.isBinary { return .undefined }
        guard let key = assertionKey(attr, value) else { return .undefined }
        for v in values {
            guard let vk = DirectorySchema.matchKey(v, syntax: syntax) else { continue }
            let cmp: Int
            if syntax.isInteger, let a = Int64(String(decoding: vk, as: UTF8.self)),
               let b = Int64(String(decoding: key, as: UTF8.self)) {
                cmp = a < b ? -1 : (a > b ? 1 : 0)
            } else {
                cmp = vk.lexicographicallyPrecedes(key) ? -1 : (vk == key ? 0 : 1)
            }
            if ok(cmp) { return .true }
        }
        return .false
    }

    func substrings(_ attr: String, _ initial: [UInt8]?, _ any: [[UInt8]], _ final: [UInt8]?,
                    _ e: DirectoryEntry) -> FilterResult {
        let values = e.values(attr)
        guard !values.isEmpty else { return .false }
        let syntax = DirectorySchema.syntax(of: attr)
        let fold: ([UInt8]) -> [UInt8] = syntax.isBinary ? { $0 } : {
            Array(String(decoding: $0, as: UTF8.self).lowercased().utf8)
        }
        let ini = initial.map(fold), fin = final.map(fold), mids = any.map(fold)
        for raw in values {
            let v = fold(raw)
            var pos = 0
            if let ini {
                guard v.starts(with: ini) else { continue }
                pos = ini.count
            }
            var end = v.count
            if let fin {
                guard v.count - pos >= fin.count, Array(v.suffix(fin.count)) == fin else { continue }
                end = v.count - fin.count
            }
            var ok = true
            for m in mids {
                guard let r = find(m, in: v, from: pos, to: end) else { ok = false; break }
                pos = r
            }
            if ok { return .true }
        }
        return .false
    }

    /// Index just past the first occurrence of `needle` in `hay[from..<to]`.
    private func find(_ needle: [UInt8], in hay: [UInt8], from: Int, to: Int) -> Int? {
        if needle.isEmpty { return from }
        guard to - from >= needle.count else { return nil }
        var i = from
        while i + needle.count <= to {
            if hay[i..<(i + needle.count)].elementsEqual(needle) { return i + needle.count }
            i += 1
        }
        return nil
    }

    func extensible(_ rule: String?, _ attr: String?, _ value: [UInt8], _ dnAttributes: Bool,
                    _ e: DirectoryEntry) throws -> FilterResult {
        let r = rule?.lowercased()
        var result = FilterResult.false
        if let r, r == MatchingRule.bitAnd || r == MatchingRule.bitOr {
            guard let attr else { return .undefined }
            guard let bits = Int64(String(decoding: value, as: UTF8.self).trimmingSpaces) else { return .undefined }
            for v in e.values(attr) {
                guard let n = Int64(String(decoding: v, as: UTF8.self)) else { continue }
                if r == MatchingRule.bitAnd ? (n & bits) == bits : (n & bits) != 0 { return .true }
            }
            return .false
        } else if r == MatchingRule.inChain {
            guard let attr, let chain, let target = try? DN(string: String(decoding: value, as: UTF8.self)) else {
                return .undefined
            }
            return try chain(e, attr, target) ? .true : .false
        } else if r == nil || MatchingRule.equalityRules.contains(r!) {
            if let attr {
                result = equality(attr, value, e)
            } else {
                for a in e.attributes where equality(a.name, value, e) == .true { return .true }
            }
        } else {
            return .undefined
        }
        if result != .true, dnAttributes {
            let text = String(decoding: value, as: UTF8.self).lowercased()
            for rdn in e.dn.rdns {
                for c in rdn.components where (attr == nil || c.type.caseInsensitiveCompare(attr!) == .orderedSame)
                    && c.value.lowercased() == text {
                    return .true
                }
            }
        }
        return result
    }
}
