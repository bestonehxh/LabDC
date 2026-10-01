/// Errors of the BER codec, the LDAP message model and the RFC 4515 filter parser.
public enum LDAPCoreError: Error, CustomStringConvertible, Sendable, Equatable {
    /// The input ended inside an element.
    case truncated(String)
    /// The bytes are not valid BER / LDAP (`what` names the element).
    case malformed(what: String, reason: String)
    /// An element had a different tag than the grammar requires.
    case unexpectedTag(expected: String, found: BERTag)
    /// A message or element is larger than the configured limit.
    case tooLarge(size: Int, limit: Int)
    /// An INTEGER does not fit the Swift type.
    case integerOverflow(String)
    /// Constructed elements (filters, constructed strings) nest deeper than allowed.
    case nestingTooDeep(limit: Int)
    /// An RFC 4515 filter string is invalid at `position` (character offset).
    case invalidFilter(String, position: Int)

    public var description: String {
        switch self {
        case .truncated(let s): "truncated BER: \(s)"
        case let .malformed(what, reason): "malformed \(what): \(reason)"
        case let .unexpectedTag(expected, found): "expected \(expected), found tag \(found)"
        case let .tooLarge(size, limit): "element of \(size) bytes exceeds the limit of \(limit)"
        case .integerOverflow(let s): "integer overflow in \(s)"
        case .nestingTooDeep(let n): "nesting deeper than \(n) levels"
        case let .invalidFilter(reason, position): "invalid filter at \(position): \(reason)"
        }
    }
}
