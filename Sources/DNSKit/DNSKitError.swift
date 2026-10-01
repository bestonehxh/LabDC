/// Errors of the DNSKit module.
///
/// Wire-format problems (`.malformed`) are answered with FORMERR by the server; the other
/// cases are configuration and listener problems.
public enum DNSKitError: Error, CustomStringConvertible, Sendable, Equatable {
    /// The message bytes do not parse (truncated, bad pointer, bad label, bad RDATA length).
    case malformed(String)
    /// A value cannot be encoded (label longer than 63 bytes, name longer than 255 bytes, ...).
    case unencodable(String)
    /// A textual name or address is invalid.
    case invalidText(String)
    /// The listen port is already held by another process; `holder` is `lsof` output.
    case portInUse(port: UInt16, holder: String)
    /// The network listener could not start.
    case listener(String)
    /// The upstream resolver did not answer in time or failed.
    case upstream(String)
    /// The zone source refused a change.
    case source(String)

    public var description: String {
        switch self {
        case .malformed(let why): "malformed DNS message: \(why)"
        case .unencodable(let why): "cannot encode DNS message: \(why)"
        case .invalidText(let why): "invalid DNS text: \(why)"
        case let .portInUse(port, holder):
            "port \(port) is already in use; refusing to start. Holder (lsof -nP -iUDP:\(port) -iTCP:\(port)):\n\(holder)"
        case .listener(let why): "listener: \(why)"
        case .upstream(let why): "upstream resolver: \(why)"
        case .source(let why): "zone source: \(why)"
        }
    }
}
