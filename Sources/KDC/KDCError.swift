import KerberosASN1

/// Errors of the KDC module.
///
/// `.protocolError` carries the RFC 4120 §7.5.9 code the KDC answers with (and optional
/// `e-data`); the other cases are configuration and I/O problems of the store, keytab and
/// listener.
public enum KDCError: Error, CustomStringConvertible, Sendable, Equatable {
    /// A request is refused with `code`; `eData` becomes the KRB-ERROR `e-data`.
    case protocolError(code: Int32, reason: String, eData: [UInt8]? = nil)
    /// The principals file is malformed or inconsistent.
    case invalidConfiguration(String)
    /// Reading or writing a file failed.
    case io(String)
    /// The keytab bytes are malformed.
    case invalidKeytab(String)
    /// The network listener could not start.
    case listener(String)

    /// The KRB-ERROR code, for protocol errors.
    public var krbErrorCode: Int32? {
        if case .protocolError(let code, _, _) = self { return code }
        return nil
    }

    public var description: String {
        switch self {
        case let .protocolError(code, reason, _): "\(KerberosErrorCode.name(code)): \(reason)"
        case .invalidConfiguration(let why): "invalid principals file: \(why)"
        case .io(let why): "I/O error: \(why)"
        case .invalidKeytab(let why): "invalid keytab: \(why)"
        case .listener(let why): "listener: \(why)"
        }
    }

    static func krb(_ code: Int32, _ reason: String, eData: [UInt8]? = nil) -> KDCError {
        .protocolError(code: code, reason: reason, eData: eData)
    }
}
