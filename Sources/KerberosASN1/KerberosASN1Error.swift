/// Errors raised while decoding (or, rarely, encoding) Kerberos ASN.1 messages.
///
/// Every case maps to an RFC 4120 §7.5.9 error code (`kerberosErrorCode`) so the KDC can
/// answer a malformed request with a sensible `KRB-ERROR`.
public enum KerberosASN1Error: Error, CustomStringConvertible, Sendable, Hashable {
    /// The bytes are not valid DER for the expected type (wraps swift-asn1's message).
    case malformedDER(String)
    /// `pvno` / `tkt-vno` / `authenticator-vno` is not 5.
    case badProtocolVersion(Int64)
    /// `msg-type` does not match the APPLICATION tag of the message.
    case unexpectedMessageType(expected: Int32, got: Int32)
    /// The outer APPLICATION tag is not one this module knows (or not the one expected).
    case unexpectedApplicationTag(expected: UInt?, got: UInt?)
    /// A field decoded structurally but its value is out of range / not representable.
    case invalidField(name: String, reason: String)

    /// RFC 4120 §7.5.9 error code a KDC should answer with.
    public var kerberosErrorCode: Int32 {
        switch self {
        case .badProtocolVersion: return KerberosErrorCode.kdcErrBadPvno
        case .unexpectedMessageType, .unexpectedApplicationTag: return KerberosErrorCode.krbApErrMsgType
        case .malformedDER, .invalidField: return KerberosErrorCode.krbErrGeneric
        }
    }

    public var description: String {
        switch self {
        case .malformedDER(let why): return "malformed DER: \(why)"
        case .badProtocolVersion(let v): return "unsupported protocol version \(v) (expected 5)"
        case .unexpectedMessageType(let e, let g): return "msg-type \(g) does not match expected \(e)"
        case .unexpectedApplicationTag(let e, let g):
            let es = e.map { "[APPLICATION \($0)]" } ?? "a Kerberos message"
            let gs = g.map { "[APPLICATION \($0)]" } ?? "a non-APPLICATION tag"
            return "expected \(es), got \(gs)"
        case .invalidField(let name, let reason): return "invalid field \(name): \(reason)"
        }
    }

    /// Wraps any error thrown while decoding into a `KerberosASN1Error`.
    static func wrap(_ error: any Error) -> KerberosASN1Error {
        if let e = error as? KerberosASN1Error { return e }
        return .malformedDER(String(describing: error))
    }
}
