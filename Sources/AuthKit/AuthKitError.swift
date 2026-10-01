/// Errors of the AuthKit module. Kerberos failures carry the RFC 4120 §7.5.9 error code so a
/// caller can build a KRB-ERROR; NTLM failures map to the NTSTATUS a Windows server returns.
public enum AuthKitError: Error, CustomStringConvertible, Sendable, Equatable {
    /// A token or message could not be parsed (`what` names it, `reason` says why).
    case malformed(what: String, reason: String)
    /// The token uses a mechanism, OID or feature this acceptor does not implement.
    case unsupported(String)
    /// Kerberos validation failed with RFC 4120 error `code` (e.g. 34 KRB_AP_ERR_REPEAT).
    case kerberos(code: Int32, reason: String)
    /// No long-term key for the ticket's service name / enctype.
    case noServiceKey(spn: String, etype: Int32)
    /// NTLM authentication failed. `status` is the NTSTATUS a Windows server reports
    /// (0xC000006D STATUS_LOGON_FAILURE, 0xC0000418 STATUS_NTLM_BLOCKED, ...).
    case ntlm(status: UInt32, reason: String)
    /// A per-message token (wrap/unwrap/MIC) failed its integrity check.
    case integrityCheckFailed(String)
    /// A per-message token carried an unexpected sequence number.
    case sequenceError(expected: UInt64, got: UInt64)
    /// A per-message token claims the wrong direction (reflection).
    case badDirection
    /// SPNEGO negotiation failed (no common mechanism, bad mechListMIC, bad state).
    case negotiation(String)
    /// SASL-level failure (bad security-layer choice, step after completion, ...).
    case sasl(String)
    /// The call is not valid in the current state (e.g. `step` after completion).
    case invalidState(String)

    public var description: String {
        switch self {
        case .malformed(let what, let reason): "malformed \(what): \(reason)"
        case .unsupported(let s): "unsupported: \(s)"
        case .kerberos(let code, let reason): "Kerberos error \(code): \(reason)"
        case .noServiceKey(let spn, let etype): "no key for \(spn) etype \(etype)"
        case .ntlm(let status, let reason): "NTLM failure 0x\(String(status, radix: 16, uppercase: true)): \(reason)"
        case .integrityCheckFailed(let s): "integrity check failed: \(s)"
        case .sequenceError(let e, let g): "sequence error: expected \(e), got \(g)"
        case .badDirection: "token direction is wrong (reflected token?)"
        case .negotiation(let s): "SPNEGO: \(s)"
        case .sasl(let s): "SASL: \(s)"
        case .invalidState(let s): "invalid state: \(s)"
        }
    }

    /// NTSTATUS values used by the NTLM server.
    public enum NTStatus {
        public static let logonFailure: UInt32 = 0xC000_006D
        public static let noSuchUser: UInt32 = 0xC000_0064
        public static let ntlmBlocked: UInt32 = 0xC000_0418
        public static let invalidParameter: UInt32 = 0xC000_000D
        public static let accessDenied: UInt32 = 0xC000_0022
    }
}
