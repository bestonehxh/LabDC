/// Errors of the SMBKit module.
public enum SMBKitError: Error, CustomStringConvertible, Sendable, Equatable {
    /// A PDU could not be parsed.
    case malformed(String)
    /// The client violated the protocol badly enough that the connection is dropped
    /// (bad credit window, SMB1 after negotiate, encrypted transform, …).
    case protocolViolation(String)
    /// A request failed with this NTSTATUS (used internally to build error responses).
    case status(UInt32, String)
    /// A listener could not be bound.
    case listener(String)
    /// `start()` was called twice.
    case alreadyStarted
    /// A named pipe operation failed.
    case pipe(String)

    public var description: String {
        switch self {
        case .malformed(let s): "malformed SMB PDU: \(s)"
        case .protocolViolation(let s): "SMB protocol violation: \(s)"
        case .status(let st, let s): "NTSTATUS 0x\(String(st, radix: 16, uppercase: true)): \(s)"
        case .listener(let s): "SMB listener: \(s)"
        case .alreadyStarted: "SMB server already started"
        case .pipe(let s): "named pipe: \(s)"
        }
    }
}
