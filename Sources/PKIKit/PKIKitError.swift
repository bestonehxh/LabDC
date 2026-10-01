import Foundation

/// Errors thrown by PKIKit.
public enum PKIKitError: Error, Sendable, CustomStringConvertible {
    /// `ensureCA` has not been called and no CA was found on disk.
    case caNotInitialized
    /// `ensureServerCertificate` has not been called and no server certificate was found on disk.
    case serverCertificateNotInitialized
    /// A string passed as an IP address is neither dotted IPv4 nor IPv6.
    case invalidIPAddress(String)
    /// A host name is empty or not a plausible DNS name.
    case invalidHostname(String)
    /// `ensureServerCertificate` was called without a host name (the first one is the subject CN).
    case noHostnames
    /// A PEM file on disk could not be parsed, or a key does not match its certificate.
    case corruptFile(path: String, reason: String)
    /// A POSIX file operation failed.
    case fileSystem(path: String, operation: String, errno: Int32)
    /// swift-certificates or NIOSSL rejected something.
    case encoding(String)
    /// `createCA`: the name is not 1-64 characters of letters, digits, `.`, `_`, `-`.
    case invalidCAName(String)
    /// `createCA`: the lifetime is outside 1...50 years.
    case invalidCALifetime(Int)
    /// `createCA`: a CA with this name already exists.
    case caExists(String)
    /// No CA with this name in the PKI directory.
    case unknownCA(String)

    public var description: String {
        switch self {
        case .caNotInitialized:
            return "PKIKit: lab CA not initialised (call ensureCA first)"
        case .serverCertificateNotInitialized:
            return "PKIKit: server certificate not initialised (call ensureServerCertificate first)"
        case .invalidIPAddress(let s):
            return "PKIKit: invalid IP address '\(s)'"
        case .invalidHostname(let s):
            return "PKIKit: invalid host name '\(s)'"
        case .noHostnames:
            return "PKIKit: at least one host name is required"
        case .corruptFile(let path, let reason):
            return "PKIKit: \(path): \(reason) (delete the file to regenerate)"
        case .fileSystem(let path, let op, let err):
            return "PKIKit: \(op) \(path) failed: \(String(cString: strerror(err)))"
        case .encoding(let s):
            return "PKIKit: \(s)"
        case .invalidCAName(let s):
            return "PKIKit: invalid CA name '\(s)' (1-64 characters: letters, digits, '.', '_', '-'; it appears in the CRL URL)"
        case .invalidCALifetime(let years):
            return "PKIKit: a CA lifetime must be 1 to 50 years, not \(years)"
        case .caExists(let s):
            return "PKIKit: a CA named '\(s)' already exists"
        case .unknownCA(let s):
            return "PKIKit: no CA named '\(s)' (see `labdc ca list`)"
        }
    }
}
