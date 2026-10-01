/// Errors of the converter. `description` is a sentence meant for the user (CLI and UI show it as is).
public enum CertConvertError: Error, Equatable, Sendable, CustomStringConvertible {
    /// The input is encrypted and no password was given.
    case passwordRequired(String)
    /// The password is wrong (MAC or keyed digest mismatch, or bad padding after decryption).
    case badPassword(String)
    /// The bytes are not any format the converter knows.
    case unrecognizedInput(String)
    /// The format was recognised but is malformed.
    case malformed(String)
    /// A recognised but unsupported algorithm or variant.
    case unsupported(String)
    /// The requested output cannot be built from what was loaded (e.g. PKCS#12 without a key).
    case missing(String)
    /// Invalid options for the requested output.
    case invalidOptions(String)

    public var description: String {
        switch self {
        case .passwordRequired(let s), .badPassword(let s), .unrecognizedInput(let s), .malformed(let s),
             .unsupported(let s), .missing(let s), .invalidOptions(let s):
            s
        }
    }
}
