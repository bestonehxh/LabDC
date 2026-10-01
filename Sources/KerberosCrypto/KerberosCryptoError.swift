/// Errors of the KerberosCrypto module.
///
/// `krbErrorCode` gives the RFC 4120 §7.5.9 code a KDC should answer with, where one fits.
public enum KerberosCryptoError: Error, CustomStringConvertible, Sendable, Equatable {
    /// Key material has the wrong length for its enctype.
    case invalidKeyLength(type: EncryptionType, expected: Int, actual: Int)
    /// String-to-key parameters (`s2kparams`) are malformed or out of range.
    case invalidStringToKeyParameters(String)
    /// Ciphertext is shorter than confounder + integrity tag (or otherwise cannot be valid).
    case ciphertextTooShort(type: EncryptionType, length: Int)
    /// The HMAC over the decrypted plaintext did not match: wrong key, wrong usage, or tampering.
    case integrityCheckFailed
    /// The checksum type cannot be computed with a key of this enctype.
    case checksumKeyMismatch(checksum: ChecksumType, key: EncryptionType)
    /// CommonCrypto returned an error status.
    case commonCrypto(status: Int32)

    /// The Kerberos error code (RFC 4120 §7.5.9) matching this failure, if any.
    public var krbErrorCode: Int32? {
        switch self {
        case .integrityCheckFailed: 31          // KRB_AP_ERR_BAD_INTEGRITY
        case .checksumKeyMismatch: 50           // KRB_AP_ERR_INAPP_CKSUM
        case .ciphertextTooShort: 31            // treated as an integrity failure
        case .invalidKeyLength, .invalidStringToKeyParameters, .commonCrypto: nil
        }
    }

    public var description: String {
        switch self {
        case let .invalidKeyLength(type, expected, actual):
            "\(type) key must be \(expected) bytes, got \(actual)"
        case .invalidStringToKeyParameters(let why):
            "invalid string-to-key parameters: \(why)"
        case let .ciphertextTooShort(type, length):
            "\(type) ciphertext of \(length) bytes is too short"
        case .integrityCheckFailed:
            "decrypt integrity check failed"
        case let .checksumKeyMismatch(checksum, key):
            "checksum \(checksum) cannot be keyed with a \(key) key"
        case .commonCrypto(let status):
            "CommonCrypto failed with status \(status)"
        }
    }
}
