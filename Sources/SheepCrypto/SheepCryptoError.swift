/// Errors of the SheepCrypto module. The phase-0 primitives are total functions (invalid
/// arguments are programmer errors and trap), so this is reserved for later fallible APIs and
/// exists to follow the one-error-enum-per-module convention.
public enum SheepCryptoError: Error, CustomStringConvertible, Sendable, Equatable {
    case commonCrypto(status: Int32)

    public var description: String {
        switch self {
        case .commonCrypto(let status): "CommonCrypto failed with status \(status)"
        }
    }
}
