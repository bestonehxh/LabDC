/// Errors of the directory store. Cases mirror the LDAP result codes (RFC 4511 §4.1.9) that the
/// LDAP layer maps them to; `ldapResultCode` gives the number.
public enum StoreError: Error, CustomStringConvertible, Sendable, Equatable {
    /// No object at that DN / id (32).
    case noSuchObject(String)
    /// An object with that DN already exists (68).
    case entryAlreadyExists(String)
    /// `sAMAccountName` is taken (AD `00002071`, LDAP 68).
    case samAccountNameExists(String)
    /// `userPrincipalName` is taken (LDAP 19).
    case upnExists(String)
    /// Adding a value that is already present (20).
    case attributeOrValueExists(String)
    /// Deleting a value or attribute that is not present (16).
    case noSuchAttribute(String)
    /// Read-only, single-valued or malformed values (19).
    case constraintViolation(String)
    /// A value that is not valid for the attribute's syntax, e.g. a 32-bit INTEGER out of range (21).
    case invalidAttributeSyntax(String)
    /// Modifying the naming attribute through modify instead of rename (67).
    case notAllowedOnRDN(String)
    /// Deleting an object that has children (66).
    case notAllowedOnNonLeaf(String)
    /// Missing mandatory attributes or an invalid class change (65).
    case objectClassViolation(String)
    /// The operation is refused (53).
    case unwillingToPerform(String)
    /// A password does not satisfy the domain policy (AD `0000052D`, LDAP 19).
    case passwordPolicy(PasswordPolicyViolation)
    /// A DN string is not RFC 4514 (34).
    case invalidDN(String)
    /// The store has not been provisioned yet, or already has been.
    case provisioning(String)
    /// The RID pool is exhausted.
    case ridPoolExhausted
    /// A JSON export could not be read or written.
    case invalidExport(String)
    /// SQLite reported an error.
    case sqlite(code: Int32, message: String)

    /// The LDAP result code this error maps to.
    public var ldapResultCode: Int {
        switch self {
        case .noSuchObject: 32
        case .entryAlreadyExists, .samAccountNameExists: 68
        case .attributeOrValueExists: 20
        case .noSuchAttribute: 16
        case .constraintViolation, .upnExists, .passwordPolicy: 19
        case .invalidAttributeSyntax: 21
        case .notAllowedOnRDN: 67
        case .notAllowedOnNonLeaf: 66
        case .objectClassViolation: 65
        case .invalidDN: 34
        case .unwillingToPerform, .provisioning, .ridPoolExhausted, .invalidExport: 53
        case .sqlite: 80
        }
    }

    public var description: String {
        switch self {
        case .noSuchObject(let s): "no such object: \(s)"
        case .entryAlreadyExists(let s): "entry already exists: \(s)"
        case .samAccountNameExists(let s): "sAMAccountName already in use: \(s)"
        case .upnExists(let s): "userPrincipalName already in use: \(s)"
        case .attributeOrValueExists(let s): "attribute or value exists: \(s)"
        case .noSuchAttribute(let s): "no such attribute: \(s)"
        case .constraintViolation(let s): "constraint violation: \(s)"
        case .invalidAttributeSyntax(let s): "invalid attribute syntax: \(s)"
        case .notAllowedOnRDN(let s): "not allowed on RDN: \(s)"
        case .notAllowedOnNonLeaf(let s): "not allowed on non-leaf: \(s)"
        case .objectClassViolation(let s): "object class violation: \(s)"
        case .unwillingToPerform(let s): "unwilling to perform: \(s)"
        case .passwordPolicy(let v): "password policy: \(v)"
        case .invalidDN(let s): "invalid DN: \(s)"
        case .provisioning(let s): "provisioning: \(s)"
        case .ridPoolExhausted: "RID pool exhausted"
        case .invalidExport(let s): "invalid export: \(s)"
        case let .sqlite(code, message): "sqlite error \(code): \(message)"
        }
    }
}

/// Why a password was refused ("password must meet complexity requirements", MS-SAMR §3.1.1.8.7).
public enum PasswordPolicyViolation: Sendable, Equatable, CustomStringConvertible {
    case tooShort(minimum: Int)
    case tooLong(maximum: Int)
    /// Fewer than 3 of the 5 character categories.
    case notComplex
    /// Contains the sAMAccountName or a displayName token.
    case containsAccountName
    /// Matches the current password or one in the history.
    case inHistory

    public var description: String {
        switch self {
        case .tooShort(let n): "shorter than \(n) characters"
        case .tooLong(let n): "longer than \(n) characters"
        case .notComplex: "needs characters from 3 of: upper case, lower case, digits, symbols, other letters"
        case .containsAccountName: "contains the account name or part of the display name"
        case .inHistory: "was used recently"
        }
    }
}
