import LDAPCore
import Store

/// Errors of the LDAP server itself (lifecycle, listeners, TLS). Protocol-level failures are
/// LDAP results sent to the client, not Swift errors.
public enum DirectoryKitError: Error, CustomStringConvertible, Sendable, Equatable {
    /// The store has no domain yet (`provision` first).
    case notProvisioned
    /// A listener could not be bound.
    case listener(String)
    /// The TLS configuration could not be built from the PKI.
    case tls(String)
    /// `start()` was called twice.
    case alreadyStarted

    public var description: String {
        switch self {
        case .notProvisioned: "the directory store is not provisioned"
        case .listener(let s): "listener: \(s)"
        case .tls(let s): "TLS: \(s)"
        case .alreadyStarted: "the server is already running"
        }
    }
}

/// An LDAP result to send instead of success (thrown inside request processing).
struct LDAPFailure: Error, CustomStringConvertible {
    var result: LDAPResult

    init(_ code: LDAPResultCode, _ diagnostic: String = "", matchedDN: String = "") {
        result = LDAPResult(code, matchedDN: matchedDN, diagnosticMessage: diagnostic)
    }

    var description: String { "\(result.resultCode): \(result.diagnosticMessage)" }
}

/// AD-format `diagnosticMessage` texts (clients such as Windows, sssd and Java parse the
/// leading hex Win32 code and the `data` field).
enum ADDiagnostic {
    static let version = "v4563"

    static func noSuchObject(bestMatch: String) -> String {
        "00000525: NameErr: DSID-03100241, problem 2001 (NO_OBJECT), data 0, best match of:\n\t'\(bestMatch)'\n"
    }

    /// Bind failures: `data` is the Win32 status (52e bad password, 525 no such user, 530 time
    /// restriction, 531 workstation, 532 password expired, 533 disabled, 701 account expired,
    /// 773 must change, 775 locked out).
    static func invalidCredentials(data: String = "52e") -> String {
        let lead = String(repeating: "0", count: max(0, 8 - data.count)) + data.uppercased()
        return "\(lead): LdapErr: DSID-0C09056D, comment: AcceptSecurityContext error, data \(data), \(version)"
    }

    static let unicodePwdNeedsSecureConnection =
        "00002077: SvcErr: DSID-03190F4C, problem 5003 (WILL_NOT_PERFORM), data 0\n"

    static func passwordPolicy(attribute: String = "unicodePwd") -> String {
        "0000052D: AtrErr: DSID-03191083, #1:\n\t0: 0000052D: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (\(attribute))\n"
    }

    static let entryExists = "00002071: UpdErr: DSID-031B0B1E, problem 6005 (ENTRY_EXISTS), data 0\n"

    static let bindRequired =
        "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, \(version)"

    static let insufficientAccess = "00000005: SecErr: DSID-03152E29, problem 4003 (INSUFFICIENT_ACCESS_RIGHTS), data 0\n"

    /// Over `ms-DS-MachineAccountQuota`: LDAP result `insufficientAccessRights` with the
    /// ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED (0x216D) code AD reports.
    static let machineAccountQuotaExceeded = "0000216D: SvcErr: DSID-03152E29, problem 4003 (INSUFFICIENT_ACCESS_RIGHTS), data 0\n"

    static let unwillingToPerform = "00002035: SvcErr: DSID-031A1254, problem 5003 (WILL_NOT_PERFORM), data 0\n"

    static let criticalControl = "00000057: LdapErr: DSID-0C090B0A, comment: Error processing control, data 0, \(version)"

    static let attributeConversion = "00000057: LdapErr: DSID-0C090D8A, comment: Error in attribute conversion operation, data 0, \(version)"

    static func invalidDN(_ dn: String) -> String {
        "0000208F: NameErr: DSID-03100225, problem 2006 (BAD_NAME), data 8350, best match of:\n\t'\(dn)'\n"
    }

    static let attributeOrValueExists = "00002083: AtrErr: DSID-03151946, problem 1006 (ATT_OR_VALUE_EXISTS), data 0\n"
    static let noSuchAttribute = "00002080: AtrErr: DSID-03152D2C, problem 1001 (NO_ATTRIBUTE_OR_VAL), data 0\n"
    static let constraintViolation = "000020B5: AtrErr: DSID-03152D2C, problem 1005 (CONSTRAINT_ATT_TYPE), data 0\n"
    /// A value that does not convert to the attribute's syntax (LDAP 21), e.g. a 32-bit INTEGER
    /// out of range.
    static let invalidAttributeSyntax = "00000057: LdapErr: DSID-0C090D8A, comment: Error in attribute conversion operation, data 0\n"
    /// A value refused by a validated write or a uniqueness rule: `0000202F` constraint
    /// violation, `000021C7` duplicate SPN, `000021C8` duplicate UPN; `attribute` is
    /// `<ATTRTYP hex> (<name>)`.
    static func constraint(code: String, attribute: String) -> String {
        "\(code): AtrErr: DSID-03200BBA, #1:\n\t0: \(code): DSID-03200BBA, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att \(attribute)\n"
    }
    static let notAllowedOnRDN = "00002016: UpdErr: DSID-030F0F0E, problem 6004 (CANT_ON_RDN), data 0\n"
    static let notAllowedOnNonLeaf = "0000208C: UpdErr: DSID-030F0F2A, problem 6003 (CANT_ON_NON_LEAF), data 0\n"
    static let objectClassViolation = "00002014: objectclass: DSID-03151785, problem 6002 (OBJ_CLASS_VIOLATION), data 0\n"
    static let operationsError = "000020EF: SvcErr: DSID-0C090D8A, problem 5012 (DIR_ERROR), data 0\n"

    /// Maps a store error to the LDAP result (with the AD text) a DC would send.
    static func failure(for error: StoreError, bestMatch: String = "") -> LDAPFailure {
        switch error {
        case .noSuchObject: LDAPFailure(.noSuchObject, noSuchObject(bestMatch: bestMatch), matchedDN: bestMatch)
        case .entryAlreadyExists, .samAccountNameExists: LDAPFailure(.entryAlreadyExists, entryExists)
        case .upnExists: LDAPFailure(.constraintViolation, constraintViolation)
        case .attributeOrValueExists: LDAPFailure(.attributeOrValueExists, attributeOrValueExists)
        case .noSuchAttribute: LDAPFailure(.noSuchAttribute, noSuchAttribute)
        case .constraintViolation: LDAPFailure(.constraintViolation, constraintViolation)
        case .invalidAttributeSyntax: LDAPFailure(.invalidAttributeSyntax, invalidAttributeSyntax)
        case .notAllowedOnRDN: LDAPFailure(.notAllowedOnRDN, notAllowedOnRDN)
        case .notAllowedOnNonLeaf: LDAPFailure(.notAllowedOnNonLeaf, notAllowedOnNonLeaf)
        case .objectClassViolation: LDAPFailure(.objectClassViolation, objectClassViolation)
        case .passwordPolicy: LDAPFailure(.constraintViolation, passwordPolicy())
        case .invalidDN(let s): LDAPFailure(.invalidDNSyntax, invalidDN(s))
        case .unwillingToPerform, .provisioning, .ridPoolExhausted, .invalidExport:
            LDAPFailure(.unwillingToPerform, unwillingToPerform)
        case .sqlite: LDAPFailure(.other, operationsError)
        }
    }
}
