// Assigned numbers used in Kerberos ASN.1 fields (RFC 4120 §7.5, RFC 6113, MS-KILE, MS-SFU).
// Modelled as `Int32` statics rather than closed enums: unknown values must round-trip.

/// `msg-type` values (RFC 4120 §7.5.7); also the APPLICATION tag of each message.
public enum MessageType {
    public static let asReq: Int32 = 10
    public static let asRep: Int32 = 11
    public static let tgsReq: Int32 = 12
    public static let tgsRep: Int32 = 13
    public static let apReq: Int32 = 14
    public static let apRep: Int32 = 15
    public static let krbSafe: Int32 = 20
    public static let krbPriv: Int32 = 21
    public static let krbCred: Int32 = 22
    public static let krbError: Int32 = 30
}

/// Principal `name-type` (RFC 4120 §6.2, RFC 6111, MS-KILE).
public enum NameType {
    public static let unknown: Int32 = 0
    /// NT-PRINCIPAL: users.
    public static let principal: Int32 = 1
    /// NT-SRV-INST: `service/instance`, e.g. `krbtgt/REALM`.
    public static let srvInst: Int32 = 2
    /// NT-SRV-HST: `service/hostname`.
    public static let srvHst: Int32 = 3
    public static let srvXhst: Int32 = 4
    public static let uid: Int32 = 5
    public static let x500Principal: Int32 = 6
    public static let smtpName: Int32 = 7
    /// NT-ENTERPRISE (RFC 6806): single component `user@upn.suffix`.
    public static let enterprise: Int32 = 10
    public static let wellknown: Int32 = 11
    /// NT-MS-PRINCIPAL (MS-KILE).
    public static let msPrincipal: Int32 = -128
}

/// `addr-type` (RFC 4120 §7.5.3).
public enum AddressType {
    public static let ipv4: Int32 = 2
    public static let directional: Int32 = 3
    public static let chaosNet: Int32 = 5
    public static let xns: Int32 = 6
    public static let iso: Int32 = 7
    public static let decnetPhaseIV: Int32 = 12
    public static let appletalkDDP: Int32 = 16
    public static let netbios: Int32 = 20
    public static let ipv6: Int32 = 24
}

/// `padata-type` (RFC 4120 §7.5.2, RFC 6113, MS-KILE §2.2).
public enum PADataType {
    public static let tgsReq: Int32 = 1
    public static let encTimestamp: Int32 = 2
    public static let pwSalt: Int32 = 3
    public static let etypeInfo: Int32 = 11
    public static let pkAsReq: Int32 = 16
    public static let pkAsRep: Int32 = 17
    public static let etypeInfo2: Int32 = 19
    public static let forUser: Int32 = 129
    public static let fxCookie: Int32 = 133
    public static let fxFast: Int32 = 136
    public static let fxError: Int32 = 137
    public static let encryptedChallenge: Int32 = 138
    public static let pacRequest: Int32 = 128
    /// PA-REQ-ENC-PA-REP (RFC 6806); Heimdal sends it empty in every AS-REQ.
    public static let reqEncPaRep: Int32 = 149
    public static let asFreshness: Int32 = 150
    public static let supportedEnctypes: Int32 = 165
    public static let pacOptions: Int32 = 167
}

/// `ad-type` (RFC 4120 §7.5.4, MS-KILE / MS-PAC).
public enum AuthorizationDataType {
    public static let ifRelevant: Int32 = 1
    public static let intendedForServer: Int32 = 2
    public static let intendedForApplicationClass: Int32 = 3
    public static let kdcIssued: Int32 = 4
    public static let andOr: Int32 = 5
    public static let mandatoryTicketExtensions: Int32 = 6
    public static let inTicketExtensions: Int32 = 7
    public static let mandatoryForKDC: Int32 = 8
    /// AD-WIN2K-PAC: the MS-PAC blob.
    public static let win2kPAC: Int32 = 128
    public static let etypeNegotiation: Int32 = 129
    public static let tokenRestrictions: Int32 = 141
    public static let local: Int32 = 142
    public static let apOptions: Int32 = 143
}

/// `lr-type` (RFC 4120 §5.4.2).
public enum LastReqType {
    public static let none: Int32 = 0
    public static let lastInitialTGTRequest: Int32 = 1
    public static let lastInitialRequest: Int32 = 2
    public static let newestTGTIssue: Int32 = 3
    public static let lastRenewal: Int32 = 4
    public static let lastRequest: Int32 = 5
    public static let passwordExpiration: Int32 = 6
    public static let accountExpiration: Int32 = 7
}

/// `tr-type` (RFC 4120 §7.5.5).
public enum TransitedType {
    public static let domainX500Compress: Int32 = 1
}

/// KRB-ERROR `error-code` values: RFC 4120 §7.5.9 (plus RFC 4556 / RFC 6113 additions).
/// Swift names are the RFC names in lowerCamelCase (`KDC_ERR_PREAUTH_REQUIRED` -> `kdcErrPreauthRequired`).
public enum KerberosErrorCode {
    public static let kdcErrNone: Int32 = 0
    public static let kdcErrNameExp: Int32 = 1
    public static let kdcErrServiceExp: Int32 = 2
    public static let kdcErrBadPvno: Int32 = 3
    public static let kdcErrCOldMastKvno: Int32 = 4
    public static let kdcErrSOldMastKvno: Int32 = 5
    public static let kdcErrCPrincipalUnknown: Int32 = 6
    public static let kdcErrSPrincipalUnknown: Int32 = 7
    public static let kdcErrPrincipalNotUnique: Int32 = 8
    public static let kdcErrNullKey: Int32 = 9
    public static let kdcErrCannotPostdate: Int32 = 10
    public static let kdcErrNeverValid: Int32 = 11
    public static let kdcErrPolicy: Int32 = 12
    public static let kdcErrBadoption: Int32 = 13
    public static let kdcErrEtypeNosupp: Int32 = 14
    public static let kdcErrSumtypeNosupp: Int32 = 15
    public static let kdcErrPadataTypeNosupp: Int32 = 16
    public static let kdcErrTrtypeNosupp: Int32 = 17
    public static let kdcErrClientRevoked: Int32 = 18
    public static let kdcErrServiceRevoked: Int32 = 19
    public static let kdcErrTgtRevoked: Int32 = 20
    public static let kdcErrClientNotyet: Int32 = 21
    public static let kdcErrServiceNotyet: Int32 = 22
    public static let kdcErrKeyExpired: Int32 = 23
    public static let kdcErrPreauthFailed: Int32 = 24
    public static let kdcErrPreauthRequired: Int32 = 25
    public static let kdcErrServerNomatch: Int32 = 26
    public static let kdcErrMustUseUser2user: Int32 = 27
    public static let kdcErrPathNotAccepted: Int32 = 28
    public static let kdcErrSvcUnavailable: Int32 = 29
    public static let krbApErrBadIntegrity: Int32 = 31
    public static let krbApErrTktExpired: Int32 = 32
    public static let krbApErrTktNyv: Int32 = 33
    public static let krbApErrRepeat: Int32 = 34
    public static let krbApErrNotUs: Int32 = 35
    public static let krbApErrBadmatch: Int32 = 36
    public static let krbApErrSkew: Int32 = 37
    public static let krbApErrBadaddr: Int32 = 38
    public static let krbApErrBadversion: Int32 = 39
    public static let krbApErrMsgType: Int32 = 40
    public static let krbApErrModified: Int32 = 41
    public static let krbApErrBadorder: Int32 = 42
    /// Not in RFC 4120's table (RFC 1510 legacy), still used by MIT/Heimdal.
    public static let krbApErrIllCrTkt: Int32 = 43
    public static let krbApErrBadkeyver: Int32 = 44
    public static let krbApErrNokey: Int32 = 45
    public static let krbApErrMutFail: Int32 = 46
    public static let krbApErrBaddirection: Int32 = 47
    public static let krbApErrMethod: Int32 = 48
    public static let krbApErrBadseq: Int32 = 49
    public static let krbApErrInappCksum: Int32 = 50
    public static let krbApPathNotAccepted: Int32 = 51
    public static let krbErrResponseTooBig: Int32 = 52
    public static let krbErrGeneric: Int32 = 60
    public static let krbErrFieldToolong: Int32 = 61
    public static let kdcErrorClientNotTrusted: Int32 = 62
    public static let kdcErrorKdcNotTrusted: Int32 = 63
    public static let kdcErrorInvalidSig: Int32 = 64
    public static let kdcErrKeyTooWeak: Int32 = 65
    public static let kdcErrCertificateMismatch: Int32 = 66
    public static let krbApErrNoTgt: Int32 = 67
    public static let kdcErrWrongRealm: Int32 = 68
    public static let krbApErrUserToUserRequired: Int32 = 69
    public static let kdcErrCantVerifyCertificate: Int32 = 70
    public static let kdcErrInvalidCertificate: Int32 = 71
    public static let kdcErrRevokedCertificate: Int32 = 72
    public static let kdcErrRevocationStatusUnknown: Int32 = 73
    public static let kdcErrRevocationStatusUnavailable: Int32 = 74
    public static let kdcErrClientNameMismatch: Int32 = 75
    public static let kdcErrKdcNameMismatch: Int32 = 76
    /// RFC 6113 (FAST).
    public static let kdcErrPreauthExpired: Int32 = 90
    public static let kdcErrMorePreauthDataRequired: Int32 = 91
    public static let kdcErrPreauthBadAuthenticationSet: Int32 = 92
    public static let kdcErrUnknownCriticalFastOptions: Int32 = 93

    private static let names: [Int32: String] = [
        0: "KDC_ERR_NONE", 1: "KDC_ERR_NAME_EXP", 2: "KDC_ERR_SERVICE_EXP", 3: "KDC_ERR_BAD_PVNO",
        4: "KDC_ERR_C_OLD_MAST_KVNO", 5: "KDC_ERR_S_OLD_MAST_KVNO", 6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE", 9: "KDC_ERR_NULL_KEY",
        10: "KDC_ERR_CANNOT_POSTDATE", 11: "KDC_ERR_NEVER_VALID", 12: "KDC_ERR_POLICY", 13: "KDC_ERR_BADOPTION",
        14: "KDC_ERR_ETYPE_NOSUPP", 15: "KDC_ERR_SUMTYPE_NOSUPP", 16: "KDC_ERR_PADATA_TYPE_NOSUPP",
        17: "KDC_ERR_TRTYPE_NOSUPP", 18: "KDC_ERR_CLIENT_REVOKED", 19: "KDC_ERR_SERVICE_REVOKED",
        20: "KDC_ERR_TGT_REVOKED", 21: "KDC_ERR_CLIENT_NOTYET", 22: "KDC_ERR_SERVICE_NOTYET",
        23: "KDC_ERR_KEY_EXPIRED", 24: "KDC_ERR_PREAUTH_FAILED", 25: "KDC_ERR_PREAUTH_REQUIRED",
        26: "KDC_ERR_SERVER_NOMATCH", 27: "KDC_ERR_MUST_USE_USER2USER", 28: "KDC_ERR_PATH_NOT_ACCEPTED",
        29: "KDC_ERR_SVC_UNAVAILABLE", 31: "KRB_AP_ERR_BAD_INTEGRITY", 32: "KRB_AP_ERR_TKT_EXPIRED",
        33: "KRB_AP_ERR_TKT_NYV", 34: "KRB_AP_ERR_REPEAT", 35: "KRB_AP_ERR_NOT_US", 36: "KRB_AP_ERR_BADMATCH",
        37: "KRB_AP_ERR_SKEW", 38: "KRB_AP_ERR_BADADDR", 39: "KRB_AP_ERR_BADVERSION", 40: "KRB_AP_ERR_MSG_TYPE",
        41: "KRB_AP_ERR_MODIFIED", 42: "KRB_AP_ERR_BADORDER", 43: "KRB_AP_ERR_ILL_CR_TKT",
        44: "KRB_AP_ERR_BADKEYVER", 45: "KRB_AP_ERR_NOKEY", 46: "KRB_AP_ERR_MUT_FAIL",
        47: "KRB_AP_ERR_BADDIRECTION", 48: "KRB_AP_ERR_METHOD", 49: "KRB_AP_ERR_BADSEQ",
        50: "KRB_AP_ERR_INAPP_CKSUM", 51: "KRB_AP_PATH_NOT_ACCEPTED", 52: "KRB_ERR_RESPONSE_TOO_BIG",
        60: "KRB_ERR_GENERIC", 61: "KRB_ERR_FIELD_TOOLONG", 62: "KDC_ERROR_CLIENT_NOT_TRUSTED",
        63: "KDC_ERROR_KDC_NOT_TRUSTED", 64: "KDC_ERROR_INVALID_SIG", 65: "KDC_ERR_KEY_TOO_WEAK",
        66: "KDC_ERR_CERTIFICATE_MISMATCH", 67: "KRB_AP_ERR_NO_TGT", 68: "KDC_ERR_WRONG_REALM",
        69: "KRB_AP_ERR_USER_TO_USER_REQUIRED", 70: "KDC_ERR_CANT_VERIFY_CERTIFICATE",
        71: "KDC_ERR_INVALID_CERTIFICATE", 72: "KDC_ERR_REVOKED_CERTIFICATE",
        73: "KDC_ERR_REVOCATION_STATUS_UNKNOWN", 74: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
        75: "KDC_ERR_CLIENT_NAME_MISMATCH", 76: "KDC_ERR_KDC_NAME_MISMATCH",
        90: "KDC_ERR_PREAUTH_EXPIRED", 91: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
        92: "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET", 93: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS",
    ]

    /// RFC spelling for logs, e.g. `name(25) == "KDC_ERR_PREAUTH_REQUIRED"`; `"ERROR_<n>"` if unknown.
    public static func name(_ code: Int32) -> String { names[code] ?? "ERROR_\(code)" }
}
