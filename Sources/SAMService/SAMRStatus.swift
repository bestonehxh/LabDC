import Foundation

/// The subset of NTSTATUS codes (MS-ERREF §2.3.1) SAMR replies carry in the `ErrorCode` field of
/// each response (SAMR does not fault on business errors; it returns a well-formed reply whose
/// status word is non-zero). Values are the on-the-wire little-endian UInt32.
public enum NTStatus: UInt32, Sendable {
    case success              = 0x0000_0000
    case someNotMapped        = 0x0000_0107   // STATUS_SOME_NOT_MAPPED (a warning, not an error)
    case moreEntries          = 0x0000_0105   // STATUS_MORE_ENTRIES
    case noMoreEntries        = 0x8000_001A   // STATUS_NO_MORE_ENTRIES
    case invalidInfoClass     = 0xC000_0003
    case invalidParameter     = 0xC000_000D
    case invalidHandle        = 0xC000_0008
    case accessDenied         = 0xC000_0022
    case objectNameNotFound   = 0xC000_0034
    case noSuchUser           = 0xC000_0064
    case wrongPassword        = 0xC000_006A
    case passwordRestriction  = 0xC000_006C
    case noSuchDomain         = 0xC000_00DF
    case noSuchGroup          = 0xC000_0066
    case noSuchAlias          = 0xC000_0151
    case memberNotInGroup     = 0xC000_0068
    case userExists           = 0xC000_0063
    case groupExists          = 0xC000_0065
    case noneMapped           = 0xC000_0073
    case notSupported         = 0xC000_00BB
    case noUserSessionKey     = 0xC000_0202   // STATUS_NO_USER_SESSION_KEY
    case internalError        = 0xC000_00E5
    case machineAccountQuotaExceeded = 0xC000_02E7  // STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED
}

/// A SAMR business error carrying the NTSTATUS to place in a response's `ErrorCode`. Handlers
/// throw this; each opnum's marshaller catches it and emits the empty/nulled out parameters with
/// the code (SAMR replies are always well-formed NDR, never RPC faults).
struct SAMRError: Error {
    let status: NTStatus
    init(_ status: NTStatus) { self.status = status }
}
