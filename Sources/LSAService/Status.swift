import Foundation

/// NTSTATUS values the LSA interface returns (MS-ERREF §2.3.1).
public enum NTStatus {
    public static let success: UInt32 = 0x0000_0000
    /// `STATUS_SOME_NOT_MAPPED` — a lookup translated some, but not all, of the names/SIDs.
    public static let someNotMapped: UInt32 = 0x0000_0107
    /// `STATUS_NO_MORE_ENTRIES` — an enumeration has nothing (more) to return.
    public static let noMoreEntries: UInt32 = 0x8000_001A
    public static let invalidInfoClass: UInt32 = 0xC000_0003
    public static let invalidHandle: UInt32 = 0xC000_0008
    public static let invalidParameter: UInt32 = 0xC000_000D
    public static let accessDenied: UInt32 = 0xC000_0022
    /// `STATUS_NONE_MAPPED` — no name/SID in a lookup could be translated.
    public static let noneMapped: UInt32 = 0xC000_0073
    public static let notSupported: UInt32 = 0xC000_00BB
}

/// Win32 / NET_API_STATUS values srvsvc and wkssvc return (MS-ERREF §2.2).
public enum NetAPIStatus {
    public static let success: UInt32 = 0
    public static let accessDenied: UInt32 = 5
    public static let invalidParameter: UInt32 = 87
    public static let invalidLevel: UInt32 = 124
    /// `NERR_NetNameNotFound` — no share by that name.
    public static let netNameNotFound: UInt32 = 2310
}

/// `SID_NAME_USE` (MS-LSAT §2.2.13), a 16-bit NDR enum on the wire.
public enum SIDNameUse: UInt16, Sendable, Hashable, CaseIterable {
    case user = 1
    case group = 2
    case domain = 3
    case alias = 4
    case wellKnownGroup = 5
    case deletedAccount = 6
    case invalid = 7
    case unknown = 8
    case computer = 9
    case label = 10
}

/// Errors raised inside the service layer. Stub decoding failures surface to the client as
/// `nca_s_fault_ndr`.
public enum LSAServiceError: Error, CustomStringConvertible, Sendable {
    case malformed(String)

    public var description: String {
        switch self {
        case .malformed(let m): "malformed request: \(m)"
        }
    }
}
