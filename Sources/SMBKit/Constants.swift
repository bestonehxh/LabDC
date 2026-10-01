/// NTSTATUS values used by the server (MS-ERREF §2.3.1).
public enum NTStatus {
    public static let success: UInt32 = 0x0000_0000
    public static let pending: UInt32 = 0x0000_0103
    public static let bufferOverflow: UInt32 = 0x8000_0005
    public static let noMoreFiles: UInt32 = 0x8000_0006
    public static let notImplemented: UInt32 = 0xC000_0002
    public static let invalidInfoClass: UInt32 = 0xC000_0003
    public static let infoLengthMismatch: UInt32 = 0xC000_0004
    public static let invalidHandle: UInt32 = 0xC000_0008
    public static let invalidParameter: UInt32 = 0xC000_000D
    public static let noSuchFile: UInt32 = 0xC000_000F
    public static let invalidDeviceRequest: UInt32 = 0xC000_0010
    public static let endOfFile: UInt32 = 0xC000_0011
    public static let moreProcessingRequired: UInt32 = 0xC000_0016
    public static let accessDenied: UInt32 = 0xC000_0022
    public static let bufferTooSmall: UInt32 = 0xC000_0023
    public static let objectNameInvalid: UInt32 = 0xC000_0033
    public static let objectNameNotFound: UInt32 = 0xC000_0034
    public static let objectNameCollision: UInt32 = 0xC000_0035
    public static let objectPathNotFound: UInt32 = 0xC000_003A
    public static let objectPathSyntaxBad: UInt32 = 0xC000_003B
    public static let logonFailure: UInt32 = 0xC000_006D
    public static let pipeEmpty: UInt32 = 0xC000_00D9
    public static let notSupported: UInt32 = 0xC000_00BB
    public static let networkNameDeleted: UInt32 = 0xC000_00C9
    public static let badNetworkName: UInt32 = 0xC000_00CC
    public static let requestNotAccepted: UInt32 = 0xC000_00D0
    public static let fileIsADirectory: UInt32 = 0xC000_00BA
    public static let notADirectory: UInt32 = 0xC000_0103
    public static let cancelled: UInt32 = 0xC000_0120
    public static let fileClosed: UInt32 = 0xC000_0128
    public static let fsDriverRequired: UInt32 = 0xC000_019C
    public static let notFound: UInt32 = 0xC000_0225
    public static let userSessionDeleted: UInt32 = 0xC000_0203
    public static let networkSessionExpired: UInt32 = 0xC000_035C
    public static let mediaWriteProtected: UInt32 = 0xC000_00A2

    /// Error severity (the two high bits are 11); warnings (10) still carry a body.
    public static func isError(_ s: UInt32) -> Bool { s & 0xC000_0000 == 0xC000_0000 }
}

/// SMB2 command codes (MS-SMB2 §2.2.1.2).
public enum SMB2Command: UInt16, Sendable, CaseIterable {
    case negotiate = 0x00, sessionSetup = 0x01, logoff = 0x02, treeConnect = 0x03, treeDisconnect = 0x04
    case create = 0x05, close = 0x06, flush = 0x07, read = 0x08, write = 0x09, lock = 0x0A, ioctl = 0x0B
    case cancel = 0x0C, echo = 0x0D, queryDirectory = 0x0E, changeNotify = 0x0F, queryInfo = 0x10
    case setInfo = 0x11, oplockBreak = 0x12
}

/// SMB2 header flags.
public enum SMB2Flags {
    public static let serverToRedir: UInt32 = 0x0000_0001
    public static let asyncCommand: UInt32 = 0x0000_0002
    public static let relatedOperations: UInt32 = 0x0000_0004
    public static let signed: UInt32 = 0x0000_0008
    public static let priorityMask: UInt32 = 0x0000_0070
    public static let dfsOperations: UInt32 = 0x1000_0000
    public static let replayOperation: UInt32 = 0x2000_0000
}

/// Dialect revisions (MS-SMB2 §2.2.3).
public enum SMB2Dialect {
    public static let smb202: UInt16 = 0x0202
    public static let smb210: UInt16 = 0x0210
    public static let smb300: UInt16 = 0x0300
    public static let smb302: UInt16 = 0x0302
    public static let smb311: UInt16 = 0x0311
    /// The wildcard revision of an SMB2 answer to an SMB1 multi-protocol negotiate.
    public static let wildcard: UInt16 = 0x02FF
    public static let all: [UInt16] = [smb202, smb210, smb300, smb302, smb311]

    public static func isSMB3(_ d: UInt16) -> Bool { d >= smb300 && d != wildcard }

    public static func name(_ d: UInt16) -> String {
        switch d {
        case smb202: "2.0.2"
        case smb210: "2.1"
        case smb300: "3.0"
        case smb302: "3.0.2"
        case smb311: "3.1.1"
        case wildcard: "2.???"
        default: "0x" + String(d, radix: 16)
        }
    }
}

/// Global capabilities (MS-SMB2 §2.2.4).
public enum SMB2Capabilities {
    public static let dfs: UInt32 = 0x01
    public static let leasing: UInt32 = 0x02
    public static let largeMTU: UInt32 = 0x04
    public static let multiChannel: UInt32 = 0x08
    public static let persistentHandles: UInt32 = 0x10
    public static let directoryLeasing: UInt32 = 0x20
    public static let encryption: UInt32 = 0x40
}

/// FSCTL / IOCTL codes (MS-FSCC §2.3, MS-SMB2 §2.2.31).
public enum FSCTL {
    public static let dfsGetReferrals: UInt32 = 0x0006_0194
    public static let dfsGetReferralsEx: UInt32 = 0x0006_01B0
    public static let pipePeek: UInt32 = 0x0011_400C
    public static let pipeWait: UInt32 = 0x0011_0018
    public static let pipeTransceive: UInt32 = 0x0011_C017
    public static let srvCopyChunk: UInt32 = 0x0014_40F2
    public static let srvEnumerateSnapshots: UInt32 = 0x0014_4064
    public static let srvRequestResumeKey: UInt32 = 0x0014_0078
    public static let srvReadHash: UInt32 = 0x0014_41BB
    public static let lmrRequestResiliency: UInt32 = 0x0014_01D4
    public static let queryNetworkInterfaceInfo: UInt32 = 0x0014_01FC
    public static let validateNegotiateInfo: UInt32 = 0x0014_0204
    public static let getReparsePoint: UInt32 = 0x0009_00A8
    public static let createOrGetObjectID: UInt32 = 0x0009_00C0
}

/// Access mask bits (MS-SMB2 §2.2.13.1).
public enum FileAccess {
    public static let readData: UInt32 = 0x0000_0001
    public static let writeData: UInt32 = 0x0000_0002
    public static let appendData: UInt32 = 0x0000_0004
    public static let readEA: UInt32 = 0x0000_0008
    public static let writeEA: UInt32 = 0x0000_0010
    public static let execute: UInt32 = 0x0000_0020
    public static let deleteChild: UInt32 = 0x0000_0040
    public static let readAttributes: UInt32 = 0x0000_0080
    public static let writeAttributes: UInt32 = 0x0000_0100
    public static let delete: UInt32 = 0x0001_0000
    public static let readControl: UInt32 = 0x0002_0000
    public static let writeDAC: UInt32 = 0x0004_0000
    public static let writeOwner: UInt32 = 0x0008_0000
    public static let synchronize: UInt32 = 0x0010_0000
    public static let accessSystemSecurity: UInt32 = 0x0100_0000
    public static let maximumAllowed: UInt32 = 0x0200_0000
    public static let genericAll: UInt32 = 0x1000_0000
    public static let genericExecute: UInt32 = 0x2000_0000
    public static let genericWrite: UInt32 = 0x4000_0000
    public static let genericRead: UInt32 = 0x8000_0000

    /// Anything that would modify a file or its metadata.
    public static let writeMask: UInt32 = writeData | appendData | writeEA | writeAttributes | delete | writeDAC
        | writeOwner | genericWrite | genericAll | deleteChild | accessSystemSecurity
    /// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: what a read-only share grants.
    public static let readOnlyMaximal: UInt32 = 0x0012_00A9
    /// FILE_ALL_ACCESS.
    public static let all: UInt32 = 0x001F_01FF
}

/// File attributes (MS-FSCC §2.6).
public enum FileAttributes {
    public static let readOnly: UInt32 = 0x0001
    public static let hidden: UInt32 = 0x0002
    public static let directory: UInt32 = 0x0010
    public static let archive: UInt32 = 0x0020
    public static let normal: UInt32 = 0x0080
}

/// FileInformationClass values (MS-FSCC §2.4) used by QUERY_INFO and QUERY_DIRECTORY.
public enum FileInfoClass {
    public static let directory: UInt8 = 1
    public static let fullDirectory: UInt8 = 2
    public static let bothDirectory: UInt8 = 3
    public static let basic: UInt8 = 4
    public static let standard: UInt8 = 5
    public static let `internal`: UInt8 = 6
    public static let ea: UInt8 = 7
    public static let access: UInt8 = 8
    public static let name: UInt8 = 9
    public static let names: UInt8 = 12
    public static let position: UInt8 = 14
    public static let mode: UInt8 = 16
    public static let alignment: UInt8 = 17
    public static let all: UInt8 = 18
    public static let alternateName: UInt8 = 21
    public static let stream: UInt8 = 22
    public static let pipe: UInt8 = 23
    public static let pipeLocal: UInt8 = 24
    public static let compression: UInt8 = 28
    public static let networkOpen: UInt8 = 34
    public static let attributeTag: UInt8 = 35
    public static let idBothDirectory: UInt8 = 37
    public static let idFullDirectory: UInt8 = 38
    public static let normalizedName: UInt8 = 48
    public static let idExtdDirectory: UInt8 = 60
}

/// FsInformationClass values (MS-FSCC §2.5).
public enum FsInfoClass {
    public static let volume: UInt8 = 1
    public static let size: UInt8 = 3
    public static let device: UInt8 = 4
    public static let attribute: UInt8 = 5
    public static let fullSize: UInt8 = 7
    public static let objectID: UInt8 = 8
    public static let sectorSize: UInt8 = 11
}

/// QUERY_INFO InfoType.
public enum InfoType {
    public static let file: UInt8 = 1
    public static let filesystem: UInt8 = 2
    public static let security: UInt8 = 3
    public static let quota: UInt8 = 4
}
