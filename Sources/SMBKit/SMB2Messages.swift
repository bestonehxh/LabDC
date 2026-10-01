/// SMB2 request and response bodies (MS-SMB2 §2.2). Every buffer offset on the wire is
/// relative to the start of the SMB2 header, so encoders here produce the body that follows a
/// 64-byte header and compute offsets as `64 + position`. Requests are parsed by the server
/// and encoded by clients (tests); responses the other way round.

/// SMB2_FILEID (persistent, volatile).
public struct SMB2FileID: Sendable, Hashable, CustomStringConvertible {
    public var persistent: UInt64
    public var volatile: UInt64
    public init(persistent: UInt64, volatile: UInt64) {
        self.persistent = persistent
        self.volatile = volatile
    }
    /// 0xFFFFFFFFFFFFFFFF:0xFFFFFFFFFFFFFFFF, "the FileId of the previous CREATE" in a related compound
    /// and "no file" for IOCTLs such as VALIDATE_NEGOTIATE_INFO.
    public static let any = SMB2FileID(persistent: .max, volatile: .max)
    public var bytes: [UInt8] {
        var b: [UInt8] = []
        b.put64(persistent)
        b.put64(volatile)
        return b
    }
    init(_ r: inout SMBReader) throws {
        persistent = try r.u64()
        volatile = try r.u64()
    }
    public var description: String { "\(String(persistent, radix: 16)):\(String(volatile, radix: 16))" }
}

private let headerSize = SMB2Header.size

/// Reads `length` bytes at a header-relative `offset` of the whole message `m` (0/0 is empty).
func field(_ m: [UInt8], offset: Int, length: Int) throws -> [UInt8] {
    if length == 0 { return [] }
    guard let b = m.slice(offset, length) else {
        throw SMBKitError.malformed("buffer \(offset)+\(length) outside a \(m.count)-byte message")
    }
    return b
}

/// Checks StructureSize and returns a reader positioned after it.
func body(_ m: [UInt8], structureSize: UInt16) throws -> SMBReader {
    var r = SMBReader(m, offset: headerSize)
    let s = try r.u16()
    guard s == structureSize else { throw SMBKitError.malformed("StructureSize \(s), expected \(structureSize)") }
    return r
}

// MARK: - NEGOTIATE

/// A negotiate context (MS-SMB2 §2.2.3.1): ContextType(2) DataLength(2) Reserved(4) Data.
public struct SMB2NegotiateContext: Sendable, Equatable {
    public static let preauthIntegrity: UInt16 = 0x0001
    public static let encryption: UInt16 = 0x0002
    public static let compression: UInt16 = 0x0003
    public static let netname: UInt16 = 0x0005
    public static let transport: UInt16 = 0x0006
    public static let rdmaTransform: UInt16 = 0x0007
    public static let signing: UInt16 = 0x0008

    public var type: UInt16
    public var data: [UInt8]
    public init(type: UInt16, data: [UInt8]) {
        self.type = type
        self.data = data
    }

    /// Encodes a list, each context 8-byte aligned (relative to `startAlignment`).
    static func encodeList(_ list: [SMB2NegotiateContext]) -> [UInt8] {
        var b: [UInt8] = []
        for (i, c) in list.enumerated() {
            if i > 0 { b.pad(to: 8) }
            b.put16(c.type)
            b.put16(UInt16(c.data.count))
            b.put32(0)
            b += c.data
        }
        return b
    }

    static func decodeList(_ m: [UInt8], offset: Int, count: Int) throws -> [SMB2NegotiateContext] {
        var out: [SMB2NegotiateContext] = []
        var at = offset
        for _ in 0..<count {
            at = (at + 7) & ~7
            var r = SMBReader(m, offset: at)
            let type = try r.u16()
            let len = Int(try r.u16())
            try r.skip(4)
            out.append(SMB2NegotiateContext(type: type, data: try r.take(len)))
            at = r.offset
        }
        return out
    }

    /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES: HashAlgorithmCount(2) SaltLength(2) HashAlgorithms(2*n) Salt.
    public static func preauth(hashAlgorithms: [UInt16] = [1], salt: [UInt8]) -> SMB2NegotiateContext {
        var d: [UInt8] = []
        d.put16(UInt16(hashAlgorithms.count))
        d.put16(UInt16(salt.count))
        for h in hashAlgorithms { d.put16(h) }
        d += salt
        return SMB2NegotiateContext(type: preauthIntegrity, data: d)
    }

    /// SMB2_SIGNING_CAPABILITIES: SigningAlgorithmCount(2) SigningAlgorithms(2*n).
    /// 0 HMAC-SHA256, 1 AES-CMAC, 2 AES-GMAC.
    public static func signingCapabilities(_ algorithms: [UInt16]) -> SMB2NegotiateContext {
        var d: [UInt8] = []
        d.put16(UInt16(algorithms.count))
        for a in algorithms { d.put16(a) }
        return SMB2NegotiateContext(type: signing, data: d)
    }

    /// The UInt16 list of a preauth (hash algorithms), encryption (ciphers) or signing context.
    public var algorithmList: [UInt16] {
        guard data.count >= 2 else { return [] }
        let n = Int(data.le16(0))
        let start = type == Self.preauthIntegrity ? 4 : 2
        var out: [UInt16] = []
        for i in 0..<n where start + 2 * i + 2 <= data.count { out.append(data.le16(start + 2 * i)) }
        return out
    }
}

public struct SMB2NegotiateRequest: Sendable, Equatable {
    public var dialects: [UInt16]
    public var securityMode: UInt16
    public var capabilities: UInt32
    public var clientGUID: [UInt8]
    public var contexts: [SMB2NegotiateContext]

    public init(dialects: [UInt16], securityMode: UInt16 = 1, capabilities: UInt32 = 0,
                clientGUID: [UInt8] = [UInt8](repeating: 0, count: 16), contexts: [SMB2NegotiateContext] = []) {
        self.dialects = dialects
        self.securityMode = securityMode
        self.capabilities = capabilities
        self.clientGUID = clientGUID
        self.contexts = contexts
    }

    /// StructureSize 36, DialectCount, SecurityMode, Reserved, Capabilities, ClientGuid,
    /// NegotiateContextOffset(4)+Count(2)+Reserved2(2) (3.1.1) or ClientStartTime(8), Dialects.
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 36)
        let count = Int(try r.u16())
        securityMode = try r.u16()
        try r.skip(2)
        capabilities = try r.u32()
        clientGUID = try r.take(16)
        let ctxOffset = Int(try r.u32())
        let ctxCount = Int(try r.u16())
        try r.skip(2)
        guard count > 0, count <= 64 else { throw SMBKitError.malformed("DialectCount \(count)") }
        var d: [UInt16] = []
        for _ in 0..<count { d.append(try r.u16()) }
        dialects = d
        if d.contains(SMB2Dialect.smb311), ctxCount > 0 {
            guard ctxCount <= 32 else { throw SMBKitError.malformed("NegotiateContextCount \(ctxCount)") }
            contexts = try SMB2NegotiateContext.decodeList(m, offset: ctxOffset, count: ctxCount)
        } else {
            contexts = []
        }
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(36)
        b.put16(UInt16(dialects.count))
        b.put16(securityMode)
        b.put16(0)
        b.put32(capabilities)
        b += clientGUID
        let ctxAt = b.count
        b.put32(0)
        b.put16(UInt16(contexts.count))
        b.put16(0)
        for d in dialects { b.put16(d) }
        if !contexts.isEmpty {
            b.pad(to: 8)                   // header is 64 bytes, so body alignment == message alignment
            b.set32(UInt32(headerSize + b.count), at: ctxAt)
            b += SMB2NegotiateContext.encodeList(contexts)
        }
        return b
    }
}

public struct SMB2NegotiateResponse: Sendable, Equatable {
    public var securityMode: UInt16
    public var dialect: UInt16
    public var serverGUID: [UInt8]
    public var capabilities: UInt32
    public var maxTransactSize: UInt32
    public var maxReadSize: UInt32
    public var maxWriteSize: UInt32
    public var systemTime: UInt64
    public var serverStartTime: UInt64
    public var securityBuffer: [UInt8]
    public var contexts: [SMB2NegotiateContext]

    public init(securityMode: UInt16, dialect: UInt16, serverGUID: [UInt8], capabilities: UInt32, maxTransactSize: UInt32,
                maxReadSize: UInt32, maxWriteSize: UInt32, systemTime: UInt64, serverStartTime: UInt64,
                securityBuffer: [UInt8], contexts: [SMB2NegotiateContext]) {
        self.securityMode = securityMode
        self.dialect = dialect
        self.serverGUID = serverGUID
        self.capabilities = capabilities
        self.maxTransactSize = maxTransactSize
        self.maxReadSize = maxReadSize
        self.maxWriteSize = maxWriteSize
        self.systemTime = systemTime
        self.serverStartTime = serverStartTime
        self.securityBuffer = securityBuffer
        self.contexts = contexts
    }

    /// StructureSize 65 | SecurityMode | DialectRevision | NegotiateContextCount | ServerGuid(16) |
    /// Capabilities | MaxTransactSize | MaxReadSize | MaxWriteSize | SystemTime(8) | ServerStartTime(8) |
    /// SecurityBufferOffset(2)=0x80 | SecurityBufferLength(2) | NegotiateContextOffset(4) | Buffer | pad8 | contexts
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(65)
        b.put16(securityMode)
        b.put16(dialect)
        b.put16(dialect == SMB2Dialect.smb311 ? UInt16(contexts.count) : 0)
        b += serverGUID
        b.put32(capabilities)
        b.put32(maxTransactSize)
        b.put32(maxReadSize)
        b.put32(maxWriteSize)
        b.put64(systemTime)
        b.put64(serverStartTime)
        b.put16(securityBuffer.isEmpty ? 0 : UInt16(headerSize + 64))
        b.put16(UInt16(securityBuffer.count))
        let ctxAt = b.count
        b.put32(0)
        b += securityBuffer
        if dialect == SMB2Dialect.smb311, !contexts.isEmpty {
            b.pad(to: 8)
            b.set32(UInt32(headerSize + b.count), at: ctxAt)
            b += SMB2NegotiateContext.encodeList(contexts)
        }
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 65)
        securityMode = try r.u16()
        dialect = try r.u16()
        let ctxCount = Int(try r.u16())
        serverGUID = try r.take(16)
        capabilities = try r.u32()
        maxTransactSize = try r.u32()
        maxReadSize = try r.u32()
        maxWriteSize = try r.u32()
        systemTime = try r.u64()
        serverStartTime = try r.u64()
        let off = Int(try r.u16())
        let len = Int(try r.u16())
        let ctxOffset = Int(try r.u32())
        securityBuffer = try field(m, offset: off, length: len)
        contexts = dialect == SMB2Dialect.smb311 ? try SMB2NegotiateContext.decodeList(m, offset: ctxOffset, count: ctxCount) : []
    }
}

// MARK: - SESSION_SETUP

public struct SMB2SessionSetupRequest: Sendable, Equatable {
    public static let flagBinding: UInt8 = 0x01
    public var flags: UInt8
    public var securityMode: UInt8
    public var capabilities: UInt32
    public var channel: UInt32
    public var securityBuffer: [UInt8]
    public var previousSessionID: UInt64

    public init(flags: UInt8 = 0, securityMode: UInt8 = 1, capabilities: UInt32 = 0, securityBuffer: [UInt8],
                previousSessionID: UInt64 = 0) {
        self.flags = flags
        self.securityMode = securityMode
        self.capabilities = capabilities
        self.channel = 0
        self.securityBuffer = securityBuffer
        self.previousSessionID = previousSessionID
    }

    /// StructureSize 25 | Flags(1) | SecurityMode(1) | Capabilities(4) | Channel(4) |
    /// SecurityBufferOffset(2)=0x58 | SecurityBufferLength(2) | PreviousSessionId(8) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 25)
        flags = try r.u8()
        securityMode = try r.u8()
        capabilities = try r.u32()
        channel = try r.u32()
        let off = Int(try r.u16())
        let len = Int(try r.u16())
        previousSessionID = try r.u64()
        securityBuffer = try field(m, offset: off, length: len)
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(25)
        b.append(flags)
        b.append(securityMode)
        b.put32(capabilities)
        b.put32(channel)
        b.put16(UInt16(headerSize + 24))
        b.put16(UInt16(securityBuffer.count))
        b.put64(previousSessionID)
        b += securityBuffer
        return b
    }
}

public struct SMB2SessionSetupResponse: Sendable, Equatable {
    public static let isGuest: UInt16 = 0x0001
    public static let isNull: UInt16 = 0x0002
    public static let encryptData: UInt16 = 0x0004
    public var sessionFlags: UInt16
    public var securityBuffer: [UInt8]

    public init(sessionFlags: UInt16, securityBuffer: [UInt8]) {
        self.sessionFlags = sessionFlags
        self.securityBuffer = securityBuffer
    }

    /// StructureSize 9 | SessionFlags(2) | SecurityBufferOffset(2)=0x48 | SecurityBufferLength(2) | Buffer
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(9)
        b.put16(sessionFlags)
        b.put16(securityBuffer.isEmpty ? 0 : UInt16(headerSize + 8))
        b.put16(UInt16(securityBuffer.count))
        b += securityBuffer
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 9)
        sessionFlags = try r.u16()
        let off = Int(try r.u16())
        let len = Int(try r.u16())
        securityBuffer = try field(m, offset: off, length: len)
    }
}

// MARK: - TREE_CONNECT

public struct SMB2TreeConnectRequest: Sendable, Equatable {
    public var flags: UInt16
    /// `\\server\share`
    public var path: String

    public init(path: String, flags: UInt16 = 0) {
        self.path = path
        self.flags = flags
    }

    /// StructureSize 9 | Flags/Reserved(2) | PathOffset(2)=0x48 | PathLength(2) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 9)
        flags = try r.u16()
        let off = Int(try r.u16())
        let len = Int(try r.u16())
        path = UTF16LE.decode(try field(m, offset: off, length: len))
    }

    public func encode() -> [UInt8] {
        let p = UTF16LE.encode(path)
        var b: [UInt8] = []
        b.put16(9)
        b.put16(flags)
        b.put16(UInt16(headerSize + 8))
        b.put16(UInt16(p.count))
        b += p
        return b
    }
}

public struct SMB2TreeConnectResponse: Sendable, Equatable {
    public static let typeDisk: UInt8 = 0x01
    public static let typePipe: UInt8 = 0x02
    /// SMB2_SHAREFLAG_NO_CACHING (0x30) and friends.
    public static let flagNoCaching: UInt32 = 0x0000_0030
    public var shareType: UInt8
    public var shareFlags: UInt32
    public var capabilities: UInt32
    public var maximalAccess: UInt32

    public init(shareType: UInt8, shareFlags: UInt32, capabilities: UInt32, maximalAccess: UInt32) {
        self.shareType = shareType
        self.shareFlags = shareFlags
        self.capabilities = capabilities
        self.maximalAccess = maximalAccess
    }

    /// StructureSize 16 | ShareType(1) | Reserved(1) | ShareFlags(4) | Capabilities(4) | MaximalAccess(4)
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(16)
        b.append(shareType)
        b.append(0)
        b.put32(shareFlags)
        b.put32(capabilities)
        b.put32(maximalAccess)
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 16)
        shareType = try r.u8()
        try r.skip(1)
        shareFlags = try r.u32()
        capabilities = try r.u32()
        maximalAccess = try r.u32()
    }
}

// MARK: - CREATE

/// A create context (MS-SMB2 §2.2.13.2): Next(4) NameOffset(2) NameLength(2) Reserved(2)
/// DataOffset(2) DataLength(4) Name pad8 Data.
public struct SMB2CreateContext: Sendable, Equatable {
    public var name: [UInt8]
    public var data: [UInt8]
    public init(name: [UInt8], data: [UInt8]) {
        self.name = name
        self.data = data
    }
    public var nameString: String { String(decoding: name, as: UTF8.self) }

    static func decodeList(_ b: [UInt8]) throws -> [SMB2CreateContext] {
        var out: [SMB2CreateContext] = []
        var at = 0
        while at < b.count {
            guard let hdr = b.slice(at, 16) else { throw SMBKitError.malformed("create context header") }
            let next = Int(hdr.le32(0))
            let nameOff = Int(hdr.le16(4)), nameLen = Int(hdr.le16(6))
            let dataOff = Int(hdr.le16(10)), dataLen = Int(hdr.le32(12))
            guard let name = b.slice(at + nameOff, nameLen) else { throw SMBKitError.malformed("create context name") }
            let data = dataLen == 0 ? [] : b.slice(at + dataOff, dataLen)
            guard let data else { throw SMBKitError.malformed("create context data") }
            out.append(SMB2CreateContext(name: name, data: data))
            if next == 0 { break }
            guard next >= 16, next % 8 == 0 else { throw SMBKitError.malformed("create context Next \(next)") }
            at += next
            if out.count > 32 { throw SMBKitError.malformed("too many create contexts") }
        }
        return out
    }

    static func encodeList(_ list: [SMB2CreateContext]) -> [UInt8] {
        var out: [UInt8] = []
        for (i, c) in list.enumerated() {
            var e: [UInt8] = []
            e.put32(0)
            e.put16(16)
            e.put16(UInt16(c.name.count))
            e.put16(0)
            let dataOffAt = e.count
            e.put16(0)
            e.put32(UInt32(c.data.count))
            e += c.name
            if !c.data.isEmpty {
                e.pad(to: 8)
                e.set16(UInt16(e.count), at: dataOffAt)
                e += c.data
            }
            if i < list.count - 1 {
                e.pad(to: 8)
                e.set32(UInt32(e.count), at: 0)
            }
            out += e
        }
        return out
    }
}

public struct SMB2CreateRequest: Sendable, Equatable {
    public var securityFlags: UInt8 = 0
    public var requestedOplockLevel: UInt8 = 0
    public var impersonationLevel: UInt32 = 2
    public var createFlags: UInt64 = 0
    public var desiredAccess: UInt32
    public var fileAttributes: UInt32 = 0
    public var shareAccess: UInt32 = 7
    public var createDisposition: UInt32 = 1
    public var createOptions: UInt32 = 0
    public var name: String
    public var contexts: [SMB2CreateContext] = []

    public init(name: String, desiredAccess: UInt32, createDisposition: UInt32 = 1, createOptions: UInt32 = 0,
                contexts: [SMB2CreateContext] = []) {
        self.name = name
        self.desiredAccess = desiredAccess
        self.createDisposition = createDisposition
        self.createOptions = createOptions
        self.contexts = contexts
    }

    /// StructureSize 57 | SecurityFlags(1) | RequestedOplockLevel(1) | ImpersonationLevel(4) |
    /// SmbCreateFlags(8) | Reserved(8) | DesiredAccess(4) | FileAttributes(4) | ShareAccess(4) |
    /// CreateDisposition(4) | CreateOptions(4) | NameOffset(2)=0x78 | NameLength(2) |
    /// CreateContextsOffset(4) | CreateContextsLength(4) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 57)
        securityFlags = try r.u8()
        requestedOplockLevel = try r.u8()
        impersonationLevel = try r.u32()
        createFlags = try r.u64()
        try r.skip(8)
        desiredAccess = try r.u32()
        fileAttributes = try r.u32()
        shareAccess = try r.u32()
        createDisposition = try r.u32()
        createOptions = try r.u32()
        let nameOff = Int(try r.u16())
        let nameLen = Int(try r.u16())
        let ctxOff = Int(try r.u32())
        let ctxLen = Int(try r.u32())
        name = UTF16LE.decode(try field(m, offset: nameOff, length: nameLen))
        contexts = ctxLen == 0 ? [] : try SMB2CreateContext.decodeList(try field(m, offset: ctxOff, length: ctxLen))
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(57)
        b.append(securityFlags)
        b.append(requestedOplockLevel)
        b.put32(impersonationLevel)
        b.put64(createFlags)
        b.put64(0)
        b.put32(desiredAccess)
        b.put32(fileAttributes)
        b.put32(shareAccess)
        b.put32(createDisposition)
        b.put32(createOptions)
        let n = UTF16LE.encode(name)
        b.put16(UInt16(headerSize + 56))
        b.put16(UInt16(n.count))
        let ctxAt = b.count
        b.put32(0)
        b.put32(0)
        b += n
        if n.isEmpty { b.append(0) }         // the Buffer is at least one byte
        if !contexts.isEmpty {
            b.pad(to: 8)
            let c = SMB2CreateContext.encodeList(contexts)
            b.set32(UInt32(headerSize + b.count), at: ctxAt)
            b.set32(UInt32(c.count), at: ctxAt + 4)
            b += c
        }
        return b
    }
}

/// The attributes CREATE, CLOSE (post-query) and FileNetworkOpenInformation report.
public struct SMB2FileTimes: Sendable, Equatable {
    public var creation: UInt64 = 0
    public var lastAccess: UInt64 = 0
    public var lastWrite: UInt64 = 0
    public var change: UInt64 = 0
    public var allocationSize: UInt64 = 0
    public var endOfFile: UInt64 = 0
    public var attributes: UInt32 = 0
    public init() {}
}

public struct SMB2CreateResponse: Sendable, Equatable {
    public var oplockLevel: UInt8 = 0
    public var flags: UInt8 = 0
    public var createAction: UInt32 = 1
    public var times: SMB2FileTimes
    public var fileID: SMB2FileID
    public var contexts: [SMB2CreateContext] = []

    public init(createAction: UInt32 = 1, times: SMB2FileTimes, fileID: SMB2FileID, contexts: [SMB2CreateContext] = []) {
        self.createAction = createAction
        self.times = times
        self.fileID = fileID
        self.contexts = contexts
    }

    /// StructureSize 89 | OplockLevel(1) | Flags(1) | CreateAction(4) | CreationTime(8) |
    /// LastAccessTime(8) | LastWriteTime(8) | ChangeTime(8) | AllocationSize(8) | EndofFile(8) |
    /// FileAttributes(4) | Reserved2(4) | FileId(16) | CreateContextsOffset(4) | CreateContextsLength(4) | Buffer
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(89)
        b.append(oplockLevel)
        b.append(flags)
        b.put32(createAction)
        b.put64(times.creation)
        b.put64(times.lastAccess)
        b.put64(times.lastWrite)
        b.put64(times.change)
        b.put64(times.allocationSize)
        b.put64(times.endOfFile)
        b.put32(times.attributes)
        b.put32(0)
        b += fileID.bytes
        if contexts.isEmpty {
            b.put32(0)
            b.put32(0)
            b.append(0)                      // Buffer (variable, at least one byte on the wire)
        } else {
            let c = SMB2CreateContext.encodeList(contexts)
            b.put32(UInt32(headerSize + 88))
            b.put32(UInt32(c.count))
            b += c
        }
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 89)
        oplockLevel = try r.u8()
        flags = try r.u8()
        createAction = try r.u32()
        var t = SMB2FileTimes()
        t.creation = try r.u64()
        t.lastAccess = try r.u64()
        t.lastWrite = try r.u64()
        t.change = try r.u64()
        t.allocationSize = try r.u64()
        t.endOfFile = try r.u64()
        t.attributes = try r.u32()
        try r.skip(4)
        times = t
        fileID = try SMB2FileID(&r)
        let off = Int(try r.u32())
        let len = Int(try r.u32())
        contexts = len == 0 ? [] : try SMB2CreateContext.decodeList(try field(m, offset: off, length: len))
    }
}

// MARK: - CLOSE / FLUSH

public struct SMB2CloseRequest: Sendable, Equatable {
    public static let postQueryAttributes: UInt16 = 0x0001
    public var flags: UInt16
    public var fileID: SMB2FileID
    public init(fileID: SMB2FileID, flags: UInt16 = 0) {
        self.fileID = fileID
        self.flags = flags
    }
    /// StructureSize 24 | Flags(2) | Reserved(4) | FileId(16)
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 24)
        flags = try r.u16()
        try r.skip(4)
        fileID = try SMB2FileID(&r)
    }
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(24)
        b.put16(flags)
        b.put32(0)
        b += fileID.bytes
        return b
    }
}

public struct SMB2CloseResponse: Sendable, Equatable {
    public var flags: UInt16
    public var times: SMB2FileTimes
    public init(flags: UInt16, times: SMB2FileTimes) {
        self.flags = flags
        self.times = times
    }
    /// StructureSize 60 | Flags(2) | Reserved(4) | CreationTime .. ChangeTime (32) |
    /// AllocationSize(8) | EndofFile(8) | FileAttributes(4)
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(60)
        b.put16(flags)
        b.put32(0)
        b.put64(times.creation)
        b.put64(times.lastAccess)
        b.put64(times.lastWrite)
        b.put64(times.change)
        b.put64(times.allocationSize)
        b.put64(times.endOfFile)
        b.put32(times.attributes)
        return b
    }
}

/// StructureSize 24 | Reserved1(2) | Reserved2(4) | FileId(16)
func parseFlush(_ m: [UInt8]) throws -> SMB2FileID {
    var r = try body(m, structureSize: 24)
    try r.skip(6)
    return try SMB2FileID(&r)
}

// MARK: - READ / WRITE

public struct SMB2ReadRequest: Sendable, Equatable {
    public var length: UInt32
    public var offset: UInt64
    public var fileID: SMB2FileID
    public var minimumCount: UInt32 = 0

    public init(fileID: SMB2FileID, length: UInt32, offset: UInt64) {
        self.fileID = fileID
        self.length = length
        self.offset = offset
    }

    /// StructureSize 49 | Padding(1) | Flags(1) | Length(4) | Offset(8) | FileId(16) |
    /// MinimumCount(4) | Channel(4) | RemainingBytes(4) | ReadChannelInfoOffset(2) |
    /// ReadChannelInfoLength(2) | Buffer(1)
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 49)
        try r.skip(2)
        length = try r.u32()
        offset = try r.u64()
        fileID = try SMB2FileID(&r)
        minimumCount = try r.u32()
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(49)
        b.append(0x50)
        b.append(0)
        b.put32(length)
        b.put64(offset)
        b += fileID.bytes
        b.put32(minimumCount)
        b.put32(0)
        b.put32(0)
        b.put16(0)
        b.put16(0)
        b.append(0)
        return b
    }
}

public struct SMB2ReadResponse: Sendable, Equatable {
    public var data: [UInt8]
    public var remaining: UInt32 = 0
    public init(data: [UInt8]) { self.data = data }

    /// StructureSize 17 | DataOffset(1)=0x50 | Reserved(1) | DataLength(4) | DataRemaining(4) | Reserved2(4) | Buffer
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(17)
        b.append(UInt8(headerSize + 16))
        b.append(0)
        b.put32(UInt32(data.count))
        b.put32(remaining)
        b.put32(0)
        b += data
        if data.isEmpty { b.append(0) }
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 17)
        let off = Int(try r.u8())
        try r.skip(1)
        let len = Int(try r.u32())
        remaining = try r.u32()
        data = try field(m, offset: off, length: len)
    }
}

public struct SMB2WriteRequest: Sendable, Equatable {
    public var offset: UInt64
    public var fileID: SMB2FileID
    public var data: [UInt8]

    public init(fileID: SMB2FileID, offset: UInt64, data: [UInt8]) {
        self.fileID = fileID
        self.offset = offset
        self.data = data
    }

    /// StructureSize 49 | DataOffset(2)=0x70 | Length(4) | Offset(8) | FileId(16) | Channel(4) |
    /// RemainingBytes(4) | WriteChannelInfoOffset(2) | WriteChannelInfoLength(2) | Flags(4) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 49)
        let off = Int(try r.u16())
        let len = Int(try r.u32())
        offset = try r.u64()
        fileID = try SMB2FileID(&r)
        data = try field(m, offset: off, length: len)
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(49)
        b.put16(UInt16(headerSize + 48))
        b.put32(UInt32(data.count))
        b.put64(offset)
        b += fileID.bytes
        b.put32(0)
        b.put32(0)
        b.put16(0)
        b.put16(0)
        b.put32(0)
        b += data
        return b
    }
}

/// StructureSize 17 | Reserved(2) | Count(4) | Remaining(4) | WriteChannelInfoOffset(2) | WriteChannelInfoLength(2)
func encodeWriteResponse(count: UInt32) -> [UInt8] {
    var b: [UInt8] = []
    b.put16(17)
    b.put16(0)
    b.put32(count)
    b.put32(0)
    b.put16(0)
    b.put16(0)
    return b
}

// MARK: - IOCTL

public struct SMB2IoctlRequest: Sendable, Equatable {
    public static let isFSCTL: UInt32 = 0x0000_0001
    public var ctlCode: UInt32
    public var fileID: SMB2FileID
    public var input: [UInt8]
    public var maxInputResponse: UInt32 = 0
    public var maxOutputResponse: UInt32
    public var flags: UInt32 = isFSCTL

    public init(ctlCode: UInt32, fileID: SMB2FileID, input: [UInt8], maxOutputResponse: UInt32) {
        self.ctlCode = ctlCode
        self.fileID = fileID
        self.input = input
        self.maxOutputResponse = maxOutputResponse
    }

    /// StructureSize 57 | Reserved(2) | CtlCode(4) | FileId(16) | InputOffset(4) | InputCount(4) |
    /// MaxInputResponse(4) | OutputOffset(4) | OutputCount(4) | MaxOutputResponse(4) | Flags(4) |
    /// Reserved2(4) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 57)
        try r.skip(2)
        ctlCode = try r.u32()
        fileID = try SMB2FileID(&r)
        let inOff = Int(try r.u32())
        let inCount = Int(try r.u32())
        maxInputResponse = try r.u32()
        _ = try r.u32()
        _ = try r.u32()
        maxOutputResponse = try r.u32()
        flags = try r.u32()
        input = try field(m, offset: inOff, length: inCount)
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(57)
        b.put16(0)
        b.put32(ctlCode)
        b += fileID.bytes
        b.put32(input.isEmpty ? 0 : UInt32(headerSize + 56))
        b.put32(UInt32(input.count))
        b.put32(maxInputResponse)
        b.put32(0)
        b.put32(0)
        b.put32(maxOutputResponse)
        b.put32(flags)
        b.put32(0)
        b += input
        return b
    }
}

public struct SMB2IoctlResponse: Sendable, Equatable {
    public var ctlCode: UInt32
    public var fileID: SMB2FileID
    public var output: [UInt8]

    public init(ctlCode: UInt32, fileID: SMB2FileID, output: [UInt8]) {
        self.ctlCode = ctlCode
        self.fileID = fileID
        self.output = output
    }

    /// StructureSize 49 | Reserved(2) | CtlCode(4) | FileId(16) | InputOffset(4)=0x70 | InputCount(4)=0 |
    /// OutputOffset(4)=0x70 | OutputCount(4) | Flags(4) | Reserved2(4) | Buffer
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(49)
        b.put16(0)
        b.put32(ctlCode)
        b += fileID.bytes
        b.put32(UInt32(headerSize + 48))
        b.put32(0)
        b.put32(UInt32(headerSize + 48))
        b.put32(UInt32(output.count))
        b.put32(0)
        b.put32(0)
        b += output
        return b
    }

    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 49)
        try r.skip(2)
        ctlCode = try r.u32()
        fileID = try SMB2FileID(&r)
        _ = try r.u32()
        _ = try r.u32()
        let off = Int(try r.u32())
        let len = Int(try r.u32())
        output = try field(m, offset: off, length: len)
    }
}

// MARK: - QUERY_DIRECTORY / QUERY_INFO / SET_INFO

public struct SMB2QueryDirectoryRequest: Sendable, Equatable {
    public static let restartScans: UInt8 = 0x01
    public static let returnSingleEntry: UInt8 = 0x02
    public static let indexSpecified: UInt8 = 0x04
    public static let reopen: UInt8 = 0x10
    public var infoClass: UInt8
    public var flags: UInt8
    public var fileIndex: UInt32 = 0
    public var fileID: SMB2FileID
    public var pattern: String
    public var outputBufferLength: UInt32

    public init(infoClass: UInt8, flags: UInt8 = 0, fileID: SMB2FileID, pattern: String, outputBufferLength: UInt32 = 65536) {
        self.infoClass = infoClass
        self.flags = flags
        self.fileID = fileID
        self.pattern = pattern
        self.outputBufferLength = outputBufferLength
    }

    /// StructureSize 33 | FileInformationClass(1) | Flags(1) | FileIndex(4) | FileId(16) |
    /// FileNameOffset(2)=0x60 | FileNameLength(2) | OutputBufferLength(4) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 33)
        infoClass = try r.u8()
        flags = try r.u8()
        fileIndex = try r.u32()
        fileID = try SMB2FileID(&r)
        let off = Int(try r.u16())
        let len = Int(try r.u16())
        outputBufferLength = try r.u32()
        pattern = UTF16LE.decode(try field(m, offset: off, length: len))
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(33)
        b.append(infoClass)
        b.append(flags)
        b.put32(fileIndex)
        b += fileID.bytes
        let p = UTF16LE.encode(pattern)
        b.put16(UInt16(headerSize + 32))
        b.put16(UInt16(p.count))
        b.put32(outputBufferLength)
        b += p
        if p.isEmpty { b.append(0) }
        return b
    }
}

/// QUERY_DIRECTORY and QUERY_INFO responses share this shape:
/// StructureSize 9 | OutputBufferOffset(2)=0x48 | OutputBufferLength(4) | Buffer
public struct SMB2OutputBufferResponse: Sendable, Equatable {
    public var output: [UInt8]
    public init(output: [UInt8]) { self.output = output }
    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(9)
        b.put16(UInt16(headerSize + 8))
        b.put32(UInt32(output.count))
        b += output
        if output.isEmpty { b.append(0) }
        return b
    }
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 9)
        let off = Int(try r.u16())
        let len = Int(try r.u32())
        output = try field(m, offset: off, length: len)
    }
}

public struct SMB2QueryInfoRequest: Sendable, Equatable {
    public var infoType: UInt8
    public var infoClass: UInt8
    public var outputBufferLength: UInt32
    public var input: [UInt8] = []
    public var additionalInformation: UInt32 = 0
    public var flags: UInt32 = 0
    public var fileID: SMB2FileID

    public init(infoType: UInt8, infoClass: UInt8, fileID: SMB2FileID, outputBufferLength: UInt32 = 65536,
                additionalInformation: UInt32 = 0) {
        self.infoType = infoType
        self.infoClass = infoClass
        self.fileID = fileID
        self.outputBufferLength = outputBufferLength
        self.additionalInformation = additionalInformation
    }

    /// StructureSize 41 | InfoType(1) | FileInfoClass(1) | OutputBufferLength(4) |
    /// InputBufferOffset(2) | Reserved(2) | InputBufferLength(4) | AdditionalInformation(4) |
    /// Flags(4) | FileId(16) | Buffer
    public init(parsing m: [UInt8]) throws {
        var r = try body(m, structureSize: 41)
        infoType = try r.u8()
        infoClass = try r.u8()
        outputBufferLength = try r.u32()
        let off = Int(try r.u16())
        try r.skip(2)
        let len = Int(try r.u32())
        additionalInformation = try r.u32()
        flags = try r.u32()
        fileID = try SMB2FileID(&r)
        input = try field(m, offset: off, length: len)
    }

    public func encode() -> [UInt8] {
        var b: [UInt8] = []
        b.put16(41)
        b.append(infoType)
        b.append(infoClass)
        b.put32(outputBufferLength)
        b.put16(input.isEmpty ? 0 : UInt16(headerSize + 40))
        b.put16(0)
        b.put32(UInt32(input.count))
        b.put32(additionalInformation)
        b.put32(flags)
        b += fileID.bytes
        b += input
        if input.isEmpty { b.append(0) }
        return b
    }
}

/// StructureSize 33 | InfoType(1) | FileInfoClass(1) | BufferLength(4) | BufferOffset(2) |
/// Reserved(2) | AdditionalInformation(4) | FileId(16) | Buffer
func parseSetInfo(_ m: [UInt8]) throws -> (infoType: UInt8, infoClass: UInt8, fileID: SMB2FileID, buffer: [UInt8]) {
    var r = try body(m, structureSize: 33)
    let type = try r.u8()
    let cls = try r.u8()
    let len = Int(try r.u32())
    let off = Int(try r.u16())
    try r.skip(6)
    let id = try SMB2FileID(&r)
    return (type, cls, id, try field(m, offset: off, length: len))
}

// MARK: - small fixed bodies

enum SMB2Body {
    /// ECHO / LOGOFF / TREE_DISCONNECT / FLUSH responses and ECHO/LOGOFF/TREE_DISCONNECT
    /// requests: StructureSize 4 | Reserved(2).
    static let four: [UInt8] = [4, 0, 0, 0]
    /// SET_INFO response: StructureSize 2.
    static let setInfoResponse: [UInt8] = [2, 0]

    /// SMB2 ERROR response (MS-SMB2 §2.2.2): StructureSize 9 | ErrorContextCount(1) |
    /// Reserved(1) | ByteCount(4) | ErrorData (at least one byte).
    static func error(data: [UInt8] = []) -> [UInt8] {
        var b: [UInt8] = []
        b.put16(9)
        b.append(0)
        b.append(0)
        b.put32(UInt32(data.count))
        b += data.isEmpty ? [0] : data
        return b
    }
}
