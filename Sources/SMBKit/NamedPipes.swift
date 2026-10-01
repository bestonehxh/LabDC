import AuthKit
import Synchronization

/// What an RPC service learns about the SMB session a pipe was opened on.
public struct SMBSessionInfo: Sendable {
    public let sessionID: UInt64
    public let identity: AuthenticatedIdentity
    /// The 16-byte key an RPC server over this pipe uses as "the session key" (SAMR password
    /// encryption, MS-SAMR §3.2.2.3): Session.ApplicationKey of MS-SMB2 §3.3.5.5.3, which is
    /// Session.SessionKey for 2.0.2/2.1 and the SMB3KDF-derived application key for 3.x.
    /// All zero for an anonymous session.
    public let sessionKey: [UInt8]
    public let isGuest: Bool
    /// `ip:port` of the client.
    public let clientAddress: String
    /// Negotiated dialect (`SMB2Dialect`).
    public let dialect: UInt16
    public let signingRequired: Bool

    public init(sessionID: UInt64, identity: AuthenticatedIdentity, sessionKey: [UInt8], isGuest: Bool,
                clientAddress: String, dialect: UInt16, signingRequired: Bool) {
        self.sessionID = sessionID
        self.identity = identity
        self.sessionKey = sessionKey
        self.isGuest = isGuest
        self.clientAddress = clientAddress
        self.dialect = dialect
        self.signingRequired = signingRequired
    }
}

/// A named pipe endpoint on IPC$ (implemented by RPCKit per pipe name).
public protocol NamedPipeService: Sendable {
    /// `samr`, `lsarpc`, `netlogon`, `srvsvc`, `wkssvc` (matched case-insensitively, with or
    /// without a leading `\` or `PIPE\`).
    var pipeName: String { get }
    /// Called for every CREATE of the pipe; the handle lives until CLOSE, TREE_DISCONNECT,
    /// LOGOFF or the end of the connection.
    func open(session: SMBSessionInfo) async -> any NamedPipeHandle
}

/// One open instance of a named pipe (message mode).
public protocol NamedPipeHandle: AnyObject, Sendable {
    /// Client -> server PDU bytes (may be partial fragments). SMB2 WRITE.
    func write(_ data: [UInt8]) async throws
    /// Server -> client bytes available (empty if none yet). SMB2 READ.
    func read(maxBytes: Int) async throws -> [UInt8]
    /// FSCTL_PIPE_TRANSCEIVE: write `data`, return up to `maxOutput` bytes of the reply and
    /// whether more of the reply is left for READs (STATUS_BUFFER_OVERFLOW on the wire).
    func transceive(_ data: [UInt8], maxOutput: Int) async throws -> (output: [UInt8], moreData: Bool)
    func close() async
}

/// A pipe that answers every message with itself (tests, diagnostics). A transceive returns
/// the input; writes queue their bytes for reads. Message boundaries are kept: a read never
/// spans two messages.
public struct EchoPipeService: NamedPipeService {
    public let pipeName: String
    public init(pipeName: String = "echo") { self.pipeName = pipeName }

    public func open(session: SMBSessionInfo) async -> any NamedPipeHandle { EchoPipeHandle() }
}

public final class EchoPipeHandle: NamedPipeHandle {
    private let state = Mutex<(queue: [[UInt8]], closed: Bool)>((queue: [], closed: false))

    public init() {}

    public func write(_ data: [UInt8]) async throws {
        try state.withLock { s in
            guard !s.closed else { throw SMBKitError.pipe("closed") }
            s.queue.append(data)
        }
    }

    public func read(maxBytes: Int) async throws -> [UInt8] {
        try state.withLock { s in
            guard !s.closed else { throw SMBKitError.pipe("closed") }
            guard var first = s.queue.first else { return [] }
            let n = min(maxBytes, first.count)
            let out = Array(first[0..<n])
            first.removeFirst(n)
            if first.isEmpty { s.queue.removeFirst() } else { s.queue[0] = first }
            return out
        }
    }

    public func transceive(_ data: [UInt8], maxOutput: Int) async throws -> (output: [UInt8], moreData: Bool) {
        try state.withLock { s in
            guard !s.closed else { throw SMBKitError.pipe("closed") }
            if data.count <= maxOutput { return (data, false) }
            s.queue.append(Array(data[maxOutput...]))
            return (Array(data[0..<maxOutput]), true)
        }
    }

    public func close() async { state.withLock { $0 = (queue: [], closed: true) } }

    public var isClosed: Bool { state.withLock { $0.closed } }
}

/// Pipe names are matched case-insensitively and without a leading `\` / `PIPE\`.
enum PipeName {
    static func normalize(_ name: String) -> String {
        var n = name.lowercased()
        while n.hasPrefix("\\") { n.removeFirst() }
        if n.hasPrefix("pipe\\") { n.removeFirst(5) }
        return n
    }
}
