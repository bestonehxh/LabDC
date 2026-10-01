import Foundation

/// A transport-agnostic message channel carrying whole DCERPC PDU byte strings. SMBKit (WP-R)
/// exposes named pipes; WP-X adapts a `NamedPipeHandle` to this. Each `receive()` returns one or
/// more bytes as they arrive; the connection layer frames PDUs by `frag_length`, so a transport
/// need not preserve message boundaries — but the in-memory and TCP transports below do deliver
/// whole PDUs, which keeps the framing simple and testable.
public protocol RPCTransport: Sendable {
    /// Returns the next chunk of bytes from the peer. An empty array signals a clean close.
    func receive() async throws -> [UInt8]
    /// Sends bytes to the peer.
    func send(_ bytes: [UInt8]) async throws
    /// A stable description of the remote endpoint, surfaced in `RPCCallContext`.
    var remoteAddress: String { get }
}

/// An unbounded async byte-chunk queue used by the in-memory transport.
private actor ByteChannel {
    private var chunks: [[UInt8]] = []
    private var waiters: [CheckedContinuation<[UInt8], Never>] = []
    private var closed = false

    func send(_ b: [UInt8]) {
        if let w = waiters.first {
            waiters.removeFirst()
            w.resume(returning: b)
        } else {
            chunks.append(b)
        }
    }

    func close() {
        closed = true
        while let w = waiters.first {
            waiters.removeFirst()
            w.resume(returning: [])
        }
    }

    func receive() async -> [UInt8] {
        if !chunks.isEmpty { return chunks.removeFirst() }
        if closed { return [] }
        return await withCheckedContinuation { waiters.append($0) }
    }
}

/// One end of an in-memory transport pair, for tests and for driving a server without a socket.
public final class InMemoryTransport: RPCTransport, @unchecked Sendable {
    private let inbound: ByteChannel
    private let outbound: ByteChannel
    public let remoteAddress: String

    fileprivate init(inbound: ByteChannel, outbound: ByteChannel, remoteAddress: String) {
        self.inbound = inbound
        self.outbound = outbound
        self.remoteAddress = remoteAddress
    }

    public func receive() async throws -> [UInt8] { await inbound.receive() }
    public func send(_ bytes: [UInt8]) async throws { await outbound.send(bytes) }
    public func close() async { await outbound.close() }

    /// Creates a connected `(client, server)` pair; bytes sent on one arrive on the other.
    public static func pair(remoteAddress: String = "memory:peer") -> (client: InMemoryTransport, server: InMemoryTransport) {
        let a = ByteChannel()   // client -> server
        let b = ByteChannel()   // server -> client
        let client = InMemoryTransport(inbound: b, outbound: a, remoteAddress: remoteAddress)
        let server = InMemoryTransport(inbound: a, outbound: b, remoteAddress: remoteAddress)
        return (client, server)
    }
}
