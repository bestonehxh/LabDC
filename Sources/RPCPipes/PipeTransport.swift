import Foundation
import RPCKit
import SMBKit

/// Bridges an SMB named-pipe handle (message-mode WRITE / READ / FSCTL_PIPE_TRANSCEIVE, WP-R)
/// to an `RPCServerConnection` driven over an `RPCTransport` (WP-S).
///
/// Client PDU bytes written to the pipe are the transport's inbound byte stream; the connection's
/// response bytes are buffered for READ and transceive output. The connection reassembles request
/// fragments and fragments its responses by `frag_length`, so the channel need not preserve
/// message boundaries — it is a byte pipe in each direction, exactly what `ncacn_np` provides.
///
/// - WRITE feeds bytes and returns at once; the server processes asynchronously (older clients
///   that WRITE then READ).
/// - READ drains whatever response bytes are ready (empty if none yet); SMBKit polls it up to
///   `pipeReadTimeout` and answers `STATUS_PIPE_EMPTY` if nothing arrives.
/// - FSCTL_PIPE_TRANSCEIVE feeds the request bytes, waits for the connection to produce the whole
///   response (it goes idle again on the next `receive()`), then returns up to `maxOutput` bytes;
///   a longer response sets `moreData` and the remainder is drained by READs (STATUS_BUFFER_OVERFLOW).
actor PipeChannel {
    private var inbound: [UInt8] = []
    /// Server -> client responses, one entry per PDU. A Windows named pipe in message mode returns
    /// one message per READ, and impacket (and Windows RPC) read one PDU per SMB READ: concatenating
    /// fragments into a byte stream makes the client's next read of a multi-fragment response find an
    /// empty pipe (STATUS_PIPE_EMPTY). So each `RPCServerConnection` PDU (`transport.send`) is kept
    /// as its own message.
    private var outbound: [[UInt8]] = []
    /// The unread tail of a message the client has only partially READ (message-mode continuation).
    private var partial: [UInt8] = []
    private var closed = false
    /// The server's pending `receive()` (it is blocked waiting for client bytes).
    private var receiveWaiter: CheckedContinuation<[UInt8], Never>?
    /// Callers of `transceive` waiting for the server to finish this request and go idle.
    private var idleWaiters: [CheckedContinuation<Void, Never>] = []

    // MARK: client -> server

    /// Appends client bytes; wakes the server if it is blocked in `receive()`.
    func feed(_ bytes: [UInt8]) {
        guard !closed, !bytes.isEmpty else { return }
        if let w = receiveWaiter {
            receiveWaiter = nil
            w.resume(returning: bytes)
        } else {
            inbound.append(contentsOf: bytes)
        }
    }

    // MARK: server transport (RPCTransport)

    /// The next chunk of client bytes; empty array signals a clean close. When the server blocks
    /// here with nothing buffered it has finished the previous request, so any `transceive` waiter
    /// is released to collect the response.
    func receive() async -> [UInt8] {
        if !inbound.isEmpty {
            let c = inbound
            inbound = []
            return c
        }
        if closed { return [] }
        let waiters = idleWaiters
        idleWaiters = []
        for w in waiters { w.resume() }
        return await withCheckedContinuation { receiveWaiter = $0 }
    }

    /// Buffers one server response PDU as its own message.
    func send(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        outbound.append(bytes)
    }

    // MARK: client READ / TRANSCEIVE

    /// Up to `max` bytes of the next message (message boundaries preserved), or empty if none are
    /// ready (non-blocking). A message larger than `max` is returned across successive reads.
    func readOutbound(max: Int) -> [UInt8] {
        guard max > 0 else { return [] }
        if partial.isEmpty {
            guard !outbound.isEmpty else { return [] }
            partial = outbound.removeFirst()
        }
        let n = Swift.min(max, partial.count)
        let o = Array(partial[0..<n])
        partial.removeFirst(n)
        return o
    }

    private var hasOutbound: Bool { !partial.isEmpty || !outbound.isEmpty }

    /// Feed a request, wait for the server to settle, then return the first response message (up to
    /// `max`); `more` is true when that message did not fit and the remainder must be READ
    /// (STATUS_BUFFER_OVERFLOW). Further response PDUs are separate messages the client READs next.
    func transceive(_ bytes: [UInt8], max: Int) async -> (output: [UInt8], more: Bool) {
        if !closed {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                idleWaiters.append(c)
                feed(bytes)
            }
        }
        let out = readOutbound(max: max)
        return (out, !partial.isEmpty)
    }

    func close() {
        closed = true
        if let w = receiveWaiter {
            receiveWaiter = nil
            w.resume(returning: [])
        }
        let waiters = idleWaiters
        idleWaiters = []
        for w in waiters { w.resume() }
    }
}

/// The `RPCTransport` the connection is driven over: it reads and writes the shared `PipeChannel`.
struct PipeChannelTransport: RPCTransport {
    let channel: PipeChannel
    let remoteAddress: String

    func receive() async throws -> [UInt8] { await channel.receive() }
    func send(_ bytes: [UInt8]) async throws { await channel.send(bytes) }
}

/// One open pipe instance: an `RPCServerConnection` running over a `PipeChannel`, exposed to
/// SMBKit as a `NamedPipeHandle`.
public final class RPCPipeHandle: NamedPipeHandle, @unchecked Sendable {
    private let channel = PipeChannel()
    private let task: Task<Void, Never>

    public init(session: SMBSessionInfo, setup: RPCPipeSetup) {
        let channel = self.channel
        let transport = PipeChannelTransport(channel: channel, remoteAddress: session.clientAddress)
        let connection = RPCServerConnection(transport: transport, identity: session.identity,
                                             sessionKey: session.sessionKey, authProvider: setup.authProvider)
        for iface in setup.interfaces { connection.register(iface) }
        task = Task { try? await connection.run() }
    }

    public func write(_ data: [UInt8]) async throws { await channel.feed(data) }

    public func read(maxBytes: Int) async throws -> [UInt8] { await channel.readOutbound(max: maxBytes) }

    public func transceive(_ data: [UInt8], maxOutput: Int) async throws -> (output: [UInt8], moreData: Bool) {
        let r = await channel.transceive(data, max: maxOutput)
        return (r.output, r.more)
    }

    public func close() async {
        await channel.close()
        task.cancel()
    }
}
