import Foundation
import NIOConcurrencyHelpers
import NIOCore
import RPCKit

/// A lock-guarded FIFO of inbound byte chunks with a single async waiter. NIO delivers `channelRead`
/// serially on the event loop, so pushing there preserves byte order; `RPCServerConnection` frames
/// PDUs by `frag_length`, so chunk boundaries do not matter. An empty `receive()` result signals a
/// clean close.
final class RPCByteInbox: @unchecked Sendable {
    private let lock = NIOLock()
    private var chunks: [[UInt8]] = []
    private var waiter: CheckedContinuation<[UInt8], Never>?
    private var closed = false

    func push(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        lock.lock()
        if let w = waiter {
            waiter = nil
            lock.unlock()
            w.resume(returning: bytes)
        } else {
            chunks.append(bytes)
            lock.unlock()
        }
    }

    func close() {
        lock.lock()
        closed = true
        let w = waiter
        waiter = nil
        lock.unlock()
        w?.resume(returning: [])
    }

    func receive() async -> [UInt8] {
        lock.lock()
        if !chunks.isEmpty {
            let c = chunks.removeFirst()
            lock.unlock()
            return c
        }
        if closed {
            lock.unlock()
            return []
        }
        return await withCheckedContinuation { (c: CheckedContinuation<[UInt8], Never>) in
            self.waiter = c
            self.lock.unlock()
        }
    }
}

/// The `RPCTransport` that drives one `RPCServerConnection` over a NIO channel: reads arrive through
/// the `RPCByteInbox`, writes go straight to the channel.
final class NIORPCTransport: RPCTransport, @unchecked Sendable {
    private let channel: Channel
    private let inbox: RPCByteInbox
    let remoteAddress: String

    init(channel: Channel, inbox: RPCByteInbox, remoteAddress: String) {
        self.channel = channel
        self.inbox = inbox
        self.remoteAddress = remoteAddress
    }

    func receive() async throws -> [UInt8] { await inbox.receive() }

    func send(_ bytes: [UInt8]) async throws {
        var buf = channel.allocator.buffer(capacity: bytes.count)
        buf.writeBytes(bytes)
        try await channel.writeAndFlush(buf).get()
    }
}

/// Feeds inbound channel bytes to the connection's inbox and closes it when the peer disconnects.
final class RPCInboundHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let inbox: RPCByteInbox

    init(inbox: RPCByteInbox) { self.inbox = inbox }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        if let bytes = buf.readBytes(length: buf.readableBytes) { inbox.push(bytes) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        inbox.close()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        inbox.close()
        context.close(promise: nil)
    }

    /// WP-AJ: the `IdleStateHandler` in front of us fires after the endpoint's idle timeout with no
    /// reads or writes; close the connection (the RPC loop sees a clean close).
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is IdleStateHandler.IdleStateEvent {
            inbox.close()
            context.close(promise: nil)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }
}
