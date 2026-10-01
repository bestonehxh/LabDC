import AuthKit
import LDAPCore
import NIOCore

/// Splits the byte stream into complete LDAPMessage TLVs (`30 len …`), refusing anything
/// that is not a SEQUENCE or that announces more than `maxMessageSize` bytes.
struct LDAPFrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer

    let maxMessageSize: Int

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let first = buffer.readableBytesView.first else { return .needMoreData }
        guard first == 0x30 else {
            throw LDAPCoreError.malformed(what: "LDAPMessage", reason: "starts with 0x\(String(first, radix: 16))")
        }
        guard let length = try BERElement.frameLength(buffer.readableBytesView, limit: maxMessageSize),
              let frame = buffer.readSlice(length: length) else { return .needMoreData }
        context.fireChannelRead(wrapInboundOut(frame))
        return .continue
    }

    mutating func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        while try decode(context: context, buffer: &buffer) == .continue {}
        return .needMoreData
    }
}

/// The negotiated SASL security layer (RFC 4422 §3.7): inbound `length(4) | token` buffers are
/// unwrapped into the plaintext LDAP stream, outbound plaintext is wrapped into such buffers
/// (split so that no token exceeds the peer's maximum).
final class SASLLayerHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let layer: SASLSecurityLayer
    private var pending: [UInt8] = []

    init(layer: SASLSecurityLayer) { self.layer = layer }

    /// Plaintext per wrapped buffer: the peer's maximum minus room for the token header,
    /// padding and checksum.
    private var chunkSize: Int {
        let max = Int(layer.maxSendSize)
        guard max > 0 else { return 1 << 20 }
        return Swift.max(64, max - 128)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        pending += buffer.readBytes(length: buffer.readableBytes) ?? []
        do {
            for plaintext in try layer.deframe(&pending) {
                context.fireChannelRead(wrapInboundOut(context.channel.allocator.buffer(bytes: plaintext)))
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = unwrapOutboundIn(data)
        let plaintext = buffer.readBytes(length: buffer.readableBytes) ?? []
        do {
            var out: [UInt8] = []
            var offset = 0
            repeat {
                let end = min(plaintext.count, offset + chunkSize)
                out += try layer.frame(Array(plaintext[offset..<end]))
                offset = end
            } while offset < plaintext.count
            context.write(wrapOutboundOut(context.channel.allocator.buffer(bytes: out)), promise: promise)
        } catch {
            promise?.fail(error)
            context.fireErrorCaught(error)
        }
    }
}

/// Feeds complete LDAP messages to the connection's serial processing task.
final class LDAPConnectionHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let context: ServerContext
    private let kind: ListenerKind
    private var continuation: AsyncStream<[UInt8]>.Continuation?

    init(context: ServerContext, kind: ListenerKind) {
        self.context = context
        self.kind = kind
    }

    func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive { start(context) }
    }

    func channelActive(context: ChannelHandlerContext) {
        start(context)
        context.fireChannelActive()
    }

    private func start(_ ctx: ChannelHandlerContext) {
        guard continuation == nil else { return }
        let (stream, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        self.continuation = continuation
        let channel = ctx.channel
        let server = context
        let kind = kind
        Task {
            let connection = LDAPConnection(channel: channel, server: server, kind: kind)
            await connection.run(stream)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        continuation?.yield(Array(buffer.readableBytesView))
    }

    func channelInactive(context: ChannelHandlerContext) {
        continuation?.finish()
        continuation = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.context.logger.info("LDAP connection \(String(describing: context.remoteAddress), privacy: .public): \(String(describing: error), privacy: .public)")
        // Undecodable framing, oversize messages and broken SASL buffers end the connection
        // with a Notice of Disconnection (RFC 4511 §4.4.1), as AD does.
        if error is LDAPCoreError || error is ByteToMessageDecoderError || error is AuthKitError {
            let notice = LDAPMessage(messageID: 0, .extendedResponse(ExtendedResponse(
                result: LDAPResult(.protocolError, diagnosticMessage: "\(error)"), name: LDAPExtendedOID.noticeOfDisconnection)))
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: notice.encoded())), promise: nil)
        }
        continuation?.finish()
        continuation = nil
        context.close(promise: nil)
    }
}
