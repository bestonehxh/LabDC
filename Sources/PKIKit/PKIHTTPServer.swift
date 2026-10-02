import AuthKit
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

/// A small HTTP/1.1 server: plain HTTP for the CRL distribution point and AIA URLs (CDPs must be
/// HTTP, not HTTPS) and SCEP (PK-7), or HTTPS (`tls`) for EST (PK-7). Every request goes to the
/// handler; the response is sent with a Content-Length, keep-alive is honoured.
public final class PKIHTTPServer: Sendable {
    /// One request, with its body collected (at most `maxBodyBytes`).
    public struct Request: Sendable {
        public var method: String
        /// As received (path + query).
        public var uri: String
        /// Percent-decoded path without the query.
        public var path: String
        /// Query parameters, percent-decoded (`+` is kept: SCEP puts raw base64 there).
        public var query: [String: String]
        /// Header names lower-cased; repeated headers joined with ", ".
        public var headers: [String: String]
        public var body: [UInt8]
        public var remoteAddress: String
        /// TLS only: the client certificate the peer presented (DER), if any.
        public var peerCertificateDER: [UInt8]?
        public var isTLS: Bool
        /// Identifies the TCP connection (PK-6: HTTP Negotiate/NTLM authentication is per connection).
        public var connectionID: UInt64
        /// TLS only: the `tls-server-end-point` binding of the certificate the server presented
        /// (Extended Protection for the CES / CEP's Negotiate authentication).
        public var channelBindings: ChannelBindings?

        public init(method: String, uri: String, headers: [String: String] = [:], body: [UInt8] = [],
                    remoteAddress: String = "?", peerCertificateDER: [UInt8]? = nil, isTLS: Bool = false,
                    connectionID: UInt64 = 0, channelBindings: ChannelBindings? = nil) {
            self.channelBindings = channelBindings
            self.method = method
            self.uri = uri
            var path = uri
            var query: [String: String] = [:]
            if let hash = path.firstIndex(of: "#") { path = String(path[..<hash]) }
            if let q = path.firstIndex(of: "?") {
                for item in path[path.index(after: q)...].split(separator: "&", omittingEmptySubsequences: true) {
                    let kv = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    let key = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                    let value = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
                    if query[key] == nil { query[key] = value }
                }
                path = String(path[..<q])
            }
            self.path = path.removingPercentEncoding ?? path
            self.query = query
            self.headers = headers
            self.body = body
            self.remoteAddress = remoteAddress
            self.peerCertificateDER = peerCertificateDER
            self.isTLS = isTLS
            self.connectionID = connectionID
        }

        public func header(_ name: String) -> String? { headers[name.lowercased()] }
    }

    public struct Response: Sendable, Equatable {
        public var status: Int
        public var contentType: String
        public var body: [UInt8]
        /// Extra headers (`WWW-Authenticate`, `Content-Transfer-Encoding`, …).
        public var headers: [String: String]

        public init(status: Int, contentType: String, body: [UInt8], headers: [String: String] = [:]) {
            self.status = status
            self.contentType = contentType
            self.body = body
            self.headers = headers
        }

        public static let notFound = Response(status: 404, contentType: "text/plain", body: Array("not found\n".utf8))
    }

    public typealias Handler = @Sendable (_ method: String, _ path: String) async -> Response
    public typealias RequestHandler = @Sendable (Request) async -> Response

    /// Larger request bodies are answered 413 (SCEP / EST messages are a few KB).
    public static let maxBodyBytes = 256 * 1024

    public let requestedPort: Int
    private let bindAddresses: [String]
    private let handler: RequestHandler
    private let tls: TLSConfiguration?
    private let onRequest: (@Sendable (String) -> Void)?
    private let onConnectionClosed: (@Sendable (UInt64) -> Void)?
    static let connectionCounter = NIOLockedValueBox<UInt64>(0)

    private struct State {
        var group: MultiThreadedEventLoopGroup?
        var listeners: [Channel] = []
        var boundPort: Int?
    }
    private let state = NIOLockedValueBox(State())

    /// - Parameters:
    ///   - port: TCP port (80 in `serve`; 0 = ephemeral, read back via `boundPort`).
    ///   - onRequest: gets one line per request (`GET /pki/lab.crl -> 200 (412 bytes) from 10.0.0.5`).
    public convenience init(port: Int, bindAddresses: [String] = ["0.0.0.0", "::"],
                            onRequest: (@Sendable (String) -> Void)? = nil, handler: @escaping Handler) {
        self.init(port: port, bindAddresses: bindAddresses, tls: nil, onRequest: onRequest,
                  requestHandler: { request in await handler(request.method, request.uri) })
    }

    /// - Parameter tls: serve HTTPS with this configuration (client certificates, if requested
    ///   by it, are passed on in `Request.peerCertificateDER`).
    ///   `onConnectionClosed` gets the `Request.connectionID` of each connection that closes.
    public init(port: Int, bindAddresses: [String] = ["0.0.0.0", "::"], tls: TLSConfiguration?,
                onRequest: (@Sendable (String) -> Void)? = nil,
                onConnectionClosed: (@Sendable (UInt64) -> Void)? = nil,
                requestHandler: @escaping RequestHandler) {
        self.requestedPort = port
        self.bindAddresses = bindAddresses
        self.handler = requestHandler
        self.tls = tls
        self.onRequest = onRequest
        self.onConnectionClosed = onConnectionClosed
    }

    public var boundPort: Int? { state.withLockedValue { $0.boundPort } }

    public func start() async throws {
        let sslContext: NIOSSLContext?
        if let tls {
            do { sslContext = try NIOSSLContext(configuration: tls) } catch {
                throw PKIKitError.encoding("TLS context: \(error)")
            }
        } else {
            sslContext = nil
        }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        state.withLockedValue { $0.group = group }
        let handler = self.handler
        let onRequest = self.onRequest
        let onClosed = self.onConnectionClosed
        let bindings = tls?.tlsServerEndPoint
        var bound = requestedPort
        var boundAny = false
        for address in bindAddresses {
            let isV6 = address.contains(":")
            var bootstrap = ServerBootstrap(group: group)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .serverChannelOption(.backlog, value: 64)
                .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
                .childChannelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        if let sslContext {
                            try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: sslContext))
                        }
                        try channel.pipeline.syncOperations.configureHTTPServerPipeline(withErrorHandling: true)
                        try channel.pipeline.syncOperations.addHandler(
                            HTTPHandler(handler: handler, onRequest: onRequest, onClosed: onClosed, isTLS: sslContext != nil,
                                        channelBindings: bindings))
                    }
                }
            if isV6 {
                bootstrap = bootstrap.serverChannelOption(
                    ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only), value: 1)
            }
            do {
                let channel = try await bootstrap.bind(host: address, port: bound).get()
                state.withLockedValue { $0.listeners.append(channel) }
                if bound == 0, let p = channel.localAddress?.port { bound = p }
                boundAny = true
            } catch {
                if boundAny { continue }
                if isV6 && address != bindAddresses.first { continue }
                await stop()
                throw PKIKitError.encoding("HTTP listener \(address):\(bound): \(error)")
            }
        }
        guard boundAny else {
            await stop()
            throw PKIKitError.encoding("HTTP listener: no address could be bound for port \(requestedPort)")
        }
        state.withLockedValue { $0.boundPort = bound }
    }

    public func stop() async {
        let (channels, group): ([Channel], MultiThreadedEventLoopGroup?) = state.withLockedValue {
            let c = $0.listeners
            $0.listeners = []
            let g = $0.group
            $0.group = nil
            $0.boundPort = nil
            return (c, g)
        }
        for c in channels { try? await c.close() }
        if let group { try? await group.shutdownGracefully() }
    }

    /// The URI as logged: a SCEP `message=` (a whole PKCS#7 in base64) is shown by its size.
    public static func loggableURI(_ uri: String) -> String {
        guard let q = uri.firstIndex(of: "?") else { return uri }
        let items = uri[uri.index(after: q)...].split(separator: "&", omittingEmptySubsequences: false).map { item -> String in
            let kv = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if kv[0].lowercased() == "message", kv.count > 1 { return "message=<\(kv[1].count) chars>" }
            return String(item)
        }
        return String(uri[..<q]) + "?" + items.joined(separator: "&")
    }
}

private final class HTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let handler: PKIHTTPServer.RequestHandler
    private let onRequest: (@Sendable (String) -> Void)?
    private let onClosed: (@Sendable (UInt64) -> Void)?
    private let isTLS: Bool
    private let channelBindings: ChannelBindings?
    private let connectionID: UInt64
    private var head: HTTPRequestHead?
    private var body: [UInt8] = []
    private var tooLarge = false

    init(handler: @escaping PKIHTTPServer.RequestHandler, onRequest: (@Sendable (String) -> Void)?,
         onClosed: (@Sendable (UInt64) -> Void)?, isTLS: Bool, channelBindings: ChannelBindings?) {
        self.handler = handler
        self.channelBindings = channelBindings
        self.onRequest = onRequest
        self.onClosed = onClosed
        self.isTLS = isTLS
        connectionID = PKIHTTPServer.connectionCounter.withLockedValue { $0 += 1; return $0 }
    }

    func channelInactive(context: ChannelHandlerContext) {
        onClosed?(connectionID)
        context.fireChannelInactive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body = []
            tooLarge = false
            if h.headers["expect"].contains(where: { $0.lowercased() == "100-continue" }) {
                context.writeAndFlush(wrapOutboundOut(.head(HTTPResponseHead(version: h.version, status: .continue))),
                                      promise: nil)
            }
        case .body(var buffer):
            if body.count + buffer.readableBytes > PKIHTTPServer.maxBodyBytes {
                tooLarge = true
            } else if let bytes = buffer.readBytes(length: buffer.readableBytes) {
                body += bytes
            }
        case .end:
            guard let head else { return }
            self.head = nil
            let onRequest = self.onRequest
            let method = head.method.rawValue
            let uri = head.uri
            let keepAlive = head.isKeepAlive
            let version = head.version
            let remote = context.channel.remoteAddress?.ipAddress ?? "?"
            let loop = context.eventLoop
            let contextBox = NIOLoopBound(context, eventLoop: loop)
            let selfBox = NIOLoopBound(self, eventLoop: loop)
            if tooLarge {
                write(.init(status: 413, contentType: "text/plain", body: Array("request too large\n".utf8)), method: method,
                      version: version, keepAlive: false, context: context)
                onRequest?("\(method) \(PKIHTTPServer.loggableURI(uri)) -> 413 from \(remote)")
                return
            }
            var headers: [String: String] = [:]
            for (name, value) in head.headers {
                let key = name.lowercased()
                headers[key] = headers[key].map { $0 + ", " + value } ?? value
            }
            var peer: [UInt8]?
            if isTLS, let ssl = try? context.pipeline.syncOperations.handler(type: NIOSSLServerHandler.self) {
                peer = try? ssl.peerCertificate?.toDERBytes()
            }
            let request = PKIHTTPServer.Request(method: method, uri: uri, headers: headers, body: body, remoteAddress: remote,
                                                peerCertificateDER: peer, isTLS: isTLS, connectionID: connectionID,
                                                channelBindings: isTLS ? channelBindings : nil)
            body = []
            let handler = self.handler
            Task {
                let response = await handler(request)
                onRequest?("\(method) \(PKIHTTPServer.loggableURI(uri)) -> \(response.status) (\(response.body.count) bytes) from \(remote)")
                loop.execute {
                    selfBox.value.write(response, method: method, version: version, keepAlive: keepAlive,
                                        context: contextBox.value)
                }
            }
        }
    }

    private func write(_ response: PKIHTTPServer.Response, method: String, version: HTTPVersion, keepAlive: Bool,
                       context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: response.contentType)
        headers.add(name: "Content-Length", value: String(response.body.count))
        headers.add(name: "Server", value: "LabDC")
        for (name, value) in response.headers.sorted(by: { $0.key < $1.key }) { headers.add(name: name, value: value) }
        if response.status == 200, response.headers["Cache-Control"] == nil, method == "GET",
           response.contentType == "application/pkix-crl" || response.contentType == "application/pkix-cert" {
            headers.add(name: "Cache-Control", value: "max-age=3600")
        }
        if !keepAlive { headers.add(name: "Connection", value: "close") }
        let head = HTTPResponseHead(version: version, status: HTTPResponseStatus(statusCode: response.status),
                                    headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        if method != "HEAD", !response.body.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: response.body.count)
            buffer.writeBytes(response.body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        let channel = context.channel
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            if !keepAlive { channel.close(promise: nil) }
        }
    }
}
