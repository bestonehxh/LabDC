import Foundation
import NIOCore
import NIOPosix
import os

// MARK: - RFC 1002 NetBIOS names

/// First- and second-level NetBIOS name encoding (RFC 1002 §4.1). A 16-byte NetBIOS name is
/// 15 characters (space-padded, upper case) plus a one-byte *suffix* that names the service
/// (`<20>` file server, `<00>` workstation, `<1B>` PDC, `<1C>` domain controllers). Each of the
/// 16 bytes is split into two nibbles, each added to `'A'`, giving the 32 "half-ASCII" bytes on
/// the wire, framed by a length byte (0x20) and terminated by an empty scope (0x00).
public enum NetBIOSName {
    /// Well-known suffixes LabDC answers for.
    public enum Suffix {
        public static let workstation: UInt8 = 0x00
        public static let fileServer: UInt8 = 0x20
        public static let pdc: UInt8 = 0x1B
        public static let domainControllers: UInt8 = 0x1C
    }

    /// The raw 16-byte NetBIOS name: 15 characters (upper-cased, space-padded) plus `suffix`.
    /// This is the form carried inside an NBSTAT node-status entry (not first-level encoded).
    public static func raw16(_ name: String, suffix: UInt8) -> [UInt8] {
        var raw = Array(name.uppercased().utf8.prefix(15))
        while raw.count < 15 { raw.append(0x20) }
        raw.append(suffix)
        return raw
    }

    /// The 32 half-ASCII bytes for `name` (upper-cased, space-padded to 15) plus `suffix`.
    public static func encode(_ name: String, suffix: UInt8) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for b in raw16(name, suffix: suffix) {
            out.append(0x41 &+ (b >> 4))
            out.append(0x41 &+ (b & 0x0F))
        }
        return out
    }

    /// The full wire encoding of a question/RR name: length(0x20) + 32 bytes + empty scope(0x00).
    public static func wire(_ name: String, suffix: UInt8) -> [UInt8] {
        [0x20] + encode(name, suffix: suffix) + [0x00]
    }

    /// Decodes a wire name at `offset`, advancing it past the name and its scope. Returns the
    /// trimmed name (trailing spaces/NULs removed) and the suffix, or nil when malformed.
    public static func decode(_ bytes: [UInt8], at offset: inout Int) -> (name: String, suffix: UInt8)? {
        guard offset < bytes.count else { return nil }
        let len = Int(bytes[offset]); offset += 1
        guard len == 32, offset + 32 <= bytes.count else { return nil }
        var raw: [UInt8] = []
        raw.reserveCapacity(16)
        var i = offset
        while i < offset + 32 {
            let hi = bytes[i] &- 0x41, lo = bytes[i + 1] &- 0x41
            guard hi <= 0x0F, lo <= 0x0F else { return nil }
            raw.append(hi << 4 | lo)
            i += 2
        }
        offset += 32
        // Scope: a sequence of length-prefixed labels ending in a zero length byte.
        while offset < bytes.count, bytes[offset] != 0 {
            offset += 1 + Int(bytes[offset])
            if offset > bytes.count { return nil }
        }
        if offset < bytes.count { offset += 1 }             // scope terminator
        let suffix = raw[15]
        var nameBytes = Array(raw[0..<15])
        while let last = nameBytes.last, last == 0x20 || last == 0x00 { nameBytes.removeLast() }
        return (String(decoding: nameBytes, as: UTF8.self), suffix)
    }
}

// MARK: - NBNS responder

/// Answers NetBIOS Name Service datagrams (RFC 1002 §4.2) for the DC's own names: the computer
/// name `<00>`/`<20>`, the domain `<1B>` (PDC, unique) and `<1C>` (domain controllers, group),
/// plus NBSTAT (`*`) node status. Every answer carries the advertised IPv4. It only ever answers
/// for names it owns (broadcast semantics: a name it does not hold gets no reply), so it is safe
/// on a shared segment.
public struct NBNSResponder: Sendable {
    public let dcName: String
    public let netbiosDomain: String
    public let addressBytes: [UInt8]
    public var ttl: UInt32
    /// Unit ID reported in NBSTAT statistics (a MAC address; zeros are fine).
    public var unitID: [UInt8]

    /// FLAGS field bits (RFC 1002 §4.2.1.1).
    enum Flags {
        static let response: UInt16 = 0x8000
        static let authoritative: UInt16 = 0x0400
        static let recursionDesired: UInt16 = 0x0100
        static let recursionAvailable: UInt16 = 0x0080
        static let opcodeMask: UInt16 = 0x7800
    }
    static let typeNB: UInt16 = 0x0020
    static let typeNBSTAT: UInt16 = 0x0021
    static let classIN: UInt16 = 0x0001
    /// NB_FLAGS: group-name bit (RFC 1002 §4.2.13).
    static let groupBit: UInt16 = 0x8000
    /// NAME_FLAGS active bit in a node-status entry (RFC 1002 §4.2.18).
    static let nodeActive: UInt16 = 0x0400

    public init?(dcName: String, netbiosDomain: String, advertisedIPv4: String,
                 ttl: UInt32 = 300_000, unitID: [UInt8] = [UInt8](repeating: 0, count: 6)) {
        guard let addr = Self.parseIPv4(advertisedIPv4) else { return nil }
        self.dcName = dcName.uppercased()
        self.netbiosDomain = netbiosDomain.uppercased()
        self.addressBytes = addr
        self.ttl = ttl
        self.unitID = unitID
    }

    /// One (name, suffix, group?) entry LabDC advertises.
    struct OwnedName { let name: String; let suffix: UInt8; let group: Bool }

    var ownedNames: [OwnedName] {
        [
            OwnedName(name: dcName, suffix: NetBIOSName.Suffix.workstation, group: false),
            OwnedName(name: dcName, suffix: NetBIOSName.Suffix.fileServer, group: false),
            OwnedName(name: netbiosDomain, suffix: NetBIOSName.Suffix.pdc, group: false),
            OwnedName(name: netbiosDomain, suffix: NetBIOSName.Suffix.domainControllers, group: true),
        ]
    }

    /// Answers a query datagram, or nil when it is malformed, not a query, or for a name we do
    /// not own.
    public func respond(to datagram: [UInt8]) -> [UInt8]? {
        guard datagram.count >= 12 else { return nil }
        let trnID = UInt16(datagram[0]) << 8 | UInt16(datagram[1])
        let flags = UInt16(datagram[2]) << 8 | UInt16(datagram[3])
        let qdCount = UInt16(datagram[4]) << 8 | UInt16(datagram[5])
        // Only a request (R=0) query (OPCODE=0) with a question.
        guard flags & Flags.response == 0, flags & Flags.opcodeMask == 0, qdCount >= 1 else { return nil }

        var offset = 12
        guard let (name, suffix) = NetBIOSName.decode(datagram, at: &offset),
              offset + 4 <= datagram.count else { return nil }
        let qType = UInt16(datagram[offset]) << 8 | UInt16(datagram[offset + 1])

        if qType == Self.typeNBSTAT {
            return nodeStatusResponse(trnID: trnID, queryName: name, querySuffix: suffix)
        }
        guard qType == Self.typeNB,
              let owned = ownedNames.first(where: { $0.name == name && $0.suffix == suffix }) else {
            return nil
        }
        return nameQueryResponse(trnID: trnID, owned: owned)
    }

    /// Positive Name Query Response (RFC 1002 §4.2.13): one address record.
    private func nameQueryResponse(trnID: UInt16, owned: OwnedName) -> [UInt8] {
        var out: [UInt8] = []
        appendHeader(&out, trnID: trnID,
                     flags: Flags.response | Flags.authoritative | Flags.recursionDesired | Flags.recursionAvailable,
                     qd: 0, an: 1)
        out += NetBIOSName.wire(owned.name, suffix: owned.suffix)
        appendU16(&out, Self.typeNB)
        appendU16(&out, Self.classIN)
        appendU32(&out, ttl)
        appendU16(&out, 6)                                   // RDLENGTH: NB_FLAGS + IPv4
        appendU16(&out, owned.group ? Self.groupBit : 0)     // NB_FLAGS
        out += addressBytes
        return out
    }

    /// Node Status Response (RFC 1002 §4.2.18): the DC's whole name list plus statistics.
    /// nil for a node-status probe of a name we do not own (wildcard `*` always answers).
    private func nodeStatusResponse(trnID: UInt16, queryName: String, querySuffix: UInt8) -> [UInt8]? {
        let known = queryName == "*" || ownedNames.contains { $0.name == queryName && $0.suffix == querySuffix }
        guard known else { return nil }

        var rdata: [UInt8] = []
        rdata.append(UInt8(ownedNames.count))                // NUM_NAMES
        for n in ownedNames {
            rdata += NetBIOSName.raw16(n.name, suffix: n.suffix)    // 16-byte name, no length/scope
            appendU16(&rdata, (n.group ? Self.groupBit : 0) | Self.nodeActive)
        }
        rdata += unitID                                      // STATISTICS: unit ID (6)
        rdata += [UInt8](repeating: 0, count: 40)            // the remaining 40 statistics bytes

        var out: [UInt8] = []
        appendHeader(&out, trnID: trnID, flags: Flags.response | Flags.authoritative, qd: 0, an: 1)
        out += NetBIOSName.wire(queryName == "*" ? "*" : queryName, suffix: querySuffix)
        appendU16(&out, Self.typeNBSTAT)
        appendU16(&out, Self.classIN)
        appendU32(&out, 0)                                   // node status TTL is 0
        appendU16(&out, UInt16(rdata.count))
        out += rdata
        return out
    }

    // MARK: byte helpers (NBNS is big-endian)

    private func appendU16(_ out: inout [UInt8], _ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF)) }
    private func appendU32(_ out: inout [UInt8], _ v: UInt32) {
        out.append(UInt8((v >> 24) & 0xFF)); out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF)); out.append(UInt8(v & 0xFF))
    }
    private func appendHeader(_ out: inout [UInt8], trnID: UInt16, flags: UInt16, qd: UInt16, an: UInt16) {
        appendU16(&out, trnID); appendU16(&out, flags)
        appendU16(&out, qd); appendU16(&out, an); appendU16(&out, 0); appendU16(&out, 0)
    }

    static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for p in parts { guard let v = UInt8(p) else { return nil }; out.append(v) }
        return out
    }
}

// MARK: - NBNS server (UDP 137)

/// A SwiftNIO UDP listener that answers `NBNSResponder` on port 137. Kept separate from the SMB
/// (445/139) listener; `serve` binds it when NetBIOS is enabled.
public final class NBNSServer: @unchecked Sendable {
    public let responder: NBNSResponder
    private let requestedPort: Int
    private let group: MultiThreadedEventLoopGroup
    private var channel: Channel?
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "NBNS")

    public init(responder: NBNSResponder, port: Int = 137,
                group: MultiThreadedEventLoopGroup = .singleton) {
        self.responder = responder
        self.requestedPort = port
        self.group = group
    }

    /// The bound port (useful when 0 was requested). Valid after `start()`.
    public var port: Int { channel?.localAddress?.port ?? requestedPort }

    public func start(host: String = "0.0.0.0") async throws {
        let bootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { [responder] channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NBNSHandler(responder: responder))
                }
            }
        let ch = try await bootstrap.bind(host: host, port: requestedPort).get()
        self.channel = ch
        Self.logger.notice("NBNS listening on udp port \(ch.localAddress?.port ?? self.requestedPort)")
    }

    public func stop() async {
        try? await channel?.close().get()
        channel = nil
    }
}

private final class NBNSHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    let responder: NBNSResponder

    init(responder: NBNSResponder) { self.responder = responder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let bytes = envelope.data.getBytes(at: envelope.data.readerIndex, length: envelope.data.readableBytes) ?? []
        guard let reply = responder.respond(to: bytes) else { return }
        var buffer = context.channel.allocator.buffer(capacity: reply.count)
        buffer.writeBytes(reply)
        context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: buffer)),
                              promise: nil)
    }
}
