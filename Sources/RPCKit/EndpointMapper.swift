import Foundation

/// A concrete RPC endpoint a tower advertises: `ncacn_ip_tcp` (dynamic port) or `ncacn_np`
/// (named pipe). The protocol-tower floor encoding is MS-RPCE §2.2.1.2.5 / C706 appendix L.
public enum RPCEndpoint: Sendable, Hashable {
    /// `ncacn_ip_tcp:<ipv4>[<port>]` — the transport floor pair is TCP port (0x07) + IPv4 (0x09).
    case tcp(ipv4: String, port: UInt16)
    /// `ncacn_np:<host>[\pipe\<name>]` — the transport floor pair is named pipe (0x0f) + host (0x11).
    case namedPipe(pipe: String, host: String)
}

/// One protocol tower: an interface, the NDR transfer syntax, and a concrete endpoint. Encodes to
/// the octet string carried by `ept_map` / `ept_lookup` (MS-RPCE §2.2.1.2.5).
public struct RPCTower: Sendable, Hashable {
    public var interface: RPCSyntaxID
    public var transferSyntax: RPCSyntaxID
    public var endpoint: RPCEndpoint

    public init(interface: RPCSyntaxID, transferSyntax: RPCSyntaxID = RPCTransferSyntax.ndr32, endpoint: RPCEndpoint) {
        self.interface = interface
        self.transferSyntax = transferSyntax
        self.endpoint = endpoint
    }

    // MARK: tower octet-string codec

    /// Protocol identifiers (C706 appendix I / MS-RPCE §2.2.1.2.5).
    enum ProtID {
        static let uuid: UInt8 = 0x0d          // interface / transfer-syntax floors
        static let connectionOriented: UInt8 = 0x0b  // ncacn
        static let tcpPort: UInt8 = 0x07
        static let ipv4: UInt8 = 0x09
        static let namedPipe: UInt8 = 0x0f
        static let hostName: UInt8 = 0x11
    }

    private static func le16(_ v: UInt16) -> [UInt8] { [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8)] }

    /// A single floor: `lhs_count(2) | lhs | rhs_count(2) | rhs` (all counts little-endian).
    private static func floor(lhs: [UInt8], rhs: [UInt8]) -> [UInt8] {
        le16(UInt16(lhs.count)) + lhs + le16(UInt16(rhs.count)) + rhs
    }

    private static func syntaxFloor(_ s: RPCSyntaxID) -> [UInt8] {
        var lhs = [ProtID.uuid]
        lhs += s.uuid.bytes
        lhs += le16(s.versionMajor)
        return floor(lhs: lhs, rhs: le16(s.versionMinor))
    }

    /// The tower as its octet string (`tower_octet_string`).
    public func encode() -> [UInt8] {
        var floors: [[UInt8]] = []
        floors.append(Self.syntaxFloor(interface))
        floors.append(Self.syntaxFloor(transferSyntax))
        // Floor 3: RPC connection-oriented protocol; RHS is a 2-byte minor version (0).
        floors.append(Self.floor(lhs: [ProtID.connectionOriented], rhs: [0, 0]))
        switch endpoint {
        case .tcp(let ipv4, let port):
            // Port RHS is big-endian; IPv4 RHS is network order.
            floors.append(Self.floor(lhs: [ProtID.tcpPort], rhs: [UInt8(port >> 8), UInt8(truncatingIfNeeded: port)]))
            floors.append(Self.floor(lhs: [ProtID.ipv4], rhs: Self.ipv4Bytes(ipv4)))
        case .namedPipe(let pipe, let host):
            floors.append(Self.floor(lhs: [ProtID.namedPipe], rhs: Array(pipe.utf8) + [0]))
            floors.append(Self.floor(lhs: [ProtID.hostName], rhs: Array(host.utf8) + [0]))
        }
        var out = Self.le16(UInt16(floors.count))
        for f in floors { out += f }
        return out
    }

    static func ipv4Bytes(_ s: String) -> [UInt8] {
        let parts = s.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : [0, 0, 0, 0]
    }

    /// Reads the interface floor (floor 1) from a tower octet string. Enough to match an
    /// `ept_map` request to a registered interface.
    public static func decodeInterface(_ octets: [UInt8]) throws -> RPCSyntaxID {
        var r = LE(octets)
        let floorCount = try r.u16()
        guard floorCount >= 1 else { throw RPCError.malformedPDU("tower with no floors") }
        let lhsLen = Int(try r.u16())
        guard lhsLen >= 19 else { throw RPCError.malformedPDU("interface floor LHS too short") }
        let lhs = try r.take(lhsLen)
        guard lhs.first == ProtID.uuid else { throw RPCError.malformedPDU("interface floor is not a UUID floor") }
        let uuid = DCEUUID(bytes: Array(lhs[1..<17]))
        let major = UInt16(lhs[17]) | (UInt16(lhs[18]) << 8)
        let rhsLen = Int(try r.u16())
        let rhs = try r.take(rhsLen)
        let minor = rhs.count >= 2 ? UInt16(rhs[0]) | (UInt16(rhs[1]) << 8) : 0
        return RPCSyntaxID(uuid: uuid, versionMajor: major, versionMinor: minor)
    }
}

/// A registered interface and the endpoints the endpoint mapper advertises for it.
public struct EPMRegistration: Sendable {
    public var interface: RPCSyntaxID
    /// A human annotation Windows/impacket display (e.g. "LabDC LSA"). NUL-terminated on the wire.
    public var annotation: String
    public var endpoints: [RPCEndpoint]

    public init(interface: RPCSyntaxID, annotation: String, endpoints: [RPCEndpoint]) {
        self.interface = interface
        self.annotation = annotation
        self.endpoints = endpoints
    }

    /// One tower per endpoint.
    public var towers: [RPCTower] {
        endpoints.map { RPCTower(interface: interface, endpoint: $0) }
    }
}

/// The RPC endpoint mapper (MS-RPCE §2.2.1.2): interface
/// `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0. Answers `ept_lookup` (opnum 2, the enumeration
/// `rpcdump` uses) and `ept_map` (opnum 3, "what port hosts interface X?"). Unknown interfaces in
/// `ept_map` get zero towers and `EPT_S_NOT_REGISTERED`.
public final class EndpointMapperService: RPCInterface, @unchecked Sendable {
    public static let interfaceID = RPCSyntaxID("e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3, 0)
    /// `EPT_S_NOT_REGISTERED` (MS-RPCE §2.2.1.2, `ept_map` status).
    public static let notRegistered: UInt32 = 0x16C9_A0D6

    public var interfaceUUID: DCEUUID { Self.interfaceID.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (Self.interfaceID.versionMajor, Self.interfaceID.versionMinor) }

    private let registrations: [EPMRegistration]

    public init(registrations: [EPMRegistration]) {
        self.registrations = registrations
    }

    /// The flat list of every advertised tower with its annotation, for `ept_lookup`.
    private var allEntries: [(tower: RPCTower, annotation: String)] {
        registrations.flatMap { reg in reg.towers.map { ($0, reg.annotation) } }
    }

    public func dispatch(opnum: UInt16, input: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        switch opnum {
        case 2: return try eptLookup(input, context: context)
        case 3: return try eptMap(input)
        default: throw RPCError.fault(.opRangeError)
        }
    }

    // MARK: ept_lookup (opnum 2)

    private func eptLookup(_ r: NDRReader, context: RPCCallContext) throws -> NDRWriter {
        _ = try r.u32()                       // inquiry_type (we return everything regardless)
        if try r.pointer() != nil { _ = try r.guid() }     // object filter (ignored)
        if try r.pointer() != nil {           // interface-id filter (ignored, we return all)
            _ = try r.guid(); _ = try r.u16(); _ = try r.u16()
        }
        _ = try r.u32()                       // vers_option
        let inHandle = try r.contextHandle()  // entry_handle [in,out]
        let maxEnts = Int(try r.u32())

        let w = NDRWriter()
        // First call (null handle) returns every entry and a non-null handle; the follow-up call
        // (non-null handle) returns zero entries and a null handle, so any client loop terminates.
        if inHandle.isNull {
            let entries = Array(allEntries.prefix(maxEnts))
            let doneHandle = ContextHandle(attributes: 1, uuid: [UInt8](repeating: 0, count: 15) + [1])
            w.contextHandle(doneHandle)
            w.u32(UInt32(entries.count))                    // num_ents
            marshalEntries(entries, maxEnts: maxEnts, into: w)
            w.u32(0)                                        // status = EPT_S_OK
        } else {
            w.contextHandle(.null)
            w.u32(0)                                        // num_ents
            marshalEntries([], maxEnts: maxEnts, into: w)
            w.u32(0)
        }
        return w
    }

    /// `ept_entry_t entries[]` — a top-level conformant/varying array (no wrapping pointer). Each
    /// entry is `object UUID(16) | tower referent(4) | annotation (varying char array)`; the
    /// `twr_t` bodies are deferred after every element's flat part (NDR pointer deferral).
    private func marshalEntries(_ entries: [(tower: RPCTower, annotation: String)], maxEnts: Int, into w: NDRWriter) {
        w.u32(UInt32(maxEnts))          // MaximumCount (size_is)
        w.u32(0)                        // Offset
        w.u32(UInt32(entries.count))    // ActualCount (length_is)
        var refID: UInt32 = 0x0002_0000
        var refs: [UInt32] = []
        let nilObject = DCEUUID(bytes: [UInt8](repeating: 0, count: 16))
        for (i, e) in entries.enumerated() {
            w.align(4)
            w.guid(nilObject)                   // object: nil UUID (no object registered)
            let ref = refID; refID += 4; refs.append(ref)
            w.u32(ref)                          // tower pointer referent id
            // annotation: NDRUniVaryingArray of char.
            let ann = Array(e.annotation.utf8) + [0]
            w.u32(0)                            // Offset
            w.u32(UInt32(ann.count))            // ActualCount
            w.raw(ann)
            _ = i
        }
        // Deferred twr_t bodies, in element order.
        for e in entries { marshalTowerBody(e.tower, into: w) }
    }

    // MARK: ept_map (opnum 3)

    private func eptMap(_ r: NDRReader) throws -> NDRWriter {
        if try r.pointer() != nil { _ = try r.guid() }     // obj (ignored)
        let requested: RPCSyntaxID?
        if try r.pointer() != nil {
            // twr_t: MaximumCount (hoisted) | tower_length | octets.
            _ = try r.u32()                   // MaximumCount
            let towerLen = Int(try r.u32())
            let octets = try r.take(towerLen)
            r.align(4)
            requested = try? RPCTower.decodeInterface(octets)
        } else {
            requested = nil
        }
        _ = try r.contextHandle()             // entry_handle [in,out]
        let maxTowers = Int(try r.u32())

        // Match by interface UUID and major version.
        let matches: [RPCTower]
        if let requested {
            matches = registrations
                .filter { $0.interface.uuid == requested.uuid && $0.interface.versionMajor == requested.versionMajor }
                .flatMap(\.towers)
        } else {
            matches = []
        }
        let towers = Array(matches.prefix(maxTowers))

        let w = NDRWriter()
        w.contextHandle(.null)                 // entry_handle (single-shot)
        w.u32(UInt32(towers.count))            // num_towers
        // ITowers: twr_p_t[] — top-level conformant/varying array of pointers.
        w.u32(UInt32(maxTowers))               // MaximumCount (size_is)
        w.u32(0)                               // Offset
        w.u32(UInt32(towers.count))            // ActualCount (length_is)
        var refID: UInt32 = 0x0002_0000
        for _ in towers { w.u32(refID); refID += 4 }   // one referent id per tower pointer
        for t in towers { marshalTowerBody(t, into: w) }
        w.u32(towers.isEmpty ? Self.notRegistered : 0)  // status
        return w
    }

    /// A `twr_t` body (the deferred pointee of a `twr_p_t`): `MaximumCount | tower_length | octets`,
    /// padded to a 4-byte boundary (the conformant byte array).
    private func marshalTowerBody(_ tower: RPCTower, into w: NDRWriter) {
        w.align(4)
        let octets = tower.encode()
        w.u32(UInt32(octets.count))    // MaximumCount (conformant, hoisted)
        w.u32(UInt32(octets.count))    // tower_length
        w.raw(octets)
        w.align(4)
    }
}
