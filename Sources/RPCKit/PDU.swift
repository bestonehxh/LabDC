import Foundation

/// DCERPC connection-oriented PDU types (MS-RPCE / DCE 1.1, `ptype`).
public enum PDUType: UInt8, Sendable {
    case request = 0
    case response = 2
    case fault = 3
    case bind = 11
    case bindAck = 12
    case bindNak = 13
    case alterContext = 14
    case alterContextResp = 15
    case auth3 = 16
    case shutdown = 17
}

/// PDU header `pfc_flags` (MS-RPCE §2.2.2.3).
public struct PFCFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let firstFrag = PFCFlags(rawValue: 0x01)
    public static let lastFrag = PFCFlags(rawValue: 0x02)
    public static let pendingCancel = PFCFlags(rawValue: 0x04)
    public static let concMpx = PFCFlags(rawValue: 0x10)
    public static let didNotExecute = PFCFlags(rawValue: 0x20)
    public static let maybe = PFCFlags(rawValue: 0x40)
    public static let objectUUID = PFCFlags(rawValue: 0x80)
}

/// The 16-byte common PDU header (MS-RPCE §2.2.2.6). DREP is fixed at little-endian / ASCII /
/// IEEE (`10 00 00 00`).
public struct RPCHeader: Sendable {
    public var type: PDUType
    public var flags: PFCFlags
    public var fragLength: UInt16
    public var authLength: UInt16
    public var callID: UInt32

    /// Little-endian, ASCII, IEEE float — the only DREP we emit and the only one we accept.
    public static let drep: [UInt8] = [0x10, 0x00, 0x00, 0x00]

    public init(type: PDUType, flags: PFCFlags, fragLength: UInt16, authLength: UInt16, callID: UInt32) {
        self.type = type
        self.flags = flags
        self.fragLength = fragLength
        self.authLength = authLength
        self.callID = callID
    }
}

/// The `auth_verifier` trailer (MS-RPCE §2.2.2.11): the 8-byte `sec_trailer` header plus the
/// opaque `auth_value`. `padLength` is the number of stub pad bytes preceding the trailer that
/// bring it to 4-byte alignment.
public struct AuthVerifier: Sendable {
    public var type: UInt8       // RPC_C_AUTHN_* (0 = none, 9 = SPNEGO, 10 = NTLM, 68 = schannel)
    public var level: UInt8      // RPC_C_AUTHN_LEVEL_*
    public var padLength: UInt8
    public var contextID: UInt32
    public var data: [UInt8]

    public init(type: UInt8, level: UInt8, padLength: UInt8, contextID: UInt32, data: [UInt8]) {
        self.type = type
        self.level = level
        self.padLength = padLength
        self.contextID = contextID
        self.data = data
    }
}

/// A presentation context proposed in a bind: one abstract syntax and its candidate transfer
/// syntaxes (MS-RPCE §2.2.2.4).
public struct PresentationContext: Sendable {
    public var id: UInt16
    public var abstractSyntax: RPCSyntaxID
    public var transferSyntaxes: [RPCSyntaxID]
    public init(id: UInt16, abstractSyntax: RPCSyntaxID, transferSyntaxes: [RPCSyntaxID]) {
        self.id = id
        self.abstractSyntax = abstractSyntax
        self.transferSyntaxes = transferSyntaxes
    }
}

/// One entry of a bind_ack result list (MS-RPCE §2.2.2.5).
public struct ContextResult: Sendable {
    public var result: RPCContextResult
    public var reason: UInt16
    public var transferSyntax: RPCSyntaxID
    public init(result: RPCContextResult, reason: UInt16, transferSyntax: RPCSyntaxID) {
        self.result = result
        self.reason = reason
        self.transferSyntax = transferSyntax
    }
}

/// A little-endian byte reader used by the PDU decoder (independent of NDR alignment).
struct LE {
    let b: [UInt8]
    var p: Int
    init(_ b: [UInt8], _ p: Int = 0) { self.b = b; self.p = p }
    mutating func u8() throws -> UInt8 {
        guard p < b.count else { throw RPCError.malformedPDU("truncated at offset \(p)") }
        defer { p += 1 }; return b[p]
    }
    mutating func u16() throws -> UInt16 {
        guard p + 2 <= b.count else { throw RPCError.malformedPDU("truncated u16 at \(p)") }
        defer { p += 2 }; return UInt16(b[p]) | (UInt16(b[p + 1]) << 8)
    }
    mutating func u32() throws -> UInt32 {
        guard p + 4 <= b.count else { throw RPCError.malformedPDU("truncated u32 at \(p)") }
        defer { p += 4 }
        var v: UInt32 = 0; for i in 0..<4 { v |= UInt32(b[p + i]) << (8 * i) }; return v
    }
    mutating func take(_ n: Int) throws -> [UInt8] {
        guard p + n <= b.count else { throw RPCError.malformedPDU("truncated \(n) bytes at \(p)") }
        defer { p += n }; return Array(b[p..<p + n])
    }
    mutating func skip(_ n: Int) throws { _ = try take(n) }
}

struct BE {
    static func u16(_ v: UInt16) -> [UInt8] { [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8)] }
    static func u32(_ v: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) }
    }
}

/// Encodes and decodes connection-oriented DCERPC PDUs. Fragmentation is handled by the
/// connection layer; these functions serialise/parse one whole PDU.
public enum PDUCodec {

    static func le16(_ v: UInt16) -> [UInt8] { [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8)] }
    static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    /// Assembles header + body + optional auth trailer, filling in `frag_length`/`auth_length`.
    /// The caller supplies the body already laid out for `type`; padding to align the trailer to
    /// 4 bytes is inserted here and reflected in `verifier.padLength`.
    static func assemble(type: PDUType, flags: PFCFlags, callID: UInt32,
                         body: [UInt8], verifier: AuthVerifier?) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(16 + body.count + (verifier.map { 8 + $0.data.count } ?? 0))
        var payload = body
        var trailer = [UInt8]()
        var authLen: UInt16 = 0
        if let v = verifier {
            // Pad the stub so the sec_trailer starts at a 4-byte boundary relative to PDU start.
            // WP-Z: a non-zero `padLength` means the caller already appended the pad to the stub
            // *inside* the signed/sealed region (MS-RPCE §2.2.2.11; Samba verifies the response
            // checksum over stub ‖ pad), so only record it.
            let preTrailer = 16 + payload.count
            let pad = v.padLength > 0 ? 0 : (4 - preTrailer % 4) % 4
            payload.append(contentsOf: repeatElement(0, count: pad))
            trailer.append(v.type)
            trailer.append(v.level)
            trailer.append(v.padLength > 0 ? v.padLength : UInt8(pad))
            trailer.append(0)                          // auth_reserved
            trailer.append(contentsOf: le32(v.contextID))
            trailer.append(contentsOf: v.data)
            authLen = UInt16(v.data.count)
        }
        let fragLen = UInt16(16 + payload.count + trailer.count)
        out.append(5); out.append(0)                    // version 5.0
        out.append(type.rawValue)
        out.append(flags.rawValue)
        out.append(contentsOf: RPCHeader.drep)
        out.append(contentsOf: le16(fragLen))
        out.append(contentsOf: le16(authLen))
        out.append(contentsOf: le32(callID))
        out.append(contentsOf: payload)
        out.append(contentsOf: trailer)
        return out
    }

    /// A fully split PDU: header, the body **without** the auth trailer or its pad, and the
    /// trailer if present.
    public struct Parsed: Sendable {
        public var header: RPCHeader
        public var body: [UInt8]
        public var verifier: AuthVerifier?
        /// The auth-trailer pad bytes (present only for protected PDUs); `body` excludes them, but
        /// they are part of the auth provider's covered range (WP-V).
        public var authPad: [UInt8] = []
    }

    /// Parses one PDU from `bytes` (which must be exactly `frag_length` long for the strict
    /// path, or at least that long). Returns the split PDU and the number of bytes consumed.
    public static func parse(_ bytes: [UInt8]) throws -> (Parsed, consumed: Int) {
        guard bytes.count >= 16 else { throw RPCError.malformedPDU("PDU shorter than 16-byte header") }
        var r = LE(bytes)
        let verMajor = try r.u8(); let verMinor = try r.u8()
        guard verMajor == 5, verMinor == 0 else {
            throw RPCError.malformedPDU("RPC version \(verMajor).\(verMinor) is not 5.0")
        }
        guard let ptype = PDUType(rawValue: try r.u8()) else {
            throw RPCError.malformedPDU("unknown ptype")
        }
        let flags = PFCFlags(rawValue: try r.u8())
        let drep = try r.take(4)
        guard drep[0] == 0x10 else {
            throw RPCError.malformedPDU("DREP 0x\(String(drep[0], radix: 16)) is not little-endian")
        }
        let fragLen = try r.u16()
        let authLen = try r.u16()
        let callID = try r.u32()
        guard Int(fragLen) >= 16, Int(fragLen) <= bytes.count else {
            throw RPCError.malformedPDU("frag_length \(fragLen) out of range (have \(bytes.count))")
        }
        let header = RPCHeader(type: ptype, flags: flags, fragLength: fragLen, authLength: authLen, callID: callID)

        var verifier: AuthVerifier?
        var authPad = [UInt8]()
        var bodyEnd = Int(fragLen)
        if authLen > 0 {
            let trailerStart = Int(fragLen) - 8 - Int(authLen)
            guard trailerStart >= 16 else { throw RPCError.auth("auth trailer overlaps header") }
            let type = bytes[trailerStart]
            let level = bytes[trailerStart + 1]
            let padLen = bytes[trailerStart + 2]
            var cr = LE(bytes, trailerStart + 4)
            let ctxID = try cr.u32()
            let data = Array(bytes[(trailerStart + 8)..<(trailerStart + 8 + Int(authLen))])
            verifier = AuthVerifier(type: type, level: level, padLength: padLen, contextID: ctxID, data: data)
            bodyEnd = trailerStart - Int(padLen)
            guard bodyEnd >= 16 else { throw RPCError.auth("auth pad underflows body") }
            // WP-V: also expose the auth pad bytes (between body and trailer). Netlogon schannel
            // (`NL_AUTH_SHA2_SIGNATURE`, MS-NRPC §3.3.4.2) checksums/seals the padded stub, so the
            // connection appends these to the stub before verify/unseal and strips them after.
            authPad = Array(bytes[bodyEnd..<trailerStart])
        }
        let body = Array(bytes[16..<bodyEnd])
        return (Parsed(header: header, body: body, verifier: verifier, authPad: authPad), Int(fragLen))
    }

    // MARK: bind / bind_ack / bind_nak

    public static func encodeBind(callID: UInt32, maxXmit: UInt16, maxRecv: UInt16,
                                  assocGroup: UInt32, contexts: [PresentationContext],
                                  alter: Bool = false, verifier: AuthVerifier? = nil) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le16(maxXmit))
        body.append(contentsOf: le16(maxRecv))
        body.append(contentsOf: le32(assocGroup))
        body.append(UInt8(contexts.count))
        body.append(0); body.append(contentsOf: le16(0))   // reserved, reserved2
        for c in contexts {
            body.append(contentsOf: le16(c.id))
            body.append(UInt8(c.transferSyntaxes.count))
            body.append(0)                                  // reserved
            body.append(contentsOf: c.abstractSyntax.wire)
            for ts in c.transferSyntaxes { body.append(contentsOf: ts.wire) }
        }
        return assemble(type: alter ? .alterContext : .bind,
                        flags: [.firstFrag, .lastFrag], callID: callID, body: body, verifier: verifier)
    }

    public static func decodeBind(_ p: Parsed) throws -> (maxXmit: UInt16, maxRecv: UInt16, assocGroup: UInt32, contexts: [PresentationContext]) {
        var r = LE(p.body)
        let maxXmit = try r.u16()
        let maxRecv = try r.u16()
        let assoc = try r.u32()
        let n = try r.u8()
        _ = try r.u8(); _ = try r.u16()                     // reserved, reserved2
        var contexts = [PresentationContext]()
        for _ in 0..<n {
            let id = try r.u16()
            let nts = Int(try r.u8())
            _ = try r.u8()
            guard let abs = RPCSyntaxID(wire: ArraySlice(try r.take(20))) else {
                throw RPCError.malformedPDU("bad abstract syntax")
            }
            var tss = [RPCSyntaxID]()
            for _ in 0..<nts {
                guard let ts = RPCSyntaxID(wire: ArraySlice(try r.take(20))) else {
                    throw RPCError.malformedPDU("bad transfer syntax")
                }
                tss.append(ts)
            }
            contexts.append(PresentationContext(id: id, abstractSyntax: abs, transferSyntaxes: tss))
        }
        return (maxXmit, maxRecv, assoc, contexts)
    }

    public static func encodeBindAck(callID: UInt32, maxXmit: UInt16, maxRecv: UInt16,
                                     assocGroup: UInt32, secondaryAddress: String,
                                     results: [ContextResult], alter: Bool = false,
                                     verifier: AuthVerifier? = nil) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le16(maxXmit))
        body.append(contentsOf: le16(maxRecv))
        body.append(contentsOf: le32(assocGroup))
        // Secondary address: length includes the terminating NUL. For alter_context_resp Windows
        // sends length 0.
        if alter {
            body.append(contentsOf: le16(0))
        } else {
            let addr = Array(secondaryAddress.utf8) + [0]
            body.append(contentsOf: le16(UInt16(addr.count)))
            body.append(contentsOf: addr)
        }
        // Pad so the result list is 4-byte aligned relative to the PDU start.
        while (16 + body.count) % 4 != 0 { body.append(0) }
        body.append(UInt8(results.count))
        body.append(0); body.append(contentsOf: le16(0))
        for res in results {
            body.append(contentsOf: le16(res.result.rawValue))
            body.append(contentsOf: le16(res.reason))
            body.append(contentsOf: res.transferSyntax.wire)
        }
        return assemble(type: alter ? .alterContextResp : .bindAck,
                        flags: [.firstFrag, .lastFrag], callID: callID, body: body, verifier: verifier)
    }

    public static func decodeBindAck(_ p: Parsed) throws -> (maxXmit: UInt16, maxRecv: UInt16, assocGroup: UInt32, secondaryAddress: String, results: [ContextResult]) {
        var r = LE(p.body)
        let maxXmit = try r.u16()
        let maxRecv = try r.u16()
        let assoc = try r.u32()
        let secLen = Int(try r.u16())
        let secBytes = try r.take(secLen)
        let addr = secLen > 0 ? String(decoding: secBytes.prefix(while: { $0 != 0 }), as: UTF8.self) : ""
        // Realign result list to 4-byte boundary relative to PDU start.
        while (16 + r.p) % 4 != 0 { _ = try r.u8() }
        let n = try r.u8()
        _ = try r.u8(); _ = try r.u16()
        var results = [ContextResult]()
        for _ in 0..<n {
            guard let rr = RPCContextResult(rawValue: try r.u16()) else {
                throw RPCError.malformedPDU("bad context result")
            }
            let reason = try r.u16()
            guard let ts = RPCSyntaxID(wire: ArraySlice(try r.take(20))) else {
                throw RPCError.malformedPDU("bad ack transfer syntax")
            }
            results.append(ContextResult(result: rr, reason: reason, transferSyntax: ts))
        }
        return (maxXmit, maxRecv, assoc, addr, results)
    }

    public static func encodeBindNak(callID: UInt32, reason: RPCBindNakReason) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le16(reason.rawValue))
        body.append(0)   // n_protocols
        return assemble(type: .bindNak, flags: [.firstFrag, .lastFrag], callID: callID, body: body, verifier: nil)
    }

    // MARK: request / response / fault

    public static func encodeRequest(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                     contextID: UInt16, opnum: UInt16, objectUUID: DCEUUID? = nil,
                                     stub: [UInt8], verifier: AuthVerifier? = nil) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le32(allocHint))
        body.append(contentsOf: le16(contextID))
        body.append(contentsOf: le16(opnum))
        var f = flags
        if let obj = objectUUID {
            f.insert(.objectUUID)
            body.append(contentsOf: obj.bytes)
        }
        body.append(contentsOf: stub)
        return assemble(type: .request, flags: f, callID: callID, body: body, verifier: verifier)
    }

    public static func decodeRequest(_ p: Parsed) throws -> (allocHint: UInt32, contextID: UInt16, opnum: UInt16, objectUUID: DCEUUID?, stub: [UInt8]) {
        var r = LE(p.body)
        let allocHint = try r.u32()
        let ctxID = try r.u16()
        let opnum = try r.u16()
        var obj: DCEUUID?
        if p.header.flags.contains(.objectUUID) {
            obj = DCEUUID(bytes: try r.take(16))
        }
        let stub = try r.take(p.body.count - r.p)
        return (allocHint, ctxID, opnum, obj, stub)
    }

    public static func encodeResponse(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                                      contextID: UInt16, cancelCount: UInt8 = 0,
                                      stub: [UInt8], verifier: AuthVerifier? = nil) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le32(allocHint))
        body.append(contentsOf: le16(contextID))
        body.append(cancelCount)
        body.append(0)   // reserved
        body.append(contentsOf: stub)
        return assemble(type: .response, flags: flags, callID: callID, body: body, verifier: verifier)
    }

    public static func decodeResponse(_ p: Parsed) throws -> (allocHint: UInt32, contextID: UInt16, cancelCount: UInt8, stub: [UInt8]) {
        var r = LE(p.body)
        let allocHint = try r.u32()
        let ctxID = try r.u16()
        let cancel = try r.u8()
        _ = try r.u8()
        let stub = try r.take(p.body.count - r.p)
        return (allocHint, ctxID, cancel, stub)
    }

    public static func encodeFault(callID: UInt32, contextID: UInt16, status: RPCFault) -> [UInt8] {
        var body = [UInt8]()
        body.append(contentsOf: le32(0))          // alloc_hint
        body.append(contentsOf: le16(contextID))
        body.append(0)                            // cancel_count
        body.append(0)                            // reserved / flags
        body.append(contentsOf: le32(status.rawValue))
        body.append(contentsOf: le32(0))          // reserved2
        return assemble(type: .fault, flags: [.firstFrag, .lastFrag], callID: callID, body: body, verifier: nil)
    }

    public static func decodeFault(_ p: Parsed) throws -> (contextID: UInt16, status: UInt32) {
        var r = LE(p.body)
        _ = try r.u32()
        let ctxID = try r.u16()
        _ = try r.u8(); _ = try r.u8()
        let status = try r.u32()
        return (ctxID, status)
    }
}
