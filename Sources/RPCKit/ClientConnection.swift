import Foundation

/// Client end of a DCERPC connection over an `RPCTransport`, used by later WPs' tests and the
/// phase-2 acceptance to exercise our own server without impacket. It binds a single interface,
/// fragments requests, and reassembles responses; faults surface as `RPCError.fault`.
public final class RPCClientConnection: @unchecked Sendable {
    private let transport: RPCTransport
    private var callID: UInt32 = 1
    private var contextID: UInt16 = 0
    private var negotiatedFrag = 4280
    private var accumulator: [UInt8] = []

    public init(transport: RPCTransport) { self.transport = transport }

    /// The presentation context id negotiated by `bind`.
    public var boundContextID: UInt16 { contextID }

    private func nextPDU() async throws -> [UInt8] {
        while true {
            if accumulator.count >= 16 {
                let fragLen = Int(UInt16(accumulator[8]) | (UInt16(accumulator[9]) << 8))
                if fragLen >= 16, accumulator.count >= fragLen {
                    let pdu = Array(accumulator[0..<fragLen])
                    accumulator.removeFirst(fragLen)
                    return pdu
                }
            }
            let chunk = try await transport.receive()
            if chunk.isEmpty { throw RPCError.transportClosed }
            accumulator.append(contentsOf: chunk)
        }
    }

    /// Binds `interface` (an abstract syntax id) proposing NDR32, plus optionally NDR64 and the
    /// bind-time feature negotiation context. Returns the accepted transfer syntax.
    /// Throws `RPCError.bindRejected` on a bind_nak or if the context is not accepted.
    @discardableResult
    public func bind(interface: RPCSyntaxID, contextID: UInt16 = 0,
                     proposeNDR64: Bool = false) async throws -> RPCSyntaxID {
        self.contextID = contextID
        var syntaxes = [RPCTransferSyntax.ndr32]
        if proposeNDR64 { syntaxes.append(RPCTransferSyntax.ndr64) }
        let ctx = PresentationContext(id: contextID, abstractSyntax: interface, transferSyntaxes: syntaxes)
        let bind = PDUCodec.encodeBind(callID: callID, maxXmit: RPCServerConnection.defaultMaxXmit,
                                       maxRecv: RPCServerConnection.defaultMaxRecv, assocGroup: 0,
                                       contexts: [ctx])
        try await transport.send(bind)
        let (parsed, _) = try PDUCodec.parse(try await nextPDU())
        switch parsed.header.type {
        case .bindAck, .alterContextResp:
            let ack = try PDUCodec.decodeBindAck(parsed)
            negotiatedFrag = min(Int(ack.maxXmit), Int(ack.maxRecv))
            if negotiatedFrag < 128 { negotiatedFrag = 4280 }
            guard let r = ack.results.first else { throw RPCError.bindRejected(.reasonNotSpecified) }
            guard r.result == .acceptance else { throw RPCError.bindRejected(.reasonNotSpecified) }
            callID += 1
            return r.transferSyntax
        case .bindNak:
            var le = LE(parsed.body)
            let reason = RPCBindNakReason(rawValue: try le.u16()) ?? .reasonNotSpecified
            throw RPCError.bindRejected(reason)
        default:
            throw RPCError.malformedPDU("expected bind_ack, got \(parsed.header.type)")
        }
    }

    /// Makes a call: fragments `body` as request PDUs, reassembles the response, returns the
    /// response stub. A fault PDU throws `RPCError.fault`.
    public func call(opnum: UInt16, body: [UInt8]) async throws -> [UInt8] {
        let thisCall = callID
        callID += 1
        let maxStub = max(16, negotiatedFrag - 24)
        let total = body.count
        var offset = 0
        repeat {
            let end = min(offset + maxStub, total)
            let chunk = total == 0 ? [] : Array(body[offset..<end])
            var flags = PFCFlags()
            if offset == 0 { flags.insert(.firstFrag) }
            if end == total { flags.insert(.lastFrag) }
            let pdu = PDUCodec.encodeRequest(callID: thisCall, flags: flags, allocHint: UInt32(total - offset),
                                             contextID: contextID, opnum: opnum, stub: chunk)
            try await transport.send(pdu)
            offset = end
        } while offset < total

        // Reassemble the response.
        var out = [UInt8]()
        while true {
            let (p, _) = try PDUCodec.parse(try await nextPDU())
            switch p.header.type {
            case .response:
                let r = try PDUCodec.decodeResponse(p)
                out.append(contentsOf: r.stub)
                if p.header.flags.contains(.lastFrag) { return out }
            case .fault:
                let f = try PDUCodec.decodeFault(p)
                throw RPCError.fault(RPCFault(rawValue: f.status) ?? .cantPerform)
            default:
                throw RPCError.malformedPDU("expected response, got \(p.header.type)")
            }
        }
    }
}
