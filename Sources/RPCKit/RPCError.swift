import Foundation

/// DCERPC fault status codes (MS-RPCE §2.2.4.10 / DCE 1.1 nca_* codes) that this
/// implementation emits or recognises. Values are the on-the-wire little-endian UInt32.
public enum RPCFault: UInt32, Sendable {
    /// `nca_s_fault_access_denied` — the caller is not allowed to make the call.
    case accessDenied = 0x0000_0005
    /// `nca_s_fault_ndr` — a stub could not decode/encode the arguments per NDR.
    case ndr = 0x0000_06F7
    /// `nca_s_fault_cant_perform` — generic server-side failure.
    case cantPerform = 0x0000_06D8
    /// `nca_op_rng_error` — the requested opnum is out of range for the interface.
    case opRangeError = 0x1C01_0002
    /// `nca_s_fault_context_mismatch` — a context handle did not match.
    case contextMismatch = 0x1C00_001A
    /// `nca_s_fault_remote_no_memory`.
    case noMemory = 0x1C00_0017
    /// `nca_proto_error` — malformed PDU.
    case protoError = 0x1C01_0003
}

/// Bind rejection reasons (MS-RPCE §2.2.4.2, `bind_nak` reject_reason).
public enum RPCBindNakReason: UInt16, Sendable {
    case reasonNotSpecified = 0
    case temporaryCongestion = 1
    case localLimitExceeded = 2
    case protocolVersionNotSupported = 4
    case authenticationTypeNotRecognized = 8
    case invalidChecksum = 9
}

/// Per-context negotiation result (MS-RPCE §2.2.4.3, `p_cont_def_result_t`).
public enum RPCContextResult: UInt16, Sendable {
    case acceptance = 0
    case userRejection = 1
    case providerRejection = 2
    /// Bind-time feature negotiation acknowledgement (MS-RPCE §3.3.1.5.3).
    case negotiateAck = 3
}

/// Per-context rejection reason (MS-RPCE §2.2.4.3, `p_provider_reason_t`).
public enum RPCContextReason: UInt16, Sendable {
    case reasonNotSpecified = 0
    case abstractSyntaxNotSupported = 1
    case proposedTransferSyntaxesNotSupported = 2
    case localLimitExceeded = 3
}

/// Errors raised by the DCERPC codec and the connection state machines. A thrown
/// `RPCError` reaching the server dispatch loop is mapped to a `fault` PDU.
public enum RPCError: Error, CustomStringConvertible, Sendable {
    /// A well-formed request that the server answers with a fault of this status.
    case fault(RPCFault)
    /// The PDU could not be parsed (offset, reason).
    case malformedPDU(String)
    /// The bind could not be satisfied at all; a `bind_nak` is sent.
    case bindRejected(RPCBindNakReason)
    /// An unknown / unbound presentation context id was used in a request.
    case unknownContext(UInt16)
    /// The transport closed or returned no data when a PDU was expected.
    case transportClosed
    /// A fragment/reassembly rule was violated (e.g. a fragment larger than the
    /// negotiated maximum, or interleaved calls).
    case reassembly(String)
    /// The auth verifier trailer was malformed or failed verification.
    case auth(String)

    public var description: String {
        switch self {
        case .fault(let f): return "RPC fault 0x\(String(f.rawValue, radix: 16))"
        case .malformedPDU(let r): return "malformed PDU: \(r)"
        case .bindRejected(let r): return "bind rejected: \(r)"
        case .unknownContext(let c): return "unknown presentation context \(c)"
        case .transportClosed: return "transport closed"
        case .reassembly(let r): return "reassembly error: \(r)"
        case .auth(let r): return "auth verifier error: \(r)"
        }
    }

    /// The fault status this error maps to when it surfaces in the dispatch loop.
    public var faultStatus: RPCFault {
        switch self {
        case .fault(let f): return f
        case .malformedPDU, .reassembly: return .protoError
        case .auth: return .accessDenied
        case .unknownContext: return .contextMismatch
        default: return .cantPerform
        }
    }
}

/// An NDR marshalling/unmarshalling error, carrying the byte offset (relative to the
/// stub start) where it was detected.
public struct NDRError: Error, CustomStringConvertible, Sendable {
    public let offset: Int
    public let reason: String
    public init(offset: Int, reason: String) {
        self.offset = offset
        self.reason = reason
    }
    public var description: String { "NDR error at stub offset \(offset): \(reason)" }
}
