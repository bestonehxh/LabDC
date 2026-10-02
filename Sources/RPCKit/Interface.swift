import Foundation
import AuthKit

/// The context handed to an interface's `dispatch`: who is calling (from the SMB session), the
/// session key SAMR needs to decrypt password blobs, the client's address, and the connection's
/// context-handle table.
public struct RPCCallContext: Sendable {
    public let identity: AuthenticatedIdentity
    /// The 16-byte SMB session key, or empty for the in-memory/no-auth case.
    public let sessionKey: [UInt8]
    public let clientAddress: String
    public let handles: RPCHandleTable
    /// The presentation context id the call arrived on (opnum interpretation is per interface).
    public let contextID: UInt16
    /// The negotiated RPC authentication level for this connection (MS-RPCE §2.2.1.1.8). Interfaces
    /// that mandate a protection level — DRSUAPI requires `pktPrivacy` — check it here.
    public let authLevel: RPCAuthLevel
    /// The RPC auth service of the connection's established security context (`.none` when the
    /// binding carries no RPC-level authentication, e.g. a plain SMB pipe).
    public let authType: RPCAuthType
    /// The principal the RPC security context is bound to, when the provider names one — for
    /// Netlogon schannel the computer whose secure channel signed the request.
    public let authPrincipal: String?

    public init(identity: AuthenticatedIdentity, sessionKey: [UInt8], clientAddress: String,
                handles: RPCHandleTable, contextID: UInt16, authLevel: RPCAuthLevel = .none,
                authType: RPCAuthType = .none, authPrincipal: String? = nil) {
        self.identity = identity
        self.sessionKey = sessionKey
        self.clientAddress = clientAddress
        self.handles = handles
        self.contextID = contextID
        self.authLevel = authLevel
        self.authType = authType
        self.authPrincipal = authPrincipal
    }
}

/// A DCERPC interface: an abstract-syntax UUID/version and an opnum dispatcher. Implementations
/// unmarshal from `input`, do the work, and marshal `[out]` results into the returned writer.
/// Throwing `RPCError.fault(...)` (or any error, mapped via `faultStatus`) produces a fault PDU;
/// throwing for an out-of-range opnum should use `.fault(.opRangeError)`.
public protocol RPCInterface: Sendable {
    var interfaceUUID: DCEUUID { get }
    var interfaceVersion: (UInt16, UInt16) { get }
    func dispatch(opnum: UInt16, input: NDRReader, context: RPCCallContext) async throws -> NDRWriter
}

extension RPCInterface {
    /// The abstract syntax id (UUID + version) used to match bind requests.
    public var abstractSyntax: RPCSyntaxID {
        RPCSyntaxID(uuid: interfaceUUID, versionMajor: interfaceVersion.0, versionMinor: interfaceVersion.1)
    }
}
