import Foundation

/// RPC authentication service identifiers (MS-RPCE §2.2.1.1.7 `auth_type`).
public enum RPCAuthType: UInt8, Sendable {
    case none = 0
    case spnego = 9        // RPC_C_AUTHN_GSS_NEGOTIATE
    case ntlm = 10         // RPC_C_AUTHN_WINNT
    case kerberos = 16     // RPC_C_AUTHN_GSS_KERBEROS
    case schannel = 68     // RPC_C_AUTHN_NETLOGON
}

/// RPC authentication levels (MS-RPCE §2.2.1.1.8 `auth_level`).
public enum RPCAuthLevel: UInt8, Sendable {
    case none = 1
    case connect = 2
    case call = 3
    case pkt = 4
    case pktIntegrity = 5
    case pktPrivacy = 6
}

/// A pluggable per-connection authentication provider. The connection asks it to process the
/// bind verifier and, once established, to sign/seal outgoing PDU bodies and verify/unseal
/// incoming ones. The "none" provider is implemented here; WP-V adds the type-68 Netlogon
/// schannel provider (`NL_AUTH_MESSAGE` at bind, then `NL_AUTH_SHA2_SIGNATURE` per PDU) and
/// WP-I's NTLM/SPNEGO acceptors back types 10/9.
///
/// `sign`/`seal` operate on the marshalled stub of a single (already fragmented) PDU. The
/// connection places the returned auth value in the trailer and, for privacy, replaces the stub
/// with the sealed bytes. Implementations must be `Sendable`.
public protocol RPCAuthProvider: Sendable {
    /// The auth_type this provider handles.
    var authType: RPCAuthType { get }
    /// The negotiated auth_level, after `bind`.
    var authLevel: RPCAuthLevel { get }

    /// Consumes the bind (or alter_context / auth3) auth value at the requested `authLevel` and
    /// returns the response auth value to place in the bind_ack (or alter_context_resp) trailer, or
    /// nil for none (or for a leg that produces no response, e.g. the final NTLM `auth3`).
    /// Multi-leg providers return a non-nil value and are called again on the next leg. The provider
    /// adopts `authLevel` (integrity/privacy) from the bind verifier here. `authType` is the auth
    /// service the client selected in the verifier (WP-AE: a `ncacn_ip_tcp` connection picks the
    /// provider by it); single-type providers (schannel, no-auth) ignore it. `bind` is `async` so
    /// providers can drive the AuthKit acceptors (NTLM/SPNEGO/Kerberos), which are `async`.
    mutating func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]?
    /// True once the security context is complete and per-PDU protection applies.
    var isEstablished: Bool { get }

    /// Produces the auth value (signature) for an outgoing PDU whose protected body is `body`
    /// (the request/response header fields + stub, per the provider's covered range).
    func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8]
    /// Seals `body` in place, returning (sealedBody, authValue).
    func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8])
    /// Verifies the signature over an incoming `body`.
    func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws
    /// Unseals an incoming `body`, returning the plaintext.
    func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8]
}

/// The no-authentication provider used for RPC over authenticated SMB pipes, where SMB already
/// carries the identity and signing. It emits no trailer and performs no per-PDU protection.
public struct NoAuthProvider: RPCAuthProvider {
    public init() {}
    public var authType: RPCAuthType { .none }
    public var authLevel: RPCAuthLevel { .none }
    public var isEstablished: Bool { true }
    public mutating func bind(authType: RPCAuthType, authData: [UInt8], authLevel: RPCAuthLevel) async throws -> [UInt8]? { nil }
    public func sign(body: [UInt8], sequence: UInt32) throws -> [UInt8] { [] }
    public func seal(body: [UInt8], sequence: UInt32) throws -> (sealed: [UInt8], auth: [UInt8]) { (body, []) }
    public func verify(body: [UInt8], auth: [UInt8], sequence: UInt32) throws {}
    public func unseal(body: [UInt8], auth: [UInt8], sequence: UInt32) throws -> [UInt8] { body }
}
