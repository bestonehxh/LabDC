import Foundation
import AuthKit

/// WP-AE: the additional capabilities an RPC-level authentication provider needs on a
/// `ncacn_ip_tcp` connection, where — unlike an authenticated SMB pipe — the identity, the session
/// key and the per-PDU protection all come from the RPC auth verifier itself.
///
/// These are deliberately kept as *separate* protocols, discovered by `RPCServerConnection` via
/// `as?`, so the existing `RPCAuthProvider` conformers (`NoAuthProvider`, `NetlogonSchannelProvider`)
/// are untouched: schannel keeps its stub-only `NL_AUTH_SHA2_SIGNATURE` path and its identity keeps
/// coming from the SMB session.

/// A provider that establishes a caller identity (and optionally a session key) from the RPC bind
/// handshake. `RPCServerConnection` prefers these over its constructor-supplied identity when the
/// security context is complete.
public protocol RPCConnectionIdentity: Sendable {
    /// The authenticated identity once `isEstablished`, else nil (the connection keeps its default).
    var establishedIdentity: AuthenticatedIdentity? { get }
    /// The 16-byte session key the security context derived, or nil.
    var establishedSessionKey: [UInt8]? { get }
}

/// A provider whose per-PDU protection covers the whole PDU (header + body + `sec_trailer` header),
/// not just the marshalled stub — the scheme NTLMSSP and Kerberos use on connection-oriented RPC
/// (MS-RPCE §2.2.2.11/§2.2.2.12; the NTLM MAC signs `pdu[:-signature]`, and PDU privacy seals only
/// the stub while still signing the whole plaintext PDU). Because the header carries `frag_length`
/// and `auth_length` and the `sec_trailer` carries `auth_pad_length`/`auth_context_id`, the provider
/// must own the entire fragment layout, so it builds the outgoing PDU and opens the incoming PDU in
/// full rather than being handed an isolated stub.
public protocol RPCWholePDUAuthenticator: RPCAuthProvider {
    /// Builds one complete, protected response PDU fragment. `stub` is this fragment's already
    /// marshalled `[out]` bytes; the provider appends the alignment pad, the `sec_trailer`, seals the
    /// stub (privacy) and appends the signature computed over the whole PDU.
    func buildResponsePDU(callID: UInt32, flags: PFCFlags, allocHint: UInt32,
                          contextID: UInt16, stub: [UInt8]) throws -> [UInt8]
    /// Verifies (and for privacy decrypts) one raw incoming PDU fragment. `stubOffset` is where the
    /// stub begins inside `pdu` (after the type-specific header, plus any object UUID). Returns the
    /// plaintext stub with the auth pad removed. Throws `RPCError.auth` on any failure, which the
    /// connection maps to `nca_s_fault_access_denied`.
    func openRequestPDU(_ pdu: [UInt8], stubOffset: Int) throws -> [UInt8]
}

/// The umbrella an `ncacn_ip_tcp` auth provider (NTLM/SPNEGO/Kerberos) conforms to.
public protocol RPCAuthenticator: RPCWholePDUAuthenticator, RPCConnectionIdentity {}

/// RC4 with persistent state. NTLM sealing (MS-NLMP §3.4.3) uses one continuous RC4 handle per
/// direction, advanced across every protected PDU and, when key exchange is negotiated, across the
/// 8-byte MAC checksum too. Kept here (a copy of AuthKit's internal `RC4Stream`) so RPCKit can drive
/// the byte-exact stream the DCERPC MAC needs.
struct RPCRC4Stream: Sendable {
    private var s: [UInt8]
    private var i: UInt8 = 0
    private var j: UInt8 = 0

    init(key: [UInt8]) {
        s = (0...255).map { UInt8($0) }
        var j: UInt8 = 0
        for i in 0..<256 {
            j = j &+ s[i] &+ key[i % key.count]
            s.swapAt(i, Int(j))
        }
    }

    mutating func process(_ data: [UInt8]) -> [UInt8] {
        var out = data
        for k in out.indices {
            i = i &+ 1
            j = j &+ s[Int(i)]
            s.swapAt(Int(i), Int(j))
            out[k] ^= s[Int(s[Int(i)] &+ s[Int(j)])]
        }
        return out
    }
}

/// A little-endian helper local to the auth providers.
enum LEBytes {
    static func u16(_ v: UInt16) -> [UInt8] { [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8)] }
    static func u32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }
    static func readU16(_ b: [UInt8], _ o: Int) -> UInt16 { UInt16(b[o]) | (UInt16(b[o + 1]) << 8) }
    static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 {
        var v: UInt32 = 0; for k in 0..<4 { v |= UInt32(b[o + k]) << (8 * k) }; return v
    }
}
