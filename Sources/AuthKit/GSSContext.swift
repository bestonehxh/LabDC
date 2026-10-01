/// GSS context flags (RFC 2744 values, also the `Flags` field of the RFC 4121 §4.1.1
/// authenticator checksum and of SPNEGO `reqFlags`).
public struct GSSContextFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let delegate = GSSContextFlags(rawValue: 0x1)
    public static let mutual = GSSContextFlags(rawValue: 0x2)
    public static let replay = GSSContextFlags(rawValue: 0x4)
    public static let sequence = GSSContextFlags(rawValue: 0x8)
    public static let confidentiality = GSSContextFlags(rawValue: 0x10)
    public static let integrity = GSSContextFlags(rawValue: 0x20)
    public static let anonymous = GSSContextFlags(rawValue: 0x40)
    /// MS-KILE §3.2.5.2 DCE-style (three-leg) authentication; not used by LDAP.
    public static let dceStyle = GSSContextFlags(rawValue: 0x1000)
    public static let identify = GSSContextFlags(rawValue: 0x2000)
    public static let extendedError = GSSContextFlags(rawValue: 0x4000)
}

/// An established GSS security context: per-message protection (RFC 2743 §2.3).
///
/// Implementations keep sequence numbers (and for NTLM the RC4 cipher state), so they are
/// reference types with internal locking; calls must still be made in wire order.
public protocol GSSSecurityContext: AnyObject, Sendable {
    /// The mechanism that produced this context (`.kerberos`/`.msKerberos`/`.ntlm`).
    var mechanism: GSSMechanism { get }
    /// Flags the peer asked for (and we granted). `.confidentiality` / `.integrity` decide the
    /// GSS-SPNEGO SASL layer (see docs/notes/wp-i.md).
    var flags: GSSContextFlags { get }
    /// GSS_Wrap. `confidential == false` produces an integrity-only token.
    func wrap(_ message: [UInt8], confidential: Bool) throws -> [UInt8]
    /// GSS_Unwrap: returns the message and whether it was encrypted.
    func unwrap(_ token: [UInt8]) throws -> (message: [UInt8], confidential: Bool)
    /// GSS_GetMIC.
    func getMIC(_ message: [UInt8]) throws -> [UInt8]
    /// GSS_VerifyMIC; throws when the MIC is wrong or out of sequence.
    func verifyMIC(_ message: [UInt8], token: [UInt8]) throws
}
