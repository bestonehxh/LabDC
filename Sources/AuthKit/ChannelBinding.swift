import CryptoKit
import SheepCrypto
import SwiftASN1

/// Extended Protection for Authentication (EPA): how strictly an authentication over TLS must be
/// bound to that TLS channel, AD's `LdapEnforceChannelBinding` (0 / 1 / 2) and IIS'
/// `extendedProtection tokenChecking` (None / Allow / Require).
public enum ChannelBindingPolicy: String, Sendable, Hashable, CaseIterable, Codable {
    /// No check (`LdapEnforceChannelBinding` = 0).
    case never
    /// A client that sends a channel binding must send the right one; a client that sends none
    /// (or the all-zero "unbound" value) is still accepted (= 1, the default).
    case whenSupported
    /// Every NTLM / Kerberos authentication over TLS must carry the right binding (= 2).
    case always

    public var settingsLabel: String {
        switch self {
        case .never: "Never"
        case .whenSupported: "When supported"
        case .always: "Always"
        }
    }
}

/// The `tls-server-end-point` channel binding (RFC 5929 §4) of a TLS server certificate, and the
/// 16-byte hash NTLM (MsvAvChannelBindings, MS-NLMP §2.2.2.1) and Kerberos (the `Bnd` field of the
/// RFC 4121 §4.1.1 checksum) carry: MD5 of the `gss_channel_bindings_struct` (RFC 2744 §3.11)
/// with no addresses and `application_data` = `"tls-server-end-point:" || H(certificate)`.
public struct ChannelBindings: Sendable, Hashable {
    /// `"tls-server-end-point:" || H(certificate)`.
    public let applicationData: [UInt8]
    /// MD5(gss_channel_bindings_struct), what the client puts in its token.
    public let hash: [UInt8]

    public init(applicationData: [UInt8]) {
        self.applicationData = applicationData
        self.hash = Self.structHash(applicationData)
    }

    /// `tls-server-end-point` of a DER certificate: the certificate's own signature hash, or
    /// SHA-256 when that is MD5 or SHA-1 (RFC 5929 §4.1). Unknown algorithms use SHA-256.
    public static func tlsServerEndPoint(certificateDER der: [UInt8]) -> ChannelBindings {
        let digest: [UInt8]
        switch Self.signatureHash(certificateDER: der) {
        case .sha384: digest = Array(SHA384.hash(data: der))
        case .sha512: digest = Array(SHA512.hash(data: der))
        case .sha256: digest = Array(SHA256.hash(data: der))
        }
        return ChannelBindings(applicationData: Array("tls-server-end-point:".utf8) + digest)
    }

    enum Hash { case sha256, sha384, sha512 }

    /// The hash of the certificate's `signatureAlgorithm` (RFC 5929: MD5 / SHA-1 → SHA-256).
    static func signatureHash(certificateDER der: [UInt8]) -> Hash {
        guard let root = try? DER.parse(der), case .constructed(let items) = root.content else { return .sha256 }
        let nodes = Array(items)
        guard nodes.count >= 2, case .constructed(let alg) = nodes[1].content, let oidNode = Array(alg).first,
              let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode) else { return .sha256 }
        switch oid.description {
        case "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3": return .sha384      // sha384WithRSA, ecdsa-with-SHA384
        case "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4": return .sha512      // sha512WithRSA, ecdsa-with-SHA512
        case "1.2.840.113549.1.1.10":                                            // RSASSA-PSS: the hash in the parameters
            let params = Array(alg).dropFirst().first
            switch params.flatMap(firstOID) {
            case "2.16.840.1.101.3.4.2.2": return .sha384
            case "2.16.840.1.101.3.4.2.3": return .sha512
            default: return .sha256
            }
        default: return .sha256
        }
    }

    /// The first OBJECT IDENTIFIER inside `node` (depth first).
    private static func firstOID(_ node: ASN1Node) -> String? {
        if node.identifier == .objectIdentifier { return (try? ASN1ObjectIdentifier(derEncoded: node))?.description }
        guard case .constructed(let children) = node.content else { return nil }
        for child in children { if let oid = firstOID(child) { return oid } }
        return nil
    }

    /// MD5 over `initiator_addrtype (4) | initiator_address (len 4 + 0) | acceptor_addrtype (4) |
    /// acceptor_address (len 4 + 0) | application_data (len 4 LE + bytes)`.
    static func structHash(_ applicationData: [UInt8]) -> [UInt8] {
        var s = [UInt8](repeating: 0, count: 16)
        s.appendLE32(UInt32(applicationData.count))
        return MD5.hash(s + applicationData)
    }

    /// What a client sends when it has no channel to bind to: all zeros, or the hash of an empty
    /// structure (both mean "not bound", MS-NLMP §3.1.5.2.2 / MS-KILE §3.2.5.8).
    public static let unbound: Set<[UInt8]> = [[UInt8](repeating: 0, count: 16), structHash([])]
}

/// What one acceptor checks: the policy and, on a TLS connection, the expected binding. Without
/// `expected` (no TLS) nothing is checked: there is no channel to bind to.
public struct ChannelBindingCheck: Sendable, Hashable {
    public var policy: ChannelBindingPolicy
    public var expected: ChannelBindings?

    public init(policy: ChannelBindingPolicy, expected: ChannelBindings?) {
        self.policy = policy
        self.expected = expected
    }

    /// No check (plain transports, tests).
    public static let none = ChannelBindingCheck(policy: .never, expected: nil)

    /// Checks the 16-byte hash a client sent (`nil` when its token had none).
    /// - Throws: `AuthKitError.channelBinding` when the policy refuses it.
    public func verify(_ sent: [UInt8]?, mechanism: String) throws {
        guard policy != .never, let expected else { return }
        let provided = sent.flatMap { ChannelBindings.unbound.contains($0) ? nil : $0 }
        guard let provided else {
            if policy == .always {
                throw AuthKitError.channelBinding("\(mechanism) authentication over TLS without a channel binding token")
            }
            return
        }
        guard provided.count == 16, ConstantTime.equal(provided, expected.hash) else {
            throw AuthKitError.channelBinding("\(mechanism) channel binding token does not match this TLS channel (relayed?)")
        }
    }
}
