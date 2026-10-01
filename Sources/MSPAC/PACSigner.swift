import SheepCrypto

/// Constants of the PAC signature scheme (MS-PAC §2.8).
public enum PACChecksum {
    /// KERB_NON_KERB_CKSUM_SALT (MS-KILE §3.1.5.9): key usage for every PAC signature.
    public static let keyUsage: Int32 = 17

    public static let hmacSha1_96_aes128: Int32 = 15
    public static let hmacSha1_96_aes256: Int32 = 16
    public static let hmacSha256_128_aes128: Int32 = 19
    public static let hmacSha384_192_aes256: Int32 = 20
    /// KERB_CHECKSUM_HMAC_MD5, used with RC4 keys.
    public static let hmacMD5: Int32 = -138

    /// The ad-data that replaces the PAC inside the EncTicketPart when the ticket signature is
    /// computed (MS-PAC §2.8.2): a single zero byte.
    public static let ticketSignaturePlaceholderADData: [UInt8] = [0x00]

    /// Signature length in bytes for the checksum types a PAC can carry, nil if unknown.
    public static func signatureLength(forChecksumType type: Int32) -> Int? {
        switch type {
        case hmacSha1_96_aes128, hmacSha1_96_aes256: 12
        case hmacSha256_128_aes128: 16
        case hmacSha384_192_aes256: 24
        case hmacMD5: 16
        default: nil
        }
    }
}

/// Verifies one PAC signature. WP-E implements it with KerberosCrypto.verifyChecksum; every
/// `PACSigner` is also a verifier (it recomputes and compares in constant time).
public protocol PACVerifier: Sendable {
    func verify(_ data: [UInt8], usage: Int32, type: Int32, signature: [UInt8]) throws -> Bool
}

/// Computes a PAC signature with one long-term key (service key or krbtgt key).
///
/// `checksumType` and `signatureLength` must be known before signing because the PAC layout
/// (buffer sizes, offsets) is fixed before the server signature is computed over it.
/// `signatureLength` defaults to the table in `PACChecksum`; implement it for other types.
public protocol PACSigner: PACVerifier {
    var checksumType: Int32 { get }
    var signatureLength: Int { get }
    func sign(_ data: [UInt8], usage: Int32) throws -> (type: Int32, signature: [UInt8])
}

extension PACSigner {
    public var signatureLength: Int { PACChecksum.signatureLength(forChecksumType: checksumType) ?? 0 }

    public func verify(_ data: [UInt8], usage: Int32, type: Int32, signature: [UInt8]) throws -> Bool {
        guard type == checksumType else { return false }
        let computed = try sign(data, usage: usage)
        return computed.type == type && ConstantTime.equal(computed.signature, signature)
    }

    /// Signs and checks that the result matches the announced type and length.
    func checkedSign(_ data: [UInt8]) throws -> PACSignatureData {
        let (type, signature) = try sign(data, usage: PACChecksum.keyUsage)
        guard type == checksumType, signature.count == signatureLength else {
            throw MSPACError.signerMismatch(expectedType: checksumType, expectedLength: signatureLength,
                                            gotType: type, gotLength: signature.count)
        }
        return PACSignatureData(type: type, signature: signature)
    }
}
