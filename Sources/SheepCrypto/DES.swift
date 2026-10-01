import CommonCrypto

/// Single-DES via CommonCrypto, one 8-byte block in ECB mode, no padding. Needed later for
/// MS-CHAP (RFC 2759) challenge responses; not used by Kerberos in phase 0.
public nonisolated enum DES {
    /// Encrypts one 8-byte `block` under an 8-byte `key` (parity bits are ignored).
    /// - Precondition: `key.count == 8` and `block.count == 8`.
    public static func encryptBlock(key: [UInt8], _ block: [UInt8]) -> [UInt8] {
        precondition(key.count == kCCKeySizeDES, "DES key must be 8 bytes")
        precondition(block.count == kCCBlockSizeDES, "DES block must be 8 bytes")
        return CommonCryptor.crypt(CCOperation(kCCEncrypt), algorithm: CCAlgorithm(kCCAlgorithmDES),
                                   options: CCOptions(kCCOptionECBMode), key: key, input: block)
    }

    /// Decrypts one 8-byte `block` under an 8-byte `key` (parity bits ignored). Needed for the
    /// MS-SAMR `SamrSetInformationUser2` level-18 NT-OWF recovery (§2.2.11.1.1 `Decrypt`).
    /// - Precondition: `key.count == 8` and `block.count == 8`.
    public static func decryptBlock(key: [UInt8], _ block: [UInt8]) -> [UInt8] {
        precondition(key.count == kCCKeySizeDES, "DES key must be 8 bytes")
        precondition(block.count == kCCBlockSizeDES, "DES block must be 8 bytes")
        return CommonCryptor.crypt(CCOperation(kCCDecrypt), algorithm: CCAlgorithm(kCCAlgorithmDES),
                                   options: CCOptions(kCCOptionECBMode), key: key, input: block)
    }
}
