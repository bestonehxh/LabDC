import CommonCrypto

/// RC4 stream cipher via CommonCrypto (`kCCAlgorithmRC4`). Encryption and decryption are the
/// same operation. Used only by RC4-HMAC (RFC 4757).
public nonisolated enum RC4 {
    /// XORs `bytes` with the RC4 keystream for `key`, starting at keystream offset 0.
    /// - Precondition: `key.count` is 1...512 bytes.
    public static func apply(key: [UInt8], _ bytes: [UInt8]) -> [UInt8] {
        precondition((kCCKeySizeMinRC4...kCCKeySizeMaxRC4).contains(key.count), "RC4 key must be 1...512 bytes")
        if bytes.isEmpty { return [] }
        return CommonCryptor.crypt(CCOperation(kCCEncrypt), algorithm: CCAlgorithm(kCCAlgorithmRC4),
                                   options: 0, key: key, input: bytes)
    }
}
