import CommonCrypto

/// HMAC-MD5 (RFC 2104) via CommonCrypto `CCHmac`. Used by RC4-HMAC (RFC 4757) and MS-CHAP.
public nonisolated enum HMACMD5 {
    /// Returns the 16-byte HMAC-MD5 of `bytes` under `key`. Any key length is accepted
    /// (keys longer than 64 bytes are hashed first, per RFC 2104).
    public static func authenticate(key: [UInt8], _ bytes: [UInt8]) -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        key.withUnsafeBufferPointer { k in
            bytes.withUnsafeBufferPointer { d in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgMD5), k.baseAddress, k.count, d.baseAddress, d.count, &mac)
            }
        }
        return mac
    }
}
