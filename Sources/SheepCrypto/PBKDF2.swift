import CommonCrypto

/// PBKDF2 (RFC 8018) via CommonCrypto `CCKeyDerivationPBKDF`. Used by AES string-to-key
/// (RFC 3962).
public nonisolated enum PBKDF2 {
    /// PBKDF2 with HMAC-SHA1 as the PRF.
    /// - Precondition: `iterations >= 1`, `iterations <= UInt32.max`, `keyLength >= 1`.
    public static func hmacSHA1(password: [UInt8], salt: [UInt8], iterations: Int, keyLength: Int) -> [UInt8] {
        precondition(iterations >= 1 && iterations <= Int(UInt32.max), "PBKDF2 iterations out of range")
        precondition(keyLength >= 1, "PBKDF2 keyLength must be positive")
        var derived = [UInt8](repeating: 0, count: keyLength)
        let status = password.withUnsafeBufferPointer { p in
            p.withMemoryRebound(to: CChar.self) { pc in
                salt.withUnsafeBufferPointer { s in
                    derived.withUnsafeMutableBufferPointer { out in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             pc.baseAddress, pc.count,
                                             s.baseAddress, s.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                             UInt32(iterations),
                                             out.baseAddress, out.count)
                    }
                }
            }
        }
        precondition(status == Int32(kCCSuccess), "CCKeyDerivationPBKDF failed with status \(status)")
        return derived
    }
}
