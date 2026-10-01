import CommonCrypto
import SheepCrypto

/// `aes128-cts-hmac-sha1-96` and `aes256-cts-hmac-sha1-96`: the RFC 3961 §5.3 simplified
/// profile with the RFC 3962 parameters.
nonisolated enum AESProfile {
    static let confounderLength = 16
    static let macLength = 12
    static let defaultIterations: UInt32 = 4096

    /// Key-derivation constant suffixes (RFC 3961 §5.3).
    static let encryptionKeyConstant: UInt8 = 0xAA    // Ke
    static let integrityKeyConstant: UInt8 = 0x55     // Ki
    static let checksumKeyConstant: UInt8 = 0x99      // Kc

    /// RFC 3962 §4: tkey = random-to-key(PBKDF2-HMAC-SHA1(password, salt, iterations)),
    /// key = DK(tkey, "kerberos"). random-to-key is the identity for AES.
    static func stringToKey(_ type: EncryptionType, password: [UInt8], salt: [UInt8],
                            iterations: UInt32) throws(KerberosCryptoError) -> KerberosKey {
        let tkey = PBKDF2.hmacSHA1(password: password, salt: salt, iterations: Int(iterations),
                                   keyLength: type.keyLength)
        let key = try derive(tkey, constant: Array("kerberos".utf8))
        return KerberosKey(uncheckedType: type, bytes: key)
    }

    /// DK(base, constant) = random-to-key(DR(base, constant)) with DR from RFC 3961 §5.1:
    /// repeatedly encrypt n-fold(constant, block size) with AES-CBC-CTS (zero IV; each input is
    /// exactly one block, so this is plain AES) and concatenate until the key length is reached.
    static func derive(_ base: [UInt8], constant: [UInt8]) throws(KerberosCryptoError) -> [UInt8] {
        var block = nFold(constant, outputBytes: AESCBC.blockSize)
        var out = [UInt8]()
        while out.count < base.count {
            block = try AESCBC.ctsEncrypt(key: base, block)
            out += block
        }
        return Array(out[..<base.count])
    }

    /// Derived key for `usage` with the given suffix: DK(base, usage(4 bytes BE) | suffix).
    static func usageKey(_ key: KerberosKey, usage: Int32, _ suffix: UInt8) throws(KerberosCryptoError) -> [UInt8] {
        let u = UInt32(bitPattern: usage)
        let constant: [UInt8] = [UInt8(u >> 24), UInt8(truncatingIfNeeded: u >> 16),
                                 UInt8(truncatingIfNeeded: u >> 8), UInt8(truncatingIfNeeded: u), suffix]
        return try derive(key.bytes, constant: constant)
    }

    /// RFC 3961 §5.3 encrypt: C = E(Ke, conf | plaintext), H = HMAC-SHA1-96(Ki, conf | plaintext),
    /// output C | H.
    static func encrypt(_ plaintext: [UInt8], key: KerberosKey, usage: Int32,
                        rng: RandomBytes) throws(KerberosCryptoError) -> [UInt8] {
        let ke = try usageKey(key, usage: usage, encryptionKeyConstant)
        let ki = try usageKey(key, usage: usage, integrityKeyConstant)
        let data = rng.next(confounderLength) + plaintext
        let c = try AESCBC.ctsEncrypt(key: ke, data)
        let h = HMACSHA1.authenticate(key: ki, data).prefix(macLength)
        return c + h
    }

    static func decrypt(_ ciphertext: [UInt8], key: KerberosKey, usage: Int32) throws(KerberosCryptoError) -> [UInt8] {
        guard ciphertext.count >= confounderLength + macLength else {
            throw .ciphertextTooShort(type: key.type, length: ciphertext.count)
        }
        let ke = try usageKey(key, usage: usage, encryptionKeyConstant)
        let ki = try usageKey(key, usage: usage, integrityKeyConstant)
        let split = ciphertext.count - macLength
        let data = try AESCBC.ctsDecrypt(key: ke, Array(ciphertext[..<split]))
        let expected = Array(HMACSHA1.authenticate(key: ki, data).prefix(macLength))
        guard ConstantTime.equal(expected, Array(ciphertext[split...])) else {
            throw .integrityCheckFailed
        }
        return Array(data[confounderLength...])
    }

    /// `hmac-sha1-96-aes128/256` (RFC 3962 §7): HMAC-SHA1(Kc, data) truncated to 96 bits.
    static func checksum(_ data: [UInt8], key: KerberosKey, usage: Int32) throws(KerberosCryptoError) -> [UInt8] {
        let kc = try usageKey(key, usage: usage, checksumKeyConstant)
        return Array(HMACSHA1.authenticate(key: kc, data).prefix(macLength))
    }
}
