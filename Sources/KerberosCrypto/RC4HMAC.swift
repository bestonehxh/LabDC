import SheepCrypto

/// `arcfour-hmac` (RFC 4757), the non-export variant only.
nonisolated enum RC4HMAC {
    static let confounderLength = 8
    static let macLength = 16

    /// RFC 4757 §4: the key is the NT hash, MD4(UTF-16LE(password)). The salt and any
    /// string-to-key parameters are ignored.
    static func stringToKey(password: String) -> KerberosKey {
        var utf16le = [UInt8]()
        utf16le.reserveCapacity(password.utf16.count * 2)
        for unit in password.utf16 {
            utf16le.append(UInt8(truncatingIfNeeded: unit))
            utf16le.append(UInt8(truncatingIfNeeded: unit >> 8))
        }
        return KerberosKey(uncheckedType: .rc4Hmac, bytes: MD4.hash(utf16le))
    }

    /// Message type T for a Kerberos key usage (RFC 4757 §3): 3 -> 8, 23 -> 13, all else unmapped.
    ///
    /// Usage 9 (TGS-REP enc-part under the authenticator subkey) stays 9, matching MIT krb5
    /// (`krb5int_arcfour_translate_usage`: `case 9: return 9`) and Heimdal (probed with
    /// `krb5_encrypt`). The RFC 4757 table's T = 8 for usage 9 is what Windows 2000 DCs did;
    /// Heimdal clients carry a fallback for that, MIT clients do not. Not supported here.
    static func messageType(forUsage usage: Int32) -> Int32 {
        switch usage {
        case 3: 8
        case 23: 13
        default: usage
        }
    }

    private static func littleEndian(_ t: Int32) -> [UInt8] {
        let u = UInt32(bitPattern: t)
        return [UInt8(truncatingIfNeeded: u), UInt8(truncatingIfNeeded: u >> 8),
                UInt8(truncatingIfNeeded: u >> 16), UInt8(truncatingIfNeeded: u >> 24)]
    }

    /// RFC 4757 §5: K1 = HMAC-MD5(K, T as 4 bytes LE); K2 = K1 (non-export);
    /// checksum = HMAC-MD5(K2, conf | plaintext); K3 = HMAC-MD5(K1, checksum);
    /// output checksum | RC4(K3, conf | plaintext).
    static func encrypt(_ plaintext: [UInt8], key: KerberosKey, usage: Int32, rng: RandomBytes) -> [UInt8] {
        encrypt(plaintext, key: key, messageType: messageType(forUsage: usage), rng: rng)
    }

    /// Encrypt with a raw message type T (no usage map). Internal hook for tests.
    static func encrypt(_ plaintext: [UInt8], key: KerberosKey, messageType t: Int32, rng: RandomBytes) -> [UInt8] {
        let k1 = HMACMD5.authenticate(key: key.bytes, littleEndian(t))
        let data = rng.next(confounderLength) + plaintext
        let checksum = HMACMD5.authenticate(key: k1, data)
        let k3 = HMACMD5.authenticate(key: k1, checksum)
        return checksum + RC4.apply(key: k3, data)
    }

    static func decrypt(_ ciphertext: [UInt8], key: KerberosKey, usage: Int32) throws(KerberosCryptoError) -> [UInt8] {
        try decrypt(ciphertext, key: key, messageType: messageType(forUsage: usage))
    }

    /// Decrypt with a raw message type T (no usage map). Internal hook for tests.
    static func decrypt(_ ciphertext: [UInt8], key: KerberosKey, messageType t: Int32) throws(KerberosCryptoError) -> [UInt8] {
        guard ciphertext.count >= macLength + confounderLength else {
            throw .ciphertextTooShort(type: .rc4Hmac, length: ciphertext.count)
        }
        let k1 = HMACMD5.authenticate(key: key.bytes, littleEndian(t))
        let checksum = Array(ciphertext[..<macLength])
        let k3 = HMACMD5.authenticate(key: k1, checksum)
        let data = RC4.apply(key: k3, Array(ciphertext[macLength...]))
        guard ConstantTime.equal(HMACMD5.authenticate(key: k1, data), checksum) else {
            throw .integrityCheckFailed
        }
        return Array(data[confounderLength...])
    }

    /// `hmac-md5` checksum (RFC 4757 §4, type -138): Ksign = HMAC-MD5(K, "signaturekey\0"),
    /// tmp = MD5(T as 4 bytes LE | data), checksum = HMAC-MD5(Ksign, tmp). T uses the same
    /// usage map as encryption (Heimdal and MIT do the same).
    static func checksum(_ data: [UInt8], key: KerberosKey, usage: Int32) -> [UInt8] {
        checksum(data, key: key, messageType: messageType(forUsage: usage))
    }

    /// Checksum with a raw message type T (no usage map). Internal hook for tests.
    static func checksum(_ data: [UInt8], key: KerberosKey, messageType t: Int32) -> [UInt8] {
        let ksign = HMACMD5.authenticate(key: key.bytes, Array("signaturekey".utf8) + [0])
        let tmp = MD5.hash(littleEndian(t) + data)
        return HMACMD5.authenticate(key: ksign, tmp)
    }
}
