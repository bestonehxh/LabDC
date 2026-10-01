import SheepCrypto

/// RFC 3961 operations for the phase-0 enctypes: string-to-key, random keys, encrypt /
/// decrypt with a key usage, and keyed checksums.
///
/// All functions are pure; randomness (confounders, random keys) comes from the injected
/// `RandomBytes`. Nothing here logs.
public nonisolated enum KerberosCrypto {
    /// Derives a long-term key from a password.
    ///
    /// - AES (RFC 3962): PBKDF2-HMAC-SHA1 over the UTF-8 password and salt, then
    ///   DK(tkey, "kerberos"). `parameters` is the `s2kparams` value: the iteration count as a
    ///   4-byte big-endian unsigned integer; `nil` or empty means the default of 4096.
    /// - RC4 (RFC 4757): MD4(UTF-16LE(password)); `salt` and `parameters` are ignored.
    ///
    /// No Unicode normalisation is applied (Heimdal and MIT do not normalise either).
    /// - Throws: `invalidStringToKeyParameters` if `parameters` is not 4 bytes, or encodes 0
    ///   (which RFC 3962 defines as 2^32 iterations; refused as unreasonable).
    public static func stringToKey(_ type: EncryptionType, password: String, salt: String,
                                   parameters: [UInt8]?) throws -> KerberosKey {
        switch type {
        case .rc4Hmac:
            return RC4HMAC.stringToKey(password: password)
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1:
            return try stringToKey(type, password: Array(password.utf8), salt: Array(salt.utf8),
                                   parameters: parameters)
        }
    }

    /// Byte-oriented variant of `stringToKey` for salts or passwords that are not text.
    /// For RC4 the password bytes must be UTF-8 (they are converted to UTF-16LE).
    public static func stringToKey(_ type: EncryptionType, password: [UInt8], salt: [UInt8],
                                   parameters: [UInt8]?) throws -> KerberosKey {
        switch type {
        case .rc4Hmac:
            guard let text = String(validating: password, as: UTF8.self) else {
                throw KerberosCryptoError.invalidStringToKeyParameters("RC4 password is not UTF-8")
            }
            return RC4HMAC.stringToKey(password: text)
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1:
            var iterations = AESProfile.defaultIterations
            if let parameters, !parameters.isEmpty {
                guard parameters.count == 4 else {
                    throw KerberosCryptoError.invalidStringToKeyParameters("AES s2kparams must be 4 bytes, got \(parameters.count)")
                }
                iterations = parameters.reduce(0) { $0 << 8 | UInt32($1) }
                guard iterations != 0 else {
                    throw KerberosCryptoError.invalidStringToKeyParameters("iteration count 0 (2^32) is not supported")
                }
            }
            return try AESProfile.stringToKey(type, password: password, salt: salt, iterations: iterations)
        }
    }

    /// Encodes an AES iteration count as `s2kparams` (4 bytes, big-endian).
    public static func stringToKeyParameters(iterations: UInt32) -> [UInt8] {
        [UInt8(iterations >> 24), UInt8(truncatingIfNeeded: iterations >> 16),
         UInt8(truncatingIfNeeded: iterations >> 8), UInt8(truncatingIfNeeded: iterations)]
    }

    /// The default salt (RFC 4120 §4): the realm followed by every name component, with no
    /// separators. `defaultSalt(realm: "LAB.SHEEP", principal: ["alice"])` is `"LAB.SHEEPalice"`.
    public static func defaultSalt(realm: String, principal: [String]) -> String {
        realm + principal.joined()
    }

    /// A fresh random key (random-to-key is the identity for all phase-0 enctypes).
    public static func randomKey(_ type: EncryptionType, rng: RandomBytes) -> KerberosKey {
        KerberosKey(uncheckedType: type, bytes: rng.next(type.keyLength))
    }

    /// RFC 3961 encrypt: prepends a random confounder (16 bytes AES, 8 bytes RC4) and returns
    /// the ciphertext with its integrity tag — the value that goes into `EncryptedData.cipher`.
    /// AES: `CTS(conf|pt) | HMAC-SHA1-96`; RC4: `HMAC-MD5 | RC4(conf|pt)`.
    public static func encrypt(_ plaintext: [UInt8], key: KerberosKey, usage: Int32,
                               rng: RandomBytes) throws -> [UInt8] {
        switch key.type {
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1:
            try AESProfile.encrypt(plaintext, key: key, usage: usage, rng: rng)
        case .rc4Hmac:
            RC4HMAC.encrypt(plaintext, key: key, usage: usage, rng: rng)
        }
    }

    /// RFC 3961 decrypt: verifies the integrity tag (constant-time) and strips the confounder.
    /// - Throws: `integrityCheckFailed` for a wrong key, wrong usage or tampered data;
    ///   `ciphertextTooShort` when the input cannot even hold confounder and tag.
    public static func decrypt(_ ciphertext: [UInt8], key: KerberosKey, usage: Int32) throws -> [UInt8] {
        switch key.type {
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1:
            try AESProfile.decrypt(ciphertext, key: key, usage: usage)
        case .rc4Hmac:
            try RC4HMAC.decrypt(ciphertext, key: key, usage: usage)
        }
    }

    /// Keyed checksum of `data`.
    /// - Throws: `checksumKeyMismatch` unless `key.type == type.keyType`.
    public static func checksum(_ type: ChecksumType, data: [UInt8], key: KerberosKey,
                                usage: Int32) throws -> [UInt8] {
        guard key.type == type.keyType else {
            throw KerberosCryptoError.checksumKeyMismatch(checksum: type, key: key.type)
        }
        switch type {
        case .hmacSha1Aes128, .hmacSha1Aes256:
            return try AESProfile.checksum(data, key: key, usage: usage)
        case .hmacMd5:
            return RC4HMAC.checksum(data, key: key, usage: usage)
        }
    }

    /// Recomputes the checksum and compares it with `expected` in constant time.
    /// Returns `false` on mismatch (including a wrong length); throws only when the checksum
    /// type and key do not fit together.
    public static func verifyChecksum(_ type: ChecksumType, data: [UInt8], key: KerberosKey,
                                      usage: Int32, expected: [UInt8]) throws -> Bool {
        ConstantTime.equal(try checksum(type, data: data, key: key, usage: usage), expected)
    }

    /// The mandatory checksum type of each enctype (RFC 3961 §4 "required checksum mechanism").
    public static func defaultChecksumType(for type: EncryptionType) -> ChecksumType {
        switch type {
        case .aes256CtsHmacSha1: .hmacSha1Aes256
        case .aes128CtsHmacSha1: .hmacSha1Aes128
        case .rc4Hmac: .hmacMd5
        }
    }
}
