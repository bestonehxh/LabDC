import Foundation

/// A password-based encryption scheme as found in an `EncryptedPrivateKeyInfo` or a PKCS#7
/// `EncryptedData`: PBES2 (PBKDF2 + AES/3DES/DES), PKCS#5 v1.5 PBES1, or PKCS#12 PBE.
public struct PBEScheme: Equatable, Sendable, CustomStringConvertible {
    enum Kind: Equatable, Sendable {
        case pbes2(prf: HashKind, salt: [UInt8], iterations: Int, cipher: Cipher, iv: [UInt8])
        case pbes1(hash: HashKind, cipher: Cipher, salt: [UInt8], iterations: Int)
        case pkcs12(cipher: Cipher, salt: [UInt8], iterations: Int)
    }

    let kind: Kind

    /// How the scheme reads in `openssl pkcs12 -info` terms, e.g. "PBES2, PBKDF2, AES-256-CBC,
    /// Iteration 2048, PRF hmacWithSHA256".
    public var description: String {
        switch kind {
        case let .pbes2(prf, _, iterations, cipher, _):
            "PBES2, PBKDF2, \(cipher.name), Iteration \(iterations), PRF hmacWith\(prf.rawValue.uppercased())"
        case let .pbes1(hash, cipher, _, iterations):
            "PBES1 pbeWith\(hash.rawValue.uppercased())And\(cipher.name), Iteration \(iterations)"
        case let .pkcs12(cipher, _, iterations):
            "pbeWithSHA1And\(Self.pkcs12Name(cipher)), Iteration \(iterations)"
        }
    }

    /// True for anything but PBES2 with AES (the "legacy" family old appliances need).
    public var isLegacy: Bool {
        if case .pbes2(_, _, _, .aes, _) = kind { return false }
        return true
    }

    private static func pkcs12Name(_ c: Cipher) -> String {
        switch c {
        case .desEDE3: "3-KeyTripleDES-CBC"
        case .desEDE2: "2-KeyTripleDES-CBC"
        case .rc2(let k, _): "\(k * 8)BitRC2-CBC"
        case .rc4(let k): "\(k * 8)BitRC4"
        default: c.name
        }
    }

    // MARK: Parsing

    /// Parses an AlgorithmIdentifier node.
    static func parse(_ alg: ASN) throws -> PBEScheme {
        let oid = try alg.child(0).oid()
        let params = alg.children.count > 1 ? try alg.child(1) : nil
        func saltIter(_ p: ASN?) throws -> ([UInt8], Int) {
            guard let p, p.isSequence else { throw CertConvertError.malformed("PBE parameters missing") }
            return (try p.child(0).octets(), try p.child(1).int())
        }
        switch oid {
        case OID.pbes2:
            guard let params, params.isSequence else { throw CertConvertError.malformed("PBES2 parameters missing") }
            let kdf = try params.child(0)
            let enc = try params.child(1)
            guard try kdf.child(0).oid() == OID.pbkdf2 else {
                throw CertConvertError.unsupported("PBES2 key derivation \(try kdf.child(0).oid()) (only PBKDF2)")
            }
            let kp = try kdf.child(1)
            let salt = try kp.child(0).octets()
            let iterations = try kp.child(1).int()
            var prf = HashKind.sha1
            var explicitKeyLength: Int?
            for extra in kp.children.dropFirst(2) {
                if extra.isUniversal(2) {
                    explicitKeyLength = try extra.int()
                } else if extra.isSequence {
                    let prfOID = try extra.child(0).oid()
                    guard let h = HashKind(hmacOID: prfOID) else { throw CertConvertError.unsupported("PBKDF2 PRF \(prfOID)") }
                    prf = h
                }
            }
            let encOID = try enc.child(0).oid()
            let cipher: Cipher
            switch encOID {
            case OID.aes128CBC: cipher = .aes(keyBytes: 16)
            case OID.aes192CBC: cipher = .aes(keyBytes: 24)
            case OID.aes256CBC: cipher = .aes(keyBytes: 32)
            case OID.desEDE3CBC: cipher = .desEDE3
            case OID.desCBC: cipher = .des
            default: throw CertConvertError.unsupported("PBES2 cipher \(encOID)")
            }
            if let k = explicitKeyLength, k != cipher.keyLength {
                throw CertConvertError.malformed("PBES2 key length \(k) does not fit \(cipher.name)")
            }
            let iv = try enc.child(1).octets()
            guard iv.count == cipher.ivLength else { throw CertConvertError.malformed("PBES2 IV length \(iv.count)") }
            return PBEScheme(kind: .pbes2(prf: prf, salt: salt, iterations: iterations, cipher: cipher, iv: iv))
        case OID.pbeMD5DES, OID.pbeSHA1DES, OID.pbeMD5RC2, OID.pbeSHA1RC2:
            let (salt, iter) = try saltIter(params)
            let hash: HashKind = (oid == OID.pbeMD5DES || oid == OID.pbeMD5RC2) ? .md5 : .sha1
            let cipher: Cipher = (oid == OID.pbeMD5DES || oid == OID.pbeSHA1DES) ? .des : .rc2(keyBytes: 8, effectiveBits: 64)
            return PBEScheme(kind: .pbes1(hash: hash, cipher: cipher, salt: salt, iterations: iter))
        case OID.pkcs12SHA13DES, OID.pkcs12SHA12DES, OID.pkcs12SHA1RC2_128, OID.pkcs12SHA1RC2_40,
             OID.pkcs12SHA1RC4_128, OID.pkcs12SHA1RC4_40:
            let (salt, iter) = try saltIter(params)
            let cipher: Cipher
            switch oid {
            case OID.pkcs12SHA13DES: cipher = .desEDE3
            case OID.pkcs12SHA12DES: cipher = .desEDE2
            case OID.pkcs12SHA1RC2_128: cipher = .rc2(keyBytes: 16, effectiveBits: 128)
            case OID.pkcs12SHA1RC2_40: cipher = .rc2(keyBytes: 5, effectiveBits: 40)
            case OID.pkcs12SHA1RC4_128: cipher = .rc4(keyBytes: 16)
            default: cipher = .rc4(keyBytes: 5)
            }
            return PBEScheme(kind: .pkcs12(cipher: cipher, salt: salt, iterations: iter))
        default:
            throw CertConvertError.unsupported("encryption algorithm \(oid)")
        }
    }

    // MARK: Crypto

    func decrypt(_ ciphertext: [UInt8], password: String) throws -> [UInt8] {
        switch kind {
        case let .pbes2(prf, salt, iterations, cipher, iv):
            let key = try KDF.pbkdf2(prf, password: Array(password.utf8), salt: salt, iterations: iterations,
                                     keyLength: cipher.keyLength)
            return try cipher.decrypt(key: key, iv: iv, ciphertext)
        case let .pbes1(hash, cipher, salt, iterations):
            let dk = KDF.pbkdf1(hash, password: Array(password.utf8), salt: salt, iterations: iterations, length: 16)
            return try cipher.decrypt(key: Array(dk[0..<8]), iv: Array(dk[8..<16]), ciphertext)
        case let .pkcs12(cipher, salt, iterations):
            // Try the BMP password with terminator first, then the empty (NULL) form for "".
            var candidates = [KDF.bmpPassword(password)]
            if password.isEmpty { candidates.append([]) }
            var lastError: Error = CertConvertError.badPassword("wrong password")
            for pw in candidates {
                do { return try Self.pkcs12Crypt(cipher, decrypt: true, password: pw, salt: salt, iterations: iterations, ciphertext) } catch {
                    lastError = error
                }
            }
            throw lastError
        }
    }

    func encrypt(_ plaintext: [UInt8], password: String) throws -> [UInt8] {
        switch kind {
        case let .pbes2(prf, salt, iterations, cipher, iv):
            let key = try KDF.pbkdf2(prf, password: Array(password.utf8), salt: salt, iterations: iterations,
                                     keyLength: cipher.keyLength)
            return try cipher.encrypt(key: key, iv: iv, plaintext)
        case let .pbes1(hash, cipher, salt, iterations):
            let dk = KDF.pbkdf1(hash, password: Array(password.utf8), salt: salt, iterations: iterations, length: 16)
            return try cipher.encrypt(key: Array(dk[0..<8]), iv: Array(dk[8..<16]), plaintext)
        case let .pkcs12(cipher, salt, iterations):
            return try Self.pkcs12Crypt(cipher, decrypt: false, password: KDF.bmpPassword(password), salt: salt,
                                        iterations: iterations, plaintext)
        }
    }

    private static func pkcs12Crypt(_ cipher: Cipher, decrypt: Bool, password: [UInt8], salt: [UInt8], iterations: Int,
                                    _ input: [UInt8]) throws -> [UInt8] {
        let c = cipher
        let key = KDF.pkcs12(.sha1, id: 1, password: password, salt: salt, iterations: iterations, length: cipher.keyLength)
        let iv = c.ivLength > 0
            ? KDF.pkcs12(.sha1, id: 2, password: password, salt: salt, iterations: iterations, length: c.ivLength) : []
        return decrypt ? try c.decrypt(key: key, iv: iv, input) : try c.encrypt(key: key, iv: iv, input)
    }

    // MARK: Building

    /// The modern default: PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC, 16-byte salt (as OpenSSL 3).
    static func modern(iterations: Int = 2048) -> PBEScheme {
        PBEScheme(kind: .pbes2(prf: .sha256, salt: randomBytes(16), iterations: iterations, cipher: .aes(keyBytes: 32),
                               iv: randomBytes(16)))
    }

    /// The legacy default: pbeWithSHAAnd3-KeyTripleDES-CBC, 8-byte salt.
    static func legacy3DES(iterations: Int = 2048) -> PBEScheme {
        PBEScheme(kind: .pkcs12(cipher: .desEDE3, salt: randomBytes(8), iterations: iterations))
    }

    /// The AlgorithmIdentifier DER.
    var algorithmIdentifier: [UInt8] {
        switch kind {
        case let .pbes2(prf, salt, iterations, cipher, iv):
            let cipherOID: String
            switch cipher {
            case .aes(16): cipherOID = OID.aes128CBC
            case .aes(24): cipherOID = OID.aes192CBC
            case .aes: cipherOID = OID.aes256CBC
            case .des: cipherOID = OID.desCBC
            default: cipherOID = OID.desEDE3CBC
            }
            let prfPart = prf == .sha1 ? [] : DERW.algorithm(prf.hmacOID!, DERW.null)
            let kdf = DERW.algorithm(OID.pbkdf2, DERW.seq(DERW.octets(salt), DERW.int(iterations), prfPart))
            return DERW.algorithm(OID.pbes2, DERW.seq(kdf, DERW.algorithm(cipherOID, DERW.octets(iv))))
        case let .pbes1(hash, cipher, salt, iterations):
            let oid: String = switch (hash, cipher) {
            case (.md5, .des): OID.pbeMD5DES
            case (.md5, _): OID.pbeMD5RC2
            case (_, .des): OID.pbeSHA1DES
            default: OID.pbeSHA1RC2
            }
            return DERW.algorithm(oid, DERW.seq(DERW.octets(salt), DERW.int(iterations)))
        case let .pkcs12(cipher, salt, iterations):
            let oid: String = switch cipher {
            case .desEDE3: OID.pkcs12SHA13DES
            case .desEDE2: OID.pkcs12SHA12DES
            case .rc2(16, _): OID.pkcs12SHA1RC2_128
            case .rc2: OID.pkcs12SHA1RC2_40
            case .rc4(16): OID.pkcs12SHA1RC4_128
            default: OID.pkcs12SHA1RC4_40
            }
            return DERW.algorithm(oid, DERW.seq(DERW.octets(salt), DERW.int(iterations)))
        }
    }
}

/// PKCS#8 `EncryptedPrivateKeyInfo`.
enum EncryptedPKCS8 {
    /// Returns the scheme and the decrypted `PrivateKeyInfo` DER.
    static func decrypt(_ der: [UInt8], password: String) throws -> (PBEScheme, [UInt8]) {
        let root = try ASN.parse(der)
        let scheme = try PBEScheme.parse(try root.child(0))
        let plain = try scheme.decrypt(try root.child(1).octets(), password: password)
        // A wrong password with lucky padding still yields garbage: require a parsable PrivateKeyInfo.
        guard let inner = try? ASN.parse(plain), inner.isSequence else {
            throw CertConvertError.badPassword("wrong password for the encrypted private key")
        }
        return (scheme, plain)
    }

    static func scheme(of der: [UInt8]) throws -> PBEScheme {
        try PBEScheme.parse(try ASN.parse(der).child(0))
    }

    static func encrypt(_ pkcs8: [UInt8], password: String, scheme: PBEScheme) throws -> [UInt8] {
        DERW.seq(scheme.algorithmIdentifier, DERW.octets(try scheme.encrypt(pkcs8, password: password)))
    }

    /// True when `der` looks like an EncryptedPrivateKeyInfo (SEQUENCE { AlgorithmIdentifier, OCTET STRING }).
    static func looksLike(_ root: ASN) -> Bool {
        let c = root.children
        guard root.isSequence, c.count == 2, c[0].isSequence, c[1].isUniversal(4),
              let oid = try? c[0].child(0).oid() else { return false }
        return oid.hasPrefix("1.2.840.113549.1.5.") || oid.hasPrefix("1.2.840.113549.1.12.1.") || oid == OID.sunJKSKeyProtector
    }
}
