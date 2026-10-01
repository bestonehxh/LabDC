import CommonCrypto
import CryptoKit
import Foundation

/// The block/stream ciphers the password-based schemes need. AES, DES and 3DES come from
/// CommonCrypto (CBC, PKCS#7 padding); RC2 is our own (CommonCrypto cannot set the effective
/// key bits RC2-40 needs); RC4 is CommonCrypto.
enum Cipher: Equatable, Sendable {
    case aes(keyBytes: Int)
    case desEDE3
    /// Two-key triple DES (K1 K2 K1), only for pbeWithSHAAnd2-KeyTripleDES-CBC.
    case desEDE2
    case des
    case rc2(keyBytes: Int, effectiveBits: Int)
    case rc4(keyBytes: Int)

    var keyLength: Int {
        switch self {
        case .aes(let k): k
        case .desEDE3: 24
        case .desEDE2: 16
        case .des: 8
        case .rc2(let k, _): k
        case .rc4(let k): k
        }
    }

    var ivLength: Int {
        switch self {
        case .aes: 16
        case .desEDE3, .desEDE2, .des, .rc2: 8
        case .rc4: 0
        }
    }

    var name: String {
        switch self {
        case .aes(let k): "AES-\(k * 8)-CBC"
        case .desEDE3: "DES-EDE3-CBC"
        case .desEDE2: "DES-EDE-CBC"
        case .des: "DES-CBC"
        case .rc2(_, let bits): "RC2-\(bits)-CBC"
        case .rc4(let k): "RC4-\(k * 8)"
        }
    }

    func encrypt(key: [UInt8], iv: [UInt8], _ plaintext: [UInt8]) throws -> [UInt8] {
        switch self {
        case .rc2(_, let bits):
            return RC2(key: key, effectiveBits: bits).cbcEncrypt(iv: iv, pkcs7Pad(plaintext, block: 8))
        case .rc4:
            return try Self.commonCrypt(kCCEncrypt, kCCAlgorithmRC4, options: 0, key: key, iv: nil, plaintext)
        case .desEDE2:
            return try Self.commonCrypt(kCCEncrypt, kCCAlgorithm3DES, options: kCCOptionPKCS7Padding, key: key + key.prefix(8), iv: iv, plaintext)
        default:
            return try Self.commonCrypt(kCCEncrypt, ccAlgorithm, options: kCCOptionPKCS7Padding, key: key, iv: iv, plaintext)
        }
    }

    /// Decrypts; a padding failure (the usual sign of a wrong password) throws `badPassword`.
    func decrypt(key: [UInt8], iv: [UInt8], _ ciphertext: [UInt8]) throws -> [UInt8] {
        switch self {
        case .rc2(_, let bits):
            guard ciphertext.count % 8 == 0, !ciphertext.isEmpty else {
                throw CertConvertError.malformed("RC2 ciphertext is not a whole number of blocks")
            }
            return try pkcs7Unpad(RC2(key: key, effectiveBits: bits).cbcDecrypt(iv: iv, ciphertext), block: 8)
        case .rc4:
            return try Self.commonCrypt(kCCDecrypt, kCCAlgorithmRC4, options: 0, key: key, iv: nil, ciphertext)
        case .desEDE2:
            return try Self.commonCrypt(kCCDecrypt, kCCAlgorithm3DES, options: kCCOptionPKCS7Padding, key: key + key.prefix(8), iv: iv, ciphertext)
        default:
            return try Self.commonCrypt(kCCDecrypt, ccAlgorithm, options: kCCOptionPKCS7Padding, key: key, iv: iv, ciphertext)
        }
    }

    private var ccAlgorithm: Int {
        switch self {
        case .aes: kCCAlgorithmAES
        case .desEDE3, .desEDE2: kCCAlgorithm3DES
        case .des: kCCAlgorithmDES
        case .rc2, .rc4: -1
        }
    }

    private static func commonCrypt(_ op: Int, _ alg: Int, options: Int, key: [UInt8], iv: [UInt8]?,
                                    _ input: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: input.count + 32)
        var moved = 0
        let status = key.withUnsafeBytes { k in
            input.withUnsafeBytes { i in
                out.withUnsafeMutableBytes { o in
                    if let iv {
                        iv.withUnsafeBytes { v in
                            CCCrypt(CCOperation(op), CCAlgorithm(alg), CCOptions(options), k.baseAddress, k.count,
                                    v.baseAddress, i.baseAddress, i.count, o.baseAddress, o.count, &moved)
                        }
                    } else {
                        CCCrypt(CCOperation(op), CCAlgorithm(alg), CCOptions(options), k.baseAddress, k.count,
                                nil, i.baseAddress, i.count, o.baseAddress, o.count, &moved)
                    }
                }
            }
        }
        if status == CCCryptorStatus(kCCDecodeError) || (op == kCCDecrypt && status == CCCryptorStatus(kCCAlignmentError)) {
            throw CertConvertError.badPassword("decryption failed (wrong password?)")
        }
        guard status == CCCryptorStatus(kCCSuccess) else {
            throw CertConvertError.malformed("cipher error \(status)")
        }
        return Array(out[..<moved])
    }
}

func pkcs7Pad(_ data: [UInt8], block: Int) -> [UInt8] {
    let n = block - data.count % block
    return data + [UInt8](repeating: UInt8(n), count: n)
}

func pkcs7Unpad(_ data: [UInt8], block: Int) throws -> [UInt8] {
    guard let last = data.last, last >= 1, Int(last) <= block, Int(last) <= data.count,
          data.suffix(Int(last)).allSatisfy({ $0 == last }) else {
        throw CertConvertError.badPassword("decryption failed (wrong password?)")
    }
    return Array(data.dropLast(Int(last)))
}

func randomBytes(_ n: Int) -> [UInt8] {
    var g = SystemRandomNumberGenerator()
    return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
}

/// RC2 (RFC 2268) with an explicit effective key length, CBC mode.
struct RC2 {
    private var k = [UInt16](repeating: 0, count: 64)

    private static let piTable: [UInt8] = [
        0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
        0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
        0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
        0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
        0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
        0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
        0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
        0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
        0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
        0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
        0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
        0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
        0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
        0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
        0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
        0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
    ]

    init(key: [UInt8], effectiveBits: Int) {
        precondition(!key.isEmpty && key.count <= 128 && effectiveBits >= 1 && effectiveBits <= 1024)
        var l = [UInt8](repeating: 0, count: 128)
        for (i, b) in key.enumerated() { l[i] = b }
        let t = key.count
        let t8 = (effectiveBits + 7) / 8
        let tm = UInt8(255 % (1 << (8 + effectiveBits - 8 * t8)))
        for i in t..<128 { l[i] = Self.piTable[Int(l[i - 1] &+ l[i - t])] }
        l[128 - t8] = Self.piTable[Int(l[128 - t8] & tm)]
        if t8 < 128 {
            for i in stride(from: 127 - t8, through: 0, by: -1) {
                l[i] = Self.piTable[Int(l[i + 1] ^ l[i + t8])]
            }
        }
        for i in 0..<64 { k[i] = UInt16(l[2 * i]) | UInt16(l[2 * i + 1]) << 8 }
    }

    private static func rol(_ x: UInt16, _ s: UInt16) -> UInt16 { x << s | x >> (16 - s) }
    private static func ror(_ x: UInt16, _ s: UInt16) -> UInt16 { x >> s | x << (16 - s) }

    func encryptBlock(_ b: ArraySlice<UInt8>) -> [UInt8] {
        let s = b.startIndex
        var r = (0..<4).map { UInt16(b[s + 2 * $0]) | UInt16(b[s + 2 * $0 + 1]) << 8 }
        var j = 0
        func mix() {
            let shifts: [UInt16] = [1, 2, 3, 5]
            for i in 0..<4 {
                r[i] = r[i] &+ k[j] &+ (r[(i + 3) % 4] & r[(i + 2) % 4]) &+ (~r[(i + 3) % 4] & r[(i + 1) % 4])
                j += 1
                r[i] = Self.rol(r[i], shifts[i])
            }
        }
        func mash() { for i in 0..<4 { r[i] = r[i] &+ k[Int(r[(i + 3) % 4] & 63)] } }
        for _ in 0..<5 { mix() }
        mash()
        for _ in 0..<6 { mix() }
        mash()
        for _ in 0..<5 { mix() }
        return r.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }
    }

    func decryptBlock(_ b: ArraySlice<UInt8>) -> [UInt8] {
        let s = b.startIndex
        var r = (0..<4).map { UInt16(b[s + 2 * $0]) | UInt16(b[s + 2 * $0 + 1]) << 8 }
        var j = 63
        func rmix() {
            let shifts: [UInt16] = [1, 2, 3, 5]
            for i in stride(from: 3, through: 0, by: -1) {
                r[i] = Self.ror(r[i], shifts[i])
                r[i] = r[i] &- k[j] &- (r[(i + 3) % 4] & r[(i + 2) % 4]) &- (~r[(i + 3) % 4] & r[(i + 1) % 4])
                j -= 1
            }
        }
        func rmash() { for i in stride(from: 3, through: 0, by: -1) { r[i] = r[i] &- k[Int(r[(i + 3) % 4] & 63)] } }
        for _ in 0..<5 { rmix() }
        rmash()
        for _ in 0..<6 { rmix() }
        rmash()
        for _ in 0..<5 { rmix() }
        return r.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }
    }

    func cbcEncrypt(iv: [UInt8], _ data: [UInt8]) -> [UInt8] {
        var prev = iv
        var out: [UInt8] = []
        for off in stride(from: 0, to: data.count, by: 8) {
            let x = zip(data[off..<off + 8], prev).map { $0 ^ $1 }
            prev = encryptBlock(x[...])
            out += prev
        }
        return out
    }

    func cbcDecrypt(iv: [UInt8], _ data: [UInt8]) -> [UInt8] {
        var prev = iv
        var out: [UInt8] = []
        for off in stride(from: 0, to: data.count, by: 8) {
            let c = data[off..<off + 8]
            out += zip(decryptBlock(c), prev).map { $0 ^ $1 }
            prev = Array(c)
        }
        return out
    }
}

/// Hash functions used by the KDFs and MACs.
enum HashKind: String, Sendable {
    case md5, sha1, sha256, sha384, sha512

    var outputLength: Int {
        switch self {
        case .md5: 16
        case .sha1: 20
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    var blockLength: Int {
        switch self {
        case .md5, .sha1, .sha256: 64
        case .sha384, .sha512: 128
        }
    }

    func hash(_ data: [UInt8]) -> [UInt8] {
        switch self {
        case .md5: Array(Insecure.MD5.hash(data: data))
        case .sha1: Array(Insecure.SHA1.hash(data: data))
        case .sha256: Array(SHA256.hash(data: data))
        case .sha384: Array(SHA384.hash(data: data))
        case .sha512: Array(SHA512.hash(data: data))
        }
    }

    func hmac(key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        let k = SymmetricKey(data: key)
        switch self {
        case .md5: return Array(HMAC<Insecure.MD5>.authenticationCode(for: data, using: k))
        case .sha1: return Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: k))
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: data, using: k))
        case .sha384: return Array(HMAC<SHA384>.authenticationCode(for: data, using: k))
        case .sha512: return Array(HMAC<SHA512>.authenticationCode(for: data, using: k))
        }
    }

    var digestOID: String? {
        switch self {
        case .md5: nil
        case .sha1: OID.sha1
        case .sha256: OID.sha256
        case .sha384: OID.sha384
        case .sha512: OID.sha512
        }
    }

    var hmacOID: String? {
        switch self {
        case .md5: nil
        case .sha1: OID.hmacSHA1
        case .sha256: OID.hmacSHA256
        case .sha384: OID.hmacSHA384
        case .sha512: OID.hmacSHA512
        }
    }

    init?(digestOID: String) {
        switch digestOID {
        case OID.sha1: self = .sha1
        case OID.sha256: self = .sha256
        case OID.sha384: self = .sha384
        case OID.sha512: self = .sha512
        default: return nil
        }
    }

    init?(hmacOID: String) {
        switch hmacOID {
        case OID.hmacSHA1: self = .sha1
        case OID.hmacSHA256: self = .sha256
        case OID.hmacSHA384: self = .sha384
        case OID.hmacSHA512: self = .sha512
        default: return nil
        }
    }
}

enum KDF {
    /// PBKDF2 (RFC 8018 §5.2) via CommonCrypto.
    static func pbkdf2(_ prf: HashKind, password: [UInt8], salt: [UInt8], iterations: Int, keyLength: Int) throws -> [UInt8] {
        guard iterations >= 1, iterations <= Int(UInt32.max), keyLength >= 1 else {
            throw CertConvertError.malformed("PBKDF2 parameters out of range")
        }
        let alg: Int
        switch prf {
        case .sha1: alg = kCCPRFHmacAlgSHA1
        case .sha256: alg = kCCPRFHmacAlgSHA256
        case .sha384: alg = kCCPRFHmacAlgSHA384
        case .sha512: alg = kCCPRFHmacAlgSHA512
        case .md5: throw CertConvertError.unsupported("PBKDF2 with HMAC-MD5")
        }
        var out = [UInt8](repeating: 0, count: keyLength)
        let status = password.withUnsafeBytes { p in
            salt.withUnsafeBytes { s in
                out.withUnsafeMutableBytes { o in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         p.baseAddress?.assumingMemoryBound(to: CChar.self), p.count,
                                         s.baseAddress?.assumingMemoryBound(to: UInt8.self), s.count,
                                         CCPseudoRandomAlgorithm(alg), UInt32(iterations),
                                         o.baseAddress?.assumingMemoryBound(to: UInt8.self), o.count)
                }
            }
        }
        guard status == kCCSuccess else { throw CertConvertError.malformed("PBKDF2 failed (\(status))") }
        return out
    }

    /// PBKDF1 (RFC 8018 §5.1): T = Hash^c(P || S).
    static func pbkdf1(_ hash: HashKind, password: [UInt8], salt: [UInt8], iterations: Int, length: Int) -> [UInt8] {
        var t = hash.hash(password + salt)
        for _ in 1..<max(iterations, 1) { t = hash.hash(t) }
        return Array(t.prefix(length))
    }

    /// PKCS#12 key derivation (RFC 7292 appendix B.2). `password` is already the BMPString
    /// form with its two-byte terminator (or empty for a NULL password).
    static func pkcs12(_ hash: HashKind, id: UInt8, password: [UInt8], salt: [UInt8], iterations: Int, length: Int) -> [UInt8] {
        let v = hash.blockLength
        let u = hash.outputLength
        let d = [UInt8](repeating: id, count: v)
        func stretch(_ x: [UInt8]) -> [UInt8] {
            guard !x.isEmpty else { return [] }
            let n = v * ((x.count + v - 1) / v)
            return (0..<n).map { x[$0 % x.count] }
        }
        var i = stretch(salt) + stretch(password)
        var out: [UInt8] = []
        while out.count < length {
            var a = hash.hash(d + i)
            for _ in 1..<max(iterations, 1) { a = hash.hash(a) }
            out += a
            if out.count >= length { break }
            let b = (0..<v).map { a[$0 % u] }
            for block in stride(from: 0, to: i.count, by: v) {
                var carry: UInt16 = 1
                for j in stride(from: v - 1, through: 0, by: -1) {
                    let sum = UInt16(i[block + j]) + UInt16(b[j]) + carry
                    i[block + j] = UInt8(sum & 0xFF)
                    carry = sum >> 8
                }
            }
        }
        return Array(out.prefix(length))
    }

    /// OpenSSL `EVP_BytesToKey` with MD5 and one iteration, as used by traditional encrypted PEM.
    static func evpBytesToKey(password: [UInt8], salt: [UInt8], keyLength: Int) -> [UInt8] {
        var out: [UInt8] = []
        var prev: [UInt8] = []
        while out.count < keyLength {
            prev = HashKind.md5.hash(prev + password + salt)
            out += prev
        }
        return Array(out.prefix(keyLength))
    }

    /// Password as BMPString bytes plus the 00 00 terminator (RFC 7292 B.1).
    static func bmpPassword(_ password: String) -> [UInt8] {
        DERW.bmp(password) + [0, 0]
    }
}
