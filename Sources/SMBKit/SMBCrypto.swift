import CommonCrypto
import CryptoKit
import Foundation

/// The SMB2/3 cryptographic primitives: signing (HMAC-SHA256, AES-128-CMAC), the SMB 3.x
/// key derivation function and the 3.1.1 preauth integrity hash.
public enum SMBCrypto {
    /// HMAC-SHA256 (full 32 bytes).
    public static func hmacSHA256(key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    public static func sha512(_ data: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: data)) }

    /// AES-128-CMAC (RFC 4493). The CBC-MAC over all but the last block is one CommonCrypto
    /// CBC call, so signing a 1 MiB READ response stays cheap.
    public static func aesCMAC(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        precondition(key.count == 16, "AES-128-CMAC needs a 16-byte key")
        let l = aesBlock(key: key, [UInt8](repeating: 0, count: 16))
        let k1 = shiftXor(l)
        let k2 = shiftXor(k1)
        let n = max(1, (message.count + 15) / 16)
        let complete = !message.isEmpty && message.count % 16 == 0
        var last: [UInt8]
        if complete {
            last = Array(message[((n - 1) * 16)...])
            for i in 0..<16 { last[i] ^= k1[i] }
        } else {
            last = Array(message[((n - 1) * 16)...]) + [0x80]
            last += [UInt8](repeating: 0, count: 16 - last.count)
            for i in 0..<16 { last[i] ^= k2[i] }
        }
        var x = [UInt8](repeating: 0, count: 16)
        if n > 1 {
            let cbc = aesCBC(key: key, Array(message[0..<((n - 1) * 16)]))
            x = Array(cbc[(cbc.count - 16)...])
        }
        for i in 0..<16 { x[i] ^= last[i] }
        return aesBlock(key: key, x)
    }

    private static func shiftXor(_ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        var carry: UInt8 = 0
        for i in stride(from: 15, through: 0, by: -1) {
            out[i] = (b[i] << 1) | carry
            carry = b[i] >> 7
        }
        if b[0] & 0x80 != 0 { out[15] ^= 0x87 }
        return out
    }

    static func aesBlock(key: [UInt8], _ block: [UInt8]) -> [UInt8] {
        crypt(key: key, input: block, options: CCOptions(kCCOptionECBMode))
    }

    /// AES-CBC encryption with a zero IV and no padding (input is a multiple of 16).
    static func aesCBC(key: [UInt8], _ input: [UInt8]) -> [UInt8] {
        crypt(key: key, input: input, options: 0)
    }

    private static func crypt(key: [UInt8], input: [UInt8], options: CCOptions) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let iv = [UInt8](repeating: 0, count: 16)
        let status = key.withUnsafeBufferPointer { k in
            input.withUnsafeBufferPointer { i in
                iv.withUnsafeBufferPointer { v in
                    out.withUnsafeMutableBufferPointer { o in
                        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), options, k.baseAddress, k.count,
                                v.baseAddress, i.baseAddress, i.count, o.baseAddress, o.count, &moved)
                    }
                }
            }
        }
        precondition(status == CCCryptorStatus(kCCSuccess) && moved == input.count, "CCCrypt AES failed: \(status)")
        return out
    }

    /// SMB3KDF (MS-SMB2 §3.1.4.2): SP800-108 counter mode with HMAC-SHA256, r = 32, L = 128,
    /// one iteration: `HMAC-SHA256(Ki, 00000001 | Label | 00 | Context | 00000080)[0..<16]`.
    /// `label` and `context` are passed exactly as MS-SMB2 lists them (the labels include
    /// their terminating NUL; the separator 00 is added here).
    public static func kdf(key: [UInt8], label: [UInt8], context: [UInt8], length: Int = 16) -> [UInt8] {
        var input: [UInt8] = [0, 0, 0, 1]
        input += label
        input.append(0)
        input += context
        let bits = UInt32(length * 8)
        input += [UInt8(bits >> 24), UInt8((bits >> 16) & 0xFF), UInt8((bits >> 8) & 0xFF), UInt8(bits & 0xFF)]
        return Array(hmacSHA256(key: key, input).prefix(length))
    }

    /// Labels and contexts of MS-SMB2 §3.3.5.5.3 (NUL-terminated as the spec writes them).
    public enum Label {
        public static let smb30Signing = Array("SMB2AESCMAC".utf8) + [0]
        public static let smb30SigningContext = Array("SmbSign".utf8) + [0]
        public static let smb30Application = Array("SMB2APP".utf8) + [0]
        public static let smb30ApplicationContext = Array("SmbRpc".utf8) + [0]
        public static let smb311Signing = Array("SMBSigningKey".utf8) + [0]
        public static let smb311Application = Array("SMBAppKey".utf8) + [0]
    }

    /// The keys of an authenticated session.
    public struct SessionKeys: Sendable, Equatable {
        /// Session.SessionKey: the GSS key, first 16 bytes, zero padded.
        public var sessionKey: [UInt8]
        /// Session.SigningKey.
        public var signingKey: [UInt8]
        /// Session.ApplicationKey (what an RPC server over this session uses as "the session key").
        public var applicationKey: [UInt8]
    }

    /// Derives the session keys for `dialect` from the GSS key (MS-SMB2 §3.3.5.5.3).
    /// `preauthHash` is Session.PreauthIntegrityHashValue (3.1.1 only).
    public static func sessionKeys(gssKey: [UInt8], dialect: UInt16, preauthHash: [UInt8]?) -> SessionKeys {
        var sk = Array(gssKey.prefix(16))
        if sk.count < 16 { sk += [UInt8](repeating: 0, count: 16 - sk.count) }
        switch dialect {
        case SMB2Dialect.smb311:
            let ctx = preauthHash ?? [UInt8](repeating: 0, count: 64)
            return SessionKeys(sessionKey: sk, signingKey: kdf(key: sk, label: Label.smb311Signing, context: ctx),
                               applicationKey: kdf(key: sk, label: Label.smb311Application, context: ctx))
        case SMB2Dialect.smb300, SMB2Dialect.smb302:
            return SessionKeys(sessionKey: sk,
                               signingKey: kdf(key: sk, label: Label.smb30Signing, context: Label.smb30SigningContext),
                               applicationKey: kdf(key: sk, label: Label.smb30Application, context: Label.smb30ApplicationContext))
        default:
            return SessionKeys(sessionKey: sk, signingKey: sk, applicationKey: sk)
        }
    }

    /// The 16-byte signature of one SMB2 message (its header's Signature field is ignored):
    /// HMAC-SHA256 truncated for 2.x, AES-128-CMAC for 3.x (MS-SMB2 §3.1.4.1).
    public static func signature(of message: [UInt8], signingKey: [UInt8], dialect: UInt16) -> [UInt8] {
        var m = message
        if m.count >= 64 { for i in 48..<64 { m[i] = 0 } }
        if SMB2Dialect.isSMB3(dialect) { return aesCMAC(key: signingKey, m) }
        return Array(hmacSHA256(key: signingKey, m).prefix(16))
    }

    /// Sets the SIGNED flag and writes the signature into `message` (one SMB2 message).
    public static func sign(_ message: inout [UInt8], signingKey: [UInt8], dialect: UInt16) {
        guard message.count >= 64 else { return }
        message.set32(message.le32(16) | SMB2Flags.signed, at: 16)
        let sig = signature(of: message, signingKey: signingKey, dialect: dialect)
        message.replaceSubrange(48..<64, with: sig)
    }

    /// Constant-time check of the signature carried by `message`.
    public static func verify(_ message: [UInt8], signingKey: [UInt8], dialect: UInt16) -> Bool {
        guard message.count >= 64 else { return false }
        let expected = signature(of: message, signingKey: signingKey, dialect: dialect)
        var diff: UInt8 = 0
        for i in 0..<16 { diff |= expected[i] ^ message[48 + i] }
        return diff == 0
    }
}
