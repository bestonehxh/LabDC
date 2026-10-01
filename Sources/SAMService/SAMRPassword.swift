import Foundation
import SheepCrypto

/// The MS-SAMR password-blob cryptography (§2.2.6.21/§2.2.6.22 and §2.2.11.1) implemented on top
/// of SheepCrypto's RC4/MD5/DES primitives. All of it is pure byte shuffling; nothing here derives
/// Kerberos keys (that happens in Store, from the recovered cleartext or NT hash).
enum SAMRPassword {
    /// Expands a 7-byte key block to an 8-byte DES key (with parity spacing), MS-SAMR §2.2.11.1.2
    /// (the same transform LM/NTLM use). Shorter input is zero-padded to 7 bytes.
    static func desKey(from block7: [UInt8]) -> [UInt8] {
        var i = block7
        if i.count < 7 { i += [UInt8](repeating: 0, count: 7 - i.count) }
        var o = [UInt8](repeating: 0, count: 8)
        o[0] = i[0] >> 1
        o[1] = ((i[0] & 0x01) << 6) | (i[1] >> 2)
        o[2] = ((i[1] & 0x03) << 5) | (i[2] >> 3)
        o[3] = ((i[2] & 0x07) << 4) | (i[3] >> 4)
        o[4] = ((i[3] & 0x0F) << 3) | (i[4] >> 5)
        o[5] = ((i[4] & 0x1F) << 2) | (i[5] >> 6)
        o[6] = ((i[5] & 0x3F) << 1) | (i[6] >> 7)
        o[7] = i[6] & 0x7F
        for j in 0..<8 { o[j] = (o[j] << 1) & 0xFE }
        return o
    }

    /// DES-ECB encrypts a 16-byte value as two 8-byte blocks keyed by the first 14 bytes of `key`
    /// (MS-SAMR §2.2.11.1.1 `Encrypt`). This is impacket's `SamEncryptNTLMHash`. Used to build and
    /// to verify the `ENCRYPTED_NT_OWF_PASSWORD` cross-encryptions.
    static func encryptOWF(_ value16: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(value16.count == 16 && key.count >= 14)
        let k1 = desKey(from: Array(key[0..<7]))
        let k2 = desKey(from: Array(key[7..<14]))
        return DES.encryptBlock(key: k1, Array(value16[0..<8]))
            + DES.encryptBlock(key: k2, Array(value16[8..<16]))
    }

    /// DES-ECB decrypts a 16-byte `ENCRYPTED_NT_OWF_PASSWORD` keyed by the first 14 bytes of `key`
    /// (MS-SAMR §2.2.11.1.1 `Decrypt`, impacket's `SamDecryptNTLMHash`): the level-18 NT-hash
    /// recovery from `SamrSetInformationUser2`.
    static func decryptOWF(_ value16: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(value16.count == 16 && key.count >= 14)
        let k1 = desKey(from: Array(key[0..<7]))
        let k2 = desKey(from: Array(key[7..<14]))
        return DES.decryptBlock(key: k1, Array(value16[0..<8]))
            + DES.decryptBlock(key: k2, Array(value16[8..<16]))
    }

    /// Recovers the cleartext password from a `SAMPR_ENCRYPTED_USER_PASSWORD` (§2.2.6.21, 516
    /// bytes: an RC4-encrypted `SAMPR_USER_PASSWORD` = 512-byte buffer + 4-byte length) keyed by
    /// `rc4Key` (the SMB session key for level 24, or the old NT hash for the change call).
    /// Returns the UTF-16LE password decoded to a `String`. Throws on a malformed length.
    static func decryptUserPassword(_ blob516: [UInt8], rc4Key: [UInt8]) throws -> String {
        guard blob516.count == 516 else { throw SAMRError(.invalidParameter) }
        let plain = RC4.apply(key: rc4Key, blob516)
        return try clearFromUserPassword(buffer512: Array(plain[0..<512]),
                                         length: le32(Array(plain[512..<516])))
    }

    /// Recovers the cleartext from a `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` (§2.2.6.22, 532 bytes:
    /// a 516-byte RC4-encrypted `SAMPR_USER_PASSWORD` followed by a 16-byte cleartext salt). The
    /// RC4 key is `MD5(salt || sessionKey)`.
    static func decryptUserPasswordNew(_ blob532: [UInt8], sessionKey: [UInt8]) throws -> String {
        guard blob532.count == 532 else { throw SAMRError(.invalidParameter) }
        let salt = Array(blob532[516..<532])
        let key = MD5.hash(salt + sessionKey)
        let plain = RC4.apply(key: key, Array(blob532[0..<516]))
        return try clearFromUserPassword(buffer512: Array(plain[0..<512]),
                                         length: le32(Array(plain[512..<516])))
    }

    /// The `SAMPR_USER_PASSWORD` convention: the password's UTF-16LE bytes sit in the *last*
    /// `length` bytes of the 512-byte buffer (the front is random/zero padding).
    private static func clearFromUserPassword(buffer512: [UInt8], length: UInt32) throws -> String {
        let n = Int(length)
        guard n <= 512, n % 2 == 0 else { throw SAMRError(.wrongPassword) }
        let start = 512 - n
        let units: [UInt16] = stride(from: start, to: 512, by: 2).map {
            UInt16(buffer512[$0]) | (UInt16(buffer512[$0 + 1]) << 8)
        }
        return String(decoding: units, as: UTF16.self)
    }

    private static func le32(_ b: [UInt8]) -> UInt32 {
        UInt32(b[0]) | (UInt32(b[1]) << 8) | (UInt32(b[2]) << 16) | (UInt32(b[3]) << 24)
    }
}
