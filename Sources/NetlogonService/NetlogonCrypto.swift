import Foundation
import CommonCrypto
import SheepCrypto

/// The cryptographic primitives of MS-NRPC §3.1.4 (secure channel) and §3.3.4 (schannel sign/seal):
/// the AES session-key derivation, AES-CFB8 credential/blob transforms, the strong-key (RC4) legacy
/// path, and the `NL_AUTH_SHA2_SIGNATURE` checksum / sequence-number helpers. Cross-checked against
/// impacket `impacket.dcerpc.v5.nrpc` (`ComputeSessionKeyAES`, `ComputeNetlogonCredentialAES`,
/// `ComputeNetlogonAuthenticatorAES`, `ComputeNetlogonSignatureAES`, `deriveSequenceNumber`,
/// `encryptSequenceNumberAES`, `SEAL`/`SIGN`).
public enum NetlogonCrypto {

    // MARK: AES-128-CFB8 (segment size = 8 bits, the mode pycryptodome uses by default)

    /// AES-128 single-block ECB encryption (the CFB8 keystream generator).
    static func aesEncryptBlock(key: [UInt8], _ block: [UInt8]) -> [UInt8] {
        precondition(key.count == 16 && block.count == 16)
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = key.withUnsafeBytes { k in
            block.withUnsafeBytes { i in
                out.withUnsafeMutableBytes { o in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode), k.baseAddress, 16, nil,
                            i.baseAddress, 16, o.baseAddress, 16, &moved)
                }
            }
        }
        precondition(status == CCCryptorStatus(kCCSuccess) && moved == 16, "AES-ECB block failed")
        return out
    }

    /// AES-CFB8 with a 16-byte IV. `encrypt == true` for sealing, false for unsealing.
    public static func aesCFB8(key: [UInt8], iv: [UInt8], _ input: [UInt8], encrypt: Bool) -> [UInt8] {
        precondition(iv.count == 16)
        var sr = iv
        var out = [UInt8](); out.reserveCapacity(input.count)
        for byte in input {
            let e = aesEncryptBlock(key: key, sr)[0]
            let outByte = byte ^ e
            out.append(outByte)
            // Shift the register left one byte, appending the ciphertext byte.
            let feedback = encrypt ? outByte : byte
            sr.removeFirst()
            sr.append(feedback)
        }
        return out
    }

    // MARK: HMAC

    static func hmacSHA256(key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { k in
            data.withUnsafeBytes { d in
                out.withUnsafeMutableBytes { o in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), k.baseAddress, key.count,
                           d.baseAddress, data.count, o.baseAddress)
                }
            }
        }
        return out
    }

    // MARK: session key and credentials (§3.1.4.3 / §3.1.4.4)

    /// AES session key = HMAC-SHA256(NT hash of the machine account, clientChallenge‖serverChallenge)[0..<16].
    public static func sessionKeyAES(ntHash: [UInt8], clientChallenge: [UInt8], serverChallenge: [UInt8]) -> [UInt8] {
        Array(hmacSHA256(key: ntHash, clientChallenge + serverChallenge).prefix(16))
    }

    /// Strong-key (RC4/HMAC-MD5) legacy session key (§3.1.4.3.2): HMAC-MD5(NT hash,
    /// MD5(0000‖clientChallenge‖serverChallenge)).
    public static func sessionKeyStrong(ntHash: [UInt8], clientChallenge: [UInt8], serverChallenge: [UInt8]) -> [UInt8] {
        let inner = MD5.hash([0, 0, 0, 0] + clientChallenge + serverChallenge)
        return HMACMD5.authenticate(key: ntHash, inner)
    }

    /// AES credential = AES-128-CFB8(sessionKey, IV=0)(input). Input/output are 8 bytes.
    public static func credentialAES(sessionKey: [UInt8], _ input: [UInt8]) -> [UInt8] {
        aesCFB8(key: sessionKey, iv: [UInt8](repeating: 0, count: 16), input, encrypt: true)
    }

    /// RC4/DES legacy credential (§3.1.4.4.2): two-key DES over the 8-byte input.
    public static func credentialDES(sessionKey: [UInt8], _ input: [UInt8]) -> [UInt8] {
        let k1 = desTransform(Array(sessionKey[0..<7]))
        let k2 = desTransform(Array(sessionKey[7..<14]))
        return desECB(key: k2, desECB(key: k1, input))
    }

    /// Adds `timestamp` to the low 32 bits (little-endian, mod 2^32) of an 8-byte stored credential,
    /// as impacket's `ComputeNetlogonAuthenticatorAES` does before encrypting.
    public static func addTimestamp(_ credential: [UInt8], _ timestamp: UInt32) -> [UInt8] {
        precondition(credential.count == 8)
        let low = UInt32(credential[0]) | (UInt32(credential[1]) << 8)
              | (UInt32(credential[2]) << 16) | (UInt32(credential[3]) << 24)
        let sum = low &+ timestamp
        var out = credential
        out[0] = UInt8(truncatingIfNeeded: sum)
        out[1] = UInt8(truncatingIfNeeded: sum >> 8)
        out[2] = UInt8(truncatingIfNeeded: sum >> 16)
        out[3] = UInt8(truncatingIfNeeded: sum >> 24)
        return out
    }

    // MARK: NL_AUTH_SHA2_SIGNATURE (§3.3.4.2)

    /// The signature checksum: HMAC-SHA256(sessionKey, sigHeader8 ‖ confounder ‖ message)[0..<8].
    /// `sigHeader8` is the first 8 bytes of the signature (algorithm/seal/pad/flags).
    public static func signatureChecksum(sessionKey: [UInt8], sigHeader8: [UInt8],
                                         confounder: [UInt8], message: [UInt8]) -> [UInt8] {
        Array(hmacSHA256(key: sessionKey, sigHeader8 + confounder + message).prefix(8))
    }

    /// The 8-byte on-the-wire sequence number (before encryption): SequenceLow (BE) ‖ SequenceHigh
    /// (BE), where the high dword's top bit is set for the initiator (client→server) direction.
    public static func deriveSequenceNumber(_ sequence: UInt64, initiator: Bool) -> [UInt8] {
        let low = UInt32(truncatingIfNeeded: sequence)
        var high = UInt32(truncatingIfNeeded: sequence >> 32)
        if initiator { high |= 0x8000_0000 }
        func be(_ v: UInt32) -> [UInt8] { (0..<4).reversed().map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }
        return be(low) + be(high)
    }

    /// Encrypts (or decrypts — the operation is symmetric for CFB8 on the seq itself here since impacket
    /// uses encrypt for both) the 8-byte derived sequence number with AES-CFB8, IV = checksum[0..<8] ‖
    /// checksum[0..<8].
    public static func sealSequenceNumberAES(sessionKey: [UInt8], checksum: [UInt8], _ derivedSeq: [UInt8]) -> [UInt8] {
        let iv = Array(checksum.prefix(8)) + Array(checksum.prefix(8))
        return aesCFB8(key: sessionKey, iv: iv, derivedSeq, encrypt: true)
    }

    /// The AES seal key: sessionKey XOR 0xF0 in every byte (§3.3.4.2.1).
    public static func sealKeyAES(_ sessionKey: [UInt8]) -> [UInt8] { sessionKey.map { $0 ^ 0xF0 } }

    // MARK: Encrypted OWF passwords (WP-AQ)

    /// `ENCRYPTED_NT_OWF_PASSWORD` for `NetrServerGetTrustInfo` (MS-NRPC §3.5.4.7.6): the 16-byte
    /// NT OWF encrypted per MS-SAMR §2.2.11.1.1 with the session key through the 16-byte-key process
    /// (§2.2.11.1.4): block 1 = DES-ECB under `sessionKey[0..<7]`, block 2 under `sessionKey[7..<14]`.
    /// Samba `netlogon_creds_crypt_samr_Password` → `des_crypt112_16`: DES **even when AES or RC4
    /// was negotiated**, and an all-zero value is left as is.
    public static func encryptOWF(sessionKey: [UInt8], _ owf: [UInt8]) -> [UInt8] {
        cryptOWF(sessionKey: sessionKey, owf, decrypt: false)
    }

    /// Inverse of `encryptOWF` (the member's side; used by the tests).
    public static func decryptOWF(sessionKey: [UInt8], _ encrypted: [UInt8]) -> [UInt8] {
        cryptOWF(sessionKey: sessionKey, encrypted, decrypt: true)
    }

    private static func cryptOWF(sessionKey: [UInt8], _ input: [UInt8], decrypt: Bool) -> [UInt8] {
        precondition(sessionKey.count >= 14 && input.count == 16)
        if input.allSatisfy({ $0 == 0 }) { return input }
        let k1 = desTransform(Array(sessionKey[0..<7]))
        let k2 = desTransform(Array(sessionKey[7..<14]))
        return desECB(key: k1, Array(input[0..<8]), decrypt: decrypt)
            + desECB(key: k2, Array(input[8..<16]), decrypt: decrypt)
    }

    // MARK: DES helpers (legacy credential path)

    /// Expands a 7-byte key to 8 bytes with odd parity, as MS-NRPC / MS-SAMR do.
    static func desTransform(_ key7: [UInt8]) -> [UInt8] {
        precondition(key7.count == 7)
        var out = [UInt8](repeating: 0, count: 8)
        out[0] = key7[0] >> 1
        out[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
        out[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
        out[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
        out[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
        out[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
        out[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
        out[7] = key7[6] & 0x7F
        for i in 0..<8 { out[i] = (out[i] << 1) }
        return out
    }

    static func desECB(key: [UInt8], _ block: [UInt8], decrypt: Bool = false) -> [UInt8] {
        precondition(key.count == 8 && block.count == 8)
        var out = [UInt8](repeating: 0, count: 8)
        var moved = 0
        _ = key.withUnsafeBytes { k in
            block.withUnsafeBytes { i in
                out.withUnsafeMutableBytes { o in
                    CCCrypt(CCOperation(decrypt ? kCCDecrypt : kCCEncrypt), CCAlgorithm(kCCAlgorithmDES),
                            CCOptions(kCCOptionECBMode), k.baseAddress, 8, nil,
                            i.baseAddress, 8, o.baseAddress, 8, &moved)
                }
            }
        }
        return out
    }

    /// Samba `netlogon_creds_is_random_challenge` negated: true when the first 5 bytes are all
    /// equal (the Zerologon pattern), so the challenge or credential must be refused.
    static func isWeakChallenge(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 5 else { return true }
        return bytes[1..<5].allSatisfy { $0 == bytes[0] }
    }
}
