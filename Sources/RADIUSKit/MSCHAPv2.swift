import Foundation
import Crypto
import SheepCrypto

/// MS-CHAPv2 (RFC 2759) and the MPPE key derivation (RFC 3079) + RADIUS carriage (RFC 2548).
/// The server holds the NT hash (MD4 of UTF-16LE, the directory's stored secret) and checks the
/// client's 24-byte reply.
public enum MSCHAPv2 {
    /// MS-CHAP2-Response (RFC 2548 §2.3.2): ident (1), flags (1), peer challenge (16),
    /// reserved (8), NT-Response (24) — exactly 50 bytes.
    public struct Response: Sendable, Equatable {
        public var ident: UInt8
        public var flags: UInt8
        public var peerChallenge: [UInt8]
        public var ntResponse: [UInt8]

        public init?(_ value: [UInt8]) {
            guard value.count == 50 else { return nil }
            ident = value[0]
            flags = value[1]
            peerChallenge = Array(value[2..<18])
            ntResponse = Array(value[26..<50])
        }

        public init(ident: UInt8, flags: UInt8 = 0, peerChallenge: [UInt8], ntResponse: [UInt8]) {
            self.ident = ident; self.flags = flags; self.peerChallenge = peerChallenge; self.ntResponse = ntResponse
        }

        public var bytes: [UInt8] { [ident, flags] + peerChallenge + [UInt8](repeating: 0, count: 8) + ntResponse }
    }

    /// What a verified exchange gives back to the NAS.
    public struct Success: Sendable, Equatable {
        /// `S=<40 hex>` (GenerateAuthenticatorResponse).
        public var authenticatorResponse: [UInt8]
        /// MPPE keys from the server's point of view (RFC 3079 §3.3, 128-bit).
        public var sendKey: [UInt8]
        public var recvKey: [UInt8]
        /// MS-CHAP2-Success value: the response's ident + `S=…`.
        public var successValue: [UInt8]
    }

    /// Recomputes the NT-Response for `username` and, when it matches (constant time), returns
    /// the authenticator response and the MPPE keys.
    public static func verify(challenge: [UInt8], response: Response, username: String, ntHash: [UInt8]) -> Success? {
        guard challenge.count == 16 else { return nil }
        let expected = ntResponse(challenge: challenge, peerChallenge: response.peerChallenge, username: username, ntHash: ntHash)
        guard ConstantTime.equal(expected, response.ntResponse) else { return nil }
        let auth = authenticatorResponse(ntHash: ntHash, ntResponse: response.ntResponse, peerChallenge: response.peerChallenge,
                                         authenticatorChallenge: challenge, username: username)
        let keys = mppeKeys(ntHash: ntHash, ntResponse: response.ntResponse)
        let hex = auth.map { String(format: "%02X", $0) }.joined()
        return Success(authenticatorResponse: auth, sendKey: keys.send, recvKey: keys.recv,
                       successValue: [response.ident] + Array("S=\(hex)".utf8))
    }

    /// `GenerateNTResponse` — what the client sent; the server recomputes and compares.
    public static func ntResponse(challenge: [UInt8], peerChallenge: [UInt8], username: String, ntHash: [UInt8]) -> [UInt8] {
        let ch = challengeHash(peerChallenge: peerChallenge, authenticatorChallenge: challenge, username: username)
        return challengeResponse(challenge: ch, ntHash: ntHash)
    }

    /// The user name ChallengeHash hashes: "excluding any prepended domain name" (RFC 2759 §4,
    /// GenerateNTResponse) — `LAB\alice` → `alice`.
    public static func challengeUserName(_ username: String) -> String {
        username.split(separator: "\\", omittingEmptySubsequences: false).last.map(String.init) ?? username
    }

    /// `ChallengeHash` (§8.2): SHA-1(peer + authenticator challenge + user without domain), first 8 bytes.
    public static func challengeHash(peerChallenge: [UInt8], authenticatorChallenge: [UInt8], username: String) -> [UInt8] {
        let data = peerChallenge + authenticatorChallenge + Array(challengeUserName(username).utf8)
        return Array(Insecure.SHA1.hash(data: data).prefix(8))
    }

    /// The stored secret: MD4 of UTF-16LE (SheepCrypto's MD4, the owner's own).
    public static func ntHash(_ password: String) -> [UInt8] {
        MD4.hash(password.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] })
    }

    /// The 56 raw bits of `seven` bytes become 8 bytes: each output byte is the next 7 bits
    /// followed by an odd-parity bit (RFC 2759 §9.3's worked example: FC 15 6A F7 ED CD 6C →
    /// FD 0B 5B 5E 7F 6E 34 D9).
    static func parity(_ seven: [UInt8]) -> [UInt8] {
        let bits: [Bool] = seven.prefix(7).flatMap { byte in (0..<8).map { (byte >> (7 - $0)) & 1 == 1 } }
        var out = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            var byte: UInt8 = 0
            for j in 0..<7 { byte = (byte << 1) | (bits[i * 7 + j] ? 1 : 0) }
            byte = byte << 1                          // the data sits in bits 7…1
            if byte.nonzeroBitCount % 2 == 0 { byte |= 1 }   // odd parity in bit 0
            out[i] = byte
        }
        return out
    }

    /// `ChallengeResponse` (§8.5): three DES encryptions of the 8-byte challenge.
    public static func challengeResponse(challenge: [UInt8], ntHash: [UInt8]) -> [UInt8] {
        let padded = Array((ntHash + [UInt8](repeating: 0, count: 21)).prefix(21))
        var out: [UInt8] = []
        for i in 0..<3 {
            out += DES.encrypt(block: challenge, key: MSCHAPv2.parity(Array(padded[i * 7..<(i * 7 + 7)])))
        }
        return out
    }

    /// `GenerateAuthenticatorResponse` (§8.7).
    public static func authenticatorResponse(ntHash: [UInt8], ntResponse: [UInt8], peerChallenge: [UInt8],
                                             authenticatorChallenge: [UInt8], username: String) -> [UInt8] {
        let magic1 = Array("Magic server to client signing constant".utf8)   // 39 bytes, no NUL
        let hashHash = MD4.hash(ntHash)
        let digest = Insecure.SHA1.hash(data: hashHash + ntResponse + magic1)
        let ch = challengeHash(peerChallenge: peerChallenge, authenticatorChallenge: authenticatorChallenge, username: username)
        let magic2 = Array("Pad to make it do more than one iteration".utf8)   // 41 bytes, no NUL
        return Array(Insecure.SHA1.hash(data: Array(digest) + ch + magic2))
    }

    // MARK: MPPE (RFC 3079 §3.3–3.4)

    /// `GetMasterKey`: SHA-1(PasswordHashHash + NT-Response + Magic1)[0..16].
    public static func masterKey(ntHash: [UInt8], ntResponse: [UInt8]) -> [UInt8] {
        let magic1 = Array("This is the MPPE Master Key".utf8)   // 27 bytes
        return Array(Insecure.SHA1.hash(data: MD4.hash(ntHash) + ntResponse + magic1).prefix(16))
    }

    /// `GetAsymmetricStartKey`: SHA-1(MasterKey + SHSpad1 + s + SHSpad2)[0..keyLength], where s is
    /// Magic3 for (send, server) / (receive, client) and Magic2 otherwise.
    public static func asymmetricStartKey(masterKey: [UInt8], keyLength: Int = 16, isSend: Bool, isServer: Bool) -> [UInt8] {
        let magic2 = Array("On the client side, this is the send key; on the server side, it is the receive key.".utf8)
        let magic3 = Array("On the client side, this is the receive key; on the server side, it is the send key.".utf8)
        let shsPad1 = [UInt8](repeating: 0x00, count: 40)
        let shsPad2 = [UInt8](repeating: 0xF2, count: 40)
        let s = isSend == isServer ? magic3 : magic2
        return Array(Insecure.SHA1.hash(data: masterKey + shsPad1 + s + shsPad2).prefix(keyLength))
    }

    /// The server's 128-bit MPPE send/receive keys (MS-MPPE-Send-Key / MS-MPPE-Recv-Key, the
    /// WPA2 PMK material: the NAS sends with `send`, receives with `recv`).
    public static func mppeKeys(ntHash: [UInt8], ntResponse: [UInt8]) -> (send: [UInt8], recv: [UInt8]) {
        let master = masterKey(ntHash: ntHash, ntResponse: ntResponse)
        return (asymmetricStartKey(masterKey: master, isSend: true, isServer: true),
                asymmetricStartKey(masterKey: master, isSend: false, isServer: true))
    }
}

/// DES (encrypt, one block) — only MS-CHAPv2's ChallengeResponse needs it. CommonCrypto's DES
/// (deprecated since 10.14 but present) spares us a hand-rolled table implementation; MS-CHAPv2
/// still negotiates it on the wire, so the dependency stays until EAP-TLS replaces it.
import CommonCrypto

enum DES {
    /// Encrypts one 8-byte block with ECB (a zero IV over one block is the same thing).
    static func encrypt(block: [UInt8], key: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 8)
        var data = Array((block + [UInt8](repeating: 0, count: 8)).prefix(8))
        var key = Array((key + [UInt8](repeating: 0, count: 8)).prefix(8))
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES),
                             CCOptions(kCCOptionECBMode), &key, key.count, nil,
                             &data, data.count, &out, out.count, nil)
        precondition(status == kCCSuccess, "DES failed: \(status)")
        return out
    }
}
