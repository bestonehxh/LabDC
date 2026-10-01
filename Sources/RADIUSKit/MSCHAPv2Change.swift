import Foundation
import SheepCrypto

// MARK: Failure codes and password change (RFC 2759 §6–§7, [MS-CHAP] §2.2)

extension MSCHAPv2 {
    /// The `E=` codes of a Failure packet / MS-CHAP-Error ([MS-CHAP] §2.2.5; RFC 2759 §6).
    public enum ErrorCode: Int, Sendable {
        case restrictedLogonHours = 646
        case accountDisabled = 647
        case passwordExpired = 648
        case noDialinPermission = 649
        case authenticationFailure = 691
        case changingPassword = 709

        public var text: String {
            switch self {
            case .restrictedLogonHours: "Logon outside the allowed hours"
            case .accountDisabled: "Account disabled"
            case .passwordExpired: "Password expired"
            case .noDialinPermission: "No dial-in permission"
            case .authenticationFailure: "Authentication failed"
            case .changingPassword: "Password change failed"
            }
        }
    }

    /// `E=648 R=0 C=<32 hex> V=3 M=Password expired` — the Failure message text. `challenge` is
    /// the new Authenticator Challenge the peer uses for a Change-Password (E=648/709).
    public static func failureMessage(_ code: ErrorCode, challenge: [UInt8]) -> String {
        let hex = challenge.map { String(format: "%02X", $0) }.joined()
        return "E=\(code.rawValue) R=0 C=\(hex) V=3 M=\(code.text)"
    }

    /// The Change-Password packet body after OpCode 7, MS-CHAPv2-ID and MS-Length (RFC 2759
    /// §7): Encrypted-Password (516), Encrypted-Hash (16), Peer-Challenge (16), Reserved (8),
    /// NT-Response (24), Flags (2). RADIUS carries the same fields as MS-CHAP2-CPW (ident,
    /// hash, challenge, response, flags) + the MS-CHAP-NT-Enc-PW chunks (RFC 2548 §2.3.3–2.3.4).
    public struct ChangePassword: Sendable, Equatable {
        public var encryptedPassword: [UInt8]
        public var encryptedHash: [UInt8]
        public var peerChallenge: [UInt8]
        public var ntResponse: [UInt8]
        public var flags: UInt16

        public static let length = 516 + 16 + 16 + 8 + 24 + 2

        public init(encryptedPassword: [UInt8], encryptedHash: [UInt8], peerChallenge: [UInt8], ntResponse: [UInt8], flags: UInt16 = 0) {
            self.encryptedPassword = encryptedPassword; self.encryptedHash = encryptedHash
            self.peerChallenge = peerChallenge; self.ntResponse = ntResponse; self.flags = flags
        }

        public init?(_ body: [UInt8]) {
            guard body.count >= Self.length else { return nil }
            encryptedPassword = Array(body[0..<516])
            encryptedHash = Array(body[516..<532])
            peerChallenge = Array(body[532..<548])
            ntResponse = Array(body[556..<580])
            flags = UInt16(body[580]) << 8 | UInt16(body[581])
        }

        /// From RADIUS: MS-CHAP2-CPW (code 7, ident, Encrypted-Hash 16, Peer-Challenge 16,
        /// reserved 8, NT-Response 24, flags 2 = 68 bytes) and the MS-CHAP-NT-Enc-PW values
        /// (code 6, ident, sequence 2, data), joined in sequence order into the 516 bytes.
        public init?(cpw: [UInt8], encPW: [[UInt8]]) {
            guard cpw.count == 68, cpw[0] == 7 else { return nil }
            let chunks = encPW.filter { $0.count > 4 && $0[0] == 6 }
                .sorted { (Int($0[2]) << 8 | Int($0[3])) < (Int($1[2]) << 8 | Int($1[3])) }
            let blob = chunks.flatMap { $0.dropFirst(4) }
            guard blob.count == 516 else { return nil }
            encryptedPassword = Array(blob)
            encryptedHash = Array(cpw[2..<18])
            peerChallenge = Array(cpw[18..<34])
            ntResponse = Array(cpw[42..<66])
            flags = UInt16(cpw[66]) << 8 | UInt16(cpw[67])
        }

        public var bytes: [UInt8] {
            encryptedPassword + encryptedHash + peerChallenge + [UInt8](repeating: 0, count: 8) + ntResponse
                + [UInt8(flags >> 8), UInt8(flags & 0xff)]
        }

        /// The peer side (tests, the test supplicant): the new password encrypted with the old
        /// hash, the old hash encrypted with the new one, and the NT-Response over `challenge`
        /// computed with the new password.
        public static func make(oldPassword: String, newPassword: String, username: String, challenge: [UInt8],
                                peerChallenge: [UInt8]) -> ChangePassword {
            let oldHash = MSCHAPv2.ntHash(oldPassword), newHash = MSCHAPv2.ntHash(newPassword)
            let unicode = newPassword.utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] }
            var block = (0..<(512 - unicode.count)).map { _ in UInt8.random(in: 0...255) } + unicode
            let n = UInt32(unicode.count)
            block += [UInt8(n & 0xff), UInt8(n >> 8 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 24 & 0xff)]
            return ChangePassword(encryptedPassword: RC4.apply(key: oldHash, block),
                                  encryptedHash: MSCHAPv2.hashEncryptedWithHash(oldHash, key: newHash),
                                  peerChallenge: peerChallenge,
                                  ntResponse: MSCHAPv2.ntResponse(challenge: challenge, peerChallenge: peerChallenge,
                                                                  username: username, ntHash: newHash))
        }
    }

    /// `NewPasswordEncryptedWithOldNtPasswordHash` undone: RC4 with the old NT hash; the
    /// password is the last `length` bytes of the 512-byte buffer (UTF-16LE). nil when the length
    /// is impossible (the wrong old hash gives garbage).
    public static func decryptNewPassword(_ blob: [UInt8], oldHash: [UInt8]) -> String? {
        guard blob.count == 516 else { return nil }
        let plain = RC4.apply(key: oldHash, blob)
        let n = Int(plain[512]) | Int(plain[513]) << 8 | Int(plain[514]) << 16 | Int(plain[515]) << 24
        guard n > 0, n <= 512, n % 2 == 0 else { return nil }
        let units: [UInt16] = stride(from: 512 - n, to: 512, by: 2).map { UInt16(plain[$0]) | UInt16(plain[$0 + 1]) << 8 }
        return String(decoding: units, as: UTF16.self)
    }

    /// `NtPasswordHashEncryptedWithBlock` (RFC 2759 §8.13): each 8-byte half of `hash` DES-
    /// encrypted with a 7-byte slice of `key` (parity-expanded).
    public static func hashEncryptedWithHash(_ hash: [UInt8], key: [UInt8]) -> [UInt8] {
        DES.encrypt(block: Array(hash[0..<8]), key: parity(Array(key[0..<7])))
            + DES.encrypt(block: Array(hash[8..<16]), key: parity(Array(key[7..<14])))
    }

    /// Checks a Change-Password against the stored (old) NT hash: the old hash encrypted with the
    /// new one must match, and the NT-Response must be the new password's answer to `challenge`.
    /// Returns the new password, or nil (wrong old password, tampered packet).
    public static func verifyChange(_ change: ChangePassword, username: String, challenge: [UInt8], oldHash: [UInt8]) -> String? {
        guard let password = decryptNewPassword(change.encryptedPassword, oldHash: oldHash) else { return nil }
        let newHash = ntHash(password)
        guard ConstantTime.equal(hashEncryptedWithHash(oldHash, key: newHash), change.encryptedHash) else { return nil }
        let expected = ntResponse(challenge: challenge, peerChallenge: change.peerChallenge, username: username, ntHash: newHash)
        guard ConstantTime.equal(expected, change.ntResponse) else { return nil }
        return password
    }

    /// The PEAP ISK of an MS-CHAPv2 exchange ([MS-PEAP] §3.1.5.5; hostapd): the server's MPPE
    /// receive key, then its send key.
    public static func innerSessionKey(_ success: Success) -> [UInt8] { success.recvKey + success.sendKey }
}

extension RADIUSPacket {
    /// RFC 2865 §5.33: every Proxy-State of the request, in order, goes back unchanged in the reply.
    public mutating func echoProxyState(from request: RADIUSPacket) {
        attributes += request.all(.proxyState)
    }
}
