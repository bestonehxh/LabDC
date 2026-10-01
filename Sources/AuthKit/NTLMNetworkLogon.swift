import Foundation
import SheepCrypto

/// Additive WP-V helper: validate an NTLMv2 network logon from the raw fields NETLOGON's
/// `NetrLogonSamLogon*` carries (server challenge + `NtChallengeResponse` blob + the target's NT
/// hash), independent of the NTLM message framing that `NTLMServer` parses. MS-NLMP §3.3.2 / §3.4.5.
public enum NTLMNetworkLogon {
    /// The outcome of a network logon validation.
    public struct Result: Sendable, Equatable {
        /// The NTLMv2 session base key (`HMAC_MD5(NTOWFv2, NTProofStr)`), which NETLOGON returns
        /// as the `UserSessionKey` (sealed with the schannel session key).
        public var sessionBaseKey: [UInt8]
        /// The domain (of the candidates) whose NTOWFv2 matched.
        public var matchedDomain: String
    }

    /// Reasons a validation is rejected, mapped by the caller to NTSTATUS.
    public enum Failure: Error, Sendable, Equatable {
        /// The response is an LM/NTLMv1 (<= 24-byte) response, which we refuse (MS-NLMP: NTLMv2 only).
        case downlevelResponse
        /// The NTLMv2 client-challenge blob is malformed.
        case malformedBlob
        /// The NTProofStr did not match for any candidate domain (wrong password).
        case wrongPassword
    }

    /// Validates an NTLMv2 network logon. `ntChallengeResponse` is `NTProofStr(16) || temp`.
    /// `domains` are the domain forms to try in `NTOWFv2` (the logon domain as sent first, then the
    /// empty string and the server's NetBIOS/DNS names), matching `NTLMServer.authenticate`.
    public static func validate(username: String,
                                domains: [String],
                                ntHash: [UInt8],
                                serverChallenge: [UInt8],
                                ntChallengeResponse: [UInt8]) throws -> Result {
        guard ntChallengeResponse.count > 24 else { throw Failure.downlevelResponse }
        let proof = Array(ntChallengeResponse[0..<16])
        let temp = Array(ntChallengeResponse[16...])
        guard temp.count >= 28, temp[0] == 1, temp[1] == 1 else { throw Failure.malformedBlob }
        var tried = Set<String>()
        for d in domains where tried.insert(d).inserted {
            let key = NTLMCrypto.ntowfv2(ntHash: ntHash, user: username, domain: d)
            let computed = NTLMCrypto.ntProofStr(responseKeyNT: key, serverChallenge: serverChallenge, temp: temp)
            if ConstantTime.equal(computed, proof) {
                return Result(sessionBaseKey: NTLMCrypto.sessionBaseKey(responseKeyNT: key, ntProofStr: proof),
                              matchedDomain: d)
            }
        }
        throw Failure.wrongPassword
    }

    // MARK: NTLMv1 / MS-CHAPv2 (WP-Z)

    /// The NTLMv1 24-byte response: DESL(NT hash, challenge) — the NT hash padded to 21 bytes and
    /// split into three 7-byte DES keys (MS-NLMP §3.3.1, §6 `DESL`). MS-CHAPv2 (RFC 2759
    /// `ChallengeResponse`) is the same function over its SHA-1-derived 8-byte challenge.
    public static func ntlmv1Response(ntHash: [UInt8], challenge: [UInt8]) -> [UInt8] {
        precondition(ntHash.count == 16 && challenge.count == 8)
        let k = ntHash + [UInt8](repeating: 0, count: 5)
        return [0, 7, 14].flatMap { DES.encryptBlock(key: desKey(Array(k[$0..<($0 + 7)])), challenge) }
    }

    /// Validates an NTLMv1-style (24-byte) NT response — the MS-CHAPv2 pass-through a RADIUS server
    /// sends through winbind (`ntlm_auth --request-nt-key`), or a plain NTLMv1 logon. Returns the
    /// NTLMv1 user session key, `MD4(NT hash)` (MS-NLMP §3.3.1 `SessionBaseKey`; Samba
    /// `SMBsesskeygen_ntv1`), which is what `ntlm_auth` prints as `NT_KEY` and RFC 3079 calls
    /// PasswordHashHash for the MPPE keys. Throws `wrongPassword` on a mismatch, `downlevelResponse`
    /// if the response is not 24 bytes.
    public static func validateV1(ntHash: [UInt8], serverChallenge: [UInt8], ntResponse: [UInt8]) throws -> [UInt8] {
        guard ntResponse.count == 24, ntHash.count == 16, serverChallenge.count == 8 else { throw Failure.downlevelResponse }
        guard ConstantTime.equal(ntlmv1Response(ntHash: ntHash, challenge: serverChallenge), ntResponse) else {
            throw Failure.wrongPassword
        }
        return MD4.hash(ntHash)
    }

    /// 7 key bytes → 8 DES key bytes (parity bits left zero; DES ignores them).
    static func desKey(_ k: [UInt8]) -> [UInt8] {
        [k[0] >> 1,
         ((k[0] & 0x01) << 6) | (k[1] >> 2),
         ((k[1] & 0x03) << 5) | (k[2] >> 3),
         ((k[2] & 0x07) << 4) | (k[3] >> 4),
         ((k[3] & 0x0F) << 3) | (k[4] >> 5),
         ((k[4] & 0x1F) << 2) | (k[5] >> 6),
         ((k[5] & 0x3F) << 1) | (k[6] >> 7),
         k[6] & 0x7F].map { $0 << 1 }
    }
}
