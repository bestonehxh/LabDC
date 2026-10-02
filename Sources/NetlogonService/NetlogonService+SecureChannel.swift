import Foundation
import RPCKit
import Store
import SheepCrypto

extension NetlogonService {

    /// `NetrServerReqChallenge` (opnum 4): store the client challenge, return a fresh server challenge.
    func reqChallenge(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                 // PrimaryName (ignored)
        let computer = try NLNDR.readInlineWSTR(r)          // ComputerName
        let clientChallenge = try r.take(8)

        // CVE-2020-1472 (Zerologon): a client challenge whose first 5 bytes are all the same is
        // refused, as Windows and Samba do (MS-NRPC §3.1.4.1). Attackers send all zeros.
        guard !NetlogonCrypto.isWeakChallenge(clientChallenge) else {
            logEvent("ReqChallenge \(computer)" + fromClause(account: nil)
                     + Self.outcome(NLStatus.accessDenied, "client challenge is not random (CVE-2020-1472)"))
            let w = NDRWriter()
            w.raw([UInt8](repeating: 0, count: 8))
            w.u32(NLStatus.accessDenied)
            return w
        }

        let serverChallenge = rng.next(8)
        state.setPending(computer: computer,
                         NetlogonPendingChallenge(clientChallenge: clientChallenge, serverChallenge: serverChallenge))
        logEvent("ReqChallenge \(computer)" + fromClause(account: nil) + Self.outcome(NLStatus.success))

        let w = NDRWriter()
        w.raw(serverChallenge)
        w.u32(NLStatus.success)
        return w
    }

    /// `NetrServerAuthenticate3` (opnum 26): derive the session key, verify the client credential,
    /// establish the secure channel, and return the server credential + negotiated flags + RID.
    func authenticate3(_ r: NDRReader, legacy: UInt16? = nil) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                 // PrimaryName
        let accountName = try NLNDR.readInlineWSTR(r)       // AccountName ("PC1$")
        let channelTypeRaw = try r.enum16()
        let computer = try NLNDR.readInlineWSTR(r)          // ComputerName ("PC1")
        let clientCredential = try r.take(8)
        // Authenticate2/Authenticate carry no NegotiateFlags; default to our advertised set.
        let clientFlags = legacy == 5 ? NetlogonNegotiateFlags.advertised.rawValue : try r.u32()

        let logHead = "Authenticate3 \(accountName) (\(computer)) type=\(Self.channelTypeName(channelTypeRaw))"
            + String(format: " flags=0x%08x", clientFlags)
        func fail(_ status: UInt32, _ reason: String? = nil) -> NDRWriter {
            logEvent(logHead + fromClause(account: nil) + Self.outcome(status, reason))
            let w = NDRWriter()
            w.raw([UInt8](repeating: 0, count: 8))          // ServerCredential
            w.u32(0)                                        // NegotiateFlags
            w.u32(0)                                        // AccountRid
            w.u32(status)
            return w
        }

        // Throttle (security audit, 1 Oct 2026): every failed credential check counts against the
        // computer account and the source address; past `lockoutThreshold` failures within
        // `lockoutWindow` both are refused for `lockoutDuration` — an online guess of the machine
        // password (or a Zerologon-style credential search) cannot run unbounded.
        let now = clock()
        let throttleKeys = ["acct:" + accountName, "ip:" + (NetlogonCallInfo.current?.address ?? "-")]
        if let until = throttleKeys.lazy.compactMap({ self.authenticateFailures.lockedUntil($0, now: now) }).first {
            return fail(NLStatus.accessDenied, "too many failed Authenticate3 attempts; refused until "
                        + until.formatted(.dateTime.hour().minute()))
        }
        func failCounted(_ status: UInt32, _ reason: String) -> NDRWriter {
            var locked = false
            for key in throttleKeys {
                locked = authenticateFailures.recordFailure(key, now: now, threshold: config.lockoutThreshold,
                                                            window: config.lockoutWindow,
                                                            duration: config.lockoutDuration) || locked
            }
            return fail(status, locked ? reason + "; further attempts throttled" : reason)
        }
        // RequireSignOrSeal: a client that does not negotiate NETLOGON_NEG_AUTHENTICATED_RPC would
        // run the secure channel's calls unsigned, which this DC refuses (CVE-2022-38023).
        guard clientFlags & NetlogonNegotiateFlags.authenticatedRPC.rawValue != 0 else {
            return fail(NLStatus.accessDenied, "client did not negotiate NETLOGON_NEG_AUTHENTICATED_RPC (schannel)")
        }

        guard let account = try await machineNTHash(sam: accountName) else {
            return failCounted(NLStatus.noTrustSamAccount, "no such machine account")
        }
        guard let pending = state.takePending(computer: computer) else {
            return fail(NLStatus.accessDenied, "no ReqChallenge pending for this computer")
        }
        // CVE-2020-1472: a credential with 5 identical leading bytes is how Zerologon guesses its way in.
        guard !NetlogonCrypto.isWeakChallenge(pending.clientChallenge),
              !NetlogonCrypto.isWeakChallenge(clientCredential) else {
            return failCounted(NLStatus.accessDenied, "client credential is not random (CVE-2020-1472)")
        }
        if let reason = Self.trustAccountMismatch(account.userAccountControl, channelType: channelTypeRaw) {
            return fail(NLStatus.noTrustSamAccount, reason)
        }

        let negotiated = (NetlogonNegotiateFlags.advertised.rawValue & clientFlags)
        let usesAES = (negotiated & NetlogonNegotiateFlags.supportsAES.rawValue) != 0
        let sessionKey: [UInt8]
        if usesAES {
            sessionKey = NetlogonCrypto.sessionKeyAES(ntHash: account.ntHash,
                                                      clientChallenge: pending.clientChallenge,
                                                      serverChallenge: pending.serverChallenge)
        } else if config.allowRC4 {
            sessionKey = NetlogonCrypto.sessionKeyStrong(ntHash: account.ntHash,
                                                         clientChallenge: pending.clientChallenge,
                                                         serverChallenge: pending.serverChallenge)
        } else {
            return fail(NLStatus.downgradeDetected, "client did not offer AES")
        }

        func credential(_ input: [UInt8]) -> [UInt8] {
            usesAES ? NetlogonCrypto.credentialAES(sessionKey: sessionKey, input)
                    : NetlogonCrypto.credentialDES(sessionKey: sessionKey, input)
        }
        let expectedClient = credential(pending.clientChallenge)
        guard ConstantTime.equal(expectedClient, clientCredential) else {
            return failCounted(NLStatus.accessDenied, "client credential mismatch: machine password differs from the DC's")
        }
        for key in throttleKeys { authenticateFailures.recordSuccess(key) }
        let serverCredential = credential(pending.serverChallenge)

        var channel = NetlogonChannel(
            computerName: computer,
            accountName: accountName,
            secureChannelType: NetlogonSecureChannelType(rawValue: UInt32(channelTypeRaw)) ?? .workstation,
            sessionKey: sessionKey,
            negotiatedFlags: NetlogonNegotiateFlags(rawValue: negotiated),
            usesAES: usesAES,
            clientStoredCredential: expectedClient,
            accountRid: account.rid)
        channel.requestedFlags = clientFlags
        state.establish(channel)
        logEvent(logHead + fromClause(account: nil) + Self.outcome(NLStatus.success)
                 + " \(usesAES ? "aes" : "rc4") rid=\(account.rid)")

        let w = NDRWriter()
        w.raw(serverCredential)
        w.u32(negotiated)
        w.u32(account.rid)
        w.u32(NLStatus.success)
        return w
    }
}
