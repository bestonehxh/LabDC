import Foundation
import RPCKit
import Store
import AuthKit
import MSPAC
import SheepCrypto

/// NTSTATUS / NET_API_STATUS values NETLOGON returns.
enum NLStatus {
    static let success: UInt32 = 0x0000_0000
    static let accessDenied: UInt32 = 0xC000_0022
    static let noSuchUser: UInt32 = 0xC000_0064
    static let wrongPassword: UInt32 = 0xC000_006A
    static let noTrustSamAccount: UInt32 = 0xC000_018B
    static let accountDisabled: UInt32 = 0xC000_0072
    static let accountExpired: UInt32 = 0xC000_0193
    static let passwordMustChange: UInt32 = 0xC000_0224
    static let accountLockedOut: UInt32 = 0xC000_0234
    static let downgradeDetected: UInt32 = 0xC000_0388
    static let notSupported: UInt32 = 0xC000_00BB
    static let invalidParameter: UInt32 = 0xC000_000D
    static let invalidLevel: UInt32 = 0xC000_0148
    static let nologonWorkstationTrustAccount: UInt32 = 0xC000_0199
    static let nologonServerTrustAccount: UInt32 = 0xC000_019A
    // NET_API_STATUS (Win32)
    static let errorSuccess: UInt32 = 0
    static let errorNoSuchDomain: UInt32 = 1355
    static let errorNoTrustSamAccount: UInt32 = 1787
}

/// Lab knobs for behaviour that is refused by default (hardening).
public struct NetlogonServiceConfig: Sendable {
    /// Permit the RC4 strong-key secure channel (no AES). Off by default.
    public var allowRC4: Bool
    /// Permit `NetrServerAuthenticate2`/`Authenticate` (older, no negotiate flags echo) instead of
    /// answering `STATUS_DOWNGRADE_DETECTED`. Off by default.
    public var allowDowngradeAuthenticate: Bool
    /// Which NTLM response kinds a network logon (`NetrLogonSamLogon*`) accepts. Default: Samba's
    /// `ntlm auth = mschapv2-and-ntlmv2-only` — what the SheepRadius 2.0 Samba DC ran for the
    /// iMaster/ClearPass PEAP-MSCHAPv2 pass-through.
    public var ntlmAuth: NTLMAuthPolicy
    /// Operational log sink (WP-AK): one line per secure-channel setup, password rotation and
    /// SamLogon (`SamLogon Network LABSHEEP\alice ws=PC1 ... -> OK`). Never carries key material.
    public var onEvent: (@Sendable (String) -> Void)?
    /// NAC password guessing limit (audit 27 Sep 2026): after `lockoutThreshold` wrong passwords
    /// for one account within `lockoutWindow` seconds, pass-through logons for it are refused with
    /// STATUS_ACCOUNT_LOCKED_OUT for `lockoutDuration` seconds (0 threshold = off).
    public var lockoutThreshold: Int
    public var lockoutWindow: TimeInterval
    public var lockoutDuration: TimeInterval
    public init(allowRC4: Bool = false, allowDowngradeAuthenticate: Bool = false,
                ntlmAuth: NTLMAuthPolicy = .mschapv2AndNTLMv2Only,
                lockoutThreshold: Int = 20, lockoutWindow: TimeInterval = 900, lockoutDuration: TimeInterval = 900,
                onEvent: (@Sendable (String) -> Void)? = nil) {
        self.allowRC4 = allowRC4
        self.allowDowngradeAuthenticate = allowDowngradeAuthenticate
        self.ntlmAuth = ntlmAuth
        self.lockoutThreshold = lockoutThreshold
        self.lockoutWindow = lockoutWindow
        self.lockoutDuration = lockoutDuration
        self.onEvent = onEvent
    }
}

/// Samba's `ntlm auth` parameter, applied to Netlogon network logons (WP-Z;
/// `libcli/auth/ntlm_check.c` `ntlm_password_check`).
public enum NTLMAuthPolicy: String, Sendable, CaseIterable {
    /// NTLMv2 only; every 24-byte NTLMv1 response is refused (`ntlmv2-only`).
    case ntlmv2Only = "ntlmv2-only"
    /// NTLMv2 always; a 24-byte NTLMv1-style NT response only when the request's
    /// `ParameterControl` carries `MSV1_0_ALLOW_MSVCHAPV2` (0x00010000) — what winbind/`ntlm_auth
    /// --allow-mschapv2` sets for an MS-CHAPv2 pass-through (`mschapv2-and-ntlmv2-only`).
    case mschapv2AndNTLMv2Only = "mschapv2-and-ntlmv2-only"
    /// NTLMv2 and NTLMv1 regardless of the flag (lab use; `ntlm auth = yes`).
    case on = "yes"
}

/// `NETLOGON_LOGON_IDENTITY_INFO.ParameterControl` bits (MS-NRPC §2.2.1.4.15; MS-APDS §3.1.5.2).
enum MSV1_0 {
    static let allowServerTrustAccount: UInt32 = 0x0000_0020
    static let allowWorkstationTrustAccount: UInt32 = 0x0000_0800
    static let allowMSVCHAPv2: UInt32 = 0x0001_0000
}

/// MS-NRPC NETLOGON interface (`12345678-1234-abcd-ef00-01234567cffb` v1.0) over RPCKit.
/// Implements the secure-channel establishment, `SamLogon` network logon, the `DsrGetDcName*` DC
/// locator, `GetDomainInfo`/`PasswordSet2` join maintenance, and the trivial control calls.
public final class NetlogonService: RPCInterface, @unchecked Sendable {
    public let interfaceUUID = DCEUUID("12345678-1234-abcd-ef00-01234567cffb")
    public let interfaceVersion: (UInt16, UInt16) = (1, 0)

    let store: DirectoryStore
    public let state: NetlogonStateStore
    let dcInfo: NetlogonDCInfoProvider
    let config: NetlogonServiceConfig
    let clock: @Sendable () -> Date
    let rng: RandomBytes
    /// Wrong-password counts per account for the NAC lockout (in memory; a restart clears them).
    let badPasswords = BadPasswordTracker()

    public init(store: DirectoryStore, state: NetlogonStateStore, dcInfo: NetlogonDCInfoProvider,
                config: NetlogonServiceConfig = .init(), rng: RandomBytes = RandomBytes(),
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.state = state
        self.dcInfo = dcInfo
        self.config = config
        self.rng = rng
        self.clock = clock
    }

    public func dispatch(opnum: UInt16, input: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        // The caller's address/transport, for the operational log lines (WP-AK).
        try await NetlogonCallInfo.$current.withValue(NetlogonCallInfo(context)) {
            try await dispatchOp(opnum: opnum, input: input)
        }
    }

    private func dispatchOp(opnum: UInt16, input: NDRReader) async throws -> NDRWriter {
        switch opnum {
        case 4:  return try await reqChallenge(input)
        case 26: return try await authenticate3(input)
        case 15, 5:
            guard config.allowDowngradeAuthenticate else {
                // NetrServerAuthenticate2 (15) / NetrServerAuthenticate (5): refuse the downgrade.
                let w = NDRWriter(); w.raw([UInt8](repeating: 0, count: 8))
                if opnum == 15 { w.u32(0) }  // NegotiateFlags (Authenticate2 only)
                w.u32(NLStatus.downgradeDetected)
                return w
            }
            return try await authenticate3(input, legacy: opnum)
        case 21: return try await getCapabilities(input)
        case 29: return try await getDomainInfo(input)
        case 30: return try await passwordSet2(input)
        case 39: return try await samLogonEx(input)
        case 45: return try await samLogonWithFlags(input, withFlags: true)
        case 2:  return try await samLogonWithFlags(input, withFlags: false)
        case 20: return try await dsrGetDcName(input, variant: .base)
        case 27: return try await dsrGetDcName(input, variant: .ex)
        case 34: return try await dsrGetDcName(input, variant: .ex2)
        case 28: return try await dsrGetSiteName(input)
        case 40: return try await dsrEnumerateDomainTrusts(input)
        case 23: return try await netrLogonGetTrustRid(input)
        case 46: return try await netrServerGetTrustInfo(input)
        case 42: return try await netrServerTrustPasswordsGet(input)
        case 31: return try await netrServerPasswordGet(input)
        case 18, 14: return try await netrLogonControl2(input)
        case 12: return try await netrLogonControl2(input, withData: false)
        default:
            throw RPCError.fault(.opRangeError)
        }
    }

    // MARK: helpers

    func readAuthenticator(_ r: NDRReader) throws -> (credential: [UInt8], timestamp: UInt32) {
        r.align(4)
        let cred = try r.take(8)
        let ts = try r.u32()
        return (cred, ts)
    }

    /// Validates a per-call authenticator against a channel and computes the return authenticator.
    /// Returns nil credential when the client credential does not match (`STATUS_ACCESS_DENIED`).
    func stepAuthenticator(_ channel: NetlogonChannel, received: (credential: [UInt8], timestamp: UInt32))
        -> (ok: Bool, returnCredential: [UInt8]) {
        func credential(_ input: [UInt8]) -> [UInt8] {
            channel.usesAES ? NetlogonCrypto.credentialAES(sessionKey: channel.sessionKey, input)
                            : NetlogonCrypto.credentialDES(sessionKey: channel.sessionKey, input)
        }
        // WP-Z: MS-NRPC §3.1.4.5 chains the credential: after each verified call
        // ClientStoredCredential = stored + timestamp + 1 (Samba's `netlogon_creds_step` does this,
        // so its second authenticated call — GetCapabilities level 2 — failed against a fixed base).
        // impacket instead re-bases every call on the Authenticate3 credential; accept that too.
        let bases = channel.initialCredential.isEmpty || channel.initialCredential == channel.clientStoredCredential
            ? [channel.clientStoredCredential] : [channel.clientStoredCredential, channel.initialCredential]
        for base in bases {
            let stepped = NetlogonCrypto.addTimestamp(base, received.timestamp)
            guard ConstantTime.equal(credential(stepped), received.credential) else { continue }
            let next = NetlogonCrypto.addTimestamp(stepped, 1)
            state.advance(channel, storedCredential: next)
            return (true, credential(next))
        }
        return (false, [UInt8](repeating: 0, count: 8))
    }

    func writeAuthenticator(_ w: NDRWriter, credential: [UInt8], timestamp: UInt32) {
        w.raw(credential)
        w.u32(timestamp)
    }

    func machineNTHash(sam: String) async throws -> (id: ObjectID, rid: UInt32, ntHash: [UInt8], userAccountControl: UInt32)? {
        guard let entry = try? await store.read(sam: sam), let sid = entry.sid,
              let secrets = try? await store.secrets(id: entry.id), let nt = secrets.ntHash else { return nil }
        return (entry.id, sid.rid ?? 0, nt, UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0))
    }

    /// Samba `dcesrv_netr_ServerAuthenticate3_helper`: the account's `userAccountControl` (UF
    /// bits) must fit the requested secure-channel type — a disabled account, or a workstation
    /// channel without UF_WORKSTATION_TRUST_ACCOUNT (BDC: SERVER_TRUST, trusted domain:
    /// INTERDOMAIN_TRUST, RODC: PARTIAL_SECRETS), is `STATUS_NO_TRUST_SAM_ACCOUNT`. Returns the
    /// log reason, or nil when the account fits. Other channel types are not checked (unchanged).
    static func trustAccountMismatch(_ uac: UInt32, channelType: UInt16) -> String? {
        let hex = "userAccountControl 0x" + String(uac, radix: 16)
        if uac & UserAccountControl.accountDisable != 0 { return "account disabled (\(hex))" }
        let required: (UInt32, String)?
        switch UInt32(channelType) {
        case NetlogonSecureChannelType.workstation.rawValue:
            required = (UserAccountControl.workstationTrustAccount, "workstation trust")
        case NetlogonSecureChannelType.trustedDomain.rawValue, NetlogonSecureChannelType.trustedDnsDomain.rawValue:
            required = (UserAccountControl.interdomainTrustAccount, "interdomain trust")
        case NetlogonSecureChannelType.server.rawValue:
            required = (UserAccountControl.serverTrustAccount, "server trust")
        case NetlogonSecureChannelType.cdcServer.rawValue:     // SEC_CHAN_RODC
            required = (UserAccountControl.partialSecretsAccount, "partial secrets (RODC)")
        default:
            required = nil
        }
        if let (bit, name) = required, uac & bit == 0 { return "not a \(name) account (\(hex))" }
        return nil
    }
}
