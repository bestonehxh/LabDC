import Foundation
import MSPAC

/// UI-5 (Activity ▸ Test login): a network logon validated in-process by the same function the
/// `NetrLogonSamLogon*` handlers call (`validateLogon`), logged with the same `SamLogon` line.
/// No secure channel is involved: the app is the DC, so the challenge/response goes straight to
/// the validation path, exactly as it would after a NAC's schannel-sealed `SamLogonEx`.
public struct NetlogonTestLogon: Sendable, Equatable {
    /// `NETLOGON_LOGON_IDENTITY_INFO.LogonDomainName` (`LABSHEEP`, or empty).
    public var logonDomain: String
    /// `UserName` as the NAC forwards it (`alice`, `alice@lab.sheep`, `PC1$`).
    public var userName: String
    /// `Workstation` (the NAC's name, without `\\`).
    public var workstation: String
    /// The 8-byte `LmChallenge` (NTLMv2: the server challenge; MS-CHAPv2: the RFC 2759 ChallengeHash).
    public var serverChallenge: [UInt8]
    /// The NT response: an NTLMv2 blob (> 24 bytes) or a 24-byte NTLMv1 / MS-CHAPv2 response.
    public var ntResponse: [UInt8]
    public var lmResponse: [UInt8]
    /// `ParameterControl` (`MSV1_0_*`): `0x820` as `ntlm_auth` sends, `0x10820` for MS-CHAPv2.
    public var parameterControl: UInt32

    public init(logonDomain: String, userName: String, workstation: String, serverChallenge: [UInt8],
                ntResponse: [UInt8], lmResponse: [UInt8] = [], parameterControl: UInt32) {
        self.logonDomain = logonDomain
        self.userName = userName
        self.workstation = workstation
        self.serverChallenge = serverChallenge
        self.ntResponse = ntResponse
        self.lmResponse = lmResponse
        self.parameterControl = parameterControl
    }

    /// `MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT`.
    public static let allowTrustAccounts: UInt32 = 0x0000_0820
    /// `MSV1_0_ALLOW_MSVCHAPV2`.
    public static let allowMSCHAPv2: UInt32 = 0x0001_0000
}

/// What the validation answered (the fields of `NETLOGON_VALIDATION_SAM_INFO4` a person reads).
public struct NetlogonTestLogonResult: Sendable, Equatable {
    /// NTSTATUS (0 = success).
    public var status: UInt32
    /// `STATUS_SUCCESS`, `STATUS_WRONG_PASSWORD`, …
    public var statusName: String
    /// The log reason (`bad password`, `account disabled`, …), nil on success.
    public var reason: String?
    /// The sAMAccountName the name resolved to.
    public var account: String?
    /// `ntlmv2` / `ntlmv1`.
    public var kind: String?
    public var effectiveName: String?
    public var fullName: String?
    public var userId: UInt32?
    public var primaryGroupId: UInt32?
    /// Global/universal group RIDs, primary group first.
    public var groupRIDs: [UInt32]
    public var logonDomainName: String?
    public var logonDomainId: SID?
    public var upn: String?
    /// MS-SAMR ACB flags.
    public var userAccountControl: UInt32?

    public var succeeded: Bool { status == 0 }
}

extension NetlogonService {
    /// Validates `logon` like a `SamLogonEx` (validation level 6) from `transport` at `address`,
    /// and emits the usual `SamLogon Network …` line (`from <workstation>@<address>/<transport>`).
    /// The default transport `test` marks the line as a Test login in the Activity feed.
    public func testNetworkLogon(_ logon: NetlogonTestLogon, address: String = "127.0.0.1",
                                 transport: String = "test") async throws -> NetlogonTestLogonResult {
        let network = NetworkLogon(logonDomain: logon.logonDomain, userName: logon.userName, workstation: logon.workstation,
                                   serverChallenge: logon.serverChallenge, ntResponse: logon.ntResponse,
                                   lmResponse: logon.lmResponse, parameterControl: logon.parameterControl)
        let computer = logon.workstation
        return try await NetlogonCallInfo.$current.withValue(NetlogonCallInfo(address: address, transport: transport)) {
            let outcome = try await validateLogon(network, computer: computer, validationLevel: 6)
            logSamLogon(level: 2, validationLevel: 6, network: network, computer: computer, outcome: outcome)
            let v = outcome.info
            return NetlogonTestLogonResult(
                status: outcome.status, statusName: NLStatus.name(outcome.status), reason: outcome.reason,
                account: outcome.account, kind: outcome.kind, effectiveName: v?.effectiveName, fullName: v?.fullName,
                userId: v?.userId, primaryGroupId: v?.primaryGroupId, groupRIDs: v?.groupRIDs ?? [],
                logonDomainName: v?.logonDomainName, logonDomainId: v?.logonDomainId, upn: v?.upn,
                userAccountControl: v?.userAccountControl)
        }
    }
}
