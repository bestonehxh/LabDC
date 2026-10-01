import Foundation
import RPCKit
import os

/// Who is calling, for the operational log (WP-AK). Bound per `dispatch` as a task-local so the
/// opnum handlers keep their signatures.
struct NetlogonCallInfo: Sendable {
    /// Peer address without port (`172.18.1.210`).
    var address: String
    /// `np` (SMB named pipe `\netlogon`), `tcp` (ncacn_ip_tcp) or `rpc` (in-memory / unknown).
    var transport: String
    /// The connection's RPC authentication level (schannel sign/seal = pktIntegrity/pktPrivacy).
    var authLevel: RPCAuthLevel = .none

    @TaskLocal static var current: NetlogonCallInfo?

    init(address: String, transport: String) {
        self.address = address
        self.transport = transport
    }

    /// The SMB server describes its peer as `ip:port` / `[ipv6]:port`; the TCP endpoint passes the
    /// bare IP; the in-memory test transport passes `memory:peer`.
    init(_ context: RPCCallContext) {
        self = Self.parse(context.clientAddress)
        authLevel = context.authLevel
    }

    /// True for real clients (SMB named pipe or ncacn_ip_tcp), false for the in-memory test transport.
    var isNetworkTransport: Bool { transport == "np" || transport == "tcp" }

    /// Secure RPC: the call arrived on a signed or sealed (schannel) binding.
    var isSecureRPC: Bool { authLevel.rawValue >= RPCAuthLevel.pktIntegrity.rawValue }

    static func parse(_ a: String) -> NetlogonCallInfo {
        if a.hasPrefix("["), let close = a.firstIndex(of: "]") {
            return .init(address: String(a[a.index(after: a.startIndex)..<close]), transport: "np")
        }
        let parts = a.split(separator: ":", omittingEmptySubsequences: false)
        if parts.count == 2 {
            if !parts[1].isEmpty, parts[1].allSatisfy(\.isNumber) { return .init(address: String(parts[0]), transport: "np") }
            return .init(address: a, transport: "rpc")
        }
        return .init(address: a, transport: "tcp")    // IPv4 or IPv6 without port
    }

    var description: String { "\(address)/\(transport)" }
}

extension NetlogonService {
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "NETLOGON")

    /// Emits one operational line (`labdc serve` prints it as `NETLOGON <line>`).
    func logEvent(_ line: String) {
        Self.logger.info("\(line, privacy: .public)")
        config.onEvent?(line)
    }

    /// ` from CLEARPASS-ENTRY$@172.18.1.210/np` — the secure-channel account when one is known.
    func fromClause(account: String?) -> String {
        let call = NetlogonCallInfo.current
        var s = ""
        if let account, !account.isEmpty { s = account + (call == nil ? "" : "@") }
        if let call { s += call.description }
        return " from " + (s.isEmpty ? "-" : s)
    }

    /// `" -> OK"` or `" -> STATUS_NO_SUCH_USER (reason)"`.
    static func outcome(_ status: UInt32, _ reason: String? = nil) -> String {
        var s = " -> " + (status == 0 ? "OK" : NLStatus.name(status))
        if let reason, !reason.isEmpty { s += " (\(reason))" }
        return s
    }

    /// `NETLOGON_LOGON_INFO_CLASS` names (MS-NRPC §2.2.1.4.16).
    static func logonLevelName(_ level: UInt16) -> String {
        switch level {
        case 1: "Interactive"
        case 2: "Network"
        case 3: "Service"
        case 4: "Generic"
        case 5: "InteractiveTransitive"
        case 6: "NetworkTransitive"
        case 7: "ServiceTransitive"
        default: "Level\(level)"
        }
    }

    static func channelTypeName(_ raw: UInt16) -> String {
        switch raw {
        case 2: "workstation"
        case 4: "domain"
        case 6: "server"
        case 7: "rodc"
        default: "type\(raw)"
        }
    }
}

extension NLStatus {
    /// NTSTATUS / Win32 names for the codes NETLOGON returns; hex for anything else.
    static func name(_ s: UInt32) -> String {
        switch s {
        case success: "STATUS_SUCCESS"
        case accessDenied: "STATUS_ACCESS_DENIED"
        case noSuchUser: "STATUS_NO_SUCH_USER"
        case wrongPassword: "STATUS_WRONG_PASSWORD"
        case noTrustSamAccount: "STATUS_NO_TRUST_SAM_ACCOUNT"
        case accountDisabled: "STATUS_ACCOUNT_DISABLED"
        case accountExpired: "STATUS_ACCOUNT_EXPIRED"
        case passwordMustChange: "STATUS_PASSWORD_MUST_CHANGE"
        case downgradeDetected: "STATUS_DOWNGRADE_DETECTED"
        case notSupported: "STATUS_NOT_SUPPORTED"
        case invalidParameter: "STATUS_INVALID_PARAMETER"
        case invalidLevel: "STATUS_INVALID_LEVEL"
        case nologonWorkstationTrustAccount: "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"
        case nologonServerTrustAccount: "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT"
        default: String(format: "0x%08X", s)
        }
    }
}
