import Foundation

/// MS-NRPC §3.1.4.2 negotiable flags (subset we care about).
public struct NetlogonNegotiateFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let accountLockout       = NetlogonNegotiateFlags(rawValue: 0x0000_0002)
    public static let strongKeys           = NetlogonNegotiateFlags(rawValue: 0x0000_4000) // NETLOGON_NEG_STRONG_KEYS
    public static let secureRPC            = NetlogonNegotiateFlags(rawValue: 0x0000_0001)
    public static let supportsAES          = NetlogonNegotiateFlags(rawValue: 0x0100_0000) // NETLOGON_NEG_SUPPORTS_AES
    public static let authenticatedRPC     = NetlogonNegotiateFlags(rawValue: 0x4000_0000) // NETLOGON_NEG_AUTHENTICATED_RPC
    public static let authRPCLSASS         = NetlogonNegotiateFlags(rawValue: 0x2000_0000)

    /// What this DC advertises. A superset that always includes AES and strong keys; the reply is
    /// `client ∧ ours` (§3.5.4.4.2). 0x612F_FFFF-style set as WP-V specifies.
    public static let advertised = NetlogonNegotiateFlags(rawValue: 0x612F_FFFF)
}

/// MS-NRPC §2.2.1.3.13 secure-channel types.
public enum NetlogonSecureChannelType: UInt32, Sendable, Hashable {
    case null = 0
    case msvApp = 1
    case workstation = 2
    case trustedDnsDomain = 3
    case trustedDomain = 4
    case uasServer = 5
    case server = 6
    case cdcServer = 7
}

/// One computer's secure-channel state, keyed by computer name + channel type.
public struct NetlogonChannel: Sendable {
    public var computerName: String
    public var accountName: String
    public var secureChannelType: NetlogonSecureChannelType
    public var sessionKey: [UInt8]
    public var negotiatedFlags: NetlogonNegotiateFlags
    /// The AES session-key path was negotiated (vs. the RC4 strong-key legacy path).
    public var usesAES: Bool
    /// `ClientStoredCredential` (§3.1.4.5): the fixed base credential from `NetrServerAuthenticate3`.
    /// Per-call authenticators re-base on this + timestamp; impacket does the same.
    public var clientStoredCredential: [UInt8]
    public var accountRid: UInt32
    /// The flags the client *requested* in `NetrServerAuthenticate3` (before the AND with ours).
    /// `NetrLogonGetCapabilities` level 2 returns them so the client can detect a downgrade
    /// (MS-NRPC §3.5.4.4.10; Samba `netlogon_creds_cli_check` compares them). WP-Z.
    public var requestedFlags: UInt32 = 0
    /// The credential computed in `NetrServerAuthenticate3`; `clientStoredCredential` advances from
    /// it per call. Kept so an impacket-style client that re-bases every authenticator on it still
    /// verifies (see `NetlogonService.stepAuthenticator`). Empty = same as the stored one.
    public var initialCredential: [UInt8] = []
}

/// A pending `NetrServerReqChallenge` before `NetrServerAuthenticate3` completes it.
struct NetlogonPendingChallenge: Sendable {
    var clientChallenge: [UInt8]
    var serverChallenge: [UInt8]
}

/// Shared, connection-independent secure-channel state. `NetrServerReqChallenge`/`Authenticate3`
/// run over an unauthenticated netlogon binding and establish state here; a later schannel bind
/// (RPC auth type 68, possibly a different pipe/connection) looks it up by computer name. A plain
/// locked class (not an actor) so the synchronous `RPCAuthProvider` can read it.
public final class NetlogonStateStore: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [String: NetlogonPendingChallenge] = [:]
    private var channels: [String: NetlogonChannel] = [:]

    public init() {}

    private static func key(_ computer: String, _ type: NetlogonSecureChannelType) -> String {
        computer.uppercased() + "\u{0}" + String(type.rawValue)
    }
    private static func nameKey(_ computer: String) -> String { computer.uppercased() }

    func setPending(computer: String, _ c: NetlogonPendingChallenge) {
        lock.lock(); defer { lock.unlock() }
        pending[Self.nameKey(computer)] = c
    }

    func takePending(computer: String) -> NetlogonPendingChallenge? {
        lock.lock(); defer { lock.unlock() }
        return pending.removeValue(forKey: Self.nameKey(computer))
    }

    func establish(_ channel: NetlogonChannel) {
        lock.lock(); defer { lock.unlock() }
        channels[Self.key(channel.computerName, channel.secureChannelType)] = channel
        // Also index by name alone so the schannel bind (which knows only the computer name) resolves.
        channels[Self.nameKey(channel.computerName)] = channel
        lastEstablished = channel
    }

    /// Advances `ClientStoredCredential` after a verified authenticator (MS-NRPC §3.1.4.5), for the
    /// entries that still hold this channel (same session key).
    func advance(_ channel: NetlogonChannel, storedCredential: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        for k in [Self.key(channel.computerName, channel.secureChannelType), Self.nameKey(channel.computerName)] {
            guard var c = channels[k], c.sessionKey == channel.sessionKey else { continue }
            if c.initialCredential.isEmpty { c.initialCredential = c.clientStoredCredential }
            c.clientStoredCredential = storedCredential
            channels[k] = c
        }
    }

    /// The channel for `computer` (and, when given, the exact `type`).
    public func channel(computer: String, type: NetlogonSecureChannelType? = nil) -> NetlogonChannel? {
        lock.lock(); defer { lock.unlock() }
        if let type { return channels[Self.key(computer, type)] }
        return channels[Self.nameKey(computer)]
    }

    /// The most recently established channel, or nil. Lab fallback for the schannel bind when the
    /// `NL_AUTH_MESSAGE` computer name does not resolve exactly.
    private var lastEstablished: NetlogonChannel?
    func recordLast(_ c: NetlogonChannel) { lock.lock(); lastEstablished = c; lock.unlock() }
    public func anyChannel() -> NetlogonChannel? { lock.lock(); defer { lock.unlock() }; return lastEstablished }
}
