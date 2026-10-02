import AuthKit
import Foundation
import MSPAC

/// Settings ▸ DNS "Dynamic updates" (`--dns-updates`), Windows' zone setting of the same name.
public enum DNSDynamicUpdateMode: String, Sendable, CaseIterable, Codable {
    /// GSS-TSIG updates from domain accounts, plus unsigned updates under the own-address rules
    /// (non-domain devices). The default.
    case secureAndNonsecure = "nonsecure"
    /// Only GSS-TSIG updates; an unsigned one is REFUSED (Windows then retries signed).
    case secureOnly = "secure"
    /// No dynamic updates at all.
    case off

    /// `--dns-updates secure|nonsecure|off` (also `secure-only`, `nonsecure-and-secure`).
    public init?(argument: String) {
        switch argument.lowercased() {
        case "nonsecure", "nonsecure-and-secure", "secure-and-nonsecure", "both": self = .secureAndNonsecure
        case "secure", "secure-only": self = .secureOnly
        case "off", "none": self = .off
        default: return nil
        }
    }

    public var settingsLabel: String {
        switch self {
        case .secureAndNonsecure: "Secure and nonsecure"
        case .secureOnly: "Secure only"
        case .off: "Off"
        }
    }
}

/// What the DNS server needs to know about a directory account to authorize a secure update.
public protocol DNSUpdateDirectory: Sendable {
    /// The account's `dNSHostName` (`laptop-7.lab.sheep`); nil when it has none.
    func dnsHostName(accountSID: SID) async -> String?
    /// Whether the account is (directly or nested) a member of Domain Admins, Enterprise Admins or
    /// DnsAdmins.
    func isDNSAdministrator(accountSID: SID) async -> Bool
}

/// GSS-TSIG (RFC 3645) configuration of a `DNSResponder`.
public struct DNSSecureUpdateConfig: Sendable {
    /// A Kerberos acceptor for `DNS/<dc>` tickets (share one replay cache between calls).
    public var kerberos: @Sendable () -> KerberosAcceptor
    /// Account lookups for authorization; nil: names from sAMAccountName only, admins from the PAC.
    public var directory: (any DNSUpdateDirectory)?
    /// Wall clock for TSIG time checks and context expiry (tests inject one).
    public var clock: @Sendable () -> Date
    /// How long an established context may sign (RFC 2930 expiration).
    public var contextLifetime: TimeInterval
    /// How long a half-finished negotiation is kept.
    public var pendingLifetime: TimeInterval
    /// Most established contexts kept at once (the oldest established one dropped beyond it).
    public var maxContexts: Int
    /// Most half-finished negotiations kept at once (the oldest pending one dropped beyond it).
    /// Counted apart from `maxContexts`: anyone can start a negotiation without credentials, so
    /// a flood of them must never push out an established context.
    public var maxPending: Int

    public init(kerberos: @escaping @Sendable () -> KerberosAcceptor, directory: (any DNSUpdateDirectory)? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }, contextLifetime: TimeInterval = 3600,
                pendingLifetime: TimeInterval = 60, maxContexts: Int = 1000, maxPending: Int = 256) {
        self.kerberos = kerberos
        self.directory = directory
        self.clock = clock
        self.contextLifetime = contextLifetime
        self.pendingLifetime = pendingLifetime
        self.maxContexts = maxContexts
        self.maxPending = maxPending
    }
}

/// The signed messages an established context has accepted within the TSIG time window, so a
/// captured one cannot be replayed: its MAC (any message) and its GSS sequence number (when the
/// MIC token carries it in clear, RFC 4121). Entries whose time signed is more than the fudge in
/// the past are forgotten — a replay of those fails the time check (BADTIME).
struct DNSTSIGReplayWindow: Sendable {
    private(set) var macs: [[UInt8]: UInt64] = [:]
    private(set) var sequences: [UInt64: UInt64] = [:]
    /// Most messages remembered for one context within the window; beyond it signed messages
    /// are refused until older ones age out (a member signs a handful an hour).
    static let limit = 4096

    enum Verdict: Equatable { case fresh, replayed, full }

    /// Records a verified message (MAC, optional sequence number, time signed) at `now`;
    /// `.replayed` when its MAC or sequence number was seen.
    mutating func admit(mac: [UInt8], sequence: UInt64?, timeSigned: UInt64, now: UInt64, fudge: UInt64) -> Verdict {
        let horizon = now > fudge ? now - fudge : 0
        if macs.count >= Self.limit / 2 || sequences.count >= Self.limit / 2 {
            macs = macs.filter { $0.value >= horizon }
            sequences = sequences.filter { $0.value >= horizon }
        }
        if macs[mac] != nil { return .replayed }
        if let sequence, sequences[sequence] != nil { return .replayed }
        guard macs.count < Self.limit, sequences.count < Self.limit else { return .full }
        macs[mac] = timeSigned
        if let sequence { sequences[sequence] = timeSigned }
        return .fresh
    }

    /// SND_SEQ of an RFC 4121 MIC token (`04 04`, flags, five `FF`, 8-byte sequence number);
    /// nil for other tokens (the RFC 1964 / RC4 ones encrypt it).
    static func sequence(ofMIC token: [UInt8]) -> UInt64? {
        guard token.count >= 16, token[0] == 0x04, token[1] == 0x04 else { return nil }
        return token[8..<16].reduce(0) { $0 << 8 | UInt64($1) }
    }
}

/// One TKEY key name: a negotiation in progress, or an established GSS context with the account
/// it authenticated (SID + sAMAccountName; the context holds the session / acceptor subkey).
struct DNSGSSKey: Sendable {
    var algorithm: DNSName
    var created: Date
    var expires: Date
    var pending: SPNEGOAcceptor? = nil
    var identity: AuthenticatedIdentity? = nil
    var context: (any GSSSecurityContext)? = nil
    /// The address that started a pending negotiation (only it may continue or abandon it).
    var origin: DNSAddress? = nil
    /// Messages this established context accepted recently (replay check).
    var replay = DNSTSIGReplayWindow()

    var isEstablished: Bool { context != nil && identity != nil }
}

/// The bounded, expiring table of TKEY contexts, keyed by key name (canonical). Established
/// contexts and pending negotiations have separate caps, and a pending one never takes the
/// place of an established one (CVE audit 2 Oct 2026: unauthenticated SPNEGO offers pushed out
/// every member's context).
struct DNSGSSKeyTable {
    private(set) var keys: [DNSName: DNSGSSKey] = [:]
    let limit: Int
    let pendingLimit: Int

    init(limit: Int, pendingLimit: Int = 256) {
        self.limit = max(1, limit)
        self.pendingLimit = max(1, pendingLimit)
    }

    static func key(_ name: DNSName) -> DNSName { DNSName(labels: name.canonicalLabels) }

    mutating func purge(now: Date) {
        keys = keys.filter { $0.value.expires > now }
    }

    /// Updates the live entry for `name` in place; nil when there is none.
    mutating func modify<R>(_ name: DNSName, _ body: (inout DNSGSSKey) -> R) -> R? {
        let k = Self.key(name)
        guard keys[k] != nil else { return nil }
        return body(&keys[k]!)
    }

    /// The live entry for `name` (an expired one is dropped).
    mutating func get(_ name: DNSName, now: Date) -> DNSGSSKey? {
        let k = Self.key(name)
        guard let entry = keys[k] else { return nil }
        if entry.expires <= now {
            keys[k] = nil
            return nil
        }
        return entry
    }

    /// Stores `entry`. Beyond its cap, the oldest entry of the same kind is dropped: a pending
    /// one for a pending one, an established one for an established one. An established entry
    /// is never replaced by a pending one.
    mutating func set(_ name: DNSName, _ entry: DNSGSSKey, now: Date) {
        purge(now: now)
        let k = Self.key(name)
        if let current = keys[k], current.isEstablished, !entry.isEstablished { return }
        let established = entry.isEstablished
        let sameKind = keys.filter { $0.key != k && $0.value.isEstablished == established }
        if sameKind.count >= (established ? limit : pendingLimit),
           let oldest = sameKind.min(by: { $0.value.created < $1.value.created })?.key {
            keys[oldest] = nil
        }
        keys[k] = entry
    }

    /// Drops a pending negotiation started from `origin`; an established context, or another
    /// sender's negotiation, stays.
    mutating func abandon(_ name: DNSName, origin: DNSAddress?) {
        let k = Self.key(name)
        guard let entry = keys[k], !entry.isEstablished, entry.origin == origin else { return }
        keys[k] = nil
    }

    var count: Int { keys.count }
    var establishedCount: Int { keys.values.filter(\.isEstablished).count }
    var pendingCount: Int { keys.count - establishedCount }
}

/// Who signed an update: the account a GSS-TSIG context authenticated.
public struct DNSUpdateSigner: Sendable, Hashable {
    public var identity: AuthenticatedIdentity
    /// The key name of the context (for logs).
    public var keyName: DNSName

    public var accountName: String { identity.sam }
    public var isComputer: Bool { identity.sam.hasSuffix("$") }
    public var holder: DNSRecordOwner.Holder { .account(sid: identity.sid.description, name: identity.sam) }
}
