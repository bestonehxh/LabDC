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
    /// Most contexts kept at once (oldest dropped beyond it).
    public var maxContexts: Int

    public init(kerberos: @escaping @Sendable () -> KerberosAcceptor, directory: (any DNSUpdateDirectory)? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }, contextLifetime: TimeInterval = 3600,
                pendingLifetime: TimeInterval = 60, maxContexts: Int = 1000) {
        self.kerberos = kerberos
        self.directory = directory
        self.clock = clock
        self.contextLifetime = contextLifetime
        self.pendingLifetime = pendingLifetime
        self.maxContexts = maxContexts
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

    var isEstablished: Bool { context != nil && identity != nil }
}

/// The bounded, expiring table of TKEY contexts, keyed by key name (canonical).
struct DNSGSSKeyTable {
    private(set) var keys: [DNSName: DNSGSSKey] = [:]
    let limit: Int

    init(limit: Int) { self.limit = limit }

    static func key(_ name: DNSName) -> DNSName { DNSName(labels: name.canonicalLabels) }

    mutating func purge(now: Date) {
        keys = keys.filter { $0.value.expires > now }
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

    mutating func set(_ name: DNSName, _ entry: DNSGSSKey, now: Date) {
        purge(now: now)
        let k = Self.key(name)
        if keys[k] == nil, keys.count >= limit,
           let oldest = keys.min(by: { $0.value.created < $1.value.created })?.key {
            keys[oldest] = nil
        }
        keys[k] = entry
    }

    mutating func remove(_ name: DNSName) { keys[Self.key(name)] = nil }

    var count: Int { keys.count }
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
