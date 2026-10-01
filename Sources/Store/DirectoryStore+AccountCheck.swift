import Foundation
import MSPAC
import SheepCrypto

/// Why a password sign-in was refused. One vocabulary for the LDAP simple bind and RADIUS
/// (PAP, MS-CHAPv2) so both take the same path and log the same reasons (30 Sep 2026).
public enum AccountRefusal: Equatable, Sendable, CustomStringConvertible {
    case noSuchAccount
    case noPassword
    case wrongPassword
    case disabled
    case expired
    case lockedOut(until: Date?)

    public var description: String {
        switch self {
        case .noSuchAccount: "no such account"
        case .noPassword: "the account has no password"
        case .wrongPassword: "wrong password"
        case .disabled: "account disabled"
        case .expired: "account expired"
        case .lockedOut(let until?): "locked out until " + until.formatted(.dateTime.hour().minute())
        case .lockedOut(nil): "account locked out"
        }
    }
}

extension DirectoryStore {
    /// The account-state checks every password path shares: disabled (UF_ACCOUNTDISABLE),
    /// locked (UF_LOCKOUT) and expired (`accountExpires` in the past).
    public nonisolated func accountRefusal(_ entry: DirectoryEntry, now: Date) -> AccountRefusal? {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & UserAccountControl.accountDisable != 0 { return .disabled }
        if uac & UserAccountControl.lockout != 0 { return .lockedOut(until: nil) }
        if let expires = entry.int("accountExpires"), expires > 0, expires != Int64.max,
           let date = FileTime(rawValue: UInt64(expires)).date, date <= now {
            return .expired
        }
        return nil
    }

    /// Netlogon's must-change rule (Samba `authsam_account_ok`): the password must be changed
    /// before this account may sign in — `pwdLastSet` is 0 ("User must change password at next
    /// logon") or UF_PASSWORD_EXPIRED is set — unless UF_DONT_EXPIRE_PASSWORD. Trust accounts
    /// (machines, DCs, domain trusts) never have to.
    public func passwordMustChange(_ entry: DirectoryEntry) throws -> Bool {
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        let trust = UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount
            | UserAccountControl.interdomainTrustAccount
        if uac & trust != 0 || uac & UserAccountControl.dontExpirePassword != 0 { return false }
        if uac & UserAccountControl.passwordExpired != 0 { return true }
        guard let secrets = try secrets(id: entry.id) else { return false }
        return secrets.pwdLastSet.rawValue == 0
    }

    /// When the password was last set (nil: never / no secrets row).
    public func passwordLastSet(_ entry: DirectoryEntry) throws -> Date? {
        guard let secrets = try secrets(id: entry.id), secrets.pwdLastSet.rawValue != 0 else { return nil }
        return secrets.pwdLastSet.date
    }

    /// `logonHours` (21 bytes, one bit per hour of the week in UTC, Sunday 00:00 first, low bit
    /// first): false when the bit for `now` is clear. No attribute (or a malformed one) = any time.
    public nonisolated func logonHoursAllow(_ entry: DirectoryEntry, now: Date) -> Bool {
        guard let hours = entry.values("logonHours").first, hours.count == 21 else { return true }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .current
        let c = calendar.dateComponents([.weekday, .hour], from: now)
        let bit = ((c.weekday ?? 1) - 1) * 24 + (c.hour ?? 0)
        return hours[bit / 8] & (UInt8(1) << UInt8(bit % 8)) != 0
    }

    /// The simple-bind check (LDAP and RADIUS PAP): the password against the stored NT hash in
    /// constant time first (a wrong password never reveals the account state), then
    /// `accountRefusal`. nil = the password is right and the account may sign in.
    public func checkPassword(_ entry: DirectoryEntry, password: String, now: Date) throws -> AccountRefusal? {
        guard let hash = try secrets(id: entry.id)?.ntHash else { return .noPassword }
        guard ConstantTime.equal(Self.ntHash(password), hash) else { return .wrongPassword }
        return accountRefusal(entry, now: now)
    }
}

/// Per-account wrong-password counter: after `threshold` wrong passwords inside `window` the
/// account is refused for `duration` (Netlogon's NAC lockout; RADIUS keeps one of its own).
public final class BadPasswordTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var failures: [String: [Date]] = [:]
    private var lockedUntil: [String: Date] = [:]

    public init() {}

    /// The time the account stays locked until, when it is locked at `now`.
    public func lockedUntil(_ account: String, now: Date) -> Date? {
        lock.lock(); defer { lock.unlock() }
        let key = account.lowercased()
        if let until = lockedUntil[key], until > now { return until }
        lockedUntil[key] = nil
        return nil
    }

    /// Records a wrong password; returns true when this one locks the account.
    public func recordFailure(_ account: String, now: Date, threshold: Int, window: TimeInterval, duration: TimeInterval) -> Bool {
        guard threshold > 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        let key = account.lowercased()
        var recent = (failures[key] ?? []).filter { now.timeIntervalSince($0) < window }
        recent.append(now)
        if recent.count >= threshold {
            failures[key] = nil
            lockedUntil[key] = now.addingTimeInterval(duration)
            return true
        }
        // Keep the table bounded against a spray of made-up names.
        if failures.count > 10_000 { failures = failures.filter { !$0.value.isEmpty && now.timeIntervalSince($0.value.last!) < window } }
        failures[key] = recent
        return false
    }

    public func recordSuccess(_ account: String) {
        lock.lock(); defer { lock.unlock() }
        failures[account.lowercased()] = nil
    }
}

extension DirectoryStore {
    /// Resolves a sign-in name to a live account, the AD name forms: DN, `user@domain` (UPN or
    /// sam@dnsDomain), `DOMAIN\user`, bare sAMAccountName, and the 802.1X machine forms
    /// `host/NAME` / `host/name.domain` → `NAME$` (a bare name also finds `NAME$`). Shared by the
    /// LDAP simple bind and RADIUS so both accept the same names.
    public func resolveSignInName(_ rawName: String) throws -> DirectoryEntry? {
        var name = rawName.trimmingCharacters(in: .whitespaces)
        if name.lowercased().hasPrefix("dn:") { name = String(name.dropFirst(3)) }
        else if name.lowercased().hasPrefix("u:") { name = String(name.dropFirst(2)) }
        guard !name.isEmpty else { return nil }
        let info = try domainInfo()
        if name.contains("=") {
            guard let dn = try? DN(string: name) else { return nil }
            return try read(dn: dn)
        }
        if name.lowercased().hasPrefix("host/") {
            var host = String(name.dropFirst(5))
            let suffix = "." + info.dnsDomain.lowercased()
            if host.lowercased().hasSuffix(suffix) { host = String(host.dropLast(suffix.count)) }
            guard !host.isEmpty, !host.contains(".") else { return nil }
            return try read(sam: host + "$")
        }
        if let slash = name.firstIndex(of: "\\") {
            let domain = name[..<slash].lowercased()
            let sam = String(name[name.index(after: slash)...])
            guard domain == info.netbiosDomain.lowercased() || domain == info.dnsDomain.lowercased() else { return nil }
            return try signInAccount(sam: sam)
        }
        if let at = name.lastIndex(of: "@") {
            if let e = try read(upn: name) { return e }
            let suffix = name[name.index(after: at)...].lowercased()
            guard suffix == info.dnsDomain.lowercased() || suffix == info.realm.lowercased() else { return nil }
            return try signInAccount(sam: String(name[..<at]))
        }
        return try signInAccount(sam: name)
    }

    private func signInAccount(sam: String) throws -> DirectoryEntry? {
        if let e = try read(sam: sam) { return e }
        return sam.hasSuffix("$") ? nil : try read(sam: sam + "$")
    }
}
