import Foundation
import Store

/// One of the two GPOs every AD domain has from `dcpromo` on (MS-GPOL §1.3; MS-ADTS §6.1.1.4.x
/// well-known policy GUIDs). The GUID spelling (including the lower-case `f` in the DC policy)
/// is the one Windows uses for both the folder name and the RDN.
public struct DefaultGPO: Sendable, Hashable {
    /// Where the GPO is linked.
    public enum LinkTarget: Sendable, Hashable {
        /// The domain NC head (`DC=lab,DC=sheep`).
        case domainRoot
        /// `OU=Domain Controllers,<domain>`.
        case domainControllersOU
    }

    /// `{31B2F340-...}` style, braces included.
    public let guid: String
    public let displayName: String
    public let linkTarget: LinkTarget
    /// Whether `GptTmpl.inf` carries the domain `[System Access]` (password/lockout) section.
    public let carriesAccountPolicy: Bool

    public static let defaultDomainPolicy = DefaultGPO(
        guid: "{31B2F340-016D-11D2-945F-00C04FB984F9}", displayName: "Default Domain Policy",
        linkTarget: .domainRoot, carriesAccountPolicy: true)
    public static let defaultDomainControllersPolicy = DefaultGPO(
        guid: "{6AC1786C-016F-11D2-945F-00C04fB984F9}", displayName: "Default Domain Controllers Policy",
        linkTarget: .domainControllersOU, carriesAccountPolicy: false)
    public static let all: [DefaultGPO] = [defaultDomainPolicy, defaultDomainControllersPolicy]

    /// Client-side extension list for a GPO whose only settings are SecEdit's:
    /// `[{Security CSE}{Computer Configuration snap-in tool}]` (MS-GPOL §2.2.4).
    public static let secEditMachineExtensionNames =
        "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"

    /// `CN=<guid>,CN=Policies,CN=System,<domain>`.
    public func dn(domainDN: DN) -> DN {
        DefaultGPO.policiesDN(domainDN: domainDN).child(RDN("CN", guid))
    }

    /// `CN=Policies,CN=System,<domain>`.
    public static func policiesDN(domainDN: DN) -> DN {
        domainDN.child(RDN("CN", "System")).child(RDN("CN", "Policies"))
    }

    /// The DN the GPO is linked on.
    public func linkedDN(domainDN: DN) -> DN {
        switch linkTarget {
        case .domainRoot: domainDN
        case .domainControllersOU: domainDN.child(RDN("OU", "Domain Controllers"))
        }
    }

    /// `\\lab.sheep\SysVol\lab.sheep\Policies\{...}` (the GPC's `gPCFileSysPath`, spelled as a
    /// Windows DC writes it; share names are case-insensitive, so stores provisioned with the
    /// older `sysvol` spelling work too and `SysvolLayout.ensure` only re-cases the value).
    public func fileSysPath(dnsDomain: String) -> String {
        "\\\\\(dnsDomain)\\SysVol\\\(dnsDomain)\\Policies\\\(guid)"
    }

    /// One `gPLink` element, link options 0 (enabled, not enforced): `[LDAP://<dn>;0]`.
    public func gPLinkElement(domainDN: DN) -> String {
        "[LDAP://\(dn(domainDN: domainDN).description);0]"
    }

    // MARK: - File contents

    /// `GPT.INI` (ASCII, CRLF). Version 0 matches `versionNumber` 0 on the GPC.
    public static let gptINI: [UInt8] = Array("[General]\r\nVersion=0\r\n".utf8)

    /// `MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf` text (CRLF line ends). Windows writes
    /// this file as UTF-16LE with a BOM; `encodedTemplate` does that.
    public func securityTemplate(_ access: SystemAccessPolicy?) -> String {
        var lines = ["[Unicode]", "Unicode=yes"]
        if carriesAccountPolicy, let access { lines += ["[System Access]"] + access.infLines }
        lines += ["[Version]", "signature=\"$CHICAGO$\"", "Revision=1"]
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    /// `securityTemplate` as UTF-16LE with a byte-order mark.
    public func encodedTemplate(_ access: SystemAccessPolicy?) -> [UInt8] {
        [0xFF, 0xFE] + securityTemplate(access).utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }
    }
}

/// The `[System Access]` values of the Default Domain Policy, taken from the domain object
/// (the values the DC itself enforces).
public struct SystemAccessPolicy: Sendable, Hashable {
    public var minimumPasswordAgeDays: Int
    /// -1 = never expires.
    public var maximumPasswordAgeDays: Int
    public var minimumPasswordLength: Int
    public var passwordComplexity: Bool
    public var passwordHistorySize: Int
    public var lockoutBadCount: Int
    public var resetLockoutCountMinutes: Int
    public var lockoutDurationMinutes: Int
    public var clearTextPassword: Bool

    public init(minimumPasswordAgeDays: Int = 1, maximumPasswordAgeDays: Int = 42, minimumPasswordLength: Int = 7,
                passwordComplexity: Bool = true, passwordHistorySize: Int = 24, lockoutBadCount: Int = 0,
                resetLockoutCountMinutes: Int = 30, lockoutDurationMinutes: Int = 30, clearTextPassword: Bool = false) {
        self.minimumPasswordAgeDays = minimumPasswordAgeDays
        self.maximumPasswordAgeDays = maximumPasswordAgeDays
        self.minimumPasswordLength = minimumPasswordLength
        self.passwordComplexity = passwordComplexity
        self.passwordHistorySize = passwordHistorySize
        self.lockoutBadCount = lockoutBadCount
        self.resetLockoutCountMinutes = resetLockoutCountMinutes
        self.lockoutDurationMinutes = lockoutDurationMinutes
        self.clearTextPassword = clearTextPassword
    }

    /// Reads the domain object and `passwordPolicy()`. A relaxed (lab) policy is written as
    /// what the DC enforces: length 0, no complexity, no history.
    public static func from(store: DirectoryStore) async throws -> SystemAccessPolicy {
        let info = try await store.domainInfo()
        let policy = try await store.passwordPolicy()
        let domain = try await store.read(dn: info.domainDN,
                                          attrs: ["minPwdAge", "maxPwdAge", "lockoutThreshold",
                                                  "lockOutObservationWindow", "lockoutDuration", "pwdProperties"])
        func interval(_ name: String) -> Int64? { domain?.int(name) }
        var out = SystemAccessPolicy()
        out.minimumPasswordAgeDays = days(interval("minPwdAge"), never: 0) ?? 1
        out.maximumPasswordAgeDays = days(interval("maxPwdAge"), never: -1) ?? 42
        out.minimumPasswordLength = policy.relaxed ? 0 : policy.minLength
        out.passwordComplexity = policy.relaxed ? false : policy.complexity
        out.passwordHistorySize = policy.relaxed ? 0 : policy.historyLength
        out.lockoutBadCount = Int(interval("lockoutThreshold") ?? 0)
        out.resetLockoutCountMinutes = minutes(interval("lockOutObservationWindow")) ?? 30
        out.lockoutDurationMinutes = minutes(interval("lockoutDuration")) ?? 30
        out.clearTextPassword = ((interval("pwdProperties") ?? 0) & 0x10) != 0  // DOMAIN_PASSWORD_STORE_CLEARTEXT
        return out
    }

    /// AD intervals are negative 100 ns counts; 0 and Int64.min mean "none/never".
    static func days(_ v: Int64?, never: Int) -> Int? {
        guard let v else { return nil }
        if v == 0 || v == Int64.min { return never }
        return Int(v.magnitude / 864_000_000_000)
    }

    static func minutes(_ v: Int64?) -> Int? {
        guard let v else { return nil }
        if v == Int64.min { return -1 }
        return Int(v.magnitude / 600_000_000)
    }

    /// Lines in the order `secedit /export` writes them.
    var infLines: [String] {
        var lines = [
            "MinimumPasswordAge = \(minimumPasswordAgeDays)",
            "MaximumPasswordAge = \(maximumPasswordAgeDays)",
            "MinimumPasswordLength = \(minimumPasswordLength)",
            "PasswordComplexity = \(passwordComplexity ? 1 : 0)",
            "PasswordHistorySize = \(passwordHistorySize)",
            "LockoutBadCount = \(lockoutBadCount)",
        ]
        if lockoutBadCount > 0 {
            lines += ["ResetLockoutCount = \(resetLockoutCountMinutes)", "LockoutDuration = \(lockoutDurationMinutes)"]
        }
        lines += [
            "RequireLogonToChangePassword = 0",
            "ForceLogoffWhenHourExpire = 0",
            "ClearTextPassword = \(clearTextPassword ? 1 : 0)",
            "LSAAnonymousNameLookup = 0",
        ]
        return lines
    }
}
