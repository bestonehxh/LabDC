import Foundation

/// Setup wizard step 1: everything derived from the domain name the owner types
/// (`lab.sheep` → realm `LAB.SHEEP`, NetBIOS `LAB`, base DN `DC=lab,DC=sheep`, DC `dc1.lab.sheep`).
public struct DomainSetup: Equatable, Sendable {
    public var dnsDomain: String
    public var realm: String
    public var netbios: String
    public var baseDN: String
    public var dcName: String
    public var dcFQDN: String

    public static let suggested = "lab.sheep"

    public enum Problem: Error, Equatable, Sendable, CustomStringConvertible {
        case empty
        case singleLabel
        case local
        case badLabel(String)
        case tooLong
        case numericTopLevel

        public var description: String {
            switch self {
            case .empty: "Type a domain name, like lab.sheep."
            case .singleLabel: "Use at least two parts, like lab.sheep."
            case .local: "Don't use .local — it collides with Bonjour on Macs and iPhones."
            case .badLabel(let l): "“\(l)” can only use letters, digits and hyphens (not at the start or end), up to 63 characters."
            case .tooLong: "The domain name is longer than 253 characters."
            case .numericTopLevel: "The last part can't be only digits."
            }
        }
    }

    /// Derives the names from `input` (trimmed, lower-cased, a trailing dot dropped).
    public static func derive(_ input: String, dcName: String = "dc1") -> Result<DomainSetup, Problem> {
        var name = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty else { return .failure(.empty) }
        guard name.count <= 253 else { return .failure(.tooLong) }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        for label in labels {
            let ok = !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" }
            if !ok { return .failure(.badLabel(label)) }
        }
        guard labels.count >= 2 else { return .failure(.singleLabel) }
        if labels.last == "local" { return .failure(.local) }
        if labels.last!.allSatisfy(\.isNumber) { return .failure(.numericTopLevel) }
        let netbios = String(labels[0].uppercased().prefix(15))
        let dc = dcName.lowercased()
        return .success(DomainSetup(dnsDomain: name, realm: name.uppercased(), netbios: netbios,
                                    baseDN: labels.map { "DC=\($0)" }.joined(separator: ","),
                                    dcName: dc, dcFQDN: "\(dc).\(name)"))
    }

    /// What `validNetbios` accepts, as the wizard and Settings say it.
    public static let netbiosRule = "1 to 15 letters, digits or hyphens — no dots or spaces."

    /// The NetBIOS domain name `input` names (trimmed, upper-cased) when it is 1–15 ASCII
    /// letters, digits or hyphens; nil otherwise. Dots and spaces confuse Windows joins
    /// (owner review, 30 Sep 2026).
    public static func validNetbios(_ input: String) -> String? {
        let name = input.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard (1...15).contains(name.count),
              name.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" }) else { return nil }
        return name
    }

    /// The `--provision` spec for these names.
    public func provisionSpec(adminPassword: String) -> ProvisionSpec {
        ProvisionSpec(realm: realm, dnsDomain: dnsDomain, netbios: netbios, dcName: dcName, adminPassword: adminPassword)
    }
}

/// Setup wizard step 2 / Settings ▸ General: how the password fares against the domain's default
/// policy (AD defaults: 7 characters, 3 of upper/lower/digit/symbol/other letters, not containing
/// the account name) — the same rules the store enforces when it sets the password.
public struct PasswordStrength: Equatable, Sendable {
    public enum Level: Int, Sendable, Comparable {
        case empty, refused, fair, strong
        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
    }

    public var level: Level
    /// One sentence under the field.
    public var hint: String
    public var isAcceptable: Bool { level >= .fair }

    public static let minimumLength = 7

    public static func evaluate(_ password: String, account: String = "Administrator") -> PasswordStrength {
        if password.isEmpty { return .init(level: .empty, hint: "At least 7 characters, with 3 of: upper case, lower case, digits, symbols.") }
        if password.count < minimumLength {
            return .init(level: .refused, hint: "Too short: at least \(minimumLength) characters.")
        }
        if password.count > 256 { return .init(level: .refused, hint: "Too long: at most 256 characters.") }
        if account.count >= 3, password.lowercased().contains(account.lowercased()) {
            return .init(level: .refused, hint: "Must not contain “\(account)”.")
        }
        // Lab-first (owner, 30 Sep 2026): length is the rule; the character mix is advice.
        let classes = characterClasses(password)
        if password.count >= 12, classes >= 3 {
            return .init(level: .strong, hint: "Strong password.")
        }
        if classes < 3 {
            return .init(level: .fair, hint: "Accepted. 3 of upper case, lower case, digits, symbols would be stronger (has \(classes)).")
        }
        return .init(level: .fair, hint: "Accepted. 12 or more characters would be stronger.")
    }

    /// Upper, lower, digit, symbol, other letters (the store's `isComplex` classes).
    static func characterClasses(_ password: String) -> Int {
        var upper = false, lower = false, digit = false, symbol = false, other = false
        let symbols = Set("~!@#$%^&*_-+=`|\\(){}[]:;\"'<>,.?/")
        for c in password {
            if c.isASCII, c.isNumber { digit = true }
            else if symbols.contains(c) { symbol = true }
            else if c.isUppercase { upper = true }
            else if c.isLowercase { lower = true }
            else if c.isLetter { other = true }
        }
        return [upper, lower, digit, symbol, other].filter { $0 }.count
    }
}
