import Foundation

/// A GPO version (MS-GPOL §2.2.4 / §3.2.5.1.6): the upper 16 bits count user-side changes, the
/// lower 16 bits machine-side changes. The same number is kept twice, in `GPT.INI`
/// (`Version=`, the "GPO file system version") and in the GPC's `versionNumber` (the "GPO
/// container version"); a GPO whose two versions are both 0 is "empty" and skipped by clients.
public struct GPOVersion: Sendable, Hashable, Comparable, CustomStringConvertible {
    public var user: UInt16
    public var machine: UInt16

    public init(user: UInt16 = 0, machine: UInt16 = 0) {
        self.user = user
        self.machine = machine
    }

    public init(raw: UInt32) {
        user = UInt16(raw >> 16)
        machine = UInt16(raw & 0xFFFF)
    }

    /// Parses the decimal `versionNumber` / `Version=` text (AD stores it as a signed 32-bit
    /// INTEGER, so a user version ≥ 0x8000 reads back negative).
    public init?(text: String) {
        let t = text.trimmingCharacters(in: .whitespaces)
        if let v = UInt32(t) { self.init(raw: v) } else if let v = Int32(t) { self.init(raw: UInt32(bitPattern: v)) } else { return nil }
    }

    public var raw: UInt32 { UInt32(user) << 16 | UInt32(machine) }

    /// `versionNumber` as AD stores an INTEGER (signed 32-bit decimal).
    public var directoryText: String { String(Int32(bitPattern: raw)) }

    /// Component-wise maximum, so neither side can go backwards when the two copies disagree.
    public static func newest(_ a: GPOVersion, _ b: GPOVersion) -> GPOVersion {
        GPOVersion(user: max(a.user, b.user), machine: max(a.machine, b.machine))
    }

    /// The next version after a change on one side (wrapping 0xFFFF to 1, never back to 0).
    public func bumped(machine m: Bool, user u: Bool) -> GPOVersion {
        func next(_ v: UInt16) -> UInt16 { v == .max ? 1 : v + 1 }
        return GPOVersion(user: u ? next(user) : user, machine: m ? next(machine) : machine)
    }

    public static func < (a: GPOVersion, b: GPOVersion) -> Bool { a.raw < b.raw }

    public var description: String { "\(raw) (user \(user), machine \(machine))" }
}

/// `GPT.INI` (MS-GPOL §2.2.4): an ANSI INI file with a `[General]` section whose `Version` key
/// is the GPO file system version. GPMC also writes `displayName`; we write
///
///     [General]\r\nVersion=<n>\r\ndisplayName=<name>\r\n
///
/// and keep any other `[General]` keys (and other sections) a previous writer left.
public struct GPTIni: Sendable, Hashable {
    public var version: GPOVersion
    public var displayName: String?
    /// Other `[General]` keys, in file order.
    public var otherGeneralKeys: [(String, String)] = []
    /// Everything after `[General]`'s keys that belongs to other sections, verbatim lines.
    public var otherSections: [String] = []

    public init(version: GPOVersion, displayName: String? = nil) {
        self.version = version
        self.displayName = displayName
    }

    public static func == (a: GPTIni, b: GPTIni) -> Bool {
        a.version == b.version && a.displayName == b.displayName && a.otherSections == b.otherSections
            && a.otherGeneralKeys.map(\.0) == b.otherGeneralKeys.map(\.0) && a.otherGeneralKeys.map(\.1) == b.otherGeneralKeys.map(\.1)
    }

    public func hash(into h: inout Hasher) {
        h.combine(version)
        h.combine(displayName)
    }

    /// Parses a file; a missing `[General]` or `Version` reads as version 0 (MS-GPOL calls such
    /// a file corrupt; a writer repairs it).
    public init(bytes: [UInt8]) {
        let text = String(decoding: bytes, as: UTF8.self)
        version = GPOVersion()
        displayName = nil
        var section: String?
        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            let line = rawLine.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                section = String(trimmed.dropFirst().dropLast())
                if section?.caseInsensitiveCompare("General") != .orderedSame { otherSections.append(trimmed) }
                continue
            }
            guard section?.caseInsensitiveCompare("General") == .orderedSame else {
                if section != nil { otherSections.append(line) }
                continue
            }
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let key = trimmed[..<eq].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if key.caseInsensitiveCompare("Version") == .orderedSame {
                version = GPOVersion(text: value) ?? GPOVersion()
            } else if key.caseInsensitiveCompare("displayName") == .orderedSame {
                displayName = value
            } else {
                otherGeneralKeys.append((key, value))
            }
        }
    }

    /// The file bytes (CRLF line ends; the name is written as UTF-8, which is ANSI for the
    /// ASCII names GPOs normally carry — only `Version` is read by clients).
    public var encoded: [UInt8] {
        var lines = ["[General]", "Version=\(version.raw)"]
        if let displayName { lines.append("displayName=\(displayName)") }
        lines += otherGeneralKeys.map { "\($0.0)=\($0.1)" }
        lines += otherSections
        return Array((lines.joined(separator: "\r\n") + "\r\n").utf8)
    }
}

/// `gPCMachineExtensionNames` / `gPCUserExtensionNames` (MS-GPOL §2.2.3 attribute table):
/// `[<CSE GUID><tool GUID>...][...]`, pairs sorted case-insensitively ascending by CSE GUID
/// ("Group Policy processing terminates at the first <CSE GUIDn> out of sequence"); tool GUIDs
/// in a pair are kept sorted too. GUIDs are 38-character braced strings.
public struct GPOExtensionNames: Sendable, Hashable, CustomStringConvertible {
    public struct Pair: Sendable, Hashable {
        public var cse: String
        public var tools: [String]
    }

    public private(set) var pairs: [Pair] = []

    /// Registry CSE ("Administrative Templates" / registry policy), MS-GPREG §1.9.
    public static let registryCSE = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    /// Public Key Policies tool extension as registered for the Default Domain Policy
    /// (MS-GPEF §1.9 "default domain policy settings"; the Default Domain Policy's own
    /// `[{35378EAC-…}{53D6AB1B-…}]` pair in Samba's provision LDIF, copied from Windows).
    public static let publicKeyPoliciesTool = "{53D6AB1B-2488-11D1-A28C-00C04FB94F17}"
    /// Public Key Policies tool extension for other GPOs (MS-GPEF §1.9 "computer policy settings").
    public static let publicKeyPoliciesToolOtherGPO = "{53D6AB1D-2488-11D1-A28C-00C04FB94F17}"
    /// Security CSE (SecEdit) and its "Computer Configuration" tool (what `GptTmpl.inf` needs).
    public static let securityCSE = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
    public static let securityTool = "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"

    public init() {}

    /// Lenient parse: every `[` ... `]` group of braced GUIDs; the first is the CSE.
    public init(_ text: String) {
        var p = text.startIndex
        while let open = text[p...].firstIndex(of: "[") {
            guard let close = text[open...].firstIndex(of: "]") else { break }
            let inner = text[text.index(after: open)..<close]
            var guids: [String] = []
            var q = inner.startIndex
            while let b = inner[q...].firstIndex(of: "{"), let e = inner[b...].firstIndex(of: "}") {
                guids.append(String(inner[b...e]).uppercased())
                q = inner.index(after: e)
            }
            if let cse = guids.first { add(cse: cse, tools: Array(guids.dropFirst())) }
            p = text.index(after: close)
        }
    }

    /// Adds a CSE with its tools, merging with an existing pair; keeps everything sorted.
    public mutating func add(cse: String, tools: [String]) {
        let c = cse.uppercased()
        if let i = pairs.firstIndex(where: { $0.cse == c }) {
            pairs[i].tools = Self.sortedUnique(pairs[i].tools + tools.map { $0.uppercased() })
        } else {
            pairs.append(Pair(cse: c, tools: Self.sortedUnique(tools.map { $0.uppercased() })))
            pairs.sort { $0.cse < $1.cse }
        }
    }

    public func contains(cse: String, tool: String? = nil) -> Bool {
        guard let p = pairs.first(where: { $0.cse == cse.uppercased() }) else { return false }
        return tool.map { p.tools.contains($0.uppercased()) } ?? true
    }

    /// The attribute text; empty when there are no pairs.
    public var description: String {
        pairs.map { "[" + $0.cse + $0.tools.joined() + "]" }.joined()
    }

    private static func sortedUnique(_ v: [String]) -> [String] { Array(Set(v)).sorted() }
}
