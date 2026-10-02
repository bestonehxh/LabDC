import Foundation
import Store
import os

/// The two halves of a GPO (MS-GPOL §1.3.2): `Machine/` (Computer Configuration, HKLM) and
/// `User/` (User Configuration, HKCU).
public enum GPOScope: String, Sendable, CaseIterable {
    case machine = "Machine"
    case user = "User"
}

/// Errors of GPO authoring.
public enum GroupPolicyError: Error, CustomStringConvertible, Sendable {
    case missingGPO(String)
    case filesystem(String)
    case invalidCertificate(String)
    case unknownThumbprint(String)

    public var description: String {
        switch self {
        case .missingGPO(let s): "GPO \(s) does not exist; run `labdc gpo init`"
        case .filesystem(let s): "SYSVOL: \(s)"
        case .invalidCertificate(let s): "certificate: \(s)"
        case .unknownThumbprint(let s): "no trusted root with thumbprint \(s) in the GPO"
        }
    }
}

/// What one GPO looks like right now (GPC in the directory + GPT in SYSVOL).
public struct GPOState: Sendable {
    public let gpo: DefaultGPO
    public let dn: DN
    public let displayName: String
    public let fileSysPath: String
    /// `versionNumber` on the GPC.
    public let containerVersion: GPOVersion
    /// `Version=` in GPT.INI.
    public let fileVersion: GPOVersion
    public let machineExtensions: GPOExtensionNames
    public let userExtensions: GPOExtensionNames
    public let flags: Int64
    /// DNs whose `gPLink` names this GPO.
    public let linkedOn: [DN]
    /// Folder of the GPT (`<root>/<dns>/Policies/{GUID}`).
    public let folder: URL

    /// Both copies agree (a client that sees them differ still applies the GPO, but GPMC shows
    /// it as "inconsistent" / out of sync).
    public var versionsMatch: Bool { containerVersion == fileVersion }
}

/// Result of an edit.
public struct GPOEditResult: Sendable, Equatable {
    /// Whether the policy file changed (and so the versions were bumped).
    public let changed: Bool
    public let previous: GPOVersion
    public let version: GPOVersion
}

/// Authoring side of Group Policy (what GPMC + the Group Policy Management Editor do): edits a
/// GPO's `Registry.pol`, then bumps the version in `GPT.INI` and on the GPC (`versionNumber`,
/// user << 16 | machine) and registers the client-side extension in
/// `gPC{Machine,User}ExtensionNames`. Order: the policy file, then the GPC (MS-GPOL §3.3.5.2
/// "GPO Extension Update": `versionNumber` + extension names), then `GPT.INI` (§3.3.5.4 "GPO File
/// System Version Update"), so a client reading between the steps applies the new file or skips an
/// unchanged-looking GPO until its next refresh.
///
/// Works on the store and the SYSVOL folder directly; `serve` serves both live, so a change is
/// visible to members at their next refresh (`gpupdate /force`).
public struct GroupPolicyEditor: Sendable {
    public let root: URL
    public let store: DirectoryStore
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "GPO")

    public init(root: URL, store: DirectoryStore) {
        self.root = root
        self.store = store
    }

    /// Creates the default GPOs (folders, GPT.INI, GPC objects, links) when missing
    /// (`SysvolLayout.ensure`).
    @discardableResult
    public func ensureDefaultGPOs() async throws -> SysvolEnsureResult {
        try await SysvolLayout.ensure(root: root, store: store)
    }

    // MARK: Reading

    public func folder(_ gpo: DefaultGPO) async throws -> URL {
        let info = try await store.domainInfo()
        return root.appendingPathComponent(info.dnsDomain, isDirectory: true)
            .appendingPathComponent("Policies", isDirectory: true)
            .appendingPathComponent(gpo.guid, isDirectory: true)
    }

    public func state(_ gpo: DefaultGPO) async throws -> GPOState {
        let info = try await store.domainInfo()
        let dn = gpo.dn(domainDN: info.domainDN)
        guard let gpc = try await store.read(dn: dn) else { throw GroupPolicyError.missingGPO("\(gpo.displayName) \(gpo.guid)") }
        let folder = try await folder(gpo)
        let ini = GPTIni(bytes: Self.child(of: folder, named: "GPT.INI").flatMap(Self.readFile) ?? [])
        let linked = try await store.search(base: info.domainDN, scope: .subtree,
                                            filter: .substrings(attribute: "gPLink", initial: nil,
                                                                any: [Array(gpo.guid.lowercased().utf8)], final: nil),
                                            attrs: ["gPLink"])
        return GPOState(gpo: gpo, dn: dn, displayName: gpc.string("displayName") ?? gpo.displayName,
                        fileSysPath: gpc.string("gPCFileSysPath") ?? "",
                        containerVersion: gpc.string("versionNumber").flatMap(GPOVersion.init(text:)) ?? GPOVersion(),
                        fileVersion: ini.version,
                        machineExtensions: GPOExtensionNames(gpc.string("gPCMachineExtensionNames") ?? ""),
                        userExtensions: GPOExtensionNames(gpc.string("gPCUserExtensionNames") ?? ""),
                        flags: gpc.int("flags") ?? 0, linkedOn: linked.map(\.dn), folder: folder)
    }

    /// The scope's `Registry.pol` (empty when the file does not exist).
    public func registryPolicy(_ gpo: DefaultGPO, scope: GPOScope) async throws -> RegistryPolicyFile {
        let folder = try await folder(gpo)
        guard let dir = Self.child(of: folder, named: scope.rawValue),
              let file = Self.child(of: dir, named: "Registry.pol"),
              let bytes = Self.readFile(file) else { return RegistryPolicyFile() }
        return try RegistryPolicyFile(bytes: bytes)
    }

    // MARK: Editing

    /// Applies `edit` to the scope's `Registry.pol`. When the file changes: writes it, bumps the
    /// scope's half of the version (`versionNumber`, then GPT.INI), and adds `extension` (CSE +
    /// tool GUID) to the scope's extension-names attribute. An edit that changes nothing leaves
    /// every file and attribute alone.
    @discardableResult
    public func editRegistryPolicy(_ gpo: DefaultGPO, scope: GPOScope,
                                   extension: (cse: String, tool: String)? = (GPOExtensionNames.registryCSE,
                                                                              GPOExtensionNames.publicKeyPoliciesTool),
                                   _ edit: (inout RegistryPolicyFile) throws -> Void) async throws -> GPOEditResult {
        try await ensureDefaultGPOs()
        let before = try await registryPolicy(gpo, scope: scope)
        var after = before
        try edit(&after)
        let current = try await state(gpo)
        let previous = GPOVersion.newest(current.containerVersion, current.fileVersion)
        guard after != before else { return GPOEditResult(changed: false, previous: previous, version: previous) }

        // 1. The policy file.
        let bytes = try after.encoded()
        let scopeDir = try Self.ensureChild(of: current.folder, named: scope.rawValue)
        let polURL = Self.child(of: scopeDir, named: "Registry.pol") ?? scopeDir.appendingPathComponent("Registry.pol")
        try Self.writeFile(polURL, bytes)

        // 2. The container: versionNumber + the extension list (MS-GPOL §3.3.5.2).
        let version = previous.bumped(machine: scope == .machine, user: scope == .user)
        var ops: [ModifyOp] = [.replace("versionNumber", strings: [version.directoryText])]
        if let ext = `extension` {
            var names = scope == .machine ? current.machineExtensions : current.userExtensions
            if !names.contains(cse: ext.cse, tool: ext.tool) {
                names.add(cse: ext.cse, tools: [ext.tool])
                ops.append(.replace(scope == .machine ? "gPCMachineExtensionNames" : "gPCUserExtensionNames",
                                    strings: [names.description]))
            }
        }
        guard let id = try await store.id(of: current.dn) else { throw GroupPolicyError.missingGPO(current.dn.description) }
        try await store.update(id: id, ops: ops)

        // 3. GPT.INI (§3.3.5.4), keeping whatever else a previous writer put there.
        let iniURL = Self.child(of: current.folder, named: "GPT.INI") ?? current.folder.appendingPathComponent("GPT.INI")
        var ini = GPTIni(bytes: Self.readFile(iniURL) ?? [])
        ini.version = version
        ini.displayName = current.displayName
        try Self.writeFile(iniURL, ini.encoded)
        Self.logger.notice("""
            GPO \(current.displayName, privacy: .public) \(scope.rawValue, privacy: .public)/Registry.pol: \
            \(after.entries.count) instructions, version \(previous.raw) -> \(version.raw)
            """)
        return GPOEditResult(changed: true, previous: previous, version: version)
    }

    // MARK: Files

    /// `name` under `dir`, matched case-insensitively (the default GPOs use `MACHINE`/`USER`
    /// as dcpromo does; GPMC-created ones `Machine`/`User`; the SMB server resolves either).
    static func child(of dir: URL, named name: String) -> URL? {
        let fm = FileManager.default
        let exact = dir.appendingPathComponent(name)
        if fm.fileExists(atPath: exact.path) { return exact }
        guard let names = try? fm.contentsOfDirectory(atPath: dir.path),
              let match = names.first(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) else { return nil }
        return dir.appendingPathComponent(match)
    }

    static func ensureChild(of dir: URL, named name: String) throws -> URL {
        if let found = child(of: dir, named: name) { return found }
        let u = dir.appendingPathComponent(name, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            throw GroupPolicyError.filesystem("cannot create \(u.path): \(error.localizedDescription)")
        }
        return u
    }

    static func readFile(_ url: URL) -> [UInt8]? {
        (try? Data(contentsOf: url)).map { Array($0) }
    }

    /// Atomic replace (temp file + rename), mode 0600 like the rest of SYSVOL.
    static func writeFile(_ url: URL, _ bytes: [UInt8]) throws {
        do {
            try Data(bytes).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw GroupPolicyError.filesystem("cannot write \(url.path): \(error.localizedDescription)")
        }
    }
}

// MARK: - 802.1X (wired/wireless) policy objects ([MS-GPWL])

extension GPOExtensionNames {
    /// Wireless (802.11) CSE and its GPMC tool ([MS-GPWL] §1.9).
    public static let wirelessCSE = "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}"
    public static let wirelessTool = "{2DA6AA7F-8C88-4194-A558-0D36E7FD3E64}"
    /// Wired (802.3) CSE and its GPMC tool.
    public static let wiredCSE = "{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}"
    public static let wiredTool = "{06993B16-A5C7-47EB-B61C-B1CB7EE600AC}"
}

extension GroupPolicyEditor {
    /// Where the 802.1X policy objects live: `CN=<container>,CN=Windows,CN=Microsoft,CN=Machine,<GPO>`
    /// (the WLAN/LAN extensions search the GPO's Machine subtree for their class).
    func dot1XContainerDN(_ container: String, gpo: DefaultGPO = .defaultDomainPolicy) async throws -> DN {
        let gpoDN = gpo.dn(domainDN: try await store.domainInfo().domainDN)
        return gpoDN.child(RDN("CN", "Machine")).child(RDN("CN", "Microsoft")).child(RDN("CN", "Windows")).child(RDN("CN", container))
    }

    /// Publishes (or updates) the wireless policy object (`ms-net-ieee-80211-GroupPolicy`,
    /// [MS-GPWL] §3.1.1) in the Default Domain Policy and makes Windows pick it up: the
    /// wireless CSE in `gPCMachineExtensionNames`, the machine version bumped, and the WLAN
    /// AutoConfig service (Wlansvc) set to Automatic.
    public func set80211Policy(_ policy: Dot1XPolicy) async throws {
        try policy.validate()
        let policy = try await keepingFormerName(policy, container: "IEEE80211")
        try await setPolicy(policy.name, container: "IEEE80211", objectClass: "ms-net-ieee-80211-GroupPolicy",
                            guidAttribute: "ms-net-ieee-80211-GP-PolicyGUID",
                            dataAttribute: "ms-net-ieee-80211-GP-PolicyData",
                            data: policy.wirelessXML,
                            description: "802.1X wireless profile (\(policy.ssid))",
                            extension: (GPOExtensionNames.wirelessCSE, GPOExtensionNames.wirelessTool),
                            service: "Wlansvc")
    }

    /// The wired (802.3) equivalent (`ms-net-ieee-8023-GroupPolicy`); sets Wired AutoConfig
    /// (dot3svc) to Automatic — without it Windows ignores wired 802.1X profiles.
    public func set8023Policy(_ policy: Dot1XPolicy) async throws {
        let policy = try await keepingFormerName(policy, container: "IEEE8023")
        try await setPolicy(policy.name, container: "IEEE8023", objectClass: "ms-net-ieee-8023-GroupPolicy",
                            guidAttribute: "ms-net-ieee-8023-GP-PolicyGUID",
                            dataAttribute: "ms-net-ieee-8023-GP-PolicyData",
                            data: policy.wiredXML,
                            description: "802.1X wired profile",
                            extension: (GPOExtensionNames.wiredCSE, GPOExtensionNames.wiredTool),
                            service: "dot3svc")
    }

    /// The app's default policy name, or a former default (SheepAuth 802.1X) when only that object
    /// exists: re-publishing updates it in place, so its GUID — the profile's identity on joined
    /// PCs — stays and Windows never sees a second policy after the rename to LabDC (1 Oct 2026).
    func keepingFormerName(_ policy: Dot1XPolicy, container: String) async throws -> Dot1XPolicy {
        guard policy.name == Dot1XPolicy.defaultName else { return policy }
        var kept = policy
        kept.name = try await appPolicyName(container: container)
        return kept
    }

    /// The CN the app publishes under in `container`: `LabDC 802.1X`, or a former default when
    /// only that object exists.
    func appPolicyName(container: String) async throws -> String {
        let parent = try await dot1XContainerDN(container)
        guard try await store.id(of: parent.child(RDN("CN", Dot1XPolicy.defaultName))) == nil else { return Dot1XPolicy.defaultName }
        for former in Dot1XPolicy.formerDefaultNames where try await store.id(of: parent.child(RDN("CN", former))) != nil {
            return former
        }
        return Dot1XPolicy.defaultName
    }

    private func setPolicy(_ name: String, container: String, objectClass: String,
                           guidAttribute: String, dataAttribute: String, data: String,
                           description: String, extension ext: (cse: String, tool: String), service: String) async throws {
        try await writePolicyObject(name, container: container, objectClass: objectClass, guidAttribute: guidAttribute,
                                    dataAttribute: dataAttribute, data: data, description: description)
        try writeServiceStartup([service: 2], gpo: try await folder(.defaultDomainPolicy))
        try await bumpMachineVersion(.defaultDomainPolicy, extensions: [ext, (GPOExtensionNames.securityCSE, GPOExtensionNames.securityTool)])
    }

    /// Group Policy page (1 Oct 2026): publishes the wireless profiles as one `<WLANPolicy>` (one
    /// `<WLANProfile>` each, in order) named `wirelessName` / `wirelessDescription`, and the wired
    /// profile as one `<LANPolicy>` (its `name` / `policyDescription`), in the app's policy
    /// objects (`LabDC 802.1X`, or the SheepAuth-era object updated in place). The objects keep
    /// their CN and GUID whatever the policy is named. An empty wireless list / nil wired removes
    /// that object. WLAN AutoConfig / Wired AutoConfig are set to Automatic for what is published,
    /// and the machine version is bumped once for the whole publish.
    @discardableResult
    public func publishDot1X(wireless: [Dot1XPolicy], wired: Dot1XPolicy?,
                             wirelessName: String = Dot1XPolicy.defaultName,
                             wirelessDescription: String = Dot1XProfileSet.defaultDescription) async throws -> GPOVersion {
        var seen = Set<String>()
        for p in wireless {
            try p.validate()
            let name = p.profileName ?? p.ssid
            guard seen.insert(name).inserted else { throw Dot1XPolicy.Invalid.duplicateProfile(name) }
        }
        try await ensureDefaultGPOs()
        let wlanName = try await appPolicyName(container: "IEEE80211")
        let lanName = try await appPolicyName(container: "IEEE8023")
        var extensions: [(cse: String, tool: String)] = []
        var services: [String: Int] = [:]
        var removing: [String] = []
        if wireless.isEmpty {
            try await deletePolicyObject(wlanName, container: "IEEE80211")
            if try await containerIsEmpty("IEEE80211") { removing.append(GPOExtensionNames.wirelessCSE) }
        } else {
            try await writePolicyObject(wlanName, container: "IEEE80211", objectClass: "ms-net-ieee-80211-GroupPolicy",
                                        guidAttribute: "ms-net-ieee-80211-GP-PolicyGUID",
                                        dataAttribute: "ms-net-ieee-80211-GP-PolicyData",
                                        data: Dot1XPolicy.wirelessPolicyXML(name: wirelessName, description: wirelessDescription,
                                                                            profiles: wireless),
                                        description: wirelessDescription)
            extensions.append((GPOExtensionNames.wirelessCSE, GPOExtensionNames.wirelessTool))
            services["Wlansvc"] = 2
        }
        if let wired {
            try await writePolicyObject(lanName, container: "IEEE8023", objectClass: "ms-net-ieee-8023-GroupPolicy",
                                        guidAttribute: "ms-net-ieee-8023-GP-PolicyGUID",
                                        dataAttribute: "ms-net-ieee-8023-GP-PolicyData",
                                        data: wired.wiredXML, description: wired.description)
            extensions.append((GPOExtensionNames.wiredCSE, GPOExtensionNames.wiredTool))
            services["dot3svc"] = 2
        } else {
            try await deletePolicyObject(lanName, container: "IEEE8023")
            if try await containerIsEmpty("IEEE8023") { removing.append(GPOExtensionNames.wiredCSE) }
        }
        if !services.isEmpty {
            try writeServiceStartup(services, gpo: try await folder(.defaultDomainPolicy))
            extensions.append((GPOExtensionNames.securityCSE, GPOExtensionNames.securityTool))
        }
        let version = try await bumpMachineVersion(.defaultDomainPolicy, extensions: extensions, removing: removing)
        Self.logger.notice("""
            GPO 802.1X published: \(wireless.count) wireless profile(s), wired \(wired == nil ? "off" : "on", privacy: .public), \
            version \(version.raw)
            """)
        return version
    }

    /// What the app's policy objects carry now (parsed from their XML), and the policy XML of
    /// each (nil when that object does not exist).
    public func publishedDot1XProfiles() async throws -> (set: Dot1XProfileSet, wirelessXML: String?, wiredXML: String?) {
        var xml: [String: String] = [:]
        for (container, attribute) in [("IEEE80211", "ms-net-ieee-80211-GP-PolicyData"), ("IEEE8023", "ms-net-ieee-8023-GP-PolicyData")] {
            let dn = try await dot1XContainerDN(container).child(RDN("CN", try await appPolicyName(container: container)))
            if let data = try await store.read(dn: dn)?.string(attribute) { xml[container] = data }
        }
        let dc = try? await store.domainInfo().dcDNSName
        return (Dot1XProfileSet.parse(wirelessXML: xml["IEEE80211"], wiredXML: xml["IEEE8023"], labServerName: dc),
                xml["IEEE80211"], xml["IEEE8023"])
    }

    /// No policy object left under `container` (another made with GPMC keeps its CSE listed).
    private func containerIsEmpty(_ container: String) async throws -> Bool {
        guard let window = try await store.read(dn: try await dot1XContainerDN(container)) else { return true }
        return try await store.children(of: window.id).isEmpty
    }

    private func deletePolicyObject(_ name: String, container: String) async throws {
        let dn = try await dot1XContainerDN(container).child(RDN("CN", name))
        if let id = try await store.id(of: dn) { try await store.delete(id: id) }
    }

    /// Creates or updates one policy object (the container chain under CN=Machine as needed),
    /// keeping its GUID. No version bump.
    private func writePolicyObject(_ name: String, container: String, objectClass: String,
                                   guidAttribute: String, dataAttribute: String, data: String,
                                   description: String) async throws {
        try await ensureDefaultGPOs()
        let gpoDN = DefaultGPO.defaultDomainPolicy.dn(domainDN: try await store.domainInfo().domainDN)
        // An earlier build wrote the objects outside CN=Machine, where no client looks.
        try await removeLegacyDot1X(container, gpoDN: gpoDN)
        var parent = gpoDN.child(RDN("CN", "Machine"))
        for rdn in ["Machine", "Microsoft", "Windows", container].dropFirst() {
            let dn = parent.child(RDN("CN", rdn))
            if try await store.id(of: dn) == nil {
                _ = try await store.create(parent: parent, rdn: RDN("CN", rdn), objectClass: "container", strings: [:])
            }
            parent = dn
        }
        let policyDN = parent.child(RDN("CN", name))
        // The policy GUID is minted once (braced) and kept on every update, as [MS-GPWL] §3.1.4.2
        // modifies the existing object. Windows 10 downloads a changed policy at gpupdate but WLAN
        // AutoConfig applies changes to a profile it already has only after it restarts — with
        // the same GUID or a new one (tested 2 Oct 2026); new or renamed profiles apply at once.
        var attributes: [String: [String]] = [dataAttribute: [data], "description": [description]]
        if let existing = try await store.read(dn: policyDN) {
            if existing.string(guidAttribute) == nil { attributes[guidAttribute] = ["{\(UUID().uuidString)}"] }
            try await store.update(id: existing.id, ops: attributes.map { .replace($0.key, strings: $0.value) })
        } else {
            attributes[guidAttribute] = ["{\(UUID().uuidString)}"]
            _ = try await store.create(parent: parent, rdn: RDN("CN", name), objectClass: objectClass, strings: attributes)
        }
    }

    private func removeLegacyDot1X(_ container: String, gpoDN: DN) async throws {
        let legacy = gpoDN.child(RDN("CN", "Microsoft")).child(RDN("CN", "Windows")).child(RDN("CN", container))
        guard let window = try await store.read(dn: legacy) else { return }
        for child in try await store.children(of: window.id) { try? await store.delete(id: child.id) }
        try? await store.delete(id: window.id)
    }

    /// Bumps the machine half of the GPO version (`versionNumber` + extension names on the GPC,
    /// then GPT.INI — MS-GPOL §3.3.5.2/§3.3.5.4) so clients re-read a policy that lives in the
    /// directory (802.1X), not in a Registry.pol.
    @discardableResult
    /// `removing`: CSEs whose settings left the GPO — a CSE still listed with nothing to read
    /// fails on the clients ("Windows failed to apply the Wireless Group Policy settings"), and
    /// once it is gone Windows removes what that CSE applied, like GPMC's delete.
    func bumpMachineVersion(_ gpo: DefaultGPO, extensions: [(cse: String, tool: String)] = [],
                            removing: [String] = []) async throws -> GPOVersion {
        try await ensureDefaultGPOs()
        let current = try await state(gpo)
        let version = GPOVersion.newest(current.containerVersion, current.fileVersion).bumped(machine: true, user: false)
        var ops: [ModifyOp] = [.replace("versionNumber", strings: [version.directoryText])]
        var names = current.machineExtensions
        for cse in removing { names.remove(cse: cse) }
        for ext in extensions where !names.contains(cse: ext.cse, tool: ext.tool) { names.add(cse: ext.cse, tools: [ext.tool]) }
        if names != current.machineExtensions { ops.append(.replace("gPCMachineExtensionNames", strings: [names.description])) }
        guard let id = try await store.id(of: current.dn) else { throw GroupPolicyError.missingGPO(current.dn.description) }
        try await store.update(id: id, ops: ops)
        let iniURL = Self.child(of: current.folder, named: "GPT.INI") ?? current.folder.appendingPathComponent("GPT.INI")
        var ini = GPTIni(bytes: Self.readFile(iniURL) ?? [])
        ini.version = version
        ini.displayName = current.displayName
        try Self.writeFile(iniURL, ini.encoded)
        return version
    }

    /// `[Service General Setting]` in the GPO's `GptTmpl.inf` (UTF-16LE): `"dot3svc",2,""` sets a
    /// service to Automatic (2) without touching its permissions. Other sections stay as they are.
    func writeServiceStartup(_ services: [String: Int], gpo folder: URL) throws {
        let dir = try ["MACHINE", "Microsoft", "Windows NT", "SecEdit"].reduce(folder) { try Self.ensureChild(of: $0, named: $1) }
        let file = Self.child(of: dir, named: "GptTmpl.inf") ?? dir.appendingPathComponent("GptTmpl.inf")
        var text = Self.readFile(file).map(Self.decodeUTF16) ?? "[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n"
        text = Self.settingServices(services, in: text)
        try Self.writeFile(file, [0xFF, 0xFE] + text.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] })
    }

    static func decodeUTF16(_ bytes: [UInt8]) -> String {
        var b = bytes
        if b.starts(with: [0xFF, 0xFE]) { b.removeFirst(2) }
        let units = stride(from: 0, to: b.count - b.count % 2, by: 2).map { UInt16(b[$0]) | UInt16(b[$0 + 1]) << 8 }
        return String(decoding: units, as: UTF16.self)
    }

    /// Adds/updates the service lines in `[Service General Setting]` (created before `[Version]`).
    static func settingServices(_ services: [String: Int], in text: String) -> String {
        var lines = text.components(separatedBy: "\r\n")
        if lines.last == "" { lines.removeLast() }
        let header = "[Service General Setting]"
        var start = lines.firstIndex { $0.caseInsensitiveCompare(header) == .orderedSame }
        if start == nil {
            let at = lines.firstIndex { $0.caseInsensitiveCompare("[Version]") == .orderedSame } ?? lines.count
            lines.insert(header, at: at)
            start = at
        }
        guard let s = start else { return text }
        var end = s + 1
        while end < lines.count, !lines[end].hasPrefix("[") { end += 1 }
        var section = Array(lines[(s + 1)..<end])
        for (name, mode) in services.sorted(by: { $0.key < $1.key }) {
            let line = "\"\(name)\",\(mode),\"\""
            if let i = section.firstIndex(where: { $0.lowercased().hasPrefix("\"\(name.lowercased())\",") }) { section[i] = line }
            else { section.append(line) }
        }
        lines.replaceSubrange((s + 1)..<end, with: section)
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    /// Removes the 802.1X policy objects (wireless and wired) and bumps the version so clients
    /// drop the profiles.
    /// Startup repair: a wireless/wired CSE listed in the Default Domain Policy with no policy
    /// object under it (an earlier LabDC removed the object only) fails gpupdate on every PC.
    /// Drops such CSEs and bumps the version so Windows removes the stale profiles. Returns the
    /// CSEs removed (empty: nothing to do, no bump).
    @discardableResult
    public func dropOrphanDot1XExtensions() async throws -> [String] {
        let current = try await state(.defaultDomainPolicy)
        var orphans: [String] = []
        for (cse, container) in [(GPOExtensionNames.wirelessCSE, "IEEE80211"), (GPOExtensionNames.wiredCSE, "IEEE8023")]
        where current.machineExtensions.contains(cse: cse) {
            if try await containerIsEmpty(container) { orphans.append(cse) }
        }
        if !orphans.isEmpty { try await bumpMachineVersion(.defaultDomainPolicy, removing: orphans) }
        return orphans
    }

    public func remove80211Policies() async throws {
        let gpoDN = DefaultGPO.defaultDomainPolicy.dn(domainDN: try await store.domainInfo().domainDN)
        for container in ["IEEE80211", "IEEE8023"] {
            try await removeLegacyDot1X(container, gpoDN: gpoDN)
            // Only LabDC's own objects (current and former default names): a policy another admin
            // made with GPMC stays, and so does its CSE.
            for name in [Dot1XPolicy.defaultName] + Dot1XPolicy.formerDefaultNames {
                try await deletePolicyObject(name, container: container)
            }
        }
        var removing: [String] = []
        if try await containerIsEmpty("IEEE80211") { removing.append(GPOExtensionNames.wirelessCSE) }
        if try await containerIsEmpty("IEEE8023") { removing.append(GPOExtensionNames.wiredCSE) }
        try await bumpMachineVersion(.defaultDomainPolicy, removing: removing)
    }
}
