import Foundation

/// What the app publishes as 802.1X Group Policy (Group Policy page, 1 Oct 2026), shaped like
/// GPMC's Wireless Network (IEEE 802.11) Policies editor: one wireless policy (name,
/// description) holding an ordered list of profiles — each with its own name, one or more SSIDs
/// and connection settings — and at most one wired policy. Only the choices live here; the
/// trust (lab root, server name, client-issuer filter) is filled in when publishing, unless a
/// profile names another RADIUS server (`server`).
public struct Dot1XProfileSet: Codable, Equatable, Sendable {
    public static let defaultDescription = "802.1X for the domain's Windows PCs, published by LabDC"

    /// The RADIUS server a profile's clients validate when it is not this DC (owner, 1 Oct 2026:
    /// ClearPass with a self-signed certificate): Windows `ServerNames` and the `TrustedRootCA`
    /// certificates — like GPMC's Trusted Root list, any certificate (a root CA, the self-signed
    /// server certificate, or the server's own certificate issued by another CA), each of which
    /// must be in the Default Domain Policy's trusted roots.
    public struct RadiusServer: Codable, Equatable, Sendable {
        /// The names in that server's certificate (`ServerNames`, joined with ";").
        public var serverNames: [String]
        /// Upper-case hex SHA-1 thumbprint of the trusted certificate.
        public var trustedRoot: String
        /// More certificates the profile trusts (e.g. the root next to the chosen server
        /// certificate, both picked from one file); empty for drafts saved before (1 Oct 2026).
        public var alsoTrusted: [String]

        public init(serverNames: [String], trustedRoot: String, alsoTrusted: [String] = []) {
            self.serverNames = serverNames.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let primary = TrustedRoot.normalizedThumbprint(trustedRoot) ?? trustedRoot
            self.trustedRoot = primary
            var more: [String] = []
            for t in alsoTrusted.map({ TrustedRoot.normalizedThumbprint($0) ?? $0 }) where t != primary && !more.contains(t) {
                more.append(t)
            }
            self.alsoTrusted = more
        }

        private enum CodingKeys: String, CodingKey { case serverNames, trustedRoot, alsoTrusted }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.init(serverNames: try c.decode([String].self, forKey: .serverNames),
                      trustedRoot: try c.decode(String.self, forKey: .trustedRoot),
                      alsoTrusted: try c.decodeIfPresent([String].self, forKey: .alsoTrusted) ?? [])
        }

        /// The chosen certificate first, then the others.
        public var allTrusted: [String] { [trustedRoot] + alsoTrusted }

        /// "a.lab;b.lab" / "a.lab, b.lab" to names.
        public static func names(_ text: String) -> [String] {
            text.split(whereSeparator: { $0 == ";" || $0 == "," }).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        public func validate() throws {
            // No names: Windows checks only the certificate chain, as GPMC allows (1 Oct 2026).
            for t in allTrusted where TrustedRoot.normalizedThumbprint(t) == nil { throw Dot1XPolicy.Invalid.badTrustedRoot(t) }
        }
    }

    /// GPMC's server-validation choices of one profile (Wi-Fi or wired), the same for this DC
    /// and another server.
    public struct ServerValidation: Codable, Equatable, Sendable {
        /// "Verify the server's identity by validating the certificate" (`PerformServerValidation`).
        public var verify: Bool
        /// "Ask the user when the server can't be verified": GPMC's "Do not prompt user to
        /// authorize new servers or trusted CAs" inverted (`DisableUserPromptForServerValidation`).
        public var promptUser: Bool

        /// What every profile did before these choices existed: verify, never ask.
        public static let standard = ServerValidation()

        public init(verify: Bool = true, promptUser: Bool = false) {
            self.verify = verify
            self.promptUser = promptUser
        }

        public func apply(to p: inout Dot1XPolicy) {
            p.performServerValidation = verify
            p.promptUserForServerValidation = promptUser
        }
    }

    /// A certificate added with "Add a certificate…" for another RADIUS server: it joins the
    /// Default Domain Policy's trusted roots in the next publish (then leaves this list).
    public struct PendingRoot: Codable, Equatable, Sendable {
        public var der: Data
        public var name: String?
        public var thumbprint: String { CertificateBlob.thumbprint(Array(der)) }

        public init(der: [UInt8], name: String?) {
            self.der = Data(der)
            self.name = name
        }
    }

    /// One Wi-Fi profile (a `<WLANProfile>`), identified by its name.
    public struct Wireless: Codable, Equatable, Sendable, Identifiable {
        /// The profile's name (`netsh wlan show profiles`). Windows replaces a Group Policy
        /// profile by name, so a rename removes the old-named profile from PCs at the next gpupdate.
        public var name: String
        /// 1–25 SSIDs, case-sensitive.
        public var ssids: [String]
        public var security: Dot1XPolicy.Security
        public var method: Dot1XPolicy.Method
        public var signInAs: Dot1XPolicy.AuthMode
        /// "Connect automatically when this network is in range".
        public var connectAutomatically: Bool
        /// "Connect even if the network is not broadcasting its name".
        public var connectHidden: Bool
        /// "Switch to a more preferred network if available".
        public var autoSwitch: Bool
        /// "Enable Single Sign On" (immediately before user logon).
        public var singleSignOn: Bool
        /// "Cache user information for subsequent connections".
        public var cacheUserData: Bool
        /// nil: this DC (LabDC RADIUS), the default.
        public var server: RadiusServer?
        /// Verify the server / ask the user; drafts saved before (1 Oct 2026) get the standard.
        public var validation: ServerValidation

        public var id: String { name }

        public init(name: String, ssids: [String]? = nil, security: Dot1XPolicy.Security = .wpa2,
                    method: Dot1XPolicy.Method = .tls, signInAs: Dot1XPolicy.AuthMode = .machineOrUser,
                    connectAutomatically: Bool = true, connectHidden: Bool = false, autoSwitch: Bool = false,
                    singleSignOn: Bool = false, cacheUserData: Bool = true, server: RadiusServer? = nil,
                    validation: ServerValidation = .standard) {
            self.name = name; self.ssids = ssids ?? [name]; self.security = security; self.method = method
            self.signInAs = signInAs; self.connectAutomatically = connectAutomatically
            self.connectHidden = connectHidden; self.autoSwitch = autoSwitch
            self.singleSignOn = singleSignOn; self.cacheUserData = cacheUserData; self.server = server
            self.validation = validation
        }

        private enum CodingKeys: String, CodingKey {
            case name, ssids, security, method, signInAs, connectAutomatically, connectHidden, autoSwitch
            case singleSignOn, cacheUserData, server, validation
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            name = try c.decode(String.self, forKey: .name)
            ssids = try c.decode([String].self, forKey: .ssids)
            security = try c.decode(Dot1XPolicy.Security.self, forKey: .security)
            method = try c.decode(Dot1XPolicy.Method.self, forKey: .method)
            signInAs = try c.decode(Dot1XPolicy.AuthMode.self, forKey: .signInAs)
            connectAutomatically = try c.decode(Bool.self, forKey: .connectAutomatically)
            connectHidden = try c.decode(Bool.self, forKey: .connectHidden)
            autoSwitch = try c.decode(Bool.self, forKey: .autoSwitch)
            singleSignOn = try c.decode(Bool.self, forKey: .singleSignOn)
            cacheUserData = try c.decode(Bool.self, forKey: .cacheUserData)
            server = try c.decodeIfPresent(RadiusServer.self, forKey: .server)
            validation = try c.decodeIfPresent(ServerValidation.self, forKey: .validation) ?? .standard
        }

        /// A name; 1–25 SSIDs of 1–32 bytes; WPA3-Enterprise 192-bit only with EAP-TLS; another
        /// server with its names and a thumbprint.
        public func validate() throws {
            if name.trimmingCharacters(in: .whitespaces).isEmpty { throw Dot1XPolicy.Invalid.noProfileName }
            try Dot1XPolicy.validate(ssids: ssids, security: security, method: method)
            try server?.validate()
        }
    }

    /// 802.1X on Ethernet (a `<LANPolicy>` with one profile): no SSID, no security mode.
    public struct Wired: Codable, Equatable, Sendable {
        public var name: String
        public var description: String
        public var method: Dot1XPolicy.Method
        public var signInAs: Dot1XPolicy.AuthMode
        /// nil: this DC (LabDC RADIUS), the default.
        public var server: RadiusServer?
        /// Verify the server / ask the user; drafts saved before (1 Oct 2026) get the standard.
        public var validation: ServerValidation

        public init(name: String = Dot1XPolicy.defaultName, description: String = Dot1XProfileSet.defaultDescription,
                    method: Dot1XPolicy.Method = .tls, signInAs: Dot1XPolicy.AuthMode = .machineOrUser,
                    server: RadiusServer? = nil, validation: ServerValidation = .standard) {
            self.name = name; self.description = description; self.method = method; self.signInAs = signInAs
            self.server = server; self.validation = validation
        }

        private enum CodingKeys: String, CodingKey { case name, description, method, signInAs, server, validation }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            name = try c.decode(String.self, forKey: .name)
            description = try c.decode(String.self, forKey: .description)
            method = try c.decode(Dot1XPolicy.Method.self, forKey: .method)
            signInAs = try c.decode(Dot1XPolicy.AuthMode.self, forKey: .signInAs)
            server = try c.decodeIfPresent(RadiusServer.self, forKey: .server)
            validation = try c.decodeIfPresent(ServerValidation.self, forKey: .validation) ?? .standard
        }
    }

    /// The wireless policy's name and description (`<WLANPolicy>` `<name>` / `<description>`).
    /// Renaming changes these, not the directory object: it keeps its CN and GUID.
    public var name: String
    public var description: String
    /// In preference order.
    public var wireless: [Wireless]
    /// nil: no wired policy.
    public var wired: Wired?
    /// Certificates to add to the trusted roots with the next publish (another RADIUS server's).
    public var pendingRoots: [PendingRoot]

    public init(name: String = Dot1XPolicy.defaultName, description: String = Dot1XProfileSet.defaultDescription,
                wireless: [Wireless] = [], wired: Wired? = nil, pendingRoots: [PendingRoot] = []) {
        self.name = name
        self.description = description
        self.wireless = wireless
        self.wired = wired
        self.pendingRoots = pendingRoots
    }

    private enum CodingKeys: String, CodingKey { case name, description, wireless, wired, pendingRoots }

    /// Drafts saved before `pendingRoots` (1 Oct 2026) have none.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        description = try c.decode(String.self, forKey: .description)
        wireless = try c.decode([Wireless].self, forKey: .wireless)
        wired = try c.decodeIfPresent(Wired.self, forKey: .wired)
        pendingRoots = try c.decodeIfPresent([PendingRoot].self, forKey: .pendingRoots) ?? []
    }

    /// Keeps `root` for the next publish (once per thumbprint).
    public mutating func addPendingRoot(_ root: PendingRoot) {
        if !pendingRoots.contains(where: { $0.thumbprint == root.thumbprint }) { pendingRoots.append(root) }
    }

    /// Drops pending certificates no profile trusts any more.
    public mutating func prunePendingRoots() {
        let used = Set(wireless.flatMap { $0.server?.allTrusted ?? [] } + (wired?.server?.allTrusted ?? []))
        pendingRoots.removeAll { !used.contains($0.thumbprint) }
    }

    /// The profiles that trust `thumbprint` for another RADIUS server: "Wi-Fi profile Staff",
    /// "the wired profile".
    public func profiles(trusting thumbprint: String) -> [String] {
        guard let t = TrustedRoot.normalizedThumbprint(thumbprint) else { return [] }
        return wireless.filter { $0.server?.allTrusted.contains(t) == true }.map { "Wi-Fi profile \($0.name)" }
            + (wired?.server?.allTrusted.contains(t) == true ? ["the wired profile"] : [])
    }

    public var isEmpty: Bool { wireless.isEmpty && wired == nil }

    public func wireless(named name: String) -> Wireless? { wireless.first { $0.name == name } }

    /// Adds `profile` at the end, or replaces the one named `replacing` (default: the same name)
    /// in place. Validates it and that no other profile has its name.
    public mutating func save(_ profile: Wireless, replacing old: String? = nil) throws {
        var profile = profile
        profile.name = profile.name.trimmingCharacters(in: .whitespaces)
        profile.ssids = profile.ssids.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        // What the XML can say (autoSwitch only with connectionMode auto): otherwise the draft
        // never equals what reads back from Group Policy and stays "changed" after Publish.
        profile.autoSwitch = profile.autoSwitch && profile.connectAutomatically
        try profile.validate()
        let key = old ?? profile.name
        if wireless.contains(where: { $0.name == profile.name && $0.name != key }) {
            throw Dot1XPolicy.Invalid.duplicateProfile(profile.name)
        }
        if let i = wireless.firstIndex(where: { $0.name == key }) {
            wireless[i] = profile
        } else {
            wireless.append(profile)
        }
    }

    /// Group Policy ▸ Wireless ▸ Delete policy: no profiles (so publishing removes the
    /// `<WLANPolicy>`), and the default name and description for a policy created later.
    public mutating func deleteWirelessPolicy() {
        wireless = []
        name = Dot1XPolicy.defaultName
        description = Dot1XProfileSet.defaultDescription
    }

    @discardableResult
    public mutating func remove(named name: String) -> Bool {
        let before = wireless.count
        wireless.removeAll { $0.name == name }
        // The last profile gone: the wireless policy is gone too (GPMC: it exists or not).
        if wireless.isEmpty && before > 0 { deleteWirelessPolicy() }
        return wireless.count != before
    }

    /// Moves a profile to `position` (0-based, clamped): the preference order.
    @discardableResult
    public mutating func move(named name: String, to position: Int) -> Bool {
        guard let i = wireless.firstIndex(where: { $0.name == name }) else { return false }
        let p = wireless.remove(at: i)
        wireless.insert(p, at: min(max(0, position), wireless.count))
        return true
    }

    public func validate() throws {
        try wired?.server?.validate()
        var seen = Set<String>()
        for w in wireless {
            try w.validate()
            guard seen.insert(w.name).inserted else { throw Dot1XPolicy.Invalid.duplicateProfile(w.name) }
        }
    }

    // MARK: Reading what is published

    /// The choices of published `<WLANPolicy>` / `<LANPolicy>` XML (what `GroupPolicyEditor`
    /// publishes, or what an earlier build published as one profile named after its SSID): one
    /// entry per `<WLANProfile>`, in order. Unreadable XML counts as no profile. With
    /// `labServerName` (this DC's DNS name), a profile whose `ServerNames` is anything else reads
    /// back as another RADIUS server; without it every profile is this DC's.
    public static func parse(wirelessXML: String?, wiredXML: String?, labServerName: String? = nil) -> Dot1XProfileSet {
        var set = Dot1XProfileSet()
        if let xml = wirelessXML, let doc = try? XMLDocument(xmlString: xml), let root = doc.rootElement() {
            set.name = child(root, "name") ?? set.name
            set.description = child(root, "description") ?? ""
            for case let profile as XMLElement in (try? doc.nodes(forXPath: "//*[local-name()='WLANProfile']")) ?? [] {
                let ssids = ssidNames(profile)
                guard let name = child(profile, "name") ?? ssids.first, !ssids.isEmpty else { continue }
                let security: Dot1XPolicy.Security = switch (first(profile, "authentication") ?? "WPA2").uppercased() {
                case "WPA3ENT192": .wpa3Suite192
                case "WPA3ENT", "WPA3": .wpa3
                default: .wpa2
                }
                set.wireless.append(Wireless(
                    name: name, ssids: ssids, security: security, method: method(profile), signInAs: authMode(profile),
                    connectAutomatically: (child(profile, "connectionMode") ?? "auto") != "manual",
                    connectHidden: first(profile, "nonBroadcast") == "true",
                    autoSwitch: child(profile, "autoSwitch") == "true",
                    singleSignOn: (try? profile.nodes(forXPath: ".//*[local-name()='singleSignOn']"))?.isEmpty == false,
                    cacheUserData: first(profile, "cacheUserData") != "false",
                    server: server(profile, labServerName: labServerName), validation: validation(profile)))
            }
        }
        if let xml = wiredXML, let doc = try? XMLDocument(xmlString: xml), let root = doc.rootElement(),
           let profile = (try? doc.nodes(forXPath: "//*[local-name()='LANProfile']"))?.first as? XMLElement {
            set.wired = Wired(name: child(root, "name") ?? Dot1XPolicy.defaultName, description: child(root, "description") ?? "",
                              method: method(profile), signInAs: authMode(profile),
                              server: server(profile, labServerName: labServerName), validation: validation(profile))
        }
        return set
    }

    /// Another RADIUS server: `ServerNames` other than this DC's name, the `TrustedRootCA`s.
    private static func server(_ profile: XMLElement, labServerName: String?) -> RadiusServer? {
        guard let lab = labServerName?.lowercased(), let text = first(profile, "ServerNames") else { return nil }
        let names = RadiusServer.names(text)
        let roots = ((try? profile.nodes(forXPath: ".//*[local-name()='TrustedRootCA']")) ?? [])
            .compactMap { $0.stringValue.flatMap(TrustedRoot.normalizedThumbprint) }
        // No names is another server too: LabDC's own profiles always name this DC.
        guard names.map({ $0.lowercased() }) != [lab], let root = roots.first else { return nil }
        return RadiusServer(serverNames: names, trustedRoot: root, alsoTrusted: Array(roots.dropFirst()))
    }

    /// `PerformServerValidation` (absent: true) and `DisableUserPromptForServerValidation`
    /// (absent: no prompt, what LabDC always wrote before).
    private static func validation(_ profile: XMLElement) -> ServerValidation {
        ServerValidation(verify: first(profile, "PerformServerValidation")?.lowercased() != "false",
                         promptUser: first(profile, "DisableUserPromptForServerValidation")?.lowercased() == "false")
    }

    /// The text of the first descendant named `localName`.
    private static func first(_ element: XMLElement, _ localName: String) -> String? {
        (try? element.nodes(forXPath: ".//*[local-name()='\(localName)']"))?.first?.stringValue?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The text of the direct child named `localName`.
    private static func child(_ element: XMLElement, _ localName: String) -> String? {
        (try? element.nodes(forXPath: "./*[local-name()='\(localName)']"))?.first?.stringValue?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func ssidNames(_ profile: XMLElement) -> [String] {
        let nodes = (try? profile.nodes(forXPath: "./*[local-name()='SSIDConfig']/*[local-name()='SSID']")) ?? []
        return nodes.compactMap { node -> String? in
            guard let ssid = node as? XMLElement else { return nil }
            if let name = child(ssid, "name"), !name.isEmpty { return name }
            guard let hex = child(ssid, "hex"), hex.count % 2 == 0 else { return nil }
            var bytes: [UInt8] = []
            var i = hex.startIndex
            while i < hex.endIndex {
                let j = hex.index(i, offsetBy: 2)
                guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
                bytes.append(b)
                i = j
            }
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    private static func method(_ profile: XMLElement) -> Dot1XPolicy.Method {
        let type = (try? profile.nodes(forXPath: ".//*[local-name()='EapMethod']/*[local-name()='Type']"))?.first?.stringValue
        return type?.trimmingCharacters(in: .whitespaces) == "25" ? .peapMSCHAPv2 : .tls
    }

    private static func authMode(_ profile: XMLElement) -> Dot1XPolicy.AuthMode {
        first(profile, "authMode").flatMap(Dot1XPolicy.AuthMode.init(rawValue:)) ?? .machineOrUser
    }
}
