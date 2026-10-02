import Foundation
import Store

/// One trusted-root rewrite of the published 802.1X profiles (see `rewriteDot1XTrustedRoots`).
public struct Dot1XTrustRewrite: Sendable, Equatable {
    public var anchor: String
    public var adding: [String]
    public var removing: [String]
    public var suiteB: Bool?

    public init(whereListed anchor: String, adding: [String], removing: [String], suiteB: Bool? = nil) {
        self.anchor = anchor
        self.adding = adding
        self.removing = removing
        self.suiteB = suiteB
    }
}

extension GroupPolicyEditor {
    /// Root migration (1 Oct 2026): rewrites the trusted roots of every published 802.1X profile
    /// (wireless and wired, Default Domain Policy) in place — `ServerValidation/TrustedRootCA` and
    /// the EAP-TLS client-issuer filter (`CAHashList/IssuerHash`) — for the profiles that list
    /// `anchor` (the old root): `adding` joins, `removing` leaves. The policy objects keep their
    /// GUIDs; the machine version is bumped once when anything changed, so joined PCs pick the
    /// change up at their next `gpupdate`. Returns the number of policy objects rewritten.
    ///
    /// `suiteB`: nil rewrites every profile; true only the WPA3-Enterprise 192-bit Wi-Fi
    /// profiles, false every other profile (a 192-bit profile trusts a P-384 root, which a
    /// switch to a P-256 root must not replace).
    @discardableResult
    public func rewriteDot1XTrustedRoots(whereListed anchor: String, adding: [String], removing: [String],
                                         suiteB: Bool? = nil) async throws -> Int {
        try await rewriteDot1XTrustedRoots([Dot1XTrustRewrite(whereListed: anchor, adding: adding, removing: removing, suiteB: suiteB)])
    }

    /// Several `rewriteDot1XTrustedRoots` rewrites applied in order to each policy object; a
    /// policy object changed by more than one of them (the WPA2 and the 192-bit profiles of one
    /// `<WLANPolicy>`) is written and counted once.
    @discardableResult
    public func rewriteDot1XTrustedRoots(_ rewrites: [Dot1XTrustRewrite]) async throws -> Int {
        var changed = 0
        for (container, attribute) in [("IEEE80211", "ms-net-ieee-80211-GP-PolicyData"), ("IEEE8023", "ms-net-ieee-8023-GP-PolicyData")] {
            guard let parent = try await store.read(dn: try await dot1XContainerDN(container)) else { continue }
            for child in try await store.children(of: parent.id) {
                guard let xml = child.string(attribute) else { continue }
                var rewritten = xml
                for r in rewrites {
                    rewritten = Dot1XPolicy.rewriteProfileTrustedRoots(rewritten, whereListed: r.anchor, adding: r.adding,
                                                                       removing: r.removing, suiteB: r.suiteB)
                }
                guard rewritten != xml else { continue }
                try await store.update(id: child.id, ops: [.replace(attribute, strings: [rewritten])])
                changed += 1
            }
        }
        if changed > 0 { try await bumpMachineVersion(.defaultDomainPolicy) }
        return changed
    }

    /// The policy data (`<WLANPolicy>` / `<LANPolicy>` XML) of every published 802.1X profile.
    public func publishedDot1XPolicies() async throws -> [String] {
        var out: [String] = []
        for (container, attribute) in [("IEEE80211", "ms-net-ieee-80211-GP-PolicyData"), ("IEEE8023", "ms-net-ieee-8023-GP-PolicyData")] {
            guard let parent = try await store.read(dn: try await dot1XContainerDN(container)) else { continue }
            for child in try await store.children(of: parent.id) {
                if let xml = child.string(attribute) { out.append(xml) }
            }
        }
        return out
    }
}

extension Dot1XPolicy {
    /// `<authentication>` of a WPA3-Enterprise 192-bit Wi-Fi profile.
    static let suiteBAuthenticationElement = "<authentication>\(Security.wpa3Suite192.authentication)</authentication>"

    /// Whether published `<WLANPolicy>` XML holds a WPA3-Enterprise 192-bit profile.
    public static func containsSuiteBProfile(_ xml: String) -> Bool {
        xml.contains(suiteBAuthenticationElement)
    }

    /// `rewriteTrustedRoots` applied to each `<WLANProfile>` of a `<WLANPolicy>` on its own (a
    /// policy carries one per Wi-Fi network, each with its own contiguous lists — rewriting the
    /// whole policy at once would span from the first profile's list to the last one's), or to
    /// the whole XML when it has none (a `<LANPolicy>`, never 192-bit). `suiteB` picks the
    /// profiles (see `GroupPolicyEditor.rewriteDot1XTrustedRoots`).
    public static func rewriteProfileTrustedRoots(_ xml: String, whereListed anchor: String, adding: [String],
                                                  removing: [String], suiteB: Bool? = nil) -> String {
        func wanted(_ segment: Substring) -> Bool {
            guard let suiteB else { return true }
            return segment.contains(suiteBAuthenticationElement) == suiteB
        }
        let open = "<WLANProfile", close = "</WLANProfile>"
        guard xml.contains(open) else {
            return wanted(xml[...]) ? rewriteTrustedRoots(xml, whereListed: anchor, adding: adding, removing: removing) : xml
        }
        var out = ""
        var cursor = xml.startIndex
        while let a = xml.range(of: open, range: cursor..<xml.endIndex),
              let b = xml.range(of: close, range: a.upperBound..<xml.endIndex) {
            out += xml[cursor..<a.lowerBound]
            let segment = xml[a.lowerBound..<b.upperBound]
            out += wanted(segment)
                ? rewriteTrustedRoots(String(segment), whereListed: anchor, adding: adding, removing: removing)
                : String(segment)
            cursor = b.upperBound
        }
        out += xml[cursor...]
        return out
    }
}
