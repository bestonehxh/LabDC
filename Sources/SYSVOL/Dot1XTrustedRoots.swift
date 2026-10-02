import Foundation
import Store

extension GroupPolicyEditor {
    /// Root migration (1 Oct 2026): rewrites the trusted roots of every published 802.1X profile
    /// (wireless and wired, Default Domain Policy) in place — `ServerValidation/TrustedRootCA` and
    /// the EAP-TLS client-issuer filter (`CAHashList/IssuerHash`) — for the profiles that list
    /// `anchor` (the old root): `adding` joins, `removing` leaves. The policy objects keep their
    /// GUIDs; the machine version is bumped once when anything changed, so joined PCs pick the
    /// change up at their next `gpupdate`. Returns the number of profiles rewritten.
    @discardableResult
    public func rewriteDot1XTrustedRoots(whereListed anchor: String, adding: [String], removing: [String]) async throws -> Int {
        var changed = 0
        for (container, attribute) in [("IEEE80211", "ms-net-ieee-80211-GP-PolicyData"), ("IEEE8023", "ms-net-ieee-8023-GP-PolicyData")] {
            guard let parent = try await store.read(dn: try await dot1XContainerDN(container)) else { continue }
            for child in try await store.children(of: parent.id) {
                guard let xml = child.string(attribute) else { continue }
                let rewritten = Dot1XPolicy.rewriteTrustedRoots(xml, whereListed: anchor, adding: adding, removing: removing)
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
