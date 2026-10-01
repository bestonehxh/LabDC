import AuthKit
import KerberosCrypto
import MSPAC
import Store

/// `AuthSecretSource` over a provisioned `DirectoryStore`: NT hashes and identities by
/// sAMAccountName (disabled accounts are unknown), service keys by SPN (`host/`, `ldap/`,
/// `GC/` and every other `servicePrincipalName`, plus `NAME$`), identities from the PAC.
public struct StoreSecretSource: AuthSecretSource {
    public let store: DirectoryStore
    public let netbiosDomain: String
    public let dnsDomain: String
    public let dcName: String

    /// Reads the realm values of a provisioned store.
    public init(store: DirectoryStore) async throws {
        guard await store.isProvisioned else { throw DirectoryKitError.notProvisioned }
        let info = try await store.domainInfo()
        self.store = store
        netbiosDomain = info.netbiosDomain
        dnsDomain = info.dnsDomain
        dcName = info.dcName
    }

    public func ntHash(forSAM sam: String) async -> (hash: [UInt8], identity: AuthenticatedIdentity)? {
        guard let entry = await account(sam),
              let uac = entry.int("userAccountControl"), UInt32(truncatingIfNeeded: uac) & UserAccountControl.accountDisable == 0,
              let hash = try? await store.secrets(id: entry.id)?.ntHash,
              let identity = await identity(of: entry) else { return nil }
        return (hash, identity)
    }

    public func serviceKeys(forSPN spn: String) async -> [KerberosKey] {
        let components = spn.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard let (account, _) = try? await store.kerberosAccount(components: components, realm: realm) else { return [] }
        return account.keys
    }

    public func identity(forSAM sam: String) async -> AuthenticatedIdentity? {
        guard let entry = await account(sam) else { return nil }
        return await identity(of: entry)
    }

    private func account(_ sam: String) async -> DirectoryEntry? {
        if let e = try? await store.read(sam: sam) { return e }
        return try? await store.read(sam: sam + "$")
    }

    /// The identity of a stored account: SID, sAMAccountName, NetBIOS domain and its
    /// transitive group SIDs (domain and builtin).
    public func identity(of entry: DirectoryEntry) async -> AuthenticatedIdentity? {
        guard let sid = entry.sid, let sam = entry.samAccountName else { return nil }
        let groups = (try? await store.groupSIDs(of: entry.id)) ?? []
        return AuthenticatedIdentity(sid: sid, sam: sam, domain: netbiosDomain, groups: groups,
                                     principal: "\(sam)@\(realm)")
    }
}
