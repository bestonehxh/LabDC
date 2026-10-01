import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC
import SheepCrypto
import os

/// The on-disk format of `Scripts/principals.json`.
///
/// ```json
/// { "realm": "LAB.SHEEP", "domainSID": "S-1-5-21-…", "netbiosDomain": "LABSHEEP", "dcName": "DC1",
///   "principals": [
///     { "name": "krbtgt/LAB.SHEEP", "kind": "krbtgt" },                      // keys generated on first run
///     { "name": "host/dc1.lab.sheep", "kind": "service", "password": "…" },
///     { "name": "ldap/dc1.lab.sheep", "kind": "service", "aliasOf": "host/dc1.lab.sheep" },
///     { "name": "alice", "kind": "user", "password": "…", "rid": 1104, "groups": [513, 512] } ] }
/// ```
/// Every entry may also carry `kvno` (default 1), `etypes` (default `[18, 17, 23]`), `enabled`
/// (default true), `passwordSet` (ISO 8601), `upn` (users; default `name@dnsDomain`) and
/// `keys` (`[{"etype": 18, "hex": "…"}]`, used instead of `password`).
public struct PrincipalsFile: Codable, Sendable {
    public struct KeyEntry: Codable, Sendable {
        public var etype: Int32
        public var hex: String
    }

    public struct Entry: Codable, Sendable {
        public var name: String
        public var kind: String
        public var password: String?
        public var keys: [KeyEntry]?
        public var aliasOf: String?
        public var kvno: UInt32?
        public var rid: UInt32?
        public var groups: [UInt32]?
        public var upn: String?
        public var etypes: [Int32]?
        public var enabled: Bool?
        public var passwordSet: String?
    }

    public var realm: String
    public var domainSID: String
    public var netbiosDomain: String
    public var dcName: String
    public var dnsDomain: String?
    public var principals: [Entry]
}

/// A `PrincipalStore` loaded from a JSON file (see `PrincipalsFile`).
///
/// At load time it derives AES and RC4 keys from passwords with the RFC 4120 default salt
/// (realm + name components). A krbtgt entry without keys gets random keys for every enctype,
/// which are written back to the file (mode 0600) so tickets survive a restart.
public actor JSONPrincipalStore: PrincipalStore {
    public nonisolated let realm: String
    public nonisolated let domainSID: SID
    public nonisolated let netbiosDomain: String
    public nonisolated let dcName: String
    public nonisolated let dnsDomain: String
    /// Where the file was loaded from (nil when built from bytes).
    public nonisolated let url: URL?
    /// True when this load generated krbtgt keys (and wrote them back if `url` is set).
    public nonisolated let generatedKeys: Bool

    private let principals: [Principal]

    private static let logger = Logger(subsystem: "dev.labdc.app", category: "KDC")

    /// Loads `url`; generates and persists missing krbtgt keys.
    public init(contentsOf url: URL, rng: RandomBytes = RandomBytes()) throws {
        let data: Data
        do { data = try Data(contentsOf: url) } catch {
            throw KDCError.io("cannot read \(url.path): \(error.localizedDescription)")
        }
        try self.init(data: data, url: url, rng: rng)
    }

    /// Builds the store from JSON bytes without touching the file system.
    public init(json: Data, rng: RandomBytes = RandomBytes()) throws {
        try self.init(data: json, url: nil, rng: rng)
    }

    private init(data: Data, url: URL?, rng: RandomBytes) throws {
        var file: PrincipalsFile
        do { file = try JSONDecoder().decode(PrincipalsFile.self, from: data) } catch {
            throw KDCError.invalidConfiguration("JSON: \(error)")
        }
        let generated = try Self.generateMissingKrbtgtKeys(&file, rng: rng)
        let (principals, info) = try Self.load(file)
        self.realm = info.realm
        self.domainSID = info.domainSID
        self.netbiosDomain = info.netbiosDomain
        self.dcName = info.dcName
        self.dnsDomain = info.dnsDomain
        self.principals = principals
        self.url = url
        self.generatedKeys = generated
        if generated, let url {
            try Self.write(file, to: url)
            Self.logger.notice("generated krbtgt keys and wrote them to \(url.path, privacy: .public)")
        }
    }

    public func principal(_ name: PrincipalName, realm: String) async throws -> Principal? {
        guard realm.caseInsensitiveCompare(self.realm) == .orderedSame else { return nil }
        return principals.first { $0.name.matchesIgnoringCase(name) }
    }

    public func allPrincipals() async throws -> [Principal] { principals }

    // MARK: - Loading

    private struct RealmInfo {
        var realm: String
        var domainSID: SID
        var netbiosDomain: String
        var dcName: String
        var dnsDomain: String
    }

    static func splitName(_ name: String) -> [String] {
        name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    }

    private static func load(_ file: PrincipalsFile) throws -> ([Principal], RealmInfo) {
        let realm = file.realm.uppercased()
        guard !realm.isEmpty else { throw KDCError.invalidConfiguration("realm is empty") }
        let domainSID: SID
        do { domainSID = try SID(string: file.domainSID) } catch {
            throw KDCError.invalidConfiguration("domainSID: \(error)")
        }
        let info = RealmInfo(realm: realm, domainSID: domainSID, netbiosDomain: file.netbiosDomain.uppercased(),
                             dcName: file.dcName.uppercased(), dnsDomain: (file.dnsDomain ?? realm).lowercased())

        // Two passes: real accounts first, then aliases that borrow their keys.
        var byName: [String: Principal] = [:]
        var result: [Principal?] = Array(repeating: nil, count: file.principals.count)
        for (i, entry) in file.principals.enumerated() where entry.aliasOf == nil {
            let p = try principal(from: entry, info: info)
            guard byName[entry.name.lowercased()] == nil else {
                throw KDCError.invalidConfiguration("duplicate principal \(entry.name)")
            }
            byName[entry.name.lowercased()] = p
            result[i] = p
        }
        for (i, entry) in file.principals.enumerated() {
            guard let target = entry.aliasOf else { continue }
            guard var p = byName[target.lowercased()] else {
                throw KDCError.invalidConfiguration("\(entry.name): aliasOf unknown principal \(target)")
            }
            p.name = try principalName(entry.name, kind: p.kind)
            result[i] = p
        }
        let principals = result.compactMap { $0 }
        guard principals.contains(where: { $0.name.isKrbtgt(realm: realm) }) else {
            throw KDCError.invalidConfiguration("no krbtgt/\(realm) principal")
        }
        return (principals, info)
    }

    private static func principalName(_ name: String, kind: Principal.Kind) throws -> PrincipalName {
        let parts = splitName(name)
        guard !parts.isEmpty, !parts.contains(where: \.isEmpty) else {
            throw KDCError.invalidConfiguration("bad principal name '\(name)'")
        }
        let type: Int32 = switch kind {
        case .user, .computer: NameType.principal
        case .krbtgt: NameType.srvInst
        case .service: parts.count == 2 ? NameType.srvHst : NameType.principal
        }
        return PrincipalName(nameType: type, nameString: parts)
    }

    private static func enctypes(_ entry: PrincipalsFile.Entry) throws -> [EncryptionType] {
        guard let raw = entry.etypes else { return KDCPolicy.enctypePreference }
        return try raw.map {
            guard let t = EncryptionType(rawValue: $0) else {
                throw KDCError.invalidConfiguration("\(entry.name): unsupported etype \($0)")
            }
            return t
        }
    }

    private static func principal(from entry: PrincipalsFile.Entry, info: RealmInfo) throws -> Principal {
        let parts = splitName(entry.name)
        let kind: Principal.Kind
        switch entry.kind.lowercased() {
        case "user", "computer":
            guard let rid = entry.rid else { throw KDCError.invalidConfiguration("\(entry.name): \(entry.kind) needs a rid") }
            guard parts.count == 1 else {
                throw KDCError.invalidConfiguration("\(entry.name): \(entry.kind) names have one component")
            }
            let sid: SID
            do { sid = try info.domainSID.appending(rid: rid) } catch {
                throw KDCError.invalidConfiguration("\(entry.name): \(error)")
            }
            let groups = entry.groups ?? [513]
            if entry.kind.lowercased() == "user" {
                kind = .user(sid: sid, upn: entry.upn ?? "\(parts[0])@\(info.dnsDomain)", samName: parts[0], groups: groups)
            } else {
                kind = .computer(sid: sid, samName: parts[0], groups: groups)
            }
        case "service": kind = .service
        case "krbtgt":
            guard PrincipalName(nameType: NameType.srvInst, nameString: parts).isKrbtgt(realm: info.realm) else {
                throw KDCError.invalidConfiguration("\(entry.name): krbtgt must be named krbtgt/\(info.realm)")
            }
            kind = .krbtgt
        default:
            throw KDCError.invalidConfiguration("\(entry.name): unknown kind '\(entry.kind)'")
        }
        let name = try principalName(entry.name, kind: kind)
        let types = try enctypes(entry)
        var keys: [KerberosKey] = []
        var salt: String?
        if let stored = entry.keys, !stored.isEmpty {
            for k in stored {
                guard let t = EncryptionType(rawValue: k.etype) else {
                    throw KDCError.invalidConfiguration("\(entry.name): unsupported key etype \(k.etype)")
                }
                guard types.contains(t) else { continue }
                guard k.hex.count.isMultiple(of: 2), k.hex.allSatisfy(\.isHexDigit) else {
                    throw KDCError.invalidConfiguration("\(entry.name): key for etype \(k.etype) is not hex")
                }
                let bytes = [UInt8](hex: k.hex)
                do { keys.append(try KerberosKey(type: t, bytes: bytes)) } catch {
                    throw KDCError.invalidConfiguration("\(entry.name): \(error)")
                }
            }
        } else if let password = entry.password {
            let s = KerberosCrypto.defaultSalt(realm: info.realm, principal: parts)
            salt = s
            for t in types {
                do {
                    keys.append(try KerberosCrypto.stringToKey(t, password: password, salt: s, parameters: nil))
                } catch {
                    throw KDCError.invalidConfiguration("\(entry.name): \(error)")
                }
            }
        } else {
            throw KDCError.invalidConfiguration("\(entry.name): needs a password or keys")
        }
        guard !keys.isEmpty else { throw KDCError.invalidConfiguration("\(entry.name): no usable keys") }
        var passwordSet = Date(timeIntervalSince1970: 0)
        if let text = entry.passwordSet {
            guard let d = ISO8601DateFormatter().date(from: text) else {
                throw KDCError.invalidConfiguration("\(entry.name): passwordSet '\(text)' is not ISO 8601")
            }
            passwordSet = d
        }
        return Principal(name: name, realm: info.realm, keys: keys, kvno: entry.kvno ?? 1, kind: kind,
                         passwordSet: passwordSet, enabled: entry.enabled ?? true, salt: salt)
    }

    /// Fills in random keys for krbtgt entries that have neither keys nor a password.
    private static func generateMissingKrbtgtKeys(_ file: inout PrincipalsFile, rng: RandomBytes) throws -> Bool {
        var generated = false
        for i in file.principals.indices where file.principals[i].kind.lowercased() == "krbtgt" {
            let e = file.principals[i]
            guard (e.keys ?? []).isEmpty, e.password == nil, e.aliasOf == nil else { continue }
            let types = try enctypes(e)
            file.principals[i].keys = types.map {
                PrincipalsFile.KeyEntry(etype: $0.rawValue, hex: KerberosCrypto.randomKey($0, rng: rng).bytes.hex)
            }
            if file.principals[i].kvno == nil { file.principals[i].kvno = 1 }
            if file.principals[i].passwordSet == nil {
                file.principals[i].passwordSet = ISO8601DateFormatter().string(from: Date())
            }
            generated = true
        }
        return generated
    }

    /// Encodes the file the way it is committed: pretty, sorted keys, unescaped slashes.
    public static func encode(_ file: PrincipalsFile) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(file) + Data("\n".utf8) } catch {
            throw KDCError.invalidConfiguration("cannot encode: \(error)")
        }
    }

    private static func write(_ file: PrincipalsFile, to url: URL) throws {
        let data = try encode(file)
        do {
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw KDCError.io("cannot write \(url.path): \(error.localizedDescription)")
        }
    }
}
