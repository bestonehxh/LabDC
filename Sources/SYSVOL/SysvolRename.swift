import Foundation
import Store

/// Domain rename, SYSVOL side (30 Sep 2026): `<root>/<old dnsDomain>` moves to
/// `<root>/<new dnsDomain>` so GPO customisations and logon scripts survive, and GPT / script
/// files that spell the old domain (UNC paths, DN runs) are rewritten in their own encoding.
public enum SysvolRename {
    /// Text files rewritten in place (UTF-8, or UTF-16LE with a BOM as GptTmpl.inf is).
    static let textExtensions: Set<String> = ["ini", "inf", "xml", "bat", "cmd", "ps1", "vbs", "js", "txt", "kix", "aas"]

    /// Moves the domain folder; returns true when one was moved (false: no old folder, the
    /// next `SysvolLayout.ensure` creates the new one). Throws when the new folder already
    /// holds something.
    @discardableResult
    public static func moveDomainFolder(root: URL, from old: String, to new: String) throws -> Bool {
        let fm = FileManager.default
        let names = (try? fm.contentsOfDirectory(atPath: root.path)) ?? []
        guard let current = names.first(where: { $0.caseInsensitiveCompare(old) == .orderedSame }) else { return false }
        let source = root.appendingPathComponent(current, isDirectory: true)
        let target = root.appendingPathComponent(new.lowercased(), isDirectory: true)
        if current.caseInsensitiveCompare(new) == .orderedSame { return false }
        if fm.fileExists(atPath: target.path) {
            let inside = (try? fm.contentsOfDirectory(atPath: target.path)) ?? []
            guard inside.isEmpty else {
                throw SysvolError.unexpectedItem("\(target.path) already exists; move it away before renaming the domain")
            }
            try fm.removeItem(at: target)
        }
        do {
            try fm.moveItem(at: source, to: target)
        } catch {
            throw SysvolError.filesystem("cannot move \(source.path) to \(target.path): \(error.localizedDescription)")
        }
        return true
    }

    /// What `rewriteAll` did: files rewritten and files that needed a rewrite but could not be
    /// written (relative path → why), both relative to the SYSVOL root.
    public struct RewriteReport: Sendable, Equatable {
        public var changed: [String] = []
        public var failed: [String: String] = [:]
    }

    /// Rewrites the old domain in the text files and `Registry.pol` string values below
    /// `<root>/<new>`. Returns the relative paths changed; unreadable files are left alone.
    /// Throws on the first file that cannot be written (`rewriteAll` goes on and reports).
    @discardableResult
    public static func rewriteReferences(root: URL, rewriter rw: DomainNameRewriter) throws -> [String] {
        let report = rewriteAll(root: root, rewriter: rw)
        if let (path, why) = report.failed.sorted(by: { $0.key < $1.key }).first {
            throw SysvolError.filesystem("cannot rewrite \(path): \(why)")
        }
        return report.changed
    }

    /// `rewriteReferences` that never stops at a failed file: every other file is still
    /// rewritten, and the failures come back by path.
    public static func rewriteAll(root: URL, rewriter rw: DomainNameRewriter) -> RewriteReport {
        let fm = FileManager.default
        let base = root.appendingPathComponent(rw.newDNS, isDirectory: true)
        var report = RewriteReport()
        guard let walker = fm.enumerator(at: base, includingPropertiesForKeys: [.isRegularFileKey]) else { return report }
        for case let url as URL in walker {
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true,
                  let data = fm.contents(atPath: url.path) else { continue }
            let ext = url.pathExtension.lowercased()
            let updated: [UInt8]?
            if ext == "pol" {
                updated = rewritePolicyFile(Array(data), rw)
            } else if textExtensions.contains(ext) {
                updated = rewriteText(Array(data), rw)
            } else {
                updated = nil
            }
            guard let updated else { continue }
            let relative = relativePath(url, under: root)
            let perms = (try? fm.attributesOfItem(atPath: url.path))?[.posixPermissions]
            do {
                try Data(updated).write(to: url, options: .atomic)
            } catch {
                report.failed[relative] = error.localizedDescription
                continue
            }
            if let perms { try? fm.setAttributes([.posixPermissions: perms], ofItemAtPath: url.path) }
            report.changed.append(relative)
        }
        return report
    }

    /// `url` relative to `root`, even when the enumerator spells it through a resolved symlink
    /// (`/private/var/…` for a root under `/var/…`).
    static func relativePath(_ url: URL, under root: URL) -> String {
        let base = root.resolvingSymlinksInPath().path
        let path = url.resolvingSymlinksInPath().path
        return path.hasPrefix(base + "/") ? String(path.dropFirst(base.count + 1)) : String(url.path.dropFirst(root.path.count + 1))
    }

    /// After a rename every GPO's GPC changed (its DN and `gPCFileSysPath` name the new domain),
    /// and some GPT files may have too, so clients must see a new version: both halves of each
    /// GPO's version go up by one, written the same to `versionNumber` and GPT.INI (container
    /// first, then the file — MS-GPOL §3.3.5.2/§3.3.5.4). Returns the GPO GUIDs bumped.
    @discardableResult
    public static func bumpGPOVersions(root: URL, store: DirectoryStore) async throws -> [String] {
        let info = try await store.domainInfo()
        let gpcs = try await store.search(base: DefaultGPO.policiesDN(domainDN: info.domainDN), scope: .oneLevel,
                                          filter: .equality(attribute: "objectClass", value: Array("groupPolicyContainer".utf8)),
                                          attrs: ["cn", "displayName", "versionNumber"])
        let policies = root.appendingPathComponent(info.dnsDomain, isDirectory: true)
            .appendingPathComponent("Policies", isDirectory: true)
        var bumped: [String] = []
        for gpc in gpcs {
            guard let guid = gpc.string("cn") else { continue }
            let folder = GroupPolicyEditor.child(of: policies, named: guid) ?? policies.appendingPathComponent(guid, isDirectory: true)
            let iniURL = GroupPolicyEditor.child(of: folder, named: "GPT.INI") ?? folder.appendingPathComponent("GPT.INI")
            let iniBytes = GroupPolicyEditor.readFile(iniURL)
            var ini = GPTIni(bytes: iniBytes ?? [])
            let container = gpc.string("versionNumber").flatMap(GPOVersion.init(text:)) ?? GPOVersion()
            let version = GPOVersion.newest(container, ini.version).bumped(machine: true, user: true)
            try await store.update(id: gpc.id, ops: [.replace("versionNumber", strings: [version.directoryText])])
            if iniBytes != nil || FileManager.default.fileExists(atPath: folder.path) {
                ini.version = version
                if ini.displayName == nil { ini.displayName = gpc.string("displayName") }
                try GroupPolicyEditor.writeFile(iniURL, ini.encoded)
            }
            bumped.append(guid)
        }
        return bumped
    }

    /// UTF-16LE (BOM) or UTF-8 text with the domain rewritten; nil when unchanged or binary.
    static func rewriteText(_ bytes: [UInt8], _ rw: DomainNameRewriter) -> [UInt8]? {
        if bytes.count >= 2, bytes[0] == 0xFF, bytes[1] == 0xFE {
            var units: [UInt16] = []
            var i = 2
            while i + 1 < bytes.count { units.append(UInt16(bytes[i]) | UInt16(bytes[i + 1]) << 8); i += 2 }
            guard let text = String(validating: units, as: UTF16.self), let out = rw.rewrite(text: text) else { return nil }
            var encoded: [UInt8] = [0xFF, 0xFE]
            for u in out.utf16 { encoded += [UInt8(u & 0xFF), UInt8(u >> 8)] }
            return encoded
        }
        guard !bytes.contains(0), let text = String(validating: bytes, as: UTF8.self),
              let out = rw.rewrite(text: text) else { return nil }
        return Array(out.utf8)
    }

    /// `Registry.pol` with REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ data rewritten.
    static func rewritePolicyFile(_ bytes: [UInt8], _ rw: DomainNameRewriter) -> [UInt8]? {
        guard var file = try? RegistryPolicyFile(bytes: bytes) else { return nil }
        var changed = false
        for (i, e) in file.entries.enumerated() {
            switch e.type {
            case .sz?, .expandSz?:
                guard let out = rw.rewrite(text: RegistryPolicyFile.decodeUTF16(e.data)) else { continue }
                file.entries[i].data = RegistryPolicyFile.utf16z(out)
                changed = true
            case .multiSz?:
                var units: [UInt16] = []
                var j = 0
                while j + 1 < e.data.count { units.append(UInt16(e.data[j]) | UInt16(e.data[j + 1]) << 8); j += 2 }
                let parts = units.split(separator: 0, omittingEmptySubsequences: true).map { String(decoding: $0, as: UTF16.self) }
                let rewritten = parts.map { rw.rewrite(text: $0) ?? $0 }
                guard rewritten != parts else { continue }
                file.entries[i].data = rewritten.flatMap(RegistryPolicyFile.utf16z) + [0, 0]
                changed = true
            default:
                continue
            }
        }
        return changed ? try? file.encoded() : nil
    }
}
