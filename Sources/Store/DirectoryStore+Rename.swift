import Foundation
import KerberosCrypto

/// What a domain rename changed (owner request, 30 Sep 2026).
public struct DomainRenameResult: Sendable, Equatable {
    public var oldDNS: String
    public var newDNS: String
    /// Objects whose DN moved under the new base DN.
    public var objects: Int
    /// Stored attribute values rewritten (DN-valued and text values naming the domain).
    public var values: Int
    /// DNS rows whose zone, owner or RDATA target changed.
    public var dnsRecords: Int
    /// The DC's old FQDN (`dc.lab.sheep`), which DNS and the CRL/AIA web endpoint keep answering:
    /// certificates issued before the rename carry CRL and CA-issuer URLs naming it.
    public var formerDCName: String?
    /// GPOs whose version went up because their GPC or GPT files changed (SYSVOL side).
    public var gposUpdated: Int = 0
    /// Things that went wrong after the store was committed (SYSVOL files that could not be
    /// rewritten, …): the rename stands, but these need a look.
    public var warnings: [String] = []

    public init(oldDNS: String, newDNS: String, objects: Int, values: Int, dnsRecords: Int, formerDCName: String? = nil) {
        self.oldDNS = oldDNS
        self.newDNS = newDNS
        self.objects = objects
        self.values = values
        self.dnsRecords = dnsRecords
        self.formerDCName = formerDCName
    }

    /// Joined devices keep the old DNS suffix, realm and machine SPNs, so they rejoin (AD's own
    /// rename needs the same per-member step).
    public var devicesMustRejoin: Bool { true }

    public var summary: String {
        var text = "Renamed \(oldDNS) to \(newDNS): \(objects) objects, \(values) values, \(dnsRecords) DNS records"
            + (gposUpdated > 0 ? ", \(gposUpdated) GPO\(gposUpdated == 1 ? "" : "s") re-versioned" : "") + ". "
            + "Joined devices must leave and join \(newDNS) again."
        if let formerDCName {
            text += " \(formerDCName) still answers, so certificates issued before the rename keep reaching their CRL and CA certificate."
        }
        for w in warnings { text += " Warning: \(w)" }
        return text
    }
}

/// Rewrites one DNS domain name into another wherever it appears: DNs (suffix swap on parsed
/// DNs), `DC=…,DC=…` runs inside text (gPLink, fSMORoleOwner), dotted names in text (SPNs, UPNs,
/// dNSHostName, `\\domain\SysVol\domain\…` paths, the realm in upper case) and DNS wire-format
/// names. Matching is case-insensitive and bounded, so `notlab.sheep` or `lab.sheep.com` are left
/// alone. SYSVOL uses it for GPT files (30 Sep 2026).
public struct DomainNameRewriter: Sendable {
    public let oldDNS: String
    public let newDNS: String
    public let oldDN: DN
    public let newDN: DN
    private let oldLabels: [String]
    private let newLabels: [String]
    private let dotted: NSRegularExpression
    private let dcRun: NSRegularExpression

    public init(old: String, new: String) {
        oldDNS = old.lowercased()
        newDNS = new.lowercased()
        oldDN = DN(dnsDomain: oldDNS)
        newDN = DN(dnsDomain: newDNS)
        oldLabels = oldDNS.split(separator: ".").map(String.init)
        newLabels = newDNS.split(separator: ".").map(String.init)
        let bound = "A-Za-z0-9_\\-"
        dotted = try! NSRegularExpression(
            pattern: "(?<![\(bound)])" + NSRegularExpression.escapedPattern(for: oldDNS) + "(?![\(bound)]|\\.[A-Za-z0-9])",
            options: [.caseInsensitive])
        let run = oldLabels.map { "DC\\s*=\\s*" + NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "\\s*,\\s*")
        dcRun = try! NSRegularExpression(
            pattern: "(?<![\(bound)=])" + run + "(?![\(bound)]|\\s*[,;+]\\s*DC\\s*=)",
            options: [.caseInsensitive])
    }

    /// `dn` under the new base DN, or nil when it is not below the old one.
    public func rewrite(_ dn: DN) -> DN? {
        guard dn.isDescendant(of: oldDN) else { return nil }
        return DN(rdns: Array(dn.rdns.dropLast(oldDN.rdns.count)) + newDN.rdns)
    }

    /// `text` with every `DC=…` run and dotted spelling of the old domain replaced; nil when
    /// nothing matched. An all-upper match (the realm) stays upper case.
    public func rewrite(text: String) -> String? {
        var out = text
        var changed = false
        func replace(_ regex: NSRegularExpression, _ make: (String) -> String) {
            let ns = out as NSString
            let matches = regex.matches(in: out, range: NSRange(location: 0, length: ns.length))
            guard !matches.isEmpty else { return }
            var result = ""
            var cursor = 0
            for m in matches {
                result += ns.substring(with: NSRange(location: cursor, length: m.range.location - cursor))
                result += make(ns.substring(with: m.range))
                cursor = m.range.location + m.range.length
            }
            result += ns.substring(from: cursor)
            out = result
            changed = true
        }
        replace(dcRun) { match in
            let dc = match.hasPrefix("dc") ? "dc" : match.hasPrefix("Dc") ? "Dc" : "DC"
            return newLabels.map { "\(dc)=\($0)" }.joined(separator: ",")
        }
        replace(dotted) { match in
            match == match.uppercased() && match != match.lowercased() ? newDNS.uppercased() : newDNS
        }
        return changed ? out : nil
    }

    /// A DN string rewritten (parsed suffix swap, else the text rules); nil when unchanged.
    public func rewrite(dnString s: String) -> String? {
        if let dn = try? DN(string: s), !dn.isRoot {
            return rewrite(dn).map(\.description)
        }
        return rewrite(text: s)
    }

    /// A zone or owner name (`_msdcs.lab.sheep`, `pc1.lab.sheep.`) at or below the old domain.
    public func rewrite(dnsName s: String) -> String? {
        let trailing = s.hasSuffix(".")
        let body = trailing ? String(s.dropLast()) : s
        let lower = body.lowercased()
        if lower == oldDNS { return newDNS + (trailing ? "." : "") }
        guard lower.hasSuffix("." + oldDNS) else { return nil }
        return String(body.dropLast(oldDNS.count)) + newDNS + (trailing ? "." : "")
    }

    /// Uncompressed wire-format name at `offset`: the rewritten bytes and the offset after it.
    func rewrite(wireName bytes: [UInt8], at offset: Int) -> (bytes: [UInt8], end: Int, changed: Bool)? {
        var labels: [[UInt8]] = []
        var i = offset
        while true {
            guard i < bytes.count else { return nil }
            let n = Int(bytes[i])
            if n == 0 { i += 1; break }
            guard n < 64, i + 1 + n <= bytes.count else { return nil }    // no compression in storage
            labels.append(Array(bytes[(i + 1)..<(i + 1 + n)]))
            i += 1 + n
        }
        let old = oldLabels.map { Array($0.utf8) }
        var out = labels
        var changed = false
        if labels.count >= old.count,
           zip(labels.suffix(old.count), old).allSatisfy({ String(decoding: $0.0, as: UTF8.self).lowercased()
                                                          == String(decoding: $0.1, as: UTF8.self) }) {
            out = Array(labels.dropLast(old.count)) + newLabels.map { Array($0.utf8) }
            changed = true
        }
        var encoded: [UInt8] = []
        for l in out { encoded.append(UInt8(l.count)); encoded += l }
        encoded.append(0)
        return (encoded, i, changed)
    }

    /// RDATA of `type` with its target names rewritten (NS, CNAME, SOA, PTR, MX, SRV, DNAME);
    /// nil when unchanged or not a name-bearing type.
    public func rewrite(rdata: [UInt8], type: UInt16) -> [UInt8]? {
        func names(prefix: Int, count: Int) -> [UInt8]? {
            guard rdata.count >= prefix else { return nil }
            var out = Array(rdata[0..<prefix])
            var i = prefix
            var changed = false
            for _ in 0..<count {
                guard let r = rewrite(wireName: rdata, at: i) else { return nil }
                out += r.bytes
                i = r.end
                changed = changed || r.changed
            }
            out += rdata[i...]
            return changed ? out : nil
        }
        switch type {
        case 2, 5, 12, 39: return names(prefix: 0, count: 1)      // NS, CNAME, PTR, DNAME
        case 6: return names(prefix: 0, count: 2)                 // SOA mname, rname (+ 20 bytes kept)
        case 15: return names(prefix: 2, count: 1)                // MX preference
        case 33: return names(prefix: 6, count: 1)                // SRV priority, weight, port
        default: return nil
        }
    }
}

/// In-place domain rename (owner request, 30 Sep 2026): the DNS domain, realm and base DN become
/// editable. Every object's DN and normalised DN, every DN-valued attribute (fSMORoleOwner,
/// serverReference, defaultObjectCategory, objectCategory, gPLink, wellKnownObjects, …), text
/// values naming the domain (SPNs, UPNs, dNSHostName, dnsRoot, gPCFileSysPath), their match keys,
/// the `upn` column, the DNS zones/owners/RDATA targets and the `domain` table move to the new
/// name. Binary values (certificates, SIDs, security descriptors) are never touched. Linked
/// attributes (member/memberOf) are id-based and follow by themselves.
///
/// Keys stay as they are (AD semantics: a rename does not re-key accounts): the stored salt goes
/// on being announced in PA-ETYPE-INFO2, so AES and RC4 keep working with the same kvno until the
/// next password set derives a salt under the new realm. Joined devices still rejoin — their DNS
/// suffix, realm and machine SPNs name the old domain.
extension DirectoryStore {
    /// `domain` table key: the DC's FQDNs before renames, space separated.
    static let formerDCNamesKey = "formerDCNames"

    /// The DC's FQDNs from before domain renames (`dc.lab.sheep`), oldest first.
    public func formerDCHostNames() throws -> [String] {
        (try domainValue(forKey: Self.formerDCNamesKey) ?? "").split(separator: " ").map(String.init)
    }

    @discardableResult
    public func renameDomain(newDNS raw: String) throws -> DomainRenameResult {
        var new = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if new.hasSuffix(".") { new.removeLast() }
        let labels = new.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, new.count <= 253, labels.allSatisfy({ l in
            !l.isEmpty && l.count <= 63 && !l.hasPrefix("-") && !l.hasSuffix("-")
                && l.allSatisfy { ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" }
        }) else {
            throw StoreError.constraintViolation("'\(raw)' is not a valid domain name (two or more labels of letters, digits, hyphens)")
        }
        return try transaction {
            let info = try domainInfo()
            let old = info.dnsDomain.lowercased()
            var result = DomainRenameResult(oldDNS: old, newDNS: new, objects: 0, values: 0, dnsRecords: 0)
            guard old != new else { return result }
            let rw = DomainNameRewriter(old: old, new: new)

            // 0. Pin the salt of password-derived keys that relied on the realm default, so the
            //    KDC keeps announcing the salt they were made with.
            for r in try db.query("""
                SELECT s.object_id, o.sam_account_name FROM secrets s JOIN objects o ON o.id = s.object_id
                WHERE s.salt IS NULL AND (s.aes256 IS NOT NULL OR s.aes128 IS NOT NULL) AND o.sam_account_name IS NOT NULL
                """) {
                guard let id = r[0].int, let sam = r[1].text else { continue }
                try db.run("UPDATE secrets SET salt = ? WHERE object_id = ?",
                           [.text(KerberosCrypto.defaultSalt(realm: info.realm, principal: [sam])), .int(id)])
            }

            // 1. Objects: DN and dn_norm through the DN parser (dn_norm is lower case), two
            //    passes so the UNIQUE index never sees a transient clash.
            var moves: [(ObjectID, String, String)] = []
            for r in try db.query("SELECT id, dn, dn_norm FROM objects") {
                guard let id = r[0].int, let dn = r[1].text, let norm = r[2].text else { continue }
                if let parsed = try? DN(string: dn), !parsed.isRoot {
                    guard let moved = rw.rewrite(parsed) else { continue }
                    moves.append((id, moved.description, moved.normalized))
                } else if let text = rw.rewrite(text: dn) {
                    moves.append((id, text, rw.rewrite(text: norm)?.lowercased() ?? text.lowercased()))
                }
            }
            for (id, _, _) in moves {
                try db.run("UPDATE objects SET dn_norm = ? WHERE id = ?", [.text("#rename#\(id)"), .int(id)])
            }
            for (id, dn, norm) in moves {
                try db.run("UPDATE objects SET dn = ?, dn_norm = ? WHERE id = ?", [.text(dn), .text(norm), .int(id)])
            }
            result.objects = moves.count
            let oldFirst = String(old.split(separator: ".")[0]), newFirst = String(new.split(separator: ".")[0])
            let headNorm = rw.newDN.normalized
            if let head = try row(dnNorm: headNorm) {
                try db.run("UPDATE objects SET rdn_value = ? WHERE id = ?", [.text(newFirst), .int(head.id)])
                try db.run("UPDATE attributes SET value = ?, value_norm = ? WHERE object_id = ? AND name IN ('dc', 'name') "
                           + "AND lower(CAST(value AS TEXT)) = ? AND typeof(value) = 'blob'",
                           [.blob(Array(newFirst.utf8)), .text(newFirst), .int(head.id), .text(oldFirst)])
            }

            // 2. Stored values: DN syntaxes by parsed suffix swap, text by the bounded rules,
            //    match keys recomputed. Binary syntaxes (and anything not clean UTF-8) are skipped.
            for r in try db.query("SELECT rowid, name, value FROM attributes") {
                guard let rowid = r[0].int, let name = r[1].text else { continue }
                let syntax = DirectorySchema.syntax(of: name)
                guard !syntax.isBinary, case .blob(let bytes) = r[2], !bytes.contains(0),
                      let text = String(validating: bytes, as: UTF8.self) else { continue }
                let updated: String?
                switch syntax {
                case .dn:
                    updated = rw.rewrite(dnString: text)
                case .dnBinary:
                    // `B:<n>:<hex>:<dn>`
                    let parts = text.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
                    if parts.count == 4, let dn = rw.rewrite(dnString: String(parts[3])) {
                        updated = parts[0..<3].joined(separator: ":") + ":" + dn
                    } else {
                        updated = nil
                    }
                case .integer, .largeInteger, .boolean, .generalizedTime, .oid:
                    updated = nil
                default:
                    updated = rw.rewrite(text: text)
                }
                guard let updated else { continue }
                let value = Array(updated.utf8)
                try db.run("UPDATE attributes SET value = ?, value_norm = ? WHERE rowid = ?",
                           [.blob(value), .optional(DirectorySchema.storedNorm(value, name: name)), .int(rowid)])
                result.values += 1
            }
            for r in try db.query("SELECT id, upn FROM objects WHERE upn IS NOT NULL") {
                guard let id = r[0].int, let upn = r[1].text, let updated = rw.rewrite(text: upn) else { continue }
                try db.run("UPDATE objects SET upn = ? WHERE id = ?", [.text(updated), .int(id)])
            }

            // 3. The domain table (dcDNSName and friends), then the exact keys. The DC's old
            //    FQDN joins the former names (kept verbatim, never rewritten): certificates issued
            //    before the rename point their CDP/AIA at it, so DNS keeps answering it.
            let oldDCName = info.dcDNSName.lowercased()
            let newDCName = rw.rewrite(text: oldDCName) ?? oldDCName
            var former = try formerDCHostNames().filter { $0 != newDCName }
            if oldDCName != newDCName, !former.contains(oldDCName) { former.append(oldDCName) }
            for r in try db.query("SELECT key, value FROM domain") {
                guard let key = r[0].text, key != Self.formerDCNamesKey, let value = r[1].text,
                      let updated = rw.rewrite(text: value) else { continue }
                try setDomainValue(updated, forKey: key)
            }
            try setDomainValue(new, forKey: "dnsDomain")
            try setDomainValue(new.uppercased(), forKey: "realm")
            try setDomainValue(former.joined(separator: " "), forKey: Self.formerDCNamesKey)
            result.formerDCName = oldDCName != newDCName ? oldDCName : nil

            // 4. DNS: zones at or below the domain, absolute owners, and wire-format RDATA targets.
            for r in try db.query("SELECT id, zone, name, type, rdata FROM dns_records") {
                guard let id = r[0].int, let zone = r[1].text, let name = r[2].text, let type = r[3].int,
                      case .blob(let rdata) = r[4] else { continue }
                let z = rw.rewrite(dnsName: zone)
                let n = name.hasSuffix(".") ? rw.rewrite(dnsName: name) : nil
                let d = rw.rewrite(rdata: rdata, type: UInt16(truncatingIfNeeded: type))
                guard z != nil || n != nil || d != nil else { continue }
                try db.run("UPDATE dns_records SET zone = ?, name = ?, rdata = ? WHERE id = ?",
                           [.text(z ?? zone), .text(n ?? name), .blob(d ?? rdata), .int(id)])
                result.dnsRecords += 1
            }

            cachedInfo = try Self.loadInfo(db)
            sdCache = [:]
            _ = try nextUSN()
            Self.logger.notice("domain renamed \(old, privacy: .public) -> \(new, privacy: .public)")
            return result
        }
    }
}
