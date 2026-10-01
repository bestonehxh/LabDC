import Foundation
import MSPAC
import Store
import SYSVOL
import X509

extension PKIDirectory {
    /// Attributes left out of `describe` (bookkeeping every object has).
    static let hiddenAttributes: Set<String> = [
        "objectguid", "usncreated", "usnchanged", "whencreated", "whenchanged", "instancetype", "distinguishedname",
        "name", "objectcategory", "showinadvancedviewonly",
    ]

    /// `labdc pki show`: every object under `CN=Public Key Services`, attributes decoded the
    /// way `certutil -v -dstemplate` / `certutil -dump` render them (periods as `1 Years`, key
    /// usage bytes, flag words in hex, certificates by subject and SHA-1, the Enroll / AutoEnroll
    /// ACEs with account names).
    public static func describe(store: DirectoryStore) async throws -> [String] {
        let info = try await store.domainInfo()
        let base = publicKeyServicesDN(configurationDN: info.configurationDN)
        guard try await store.id(of: base) != nil else { return ["\(base): not present"] }
        var out: [String] = []
        let entries = try await store.search(base: base, scope: .subtree)
        for e in entries.sorted(by: { $0.dn.reversedKey < $1.dn.reversedKey }) {
            out.append("")
            out.append("[\(e.dn.rdn?.value ?? e.dn.description)] \(e.dn)")
            for a in e.attributes where !hiddenAttributes.contains(a.name.lowercased()) {
                for line in try await render(a.name, a.values, store: store) { out.append("  \(a.name) = \(line)") }
            }
        }
        return Array(out.dropFirst())
    }

    static func render(_ name: String, _ values: [[UInt8]], store: DirectoryStore) async throws -> [String] {
        func text(_ v: [UInt8]) -> String { String(decoding: v, as: UTF8.self) }
        switch name.lowercased() {
        case "cacertificate":
            return values.map { der in
                let subject = (try? Certificate(derEncoded: der)).map { "\($0.subject)" } ?? "?"
                return "\(subject) (sha1 \(CertificateBlob.thumbprint(der)), \(der.count) bytes)"
            }
        case "certificaterevocationlist", "authorityrevocationlist", "deltarevocationlist":
            return values.map { v in
                if v == [0] { return "00 (empty)" }
                guard let crl = try? CertificateRevocationList(derEncoded: v) else { return "\(v.count) bytes" }
                return "CRL #\(crl.crlNumber ?? 0), \(crl.entries.count) entries, next update "
                    + (crl.nextUpdate.map { $0.formatted(Date.ISO8601FormatStyle()) } ?? "-") + " (\(v.count) bytes)"
            }
        case "pkiexpirationperiod", "pkioverlapperiod":
            return values.map { "\"\(TemplateDirectory.describePeriod($0))\" (\(hex($0)))" }
        case "pkikeyusage":
            return values.map { "\"\(hex($0))\" \(TemplateDirectory.keyUsage(fromBytes: $0).names.joined(separator: ", "))" }
        case "flags", "mspki-enrollment-flag", "mspki-private-key-flag", "mspki-certificate-name-flag":
            return values.map { v in
                let n = Int64(text(v)) ?? 0
                return "\"\(n)\" 0x\(String(UInt32(truncatingIfNeeded: n), radix: 16))"
            }
        case "mspki-enrollment-servers":
            return values.map { text($0).replacingOccurrences(of: "\n", with: "\\n") }
        case "ntsecuritydescriptor":
            var lines: [String] = []
            for v in values {
                let sd = try SecurityDescriptor.decode(v)
                lines.append("owner \(try await account(sd.owner, store: store)), DACL\(sd.isDACLProtected ? " protected" : "")")
                for ace in sd.dacl ?? [] { lines.append("  " + (try await describe(ace, store: store))) }
            }
            return lines
        default:
            if DirectorySchema.syntax(of: name).isBinary { return values.map { hex($0) } }
            return values.map(text)
        }
    }

    static func describe(_ ace: DecodedACE, store: DirectoryStore) async throws -> String {
        let who = try await account(ace.sid, store: store)
        let verb = ace.isAllow ? "Allow" : "Deny"
        let right: String
        switch ace.objectType?.description.lowercased() {
        case TemplateDirectory.enrollRight: right = "Enroll"
        case TemplateDirectory.autoEnrollRight: right = "AutoEnroll"
        case let other?: right = "0x\(String(ace.mask, radix: 16)) on \(other)"
        case nil:
            let full: UInt32 = 0x000F_01FF, fullWithoutCR: UInt32 = 0x000F_00FF
            right = ace.mask & full == full ? "Full Control"
                : ace.mask == fullWithoutCR ? "Full Control except extended rights (no Enroll)"
                : ace.mask == 0x0002_0094 ? "Read" : "0x\(String(ace.mask, radix: 16))"
        }
        return "\(verb) \(right)\t\(who)"
    }

    /// `LABSHEEP\Domain Computers (S-1-5-21-…-515)`, or the well-known name.
    static func account(_ sid: SID?, store: DirectoryStore) async throws -> String {
        guard let sid else { return "-" }
        let wellKnown = ["S-1-5-11": "NT AUTHORITY\\Authenticated Users", "S-1-5-18": "NT AUTHORITY\\SYSTEM",
                         "S-1-1-0": "Everyone"]
        if let name = wellKnown[sid.description] { return "\(name) (\(sid))" }
        if let e = try await store.read(sid: sid, attrs: ["sAMAccountName"]), let sam = e.samAccountName {
            let info = try await store.domainInfo()
            return "\(info.netbiosDomain)\\\(sam) (\(sid))"
        }
        return sid.description
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined(separator: " ") }
}

extension DN {
    /// Sort key that lists parents before children.
    var reversedKey: String { normalized.split(separator: ",").reversed().joined(separator: ",") }
}
