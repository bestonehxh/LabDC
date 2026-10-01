import Foundation
import MSPAC

/// Self-relative security descriptors (MS-DTYP §2.4.6) built from a subset of SDDL
/// (MS-DTYP §2.5.1): `O:`, `G:`, `D:` with `P`/`AI`/`AR` flags, ACE types `A`, `D`, `OA`, `OD`,
/// the common ACE flags and rights, SID aliases and literal `S-1-...` SIDs. No SACL.
public enum SecurityDescriptor {
    /// Default `nTSecurityDescriptor` SDDL per structural class (a simplification of the
    /// schema's `defaultSecurityDescriptor` values; see docs/notes/wp-f.md).
    public static func defaultSDDL(for objectClass: String) -> String {
        let full = "RPWPCRCCDCLCLORCWOWDSDDTSW"
        switch objectClass.lowercased() {
        case "user":
            return "O:DAG:DUD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;\(full);;;AO)(A;;RPLCLORC;;;AU)"
                + "(A;;RPLCLORC;;;PS)(OA;;CR;\(changePassword);;PS)(OA;;CR;\(changePassword);;WD)(A;;RC;;;WD)"
        case "computer":
            return "O:DAG:DCD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;\(full);;;AO)(A;;RPLCLORC;;;AU)"
                + "(A;;RPLCLORC;;;PS)(OA;;CR;\(changePassword);;PS)(OA;;SW;\(validatedSPN);;PS)"
                + "(OA;;SW;\(validatedDNSHostName);;PS)"
        case "group":
            return "O:DAG:DAD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;\(full);;;AO)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;PS)"
        case "domaindns":
            return "O:BAG:BAD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;\(full);;;EA)(A;;\(full);;;BA)"
                + "(A;;RPLCLORC;;;AU)(A;;RP;;;WD)(OA;;CR;\(replicationGetChanges);;ED)(OA;;CR;\(replicationGetChangesAll);;ED)"
        case "organizationalunit":
            return "O:DAG:DAD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;RPLCLORC;;;AU)(A;;CCDC;;;AO)"
        case "configuration", "dmd", "classschema", "attributeschema", "subschema", "crossref",
             "crossrefcontainer", "site", "sitescontainer", "serverscontainer", "server", "ntdsdsa",
             "ntdssitesettings", "subnetcontainer", "ntdsservice":
            return "O:EAG:EAD:AI(A;;\(full);;;SY)(A;;\(full);;;EA)(A;;\(full);;;DA)(A;;RPLCLORC;;;AU)"
        default:
            return "O:DAG:DAD:AI(A;;\(full);;;SY)(A;;\(full);;;DA)(A;;RPLCLORC;;;AU)"
        }
    }

    /// User-Change-Password extended right.
    static let changePassword = "ab721a53-1e2f-11d0-9819-00aa0040529b"
    /// Validated-SPN.
    static let validatedSPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
    /// Validated-DNS-Host-Name.
    static let validatedDNSHostName = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
    /// DS-Replication-Get-Changes / -All.
    static let replicationGetChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    static let replicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

    private static let rights: [String: UInt32] = [
        "GA": 0x1000_0000, "GX": 0x2000_0000, "GW": 0x4000_0000, "GR": 0x8000_0000,
        "SD": 0x0001_0000, "RC": 0x0002_0000, "WD": 0x0004_0000, "WO": 0x0008_0000,
        "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
    ]
    private static let aceFlags: [String: UInt8] = ["OI": 0x01, "CI": 0x02, "NP": 0x04, "IO": 0x08, "ID": 0x10]

    private static let wellKnown: [String: String] = [
        "WD": "S-1-1-0", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4", "NU": "S-1-5-2", "IU": "S-1-5-4",
        "SU": "S-1-5-6", "AN": "S-1-5-7", "ED": "S-1-5-9", "PS": "S-1-5-10", "AU": "S-1-5-11", "SY": "S-1-5-18",
        "LS": "S-1-5-19", "NS": "S-1-5-20", "BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546",
        "PU": "S-1-5-32-547", "AO": "S-1-5-32-548", "SO": "S-1-5-32-549", "PO": "S-1-5-32-550",
        "BO": "S-1-5-32-551", "RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "RD": "S-1-5-32-555",
        "NO": "S-1-5-32-556",
    ]
    private static let domainRelative: [String: UInt32] = [
        "RO": 498, "LA": 500, "LG": 501, "DA": 512, "DU": 513, "DG": 514, "DC": 515, "DD": 516,
        "CA": 517, "SA": 518, "EA": 519, "PA": 520, "RS": 553,
    ]

    /// Resolves an SDDL SID string (alias or `S-1-...`).
    static func sid(_ token: String, domainSID: SID) throws -> SID {
        if let s = wellKnown[token] { return try SID(string: s) }
        if let rid = domainRelative[token] { return try domainSID.appending(rid: rid) }
        do { return try SID(string: token) } catch {
            throw StoreError.constraintViolation("SDDL: unknown SID '\(token)'")
        }
    }

    /// Builds the self-relative binary form: header, owner, group, DACL.
    public static func fromSDDL(_ sddl: String, domainSID: SID) throws -> [UInt8] {
        var owner: SID?, group: SID?, dacl: [UInt8]?, control: UInt16 = 0x8000  // SE_SELF_RELATIVE
        for (tag, body) in try sections(sddl) {
            switch tag {
            case "O": owner = try sid(body, domainSID: domainSID)
            case "G": group = try sid(body, domainSID: domainSID)
            case "D":
                control |= 0x0004  // SE_DACL_PRESENT
                let (flags, aces) = try splitACL(body)
                if flags.contains("P") { control |= 0x1000 }
                if flags.contains("AI") { control |= 0x0400 }
                if flags.contains("AR") { control |= 0x0100 }
                dacl = try acl(aces, domainSID: domainSID)
            default:
                throw StoreError.constraintViolation("SDDL: unsupported section '\(tag):'")
            }
        }
        var out = [UInt8](repeating: 0, count: 20)
        out[0] = 1
        func put32(_ v: Int, at i: Int) { for k in 0..<4 { out[i + k] = UInt8(truncatingIfNeeded: v >> (8 * k)) } }
        if let owner { put32(out.count, at: 4); out += owner.bytes }
        if let group { put32(out.count, at: 8); out += group.bytes }
        if let dacl { put32(out.count, at: 16); out += dacl }
        out[2] = UInt8(control & 0xFF)
        out[3] = UInt8(control >> 8)
        return out
    }

    private static func sections(_ sddl: String) throws -> [(String, String)] {
        let chars = Array(sddl)
        var result: [(String, String)] = []
        var i = 0, depth = 0, current: String?, start = 0
        while i < chars.count {
            let c = chars[i]
            if c == "(" { depth += 1 } else if c == ")" { depth -= 1 }
            if depth == 0, i + 1 < chars.count, chars[i + 1] == ":", "OGDS".contains(c) {
                if let current { result.append((current, String(chars[start..<i]))) }
                current = String(c)
                start = i + 2
                i += 2
                continue
            }
            i += 1
        }
        guard let current else { throw StoreError.constraintViolation("SDDL: no sections in '\(sddl)'") }
        result.append((current, String(chars[start...])))
        return result
    }

    private static func splitACL(_ body: String) throws -> ([String], [String]) {
        guard let open = body.firstIndex(of: "(") else { return (flagTokens(body), []) }
        let flags = flagTokens(String(body[..<open]))
        var aces: [String] = []
        var rest = body[open...]
        while let o = rest.firstIndex(of: "("), let c = rest.firstIndex(of: ")") {
            aces.append(String(rest[rest.index(after: o)..<c]))
            rest = rest[rest.index(after: c)...]
        }
        return (flags, aces)
    }

    private static func flagTokens(_ s: String) -> [String] {
        var out: [String] = []
        var rest = Substring(s)
        while !rest.isEmpty {
            if rest.hasPrefix("AI") || rest.hasPrefix("AR") { out.append(String(rest.prefix(2))); rest = rest.dropFirst(2) }
            else { out.append(String(rest.prefix(1))); rest = rest.dropFirst() }
        }
        return out
    }

    private static func pairs(_ s: String) -> [String] {
        var out: [String] = []
        var rest = Substring(s)
        while rest.count >= 2 { out.append(String(rest.prefix(2))); rest = rest.dropFirst(2) }
        return out
    }

    private static func acl(_ aces: [String], domainSID: SID) throws -> [UInt8] {
        var body: [UInt8] = []
        var hasObjectACE = false
        for ace in aces {
            let f = ace.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
            guard f.count == 6 else { throw StoreError.constraintViolation("SDDL: bad ACE '\(ace)'") }
            let type: UInt8
            switch f[0] {
            case "A": type = 0x00
            case "D": type = 0x01
            case "OA": type = 0x05
            case "OD": type = 0x06
            default: throw StoreError.constraintViolation("SDDL: unsupported ACE type '\(f[0])'")
            }
            var flags: UInt8 = 0
            for t in pairs(f[1]) {
                guard let v = aceFlags[t] else { throw StoreError.constraintViolation("SDDL: ACE flag '\(t)'") }
                flags |= v
            }
            var mask: UInt32 = 0
            if f[2].hasPrefix("0x"), let v = UInt32(f[2].dropFirst(2), radix: 16) {
                mask = v
            } else {
                for t in pairs(f[2]) {
                    guard let v = rights[t] else { throw StoreError.constraintViolation("SDDL: right '\(t)'") }
                    mask |= v
                }
            }
            var ace: [UInt8] = [type, flags, 0, 0]
            ace += le32(mask)
            if type == 0x05 || type == 0x06 {
                hasObjectACE = true
                var objFlags: UInt32 = 0
                var guids: [UInt8] = []
                if !f[3].isEmpty {
                    guard let g = GUID(string: f[3]) else { throw StoreError.constraintViolation("SDDL: GUID '\(f[3])'") }
                    objFlags |= 1
                    guids += g.bytes
                }
                if !f[4].isEmpty {
                    guard let g = GUID(string: f[4]) else { throw StoreError.constraintViolation("SDDL: GUID '\(f[4])'") }
                    objFlags |= 2
                    guids += g.bytes
                }
                ace += le32(objFlags) + guids
            }
            ace += try sid(f[5], domainSID: domainSID).bytes
            ace[2] = UInt8(ace.count & 0xFF)
            ace[3] = UInt8(ace.count >> 8)
            body += ace
        }
        let size = 8 + body.count
        // ACL_REVISION_DS (4) when object ACEs are present, ACL_REVISION (2) otherwise.
        return [hasObjectACE ? 4 : 2, 0, UInt8(size & 0xFF), UInt8(size >> 8),
                UInt8(aces.count & 0xFF), UInt8(aces.count >> 8), 0, 0] + body
    }

    private static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]
    }
}

// MARK: - Decoding (PK-5)

/// One ACE of a decoded DACL (MS-DTYP §2.4.4). Object ACEs (types 5/6) carry their GUIDs.
public struct DecodedACE: Sendable, Hashable, CustomStringConvertible {
    /// 0 ACCESS_ALLOWED, 1 ACCESS_DENIED, 5 ACCESS_ALLOWED_OBJECT, 6 ACCESS_DENIED_OBJECT, ….
    public var type: UInt8
    public var flags: UInt8
    public var mask: UInt32
    public var objectType: GUID?
    public var inheritedObjectType: GUID?
    public var sid: SID

    public var isAllow: Bool { type == 0x00 || type == 0x05 }

    /// SDDL-like: `(OA;;0x100;0e10c968-…;;S-1-5-21-…-515)`.
    public var description: String {
        let kind = switch type {
        case 0x00: "A"
        case 0x01: "D"
        case 0x05: "OA"
        case 0x06: "OD"
        default: String(format: "type 0x%02x", type)
        }
        return "(\(kind);\(flags == 0 ? "" : String(format: "0x%02x", flags));\(String(format: "0x%x", mask));"
            + "\(objectType?.description ?? "");\(inheritedObjectType?.description ?? "");\(sid))"
    }
}

/// A self-relative security descriptor taken apart (owner, group, DACL; the SACL is skipped).
public struct DecodedSecurityDescriptor: Sendable, Hashable {
    public var control: UInt16
    public var owner: SID?
    public var group: SID?
    /// nil when SE_DACL_PRESENT is clear.
    public var dacl: [DecodedACE]?

    /// SE_DACL_PROTECTED (`P` in SDDL).
    public var isDACLProtected: Bool { control & 0x1000 != 0 }

    /// Whether an allow ACE for `sid` grants the extended right `right` (a control-access
    /// GUID): an object ACE with that object type, or a plain allow ACE, with
    /// ADS_RIGHT_DS_CONTROL_ACCESS set — how MS-CRTD §2.5.1 / §2.5.2 evaluate Enroll and
    /// AutoEnroll. (Deny ACEs are not evaluated.)
    public func grants(extendedRight right: GUID, to sid: SID) -> Bool {
        (dacl ?? []).contains { ace in
            ace.sid == sid && ace.mask & 0x100 != 0
                && ((ace.type == 0x05 && ace.objectType == right) || ace.type == 0x00)
        }
    }
}

extension SecurityDescriptor {
    /// Parses a self-relative descriptor (MS-DTYP §2.4.6). Throws `constraintViolation` when it
    /// is truncated or malformed.
    public static func decode(_ sd: [UInt8]) throws -> DecodedSecurityDescriptor {
        func bad(_ what: String) -> StoreError { .constraintViolation("security descriptor: \(what)") }
        guard sd.count >= 20, sd[0] == 1 else { throw bad("header") }
        func u16(_ i: Int) -> UInt16 { UInt16(sd[i]) | UInt16(sd[i + 1]) << 8 }
        func u32(_ i: Int) -> UInt32 { (0..<4).reduce(UInt32(0)) { $0 | UInt32(sd[i + $1]) << (8 * UInt32($1)) } }
        func sidAt(_ offset: Int) throws -> SID {
            guard offset + 8 <= sd.count else { throw bad("SID at \(offset)") }
            let end = offset + 8 + 4 * Int(sd[offset + 1])
            guard end <= sd.count else { throw bad("SID at \(offset)") }
            return try SID(bytes: Array(sd[offset..<end]))
        }
        let control = u16(2)
        let ownerOffset = Int(u32(4)), groupOffset = Int(u32(8)), daclOffset = Int(u32(16))
        var out = DecodedSecurityDescriptor(control: control, owner: ownerOffset == 0 ? nil : try sidAt(ownerOffset),
                                            group: groupOffset == 0 ? nil : try sidAt(groupOffset), dacl: nil)
        guard control & 0x0004 != 0, daclOffset != 0 else { return out }
        guard daclOffset + 8 <= sd.count else { throw bad("DACL header") }
        let aclSize = Int(u16(daclOffset + 2)), count = Int(u16(daclOffset + 4))
        guard daclOffset + aclSize <= sd.count else { throw bad("DACL size") }
        var aces: [DecodedACE] = []
        var p = daclOffset + 8
        for _ in 0..<count {
            guard p + 8 <= daclOffset + aclSize else { throw bad("ACE header") }
            let type = sd[p], flags = sd[p + 1], size = Int(u16(p + 2))
            guard size >= 8, p + size <= daclOffset + aclSize else { throw bad("ACE size") }
            let mask = u32(p + 4)
            var q = p + 8
            var objectType: GUID?, inherited: GUID?
            if (0x05...0x08).contains(type) {
                guard q + 4 <= p + size else { throw bad("object ACE") }
                let objFlags = u32(q)
                q += 4
                if objFlags & 1 != 0 {
                    guard q + 16 <= p + size else { throw bad("object ACE GUID") }
                    objectType = try GUID(bytes: Array(sd[q..<q + 16]))
                    q += 16
                }
                if objFlags & 2 != 0 {
                    guard q + 16 <= p + size else { throw bad("object ACE GUID") }
                    inherited = try GUID(bytes: Array(sd[q..<q + 16]))
                    q += 16
                }
            }
            aces.append(DecodedACE(type: type, flags: flags, mask: mask, objectType: objectType,
                                   inheritedObjectType: inherited, sid: try sidAt(q)))
            p += size
        }
        out.dacl = aces
        return out
    }
}
