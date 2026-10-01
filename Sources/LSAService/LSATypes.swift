import Foundation
import MSPAC
import RPCKit

// MARK: - LSAPR_REFERENCED_DOMAIN_LIST (MS-LSAT §2.2.12)

/// `LSAPR_TRUST_INFORMATION` (MS-LSAT §2.2.11): `RPC_UNICODE_STRING Name; PRPC_SID Sid;`.
public struct TrustInformation: Sendable, Hashable {
    public var name: String
    public var sid: SID?

    public init(name: String, sid: SID?) {
        self.name = name
        self.sid = sid
    }
}

/// `LSAPR_REFERENCED_DOMAIN_LIST`: `Entries; [size_is(Entries)] PLSAPR_TRUST_INFORMATION Domains;
/// MaxEntries`. Always marshalled as the pointee of the `[out] PLSAPR_REFERENCED_DOMAIN_LIST*`.
public struct ReferencedDomainList: Sendable, Hashable {
    public var domains: [TrustInformation]
    /// Windows reports 32 (the allocation granularity); receivers ignore it.
    public var maxEntries: UInt32

    public init(domains: [TrustInformation] = [], maxEntries: UInt32 = 32) {
        self.domains = domains
        self.maxEntries = maxEntries
    }

    /// Writes the top-level `PLSAPR_REFERENCED_DOMAIN_LIST*` (unique pointer, then the list).
    public static func encodeTopLevel(_ list: ReferencedDomainList?, _ w: NDRWriter) {
        guard let list else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.u32(UInt32(list.domains.count))
        if w.uniquePointer(!list.domains.isEmpty) {
            let domains = list.domains
            w.deferPointee { [weak w] in
                guard let w else { return }
                w.u32(UInt32(domains.count))
                for d in domains {
                    w.rpcUnicodeString(d.name)
                    w.sidPointer(d.sid)
                }
            }
        }
        w.u32(list.maxEntries)
        w.flushDeferred()
    }

    public static func decodeTopLevel(_ r: NDRReader) throws -> ReferencedDomainList? {
        guard try r.pointer() != nil else { return nil }
        let entries = Int(try r.u32())
        let hasDomains = try r.pointer() != nil
        let maxEntries = try r.u32()
        var domains: [TrustInformation] = []
        if hasDomains {
            let n = try r.boundedCount(max: 4096)
            guard n == entries else { throw NDRError(offset: r.offset, reason: "domain array \(n) != Entries \(entries)") }
            var flats: [(UnicodeStringHeader, Bool)] = []
            for _ in 0..<n { flats.append((try r.unicodeStringFlat(), try r.pointer() != nil)) }
            for (h, hasSID) in flats {
                let name = try r.unicodeStringBody(h) ?? ""
                domains.append(TrustInformation(name: name, sid: hasSID ? try r.sid() : nil))
            }
        }
        return ReferencedDomainList(domains: domains, maxEntries: maxEntries)
    }
}

// MARK: - Translated SIDs (MS-LSAT §2.2.15, 2.2.16, 2.2.17 and the *_EX/_EX2 lists)

/// The three wire forms of a translated SID.
public enum TranslatedSIDForm: Sendable, Hashable {
    /// `LSA_TRANSLATED_SID`: `Use; RelativeId; DomainIndex`.
    case v1
    /// `LSAPR_TRANSLATED_SID_EX`: `Use; RelativeId; DomainIndex; Flags`.
    case ex
    /// `LSAPR_TRANSLATED_SID_EX2`: `Use; PRPC_SID Sid; DomainIndex; Flags`.
    case ex2
}

public struct TranslatedSID: Sendable, Hashable {
    public var use: UInt16
    /// v1/EX: the RID relative to the referenced domain.
    public var relativeID: UInt32
    /// EX2: the full SID (NULL when unmapped).
    public var sid: SID?
    public var domainIndex: Int32
    public var flags: UInt32

    public init(use: UInt16, relativeID: UInt32 = 0, sid: SID? = nil, domainIndex: Int32, flags: UInt32 = 0) {
        self.use = use
        self.relativeID = relativeID
        self.sid = sid
        self.domainIndex = domainIndex
        self.flags = flags
    }
}

/// `LSAPR_TRANSLATED_SIDS(_EX/_EX2)`: `Entries; [size_is(Entries)] P… Sids;`. A top-level
/// `[in,out]` reference parameter, so the struct is written inline without a referent.
public enum TranslatedSIDs {
    public static func encode(_ entries: [TranslatedSID], form: TranslatedSIDForm, _ w: NDRWriter) {
        w.u32(UInt32(entries.count))
        if w.uniquePointer(!entries.isEmpty) {
            w.deferPointee { [weak w] in
                guard let w else { return }
                w.u32(UInt32(entries.count))
                for e in entries {
                    w.enum16(e.use)
                    switch form {
                    case .v1:
                        w.u32(e.relativeID); w.i32(e.domainIndex)
                    case .ex:
                        w.u32(e.relativeID); w.i32(e.domainIndex); w.u32(e.flags)
                    case .ex2:
                        w.sidPointer(e.sid); w.i32(e.domainIndex); w.u32(e.flags)
                    }
                }
            }
        }
        w.flushDeferred()
    }

    public static func decode(form: TranslatedSIDForm, _ r: NDRReader) throws -> [TranslatedSID] {
        let entries = Int(try r.u32())
        guard try r.pointer() != nil else { return [] }
        let n = try r.boundedCount(max: 20480)
        guard n == entries else { throw NDRError(offset: r.offset, reason: "sid array \(n) != Entries \(entries)") }
        var out: [TranslatedSID] = []
        var sidPresent: [Bool] = []
        for _ in 0..<n {
            let use = try r.enum16()
            switch form {
            case .v1:
                let rid = try r.u32(), idx = try r.i32()
                out.append(TranslatedSID(use: use, relativeID: rid, domainIndex: idx))
            case .ex:
                let rid = try r.u32(), idx = try r.i32(), flags = try r.u32()
                out.append(TranslatedSID(use: use, relativeID: rid, domainIndex: idx, flags: flags))
            case .ex2:
                let present = try r.pointer() != nil
                let idx = try r.i32(), flags = try r.u32()
                sidPresent.append(present)
                out.append(TranslatedSID(use: use, domainIndex: idx, flags: flags))
            }
        }
        if form == .ex2 {
            for i in 0..<n where sidPresent[i] { out[i].sid = try r.sid() }
        }
        return out
    }
}

// MARK: - Translated names (MS-LSAT §2.2.19, 2.2.20 and lists)

public enum TranslatedNameForm: Sendable, Hashable {
    /// `LSAPR_TRANSLATED_NAME`: `Use; RPC_UNICODE_STRING Name; DomainIndex`.
    case v1
    /// `LSAPR_TRANSLATED_NAME_EX`: `Use; Name; DomainIndex; Flags`.
    case ex
}

public struct TranslatedName: Sendable, Hashable {
    public var use: UInt16
    public var name: String?
    public var domainIndex: Int32
    public var flags: UInt32

    public init(use: UInt16, name: String?, domainIndex: Int32, flags: UInt32 = 0) {
        self.use = use
        self.name = name
        self.domainIndex = domainIndex
        self.flags = flags
    }
}

/// `LSAPR_TRANSLATED_NAMES(_EX)`: `Entries; [size_is(Entries)] P… Names;` (top-level `[in,out]`).
public enum TranslatedNames {
    public static func encode(_ entries: [TranslatedName], form: TranslatedNameForm, _ w: NDRWriter) {
        w.u32(UInt32(entries.count))
        if w.uniquePointer(!entries.isEmpty) {
            w.deferPointee { [weak w] in
                guard let w else { return }
                w.u32(UInt32(entries.count))
                for e in entries {
                    w.enum16(e.use)
                    w.rpcUnicodeString(e.name)
                    w.i32(e.domainIndex)
                    if form == .ex { w.u32(e.flags) }
                }
            }
        }
        w.flushDeferred()
    }

    public static func decode(form: TranslatedNameForm, _ r: NDRReader) throws -> [TranslatedName] {
        let entries = Int(try r.u32())
        guard try r.pointer() != nil else { return [] }
        let n = try r.boundedCount(max: 20480)
        guard n == entries else { throw NDRError(offset: r.offset, reason: "name array \(n) != Entries \(entries)") }
        var flats: [(UInt16, UnicodeStringHeader, Int32, UInt32)] = []
        for _ in 0..<n {
            let use = try r.enum16()
            let h = try r.unicodeStringFlat()
            let idx = try r.i32()
            let flags = form == .ex ? try r.u32() : 0
            flats.append((use, h, idx, flags))
        }
        var out: [TranslatedName] = []
        for (use, h, idx, flags) in flats {
            out.append(TranslatedName(use: use, name: try r.unicodeStringBody(h), domainIndex: idx, flags: flags))
        }
        return out
    }
}

// MARK: - Request-side lists

/// `[in, size_is(Count)] PRPC_UNICODE_STRING Names` — a top-level conformant array of
/// `RPC_UNICODE_STRING` (no referent: the top-level pointer is `[ref]`).
public enum UnicodeStringArray {
    public static func encode(_ names: [String], _ w: NDRWriter) {
        w.u32(UInt32(names.count))
        for n in names { w.rpcUnicodeString(n) }
        w.flushDeferred()
    }

    public static func decode(_ r: NDRReader, max: Int = 1000) throws -> [String] {
        let n = try r.boundedCount(max: max)
        var flats: [UnicodeStringHeader] = []
        for _ in 0..<n { flats.append(try r.unicodeStringFlat()) }
        return try flats.map { try r.unicodeStringBody($0) ?? "" }
    }
}

/// `LSAPR_SID_ENUM_BUFFER` (MS-LSAT §2.2.18): `Entries; [size_is(Entries)] PLSAPR_SID_INFORMATION
/// SidInfo;` where `LSAPR_SID_INFORMATION` is `{ PRPC_SID Sid; }`. Top-level `[in]` reference.
public enum SIDEnumBuffer {
    public static func encode(_ sids: [SID], _ w: NDRWriter) {
        w.u32(UInt32(sids.count))
        if w.uniquePointer(!sids.isEmpty) {
            w.deferPointee { [weak w] in
                guard let w else { return }
                w.u32(UInt32(sids.count))
                for s in sids { w.sidPointer(s) }
            }
        }
        w.flushDeferred()
    }

    /// Returns the SIDs; a NULL `Sid` pointer inside the array is reported as nil.
    public static func decode(_ r: NDRReader, max: Int = 20480) throws -> [SID?] {
        let entries = Int(try r.u32())
        guard entries <= max else { throw NDRError(offset: r.offset, reason: "SID count \(entries) exceeds \(max)") }
        guard try r.pointer() != nil else { return [] }
        let n = try r.boundedCount(max: max)
        guard n == entries else { throw NDRError(offset: r.offset, reason: "SID array \(n) != Entries \(entries)") }
        var present: [Bool] = []
        for _ in 0..<n { present.append(try r.pointer() != nil) }
        return try present.map { $0 ? try r.sid() : nil }
    }
}

// MARK: - LSAPR_POLICY_INFORMATION (MS-LSAD §2.2.4.2)

/// `POLICY_INFORMATION_CLASS` values this server answers.
public enum PolicyInformationClass {
    public static let auditEvents: UInt16 = 2
    public static let primaryDomain: UInt16 = 3
    public static let accountDomain: UInt16 = 5
    public static let lsaServerRole: UInt16 = 6
    public static let dnsDomain: UInt16 = 12
    public static let dnsDomainInt: UInt16 = 13
}

/// `LSAPR_POLICY_DNS_DOMAIN_INFO` (MS-LSAD §2.2.4.13).
public struct DNSDomainInfo: Sendable, Hashable {
    public var name: String
    public var dnsDomainName: String
    public var dnsForestName: String
    public var domainGUID: DCEUUID
    public var sid: SID?

    public init(name: String, dnsDomainName: String, dnsForestName: String, domainGUID: DCEUUID, sid: SID?) {
        self.name = name
        self.dnsDomainName = dnsDomainName
        self.dnsForestName = dnsForestName
        self.domainGUID = domainGUID
        self.sid = sid
    }
}

/// The arms of the `LSAPR_POLICY_INFORMATION` union this server produces.
public enum PolicyInformation: Sendable, Hashable {
    /// `LSAPR_POLICY_AUDIT_EVENTS_INFO`: `UCHAR AuditingMode; [size_is(MaximumAuditEventCount)]
    /// unsigned long* EventAuditingOptions; unsigned long MaximumAuditEventCount`.
    case auditEvents(auditingMode: Bool, options: [UInt32])
    /// `LSAPR_POLICY_PRIMARY_DOM_INFO`: `RPC_UNICODE_STRING Name; PRPC_SID Sid`.
    case primaryDomain(name: String, sid: SID?)
    /// `LSAPR_POLICY_ACCOUNT_DOM_INFO`: `RPC_UNICODE_STRING DomainName; PRPC_SID DomainSid`.
    case accountDomain(name: String, sid: SID?)
    /// `POLICY_LSA_SERVER_ROLE_INFO`: `POLICY_LSA_SERVER_ROLE` (enum16; 2 backup, 3 primary).
    case serverRole(UInt16)
    case dnsDomain(DNSDomainInfo)
    case dnsDomainInt(DNSDomainInfo)

    public var infoClass: UInt16 {
        switch self {
        case .auditEvents: PolicyInformationClass.auditEvents
        case .primaryDomain: PolicyInformationClass.primaryDomain
        case .accountDomain: PolicyInformationClass.accountDomain
        case .serverRole: PolicyInformationClass.lsaServerRole
        case .dnsDomain: PolicyInformationClass.dnsDomain
        case .dnsDomainInt: PolicyInformationClass.dnsDomainInt
        }
    }

    /// Writes `[out, switch_is(InformationClass)] PLSAPR_POLICY_INFORMATION* PolicyInformation`:
    /// a unique pointer, then the non-encapsulated union (16-bit discriminant, then the arm at
    /// its own alignment — NDR32 does not align a union to its widest arm).
    public static func encodeTopLevel(_ info: PolicyInformation?, _ w: NDRWriter) {
        guard let info else { w.u32(0); return }
        _ = w.uniquePointer(true)
        w.enum16(info.infoClass)
        // The arm starts 4-aligned even when it is a lone enum16 (POLICY_LSA_SERVER_ROLE_INFO):
        // MIDL aligns a non-encapsulated union's arm to the union's widest arm, and impacket
        // (from Windows captures) and Wireshark both expect the role at offset 8, not 6.
        w.align(4)
        switch info {
        case .auditEvents(let mode, let options):
            w.align(4)       // the arm struct is 4-aligned (pointer member) before its UCHAR
            w.u8(mode ? 1 : 0)
            if w.uniquePointer(!options.isEmpty) {
                w.deferPointee { [weak w] in w?.conformantUInt32Array(options) }
            }
            w.u32(UInt32(options.count))
        case .primaryDomain(let name, let sid), .accountDomain(let name, let sid):
            w.rpcUnicodeString(name)
            w.sidPointer(sid)
        case .serverRole(let role):
            w.enum16(role)
        case .dnsDomain(let d), .dnsDomainInt(let d):
            w.rpcUnicodeString(d.name)
            w.rpcUnicodeString(d.dnsDomainName)
            w.rpcUnicodeString(d.dnsForestName)
            w.guid(d.domainGUID)
            w.sidPointer(d.sid)
        }
        w.flushDeferred()
    }

    public static func decodeTopLevel(_ r: NDRReader) throws -> PolicyInformation? {
        guard try r.pointer() != nil else { return nil }
        let tag = try r.enum16()
        r.align(4)
        switch tag {
        case PolicyInformationClass.auditEvents:
            r.align(4)
            let mode = try r.u8()
            let present = try r.pointer() != nil
            let max = Int(try r.u32())
            var options: [UInt32] = []
            if present {
                options = try r.conformantUInt32Array(maxElements: 1024)
                guard options.count == max else {
                    throw NDRError(offset: r.offset, reason: "audit options \(options.count) != \(max)")
                }
            }
            return .auditEvents(auditingMode: mode != 0, options: options)
        case PolicyInformationClass.primaryDomain, PolicyInformationClass.accountDomain:
            let h = try r.unicodeStringFlat()
            let hasSID = try r.pointer() != nil
            let name = try r.unicodeStringBody(h) ?? ""
            let sid = hasSID ? try r.sid() : nil
            return tag == PolicyInformationClass.primaryDomain ? .primaryDomain(name: name, sid: sid)
                                                               : .accountDomain(name: name, sid: sid)
        case PolicyInformationClass.lsaServerRole:
            return .serverRole(try r.enum16())
        case PolicyInformationClass.dnsDomain, PolicyInformationClass.dnsDomainInt:
            let h1 = try r.unicodeStringFlat(), h2 = try r.unicodeStringFlat(), h3 = try r.unicodeStringFlat()
            let guid = try r.guid()
            let hasSID = try r.pointer() != nil
            let d = DNSDomainInfo(name: try r.unicodeStringBody(h1) ?? "",
                                  dnsDomainName: try r.unicodeStringBody(h2) ?? "",
                                  dnsForestName: try r.unicodeStringBody(h3) ?? "",
                                  domainGUID: guid, sid: hasSID ? try r.sid() : nil)
            return tag == PolicyInformationClass.dnsDomain ? .dnsDomain(d) : .dnsDomainInt(d)
        default:
            throw NDRError(offset: r.offset, reason: "unsupported policy information class \(tag)")
        }
    }
}
