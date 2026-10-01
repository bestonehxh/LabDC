import Foundation
import RPCKit
import Store
import MSPAC

// MARK: - Constants (MS-NRPC §2.2.1.3.6 / §2.2.1.6.2, Samba `netlogon.idl`)

/// `NETLOGON_WORKSTATION_INFO.WorkstationFlags` / `NETLOGON_DOMAIN_INFO.WorkstationFlags`.
enum NetlogonWorkstationFlags {
    /// `NETR_WS_FLAG_HANDLES_INBOUND_TRUSTS`: the client wants inbound trusts in the list.
    static let handlesInboundTrusts: UInt32 = 0x0000_0001
    /// `NETR_WS_FLAG_HANDLES_SPN_UPDATE`: the client writes its own dNSHostName/SPNs over LDAP;
    /// the DC must not touch them.
    static let handlesSPNUpdate: UInt32 = 0x0000_0002
    static let all: UInt32 = handlesInboundTrusts | handlesSPNUpdate
}

/// `DS_DOMAIN_TRUSTSW.Flags` = `netr_TrustFlags` (also `NL_TRUST_EXTENSION.Flags`).
enum NetlogonTrustFlags {
    static let inForest: UInt32 = 0x0000_0001
    static let directOutbound: UInt32 = 0x0000_0002
    static let treeRoot: UInt32 = 0x0000_0004
    static let primary: UInt32 = 0x0000_0008
    static let nativeMode: UInt32 = 0x0000_0010
    static let directInbound: UInt32 = 0x0000_0020
    /// Our own domain in a single-domain forest: Samba's `fill_our_one_domain_info` (trust list)
    /// and `DsrEnumerateDomainTrusts` both send `PRIMARY|IN_FOREST|NATIVE|TREEROOT` = 0x1D.
    static let ownDomain: UInt32 = primary | inForest | nativeMode | treeRoot
}

/// `TrustType` (MS-LSAD §2.2.7.9 / `lsa_TrustType`): 2 = `TRUST_TYPE_UPLEVEL` (an AD domain).
let netlogonTrustTypeUplevel: UInt32 = 2

// MARK: - Request / reply models

/// `OSVERSIONINFOEXW` as carried in `NETLOGON_WORKSTATION_INFO.OsVersion` (a 284-byte blob inside
/// a `UNICODE_STRING`, MS-NRPC §2.2.1.3.6 → MS-RPRN §2.2.3.10.2).
struct NetlogonOSVersion: Sendable, Equatable {
    var major: UInt32
    var minor: UInt32
    var build: UInt32
    var platformID: UInt32
    var csdVersion: String
    var servicePackMajor: UInt16
    var servicePackMinor: UInt16
    var suiteMask: UInt16
    var productType: UInt8

    static let size = 284

    /// The `operatingSystemVersion` value Windows DCs and Samba write: `"10.0 (19045)"`.
    var operatingSystemVersion: String { "\(major).\(minor) (\(build))" }

    /// Parses the blob; nil unless it is a whole `OSVERSIONINFOEXW` (size field 284).
    static func parse(_ b: [UInt8]) -> NetlogonOSVersion? {
        guard b.count >= size else { return nil }
        func u32(_ o: Int) -> UInt32 {
            UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
        }
        func u16(_ o: Int) -> UInt16 { UInt16(b[o]) | UInt16(b[o + 1]) << 8 }
        guard u32(0) == UInt32(size) else { return nil }
        var units: [UInt16] = []
        for i in stride(from: 20, to: 20 + 256, by: 2) {
            let u = u16(i)
            if u == 0 { break }
            units.append(u)
        }
        return NetlogonOSVersion(major: u32(4), minor: u32(8), build: u32(12), platformID: u32(16),
                                 csdVersion: String(decoding: units, as: UTF16.self),
                                 servicePackMajor: u16(276), servicePackMinor: u16(278),
                                 suiteMask: u16(280), productType: b[282])
    }

    /// The 284-byte wire form (for tests and fixtures).
    var bytes: [UInt8] {
        var b = [UInt8]()
        func u32(_ v: UInt32) { for s in stride(from: 0, to: 32, by: 8) { b.append(UInt8(truncatingIfNeeded: v >> s)) } }
        func u16(_ v: UInt16) { b.append(UInt8(truncatingIfNeeded: v)); b.append(UInt8(truncatingIfNeeded: v >> 8)) }
        u32(UInt32(Self.size)); u32(major); u32(minor); u32(build); u32(platformID)
        var csd = [UInt8](repeating: 0, count: 256)
        for (i, u) in csdVersion.utf16.prefix(127).enumerated() {
            csd[2 * i] = UInt8(truncatingIfNeeded: u); csd[2 * i + 1] = UInt8(truncatingIfNeeded: u >> 8)
        }
        b += csd
        u16(servicePackMajor); u16(servicePackMinor); u16(suiteMask)
        b.append(productType); b.append(0)
        return b
    }
}

/// The parts of `NETLOGON_WORKSTATION_INFO` (MS-NRPC §2.2.1.3.6) the DC acts on.
struct NetlogonWorkstationInfo: Sendable, Equatable {
    var dnsHostName: String?
    var siteName: String?
    var osName: String?
    /// The `OsVersion` buffer was present (non-NULL).
    var osVersionPresent = false
    /// The parsed `OsVersion` blob; nil when absent or not an `OSVERSIONINFOEXW`.
    var osVersion: NetlogonOSVersion?
    var workstationFlags: UInt32 = 0
    var kerberosSupportedEncryptionTypes: UInt32 = 0

    /// Reads the `NETLOGON_WORKSTATION_INFO` struct (the referent of the union arm): scalars, then
    /// the deferred bodies in field order.
    static func read(_ r: NDRReader) throws -> NetlogonWorkstationInfo {
        var ws = NetlogonWorkstationInfo()
        r.align(4)
        let lsaPolicySize = try r.u32()                    // LsaPolicy.LsaPolicySize
        let lsaPolicyPtr = try r.u32()                     // LsaPolicy.LsaPolicy
        let dnsPtr = try r.u32()
        let sitePtr = try r.u32()
        var dummyPtrs: [UInt32] = []
        for _ in 0..<4 { dummyPtrs.append(try r.u32()) }   // Dummy1..4 LPWSTR
        let osVerPresent = try NLNDR.readStringHeader(r)
        let osNamePresent = try NLNDR.readStringHeader(r)
        let dummy3Present = try NLNDR.readStringHeader(r)  // DummyString3
        let dummy4Present = try NLNDR.readStringHeader(r)  // DummyString4
        ws.workstationFlags = try r.u32()
        ws.kerberosSupportedEncryptionTypes = try r.u32()
        _ = try r.u32(); _ = try r.u32()                   // DummyLong3, DummyLong4
        // Deferred bodies, in field order.
        if lsaPolicyPtr != 0 { _ = try r.u32(); _ = try r.take(Int(lsaPolicySize)); r.align(4) }
        if dnsPtr != 0 { ws.dnsHostName = try NLNDR.readWCharBody(r, stripNUL: true) }
        if sitePtr != 0 { ws.siteName = try NLNDR.readWCharBody(r, stripNUL: true) }
        for p in dummyPtrs where p != 0 { _ = try NLNDR.readWCharBody(r, stripNUL: true) }
        if osVerPresent {
            ws.osVersionPresent = true
            ws.osVersion = NetlogonOSVersion.parse(try NLNDR.readWCharBodyBytes(r))
        }
        if osNamePresent { ws.osName = try NLNDR.readWCharBody(r, stripNUL: true) }
        if dummy3Present { _ = try NLNDR.readWCharBodyBytes(r) }
        if dummy4Present { _ = try NLNDR.readWCharBodyBytes(r) }
        return ws
    }
}

/// `NETLOGON_ONE_DOMAIN_INFO` (MS-NRPC §2.2.1.3.10). Dummy strings are always NULL and dummy
/// longs zero, as the spec requires and Samba sends.
struct NetlogonOneDomainInfo: Sendable, Equatable {
    var domainName: String
    var dnsDomainName: String?
    var dnsForestName: String?
    var domainGUID: DCEUUID
    var domainSID: SID?
    /// The 16-byte `NL_TRUST_EXTENSION` (Flags, ParentIndex, TrustType, TrustAttributes), or nil
    /// for a NULL `TrustExtension`.
    var trustExtension: [UInt8]?

    static func trustExtension(flags: UInt32, parentIndex: UInt32, trustType: UInt32,
                               trustAttributes: UInt32) -> [UInt8] {
        var b = [UInt8]()
        for v in [flags, parentIndex, trustType, trustAttributes] {
            for s in stride(from: 0, to: 32, by: 8) { b.append(UInt8(truncatingIfNeeded: v >> s)) }
        }
        return b
    }

    /// Writes the struct's scalars; the embedded pointees (name buffers, SID, TrustExtension) are
    /// appended to `bodies` in field order for the caller to emit.
    func writeScalars(_ w: NDRWriter, bodies: inout [() -> Void]) {
        w.align(4)
        NLNDR.writeUnicodeString(w, domainName, large: true, bodies: &bodies)
        NLNDR.writeUnicodeString(w, dnsDomainName, large: true, bodies: &bodies)
        NLNDR.writeUnicodeString(w, dnsForestName, large: true, bodies: &bodies)
        w.guid(domainGUID)
        if let sid = domainSID {
            _ = w.uniquePointer(true)
            bodies.append { w.sid(sid) }
        } else {
            w.u32(0)
        }
        NLNDR.writeBlobUnicodeString(w, trustExtension, bodies: &bodies)
        NLNDR.writeUnicodeString(w, nil, bodies: &bodies)  // DummyString2
        NLNDR.writeUnicodeString(w, nil, bodies: &bodies)  // DummyString3
        NLNDR.writeUnicodeString(w, nil, bodies: &bodies)  // DummyString4
        w.u32(0); w.u32(0); w.u32(0); w.u32(0)             // DummyLong1..4
    }
}

/// `NETLOGON_DOMAIN_INFO` (MS-NRPC §2.2.1.3.11) as we return it.
struct NetlogonDomainInfoReply: Sendable, Equatable {
    var primaryDomain: NetlogonOneDomainInfo
    var trustedDomains: [NetlogonOneDomainInfo]
    var dnsHostNameInDs: String?
    var workstationFlags: UInt32
    var supportedEncTypes: UInt32

    /// Writes the struct (the pointee of the `NETLOGON_DOMAIN_INFORMATION` arm) and **flushes** the
    /// writer's deferred queue, so its pointees come out in NDR order before the caller's next field.
    func write(_ w: NDRWriter) {
        w.align(4)
        var primaryBodies: [() -> Void] = []
        primaryDomain.writeScalars(w, bodies: &primaryBodies)
        for b in primaryBodies { w.deferPointee(b) }
        w.u32(UInt32(trustedDomains.count))                // TrustedDomainCount
        if trustedDomains.isEmpty {
            w.u32(0)                                        // TrustedDomains NULL
        } else {
            _ = w.uniquePointer(true)
            let domains = trustedDomains
            w.deferPointee {
                // Conformant array of NETLOGON_ONE_DOMAIN_INFO, then the elements' pointees in
                // element/field order — before the parent's remaining deferred pointees.
                w.u32(UInt32(domains.count))
                var bodies: [() -> Void] = []
                for d in domains { d.writeScalars(w, bodies: &bodies) }
                for b in bodies { b() }
            }
        }
        w.u32(0); w.u32(0)                                  // LsaPolicy: LsaPolicySize 0, LsaPolicy NULL
        var tailBodies: [() -> Void] = []
        NLNDR.writeUnicodeString(w, dnsHostNameInDs, large: true, bodies: &tailBodies)   // DnsHostNameInDs
        NLNDR.writeUnicodeString(w, nil, bodies: &tailBodies)                            // DummyString2
        NLNDR.writeUnicodeString(w, nil, bodies: &tailBodies)                            // DummyString3
        NLNDR.writeUnicodeString(w, nil, bodies: &tailBodies)                            // DummyString4
        for b in tailBodies { w.deferPointee(b) }
        w.u32(workstationFlags)
        w.u32(supportedEncTypes)
        w.u32(0); w.u32(0)                                  // DummyLong3, DummyLong4
        w.flushDeferred()
    }
}

// MARK: - NetrLogonGetDomainInfo

extension NetlogonService {

    /// `NetrLogonGetDomainInfo` (opnum 29), MS-NRPC §3.5.4.4.10, shaped like Samba's
    /// `dcesrv_netr_LogonGetDomainInfo` (WP-AP):
    /// - PrimaryDomain: NetBIOS name, DNS domain and forest **with a trailing dot**, GUID, SID, no
    ///   TrustExtension (Samba: "w2k8 only fills this on trusted domains").
    /// - TrustedDomains: our own domain (DNS name without the dot, forest NULL) with an
    ///   `NL_TRUST_EXTENSION` of `PRIMARY|IN_FOREST|NATIVE|TREEROOT`, parent 0, uplevel, attrs 0.
    /// - WorkstationFlags = client's ∧ 0x3; SupportedEncTypes = the computer's
    ///   msDS-SupportedEncryptionTypes, else 0xFFFFFFFF; LsaPolicy 0/NULL; DnsHostNameInDs = the
    ///   stored dNSHostName when the client handles its SPNs, else NULL.
    /// - operatingSystem[/Version/ServicePack] always; dNSHostName + HOST SPNs only when the client
    ///   does **not** set `NETR_WS_FLAG_HANDLES_SPN_UPDATE` (SPNs are added, never replaced).
    func getDomainInfo(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readInlineWSTR(r)                     // ServerName
        let computer = try NLNDR.readTopLevelString(r) ?? ""
        let auth = try readAuthenticator(r)
        _ = try readAuthenticator(r)                        // ReturnAuthenticator
        let level = try r.u32()                             // Level

        // NETLOGON_WORKSTATION_INFORMATION union (tag, arm pointer, pointee inline).
        let tag = try r.u32()
        let armPresent = try r.u32() != 0
        var ws: NetlogonWorkstationInfo?
        if armPresent, tag == 1 { ws = try NetlogonWorkstationInfo.read(r) }

        let w = NDRWriter()
        var logHead = "GetDomainInfo \(computer)"
        if let ws {
            logHead += " dns=\(ws.dnsHostName ?? "-") os='\(ws.osName ?? "")'"
            if let v = ws.osVersion { logHead += " ver='\(v.operatingSystemVersion)'" }
            logHead += " wsflags=0x" + String(ws.workstationFlags, radix: 16)
                + " enctypes=0x" + String(ws.kerberosSupportedEncryptionTypes, radix: 16)
        } else {
            logHead += " level=\(level) wkstainfo=NULL"
        }

        guard let channel = state.channel(computer: computer) else {
            logEvent(logHead + fromClause(account: nil) + Self.outcome(NLStatus.accessDenied, "no secure channel"))
            writeAuthenticator(w, credential: [UInt8](repeating: 0, count: 8), timestamp: 0)
            w.u32(level); w.u32(0)                          // DomBuffer tag, NULL arm
            w.u32(NLStatus.accessDenied)
            return w
        }
        let step = stepAuthenticator(channel, received: auth)
        writeAuthenticator(w, credential: step.returnCredential, timestamp: 0)
        guard step.ok else {
            logEvent(logHead + fromClause(account: channel.accountName)
                     + Self.outcome(NLStatus.accessDenied, "authenticator mismatch"))
            w.u32(level); w.u32(0)
            w.u32(NLStatus.accessDenied)
            return w
        }

        switch level {
        case 1:
            let account = channel.accountName.isEmpty ? computer + "$" : channel.accountName
            let entry = try? await store.read(sam: account)
            var notes: [String] = []
            if let ws, let entry {
                notes += await applyWorkstationInfo(entry: entry, computer: computer, ws: ws)
            } else if entry == nil {
                notes.append("no computer object \(account)")
            }
            let reply = try await domainInfoReply(entry: entry, ws: ws)
            w.u32(1)                                        // NETLOGON_DOMAIN_INFORMATION tag
            NLNDR.writeReferent(w)                          // PNETLOGON_DOMAIN_INFO
            reply.write(w)
            w.u32(NLStatus.success)
            notes.insert("trusts=\(reply.trustedDomains.count) reply wsflags=0x"
                         + String(reply.workstationFlags, radix: 16)
                         + " enctypes=0x" + String(reply.supportedEncTypes, radix: 16)
                         + " dnsInDs=\(reply.dnsHostNameInDs ?? "NULL")", at: 0)
            logEvent(logHead + fromClause(account: channel.accountName)
                     + Self.outcome(NLStatus.success, notes.joined(separator: "; ")))
        case 2:
            w.u32(2)                                        // NETLOGON_DOMAIN_INFORMATION tag
            NLNDR.writeReferent(w)                          // PNETLOGON_LSA_POLICY_INFO
            w.u32(0); w.u32(0)                              // LsaPolicySize 0, LsaPolicy NULL
            w.u32(NLStatus.success)
            logEvent(logHead + fromClause(account: channel.accountName) + Self.outcome(NLStatus.success, "lsa policy"))
        default:
            w.u32(level); w.u32(0)
            w.u32(NLStatus.invalidLevel)
            logEvent(logHead + fromClause(account: channel.accountName) + Self.outcome(NLStatus.invalidLevel))
        }
        return w
    }

    /// Builds the level-1 reply from the domain and the computer object as read **before** the
    /// workstation-info update (MS-NRPC: "the AD query is done prior to changing the value").
    func domainInfoReply(entry: DirectoryEntry?, ws: NetlogonWorkstationInfo?) async throws -> NetlogonDomainInfoReply {
        let info = try await store.domainInfo()
        let guid = DCEUUID(bytes: info.domainGUID.bytes)
        let dns = info.dnsDomain.hasSuffix(".") ? String(info.dnsDomain.dropLast()) : info.dnsDomain
        let primary = NetlogonOneDomainInfo(domainName: info.netbiosDomain,
                                            dnsDomainName: dns + ".", dnsForestName: dns + ".",
                                            domainGUID: guid, domainSID: info.domainSID, trustExtension: nil)
        let own = NetlogonOneDomainInfo(
            domainName: info.netbiosDomain, dnsDomainName: dns, dnsForestName: nil,
            domainGUID: guid, domainSID: info.domainSID,
            trustExtension: NetlogonOneDomainInfo.trustExtension(flags: NetlogonTrustFlags.ownDomain,
                                                                 parentIndex: 0,
                                                                 trustType: netlogonTrustTypeUplevel,
                                                                 trustAttributes: 0))
        let clientFlags = ws?.workstationFlags ?? 0
        let encTypes = entry?.string("msDS-SupportedEncryptionTypes")
            .flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) }
            .map { UInt32(truncatingIfNeeded: $0) } ?? 0xFFFF_FFFF
        let dnsInDs = clientFlags & NetlogonWorkstationFlags.handlesSPNUpdate != 0
            ? entry?.string("dNSHostName") : nil
        return NetlogonDomainInfoReply(primaryDomain: primary, trustedDomains: [own],
                                       dnsHostNameInDs: dnsInDs,
                                       workstationFlags: clientFlags & NetlogonWorkstationFlags.all,
                                       supportedEncTypes: encTypes)
    }

    /// Applies `NETLOGON_WORKSTATION_INFO` to the computer object (MS-NRPC §3.5.4.4.10, Samba):
    /// operatingSystem, operatingSystemVersion `"M.m (build)"`, operatingSystemServicePack; and,
    /// only when the client does not handle its own SPNs, dNSHostName plus the HOST/ and
    /// RestrictedKrbHost/ SPNs for the NetBIOS and DNS names — **added** to what is there, so SPNs
    /// Windows or an admin registered are kept. Returns notes for the log line.
    private func applyWorkstationInfo(entry: DirectoryEntry, computer: String, ws: NetlogonWorkstationInfo) async -> [String] {
        var ops: [ModifyOp] = []
        var notes: [String] = []
        let present = { (attr: String) in !entry.strings(attr).isEmpty }

        if let os = ws.osName, !os.isEmpty { ops.append(.replace("operatingSystem", strings: [os])) }
        if let v = ws.osVersion {
            ops.append(.replace("operatingSystemVersion", strings: [v.operatingSystemVersion]))
            if !v.csdVersion.isEmpty {
                ops.append(.replace("operatingSystemServicePack", strings: [v.csdVersion]))
            } else if present("operatingSystemServicePack") {
                ops.append(.replace("operatingSystemServicePack", strings: []))
            }
        } else if !ws.osVersionPresent {
            // Samba clears both when the client sends no OsVersion.
            if present("operatingSystemVersion") { ops.append(.replace("operatingSystemVersion", strings: [])) }
            if present("operatingSystemServicePack") { ops.append(.replace("operatingSystemServicePack", strings: [])) }
        }

        if ws.workstationFlags & NetlogonWorkstationFlags.handlesSPNUpdate != 0 {
            notes.append("spn: client-managed")
        } else if let dns = ws.dnsHostName, !dns.isEmpty {
            ops.append(.replace("dNSHostName", strings: [dns]))
            let existing = Set(entry.strings("servicePrincipalName").map { $0.lowercased() })
            var added: [String] = []
            for s in ["HOST/\(computer)", "HOST/\(dns)", "RestrictedKrbHost/\(computer)", "RestrictedKrbHost/\(dns)"]
                where !existing.contains(s.lowercased()) && !added.contains(where: { $0.lowercased() == s.lowercased() }) {
                added.append(s)
            }
            if !added.isEmpty { ops.append(.add("servicePrincipalName", strings: added)) }
            notes.append("spn: dc-managed" + (added.isEmpty ? "" : " +" + added.joined(separator: ",")))
        }
        if !ops.isEmpty {
            do { try await store.update(id: entry.id, ops: ops) } catch { notes.append("store: \(error)") }
        }
        return notes
    }
}
