import Foundation
import RPCKit
import Store

extension DRSService {
    // MARK: IDL_DRSDomainControllerInfo (opnum 16)

    func dsDomainControllerInfo(_ r: NDRReader, _ context: RPCCallContext) async throws -> NDRWriter {
        // ([in] DRS_HANDLE hDrs, [in] DWORD dwInVersion, [in] DRS_MSG_DCINFOREQ* pmsgIn,
        //  [out] DWORD* pdwOutVersion, [out] DRS_MSG_DCINFOREPLY* pmsgOut)
        _ = try r.contextHandle()
        _ = try r.u32()                       // dwInVersion
        _ = try r.u32()                       // union tag (V1)
        // DRS_MSG_DCINFOREQ_V1 flat part: the Domain pointer then InfoLevel; the Domain WCHAR buffer
        // is a deferred pointee that follows InfoLevel (NDR pointer-referent ordering).
        let domainPresent = try r.pointer() != nil
        let level = try r.u32()               // InfoLevel
        var domain: String? = nil
        if domainPresent { r.align(4); domain = try r.varyingWCharBody(stripNUL: true) }

        let info = try await store.domainInfo()
        _ = domain                            // a single-domain DC answers for its own domain

        // Gather the DC(s). We serve exactly this DC.
        let netbios = String(info.dcName.split(separator: ".").first ?? Substring(info.dcName)).uppercased()
        let computerGuid = (try? await store.read(sam: "\(netbios)$"))??.guid
        let dc = DCRecord(info: info, computerGuid: computerGuid)
        logEvent("DsDomainControllerInfo level=\(level) \(domain.map(Self.quote) ?? "-") from \(Self.caller(context))"
                 + " -> OK 1 DC (\(dc.dnsHostName))")

        let w = NDRWriter()
        switch level {
        case 2:
            w.u32(2)                          // pdwOutVersion = 2
            w.u32(2)                          // pmsgOut tag = V2
            writeInfo2(w, [dc], info: info)
        default:
            // Level 1 (and anything else we treat as 1: nltest uses 1).
            w.u32(1)                          // pdwOutVersion = 1
            w.u32(1)                          // pmsgOut tag = V1
            writeInfo1(w, [dc], info: info)
        }
        w.align(4)                            // 4-align the trailing DWORD after the WCHAR arrays
        w.u32(0)                              // ErrorCode = 0
        return w
    }

    /// DRS_MSG_DCINFOREPLY_V1 { cItems, rItems -> DS_DOMAIN_CONTROLLER_INFO_1W[] }.
    private func writeInfo1(_ w: NDRWriter, _ dcs: [DCRecord], info: DomainInfo) {
        w.u32(UInt32(dcs.count))              // cItems
        _ = w.uniquePointer(true)             // rItems
        w.deferPointee {
            w.u32(UInt32(dcs.count))          // array max_count
            for dc in dcs {
                DRSService.drsStringPointer(w, dc.netbiosName)
                DRSService.drsStringPointer(w, dc.dnsHostName)
                DRSService.drsStringPointer(w, dc.siteName)
                DRSService.drsStringPointer(w, dc.computerObjectName)
                DRSService.drsStringPointer(w, dc.serverObjectName)
                w.u32(dc.isPdc ? 1 : 0)       // fIsPdc (BOOL = LONG)
                w.u32(1)                      // fDsEnabled
            }
        }
        w.flushDeferred()
    }

    /// DRS_MSG_DCINFOREPLY_V2 { cItems, rItems -> DS_DOMAIN_CONTROLLER_INFO_2W[] }.
    private func writeInfo2(_ w: NDRWriter, _ dcs: [DCRecord], info: DomainInfo) {
        w.u32(UInt32(dcs.count))
        _ = w.uniquePointer(true)
        w.deferPointee {
            w.u32(UInt32(dcs.count))
            for dc in dcs {
                DRSService.drsStringPointer(w, dc.netbiosName)
                DRSService.drsStringPointer(w, dc.dnsHostName)
                DRSService.drsStringPointer(w, dc.siteName)
                DRSService.drsStringPointer(w, dc.siteObjectName)
                DRSService.drsStringPointer(w, dc.computerObjectName)
                DRSService.drsStringPointer(w, dc.serverObjectName)
                DRSService.drsStringPointer(w, dc.ntdsDsaObjectName)
                w.u32(dc.isPdc ? 1 : 0)       // fIsPdc
                w.u32(1)                      // fDsEnabled
                w.u32(1)                      // fIsGc
                w.guid(dc.siteObjectGuid)     // SiteObjectGuid
                w.guid(dc.computerObjectGuid) // ComputerObjectGuid
                w.guid(dc.serverObjectGuid)   // ServerObjectGuid
                w.guid(dc.ntdsDsaObjectGuid)  // NtdsDsaObjectGuid
            }
        }
        w.flushDeferred()
    }
}

/// One DC as DRSUAPI reports it, derived from the provisioned domain info.
struct DCRecord {
    let netbiosName: String
    let dnsHostName: String
    let siteName: String
    let siteObjectName: String
    let computerObjectName: String
    let serverObjectName: String
    let ntdsDsaObjectName: String
    let isPdc: Bool
    let siteObjectGuid: DCEUUID
    let computerObjectGuid: DCEUUID
    let serverObjectGuid: DCEUUID
    let ntdsDsaObjectGuid: DCEUUID

    init(info: DomainInfo, computerGuid: GUID?) {
        let netbios = String(info.dcName.split(separator: ".").first ?? Substring(info.dcName)).uppercased()
        self.netbiosName = netbios
        self.dnsHostName = info.dcDNSName
        self.siteName = "Default-First-Site-Name"
        let baseDN = info.dnsDomain.split(separator: ".").map { "DC=\($0)" }.joined(separator: ",")
        self.computerObjectName = "CN=\(netbios),OU=Domain Controllers,\(baseDN)"
        self.serverObjectName =
            "CN=\(netbios),CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,\(baseDN)"
        self.ntdsDsaObjectName = "CN=NTDS Settings,\(self.serverObjectName)"
        self.siteObjectName = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,\(baseDN)"
        self.isPdc = true
        let zero = DCEUUID(bytes: [UInt8](repeating: 0, count: 16))
        // Prefer the real GUID from the store's DC computer object when present.
        self.computerObjectGuid = computerGuid.map { DCEUUID(bytes: $0.bytes) } ?? zero
        self.serverObjectGuid = zero
        self.siteObjectGuid = zero
        self.ntdsDsaObjectGuid = zero
    }
}
