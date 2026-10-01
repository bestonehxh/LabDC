import Foundation
import RPCKit
import Store
import MSPAC

extension NetlogonService {
    enum DcNameVariant { case base, ex, ex2 }

    /// The result of the shared trust-passwords computation (opnums 46 / 42 / 31): the reply status,
    /// the return authenticator credential, and the two DES-encrypted OWFs (`nil` = 16 zero bytes).
    struct TrustPasswordsResult {
        var status: UInt32
        var returnCredential: [UInt8]
        var new: [UInt8]?
        var old: [UInt8]?
    }

    static let dsReturnFlatName: UInt32 = 0x8000_0000

    /// `DsrGetDcName` (20) / `DsrGetDcNameEx` (27) / `DsrGetDcNameEx2` (34): return `DOMAIN_CONTROLLER_INFOW`.
    func dsrGetDcName(_ r: NDRReader, variant: DcNameVariant) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // ComputerName
        if variant == .ex2 {
            _ = try NLNDR.readTopLevelString(r)              // AccountName
            _ = try r.u32()                                  // AllowableAccountControlBits
        }
        let domainName = try NLNDR.readTopLevelString(r)     // DomainName
        _ = try NLNDR.readTopLevelGUID(r)                    // DomainGuid
        switch variant {
        case .base: _ = try NLNDR.readTopLevelGUID(r)        // SiteGuid
        case .ex, .ex2: _ = try NLNDR.readTopLevelString(r)  // SiteName
        }
        let flags = try r.u32()

        let info = try await store.domainInfo()
        let w = NDRWriter()
        // Domain match: accept our DNS or NetBIOS name (or an empty request = "this domain").
        if let d = domainName, !d.isEmpty,
           d.caseInsensitiveCompare(info.dnsDomain) != .orderedSame,
           d.caseInsensitiveCompare(info.netbiosDomain) != .orderedSame {
            w.u32(0)                                          // NULL DomainControllerInfo
            w.u32(NLStatus.errorNoSuchDomain)
            return w
        }

        let flat = (flags & Self.dsReturnFlatName) != 0
        let dcName = flat ? "\\\\" + info.dcName.uppercased() : "\\\\" + info.dcDNSName
        let address = "\\\\" + (dcInfo.advertisedIPv4 ?? info.dcDNSName)
        let domain = flat ? info.netbiosDomain : info.dnsDomain
        let site = dcInfo.dcSiteName

        NLNDR.writeReferent(w)                               // PDOMAIN_CONTROLLER_INFOW
        w.stringPointer(dcName)                              // DomainControllerName (LPWSTR)
        w.stringPointer(address)                             // DomainControllerAddress
        w.u32(1)                                             // DomainControllerAddressType = inet
        w.guid(DCEUUID(bytes: info.domainGUID.bytes))        // DomainGuid
        w.stringPointer(domain)                              // DomainName
        w.stringPointer(info.dnsDomain)                      // DnsForestName
        w.u32(dcInfo.dcFlags)                                // Flags
        w.stringPointer(site)                                // DcSiteName
        w.stringPointer(dcInfo.clientSiteName(forClientAddress: ""))  // ClientSiteName
        w.flushDeferred()
        w.u32(NLStatus.errorSuccess)
        return w
    }

    /// `DsrGetSiteName` (28): the client's site name.
    func dsrGetSiteName(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // ComputerName
        let w = NDRWriter()
        w.stringPointer(dcInfo.clientSiteName(forClientAddress: ""))
        w.flushDeferred()
        w.u32(NLStatus.errorSuccess)
        return w
    }

    /// `DsrEnumerateDomainTrusts` (40): just this domain (primary, in-forest, native, tree root).
    func dsrEnumerateDomainTrusts(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // ServerName
        _ = try r.u32()                                      // Flags
        let info = try await store.domainInfo()
        let w = NDRWriter()
        w.u32(1)                                             // DomainCount
        NLNDR.writeReferent(w)                               // Domains PDS_DOMAIN_TRUSTSW_ARRAY
        let netbios = info.netbiosDomain, dns = info.dnsDomain
        let sid = info.domainSID
        let guidBytes = info.domainGUID.bytes
        w.deferPointee {
            w.u32(1)                                         // conformant MaximumCount
            // DS_DOMAIN_TRUSTSW[0]
            w.stringPointer(netbios)                         // NetbiosDomainName
            w.stringPointer(dns)                             // DnsDomainName
            // Flags: IN_FOREST|PRIMARY|NATIVE_MODE|TREE_ROOT = 0x1D (Samba). It was 0x0F, which
            // is IN_FOREST|DIRECT_OUTBOUND|TREE_ROOT|PRIMARY — no NATIVE_MODE, a bogus outbound bit.
            w.u32(NetlogonTrustFlags.ownDomain)
            w.u32(0)                                         // ParentIndex
            w.u32(2)                                         // TrustType = uplevel
            w.u32(0)                                         // TrustAttributes
            NLNDR.writeReferent(w); w.deferPointee { w.sid(sid) }  // DomainSid
            w.guid(DCEUUID(bytes: guidBytes))               // DomainGuid
        }
        w.flushDeferred()
        w.u32(NLStatus.success)
        return w
    }

    /// `NetrLogonGetTrustRid` (23): the RID of this DC's own account (minimal).
    func netrLogonGetTrustRid(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // ServerName
        _ = try NLNDR.readTopLevelString(r)                  // DomainName
        let info = try await store.domainInfo()
        var rid: UInt32 = 0
        if let entry = try? await store.read(sam: info.dcName.uppercased() + "$"), let sid = entry.sid { rid = sid.rid ?? 0 }
        let w = NDRWriter()
        w.u32(rid)
        w.u32(NLStatus.success)
        return w
    }

    /// `NetrServerGetTrustInfo` (46), as Samba's `dcesrv_netr_ServerGetTrustInfo` and MS-NRPC
    /// §3.5.4.7.6 (WP-AQ). `nltest /sc_verify` calls it over the schannel and compares the returned
    /// OWFs with the member's own machine password: returning zeros was `ERROR_INVALID_PASSWORD`.
    ///
    /// - authenticator verified first (`STATUS_ACCESS_DENIED` otherwise, zero OWFs);
    /// - AccountName / SecureChannelType / ComputerName must be the channel's
    ///   (`STATUS_INVALID_PARAMETER`, Samba);
    /// - workstation/server/RODC channels: EncryptedNewOwfPassword = the account's current NT hash,
    ///   EncryptedOldOwfPassword = NTOWFv1("") — the spec and Samba use the empty string's OWF as
    ///   the "previous" password of a computer account, not the password history — and TrustInfo
    ///   NULL. Trusted-domain channels would read the TDO's trustAuthIncoming; LabDC has no
    ///   TDOs, which Samba answers `STATUS_ACCOUNT_DISABLED`;
    /// - both OWFs DES-encrypted with the session key (`NetlogonCrypto.encryptOWF`), whatever the
    ///   negotiated flags.
    func netrServerGetTrustInfo(_ r: NDRReader) async throws -> NDRWriter {
        let tp = try await serverTrustInfoCore(r, label: "GetTrustInfo", bdcOnly: false)
        let zero16 = [UInt8](repeating: 0, count: 16)
        let w = NDRWriter()
        writeAuthenticator(w, credential: tp.returnCredential, timestamp: 0)
        w.raw(tp.new ?? zero16)                              // EncryptedNewOwfPassword
        w.raw(tp.old ?? zero16)                              // EncryptedOldOwfPassword
        w.u32(0)                                             // TrustInfo PNL_GENERIC_RPC_DATA = NULL
        w.u32(tp.status)
        return w
    }

    /// `NetrServerTrustPasswordsGet` (42), MS-NRPC §3.5.4.4.8. Samba routes it through
    /// `dcesrv_netr_ServerGetTrustInfo` (`dcesrv_netr_ServerTrustPasswordsGet`), so it behaves
    /// exactly like GetTrustInfo (same authenticator step, same parameter checks, the current NT
    /// hash as the new OWF and NTOWFv1("") as the old, both DES-encrypted with the session key),
    /// only the reply drops the trailing `TrustInfo` field.
    func netrServerTrustPasswordsGet(_ r: NDRReader) async throws -> NDRWriter {
        let tp = try await serverTrustInfoCore(r, label: "ServerTrustPasswordsGet", bdcOnly: false)
        let zero16 = [UInt8](repeating: 0, count: 16)
        let w = NDRWriter()
        writeAuthenticator(w, credential: tp.returnCredential, timestamp: 0)
        w.raw(tp.new ?? zero16)                              // EncryptedNewOwfPassword
        w.raw(tp.old ?? zero16)                              // EncryptedOldOwfPassword
        w.u32(tp.status)
        return w
    }

    /// `NetrServerPasswordGet` (31), MS-NRPC §3.5.4.4.6. Samba's
    /// `dcesrv_netr_ServerPasswordGet` runs `dcesrv_netr_ServerGetTrustInfo` and then returns only
    /// the single (current) OWF — but only for a `SEC_CHAN_BDC` (`.server`, 6) channel. Any other
    /// requested channel type (a plain workstation member) gets `STATUS_ACCESS_DENIED` with a zeroed
    /// OWF, though the return authenticator from the step is still valid. `serverTrustInfoCore`
    /// applies that BDC gate when `bdcOnly` is set.
    func netrServerPasswordGet(_ r: NDRReader) async throws -> NDRWriter {
        let tp = try await serverTrustInfoCore(r, label: "ServerPasswordGet", bdcOnly: true)
        let zero16 = [UInt8](repeating: 0, count: 16)
        let w = NDRWriter()
        writeAuthenticator(w, credential: tp.returnCredential, timestamp: 0)
        w.raw(tp.new ?? zero16)                              // EncryptedNtOwfPassword (single OWF)
        w.u32(tp.status)
        return w
    }

    /// The trust-passwords computation shared by opnums 46, 42 and 31 (Samba's
    /// `dcesrv_netr_ServerGetTrustInfo`). Reads the common request shape, runs the authenticator
    /// step and the AccountName / SecureChannelType / ComputerName checks, and — for a
    /// workstation/server/RODC channel — returns the account's current NT hash as `new` and
    /// NTOWFv1("") as `old`, both DES-encrypted with the session key. Trusted-domain channels get
    /// `STATUS_ACCOUNT_DISABLED` (no TDOs). `label` names the op in the log line. When `bdcOnly`
    /// is set (opnum 31), a non-`SEC_CHAN_BDC` request is demoted to `STATUS_ACCESS_DENIED` with a
    /// zeroed OWF before logging.
    private func serverTrustInfoCore(_ r: NDRReader, label: String, bdcOnly: Bool) async throws -> TrustPasswordsResult {
        _ = try NLNDR.readTopLevelString(r)                  // TrustedDcName / PrimaryName (not checked, = Samba)
        let accountName = try NLNDR.readInlineWSTR(r)        // AccountName ("PC1$")
        let channelTypeRaw = try r.enum16()                  // SecureChannelType
        let computer = try NLNDR.readInlineWSTR(r)           // ComputerName
        let auth = try readAuthenticator(r)

        var returnCredential = [UInt8](repeating: 0, count: 8)
        let compute: () async throws -> (status: UInt32, account: String?, reason: String?, new: [UInt8]?, old: [UInt8]?) = {
            guard let channel = self.state.channel(computer: computer) else {
                return (NLStatus.accessDenied, nil, "no secure channel", nil, nil)
            }
            let step = self.stepAuthenticator(channel, received: auth)
            returnCredential = step.returnCredential
            guard step.ok else {
                return (NLStatus.accessDenied, channel.accountName, "authenticator mismatch", nil, nil)
            }
            guard accountName.caseInsensitiveCompare(channel.accountName) == .orderedSame else {
                return (NLStatus.invalidParameter, channel.accountName,
                        "account name is not the channel's \(channel.accountName)", nil, nil)
            }
            guard UInt32(channelTypeRaw) == channel.secureChannelType.rawValue else {
                return (NLStatus.invalidParameter, channel.accountName,
                        "type=\(Self.channelTypeName(channelTypeRaw)) is not the channel's", nil, nil)
            }
            guard computer.caseInsensitiveCompare(channel.computerName) == .orderedSame else {
                return (NLStatus.invalidParameter, channel.accountName, "computer name", nil, nil)
            }
            switch channel.secureChannelType {
            case .trustedDomain, .trustedDnsDomain:
                return (NLStatus.accountDisabled, channel.accountName, "no trusted domain object", nil, nil)
            default:
                break
            }
            guard let account = try await self.machineNTHash(sam: channel.accountName) else {
                return (NLStatus.accountDisabled, channel.accountName, "no such account / NT hash", nil, nil)
            }
            let new = NetlogonCrypto.encryptOWF(sessionKey: channel.sessionKey, account.ntHash)
            let old = NetlogonCrypto.encryptOWF(sessionKey: channel.sessionKey, DirectoryStore.ntHash(""))
            return (NLStatus.success, channel.accountName, nil, new, old)
        }

        var (status, account, reason, new, old) = try await compute()

        if bdcOnly && UInt32(channelTypeRaw) != NetlogonSecureChannelType.server.rawValue {
            status = NLStatus.accessDenied
            reason = "channel type \(Self.channelTypeName(channelTypeRaw)) is not a BDC"
            new = nil
            old = nil
        }

        logEvent("\(label) \(accountName)" + fromClause(account: account) + Self.outcome(status, reason))
        return TrustPasswordsResult(status: status, returnCredential: returnCredential, new: new, old: old)
    }

    /// `NetrLogonControl2Ex` (18) / `NetrLogonControl2` (14): trivial `NETLOGON_INFO_1/2`.
    /// `NetrLogonControl2Ex` (18) / `NetrLogonControl2` (14), and with `withData: false`
    /// `NetrLogonControl` (12), which has no `Data` argument — winbindd calls it
    /// (`dcerpc_netr_LogonControl`, NETLOGON_CONTROL_QUERY level 1) when it sets up a domain (WP-Z).
    func netrLogonControl2(_ r: NDRReader, withData: Bool = true) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // ServerName
        _ = try r.u32()                                      // FunctionCode
        let queryLevel = try r.u32()
        if withData {
            // NETLOGON_CONTROL_DATA_INFORMATION: discriminant then an optional arm we do not need.
            let dataTag = try r.u32()
            switch dataTag {
            case 5, 6, 8, 9, 10: _ = try NLNDR.readTopLevelString(r)  // TrustedDomainName / UserName
            case 65534: _ = try r.u32()                               // DebugFlag
            default: break
            }
        }
        let info = try await store.domainInfo()
        let w = NDRWriter()
        let level = queryLevel == 0 ? 1 : queryLevel
        w.u32(level)                                         // NETLOGON_CONTROL_QUERY_INFORMATION tag
        NLNDR.writeReferent(w)                               // arm pointer
        switch level {
        case 2:
            w.u32(0)                                         // netlog2_flags
            w.u32(0)                                         // netlog2_pdc_connection_status
            w.stringPointer("\\\\" + info.dcDNSName)         // netlog2_trusted_dc_name
            w.u32(0)                                         // netlog2_tc_connection_status
            w.flushDeferred()
        case 3:
            w.u32(0); w.u32(0); w.u32(0); w.u32(0); w.u32(0); w.u32(0); w.u32(0)  // INFO_3
        case 4:
            w.stringPointer("\\\\" + info.dcDNSName)         // netlog4_trusted_dc_name
            w.stringPointer(info.dnsDomain)                  // netlog4_trusted_domain_name
            w.flushDeferred()
        default:
            w.u32(0)                                         // netlog1_flags
            w.u32(0)                                         // netlog1_pdc_connection_status
        }
        w.u32(NLStatus.errorSuccess)
        return w
    }
}
