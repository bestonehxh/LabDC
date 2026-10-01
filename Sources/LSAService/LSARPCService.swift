import AuthKit
import Foundation
import MSPAC
import os
import RPCKit
import Store

/// State behind an LSA policy handle.
struct PolicyHandleState: Sendable {
    let grantedAccess: UInt32
    let opener: String
}

/// The `lsarpc` interface (MS-LSAD + MS-LSAT, UUID 12345778-1234-abcd-ef00-0123456789ab v0.0) of a
/// single-domain DC, backed by the Store.
///
/// Opnums: `LsarClose` 0, `LsarOpenPolicy` 6, `LsarQueryInformationPolicy` 7, `LsarLookupNames` 14,
/// `LsarLookupSids` 15, `LsarOpenPolicy2` 44, `LsarGetUserName` 45, `LsarQueryInformationPolicy2`
/// 46, `LsarEnumerateTrustedDomainsEx` 50, `LsarLookupSids2` 57, `LsarLookupNames2` 58,
/// `LsarLookupNames3` 68, `LsarLookupSids3` 76, `LsarLookupNames4` 77, `LsarOpenPolicy3` 130.
/// Anything else faults with `nca_op_rng_error`.
///
/// Access: an anonymous caller (NT AUTHORITY\ANONYMOUS LOGON on the pipe's SMB session) gets
/// `STATUS_ACCESS_DENIED` from the policy opens and the handle-less lookups unless
/// `allowAnonymous` is set; `LsarGetUserName` answers anyone.
public struct LSARPCService: RPCInterface {
    public static let uuid = DCEUUID("12345778-1234-abcd-ef00-0123456789ab")
    public static let pipeName = "lsarpc"
    static let handleType = "lsa.policy"
    static let logger = Logger(subsystem: "dev.labdc.app", category: "LSAService")

    public enum Opnum {
        public static let close: UInt16 = 0
        public static let openPolicy: UInt16 = 6
        public static let queryInformationPolicy: UInt16 = 7
        public static let lookupNames: UInt16 = 14
        public static let lookupSids: UInt16 = 15
        public static let openPolicy2: UInt16 = 44
        public static let getUserName: UInt16 = 45
        public static let queryInformationPolicy2: UInt16 = 46
        public static let enumerateTrustedDomainsEx: UInt16 = 50
        /// LsarEnumerateTrustedDomains — same wire shape as the Ex form; `rpcclient enumtrust` (WP-Z).
        public static let enumerateTrustedDomains: UInt16 = 13
        public static let lookupSids2: UInt16 = 57
        public static let lookupNames2: UInt16 = 58
        public static let lookupNames3: UInt16 = 68
        public static let lookupSids3: UInt16 = 76
        public static let lookupNames4: UInt16 = 77
        /// LsarOpenPolicy3 (MS-LSAD §3.1.4.4.1, Windows 10+/Server 2019+; Samba `lsa_OpenPolicy3`):
        /// Windows netjoin (`NetpDsValidateComputerAccountReuseAttempt`) opens the policy with it.
        public static let openPolicy3: UInt16 = 130
    }

    public let store: DirectoryStore
    public let resolver: AccountResolver
    /// Lab flag: let anonymous callers open policy handles and look up names.
    public let allowAnonymous: Bool

    public init(store: DirectoryStore, allowAnonymous: Bool = false) {
        self.store = store
        self.resolver = AccountResolver(store: store)
        self.allowAnonymous = allowAnonymous
    }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (0, 0) }

    public func dispatch(opnum: UInt16, input: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        let w = NDRWriter()
        switch opnum {
        case Opnum.close: try close(input, context, w)
        case Opnum.openPolicy, Opnum.openPolicy2: try openPolicy(input, context, w)
        case Opnum.openPolicy3: try openPolicy3(input, context, w)
        case Opnum.queryInformationPolicy, Opnum.queryInformationPolicy2: try await queryInformation(input, context, w)
        case Opnum.lookupNames: try await lookupNames(input, context, w, form: .v1, hasHandle: true, extended: false)
        case Opnum.lookupNames2: try await lookupNames(input, context, w, form: .ex, hasHandle: true, extended: true)
        case Opnum.lookupNames3: try await lookupNames(input, context, w, form: .ex2, hasHandle: true, extended: true)
        case Opnum.lookupNames4: try await lookupNames(input, context, w, form: .ex2, hasHandle: false, extended: true)
        case Opnum.lookupSids: try await lookupSids(input, context, w, form: .v1, hasHandle: true, extended: false)
        case Opnum.lookupSids2: try await lookupSids(input, context, w, form: .ex, hasHandle: true, extended: true)
        case Opnum.lookupSids3: try await lookupSids(input, context, w, form: .ex, hasHandle: false, extended: true)
        case Opnum.getUserName: try getUserName(input, context, w)
        case Opnum.enumerateTrustedDomainsEx, Opnum.enumerateTrustedDomains: try enumerateTrustedDomains(input, context, w)
        default:
            throw RPCError.fault(.opRangeError)
        }
        return w
    }

    // MARK: handles

    private func policy(_ r: NDRReader, _ context: RPCCallContext) throws -> PolicyHandleState {
        let h = try r.contextHandle()
        guard let state = context.handles.resolve(h, type: Self.handleType, as: PolicyHandleState.self) else {
            throw RPCError.fault(.contextMismatch)
        }
        return state
    }

    private func denied(_ context: RPCCallContext) -> Bool {
        context.identity.isAnonymous && !allowAnonymous
    }

    /// `NTSTATUS LsarClose([in, out] LSAPR_HANDLE* ObjectHandle)`.
    private func close(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) throws {
        let h = try r.contextHandle()
        guard context.handles.resolve(h, type: Self.handleType, as: PolicyHandleState.self) != nil else {
            throw RPCError.fault(.contextMismatch)
        }
        context.handles.close(h)
        w.contextHandle(.null)
        w.u32(NTStatus.success)
    }

    /// `LsarOpenPolicy([in, unique] wchar_t* SystemName, [in] PLSAPR_OBJECT_ATTRIBUTES, [in]
    /// ACCESS_MASK DesiredAccess, [out] LSAPR_HANDLE*)` and `LsarOpenPolicy2` (SystemName is
    /// `[string]` there). MS-LSAD §3.1.4.4.1 says the object attributes are ignored, so only the
    /// trailing `DesiredAccess` is read; the stub must at least hold a NULL SystemName and the
    /// 24-byte attribute struct.
    private func openPolicy(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) throws {
        let rest = try r.take(r.remaining)
        guard rest.count >= 32 else { throw NDRError(offset: 0, reason: "OpenPolicy stub too short (\(rest.count))") }
        let n = rest.count
        let access = UInt32(rest[n - 4]) | UInt32(rest[n - 3]) << 8 | UInt32(rest[n - 2]) << 16 | UInt32(rest[n - 1]) << 24
        if denied(context) {
            Self.logger.info("LsarOpenPolicy denied to anonymous caller")
            w.contextHandle(.null)
            w.u32(NTStatus.accessDenied)
            return
        }
        let h = context.handles.allocate(type: Self.handleType,
                                         state: PolicyHandleState(grantedAccess: access, opener: context.identity.downLevelName))
        w.contextHandle(h)
        w.u32(NTStatus.success)
    }

    /// `LSA_FEATURE_TDO_AUTH_INFO_AES_CIPHER` (MS-LSAD §2.2.1.1.x `LSAPR_REVISION_INFO_V1`), what
    /// Samba's `dcesrv_lsa_OpenPolicy3` advertises.
    static let featureTDOAuthInfoAESCipher: UInt32 = 0x0000_0001

    /// `NTSTATUS LsarOpenPolicy3([in, unique, string] wchar_t* SystemName, [in]
    /// PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes, [in] ACCESS_MASK DesiredAccess, [in] unsigned long
    /// InVersion, [in, switch_is(InVersion)] LSAPR_REVISION_INFO* InRevisionInfo, [out] unsigned
    /// long* OutVersion, [out, switch_is(*OutVersion)] LSAPR_REVISION_INFO* OutRevisionInfo, [out]
    /// LSAPR_HANDLE* PolicyHandle)` — OpenPolicy2 plus a revision exchange (MS-LSAD §3.1.4.4.1;
    /// Samba `source4/rpc_server/lsa/lsa_init.c` `dcesrv_lsa_OpenPolicy3`):
    /// - the object attributes are ignored except that a non-NULL RootDirectory is
    ///   `STATUS_INVALID_PARAMETER`;
    /// - InVersion must be 1 (`STATUS_NOT_SUPPORTED` otherwise); the answer is OutVersion 1,
    ///   `{Revision 1, SupportedFeatures LSA_FEATURE_TDO_AUTH_INFO_AES_CIPHER}`;
    /// - then the same handle as OpenPolicy2 (anonymous → `STATUS_ACCESS_DENIED`).
    /// The out-parameters are always a well-formed version-1 union, also on failure (Samba would
    /// fault marshalling a version-0 union), with a NULL handle.
    private func openPolicy3(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) throws {
        let systemName = try r.stringPointerInline()
        // LSAPR_OBJECT_ATTRIBUTES ([ref], so no referent id): the flat part, then its pointees.
        r.align(4)
        _ = try r.u32()                                    // Length
        let rootDirectory = try r.pointer()
        let objectName = try r.pointer()
        _ = try r.u32()                                    // Attributes
        let securityDescriptor = try r.pointer()
        let qos = try r.pointer()
        let access: UInt32, inVersion: UInt32
        if objectName == nil, securityDescriptor == nil {
            if rootDirectory != nil { _ = try r.u8() }     // unsigned char* RootDirectory
            if qos != nil { r.align(4); _ = try r.take(8) } // SECURITY_QUALITY_OF_SERVICE
            access = try r.u32()
            inVersion = try r.u32()
            if inVersion == 1 {
                let tag = try r.u32()                      // non-encapsulated union discriminant
                guard tag == inVersion else {
                    throw NDRError(offset: r.offset, reason: "OpenPolicy3 InRevisionInfo tag \(tag) != InVersion 1")
                }
                _ = try r.u32(); _ = try r.u32()           // V1 {Revision, SupportedFeatures}
            }
        } else {
            // MS-LSAD says these are ignored, and their encodings differ between the MS-LSAD and
            // Samba IDLs (STRING vs [string] wchar_t*, LSAPR_SECURITY_DESCRIPTOR vs
            // security_descriptor): read the fixed tail of a version-1 call instead.
            let rest = try r.take(r.remaining)
            guard rest.count >= 20 else { throw NDRError(offset: 0, reason: "OpenPolicy3 stub too short") }
            func le(_ i: Int) -> UInt32 {
                UInt32(rest[i]) | UInt32(rest[i + 1]) << 8 | UInt32(rest[i + 2]) << 16 | UInt32(rest[i + 3]) << 24
            }
            let n = rest.count
            access = le(n - 20)
            inVersion = le(n - 16) == 1 && le(n - 12) == 1 ? 1 : 0
        }

        func reply(_ status: UInt32, _ handle: ContextHandle) {
            w.u32(1)                                       // OutVersion
            w.u32(1)                                       // OutRevisionInfo union discriminant
            w.u32(1)                                       // V1.Revision
            w.u32(Self.featureTDOAuthInfoAESCipher)        // V1.SupportedFeatures
            w.contextHandle(handle)
            w.u32(status)
        }
        let caller = context.identity.downLevelName
        let head = "LsarOpenPolicy3 \(systemName ?? "(null)") InVersion=\(inVersion) access=0x\(String(access, radix: 16)) from \(caller)"
        if rootDirectory != nil {
            Self.logger.info("\(head, privacy: .public) -> INVALID_PARAMETER (RootDirectory)")
            return reply(NTStatus.invalidParameter, .null)
        }
        guard inVersion == 1 else {
            Self.logger.info("\(head, privacy: .public) -> NOT_SUPPORTED")
            return reply(NTStatus.notSupported, .null)
        }
        if denied(context) {
            Self.logger.info("\(head, privacy: .public) -> ACCESS_DENIED (anonymous)")
            return reply(NTStatus.accessDenied, .null)
        }
        let h = context.handles.allocate(type: Self.handleType,
                                         state: PolicyHandleState(grantedAccess: access, opener: caller))
        Self.logger.info("\(head, privacy: .public) -> OK")
        reply(NTStatus.success, h)
    }

    // MARK: QueryInformationPolicy(2)

    /// `LsarQueryInformationPolicy(2)([in] LSAPR_HANDLE, [in] POLICY_INFORMATION_CLASS, [out,
    /// switch_is(InformationClass)] PLSAPR_POLICY_INFORMATION* PolicyInformation)`.
    private func queryInformation(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) async throws {
        _ = try policy(r, context)
        let infoClass = try r.enum16()
        guard let info = try await policyInformation(infoClass) else {
            PolicyInformation.encodeTopLevel(nil, w)
            w.u32(NTStatus.invalidParameter)
            return
        }
        PolicyInformation.encodeTopLevel(info, w)
        w.u32(NTStatus.success)
    }

    /// The policy information this DC reports for `infoClass`, or nil for an unsupported class.
    public func policyInformation(_ infoClass: UInt16) async throws -> PolicyInformation? {
        let info = try await store.domainInfo()
        let dns = DNSDomainInfo(name: info.netbiosDomain, dnsDomainName: info.dnsDomain, dnsForestName: info.dnsDomain,
                                domainGUID: DCEUUID(bytes: info.domainGUID.bytes), sid: info.domainSID)
        switch infoClass {
        case PolicyInformationClass.auditEvents:
            // Auditing off; one "unchanged/none" option per POLICY_AUDIT_EVENT_TYPE (9 categories).
            return .auditEvents(auditingMode: false, options: Array(repeating: 0, count: 9))
        case PolicyInformationClass.primaryDomain: return .primaryDomain(name: info.netbiosDomain, sid: info.domainSID)
        case PolicyInformationClass.accountDomain: return .accountDomain(name: info.netbiosDomain, sid: info.domainSID)
        case PolicyInformationClass.lsaServerRole: return .serverRole(3)   // PolicyServerRolePrimary
        case PolicyInformationClass.dnsDomain: return .dnsDomain(dns)
        case PolicyInformationClass.dnsDomainInt: return .dnsDomainInt(dns)
        default: return nil
        }
    }

    // MARK: LookupNames(2/3/4)

    /// `LsarLookupNames` (14): `[in] LSAPR_HANDLE, [in, range(0,1000)] Count, [in, size_is(Count)]
    /// PRPC_UNICODE_STRING Names, [out] PLSAPR_REFERENCED_DOMAIN_LIST*, [in, out]
    /// PLSAPR_TRANSLATED_SIDS, [in] LSAP_LOOKUP_LEVEL, [in, out] unsigned long* MappedCount`;
    /// `…2` (58) and `…3` (68) add `[in] LookupOptions, [in] ClientRevision` and use the _EX /
    /// _EX2 SID forms; `…4` (77) is `…3` without the policy handle.
    private func lookupNames(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter,
                             form: TranslatedSIDForm, hasHandle: Bool, extended: Bool) async throws {
        if hasHandle { _ = try policy(r, context) }
        let count = Int(try r.u32())
        guard count <= 1000 else { throw NDRError(offset: r.offset, reason: "Count \(count) out of range(0,1000)") }
        let names = try UnicodeStringArray.decode(r)
        guard names.count == count else { throw NDRError(offset: r.offset, reason: "Names \(names.count) != Count \(count)") }
        _ = try TranslatedSIDs.decode(form: form, r)     // [in] side, normally empty
        let level = try r.enum16()
        _ = try r.u32()                                   // MappedCount in
        if extended { _ = try r.u32(); _ = try r.u32() }  // LookupOptions, ClientRevision

        if (!hasHandle && denied(context)) || !(1...6).contains(level) {
            ReferencedDomainList.encodeTopLevel(nil, w)
            TranslatedSIDs.encode([], form: form, w)
            w.u32(0)
            w.u32(denied(context) ? NTStatus.accessDenied : NTStatus.invalidParameter)
            return
        }

        var domains = DomainIndexer()
        var out: [TranslatedSID] = []
        var mapped = 0
        for name in names {
            if let a = try await resolver.resolve(name: name) {
                mapped += 1
                out.append(TranslatedSID(use: a.use.rawValue, relativeID: a.relativeID, sid: a.sid,
                                         domainIndex: domains.index(of: a.domain)))
            } else {
                out.append(TranslatedSID(use: SIDNameUse.unknown.rawValue, relativeID: 0, sid: nil, domainIndex: -1))
            }
        }
        ReferencedDomainList.encodeTopLevel(ReferencedDomainList(domains: domains.list), w)
        TranslatedSIDs.encode(out, form: form, w)
        w.u32(UInt32(mapped))
        w.u32(Self.lookupStatus(mapped: mapped, total: names.count))
    }

    // MARK: LookupSids(2/3)

    /// `LsarLookupSids` (15): `[in] LSAPR_HANDLE, [in] PLSAPR_SID_ENUM_BUFFER, [out]
    /// PLSAPR_REFERENCED_DOMAIN_LIST*, [in, out] PLSAPR_TRANSLATED_NAMES, [in] LSAP_LOOKUP_LEVEL,
    /// [in, out] unsigned long* MappedCount`; `…2` (57) adds `LookupOptions, ClientRevision` with
    /// the _EX name form; `…3` (76) is `…2` without the handle.
    private func lookupSids(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter,
                            form: TranslatedNameForm, hasHandle: Bool, extended: Bool) async throws {
        if hasHandle { _ = try policy(r, context) }
        let sids = try SIDEnumBuffer.decode(r)
        _ = try TranslatedNames.decode(form: form, r)
        let level = try r.enum16()
        _ = try r.u32()
        if extended { _ = try r.u32(); _ = try r.u32() }

        if (!hasHandle && denied(context)) || !(1...6).contains(level) {
            ReferencedDomainList.encodeTopLevel(nil, w)
            TranslatedNames.encode([], form: form, w)
            w.u32(0)
            w.u32(denied(context) ? NTStatus.accessDenied : NTStatus.invalidParameter)
            return
        }

        var domains = DomainIndexer()
        var out: [TranslatedName] = []
        var mapped = 0
        for sid in sids {
            guard let sid else {
                out.append(TranslatedName(use: SIDNameUse.unknown.rawValue, name: "", domainIndex: -1))
                continue
            }
            if let a = try await resolver.resolve(sid: sid) {
                mapped += 1
                out.append(TranslatedName(use: a.use.rawValue, name: a.name, domainIndex: domains.index(of: a.domain)))
            } else {
                // Unmapped: the SID string as the name; the domain is still referenced when known.
                let idx = try await resolver.authority(of: sid).map { domains.index(of: $0) } ?? -1
                out.append(TranslatedName(use: SIDNameUse.unknown.rawValue, name: sid.description, domainIndex: idx))
            }
        }
        ReferencedDomainList.encodeTopLevel(ReferencedDomainList(domains: domains.list), w)
        TranslatedNames.encode(out, form: form, w)
        w.u32(UInt32(mapped))
        w.u32(Self.lookupStatus(mapped: mapped, total: sids.count))
    }

    static func lookupStatus(mapped: Int, total: Int) -> UInt32 {
        if mapped == total { return NTStatus.success }
        return mapped == 0 ? NTStatus.noneMapped : NTStatus.someNotMapped
    }

    // MARK: GetUserName

    /// `LsarGetUserName([in, unique, string] wchar_t* SystemName, [in, out] PRPC_UNICODE_STRING*
    /// UserName, [in, out, unique] PRPC_UNICODE_STRING* DomainName)`. Returns the caller's
    /// identity from the SMB session (`NT AUTHORITY\ANONYMOUS LOGON` for anonymous).
    private func getUserName(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) throws {
        _ = try r.stringPointerInline()
        if try r.pointer() != nil { _ = try r.unicodeStringInline() }       // *UserName (usually NULL)
        let wantsDomain = try r.pointer() != nil                             // DomainName (outer)
        if wantsDomain, try r.pointer() != nil { _ = try r.unicodeStringInline() }

        _ = w.uniquePointer(true)
        w.rpcUnicodeString(context.identity.sam)
        w.flushDeferred()
        if w.uniquePointer(wantsDomain) {
            _ = w.uniquePointer(true)
            w.rpcUnicodeString(context.identity.domain)
            w.flushDeferred()
        }
        w.u32(NTStatus.success)
    }

    // MARK: EnumerateTrustedDomainsEx

    /// `LsarEnumerateTrustedDomainsEx([in] LSAPR_HANDLE, [in, out] unsigned long*
    /// EnumerationContext, [out] PLSAPR_TRUSTED_ENUM_BUFFER_EX, [in] PreferedMaximumLength)`:
    /// a single-domain forest has no trusts, so `STATUS_NO_MORE_ENTRIES` with an empty buffer.
    private func enumerateTrustedDomains(_ r: NDRReader, _ context: RPCCallContext, _ w: NDRWriter) throws {
        _ = try policy(r, context)
        let enumContext = try r.u32()
        _ = try r.u32()
        w.u32(enumContext)
        w.u32(0)          // EntriesRead
        w.u32(0)          // EnumerationBuffer = NULL
        w.u32(NTStatus.noMoreEntries)
    }
}

/// Builds the `LSAPR_REFERENCED_DOMAIN_LIST` in first-reference order.
struct DomainIndexer {
    private(set) var domains: [ReferencedDomain] = []

    mutating func index(of d: ReferencedDomain) -> Int32 {
        if let i = domains.firstIndex(where: { $0.sid == d.sid }) { return Int32(i) }
        domains.append(d)
        return Int32(domains.count - 1)
    }

    var list: [TrustInformation] { domains.map { TrustInformation(name: $0.name, sid: $0.sid) } }
}
