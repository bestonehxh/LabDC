/// GROUP_MEMBERSHIP (MS-PAC §2.2.2): a RID in the account (or resource) domain plus
/// SE_GROUP_* attributes.
public struct GroupMembership: Sendable, Hashable {
    public var relativeId: UInt32
    public var attributes: UInt32

    /// SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED.
    public static let defaultAttributes: UInt32 = 0x0000_0007

    public init(relativeId: UInt32, attributes: UInt32 = GroupMembership.defaultAttributes) {
        self.relativeId = relativeId
        self.attributes = attributes
    }

    /// The account-domain group RIDs a DC puts in `GroupIds` (KERB_VALIDATION_INFO and
    /// NETLOGON_VALIDATION_SAM_INFO*): the primary group first, then `rids` in order, each RID
    /// once. Windows DCs and Samba (`auth_sam_reply.c`, from PRIMARY_GROUP_SID_INDEX) always list
    /// the primary group here as well as in `PrimaryGroupId`; a token built without it has no
    /// `Domain Users` (WP-AO).
    public static func accountGroupRIDs(primary: UInt32, rids: [UInt32]) -> [UInt32] {
        var out = [primary]
        for rid in rids where !out.contains(rid) { out.append(rid) }
        return out
    }

    /// `accountGroupRIDs(primary:rids:)` with SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED.
    public static func accountGroups(primary: UInt32, rids: [UInt32]) -> [GroupMembership] {
        accountGroupRIDs(primary: primary, rids: rids).map { GroupMembership(relativeId: $0) }
    }
}

/// KERB_SID_AND_ATTRIBUTES (MS-PAC §2.2.1).
public struct SIDAndAttributes: Sendable, Hashable {
    public var sid: SID
    public var attributes: UInt32

    public init(sid: SID, attributes: UInt32 = GroupMembership.defaultAttributes) {
        self.sid = sid
        self.attributes = attributes
    }
}

/// KERB_VALIDATION_INFO (MS-PAC §2.5), the body of PAC_LOGON_INFO (buffer type 1).
///
/// Fields are in wire order. Reserved fields (`Reserved1[2]`, `Reserved3`) are not modelled:
/// they are written as zero and ignored on receipt, as the spec requires. `GroupCount`,
/// `SidCount` and `ResourceGroupCount` are derived from the arrays.
public struct KerberosValidationInfo: Sendable, Hashable {
    public var logonTime: FileTime
    public var logoffTime: FileTime
    public var kickOffTime: FileTime
    public var passwordLastSet: FileTime
    public var passwordCanChange: FileTime
    public var passwordMustChange: FileTime
    public var effectiveName: String
    public var fullName: String
    public var logonScript: String
    public var profilePath: String
    public var homeDirectory: String
    public var homeDirectoryDrive: String
    public var logonCount: UInt16
    public var badPasswordCount: UInt16
    public var userId: UInt32
    public var primaryGroupId: UInt32
    public var groupIds: [GroupMembership]
    public var userFlags: UInt32
    /// 16 bytes; MUST be zero for Kerberos.
    public var userSessionKey: [UInt8]
    public var logonServer: String
    public var logonDomainName: String
    public var logonDomainId: SID
    public var userAccountControl: UInt32
    public var subAuthStatus: UInt32
    public var lastSuccessfulILogon: FileTime
    public var lastFailedILogon: FileTime
    public var failedILogonCount: UInt32
    public var extraSids: [SIDAndAttributes]
    public var resourceGroupDomainSid: SID?
    public var resourceGroupIds: [GroupMembership]

    // UserFlags bits valid for Kerberos (MS-PAC §2.5 "D" and "H"; netlogon values).
    public static let userFlagExtraSids: UInt32 = 0x0000_0020
    public static let userFlagResourceGroups: UInt32 = 0x0000_0200

    // UserAccountControl bits (MS-SAMR §2.2.1.12).
    public static let uacAccountDisabled: UInt32 = 0x0000_0001
    public static let uacNormalAccount: UInt32 = 0x0000_0010
    public static let uacWorkstationTrustAccount: UInt32 = 0x0000_0080
    public static let uacServerTrustAccount: UInt32 = 0x0000_0100
    public static let uacDontExpirePassword: UInt32 = 0x0000_0200

    public init(
        logonTime: FileTime = .zero,
        logoffTime: FileTime = .never,
        kickOffTime: FileTime = .never,
        passwordLastSet: FileTime = .zero,
        passwordCanChange: FileTime = .zero,
        passwordMustChange: FileTime = .never,
        effectiveName: String,
        fullName: String = "",
        logonScript: String = "",
        profilePath: String = "",
        homeDirectory: String = "",
        homeDirectoryDrive: String = "",
        logonCount: UInt16 = 0,
        badPasswordCount: UInt16 = 0,
        userId: UInt32,
        primaryGroupId: UInt32 = 513,
        groupIds: [GroupMembership],
        userFlags: UInt32 = 0,
        userSessionKey: [UInt8] = [UInt8](repeating: 0, count: 16),
        logonServer: String,
        logonDomainName: String,
        logonDomainId: SID,
        userAccountControl: UInt32 = KerberosValidationInfo.uacNormalAccount | KerberosValidationInfo.uacDontExpirePassword,
        subAuthStatus: UInt32 = 0,
        lastSuccessfulILogon: FileTime = .zero,
        lastFailedILogon: FileTime = .zero,
        failedILogonCount: UInt32 = 0,
        extraSids: [SIDAndAttributes] = [],
        resourceGroupDomainSid: SID? = nil,
        resourceGroupIds: [GroupMembership] = []
    ) {
        self.logonTime = logonTime
        self.logoffTime = logoffTime
        self.kickOffTime = kickOffTime
        self.passwordLastSet = passwordLastSet
        self.passwordCanChange = passwordCanChange
        self.passwordMustChange = passwordMustChange
        self.effectiveName = effectiveName
        self.fullName = fullName
        self.logonScript = logonScript
        self.profilePath = profilePath
        self.homeDirectory = homeDirectory
        self.homeDirectoryDrive = homeDirectoryDrive
        self.logonCount = logonCount
        self.badPasswordCount = badPasswordCount
        self.userId = userId
        self.primaryGroupId = primaryGroupId
        self.groupIds = groupIds
        self.userFlags = userFlags
        self.userSessionKey = userSessionKey
        self.logonServer = logonServer
        self.logonDomainName = logonDomainName
        self.logonDomainId = logonDomainId
        self.userAccountControl = userAccountControl
        self.subAuthStatus = subAuthStatus
        self.lastSuccessfulILogon = lastSuccessfulILogon
        self.lastFailedILogon = lastFailedILogon
        self.failedILogonCount = failedILogonCount
        self.extraSids = extraSids
        self.resourceGroupDomainSid = resourceGroupDomainSid
        self.resourceGroupIds = resourceGroupIds
    }

    /// Lab-DC defaults from the phase-0 spec: primary group `primaryGroupId` (513 unless the
    /// account's `primaryGroupID` says otherwise), GroupIds = the primary group first, then
    /// `groupRids` without duplicates (`GroupMembership.accountGroups`), UAC NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD, LogoffTime,
    /// KickOffTime and PasswordMustChange "never", UserFlags EXTRA_SIDS / RESOURCE_GROUPS set
    /// exactly when those lists are non-empty, LogonDomainName uppercased, UserSessionKey zero.
    public static func labUser(
        samAccountName: String,
        rid: UInt32,
        primaryGroupId: UInt32 = 513,
        groupRids: [UInt32],
        domainSID: SID,
        netbiosDomain: String,
        dcNetbiosName: String,
        logonTime: FileTime,
        passwordLastSet: FileTime = .zero,
        fullName: String = "",
        extraSids: [SIDAndAttributes] = []
    ) -> KerberosValidationInfo {
        var info = KerberosValidationInfo(
            logonTime: logonTime,
            passwordLastSet: passwordLastSet,
            effectiveName: samAccountName,
            fullName: fullName,
            userId: rid,
            primaryGroupId: primaryGroupId,
            groupIds: GroupMembership.accountGroups(primary: primaryGroupId, rids: groupRids),
            logonServer: dcNetbiosName.uppercased(),
            logonDomainName: netbiosDomain.uppercased(),
            logonDomainId: domainSID,
            extraSids: extraSids
        )
        info.userFlags = info.impliedUserFlags
        return info
    }

    /// EXTRA_SIDS / RESOURCE_GROUPS bits implied by the lists (other bits of `userFlags` kept).
    public var impliedUserFlags: UInt32 {
        var f = userFlags & ~(Self.userFlagExtraSids | Self.userFlagResourceGroups)
        if !extraSids.isEmpty { f |= Self.userFlagExtraSids }
        if resourceGroupDomainSid != nil || !resourceGroupIds.isEmpty { f |= Self.userFlagResourceGroups }
        return f
    }

    /// The user's SID: LogonDomainId + UserId.
    public var userSID: SID? { try? logonDomainId.appending(rid: userId) }
}

// MARK: - NDR codec

extension KerberosValidationInfo {
    /// MaximumLength policy for RPC_UNICODE_STRING. Windows (and Samba's lsa_StringLarge) send
    /// LogonServer and LogonDomainName with MaximumLength = Length + 2 (room for a NUL that is
    /// not transmitted); all other strings have MaximumLength = Length. Matches MS-PAC §3.
    private enum MaxLength { case exact, plusNul }

    /// Serializes as MS-RPCE type serialization v1: common header, private header, top-level
    /// [unique] pointer (0x00020000), the 216-byte flat structure, deferred pointees, padding
    /// to a multiple of 8. This is exactly the PAC_LOGON_INFO buffer.
    public func ndrEncoded() throws -> [UInt8] {
        guard userSessionKey.count == 16 else { throw MSPACError.valueTooLarge(field: "UserSessionKey (must be 16 bytes)") }
        let strings: [(String, String, MaxLength)] = [
            ("EffectiveName", effectiveName, .exact), ("FullName", fullName, .exact),
            ("LogonScript", logonScript, .exact), ("ProfilePath", profilePath, .exact),
            ("HomeDirectory", homeDirectory, .exact), ("HomeDirectoryDrive", homeDirectoryDrive, .exact),
            ("LogonServer", logonServer, .plusNul), ("LogonDomainName", logonDomainName, .plusNul),
        ]
        var encoded: [(bytes: [UInt8], length: UInt16, maxLength: UInt16)] = []
        for (field, s, policy) in strings {
            let b = s.utf16LEBytes
            let extra = policy == .plusNul ? 2 : 0
            guard b.count + extra <= Int(UInt16.max) - 1 else { throw MSPACError.valueTooLarge(field: field) }
            encoded.append((b, UInt16(b.count), UInt16(b.count + extra)))
        }
        guard groupIds.count <= Int(UInt32.max), extraSids.count <= Int(UInt32.max) else {
            throw MSPACError.valueTooLarge(field: "array count")
        }

        var n = NDRWriter()
        n.pointer(true)                                     // top-level referent 0x00020000

        // Flat part (216 bytes).
        for t in [logonTime, logoffTime, kickOffTime, passwordLastSet, passwordCanChange, passwordMustChange] {
            n.fileTime(t)
        }
        func unicodeHeader(_ s: (bytes: [UInt8], length: UInt16, maxLength: UInt16)) {
            n.u16(s.length)
            n.u16(s.maxLength)
            n.pointer(true)                                 // always non-null, as Windows does
        }
        for i in 0..<6 { unicodeHeader(encoded[i]) }
        n.u16(logonCount)
        n.u16(badPasswordCount)
        n.u32(userId)
        n.u32(primaryGroupId)
        n.u32(UInt32(groupIds.count))
        n.pointer(!groupIds.isEmpty)
        n.u32(userFlags)
        n.raw(userSessionKey)
        unicodeHeader(encoded[6])
        unicodeHeader(encoded[7])
        n.pointer(true)                                     // LogonDomainId
        n.u32(0); n.u32(0)                                  // Reserved1[2]
        n.u32(userAccountControl)
        n.u32(subAuthStatus)
        n.fileTime(lastSuccessfulILogon)
        n.fileTime(lastFailedILogon)
        n.u32(failedILogonCount)
        n.u32(0)                                            // Reserved3
        n.u32(UInt32(extraSids.count))
        n.pointer(!extraSids.isEmpty)
        n.pointer(resourceGroupDomainSid != nil)
        n.u32(UInt32(resourceGroupIds.count))
        n.pointer(!resourceGroupIds.isEmpty)

        // Deferred pointees, in pointer order.
        func unicodeBody(_ s: (bytes: [UInt8], length: UInt16, maxLength: UInt16)) {
            n.u32(UInt32(s.maxLength / 2))                  // MaximumCount
            n.u32(0)                                        // Offset
            n.u32(UInt32(s.length / 2))                     // ActualCount
            n.raw(s.bytes)
        }
        func groupsBody(_ groups: [GroupMembership]) {
            n.u32(UInt32(groups.count))
            for g in groups {
                n.u32(g.relativeId)
                n.u32(g.attributes)
            }
        }
        func sidBody(_ sid: SID) {
            n.u32(UInt32(sid.subAuthorities.count))         // conformance of SubAuthority[]
            n.raw(sid.bytes)                                // RPC_SID has the binary SID layout
        }
        for i in 0..<6 { unicodeBody(encoded[i]) }
        if !groupIds.isEmpty { groupsBody(groupIds) }
        unicodeBody(encoded[6])
        unicodeBody(encoded[7])
        sidBody(logonDomainId)
        if !extraSids.isEmpty {
            n.u32(UInt32(extraSids.count))
            for e in extraSids {
                n.pointer(true)
                n.u32(e.attributes)
            }
            for e in extraSids { sidBody(e.sid) }
        }
        if let rsid = resourceGroupDomainSid { sidBody(rsid) }
        if !resourceGroupIds.isEmpty { groupsBody(resourceGroupIds) }

        return NDR.typeSerialize(n.bytes)
    }

    /// Decodes a PAC_LOGON_INFO buffer (type serialization headers included).
    public init(ndr bytes: [UInt8]) throws {
        let context = "KERB_VALIDATION_INFO"
        let body = try NDR.typeDeserialize(bytes, context: context)
        var r = NDRReader(bytes, range: body, context: context)
        guard try r.pointer("top-level pointer") else { throw r.fail("top-level pointer is null") }

        struct UnicodeHeader { var name: String; var length: UInt16; var maxLength: UInt16; var present: Bool }
        func unicodeHeader(_ name: String) throws -> UnicodeHeader {
            let length = try r.u16("\(name).Length")
            let maxLength = try r.u16("\(name).MaximumLength")
            let present = try r.pointer("\(name).Buffer")
            guard length % 2 == 0, maxLength % 2 == 0, length <= maxLength else {
                throw r.fail("\(name) Length \(length) / MaximumLength \(maxLength) invalid")
            }
            if !present, length != 0 { throw r.fail("\(name) has Length \(length) but a null buffer") }
            return UnicodeHeader(name: name, length: length, maxLength: maxLength, present: present)
        }
        func unicodeBody(_ h: UnicodeHeader) throws -> String {
            guard h.present else { return "" }
            let maxCount = try r.u32("\(h.name) MaximumCount")
            let offset = try r.u32("\(h.name) Offset")
            let actual = try r.u32("\(h.name) ActualCount")
            guard maxCount == UInt32(h.maxLength / 2), offset == 0, actual == UInt32(h.length / 2) else {
                throw r.fail("\(h.name) array counts (\(maxCount), \(offset), \(actual)) disagree with Length \(h.length) / MaximumLength \(h.maxLength)")
            }
            return String(utf16LE: try r.take(Int(actual) * 2, "\(h.name) characters"))
        }
        func groupsBody(_ name: String, count: UInt32) throws -> [GroupMembership] {
            try r.conformance(name, expected: count, elementSize: 8)
            var out = [GroupMembership]()
            out.reserveCapacity(Int(count))
            for _ in 0..<count {
                let rid = try r.u32("\(name) RelativeId")
                let attributes = try r.u32("\(name) Attributes")
                out.append(GroupMembership(relativeId: rid, attributes: attributes))
            }
            return out
        }
        func sidBody(_ name: String) throws -> SID {
            let maxCount = try r.u32("\(name) MaximumCount")
            let header = try r.take(8, "\(name) header")
            guard UInt32(header[1]) == maxCount else {
                throw r.fail("\(name) MaximumCount \(maxCount) does not match SubAuthorityCount \(header[1])")
            }
            guard header[1] <= SID.maxSubAuthorities else { throw r.fail("\(name) has \(header[1]) sub-authorities") }
            let subs = try r.take(4 * Int(header[1]), "\(name) sub-authorities")
            do {
                return try SID(bytes: header + subs)
            } catch {
                throw r.fail("\(name): \(error)")
            }
        }

        let logonTime = try r.fileTime("LogonTime")
        let logoffTime = try r.fileTime("LogoffTime")
        let kickOffTime = try r.fileTime("KickOffTime")
        let passwordLastSet = try r.fileTime("PasswordLastSet")
        let passwordCanChange = try r.fileTime("PasswordCanChange")
        let passwordMustChange = try r.fileTime("PasswordMustChange")
        var headers = [UnicodeHeader]()
        for name in ["EffectiveName", "FullName", "LogonScript", "ProfilePath", "HomeDirectory", "HomeDirectoryDrive"] {
            headers.append(try unicodeHeader(name))
        }
        let logonCount = try r.u16("LogonCount")
        let badPasswordCount = try r.u16("BadPasswordCount")
        let userId = try r.u32("UserId")
        let primaryGroupId = try r.u32("PrimaryGroupId")
        let groupCount = try r.u32("GroupCount")
        let groupsPresent = try r.pointer("GroupIds")
        let userFlags = try r.u32("UserFlags")
        let userSessionKey = try r.take(16, "UserSessionKey")
        headers.append(try unicodeHeader("LogonServer"))
        headers.append(try unicodeHeader("LogonDomainName"))
        let domainIdPresent = try r.pointer("LogonDomainId")
        _ = try r.u32("Reserved1[0]")
        _ = try r.u32("Reserved1[1]")
        let userAccountControl = try r.u32("UserAccountControl")
        let subAuthStatus = try r.u32("SubAuthStatus")
        let lastSuccessfulILogon = try r.fileTime("LastSuccessfulILogon")
        let lastFailedILogon = try r.fileTime("LastFailedILogon")
        let failedILogonCount = try r.u32("FailedILogonCount")
        _ = try r.u32("Reserved3")
        let sidCount = try r.u32("SidCount")
        let extraSidsPresent = try r.pointer("ExtraSids")
        let resourceDomainPresent = try r.pointer("ResourceGroupDomainSid")
        let resourceGroupCount = try r.u32("ResourceGroupCount")
        let resourceGroupsPresent = try r.pointer("ResourceGroupIds")

        guard groupsPresent || groupCount == 0 else { throw r.fail("GroupCount \(groupCount) with null GroupIds") }
        guard extraSidsPresent || sidCount == 0 else { throw r.fail("SidCount \(sidCount) with null ExtraSids") }
        guard resourceGroupsPresent || resourceGroupCount == 0 else {
            throw r.fail("ResourceGroupCount \(resourceGroupCount) with null ResourceGroupIds")
        }
        guard domainIdPresent else { throw r.fail("LogonDomainId is null") }

        var strings = [String]()
        for h in headers[0..<6] { strings.append(try unicodeBody(h)) }
        let groupIds = groupsPresent ? try groupsBody("GroupIds", count: groupCount) : []
        strings.append(try unicodeBody(headers[6]))
        strings.append(try unicodeBody(headers[7]))
        let logonDomainId = try sidBody("LogonDomainId")
        var extraSids = [SIDAndAttributes]()
        if extraSidsPresent {
            try r.conformance("ExtraSids", expected: sidCount, elementSize: 8)
            var entries = [(present: Bool, attributes: UInt32)]()
            for _ in 0..<sidCount {
                let present = try r.pointer("ExtraSids[].Sid")
                let attributes = try r.u32("ExtraSids[].Attributes")
                entries.append((present, attributes))
            }
            for (i, e) in entries.enumerated() {
                guard e.present else { throw r.fail("ExtraSids[\(i)].Sid is null") }
                extraSids.append(SIDAndAttributes(sid: try sidBody("ExtraSids[\(i)].Sid"), attributes: e.attributes))
            }
        }
        let resourceGroupDomainSid = resourceDomainPresent ? try sidBody("ResourceGroupDomainSid") : nil
        let resourceGroupIds = resourceGroupsPresent ? try groupsBody("ResourceGroupIds", count: resourceGroupCount) : []

        self.init(
            logonTime: logonTime, logoffTime: logoffTime, kickOffTime: kickOffTime,
            passwordLastSet: passwordLastSet, passwordCanChange: passwordCanChange, passwordMustChange: passwordMustChange,
            effectiveName: strings[0], fullName: strings[1], logonScript: strings[2], profilePath: strings[3],
            homeDirectory: strings[4], homeDirectoryDrive: strings[5],
            logonCount: logonCount, badPasswordCount: badPasswordCount,
            userId: userId, primaryGroupId: primaryGroupId, groupIds: groupIds,
            userFlags: userFlags, userSessionKey: userSessionKey,
            logonServer: strings[6], logonDomainName: strings[7], logonDomainId: logonDomainId,
            userAccountControl: userAccountControl, subAuthStatus: subAuthStatus,
            lastSuccessfulILogon: lastSuccessfulILogon, lastFailedILogon: lastFailedILogon,
            failedILogonCount: failedILogonCount,
            extraSids: extraSids, resourceGroupDomainSid: resourceGroupDomainSid, resourceGroupIds: resourceGroupIds
        )
    }
}
