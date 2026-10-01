import Foundation
import MSPAC
import Store

/// PK-6: who called the CEP / CES — the Kerberos (or NTLM) identity HTTP Negotiate established:
/// the account SID and its group SIDs from the PAC, plus the SIDs Windows adds to every network
/// logon token (Everyone, Authenticated Users, NETWORK, This Organization).
public struct EnrollmentCaller: Sendable, Equatable, CustomStringConvertible {
    /// `LABSHEEP\WS1$`.
    public var name: String
    /// sAMAccountName (`WS1$`, `alice`).
    public var sam: String
    /// The account SID (text).
    public var sid: String
    /// Group SIDs from the PAC (primary group first), without the well-known additions.
    public var groupSIDs: [String]
    /// `alice@LAB.SHEEP` when Kerberos was used.
    public var principal: String?
    /// Kerberos or NTLM (for the log).
    public var mechanism: String
    public var remoteAddress: String

    public init(name: String, sam: String, sid: String, groupSIDs: [String], principal: String? = nil,
                mechanism: String = "Kerberos", remoteAddress: String = "?") {
        self.name = name
        self.sam = sam
        self.sid = sid
        self.groupSIDs = groupSIDs
        self.principal = principal
        self.mechanism = mechanism
        self.remoteAddress = remoteAddress
    }

    /// S-1-1-0 Everyone, S-1-5-11 Authenticated Users, S-1-5-2 NETWORK, S-1-5-15 This Organization.
    public static let logonSIDs = ["S-1-1-0", "S-1-5-11", "S-1-5-2", "S-1-5-15"]

    /// Every SID of the caller's token: account, groups, well-known logon SIDs.
    public var tokenSIDs: [String] {
        var out = [sid]
        for s in groupSIDs + Self.logonSIDs where !out.contains(s) { out.append(s) }
        return out
    }

    /// Domain Admins (…-512) or Enterprise Admins (…-519): may use the manual templates (WebServer),
    /// as their Enroll ACEs say.
    public var isDomainAdmin: Bool { groupSIDs.contains { $0.hasSuffix("-512") || $0.hasSuffix("-519") } }

    public var isComputer: Bool { sam.hasSuffix("$") }

    /// The PK-1 requester: the caller's SID and token groups; domain/enterprise admins count as
    /// administrators (manual templates), without any override being possible over the CES.
    public var requester: RequesterIdentity {
        RequesterIdentity(name: name, sid: sid, groupSIDs: tokenSIDs, isAdmin: isDomainAdmin)
    }

    /// `alice@10.0.0.5` for the log.
    public var logName: String { "\(sam)@\(remoteAddress)" }

    public var description: String { "\(name) (\(sid))" }
}

/// Access checks on the published security descriptors (MS-CRTD §2.5.1 / §2.5.2, MS-DTYP §2.5.3.2
/// order): the DACL is walked in order; the first ACE for one of the caller's SIDs that grants or
/// denies ADS_RIGHT_DS_CONTROL_ACCESS for the extended right (an object ACE naming it, or a plain
/// ACE, or GENERIC_ALL) decides. Inherit-only ACEs are skipped.
public enum EnrollmentAccess {
    static let controlAccess: UInt32 = 0x100
    static let genericAll: UInt32 = 0x1000_0000

    public static func allows(_ sd: DecodedSecurityDescriptor, right: GUID, sids: [SID]) -> Bool {
        guard let dacl = sd.dacl else { return true }  // no DACL: everyone has every right
        let token = Set(sids)
        for ace in dacl where token.contains(ace.sid) && ace.flags & 0x08 == 0 {
            guard ace.mask & (controlAccess | genericAll) != 0 else { continue }
            switch ace.type {
            case 0x00: return true                                     // ACCESS_ALLOWED
            case 0x01: return false                                    // ACCESS_DENIED
            case 0x05 where ace.objectType == nil || ace.objectType == right: return true
            case 0x06 where ace.objectType == nil || ace.objectType == right: return false
            default: continue
            }
        }
        return false
    }

    public static func allows(_ sd: DecodedSecurityDescriptor, right: String, sids: [String]) -> Bool {
        guard let guid = GUID(string: right) else { return false }
        return allows(sd, right: guid, sids: sids.compactMap { try? SID(string: $0) })
    }
}
