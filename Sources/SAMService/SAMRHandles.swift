import Foundation
import MSPAC
import Store

/// Context-handle state kept in the connection's `RPCHandleTable`, one struct per SAMR object kind.
/// Handles are 20-byte cookies; the state carries what the following calls need (which domain, and
/// the object's RID / row id) so a handle cannot be confused for another kind (the table type-tags
/// each one).
enum SAMRHandleType {
    static let server = "SAMR_SERVER"
    static let domain = "SAMR_DOMAIN"
    static let user   = "SAMR_USER"
    static let group  = "SAMR_GROUP"
    static let alias  = "SAMR_ALIAS"
}

struct ServerState: Sendable { let grantedAccess: UInt32 }

struct DomainState: Sendable {
    let sid: SID
    /// True for the S-1-5-32 BUILTIN domain, false for the account domain.
    let isBuiltin: Bool
    let grantedAccess: UInt32
}

struct UserState: Sendable {
    let objectID: ObjectID
    let rid: UInt32
    let domainSID: SID
    let grantedAccess: UInt32
}

struct GroupState: Sendable {
    let objectID: ObjectID
    let rid: UInt32
    let domainSID: SID
    let grantedAccess: UInt32
}

struct AliasState: Sendable {
    let objectID: ObjectID
    let rid: UInt32
    let domainSID: SID
    let isBuiltin: Bool
    let grantedAccess: UInt32
}
