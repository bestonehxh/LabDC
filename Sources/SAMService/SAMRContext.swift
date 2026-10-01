import Foundation
import RPCKit
import MSPAC

/// Convenience resolution of SAMR context handles against the connection's handle table.
extension RPCCallContext {
    func domainState(_ h: ContextHandle) throws -> DomainState {
        guard let s = handles.resolve(h, type: SAMRHandleType.domain, as: DomainState.self) else {
            throw SAMRError(.invalidHandle)
        }
        return s
    }
    func userState(_ h: ContextHandle) throws -> UserState {
        guard let s = handles.resolve(h, type: SAMRHandleType.user, as: UserState.self) else {
            throw SAMRError(.invalidHandle)
        }
        return s
    }
    func groupState(_ h: ContextHandle) throws -> GroupState {
        guard let s = handles.resolve(h, type: SAMRHandleType.group, as: GroupState.self) else {
            throw SAMRError(.invalidHandle)
        }
        return s
    }
    func aliasState(_ h: ContextHandle) throws -> AliasState {
        guard let s = handles.resolve(h, type: SAMRHandleType.alias, as: AliasState.self) else {
            throw SAMRError(.invalidHandle)
        }
        return s
    }

    /// The domain SID behind any object handle (domain/user/group/alias), for `SamrRidToSid`.
    func domainSIDForAnyHandle(_ h: ContextHandle) -> SID? {
        if let s = handles.resolve(h, type: SAMRHandleType.domain, as: DomainState.self) { return s.sid }
        if let s = handles.resolve(h, type: SAMRHandleType.user, as: UserState.self) { return s.domainSID }
        if let s = handles.resolve(h, type: SAMRHandleType.group, as: GroupState.self) { return s.domainSID }
        if let s = handles.resolve(h, type: SAMRHandleType.alias, as: AliasState.self) { return s.domainSID }
        return nil
    }
}
