import Foundation
import RPCKit
import Store
import MSPAC
import SheepCrypto

/// The fields WP-U reads out of an incoming `SAMPR_USER_ALL_INFORMATION` (levels 21/23/25); the
/// rest of the struct is consumed but ignored.
struct UserAllIn {
    var accountExpires: Int64 = 0
    var primaryGroupId: UInt32 = 0
    var userAccountControl: UInt32 = 0   // SAMR ACB flags (not UF bits)
    var whichFields: UInt32 = 0
    var passwordExpired: UInt8 = 0
}

extension NDRReader {
    /// Reads the flat part of a `SAMPR_USER_ALL_INFORMATION`, enqueuing (and discarding) each
    /// pointee body on the deferred queue. The caller reads any trailing inline fields (e.g. the
    /// `UserPassword` blob of Internal4/Internal4New) and then calls `flushDeferred()`.
    func readUserAllFlat() throws -> UserAllIn {
        var out = UserAllIn()
        _ = try oldLargeInteger()                        // LastLogon
        _ = try oldLargeInteger()                        // LastLogoff
        _ = try oldLargeInteger()                        // PasswordLastSet
        out.accountExpires = try oldLargeInteger()       // AccountExpires
        _ = try oldLargeInteger()                        // PasswordCanChange
        _ = try oldLargeInteger()                        // PasswordMustChange
        for _ in 0..<10 { _ = try samrUnicodeString() }  // UserName..Parameters
        try readShortBlob()                              // LmOwfPassword
        try readShortBlob()                              // NtOwfPassword
        _ = try samrUnicodeString()                      // PrivateData
        // SecurityDescriptor: Length u32, PCHAR_ARRAY pointer (conformant char array).
        _ = try u32()
        if try pointer() != nil { deferPointee { _ = try self.conformantByteArray() } }
        _ = try u32()                                    // UserId
        out.primaryGroupId = try u32()
        out.userAccountControl = try u32()
        out.whichFields = try u32()
        // LogonHours: UnitsPerWeek u32, PLOGON_HOURS_ARRAY pointer (conformant+varying bytes).
        _ = try u32()
        if try pointer() != nil { deferPointee { _ = try self.samrConformantVaryingByteArray() } }
        _ = try u16(); _ = try u16(); _ = try u16(); _ = try u16()   // Bad/Logon count, Country, CodePage
        _ = try u8(); _ = try u8()                       // Lm/Nt present
        out.passwordExpired = try u8()                   // PasswordExpired
        _ = try u8()                                     // PrivateDataSensitive
        return out
    }

    private func readShortBlob() throws {
        _ = try u16(); _ = try u16()                     // Length, MaximumLength
        if try pointer() != nil { deferPointee { _ = try self.samrConformantVaryingUInt16Array() } }
    }
}

extension SAMRService {
    // MARK: - SetInformationUser / 2 (37/58)

    func setInformationUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let handle = try r.contextHandle()
        let level = try r.u16()
        let tag = try r.u16()                             // union tag (equals level)
        _ = tag

        // Parse the arm; capture whatever the level carries. Deferred bodies (level 21/23/25's I1)
        // are flushed after the inline part is read.
        var newACB: UInt32?
        var newExpires: Int64?
        var newPrimaryGroup: UInt32?
        var clearPassword: String?
        var ntHashOnly: [UInt8]?
        var needsSessionKey = false

        switch level {
        case 16:
            newACB = try r.u32()
        case 18:
            let ntBlob = try r.take(16)                   // EncryptedNtOwfPassword
            _ = try r.take(16)                            // EncryptedLmOwfPassword
            _ = try r.u8()                                // NtPasswordPresent
            _ = try r.u8()                                // LmPasswordPresent
            _ = try r.u8()                                // PasswordExpired
            needsSessionKey = true
            if !ctx.sessionKey.isEmpty {
                ntHashOnly = SAMRPassword.decryptOWF(ntBlob, key: paddedSessionKey(ctx))
            }
        case 21:
            let i1 = try r.readUserAllFlat()
            applyAll(i1, acb: &newACB, expires: &newExpires, primary: &newPrimaryGroup)
        case 23:
            let i1 = try r.readUserAllFlat()
            let blob = try r.take(516)                    // UserPassword (session-key RC4)
            applyAll(i1, acb: &newACB, expires: &newExpires, primary: &newPrimaryGroup)
            needsSessionKey = true
            if !ctx.sessionKey.isEmpty { clearPassword = try SAMRPassword.decryptUserPassword(blob, rc4Key: ctx.sessionKey) }
        case 24:
            let blob = try r.take(516)
            _ = try r.u8()                                // PasswordExpired
            needsSessionKey = true
            if !ctx.sessionKey.isEmpty { clearPassword = try SAMRPassword.decryptUserPassword(blob, rc4Key: ctx.sessionKey) }
        case 25:
            let i1 = try r.readUserAllFlat()
            let blob = try r.take(532)                    // UserPassword_NEW (salted)
            applyAll(i1, acb: &newACB, expires: &newExpires, primary: &newPrimaryGroup)
            needsSessionKey = true
            if !ctx.sessionKey.isEmpty { clearPassword = try SAMRPassword.decryptUserPasswordNew(blob, sessionKey: ctx.sessionKey) }
        case 26:
            let blob = try r.take(532)
            _ = try r.u8()                                // PasswordExpired
            needsSessionKey = true
            if !ctx.sessionKey.isEmpty { clearPassword = try SAMRPassword.decryptUserPasswordNew(blob, sessionKey: ctx.sessionKey) }
        default:
            try r.flushDeferred()
            let w = NDRWriter(); w.u32(NTStatus.invalidInfoClass.rawValue); return w
        }
        try r.flushDeferred()

        let w = NDRWriter()
        do {
            let user = try ctx.userState(handle)
            guard let entry = try await directory.read(id: user.objectID) else { throw SAMRError(.noSuchUser) }
            let privileges = try await authorizePasswordSet(ctx, target: entry)
            if needsSessionKey, ctx.sessionKey.isEmpty { throw SAMRError(.noUserSessionKey) }

            let oldUAC = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
            if let acb = newACB {
                try Self.checkACBChange(old: UserAccountControl.toACB(oldUAC), new: acb, privileges: privileges)
            }
            // The primary group confers membership (and lands in the PAC), so it must name a group
            // the account already belongs to — for every caller, administrators included (AD
            // answers STATUS_MEMBER_NOT_IN_GROUP the same way).
            let becomesServerTrust = (newACB ?? UserAccountControl.toACB(oldUAC)) & ACB.serverTrust != 0
            if let pg = newPrimaryGroup, pg != 0, !(pg == 516 && becomesServerTrust),
               !(try await directory.isValidPrimaryGroup(pg, for: entry)) {
                Self.logger.notice("SAMR set \(entry.samAccountName ?? "?", privacy: .public) primaryGroupID \(pg) refused: not a member")
                throw SAMRError(.memberNotInGroup)
            }
            let isComputer = (oldUAC & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount)) != 0
                || entry.strings("objectClass").contains { $0.caseInsensitiveCompare("computer") == .orderedSame }

            if let clear = clearPassword {
                do { try await directory.setPassword(id: user.objectID, password: clear, enforcePolicy: !isComputer) }
                catch let e as StoreError {
                    if case .passwordPolicy = e { throw SAMRError(.passwordRestriction) }
                    throw SAMRError(.internalError)
                }
            }
            if let nt = ntHashOnly {
                try await directory.setPasswordFromNTHash(id: user.objectID, ntHash: nt)
            }
            var ops: [ModifyOp] = []
            if let acb = newACB {
                var uac = Self.userAccountControl(settingACB: acb, on: oldUAC)
                // The password set above cleared UF_PASSWORD_EXPIRED; flags read before it must
                // not put it back.
                if clearPassword != nil || ntHashOnly != nil { uac &= ~UserAccountControl.passwordExpired }
                ops.append(.replace("userAccountControl", strings: [String(uac)]))
                Self.logger.notice("SAMR set \(entry.samAccountName ?? "?", privacy: .public) level \(level) ACB 0x\(String(acb, radix: 16), privacy: .public): userAccountControl 0x\(String(oldUAC, radix: 16), privacy: .public) -> 0x\(String(uac, radix: 16), privacy: .public)")
            }
            if let pg = newPrimaryGroup, pg != 0 { ops.append(.replace("primaryGroupID", strings: [String(pg)])) }
            if let ex = newExpires { ops.append(.replace("accountExpires", strings: [String(ex)])) }
            if !ops.isEmpty { try await directory.update(id: user.objectID, ops: ops) }
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(e.status.rawValue)
        } catch {
            w.u32(NTStatus.internalError.rawValue)
        }
        return w
    }

    /// The `userAccountControl` a SAMR set of account flags `acb` produces on an account whose
    /// current value is `old` (MS-SAMR §3.1.5.14.2, Samba `samdb_msg_add_acct_flags` = ds_acb2uf):
    /// - every UF bit with an ACB counterpart is taken from `acb` (so ACB_WSTRUST|ACB_DISABLED →
    ///   UF_WORKSTATION_TRUST_ACCOUNT|UF_ACCOUNTDISABLE = 0x1002, and 0x80 re-enables it);
    /// - UF bits SAMR cannot express (UF_SCRIPT, UF_PASSWD_CANT_CHANGE, …) keep their old value;
    /// - an `acb` without any account-type bit keeps the account's current type, so a set can
    ///   never leave an account typeless (the state Windows refuses to reuse).
    static func userAccountControl(settingACB acb: UInt32, on old: UInt32) -> UInt32 {
        var uac = UserAccountControl.fromACB(acb) | (old & ~UserAccountControl.acbMappedBits)
        if uac & UserAccountControl.accountTypeMask == 0 { uac |= old & UserAccountControl.accountTypeMask }
        return uac
    }

    private func applyAll(_ i1: UserAllIn, acb: inout UInt32?, expires: inout Int64?, primary: inout UInt32?) {
        if i1.whichFields & UserAllFields.userAccountControl != 0 { acb = i1.userAccountControl }
        if i1.whichFields & UserAllFields.accountExpires != 0 { expires = i1.accountExpires }
        if i1.whichFields & UserAllFields.primaryGroupId != 0 { primary = i1.primaryGroupId }
    }

    /// The 16-byte session key, zero-padded to 16 if a transport handed a shorter one (DES needs 14).
    private func paddedSessionKey(_ ctx: RPCCallContext) -> [UInt8] {
        var k = ctx.sessionKey
        if k.count < 16 { k += [UInt8](repeating: 0, count: 16 - k.count) }
        return k
    }

    // MARK: - ChangePasswordUser (38) — optional, not implemented

    func changePasswordUser(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        let w = NDRWriter()
        w.u32(NTStatus.notSupported.rawValue)
        return w
    }

    // MARK: - SamrUnicodeChangePasswordUser2 (55)

    func unicodeChangePasswordUser2(_ r: NDRReader, ctx: RPCCallContext) async throws -> NDRWriter {
        // Every field is a top-level parameter, so each pointer's referent is marshalled inline.
        if try r.pointer() != nil { _ = try r.readUnicodeStringInline() }   // ServerName (skip)
        let userName = try r.readUnicodeStringInline() ?? ""
        var newBlobIn: [UInt8]? = nil
        if try r.pointer() != nil { newBlobIn = try r.take(516) }           // NewPasswordEncryptedWithOldNt
        var oldCrossIn: [UInt8]? = nil
        if try r.pointer() != nil { oldCrossIn = try r.take(16) }           // OldNtOwfPasswordEncryptedWithNewNt
        _ = try r.u8()                                                      // LmPresent
        if try r.pointer() != nil { _ = try r.take(516) }                   // NewPasswordEncryptedWithOldLm (ignored)
        if try r.pointer() != nil { _ = try r.take(16) }                    // OldLmOwfPasswordEncryptedWithNewNt (ignored)

        let w = NDRWriter()
        do {
            guard let newBlob = newBlobIn, let oldOwfCross = oldCrossIn else {
                throw SAMRError(.invalidParameter)
            }
            // Resolve the account and its stored NT hash (the shared secret proving the old password).
            var entry = try await directory.read(sam: userName)
            if entry == nil { entry = try await directory.read(sam: userName + "$") }
            guard let entry, let secrets = try await directory.secrets(id: entry.id), let oldNTHash = secrets.ntHash else {
                throw SAMRError(.wrongPassword)
            }
            // Bad-password lockout (security audit, 1 Oct 2026): this call is an online oracle for
            // the old password, so wrong guesses count like a failed logon and a locked account is
            // refused before any check runs.
            let lockKey = entry.samAccountName ?? userName
            let now = clock()
            if badPasswords.lockedUntil(lockKey, now: now) != nil {
                Self.logger.notice("SAMR password change \(userName, privacy: .public) -> ACCOUNT_LOCKED_OUT")
                throw SAMRError(.accountLockedOut)
            }
            func wrongPassword() -> SAMRError {
                let locked = badPasswords.recordFailure(lockKey, now: now, threshold: lockoutThreshold,
                                                        window: lockoutWindow, duration: lockoutDuration)
                Self.logger.notice("SAMR password change \(userName, privacy: .public) -> WRONG_PASSWORD\(locked ? "; account now locked out" : "", privacy: .public)")
                return SAMRError(.wrongPassword)
            }
            // Recover the new cleartext with the stored old NT hash, then verify the caller knew the
            // old password: SamEncrypt(oldHash, newHash) must equal the supplied cross-encryption.
            guard let newClear = try? SAMRPassword.decryptUserPassword(newBlob, rc4Key: oldNTHash) else {
                throw wrongPassword()
            }
            let newNTHash = DirectoryStore.ntHash(newClear)
            let expected = SAMRPassword.encryptOWF(oldNTHash, key: newNTHash)
            guard ConstantTime.equal(expected, oldOwfCross) else { throw wrongPassword() }
            badPasswords.recordSuccess(lockKey)
            do { try await directory.setPassword(id: entry.id, password: newClear, enforcePolicy: true) }
            catch let e as StoreError {
                if case .passwordPolicy = e { throw SAMRError(.passwordRestriction) }
                throw SAMRError(.internalError)
            }
            Self.logger.notice("SAMR password change \(userName, privacy: .public) -> SUCCESS")
            w.u32(NTStatus.success.rawValue)
        } catch let e as SAMRError {
            w.u32(e.status.rawValue)
        } catch {
            w.u32(NTStatus.wrongPassword.rawValue)
        }
        return w
    }
}
