import Foundation
import RPCKit
import Store
import AuthKit
import MSPAC
import SheepCrypto

extension NetlogonService {

    struct NetworkLogon {
        var logonDomain: String
        var userName: String
        var workstation: String
        var serverChallenge: [UInt8]
        var ntResponse: [UInt8]
        var lmResponse: [UInt8]
        /// `NETLOGON_LOGON_IDENTITY_INFO.ParameterControl` (`MSV1_0_*` bits).
        var parameterControl: UInt32 = 0
        /// Interactive logon: the session-key-encrypted NT OWF (16 bytes); `serverChallenge` is empty.
        var interactiveNTOWF: [UInt8]? = nil
    }

    /// Reads a `NETLOGON_LEVEL` for a Network(2/6) or Interactive(1/5) logon and returns the fields.
    /// Returns nil for logon levels this method does not read (e.g. generic pass-through).
    func readNetworkLevel(_ r: NDRReader) throws -> (level: UInt16, network: NetworkLogon?) {
        let logonLevel = try r.enum16()
        _ = try r.enum16()                                   // union discriminant
        r.align(4)
        let armPresent = try r.u32() != 0
        guard armPresent else { return (logonLevel, nil) }
        if logonLevel == 1 || logonLevel == 5 {
            // NETLOGON_INTERACTIVE_INFO: identity, then two 16-byte encrypted OWFs. Winbind's
            // plaintext auth (`wbinfo -a`, PAM) and a Windows interactive logon take this path;
            // the OWFs are encrypted with the schannel session key (WP-Z).
            let ldnPresent = try NLNDR.readStringHeader(r)   // Identity.LogonDomainName
            let parameterControl = try r.u32()
            _ = try r.oldLargeInteger()                      // Reserved (logon_id)
            let unPresent = try NLNDR.readStringHeader(r)    // UserName
            let wsPresent = try NLNDR.readStringHeader(r)    // Workstation
            let lmOWF = try r.take(16)                       // LmOwfPassword (encrypted)
            let ntOWF = try r.take(16)                       // NtOwfPassword (encrypted)
            _ = lmOWF
            let domain = ldnPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            let user = unPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            let ws = wsPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            return (logonLevel, NetworkLogon(logonDomain: domain, userName: user, workstation: ws,
                                             serverChallenge: [], ntResponse: [], lmResponse: [],
                                             parameterControl: parameterControl, interactiveNTOWF: ntOWF))
        }
        if logonLevel == 2 || logonLevel == 6 {
            // NETLOGON_NETWORK_INFO
            let ldnPresent = try NLNDR.readStringHeader(r)   // Identity.LogonDomainName
            let parameterControl = try r.u32()               // ParameterControl (MSV1_0_*)
            _ = try r.oldLargeInteger()                      // Reserved
            let unPresent = try NLNDR.readStringHeader(r)    // UserName
            let wsPresent = try NLNDR.readStringHeader(r)    // Workstation
            let lmChallenge = try r.take(8)                  // LmChallenge (the server challenge)
            let ntPresent = try NLNDR.readStringHeader(r)    // NtChallengeResponse (ANSI STRING)
            let lmPresent = try NLNDR.readStringHeader(r)    // LmChallengeResponse
            let domain = ldnPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            let user = unPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            let ws = wsPresent ? try NLNDR.readWCharBody(r, stripNUL: false) : ""
            let nt = ntPresent ? try NLNDR.readByteBody(r) : []
            let lm = lmPresent ? try NLNDR.readByteBody(r) : []
            return (logonLevel, NetworkLogon(logonDomain: domain, userName: user, workstation: ws,
                                             serverChallenge: lmChallenge, ntResponse: nt, lmResponse: lm,
                                             parameterControl: parameterControl))
        }
        return (logonLevel, nil)
    }

    /// The outcome of one SamLogon: validation info on success, the status, and a short reason for
    /// the operational log (never key material).
    struct SamLogonOutcome {
        var info: SamValidationInfo? = nil
        var status: UInt32
        var reason: String? = nil
        /// The account the name resolved to (sAMAccountName), when it resolved.
        var account: String? = nil
        /// `ntlmv2` / `ntlmv1` / `interactive`.
        var kind: String? = nil
    }

    /// Resolves `LogonDomainName` + `UserName` to a directory account (WP-AK): `user`, `DOMAIN\user`,
    /// `user@upn-suffix`, case-insensitive, trailing NULs dropped. See `LogonName`.
    func resolveLogonAccount(_ name: LogonName, realm: String) async -> (entry: DirectoryEntry, account: KerberosAccount)? {
        guard case .local(let lookups) = name.outcome else { return nil }
        for lookup in lookups {
            let entry: DirectoryEntry?
            switch lookup {
            case .sam(let sam): entry = try? await store.read(sam: sam)
            case .upn(let upn): entry = try? await store.read(upn: upn)
            case .spn(let spn):
                // `host/pc.lab.sheep` → the computer holding that SPN (the KDC's resolution).
                let components = spn.split(separator: "/").map(String.init)
                if let (a, _) = try? await store.kerberosAccount(components: components, realm: realm) {
                    entry = try? await store.read(id: a.id)
                } else { entry = nil }
            }
            guard let entry, !entry.isDeleted, entry.sid != nil,
                  let account = try? await store.kerberosAccount(id: entry.id), account.kind != .krbtgt else { continue }
            return (entry, account)
        }
        return nil
    }

    /// Validates a network or interactive logon and builds the validation info, or returns a status.
    func validateLogon(_ n: NetworkLogon, computer: String, validationLevel: UInt16) async throws -> SamLogonOutcome {
        let info = try await store.domainInfo()
        let name = LogonName(logonDomain: n.logonDomain, userName: n.userName,
                             local: .init(netbiosDomain: info.netbiosDomain, dnsDomain: info.dnsDomain, dcName: info.dcName))
        let kind = n.interactiveNTOWF != nil ? "interactive" : (n.ntResponse.count == 24 ? "ntlmv1" : "ntlmv2")
        func fail(_ status: UInt32, _ reason: String, account: String? = nil) -> SamLogonOutcome {
            SamLogonOutcome(info: nil, status: status, reason: reason, account: account, kind: kind)
        }
        switch name.outcome {
        case .empty:
            return fail(NLStatus.noSuchUser, "empty user name")
        case .foreignDomain(let d):
            // Samba AD DC: auth_sam declines a domain it does not serve and, with no trust to route
            // to, auth_check_password answers NT_STATUS_NO_SUCH_USER.
            return fail(NLStatus.noSuchUser, "domain '\(d)' is not \(info.netbiosDomain) or \(info.dnsDomain)")
        case .local:
            break
        }
        guard let (entry, account) = await resolveLogonAccount(name, realm: info.realm), let sid = entry.sid else {
            return fail(NLStatus.noSuchUser, "no such account")
        }
        let sam = account.samAccountName
        if account.userAccountControl & UserAccountControl.accountDisable != 0 {
            return fail(NLStatus.accountDisabled, "account disabled", account: sam)
        }
        let now = clock()
        if let until = badPasswords.lockedUntil(sam, now: now) {
            return fail(NLStatus.accountLockedOut, "locked out after \(config.lockoutThreshold) wrong passwords until "
                        + until.formatted(.dateTime.hour().minute()), account: sam)
        }
        /// A wrong password counts towards the NAC lockout.
        func wrongPassword(_ reason: String) -> SamLogonOutcome {
            let locked = badPasswords.recordFailure(sam, now: now, threshold: config.lockoutThreshold,
                                                    window: config.lockoutWindow, duration: config.lockoutDuration)
            return fail(NLStatus.wrongPassword, locked ? reason + "; account now locked out" : reason, account: sam)
        }
        guard let secrets = try? await store.secrets(id: entry.id), let ntHash = secrets.ntHash else {
            return fail(NLStatus.noSuchUser, "account has no NT hash", account: sam)
        }
        // Trust accounts log on over the network only when the caller allows it (MS-APDS §3.1.5.2.1;
        // `ntlm_auth` always sets both bits, a Windows member sets them for machine logons).
        let uac = account.userAccountControl
        if uac & UserAccountControl.workstationTrustAccount != 0,
           n.parameterControl & MSV1_0.allowWorkstationTrustAccount == 0 {
            return fail(NLStatus.nologonWorkstationTrustAccount, "workstation trust account", account: sam)
        }
        if uac & UserAccountControl.serverTrustAccount != 0,
           n.parameterControl & MSV1_0.allowServerTrustAccount == 0 {
            return fail(NLStatus.nologonServerTrustAccount, "server trust account", account: sam)
        }
        let sessionBaseKey: [UInt8]
        if let encryptedOWF = n.interactiveNTOWF {
            // Interactive: decrypt the NT OWF with the schannel session key and compare to the stored
            // hash (MS-NRPC §3.1.4.6 / §3.5.4.5.2). The session key is the SessionBaseKey = MD4(NT hash).
            guard let channel = state.channel(computer: computer) else {
                return fail(NLStatus.accessDenied, "no secure channel for \(computer)", account: sam)
            }
            let owf = channel.usesAES
                ? NetlogonCrypto.aesCFB8(key: channel.sessionKey, iv: [UInt8](repeating: 0, count: 16), encryptedOWF, encrypt: false)
                : RC4.apply(key: channel.sessionKey, encryptedOWF)
            guard ConstantTime.equal(owf, ntHash) else { return wrongPassword("bad password") }
            sessionBaseKey = MD4.hash(ntHash)
        } else {
        switch n.ntResponse.count {
        case 24:
            // NTLMv1-style response (MS-CHAPv2 pass-through or plain NTLMv1), Samba's policy.
            let permitted = config.ntlmAuth == .on
                || (config.ntlmAuth == .mschapv2AndNTLMv2Only && n.parameterControl & MSV1_0.allowMSVCHAPv2 != 0)
            guard permitted else {
                return fail(NLStatus.wrongPassword, "NTLMv1 refused by ntlm auth = \(config.ntlmAuth.rawValue)", account: sam)
            }
            guard let key = try? NTLMNetworkLogon.validateV1(ntHash: ntHash, serverChallenge: n.serverChallenge,
                                                             ntResponse: n.ntResponse) else {
                return wrongPassword("bad password")
            }
            sessionBaseKey = key
        default:
            // NTOWFv2 covers the user and domain exactly as the client typed them; try those first,
            // then the canonical sAMAccountName (a client that sent `DOMAIN\user` or a UPN in UserName).
            let domains = [name.logonDomain, "", info.netbiosDomain, info.dnsDomain]
            var users = [name.userName]
            if sam.caseInsensitiveCompare(name.userName) != .orderedSame { users.append(sam) }
            guard let result = users.lazy.compactMap({ user in
                try? NTLMNetworkLogon.validate(username: user, domains: domains, ntHash: ntHash,
                                               serverChallenge: n.serverChallenge, ntChallengeResponse: n.ntResponse)
            }).first else {
                return wrongPassword("bad password")
            }
            sessionBaseKey = result.sessionBaseKey
        }
        }
        badPasswords.recordSuccess(sam)

        // Account restrictions after the password (Samba authsam_account_ok; the LDAP bind and the
        // KDC already enforce these): an expired account, or one that must change its password.
        if let expires = entry.int("accountExpires"), expires > 0, expires != Int64.max,
           let date = FileTime(rawValue: UInt64(expires)).date, date <= now {
            return fail(NLStatus.accountExpired, "account expired", account: sam)
        }
        let isTrust = uac & (UserAccountControl.workstationTrustAccount | UserAccountControl.serverTrustAccount
                             | UserAccountControl.interdomainTrustAccount) != 0
        if !isTrust, uac & UserAccountControl.dontExpirePassword == 0,
           secrets.pwdLastSet.rawValue == 0 || uac & UserAccountControl.passwordExpired != 0 {
            return fail(NLStatus.passwordMustChange, "the password must be changed first", account: sam)
        }

        // The UserSessionKey is encrypted with the schannel session key ONLY for validation levels
        // 2 and 3 (SamInfo / SamInfo2). For level 6 (SamInfo4) it is returned in the clear because
        // that level is used only over a privacy-sealed transport (MS-NRPC §3.5.4.5.1; Samba
        // `netlogon_creds_crypt_samlogon_validation`: `skip_crypto || validation_level == 6`). WP-Z:
        // winbind binds schannel at PRIVACY and calls SamLogonEx level 6, so sealing here made
        // `ntlm_auth --request-nt-key` return the wrong NT_KEY (double-encrypted).
        var sessionKey = Array(sessionBaseKey.prefix(16))
        if Self.encryptsUserSessionKey(validationLevel), let channel = state.channel(computer: computer) {
            // AES channel: AES-CFB8 with a zero IV; the RC4 strong-key channel: RC4 with the session
            // key (Samba `netlogon_creds_arcfour_crypt`) — never the key in the clear.
            sessionKey = channel.usesAES
                ? NetlogonCrypto.aesCFB8(key: channel.sessionKey, iv: [UInt8](repeating: 0, count: 16), sessionKey, encrypt: true)
                : RC4.apply(key: channel.sessionKey, sessionKey)
        }

        var v = SamValidationInfo(effectiveName: sam,
                                  userId: sid.rid ?? 0,
                                  primaryGroupId: account.primaryGroupID,
                                  groupRIDs: account.groupRIDs,
                                  userSessionKey: sessionKey,
                                  logonServer: info.dcName.uppercased(),
                                  logonDomainName: info.netbiosDomain,
                                  logonDomainId: info.domainSID)
        v.passwordLastSet = secrets.pwdLastSet.rawValue
        v.logonTime = FileTime(clock()).rawValue
        v.userAccountControl = UserAccountControl.toACB(account.userAccountControl)   // ACB flags (MS-SAMR §2.2.1.12), as Samba: acct_flags
        v.dnsLogonDomainName = info.dnsDomain
        v.upn = account.userPrincipalName ?? (sam + "@" + info.dnsDomain)
        if let display = entry.string("displayName") { v.fullName = display }
        return SamLogonOutcome(info: v, status: NLStatus.success, reason: nil, account: sam, kind: kind)
    }

    /// Validation levels whose `UserSessionKey` is encrypted with the schannel session key
    /// (SamInfo 2, SamInfo2 3). Any other level (SamInfo4 6) carries it in the clear.
    static func encryptsUserSessionKey(_ validationLevel: UInt16) -> Bool {
        validationLevel == 2 || validationLevel == 3
    }

    /// Why a SamLogon call may not run on this binding, or nil when it may (MS-NRPC §3.5.4.5.1).
    /// - `requireOwnChannel` (SamLogonEx, which has no authenticator): the computer must have a
    ///   secure channel and, over a real transport, the call must arrive on *that* computer's
    ///   schannel binding at integrity or privacy.
    /// - A validation level that returns the UserSessionKey in the clear needs privacy (sealing)
    ///   over a real transport — integrity would put the key on the wire.
    /// The in-memory test transport is exempt from the transport checks, as before.
    func samLogonRefusal(computer: String, validationLevel: UInt16, requireOwnChannel: Bool) -> String? {
        if requireOwnChannel, state.channel(computer: computer) == nil { return "no secure channel" }
        guard let call = NetlogonCallInfo.current, call.isNetworkTransport else { return nil }
        if requireOwnChannel {
            guard call.isSecureRPC else { return "not over secure RPC (schannel)" }
            guard call.isSecureRPC(for: computer) else {
                return "schannel is bound to \(call.schannelComputer ?? "-"), not \(computer)"
            }
        }
        if !Self.encryptsUserSessionKey(validationLevel), call.authLevel != .pktPrivacy {
            return "validation level \(validationLevel) needs a sealed (privacy) binding"
        }
        return nil
    }

    /// `NetrLogonSamLogonEx` (opnum 39): no authenticator (schannel-protected); ExtraFlags trailer.
    func samLogonEx(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // LogonServer
        let computer = try NLNDR.readTopLevelString(r) ?? "" // ComputerName
        let (logonLevel, network) = try readNetworkLevel(r)
        let validationLevel = try r.enum16()
        _ = try r.u32()                                      // ExtraFlags

        let w = NDRWriter()
        // SamLogonEx carries no authenticator: MS-NRPC requires it over secure RPC (schannel) from a
        // computer that has a secure channel. Otherwise anyone reaching the DC could use it as a
        // password oracle and harvest session keys.
        // The binding must be the named computer's own schannel (an NTLM-signed user binding, or
        // another computer's channel, may not borrow it), and validation levels that return the
        // UserSessionKey in the clear need privacy (sealing).
        if let reason = samLogonRefusal(computer: computer, validationLevel: validationLevel, requireOwnChannel: true) {
            logSamLogon(level: logonLevel, validationLevel: validationLevel, network: network, computer: computer,
                        outcome: SamLogonOutcome(status: NLStatus.accessDenied, reason: reason))
            SamValidationInfo.writeEmpty(w, level: validationLevel, hasReturnAuth: false, status: NLStatus.accessDenied)
            return w
        }
        guard let network else {
            logSamLogon(level: logonLevel, validationLevel: validationLevel, network: nil, computer: computer,
                        outcome: SamLogonOutcome(status: NLStatus.invalidParameter, reason: "logon level not supported"))
            SamValidationInfo.writeEmpty(w, level: validationLevel, hasReturnAuth: false, status: NLStatus.invalidParameter)
            return w
        }
        let outcome = try await validateLogon(network, computer: computer, validationLevel: validationLevel)
        logSamLogon(level: logonLevel, validationLevel: validationLevel, network: network, computer: computer, outcome: outcome)
        let (info, status) = (outcome.info, outcome.status)
        if let info, status == NLStatus.success {
            info.writeSamLogonExResponse(w, level: validationLevel, authoritative: true, errorCode: NLStatus.success)
        } else {
            SamValidationInfo.writeEmpty(w, level: validationLevel, hasReturnAuth: false, status: status)
        }
        return w
    }

    /// `NetrLogonSamLogonWithFlags` (opnum 45) and `NetrLogonSamLogon` (opnum 2): carry application
    /// authenticators; `withFlags` adds the ExtraFlags trailer.
    func samLogonWithFlags(_ r: NDRReader, withFlags: Bool) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                  // LogonServer
        let computer = try NLNDR.readTopLevelString(r) ?? "" // ComputerName
        // Authenticator PNETLOGON_AUTHENTICATOR (pointer + inline struct)
        let authPresent = try r.u32() != 0
        let auth = authPresent ? try readAuthenticator(r) : ([UInt8](repeating: 0, count: 8), UInt32(0))
        let retPresent = try r.u32() != 0
        if retPresent { _ = try readAuthenticator(r) }       // ReturnAuthenticator (client zeros)
        let (logonLevel, network) = try readNetworkLevel(r)
        let validationLevel = try r.enum16()
        if withFlags { _ = try r.u32() }                     // ExtraFlags

        let channel = state.channel(computer: computer)
        let step = channel.map { stepAuthenticator($0, received: auth) }
        let returnCred = step?.returnCredential ?? [UInt8](repeating: 0, count: 8)

        let w = NDRWriter()
        func writeReturnAuth() {
            NLNDR.writeReferent(w)                           // PNETLOGON_AUTHENTICATOR
            writeAuthenticator(w, credential: returnCred, timestamp: 0)
        }
        // The authenticator proves the channel; a level that returns the key in the clear still
        // needs a sealed binding (the dispatcher already required schannel sign/seal).
        if step?.ok == true,
           let reason = samLogonRefusal(computer: computer, validationLevel: validationLevel, requireOwnChannel: false) {
            logSamLogon(level: logonLevel, validationLevel: validationLevel, network: network, computer: computer,
                        outcome: SamLogonOutcome(status: NLStatus.accessDenied, reason: reason))
            writeReturnAuth()
            SamValidationInfo.writeEmptyBody(w, level: validationLevel, authoritative: true,
                                             withFlags: withFlags, status: NLStatus.accessDenied)
            return w
        }
        if step == nil || step?.ok == false {
            logSamLogon(level: logonLevel, validationLevel: validationLevel, network: network, computer: computer,
                        outcome: SamLogonOutcome(status: NLStatus.accessDenied,
                                                 reason: step == nil ? "no secure channel" : "authenticator mismatch"))
            writeReturnAuth()
            SamValidationInfo.writeEmptyBody(w, level: validationLevel, authoritative: true,
                                             withFlags: withFlags, status: NLStatus.accessDenied)
            return w
        }
        guard let network else {
            logSamLogon(level: logonLevel, validationLevel: validationLevel, network: nil, computer: computer,
                        outcome: SamLogonOutcome(status: NLStatus.invalidParameter, reason: "logon level not supported"))
            writeReturnAuth()
            SamValidationInfo.writeEmptyBody(w, level: validationLevel, authoritative: true,
                                             withFlags: withFlags, status: NLStatus.invalidParameter)
            return w
        }
        let outcome = try await validateLogon(network, computer: computer, validationLevel: validationLevel)
        logSamLogon(level: logonLevel, validationLevel: validationLevel, network: network, computer: computer, outcome: outcome)
        let (info, status) = (outcome.info, outcome.status)
        writeReturnAuth()
        if let info, status == NLStatus.success {
            info.writeValidationUnion(w, level: validationLevel)
            w.u8(1)                                          // Authoritative
            if withFlags { w.u32(0) }                        // ExtraFlags
            w.u32(NLStatus.success)
        } else {
            SamValidationInfo.writeEmptyBody(w, level: validationLevel, authoritative: true,
                                             withFlags: withFlags, status: status)
        }
        return w
    }

    /// `SamLogon Interactive LABSHEEP\alice ws=\\CLEARPASS-ENTRY val=6 pc=0x0 interactive
    /// from CLEARPASS-ENTRY$@172.18.1.210/np -> OK as alice` — the names exactly as received (NULs
    /// dropped) and the `ParameterControl` bits (`MSV1_0_*`); never a hash, key or response.
    func logSamLogon(level: UInt16, validationLevel: UInt16, network: NetworkLogon?, computer: String,
                     outcome: SamLogonOutcome) {
        var line = "SamLogon \(Self.logonLevelName(level))"
        if let network {
            let domain = LogonName.stripNUL(network.logonDomain)
            let user = LogonName.stripNUL(network.userName)
            let ws = LogonName.stripNUL(network.workstation)
            line += " " + (domain.isEmpty ? user : domain + "\\" + user) + " ws=" + (ws.isEmpty ? "-" : ws)
        }
        line += " val=\(validationLevel)"
        if let network { line += " pc=0x" + String(network.parameterControl, radix: 16) }
        if let kind = outcome.kind { line += " \(kind)" }
        let account = state.channel(computer: computer)?.accountName ?? (computer.isEmpty ? nil : computer)
        line += fromClause(account: account) + Self.outcome(outcome.status, outcome.reason)
        if outcome.status == NLStatus.success, let a = outcome.account { line += " as \(a)" }
        logEvent(line)
    }
}

extension SamValidationInfo {
    /// A validation union with a NULL arm (failed logon), plus the SamLogonEx trailer.
    static func writeEmpty(_ w: NDRWriter, level: UInt16, hasReturnAuth: Bool, status: UInt32) {
        w.enum16(level)
        w.align(4)
        w.u32(0)                                             // NULL validation pointer
        w.u8(1)                                              // Authoritative
        w.u32(0)                                             // ExtraFlags
        w.u32(status)
    }

    /// A NULL validation arm plus the SamLogon/WithFlags trailer (Authoritative [+ExtraFlags] Error).
    static func writeEmptyBody(_ w: NDRWriter, level: UInt16, authoritative: Bool, withFlags: Bool, status: UInt32) {
        w.enum16(level)
        w.align(4)
        w.u32(0)                                             // NULL validation pointer
        w.u8(authoritative ? 1 : 0)
        if withFlags { w.u32(0) }
        w.u32(status)
    }
}
