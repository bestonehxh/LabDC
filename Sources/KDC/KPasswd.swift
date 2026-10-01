import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC
import SheepCrypto
import Store
import os

/// The kpasswd service (RFC 3244 §2, Microsoft change/set password) over a `DirectoryStore`.
///
/// Request: AP-REQ with a ticket for `kadmin/changepw@REALM` plus a KRB-PRIV (usage 13, under
/// the authenticator subkey when there is one, else the ticket session key):
/// - version 0x0001 (change password): user-data is the new password of the ticket's client;
/// - version 0xFF80 (set password): user-data is `ChangePasswdData`, optionally naming another
///   account (`targname`/`targrealm`).
///
/// Rules: changing one's own password needs an INITIAL ticket (obtained with the old password
/// in an AS exchange), else KRB5_KPASSWD_INITIAL_FLAG_NEEDED. Setting another account's password
/// (`targname`, resolved without requiring keys, so a freshly created computer can get its first
/// password) needs an administrator, or an Account Operator for an unprotected target, else
/// ACCESSDENIED (`denial(client:target:directory:)`). The Store policy (length, complexity,
/// history) applies to user accounts, not to computers (machine passwords are random strings
/// from the client); a violation is SOFTERROR with the Windows text. Errors before the AP-REQ is accepted are a KRB-ERROR whose
/// e-data carries the result code and string.
///
/// Reply: AP-REP (EncAPRepPart with the authenticator's ctime/cusec and our sequence number,
/// session key, usage 12) and KRB-PRIV with the result (same key as the request, our sequence
/// number, `s-address` = the local address the request came in on).
public actor KPasswdService {
    public nonisolated let store: DirectoryPrincipalStore
    private let rng: RandomBytes
    private let clock: @Sendable () -> Date
    private let onExchange: (@Sendable (ExchangeRecord) -> Void)?
    private var replayCache = ReplayCache()

    private static let logger = Logger(subsystem: "dev.labdc.app", category: "kpasswd")

    /// The text Windows shows for a policy failure (ERROR_PASSWORD_RESTRICTION).
    public static let policyText = "The password does not meet the password policy requirements. "
        + "Check the minimum password length, password complexity and password history requirements."

    public init(store: DirectoryPrincipalStore, rng: RandomBytes = RandomBytes(),
                clock: @escaping @Sendable () -> Date = { Date() },
                onExchange: (@Sendable (ExchangeRecord) -> Void)? = nil) {
        self.store = store
        self.rng = rng
        self.clock = clock
        self.onExchange = onExchange
    }

    /// Handles one kpasswd message (without the TCP length prefix) and returns the reply.
    public func handle(_ request: [UInt8], peer: PeerInfo) async -> [UInt8] {
        var record = ExchangeRecord(from: peer.from)
        record.kind = .kpasswd
        record.transport = peer.transport
        let reply = await process(request, peer: peer, record: &record)
        record.replySize = reply.count
        if let reason = record.reason {
            Self.logger.info("\(record.description, privacy: .public) (\(reason, privacy: .public))")
        } else {
            Self.logger.info("\(record.description, privacy: .public)")
        }
        onExchange?(record)
        return reply
    }

    private func now() -> KerberosTime {
        KerberosTime(secondsSince1970: Int64(clock().timeIntervalSince1970.rounded(.down)))
    }

    /// The accepted AP-REQ.
    struct APContext {
        var cname: PrincipalName
        var crealm: String
        var ticketFlags: TicketFlags
        var sessionKey: KerberosKey
        /// Authenticator subkey, else the session key: protects both KRB-PRIVs.
        var privKey: KerberosKey
        var clientSeq: UInt32?
        var ctime: KerberosTime
        var cusec: Int32
    }

    /// A failure before the AP-REQ is accepted: a KRB-ERROR reply.
    struct APFailure: Error {
        var code: Int32
        var result: KPasswdResult
        var reason: String
    }

    private func process(_ request: [UInt8], peer: PeerInfo, record: inout ExchangeRecord) async -> [UInt8] {
        let now = now()
        let message: KPasswdMessage
        do { message = try KPasswdMessage(bytes: request) } catch {
            return errorReply(APFailure(code: KerberosErrorCode.krbErrGeneric, result: .malformed,
                                        reason: "bad framing: \(error)"), now: now, record: &record)
        }
        guard message.version == KPasswdMessage.changePasswordVersion || message.version == KPasswdMessage.setPasswordVersion else {
            return errorReply(APFailure(code: KerberosErrorCode.krbErrGeneric, result: .badVersion,
                                        reason: "protocol version 0x\(String(message.version, radix: 16))"), now: now, record: &record)
        }
        let ctx: APContext
        do { ctx = try acceptAPReq(message.apData, request: request, now: now) } catch let f as APFailure {
            return errorReply(f, now: now, record: &record)
        } catch {
            return errorReply(APFailure(code: KerberosErrorCode.krbErrGeneric, result: .hardError, reason: "\(error)"),
                              now: now, record: &record)
        }
        record.client = "\(ctx.cname)@\(ctx.crealm)"
        record.server = message.version == KPasswdMessage.changePasswordVersion ? "change" : "set"
        let (result, text, reason) = await change(message, ctx: ctx, now: now, record: &record)
        record.kpasswdResult = result
        record.reason = reason
        do {
            return try reply(ctx, result: result, text: text, now: now, peer: peer)
        } catch {
            record.kpasswdResult = .hardError
            record.reason = "cannot build the reply: \(error)"
            return errorReply(APFailure(code: KerberosErrorCode.krbErrGeneric, result: .hardError, reason: "\(error)"),
                              now: now, record: &record)
        }
    }

    // MARK: AP-REQ

    private func acceptAPReq(_ bytes: [UInt8], request: [UInt8], now: KerberosTime) throws -> APContext {
        func fail(_ code: Int32, _ reason: String) -> APFailure { APFailure(code: code, result: .authError, reason: reason) }
        guard let apReq = try? APReq(derBytes: bytes) else {
            throw APFailure(code: KerberosErrorCode.krbApErrMsgType, result: .malformed, reason: "no AP-REQ")
        }
        let tkt = apReq.ticket
        let realmOK = tkt.realm.caseInsensitiveCompare(store.realm) == .orderedSame
            || tkt.realm.caseInsensitiveCompare(store.dnsDomain) == .orderedSame
        guard realmOK, tkt.sname.matchesIgnoringCase(.changePassword) else {
            throw fail(KerberosErrorCode.krbApErrNotUs, "ticket is for \(tkt.sname)@\(tkt.realm), not kadmin/changepw")
        }
        let service = store.changePasswordPrincipal
        guard let type = EncryptionType(rawValue: tkt.encPart.etype), let key = service.key(type),
              tkt.encPart.kvno.map({ $0 == service.kvno }) ?? true else {
            throw fail(KerberosErrorCode.krbApErrBadkeyver, "no kadmin/changepw key for etype \(tkt.encPart.etype)")
        }
        guard let plain = try? KerberosCrypto.decrypt(tkt.encPart.cipher, key: key, usage: KeyUsage.kdcRepTicket),
              let ticket = try? EncTicketPart(derBytes: plain) else {
            throw fail(KerberosErrorCode.krbApErrBadIntegrity, "ticket does not decrypt (issued before a restart?)")
        }
        guard ticket.endtime >= now else { throw fail(KerberosErrorCode.krbApErrTktExpired, "ticket expired") }
        if ticket.flags.invalid || (ticket.starttime.map { $0.secondsSince1970 > now.secondsSince1970 + KDCPolicy.maxSkew } ?? false) {
            throw fail(KerberosErrorCode.krbApErrTktNyv, "ticket not yet valid")
        }
        guard let st = EncryptionType(rawValue: ticket.key.keytype),
              let sessionKey = try? KerberosKey(type: st, bytes: ticket.key.keyvalue) else {
            throw fail(KerberosErrorCode.kdcErrEtypeNosupp, "session key type \(ticket.key.keytype)")
        }
        guard let authPlain = try? KerberosCrypto.decrypt(apReq.authenticator.cipher, key: sessionKey,
                                                          usage: KeyUsage.apReqAuthenticator),
              let auth = try? Authenticator(derBytes: authPlain) else {
            throw fail(KerberosErrorCode.krbApErrBadIntegrity, "authenticator does not decrypt")
        }
        guard auth.cname.matchesIgnoringCase(ticket.cname), auth.crealm.caseInsensitiveCompare(ticket.crealm) == .orderedSame else {
            throw fail(KerberosErrorCode.krbApErrBadmatch, "authenticator is for \(auth.cname)@\(auth.crealm)")
        }
        let skew = abs(auth.ctime.secondsSince1970 - now.secondsSince1970)
        guard skew <= KDCPolicy.maxSkew else { throw fail(KerberosErrorCode.krbApErrSkew, "authenticator clock is \(skew) s off") }
        if replayCache.check(apReq.authenticator.cipher, request: request, now: now.secondsSince1970) == .replay {
            throw fail(KerberosErrorCode.krbApErrRepeat, "authenticator replayed")
        }
        var privKey = sessionKey
        if let sub = auth.subkey {
            guard let t = EncryptionType(rawValue: sub.keytype), let k = try? KerberosKey(type: t, bytes: sub.keyvalue) else {
                throw fail(KerberosErrorCode.kdcErrEtypeNosupp, "subkey type \(sub.keytype)")
            }
            privKey = k
        }
        return APContext(cname: ticket.cname, crealm: ticket.crealm, ticketFlags: ticket.flags, sessionKey: sessionKey,
                         privKey: privKey, clientSeq: auth.seqNumber, ctime: auth.ctime, cusec: auth.cusec)
    }

    // MARK: The change

    private func change(_ message: KPasswdMessage, ctx: APContext, now: KerberosTime,
                        record: inout ExchangeRecord) async -> (KPasswdResult, String, String?) {
        let part: EncKrbPrivPart
        do {
            let priv = try KRBPriv(derBytes: message.body)
            part = try EncKrbPrivPart(derBytes: try KerberosCrypto.decrypt(priv.encPart.cipher, key: ctx.privKey,
                                                                          usage: KeyUsage.krbPrivEncPart))
        } catch {
            return (.malformed, "The request could not be decoded", "KRB-PRIV: \(error)")
        }
        if let expected = ctx.clientSeq, let got = part.seqNumber, expected != got {
            return (.malformed, "The request could not be decoded", "KRB-PRIV seq-number \(got), expected \(expected)")
        }

        var passwordBytes = part.userData
        var targetName: PrincipalName?
        var targetRealm: String?
        if message.version == KPasswdMessage.setPasswordVersion {
            guard let data = try? ChangePasswdData(derBytes: part.userData) else {
                return (.malformed, "The request could not be decoded", "ChangePasswdData does not decode")
            }
            (passwordBytes, targetName, targetRealm) = (data.newPassword, data.targetName, data.targetRealm)
        }
        guard let password = String(validating: passwordBytes, as: UTF8.self), !password.isEmpty else {
            return (.malformed, "The new password is not valid UTF-8", "password bytes are not UTF-8")
        }

        do {
            guard let client = try await store.principal(ctx.cname, realm: ctx.crealm) else {
                return (.hardError, "The client account does not exist", "unknown client \(ctx.cname)")
            }
            guard let targetName else {
                return try await changeOwn(client, password: password, ctx: ctx)
            }
            return try await setNamed(targetName, realm: targetRealm ?? ctx.crealm, password: password, client: client,
                                      ctx: ctx, record: &record)
        } catch StoreError.passwordPolicy(let violation) {
            return (.softError, Self.policyText, "policy: \(violation)")
        } catch {
            return (.hardError, "The password change failed", "\(error)")
        }
    }

    /// No `targname`: the ticket's client sets its own password (v1, or 0xFF80 without a target).
    private func changeOwn(_ client: Principal, password: String, ctx: APContext) async throws -> (KPasswdResult, String, String?) {
        guard ctx.ticketFlags.initial else {
            return (.initialFlagNeeded, "Expected an initial ticket", "own password change with a non-initial ticket")
        }
        guard let id = client.directoryID else {
            return (.hardError, "The account has no password", "\(client.displayName) is not a directory account")
        }
        let isUser: Bool
        switch client.kind {
        case .user: isUser = true
        case .computer: isUser = false
        case .service, .krbtgt:
            return (.hardError, "The account has no password", "\(client.displayName) is a \(client.kind.label)")
        }
        try await store.directory.setPassword(id: id, password: password, enforcePolicy: isUser)
        return (.success, "Password changed", nil)
    }

    /// MS set-password with `targname`. The target is resolved by name **without requiring
    /// keys** (`DirectoryStore.passwordAccount`: sAMAccountName, `NAME$`, UPN / enterprise
    /// `user@suffix`), so a computer created over LDAP without `unicodePwd` gets its first keys
    /// here, with the computer salt (`setPassword`): the macOS AD plugin's (`dsconfigad`) join.
    private func setNamed(_ name: PrincipalName, realm: String, password: String, client: Principal, ctx: APContext,
                          record: inout ExchangeRecord) async throws -> (KPasswdResult, String, String?) {
        guard let (target, match) = try await store.directory.passwordAccount(components: name.nameString, realm: realm) else {
            return (.hardError, "The target account does not exist", "unknown target \(name)")
        }
        let targetDisplay = "\(target.samAccountName)@\(store.realm)"
        record.server = "set \(targetDisplay)"
        if target.kind == .krbtgt || match == .servicePrincipalName || match == .krbtgt {
            return (.hardError, "The account has no password", "\(name) is a service name")
        }
        if target.id == client.directoryID {
            guard ctx.ticketFlags.initial else {
                return (.initialFlagNeeded, "Expected an initial ticket", "own password change with a non-initial ticket")
            }
        } else if let denied = try await Self.denial(client: client, target: target, directory: store.directory) {
            return (.accessDenied, "Not permitted to set the password of \(targetDisplay)", denied)
        }
        // Users get the domain policy; machine passwords are random strings chosen by the client.
        try await store.directory.setPassword(id: target.id, password: password, enforcePolicy: target.kind == .user)
        return (.success, "Password changed", nil)
    }

    // MARK: Authorization

    static let builtinDomain = try! SID(string: "S-1-5-32")
    static let builtinAdministrators = try! SID(string: "S-1-5-32-544")
    static let accountOperators = try! SID(string: "S-1-5-32-548")

    /// Accounts an Account Operator may not touch (AD's AdminSDHolder-protected set): the
    /// Administrator (500) and krbtgt (502); members of Domain Admins (512), Domain Controllers
    /// (516), Schema Admins (518), Enterprise Admins (519), Read-only DCs (521), and of the builtin
    /// Administrators, Account/Server/Print/Backup Operators and Replicator (544, 548-552); and DC
    /// machine accounts (SERVER_TRUST_ACCOUNT).
    static let protectedDomainRIDs: Set<UInt32> = [500, 502, 512, 516, 518, 519, 521]
    static let protectedBuiltinRIDs: Set<UInt32> = [544, 548, 549, 550, 551, 552]

    /// Why `client` may not set `target`'s password (nil: allowed). The rule, for a target other
    /// than the client:
    /// - **administrators** may set any user's or computer's password, with or without keys:
    ///   the Administrator (RID 500) and members (transitively) of Domain Admins (512), Enterprise
    ///   Admins (519) or BUILTIN\Administrators (S-1-5-32-544). This is exactly the set that has
    ///   write access in DirectoryKit's LDAP access model, i.e. the only accounts that can create
    ///   the keyless computer object in the first place (`dsconfigad` runs as one of them);
    /// - **Account Operators** (S-1-5-32-548) may set the password of any account that is not
    ///   protected (`protectedDomainRIDs`, `protectedBuiltinRIDs`, DC accounts), keyless computers
    ///   included, as in AD;
    /// - everyone else gets ACCESSDENIED.
    static func denial(client: Principal, target: PasswordAccount, directory: DirectoryStore) async throws -> String? {
        let clientSID: SID
        switch client.kind {
        case let .user(sid, _, _, _), let .computer(sid, _, _): clientSID = sid
        case .service, .krbtgt: return "\(client.displayName) is a \(client.kind.label)"
        }
        guard let clientID = client.directoryID else { return "\(client.displayName) is not a directory account" }
        let domain = try await directory.domainInfo().domainSID
        let groups = Set(try await directory.groupSIDs(of: clientID))
        let adminSIDs = [500, 512, 519].compactMap { try? domain.appending(rid: $0) } + [builtinAdministrators]
        if clientSID == adminSIDs[0] || adminSIDs.contains(where: groups.contains) { return nil }
        guard groups.contains(accountOperators) else {
            return "\(client.displayName) is not an administrator or account operator"
        }
        if try await isProtected(target, domain: domain, directory: directory) {
            return "\(target.samAccountName) is protected from account operators"
        }
        return nil
    }

    static func isProtected(_ target: PasswordAccount, domain: SID, directory: DirectoryStore) async throws -> Bool {
        if target.userAccountControl & UserAccountControl.serverTrustAccount != 0 { return true }
        for sid in [target.sid].compactMap({ $0 }) + (try await directory.groupSIDs(of: target.id)) {
            guard let rid = sid.rid, let parent = sid.domain else { continue }
            if parent == domain, protectedDomainRIDs.contains(rid) { return true }
            if parent == builtinDomain, protectedBuiltinRIDs.contains(rid) { return true }
        }
        return false
    }

    // MARK: Replies

    private func reply(_ ctx: APContext, result: KPasswdResult, text: String, now: KerberosTime,
                       peer: PeerInfo) throws -> [UInt8] {
        let seq = UInt32(truncatingIfNeeded: rng.next(4).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }) & 0x3FFF_FFFF
        let apPart = KPasswdEncAPRepPart(ctime: ctx.ctime, cusec: ctx.cusec, seqNumber: seq)
        let apCipher = try KerberosCrypto.encrypt(apPart.encode(), key: ctx.sessionKey, usage: KeyUsage.apRepEncPart, rng: rng)
        let apRep = KPasswdAPRep(encPart: EncryptedData(etype: ctx.sessionKey.type.rawValue, cipher: apCipher))
        let privPart = EncKrbPrivPart(
            userData: KPasswdMessage.resultData(result, text), timestamp: now, usec: 0, seqNumber: seq,
            sAddress: peer.localAddress ?? HostAddress(addrType: AddressType.ipv4, address: [127, 0, 0, 1]))
        let privCipher = try KerberosCrypto.encrypt(privPart.encode(), key: ctx.privKey, usage: KeyUsage.krbPrivEncPart, rng: rng)
        let priv = KRBPriv(encPart: EncryptedData(etype: ctx.privKey.type.rawValue, cipher: privCipher))
        return KPasswdMessage(version: KPasswdMessage.replyVersion, apData: apRep.encode(), body: priv.encode()).encode()
    }

    private func errorReply(_ f: APFailure, now: KerberosTime, record: inout ExchangeRecord) -> [UInt8] {
        record.kpasswdResult = f.result
        record.errorCode = f.code
        record.reason = f.reason
        let text = f.result == .authError ? "Authentication failed" : "The request could not be processed"
        let error = KRBError(stime: now, errorCode: f.code, realm: store.realm, sname: .changePassword,
                             eData: KPasswdMessage.resultData(f.result, text))
        return KPasswdMessage(version: KPasswdMessage.replyVersion, apData: [], body: error.encode()).encode()
    }
}

/// kpasswd on UDP and TCP (default port 464), the same Network.framework listeners as the KDC.
public final class KPasswdServer: Sendable {
    public let service: KPasswdService
    private let listener: DualListener

    public init(service: KPasswdService, port: UInt16 = 464, bindAddress: String = "0.0.0.0") {
        self.service = service
        let realm = service.store.realm
        listener = DualListener(name: "kpasswd", port: port, bindAddress: bindAddress,
                                udp: { request, peer in await service.handle(request, peer: peer) },
                                tcp: { request, peer in await service.handle(request, peer: peer) },
                                tooLong: {
                                    KRBError(stime: KerberosTime(Date()), errorCode: KerberosErrorCode.krbErrFieldToolong,
                                             realm: realm, sname: .changePassword).encode()
                                })
    }

    public var bindAddress: String { listener.bindAddress }

    /// The bound port (useful when 0 was requested). Valid after `start()`.
    public var port: UInt16 { listener.port }

    public func start() async throws { try await listener.start() }

    public func stop() { listener.stop() }
}
