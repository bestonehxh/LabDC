import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC
import SheepCrypto
import os

/// One line of the exchange log: what was asked, by whom, and how it ended.
public struct ExchangeRecord: Sendable, CustomStringConvertible {
    public enum Kind: String, Sendable {
        case asExchange = "AS"
        case tgsExchange = "TGS"
        case kpasswd = "KPASSWD"
        case unknown = "?"
    }

    public var kind: Kind = .unknown
    /// `alice@LAB.SHEEP`, when the request named a client.
    public var client: String?
    /// The requested service, `krbtgt/LAB.SHEEP` or `host/dc1.lab.sheep`.
    public var server: String?
    public var from: String
    /// The ticket's enctype on success.
    public var etype: Int32?
    /// The KRB-ERROR code, nil on success.
    public var errorCode: Int32?
    /// Ticket lifetime in seconds on success.
    public var lifetime: Int64?
    /// Why the request failed (for `--verbose`); never contains key material.
    public var reason: String?
    /// "udp" / "tcp" / nil when driven directly.
    public var transport: String?
    /// Reply size in bytes.
    public var replySize: Int = 0
    /// kpasswd: the result code sent back (in a KRB-PRIV, or in a KRB-ERROR's e-data).
    public var kpasswdResult: KPasswdResult?

    public init(from: String) { self.from = from }

    public var succeeded: Bool { errorCode == nil }

    /// `AS alice@LAB.SHEEP from 127.0.0.1 etype=18 -> OK ticket krbtgt/LAB.SHEEP 10h` or
    /// `AS alice@LAB.SHEEP from 127.0.0.1 -> KDC_ERR_PREAUTH_REQUIRED`.
    public var description: String {
        var s = "\(kind.rawValue) \(client ?? "-") from \(from)"
        if let transport { s += "/\(transport)" }
        if let kpasswdResult {
            s += " \(server ?? "-") -> \(kpasswdResult)"
            if let errorCode { s += " (\(KerberosErrorCode.name(errorCode)))" }
            return s
        }
        if let errorCode {
            s += " -> \(KerberosErrorCode.name(errorCode))"
        } else {
            if let etype { s += " etype=\(etype)" }
            s += " -> OK ticket \(server ?? "-")"
            if let lifetime { s += " \(Self.formatLifetime(lifetime))" }
        }
        return s
    }

    static func formatLifetime(_ seconds: Int64) -> String {
        let h = seconds / 3600, m = (seconds % 3600) / 60
        return m == 0 ? "\(h)h" : "\(h)h\(m)m"
    }
}

/// The KDC: AS and TGS exchanges (RFC 4120 §3.1, §3.3, MS-KILE §3.3.5) over a
/// `PrincipalStore`. Transport-agnostic: `handle(_:from:)` takes one request and returns one
/// reply (a KRB-ERROR for every failure), so tests drive it without sockets.
///
/// Windows-facing behaviour (WP-J): `canonicalize`, NT-ENTERPRISE and `DOMAIN\user` client
/// names, PA-PAC-OPTIONS and PA-SUPPORTED-ENCTYPES in `encrypted-pa-data`, ETYPE-INFO2 in
/// PREAUTH_FAILED, a PA-ENC-TIMESTAMP replay cache, renew/validate, U2U refused with BADOPTION,
/// PAC_FULL_CHECKSUM in service tickets, account state (CLIENT_REVOKED, KEY_EXPIRED) and
/// logon bookkeeping.
public actor KDC {
    public nonisolated let store: any PrincipalStore
    private let rng: RandomBytes
    private let clock: @Sendable () -> Date
    private let onExchange: (@Sendable (ExchangeRecord) -> Void)?
    /// PA-ENC-TIMESTAMP ciphertexts seen in the last `KDCPolicy.replayWindow` seconds.
    private var replayCache = ReplayCache()

    private static let logger = Logger(subsystem: "dev.labdc.app", category: "KDC")

    /// - Parameters:
    ///   - clock: the KDC's notion of now (tests inject a fixed time).
    ///   - onExchange: called once per request with the log record.
    public init(store: any PrincipalStore, rng: RandomBytes = RandomBytes(),
                clock: @escaping @Sendable () -> Date = { Date() },
                onExchange: (@Sendable (ExchangeRecord) -> Void)? = nil) {
        self.store = store
        self.rng = rng
        self.clock = clock
        self.onExchange = onExchange
    }

    /// Handles one request (AS-REQ or TGS-REQ) and returns the DER reply.
    public func handle(_ request: [UInt8], from: String) async -> [UInt8] {
        var (reply, record) = await process(request, from: from)
        record.replySize = reply.count
        emit(record)
        return reply
    }

    /// Like `handle`, for a UDP datagram: a reply larger than `limit` bytes is replaced by
    /// `KRB_ERR_RESPONSE_TOO_BIG` so the client retries over TCP (RFC 4120 §7.2.1).
    public func handleUDP(_ request: [UInt8], from: String, limit: Int = KDCPolicy.maxUDPReply) async -> [UInt8] {
        var (reply, record) = await process(request, from: from)
        record.transport = "udp"
        if reply.count > limit {
            record.reason = "reply of \(reply.count) bytes exceeds \(limit) on UDP"
            record.errorCode = KerberosErrorCode.krbErrResponseTooBig
            reply = errorReply(KerberosErrorCode.krbErrResponseTooBig, now: now(), context: Context())
        }
        record.replySize = reply.count
        emit(record)
        return reply
    }

    /// Records a TCP exchange (same as `handle`, tagged "tcp" in the log).
    public func handleTCP(_ request: [UInt8], from: String) async -> [UInt8] {
        var (reply, record) = await process(request, from: from)
        record.transport = "tcp"
        record.replySize = reply.count
        emit(record)
        return reply
    }

    private func emit(_ record: ExchangeRecord) {
        if let reason = record.reason {
            Self.logger.info("\(record.description, privacy: .public) (\(reason, privacy: .public))")
        } else {
            Self.logger.info("\(record.description, privacy: .public)")
        }
        onExchange?(record)
    }

    private func now() -> KerberosTime {
        KerberosTime(secondsSince1970: Int64(clock().timeIntervalSince1970.rounded(.down)))
    }

    /// Names echoed in a KRB-ERROR.
    struct Context {
        var crealm: String?
        var cname: PrincipalName?
        var sname: PrincipalName?
    }

    private func process(_ request: [UInt8], from: String) async -> ([UInt8], ExchangeRecord) {
        var record = ExchangeRecord(from: from)
        var context = Context()
        let now = now()
        do {
            switch KerberosMessage.applicationTag(of: request) {
            case ASReq.applicationTag:
                record.kind = .asExchange
                let req = try decode { try ASReq(derBytes: request) }
                return (try await handleAS(req, request: request, now: now, record: &record, context: &context), record)
            case TGSReq.applicationTag:
                record.kind = .tgsExchange
                let req = try decode { try TGSReq(derBytes: request) }
                return (try await handleTGS(req, now: now, record: &record, context: &context), record)
            case let tag:
                throw KDCError.krb(KerberosErrorCode.krbApErrMsgType,
                                   "not an AS-REQ or TGS-REQ (APPLICATION tag \(tag.map(String.init) ?? "none"))")
            }
        } catch {
            let (code, reason, eData) = Self.classify(error)
            record.errorCode = code
            record.reason = reason
            return (errorReply(code, now: now, context: context, eData: eData), record)
        }
    }

    private static func classify(_ error: any Error) -> (Int32, String, [UInt8]?) {
        switch error {
        case let KDCError.protocolError(code, reason, eData): (code, reason, eData)
        case let e as KerberosASN1Error: (e.kerberosErrorCode, e.description, nil)
        case let e as KerberosCryptoError: (e.krbErrorCode ?? KerberosErrorCode.krbErrGeneric, e.description, nil)
        case let e as MSPACError: (KerberosErrorCode.krbErrGeneric, "PAC: \(e)", nil)
        default: (KerberosErrorCode.krbErrGeneric, String(describing: error), nil)
        }
    }

    private func decode<T>(_ body: () throws -> T) throws -> T {
        do { return try body() } catch let e as KerberosASN1Error {
            throw KDCError.krb(e.kerberosErrorCode, e.description)
        }
    }

    /// A KRB-ERROR with no `e-text`: Heimdal prints e-text instead of its own message for the
    /// code ("Password incorrect"), so reasons go to the log only.
    private func errorReply(_ code: Int32, now: KerberosTime, context: Context, eData: [UInt8]? = nil) -> [UInt8] {
        KRBError(stime: now, susec: 0, errorCode: code,
                 crealm: context.cname == nil ? nil : (context.crealm ?? store.realm),
                 cname: context.cname, realm: store.realm,
                 sname: context.sname ?? .krbtgt(realm: store.realm),
                 eText: nil, eData: eData).encode()
    }

    // MARK: - Names

    /// The realm of a request: the realm or the DNS domain, in any case (`lab.sheep`), or the
    /// NetBIOS domain name (`LABSHEEP`). Windows sends the NetBIOS name as the realm for a
    /// `LABSHEEP\alice` logon (WP-AL); a Windows DC and Samba (`lpcfg_is_my_domain_or_realm`)
    /// treat it as an alias of the realm.
    private func isOurRealm(_ r: String) -> Bool {
        r.caseInsensitiveCompare(store.realm) == .orderedSame || isRealmAlias(r)
    }

    /// True for a realm we accept that is not the realm in some letter case: the NetBIOS domain
    /// name, or a DNS domain spelled differently from the realm. An alias is never echoed: the
    /// reply names the canonical realm (`store.realm`) whatever the `canonicalize` option
    /// (RFC 6806 §7: the reply and the ticket carry the true realm). A case variant of the realm
    /// (`lab.sheep`) is not an alias and is still echoed without `canonicalize` (WP-Y).
    private func isRealmAlias(_ r: String) -> Bool {
        guard !r.isEmpty, r.caseInsensitiveCompare(store.realm) != .orderedSame else { return false }
        return r.caseInsensitiveCompare(store.netbiosDomain) == .orderedSame
            || r.caseInsensitiveCompare(store.dnsDomain) == .orderedSame
    }

    /// `krbtgt/<our realm or an alias>`, in any case.
    private func isOurKrbtgt(_ name: PrincipalName) -> Bool {
        name.nameString.count == 2 && name.nameString[0].caseInsensitiveCompare("krbtgt") == .orderedSame
            && isOurRealm(name.nameString[1])
    }

    /// True for `krbtgt/<alias>` (`krbtgt/LABSHEEP`): such a name is never echoed either.
    private func isAliasKrbtgt(_ name: PrincipalName) -> Bool {
        isOurKrbtgt(name) && isRealmAlias(name.nameString[1])
    }

    /// The name a requested service is looked up by: `krbtgt/<alias>` is `krbtgt/REALM` (the
    /// stores know the realm and DNS domain spellings only).
    private func lookupName(_ name: PrincipalName) -> PrincipalName {
        isOurKrbtgt(name) ? .krbtgt(realm: store.realm) : name
    }

    /// Client lookup: the store's resolution (sAMAccountName, `NAME$`, NT-ENTERPRISE
    /// `user@suffix` by UPN), plus the down-level `DOMAIN\user` form (NetBIOS or DNS domain).
    func lookupClient(_ cname: PrincipalName, realm: String) async throws -> Principal? {
        var name = cname
        if name.nameString.count == 1, let slash = name.nameString[0].firstIndex(of: "\\") {
            let s = name.nameString[0]
            let domain = String(s[..<slash]), user = String(s[s.index(after: slash)...])
            guard !user.isEmpty, !user.contains("\\"),
                  domain.caseInsensitiveCompare(store.netbiosDomain) == .orderedSame
                    || domain.caseInsensitiveCompare(store.dnsDomain) == .orderedSame else { return nil }
            name = PrincipalName(nameType: NameType.principal, nameString: [user])
        }
        return try await store.principal(name, realm: realm)
    }

    /// Disabled or expired accounts get KDC_ERR_CLIENT_REVOKED with the NTSTATUS Windows expects.
    private func checkAccountState(_ client: Principal, now: KerberosTime) throws {
        guard client.enabled else {
            throw KDCError.krb(KerberosErrorCode.kdcErrClientRevoked, "client \(client.displayName) is disabled",
                               eData: KerbErrorData.extended(NTStatus.accountDisabled))
        }
        guard !client.isExpired(at: now.date) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrClientRevoked, "client \(client.displayName) expired",
                               eData: KerbErrorData.extended(NTStatus.accountExpired))
        }
    }

    // MARK: - AS exchange

    private func handleAS(_ req: ASReq, request: [UInt8], now: KerberosTime, record: inout ExchangeRecord,
                          context: inout Context) async throws -> [UInt8] {
        let body = req.reqBody
        let realm = store.realm
        let options = body.kdcOptions
        context.cname = body.cname
        context.crealm = body.realm
        context.sname = body.sname
        if let cname = body.cname { record.client = "\(cname)@\(body.realm)" }
        if let sname = body.sname { record.server = sname.description }

        guard isOurRealm(body.realm) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrWrongRealm, "realm \(body.realm) is not \(realm)")
        }
        guard let cname = body.cname else {
            throw KDCError.krb(KerberosErrorCode.kdcErrCPrincipalUnknown, "AS-REQ without cname")
        }
        // Lookups use the canonical realm: the stores do not know the NetBIOS alias.
        let alias = isRealmAlias(body.realm)
        guard let client = try await lookupClient(cname, realm: realm) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrCPrincipalUnknown, "unknown client \(cname)")
        }
        try checkAccountState(client, now: now)
        guard let sname = body.sname, let server = try await store.principal(lookupName(sname), realm: realm) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrSPrincipalUnknown, "unknown server \(body.sname?.description ?? "-")")
        }
        guard server.enabled else {
            throw KDCError.krb(KerberosErrorCode.kdcErrServiceRevoked, "server \(server.displayName) is disabled")
        }
        guard let krbtgt = try await store.principal(.krbtgt(realm: realm), realm: realm), let kdcKey = krbtgt.strongestKey else {
            throw KDCError.krb(KerberosErrorCode.krbErrGeneric, "no krbtgt key")
        }

        let offered = body.etype.compactMap(EncryptionType.init(rawValue:))
        let clientTypes = KDCPolicy.enctypePreference.filter { offered.contains($0) && client.key($0) != nil }
        guard let chosen = clientTypes.first else {
            throw KDCError.krb(KerberosErrorCode.kdcErrEtypeNosupp, "no common enctype (offered \(body.etype))")
        }

        // Pre-authentication: PA-ENC-TIMESTAMP is required (RFC 4120 §5.2.7.2).
        let etypeInfo = ETypeInfo2(clientTypes.map { etypeInfo2Entry($0, for: client) }).paData
        guard let pa = req.padata.first(ofType: PADataType.encTimestamp), !pa.value.isEmpty else {
            let methodData = MethodData([etypeInfo, PAData(type: PADataType.encTimestamp, value: [])])
            throw KDCError.krb(KerberosErrorCode.kdcErrPreauthRequired, "pre-authentication required",
                               eData: methodData.encode())
        }
        let replyKey: KerberosKey
        do {
            replyKey = try verifyEncTimestamp(pa.value, client: client, now: now, request: request)
        } catch let KDCError.protocolError(code, reason, _) where code == KerberosErrorCode.kdcErrPreauthFailed {
            // MS-KILE §3.3.5.4: ETYPE-INFO2 in the e-data, so a client can retry with the right salt.
            throw KDCError.krb(code, reason, eData: MethodData([etypeInfo]).encode())
        }

        // Account restrictions that need a proven password: the password must change (only
        // kadmin/changepw may be asked for, so the user can change it).
        if client.mustChangePassword, !server.isChangePasswordService {
            throw KDCError.krb(KerberosErrorCode.kdcErrKeyExpired, "\(client.displayName) must change the password",
                               eData: KerbErrorData.extended(NTStatus.passwordMustChange))
        }

        // Ticket enctype: the chosen one if the server has it, else the server's strongest.
        guard let ticketKey = server.key(chosen) ?? server.strongestKey else {
            throw KDCError.krb(KerberosErrorCode.kdcErrEtypeNosupp, "server \(server.displayName) has no keys")
        }
        let sessionType = KDCPolicy.enctypePreference.first { offered.contains($0) && server.key($0) != nil } ?? chosen
        let sessionKey = KerberosCrypto.randomKey(sessionType, rng: rng)

        let changePassword = server.isChangePasswordService
        var flags = TicketFlags()
        flags.forwardable = options.forwardable && !changePassword
        flags.proxiable = options.proxiable && !changePassword
        flags.initial = true
        flags.preAuthent = true

        let maxLife = changePassword ? KDCPolicy.changePasswordTicketLifetime : KDCPolicy.maxTicketLifetime
        var endtime = now.adding(seconds: maxLife)
        if body.till.secondsSince1970 > 0, body.till < endtime { endtime = body.till }
        guard endtime > now else {
            throw KDCError.krb(KerberosErrorCode.kdcErrNeverValid, "requested end time \(body.till.generalizedTimeString) is in the past")
        }
        var renewTill: KerberosTime?
        var rtime = body.rtime
        // RENEWABLE-OK: a longer lifetime than we grant becomes a renewable ticket instead.
        let renewableOK = options.renewableOK && body.till.secondsSince1970 > 0 && body.till > endtime
        if renewableOK, !options.renewable { rtime = body.till }
        if (options.renewable || renewableOK) && !changePassword {
            flags.renewable = true
            var limit = now.adding(seconds: KDCPolicy.maxRenewableLifetime)
            if let rtime, rtime.secondsSince1970 > 0, rtime < limit { limit = rtime }
            renewTill = max(limit, endtime)
        }

        // Names in the reply. With `canonicalize` (RFC 6806 §5): the account's canonical name
        // (sAMAccountName casing, NT-PRINCIPAL) and the canonical realm; krbtgt as
        // krbtgt/REALM. Without it the names are echoed as asked, since Heimdal compares them,
        // except a realm alias (`LABSHEEP`, WP-AL): the reply realm is then always the canonical
        // one, and so is a krbtgt name, as a Windows DC and Samba answer.
        let canonicalize = options.canonicalize
        let replyCname = canonicalize ? client.name : cname
        let replyRealm = canonicalize || alias ? realm : body.realm
        let replySname = (canonicalize || alias || isAliasKrbtgt(sname)) && server.kind == .krbtgt
            ? PrincipalName.krbtgt(realm: realm) : sname

        var encTicket = EncTicketPart(
            flags: flags, key: EncryptionKey(keytype: sessionKey.type.rawValue, keyvalue: sessionKey.bytes),
            crealm: replyRealm, cname: replyCname, transited: .empty, authtime: now, starttime: nil,
            endtime: endtime, renewTill: renewTill)

        // PAC (MS-KILE §3.3.5.3): included unless PA-PAC-REQUEST says include-pac = FALSE.
        var includePAC = true
        var attributes = PACAttributesInfo.givenImplicitly
        if let p = req.padata.first(ofType: PADataType.pacRequest) {
            let pacRequest = try? PAPacRequest(derBytes: p.value)
            includePAC = pacRequest?.includePAC ?? true
            attributes = .requested
        }
        var builder: PACBuilder?
        if includePAC {
            builder = try makePAC(for: client, cname: replyCname, authtime: now, attributes: attributes)
        }
        let ticket = try sealTicket(&encTicket, realm: replyRealm, sname: replySname, server: server, serverKey: ticketKey,
                                    kdcKey: server.kind == .krbtgt ? ticketKey : kdcKey, pac: builder)

        // encrypted-pa-data: what the KDC supports (MS-KILE §3.3.5.4) and PA-PAC-OPTIONS.
        var encPAData = [SupportedEnctypes.paData(krbtgt.supportedEncryptionTypesValue & SupportedEnctypes.enctypeMask)]
        if let echo = pacOptionsEcho(req.padata) { encPAData.append(echo) }

        let encPart = EncKDCRepPart(
            key: encTicket.key, lastReq: [LastReqEntry(lrType: LastReqType.none, lrValue: now)],
            nonce: body.nonce, flags: flags, authtime: now, starttime: now, endtime: endtime,
            renewTill: renewTill, srealm: replyRealm, sname: replySname, encryptedPAData: encPAData)
        let cipher = try KerberosCrypto.encrypt(EncASRepPart(encPart).encode(), key: replyKey,
                                                usage: KeyUsage.asRepEncPart, rng: rng)
        let rep = ASRep(
            padata: [ETypeInfo2([etypeInfo2Entry(replyKey.type, for: client)]).paData],
            crealm: replyRealm, cname: replyCname, ticket: ticket,
            encPart: EncryptedData(etype: replyKey.type.rawValue, kvno: client.kvno, cipher: cipher))

        await store.recordLogon(client, at: now.date)
        // The log keeps a realm alias as the client sent it (`alice@LABSHEEP`).
        if !alias { record.client = "\(replyCname)@\(replyRealm)" }
        record.server = replySname.description
        record.etype = ticketKey.type.rawValue
        record.lifetime = endtime.secondsSince1970 - now.secondsSince1970
        return rep.encode()
    }

    /// PA-PAC-OPTIONS (167) of the request, echoed for `encrypted-pa-data`.
    private func pacOptionsEcho(_ padata: [PAData]) -> PAData? {
        guard let p = padata.first(ofType: PADataType.pacOptions), let options = try? PAPacOptions(derBytes: p.value) else {
            return nil
        }
        return options.echoed.paData
    }

    /// PA-ETYPE-INFO2 entry: salt and 4096-iteration s2kparams for AES, nothing for RC4.
    private func etypeInfo2Entry(_ type: EncryptionType, for client: Principal) -> ETypeInfo2Entry {
        switch type {
        case .rc4Hmac:
            return ETypeInfo2Entry(etype: type.rawValue)
        case .aes128CtsHmacSha1, .aes256CtsHmacSha1:
            let salt = client.salt ?? KerberosCrypto.defaultSalt(realm: client.realm, principal: client.name.nameString)
            return ETypeInfo2Entry(etype: type.rawValue, salt: salt,
                                   s2kparams: ETypeInfo2Entry.aesIterations(KDCPolicy.aesIterations))
        }
    }

    /// Decrypts and checks PA-ENC-TIMESTAMP (usage 1), then the replay cache; returns the client
    /// key that worked.
    private func verifyEncTimestamp(_ value: [UInt8], client: Principal, now: KerberosTime,
                                    request: [UInt8]) throws -> KerberosKey {
        let failed = KerberosErrorCode.kdcErrPreauthFailed
        guard let enc = try? EncryptedData(derBytes: value) else {
            throw KDCError.krb(failed, "PA-ENC-TIMESTAMP is not EncryptedData")
        }
        guard let type = EncryptionType(rawValue: enc.etype), let key = client.key(type) else {
            throw KDCError.krb(failed, "PA-ENC-TIMESTAMP uses enctype \(enc.etype) the client has no key for")
        }
        let plain: [UInt8]
        do { plain = try KerberosCrypto.decrypt(enc.cipher, key: key, usage: KeyUsage.asReqPaEncTimestamp) } catch {
            throw KDCError.krb(failed, "PA-ENC-TIMESTAMP does not decrypt with \(client.displayName)'s \(type) key")
        }
        guard let ts = try? PAEncTSEnc(derBytes: plain) else {
            throw KDCError.krb(failed, "PA-ENC-TIMESTAMP plaintext is not PA-ENC-TS-ENC")
        }
        let skew = abs(ts.patimestamp.secondsSince1970 - now.secondsSince1970)
        guard skew <= KDCPolicy.maxSkew else {
            throw KDCError.krb(KerberosErrorCode.krbApErrSkew, "client clock is \(skew) s off")
        }
        switch replayCache.check(enc.cipher, request: request, now: now.secondsSince1970) {
        case .fresh: break
        case .retransmission: record(retransmission: client)
        case .replay:
            throw KDCError.krb(KerberosErrorCode.krbApErrRepeat, "PA-ENC-TIMESTAMP of \(client.displayName) replayed")
        }
        return key
    }

    private func record(retransmission client: Principal) {
        Self.logger.debug("retransmitted AS-REQ of \(client.displayName, privacy: .public) answered again")
    }

    /// PAC for a user or computer; nil for services and krbtgt (no SID).
    private func makePAC(for client: Principal, cname: PrincipalName, authtime: KerberosTime,
                         attributes: PACAttributesInfo) throws -> PACBuilder? {
        let samName: String, sid: SID, groups: [UInt32], upn: String
        let computer: Bool
        switch client.kind {
        case let .user(s, u, sam, g):
            (sid, upn, samName, groups, computer) = (s, u, sam, g, false)
        case let .computer(s, sam, g):
            (sid, upn, samName, groups, computer) = (s, "\(sam)@\(store.dnsDomain)", sam, g, true)
        case .service, .krbtgt:
            return nil
        }
        let logonTime = FileTime(authtime.date)
        // WP-AO: GroupIds = the primary group first, then the other group RIDs, each once (as a
        // Windows DC and Samba send it); PrimaryGroupId = the account's primaryGroupID. Users
        // default to Domain Users (513); computers to their first group (515, or 516 for DCs),
        // with no implicit Domain Users.
        let primary = client.primaryGroupID ?? (computer ? groups.first ?? 515 : 513)
        var logon = KerberosValidationInfo.labUser(
            samAccountName: samName, rid: sid.rid ?? 0, primaryGroupId: primary, groupRids: groups,
            domainSID: store.domainSID, netbiosDomain: store.netbiosDomain, dcNetbiosName: store.dcName,
            logonTime: logonTime,
            passwordLastSet: client.passwordSet.timeIntervalSince1970 > 0 ? FileTime(client.passwordSet) : .zero)
        if computer {
            // SAMR USER_WORKSTATION_TRUST_ACCOUNT (0x80) or USER_SERVER_TRUST_ACCOUNT (0x100).
            logon.userAccountControl = primary == 516 ? 0x100 : 0x80
        }
        return PACBuilder(
            logonInfo: logon,
            clientInfo: PACClientInfo(clientId: logonTime, name: cname.nameString.joined(separator: "/")),
            // Windows DCs write DnsDomainName in upper case (the realm), the UPN as stored.
            upnDNS: PACUpnDnsInfo(upn: upn, dnsDomainName: store.dnsDomain.uppercased(),
                                  upnConstructed: !client.hasExplicitUPN, samName: samName, sid: sid),
            attributes: attributes,
            requestor: PACRequestor(sid: sid))
    }

    /// Signs the PAC into `encTicket` and encrypts it with the server key, usage 2. Tickets not
    /// for krbtgt get the ticket signature (0x10, MS-PAC §2.8.2) and the extended KDC signature
    /// (0x13, §2.8.3); TGTs get neither, as Windows does.
    private func sealTicket(_ encTicket: inout EncTicketPart, realm: String, sname: PrincipalName, server: Principal,
                            serverKey: KerberosKey, kdcKey: KerberosKey, pac: PACBuilder?) throws -> Ticket {
        if let pac {
            let kdcSigner = KeyPACSigner(key: kdcKey)
            var ticketChecksum: PACSignatureData?
            let serviceTicket = server.kind != .krbtgt
            if serviceTicket {
                var placeholder = encTicket
                placeholder.authorizationData = .ifRelevantPAC(PACChecksum.ticketSignaturePlaceholderADData)
                ticketChecksum = try PACBuilder.ticketChecksum(encTicketPartDER: placeholder.encode(), kdcSigner: kdcSigner)
            }
            let pacBytes = try pac.build(serverSigner: KeyPACSigner(key: serverKey), kdcSigner: kdcSigner,
                                         ticketChecksum: ticketChecksum, fullChecksum: serviceTicket)
            encTicket.authorizationData = .ifRelevantPAC(pacBytes)
        }
        let cipher = try KerberosCrypto.encrypt(encTicket.encode(), key: serverKey, usage: KeyUsage.kdcRepTicket, rng: rng)
        return Ticket(realm: realm, sname: sname,
                      encPart: EncryptedData(etype: serverKey.type.rawValue, kvno: server.kvno, cipher: cipher))
    }

    // MARK: - TGS exchange

    /// Verifies the authenticator's req-body checksum (usage 6).
    ///
    /// RFC 4120 §5.5.1 leaves the authenticator checksum type to the implementation, and
    /// clients use unkeyed ones: Windows 10 sends **rsa-md5 (7)** with an AES256 session key
    /// (seen on the first real domain join, WP-Y), Heimdal sends it with an RC4 session key
    /// (WP-J). The checksum sits inside the authenticator, which is encrypted with the TGT
    /// session key, so an unkeyed collision-proof checksum is as good as a keyed one here.
    /// Like MIT (`kdc_util.c` `comp_cksum`) and Heimdal:
    /// - **rsa-md5 (7)** and **rsa-md4 (2)** are recomputed over the req-body DER as received
    ///   and accepted with any session key enctype;
    /// - **crc32 (1)** is not collision-proof and gets INAPP_CKSUM, as in MIT;
    /// - keyed checksums (15, 16, -138) are verified with the session key and must match its
    ///   enctype, else INAPP_CKSUM;
    /// - anything else is SUMTYPE_NOSUPP. A body that does not match gives MODIFIED.
    private func verifyReqBodyChecksum(_ cksum: Checksum, reqBody: [UInt8], sessionKey: KerberosKey) throws {
        switch cksum.cksumtype {
        case Self.rsaMD5, Self.rsaMD4:
            let name = cksum.cksumtype == Self.rsaMD5 ? "rsa-md5" : "rsa-md4"
            let digest = cksum.cksumtype == Self.rsaMD5 ? MD5.hash(reqBody) : MD4.hash(reqBody)
            guard ConstantTime.equal(digest, cksum.checksum) else {
                throw KDCError.krb(KerberosErrorCode.krbApErrModified, "req-body \(name) checksum does not verify")
            }
            return
        case Self.crc32:
            throw KDCError.krb(KerberosErrorCode.krbApErrInappCksum, "crc32 is not a collision-proof req-body checksum")
        default:
            break
        }
        guard let type = ChecksumType(rawValue: cksum.cksumtype) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrSumtypeNosupp, "authenticator checksum type \(cksum.cksumtype)")
        }
        guard type.keyType == sessionKey.type else {
            throw KDCError.krb(KerberosErrorCode.krbApErrInappCksum, "checksum \(type) with a \(sessionKey.type) key")
        }
        guard try KerberosCrypto.verifyChecksum(type, data: reqBody, key: sessionKey,
                                                usage: KeyUsage.tgsReqAuthenticatorChecksum, expected: cksum.checksum) else {
            throw KDCError.krb(KerberosErrorCode.krbApErrModified, "req-body checksum does not verify")
        }
    }

    /// RFC 3961 unkeyed checksum types (§6.1.3, §6.1.1, §6.1.2).
    static let crc32: Int32 = 1
    static let rsaMD4: Int32 = 2
    static let rsaMD5: Int32 = 7

    private func handleTGS(_ req: TGSReq, now: KerberosTime, record: inout ExchangeRecord,
                           context: inout Context) async throws -> [UInt8] {
        let body = req.reqBody
        let realm = store.realm
        context.sname = body.sname
        if let sname = body.sname { record.server = sname.description }

        // PA-TGS-REQ is found by type: Heimdal puts PA-FX-FAST in front of it.
        guard let apReq = try decode({ try req.tgsAPReq() }) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrPadataTypeNosupp, "TGS-REQ without PA-TGS-REQ")
        }

        // Options: user-to-user, proxy and forwarded requests are not supported.
        let options = body.kdcOptions
        let unsupported = [(options.encTktInSkey, "enc-tkt-in-skey (user-to-user)"), (options.proxy, "proxy"),
                           (options.forwarded, "forwarded"), (options.renew && options.validate, "renew+validate")]
            .filter(\.0).map(\.1)
        guard unsupported.isEmpty else {
            throw KDCError.krb(KerberosErrorCode.kdcErrBadoption, "unsupported kdc-options \(unsupported)")
        }
        let renewOrValidate = options.renew || options.validate

        // 1. The presented ticket: a TGT, or for renew/validate any ticket we issued.
        let tkt = apReq.ticket
        guard isOurRealm(tkt.realm) else {
            throw KDCError.krb(KerberosErrorCode.krbApErrNotUs, "ticket is for realm \(tkt.realm)")
        }
        guard let krbtgt = try await store.principal(.krbtgt(realm: realm), realm: realm), let kdcKey = krbtgt.strongestKey else {
            throw KDCError.krb(KerberosErrorCode.krbErrGeneric, "no krbtgt key")
        }
        let ticketServer: Principal
        if isOurKrbtgt(tkt.sname) {
            ticketServer = krbtgt
        } else if renewOrValidate, let p = try await store.principal(tkt.sname, realm: realm), p.kind != .krbtgt {
            ticketServer = p
        } else {
            throw KDCError.krb(KerberosErrorCode.krbApErrNotUs, "ticket is for \(tkt.sname)@\(tkt.realm), not krbtgt/\(realm)")
        }
        guard let tgtType = EncryptionType(rawValue: tkt.encPart.etype), let tgtKey = ticketServer.key(tgtType),
              tkt.encPart.kvno.map({ $0 == ticketServer.kvno }) ?? true else {
            throw KDCError.krb(KerberosErrorCode.krbApErrBadkeyver,
                               "no \(ticketServer.displayName) key for etype \(tkt.encPart.etype) kvno \(tkt.encPart.kvno.map(String.init) ?? "-")")
        }
        let tgt = try decode { try EncTicketPart(derBytes: try KerberosCrypto.decrypt(tkt.encPart.cipher, key: tgtKey, usage: KeyUsage.kdcRepTicket)) }
        context.cname = tgt.cname
        context.crealm = tgt.crealm
        record.client = "\(tgt.cname)@\(tgt.crealm)"
        guard tgt.endtime >= now else {
            throw KDCError.krb(KerberosErrorCode.krbApErrTktExpired, "ticket expired at \(tgt.endtime.generalizedTimeString)")
        }
        let notYetValid = tgt.starttime.map { $0.secondsSince1970 > now.secondsSince1970 + KDCPolicy.maxSkew } ?? false
        if options.validate {
            // RFC 4120 §3.3.3: only an INVALID (postdated) ticket whose start time has come.
            guard tgt.flags.invalid else {
                throw KDCError.krb(KerberosErrorCode.kdcErrBadoption, "validate: the ticket is not invalid")
            }
            if notYetValid { throw KDCError.krb(KerberosErrorCode.krbApErrTktNyv, "validate: start time not reached") }
        } else if tgt.flags.invalid || notYetValid {
            throw KDCError.krb(KerberosErrorCode.krbApErrTktNyv, "ticket not yet valid")
        }
        if options.renew {
            guard tgt.flags.renewable, let renewTill = tgt.renewTill else {
                throw KDCError.krb(KerberosErrorCode.kdcErrBadoption, "renew: the ticket is not renewable")
            }
            guard renewTill >= now else {
                throw KDCError.krb(KerberosErrorCode.krbApErrTktExpired, "renew: renew-till \(renewTill.generalizedTimeString) passed")
            }
        }

        // The authenticator, with the ticket session key (usage 7).
        guard let sessionType = EncryptionType(rawValue: tgt.key.keytype),
              let tgtSessionKey = try? KerberosKey(type: sessionType, bytes: tgt.key.keyvalue) else {
            throw KDCError.krb(KerberosErrorCode.kdcErrEtypeNosupp, "TGT session key type \(tgt.key.keytype)")
        }
        let authenticator = try decode {
            try Authenticator(derBytes: try KerberosCrypto.decrypt(apReq.authenticator.cipher, key: tgtSessionKey,
                                                                   usage: KeyUsage.tgsReqAuthenticatorSessionKey))
        }
        // The authenticator's crealm may spell the realm as an alias (`LABSHEEP`) of the TGT's.
        let sameRealm = authenticator.crealm.caseInsensitiveCompare(tgt.crealm) == .orderedSame
            || (isOurRealm(authenticator.crealm) && isOurRealm(tgt.crealm))
        guard sameRealm, authenticator.cname.matchesIgnoringCase(tgt.cname) else {
            throw KDCError.krb(KerberosErrorCode.krbApErrBadmatch, "authenticator is for \(authenticator.cname)@\(authenticator.crealm)")
        }
        let skew = abs(authenticator.ctime.secondsSince1970 - now.secondsSince1970)
        guard skew <= KDCPolicy.maxSkew else {
            throw KDCError.krb(KerberosErrorCode.krbApErrSkew, "authenticator clock is \(skew) s off")
        }
        if let cksum = authenticator.cksum {
            try verifyReqBodyChecksum(cksum, reqBody: body.rawDER ?? body.encode(), sessionKey: tgtSessionKey)
        }

        // The client must still be allowed to log on.
        if let client = try await lookupClient(tgt.cname, realm: tgt.crealm) {
            try checkAccountState(client, now: now)
        }

        // 2. The service (for renew/validate: the ticket's own server).
        let sname: PrincipalName
        let service: Principal
        if renewOrValidate {
            (sname, service) = (tkt.sname, ticketServer)
        } else {
            guard isOurRealm(body.realm) else {
                throw KDCError.krb(KerberosErrorCode.kdcErrWrongRealm, "no referrals: realm \(body.realm)")
            }
            guard let s = body.sname, let p = try await store.principal(lookupName(s), realm: realm) else {
                throw KDCError.krb(KerberosErrorCode.kdcErrSPrincipalUnknown, "unknown service \(body.sname?.description ?? "-")")
            }
            // With `canonicalize` a krbtgt is returned as krbtgt/REALM (MS-KILE §3.3.5.6.1,
            // RFC 6806 §5), as in the AS exchange; so is one asked for under a realm alias
            // (`krbtgt/LABSHEEP`, or any krbtgt in req-body realm `LABSHEEP`, WP-AL). Other
            // services are echoed (see wp-j.md); the ticket realm is always the canonical one.
            let aliasRequest = isRealmAlias(body.realm) || isAliasKrbtgt(s)
            (sname, service) = ((options.canonicalize || aliasRequest) && p.kind == .krbtgt ? .krbtgt(realm: realm) : s, p)
        }
        guard service.enabled else {
            throw KDCError.krb(KerberosErrorCode.kdcErrServiceRevoked, "service \(service.displayName) is disabled")
        }
        let serviceKey: KerberosKey
        let newSessionType: EncryptionType
        if renewOrValidate {
            // Same ticket enctype and session key type as the ticket being renewed.
            (serviceKey, newSessionType) = (tgtKey, sessionType)
        } else {
            let offered = body.etype.compactMap(EncryptionType.init(rawValue:))
            guard let serviceType = KDCPolicy.enctypePreference.first(where: { offered.contains($0) && service.key($0) != nil })
                    ?? service.enctypes.first,
                  let k = service.key(serviceType) else {
                throw KDCError.krb(KerberosErrorCode.kdcErrEtypeNosupp, "service \(service.displayName) has no usable key")
            }
            serviceKey = k
            newSessionType = offered.contains(serviceType) ? serviceType
                : (KDCPolicy.enctypePreference.first { offered.contains($0) } ?? serviceType)
        }
        let sessionKey = KerberosCrypto.randomKey(newSessionType, rng: rng)

        // 3. Flags and times.
        var flags = TicketFlags()
        var starttime = now
        var endtime: KerberosTime
        var renewTill: KerberosTime?
        if renewOrValidate {
            flags = tgt.flags
            flags.invalid = false
            renewTill = tgt.renewTill
            if options.renew, let till = tgt.renewTill {
                // RFC 4120 §3.3.3: same lifetime as before, from now, capped by renew-till.
                let life = tgt.endtime.secondsSince1970 - (tgt.starttime ?? tgt.authtime).secondsSince1970
                endtime = min(till, now.adding(seconds: max(0, life)))
            } else {
                endtime = tgt.endtime
                starttime = max(now, tgt.starttime ?? now)
            }
        } else {
            let changePassword = service.isChangePasswordService
            flags.forwardable = options.forwardable && tgt.flags.forwardable && !changePassword
            flags.proxiable = options.proxiable && tgt.flags.proxiable && !changePassword
            flags.renewable = options.renewable && tgt.flags.renewable && !changePassword
            flags.preAuthent = tgt.flags.preAuthent
            endtime = min(tgt.endtime, now.adding(seconds: changePassword ? KDCPolicy.changePasswordTicketLifetime
                                                                           : KDCPolicy.maxTicketLifetime))
            if body.till.secondsSince1970 > 0, body.till < endtime { endtime = body.till }
            if flags.renewable, let tgtRenew = tgt.renewTill {
                var limit = tgtRenew
                if let rtime = body.rtime, rtime.secondsSince1970 > 0, rtime < limit { limit = rtime }
                renewTill = max(limit, endtime)
            }
        }
        guard endtime > now else {
            throw KDCError.krb(KerberosErrorCode.kdcErrNeverValid, "requested end time is in the past")
        }

        // Re-sign the PAC of the presented ticket (after checking it was signed by us).
        var builder: PACBuilder?
        if let pacBytes = try decode({ try tgt.authorizationData.findPAC() }) {
            do {
                let parsed = try PACParser.parse(pacBytes)
                try PACParser.verify(parsed, serverVerifier: KeySetPACVerifier(keys: ticketServer.keys),
                                     kdcVerifier: KeySetPACVerifier(keys: krbtgt.keys))
                if parsed.fullChecksum != nil {
                    try PACParser.verifyFullSignature(parsed, kdcVerifier: KeySetPACVerifier(keys: krbtgt.keys))
                }
                builder = PACBuilder(resigning: parsed)
            } catch {
                throw KDCError.krb(KerberosErrorCode.krbApErrModified, "ticket PAC: \(error)")
            }
        }

        var encTicket = EncTicketPart(
            flags: flags, key: EncryptionKey(keytype: sessionKey.type.rawValue, keyvalue: sessionKey.bytes),
            crealm: tgt.crealm, cname: tgt.cname, transited: tgt.transited, authtime: tgt.authtime,
            starttime: starttime, endtime: endtime, renewTill: renewTill, caddr: tgt.caddr)
        // Renew/validate echo the ticket's realm, unless it is an alias (the outer realm of a
        // ticket is not encrypted; ours never carry one).
        let ticketRealm = renewOrValidate && !isRealmAlias(tkt.realm) ? tkt.realm : realm
        let ticket = try sealTicket(&encTicket, realm: ticketRealm, sname: sname, server: service, serverKey: serviceKey,
                                    kdcKey: service.kind == .krbtgt ? serviceKey : kdcKey, pac: builder)

        // encrypted-pa-data: the service's msDS-SupportedEncryptionTypes when it has one
        // (MS-KILE §3.3.5.7), and PA-PAC-OPTIONS.
        var encPAData: [PAData] = []
        if let supported = service.supportedEncryptionTypes { encPAData.append(SupportedEnctypes.paData(supported)) }
        if let echo = pacOptionsEcho(req.padata) { encPAData.append(echo) }

        // 4. EncTGSRepPart: authenticator subkey (usage 9) if present, else TGT session key (usage 8).
        let replyKey: KerberosKey
        let usage: Int32
        if let subkey = authenticator.subkey {
            guard let t = EncryptionType(rawValue: subkey.keytype), let k = try? KerberosKey(type: t, bytes: subkey.keyvalue) else {
                throw KDCError.krb(KerberosErrorCode.kdcErrEtypeNosupp, "authenticator subkey type \(subkey.keytype)")
            }
            (replyKey, usage) = (k, KeyUsage.tgsRepEncPartSubkey)
        } else {
            (replyKey, usage) = (tgtSessionKey, KeyUsage.tgsRepEncPartSessionKey)
        }
        let encPart = EncKDCRepPart(
            key: encTicket.key, lastReq: [LastReqEntry(lrType: LastReqType.none, lrValue: now)],
            nonce: body.nonce, flags: flags, authtime: tgt.authtime, starttime: starttime, endtime: endtime,
            renewTill: renewTill, srealm: ticketRealm, sname: sname, encryptedPAData: encPAData)
        let cipher = try KerberosCrypto.encrypt(EncTGSRepPart(encPart).encode(), key: replyKey, usage: usage, rng: rng)
        let rep = TGSRep(crealm: tgt.crealm, cname: tgt.cname, ticket: ticket,
                         encPart: EncryptedData(etype: replyKey.type.rawValue, cipher: cipher))

        record.server = sname.description + (options.renew ? " (renew)" : options.validate ? " (validate)" : "")
        record.etype = serviceKey.type.rawValue
        record.lifetime = endtime.secondsSince1970 - now.secondsSince1970
        return rep.encode()
    }
}
