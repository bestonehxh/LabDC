import Foundation
import KerberosASN1
import KerberosCrypto
import MSPAC
import SheepCrypto
import Synchronization
import os

// MARK: - Security context

/// An established Kerberos GSS context (RFC 4121), acceptor or initiator side.
///
/// Token format follows the context key: RFC 4121 CFX tokens (`05 04` / `04 04`) for AES,
/// RFC 4757 §7 tokens (`02 01` / `01 01`) for RC4. Our tokens use the acceptor subkey when
/// there is one (and then set the AcceptorSubkey flag), otherwise the initiator subkey,
/// otherwise the ticket session key.
public final class KerberosSecurityContext: GSSSecurityContext {
    public let mechanism: GSSMechanism
    public let flags: GSSContextFlags
    public let isInitiator: Bool
    /// Ticket session key.
    public let sessionKey: KerberosKey
    /// Authenticator subkey.
    public let initiatorSubkey: KerberosKey?
    /// EncAPRepPart subkey (sent only for CFX enctypes, like MIT).
    public let acceptorSubkey: KerberosKey?
    let rng: RandomBytes
    private let seq: Mutex<(send: UInt64, recv: UInt64)>

    public init(mechanism: GSSMechanism, flags: GSSContextFlags, isInitiator: Bool, sessionKey: KerberosKey,
                initiatorSubkey: KerberosKey?, acceptorSubkey: KerberosKey?, sendSeq: UInt64, recvSeq: UInt64,
                rng: RandomBytes = RandomBytes()) {
        self.mechanism = mechanism
        self.flags = flags
        self.isInitiator = isInitiator
        self.sessionKey = sessionKey
        self.initiatorSubkey = initiatorSubkey
        self.acceptorSubkey = acceptorSubkey
        self.rng = rng
        self.seq = Mutex((send: sendSeq, recv: recvSeq))
    }

    /// The key our tokens are protected with.
    public var tokenKey: KerberosKey { acceptorSubkey ?? initiatorSubkey ?? sessionKey }
    /// RFC 4121 CFX tokens (everything but RC4).
    public var usesCFX: Bool { tokenKey.type != .rc4Hmac }
    /// Next sequence numbers (for tests and diagnostics).
    public var sequenceNumbers: (send: UInt64, recv: UInt64) { seq.withLock { ($0.send, $0.recv) } }

    /// Re-bases both per-message sequence counters (WP-AI). A `GSS_C_DCE_STYLE` RPC context is
    /// built with base 0 both ways (what impacket, whose Authenticator seq-number is 0, uses); once
    /// the third leg is in, the RPC layer re-bases it to RFC 4121's values — send from the
    /// acceptor's AP-REP seq-number, receive from the initiator's Authenticator seq-number — which is
    /// what Windows uses: its SPNEGO mechListMIC on the alter_context leg carries its Authenticator
    /// seq-number, and it sets GSS_C_SEQUENCE_FLAG, so the numbers must match exactly.
    public func resetSequenceNumbers(send: UInt64, recv: UInt64) {
        seq.withLock { $0 = (send: send, recv: recv) }
    }

    var sendsFromAcceptor: Bool { !isInitiator }

    func cfxKey(_ acceptorFlag: Bool) throws -> KerberosKey {
        if acceptorFlag {
            guard let acceptorSubkey else {
                throw AuthKitError.integrityCheckFailed("token claims an acceptor subkey that was never sent")
            }
            return acceptorSubkey
        }
        return initiatorSubkey ?? sessionKey
    }

    func nextSend() -> UInt64 {
        seq.withLock { s in
            let v = s.send
            s.send = usesCFX ? s.send &+ 1 : UInt64(UInt32(truncatingIfNeeded: s.send &+ 1))
            return v
        }
    }

    /// Replay / order check (RFC 2743 §1.2.3), driven by the flags the peer asked for:
    /// - GSS_C_SEQUENCE_FLAG: exactly the next expected number;
    /// - GSS_C_REPLAY_FLAG only: the expected number or a later one (older ones are replays);
    /// - neither: no check at all. Windows' SMB client asks for neither (GSS checksum flags
    ///   0x22, mutual | integrity) and sends its SPNEGO mechListMIC with SND_SEQ 0, not the
    ///   seq-number of its Authenticator (docs/notes/wp-aa.md); Heimdal and MIT skip the check
    ///   for such contexts too.
    func checkRecv(_ got: UInt64) throws {
        let next = usesCFX ? got &+ 1 : UInt64(UInt32(truncatingIfNeeded: got &+ 1))
        try seq.withLock { s in
            guard flags.contains(.sequence) || flags.contains(.replay) else {
                if got >= s.recv { s.recv = next }
                return
            }
            if got != s.recv, got < s.recv || flags.contains(.sequence) {
                throw AuthKitError.sequenceError(expected: s.recv, got: got)
            }
            s.recv = next
        }
    }

    public func wrap(_ message: [UInt8], confidential: Bool) throws -> [UInt8] {
        let n = nextSend()
        if usesCFX {
            return try CFXToken.wrap(message, key: tokenKey, confidential: confidential, fromAcceptor: sendsFromAcceptor,
                                     acceptorSubkey: acceptorSubkey != nil, seq: n, rng: rng)
        }
        return RC4GSSToken.wrap(message, key: tokenKey, confidential: confidential, fromAcceptor: sendsFromAcceptor,
                                seq: UInt32(truncatingIfNeeded: n), rng: rng)
    }

    public func unwrap(_ token: [UInt8]) throws -> (message: [UInt8], confidential: Bool) {
        if usesCFX {
            let u = try CFXToken.unwrap(token, fromAcceptor: !sendsFromAcceptor, keyFor: cfxKey)
            try checkRecv(u.seq)
            return (u.message, u.confidential)
        }
        let u = try RC4GSSToken.unwrap(token, key: tokenKey, fromAcceptor: !sendsFromAcceptor)
        try checkRecv(UInt64(u.seq))
        return (u.message, u.confidential)
    }

    public func getMIC(_ message: [UInt8]) throws -> [UInt8] {
        let n = nextSend()
        if usesCFX {
            return try CFXToken.getMIC(message, key: tokenKey, fromAcceptor: sendsFromAcceptor,
                                       acceptorSubkey: acceptorSubkey != nil, seq: n)
        }
        return RC4GSSToken.getMIC(message, key: tokenKey, fromAcceptor: sendsFromAcceptor, seq: UInt32(truncatingIfNeeded: n))
    }

    public func verifyMIC(_ message: [UInt8], token: [UInt8]) throws {
        if usesCFX {
            try checkRecv(try CFXToken.verifyMIC(message, token: token, fromAcceptor: !sendsFromAcceptor, keyFor: cfxKey))
        } else {
            try checkRecv(UInt64(try RC4GSSToken.verifyMIC(message, token: token, key: tokenKey, fromAcceptor: !sendsFromAcceptor)))
        }
    }
}

// MARK: - Replay cache

/// In-memory authenticator replay cache (RFC 4120 §3.2.3): remembers (client, server, ctime,
/// cusec) for the clock-skew window on each side.
public final class ReplayCache: Sendable {
    private let entries = Mutex<[String: Date]>([:])
    public let window: TimeInterval

    public init(window: TimeInterval = 300) { self.window = window }

    /// Returns `false` when `key` was seen within the window; records it otherwise.
    public func insert(_ key: String, now: Date) -> Bool {
        entries.withLock { e in
            if e.count > 1024 { e = e.filter { now.timeIntervalSince($0.value) <= 2 * window } }
            if let seen = e[key], now.timeIntervalSince(seen) <= 2 * window { return false }
            e[key] = now
            return true
        }
    }

    public var count: Int { entries.withLock { $0.count } }
}

// MARK: - Acceptor

/// What `KerberosAcceptor.accept` produces.
public struct KerberosAcceptResult: Sendable {
    /// AP-REP token to send back (framed like the request), `nil` without mutual authentication.
    public var outputToken: [UInt8]?
    public var identity: AuthenticatedIdentity
    public var context: KerberosSecurityContext
    /// `alice@LAB.SHEEP`.
    public var clientPrincipal: String
    /// `ldap/dc1.lab.sheep`.
    public var servicePrincipal: String
    /// The client's GSS flags (RFC 4121 §4.1.1.1), empty for a non-GSS AP-REQ.
    public var requestedFlags: GSSContextFlags
    /// The ticket's authtime / endtime.
    public var authtime: Date
    public var endtime: Date
    /// DCE-style (three-leg) only: the ticket session key, needed to validate the client's
    /// third-leg AP-REP, and the acceptor's AP-REP sequence number (echoed by the client).
    public var dceTicketSessionKey: KerberosKey? = nil
    public var dceAcceptorSeq: UInt32? = nil
    /// DCE-style only: the acceptor's AP-REP as a bare DER `[APPLICATION 15]` (no GSS/TOK_ID
    /// framing), which is what a SPNEGO `NegTokenResp.responseToken` carries for RPC.
    public var dceBareAPRep: [UInt8]? = nil
    /// DCE-style only (WP-AI): the initiator's Authenticator seq-number — the base of the sequence
    /// numbers the initiator sends (its SPNEGO mechListMIC and every protected request).
    public var dceInitiatorSeq: UInt32? = nil
}

/// Kerberos GSS acceptor (RFC 4121 §4.1 + MS-KILE quirks).
///
/// Accepts the initial context token `60 … 06 09 2a864886f712010202 01 00 <AP-REQ>` (either
/// Kerberos OID; the MS one is echoed back) or a bare AP-REQ (answered with a bare AP-REP).
/// Validates the ticket with `serviceKeys(forSPN:)`, the authenticator (realm/name match,
/// skew, replay), the PAC server signature and PAC_CLIENT_INFO, then answers with an AP-REP
/// carrying an acceptor subkey (CFX enctypes) and our initial sequence number.
public struct KerberosAcceptor: Sendable {
    public let source: any AuthSecretSource
    public let replayCache: ReplayCache
    public let clock: @Sendable () -> Date
    public let rng: RandomBytes
    public let maxSkew: TimeInterval
    /// Require a PAC in the ticket (a DC always issues one; phase 1 keeps it on).
    public var requirePAC: Bool
    /// Extended Protection (EPA): the `Bnd` field of the GSS checksum on a TLS connection.
    public var channelBinding: ChannelBindingCheck = .none

    static let logger = Logger(subsystem: "dev.labdc.app", category: "AuthKit")

    public init(source: any AuthSecretSource, replayCache: ReplayCache = ReplayCache(),
                clock: @escaping @Sendable () -> Date = { Date() }, rng: RandomBytes = RandomBytes(),
                maxSkew: TimeInterval = 300, requirePAC: Bool = true) {
        self.source = source
        self.replayCache = replayCache
        self.clock = clock
        self.rng = rng
        self.maxSkew = maxSkew
        self.requirePAC = requirePAC
    }

    /// GSS checksum type 0x8003 (RFC 4121 §4.1.1).
    public static let gssChecksumType: Int32 = 0x8003

    /// Accepts an initial context token.
    ///
    /// - Parameter dceStyle: when `true`, a `GSS_C_DCE_STYLE` AP-REQ is accepted (MS-KILE §3.4.5):
    ///   the acceptor still answers with an AP-REP (mutual is implied), but the handshake is not yet
    ///   complete — the client sends its own AP-REP as a third leg, which the RPC layer feeds to
    ///   `completeDCEStyle`. The returned result carries `dceTicketSessionKey`/`dceAcceptorSeq` for
    ///   that step, its context uses sequence base 0 both ways (impacket/Windows reset the per-PDU
    ///   sequence to 0 after the handshake), and its per-message tokens are the RPC IOV tokens
    ///   (`KerberosSecurityContext.sealRPC`/`unsealRPC`). When `false`, a DCE-style token is refused,
    ///   preserving the LDAP/SASL behaviour.
    public func accept(_ token: [UInt8], dceStyle: Bool = false) async throws -> KerberosAcceptResult {
        // 1. Framing.
        let mech: GSSMechanism
        let framed: Bool
        let apReqBytes: [UInt8]
        if token.first == 0x60 {
            let (m, inner) = try GSSFraming.unwrap(token)
            guard m.isKerberos else { throw AuthKitError.unsupported("mechanism \(m) in a Kerberos token") }
            guard inner.count > 2 else { throw AuthKitError.malformed(what: "GSS Kerberos token", reason: "empty") }
            switch (inner[0], inner[1]) {
            case (0x01, 0x00): break
            case (0x03, 0x00): throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMsgType, reason: "peer sent KRB-ERROR")
            default: throw AuthKitError.malformed(what: "GSS Kerberos token", reason: "TOK_ID \(inner[0]) \(inner[1]) is not AP-REQ")
            }
            mech = m
            framed = true
            apReqBytes = Array(inner[2...])
        } else if token.first == 0x6E {
            mech = .kerberos
            framed = false
            apReqBytes = token
        } else {
            throw AuthKitError.malformed(what: "Kerberos token", reason: "neither GSS framing nor AP-REQ")
        }
        let apReq: APReq
        do { apReq = try APReq(derBytes: apReqBytes) } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMsgType, reason: "AP-REQ: \(error)")
        }
        if apReq.apOptions.useSessionKey {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMethod, reason: "user-to-user is not supported")
        }

        // 2. Ticket.
        let ticket = apReq.ticket
        let spn = ticket.sname.nameString.joined(separator: "/")
        guard ticket.realm.caseInsensitiveCompare(source.realm) == .orderedSame else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrNotUs, reason: "ticket realm \(ticket.realm)")
        }
        let keys = await source.serviceKeys(forSPN: spn)
        guard !keys.isEmpty else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrNotUs, reason: "unknown service \(spn)")
        }
        guard let serviceKey = keys.first(where: { $0.type.rawValue == ticket.encPart.etype }) else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrNokey, reason: "no \(ticket.encPart.etype) key for \(spn)")
        }
        let encTicket: EncTicketPart
        do {
            encTicket = try EncTicketPart(derBytes: try KerberosCrypto.decrypt(ticket.encPart.cipher, key: serviceKey,
                                                                               usage: KeyUsage.kdcRepTicket))
        } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrBadIntegrity, reason: "ticket does not decrypt")
        }
        guard let skType = EncryptionType(rawValue: encTicket.key.keytype),
              let sessionKey = try? KerberosKey(type: skType, bytes: encTicket.key.keyvalue) else {
            throw AuthKitError.unsupported("session key type \(encTicket.key.keytype)")
        }

        // 3. Authenticator.
        guard apReq.authenticator.etype == encTicket.key.keytype else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrBadIntegrity, reason: "authenticator etype")
        }
        let auth: Authenticator
        do {
            auth = try Authenticator(derBytes: try KerberosCrypto.decrypt(apReq.authenticator.cipher, key: sessionKey,
                                                                          usage: KeyUsage.apReqAuthenticator))
        } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrBadIntegrity, reason: "authenticator does not decrypt")
        }
        guard auth.crealm == encTicket.crealm, auth.cname.nameString == encTicket.cname.nameString else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrBadmatch, reason: "authenticator names another client")
        }
        let now = clock()
        let nowSec = Int64(now.timeIntervalSince1970.rounded(.down))
        let skew = Int64(maxSkew)
        guard abs(auth.ctime.secondsSince1970 - nowSec) <= skew else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrSkew, reason: "authenticator time outside ±\(skew) s")
        }
        let start = encTicket.starttime ?? encTicket.authtime
        if encTicket.flags.invalid || start.secondsSince1970 - skew > nowSec {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrTktNyv, reason: "ticket not yet valid")
        }
        guard encTicket.endtime.secondsSince1970 + skew >= nowSec else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrTktExpired, reason: "ticket expired")
        }
        let client = auth.cname.nameString.joined(separator: "/") + "@" + auth.crealm
        let replayKey = "\(client)|\(spn)|\(auth.ctime.secondsSince1970)|\(auth.cusec)"
        guard replayCache.insert(replayKey, now: now) else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrRepeat, reason: "authenticator replay")
        }

        // 4. GSS checksum (RFC 4121 §4.1.1): Lgth (4 LE) = 16, Bnd (16), Flags (4 LE), [deleg].
        //    Bnd is the channel binding hash (EPA); the authenticator is encrypted with the
        //    session key, so a relay cannot change it. With GSS_C_DELEG_FLAG the client appends
        //    DlgOpt (2 LE) = 1, Dlgth (2 LE) and Deleg (a KRB-CRED with its forwarded TGT): Windows
        //    does so for services whose ticket is OK-AS-DELEGATE (CES over Kerberos, 2 Oct 2026).
        //    LabDC never acts as the client, so the credential is only bounds-checked and
        //    dropped; anything after it (RFC 4121 Exts) is ignored.
        var requested: GSSContextFlags = []
        var bindings: [UInt8]?
        if let ck = auth.cksum, ck.cksumtype == Self.gssChecksumType {
            let c = ck.checksum
            guard c.count >= 24, c.le32(0) == 16 else {
                throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrInappCksum, reason: "bad GSS checksum")
            }
            requested = GSSContextFlags(rawValue: c.le32(20))
            bindings = Array(c[4..<20])
            if requested.contains(.delegate), c.count > 24 {
                guard c.count >= 28, c.le16(24) == 1, 28 + Int(c.le16(26)) <= c.count else {
                    throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrInappCksum, reason: "bad GSS delegation field")
                }
            }
        }
        try channelBinding.verify(bindings, mechanism: "Kerberos")
        if apReq.apOptions.mutualRequired { requested.insert(.mutual) }
        let isDCE = requested.contains(.dceStyle)
        if isDCE && !dceStyle {
            throw AuthKitError.unsupported("DCE-style (three-leg) Kerberos")
        }
        // DCE-style implies mutual authentication (the acceptor's AP-REP is always sent).
        if isDCE { requested.insert(.mutual) }

        // 5. PAC -> identity.
        let identity: AuthenticatedIdentity
        let pacBytes: [UInt8]?
        do { pacBytes = try encTicket.authorizationData.findPAC() } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "authorization-data: \(error)")
        }
        if let pacBytes {
            let pac: ParsedPAC
            do { pac = try PACParser.parse(pacBytes) } catch {
                throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "PAC: \(error)")
            }
            do {
                try PACParser.verifyServerSignature(pac, verifier: KeyPACVerifier(key: serviceKey))
            } catch {
                throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "PAC server signature")
            }
            if let ci = pac.clientInfo {
                guard ci.name.caseInsensitiveCompare(encTicket.cname.nameString.first ?? "") == .orderedSame
                        || ci.name.caseInsensitiveCompare(encTicket.cname.nameString.joined(separator: "/")) == .orderedSame,
                      ci.clientId == FileTime(encTicket.authtime.date) else {
                    throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "PAC_CLIENT_INFO does not match the ticket")
                }
            }
            var id = source.identity(fromPAC: pac)
            id.principal = client
            identity = id
        } else {
            guard !requirePAC, let sam = encTicket.cname.nameString.first,
                  var id = await source.identity(forSAM: sam) else {
                throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "ticket has no PAC")
            }
            id.principal = client
            identity = id
        }

        // 6. Keys, sequence numbers, AP-REP.
        var initiatorSubkey: KerberosKey?
        if let sk = auth.subkey {
            guard let t = EncryptionType(rawValue: sk.keytype), let k = try? KerberosKey(type: t, bytes: sk.keyvalue) else {
                throw AuthKitError.unsupported("authenticator subkey type \(sk.keytype)")
            }
            initiatorSubkey = k
        }
        let baseKey = initiatorSubkey ?? sessionKey
        // DCE-style resets the per-PDU sequence to 0 on both directions after the handshake
        // (impacket `rpcrt` sets `self.__sequence = 0`; Windows RPC does the same). Otherwise the
        // context follows the authenticator's seq-number (RFC 4121).
        let recvSeq: UInt64 = isDCE ? 0 : UInt64(auth.seqNumber ?? 0)
        var acceptorSubkey: KerberosKey?
        var sendSeq = recvSeq
        var output: [UInt8]?
        var dceSeq: UInt32?
        var bareAPRep: [UInt8]?
        if requested.contains(.mutual) {
            if baseKey.type != .rc4Hmac { acceptorSubkey = KerberosCrypto.randomKey(baseKey.type, rng: rng) }
            let ourSeq = rng.next(4).be32(0) & 0x3FFF_FFFF
            // The AP-REP carries our chosen seq (echoed in the client's third-leg AP-REP), but the
            // per-message context resets to 0 in DCE style.
            sendSeq = isDCE ? 0 : UInt64(ourSeq)
            dceSeq = ourSeq
            let part = EncAPRepPart(ctime: auth.ctime, cusec: auth.cusec,
                                    subkey: acceptorSubkey.map { EncryptionKey(keytype: $0.type.rawValue, keyvalue: $0.bytes) },
                                    seqNumber: ourSeq)
            let cipher = try KerberosCrypto.encrypt(part.encode(), key: sessionKey, usage: KeyUsage.apRepEncPart, rng: rng)
            let apRep = APRep(encPart: EncryptedData(etype: sessionKey.type.rawValue, cipher: cipher)).encode()
            output = framed ? GSSFraming.wrap(mech: mech, [0x02, 0x00] + apRep) : apRep
            bareAPRep = apRep
        }
        let context = KerberosSecurityContext(
            mechanism: mech, flags: requested, isInitiator: false, sessionKey: sessionKey,
            initiatorSubkey: initiatorSubkey, acceptorSubkey: acceptorSubkey, sendSeq: sendSeq, recvSeq: recvSeq, rng: rng)
        Self.logger.info("Kerberos: accepted \(client, privacy: .public) for \(spn, privacy: .public) etype \(baseKey.type.rawValue) dce \(isDCE, privacy: .public)")
        return KerberosAcceptResult(outputToken: output, identity: identity, context: context, clientPrincipal: client,
                                    servicePrincipal: spn, requestedFlags: requested, authtime: encTicket.authtime.date,
                                    endtime: encTicket.endtime.date,
                                    dceTicketSessionKey: isDCE ? sessionKey : nil,
                                    dceAcceptorSeq: isDCE ? dceSeq : nil,
                                    dceBareAPRep: isDCE ? bareAPRep : nil,
                                    dceInitiatorSeq: isDCE ? (auth.seqNumber ?? 0) : nil)
    }

    /// Validates the client's third leg of a `GSS_C_DCE_STYLE` exchange (MS-KILE §3.4.5): the client
    /// answers the acceptor's AP-REP with its own AP-REP, encrypted with the ticket session key
    /// (key usage 12). We decrypt it with `result.dceTicketSessionKey` and check its `seq-number`
    /// echoes the sequence number the acceptor put in its AP-REP (`result.dceAcceptorSeq`). The
    /// client sends a fresh `ctime`/`cusec`, so those are not matched (impacket rewrites them). On
    /// success the `result.context` established by `accept(_:dceStyle:)` is live for per-PDU tokens.
    public func completeDCEStyle(_ result: KerberosAcceptResult, clientAPRep token: [UInt8]) throws {
        guard let sessionKey = result.dceTicketSessionKey else {
            throw AuthKitError.unsupported("completeDCEStyle called on a non-DCE result")
        }
        var bytes = token
        if token.first == 0x60 {
            let (_, inner) = try GSSFraming.unwrap(token)
            guard inner.count > 2, inner[0] == 0x02, inner[1] == 0x00 else {
                throw AuthKitError.malformed(what: "DCE AP-REP token", reason: "TOK_ID is not 02 00")
            }
            bytes = Array(inner[2...])
        }
        let apRep: APRep
        do { apRep = try APRep(derBytes: bytes) }
        catch { throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMsgType, reason: "third-leg AP-REP: \(error)") }
        let part: EncAPRepPart
        do {
            part = try EncAPRepPart(derBytes: try KerberosCrypto.decrypt(apRep.encPart.cipher, key: sessionKey,
                                                                         usage: KeyUsage.apRepEncPart))
        } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified, reason: "third-leg AP-REP does not decrypt")
        }
        if let expected = result.dceAcceptorSeq, let got = part.seqNumber, got != expected {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrModified,
                                        reason: "third-leg AP-REP seq \(got) != \(expected)")
        }
    }

    /// A KRB-ERROR for a failed `accept`, framed as a GSS error token (`03 00`) when `framed`.
    /// Returns `nil` for errors that have no Kerberos code.
    public func errorToken(for error: AuthKitError, framed: Bool = true, mech: GSSMechanism = .kerberos) -> [UInt8]? {
        let code: Int32
        switch error {
        case .kerberos(let c, _): code = c
        case .malformed: code = KerberosErrorCode.krbApErrMsgType
        default: return nil
        }
        let err = KRBError(stime: KerberosTime(clock()), errorCode: code, realm: source.realm,
                           sname: PrincipalName(nameType: NameType.srvInst, nameString: ["host", source.dcDNSName])).encode()
        return framed ? GSSFraming.wrap(mech: mech, [0x03, 0x00] + err) : err
    }
}

/// PAC server-signature verifier with one service key.
struct KeyPACVerifier: PACVerifier {
    let key: KerberosKey
    func verify(_ data: [UInt8], usage: Int32, type: Int32, signature: [UInt8]) throws -> Bool {
        guard let ctype = ChecksumType(rawValue: type), ctype.keyType == key.type else { return false }
        return try KerberosCrypto.verifyChecksum(ctype, data: data, key: key, usage: usage, expected: signature)
    }
}

// MARK: - Initiator (tests, tools)

/// A minimal Kerberos GSS initiator: builds the AP-REQ context token from a service ticket and
/// completes the context from the AP-REP. Used by tests and by tools that talk to ourselves.
public struct KerberosInitiator: Sendable {
    public let mech: GSSMechanism
    public let sessionKey: KerberosKey
    public let subkey: KerberosKey?
    public let flags: GSSContextFlags
    public let seq: UInt32
    public let ctime: KerberosTime
    public let cusec: Int32
    public let rng: RandomBytes
    /// The token to send.
    public let token: [UInt8]

    /// - Parameters: `ticket`/`sessionKey`/`client`/`realm` come from a TGS-REP.
    public init(ticket: Ticket, sessionKey: KerberosKey, client: PrincipalName, realm: String,
                flags: GSSContextFlags = [.mutual, .replay, .sequence, .confidentiality, .integrity],
                subkey: KerberosKey?, seq: UInt32, ctime: KerberosTime, cusec: Int32 = 0,
                mech: GSSMechanism = .kerberos, framed: Bool = true, rng: RandomBytes = RandomBytes(),
                channelBindingHash: [UInt8]? = nil, checksumTail: [UInt8] = []) throws {
        var ck: [UInt8] = []
        ck.appendLE32(16)
        ck += channelBindingHash ?? [UInt8](repeating: 0, count: 16)
        ck.appendLE32(flags.rawValue)
        // `checksumTail`: what follows Flags, e.g. the DlgOpt/Dlgth/Deleg field (tests).
        ck += checksumTail
        let auth = Authenticator(crealm: realm, cname: client,
                                 cksum: Checksum(cksumtype: KerberosAcceptor.gssChecksumType, checksum: ck),
                                 cusec: cusec, ctime: ctime,
                                 subkey: subkey.map { EncryptionKey(keytype: $0.type.rawValue, keyvalue: $0.bytes) },
                                 seqNumber: seq)
        let cipher = try KerberosCrypto.encrypt(auth.encode(), key: sessionKey, usage: KeyUsage.apReqAuthenticator, rng: rng)
        var options = APOptions()
        options.mutualRequired = flags.contains(.mutual)
        let apReq = APReq(apOptions: options, ticket: ticket,
                          authenticator: EncryptedData(etype: sessionKey.type.rawValue, cipher: cipher)).encode()
        self.token = framed ? GSSFraming.wrap(mech: mech, [0x01, 0x00] + apReq) : apReq
        self.mech = mech
        self.sessionKey = sessionKey
        self.subkey = subkey
        self.flags = flags
        self.seq = seq
        self.ctime = ctime
        self.cusec = cusec
        self.rng = rng
    }

    /// Completes the context. `apRepToken == nil` for a context without mutual authentication.
    public func complete(apRepToken: [UInt8]?) throws -> KerberosSecurityContext {
        guard let apRepToken else {
            return KerberosSecurityContext(mechanism: mech, flags: flags, isInitiator: true, sessionKey: sessionKey,
                                           initiatorSubkey: subkey, acceptorSubkey: nil, sendSeq: UInt64(seq),
                                           recvSeq: UInt64(seq), rng: rng)
        }
        var bytes = apRepToken
        if apRepToken.first == 0x60 {
            let (_, inner) = try GSSFraming.unwrap(apRepToken)
            guard inner.count > 2, inner[0] == 0x02, inner[1] == 0x00 else {
                throw AuthKitError.malformed(what: "AP-REP token", reason: "TOK_ID is not 02 00")
            }
            bytes = Array(inner[2...])
        }
        let apRep = try APRep(derBytes: bytes)
        let part: EncAPRepPart
        do {
            part = try EncAPRepPart(derBytes: try KerberosCrypto.decrypt(apRep.encPart.cipher, key: sessionKey,
                                                                        usage: KeyUsage.apRepEncPart))
        } catch let e as AuthKitError {
            throw e
        } catch {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMutFail, reason: "AP-REP does not decrypt")
        }
        guard part.ctime == ctime, part.cusec == cusec else {
            throw AuthKitError.kerberos(code: KerberosErrorCode.krbApErrMutFail, reason: "AP-REP ctime/cusec mismatch")
        }
        var acceptorSubkey: KerberosKey?
        if let sk = part.subkey, let t = EncryptionType(rawValue: sk.keytype) {
            acceptorSubkey = try KerberosKey(type: t, bytes: sk.keyvalue)
        }
        return KerberosSecurityContext(mechanism: mech, flags: flags, isInitiator: true, sessionKey: sessionKey,
                                       initiatorSubkey: subkey, acceptorSubkey: acceptorSubkey, sendSeq: UInt64(seq),
                                       recvSeq: UInt64(part.seqNumber ?? seq), rng: rng)
    }
}
