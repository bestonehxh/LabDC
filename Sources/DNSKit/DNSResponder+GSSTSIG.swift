import AuthKit
import Foundation
import MSPAC

// GSS-TSIG secure dynamic update (RFC 3645): the TKEY negotiation (RFC 2930 mode 3) that sets up
// a Kerberos GSS context with a member, TSIG (RFC 8945) verification and signing with that
// context's GetMIC, and who may change what with a signed update.

extension DNSResponder {
    enum Verification {
        case verified(DNSUpdateSigner, SignPlan)
        case refused(Outcome)
    }

    /// Wall clock for TSIG and TKEY.
    var wallClock: Date { secure?.clock() ?? Date() }

    // MARK: TSIG (RFC 8945 §5.2)

    /// Checks the TSIG of a received message: a known GSS-TSIG key (else BADKEY), a MIC that
    /// verifies over the message as received (else BADSIG), a time within ±300 s (else BADTIME,
    /// answered signed). BADKEY and BADSIG answers are unsigned (empty MAC).
    func verify(_ signed: DNSWireTSIG.Signed, request: DNSMessage, from: String) -> Verification {
        let now = wallClock
        let nowSec = UInt64(max(0, now.timeIntervalSince1970.rounded(.down)))
        let tsig = signed.tsig
        let keyName = signed.keyName
        func fail(_ error: DNSTSIGError, _ reason: String, context: (any GSSSecurityContext)? = nil,
                  otherData: [UInt8] = []) -> Verification {
            Self.logger.notice("TSIG from \(from, privacy: .public) key \(keyName, privacy: .public): \(error.label, privacy: .public) (\(reason, privacy: .public))")
            onEvent?("\(request.opcode == .update ? "UPDATE" : "TSIG") from \(from) refused: \(error.label), \(reason)")
            let plan = SignPlan(keyName: keyName, algorithm: tsig.algorithm, context: context,
                                priorMAC: context == nil ? nil : tsig.mac, timeSigned: tsig.timeSigned, error: error,
                                otherData: otherData)
            return .refused(Outcome(message: request.responseSkeleton(rcode: .notAuth), sign: plan))
        }
        guard secure != nil else { return fail(.badKey, "secure updates are not set up") }
        guard tsig.isGSS else { return fail(.badKey, "algorithm \(tsig.algorithm) is not gss-tsig") }
        guard let key = gssKeys.get(keyName, now: now), key.isEstablished, let context = key.context,
              let identity = key.identity else {
            return fail(.badKey, "no security context \(keyName) (expired or never negotiated)")
        }
        let digest = tsig.digest(message: signed.unsignedMessage, keyName: keyName, priorMAC: nil)
        do {
            try context.verifyMIC(digest, token: tsig.mac)
        } catch let error as AuthKitError {
            // The MIC verified but its sequence number is out of order (a retransmission or a
            // reordered UDP update): accepted, as BIND and Samba accept GSS_S_DUPLICATE_TOKEN /
            // GSS_S_GAP_TOKEN, which are supplementary statuses, not errors.
            guard case .sequenceError = error else { return fail(.badSig, "\(error)") }
        } catch {
            return fail(.badSig, "\(error)")
        }
        let skew = abs(Double(nowSec) - Double(tsig.timeSigned))
        if skew > Double(DNSTSIG.fudge) {
            var other: [UInt8] = []
            other.appendU48(nowSec)
            return fail(.badTime, "signed \(Int(skew)) s away from this server's clock (fudge \(DNSTSIG.fudge) s)",
                        context: context, otherData: other)
        }
        let plan = SignPlan(keyName: keyName, algorithm: tsig.algorithm, context: context, priorMAC: tsig.mac,
                            timeSigned: nowSec)
        return .verified(DNSUpdateSigner(identity: identity, keyName: keyName), plan)
    }

    // MARK: TKEY (RFC 2930, RFC 3645 §3.1)

    /// A SPNEGO initial token (`60 … 06 06 2b0601050502 …`).
    static func isSPNEGO(_ token: [UInt8]) -> Bool {
        guard token.first == 0x60, let (mech, _) = try? GSSFraming.unwrap(token) else { return false }
        return mech == .spnego
    }

    /// Answers a TKEY query: runs the client's GSS token (SPNEGO, a framed Kerberos AP-REQ or a
    /// bare one) through the acceptor and returns the output token in a TKEY answer. While the
    /// negotiation continues the context is kept as pending; once complete, the answer is signed
    /// with the new context (RFC 3645 §3.1.3) and the key name can sign updates.
    func tkey(_ request: DNSMessage, from: String) async -> Outcome {
        var response = request.responseSkeleton()
        let keyName = request.questions[0].name
        guard let secure, updateMode != .off else {
            Self.logger.info("TKEY \(keyName, privacy: .public) from \(from, privacy: .public): refused (\(self.secure == nil ? "secure updates are not set up" : "dynamic updates are off", privacy: .public))")
            response.rcode = .refused
            return Outcome(message: response)
        }
        guard let offered = (request.additional + request.answers).first(where: { $0.type == .tkey }),
              case .unknown(let raw) = offered.rdata, let offer = try? DNSTKEY(rdata: raw) else {
            response.rcode = .formErr
            return Outcome(message: response)
        }
        let now = secure.clock()
        let nowSec = UInt32(clamping: Int64(now.timeIntervalSince1970.rounded(.down)))
        func reply(_ error: DNSTSIGError, token: [UInt8] = [], until: Date? = nil) -> DNSMessage {
            var m = response
            let expiration = until.map { UInt32(clamping: Int64($0.timeIntervalSince1970.rounded(.down))) } ?? nowSec
            m.answers = [DNSTKEY(algorithm: offer.algorithm, inception: nowSec, expiration: expiration, mode: offer.mode,
                                 error: error.rawValue, keyData: token).record(keyName: keyName)]
            return m
        }
        func refuse(_ error: DNSTSIGError, _ reason: String) -> Outcome {
            gssKeys.remove(keyName)
            Self.logger.notice("TKEY \(keyName, privacy: .public) from \(from, privacy: .public): \(error.label, privacy: .public) (\(reason, privacy: .public))")
            onEvent?("TKEY from \(from) refused: \(error.label), \(reason)")
            return Outcome(message: reply(error))
        }
        guard offer.mode == DNSTKEY.modeGSSAPI else { return refuse(.badMode, "mode \(offer.mode) is not GSS-API (3)") }
        guard offer.algorithm == DNSTSIG.gssTSIG || offer.algorithm == DNSTSIG.gssMicrosoft else {
            return refuse(.badAlg, "algorithm \(offer.algorithm)")
        }
        let existing = gssKeys.get(keyName, now: now)
        if existing?.isEstablished == true {
            // RFC 3645 §3.1.2: a key name already in use.
            Self.logger.notice("TKEY \(keyName, privacy: .public) from \(from, privacy: .public): BADNAME (context exists)")
            return Outcome(message: reply(.badName))
        }
        let token = offer.keyData
        var acceptor = existing?.pending
        let step: SPNEGOAcceptor.Step
        do {
            if var a = acceptor {
                step = try await a.step(token)
                acceptor = a
            } else if Self.isSPNEGO(token) {
                var a = SPNEGOAcceptor(kerberos: secure.kerberos(), ntlm: nil)
                step = try await a.step(token)
                acceptor = a
            } else {
                // Raw Kerberos (`nsupdate -g` with the krb5 mechanism, Windows 2000's gss.microsoft.com).
                let r = try await secure.kerberos().accept(token)
                step = .complete(output: r.outputToken, identity: r.identity, context: r.context)
            }
        } catch {
            return refuse(.badKey, "\(error)")
        }
        switch step {
        case .continue(let out):
            let until = now.addingTimeInterval(secure.pendingLifetime)
            gssKeys.set(keyName, DNSGSSKey(algorithm: offer.algorithm, created: now, expires: until, pending: acceptor), now: now)
            return Outcome(message: reply(.noError, token: out, until: until))
        case let .complete(out, identity, context):
            guard let context, !identity.isAnonymous else { return refuse(.badKey, "anonymous logon") }
            let until = now.addingTimeInterval(secure.contextLifetime)
            gssKeys.set(keyName, DNSGSSKey(algorithm: offer.algorithm, created: now, expires: until,
                                           identity: identity, context: context), now: now)
            Self.logger.notice("TKEY \(keyName, privacy: .public) from \(from, privacy: .public): GSS-TSIG context for \(identity.description, privacy: .public)")
            return Outcome(message: reply(.noError, token: out ?? [], until: until),
                           sign: SignPlan(keyName: keyName, algorithm: offer.algorithm, context: context, priorMAC: nil,
                                          timeSigned: UInt64(nowSec)))
        }
    }

    // MARK: Authorization of signed updates

    private static func canonical(_ name: DNSName) -> DNSName { DNSName(labels: name.canonicalLabels) }

    /// Domain Admins (RID 512) or Enterprise Admins (519) in the PAC, or the directory's verdict
    /// (which also knows DnsAdmins and nested groups).
    func isDNSAdministrator(_ signer: DNSUpdateSigner) async -> Bool {
        let sid = signer.identity.sid
        if let directory = secure?.directory, await directory.isDNSAdministrator(accountSID: sid) { return true }
        guard sid.subAuthorities.count >= 2,
              let domain = try? SID(identifierAuthority: sid.identifierAuthority, subAuthorities: Array(sid.subAuthorities.dropLast()))
        else { return false }
        let admins = [512, 519].compactMap { try? domain.appending(rid: $0) }
        return signer.identity.groups.contains { admins.contains($0) }
    }

    /// The names a computer account registers: its `dNSHostName` and `<sAMAccountName without $>.<domain>`.
    func ownNames(of signer: DNSUpdateSigner, info: DNSDomainInfo) async -> Set<DNSName> {
        var out = Set<DNSName>()
        guard signer.isComputer else { return out }
        if let directory = secure?.directory, let host = await directory.dnsHostName(accountSID: signer.identity.sid),
           let name = try? DNSName(parsing: host), !name.isRoot {
            out.insert(Self.canonical(name))
        }
        let base = String(signer.accountName.dropLast()).lowercased()
        if let label = try? DNSName(parsing: base), label.labels.count == 1 {
            out.insert(Self.canonical(label.appending(info.dnsDomain)))
        }
        return out
    }

    /// Why a signed update is refused; nil when it may go ahead.
    ///
    /// - A computer account may add, replace and delete A/AAAA of its own names (`dNSHostName`,
    ///   the sAMAccountName-derived name) from any address — it takes over a name an unsigned
    ///   update registered by address — and the PTR records pointing at those names in a reverse zone.
    /// - Domain Admins, Enterprise Admins and DnsAdmins may change any name that is not reserved.
    /// - Reserved names (the DC, `_` names, the apex, wpad/isatap, generated records) never change.
    /// - A name the DHCP server registered (it holds a DHCID) may be replaced only by the computer
    ///   whose name it is.
    func secureUpdateRefusal(_ request: DNSMessage, zone: DNSName, info: DNSDomainInfo,
                             signer: DNSUpdateSigner) async -> String? {
        let admin = await isDNSAdministrator(signer)
        guard admin || signer.isComputer else {
            return "\(signer.accountName) is neither a computer account nor a DNS administrator"
        }
        let own = await ownNames(of: signer, info: info)
        let reverse = info.reverseZones.contains(zone) && !info.zones.contains(zone)
        if !admin, !reverse, zone != info.dnsDomain { return "only the DC updates \(zone)" }
        let current = await view(zone: zone, info: info)
        let pinned = Set(current.generated.map { Self.canonical($0.name) })
        for u in request.updates {
            let name = Self.canonical(u.name)
            if let reason = Self.reservedNameReason(u.name, zone: zone, info: info, generated: pinned) { return reason }
            let atName = current.all.filter { Self.canonical($0.name) == name }
            if atName.contains(where: { $0.type == .dhcid }) {
                guard signer.isComputer, own.contains(name) else { return "\(u.name) is held by a DHCP lease" }
                Self.logger.notice("secure update: \(signer.accountName, privacy: .public) replaces the DHCP server's registration of \(u.name, privacy: .public)")
                onEvent?("UPDATE \(u.name): \(signer.accountName) replaces the DHCP server's registration (secure)")
            } else if !admin, await source.hasStaticRecords(name: name, zone: zone) {
                return "\(u.name) is a static name"
            }
            if admin { continue }
            if reverse {
                switch u.rrClass {
                case .in:
                    guard case .ptr(let target) = u.rdata else { return "\(u.type) records are not accepted in \(zone)" }
                    guard own.contains(Self.canonical(target)) else { return "PTR \(u.name) \(target) is not \(signer.accountName)'s name" }
                case .any, .none:
                    guard u.type == .ptr || u.type == .any else { return "\(u.type) records are not accepted in \(zone)" }
                default:
                    return "class \(u.rrClass)"
                }
                let others = atName.compactMap { r -> DNSName? in
                    if case .ptr(let t) = r.rdata { return Self.canonical(t) }
                    return nil
                }.filter { !own.contains($0) }
                if let other = others.first, await source.dynamicOwner(name: name, zone: zone)?.holder != signer.holder {
                    return "\(u.name) points at \(other), another host"
                }
            } else {
                guard own.contains(name) else {
                    let names = own.sorted().map(\.description).joined(separator: ", ")
                    return "\(u.name) is not \(signer.accountName)'s name (\(names.isEmpty ? "none" : names))"
                }
                switch u.rrClass {
                case .in:
                    guard u.type == .a || u.type == .aaaa else { return "\(u.type) records are not accepted from \(signer.accountName)" }
                case .any, .none:
                    guard [.a, .aaaa, .any].contains(u.type) else { return "\(u.type) records are not accepted from \(signer.accountName)" }
                default:
                    return "class \(u.rrClass)"
                }
            }
        }
        return nil
    }
}
