import AuthKit
import Foundation
import LDAPCore
import MSPAC
import NIOCore
import NIOSSL
import Store

extension LDAPConnection {
    static let saslMechanisms = ["GSSAPI", "GSS-SPNEGO"]

    // MARK: Bind

    func bind(_ message: LDAPMessage, _ request: BindRequest) async {
        let id = message.messageID
        func reply(_ result: LDAPResult, creds: [UInt8]? = nil) {
            send(LDAPMessage(messageID: id, .bindResponse(BindResponse(result: result, serverSaslCreds: creds))))
        }
        guard request.version == 3 || request.version == 2 else {
            saslExchange = nil
            return reply(LDAPResult(.protocolError, diagnosticMessage: "unsupported LDAP version \(request.version)"))
        }
        switch request.authentication {
        case .simple(let password):
            saslExchange = nil
            if !config.allowPlainSimpleBind, !password.isEmpty, !isConfidential {
                bound = nil
                reportBind("simple", request.name, "strongerAuthRequired (plain LDAP not allowed)")
                return reply(LDAPResult(.strongerAuthRequired, diagnosticMessage: "00002028: LdapErr: DSID-0C09018A, comment: "
                    + "The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, \(ADDiagnostic.version)"))
            }
            do {
                bound = try await simpleBind(name: request.name, password: password)
                server.logger.info("LDAP simple bind: \(self.bound.map { $0.identity.downLevelName } ?? "anonymous", privacy: .public)")
                if let b = bound { reportBind("simple", request.name, "OK as \(b.identity.downLevelName)") }
                reply(.success)
            } catch {
                bound = nil
                let result = Self.result(for: error)
                if !request.name.isEmpty { reportBind("simple", request.name, Self.bindOutcome(result)) }
                reply(result)
            }
        case let .sasl(mechanism, credentials):
            await saslBind(id: id, mechanism: mechanism, credentials: credentials ?? [])
        }
    }

    /// UI-1: the `onBind` line, `<method> <name> from <ip>/<listener> -> <outcome>`.
    func reportBind(_ method: String, _ name: String, _ outcome: String) {
        guard let onBind = config.onBind else { return }
        let from = channel.remoteAddress?.ipAddress ?? "?"
        let listener = switch kind {
        case .ldap: "ldap"
        case .ldaps: "ldaps"
        case .globalCatalog: "gc"
        case .globalCatalogTLS: "gc-tls"
        }
        onBind("\(method) \(name.isEmpty ? "-" : name) from \(from)/\(listener)\(isTLS && kind == .ldap ? "+starttls" : "") -> \(outcome)")
    }

    /// `invalidCredentials (52e)` / `strongerAuthRequired` for the bind log line.
    static func bindOutcome(_ result: LDAPResult) -> String {
        let name = switch result.resultCode {
        case .invalidCredentials: "invalidCredentials"
        case .strongerAuthRequired: "strongerAuthRequired"
        case .unwillingToPerform: "unwillingToPerform"
        case .inappropriateAuthentication: "inappropriateAuthentication"
        default: "result \(result.resultCode)"
        }
        if let r = result.diagnosticMessage.range(of: #"data ([0-9a-fA-F]+)"#, options: .regularExpression) {
            let code = result.diagnosticMessage[r].dropFirst(5)
            if code != "0" { return "\(name) (\(code))" }
        }
        return name
    }

    /// Simple bind (RFC 4513 §5.1) with the AD name forms: DN, `user@domain` (UPN or
    /// sam@dnsDomain), `DOMAIN\user`, bare sAMAccountName.
    func simpleBind(name: String, password: [UInt8]) async throws -> BoundIdentity? {
        if name.isEmpty, password.isEmpty { return nil }  // anonymous (§5.1.1)
        if password.isEmpty {
            // Unauthenticated bind (§5.1.2): refused.
            throw LDAPFailure(.unwillingToPerform, "00002028: LdapErr: DSID-0C0901FC, comment: unauthenticated bind (DN with no password) is not allowed, data 0, \(ADDiagnostic.version)")
        }
        guard let entry = try await resolveAccount(name) else {
            throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "52e"))
        }
        // One check for every password path (LDAP simple bind, RADIUS PAP): the password first
        // (52e), then disabled (533), locked (775) and expired (701).
        switch try await store.checkPassword(entry, password: String(decoding: password, as: UTF8.self), now: config.clock()) {
        case nil: break
        case .disabled: throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "533"))
        case .expired: throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "701"))
        case .lockedOut: throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "775"))
        case .noSuchAccount, .noPassword, .wrongPassword:
            throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "52e"))
        }
        // Must change at next logon (`pwdLastSet` 0 or PASSWORD_EXPIRED, unless the password
        // never expires): AD refuses the bind with data 773 (30 Sep 2026, restored). The change
        // itself goes through kpasswd (kadmin/changepw is still issued), SAMR or an admin reset;
        // Activity and Test login read 773 as "Password must change", not as a wrong password.
        let uac = UInt32(truncatingIfNeeded: entry.int("userAccountControl") ?? 0)
        if uac & UserAccountControl.dontExpirePassword == 0, let secrets = try await store.secrets(id: entry.id),
           secrets.pwdLastSet.rawValue == 0 || uac & UserAccountControl.passwordExpired != 0 {
            throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "773"))
        }
        guard let identity = await server.secrets.identity(of: entry) else {
            throw LDAPFailure(.invalidCredentials, ADDiagnostic.invalidCredentials(data: "52e"))
        }
        return await boundIdentity(entry: entry, identity: identity)
    }

    /// Resolves a bind or password-modify name to a live account.
    func resolveAccount(_ rawName: String) async throws -> DirectoryEntry? {
        var name = rawName.trimmingCharacters(in: .whitespaces)
        if name.lowercased().hasPrefix("dn:") { name = String(name.dropFirst(3)) }
        else if name.lowercased().hasPrefix("u:") { name = String(name.dropFirst(2)) }
        if name.contains("=") {
            guard let dn = try? DN(string: name) else { return nil }
            return try await store.read(dn: dn)
        }
        if let slash = name.firstIndex(of: "\\") {
            let domain = name[..<slash].lowercased()
            let sam = String(name[name.index(after: slash)...])
            guard domain == info.netbiosDomain.lowercased() || domain == info.dnsDomain.lowercased() else { return nil }
            return try await account(sam: sam)
        }
        if let at = name.lastIndex(of: "@") {
            if let e = try await store.read(upn: name) { return e }
            let suffix = name[name.index(after: at)...].lowercased()
            guard suffix == info.dnsDomain.lowercased() || suffix == info.realm.lowercased() else { return nil }
            return try await account(sam: String(name[..<at]))
        }
        return try await account(sam: name)
    }

    private func account(sam: String) async throws -> DirectoryEntry? {
        if let e = try await store.read(sam: sam) { return e }
        return sam.hasSuffix("$") ? nil : try await store.read(sam: sam + "$")
    }

    /// SASL bind: `GSSAPI` (RFC 4752) or `GSS-SPNEGO` (MS-ADTS), possibly several round trips;
    /// on success the security layer (if any) is installed after the response is sent.
    func saslBind(id: Int32, mechanism: String, credentials: [UInt8]) async {
        func reply(_ result: LDAPResult, creds: [UInt8]? = nil) {
            send(LDAPMessage(messageID: id, .bindResponse(BindResponse(result: result, serverSaslCreds: creds))))
        }
        let mech = mechanism.uppercased()
        guard Self.saslMechanisms.contains(mech) else {
            saslExchange = nil
            return reply(LDAPResult(.authMethodNotSupported,
                                    diagnosticMessage: "00002027: LdapErr: DSID-0C09058A, comment: Unknown authentication mechanism '\(mechanism)', data 0, \(ADDiagnostic.version)"))
        }
        if saslQOP != nil {
            // A second SASL layer cannot be stacked on the first.
            return reply(LDAPResult(.operationsError, diagnosticMessage: "00002029: LdapErr: DSID-0C09058B, comment: a SASL security layer is already in effect, data 0, \(ADDiagnostic.version)"))
        }
        let current = saslExchange.flatMap { $0.mechanism == mech ? $0 : nil }
        if credentials.isEmpty, current?.started != true || mech == "GSS-SPNEGO" {
            // Empty first leg (RFC 4513 §5.2.1.2, RFC 4511 §4.2): the client asks the server to
            // speak first. GSS-SPNEGO answers with the NegTokenInit2 hint a Windows DC sends
            // (MS-ADTS §5.1.1.1.2; Samba's `ads_sasl_spnego_bind` picks Kerberos or NTLMSSP from
            // its mechTypes); GSSAPI is client-first (RFC 4752), so its challenge is empty. The
            // exchange stays open for the next bindRequest, whatever its messageID. An empty
            // GSS-SPNEGO leg mid-exchange restarts it (SPNEGO never sends an empty token).
            // A GSSAPI exchange that has started takes the empty response as RFC 4752's step 2.
            bound = nil
            saslExchange = (mech, newSASLServer(mech), false)
            let challenge = mech == "GSS-SPNEGO" ? NegTokenInit2.ldapServerInitial : []
            server.logger.info("LDAP SASL \(mech, privacy: .public) bind with no credentials: server-initial challenge (\(challenge.count) bytes)")
            return reply(LDAPResult(.saslBindInProgress), creds: challenge)
        }
        var exchange: any SASLServer
        if let current {
            exchange = current.server
        } else {
            bound = nil
            exchange = newSASLServer(mech)
        }
        do {
            switch try await exchange.step(credentials) {
            case .continue(let out):
                saslExchange = (mech, exchange, true)
                reply(LDAPResult(.saslBindInProgress), creds: out)
            case let .complete(output, identity, layer):
                saslExchange = nil
                let entry = try await store.read(sid: identity.sid)
                bound = await boundIdentity(entry: entry, identity: identity)
                server.logger.info("LDAP SASL \(mech, privacy: .public) bind: \(identity.downLevelName, privacy: .public), layer \(layer?.qop.description ?? "none", privacy: .public)")
                reportBind(mech, identity.downLevelName, "OK as \(identity.downLevelName)")
                let response = LDAPMessage(messageID: id, .bindResponse(BindResponse(result: .success, serverSaslCreds: output)))
                if let layer {
                    try await send(response) { channel in
                        let decoder = try channel.pipeline.syncOperations.context(name: LDAPPipeline.frameDecoder)
                        try channel.pipeline.syncOperations.addHandler(SASLLayerHandler(layer: layer), name: LDAPPipeline.saslLayer,
                                                                        position: .before(decoder.handler))
                    }
                    saslQOP = layer.qop
                } else {
                    send(response)
                }
            }
        } catch {
            saslExchange = nil
            bound = nil
            server.logger.info("LDAP SASL \(mech, privacy: .public) bind failed: \(String(describing: error), privacy: .public)")
            reportBind(mech, "-", "invalidCredentials (52e)")
            reply(LDAPResult(.invalidCredentials,
                             diagnosticMessage: "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, \(ADDiagnostic.version)"))
        }
    }

    /// A fresh server side of `mech` (already checked against `saslMechanisms`).
    private func newSASLServer(_ mech: String) -> any SASLServer {
        if mech == "GSSAPI" { return GSSAPISASLServer(acceptor: server.kerberosAcceptor) }
        return GSSSPNEGOSASLServer(spnego: SPNEGOAcceptor(
            kerberos: server.kerberosAcceptor,
            ntlm: NTLMServer(source: server.secrets, allowAnonymous: false, clock: config.clock)))
    }

    // MARK: Extended operations

    func extended(_ message: LDAPMessage, _ request: ExtendedRequest) async throws {
        let id = message.messageID
        switch request.name {
        case LDAPExtendedOID.startTLS:
            guard let tls = server.tls else {
                throw LDAPFailure(.unavailable, "00000005: LdapErr: DSID-0C090F2B, comment: no server certificate, data 0, \(ADDiagnostic.version)")
            }
            guard !isTLS, saslQOP == nil else {
                throw LDAPFailure(.operationsError, "00002027: LdapErr: DSID-0C090F31, comment: TLS or a SASL layer is already in effect, data 0, \(ADDiagnostic.version)")
            }
            let response = LDAPMessage(messageID: id, .extendedResponse(ExtendedResponse(result: .success, name: LDAPExtendedOID.startTLS)))
            try await send(response) { channel in
                try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls), name: LDAPPipeline.tls, position: .first)
            }
            isTLS = true
            server.logger.info("LDAP StartTLS established")
        case LDAPExtendedOID.whoAmI:
            let authz = bound.map { "u:" + $0.identity.downLevelName } ?? ""
            send(LDAPMessage(messageID: id, .extendedResponse(ExtendedResponse(result: .success, value: Array(authz.utf8)))))
        case LDAPExtendedOID.passwordModify:
            try await passwordModify(id: id, request)
        default:
            throw LDAPFailure(.protocolError, "0000203A: LdapErr: DSID-0C09063F, comment: unsupported extended operation \(request.name), data 0, \(ADDiagnostic.version)")
        }
    }

    /// RFC 3062 Password Modify: users change their own password (old one required),
    /// administrators reset anyone's. Needs TLS or a sealed layer, as `unicodePwd` does.
    func passwordModify(id: Int32, _ request: ExtendedRequest) async throws {
        let me = try requireBound()
        guard isConfidential else { throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unicodePwdNeedsSecureConnection) }
        let value: PasswordModifyRequestValue
        do { value = try PasswordModifyRequestValue(requestValue: request.value) } catch {
            throw LDAPFailure(.protocolError, "invalid PasswdModifyRequestValue: \(error)")
        }
        let target: DirectoryEntry
        if let who = value.userIdentity {
            guard let e = try await resolveAccount(String(decoding: who, as: UTF8.self)) else {
                throw LDAPFailure(.noSuchObject, ADDiagnostic.noSuchObject(bestMatch: ""))
            }
            target = e
        } else {
            guard let myID = me.entryID, let e = try await store.read(id: myID) else {
                throw LDAPFailure(.unwillingToPerform, ADDiagnostic.unwillingToPerform)
            }
            target = e
        }
        guard let newPassword = value.newPassword.map({ String(decoding: $0, as: UTF8.self) }) else {
            throw LDAPFailure(.unwillingToPerform, "password generation is not supported; send newPasswd")
        }
        let isSelf = target.id == me.entryID
        let manages = try await mayManage(me, target)
        if !manages {
            guard isSelf else { throw LDAPFailure(.insufficientAccessRights, ADDiagnostic.insufficientAccess) }
            guard let old = value.oldPassword else {
                throw LDAPFailure(.unwillingToPerform, "00000056: AtrErr: DSID-03190F80, problem 1005 (CONSTRAINT_ATT_TYPE), data 0 (old password required)\n")
            }
            try await verifyCurrentPassword(target, String(decoding: old, as: UTF8.self))
        } else if let old = value.oldPassword {
            try await verifyCurrentPassword(target, String(decoding: old, as: UTF8.self))
        }
        try await setPassword(target, newPassword)
        send(LDAPMessage(messageID: id, .extendedResponse(ExtendedResponse(result: .success))))
    }

    /// Checks `password` against the stored NT hash (a password change must name the current one).
    func verifyCurrentPassword(_ entry: DirectoryEntry, _ password: String) async throws {
        guard let hash = try await store.secrets(id: entry.id)?.ntHash,
              constantTimeEqual(DirectoryStore.ntHash(password), hash) else {
            throw LDAPFailure(.constraintViolation,
                              "00000056: AtrErr: DSID-03190F80, #1:\n\t0: 00000056: DSID-03190F80, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)\n")
        }
    }

    /// Sets a password with the domain policy (length, complexity, history).
    func setPassword(_ entry: DirectoryEntry, _ password: String) async throws {
        do {
            try await store.setPassword(id: entry.id, password: password, enforcePolicy: !Self.isTrustAccount(entry))
        } catch StoreError.passwordPolicy(let v) {
            server.logger.info("LDAP password for \(entry.dn.description, privacy: .public) refused: \(v.description, privacy: .public)")
            throw LDAPFailure(.constraintViolation, ADDiagnostic.passwordPolicy())
        }
        server.logger.info("LDAP password set for \(entry.dn.description, privacy: .public)")
    }
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in a.indices { diff |= a[i] ^ b[i] }
    return diff == 0
}
