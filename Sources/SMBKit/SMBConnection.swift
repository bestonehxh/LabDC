import AuthKit
import Foundation
import NIOCore

/// One SMB2 connection: negotiate state, credits, sessions, trees and opens. PDUs are
/// processed strictly one after the other (`process`), so the actor is never re-entered.
actor SMBConnection {
    struct Output: Sendable {
        /// The response PDU (without the 4-byte transport header), nil when nothing is sent.
        var response: [UInt8]?
        /// Drop the transport connection after sending `response`.
        var close: Bool
    }

    let server: SMBServerContext
    let clientAddress: String
    let localAddress: SocketAddress?

    // Negotiate state.
    private(set) var dialect: UInt16?
    private var sawFirstMessage = false
    private var clientGUID = [UInt8](repeating: 0, count: 16)
    private var clientSecurityMode: UInt16 = 0
    private var clientCapabilities: UInt32 = 0
    private var clientDialects: [UInt16] = []
    private var serverCapabilities: UInt32 = 0
    private var serverSecurityMode: UInt16 = 0
    /// Connection.PreauthIntegrityHashValue (3.1.1).
    private(set) var preauthHash = [UInt8](repeating: 0, count: 64)

    // Credits: message ids below `grantedUpTo` may be used, each once.
    private(set) var grantedUpTo: UInt64 = 1
    private var outstanding = 1
    private var usedIDs = Set<UInt64>()
    private var lowestUnused: UInt64 = 0

    private(set) var sessions: [UInt64: Session] = [:]
    private var nextFileID: UInt64 = 1

    init(server: SMBServerContext, clientAddress: String, localAddress: SocketAddress?) {
        self.server = server
        self.clientAddress = clientAddress
        self.localAddress = localAddress
    }

    var config: SMBServerConfig { server.config }

    // MARK: - Model

    final class Session {
        enum State {
            case inProgress
            case valid
        }

        let id: UInt64
        var state: State = .inProgress
        var spnego: SPNEGOAcceptor
        var rawNTLM: NTLMServer?
        var identity: AuthenticatedIdentity = .anonymous
        var keys: SMBCrypto.SessionKeys?
        var isAnonymous = false
        var signingRequired = false
        var preauthHash: [UInt8]
        var trees: [UInt32: Tree] = [:]
        var nextTreeID: UInt32 = 1
        var opens: [UInt64: Open] = [:]
        var reauthenticating = false

        init(id: UInt64, spnego: SPNEGOAcceptor, preauthHash: [UInt8]) {
            self.id = id
            self.spnego = spnego
            self.preauthHash = preauthHash
        }
    }

    struct Tree {
        let id: UInt32
        let share: SMBShare
        var isIPC: Bool { share.kind == .ipc }
        var resolver: FolderResolver? {
            if case .readOnlyFolder(let path) = share.kind { return FolderResolver(root: path) }
            return nil
        }
    }

    final class Open {
        enum Kind {
            case pipe(any NamedPipeHandle, name: String)
            case file(FSNode, relative: String, resolver: FolderResolver)
        }

        let id: SMB2FileID
        let treeID: UInt32
        let kind: Kind
        let grantedAccess: UInt32
        // Directory enumeration state.
        var searchEntries: [(name: String, node: FSNode)]?
        var searchPosition = 0

        init(id: SMB2FileID, treeID: UInt32, kind: Kind, grantedAccess: UInt32) {
            self.id = id
            self.treeID = treeID
            self.kind = kind
            self.grantedAccess = grantedAccess
        }
    }

    /// What a command handler produced.
    struct Reply {
        var status: UInt32
        var body: [UInt8]
        /// Overrides the response header's SessionId / TreeId.
        var sessionID: UInt64?
        var treeID: UInt32?
        /// The FileId created by this operation (for related compounds).
        var fileID: SMB2FileID?
        /// Sign with this key (final SESSION_SETUP) instead of the session's.
        var signingKey: [UInt8]?
        /// Do not sign even if the session would.
        var noSign = false
        var close = false

        static func ok(_ body: [UInt8]) -> Reply { Reply(status: NTStatus.success, body: body) }
        static func error(_ status: UInt32, data: [UInt8] = []) -> Reply {
            Reply(status: status, body: SMB2Body.error(data: data))
        }
    }

    // MARK: - Entry point

    func process(_ pdu: [UInt8]) async -> Output {
        let first = !sawFirstMessage
        sawFirstMessage = true
        guard pdu.count >= 4 else { return Output(response: nil, close: true) }
        switch Array(pdu[0..<4]) {
        case SMB1NegotiateRequest.protocolID:
            guard first else { return fail("SMB1 after the first message") }
            return smb1Negotiate(pdu)
        case SMB2Header.protocolID:
            return await processSMB2(pdu)
        default:
            // 0xFD 'SMB' (transform, encryption not negotiated), 0xFC (compression) or garbage.
            return fail("unexpected protocol id \(Array(pdu[0..<4]).map { String($0, radix: 16) })")
        }
    }

    private func fail(_ why: String) -> Output {
        server.logger.info("SMB \(self.clientAddress, privacy: .public): dropping connection: \(why, privacy: .public)")
        return Output(response: nil, close: true)
    }

    /// Closes every open pipe (end of connection).
    func shutdown() async {
        for s in sessions.values { await closeAll(in: s, tree: nil) }
        sessions = [:]
    }

    private func closeAll(in session: Session, tree: UInt32?) async {
        for (k, o) in session.opens where tree == nil || o.treeID == tree {
            if case .pipe(let h, _) = o.kind { await h.close() }
            session.opens[k] = nil
        }
    }

    // MARK: - SMB1 → SMB2

    private func smb1Negotiate(_ pdu: [UInt8]) -> Output {
        guard let req = try? SMB1NegotiateRequest(parsing: pdu), let answer = req.smb2Answer else {
            return fail("SMB1-only client")
        }
        usedIDs.insert(0)
        lowestUnused = 1
        outstanding = 0
        var hdr = SMB2Header(command: .negotiate, messageID: 0, credits: 1, creditCharge: 0,
                             flags: SMB2Flags.serverToRedir)
        hdr.credits = grant(requested: 1)
        if answer == SMB2Dialect.smb202 {
            dialect = SMB2Dialect.smb202
            clientDialects = [SMB2Dialect.smb202]
        }
        let body = negotiateResponse(dialect: answer, contexts: []).encode()
        return Output(response: hdr.encode() + body, close: false)
    }

    // MARK: - SMB2

    private func processSMB2(_ pdu: [UInt8]) async -> Output {
        let messages: [[UInt8]]
        do {
            messages = try SMB2Compound.split(pdu)
        } catch {
            return fail("\(error)")
        }
        var responses: [[UInt8]] = []
        var signKeys: [[UInt8]?] = []
        var prevSession: UInt64 = 0
        var prevTree: UInt32 = 0
        var prevFileID: SMB2FileID?
        var prevStatus: UInt32 = NTStatus.success

        for (index, message) in messages.enumerated() {
            guard var hdr = try? SMB2Header(parsing: message), !hdr.isResponse else { return fail("bad SMB2 header") }
            guard let command = SMB2Command(rawValue: hdr.command) else {
                // Unknown command: answer INVALID_PARAMETER.
                responses.append(responseHeader(hdr, status: NTStatus.invalidParameter).encode() + SMB2Body.error())
                signKeys.append(nil)
                continue
            }
            if command == .cancel { continue }                  // no response, nothing is ever pending
            // Credits and the message id window.
            let charge = UInt64(max(1, hdr.creditCharge))
            guard hdr.messageID != .max, hdr.messageID >= lowestUnused, hdr.messageID + charge <= grantedUpTo,
                  !(hdr.messageID..<(hdr.messageID + charge)).contains(where: usedIDs.contains) else {
                return fail("message id \(hdr.messageID) outside the credit window [\(lowestUnused), \(grantedUpTo))")
            }
            for id in hdr.messageID..<(hdr.messageID + charge) { usedIDs.insert(id) }
            while usedIDs.contains(lowestUnused) {
                usedIDs.remove(lowestUnused)
                lowestUnused += 1
            }
            outstanding = max(0, outstanding - Int(charge))

            let related = hdr.isRelated && index > 0
            if related {
                hdr.sessionID = prevSession
                hdr.treeID = prevTree
            }
            var reply: Reply
            var verified = true
            if related, NTStatus.isError(prevStatus), prevFileID == nil, command != .create {
                reply = .error(prevStatus)
            } else if command != .negotiate, dialect == nil || dialect == SMB2Dialect.wildcard {
                return fail("\(command) before NEGOTIATE")
            } else {
                // Session lookup and signature verification.
                var session: Session?
                if hdr.sessionID != 0 { session = sessions[hdr.sessionID] }
                if let s = session, s.state == .valid, let keys = s.keys, !s.isAnonymous, command != .negotiate {
                    if hdr.isSigned {
                        if !SMBCrypto.verify(message, signingKey: keys.signingKey, dialect: dialect!) {
                            server.logger.info("SMB \(self.clientAddress, privacy: .public): bad signature on \(String(describing: command), privacy: .public)")
                            verified = false
                        }
                    } else if s.signingRequired, command != .sessionSetup {
                        verified = false
                    }
                }
                if !verified {
                    reply = .error(NTStatus.accessDenied)
                    reply.noSign = true
                } else {
                    let fileID = related ? prevFileID : nil
                    reply = await dispatch(command, hdr: hdr, message: message, session: session, chainedFileID: fileID)
                }
            }
            prevSession = reply.sessionID ?? hdr.sessionID
            prevTree = reply.treeID ?? hdr.treeID
            if let f = reply.fileID { prevFileID = f } else if NTStatus.isError(reply.status) && command == .create { prevFileID = nil }
            prevStatus = reply.status
            // Protocol violations end the connection without an answer (as Windows does).
            if reply.close { return Output(response: nil, close: true) }

            var rh = responseHeader(hdr, status: reply.status)
            rh.credits = grant(requested: hdr.credits)
            if let sid = reply.sessionID { rh.sessionID = sid }
            if let tid = reply.treeID { rh.treeID = tid }
            if related { rh.flags |= SMB2Flags.relatedOperations }
            let response = rh.encode() + reply.body

            // Preauth integrity (3.1.1): NEGOTIATE and SESSION_SETUP in progress.
            if dialect == SMB2Dialect.smb311 {
                if command == .negotiate, reply.status == NTStatus.success {
                    preauthHash = SMBCrypto.sha512(preauthHash + response)
                } else if command == .sessionSetup, reply.status == NTStatus.moreProcessingRequired,
                          let s = sessions[rh.sessionID], !s.reauthenticating {
                    s.preauthHash = SMBCrypto.sha512(s.preauthHash + response)
                }
            }

            // Which key signs the response.
            var key: [UInt8]?
            if !reply.noSign {
                if let k = reply.signingKey {
                    key = k
                } else if command != .negotiate, reply.status != NTStatus.moreProcessingRequired,
                          let s = sessions[rh.sessionID] ?? lastLoggedOff.flatMap({ $0.id == rh.sessionID ? $0 : nil }),
                          s.state == .valid, !s.isAnonymous, let keys = s.keys, hdr.isSigned || s.signingRequired {
                    key = keys.signingKey
                }
            }
            lastLoggedOff = nil
            responses.append(response)
            signKeys.append(key)
        }
        guard !responses.isEmpty else { return Output(response: nil, close: false) }
        var joined = SMB2Compound.join(responses)
        for i in joined.indices {
            if let k = signKeys[i], let d = dialect { SMBCrypto.sign(&joined[i], signingKey: k, dialect: d) }
        }
        return Output(response: joined.flatMap { $0 }, close: false)
    }

    /// A LOGOFF removes the session before its response is signed; keep it for that.
    private var lastLoggedOff: Session?

    private func responseHeader(_ req: SMB2Header, status: UInt32) -> SMB2Header {
        var h = SMB2Header(command: SMB2Command(rawValue: req.command) ?? .negotiate, messageID: req.messageID,
                           sessionID: req.sessionID, treeID: req.treeID, credits: 0, creditCharge: req.creditCharge,
                           flags: SMB2Flags.serverToRedir | (req.flags & SMB2Flags.priorityMask), status: status)
        h.command = req.command
        h.processID = req.processID
        return h
    }

    /// Grants credits for one response: what the client asks for (at least 1), within
    /// `maxCredits` outstanding.
    private func grant(requested: UInt16) -> UInt16 {
        let room = max(0, Int(config.maxCredits) - outstanding)
        var g = min(max(1, Int(requested)), room)
        if g == 0 && outstanding == 0 { g = 1 }
        outstanding += g
        grantedUpTo += UInt64(g)
        return UInt16(g)
    }

    // MARK: - Dispatch

    private func dispatch(_ command: SMB2Command, hdr: SMB2Header, message: [UInt8], session: Session?,
                          chainedFileID: SMB2FileID?) async -> Reply {
        do {
            switch command {
            case .negotiate:
                return try negotiate(message)
            case .sessionSetup:
                return try await sessionSetup(hdr: hdr, message: message)
            case .echo:
                return .ok(SMB2Body.four)
            default:
                break
            }
            guard let session else { return .error(NTStatus.userSessionDeleted) }
            guard session.state == .valid else { return .error(NTStatus.userSessionDeleted) }
            switch command {
            case .logoff:
                await closeAll(in: session, tree: nil)
                sessions[session.id] = nil
                lastLoggedOff = session
                return .ok(SMB2Body.four)
            case .treeConnect:
                return try treeConnect(message, session: session)
            default:
                break
            }
            guard let tree = session.trees[hdr.treeID] else { return .error(NTStatus.networkNameDeleted) }
            switch command {
            case .treeDisconnect:
                await closeAll(in: session, tree: tree.id)
                session.trees[tree.id] = nil
                return .ok(SMB2Body.four)
            case .create:
                return try await create(message, session: session, tree: tree)
            case .close:
                let req = try SMB2CloseRequest(parsing: message)
                guard let open = lookup(req.fileID, chained: chainedFileID, session: session, tree: tree) else {
                    return .error(NTStatus.fileClosed)
                }
                return await close(open, flags: req.flags, session: session)
            case .flush:
                let id = try parseFlush(message)
                guard lookup(id, chained: chainedFileID, session: session, tree: tree) != nil else { return .error(NTStatus.fileClosed) }
                return .ok(SMB2Body.four)
            case .read:
                return try await read(message, session: session, tree: tree, chained: chainedFileID)
            case .write:
                return try await write(message, session: session, tree: tree, chained: chainedFileID)
            case .ioctl:
                return try await ioctl(message, session: session, tree: tree, chained: chainedFileID)
            case .queryInfo:
                return try queryInfo(message, session: session, tree: tree, chained: chainedFileID)
            case .queryDirectory:
                return try queryDirectory(message, session: session, tree: tree, chained: chainedFileID)
            case .setInfo:
                let req = try parseSetInfo(message)
                guard let open = lookup(req.fileID, chained: chainedFileID, session: session, tree: tree) else {
                    return .error(NTStatus.fileClosed)
                }
                if case .pipe = open.kind { return .ok(SMB2Body.setInfoResponse) }  // FilePipeInformation
                return .error(NTStatus.accessDenied)
            case .lock, .changeNotify:
                return .error(NTStatus.notSupported)
            case .oplockBreak:
                return .error(NTStatus.invalidParameter)
            default:
                return .error(NTStatus.invalidParameter)
            }
        } catch SMBKitError.status(let st, _) {
            return .error(st)
        } catch SMBKitError.protocolViolation(let why) {
            server.logger.info("SMB \(self.clientAddress, privacy: .public): \(why, privacy: .public)")
            var r = Reply.error(NTStatus.invalidParameter)
            r.close = true
            return r
        } catch {
            server.logger.debug("SMB \(self.clientAddress, privacy: .public): \(String(describing: command), privacy: .public): \(String(describing: error), privacy: .public)")
            return .error(NTStatus.invalidParameter)
        }
    }

    private func lookup(_ id: SMB2FileID, chained: SMB2FileID?, session: Session, tree: Tree) -> Open? {
        let effective = id == .any ? chained : id
        guard let effective, let open = session.opens[effective.volatile], open.id == effective, open.treeID == tree.id else {
            return nil
        }
        return open
    }

    // MARK: - NEGOTIATE

    private func negotiateResponse(dialect d: UInt16, contexts: [SMB2NegotiateContext]) -> SMB2NegotiateResponse {
        let smb202 = d == SMB2Dialect.smb202
        serverCapabilities = smb202 ? 0 : SMB2Capabilities.largeMTU
        serverSecurityMode = config.requireSigning ? 0x03 : 0x01
        let io = smb202 ? 65536 : config.maxIOSize
        return SMB2NegotiateResponse(
            securityMode: serverSecurityMode, dialect: d, serverGUID: config.serverGUID, capabilities: serverCapabilities,
            maxTransactSize: io, maxReadSize: io, maxWriteSize: io, systemTime: FileTime.from(config.clock()),
            serverStartTime: 0, securityBuffer: NegTokenInit2.encode(kerberos: server.auth.kerberos, ntlm: server.auth.ntlm),
            contexts: contexts)
    }

    private func negotiate(_ message: [UInt8]) throws -> Reply {
        if let d = dialect, d != SMB2Dialect.wildcard {
            throw SMBKitError.protocolViolation("second NEGOTIATE")
        }
        let req = try SMB2NegotiateRequest(parsing: message)
        clientGUID = req.clientGUID
        clientSecurityMode = req.securityMode
        clientCapabilities = req.capabilities
        clientDialects = req.dialects
        guard let chosen = config.dialects.filter(req.dialects.contains).max() else {
            return .error(NTStatus.notSupported)
        }
        var contexts: [SMB2NegotiateContext] = []
        if chosen == SMB2Dialect.smb311 {
            guard let pre = req.contexts.first(where: { $0.type == SMB2NegotiateContext.preauthIntegrity }),
                  pre.algorithmList.contains(1) else {
                return .error(NTStatus.invalidParameter)
            }
            contexts.append(.preauth(salt: config.rng.next(32)))
            if req.contexts.contains(where: { $0.type == SMB2NegotiateContext.signing }) {
                contexts.append(.signingCapabilities([1]))           // AES-CMAC
            }
            preauthHash = SMBCrypto.sha512([UInt8](repeating: 0, count: 64) + message)
        }
        dialect = chosen
        server.logger.info("SMB \(self.clientAddress, privacy: .public): dialect \(SMB2Dialect.name(chosen), privacy: .public)")
        return .ok(negotiateResponse(dialect: chosen, contexts: contexts).encode())
    }

    // MARK: - SESSION_SETUP

    private func sessionSetup(hdr: SMB2Header, message: [UInt8]) async throws -> Reply {
        let req = try SMB2SessionSetupRequest(parsing: message)
        guard let d = dialect else { throw SMBKitError.protocolViolation("SESSION_SETUP before NEGOTIATE") }
        if req.flags & SMB2SessionSetupRequest.flagBinding != 0 { return .error(NTStatus.requestNotAccepted) }
        let session: Session
        if hdr.sessionID == 0 {
            session = Session(id: server.newSessionID(), spnego: server.spnego(), preauthHash: preauthHash)
            sessions[session.id] = session
        } else {
            guard let s = sessions[hdr.sessionID] else { return .error(NTStatus.userSessionDeleted) }
            session = s
            if s.state == .valid && !s.reauthenticating {
                s.reauthenticating = true
                s.spnego = server.spnego()
                s.rawNTLM = nil
            }
        }
        var reply = Reply(status: NTStatus.success, body: [])
        reply.sessionID = session.id
        if d == SMB2Dialect.smb311, !session.reauthenticating {
            session.preauthHash = SMBCrypto.sha512(session.preauthHash + message)
        }

        let token = req.securityBuffer
        do {
            let identity: AuthenticatedIdentity
            let context: (any GSSSecurityContext)?
            var output: [UInt8]?
            if token.starts(with: Array("NTLMSSP".utf8) + [0]) || session.rawNTLM != nil {
                guard server.auth.ntlm else { throw SMBKitError.status(NTStatus.logonFailure, "NTLM disabled") }
                var n = session.rawNTLM ?? server.ntlmServer()
                if session.rawNTLM == nil {
                    let challenge = try n.challenge(for: token)
                    session.rawNTLM = n
                    reply.status = NTStatus.moreProcessingRequired
                    reply.body = SMB2SessionSetupResponse(sessionFlags: 0, securityBuffer: challenge).encode()
                    return reply
                }
                let r = try await n.authenticate(token)
                identity = r.identity
                context = r.context
            } else {
                var sp = session.spnego
                let step = try await sp.step(token)
                session.spnego = sp
                switch step {
                case .continue(let out):
                    reply.status = NTStatus.moreProcessingRequired
                    reply.body = SMB2SessionSetupResponse(sessionFlags: 0, securityBuffer: out).encode()
                    return reply
                case .complete(let out, let id, let ctx):
                    identity = id
                    context = ctx
                    output = out
                }
            }
            // Established.
            let anonymous = context == nil || identity.isAnonymous
            if anonymous && !server.auth.allowAnonymousIPC { throw SMBKitError.status(NTStatus.accessDenied, "anonymous") }
            if !session.reauthenticating {
                if let ctx = context, let gssKey = Self.gssSessionKey(ctx) {
                    session.keys = SMBCrypto.sessionKeys(gssKey: gssKey, dialect: d,
                                                         preauthHash: d == SMB2Dialect.smb311 ? session.preauthHash : nil)
                }
                session.isAnonymous = anonymous
                session.signingRequired = config.requireSigning && !anonymous
            } else if anonymous || identity.sid != session.identity.sid {
                throw SMBKitError.status(NTStatus.accessDenied, "re-authentication as another user")
            }
            session.identity = identity
            session.state = .valid
            session.reauthenticating = false
            reply.body = SMB2SessionSetupResponse(sessionFlags: anonymous ? SMB2SessionSetupResponse.isNull : 0,
                                                  securityBuffer: output ?? []).encode()
            if let keys = session.keys, !anonymous { reply.signingKey = keys.signingKey } else { reply.noSign = true }
            if let keys = session.keys, let observe = server.sessionKeyObserver.withLock({ $0 }) { observe(session.id, keys) }
            let mech = context.map { String(describing: $0.mechanism) } ?? "anonymous"
            server.logger.info("SMB \(self.clientAddress, privacy: .public): session \(String(session.id, radix: 16), privacy: .public) for \(identity.description, privacy: .public) via \(mech, privacy: .public), dialect \(SMB2Dialect.name(d), privacy: .public)")
            return reply
        } catch {
            server.logger.info("SMB \(self.clientAddress, privacy: .public): SESSION_SETUP failed: \(String(describing: error), privacy: .public)")
            if session.state == .valid {
                session.reauthenticating = false             // the old authentication stays valid
            } else {
                sessions[session.id] = nil
            }
            var status = NTStatus.logonFailure
            if case AuthKitError.ntlm(let st, _) = error, st == AuthKitError.NTStatus.accessDenied { status = NTStatus.accessDenied }
            if case SMBKitError.status(let st, _) = error { status = st }
            var r = Reply.error(status)
            r.sessionID = session.id
            r.noSign = true
            return r
        }
    }

    /// MS-SMB2 §3.3.5.5.3: the key "queried by the GSS protocol": NTLM's exported session key,
    /// Kerberos' acceptor subkey, else initiator subkey, else ticket session key.
    static func gssSessionKey(_ ctx: any GSSSecurityContext) -> [UInt8]? {
        if let n = ctx as? NTLMSecurityContext { return n.exportedSessionKey }
        if let k = ctx as? KerberosSecurityContext { return k.tokenKey.bytes }
        return nil
    }

    // MARK: - TREE_CONNECT

    private func treeConnect(_ message: [UInt8], session: Session) throws -> Reply {
        let req = try SMB2TreeConnectRequest(parsing: message)
        let name = req.path.split(separator: "\\").last.map(String.init) ?? ""
        guard let share = server.share(named: name) else {
            server.logger.info("SMB \(self.clientAddress, privacy: .public): no share \(req.path, privacy: .public)")
            return .error(NTStatus.badNetworkName)
        }
        if session.isAnonymous && share.kind != .ipc { return .error(NTStatus.accessDenied) }
        let id = session.nextTreeID
        session.nextTreeID &+= 1
        if session.nextTreeID == 0 || session.nextTreeID == .max { session.nextTreeID = 1 }
        session.trees[id] = Tree(id: id, share: share)
        let resp: SMB2TreeConnectResponse
        if share.kind == .ipc {
            resp = SMB2TreeConnectResponse(shareType: SMB2TreeConnectResponse.typePipe,
                                           shareFlags: SMB2TreeConnectResponse.flagNoCaching, capabilities: 0,
                                           maximalAccess: FileAccess.all)
        } else {
            resp = SMB2TreeConnectResponse(shareType: SMB2TreeConnectResponse.typeDisk, shareFlags: 0, capabilities: 0,
                                           maximalAccess: FileAccess.readOnlyMaximal)
        }
        var r = Reply.ok(resp.encode())
        r.treeID = id
        return r
    }

    // MARK: - CREATE / CLOSE

    private func newFileID() -> SMB2FileID {
        defer { nextFileID &+= 1 }
        return SMB2FileID(persistent: nextFileID, volatile: nextFileID)
    }

    private func sessionInfo(_ s: Session) -> SMBSessionInfo {
        SMBSessionInfo(sessionID: s.id, identity: s.identity, sessionKey: s.keys?.applicationKey ?? [UInt8](repeating: 0, count: 16),
                       isGuest: false, clientAddress: clientAddress, dialect: dialect ?? 0, signingRequired: s.signingRequired)
    }

    private func create(_ message: [UInt8], session: Session, tree: Tree) async throws -> Reply {
        let req = try SMB2CreateRequest(parsing: message)
        if tree.isIPC {
            guard let service = server.pipe(named: req.name) else {
                server.logger.info("SMB \(self.clientAddress, privacy: .public): no pipe \(req.name, privacy: .public)")
                return .error(NTStatus.objectNameNotFound)
            }
            let handle = await service.open(session: sessionInfo(session))
            let id = newFileID()
            session.opens[id.volatile] = Open(id: id, treeID: tree.id, kind: .pipe(handle, name: PipeName.normalize(req.name)),
                                              grantedAccess: req.desiredAccess)
            var t = SMB2FileTimes()
            t.allocationSize = 4096
            t.attributes = FileAttributes.normal
            var r = Reply.ok(SMB2CreateResponse(createAction: 1, times: t, fileID: id).encode())
            r.fileID = id
            return r
        }
        guard let resolver = tree.resolver else { return .error(NTStatus.accessDenied) }
        if req.desiredAccess & FileAccess.writeMask != 0 || req.createOptions & 0x1000 != 0 {
            return .error(NTStatus.accessDenied)
        }
        switch resolver.resolve(req.name) {
        case .failed(let status):
            // A file that does not exist can only be created, and this share is read-only.
            if status == NTStatus.objectNameNotFound, ![1, 4].contains(req.createDisposition) {
                return .error(NTStatus.accessDenied)
            }
            return .error(status)
        case .found(let node, let relative):
            switch req.createDisposition {
            case 1, 3: break                                  // FILE_OPEN, FILE_OPEN_IF
            case 2: return .error(NTStatus.objectNameCollision)
            default: return .error(NTStatus.accessDenied)
            }
            if req.createOptions & 0x1 != 0, !node.isDirectory { return .error(NTStatus.notADirectory) }
            if req.createOptions & 0x40 != 0, node.isDirectory { return .error(NTStatus.fileIsADirectory) }
            let id = newFileID()
            let granted = req.desiredAccess & FileAccess.maximumAllowed != 0 || req.desiredAccess & FileAccess.genericRead != 0
                ? FileAccess.readOnlyMaximal : req.desiredAccess & FileAccess.readOnlyMaximal
            session.opens[id.volatile] = Open(id: id, treeID: tree.id, kind: .file(node, relative: relative, resolver: resolver),
                                              grantedAccess: granted)
            var contexts: [SMB2CreateContext] = []
            for c in req.contexts {
                switch c.nameString {
                case "MxAc":
                    contexts.append(SMB2CreateContext(name: c.name, data: FileInfo.u32(0) + FileInfo.u32(FileAccess.readOnlyMaximal)))
                case "QFid":
                    contexts.append(SMB2CreateContext(name: c.name, data: FileInfo.u64(node.inode) + [UInt8](repeating: 0, count: 24)))
                default:
                    break                                      // no leases, no durable handles, no AAPL
                }
            }
            var r = Reply.ok(SMB2CreateResponse(createAction: 1, times: node.times, fileID: id, contexts: contexts).encode())
            r.fileID = id
            return r
        }
    }

    private func close(_ open: Open, flags: UInt16, session: Session) async -> Reply {
        session.opens[open.id.volatile] = nil
        var times = SMB2FileTimes()
        switch open.kind {
        case .pipe(let h, _):
            await h.close()
        case .file(let node, _, _):
            if flags & SMB2CloseRequest.postQueryAttributes != 0 {
                times = (FSNode(path: node.path, name: node.name) ?? node).times
            }
        }
        return .ok(SMB2CloseResponse(flags: flags & SMB2CloseRequest.postQueryAttributes, times: times).encode())
    }

    // MARK: - READ / WRITE

    private func read(_ message: [UInt8], session: Session, tree: Tree, chained: SMB2FileID?) async throws -> Reply {
        let req = try SMB2ReadRequest(parsing: message)
        guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree) else { return .error(NTStatus.fileClosed) }
        let max = dialect == SMB2Dialect.smb202 ? 65536 : Int(config.maxIOSize)
        guard Int(req.length) <= max else { return .error(NTStatus.invalidParameter) }
        switch open.kind {
        case .pipe(let h, _):
            let deadline = ContinuousClock.now + config.pipeReadTimeout
            var data = try await h.read(maxBytes: Int(req.length))
            while data.isEmpty, req.length > 0, ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(2))
                data = try await h.read(maxBytes: Int(req.length))
            }
            if data.isEmpty && req.length > 0 { return .error(NTStatus.pipeEmpty) }
            return .ok(SMB2ReadResponse(data: data).encode())
        case .file(let node, _, _):
            guard !node.isDirectory else { return .error(NTStatus.invalidDeviceRequest) }
            guard open.grantedAccess & (FileAccess.readData | FileAccess.execute) != 0 else { return .error(NTStatus.accessDenied) }
            guard let fh = FileHandle(forReadingAtPath: node.path) else { return .error(NTStatus.accessDenied) }
            defer { try? fh.close() }
            try fh.seek(toOffset: req.offset)
            let data = [UInt8](try fh.read(upToCount: Int(req.length)) ?? Data())
            if data.isEmpty && req.length > 0 || data.count < Int(req.minimumCount) { return .error(NTStatus.endOfFile) }
            return .ok(SMB2ReadResponse(data: data).encode())
        }
    }

    private func write(_ message: [UInt8], session: Session, tree: Tree, chained: SMB2FileID?) async throws -> Reply {
        let req = try SMB2WriteRequest(parsing: message)
        guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree) else { return .error(NTStatus.fileClosed) }
        guard case .pipe(let h, _) = open.kind else { return .error(NTStatus.accessDenied) }
        try await h.write(req.data)
        return .ok(encodeWriteResponse(count: UInt32(req.data.count)))
    }

    // MARK: - IOCTL

    private func ioctl(_ message: [UInt8], session: Session, tree: Tree, chained: SMB2FileID?) async throws -> Reply {
        let req = try SMB2IoctlRequest(parsing: message)
        let maxOut = min(Int(req.maxOutputResponse), Int(config.maxIOSize))
        func out(_ bytes: [UInt8], status: UInt32 = NTStatus.success) -> Reply {
            var r = Reply.ok(SMB2IoctlResponse(ctlCode: req.ctlCode, fileID: req.fileID, output: bytes).encode())
            r.status = status
            return r
        }
        switch req.ctlCode {
        case FSCTL.validateNegotiateInfo:
            // Capabilities(4) Guid(16) SecurityMode(2) DialectCount(2) Dialects(2*n)
            var r = SMBReader(req.input)
            let caps = try r.u32()
            let guid = try r.take(16)
            let mode = try r.u16()
            let n = Int(try r.u16())
            var dialects: [UInt16] = []
            for _ in 0..<n { dialects.append(try r.u16()) }
            guard caps == clientCapabilities, guid == clientGUID, mode == clientSecurityMode, dialects == clientDialects else {
                throw SMBKitError.protocolViolation("VALIDATE_NEGOTIATE_INFO does not match the NEGOTIATE")
            }
            var o: [UInt8] = []
            o.put32(serverCapabilities)
            o += config.serverGUID
            o.put16(serverSecurityMode)
            o.put16(dialect ?? 0)
            return out(o)
        case FSCTL.pipeTransceive:
            guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree) else { return .error(NTStatus.fileClosed) }
            guard case .pipe(let h, _) = open.kind else { return .error(NTStatus.invalidDeviceRequest) }
            let (o, more) = try await h.transceive(req.input, maxOutput: maxOut)
            return out(o, status: more ? NTStatus.bufferOverflow : NTStatus.success)
        case FSCTL.pipeWait:
            // Timeout(8) NameLength(4) TimeoutSpecified(1) Padding(1) Name
            guard tree.isIPC else { return .error(NTStatus.invalidDeviceRequest) }
            var r = SMBReader(req.input)
            try r.skip(8)
            let len = Int(try r.u32())
            try r.skip(2)
            let name = UTF16LE.decode(try r.take(len))
            return server.pipe(named: name) != nil ? out([]) : .error(NTStatus.objectNameNotFound)
        case FSCTL.pipePeek:
            guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree),
                  case .pipe = open.kind else { return .error(NTStatus.invalidDeviceRequest) }
            var o: [UInt8] = []
            o.put32(3)                                         // FILE_PIPE_CONNECTED_STATE
            o.put32(0)
            o.put32(0)
            o.put32(0)
            return out(o)
        case FSCTL.dfsGetReferrals, FSCTL.dfsGetReferralsEx:
            return .error(NTStatus.fsDriverRequired)
        case FSCTL.queryNetworkInterfaceInfo:
            return out(networkInterfaceInfo())
        default:
            return .error(tree.isIPC ? NTStatus.notSupported : NTStatus.invalidDeviceRequest)
        }
    }

    /// NETWORK_INTERFACE_INFO (MS-SMB2 §2.2.32.5): Next(4) IfIndex(4) Capability(4) Reserved(4)
    /// LinkSpeed(8) SockAddr_Storage(128), one entry for the advertised (or local) IPv4.
    private func networkInterfaceInfo() -> [UInt8] {
        var ipv4: [UInt8]?
        if let adv = config.advertisedIPv4 { ipv4 = Self.parseIPv4(adv) }
        if ipv4 == nil, let local = localAddress, local.protocol == .inet, let ip = local.ipAddress { ipv4 = Self.parseIPv4(ip) }
        var b: [UInt8] = []
        b.put32(0)
        b.put32(1)
        b.put32(0)
        b.put32(0)
        b.put64(config.linkSpeed)
        var sa: [UInt8] = [0x02, 0x00, 0x00, 0x00]              // AF_INET (LE 2), port 0
        sa += ipv4 ?? [127, 0, 0, 1]
        sa.zeros(128 - sa.count)
        return b + sa
    }

    static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : nil
    }

    // MARK: - QUERY_INFO

    private func fitted(_ data: [UInt8], max: Int, minimum: Int) -> Reply {
        if data.count <= max { return .ok(SMB2OutputBufferResponse(output: data).encode()) }
        if max < minimum { return .error(NTStatus.infoLengthMismatch) }
        var r = Reply.ok(SMB2OutputBufferResponse(output: Array(data.prefix(max))).encode())
        r.status = NTStatus.bufferOverflow
        return r
    }

    private func queryInfo(_ message: [UInt8], session: Session, tree: Tree, chained: SMB2FileID?) throws -> Reply {
        let req = try SMB2QueryInfoRequest(parsing: message)
        guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree) else { return .error(NTStatus.fileClosed) }
        let max = min(Int(req.outputBufferLength), Int(config.maxIOSize))
        switch open.kind {
        case .pipe:
            guard req.infoType == InfoType.file, req.infoClass == FileInfoClass.standard else { return .error(NTStatus.notSupported) }
            var t = SMB2FileTimes()
            t.allocationSize = 4096
            return fitted(FileInfo.standard(t, isDirectory: false, deletePending: true), max: max, minimum: 24)
        case .file(let stale, let relative, let resolver):
            let node = FSNode(path: stale.path, name: stale.name) ?? stale
            let t = node.times
            switch req.infoType {
            case InfoType.file:
                let data: [UInt8]
                switch req.infoClass {
                case FileInfoClass.basic: data = FileInfo.basic(t)
                case FileInfoClass.standard: data = FileInfo.standard(t, isDirectory: node.isDirectory)
                case FileInfoClass.internal: data = FileInfo.u64(node.inode)
                case FileInfoClass.ea: data = FileInfo.u32(0)
                case FileInfoClass.access: data = FileInfo.u32(open.grantedAccess)
                case FileInfoClass.position: data = FileInfo.u64(0)
                case FileInfoClass.mode: data = FileInfo.u32(0)
                case FileInfoClass.alignment: data = FileInfo.u32(0)
                case FileInfoClass.all:
                    data = FileInfo.all(t, isDirectory: node.isDirectory, index: node.inode, access: open.grantedAccess,
                                        name: "\\" + relative)
                case FileInfoClass.networkOpen: data = FileInfo.networkOpen(t)
                case FileInfoClass.attributeTag: data = FileInfo.attributeTag(t)
                case FileInfoClass.stream: data = FileInfo.streams(t, isDirectory: node.isDirectory)
                case FileInfoClass.normalizedName: data = FileInfo.name(relative)
                case FileInfoClass.alternateName: return .error(NTStatus.objectNameNotFound)
                default: return .error(NTStatus.invalidInfoClass)
                }
                return fitted(data, max: max, minimum: FileInfo.minimumSize(req.infoClass))
            case InfoType.filesystem:
                let v = resolver.volume()
                let data: [UInt8]
                switch req.infoClass {
                case FsInfoClass.volume:
                    let serial = config.serverGUID.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
                    data = FileInfo.fsVolume(label: tree.share.name, serial: serial, created: 0)
                case FsInfoClass.size: data = FileInfo.fsSize(total: v.total, free: 0, blockSize: v.blockSize)
                case FsInfoClass.fullSize: data = FileInfo.fsFullSize(total: v.total, free: 0, blockSize: v.blockSize)
                case FsInfoClass.device: data = FileInfo.fsDevice()
                case FsInfoClass.attribute: data = FileInfo.fsAttribute()
                case FsInfoClass.objectID: data = FileInfo.fsObjectID(config.serverGUID)
                case FsInfoClass.sectorSize: data = FileInfo.fsSectorSize()
                default: return .error(NTStatus.invalidInfoClass)
                }
                return fitted(data, max: max, minimum: min(data.count, 8))
            case InfoType.security:
                let sd = SecurityInfo.descriptor(additionalInformation: req.additionalInformation, isDirectory: node.isDirectory)
                if sd.count > max { return .error(NTStatus.bufferTooSmall, data: FileInfo.u32(UInt32(sd.count))) }
                return .ok(SMB2OutputBufferResponse(output: sd).encode())
            default:
                return .error(NTStatus.invalidParameter)
            }
        }
    }

    // MARK: - QUERY_DIRECTORY

    private func queryDirectory(_ message: [UInt8], session: Session, tree: Tree, chained: SMB2FileID?) throws -> Reply {
        let req = try SMB2QueryDirectoryRequest(parsing: message)
        guard let open = lookup(req.fileID, chained: chained, session: session, tree: tree) else { return .error(NTStatus.fileClosed) }
        guard case .file(let dir, _, let resolver) = open.kind else { return .error(NTStatus.notSupported) }
        guard dir.isDirectory else { return .error(NTStatus.invalidParameter) }
        let supported: [UInt8] = [FileInfoClass.directory, FileInfoClass.fullDirectory, FileInfoClass.bothDirectory,
                                  FileInfoClass.names, FileInfoClass.idBothDirectory, FileInfoClass.idFullDirectory]
        guard supported.contains(req.infoClass) else { return .error(NTStatus.invalidInfoClass) }
        let restart = req.flags & (SMB2QueryDirectoryRequest.restartScans | SMB2QueryDirectoryRequest.reopen) != 0
        let firstQuery = open.searchEntries == nil || restart
        if firstQuery {
            let pattern = req.pattern.isEmpty ? "*" : req.pattern
            var all: [(String, FSNode)] = [(".", dir), ("..", dir)]
            all += resolver.list(dir).map { ($0.name, $0) }
            open.searchEntries = all.filter { Wildcard.matches($0.0, pattern: pattern) }.map { (name: $0.0, node: $0.1) }
            open.searchPosition = 0
        }
        let entries = open.searchEntries ?? []
        let limit = min(Int(req.outputBufferLength), Int(config.maxIOSize))
        var out: [UInt8] = []
        var lastStart: Int?
        var count = 0
        while open.searchPosition < entries.count {
            let e = entries[open.searchPosition]
            guard let entry = FileInfo.directoryEntry(cls: req.infoClass, name: e.name, times: e.node.times, fileID: e.node.inode) else {
                return .error(NTStatus.invalidInfoClass)
            }
            let start = (out.count + 7) & ~7
            guard start + entry.count <= limit else { break }
            out.zeros(start - out.count)
            if let l = lastStart { out.set32(UInt32(start - l), at: l) }
            out += entry
            lastStart = start
            open.searchPosition += 1
            count += 1
            if req.flags & SMB2QueryDirectoryRequest.returnSingleEntry != 0 { break }
        }
        if count == 0 {
            if entries.isEmpty && firstQuery { return .error(NTStatus.noSuchFile) }
            if open.searchPosition >= entries.count { return .error(NTStatus.noMoreFiles) }
            return .error(NTStatus.infoLengthMismatch)
        }
        return .ok(SMB2OutputBufferResponse(output: out).encode())
    }
}

/// The security descriptor of every file of a read-only share (self-relative, MS-DTYP
/// §2.4.6): owner BUILTIN\Administrators, group SYSTEM, DACL SYSTEM and Administrators full
/// control, Authenticated Users read and execute (inherited to children of directories).
enum SecurityInfo {
    static let owner: UInt32 = 0x1, group: UInt32 = 0x2, dacl: UInt32 = 0x4, sacl: UInt32 = 0x8

    static let administrators: [UInt8] = [1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0]
    static let system: [UInt8] = [1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0]
    static let authenticatedUsers: [UInt8] = [1, 1, 0, 0, 0, 0, 0, 5, 0x0B, 0, 0, 0]

    static func descriptor(additionalInformation info: UInt32, isDirectory: Bool) -> [UInt8] {
        let want = info == 0 ? owner | group | dacl : info
        var control: UInt16 = 0x8000                          // SE_SELF_RELATIVE
        var tail: [UInt8] = []
        var ownerOff: UInt32 = 0, groupOff: UInt32 = 0, daclOff: UInt32 = 0
        if want & owner != 0 {
            ownerOff = UInt32(20 + tail.count)
            tail += administrators
        }
        if want & group != 0 {
            groupOff = UInt32(20 + tail.count)
            tail += system
        }
        if want & dacl != 0 {
            control |= 0x0004                                 // SE_DACL_PRESENT
            daclOff = UInt32(20 + tail.count)
            let flags: UInt8 = isDirectory ? 0x03 : 0x00       // OBJECT_INHERIT | CONTAINER_INHERIT
            let aces = ace(flags, FileAccess.all, system) + ace(flags, FileAccess.all, administrators)
                + ace(flags, FileAccess.readOnlyMaximal, authenticatedUsers)
            var acl: [UInt8] = [2, 0]
            acl.put16(UInt16(8 + aces.count))
            acl.put16(3)
            acl.put16(0)
            tail += acl + aces
        }
        var b: [UInt8] = [1, 0]
        b.put16(control)
        b.put32(ownerOff)
        b.put32(groupOff)
        b.put32(0)
        b.put32(daclOff)
        return b + tail
    }

    /// ACCESS_ALLOWED_ACE: AceType 0 | AceFlags | AceSize(2) | Mask(4) | SID.
    static func ace(_ flags: UInt8, _ mask: UInt32, _ sid: [UInt8]) -> [UInt8] {
        var a: [UInt8] = [0, flags]
        a.put16(UInt16(8 + sid.count))
        a.put32(mask)
        return a + sid
    }
}
