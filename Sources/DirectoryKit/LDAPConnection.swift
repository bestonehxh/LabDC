import AuthKit
import Foundation
import LDAPCore
import MSPAC
import NIOCore
import NIOSSL
import Store

/// Who is bound on a connection.
struct BoundIdentity: Sendable {
    /// The account's object (nil for identities the store does not hold).
    var entryID: ObjectID?
    var dn: DN?
    var identity: AuthenticatedIdentity
    /// Administrator, Domain/Enterprise Admins or BUILTIN\Administrators: full access.
    var isAdmin: Bool
    /// Member of BUILTIN\Account Operators (S-1-5-32-548): manages unprotected users, groups
    /// and computers.
    var isAccountOperator: Bool = false
}

/// One LDAP connection: its state (bound identity, SASL exchange and layer, TLS, paged-search
/// cookies) and the serial processing of its requests. Lives on the connection's task.
final class LDAPConnection {
    let channel: Channel
    let server: ServerContext
    let kind: ListenerKind

    var bound: BoundIdentity?
    var isTLS: Bool
    var saslQOP: SASLQOP?
    /// The SASL exchange in progress. `started` is false while the server has only answered an
    /// empty first leg (RFC 4513 §5.2.1.2) and the mechanism has not consumed a token yet.
    var saslExchange: (mechanism: String, server: any SASLServer, started: Bool)?
    var pagedSearches: [[UInt8]: PagedSearch] = [:]
    var closed = false

    struct PagedSearch {
        var key: String
        var lastID: ObjectID
    }

    var store: DirectoryStore { server.store }
    var info: DomainInfo { server.info }
    var config: DirectoryServerConfig { server.config }

    /// `unicodePwd` and friends need TLS or a sealed SASL layer.
    var isConfidential: Bool { isTLS || saslQOP == .confidentiality }

    init(channel: Channel, server: ServerContext, kind: ListenerKind) {
        self.channel = channel
        self.server = server
        self.kind = kind
        isTLS = kind.usesTLS
    }

    func run(_ messages: AsyncStream<[UInt8]>) async {
        for await bytes in messages {
            await handle(bytes)
            if closed { break }
        }
    }

    // MARK: Output

    func send(_ message: LDAPMessage, flush: Bool = true) {
        let buffer = channel.allocator.buffer(bytes: message.encoded())
        if flush { channel.writeAndFlush(buffer, promise: nil) } else { channel.write(buffer, promise: nil) }
    }

    /// Sends `message`, then changes the pipeline in the same event-loop turn, so that the
    /// response leaves unprotected and everything after it goes through the new handler.
    func send(_ message: LDAPMessage, thenInstall install: @escaping @Sendable (Channel) throws -> Void) async throws {
        let channel = self.channel
        let buffer = channel.allocator.buffer(bytes: message.encoded())
        try await channel.eventLoop.submit {
            channel.writeAndFlush(buffer, promise: nil)
            try install(channel)
        }.get()
    }

    func close() {
        closed = true
        channel.close(promise: nil)
    }

    /// Notice of Disconnection (RFC 4511 §4.4.1), then close.
    func disconnect(_ code: LDAPResultCode, _ reason: String) {
        send(LDAPMessage(messageID: 0, .extendedResponse(ExtendedResponse(
            result: LDAPResult(code, diagnosticMessage: reason), name: LDAPExtendedOID.noticeOfDisconnection))))
        close()
    }

    // MARK: Dispatch

    /// Controls the server honours; any other control marked critical fails the operation
    /// with `unavailableCriticalExtension` (server-side sort included).
    static let knownControls: Set<String> = [
        LDAPControlOID.pagedResults, LDAPControlOID.sdFlags, LDAPControlOID.showDeleted, LDAPControlOID.showRecycled,
        LDAPControlOID.permissiveModify, LDAPControlOID.treeDelete, LDAPControlOID.domainScope, LDAPControlOID.lazyCommit,
        LDAPControlOID.manageDsaIT,
    ]

    func handle(_ bytes: [UInt8]) async {
        let message: LDAPMessage
        do {
            message = try LDAPMessage(bytes: bytes)
        } catch {
            server.logger.info("undecodable LDAP message: \(String(describing: error), privacy: .public)")
            disconnect(.protocolError, "00002024: LdapErr: DSID-0C0C0D3F, comment: \(error), data 0, \(ADDiagnostic.version)")
            return
        }
        let id = message.messageID
        server.logger.debug("LDAP #\(id) \(message.operation.name, privacy: .public)")

        if let critical = message.controls.first(where: { $0.critical && !Self.knownControls.contains($0.oid) }),
           let reply = Self.response(to: message.operation, LDAPResult(.unavailableCriticalExtension, diagnosticMessage: ADDiagnostic.criticalControl)) {
            server.logger.info("LDAP #\(id): unsupported critical control \(critical.oid, privacy: .public)")
            send(LDAPMessage(messageID: id, reply))
            return
        }

        switch message.operation {
        case .unbindRequest:
            close()
            return
        case .abandonRequest:
            // Requests run to completion one at a time; nothing is outstanding to abandon.
            return
        case .bindRequest(let r):
            await bind(message, r)
            return
        case .unrecognized, .bindResponse, .searchResultEntry, .searchResultDone, .searchResultReference, .modifyResponse,
             .addResponse, .deleteResponse, .modifyDNResponse, .compareResponse, .extendedResponse, .intermediateResponse:
            disconnect(.protocolError, "00002024: LdapErr: DSID-0C0C0D3F, comment: unexpected \(message.operation.name), data 0, \(ADDiagnostic.version)")
            return
        default:
            break
        }

        do {
            switch message.operation {
            case .searchRequest(let r): try await search(message, r)
            case .modifyRequest(let r): try await modify(message, r)
            case .addRequest(let r): try await add(message, r)
            case .deleteRequest(let dn): try await delete(message, dn)
            case .modifyDNRequest(let r): try await modifyDN(message, r)
            case .compareRequest(let r): try await compare(message, r)
            case .extendedRequest(let r): try await extended(message, r)
            default: break
            }
        } catch {
            let result = Self.result(for: error)
            if result.resultCode == .other {
                server.logger.error("LDAP #\(id) \(message.operation.name, privacy: .public): \(String(describing: error), privacy: .public)")
            } else {
                server.logger.info("LDAP #\(id) \(message.operation.name, privacy: .public): \(result.resultCode) \(String(describing: error), privacy: .public)")
            }
            if let reply = Self.response(to: message.operation, result) { send(LDAPMessage(messageID: id, reply)) }
        }
    }

    static func result(for error: Error) -> LDAPResult {
        switch error {
        case let f as LDAPFailure: f.result
        case let s as StoreError: ADDiagnostic.failure(for: s).result
        default: LDAPResult(.other, diagnosticMessage: ADDiagnostic.operationsError)
        }
    }

    /// The response operation that answers `request` with `result`.
    static func response(to request: LDAPOperation, _ result: LDAPResult) -> LDAPOperation? {
        switch request {
        case .bindRequest: .bindResponse(BindResponse(result: result))
        case .searchRequest: .searchResultDone(result)
        case .modifyRequest: .modifyResponse(result)
        case .addRequest: .addResponse(result)
        case .deleteRequest: .deleteResponse(result)
        case .modifyDNRequest: .modifyDNResponse(result)
        case .compareRequest: .compareResponse(result)
        case .extendedRequest: .extendedResponse(ExtendedResponse(result: result))
        default: nil
        }
    }

    // MARK: Helpers shared by the operations

    func requireBound() throws -> BoundIdentity {
        guard let bound else { throw LDAPFailure(.operationsError, ADDiagnostic.bindRequired) }
        return bound
    }

    func parseDN(_ text: String) throws -> DN {
        do { return try DN(string: text) } catch { throw LDAPFailure(.invalidDNSyntax, ADDiagnostic.invalidDN(text)) }
    }

    /// The deepest existing ancestor of `dn` (the `matchedDN` of a noSuchObject result).
    func bestMatch(_ dn: DN) async -> String {
        var cursor = dn.parent
        while let c = cursor, !c.isRoot {
            if let found = try? await store.id(of: c), found > 0 { return c.description }
            cursor = c.parent
        }
        return ""
    }

    func noSuchObject(_ dn: DN) async -> LDAPFailure {
        let match = await bestMatch(dn)
        return LDAPFailure(.noSuchObject, ADDiagnostic.noSuchObject(bestMatch: match), matchedDN: match)
    }

    /// Reads `dn` or throws noSuchObject with the best match.
    func requireEntry(_ dn: DN, includeDeleted: Bool = false) async throws -> DirectoryEntry {
        guard let e = try await store.read(dn: dn, includeDeleted: includeDeleted) else { throw await noSuchObject(dn) }
        return e
    }

    /// Runs a store call, mapping a noSuchObject to one with the best match of `dn`.
    func storeCall<T>(_ dn: DN, _ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch StoreError.noSuchObject {
            throw await noSuchObject(dn)
        }
    }

    /// Builds the bound identity for an account entry (and the identity AuthKit returned).
    func boundIdentity(entry: DirectoryEntry?, identity: AuthenticatedIdentity) async -> BoundIdentity {
        var groups = Set(identity.groups)
        if let entry { groups.formUnion((try? await store.groupSIDs(of: entry.id)) ?? []) }
        let domain = info.domainSID
        let adminSIDs: [SID] = [512, 519].compactMap { try? domain.appending(rid: $0) }
            + [try? SID(string: "S-1-5-32-544")].compactMap { $0 }
        let isAdmin = identity.sid == (try? domain.appending(rid: 500)) || adminSIDs.contains { groups.contains($0) }
        let isOperator = Self.builtinAccountOperators.map { groups.contains($0) } ?? false
        return BoundIdentity(entryID: entry?.id, dn: entry?.dn, identity: identity, isAdmin: isAdmin, isAccountOperator: isOperator)
    }
}
