import os

/// SPNEGO acceptor (RFC 4178, MS-SPNG) over the Kerberos acceptor and the NTLM server.
///
/// - The mechanism is the first one in the client's list we support (Kerberos under either
///   OID, then NTLMSSP). The OID the client used is echoed in `supportedMech`, so a client
///   that listed the MS KRB5 OID first gets it back (Windows expects that).
/// - The optimistic token is used only when the chosen mechanism is the client's first
///   choice; otherwise the first reply is `request-mic` with no token (RFC 4178 §5).
/// - mechListMIC (over the MechTypeList DER as received) is exchanged when the mechanism
///   was not the client's first choice, when the client sent one, or when the mechanism is
///   "new SPNEGO" (Kerberos with an RFC 4121 key, NTLM with a verified AUTHENTICATE MIC),
///   as Samba does. A client MIC is always verified when one arrives.
/// - Kerberos chosen as the client's first mechanism completes in one reply:
///   `accept-completed` + AP-REP and no mechListMIC (Samba; a MIC here makes Windows owe
///   one back in a leg SMB does not have). If the client sent a MIC with its optimistic
///   token, ours goes back with the AP-REP. Otherwise, if the client has not sent its MIC yet, the
///   reply is `accept-incomplete` with ours, and `accept-completed` follows the client's MIC
///   (RFC 4178 §5 requires that exchange when the mechanism was not the client's first).
public struct SPNEGOAcceptor: Sendable {
    public enum Step: Sendable {
        /// Send this token and wait for the next one.
        case `continue`([UInt8])
        /// Authentication finished. `output` (if any) still goes to the client. `context` is
        /// `nil` only for NTLM anonymous logons.
        case complete(output: [UInt8]?, identity: AuthenticatedIdentity, context: (any GSSSecurityContext)?)
    }

    public let kerberos: KerberosAcceptor?
    public private(set) var ntlm: NTLMServer?

    private enum State: Sendable {
        case start
        case mech
        case awaitingMIC(identity: AuthenticatedIdentity, context: any GSSSecurityContext)
        case done
    }

    private var state: State = .start
    private var chosen: GSSMechanism?
    private var clientFirst: GSSMechanism?
    private var mechTypesDER: [UInt8] = []
    private var sentFirstReply = false
    private var ntlmChallengeSent = false

    static let logger = Logger(subsystem: "dev.labdc.app", category: "AuthKit")

    public init(kerberos: KerberosAcceptor?, ntlm: NTLMServer?) {
        self.kerberos = kerberos
        self.ntlm = ntlm
    }

    /// The mechanism negotiated so far.
    public var negotiatedMechanism: GSSMechanism? { chosen }
    /// The mechanism's context once it is established (also while waiting for the client's
    /// mechListMIC).
    public private(set) var context: (any GSSSecurityContext)?

    /// `negTokenResp { negState reject }`, for a caller that wants to answer a failure.
    public static let rejectToken = SPNEGOToken.response(.init(negState: .reject)).encode()

    public mutating func step(_ token: [UInt8]) async throws -> Step {
        switch state {
        case .start:
            guard case .initial(let initial) = try SPNEGOToken(bytes: token) else {
                throw AuthKitError.negotiation("first token is not negTokenInit")
            }
            mechTypesDER = initial.mechTypesDER
            clientFirst = initial.mechTypes.first
            guard let pick = initial.mechTypes.first(where: supports) else {
                state = .done
                throw AuthKitError.negotiation("no common mechanism in \(initial.mechTypes)")
            }
            chosen = pick
            state = .mech
            if pick == clientFirst, let mechToken = initial.mechToken {
                return try await runMech(mechToken, clientMIC: initial.mechListMIC)
            }
            return .continue(reply(pick == clientFirst ? .acceptIncomplete : .requestMIC, token: nil, mic: nil))

        case .mech:
            guard case .response(let resp) = try SPNEGOToken(bytes: token) else {
                throw AuthKitError.negotiation("expected negTokenResp")
            }
            guard let t = resp.responseToken else { throw AuthKitError.negotiation("negTokenResp without a mech token") }
            return try await runMech(t, clientMIC: resp.mechListMIC)

        case .awaitingMIC(let identity, let context):
            guard case .response(let resp) = try SPNEGOToken(bytes: token), let mic = resp.mechListMIC else {
                throw AuthKitError.negotiation("expected the client's mechListMIC")
            }
            try verifyMIC(mic, context: context)
            state = .done
            return .complete(output: reply(.acceptCompleted, token: nil, mic: nil), identity: identity, context: context)

        case .done:
            throw AuthKitError.invalidState("SPNEGO exchange already finished")
        }
    }

    private func supports(_ m: GSSMechanism) -> Bool {
        (m.isKerberos && kerberos != nil) || (m == .ntlm && ntlm != nil)
    }

    private mutating func reply(_ s: SPNEGOToken.NegState, token: [UInt8]?, mic: [UInt8]?) -> [UInt8] {
        let mech = sentFirstReply ? nil : chosen
        sentFirstReply = true
        return SPNEGOToken.response(.init(negState: s, supportedMech: mech, responseToken: token, mechListMIC: mic)).encode()
    }

    private mutating func runMech(_ token: [UInt8], clientMIC: [UInt8]?) async throws -> Step {
        guard let chosen else { throw AuthKitError.invalidState("no mechanism") }
        if chosen.isKerberos, let kerberos {
            let r = try await kerberos.accept(token)
            return try finish(identity: r.identity, context: r.context, mechOutput: r.outputToken, clientMIC: clientMIC,
                              newSPNEGO: r.context.usesCFX)
        }
        guard var server = ntlm else { throw AuthKitError.invalidState("NTLM not configured") }
        if !ntlmChallengeSent {
            let challenge = try server.challenge(for: token)
            ntlm = server
            ntlmChallengeSent = true
            return .continue(reply(.acceptIncomplete, token: challenge, mic: nil))
        }
        let r = try await server.authenticate(token)
        guard let context = r.context else {
            state = .done
            return .complete(output: reply(.acceptCompleted, token: nil, mic: nil), identity: r.identity, context: nil)
        }
        return try finish(identity: r.identity, context: context, mechOutput: nil, clientMIC: clientMIC,
                          newSPNEGO: r.micVerified)
    }

    private func verifyMIC(_ mic: [UInt8], context: any GSSSecurityContext) throws {
        do {
            if let n = context as? NTLMSecurityContext {
                try n.withPreservedCipherState { try n.verifyMIC(mechTypesDER, token: mic) }
            } else {
                try context.verifyMIC(mechTypesDER, token: mic)
            }
        } catch {
            throw AuthKitError.negotiation("mechListMIC does not verify (\(error))")
        }
    }

    private func makeMIC(_ context: any GSSSecurityContext) throws -> [UInt8] {
        if let n = context as? NTLMSecurityContext {
            return try n.withPreservedCipherState { try n.getMIC(mechTypesDER) }
        }
        return try context.getMIC(mechTypesDER)
    }

    private mutating func finish(identity: AuthenticatedIdentity, context: any GSSSecurityContext, mechOutput: [UInt8]?,
                                 clientMIC: [UInt8]?, newSPNEGO: Bool) throws -> Step {
        self.context = context
        if let clientMIC { try verifyMIC(clientMIC, context: context) }
        let needMIC = chosen != clientFirst || clientMIC != nil || newSPNEGO
        let mechName = chosen?.description ?? "?"
        Self.logger.info("SPNEGO: \(mechName, privacy: .public) complete for \(identity.description, privacy: .public), mic=\(needMIC)")
        guard needMIC else {
            state = .done
            return .complete(output: reply(.acceptCompleted, token: mechOutput, mic: nil), identity: identity, context: context)
        }
        // Kerberos picked as the client's first choice, and the client sent no MIC: complete now
        // with accept-completed + AP-REP and *no* mechListMIC (Samba
        // gensec_spnego_server_negTokenInit_finish). If we sent a MIC, Windows would owe us
        // its own (MS-SPNG <8>, MIT process_mic: "if we got a MIC, we must send a MIC") and
        // need another leg, which SMB does not have after STATUS_SUCCESS: it resets the
        // connection (docs/notes/wp-aa.md). Only a mechanism that was not the client's first
        // choice must exchange MICs (RFC 4178 §5).
        let optimisticKerberos = chosen?.isKerberos == true && chosen == clientFirst
        if optimisticKerberos && clientMIC == nil {
            state = .done
            return .complete(output: reply(.acceptCompleted, token: mechOutput, mic: nil), identity: identity, context: context)
        }
        let ours = try makeMIC(context)
        if clientMIC != nil {
            state = .done
            return .complete(output: reply(.acceptCompleted, token: mechOutput, mic: ours), identity: identity, context: context)
        }
        state = .awaitingMIC(identity: identity, context: context)
        return .continue(reply(.acceptIncomplete, token: mechOutput, mic: ours))
    }
}
