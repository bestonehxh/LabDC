import os

/// One SASL server step.
public enum SASLStep: Sendable {
    /// Send `output` as the server challenge (LDAP: `saslBindInProgress` + serverSaslCreds).
    case `continue`([UInt8])
    /// Authentication succeeded. `output` (if any) goes with the success result; install
    /// `layer` on the connection after that response has been sent.
    case complete(output: [UInt8]?, identity: AuthenticatedIdentity, layer: SASLSecurityLayer?)
}

/// A server-side SASL mechanism (RFC 4422). Feed each client response to `step`.
public protocol SASLServer: Sendable {
    /// The IANA name (`GSSAPI`, `GSS-SPNEGO`).
    var mechanism: String { get }
    mutating func step(_ input: [UInt8]) async throws -> SASLStep
}

/// SASL quality of protection (RFC 4752 §3.1 security-layer bits).
public enum SASLQOP: UInt8, Sendable, Hashable, CustomStringConvertible {
    case none = 1
    case integrity = 2
    case confidentiality = 4

    public var description: String {
        switch self {
        case .none: "none"
        case .integrity: "integrity"
        case .confidentiality: "confidentiality"
        }
    }
}

/// The negotiated security layer: every SASL buffer after the bind is
/// `length (4, BE) | wrap(plaintext)` (RFC 4422 §3.7, RFC 4752 §3.3).
public final class SASLSecurityLayer: Sendable {
    /// `.integrity` or `.confidentiality`.
    public let qop: SASLQOP
    /// Largest buffer the peer accepts from us (0 = no limit announced).
    public let maxSendSize: UInt32
    /// Largest buffer we accept (what we announced).
    public let maxReceiveSize: UInt32
    public let context: any GSSSecurityContext

    public init(qop: SASLQOP, maxSendSize: UInt32, maxReceiveSize: UInt32, context: any GSSSecurityContext) {
        self.qop = qop
        self.maxSendSize = maxSendSize
        self.maxReceiveSize = maxReceiveSize
        self.context = context
    }

    /// Wraps one outgoing buffer (without the 4-byte length).
    public func wrap(_ plaintext: [UInt8]) throws -> [UInt8] {
        try context.wrap(plaintext, confidential: qop == .confidentiality)
    }

    /// Unwraps one incoming buffer (without the 4-byte length). With `.confidentiality`, an
    /// unencrypted token is refused.
    public func unwrap(_ token: [UInt8]) throws -> [UInt8] {
        if maxReceiveSize > 0, token.count > Int(maxReceiveSize) {
            throw AuthKitError.sasl("buffer of \(token.count) bytes exceeds the negotiated \(maxReceiveSize)")
        }
        let (message, confidential) = try context.unwrap(token)
        if qop == .confidentiality, !confidential { throw AuthKitError.sasl("unencrypted buffer on a sealed layer") }
        return message
    }

    /// `length (4, BE) | wrap(plaintext)`.
    public func frame(_ plaintext: [UInt8]) throws -> [UInt8] {
        let w = try wrap(plaintext)
        var out: [UInt8] = []
        out.appendBE32(UInt32(w.count))
        return out + w
    }

    /// Splits complete `length | token` buffers off the front of `buffer` and unwraps them.
    /// Leaves an incomplete tail in `buffer`.
    public func deframe(_ buffer: inout [UInt8]) throws -> [[UInt8]] {
        var out: [[UInt8]] = []
        while buffer.count >= 4 {
            let len = Int(buffer.be32(0))
            if maxReceiveSize > 0, len > Int(maxReceiveSize) + 64 {
                throw AuthKitError.sasl("announced buffer of \(len) bytes is too large")
            }
            guard buffer.count >= 4 + len else { break }
            out.append(try unwrap(Array(buffer[4..<(4 + len)])))
            buffer.removeFirst(4 + len)
        }
        return out
    }
}

/// The set of layers a server offers (RFC 4752 bitmask).
public struct SASLLayers: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let none = SASLLayers(rawValue: 1)
    public static let integrity = SASLLayers(rawValue: 2)
    public static let confidentiality = SASLLayers(rawValue: 4)
    public static let all: SASLLayers = [.none, .integrity, .confidentiality]
}

/// SASL `GSSAPI` (RFC 4752) over the Kerberos acceptor.
///
/// 1. client: initial context token → server: AP-REP (or, without mutual auth, step 2's offer)
/// 2. client: empty → server: wrap(conf=false, `layers (1) | max buffer (3, BE)`)
/// 3. client: wrap(`chosen layer (1) | max buffer (3) | authzid`) → server: success
public struct GSSAPISASLServer: SASLServer {
    public let mechanism = "GSSAPI"
    public let acceptor: KerberosAcceptor
    public let offeredLayers: SASLLayers
    public let maxReceiveSize: UInt32
    /// The authorization identity the client asked for in step 3 (empty = none).
    public private(set) var authorizationID: String = ""

    private enum State: Sendable {
        case start
        case awaitingEmpty(KerberosAcceptResult)
        case offered(KerberosAcceptResult)
        case done
    }

    private var state: State = .start

    /// - Parameter maxReceiveSize: must fit 24 bits; Windows DCs announce 0x989680 (10 MB).
    public init(acceptor: KerberosAcceptor, offeredLayers: SASLLayers = .all, maxReceiveSize: UInt32 = 0x0098_9680) {
        self.acceptor = acceptor
        self.offeredLayers = offeredLayers
        self.maxReceiveSize = min(maxReceiveSize, 0x00FF_FFFF)
    }

    private func offer(_ r: KerberosAcceptResult) throws -> [UInt8] {
        var msg: [UInt8] = [offeredLayers.rawValue]
        let size = offeredLayers == .none ? 0 : maxReceiveSize
        msg += [UInt8((size >> 16) & 0xFF), UInt8((size >> 8) & 0xFF), UInt8(size & 0xFF)]
        return try r.context.wrap(msg, confidential: false)
    }

    public mutating func step(_ input: [UInt8]) async throws -> SASLStep {
        switch state {
        case .start:
            let r = try await acceptor.accept(input)
            if let out = r.outputToken {
                state = .awaitingEmpty(r)
                return .continue(out)
            }
            state = .offered(r)
            return .continue(try offer(r))
        case .awaitingEmpty(let r):
            // RFC 4752: the client answers the final context token with an empty response.
            state = .offered(r)
            return .continue(try offer(r))
        case .offered(let r):
            state = .done
            let (msg, _) = try r.context.unwrap(input)
            guard msg.count >= 4 else { throw AuthKitError.sasl("security-layer response shorter than 4 bytes") }
            let chosen = SASLLayers(rawValue: msg[0])
            guard [SASLLayers.none, .integrity, .confidentiality].contains(chosen), offeredLayers.contains(chosen) else {
                throw AuthKitError.sasl("client chose layer bits 0x\(String(msg[0], radix: 16)), offered 0x\(String(offeredLayers.rawValue, radix: 16))")
            }
            let clientMax = UInt32(msg[1]) << 16 | UInt32(msg[2]) << 8 | UInt32(msg[3])
            authorizationID = String(decoding: msg[4...], as: UTF8.self)
            var layer: SASLSecurityLayer?
            if chosen != .none {
                layer = SASLSecurityLayer(qop: chosen == .confidentiality ? .confidentiality : .integrity,
                                          maxSendSize: clientMax, maxReceiveSize: maxReceiveSize, context: r.context)
            }
            return .complete(output: nil, identity: r.identity, layer: layer)
        case .done:
            throw AuthKitError.invalidState("GSSAPI exchange already finished")
        }
    }
}

/// SASL `GSS-SPNEGO` (MS-ADTS: SPNEGO carrying Kerberos or NTLM). There is no RFC 4752
/// layer exchange: the layer is the mechanism's own wrap, chosen by the context flags the
/// client asked for (confidentiality → sealed, integrity → signed, neither → none).
public struct GSSSPNEGOSASLServer: SASLServer {
    public let mechanism = "GSS-SPNEGO"
    public private(set) var spnego: SPNEGOAcceptor
    public let maxBufferSize: UInt32

    public init(spnego: SPNEGOAcceptor, maxBufferSize: UInt32 = 0x0098_9680) {
        self.spnego = spnego
        self.maxBufferSize = maxBufferSize
    }

    public mutating func step(_ input: [UInt8]) async throws -> SASLStep {
        switch try await spnego.step(input) {
        case .continue(let out):
            return .continue(out)
        case .complete(let out, let identity, let context):
            var layer: SASLSecurityLayer?
            if let context {
                if context.flags.contains(.confidentiality) {
                    layer = SASLSecurityLayer(qop: .confidentiality, maxSendSize: maxBufferSize, maxReceiveSize: maxBufferSize,
                                              context: context)
                } else if context.flags.contains(.integrity) {
                    layer = SASLSecurityLayer(qop: .integrity, maxSendSize: maxBufferSize, maxReceiveSize: maxBufferSize,
                                              context: context)
                }
            }
            return .complete(output: out, identity: identity, layer: layer)
        }
    }
}
