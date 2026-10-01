import SwiftASN1

/// RFC 4178 negotiation tokens.
///
/// ```
/// NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, negTokenResp [1] NegTokenResp }
/// NegTokenInit ::= SEQUENCE {
///     mechTypes   [0] MechTypeList,            -- SEQUENCE OF OID
///     reqFlags    [1] ContextFlags OPTIONAL,   -- BIT STRING
///     mechToken   [2] OCTET STRING OPTIONAL,
///     mechListMIC [3] OCTET STRING OPTIONAL }  -- MS NegTokenInit2: [3] negHints SEQUENCE, [4] mechListMIC
/// NegTokenResp ::= SEQUENCE {
///     negState      [0] ENUMERATED { accept-completed(0), accept-incomplete(1), reject(2), request-mic(3) } OPTIONAL,
///     supportedMech [1] OID OPTIONAL,
///     responseToken [2] OCTET STRING OPTIONAL,
///     mechListMIC   [3] OCTET STRING OPTIONAL }
/// ```
/// The initiator's first token is framed `60 … 06 06 2b0601050502 a0 …`; everything after is
/// a bare `a1 …`.
public enum SPNEGOToken: Sendable, Hashable {
    case initial(NegTokenInit)
    case response(NegTokenResp)

    public struct NegTokenInit: Sendable, Hashable {
        public var mechTypes: [GSSMechanism]
        /// DER of the MechTypeList exactly as received (the mechListMIC input).
        public var mechTypesDER: [UInt8]
        public var reqFlags: [UInt8]?
        public var mechToken: [UInt8]?
        public var mechListMIC: [UInt8]?

        public init(mechTypes: [GSSMechanism], mechToken: [UInt8]? = nil, mechListMIC: [UInt8]? = nil) {
            self.mechTypes = mechTypes
            self.mechTypesDER = SPNEGOToken.mechTypeListDER(mechTypes)
            self.mechToken = mechToken
            self.mechListMIC = mechListMIC
        }
    }

    public enum NegState: Int, Sendable, Hashable {
        case acceptCompleted = 0, acceptIncomplete = 1, reject = 2, requestMIC = 3
    }

    public struct NegTokenResp: Sendable, Hashable {
        public var negState: NegState?
        public var supportedMech: GSSMechanism?
        public var responseToken: [UInt8]?
        public var mechListMIC: [UInt8]?

        public init(negState: NegState? = nil, supportedMech: GSSMechanism? = nil, responseToken: [UInt8]? = nil,
                    mechListMIC: [UInt8]? = nil) {
            self.negState = negState
            self.supportedMech = supportedMech
            self.responseToken = responseToken
            self.mechListMIC = mechListMIC
        }
    }

    // MARK: Encoding (hand-written DER)

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { [tag] + DERLength.encode(content.count) + content }

    public static func mechTypeListDER(_ mechs: [GSSMechanism]) -> [UInt8] {
        tlv(0x30, mechs.flatMap(\.oidDER))
    }

    /// Encodes the token. `.initial` is framed with the SPNEGO OID (as the initiator sends it).
    public func encode() -> [UInt8] {
        switch self {
        case .initial(let i):
            var body = Self.tlv(0xA0, i.mechTypesDER)
            if let f = i.reqFlags { body += Self.tlv(0xA1, f) }
            if let t = i.mechToken { body += Self.tlv(0xA2, Self.tlv(0x04, t)) }
            if let m = i.mechListMIC { body += Self.tlv(0xA3, Self.tlv(0x04, m)) }
            return GSSFraming.wrap(mech: .spnego, Self.tlv(0xA0, Self.tlv(0x30, body)))
        case .response(let r):
            var body: [UInt8] = []
            if let s = r.negState { body += Self.tlv(0xA0, [0x0A, 0x01, UInt8(s.rawValue)]) }
            if let m = r.supportedMech { body += Self.tlv(0xA1, m.oidDER) }
            if let t = r.responseToken { body += Self.tlv(0xA2, Self.tlv(0x04, t)) }
            if let m = r.mechListMIC { body += Self.tlv(0xA3, Self.tlv(0x04, m)) }
            return Self.tlv(0xA1, Self.tlv(0x30, body))
        }
    }

    // MARK: Decoding

    /// Decodes a framed negTokenInit or a bare `a0`/`a1` token.
    public init(bytes: [UInt8]) throws {
        var inner = bytes
        if bytes.first == 0x60 {
            let (mech, rest) = try GSSFraming.unwrap(bytes)
            guard mech == .spnego else { throw AuthKitError.negotiation("framed token is \(mech), not SPNEGO") }
            inner = rest
        }
        do {
            let root = try DER.parse(inner)
            guard root.identifier.tagClass == .contextSpecific else {
                throw AuthKitError.malformed(what: "SPNEGO token", reason: "not [0] or [1]")
            }
            switch root.identifier.tagNumber {
            case 0: self = .initial(try Self.parseInit(root))
            case 1: self = .response(try Self.parseResp(root))
            default: throw AuthKitError.malformed(what: "SPNEGO token", reason: "tag [\(root.identifier.tagNumber)]")
            }
        } catch let e as AuthKitError {
            throw e
        } catch {
            throw AuthKitError.malformed(what: "SPNEGO token", reason: "\(error)")
        }
    }

    static func octets(_ node: ASN1Node) throws -> [UInt8] { Array(try ASN1OctetString(derEncoded: node).bytes) }

    static func oidContent(_ node: ASN1Node) throws -> [UInt8] {
        guard node.identifier == .objectIdentifier, case .primitive(let b) = node.content else {
            throw AuthKitError.malformed(what: "SPNEGO", reason: "expected an OID")
        }
        return Array(b)
    }

    static func parseInit(_ root: ASN1Node) throws -> NegTokenInit {
        try DER.explicitlyTagged(root, tagNumber: 0, tagClass: .contextSpecific) { seq in
            try DER.sequence(seq, identifier: .sequence) { nodes in
                var mechTypes: [GSSMechanism] = []
                var mechTypesDER: [UInt8] = []
                try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { list in
                    mechTypesDER = Array(list.encodedBytes)
                    guard case .constructed(let children) = list.content, list.identifier == .sequence else {
                        throw AuthKitError.malformed(what: "MechTypeList", reason: "not a SEQUENCE")
                    }
                    for c in children { mechTypes.append(GSSMechanism(oidContent: try oidContent(c))) }
                }
                var result = NegTokenInit(mechTypes: mechTypes)
                result.mechTypesDER = mechTypesDER
                result.reqFlags = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                    Array($0.encodedBytes)
                }
                result.mechToken = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific, octets)
                // [3] is mechListMIC (RFC 4178) or negHints (MS NegTokenInit2, then MIC at [4]).
                if let three = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific, { $0 }) {
                    if three.identifier == .octetString { result.mechListMIC = try octets(three) }
                }
                if let mic = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 4, tagClass: .contextSpecific, octets) {
                    result.mechListMIC = mic
                }
                while nodes.next() != nil {}
                return result
            }
        }
    }

    static func parseResp(_ root: ASN1Node) throws -> NegTokenResp {
        try DER.explicitlyTagged(root, tagNumber: 1, tagClass: .contextSpecific) { seq in
            try DER.sequence(seq, identifier: .sequence) { nodes in
                var r = NegTokenResp()
                r.negState = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { n in
                    guard n.identifier == .enumerated, case .primitive(let b) = n.content, b.count == 1,
                          let s = NegState(rawValue: Int(b.first!)) else {
                        throw AuthKitError.malformed(what: "negState", reason: "bad ENUMERATED")
                    }
                    return s
                }
                r.supportedMech = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                    GSSMechanism(oidContent: try oidContent($0))
                }
                r.responseToken = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific, octets)
                r.mechListMIC = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific, octets)
                while nodes.next() != nil {}
                return r
            }
        }
    }
}
