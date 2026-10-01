import Foundation
import Crypto
import SheepCrypto

/// RFC 2865/2866 wire format: one request per datagram, AVPs, `Message-Authenticator`
/// (HMAC-MD5, RFC 3579 §3.2) and the Request/Response Authenticators.
///
/// Parsing never traps on hostile input (owner review, 30 Sep 2026): every length is checked
/// before it is used, and the authenticators are computed over the exact datagram received.
public struct RADIUSPacket: Sendable, Equatable {
    public enum Code: UInt8, Sendable {
        case accessRequest = 1, accessAccept = 2, accessReject = 3
        case accountingRequest = 4, accountingResponse = 5
        case accessChallenge = 11
        /// "Access-Reject" etc.
        public var title: String {
            switch self {
            case .accessRequest: "Access-Request"
            case .accessAccept: "Access-Accept"
            case .accessReject: "Access-Reject"
            case .accountingRequest: "Accounting-Request"
            case .accountingResponse: "Accounting-Response"
            case .accessChallenge: "Access-Challenge"
            }
        }
    }

    /// The attributes the policy engine and auth care about (type numbers per RFC 2865/2866/2868/2869).
    public enum AttrType: UInt8, Sendable {
        case userName = 1, userPassword = 2, chapPassword = 3, nasIPAddress = 4, nasPort = 5, serviceType = 6
        case framedProtocol = 7, filterId = 11, framedMTU = 12, replyMessage = 18, state = 24, class_ = 25
        case vendorSpecific = 26, sessionTimeout = 27, idleTimeout = 28, terminationAction = 29
        case calledStationId = 30, callingStationId = 31, nasIdentifier = 32
        case proxyState = 33, acctStatusType = 40, acctSessionId = 44, nasPortType = 61
        case tunnelType = 64, tunnelMediumType = 65
        case eapMessage = 79, messageAuthenticator = 80, tunnelPrivateGroupID = 81
        case nasIPv6Address = 95
    }

    public var code: Code
    public var id: UInt8
    public var authenticator: [UInt8]      // 16 bytes
    public var attributes: [Attribute]
    /// The datagram this packet was parsed from (up to its declared length); nil for a packet
    /// built here. The authenticators of a received packet are checked over these bytes.
    public var raw: [UInt8]?

    public struct Attribute: Sendable, Equatable {
        public var type: UInt8
        public var value: [UInt8]

        public init(_ type: AttrType, _ value: [UInt8]) {
            self.type = type.rawValue
            self.value = value
        }
        public init(raw type: UInt8, _ value: [UInt8]) {
            self.type = type
            self.value = value
        }

        public var string: String { String(decoding: value, as: UTF8.self) }

        /// A 4-byte integer value (RFC 2865 §5 "integer"); nil for any other length.
        public var integer: UInt32? {
            guard value.count == 4 else { return nil }
            return value.reduce(0) { $0 << 8 | UInt32($1) }
        }
    }

    public init(code: Code, id: UInt8, authenticator: [UInt8], attributes: [Attribute] = []) {
        self.code = code
        self.id = id
        self.authenticator = authenticator
        self.attributes = attributes
        self.raw = nil
    }

    // MARK: Parsing

    public enum ParseError: Error, CustomStringConvertible, Equatable {
        case truncated, unknownCode(UInt8), badLength(Int), overflow

        public var description: String {
            switch self {
            case .truncated: "packet shorter than the 20-byte RADIUS header"
            case .unknownCode(let c): "unknown RADIUS code \(c)"
            case .badLength(let n): "header length \(n) does not match the datagram"
            case .overflow: "an attribute runs past the end of the packet"
            }
        }
    }

    /// Decodes and checks the header length (octets past it are padding and ignored, RFC 2865
    /// §3); the authenticators are verified separately (the caller knows the NAS secret).
    public init(bytes: [UInt8]) throws {
        guard bytes.count >= 20 else { throw ParseError.truncated }
        guard let code = Code(rawValue: bytes[0]) else { throw ParseError.unknownCode(bytes[0]) }
        let declared = Int(bytes[2]) << 8 | Int(bytes[3])
        guard declared >= 20, declared <= 4096, declared <= bytes.count else { throw ParseError.badLength(declared) }
        self.code = code
        self.id = bytes[1]
        self.authenticator = Array(bytes[4..<20])
        self.attributes = []
        var i = 20
        while i < declared {
            guard i + 2 <= declared else { throw ParseError.overflow }
            let type = bytes[i], len = Int(bytes[i + 1])
            guard len >= 2, i + len <= declared else { throw ParseError.overflow }
            attributes.append(Attribute(raw: type, Array(bytes[(i + 2)..<(i + len)])))
            i += len
        }
        self.raw = Array(bytes[0..<declared])
    }

    /// Encodes with the length field matching; attributes beyond 4096 are refused (RFC cap).
    public func encode() throws -> [UInt8] {
        var out: [UInt8] = [code.rawValue, id, 0, 0] + authenticator.prefix(16)
        while out.count < 20 { out.append(0) }
        for attr in attributes {
            let len = attr.value.count + 2
            guard len <= 255 else { throw ParseError.overflow }
            out += [attr.type, UInt8(len)] + attr.value
        }
        guard out.count <= 4096 else { throw ParseError.overflow }
        out[2] = UInt8(out.count >> 8); out[3] = UInt8(out.count & 0xff)
        return out
    }

    // MARK: Attribute access

    public func first(_ type: AttrType) -> Attribute? { attributes.first { $0.type == type.rawValue } }
    public func strings(_ type: AttrType) -> [String] { attributes.filter { $0.type == type.rawValue }.map(\.string) }
    public func all(_ type: AttrType) -> [Attribute] { attributes.filter { $0.type == type.rawValue } }
    public func string(_ type: AttrType) -> String? { first(type)?.string }
    public func integer(_ type: AttrType) -> UInt32? { first(type)?.integer }

    public mutating func remove(_ type: AttrType) { attributes.removeAll { $0.type == type.rawValue } }

    /// The EAP type (RFC 3748 §4: code, identifier, length(2), type) of the first EAP-Message,
    /// read as a fact for the policy engine; nil without EAP or for a bare EAP Success/Failure.
    public var eapType: UInt8? {
        guard let eap = first(.eapMessage)?.value, eap.count >= 5, eap[0] == 1 || eap[0] == 2 else { return nil }
        return eap[4]
    }

    // MARK: Message-Authenticator (RFC 3579 §3.2)

    /// The packet's `Message-Authenticator` if present.
    public var messageAuthenticator: [UInt8]? { first(.messageAuthenticator)?.value }

    /// Offset of the `Message-Authenticator` value in `bytes`, found by walking the attribute
    /// TLVs (never by searching for a 0x50 byte, which may sit in the header or a value). nil
    /// when absent, malformed (length ≠ 18) or when the TLV chain is broken.
    public static func messageAuthenticatorOffset(in bytes: [UInt8]) -> Int? {
        guard bytes.count >= 20 else { return nil }
        let end = min(bytes.count, Int(bytes[2]) << 8 | Int(bytes[3]))
        var i = 20
        while i + 2 <= end {
            let type = bytes[i], len = Int(bytes[i + 1])
            guard len >= 2, i + len <= end else { return nil }
            if type == AttrType.messageAuthenticator.rawValue { return len == 18 ? i + 2 : nil }
            i += len
        }
        return nil
    }

    /// HMAC-MD5 (keyed with the shared secret) over `bytes` with the Message-Authenticator value
    /// zeroed and — when given — the 16-byte authenticator field replaced by `authenticator`
    /// (a response is signed over the request's authenticator; an Accounting-Request over zeros).
    public static func messageAuthenticator(over bytes: [UInt8], authenticator: [UInt8]?, secret: [UInt8]) -> [UInt8]? {
        guard let at = messageAuthenticatorOffset(in: bytes) else { return nil }
        var b = bytes
        for j in at..<(at + 16) { b[j] = 0 }
        if let authenticator {
            guard authenticator.count == 16 else { return nil }
            b.replaceSubrange(4..<20, with: authenticator)
        }
        return Array(HMAC<Insecure.MD5>.authenticationCode(for: b, using: SymmetricKey(data: secret)))
    }

    /// Checks a received packet's `Message-Authenticator` in constant time. Access-Request: over
    /// its own Request Authenticator; Accounting-Request: over a zeroed one (RFC 5080 §2.2.4 /
    /// FreeRADIUS); a response: over `requestAuthenticator` (the request it answers).
    public func verifyMessageAuthenticator(secret: [UInt8], requestAuthenticator: [UInt8]? = nil) -> Bool {
        guard let bytes = raw ?? (try? encode()), let at = Self.messageAuthenticatorOffset(in: bytes) else { return false }
        let given = Array(bytes[at..<(at + 16)])
        let over: [UInt8]?
        switch code {
        case .accessRequest: over = nil
        case .accountingRequest: over = [UInt8](repeating: 0, count: 16)
        default: over = requestAuthenticator
        }
        guard let expected = Self.messageAuthenticator(over: bytes, authenticator: over, secret: secret) else { return false }
        return ConstantTime.equal(given, expected)
    }

    // MARK: Accounting-Request authenticator (RFC 2866 §3)

    /// MD5(Code + Identifier + Length + 16 zero octets + attributes + secret).
    public static func accountingRequestAuthenticator(over bytes: [UInt8], secret: [UInt8]) -> [UInt8] {
        var b = bytes
        if b.count >= 20 { b.replaceSubrange(4..<20, with: [UInt8](repeating: 0, count: 16)) }
        return Array(Insecure.MD5.hash(data: b + secret))
    }

    /// Checks an Accounting-Request's Request Authenticator (constant time).
    public func verifyAccountingRequestAuthenticator(secret: [UInt8]) -> Bool {
        guard code == .accountingRequest, let bytes = raw ?? (try? encode()) else { return false }
        return ConstantTime.equal(authenticator, Self.accountingRequestAuthenticator(over: bytes, secret: secret))
    }

    // MARK: Signing

    /// Finishes a reply to the request whose authenticator is `requestAuthenticator`: an optional
    /// `Message-Authenticator` over the request's authenticator (RFC 3579 §3.2), then the
    /// Response Authenticator MD5(Code+ID+Length+RequestAuth+Attributes+Secret) (RFC 2865 §3).
    public mutating func signResponse(requestAuthenticator: [UInt8], secret: [UInt8], messageAuthenticator: Bool) throws {
        remove(.messageAuthenticator)
        authenticator = requestAuthenticator
        if messageAuthenticator {
            attributes.append(Attribute(.messageAuthenticator, [UInt8](repeating: 0, count: 16)))
            let bytes = try encode()
            if let mac = Self.messageAuthenticator(over: bytes, authenticator: nil, secret: secret),
               let i = attributes.lastIndex(where: { $0.type == AttrType.messageAuthenticator.rawValue }) {
                attributes[i].value = mac
            }
        }
        authenticator = Array(Insecure.MD5.hash(data: try encode() + secret))
        raw = nil
    }

    /// Checks a response's Response Authenticator against the request it answers (client side).
    public func verifyResponseAuthenticator(requestAuthenticator: [UInt8], secret: [UInt8]) -> Bool {
        guard var bytes = raw ?? (try? encode()), bytes.count >= 20 else { return false }
        bytes.replaceSubrange(4..<20, with: requestAuthenticator)
        return ConstantTime.equal(authenticator, Array(Insecure.MD5.hash(data: bytes + secret)))
    }

    /// Signs a request as a NAS would (tests, `radius-check`): Access-Request keeps its random
    /// authenticator and gets a Message-Authenticator over it; Accounting-Request gets one over
    /// zeros (when `messageAuthenticator`), then its RFC 2866 Request Authenticator.
    public mutating func signRequest(secret: [UInt8], messageAuthenticator: Bool = true) throws {
        remove(.messageAuthenticator)
        if code == .accountingRequest { authenticator = [UInt8](repeating: 0, count: 16) }
        if messageAuthenticator {
            attributes.append(Attribute(.messageAuthenticator, [UInt8](repeating: 0, count: 16)))
            let bytes = try encode()
            if let mac = Self.messageAuthenticator(over: bytes, authenticator: nil, secret: secret),
               let i = attributes.lastIndex(where: { $0.type == AttrType.messageAuthenticator.rawValue }) {
                attributes[i].value = mac
            }
        }
        if code == .accountingRequest {
            authenticator = Self.accountingRequestAuthenticator(over: try encode(), secret: secret)
        }
        raw = nil
    }

    // MARK: User-Password (RFC 2865 §5.2)

    /// XOR with the MD5(secret + previous) chain; the password is NUL-padded to 16-byte blocks.
    public static func obfuscate(password: [UInt8], secret: [UInt8], authenticator: [UInt8]) -> [UInt8] {
        var padded = password
        if padded.isEmpty || padded.count % 16 != 0 { padded += [UInt8](repeating: 0, count: 16 - padded.count % 16) }
        var out: [UInt8] = []
        var last = authenticator
        for chunk in stride(from: 0, to: padded.count, by: 16) {
            let key = Array(Insecure.MD5.hash(data: secret + last))
            let x = zip(padded[chunk..<chunk + 16], key).map { $0 ^ $1 }
            out += x
            last = x
        }
        return out
    }

    /// The raw reverse of `obfuscate` (the NUL padding stays).
    public static func deobfuscate(_ data: [UInt8], secret: [UInt8], authenticator: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var last = authenticator
        for chunk in stride(from: 0, to: data.count, by: 16) {
            let b = Array(data[chunk..<min(chunk + 16, data.count)])
            let key = Array(Insecure.MD5.hash(data: secret + last))
            out += zip(b, key).map { $0 ^ $1 }
            last = b
        }
        return out
    }

    /// The User-Password as typed: 16…128 octets in 16-octet blocks (anything else is
    /// malformed → nil), decrypted, with the trailing NUL padding stripped.
    public static func userPassword(_ data: [UInt8], secret: [UInt8], authenticator: [UInt8]) -> [UInt8]? {
        guard (16...128).contains(data.count), data.count % 16 == 0 else { return nil }
        var plain = deobfuscate(data, secret: secret, authenticator: authenticator)
        while plain.last == 0 { plain.removeLast() }
        return plain
    }
}
