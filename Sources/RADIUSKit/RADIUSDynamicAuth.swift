import Foundation

/// RFC 5176 Dynamic Authorization (CoA / Disconnect), the DC as the client: per-NAS flavour,
/// request building and signing, reply checking. The transport lives in LabDCCore.
public enum CoAVendor: String, Codable, Sendable, CaseIterable {
    /// RFC 5176 Disconnect-Request for both actions (no standard "reauthenticate").
    case generic
    /// Cisco IOS/IOS-XE: CoA-Request `Cisco-AVPair = subscriber:command=reauthenticate`
    /// (CoA port 1700 on IOS by default; `aaa server radius dynamic-author`).
    case cisco
    /// Aruba switches (AOS-S / AOS-CX): CoA-Request `Aruba-Port-Bounce-Host` — the port goes
    /// down and up, the client runs DHCP and authentication again.
    case arubaBounce
    /// Aruba controllers / Instant APs: Disconnect-Request (the client reconnects).
    case arubaDisconnect

    public var title: String {
        switch self {
        case .generic: "Generic (Disconnect)"
        case .cisco: "Cisco (reauthenticate)"
        case .arubaBounce: "Aruba switch (port bounce)"
        case .arubaDisconnect: "Aruba (Disconnect)"
        }
    }

    /// The usual CoA port of this kind of NAS (Cisco IOS listens on 1700, the RFC says 3799).
    public var suggestedPort: UInt16 { self == .cisco ? 1700 : 3799 }
}

/// What the DC asks a NAS to do with a session.
public enum CoAAction: String, Sendable, CaseIterable {
    /// Run authentication again (new profile → new policy result): the vendor's way.
    case reauthenticate
    /// End the session (RFC 5176 Disconnect-Request).
    case disconnect

    public var title: String { self == .reauthenticate ? "Reauthenticate" : "Disconnect" }
}

/// The session a CoA/Disconnect names (RFC 5176 §3: the NAS identification and session
/// identification attributes, as the NAS reported them in accounting).
public struct CoASession: Sendable, Equatable {
    public var nasIP: String?
    public var nasIdentifier: String?
    public var acctSessionId: String?
    public var userName: String?
    public var callingStationId: String?
    public var framedIP: String?

    public init(nasIP: String? = nil, nasIdentifier: String? = nil, acctSessionId: String? = nil, userName: String? = nil,
                callingStationId: String? = nil, framedIP: String? = nil) {
        self.nasIP = nasIP; self.nasIdentifier = nasIdentifier; self.acctSessionId = acctSessionId
        self.userName = userName; self.callingStationId = callingStationId; self.framedIP = framedIP
    }
}

public enum DynamicAuth {
    /// Cisco vendor id and the Cisco-AVPair sub-attribute.
    public static let ciscoVendor: UInt32 = 9
    /// Aruba (HPE) vendor id; `Aruba-Port-Bounce-Host` is sub-attribute 40 (integer: seconds
    /// the port stays down) per FreeRADIUS `dictionary.aruba` — 29 is Aruba-AS-User-Name.
    public static let arubaVendor: UInt32 = 14823
    public static let arubaPortBounceHost: UInt8 = 40
    public static let portBounceSeconds: UInt32 = 10

    /// The code and the extra (vendor) attributes `action` becomes on a NAS of `vendor`.
    public static func plan(_ action: CoAAction, vendor: CoAVendor) -> (code: RADIUSPacket.Code, attributes: [RADIUSPacket.Attribute], text: String) {
        guard action == .reauthenticate else { return (.disconnectRequest, [], "Disconnect") }
        switch vendor {
        case .cisco:
            let avpair = VendorSpecific.attribute(vendor: ciscoVendor, type: 1, value: Array("subscriber:command=reauthenticate".utf8))
            return (.coaRequest, avpair.map { [$0] } ?? [], "CoA reauthenticate")
        case .arubaBounce:
            let bounce = VendorSpecific.attribute(vendor: arubaVendor, type: arubaPortBounceHost,
                                                  value: RADIUSPacket.bigEndian(portBounceSeconds))
            return (.coaRequest, bounce.map { [$0] } ?? [], "CoA port bounce")
        case .generic, .arubaDisconnect:
            return (.disconnectRequest, [], "Disconnect")
        }
    }

    /// A signed CoA- or Disconnect-Request: NAS identification (NAS-IP-Address when IPv4,
    /// NAS-IPv6-Address, else NAS-Identifier), session identification (Acct-Session-Id,
    /// User-Name, Calling-Station-Id, Framed-IP-Address — whatever accounting recorded),
    /// Event-Timestamp (RFC 5176 §2.3, replay protection), the vendor attributes, then a
    /// Message-Authenticator and the RFC 5176 §2.3 Request Authenticator.
    public static func request(_ action: CoAAction, vendor: CoAVendor, session: CoASession, id: UInt8,
                               secret: [UInt8], now: Date) throws -> RADIUSPacket {
        let plan = plan(action, vendor: vendor)
        var attrs: [RADIUSPacket.Attribute] = []
        if let ip = session.nasIP, let bytes = RADIUSAddress.bytes(ip) {
            attrs.append(.init(bytes.count == 4 ? .nasIPAddress : .nasIPv6Address, bytes))
        }
        if let ident = session.nasIdentifier, !ident.isEmpty { attrs.append(.init(.nasIdentifier, Array(ident.utf8))) }
        if let s = session.acctSessionId, !s.isEmpty { attrs.append(.init(.acctSessionId, Array(s.utf8))) }
        if let u = session.userName, !u.isEmpty { attrs.append(.init(.userName, Array(u.utf8))) }
        if let c = session.callingStationId, !c.isEmpty { attrs.append(.init(.callingStationId, Array(c.utf8))) }
        if let f = session.framedIP, let bytes = RADIUSAddress.bytes(f), bytes.count == 4 { attrs.append(.init(.framedIPAddress, bytes)) }
        attrs.append(RADIUSPacket.integer(.eventTimestamp, UInt32(truncatingIfNeeded: Int64(now.timeIntervalSince1970))))
        attrs += plan.attributes
        var packet = RADIUSPacket(code: plan.code, id: id, authenticator: [UInt8](repeating: 0, count: 16), attributes: attrs)
        try packet.signRequest(secret: secret, messageAuthenticator: true)
        return packet
    }

    public enum Outcome: Sendable, Equatable {
        case ack
        /// NAK with its Error-Cause (RFC 5176 §3.6), when the NAS sent one.
        case nak(errorCause: UInt32?)

        public var text: String {
            switch self {
            case .ack: "ACK"
            case .nak(let cause?): "NAK (\(RADIUSNames.errorCause(cause)))"
            case .nak(nil): "NAK"
            }
        }
    }

    public enum ReplyError: Error, Equatable, CustomStringConvertible {
        case unrelated, badAuthenticator, badMessageAuthenticator, wrongCode(UInt8)
        public var description: String {
            switch self {
            case .unrelated: "a reply to another request"
            case .badAuthenticator: "the Response Authenticator does not verify (wrong shared secret?)"
            case .badMessageAuthenticator: "the Message-Authenticator does not verify"
            case .wrongCode(let c): "unexpected code \(c)"
            }
        }
    }

    /// Checks a reply against `request`: same Identifier, the matching ACK/NAK code, the Response
    /// Authenticator and (when present) the Message-Authenticator over the request's authenticator.
    public static func outcome(of bytes: [UInt8], for request: RADIUSPacket, secret: [UInt8]) throws -> Outcome {
        let reply = try RADIUSPacket(bytes: bytes)
        guard reply.id == request.id else { throw ReplyError.unrelated }
        let (ack, nak): (RADIUSPacket.Code, RADIUSPacket.Code) =
            request.code == .coaRequest ? (.coaACK, .coaNAK) : (.disconnectACK, .disconnectNAK)
        guard reply.code == ack || reply.code == nak else { throw ReplyError.wrongCode(reply.code.rawValue) }
        guard reply.verifyResponseAuthenticator(requestAuthenticator: request.authenticator, secret: secret) else {
            throw ReplyError.badAuthenticator
        }
        if reply.messageAuthenticator != nil,
           !reply.verifyMessageAuthenticator(secret: secret, requestAuthenticator: request.authenticator) {
            throw ReplyError.badMessageAuthenticator
        }
        return reply.code == ack ? .ack : .nak(errorCause: reply.integer(.errorCause))
    }
}

/// At most one automatic CoA per MAC per `interval` (10 minutes): a device whose profile
/// flaps must not bounce its port over and over.
public struct CoARateLimiter: Sendable {
    private var last: [String: Date] = [:]
    public let interval: TimeInterval
    public let capacity: Int

    public init(interval: TimeInterval = 600, capacity: Int = 8192) {
        self.interval = interval
        self.capacity = capacity
    }

    /// True (and remembered) when `mac` may get a CoA now; false inside the interval.
    public mutating func admit(_ mac: String, now: Date) -> Bool {
        if let seen = last[mac], now.timeIntervalSince(seen) < interval { return false }
        if last.count >= capacity { last = last.filter { now.timeIntervalSince($0.value) < interval } }
        last[mac] = now
        return true
    }

    /// When `mac` may get the next one (nil = now).
    public func nextAllowed(_ mac: String, now: Date) -> Date? {
        guard let seen = last[mac], now.timeIntervalSince(seen) < interval else { return nil }
        return seen.addingTimeInterval(interval)
    }
}
