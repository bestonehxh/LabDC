import Foundation

/// One Accounting-Request as the session store keeps it (RFC 2866 §5; phase 4c accounting
/// storage). Octet counters include the Gigawords (RFC 2869 §5.1/§5.2).
public struct AccountingRecord: Sendable, Equatable {
    public enum Status: Sendable, Equatable {
        case start, interim, stop
        /// Accounting-On / Accounting-Off: the NAS (re)started — every open session of it ended.
        case nasOn, nasOff
    }

    public var status: Status
    public var sessionId: String
    /// Where the datagram came from (the NAS the DC knows); CoA goes back here.
    public var nasSource: String
    public var nasIP: String?
    public var nasIdentifier: String?
    public var nasPort: UInt32?
    public var nasPortId: String?
    public var calledStationId: String?
    /// As the NAS sent it (CoA identifies the session with the same text).
    public var callingStationId: String?
    /// Calling-Station-Id in canonical MAC form, when it is one.
    public var mac: String?
    public var userName: String?
    public var framedIP: String?
    /// Acct-Delay-Time (seconds the NAS held the record before sending it).
    public var delay: UInt32
    public var sessionTime: UInt32?
    public var inputOctets: UInt64?
    public var outputOctets: UInt64?
    public var inputPackets: UInt32?
    public var outputPackets: UInt32?
    public var terminateCause: UInt32?

    public init(status: Status, sessionId: String, nasSource: String, nasIP: String? = nil, nasIdentifier: String? = nil,
                nasPort: UInt32? = nil, nasPortId: String? = nil, calledStationId: String? = nil,
                callingStationId: String? = nil, userName: String? = nil, framedIP: String? = nil, delay: UInt32 = 0,
                sessionTime: UInt32? = nil, inputOctets: UInt64? = nil, outputOctets: UInt64? = nil,
                inputPackets: UInt32? = nil, outputPackets: UInt32? = nil, terminateCause: UInt32? = nil) {
        self.status = status; self.sessionId = sessionId; self.nasSource = nasSource; self.nasIP = nasIP
        self.nasIdentifier = nasIdentifier; self.nasPort = nasPort; self.nasPortId = nasPortId
        self.calledStationId = calledStationId; self.callingStationId = callingStationId
        self.mac = callingStationId.flatMap(RADIUSMAC.normalize)
        self.userName = userName; self.framedIP = framedIP; self.delay = delay; self.sessionTime = sessionTime
        self.inputOctets = inputOctets; self.outputOctets = outputOctets
        self.inputPackets = inputPackets; self.outputPackets = outputPackets; self.terminateCause = terminateCause
    }

    /// nil for a status the store does not keep (unknown Acct-Status-Type) or a Start/Interim/Stop
    /// without Acct-Session-Id.
    public init?(packet: RADIUSPacket, source: String) {
        let status: Status
        switch packet.integer(.acctStatusType) {
        case 1: status = .start
        case 2: status = .stop
        case 3: status = .interim
        case 7: status = .nasOn
        case 8: status = .nasOff
        default: return nil
        }
        let session = packet.string(.acctSessionId) ?? ""
        if session.isEmpty, status != .nasOn, status != .nasOff { return nil }
        func octets(_ low: RADIUSPacket.AttrType, _ high: RADIUSPacket.AttrType) -> UInt64? {
            guard let l = packet.integer(low) else { return nil }
            return UInt64(packet.integer(high) ?? 0) << 32 | UInt64(l)
        }
        let nasIP = packet.first(.nasIPAddress).flatMap { $0.value.count == 4 ? RADIUSAddress.format($0.value) : nil }
            ?? packet.first(.nasIPv6Address).flatMap { $0.value.count == 16 ? RADIUSAddress.format($0.value) : nil }
        let framed = packet.first(.framedIPAddress).flatMap { $0.value.count == 4 ? RADIUSAddress.format($0.value) : nil }
        self.init(status: status, sessionId: session, nasSource: source, nasIP: nasIP,
                  nasIdentifier: packet.string(.nasIdentifier), nasPort: packet.integer(.nasPort),
                  nasPortId: packet.string(.nasPortId), calledStationId: packet.string(.calledStationId),
                  callingStationId: packet.string(.callingStationId), userName: packet.string(.userName),
                  framedIP: framed, delay: packet.integer(.acctDelayTime) ?? 0,
                  sessionTime: packet.integer(.acctSessionTime),
                  inputOctets: octets(.acctInputOctets, .acctInputGigawords),
                  outputOctets: octets(.acctOutputOctets, .acctOutputGigawords),
                  inputPackets: packet.integer(.acctInputPackets), outputPackets: packet.integer(.acctOutputPackets),
                  terminateCause: packet.integer(.acctTerminateCause))
    }
}

extension RADIUSNames {
    /// Acct-Terminate-Cause (RFC 2866 §5.10).
    public static func terminateCause(_ value: UInt32) -> String {
        let names: [UInt32: String] = [
            1: "User-Request", 2: "Lost-Carrier", 3: "Lost-Service", 4: "Idle-Timeout", 5: "Session-Timeout",
            6: "Admin-Reset", 7: "Admin-Reboot", 8: "Port-Error", 9: "NAS-Error", 10: "NAS-Request",
            11: "NAS-Reboot", 12: "Port-Unneeded", 13: "Port-Preempted", 14: "Port-Suspended",
            15: "Service-Unavailable", 16: "Callback", 17: "User-Error", 18: "Host-Request",
        ]
        return names[value] ?? "cause \(value)"
    }

    /// Error-Cause (RFC 5176 §3.6).
    public static func errorCause(_ value: UInt32) -> String {
        let names: [UInt32: String] = [
            201: "Residual Session Context Removed", 202: "Invalid EAP Packet (Ignored)",
            401: "Unsupported Attribute", 402: "Missing Attribute", 403: "NAS Identification Mismatch",
            404: "Invalid Request", 405: "Unsupported Service", 406: "Unsupported Extension",
            407: "Invalid Attribute Value", 501: "Administratively Prohibited", 502: "Request Not Routable (Proxy)",
            503: "Session Context Not Found", 504: "Session Context Not Removable",
            505: "Other Proxy Processing Error", 506: "Resources Unavailable", 507: "Request Initiated",
            508: "Multiple Session Selection Unsupported",
        ]
        return names[value].map { "\(value) \($0)" } ?? "Error-Cause \(value)"
    }
}
