import Foundation

/// Phase 4a policy engine (docs/specs/phase4-radius.md §3): ordered rules, first match wins,
/// no match = the default action. A rule is `ALL of` rows; a row is either one condition or an
/// `ANY of` subgroup — OR inside one row of the AND list, the owner's model. A matched rule
/// returns attributes.
public struct RADIUSPolicy: Codable, Sendable, Equatable, Identifiable {
    public var id: UUID
    public var position: Int
    public var name: String
    public var enabled: Bool
    /// Rows: a condition, or an OR subgroup of conditions.
    public var rows: [Row]
    public var action: Action
    /// Attributes returned on Accept (standard + vendor-specific raw pairs).
    public var attributes: [ReturnedAttribute]
    /// The VLAN of the Accept-with-VLAN shorthand (30 Sep 2026); nil for the other actions.
    public var vlan: String?

    /// Accept-with-VLAN is Accept plus Tunnel-Type = VLAN, Tunnel-Medium-Type = 802 and
    /// Tunnel-Private-Group-ID = `vlan` (spec §3 "Accept-with-VLAN shorthand").
    public enum Action: String, Codable, Sendable, CaseIterable {
        case accept, reject, acceptVLAN

        public var title: String {
            switch self {
            case .accept: "Accept"
            case .reject: "Reject"
            case .acceptVLAN: "Accept with VLAN"
            }
        }

        public var accepts: Bool { self != .reject }
    }

    /// `ALL of` member.
    public enum Row: Codable, Sendable, Equatable {
        case condition(Condition)
        case anyOf([Condition])

        enum CodingKeys: String, CodingKey { case condition, anyOf }

        public init(condition: Condition) { self = .condition(condition) }
        public init(anyOf: [Condition]) { self = .anyOf(anyOf) }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            if let cond = try? c.decode(Condition.self, forKey: .condition) { self = .condition(cond) }
            else { self = .anyOf(try c.decode([Condition].self, forKey: .anyOf)) }
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            switch self {
            case .condition(let cond): try c.encode(cond, forKey: .condition)
            case .anyOf(let list): try c.encode(list, forKey: .anyOf)
            }
        }
    }

    /// `attribute op value` on the request's RADIUS attributes and directory facts.
    public struct Condition: Codable, Sendable, Equatable {
        public enum Field: String, Codable, Sendable, CaseIterable {
            case userName = "User-Name"            // as the NAS sent it: the outer identity (may be anonymous)
            case account = "account"               // the authenticated account: sAMAccountName or UPN
            case calledStationId = "Called-Station-Id"
            case callingStationId = "Calling-Station-Id"
            case nasIP = "NAS-IP-Address"
            case nasIdentifier = "NAS-Identifier"
            case serviceType = "Service-Type"
            case eapMethod = "EAP method"
            case innerMethod = "inner method"          // PEAP/TTLS inside: EAP-MSCHAPv2, PAP, MSCHAPv2
            case certificateSubject = "certificate subject"  // EAP-TLS client certificate
            case certificateIssuer = "certificate issuer"
            case group = "directory group"          // the account's groups, nested ones included
            case ou = "directory OU"                // the OU path (`Staff / IT`) or one OU name in it
            case machine = "machine account"        // the account is a machine (is / is not yes)
            case accountFlag = "account flag"       // userAccountControl facts (disabled, locked, …)
            case timeOfDay = "time of day"          // `08:00-18:00` (is = inside, is not = outside)
            case weekday = "weekday"                // Mon…Sun; `Mon-Fri` or a list

            /// What the value box suggests.
            public var placeholder: String {
                switch self {
                case .account: "alice or alice@lab.sheep"
                case .serviceType: "Framed-User"
                case .eapMethod: "EAP-TLS"
                case .innerMethod: "EAP-MSCHAPv2"
                case .certificateSubject: "CN=pc1"
                case .certificateIssuer: "CN=LabDC Lab CA"
                case .machine: "yes"
                case .accountFlag: "password expired"
                case .timeOfDay: "08:00-18:00"
                case .weekday: "Mon-Fri"
                case .ou: "Staff"
                case .group: "Domain Users"
                default: "value"
                }
            }
        }
        public enum Op: String, Codable, Sendable, CaseIterable {
            case `is` = "is", isNot = "is not", starts = "starts with", ends = "ends with"
            case contains = "contains", regex = "matches regex", inList = "in list"

            public func test(_ value: String, _ operand: String) -> Bool {
                let v = value.lowercased(), o = operand.lowercased()
                switch self {
                case .is: return v == o
                case .isNot: return v != o
                case .starts: return v.hasPrefix(o)
                case .ends: return v.hasSuffix(o)
                case .contains: return v.contains(o)
                case .regex: return value.range(of: operand, options: [.regularExpression, .caseInsensitive]) != nil
                case .inList: return o.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.contains(v)
                }
            }

            /// A multi-valued fact (groups, flags, OU names): a positive op matches when one value
            /// does; `is not` when none is equal.
            func testAny(_ values: [String], _ operand: String) -> Bool {
                self == .isNot ? !values.contains { Op.is.test($0, operand) } : values.contains { test($0, operand) }
            }
        }

        public var field: Field
        public var op: Op
        public var value: String

        public init(field: Field, op: Op, value: String) {
            self.field = field; self.op = op; self.value = value
        }

        /// Tests against the request + directory facts (nil strings never match except `is not`).
        public func matches(_ request: RequestContext) -> Bool {
            let single: String?
            switch field {
            case .userName: single = request.userName
            case .account:
                // sAMAccountName or UPN; `is not` = neither is equal. No account yet = no match.
                let names = [request.account, request.accountUPN].compactMap { $0 }
                guard !names.isEmpty else { return op == .isNot }
                return op.testAny(names, value)
            case .calledStationId: single = request.calledStationId
            case .callingStationId: single = request.callingStationId
            case .nasIP: single = request.nasIP
            case .nasIdentifier: single = request.nasIdentifier
            case .serviceType: single = request.serviceType
            case .eapMethod: single = request.eapMethod
            case .innerMethod: single = request.innerMethod
            case .certificateSubject: single = request.certificateSubject
            case .certificateIssuer: single = request.certificateIssuer
            case .group: return op.testAny(request.groups, value)
            case .accountFlag: return op.testAny(request.accountFlags, value)
            case .ou:
                // The full path (`Staff / IT`) or any single OU name in it.
                guard let ou = request.ou else { return op == .isNot }
                let names = [ou] + ou.components(separatedBy: " / ")
                return op.testAny(names, value)
            case .machine: return op.test(request.isMachine ? "yes" : "no", value)
            case .timeOfDay:
                if op == .is || op == .isNot, let inside = Self.within(time: request.timeOfDay, range: value) {
                    return op == .is ? inside : !inside
                }
                single = request.timeOfDay
            case .weekday:
                if op == .is || op == .isNot, let inside = Self.within(weekday: request.weekday, range: value) {
                    return op == .is ? inside : !inside
                }
                single = request.weekday
            }
            guard let single else { return op == .isNot }
            return op.test(single, value)
        }

        /// `08:00-18:00` (wrapping past midnight allowed: `22:00-06:00`); nil when `range` is not a range.
        static func within(time: String, range: String) -> Bool? {
            let parts = range.split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, let from = minutes(parts[0]), let to = minutes(parts[1]), let now = minutes(time) else { return nil }
            return from <= to ? (from <= now && now < to) : (now >= from || now < to)
        }

        static func minutes(_ text: String) -> Int? {
            let hm = text.split(separator: ":")
            guard hm.count == 2, let h = Int(hm[0]), let m = Int(hm[1]), (0...24).contains(h), (0..<60).contains(m) else { return nil }
            return h * 60 + m
        }

        static let weekdays = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

        /// `Mon-Fri` (a range) or `Sat` / `Sat, Sun` (a list); nil when it names no weekday.
        static func within(weekday: String, range: String) -> Bool? {
            func index(_ s: some StringProtocol) -> Int? {
                weekdays.firstIndex(of: String(s.trimmingCharacters(in: .whitespaces).lowercased().prefix(3)))
            }
            guard let day = index(weekday) else { return nil }
            let dash = range.split(separator: "-")
            if dash.count == 2, let from = index(dash[0]), let to = index(dash[1]) {
                return from <= to ? (from...to).contains(day) : (day >= from || day <= to)
            }
            let list = range.split(separator: ",").compactMap(index)
            return list.isEmpty ? nil : list.contains(day)
        }
    }

    /// One attribute to return on Accept: standard RADIUS (by type) or vendor-specific.
    public struct ReturnedAttribute: Codable, Sendable, Equatable, Identifiable {
        public var id: UUID
        public var vendor: String?     // nil = standard; e.g. "Microsoft", "Aruba", "Cisco"
        public var standard: Standard?
        public var vendorCode: UInt32?
        public var vendorType: UInt8?
        public var value: String

        public enum Standard: String, Codable, Sendable, CaseIterable {
            case filterId = "Filter-Id"
            case tunnelType = "Tunnel-Type"
            case tunnelMediumType = "Tunnel-Medium-Type"
            case tunnelPrivateGroupID = "Tunnel-Private-Group-ID (VLAN)"
            case sessionTimeout = "Session-Timeout"
            case idleTimeout = "Idle-Timeout"
            case replyMessage = "Reply-Message"
        }

        public init(id: UUID = UUID(), vendor: String? = nil, standard: Standard? = nil,
                    vendorCode: UInt32? = nil, vendorType: UInt8? = nil, value: String) {
            self.id = id; self.vendor = vendor; self.standard = standard
            self.vendorCode = vendorCode; self.vendorType = vendorType; self.value = value
        }

        public var title: String {
            if let standard { return standard.rawValue }
            if let preset = Self.vendorPresets.first(where: { $0.vendorCode == vendorCode && $0.vendorType == vendorType }) {
                return preset.name
            }
            return "\(vendor ?? "VSA"):\(vendorType ?? 0)"
        }

        /// String vendor attributes NAS vendors act on (the RADIUS page's "Add attribute" menu).
        /// VLANs on Aruba, Cisco, Huawei and UniFi use the standard Tunnel-* attributes.
        public static let vendorPresets: [(name: String, vendor: String, vendorCode: UInt32, vendorType: UInt8)] = [
            ("Aruba-User-Role", "Aruba", 14823, 1),
            ("Aruba-Named-User-Vlan", "Aruba", 14823, 9),
            ("Cisco-AVPair", "Cisco", 9, 1),
            ("Airespace-ACL-Name", "Cisco", 14179, 6),
        ]

        public static func preset(named name: String, value: String = "") -> ReturnedAttribute? {
            vendorPresets.first { $0.name == name }.map {
                ReturnedAttribute(vendor: $0.vendor, vendorCode: $0.vendorCode, vendorType: $0.vendorType, value: value)
            }
        }

        /// The wire attributes (tagged Tunnel-* per RFC 2868); empty when the value does not fit.
        public var wire: [RADIUSPacket.Attribute] {
            let text = value.trimmingCharacters(in: .whitespaces)
            switch standard {
            case .tunnelType:
                let v = text.isEmpty || text.lowercased() == "vlan" ? 13 : UInt32(text) ?? 13
                return [RADIUSPacket.taggedInteger(.tunnelType, v)]
            case .tunnelMediumType:
                let v = text.isEmpty || text.contains("802") ? 6 : UInt32(text) ?? 6
                return [RADIUSPacket.taggedInteger(.tunnelMediumType, v)]
            case .tunnelPrivateGroupID:
                return text.isEmpty ? [] : [RADIUSPacket.taggedString(.tunnelPrivateGroupID, text)]
            case .filterId:
                return text.isEmpty ? [] : [.init(.filterId, Array(text.utf8))]
            case .sessionTimeout:
                return UInt32(text).map { [RADIUSPacket.integer(.sessionTimeout, $0)] } ?? []
            case .idleTimeout:
                return UInt32(text).map { [RADIUSPacket.integer(.idleTimeout, $0)] } ?? []
            case .replyMessage:
                return value.isEmpty ? [] : [.init(.replyMessage, Array(value.utf8))]
            case nil:
                guard let vendorCode, let vendorType,
                      let attr = VendorSpecific.attribute(vendor: vendorCode, type: vendorType, value: Array(value.utf8)) else { return [] }
                return [attr]
            }
        }
    }

    public init(id: UUID = UUID(), position: Int = 0, name: String, enabled: Bool = true,
                rows: [Row] = [], action: Action = .accept, attributes: [ReturnedAttribute] = [], vlan: String? = nil) {
        self.id = id; self.position = position; self.name = name; self.enabled = enabled
        self.rows = rows; self.action = action; self.attributes = attributes; self.vlan = vlan
    }

    public func matches(_ request: RequestContext) -> Bool {
        for row in rows {
            switch row {
            case .condition(let c) where !c.matches(request): return false
            case .anyOf(let list) where !list.contains(where: { $0.matches(request) }): return false
            default: continue
            }
        }
        return true
    }

    /// What an Accept by this rule returns: the VLAN shorthand's three tunnel attributes first,
    /// then the listed ones (a listed Tunnel-* replaces the shorthand's).
    public var replyAttributes: [RADIUSPacket.Attribute] {
        guard action.accepts else { return [] }
        let listed = attributes.flatMap(\.wire)
        guard action == .acceptVLAN, let vlan = vlan?.trimmingCharacters(in: .whitespaces), !vlan.isEmpty else { return listed }
        let tunnel: [RADIUSPacket.Attribute] = [
            RADIUSPacket.taggedInteger(.tunnelType, 13),        // VLAN
            RADIUSPacket.taggedInteger(.tunnelMediumType, 6),   // IEEE-802
            RADIUSPacket.taggedString(.tunnelPrivateGroupID, vlan),
        ]
        let replaced = Set(listed.map(\.type))
        return tunnel.filter { !replaced.contains($0.type) } + listed
    }
}

/// Directory facts for one account (the Store computes them; the evaluator only reads them).
public struct DirectoryFacts: Sendable, Equatable {
    public var samAccountName: String
    public var userPrincipalName: String?
    /// Group names, nested membership resolved (`Domain Users` too, via primaryGroupID).
    public var groups: [String]
    /// The OU path from the domain down, `Staff / IT`; nil for an account directly under the domain.
    public var ou: String?
    public var isMachine: Bool
    /// userAccountControl + account-state facts: `disabled`, `locked`, `expired`, `password expired`,
    /// `password never expires`, `must change password`, `smartcard required`, `password not required`.
    public var accountFlags: [String]

    public init(samAccountName: String, userPrincipalName: String? = nil, groups: [String] = [], ou: String? = nil,
                isMachine: Bool = false, accountFlags: [String] = []) {
        self.samAccountName = samAccountName; self.userPrincipalName = userPrincipalName; self.groups = groups; self.ou = ou
        self.isMachine = isMachine; self.accountFlags = accountFlags
    }
}

/// What the evaluator sees: the RADIUS attributes plus the directory facts for the account.
public struct RequestContext: Sendable, Equatable {
    /// User-Name as the NAS sent it — for EAP the outer identity (`anonymous@lab.sheep`).
    public var userName: String?
    /// The authenticated account (inner identity / certificate mapping / PAP user):
    /// sAMAccountName and UPN; nil until the directory facts are merged in.
    public var account: String?
    public var accountUPN: String?
    public var calledStationId: String?
    public var callingStationId: String?
    public var nasIP: String?
    public var nasIdentifier: String?
    /// Service-Type by name (`Framed-User`), or the number when unnamed.
    public var serviceType: String?
    /// The EAP method: the EAP-Message type byte, or the method an EAP exchange finished with
    /// (`EAP-TLS`, `PEAP`, `EAP-TTLS`).
    public var eapMethod: String?
    /// Inside PEAP/TTLS: `EAP-MSCHAPv2`, `PAP`, `MSCHAPv2`.
    public var innerMethod: String?
    /// EAP-TLS: the client certificate's subject and issuer (RFC 4514 text).
    public var certificateSubject: String?
    public var certificateIssuer: String?
    /// The account's group names (nested membership resolved).
    public var groups: [String]
    /// The account's OU path (`Staff / IT`); nil when the account is missing or not in an OU.
    public var ou: String?
    public var isMachine: Bool
    /// See `DirectoryFacts.accountFlags`.
    public var accountFlags: [String]
    /// Local time `HH:mm` and weekday `Mon`…`Sun` when the request arrived.
    public var timeOfDay: String
    public var weekday: String

    public init(userName: String? = nil, calledStationId: String? = nil, callingStationId: String? = nil,
                nasIP: String? = nil, nasIdentifier: String? = nil, serviceType: String? = nil, eapMethod: String? = nil,
                groups: [String] = [], ou: String? = nil, isMachine: Bool = false, accountFlags: [String] = [],
                date: Date = Date(), timeZone: TimeZone = .current) {
        self.userName = userName; self.calledStationId = calledStationId
        self.callingStationId = callingStationId; self.nasIP = nasIP; self.nasIdentifier = nasIdentifier
        self.serviceType = serviceType; self.eapMethod = eapMethod
        self.groups = groups; self.ou = ou; self.isMachine = isMachine; self.accountFlags = accountFlags
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.hour, .minute, .weekday], from: date)
        timeOfDay = String(format: "%02d:%02d", c.hour ?? 0, c.minute ?? 0)
        // Calendar weekday: 1 = Sunday.
        weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][((c.weekday ?? 1) - 1 + 7) % 7]
    }

    /// The RADIUS side of a request: its attributes, with NAS-IP-Address falling back to the
    /// datagram's source address.
    public init(packet: RADIUSPacket, sourceIP: String, date: Date = Date(), timeZone: TimeZone = .current) {
        var nasIP = sourceIP
        if let v4 = packet.first(.nasIPAddress)?.value, v4.count == 4 {
            nasIP = v4.map(String.init).joined(separator: ".")
        }
        self.init(userName: packet.string(.userName), calledStationId: packet.string(.calledStationId),
                  callingStationId: packet.string(.callingStationId), nasIP: nasIP,
                  nasIdentifier: packet.string(.nasIdentifier),
                  serviceType: packet.integer(.serviceType).map(RADIUSNames.serviceType),
                  eapMethod: packet.eapType.map(RADIUSNames.eapType), date: date, timeZone: timeZone)
    }

    /// Adds the directory facts; the request's own attributes (User-Name as sent, Called-Station-Id,
    /// NAS-*) stay — facts never replace the request context.
    public mutating func merge(_ facts: DirectoryFacts) {
        if !facts.samAccountName.isEmpty { account = facts.samAccountName }
        accountUPN = facts.userPrincipalName
        groups = facts.groups
        ou = facts.ou
        isMachine = facts.isMachine
        accountFlags = facts.accountFlags
    }

    /// `Name = value`, one per line (the app's Test box, `labdc radius test`). Names are the
    /// RADIUS attribute names plus `Time` (HH:mm) and `Weekday`; blank lines and `#` comments are
    /// skipped. Returns the lines it did not understand.
    public static func parse(_ text: String, date: Date = Date(), timeZone: TimeZone = .current) -> (RequestContext, unknown: [String]) {
        var context = RequestContext(date: date, timeZone: timeZone)
        var unknown: [String] = []
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let eq = line.firstIndex(of: "=") else { unknown.append(line); continue }
            let name = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            var value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") { value = String(value.dropFirst().dropLast()) }
            switch name {
            case "user-name", "username", "user": context.userName = value
            case "account": context.account = value
            case "called-station-id": context.calledStationId = value
            case "calling-station-id": context.callingStationId = value
            case "nas-ip-address", "nas-ip": context.nasIP = value
            case "nas-identifier": context.nasIdentifier = value
            case "service-type": context.serviceType = UInt32(value).map(RADIUSNames.serviceType) ?? value
            case "eap-type", "eap method", "eap-method": context.eapMethod = UInt8(value).map(RADIUSNames.eapType) ?? value
            case "inner-method", "inner method": context.innerMethod = value
            case "certificate-subject", "certificate subject": context.certificateSubject = value
            case "certificate-issuer", "certificate issuer": context.certificateIssuer = value
            case "time", "time of day": context.timeOfDay = value
            case "weekday", "day": context.weekday = value
            default: unknown.append(line)
            }
        }
        return (context, unknown)
    }
}

/// The server's answer before it goes on the wire.
public struct RADIUSDecision: Sendable, Equatable {
    public var accept: Bool
    /// The matched rule's name; nil when the default action decided.
    public var rule: String?
    public var attributes: [RADIUSPacket.Attribute]

    public init(accept: Bool, rule: String?, attributes: [RADIUSPacket.Attribute]) {
        self.accept = accept; self.rule = rule; self.attributes = attributes
    }

    /// `rule Staff WiFi` / `default action`.
    public var ruleText: String { rule.map { "rule \($0)" } ?? "default action" }
}

/// Used when no rule matches (Settings on the RADIUS page; Reject unless the owner picks Accept).
public enum RADIUSDefaultAction: String, Codable, Sendable, CaseIterable {
    case reject, accept
    public var title: String { self == .reject ? "Reject" : "Accept" }
}

public enum RADIUSEvaluator {
    /// The first enabled rule that matches, in position order.
    public static func match(policies: [RADIUSPolicy], _ request: RequestContext) -> RADIUSPolicy? {
        policies
            .filter { $0.enabled }
            .sorted { $0.position < $1.position }
            .first { $0.matches(request) }
    }

    /// First match wins; no match = `defaultAction` (an Accept by default returns nothing).
    public static func decide(policies: [RADIUSPolicy], defaultAction: RADIUSDefaultAction,
                              _ request: RequestContext) -> RADIUSDecision {
        guard let rule = match(policies: policies, request) else {
            return RADIUSDecision(accept: defaultAction == .accept, rule: nil, attributes: [])
        }
        return RADIUSDecision(accept: rule.action.accepts, rule: rule.name, attributes: rule.replyAttributes)
    }

    /// `Tunnel-Type = VLAN (13)` — one line per returned attribute, for the Test box / CLI.
    public static func describe(_ attribute: RADIUSPacket.Attribute) -> String {
        func tagged(_ names: [UInt32: String]) -> String {
            guard attribute.value.count == 4 else { return "?" }
            let v = attribute.value.dropFirst().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return names[v].map { "\($0) (\(v))" } ?? String(v)
        }
        switch RADIUSPacket.AttrType(rawValue: attribute.type) {
        case .tunnelType: return "Tunnel-Type = " + tagged([13: "VLAN"])
        case .tunnelMediumType: return "Tunnel-Medium-Type = " + tagged([6: "IEEE-802"])
        case .tunnelPrivateGroupID:
            let v = attribute.value.first.map { (1...0x1F).contains($0) } == true ? Array(attribute.value.dropFirst()) : attribute.value
            return "Tunnel-Private-Group-ID = \(String(decoding: v, as: UTF8.self))"
        case .filterId: return "Filter-Id = \(attribute.string)"
        case .replyMessage: return "Reply-Message = \(attribute.string)"
        case .sessionTimeout: return "Session-Timeout = \(attribute.integer.map(String.init) ?? "?")"
        case .idleTimeout: return "Idle-Timeout = \(attribute.integer.map(String.init) ?? "?")"
        case .vendorSpecific:
            guard let vsa = VendorSpecific(attribute.value), let sub = vsa.subAttributes.first else { return "Vendor-Specific (malformed)" }
            return "Vendor-Specific \(vsa.vendor):\(sub.type) = \(String(decoding: sub.value, as: UTF8.self))"
        default: return "attribute \(attribute.type) (\(attribute.value.count) bytes)"
        }
    }
}
