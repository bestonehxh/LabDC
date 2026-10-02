import Foundation

/// Human-readable option lines for the CLI `test`/`simulate` output and the app's Test box.
public enum DHCPDescribe {
    public static func v4Name(_ code: UInt8) -> String {
        switch code {
        case 1: "Subnet mask"
        case 3: "Router"
        case 6: "DNS servers"
        case 12: "Host name"
        case 15: "Domain name"
        case 26: "MTU"
        case 28: "Broadcast"
        case 42: "NTP servers"
        case 43: "Vendor specific (43)"
        case 50: "Requested address"
        case 51: "Lease time"
        case 53: "Message type"
        case 54: "Server identifier"
        case 55: "Parameter request list"
        case 56: "Message"
        case 57: "Max message size"
        case 58: "Renewal (T1)"
        case 59: "Rebinding (T2)"
        case 60: "Vendor class"
        case 61: "Client identifier"
        case 66: "TFTP server name"
        case 67: "Boot file"
        case 77: "User class"
        case 81: "Client FQDN"
        case 82: "Relay agent information"
        case 118: "Subnet selection"
        case 119: "Domain search"
        case 121: "Classless static routes"
        case 138: "CAPWAP AC (138)"
        case 150: "TFTP servers (150)"
        case 249: "MS classless static routes"
        default: "Option \(code)"
        }
    }

    /// `Router: 10.20.0.1` — one line per option, decoded where the format is known.
    public static func v4(_ p: DHCPv4Packet) -> [String] {
        p.options.map { o -> String in
            let value: String
            switch o.code {
            case 1, 28, 50, 54, 118:
                value = IPv4Address(bytes: o.data)?.description ?? DHCPHex.string(o.data)
            case 3, 6, 42, 138, 150:
                value = o.data.count % 4 == 0
                    ? stride(from: 0, to: o.data.count, by: 4).compactMap { IPv4Address(bytes: o.data[$0..<$0 + 4])?.description }.joined(separator: ", ")
                    : DHCPHex.string(o.data)
            case 51, 58, 59:
                value = o.data.count == 4 ? "\(o.data.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }) s" : DHCPHex.string(o.data)
            case 53:
                value = o.data.first.flatMap { DHCPv4MessageType(rawValue: $0)?.description } ?? DHCPHex.string(o.data)
            case 12, 15, 56, 60, 66, 67:
                value = String(decoding: o.data, as: UTF8.self)
            case 26, 57:
                value = o.data.count == 2 ? "\(Int(o.data[0]) << 8 | Int(o.data[1]))" : DHCPHex.string(o.data)
            case 55:
                value = o.data.map(String.init).joined(separator: ",")
            case 119:
                value = (try? DHCPDNSWire.decodeList(o.data).joined(separator: ", ")) ?? DHCPHex.string(o.data)
            case 121, 249:
                value = (try? DHCPOptionBuilder.decodeClasslessRoutes(o.data).map { "\($0.destination) via \($0.gateway)" }.joined(separator: ", "))
                    ?? DHCPHex.string(o.data)
            case 81:
                if let f = try? ClientFQDN(v4: o.data) {
                    value = "\(f.name) (S=\(f.s ? 1 : 0) O=\(f.o ? 1 : 0) N=\(f.n ? 1 : 0))"
                } else { value = DHCPHex.string(o.data) }
            case 82:
                if let r = RelayAgentInformation(bytes: o.data) {
                    value = r.subOptions.map { "\($0.code)=\($0.code <= 2 ? CircuitIDDecoder.describe($0.data) : DHCPHex.string($0.data))" }
                        .joined(separator: " ")
                } else { value = DHCPHex.string(o.data) }
            default:
                value = DHCPHex.string(o.data)
            }
            return "\(v4Name(o.code)): \(value)"
        }
    }

    public static func v6Name(_ code: UInt16) -> String {
        switch code {
        case 1: "Client ID"
        case 2: "Server ID"
        case 3: "IA_NA"
        case 6: "Option request"
        case 7: "Preference"
        case 13: "Status"
        case 14: "Rapid commit"
        case 16: "Vendor class"
        case 23: "DNS servers"
        case 24: "Domain search"
        case 39: "Client FQDN"
        case 56: "NTP server"
        default: "Option \(code)"
        }
    }

    public static func v6(_ m: DHCPv6Message) -> [String] {
        m.options.flatMap { o -> [String] in
            switch o.code {
            case DHCPv6OptionCode.iaNA:
                guard let ia = try? DHCPv6IANA(bytes: o.data) else { return ["IA_NA: \(DHCPHex.string(o.data))"] }
                var lines = ["IA_NA \(ia.iaid): T1 \(ia.t1) s, T2 \(ia.t2) s"]
                lines += ia.addresses.map { "  address \($0.address) preferred \($0.preferred) s valid \($0.valid) s" }
                if let s = ia.status { lines.append("  status \(s.text)") }
                return lines
            case DHCPv6OptionCode.statusCode:
                let code = o.data.count >= 2 ? DHCPv6Status(rawValue: UInt16(o.data[0]) << 8 | UInt16(o.data[1]))?.text ?? "?" : "?"
                return ["Status: \(code) \(String(decoding: o.data.dropFirst(2), as: UTF8.self))"]
            case DHCPv6OptionCode.dnsServers:
                let list = stride(from: 0, to: o.data.count - o.data.count % 16, by: 16).compactMap { IPv6Address(bytes: o.data[$0..<$0 + 16])?.description }
                return ["DNS servers: \(list.joined(separator: ", "))"]
            case DHCPv6OptionCode.domainList:
                return ["Domain search: \((try? DHCPDNSWire.decodeList(o.data).joined(separator: ", ")) ?? DHCPHex.string(o.data))"]
            case DHCPv6OptionCode.clientFQDN:
                if let f = try? ClientFQDN(v6: o.data) { return ["Client FQDN: \(f.name) (S=\(f.s ? 1 : 0) O=\(f.o ? 1 : 0) N=\(f.n ? 1 : 0))"] }
                return ["Client FQDN: \(DHCPHex.string(o.data))"]
            case DHCPv6OptionCode.clientID, DHCPv6OptionCode.serverID:
                return ["\(v6Name(o.code)): \(DHCPv6DUID.describe(o.data)) \(DHCPHex.string(o.data))"]
            case DHCPv6OptionCode.rapidCommit:
                return ["Rapid commit"]
            default:
                return ["\(v6Name(o.code)): \(DHCPHex.string(o.data))"]
            }
        }
    }
}
