import Foundation

/// RFC 3748 §4: Code, Identifier, Length, Type, Type-Data. Parsing checks every length.
public struct EAPPacket: Sendable, Equatable {
    public enum Code: UInt8, Sendable { case request = 1, response = 2, success = 3, failure = 4 }

    public var code: Code
    public var id: UInt8
    /// Request/Response only.
    public var type: UInt8?
    public var data: [UInt8]

    public init(code: Code, id: UInt8, type: UInt8? = nil, data: [UInt8] = []) {
        self.code = code; self.id = id; self.type = type; self.data = data
    }

    public init?(_ bytes: [UInt8]) {
        guard bytes.count >= 4, let code = Code(rawValue: bytes[0]) else { return nil }
        let length = Int(bytes[2]) << 8 | Int(bytes[3])
        guard length >= 4, length <= bytes.count else { return nil }
        self.code = code
        self.id = bytes[1]
        if code == .request || code == .response {
            guard length >= 5 else { return nil }
            type = bytes[4]
            data = Array(bytes[5..<length])
        } else {
            type = nil
            data = []
        }
    }

    public var bytes: [UInt8] {
        let body: [UInt8] = type.map { [$0] + data } ?? []
        let length = 4 + body.count
        return [code.rawValue, id, UInt8(length >> 8 & 0xff), UInt8(length & 0xff)] + body
    }

    public static func success(id: UInt8) -> EAPPacket { EAPPacket(code: .success, id: id) }
    public static func failure(id: UInt8) -> EAPPacket { EAPPacket(code: .failure, id: id) }
}

/// EAP method types this server speaks or recognises (IANA "EAP Method Types").
public enum EAPType: UInt8, Sendable, CaseIterable {
    case identity = 1, notification = 2, nak = 3, md5 = 4, gtc = 6, tls = 13, ttls = 21, peap = 25, mschapv2 = 26, tlv = 33

    public var title: String {
        switch self {
        case .identity: "Identity"
        case .notification: "Notification"
        case .nak: "NAK"
        case .md5: "MD5-Challenge"
        case .gtc: "EAP-GTC"
        case .tls: "EAP-TLS"
        case .ttls: "EAP-TTLS"
        case .peap: "PEAP"
        case .mschapv2: "EAP-MSCHAPv2"
        case .tlv: "EAP-TLV"
        }
    }
}

/// The Type-Data of EAP-TLS / PEAP / TTLS (RFC 5216 §3.1, RFC 5281 §9.1): Flags (L 0x80,
/// M 0x40, S 0x20, version in the low 3 bits for PEAP/TTLS), TLS Message Length when L, data.
struct TLSMethodMessage: Equatable {
    static let lengthIncluded: UInt8 = 0x80, moreFragments: UInt8 = 0x40, start: UInt8 = 0x20

    var flags: UInt8
    var totalLength: Int?
    var data: [UInt8]

    init(flags: UInt8, totalLength: Int? = nil, data: [UInt8] = []) {
        self.flags = flags; self.totalLength = totalLength; self.data = data
    }

    init?(_ typeData: [UInt8]) {
        guard let f = typeData.first else { return nil }
        flags = f
        if f & Self.lengthIncluded != 0 {
            guard typeData.count >= 5 else { return nil }
            totalLength = typeData[1...4].reduce(0) { $0 << 8 | Int($1) }
            data = Array(typeData[5...])
        } else {
            totalLength = nil
            data = Array(typeData.dropFirst())
        }
    }

    var bytes: [UInt8] {
        var out = [flags]
        if let totalLength, flags & Self.lengthIncluded != 0 {
            out += [UInt8(totalLength >> 24 & 0xff), UInt8(totalLength >> 16 & 0xff), UInt8(totalLength >> 8 & 0xff), UInt8(totalLength & 0xff)]
        }
        return out + data
    }

    var more: Bool { flags & Self.moreFragments != 0 }
    var isStart: Bool { flags & Self.start != 0 }

    /// Splits `records` into fragments of at most `size` data bytes: the first carries L and the
    /// total length, every one but the last carries M.
    static func fragments(_ records: [UInt8], size: Int, version: UInt8) -> [TLSMethodMessage] {
        let size = max(64, size)
        var out: [TLSMethodMessage] = []
        var i = 0
        repeat {
            let end = min(records.count, i + size)
            var flags = version
            if i == 0 { flags |= lengthIncluded }
            if end < records.count { flags |= moreFragments }
            out.append(TLSMethodMessage(flags: flags, totalLength: i == 0 ? records.count : nil, data: Array(records[i..<end])))
            i = end
        } while i < records.count
        return out
    }
}

/// Diameter-style AVPs inside the TTLS tunnel (RFC 5281 §10): Code (4), Flags (V 0x80,
/// M 0x40), Length (3, header included, padding not), Vendor-ID when V, data padded to 4.
public struct TTLSAVP: Sendable, Equatable {
    public var code: UInt32
    public var vendor: UInt32?
    public var mandatory: Bool
    public var data: [UInt8]

    public init(code: UInt32, vendor: UInt32? = nil, mandatory: Bool = true, data: [UInt8]) {
        self.code = code; self.vendor = vendor; self.mandatory = mandatory; self.data = data
    }

    public var bytes: [UInt8] {
        let header = vendor == nil ? 8 : 12
        let length = header + data.count
        var out: [UInt8] = [UInt8(code >> 24 & 0xff), UInt8(code >> 16 & 0xff), UInt8(code >> 8 & 0xff), UInt8(code & 0xff),
                            (vendor == nil ? 0 : 0x80) | (mandatory ? 0x40 : 0),
                            UInt8(length >> 16 & 0xff), UInt8(length >> 8 & 0xff), UInt8(length & 0xff)]
        if let vendor { out += [UInt8(vendor >> 24 & 0xff), UInt8(vendor >> 16 & 0xff), UInt8(vendor >> 8 & 0xff), UInt8(vendor & 0xff)] }
        out += data
        while out.count % 4 != 0 { out.append(0) }
        return out
    }

    /// All AVPs in `bytes`; nil when one is malformed.
    public static func parse(_ bytes: [UInt8]) -> [TTLSAVP]? {
        var out: [TTLSAVP] = []
        var i = 0
        while i < bytes.count {
            guard i + 8 <= bytes.count else { return nil }
            let code = bytes[i..<(i + 4)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            let flags = bytes[i + 4]
            let length = bytes[(i + 5)..<(i + 8)].reduce(0) { $0 << 8 | Int($1) }
            let header = flags & 0x80 != 0 ? 12 : 8
            guard length >= header, i + length <= bytes.count else { return nil }
            let vendor = header == 12 ? bytes[(i + 8)..<(i + 12)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } : nil
            out.append(TTLSAVP(code: code, vendor: vendor, mandatory: flags & 0x40 != 0, data: Array(bytes[(i + header)..<(i + length)])))
            i += (length + 3) & ~3
        }
        return out
    }
}
