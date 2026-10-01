import Foundation

/// Errors of the SNTP module.
public enum SNTPKitError: Error, CustomStringConvertible, Sendable, Equatable {
    /// Something already holds the port; `holder` is the `lsof` output.
    case portInUse(port: UInt16, holder: String)
    case listener(String)
    case malformed(String)

    public var description: String {
        switch self {
        case .portInUse(let port, let holder): "SNTP: udp port \(port) is in use by:\n\(holder)"
        case .listener(let s): "SNTP: listener: \(s)"
        case .malformed(let s): "SNTP: malformed packet: \(s)"
        }
    }
}

/// 64-bit NTP timestamp (RFC 4330 §3): seconds since 1900-01-01 00:00 UTC and a 32-bit binary
/// fraction. Era 0 ends in 2036; later dates wrap (seconds modulo 2^32, RFC 4330 §3 "era"), which
/// is what every client expects on the wire.
public struct NTPTimestamp: Sendable, Hashable, CustomStringConvertible {
    /// Seconds between 1900-01-01 and 1970-01-01.
    public static let unixEpochOffset: UInt64 = 2_208_988_800

    public var seconds: UInt32
    public var fraction: UInt32

    public static let zero = NTPTimestamp(seconds: 0, fraction: 0)

    public init(seconds: UInt32, fraction: UInt32) {
        self.seconds = seconds
        self.fraction = fraction
    }

    /// Converts a date (fraction truncated to 2^-32 s).
    public init(date: Date) {
        let t = date.timeIntervalSince1970
        let whole = t.rounded(.down)
        let secs = Int64(whole) + Int64(Self.unixEpochOffset)
        seconds = UInt32(truncatingIfNeeded: secs)
        fraction = UInt32(min((t - whole) * 4_294_967_296.0, 4_294_967_295.0))
    }

    /// The date in era 0 (1900–2036) or, for seconds below 2^31 (after 2036-02-07), era 1.
    public var date: Date {
        var secs = Int64(seconds)
        if seconds < 0x8000_0000 { secs += 1 << 32 }  // RFC 4330 §3: MSB 0 means era 1 (2036+)
        return Date(timeIntervalSince1970: Double(secs - Int64(Self.unixEpochOffset)) + Double(fraction) / 4_294_967_296.0)
    }

    public var bytes: [UInt8] { be32(seconds) + be32(fraction) }

    init(_ b: ArraySlice<UInt8>) {
        let i = b.startIndex
        seconds = rd32(b, i)
        fraction = rd32(b, i + 4)
    }

    public var description: String { String(format: "%08x.%08x", seconds, fraction) }
}

/// The 48-byte NTP header (RFC 4330 §4).
public struct NTPPacket: Sendable, Hashable {
    public static let headerLength = 48

    public enum Mode: UInt8, Sendable {
        case reserved = 0, symmetricActive = 1, symmetricPassive = 2, client = 3, server = 4, broadcast = 5,
             control = 6, privateUse = 7
    }

    public var leapIndicator: UInt8 = 0
    public var version: UInt8 = 4
    public var mode: Mode = .client
    public var stratum: UInt8 = 0
    public var poll: Int8 = 0
    public var precision: Int8 = 0
    /// NTP short format (16.16 seconds).
    public var rootDelay: UInt32 = 0
    /// NTP short format (16.16 seconds).
    public var rootDispersion: UInt32 = 0
    public var referenceID: [UInt8] = [0, 0, 0, 0]
    public var referenceTimestamp: NTPTimestamp = .zero
    public var originateTimestamp: NTPTimestamp = .zero
    public var receiveTimestamp: NTPTimestamp = .zero
    public var transmitTimestamp: NTPTimestamp = .zero

    public init() {}

    /// Decodes the first 48 bytes; anything after them (MS-SNTP authenticator, RFC 5905 MAC) is
    /// the caller's business.
    public init(bytes: [UInt8]) throws {
        guard bytes.count >= Self.headerLength else {
            throw SNTPKitError.malformed("\(bytes.count) bytes, need \(Self.headerLength)")
        }
        leapIndicator = bytes[0] >> 6
        version = (bytes[0] >> 3) & 0x7
        mode = Mode(rawValue: bytes[0] & 0x7)!
        stratum = bytes[1]
        poll = Int8(bitPattern: bytes[2])
        precision = Int8(bitPattern: bytes[3])
        rootDelay = rd32(bytes[...], 4)
        rootDispersion = rd32(bytes[...], 8)
        referenceID = Array(bytes[12..<16])
        referenceTimestamp = NTPTimestamp(bytes[16..<24])
        originateTimestamp = NTPTimestamp(bytes[24..<32])
        receiveTimestamp = NTPTimestamp(bytes[32..<40])
        transmitTimestamp = NTPTimestamp(bytes[40..<48])
    }

    public func encode() -> [UInt8] {
        var out: [UInt8] = [(leapIndicator & 0x3) << 6 | (version & 0x7) << 3 | mode.rawValue,
                            stratum, UInt8(bitPattern: poll), UInt8(bitPattern: precision)]
        out += be32(rootDelay) + be32(rootDispersion)
        out += (referenceID + [0, 0, 0, 0]).prefix(4)
        out += referenceTimestamp.bytes + originateTimestamp.bytes + receiveTimestamp.bytes + transmitTimestamp.bytes
        return out
    }
}

func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
func le32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)] }
func rd32(_ b: ArraySlice<UInt8>, _ i: Int) -> UInt32 {
    UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
}
