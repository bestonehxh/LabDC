import Foundation

/// A DCE/RPC interface or transfer-syntax identifier: a 128-bit UUID plus a
/// major/minor interface version. The wire form is the "variant 2" UUID encoding
/// used throughout MS-RPCE (first three fields little-endian, last two big-endian)
/// followed, in presentation-context syntax lists, by the version as two UInt16 LE.
public struct DCEUUID: Sendable, Hashable, CustomStringConvertible {
    /// The 16-byte on-the-wire UUID (already in DCE mixed-endian order).
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) {
        precondition(bytes.count == 16, "a UUID is 16 bytes")
        self.bytes = bytes
    }

    /// Parses `00000000-0000-0000-0000-000000000000`.
    public init(_ string: String) {
        let hex = string.filter { $0 != "-" }
        precondition(hex.count == 32, "malformed UUID string \(string)")
        var raw = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            raw.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        // raw is big-endian field order; convert to DCE variant-2 wire order.
        var w = [UInt8](repeating: 0, count: 16)
        // field 1: 4 bytes little-endian
        w[0] = raw[3]; w[1] = raw[2]; w[2] = raw[1]; w[3] = raw[0]
        // field 2: 2 bytes little-endian
        w[4] = raw[5]; w[5] = raw[4]
        // field 3: 2 bytes little-endian
        w[6] = raw[7]; w[7] = raw[6]
        // fields 4 and 5: big-endian as-is
        for k in 8..<16 { w[k] = raw[k] }
        self.bytes = w
    }

    public var description: String {
        // Reconstruct the canonical string from the wire bytes.
        func h(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
        let f1 = h([bytes[3], bytes[2], bytes[1], bytes[0]])
        let f2 = h([bytes[5], bytes[4]])
        let f3 = h([bytes[7], bytes[6]])
        let f4 = h([bytes[8], bytes[9]])
        let f5 = h(Array(bytes[10..<16]))
        return "\(f1)-\(f2)-\(f3)-\(f4)-\(f5)"
    }
}

/// An abstract- or transfer-syntax identifier: a `DCEUUID` and a `(major, minor)`
/// version. Serialised in a presentation context as UUID(16) + major(2 LE) + minor(2 LE).
public struct RPCSyntaxID: Sendable, Hashable {
    public let uuid: DCEUUID
    public let versionMajor: UInt16
    public let versionMinor: UInt16

    public init(uuid: DCEUUID, versionMajor: UInt16, versionMinor: UInt16) {
        self.uuid = uuid
        self.versionMajor = versionMajor
        self.versionMinor = versionMinor
    }

    public init(_ uuidString: String, _ major: UInt16, _ minor: UInt16) {
        self.uuid = DCEUUID(uuidString)
        self.versionMajor = major
        self.versionMinor = minor
    }

    /// The 20-byte presentation-context syntax encoding.
    public var wire: [UInt8] {
        var out = uuid.bytes
        out.append(UInt8(truncatingIfNeeded: versionMajor))
        out.append(UInt8(truncatingIfNeeded: versionMajor >> 8))
        out.append(UInt8(truncatingIfNeeded: versionMinor))
        out.append(UInt8(truncatingIfNeeded: versionMinor >> 8))
        return out
    }

    public init?(wire: ArraySlice<UInt8>) {
        guard wire.count == 20 else { return nil }
        let a = Array(wire)
        self.uuid = DCEUUID(bytes: Array(a[0..<16]))
        self.versionMajor = UInt16(a[16]) | (UInt16(a[17]) << 8)
        self.versionMinor = UInt16(a[18]) | (UInt16(a[19]) << 8)
    }
}

/// The transfer syntaxes named by MS-RPCE.
public enum RPCTransferSyntax {
    /// NDR (`8a885d04-1ceb-11c9-9fe8-08002b104860` v2.0), the one we implement.
    public static let ndr32 = RPCSyntaxID("8a885d04-1ceb-11c9-9fe8-08002b104860", 2, 0)
    /// NDR64 (`71710533-beba-4937-8319-b5dbef9ccc36` v1.0), which we reject at bind.
    public static let ndr64 = RPCSyntaxID("71710533-beba-4937-8319-b5dbef9ccc36", 1, 0)
    /// Bind-time feature negotiation (MS-RPCE §3.3.1.5.3). The last 8 bytes of the UUID
    /// carry the requested feature bits; the version is 1.0.
    public static let bindTimeFeatureNegotiationPrefix = "6cb71c2c-9812-4540"
}
