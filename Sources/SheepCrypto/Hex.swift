public extension Array where Element == UInt8 {
    /// Decodes hexadecimal text. Upper and lower case are accepted and whitespace is skipped,
    /// so vectors can be pasted as `"01 02 0a FF"`.
    /// - Precondition: `hex` holds an even number of hex digits and nothing else but
    ///   whitespace. Intended for tests and fixed constants; do not feed it untrusted input.
    nonisolated init(hex: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.utf8.count / 2)
        var high: UInt8?
        for c in hex.utf8 {
            let nibble: UInt8
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): nibble = c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): nibble = c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): nibble = c - UInt8(ascii: "A") + 10
            case UInt8(ascii: " "), UInt8(ascii: "\n"), UInt8(ascii: "\t"), UInt8(ascii: "\r"): continue
            default: preconditionFailure("invalid hex character \(Unicode.Scalar(c))")
            }
            if let h = high {
                bytes.append(h << 4 | nibble)
                high = nil
            } else {
                high = nibble
            }
        }
        precondition(high == nil, "hex string has an odd number of digits")
        self = bytes
    }

    /// Lowercase hexadecimal, no separators. Only for non-secret values.
    nonisolated var hex: String {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(count * 2)
        for byte in self {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
