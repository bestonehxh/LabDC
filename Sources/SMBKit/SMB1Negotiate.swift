/// The SMB1 multi-protocol NEGOTIATE (MS-CIFS §2.2.4.52.1) a client may open with, only to
/// learn that the server speaks SMB2 (MS-SMB2 §3.3.5.3.1).
///
/// ```
/// FF 'S' 'M' 'B' | Command 0x72 | Status(4) | Flags(1) | Flags2(2) | PIDHigh(2) |
/// SecurityFeatures(8) | Reserved(2) | TID(2) | PIDLow(2) | UID(2) | MID(2)       (32 bytes)
/// WordCount(1) = 0 | ByteCount(2) | { 0x02 dialect-string NUL }*
/// ```
public struct SMB1NegotiateRequest: Sendable, Equatable {
    public static let protocolID: [UInt8] = [0xFF, 0x53, 0x4D, 0x42]
    public var dialects: [String]

    public init(dialects: [String]) { self.dialects = dialects }

    public init(parsing b: [UInt8]) throws {
        guard b.count >= 35, Array(b[0..<4]) == Self.protocolID else { throw SMBKitError.malformed("not SMB1") }
        guard b[4] == 0x72 else { throw SMBKitError.protocolViolation("SMB1 command 0x\(String(b[4], radix: 16))") }
        let wordCount = Int(b[32])
        var at = 33 + 2 * wordCount
        guard at + 2 <= b.count else { throw SMBKitError.malformed("SMB1 negotiate truncated") }
        let byteCount = Int(b.le16(at))
        at += 2
        guard let bytes = b.slice(at, byteCount) else { throw SMBKitError.malformed("SMB1 ByteCount \(byteCount)") }
        var out: [String] = []
        var i = 0
        while i < bytes.count {
            guard bytes[i] == 0x02 else { throw SMBKitError.malformed("SMB1 dialect buffer format \(bytes[i])") }
            i += 1
            let start = i
            while i < bytes.count, bytes[i] != 0 { i += 1 }
            out.append(String(decoding: bytes[start..<i], as: UTF8.self))
            i += 1
        }
        dialects = out
    }

    public func encode() -> [UInt8] {
        var body: [UInt8] = []
        for d in dialects { body += [0x02] + Array(d.utf8) + [0] }
        var b = Self.protocolID + [0x72, 0, 0, 0, 0, 0x08, 0x01, 0xC8]
        b.zeros(32 - b.count)
        b.set16(0xFFFF, at: 26)           // PIDLow
        b.append(0)
        b.put16(UInt16(body.count))
        return b + body
    }

    /// The SMB2 answer: "SMB 2.???" gets the wildcard revision 0x02FF, "SMB 2.002" alone
    /// gets 2.0.2, anything else is not for us.
    public var smb2Answer: UInt16? {
        if dialects.contains("SMB 2.???") { return SMB2Dialect.wildcard }
        if dialects.contains("SMB 2.002") { return SMB2Dialect.smb202 }
        return nil
    }
}

/// The SPNEGO token of the NEGOTIATE response (MS-SPNG §2.2.1 NegTokenInit2, MS-SMB2
/// §3.3.5.4): the mechanisms Windows lists, without the optional negHints.
///
/// ```
/// 60 L 06 06 2b0601050502 a0 L 30 L
///   a0 L 30 L { 06 09 2a864882f712010202 | 06 09 2a864886f712010202 | 06 0a 2b06010401823702020a }
/// ```
/// Windows adds `a3 { 30 { a0 { 1b "not_defined_in_RFC4178@please_ignore" } } }`, which every
/// client ignores. It is left out because it is only a valid NegTokenInit2, not a valid RFC 4178
/// NegTokenInit ([3] is mechListMIC there), and Wireshark picks the variant by port (< 1024 means
/// server): on any other port the hint decodes as Malformed.
public enum NegTokenInit2 {
    public static let msKerberosOID: [UInt8] = [0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02]
    public static let kerberosOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02]
    public static let ntlmOID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A]
    public static let spnegoOID: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]

    public static func encode(kerberos: Bool, ntlm: Bool) -> [UInt8] {
        var mechs: [UInt8] = []
        if kerberos { mechs += tlv(0x06, msKerberosOID) + tlv(0x06, kerberosOID) }
        if ntlm { mechs += tlv(0x06, ntlmOID) }
        let seq = tlv(0x30, tlv(0xA0, tlv(0x30, mechs)))
        return tlv(0x60, tlv(0x06, spnegoOID) + tlv(0xA0, seq))
    }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let n = content.count
        var len: [UInt8]
        if n < 0x80 {
            len = [UInt8(n)]
        } else if n < 0x100 {
            len = [0x81, UInt8(n)]
        } else if n < 0x10000 {
            len = [0x82, UInt8(n >> 8), UInt8(n & 0xFF)]
        } else {
            len = [0x83, UInt8(n >> 16), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
        }
        return [tag] + len + content
    }
}
