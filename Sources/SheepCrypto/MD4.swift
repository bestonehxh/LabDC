// Moved from SheepRadius 2.0 (`SheepRadius/MD4.swift`), the owner's own code.
// Adapted for LabDC: `[UInt8]` in and out instead of `Data`, `public`, and the
// NT-hash string helper dropped (KerberosCrypto derives the RC4 key itself).

/// MD4 (RFC 1320), needed for one thing only: the NT hash (RC4-HMAC key, RFC 4757 and
/// MS-CHAP) which is MD4 over the password in UTF-16LE.
///
/// Written out rather than called from CommonCrypto because `CC_MD4` is deprecated, and
/// CryptoKit deliberately has no MD4 — it is broken as a hash and is used here purely as the
/// fixed format Windows defined. Do not reach for this for anything else.
public nonisolated enum MD4 {
    /// The three round functions from RFC 1320 section 3.4.
    private static func f(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (~x & z) }
    private static func g(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }
    private static func h(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }

    /// Returns the 16-byte MD4 digest of `bytes`.
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        // Padding: a 0x80 byte, then zeros until 56 mod 64, then the bit length little-endian.
        var padded = bytes
        let bitLength = UInt64(bytes.count) &* 8
        padded.append(0x80)
        while padded.count % 64 != 56 { padded.append(0) }
        for shift in stride(from: 0, through: 56, by: 8) {
            padded.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
        }

        var a: UInt32 = 0x6745_2301
        var b: UInt32 = 0xEFCD_AB89
        var c: UInt32 = 0x98BA_DCFE
        var d: UInt32 = 0x1032_5476

        padded.withUnsafeBytes { raw in
            for block in stride(from: 0, to: raw.count, by: 64) {
                // Words are little-endian; loadUnaligned keeps this valid on any alignment.
                var x = [UInt32](repeating: 0, count: 16)
                for i in 0..<16 {
                    x[i] = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: block + i * 4, as: UInt32.self))
                }

                let (aa, bb, cc, dd) = (a, b, c, d)

                // Round 1: a = (a + F(b,c,d) + X[k]) <<< s
                for i in stride(from: 0, to: 16, by: 4) {
                    a = (a &+ f(b, c, d) &+ x[i]).rotated(3)
                    d = (d &+ f(a, b, c) &+ x[i + 1]).rotated(7)
                    c = (c &+ f(d, a, b) &+ x[i + 2]).rotated(11)
                    b = (b &+ f(c, d, a) &+ x[i + 3]).rotated(19)
                }
                // Round 2: + the constant 0x5A827999, indices stepping by 4
                for i in 0..<4 {
                    a = (a &+ g(b, c, d) &+ x[i] &+ 0x5A82_7999).rotated(3)
                    d = (d &+ g(a, b, c) &+ x[i + 4] &+ 0x5A82_7999).rotated(5)
                    c = (c &+ g(d, a, b) &+ x[i + 8] &+ 0x5A82_7999).rotated(9)
                    b = (b &+ g(c, d, a) &+ x[i + 12] &+ 0x5A82_7999).rotated(13)
                }
                // Round 3: + the constant 0x6ED9EBA1, bit-reversed index order
                for i in [0, 2, 1, 3] {
                    a = (a &+ h(b, c, d) &+ x[i] &+ 0x6ED9_EBA1).rotated(3)
                    d = (d &+ h(a, b, c) &+ x[i + 8] &+ 0x6ED9_EBA1).rotated(9)
                    c = (c &+ h(d, a, b) &+ x[i + 4] &+ 0x6ED9_EBA1).rotated(11)
                    b = (b &+ h(c, d, a) &+ x[i + 12] &+ 0x6ED9_EBA1).rotated(15)
                }

                a = a &+ aa
                b = b &+ bb
                c = c &+ cc
                d = d &+ dd
            }
        }

        var out = [UInt8]()
        out.reserveCapacity(16)
        for word in [a, b, c, d] {
            for shift in stride(from: 0, through: 24, by: 8) {
                out.append(UInt8(truncatingIfNeeded: word >> UInt32(shift)))
            }
        }
        return out
    }
}

private extension UInt32 {
    /// Left rotate, the only shift MD4 uses.
    nonisolated func rotated(_ places: UInt32) -> UInt32 { (self << places) | (self >> (32 - places)) }
}
