import KerberosCrypto
import SheepCrypto

/// RFC 4121 §4.2 per-message tokens ("CFX"), used for AES (and every enctype except RC4/DES).
///
/// ```
/// Wrap  05 04 | Flags | FF       | EC (2, BE) | RRC (2, BE) | SND_SEQ (8, BE) | data
/// MIC   04 04 | Flags | FF FF FF FF FF                      | SND_SEQ (8, BE) | SGN_CKSUM
/// Flags 0x01 SentByAcceptor, 0x02 Sealed, 0x04 AcceptorSubkey
/// ```
/// Sealed wrap: data = rotate_right(E(plaintext | EC filler bytes | header with RRC 0), RRC).
/// Integrity-only wrap: data = rotate_right(plaintext | checksum, RRC), EC = checksum length,
/// the checksum covers plaintext | header with EC = RRC = 0.
/// Every Wrap token (sealed or not) uses the SEAL usage, 22 acceptor / 24 initiator; MIC
/// tokens use SIGN, 23 / 25 (RFC 4121 §2; MIT `kg_seal_v3`, Heimdal `_gssapi_wrap_cfx`).
/// MIC: checksum over message | header.
public enum CFXToken {
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }
        public static let sentByAcceptor = Flags(rawValue: 0x01)
        public static let sealed = Flags(rawValue: 0x02)
        public static let acceptorSubkey = Flags(rawValue: 0x04)
    }

    /// RFC 4121 §2 key usages.
    public static let usageAcceptorSeal: Int32 = 22
    public static let usageAcceptorSign: Int32 = 23
    public static let usageInitiatorSeal: Int32 = 24
    public static let usageInitiatorSign: Int32 = 25

    static func sealUsage(fromAcceptor: Bool) -> Int32 { fromAcceptor ? usageAcceptorSeal : usageInitiatorSeal }
    static func signUsage(fromAcceptor: Bool) -> Int32 { fromAcceptor ? usageAcceptorSign : usageInitiatorSign }

    static func header(_ tokID: UInt16, flags: Flags, ec: UInt16, rrc: UInt16, seq: UInt64) -> [UInt8] {
        var h: [UInt8] = []
        h.appendBE16(tokID)
        h.append(flags.rawValue)
        h.append(0xFF)
        if tokID == 0x0404 {
            h += [0xFF, 0xFF, 0xFF, 0xFF]
        } else {
            h.appendBE16(ec)
            h.appendBE16(rrc)
        }
        h.appendBE64(seq)
        return h
    }

    static func rotateRight(_ b: [UInt8], _ n: Int) -> [UInt8] {
        guard !b.isEmpty else { return b }
        let r = n % b.count
        return r == 0 ? b : Array(b[(b.count - r)...] + b[..<(b.count - r)])
    }

    static func rotateLeft(_ b: [UInt8], _ n: Int) -> [UInt8] {
        guard !b.isEmpty else { return b }
        let r = n % b.count
        return r == 0 ? b : Array(b[r...] + b[..<r])
    }

    /// Builds a Wrap token. `ec` is the filler length for sealed tokens (0 for AES-CTS);
    /// `rrc` rotates the data (Heimdal/MIT send 0, Windows sends 28 sealed / 12 signed).
    public static func wrap(_ message: [UInt8], key: KerberosKey, confidential: Bool, fromAcceptor: Bool,
                            acceptorSubkey: Bool, seq: UInt64, ec: UInt16 = 0, rrc: UInt16 = 0,
                            rng: RandomBytes = RandomBytes()) throws -> [UInt8] {
        var flags: Flags = []
        if fromAcceptor { flags.insert(.sentByAcceptor) }
        if acceptorSubkey { flags.insert(.acceptorSubkey) }
        if confidential {
            flags.insert(.sealed)
            let inner = header(0x0504, flags: flags, ec: ec, rrc: 0, seq: seq)
            let plain = message + [UInt8](repeating: 0xFF, count: Int(ec)) + inner
            let cipher = try KerberosCrypto.encrypt(plain, key: key, usage: sealUsage(fromAcceptor: fromAcceptor), rng: rng)
            return header(0x0504, flags: flags, ec: ec, rrc: rrc, seq: seq) + rotateRight(cipher, Int(rrc))
        } else {
            let ctype = KerberosCrypto.defaultChecksumType(for: key.type)
            let cksum = try KerberosCrypto.checksum(ctype, data: message + header(0x0504, flags: flags, ec: 0, rrc: 0, seq: seq),
                                                    key: key, usage: sealUsage(fromAcceptor: fromAcceptor))
            return header(0x0504, flags: flags, ec: UInt16(cksum.count), rrc: rrc, seq: seq)
                + rotateRight(message + cksum, Int(rrc))
        }
    }

    /// Parsed and verified Wrap token.
    public struct Unwrapped: Sendable {
        public var message: [UInt8]
        public var confidential: Bool
        public var seq: UInt64
        public var flags: Flags
    }

    /// Verifies and opens a Wrap token. `key` is chosen by the caller from the token's
    /// AcceptorSubkey flag (`keyFor(flagSet)`); `fromAcceptor` is the direction we expect.
    public static func unwrap(_ token: [UInt8], fromAcceptor: Bool,
                              keyFor: (_ acceptorSubkeyFlag: Bool) throws -> KerberosKey) throws -> Unwrapped {
        guard token.count >= 16, token[0] == 0x05, token[1] == 0x04, token[3] == 0xFF else {
            throw AuthKitError.malformed(what: "RFC 4121 wrap token", reason: "bad TOK_ID or filler")
        }
        let flags = Flags(rawValue: token[2])
        guard flags.contains(.sentByAcceptor) == fromAcceptor else { throw AuthKitError.badDirection }
        let ec = Int(token.be16(4)), rrc = Int(token.be16(6)), seq = token.be64(8)
        let key = try keyFor(flags.contains(.acceptorSubkey))
        let data = rotateLeft(Array(token[16...]), rrc)
        if flags.contains(.sealed) {
            let plain: [UInt8]
            do {
                plain = try KerberosCrypto.decrypt(data, key: key, usage: sealUsage(fromAcceptor: fromAcceptor))
            } catch {
                throw AuthKitError.integrityCheckFailed("wrap token does not decrypt")
            }
            guard plain.count >= ec + 16 else { throw AuthKitError.malformed(what: "wrap token", reason: "EC too large") }
            let inner = Array(plain.suffix(16))
            // The encrypted header copy must match, except RRC (sent as 0 inside).
            guard inner[0..<6] == token[0..<6], inner[8..<16] == token[8..<16] else {
                throw AuthKitError.integrityCheckFailed("encrypted header does not match")
            }
            return Unwrapped(message: Array(plain[..<(plain.count - 16 - ec)]), confidential: true, seq: seq, flags: flags)
        } else {
            let ctype = KerberosCrypto.defaultChecksumType(for: key.type)
            guard ec == ctype.length, data.count >= ec else {
                throw AuthKitError.malformed(what: "wrap token", reason: "EC \(ec) is not the checksum length")
            }
            let message = Array(data[..<(data.count - ec)])
            let cksum = Array(data[(data.count - ec)...])
            let ok = try KerberosCrypto.verifyChecksum(
                ctype, data: message + header(0x0504, flags: flags, ec: 0, rrc: 0, seq: seq), key: key,
                usage: sealUsage(fromAcceptor: fromAcceptor), expected: cksum)
            guard ok else { throw AuthKitError.integrityCheckFailed("wrap token checksum") }
            return Unwrapped(message: message, confidential: false, seq: seq, flags: flags)
        }
    }

    public static func getMIC(_ message: [UInt8], key: KerberosKey, fromAcceptor: Bool, acceptorSubkey: Bool,
                              seq: UInt64) throws -> [UInt8] {
        var flags: Flags = []
        if fromAcceptor { flags.insert(.sentByAcceptor) }
        if acceptorSubkey { flags.insert(.acceptorSubkey) }
        let h = header(0x0404, flags: flags, ec: 0, rrc: 0, seq: seq)
        let cksum = try KerberosCrypto.checksum(KerberosCrypto.defaultChecksumType(for: key.type), data: message + h,
                                                key: key, usage: signUsage(fromAcceptor: fromAcceptor))
        return h + cksum
    }

    /// Verifies a MIC token and returns its sequence number.
    public static func verifyMIC(_ message: [UInt8], token: [UInt8], fromAcceptor: Bool,
                                 keyFor: (_ acceptorSubkeyFlag: Bool) throws -> KerberosKey) throws -> UInt64 {
        guard token.count > 16, token[0] == 0x04, token[1] == 0x04, token[3...7].allSatisfy({ $0 == 0xFF }) else {
            throw AuthKitError.malformed(what: "RFC 4121 MIC token", reason: "bad TOK_ID or filler")
        }
        let flags = Flags(rawValue: token[2])
        guard flags.contains(.sentByAcceptor) == fromAcceptor else { throw AuthKitError.badDirection }
        guard !flags.contains(.sealed) else { throw AuthKitError.malformed(what: "MIC token", reason: "Sealed flag set") }
        let key = try keyFor(flags.contains(.acceptorSubkey))
        let ok = try KerberosCrypto.verifyChecksum(
            KerberosCrypto.defaultChecksumType(for: key.type), data: message + Array(token[..<16]), key: key,
            usage: signUsage(fromAcceptor: fromAcceptor), expected: Array(token[16...]))
        guard ok else { throw AuthKitError.integrityCheckFailed("MIC token checksum") }
        return token.be64(8)
    }
}

/// RFC 4757 §7 legacy per-message tokens for RC4-HMAC keys (RFC 1964 layout, inside the
/// `60 … 06 09 2a864886f712010202` framing).
///
/// ```
/// Wrap  02 01 | SGN_ALG 11 00 | SEAL_ALG 10 00 (sealed) or FF FF | FF FF | SND_SEQ (8) | SGN_CKSUM (8) | Confounder (8) | data | pad
/// MIC   01 01 | SGN_ALG 11 00 | FF FF FF FF                       | SND_SEQ (8) | SGN_CKSUM (8)
/// SND_SEQ   = RC4(Kseq, seq (4, BE) | direction (4): 00000000 initiator, FFFFFFFF acceptor)
/// Kseq      = HMAC-MD5(HMAC-MD5(K, 00000000), SGN_CKSUM)
/// Kcrypt    = HMAC-MD5(HMAC-MD5(K XOR F0…F0, 00000000), seq (4, BE))
/// SGN_CKSUM = first 8 bytes of hmac-md5 checksum (RFC 4757 §4), T = 13 (wrap) / 15 (MIC),
///             over the 8 header bytes | confounder | data | pad (wrap) or header | message (MIC)
/// ```
/// Sealed: confounder | data | pad are RC4(Kcrypt) as one stream. Pad is one 0x01 byte (as
/// Heimdal sends); on input 1…8 bytes of value n are accepted.
public enum RC4GSSToken {
    static let usageSeal: UInt32 = 13
    static let usageSign: UInt32 = 15

    /// RFC 4757 §4 `hmac-md5` checksum with a raw message type T (no usage translation).
    static func checksum(key: [UInt8], t: UInt32, _ data: [UInt8]) -> [UInt8] {
        let ksign = HMACMD5.authenticate(key: key, Array("signaturekey".utf8) + [0])
        var tb: [UInt8] = []
        tb.appendLE32(t)
        return HMACMD5.authenticate(key: ksign, MD5.hash(tb + data))
    }

    static func seqKey(_ key: [UInt8], cksum: [UInt8]) -> [UInt8] {
        HMACMD5.authenticate(key: HMACMD5.authenticate(key: key, [0, 0, 0, 0]), cksum)
    }

    static func cryptKey(_ key: [UInt8], seq: UInt32) -> [UInt8] {
        let local = key.map { $0 ^ 0xF0 }
        var s: [UInt8] = []
        s.appendBE32(seq)
        return HMACMD5.authenticate(key: HMACMD5.authenticate(key: local, [0, 0, 0, 0]), s)
    }

    static func sndSeq(_ seq: UInt32, fromAcceptor: Bool) -> [UInt8] {
        var s: [UInt8] = []
        s.appendBE32(seq)
        return s + [UInt8](repeating: fromAcceptor ? 0xFF : 0x00, count: 4)
    }

    public static func wrap(_ message: [UInt8], key: KerberosKey, confidential: Bool, fromAcceptor: Bool,
                            seq: UInt32, rng: RandomBytes = RandomBytes()) -> [UInt8] {
        let k = key.bytes
        let hdr: [UInt8] = [0x02, 0x01, 0x11, 0x00] + (confidential ? [0x10, 0x00] : [0xFF, 0xFF]) + [0xFF, 0xFF]
        let confounder = rng.next(8)
        let data = message + [0x01]
        let cksum = Array(checksum(key: k, t: usageSeal, hdr + confounder + data).prefix(8))
        var body = confounder + data
        if confidential { body = RC4.apply(key: cryptKey(k, seq: seq), body) }
        let encSeq = RC4.apply(key: seqKey(k, cksum: cksum), sndSeq(seq, fromAcceptor: fromAcceptor))
        return GSSFraming.wrap(mech: .kerberos, hdr + encSeq + cksum + body)
    }

    public struct Unwrapped: Sendable {
        public var message: [UInt8]
        public var confidential: Bool
        public var seq: UInt32
    }

    static func open(_ token: [UInt8], tokID: [UInt8]) throws -> [UInt8] {
        let (mech, inner) = try GSSFraming.unwrap(token)
        guard mech.isKerberos else { throw AuthKitError.malformed(what: "RC4 token", reason: "mech is \(mech)") }
        guard inner.count >= 24, Array(inner[0..<2]) == tokID, inner[2] == 0x11, inner[3] == 0x00 else {
            throw AuthKitError.malformed(what: "RC4 token", reason: "bad TOK_ID or SGN_ALG")
        }
        return inner
    }

    /// Returns the sequence number after checking direction bytes.
    static func decodeSeq(_ inner: [UInt8], key: [UInt8], fromAcceptor: Bool) throws -> UInt32 {
        let cksum = Array(inner[16..<24])
        let plain = RC4.apply(key: seqKey(key, cksum: cksum), Array(inner[8..<16]))
        guard plain[4..<8].allSatisfy({ $0 == (fromAcceptor ? 0xFF : 0x00) }) else { throw AuthKitError.badDirection }
        return plain.be32(0)
    }

    public static func unwrap(_ token: [UInt8], key: KerberosKey, fromAcceptor: Bool) throws -> Unwrapped {
        let inner = try open(token, tokID: [0x02, 0x01])
        guard inner.count >= 33, inner[6] == 0xFF, inner[7] == 0xFF else {
            throw AuthKitError.malformed(what: "RC4 wrap token", reason: "too short or bad filler")
        }
        let sealed: Bool
        switch (inner[4], inner[5]) {
        case (0x10, 0x00): sealed = true
        case (0xFF, 0xFF): sealed = false
        default: throw AuthKitError.unsupported("RC4 wrap SEAL_ALG \(inner[4]) \(inner[5])")
        }
        let k = key.bytes
        let seq = try decodeSeq(inner, key: k, fromAcceptor: fromAcceptor)
        var body = Array(inner[24...])
        if sealed { body = RC4.apply(key: cryptKey(k, seq: seq), body) }
        let expected = Array(checksum(key: k, t: usageSeal, Array(inner[0..<8]) + body).prefix(8))
        guard ConstantTime.equal(expected, Array(inner[16..<24])) else {
            throw AuthKitError.integrityCheckFailed("RC4 wrap checksum")
        }
        let data = Array(body[8...])
        guard let pad = data.last, (1...8).contains(pad), data.count >= Int(pad),
              data.suffix(Int(pad)).allSatisfy({ $0 == pad }) else {
            throw AuthKitError.malformed(what: "RC4 wrap token", reason: "bad padding")
        }
        return Unwrapped(message: Array(data.dropLast(Int(pad))), confidential: sealed, seq: seq)
    }

    public static func getMIC(_ message: [UInt8], key: KerberosKey, fromAcceptor: Bool, seq: UInt32) -> [UInt8] {
        let k = key.bytes
        let hdr: [UInt8] = [0x01, 0x01, 0x11, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        let cksum = Array(checksum(key: k, t: usageSign, hdr + message).prefix(8))
        let encSeq = RC4.apply(key: seqKey(k, cksum: cksum), sndSeq(seq, fromAcceptor: fromAcceptor))
        return GSSFraming.wrap(mech: .kerberos, hdr + encSeq + cksum)
    }

    /// Verifies a MIC token and returns its sequence number.
    public static func verifyMIC(_ message: [UInt8], token: [UInt8], key: KerberosKey, fromAcceptor: Bool) throws -> UInt32 {
        let inner = try open(token, tokID: [0x01, 0x01])
        guard inner.count == 24, inner[4..<8].allSatisfy({ $0 == 0xFF }) else {
            throw AuthKitError.malformed(what: "RC4 MIC token", reason: "bad length or filler")
        }
        let k = key.bytes
        let expected = Array(checksum(key: k, t: usageSign, Array(inner[0..<8]) + message).prefix(8))
        guard ConstantTime.equal(expected, Array(inner[16..<24])) else {
            throw AuthKitError.integrityCheckFailed("RC4 MIC checksum")
        }
        return try decodeSeq(inner, key: k, fromAcceptor: fromAcceptor)
    }
}
