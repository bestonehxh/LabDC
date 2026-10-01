import KerberosCrypto
import SheepCrypto

/// RFC 4121 per-message tokens laid out for connection-oriented DCERPC (MS-RPCE §2.2.2.12), as
/// Windows and impacket drive them for `RPC_C_AUTHN_GSS_KERBEROS` / SPNEGO-Kerberos over
/// `ncacn_ip_tcp`.
///
/// Unlike the SASL/LDAP stream tokens (`CFXToken.wrap`), the RPC layout is an IOV split: the token
/// header and part of the wrapped data live in the PDU auth trailer (the `auth_value` after the
/// 8-byte `sec_trailer`), and the remaining wrapped bytes stay in the PDU stub (`pduData`). At PDU
/// privacy the stub is sealed; at PDU integrity the stub travels in the clear with a MIC token in
/// the trailer. The RPC PDU header is *not* covered here — we decline `PFC_SUPPORT_HEADER_SIGN`
/// (see `KerberosRPCAuthProvider`), which keeps both impacket and Windows on this verified path.
///
/// The AES/CFX layout follows impacket `krb5.gssapi.GSSAPI_AES.GSS_Wrap`/`GSS_Unwrap` exactly,
/// including its "rotate by RRC+EC while storing RRC=28" convention (RFC 4121 §4.2.5 "encrypt in
/// place"). The RC4 layout follows `GSSAPI_RC4.GSS_Wrap` with `authData` (RFC 4757 §7.3).
extension KerberosSecurityContext {
    /// The result of wrapping one PDU stub: the bytes that replace `pduData` and the `auth_value`
    /// that follows the `sec_trailer`.
    public struct RPCWrapped: Sendable {
        public var data: [UInt8]
        public var trailer: [UInt8]
    }

    // MARK: Produce (outgoing PDU)

    /// Wraps one response fragment's marshalled stub. At `confidential` the stub is sealed; otherwise
    /// a MIC covers it and `data` is returned unchanged. `stub` must already carry any RPC alignment
    /// pad the caller placed before the `sec_trailer`.
    public func wrapRPC(stub: [UInt8], confidential: Bool) throws -> RPCWrapped {
        let seq = nextSend()
        if usesCFX {
            return confidential ? try cfxSealProduce(stub, seq: seq) : try cfxMICProduce(stub, seq: seq)
        }
        return try rc4Produce(stub, confidential: confidential, seq: UInt32(truncatingIfNeeded: seq))
    }

    // MARK: Consume (incoming PDU)

    /// Opens one request fragment. At `confidential` `data` is the sealed stub and the plaintext is
    /// returned; otherwise the MIC in `trailer` is verified and `data` is returned unchanged. The
    /// caller strips any RPC alignment pad afterwards.
    public func unwrapRPC(data: [UInt8], trailer: [UInt8], confidential: Bool) throws -> [UInt8] {
        if usesCFX {
            return confidential ? try cfxSealConsume(data: data, trailer: trailer)
                                : try cfxMICConsume(data: data, trailer: trailer)
        }
        return try rc4Consume(data: data, trailer: trailer, confidential: confidential)
    }

    // MARK: - AES / CFX (RFC 4121 §4.2)

    private var cfxFlagsProduce: CFXToken.Flags {
        var f = CFXToken.Flags()
        if sendsFromAcceptor { f.insert(.sentByAcceptor) }
        if acceptorSubkey != nil { f.insert(.acceptorSubkey) }
        return f
    }

    private func cfxSealProduce(_ stub: [UInt8], seq: UInt64) throws -> RPCWrapped {
        let key = tokenKey
        let ec = (16 - stub.count % 16) & 0xF                 // pad to the AES block size
        let data = stub + [UInt8](repeating: 0xFF, count: ec)
        var flags = cfxFlagsProduce
        flags.insert(.sealed)
        let rrc = 28
        let header0 = CFXToken.header(0x0504, flags: flags, ec: UInt16(ec), rrc: 0, seq: seq)
        let cipher = try KerberosCrypto.encrypt(data + header0, key: key,
                                                usage: CFXToken.sealUsage(fromAcceptor: sendsFromAcceptor), rng: rng)
        let rotated = CFXToken.rotateRight(cipher, rrc + ec)
        let split = 16 + rrc + ec
        let headerFinal = CFXToken.header(0x0504, flags: flags, ec: UInt16(ec), rrc: UInt16(rrc), seq: seq)
        return RPCWrapped(data: Array(rotated[split...]), trailer: headerFinal + Array(rotated[0..<split]))
    }

    private func cfxSealConsume(data: [UInt8], trailer: [UInt8]) throws -> [UInt8] {
        guard trailer.count >= 16, trailer[0] == 0x05, trailer[1] == 0x04, trailer[3] == 0xFF else {
            throw AuthKitError.malformed(what: "RPC wrap trailer", reason: "bad TOK_ID or filler")
        }
        let flags = CFXToken.Flags(rawValue: trailer[2])
        guard flags.contains(.sentByAcceptor) == !sendsFromAcceptor else { throw AuthKitError.badDirection }
        guard flags.contains(.sealed) else {
            throw AuthKitError.malformed(what: "RPC wrap trailer", reason: "Sealed flag not set for a privacy PDU")
        }
        let ec = Int(trailer.be16(4)); let rrc = Int(trailer.be16(6)); let seq = trailer.be64(8)
        let key = try cfxKey(flags.contains(.acceptorSubkey))
        let full = Array(trailer[16...]) + data                // reassemble the rotated ciphertext
        let unrotated = CFXToken.rotateLeft(full, rrc + ec)
        let plain: [UInt8]
        do { plain = try KerberosCrypto.decrypt(unrotated, key: key,
                                                usage: CFXToken.sealUsage(fromAcceptor: !sendsFromAcceptor)) }
        catch { throw AuthKitError.integrityCheckFailed("RPC wrap token does not decrypt") }
        guard plain.count >= ec + 16 else { throw AuthKitError.malformed(what: "RPC wrap token", reason: "EC too large") }
        let inner = Array(plain.suffix(16))                    // encrypted copy of the token header (RRC 0)
        guard inner[0..<6] == trailer[0..<6], inner[8..<16] == trailer[8..<16] else {
            throw AuthKitError.integrityCheckFailed("RPC wrap encrypted header mismatch")
        }
        try checkRecv(seq)
        return Array(plain[0..<(plain.count - 16 - ec)])
    }

    private func cfxMICProduce(_ stub: [UInt8], seq: UInt64) throws -> RPCWrapped {
        let flags = cfxFlagsProduce
        let micPad = (4 - stub.count % 4) & 3
        let signed = stub + [UInt8](repeating: UInt8(micPad), count: micPad)
        let header = CFXToken.header(0x0404, flags: flags, ec: 0, rrc: 0, seq: seq)
        let cksum = try KerberosCrypto.checksum(KerberosCrypto.defaultChecksumType(for: tokenKey.type),
                                                data: signed + header, key: tokenKey,
                                                usage: CFXToken.signUsage(fromAcceptor: sendsFromAcceptor))
        return RPCWrapped(data: stub, trailer: header + cksum)
    }

    private func cfxMICConsume(data: [UInt8], trailer: [UInt8]) throws -> [UInt8] {
        guard trailer.count > 16, trailer[0] == 0x04, trailer[1] == 0x04, trailer[3...7].allSatisfy({ $0 == 0xFF }) else {
            throw AuthKitError.malformed(what: "RPC MIC trailer", reason: "bad TOK_ID or filler")
        }
        let flags = CFXToken.Flags(rawValue: trailer[2])
        guard flags.contains(.sentByAcceptor) == !sendsFromAcceptor else { throw AuthKitError.badDirection }
        let seq = trailer.be64(8)
        let key = try cfxKey(flags.contains(.acceptorSubkey))
        let micPad = (4 - data.count % 4) & 3
        let signed = data + [UInt8](repeating: UInt8(micPad), count: micPad)
        let ok = try KerberosCrypto.verifyChecksum(KerberosCrypto.defaultChecksumType(for: key.type),
                                                   data: signed + Array(trailer[0..<16]), key: key,
                                                   usage: CFXToken.signUsage(fromAcceptor: !sendsFromAcceptor),
                                                   expected: Array(trailer[16...]))
        guard ok else { throw AuthKitError.integrityCheckFailed("RPC MIC token checksum") }
        try checkRecv(seq)
        return data
    }

    // MARK: - RC4 legacy (RFC 4757 §7.3, impacket GSSAPI_RC4 + authData)

    /// The mechanism-independent GSS header impacket prepends to an RC4 RPC token.
    private static let rc4GSSHeader: [UInt8] = [0x60, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                                0xf7, 0x12, 0x01, 0x02, 0x02]

    private func rc4Produce(_ stub: [UInt8], confidential: Bool, seq: UInt32) throws -> RPCWrapped {
        // Integrity uses the RFC 4757 MIC token (stub in the clear); privacy uses the WRAP token.
        if !confidential {
            let mic = RC4GSSToken.getMIC(stub, key: tokenKey, fromAcceptor: sendsFromAcceptor, seq: seq)
            return RPCWrapped(data: stub, trailer: mic)
        }
        let k = tokenKey.bytes
        let pad = 8 - stub.count % 8                       // RFC 1964 §1.2.2.3: 1…8 bytes of value pad
        let data = stub + [UInt8](repeating: UInt8(pad), count: pad)
        let hdr8: [UInt8] = [0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xFF, 0xFF]   // TOK_ID|SGN_ALG|SEAL_ALG(RC4)|Filler
        var sndSeq: [UInt8] = []; sndSeq.appendBE32(seq)
        sndSeq += [UInt8](repeating: sendsFromAcceptor ? 0xFF : 0x00, count: 4)
        let confounder = rng.next(8)
        let ksign = HMACMD5.authenticate(key: k, Array("signaturekey".utf8) + [0])
        var md: [UInt8] = []; md.appendLE32(13)
        let sgnCksum = Array(HMACMD5.authenticate(key: ksign, MD5.hash(md + hdr8 + confounder + data)).prefix(8))
        let kseq = HMACMD5.authenticate(key: HMACMD5.authenticate(key: k, [0, 0, 0, 0]), sgnCksum)
        let encSeq = RC4.apply(key: kseq, sndSeq)
        let klocal = k.map { $0 ^ 0xF0 }
        var seqBE: [UInt8] = []; seqBE.appendBE32(seq)
        let kcrypt = HMACMD5.authenticate(key: HMACMD5.authenticate(key: klocal, [0, 0, 0, 0]), seqBE)
        let body = RC4.apply(key: kcrypt, confounder + data)
        let token = hdr8 + encSeq + sgnCksum + Array(body[0..<8])
        return RPCWrapped(data: Array(body[8...]), trailer: Self.rc4GSSHeader + token)
    }

    private func rc4Consume(data: [UInt8], trailer: [UInt8], confidential: Bool) throws -> [UInt8] {
        if !confidential {
            let seq = try RC4GSSToken.verifyMIC(data, token: trailer, key: tokenKey, fromAcceptor: !sendsFromAcceptor)
            try checkRecv(UInt64(seq))
            return data
        }
        guard trailer.count >= 13 + 32 else {
            throw AuthKitError.malformed(what: "RC4 RPC trailer", reason: "too short")
        }
        let tok = Array(trailer[13..<(13 + 32)])
        guard tok[0] == 0x02, tok[1] == 0x01, tok[2] == 0x11, tok[3] == 0x00, tok[4] == 0x10, tok[5] == 0x00 else {
            throw AuthKitError.malformed(what: "RC4 RPC token", reason: "bad TOK_ID/SGN_ALG/SEAL_ALG")
        }
        let hdr8 = Array(tok[0..<8])
        let encSeq = Array(tok[8..<16])
        let sgnCksum = Array(tok[16..<24])
        let encConfounder = Array(tok[24..<32])
        let k = tokenKey.bytes
        let kseq = HMACMD5.authenticate(key: HMACMD5.authenticate(key: k, [0, 0, 0, 0]), sgnCksum)
        let sndSeq = RC4.apply(key: kseq, encSeq)
        guard sndSeq[4..<8].allSatisfy({ $0 == (sendsFromAcceptor ? 0x00 : 0xFF) }) else {
            throw AuthKitError.badDirection
        }
        let seq = sndSeq.be32(0)
        let klocal = k.map { $0 ^ 0xF0 }
        var seqBE: [UInt8] = []; seqBE.appendBE32(seq)
        let kcrypt = HMACMD5.authenticate(key: HMACMD5.authenticate(key: klocal, [0, 0, 0, 0]), seqBE)
        let plain = RC4.apply(key: kcrypt, encConfounder + data)
        let confounder = Array(plain[0..<8])
        let dataPadded = Array(plain[8...])
        let ksign = HMACMD5.authenticate(key: k, Array("signaturekey".utf8) + [0])
        var md: [UInt8] = []; md.appendLE32(13)
        let expected = Array(HMACMD5.authenticate(key: ksign, MD5.hash(md + hdr8 + confounder + dataPadded)).prefix(8))
        guard ConstantTime.equal(expected, sgnCksum) else {
            throw AuthKitError.integrityCheckFailed("RC4 RPC token checksum")
        }
        try checkRecv(UInt64(seq))
        guard let pad = dataPadded.last, (1...8).contains(pad), dataPadded.count >= Int(pad) else {
            throw AuthKitError.malformed(what: "RC4 RPC token", reason: "bad padding")
        }
        return Array(dataPadded.dropLast(Int(pad)))
    }
}
