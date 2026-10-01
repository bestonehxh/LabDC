import CryptoKit
import Foundation

/// PKCS#12 (RFC 7292) in password-integrity + password-privacy mode.
///
/// Reads: MAC with SHA-1/SHA-256/SHA-384/SHA-512 (PKCS#12 KDF) or PBMAC1 (RFC 9579); bags
/// encrypted with PBES2 (AES, 3DES, DES), PBES1 or PKCS#12 PBE (3DES, 2-key 3DES, RC2-40/128,
/// RC4); key bags, shrouded key bags, certificate bags, nested safe-contents bags.
/// Writes: the OpenSSL 3 default layout (encrypted certificate SafeContents, then a data
/// SafeContents with the shrouded key), either modern or legacy.
public enum PKCS12 {
    /// Encryption profile for writing.
    public enum Profile: String, Equatable, Sendable {
        /// PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC for keys and certificates, HMAC-SHA256 MAC,
        /// 2048 iterations (the OpenSSL 3 default).
        case modern
        /// pbeWithSHAAnd3-KeyTripleDES-CBC for keys and certificates, HMAC-SHA1 MAC, 2048
        /// iterations (what Windows calls "TripleDES-SHA1"; readable by old appliances and by
        /// OpenSSL 3 without the legacy provider).
        case legacy
    }

    static func looksLike(_ root: ASN) -> Bool {
        let c = root.children
        guard root.isSequence, c.count >= 2, (try? c[0].int()) == 3, c[1].isSequence,
              let oid = try? c[1].child(0).oid() else { return false }
        return oid == OID.data || oid == OID.signedData
    }

    struct Contents {
        var certificates: [CertificateItem] = []
        var keys: [PrivateKeyItem] = []
        var protection: [String] = []
        var notes: [String] = []
    }

    // MARK: Reading

    static func read(_ root: ASN, password: String?) throws -> Contents {
        let c = root.children
        let authSafe = c[1]
        guard try authSafe.child(0).oid() == OID.data else {
            throw CertConvertError.unsupported("PKCS#12 in public-key integrity mode (signed authSafe) is not supported")
        }
        let authSafeBytes = try authSafe.child(1).child(0).octets()
        var out = Contents()
        if c.count > 2 {
            guard let password else { throw CertConvertError.passwordRequired("this PKCS#12 file is password protected") }
            out.protection.append(try verifyMAC(c[2], data: authSafeBytes, password: password))
        } else {
            out.notes.append("no integrity MAC")
        }
        let safes = try ASN.parse(authSafeBytes)
        for ci in safes.children {
            let type = try ci.child(0).oid()
            switch type {
            case OID.data:
                try readSafeContents(try ASN.parse(try ci.child(1).child(0).octets()), password: password, into: &out)
            case OID.encryptedData:
                guard let password else { throw CertConvertError.passwordRequired("this PKCS#12 file is password protected") }
                let encData = try ci.child(1).child(0)
                let eci = try encData.child(1)
                let scheme = try PBEScheme.parse(try eci.child(1))
                guard let encryptedNode = eci.children.first(where: { $0.isContext(0) }) else {
                    throw CertConvertError.malformed("PKCS#12 EncryptedData without content")
                }
                let plain = try scheme.decrypt(encryptedNode.bytes, password: password)
                guard let safe = try? ASN.parse(plain), safe.isSequence else {
                    throw CertConvertError.badPassword("wrong password for the PKCS#12 file")
                }
                out.protection.append("certificates: \(scheme)")
                try readSafeContents(safe, password: password, into: &out)
            default:
                throw CertConvertError.unsupported("PKCS#12 content type \(type) (public-key privacy mode is not supported)")
            }
        }
        return out
    }

    /// Checks the MAC; returns a description like "MAC: sha256, Iteration 2048".
    private static func verifyMAC(_ macData: ASN, data: [UInt8], password: String) throws -> String {
        let digestInfo = try macData.child(0)
        let alg = try digestInfo.child(0)
        let algOID = try alg.child(0).oid()
        let expected = try digestInfo.child(1).octets()
        let salt = try macData.child(1).octets()
        let iterations = macData.children.count > 2 ? try macData.child(2).int() : 1
        if algOID == OID.pbmac1 {
            let params = try alg.child(1)
            let kdf = try params.child(0)
            guard try kdf.child(0).oid() == OID.pbkdf2 else { throw CertConvertError.unsupported("PBMAC1 key derivation") }
            let kp = try kdf.child(1)
            var prf = HashKind.sha1
            var keyLength: Int?
            for extra in kp.children.dropFirst(2) {
                if extra.isUniversal(2) { keyLength = try extra.int() }
                if extra.isSequence, let h = HashKind(hmacOID: try extra.child(0).oid()) { prf = h }
            }
            let macOID = try params.child(1).child(0).oid()
            guard let mac = HashKind(hmacOID: macOID) else { throw CertConvertError.unsupported("PBMAC1 MAC \(macOID)") }
            let pbIter = try kp.child(1).int()
            let key = try KDF.pbkdf2(prf, password: Array(password.utf8), salt: try kp.child(0).octets(), iterations: pbIter,
                                     keyLength: keyLength ?? mac.outputLength)
            guard constantTimeEqual(mac.hmac(key: key, data), expected) else {
                throw CertConvertError.badPassword("wrong password for the PKCS#12 file (MAC mismatch)")
            }
            return "MAC: PBMAC1 hmacWith\(mac.rawValue.uppercased()), PBKDF2 Iteration \(pbIter)"
        }
        guard let hash = HashKind(digestOID: algOID) else { throw CertConvertError.unsupported("PKCS#12 MAC algorithm \(algOID)") }
        var candidates = [KDF.bmpPassword(password)]
        if password.isEmpty { candidates.append([]) }
        for pw in candidates {
            let key = KDF.pkcs12(hash, id: 3, password: pw, salt: salt, iterations: iterations, length: hash.outputLength)
            if constantTimeEqual(hash.hmac(key: key, data), expected) {
                return "MAC: \(hash.rawValue), Iteration \(iterations)"
            }
        }
        throw CertConvertError.badPassword("wrong password for the PKCS#12 file (MAC mismatch)")
    }

    private static func readSafeContents(_ safe: ASN, password: String?, into out: inout Contents) throws {
        for bag in safe.children {
            let bagType = try bag.child(0).oid()
            let value = try bag.child(1).child(0)
            var friendlyName: String?
            var localKeyID: [UInt8]?
            if bag.children.count > 2 {
                for attr in try bag.child(2).children {
                    let attrOID = try attr.child(0).oid()
                    guard let v = try attr.child(1).children.first else { continue }
                    if attrOID == OID.friendlyName { friendlyName = bmpString(v.bytes) }
                    if attrOID == OID.localKeyID { localKeyID = v.bytes }
                }
            }
            switch bagType {
            case OID.keyBag:
                var key = try PrivateKeyItem(der: value.encoded)
                key.friendlyName = friendlyName
                key.localKeyID = localKeyID
                out.keys.append(key)
            case OID.shroudedKeyBag:
                guard let password else { throw CertConvertError.passwordRequired("the PKCS#12 key is encrypted") }
                let (scheme, plain) = try EncryptedPKCS8.decrypt(value.encoded, password: password)
                var key = try PrivateKeyItem(der: plain)
                key.friendlyName = friendlyName
                key.localKeyID = localKeyID
                key.protection = scheme.description
                out.protection.append("key: \(scheme)")
                out.keys.append(key)
            case OID.certBag:
                let certType = try value.child(0).oid()
                guard certType == OID.x509Certificate else {
                    out.notes.append("skipped a certificate bag of type \(certType)")
                    continue
                }
                var cert = try CertificateItem(der: try value.child(1).child(0).octets())
                cert.friendlyName = friendlyName
                cert.localKeyID = localKeyID
                out.certificates.append(cert)
            case OID.safeContentsBag:
                try readSafeContents(value, password: password, into: &out)
            case OID.crlBag:
                out.notes.append("skipped a CRL bag")
            case OID.secretBag:
                out.notes.append("skipped a secret bag")
            default:
                out.notes.append("skipped a bag of type \(bagType)")
            }
        }
    }

    // MARK: Writing

    /// Builds a PFX. `certificates` should be leaf first; the leaf (the certificate matching
    /// `key`) gets the friendlyName and a localKeyID (SHA-1 of the certificate, as OpenSSL).
    public static func write(key: PrivateKeyItem?, certificates: [CertificateItem], password: String,
                             profile: Profile = .modern, friendlyName: String? = nil, iterations: Int = 2048) throws -> [UInt8] {
        guard key != nil || !certificates.isEmpty else { throw CertConvertError.missing("nothing to put in the PKCS#12 file") }
        let leafIndex = key.flatMap { k in certificates.firstIndex { k.matches($0) } }
        let localKeyID = leafIndex.map { certificates[$0].sha1Fingerprint }

        func attributes(_ name: String?, _ keyID: [UInt8]?) -> [UInt8] {
            var attrs: [[UInt8]] = []
            if let name { attrs.append(DERW.seq(DERW.oid(OID.friendlyName), DERW.setOf([DERW.tlv(0x1E, DERW.bmp(name))]))) }
            if let keyID { attrs.append(DERW.seq(DERW.oid(OID.localKeyID), DERW.setOf([DERW.octets(keyID)]))) }
            return attrs.isEmpty ? [] : DERW.setOf(attrs)
        }

        var safes: [[UInt8]] = []
        if !certificates.isEmpty {
            let bags = certificates.enumerated().map { i, cert in
                let isLeaf = i == leafIndex
                return DERW.seq(
                    DERW.oid(OID.certBag),
                    DERW.context(0, DERW.seq(DERW.oid(OID.x509Certificate), DERW.context(0, DERW.octets(cert.der)))),
                    attributes(isLeaf ? friendlyName : nil, isLeaf ? localKeyID : nil))
            }
            let scheme = profile == .modern ? PBEScheme.modern(iterations: iterations) : PBEScheme.legacy3DES(iterations: iterations)
            let encrypted = try scheme.encrypt(DERW.seq(bags), password: password)
            safes.append(DERW.seq(
                DERW.oid(OID.encryptedData),
                DERW.context(0, DERW.seq(
                    DERW.int(0),
                    DERW.seq(DERW.oid(OID.data), scheme.algorithmIdentifier, DERW.contextPrimitive(0, encrypted))))))
        }
        if let key {
            let scheme = profile == .modern ? PBEScheme.modern(iterations: iterations) : PBEScheme.legacy3DES(iterations: iterations)
            let bag = DERW.seq(
                DERW.oid(OID.shroudedKeyBag),
                DERW.context(0, try EncryptedPKCS8.encrypt(key.pkcs8, password: password, scheme: scheme)),
                attributes(friendlyName, localKeyID))
            safes.append(DERW.seq(DERW.oid(OID.data), DERW.context(0, DERW.octets(DERW.seq(bag)))))
        }
        let authSafe = DERW.seq(safes)
        let hash: HashKind = profile == .modern ? .sha256 : .sha1
        let salt = randomBytes(profile == .modern ? 16 : 8)
        let macKey = KDF.pkcs12(hash, id: 3, password: KDF.bmpPassword(password), salt: salt, iterations: iterations,
                                length: hash.outputLength)
        let mac = hash.hmac(key: macKey, authSafe)
        let macData = DERW.seq(
            DERW.seq(DERW.algorithm(hash.digestOID!, DERW.null), DERW.octets(mac)),
            DERW.octets(salt),
            DERW.int(iterations))
        return DERW.seq(DERW.int(3), DERW.seq(DERW.oid(OID.data), DERW.context(0, DERW.octets(authSafe))), macData)
    }
}

func bmpString(_ bytes: [UInt8]) -> String {
    var units: [UInt16] = []
    var i = 0
    while i + 1 < bytes.count {
        units.append(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
        i += 2
    }
    while units.last == 0 { units.removeLast() }
    return String(decoding: units, as: UTF16.self)
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}
