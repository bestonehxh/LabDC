import CommonCrypto
import Crypto
import _CryptoExtras
import Foundation
import Security
import SwiftASN1
import X509

/// The cryptography of MS-BKRP: the domain's 2048-bit RSA ClientWrap key and its self-signed
/// certificate (§2.2.1), RSA PKCS#1 v1.5 unwrapping of `EncryptedSecret` (§3.1.4.1.4), and the
/// raw (unpadded) CBC decryption of the access check. Key material never leaves this file except
/// as the §2.2.5 secret blob handed to the Store.
public enum BackupKeyCrypto {
    /// A freshly generated ClientWrap key: the §2.2.5 secret (with its certificate) and the GUID
    /// that names it.
    public struct GeneratedKey: Sendable {
        public let guid: [UInt8]
        public let keyPair: ExportedRSAKeyPair
    }

    /// Generates the RSA-2048 key and its certificate (§2.2.1): subject and issuer `CN=<DNS
    /// domain>`, serialNumber/issuerUniqueID/subjectUniqueID from `guid`, valid 365 days from
    /// `now`, self-signed with sha1RSA as Windows (and Samba's `self_sign_cert`) sign it.
    public static func generateClientWrapKey(guid: [UInt8], dnsDomain: String, now: Date) throws -> GeneratedKey {
        let signing = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let numbers = try pkcs1Numbers(signing.derRepresentation)
        let certificate = try makeCertificate(guid: guid, commonName: dnsDomain, notBefore: now, key: signing)
        let pair = ExportedRSAKeyPair(modulus: numbers[1], publicExponent: numbers[2], prime1: numbers[4], prime2: numbers[5],
                                      exponent1: numbers[6], exponent2: numbers[7], coefficient: numbers[8],
                                      privateExponent: numbers[3], certificate: certificate)
        return GeneratedKey(guid: guid, keyPair: pair)
    }

    /// The integers of a PKCS#1 `RSAPrivateKey` (RFC 8017 §A.1.2): version, n, e, d, p, q, dP,
    /// dQ, qInv — big-endian, leading zeros stripped.
    static func pkcs1Numbers(_ der: Data) throws -> [[UInt8]] {
        let node = try DER.parse(Array(der))
        let numbers: [[UInt8]] = try DER.sequence(node, identifier: .sequence) { nodes in
            var out: [[UInt8]] = []
            while let n = nodes.next() {
                guard n.identifier == .integer, case .primitive(let bytes) = n.content else {
                    throw BackupKeyStatus.internalError
                }
                let trimmed = Array(bytes.drop { $0 == 0 })
                out.append(trimmed.isEmpty ? [0] : trimmed)
            }
            return out
        }
        guard numbers.count >= 9 else { throw BackupKeyStatus.internalError }
        return numbers
    }

    /// The RSA private key of a stored §2.2.5 key pair (BoringSSL recomputes the CRT values).
    static func privateKey(_ pair: ExportedRSAKeyPair) throws -> _RSA.Encryption.PrivateKey {
        do {
            return try _RSA.Encryption.PrivateKey(n: pair.modulus, e: pair.publicExponent, d: pair.privateExponent,
                                                  p: pair.prime1, q: pair.prime2)
        } catch {
            throw BackupKeyStatus.internalError
        }
    }

    /// Decrypts `EncryptedSecret` (§3.1.4.1.4 step 3): the client stores the RSA PKCS#1 v1.5
    /// ciphertext little-endian, so it is reversed first. Bad padding is not reported: it yields
    /// random bytes (implicit rejection, as OpenSSL 3.2 does), which then fail the access-check
    /// like any other forged blob — a distinct answer would be a Bleichenbacher padding oracle
    /// on the one key that protects every user's master key in the domain.
    static func unwrapSecret(_ encryptedLittleEndian: [UInt8], pair: ExportedRSAKeyPair) throws -> [UInt8] {
        let key = try privateKey(pair)
        do {
            return [UInt8](try key.decrypt(Array(encryptedLittleEndian.reversed()), padding: ._WEAK_AND_INSECURE_PKCS_V1_5))
        } catch {
            var random = [UInt8](repeating: 0, count: 256)
            _ = SecRandomCopyBytes(kSecRandomDefault, random.count, &random)
            return random
        }
    }

    // MARK: certificate (§2.2.1)

    /// sha1WithRSAEncryption (1.2.840.113549.1.1.5).
    static let sha1WithRSA: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 5]

    static func makeCertificate(guid: [UInt8], commonName: String, notBefore: Date,
                                key: _RSA.Signing.PrivateKey) throws -> [UInt8] {
        let name = try DistinguishedName { CommonName(commonName) }
        let notAfter = notBefore.addingTimeInterval(365 * 24 * 3600)
        var tbsCoder = DER.Serializer()
        try tbsCoder.appendConstructedNode(identifier: .sequence) { c in
            // version [0] EXPLICIT INTEGER 2 (v3)
            try c.serialize(2, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            // serialNumber: the GUID bytes reversed — "identical to subjectUniqueID" read as the
            // little-endian integer CryptoAPI keeps (Samba's `self_sign_cert` does the same).
            // Written unsigned, so a GUID whose last byte has the top bit set gains a leading
            // 0x00 rather than becoming a negative serial.
            try c.serialize(ArraySlice(guid.reversed() as [UInt8]))
            try algorithm(&c)
            try c.serialize(name)                                    // issuer
            try c.appendConstructedNode(identifier: .sequence) { v in
                try v.serialize(try utcTime(notBefore))
                try v.serialize(try utcTime(notAfter))
            }
            try c.serialize(name)                                    // subject
            c.serializeRawBytes(Array(key.publicKey.derRepresentation)) // rsaEncryption SPKI
            // issuerUniqueID [1] IMPLICIT and subjectUniqueID [2] IMPLICIT: the key GUID
            // (MS-DTYP §2.3.4.2 byte order). The client names the key by these when it wraps.
            let uniqueID = ASN1BitString(bytes: ArraySlice(guid))
            try uniqueID.serialize(into: &c, withIdentifier: ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific))
            try uniqueID.serialize(into: &c, withIdentifier: ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific))
        }
        let tbs = tbsCoder.serializedBytes
        let signature = try key.signature(for: Insecure.SHA1.hash(data: tbs), padding: .insecurePKCS1v1_5)
        var certCoder = DER.Serializer()
        try certCoder.appendConstructedNode(identifier: .sequence) { c in
            c.serializeRawBytes(tbs)
            try algorithm(&c)
            try c.serialize(ASN1BitString(bytes: ArraySlice(signature.rawRepresentation)))
        }
        return certCoder.serializedBytes
    }

    private static func algorithm(_ c: inout DER.Serializer) throws {
        try c.appendConstructedNode(identifier: .sequence) { a in
            try a.serialize(sha1WithRSA)
            try a.serialize(ASN1Null())
        }
    }

    private static func utcTime(_ date: Date) throws -> UTCTime {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return try UTCTime(year: c.year!, month: c.month!, day: c.day!, hours: c.hour!, minutes: c.minute!, seconds: c.second!)
    }

    // MARK: access check cipher (§3.1.4.1.4 steps 5–6)

    /// The access check cipher: 3DES-CBC for version 2, AES-256-CBC for version 3, keyed by the
    /// leading bytes of the secret's payload key and IV'd by the rest. No padding — the access
    /// check is whole blocks by construction; a length that is not is ERROR_INVALID_DATA.
    public static func accessCheckCipher(_ operation: CCOperation, version: UInt32, payloadKey: [UInt8],
                                         _ input: [UInt8]) throws -> [UInt8] {
        let (algorithm, keyLength, block): (CCAlgorithm, Int, Int) = version == 2
            ? (CCAlgorithm(kCCAlgorithm3DES), kCCKeySize3DES, kCCBlockSize3DES)
            : (CCAlgorithm(kCCAlgorithmAES), kCCKeySizeAES256, kCCBlockSizeAES128)
        guard payloadKey.count >= keyLength + block, !input.isEmpty, input.count % block == 0 else {
            throw BackupKeyStatus.invalidData
        }
        let key = Array(payloadKey[0..<keyLength])
        let iv = Array(payloadKey[keyLength..<(keyLength + block)])
        var out = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status = key.withUnsafeBufferPointer { k in
            iv.withUnsafeBufferPointer { v in
                input.withUnsafeBufferPointer { i in
                    out.withUnsafeMutableBufferPointer { o in
                        CCCrypt(operation, algorithm, 0, k.baseAddress, k.count, v.baseAddress,
                                i.baseAddress, i.count, o.baseAddress, o.count, &moved)
                    }
                }
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), moved == input.count else { throw BackupKeyStatus.invalidData }
        return out
    }

    /// SHA-1 (version 2) or SHA-512 (version 3) — the access check hash.
    public static func accessCheckHash(version: UInt32, _ bytes: [UInt8]) -> [UInt8] {
        version == 2 ? Array(Insecure.SHA1.hash(data: bytes)) : Array(SHA512.hash(data: bytes))
    }

    // MARK: ServerWrap (§3.1.4.1.1)

    static func hmacSHA1(key: [UInt8], _ parts: [UInt8]...) -> [UInt8] {
        var mac = HMAC<Insecure.SHA1>(key: SymmetricKey(data: key))
        for p in parts { mac.update(data: p) }
        return Array(mac.finalize())
    }
}
