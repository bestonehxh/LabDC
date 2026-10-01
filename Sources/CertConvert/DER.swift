import Foundation
import SwiftASN1

/// Object identifiers used by the converter (dotted strings, compared as text).
enum OID {
    // Keys
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let ecPublicKey = "1.2.840.10045.2.1"
    static let ed25519 = "1.3.101.112"
    static let p256 = "1.2.840.10045.3.1.7"
    static let p384 = "1.3.132.0.34"
    static let p521 = "1.3.132.0.35"
    // PKCS#7
    static let data = "1.2.840.113549.1.7.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let encryptedData = "1.2.840.113549.1.7.6"
    // PKCS#5
    static let pbes2 = "1.2.840.113549.1.5.13"
    static let pbkdf2 = "1.2.840.113549.1.5.12"
    static let pbmac1 = "1.2.840.113549.1.5.14"
    static let pbeMD5DES = "1.2.840.113549.1.5.3"
    static let pbeMD5RC2 = "1.2.840.113549.1.5.6"
    static let pbeSHA1DES = "1.2.840.113549.1.5.10"
    static let pbeSHA1RC2 = "1.2.840.113549.1.5.11"
    // PRFs / digests
    static let hmacSHA1 = "1.2.840.113549.2.7"
    static let hmacSHA256 = "1.2.840.113549.2.9"
    static let hmacSHA384 = "1.2.840.113549.2.10"
    static let hmacSHA512 = "1.2.840.113549.2.11"
    static let sha1 = "1.3.14.3.2.26"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let sha384 = "2.16.840.1.101.3.4.2.2"
    static let sha512 = "2.16.840.1.101.3.4.2.3"
    // Ciphers
    static let aes128CBC = "2.16.840.1.101.3.4.1.2"
    static let aes192CBC = "2.16.840.1.101.3.4.1.22"
    static let aes256CBC = "2.16.840.1.101.3.4.1.42"
    static let desEDE3CBC = "1.2.840.113549.3.7"
    static let desCBC = "1.3.14.3.2.7"
    // PKCS#12 PBE
    static let pkcs12SHA1RC4_128 = "1.2.840.113549.1.12.1.1"
    static let pkcs12SHA1RC4_40 = "1.2.840.113549.1.12.1.2"
    static let pkcs12SHA13DES = "1.2.840.113549.1.12.1.3"
    static let pkcs12SHA12DES = "1.2.840.113549.1.12.1.4"
    static let pkcs12SHA1RC2_128 = "1.2.840.113549.1.12.1.5"
    static let pkcs12SHA1RC2_40 = "1.2.840.113549.1.12.1.6"
    // PKCS#12 bags and attributes
    static let keyBag = "1.2.840.113549.1.12.10.1.1"
    static let shroudedKeyBag = "1.2.840.113549.1.12.10.1.2"
    static let certBag = "1.2.840.113549.1.12.10.1.3"
    static let crlBag = "1.2.840.113549.1.12.10.1.4"
    static let secretBag = "1.2.840.113549.1.12.10.1.5"
    static let safeContentsBag = "1.2.840.113549.1.12.10.1.6"
    static let x509Certificate = "1.2.840.113549.1.9.22.1"
    static let friendlyName = "1.2.840.113549.1.9.20"
    static let localKeyID = "1.2.840.113549.1.9.21"
    // Java
    static let sunJKSKeyProtector = "1.3.6.1.4.1.42.2.17.1.1"
}

/// A thin reading layer over SwiftASN1's node tree (DER first, BER as a fallback so the
/// indefinite-length PKCS#7/PKCS#12 some Windows and NSS tools write are accepted).
struct ASN {
    let node: ASN1Node

    init(_ node: ASN1Node) { self.node = node }

    /// Parses one complete element (trailing bytes are rejected).
    static func parse(_ bytes: [UInt8]) throws -> ASN {
        if let n = try? DER.parse(bytes) { return ASN(n) }
        do { return ASN(try BER.parse(bytes)) } catch {
            throw CertConvertError.malformed("not valid DER/BER (\(error))")
        }
    }

    /// Parses the first element of `bytes`, ignoring anything after it (definite lengths only).
    static func parsePrefix(_ bytes: [UInt8]) throws -> ASN {
        guard let len = tlvLength(bytes) else { return try parse(bytes) }
        return try parse(Array(bytes[..<len]))
    }

    var tagClass: ASN1Identifier.TagClass { node.identifier.tagClass }
    var tagNumber: UInt { node.identifier.tagNumber }
    var isConstructed: Bool { if case .constructed = node.content { true } else { false } }
    var encoded: [UInt8] { Array(node.encodedBytes) }

    func isUniversal(_ tag: UInt) -> Bool { tagClass == .universal && tagNumber == tag }
    func isContext(_ tag: UInt) -> Bool { tagClass == .contextSpecific && tagNumber == tag }
    var isSequence: Bool { isUniversal(16) && isConstructed }

    /// Children of a constructed node (empty for a primitive one).
    var children: [ASN] {
        if case .constructed(let c) = node.content { return c.map(ASN.init) }
        return []
    }

    func child(_ i: Int) throws -> ASN {
        let c = children
        guard i < c.count else { throw CertConvertError.malformed("missing ASN.1 element \(i)") }
        return c[i]
    }

    /// Primitive content bytes; a constructed string (BER) is concatenated.
    var bytes: [UInt8] {
        switch node.content {
        case .primitive(let b): return Array(b)
        case .constructed(let c): return c.flatMap { ASN($0).bytes }
        }
    }

    func oid() throws -> String {
        guard isUniversal(6) else { throw CertConvertError.malformed("expected an OBJECT IDENTIFIER") }
        return try ASN1ObjectIdentifier(derEncoded: node).description
    }

    /// Non-negative INTEGER as Int (iteration counts, versions).
    func int() throws -> Int {
        guard isUniversal(2) else { throw CertConvertError.malformed("expected an INTEGER") }
        var b = bytes
        guard let first = b.first, first & 0x80 == 0 else { throw CertConvertError.malformed("negative or empty INTEGER") }
        while b.count > 1, b[0] == 0 { b.removeFirst() }
        guard b.count <= 7 else { throw CertConvertError.malformed("INTEGER out of range") }
        return b.reduce(0) { $0 << 8 | Int($1) }
    }

    /// INTEGER magnitude bytes without the sign-padding zero.
    func unsignedInteger() throws -> [UInt8] {
        guard isUniversal(2) else { throw CertConvertError.malformed("expected an INTEGER") }
        var b = bytes
        while b.count > 1, b[0] == 0 { b.removeFirst() }
        return b
    }

    func octets() throws -> [UInt8] {
        guard isUniversal(4) else { throw CertConvertError.malformed("expected an OCTET STRING") }
        return bytes
    }

    /// BIT STRING content without the unused-bits byte (only whole-byte strings are used here).
    func bitStringBytes() throws -> [UInt8] {
        guard isUniversal(3) else { throw CertConvertError.malformed("expected a BIT STRING") }
        let b = bytes
        guard let first = b.first, first == 0 else { throw CertConvertError.malformed("BIT STRING with unused bits") }
        return Array(b.dropFirst())
    }

    /// Length of the first TLV in `bytes` (definite lengths only), or nil if truncated/indefinite.
    static func tlvLength(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 2 else { return nil }
        var i = 1
        if bytes[0] & 0x1F == 0x1F {
            while i < bytes.count, bytes[i] & 0x80 != 0 { i += 1 }
            i += 1
        }
        guard i < bytes.count else { return nil }
        let first = bytes[i]
        i += 1
        var len = 0
        if first < 0x80 {
            len = Int(first)
        } else if first == 0x80 {
            return nil
        } else {
            let n = Int(first & 0x7F)
            guard n <= 4, i + n <= bytes.count else { return nil }
            for _ in 0..<n {
                len = len << 8 | Int(bytes[i])
                i += 1
            }
        }
        guard i + len <= bytes.count else { return nil }
        return i + len
    }
}

/// Minimal DER writer. Every builder returns a complete TLV.
enum DERW {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out = [tag]
        let n = content.count
        if n < 0x80 {
            out.append(UInt8(n))
        } else {
            var len: [UInt8] = []
            var v = n
            while v > 0 {
                len.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            out.append(0x80 | UInt8(len.count))
            out += len
        }
        return out + content
    }

    static func seq(_ parts: [UInt8]...) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    static func seq(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    /// DER SET OF: elements sorted by their encodings.
    static func setOf(_ parts: [[UInt8]]) -> [UInt8] {
        tlv(0x31, parts.sorted { $0.lexicographicallyPrecedes($1) }.flatMap { $0 })
    }
    static func octets(_ b: [UInt8]) -> [UInt8] { tlv(0x04, b) }
    static let null: [UInt8] = [0x05, 0x00]
    static func bitString(_ b: [UInt8]) -> [UInt8] { tlv(0x03, [0] + b) }
    /// Context tag `[n]`, constructed (explicit, or implicit over a constructed type).
    static func context(_ n: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0xA0 | n, content) }
    /// Context tag `[n]`, primitive (implicit over a primitive type).
    static func contextPrimitive(_ n: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0x80 | n, content) }

    static func int(_ v: Int) -> [UInt8] {
        precondition(v >= 0)
        var b: [UInt8] = []
        var x = v
        repeat {
            b.insert(UInt8(x & 0xFF), at: 0)
            x >>= 8
        } while x > 0
        if b[0] & 0x80 != 0 { b.insert(0, at: 0) }
        return tlv(0x02, b)
    }

    /// INTEGER from unsigned magnitude bytes.
    static func unsignedInt(_ magnitude: [UInt8]) -> [UInt8] {
        var b = Array(magnitude.drop { $0 == 0 })
        if b.isEmpty { b = [0] }
        if b[0] & 0x80 != 0 { b.insert(0, at: 0) }
        return tlv(0x02, b)
    }

    static func oid(_ dotted: String) -> [UInt8] {
        let arcs = dotted.split(separator: ".").map { UInt64($0)! }
        precondition(arcs.count >= 2)
        var body: [UInt8] = []
        func base128(_ v: UInt64) {
            var chunk: [UInt8] = [UInt8(v & 0x7F)]
            var x = v >> 7
            while x > 0 {
                chunk.insert(UInt8(x & 0x7F) | 0x80, at: 0)
                x >>= 7
            }
            body += chunk
        }
        base128(arcs[0] * 40 + arcs[1])
        for a in arcs.dropFirst(2) { base128(a) }
        return tlv(0x06, body)
    }

    /// AlgorithmIdentifier; `params` nil omits the parameters, `DERW.null` writes NULL.
    static func algorithm(_ oid: String, _ params: [UInt8]?) -> [UInt8] {
        seq(DERW.oid(oid), params ?? [])
    }

    /// BMPString content (UTF-16BE).
    static func bmp(_ s: String) -> [UInt8] {
        s.utf16.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
    }
}

extension Array where Element == UInt8 {
    /// Lower-case hex without separators.
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    /// Upper-case hex with `:` separators (fingerprint style).
    var colonHex: String { map { String(format: "%02X", $0) }.joined(separator: ":") }
}
