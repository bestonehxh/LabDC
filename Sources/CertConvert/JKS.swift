import CryptoKit
import Foundation

/// Sun/Oracle JKS keystore reader (read-only; writing JKS is out of scope).
///
/// Layout (big-endian): magic FEEDFEED, version (1 or 2), entry count, entries, then a SHA-1
/// over (password as UTF-16BE ‖ "Mighty Aphrodite" ‖ everything before the digest).
/// Entry tag 1 = PrivateKeyEntry: alias, timestamp, an `EncryptedPrivateKeyInfo` whose
/// algorithm is the Sun KeyProtector (1.3.6.1.4.1.42.2.17.1.1), then the certificate chain.
/// Entry tag 2 = TrustedCertEntry: alias, timestamp, one certificate. Version 2 prefixes each
/// certificate with its type string ("X.509").
public enum JKS {
    static let magic: [UInt8] = [0xFE, 0xED, 0xFE, 0xED]
    static let jceksMagic: [UInt8] = [0xCE, 0xCE, 0xCE, 0xCE]

    struct Contents {
        var certificates: [CertificateItem] = []
        var keys: [PrivateKeyItem] = []
        var protection: [String] = []
        var notes: [String] = []
    }

    private struct Reader {
        let bytes: [UInt8]
        var pos = 0

        mutating func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= bytes.count else { throw CertConvertError.malformed("JKS file is truncated") }
            defer { pos += n }
            return Array(bytes[pos..<pos + n])
        }

        mutating func u16() throws -> Int { try take(2).reduce(0) { $0 << 8 | Int($1) } }
        mutating func u32() throws -> Int { try take(4).reduce(0) { $0 << 8 | Int($1) } }
        mutating func u64() throws -> UInt64 { try take(8).reduce(0) { $0 << 8 | UInt64($1) } }
        mutating func utf() throws -> String {
            // Java "modified UTF-8"; aliases are plain text in practice.
            String(decoding: try take(try u16()), as: UTF8.self)
        }
    }

    /// Java `char[]` password bytes: UTF-16BE, no terminator.
    static func passwordBytes(_ password: String) -> [UInt8] { DERW.bmp(password) }

    /// Reads the store. `password` checks the integrity digest; `keyPassword` (defaulting to
    /// `password`) decrypts key entries. Without a password only trusted-certificate stores
    /// can be read (the integrity digest is then not checked).
    static func read(_ bytes: [UInt8], password: String?, keyPassword: String?) throws -> Contents {
        var r = Reader(bytes: bytes)
        guard try r.take(4) == magic else { throw CertConvertError.malformed("not a JKS keystore") }
        let version = try r.u32()
        guard version == 1 || version == 2 else { throw CertConvertError.unsupported("JKS version \(version)") }
        let count = try r.u32()
        var out = Contents()
        var pendingKeys: [(alias: String, protected: [UInt8], chain: [CertificateItem])] = []

        func readCert() throws -> CertificateItem {
            if version == 2 {
                let type = try r.utf()
                guard type == "X.509" else { throw CertConvertError.unsupported("JKS certificate type \(type)") }
            }
            return try CertificateItem(der: try r.take(try r.u32()))
        }

        for _ in 0..<count {
            let tag = try r.u32()
            let alias = try r.utf()
            _ = try r.u64()
            switch tag {
            case 1:
                let protected = try r.take(try r.u32())
                let chainCount = try r.u32()
                var chain: [CertificateItem] = []
                for _ in 0..<chainCount {
                    var cert = try readCert()
                    if chain.isEmpty { cert.friendlyName = alias }
                    chain.append(cert)
                }
                pendingKeys.append((alias, protected, chain))
            case 2:
                var cert = try readCert()
                cert.friendlyName = alias
                out.certificates.append(cert)
            case 3:
                throw CertConvertError.unsupported("JKS secret-key entry \(alias) (JCEKS only)")
            default:
                throw CertConvertError.malformed("JKS entry tag \(tag)")
            }
        }
        let body = Array(bytes[..<r.pos])
        let digest = try r.take(20)
        if r.pos != bytes.count { out.notes.append("\(bytes.count - r.pos) bytes after the JKS digest ignored") }

        if let password {
            let computed = Array(Insecure.SHA1.hash(data: passwordBytes(password) + Array("Mighty Aphrodite".utf8) + body))
            guard constantTimeEqual(computed, digest) else {
                throw CertConvertError.badPassword("wrong keystore password (JKS integrity check failed)")
            }
            out.protection.append("integrity: keyed SHA-1 digest")
        } else if !pendingKeys.isEmpty {
            throw CertConvertError.passwordRequired("this Java keystore holds private keys; a password is needed")
        } else {
            out.notes.append("integrity not verified (no password given)")
        }

        for entry in pendingKeys {
            let pw = keyPassword ?? password ?? ""
            let plain = try unprotect(entry.protected, password: pw, alias: entry.alias)
            var key = try PrivateKeyItem(der: plain)
            key.friendlyName = entry.alias
            key.protection = "JKS KeyProtector (SHA-1 keystream)"
            out.keys.append(key)
            out.certificates += entry.chain
        }
        if !pendingKeys.isEmpty { out.protection.append("keys: JKS KeyProtector (SHA-1 keystream)") }
        return out
    }

    /// Sun KeyProtector: salt(20) ‖ (key XOR keystream) ‖ check(20), where the keystream is
    /// SHA-1(password ‖ previous block) starting from the salt and check = SHA-1(password ‖ key).
    static func unprotect(_ encryptedInfo: [UInt8], password: String, alias: String) throws -> [UInt8] {
        let root = try ASN.parse(encryptedInfo)
        let oid = try root.child(0).child(0).oid()
        guard oid == OID.sunJKSKeyProtector else {
            throw CertConvertError.unsupported("JKS key \(alias) protected with \(oid)")
        }
        let blob = try root.child(1).octets()
        guard blob.count > 40 else { throw CertConvertError.malformed("JKS key \(alias) is too short") }
        let pw = passwordBytes(password)
        let salt = Array(blob[0..<20])
        let enc = Array(blob[20..<blob.count - 20])
        let check = Array(blob[(blob.count - 20)...])
        var plain: [UInt8] = []
        plain.reserveCapacity(enc.count)
        var digest = salt
        var i = 0
        while i < enc.count {
            digest = Array(Insecure.SHA1.hash(data: pw + digest))
            for j in 0..<min(20, enc.count - i) { plain.append(enc[i + j] ^ digest[j]) }
            i += 20
        }
        guard constantTimeEqual(Array(Insecure.SHA1.hash(data: pw + plain)), check) else {
            throw CertConvertError.badPassword("wrong key password for JKS entry \(alias)")
        }
        return plain
    }
}
