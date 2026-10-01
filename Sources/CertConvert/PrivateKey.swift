import CryptoKit
import Foundation
import X509

/// Named elliptic curves the converter handles.
public enum ECCurve: String, Equatable, Sendable {
    case p256 = "P-256"
    case p384 = "P-384"
    case p521 = "P-521"

    var oid: String {
        switch self {
        case .p256: OID.p256
        case .p384: OID.p384
        case .p521: OID.p521
        }
    }

    /// Private scalar length in bytes.
    var scalarLength: Int {
        switch self {
        case .p256: 32
        case .p384: 48
        case .p521: 66
        }
    }

    init?(oid: String) {
        switch oid {
        case OID.p256: self = .p256
        case OID.p384: self = .p384
        case OID.p521: self = .p521
        default: return nil
        }
    }

    /// Uncompressed public point for a private scalar.
    func publicPoint(privateScalar: [UInt8]) throws -> [UInt8] {
        switch self {
        case .p256: Array(try P256.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation)
        case .p384: Array(try P384.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation)
        case .p521: Array(try P521.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation)
        }
    }
}

/// Key type and size, for certificates and private keys alike.
public enum KeyAlgorithm: Equatable, Sendable, CustomStringConvertible {
    case rsa(bits: Int)
    case ec(ECCurve)
    case ed25519
    case other(oid: String)

    public var description: String {
        switch self {
        case .rsa(let bits): "RSA \(bits)"
        case .ec(let curve): "EC \(curve.rawValue)"
        case .ed25519: "Ed25519"
        case .other(let oid): "unknown key type \(oid)"
        }
    }

    /// Parses a SubjectPublicKeyInfo.
    static func fromSPKI(_ spki: [UInt8]) throws -> KeyAlgorithm {
        let root = try ASN.parse(spki)
        let alg = try root.child(0)
        let oid = try alg.child(0).oid()
        switch oid {
        case OID.rsaEncryption:
            let rsa = try ASN.parse(try root.child(1).bitStringBytes())
            return .rsa(bits: bitLength(try rsa.child(0).unsignedInteger()))
        case OID.ecPublicKey:
            let curveOID = try alg.child(1).oid()
            guard let curve = ECCurve(oid: curveOID) else { return .other(oid: curveOID) }
            return .ec(curve)
        case OID.ed25519:
            return .ed25519
        default:
            return .other(oid: oid)
        }
    }
}

func bitLength(_ magnitude: [UInt8]) -> Int {
    guard let i = magnitude.firstIndex(where: { $0 != 0 }) else { return 0 }
    return (magnitude.count - i) * 8 - magnitude[i].leadingZeroBitCount
}

/// Private key output encodings.
public enum KeyEncoding: String, Equatable, Sendable, CaseIterable {
    /// `-----BEGIN PRIVATE KEY-----` (or `ENCRYPTED PRIVATE KEY` with a password).
    case pkcs8
    /// `-----BEGIN RSA PRIVATE KEY-----` for RSA, `-----BEGIN EC PRIVATE KEY-----` for EC
    /// (OpenSSL "traditional"; with a password, `Proc-Type`/`DEK-Info` encryption).
    case traditional
}

/// A private key, held as a canonical unencrypted PKCS#8 `PrivateKeyInfo` (the form
/// `openssl pkey -outform DER` writes: RSA with the PKCS#1 key inside; EC with the curve in the
/// AlgorithmIdentifier and an inner SEC1 key without parameters but with the public key).
public struct PrivateKeyItem: Equatable, Sendable {
    public let pkcs8: [UInt8]
    public let algorithm: KeyAlgorithm
    /// PKCS#12 friendlyName / JKS alias, if the container had one.
    public var friendlyName: String?
    /// PKCS#12 localKeyID, if the container had one.
    public var localKeyID: [UInt8]?
    /// How the key was protected in the input (nil if it was not encrypted).
    public var protection: String?

    /// Accepts PKCS#8, PKCS#1 (RSA) or SEC1 (EC) DER.
    public init(der: [UInt8]) throws {
        let root = try ASN.parse(der)
        let c = root.children
        guard root.isSequence, c.count >= 2 else { throw CertConvertError.malformed("not a private key") }
        if c.count >= 3, c[1].isSequence, c[2].isUniversal(4) {
            try self.init(pkcs8: root)
        } else if c.count >= 9, c.allSatisfy({ $0.isUniversal(2) }) {
            self.init(canonical: Self.rsaPKCS8(pkcs1: der), algorithm: .rsa(bits: bitLength(try c[1].unsignedInteger())))
        } else if c[0].isUniversal(2), c[1].isUniversal(4) {
            try self.init(sec1: root, curveOID: nil)
        } else {
            throw CertConvertError.malformed("unrecognised private key structure")
        }
    }

    private init(canonical: [UInt8], algorithm: KeyAlgorithm) {
        self.pkcs8 = canonical
        self.algorithm = algorithm
    }

    private init(pkcs8 root: ASN) throws {
        let alg = try root.child(1)
        let oid = try alg.child(0).oid()
        let inner = try root.child(2).octets()
        switch oid {
        case OID.rsaEncryption:
            let rsa = try ASN.parse(inner)
            self.init(canonical: Self.rsaPKCS8(pkcs1: inner), algorithm: .rsa(bits: bitLength(try rsa.child(1).unsignedInteger())))
        case OID.ecPublicKey:
            let params = alg.children.count > 1 ? try alg.child(1) : nil
            let curveOID = try params.flatMap { $0.isUniversal(6) ? try $0.oid() : nil }
            try self.init(sec1: try ASN.parse(inner), curveOID: curveOID)
        case OID.ed25519:
            let seed = try ASN.parse(inner).octets()
            guard seed.count == 32 else { throw CertConvertError.malformed("Ed25519 key is not 32 bytes") }
            self.init(canonical: DERW.seq(DERW.int(0), DERW.algorithm(OID.ed25519, nil), DERW.octets(DERW.octets(seed))),
                      algorithm: .ed25519)
        default:
            throw CertConvertError.unsupported("private key algorithm \(oid)")
        }
    }

    /// SEC1 `ECPrivateKey`; the curve comes from the PKCS#8 wrapper or from `[0]`.
    private init(sec1 root: ASN, curveOID outer: String?) throws {
        guard try root.child(0).int() == 1 else { throw CertConvertError.malformed("EC private key version is not 1") }
        var scalar = try root.child(1).octets()
        var curveOID = outer
        var point: [UInt8]?
        for extra in root.children.dropFirst(2) {
            if extra.isContext(0), let o = try? extra.child(0).oid() { curveOID = curveOID ?? o }
            if extra.isContext(1) { point = try extra.child(0).bitStringBytes() }
        }
        guard let curveOID else { throw CertConvertError.malformed("EC private key without a named curve") }
        guard let curve = ECCurve(oid: curveOID) else { throw CertConvertError.unsupported("EC curve \(curveOID)") }
        while scalar.count > curve.scalarLength, scalar.first == 0 { scalar.removeFirst() }
        guard scalar.count <= curve.scalarLength else { throw CertConvertError.malformed("EC private scalar too long") }
        scalar = [UInt8](repeating: 0, count: curve.scalarLength - scalar.count) + scalar
        let pub = try point ?? curve.publicPoint(privateScalar: scalar)
        let inner = DERW.seq(DERW.int(1), DERW.octets(scalar), DERW.context(1, DERW.bitString(pub)))
        self.init(canonical: DERW.seq(DERW.int(0), DERW.algorithm(OID.ecPublicKey, DERW.oid(curveOID)), DERW.octets(inner)),
                  algorithm: .ec(curve))
    }

    private static func rsaPKCS8(pkcs1: [UInt8]) -> [UInt8] {
        DERW.seq(DERW.int(0), DERW.algorithm(OID.rsaEncryption, DERW.null), DERW.octets(pkcs1))
    }

    // MARK: Encodings

    /// The key inside the PKCS#8 wrapper as it is stored there.
    private var innerKey: [UInt8] {
        // pkcs8 is canonical and was built by us: child 2 is the OCTET STRING.
        (try? ASN.parse(pkcs8).child(2).octets()) ?? []
    }

    /// PKCS#1 `RSAPrivateKey` (RSA) or SEC1 `ECPrivateKey` with parameters and public key (EC),
    /// matching `openssl rsa -traditional` / `openssl ec`.
    public func traditionalDER() throws -> [UInt8] {
        switch algorithm {
        case .rsa:
            return innerKey
        case .ec(let curve):
            let sec1 = try ASN.parse(innerKey)
            let scalar = try sec1.child(1).octets()
            let pub = try sec1.children.first { $0.isContext(1) }.map { try $0.child(0).bitStringBytes() }
                ?? curve.publicPoint(privateScalar: scalar)
            return DERW.seq(DERW.int(1), DERW.octets(scalar), DERW.context(0, DERW.oid(curve.oid)),
                            DERW.context(1, DERW.bitString(pub)))
        default:
            throw CertConvertError.unsupported("\(algorithm) keys have no traditional (PKCS#1/SEC1) form; use PKCS#8")
        }
    }

    var traditionalPEMLabel: String {
        if case .rsa = algorithm { return "RSA PRIVATE KEY" }
        return "EC PRIVATE KEY"
    }

    /// swift-certificates view of the key (for signatures and the public key).
    public func certificatePrivateKey() throws -> Certificate.PrivateKey {
        try Certificate.PrivateKey(derBytes: pkcs8)
    }

    /// DER SubjectPublicKeyInfo of the matching public key, in the form certificates carry it
    /// (RSA with NULL parameters, EC with the named curve and the uncompressed point).
    public func subjectPublicKeyInfo() throws -> [UInt8] {
        switch algorithm {
        case .rsa:
            let rsa = try ASN.parse(innerKey)
            let pub = DERW.seq(DERW.unsignedInt(try rsa.child(1).unsignedInteger()),
                               DERW.unsignedInt(try rsa.child(2).unsignedInteger()))
            return DERW.seq(DERW.algorithm(OID.rsaEncryption, DERW.null), DERW.bitString(pub))
        case .ec(let curve):
            let sec1 = try ASN.parse(innerKey)
            let pub = try sec1.children.first { $0.isContext(1) }.map { try $0.child(0).bitStringBytes() }
                ?? curve.publicPoint(privateScalar: try sec1.child(1).octets())
            return DERW.seq(DERW.algorithm(OID.ecPublicKey, DERW.oid(curve.oid)), DERW.bitString(pub))
        case .ed25519:
            let seed = try ASN.parse(innerKey).octets()
            let pub = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation
            return DERW.seq(DERW.algorithm(OID.ed25519, nil), DERW.bitString(Array(pub)))
        case .other(let oid):
            throw CertConvertError.unsupported("public key of \(oid)")
        }
    }

    /// SHA-256 of the SubjectPublicKeyInfo (upper-case hex with colons), the value that pins
    /// a key independently of any certificate.
    public var publicKeyFingerprint: String? {
        (try? subjectPublicKeyInfo()).map { Array(SHA256.hash(data: $0)).colonHex }
    }

    /// True when `certificate` carries this key's public key.
    public func matches(_ certificate: CertificateItem) -> Bool {
        guard let mine = try? subjectPublicKeyInfo(), let theirs = try? certificate.subjectPublicKeyInfo() else { return false }
        return mine == theirs
    }

    /// PEM text. With a password, PKCS#8 becomes `ENCRYPTED PRIVATE KEY` (PBES2 AES-256-CBC,
    /// or PKCS#12 3DES when `legacy`) and traditional gets `DEK-Info` (AES-256-CBC, or
    /// DES-EDE3-CBC when `legacy`).
    public func pem(_ encoding: KeyEncoding, password: String? = nil, legacy: Bool = false) throws -> String {
        try pemBlock(encoding, password: password, legacy: legacy).text
    }

    func pemBlock(_ encoding: KeyEncoding, password: String?, legacy: Bool) throws -> PEMBlock {
        switch encoding {
        case .pkcs8:
            guard let password else { return PEMBlock(label: "PRIVATE KEY", der: pkcs8) }
            let scheme = legacy ? PBEScheme.legacy3DES() : PBEScheme.modern()
            return PEMBlock(label: "ENCRYPTED PRIVATE KEY", der: try EncryptedPKCS8.encrypt(pkcs8, password: password, scheme: scheme))
        case .traditional:
            let der = try traditionalDER()
            guard let password else { return PEMBlock(label: traditionalPEMLabel, der: der) }
            let cipher: Cipher = legacy ? .desEDE3 : .aes(keyBytes: 32)
            let iv = randomBytes(cipher.ivLength)
            let key = KDF.evpBytesToKey(password: Array(password.utf8), salt: Array(iv.prefix(8)), keyLength: cipher.keyLength)
            let enc = try cipher.encrypt(key: key, iv: iv, der)
            return PEMBlock(label: traditionalPEMLabel, der: enc, headers: [
                "Proc-Type": "4,ENCRYPTED",
                "DEK-Info": "\(legacy ? "DES-EDE3-CBC" : "AES-256-CBC"),\(iv.hex.uppercased())",
            ])
        }
    }

    /// Decrypts a traditional PEM body (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: <cipher>,<iv hex>`).
    static func decryptTraditional(_ block: PEMBlock, password: String) throws -> [UInt8] {
        guard let info = block.headers["DEK-Info"] else { throw CertConvertError.malformed("encrypted PEM without DEK-Info") }
        let parts = info.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2, let iv = hexBytes(parts[1]) else { throw CertConvertError.malformed("bad DEK-Info \(info)") }
        let cipher: Cipher
        switch parts[0].uppercased() {
        case "AES-128-CBC": cipher = .aes(keyBytes: 16)
        case "AES-192-CBC": cipher = .aes(keyBytes: 24)
        case "AES-256-CBC": cipher = .aes(keyBytes: 32)
        case "DES-EDE3-CBC": cipher = .desEDE3
        case "DES-CBC": cipher = .des
        default: throw CertConvertError.unsupported("PEM encryption \(parts[0])")
        }
        guard iv.count == cipher.ivLength else { throw CertConvertError.malformed("bad DEK-Info IV length") }
        let key = KDF.evpBytesToKey(password: Array(password.utf8), salt: Array(iv.prefix(8)), keyLength: cipher.keyLength)
        let plain = try cipher.decrypt(key: key, iv: iv, block.der)
        guard (try? ASN.parse(plain))?.isSequence == true else {
            throw CertConvertError.badPassword("wrong password for the encrypted \(block.label)")
        }
        return plain
    }
}

func hexBytes(_ s: String) -> [UInt8]? {
    let chars = Array(s)
    guard chars.count % 2 == 0 else { return nil }
    var out: [UInt8] = []
    for i in stride(from: 0, to: chars.count, by: 2) {
        guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
        out.append(b)
    }
    return out
}
