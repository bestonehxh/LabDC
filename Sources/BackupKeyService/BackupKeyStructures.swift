import Foundation
import MSPAC
import RPCKit

/// The MS-BKRP wire structures carried inside `pDataIn` / `ppDataOut` and the two LSA secret
/// formats. They are flat little-endian byte layouts (Samba marshals them with NDR, which for
/// these all-`uint32`/byte-array structs is the same thing), so `NDRReader`/`NDRWriter` with the
/// blob as the alignment origin read and write them.

/// A Win32 error code (`WERROR`) the `BackupKey` call returns (MS-ERREF §2.2), with the names
/// the activity log prints.
public enum BackupKeyStatus: UInt32, Sendable, Error, CustomStringConvertible {
    case ok = 0
    case fileNotFound = 2              // ERROR_FILE_NOT_FOUND
    case invalidAccess = 12            // ERROR_INVALID_ACCESS: the access check names another SID
    case invalidData = 13              // ERROR_INVALID_DATA
    case notSupported = 50             // ERROR_NOT_SUPPORTED
    case invalidParameter = 87         // ERROR_INVALID_PARAMETER
    case internalError = 1359          // ERROR_INTERNAL_ERROR

    public var description: String {
        switch self {
        case .ok: "OK"
        case .fileNotFound: "FILE_NOT_FOUND"
        case .invalidAccess: "ACCESS_DENIED"
        case .invalidData: "INVALID_DATA"
        case .notSupported: "NOT_SUPPORTED"
        case .invalidParameter: "INVALID_PARAMETER"
        case .internalError: "INTERNAL_ERROR"
        }
    }
}

/// Parsing helpers shared by the structures: any underrun or broken invariant becomes `status`
/// (each caller picks the WERROR Samba returns at that step).
enum BKRPBytes {
    static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    static func read<T>(_ status: BackupKeyStatus, _ body: () throws -> T) throws -> T {
        do { return try body() } catch { throw status }
    }

    /// A binary SID (MS-DTYP §2.4.2.2, Samba's NDR `dom_sid`: 4-byte aligned, no hoisted
    /// count) read from `r`.
    static func sid(_ r: NDRReader) throws -> SID {
        r.align(4)
        let header = try r.take(8)
        let tail = try r.take(4 * Int(header[1]))
        return try SID(bytes: header + tail)
    }
}

// MARK: - ClientWrap (MS-BKRP §2.2.2 – §2.2.4)

/// The ClientWrap blob a client hands to `BACKUPKEY_RESTORE_GUID` (§2.2.4,
/// `bkrp_client_side_wrapped`): the RSA-encrypted secret and the encrypted access check, naming
/// the server key that wrapped them.
public struct ClientSideWrapped: Sendable, Equatable {
    public var version: UInt32               // 2 or 3
    public var keyGUID: [UInt8]               // the server key's GUID (MS-DTYP §2.3.4.2 bytes)
    /// `EncryptedSecret`: RSA PKCS#1 v1.5 output stored little-endian (byte-reversed), as
    /// CryptoAPI's `CryptEncrypt` leaves it.
    public var encryptedSecret: [UInt8]
    public var accessCheck: [UInt8]

    public init(version: UInt32, keyGUID: [UInt8], encryptedSecret: [UInt8], accessCheck: [UInt8]) {
        self.version = version; self.keyGUID = keyGUID
        self.encryptedSecret = encryptedSecret; self.accessCheck = accessCheck
    }

    public var encoded: [UInt8] {
        BKRPBytes.le32(version) + BKRPBytes.le32(UInt32(encryptedSecret.count)) + BKRPBytes.le32(UInt32(accessCheck.count))
            + keyGUID + encryptedSecret + accessCheck
    }

    /// Decodes the blob; trailing bytes are ignored, as Samba's `ndr_pull_struct_blob` does.
    public init(decoding blob: [UInt8]) throws {
        let r = NDRReader(blob)
        version = try BKRPBytes.read(.invalidParameter) { try r.u32() }
        let secretLength = Int(try BKRPBytes.read(.invalidParameter) { try r.u32() })
        let checkLength = Int(try BKRPBytes.read(.invalidParameter) { try r.u32() })
        keyGUID = try BKRPBytes.read(.invalidParameter) { try r.take(16) }
        encryptedSecret = try BKRPBytes.read(.invalidParameter) { try r.take(secretLength) }
        accessCheck = try BKRPBytes.read(.invalidParameter) { try r.take(checkLength) }
    }
}

/// The plaintext of `EncryptedSecret` (§2.2.2.1 version 2 / §2.2.2.2 version 3): the wrapped
/// secret and the symmetric key + IV that encrypt the access check. Version 2 keys 3DES-CBC
/// (24-byte key, 8-byte IV), version 3 AES-256-CBC (32-byte key, 16-byte IV) — the magic values
/// 0x6610 / 0x800e are CALG_AES_256 / CALG_SHA_512.
public struct EncryptedSecretPlaintext: Sendable, Equatable {
    public var secret: [UInt8]
    public var payloadKey: [UInt8]           // key followed by IV

    public init(secret: [UInt8], payloadKey: [UInt8]) { self.secret = secret; self.payloadKey = payloadKey }

    public static func keyLength(version: UInt32) -> Int { version == 2 ? 32 : 48 }

    public func encoded(version: UInt32) -> [UInt8] {
        let magic: [UInt32] = version == 2 ? [0x20] : [0x30, 0x6610, 0x800E]
        return BKRPBytes.le32(UInt32(secret.count)) + magic.flatMap(BKRPBytes.le32) + secret + payloadKey
    }

    /// Any malformation or a wrong magic is ERROR_INVALID_DATA (Samba `bkrp_client_wrap_decrypt_data`).
    public init(decoding blob: [UInt8], version: UInt32) throws {
        let r = NDRReader(blob)
        let length = Int(try BKRPBytes.read(.invalidData) { try r.u32() })
        let magic: [UInt32] = version == 2 ? [0x20] : [0x30, 0x6610, 0x800E]
        for m in magic where try BKRPBytes.read(.invalidData, { try r.u32() }) != m { throw BackupKeyStatus.invalidData }
        secret = try BKRPBytes.read(.invalidData) { try r.take(length) }
        payloadKey = try BKRPBytes.read(.invalidData) { try r.take(Self.keyLength(version: version)) }
    }
}

/// The access check (§2.2.2.3 version 2 / §2.2.2.4 version 3): a nonce, the SID of the user the
/// secret belongs to, zero padding, and a SHA-1 (v2) / SHA-512 (v3) hash of everything before
/// the hash. The padding makes the whole structure a multiple of 8 (v2) / 16 (v3) bytes so it is
/// whole cipher blocks — Samba's hand-written `ndr_push_bkrp_access_check_v2/v3`.
public struct AccessCheck: Sendable, Equatable {
    public var nonce: [UInt8]
    public var sid: SID

    public init(nonce: [UInt8], sid: SID) { self.nonce = nonce; self.sid = sid }

    static func hashLength(version: UInt32) -> Int { version == 2 ? 20 : 64 }
    static func blockAlignment(version: UInt32) -> Int { version == 2 ? 8 : 16 }

    /// The structure up to (and including) the padding; the caller appends the hash over it.
    func unhashedPrefix(version: UInt32) -> [UInt8] {
        var b = BKRPBytes.le32(1) + BKRPBytes.le32(UInt32(nonce.count)) + nonce
        b += [UInt8](repeating: 0, count: (4 - b.count % 4) % 4)
        b += sid.bytes
        let align = Self.blockAlignment(version: version)
        b += [UInt8](repeating: 0, count: (align - (b.count + Self.hashLength(version: version)) % align) % align)
        return b
    }

    /// Decodes a decrypted access check and verifies its hash (over the blob minus the trailing
    /// hash, as Samba's `get_and_verify_access_check` computes it). Every failure is
    /// ERROR_INVALID_DATA.
    public init(decrypted blob: [UInt8], version: UInt32, hash: ([UInt8]) -> [UInt8]) throws {
        let hashLength = Self.hashLength(version: version)
        guard blob.count >= hashLength else { throw BackupKeyStatus.invalidData }
        let r = NDRReader(blob)
        guard try BKRPBytes.read(.invalidData, { try r.u32() }) == 1 else { throw BackupKeyStatus.invalidData }
        let nonceLength = Int(try BKRPBytes.read(.invalidData) { try r.u32() })
        nonce = try BKRPBytes.read(.invalidData) { try r.take(nonceLength) }
        sid = try BKRPBytes.read(.invalidData) { try BKRPBytes.sid(r) }
        let align = Self.blockAlignment(version: version)
        _ = try BKRPBytes.read(.invalidData) { try r.take((align - (r.offset + hashLength) % align) % align) }
        let stored = try BKRPBytes.read(.invalidData) { try r.take(hashLength) }
        let computed = hash(Array(blob.prefix(blob.count - hashLength)))
        guard computed.count == stored.count, zip(computed, stored).reduce(0, { $0 | ($1.0 ^ $1.1) }) == 0 else {
            throw BackupKeyStatus.invalidData
        }
    }
}

// MARK: - LSA secret formats (MS-BKRP §2.2.5, §3.1.1)

/// `G$BCKUPKEY_<guid>` for a ClientWrap key (§2.2.5, Samba `bkrp_exported_RSA_key_pair`): a
/// header, a CryptoAPI `PRIVATEKEYBLOB` (`BLOBHEADER` version 2 / CALG_RSA_KEYX, `RSAPUBKEY`
/// "RSA2" / 2048 bits, then the key numbers little-endian at fixed widths) and the certificate.
/// The values are big-endian (minimal) in this struct; the encoder reverses and zero-pads them.
public struct ExportedRSAKeyPair: Sendable, Equatable {
    public var modulus: [UInt8]
    public var publicExponent: [UInt8]
    public var prime1: [UInt8]
    public var prime2: [UInt8]
    public var exponent1: [UInt8]
    public var exponent2: [UInt8]
    public var coefficient: [UInt8]
    public var privateExponent: [UInt8]
    public var certificate: [UInt8]

    /// The fixed little-endian widths for a 2048-bit key (modulus/d 256, primes/CRT values 128).
    static let widths = (exponent: 4, modulus: 256, half: 128)
    /// 0x494: the length of the key part (BLOBHEADER + RSAPUBKEY + key numbers).
    static let keyBlobLength: UInt32 = 0x494

    public init(modulus: [UInt8], publicExponent: [UInt8], prime1: [UInt8], prime2: [UInt8], exponent1: [UInt8],
                exponent2: [UInt8], coefficient: [UInt8], privateExponent: [UInt8], certificate: [UInt8]) {
        self.modulus = modulus; self.publicExponent = publicExponent; self.prime1 = prime1; self.prime2 = prime2
        self.exponent1 = exponent1; self.exponent2 = exponent2; self.coefficient = coefficient
        self.privateExponent = privateExponent; self.certificate = certificate
    }

    static func littleEndian(_ bigEndian: [UInt8], width: Int) throws -> [UInt8] {
        let trimmed = Array(bigEndian.drop { $0 == 0 })
        guard trimmed.count <= width else { throw BackupKeyStatus.internalError }
        return trimmed.reversed() + [UInt8](repeating: 0, count: width - trimmed.count)
    }

    static func bigEndian(_ littleEndian: [UInt8]) -> [UInt8] {
        let be = Array(littleEndian.reversed().drop { $0 == 0 })
        return be.isEmpty ? [0] : be
    }

    public func encoded() throws -> [UInt8] {
        let w = Self.widths
        var b = BKRPBytes.le32(2) + BKRPBytes.le32(Self.keyBlobLength) + BKRPBytes.le32(UInt32(certificate.count))
        b += BKRPBytes.le32(0x0000_0207)          // BLOBHEADER: PRIVATEKEYBLOB, CUR_BLOB_VERSION 2
        b += BKRPBytes.le32(0x0000_A400)          // aiKeyAlg = CALG_RSA_KEYX
        b += BKRPBytes.le32(0x3241_5352)          // RSAPUBKEY.magic = "RSA2"
        b += BKRPBytes.le32(0x0000_0800)          // bitlen = 2048
        b += try Self.littleEndian(publicExponent, width: w.exponent)
        b += try Self.littleEndian(modulus, width: w.modulus)
        for v in [prime1, prime2, exponent1, exponent2, coefficient] { b += try Self.littleEndian(v, width: w.half) }
        b += try Self.littleEndian(privateExponent, width: w.modulus)
        return b + certificate
    }

    /// Decodes the secret; a malformed one is ERROR_FILE_NOT_FOUND (what Samba returns when the
    /// stored key pair does not parse).
    public init(decoding blob: [UInt8]) throws {
        let r = NDRReader(blob)
        let w = Self.widths
        do {
            guard try r.u32() == 2, try r.u32() == Self.keyBlobLength else { throw BackupKeyStatus.fileNotFound }
            let certLength = Int(try r.u32())
            guard try r.u32() == 0x207, try r.u32() == 0xA400, try r.u32() == 0x3241_5352, try r.u32() == 0x800 else {
                throw BackupKeyStatus.fileNotFound
            }
            publicExponent = Self.bigEndian(try r.take(w.exponent))
            modulus = Self.bigEndian(try r.take(w.modulus))
            prime1 = Self.bigEndian(try r.take(w.half))
            prime2 = Self.bigEndian(try r.take(w.half))
            exponent1 = Self.bigEndian(try r.take(w.half))
            exponent2 = Self.bigEndian(try r.take(w.half))
            coefficient = Self.bigEndian(try r.take(w.half))
            privateExponent = Self.bigEndian(try r.take(w.modulus))
            certificate = try r.take(certLength)
        } catch {
            throw BackupKeyStatus.fileNotFound
        }
    }
}

/// `G$BCKUPKEY_<guid>` for a ServerWrap key (§3.1.1, Samba `bkrp_dc_serverwrap_key`): version 1
/// and 256 random bytes.
public struct ServerWrapKey: Sendable, Equatable {
    public var key: [UInt8]

    public init(key: [UInt8]) { self.key = key }

    public var encoded: [UInt8] { BKRPBytes.le32(1) + key }

    /// A malformed key is ERROR_INVALID_DATA (Samba `bkrp_do_retrieve_server_wrap_key`).
    public init(decoding blob: [UInt8]) throws {
        guard blob.count >= 260, Array(blob.prefix(4)) == BKRPBytes.le32(1) else { throw BackupKeyStatus.invalidData }
        key = Array(blob[4..<260])
    }
}

// MARK: - ServerWrap (MS-BKRP §2.2.6 – §2.2.7)

/// The ServerWrap blob `BACKUPKEY_BACKUP_GUID` returns and `BACKUPKEY_RESTORE_GUID(_WIN2K)`
/// takes back (§2.2.6, Samba `bkrp_server_side_wrapped`).
public struct ServerSideWrapped: Sendable, Equatable {
    public var payloadLength: UInt32
    public var keyGUID: [UInt8]
    public var r2: [UInt8]                    // 68 random bytes: HMAC(K, R2) is the RC4 key
    public var ciphertext: [UInt8]            // RC4 over the §2.2.7 payload

    public init(payloadLength: UInt32, keyGUID: [UInt8], r2: [UInt8], ciphertext: [UInt8]) {
        self.payloadLength = payloadLength; self.keyGUID = keyGUID; self.r2 = r2; self.ciphertext = ciphertext
    }

    public var encoded: [UInt8] {
        BKRPBytes.le32(1) + BKRPBytes.le32(payloadLength) + BKRPBytes.le32(UInt32(ciphertext.count)) + keyGUID + r2 + ciphertext
    }

    /// Must consume the whole blob (Samba pulls it with `ndr_pull_struct_blob_all`); anything
    /// else, or a version other than 1, is ERROR_INVALID_PARAMETER.
    public init(decoding blob: [UInt8]) throws {
        let r = NDRReader(blob)
        guard try BKRPBytes.read(.invalidParameter, { try r.u32() }) == 1 else { throw BackupKeyStatus.invalidParameter }
        payloadLength = try BKRPBytes.read(.invalidParameter) { try r.u32() }
        let length = Int(try BKRPBytes.read(.invalidParameter) { try r.u32() })
        keyGUID = try BKRPBytes.read(.invalidParameter) { try r.take(16) }
        r2 = try BKRPBytes.read(.invalidParameter) { try r.take(68) }
        ciphertext = try BKRPBytes.read(.invalidParameter) { try r.take(length) }
        guard r.remaining == 0 else { throw BackupKeyStatus.invalidParameter }
    }
}

/// The RC4-encrypted part of a ServerWrap blob (§2.2.7, `bkrp_rc4encryptedpayload`): R3 (the
/// MAC key's seed), the HMAC-SHA1 over SID || secret, the owner's SID and the secret.
public struct ServerWrapPayload: Sendable, Equatable {
    public var r3: [UInt8]
    public var mac: [UInt8]
    public var sid: SID
    public var secret: [UInt8]

    public init(r3: [UInt8], mac: [UInt8], sid: SID, secret: [UInt8]) {
        self.r3 = r3; self.mac = mac; self.sid = sid; self.secret = secret
    }

    public var encoded: [UInt8] { r3 + mac + sid.bytes + secret }

    public init(decoding blob: [UInt8]) throws {
        let r = NDRReader(blob)
        r3 = try BKRPBytes.read(.invalidParameter) { try r.take(32) }
        mac = try BKRPBytes.read(.invalidParameter) { try r.take(20) }
        sid = try BKRPBytes.read(.invalidParameter) { try BKRPBytes.sid(r) }
        secret = try BKRPBytes.read(.invalidParameter) { try r.take(r.remaining) }
    }
}
