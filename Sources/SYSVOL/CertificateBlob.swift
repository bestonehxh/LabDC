import CryptoKit
import Foundation

/// The `Blob` value Windows keeps for each certificate of a registry certificate store
/// (`...\SystemCertificates\<store>\Certificates\<SHA-1 thumbprint>\Blob`, REG_BINARY), i.e. a
/// serialized certificate store element (`CertSerializeCertificateStoreElement`).
///
/// Layout, normative in MS-GPEF §2.2.1.1.1 (the same element format as MS-OSHARED §2.3.2.5
/// `SerializedPropertyEntry` / `SerializedCertificateEntry`):
///
///     property*  : PropertyID (LE32) | Reserved = 01 00 00 00 | Length (LE32) | Value[Length]
///     certificate: 20 00 00 00 | 01 00 00 00 | Length (LE32) | DER[Length]
///
/// "zero or more certificate properties, followed by the encoded certificate". We write
/// `SHA1_HASH` (3, the thumbprint the key is named after) and, when given, `FRIENDLY_NAME` (11,
/// UTF-16LE with NUL; what certlm.msc shows in "Friendly Name"), then the certificate
/// (`CERT_CERT_PROP_ID` 32). `KEY_IDENTIFIER` (20) and the MD5 properties are left for crypt32
/// to compute. Offsets for a blob with a friendly name "F" and a DER of n bytes:
///
///     0x00  03 00 00 00 01 00 00 00 14 00 00 00   SHA1_HASH, 20 bytes
///     0x0C  <20-byte SHA-1 of the DER>
///     0x20  0B 00 00 00 01 00 00 00 04 00 00 00   FRIENDLY_NAME, 4 bytes ("F\0" in UTF-16LE)
///     0x2C  46 00 00 00
///     0x30  20 00 00 00 01 00 00 00 <n LE32>       the certificate
///     0x3C  <DER>
public enum CertificateBlob {
    /// `CERT_*_PROP_ID` values used here (wincrypt.h; MS-GPEF §2.2.1.1.1.1).
    public enum PropertyID: UInt32, Sendable {
        case keyProvInfo = 2
        case sha1Hash = 3
        case md5Hash = 4
        case friendlyName = 11
        case keyIdentifier = 20
        /// `CERT_CERT_PROP_ID`: the element that carries the DER certificate (always last).
        case certificate = 32
    }

    /// One property record.
    public struct Property: Sendable, Hashable {
        public var id: UInt32
        public var value: [UInt8]
        public init(id: UInt32, value: [UInt8]) {
            self.id = id
            self.value = value
        }
    }

    public enum BlobError: Error, Equatable, CustomStringConvertible, Sendable {
        case truncated(offset: Int)
        case badReserved(offset: Int)
        case noCertificate

        public var description: String {
            switch self {
            case .truncated(let o): "certificate blob truncated at offset \(o)"
            case .badReserved(let o): "certificate blob: reserved field is not 1 at offset \(o)"
            case .noCertificate: "certificate blob has no certificate element (property 32)"
            }
        }
    }

    /// Upper-case hex SHA-1 of the DER (the "thumbprint", the registry key name).
    public static func thumbprint(_ der: [UInt8]) -> String {
        Insecure.SHA1.hash(data: der).map { String(format: "%02X", $0) }.joined()
    }

    /// The serialized element for `der`.
    public static func encode(der: [UInt8], friendlyName: String? = nil) -> [UInt8] {
        var props = [Property(id: PropertyID.sha1Hash.rawValue, value: Array(Insecure.SHA1.hash(data: der)))]
        if let friendlyName, !friendlyName.isEmpty {
            props.append(Property(id: PropertyID.friendlyName.rawValue, value: RegistryPolicyFile.utf16z(friendlyName)))
        }
        return encode(properties: props, der: der)
    }

    /// Properties in the given order, then the certificate element.
    public static func encode(properties: [Property], der: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        for p in properties {
            out += RegistryPolicyFile.le32(p.id) + RegistryPolicyFile.le32(1) + RegistryPolicyFile.le32(UInt32(p.value.count)) + p.value
        }
        out += RegistryPolicyFile.le32(PropertyID.certificate.rawValue) + RegistryPolicyFile.le32(1)
            + RegistryPolicyFile.le32(UInt32(der.count)) + der
        return out
    }

    /// Splits a blob into its properties and the DER certificate. Elements after the
    /// certificate (none in what Windows writes) are ignored.
    public static func decode(_ blob: [UInt8]) throws -> (properties: [Property], der: [UInt8]) {
        var props: [Property] = []
        var p = 0
        while p < blob.count {
            guard p + 12 <= blob.count else { throw BlobError.truncated(offset: p) }
            let id = RegistryPolicyFile.readLE32(blob, p)
            guard RegistryPolicyFile.readLE32(blob, p + 4) == 1 else { throw BlobError.badReserved(offset: p + 4) }
            let length = Int(RegistryPolicyFile.readLE32(blob, p + 8))
            guard p + 12 + length <= blob.count else { throw BlobError.truncated(offset: p + 12) }
            let value = Array(blob[(p + 12)..<(p + 12 + length)])
            p += 12 + length
            if id == PropertyID.certificate.rawValue { return (props, value) }
            props.append(Property(id: id, value: value))
        }
        throw BlobError.noCertificate
    }

    /// The `FRIENDLY_NAME` property of a decoded blob.
    public static func friendlyName(in properties: [Property]) -> String? {
        properties.first { $0.id == PropertyID.friendlyName.rawValue }.map { RegistryPolicyFile.decodeUTF16($0.value) }
    }
}
