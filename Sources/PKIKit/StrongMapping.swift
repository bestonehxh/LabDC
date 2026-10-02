import SwiftASN1
import X509

/// KB5014754 strong certificate mapping: the `szOID_NTDS_CA_SECURITY_EXT` extension
/// (1.3.6.1.4.1.311.25.2) an AD CS CA puts in certificates whose names come from an account,
/// carrying that account's SID:
///
/// ```
/// SEQUENCE {                                  -- GeneralNames
///   [0] {                                     -- otherName
///     OBJECT IDENTIFIER 1.3.6.1.4.1.311.25.2.1
///     [0] { OCTET STRING "S-1-5-21-…" }
///   }
/// }
/// ```
///
/// A KDC or RADIUS server that maps a certificate to an account checks the account's SID
/// against it, so a certificate cannot be moved to another account by renaming (ESC9/ESC10).
public enum NTDSSecurityExtension {
    /// The extension value (DER) for `sid` (`S-1-5-21-…`).
    public static func value(sid: String) -> [UInt8] {
        DERWriter.sequence([
            DERWriter.tlv(0xA0, DERWriter.oid(PKIOID.ntdsObjectSID)
                          + DERWriter.tlv(0xA0, DERWriter.octetString(Array(sid.utf8)))),
        ])
    }

    /// The SID string in `certificate`'s extension, nil when it has none or it does not parse.
    public static func sid(in certificate: Certificate) -> String? {
        guard let ext = certificate.extensions.first(where: { $0.oid.description == PKIOID.ntdsCASecurityExtension }) else {
            return nil
        }
        return sid(fromValue: Array(ext.value))
    }

    /// Whether `certificate` carries the extension at all (parsable or not).
    public static func isPresent(in certificate: Certificate) -> Bool {
        certificate.extensions.contains { $0.oid.description == PKIOID.ntdsCASecurityExtension }
    }

    static func sid(fromValue bytes: [UInt8]) -> String? {
        guard let root = try? DER.parse(bytes), case .constructed(let names) = root.content else { return nil }
        for name in names where name.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific) {
            guard case .constructed(let parts) = name.content else { continue }
            let items = Array(parts)
            guard items.count == 2, let oid = try? ASN1ObjectIdentifier(derEncoded: items[0]),
                  oid.description == PKIOID.ntdsObjectSID,
                  case .constructed(let wrapped) = items[1].content, let inner = Array(wrapped).first,
                  inner.identifier == .octetString, case .primitive(let text) = inner.content else { continue }
            let sid = String(decoding: text, as: UTF8.self)
            if sid.uppercased().hasPrefix("S-1-") { return sid }
        }
        return nil
    }
}
