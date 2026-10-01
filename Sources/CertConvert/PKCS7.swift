/// PKCS#7 / CMS `SignedData` used as a certificate bag ("degenerate", no signers), the
/// `.p7b` format Windows and `openssl crl2pkcs7` produce.
public enum PKCS7 {
    /// True when `root` is a ContentInfo of type signedData.
    static func looksLike(_ root: ASN) -> Bool {
        let c = root.children
        guard root.isSequence, c.count == 2, c[1].isContext(0), let oid = try? c[0].oid() else { return false }
        return oid == OID.signedData
    }

    /// Certificates in the order they appear; CRLs are counted, not returned.
    static func read(_ root: ASN) throws -> (certificates: [[UInt8]], crlCount: Int, signerCount: Int) {
        guard looksLike(root) else { throw CertConvertError.malformed("not a PKCS#7 SignedData") }
        let signed = try root.child(1).child(0)
        guard signed.isSequence else { throw CertConvertError.malformed("PKCS#7 SignedData is not a SEQUENCE") }
        var certs: [[UInt8]] = []
        var crls = 0
        var signers = 0
        for (i, part) in signed.children.enumerated() where i >= 3 {
            if part.isContext(0) {
                // CertificateChoices: only plain certificates (SEQUENCE); attribute certs are skipped.
                certs += part.children.filter(\.isSequence).map(\.encoded)
            } else if part.isContext(1) {
                crls += part.children.count
            } else if part.isUniversal(17) {
                signers = part.children.count
            }
        }
        return (certs, crls, signers)
    }

    /// Certificate-only SignedData, byte-for-byte what `openssl crl2pkcs7 -nocrl` writes:
    /// version 1, no digest algorithms, empty data content, certificates in the given order,
    /// no signers.
    public static func write(certificates: [[UInt8]]) -> [UInt8] {
        let signed = DERW.seq(
            DERW.int(1),
            DERW.tlv(0x31, []),
            DERW.seq(DERW.oid(OID.data)),
            DERW.context(0, certificates.flatMap { $0 }),
            DERW.tlv(0x31, [])
        )
        return DERW.seq(DERW.oid(OID.signedData), DERW.context(0, signed))
    }
}
