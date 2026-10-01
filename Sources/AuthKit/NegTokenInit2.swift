/// The acceptor-initiated SPNEGO token (MS-SPNG §2.2.1 `NegTokenInit2`), which a server
/// sends before the client has sent anything: SMB2 NEGOTIATE's security buffer, and the
/// answer to an LDAP `GSS-SPNEGO` bind with no credentials (MS-ADTS §5.1.1.1.2).
///
/// ```
/// NegTokenInit2 ::= SEQUENCE {
///     mechTypes   [0] MechTypeList OPTIONAL,
///     reqFlags    [1] ContextFlags OPTIONAL,
///     mechToken   [2] OCTET STRING OPTIONAL,
///     negHints    [3] NegHints OPTIONAL,
///     mechListMIC [4] OCTET STRING OPTIONAL }
/// NegHints ::= SEQUENCE {
///     hintName    [0] GeneralString OPTIONAL,
///     hintAddress [1] OCTET STRING OPTIONAL }
/// ```
/// framed like an initiator's first token: `60 … 06 06 2b0601050502 a0 30 …`.
///
/// Samba's `ads_sasl_spnego_bind` (libads, `net ads`, Aruba ClearPass) binds with empty
/// credentials first and reads `mechTypes` from this token to choose Kerberos or NTLMSSP.
public enum NegTokenInit2 {
    /// The hint Windows sends since Windows 2008 (it carries no principal on purpose).
    public static let windowsHintName = "not_defined_in_RFC4178@please_ignore"

    /// What a Windows DC lists for LDAP, less NEGOEX and KRB5-U2U: MS-KRB5, KRB5, NTLMSSP.
    public static let defaultMechanisms: [GSSMechanism] = [.msKerberos, .kerberos, .ntlm]

    /// `NegTokenInit2 { mechTypes, negHints { hintName } }` with the SPNEGO framing.
    public static func encode(mechTypes: [GSSMechanism] = defaultMechanisms,
                              hintName: String? = windowsHintName) -> [UInt8] {
        var body = tlv(0xA0, SPNEGOToken.mechTypeListDER(mechTypes))
        if let hintName {
            // [3] SEQUENCE { [0] GeneralString }
            body += tlv(0xA3, tlv(0x30, tlv(0xA0, tlv(0x1B, Array(hintName.utf8)))))
        }
        return GSSFraming.wrap(mech: .spnego, tlv(0xA0, tlv(0x30, body)))
    }

    /// The Windows-style server-initial token for LDAP (96 bytes):
    ///
    /// ```
    /// 60 5e 06 06 2b 06 01 05 05 02                      [APPLICATION 0] + SPNEGO OID
    ///   a0 54 30 52                                      negTokenInit [0] SEQUENCE
    ///     a0 24 30 22                                    mechTypes [0] SEQUENCE OF
    ///       06 09 2a 86 48 82 f7 12 01 02 02             1.2.840.48018.1.2.2   MS-KRB5
    ///       06 09 2a 86 48 86 f7 12 01 02 02             1.2.840.113554.1.2.2  KRB5
    ///       06 0a 2b 06 01 04 01 82 37 02 02 0a          1.3.6.1.4.1.311.2.2.10 NTLMSSP
    ///     a3 2a 30 28 a0 26 1b 24                        negHints [3] { hintName [0] GeneralString }
    ///       "not_defined_in_RFC4178@please_ignore"
    /// ```
    public static let ldapServerInitial: [UInt8] = encode()

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + DERLength.encode(content.count) + content
    }
}
