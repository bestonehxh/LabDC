/// Errors of the MSPAC module: malformed PAC or NDR input, values that cannot be encoded, and
/// signature problems. Errors thrown by a `PACSigner`/`PACVerifier` are passed through unchanged.
public enum MSPACError: Error, CustomStringConvertible, Sendable, Equatable {
    /// Input ended before `context` could be read.
    case truncated(context: String)
    /// The PACTYPE header is unusable (`reason` says why).
    case invalidHeader(reason: String)
    /// PACTYPE.Version was not 0.
    case unsupportedVersion(UInt32)
    /// A PAC_INFO_BUFFER points outside the PAC or into the header.
    case bufferOutOfRange(type: UInt32, offset: UInt64, size: UInt32)
    /// A PAC_INFO_BUFFER offset is not a multiple of 8 (MS-PAC §2.3).
    case misalignedBuffer(type: UInt32, offset: UInt64)
    /// A known buffer's contents are malformed.
    case invalidBuffer(type: UInt32, reason: String)
    /// Malformed NDR type serialization (MS-RPCE §2.2.6) in `context`.
    case ndr(context: String, reason: String)
    /// A SID string or binary SID is invalid.
    case invalidSID(String)
    /// A value does not fit its wire field (e.g. a string longer than 32767 UTF-16 units).
    case valueTooLarge(field: String)
    /// A buffer required for the operation is absent.
    case missingBuffer(type: UInt32)
    /// A signer returned a checksum type or length different from what it announced.
    case signerMismatch(expectedType: Int32, expectedLength: Int, gotType: Int32, gotLength: Int)
    /// A signature did not verify. `which` is "server", "kdc" or "ticket".
    case signatureMismatch(which: String)
    /// A caller-supplied buffer uses a type the builder manages itself (6, 7, 0x10, 0x13).
    case reservedBufferType(UInt32)

    public var description: String {
        switch self {
        case .truncated(let context):
            "PAC truncated while reading \(context)"
        case .invalidHeader(let reason):
            "invalid PACTYPE header: \(reason)"
        case .unsupportedVersion(let version):
            "unsupported PAC version \(version) (expected 0)"
        case .bufferOutOfRange(let type, let offset, let size):
            "PAC buffer type 0x\(String(type, radix: 16)) at offset \(offset) size \(size) is out of range"
        case .misalignedBuffer(let type, let offset):
            "PAC buffer type 0x\(String(type, radix: 16)) at offset \(offset) is not 8-byte aligned"
        case .invalidBuffer(let type, let reason):
            "invalid PAC buffer type 0x\(String(type, radix: 16)): \(reason)"
        case .ndr(let context, let reason):
            "malformed NDR in \(context): \(reason)"
        case .invalidSID(let reason):
            "invalid SID: \(reason)"
        case .valueTooLarge(let field):
            "value too large for \(field)"
        case .missingBuffer(let type):
            "PAC has no buffer of type 0x\(String(type, radix: 16))"
        case .signerMismatch(let expectedType, let expectedLength, let gotType, let gotLength):
            "signer returned checksum type \(gotType) length \(gotLength), announced type \(expectedType) length \(expectedLength)"
        case .signatureMismatch(let which):
            "PAC \(which) signature does not verify"
        case .reservedBufferType(let type):
            "PAC buffer type 0x\(String(type, radix: 16)) is managed by PACBuilder and cannot be supplied"
        }
    }
}
