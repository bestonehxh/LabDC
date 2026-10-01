import CommonCrypto

/// MD5 (RFC 1321) via CommonCrypto. Used only where a protocol fixes it (RC4-HMAC checksums,
/// MS-CHAP, RADIUS). Not a general-purpose hash.
public nonisolated enum MD5 {
    /// Returns the 16-byte MD5 digest of `bytes`.
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        // `CC_MD5` is deprecated (macOS 10.15) for being cryptographically broken. The call is
        // routed through a protocol witness declared in a deprecated context, which keeps the
        // warning out of the build without changing behaviour.
        (DeprecatedDigests() as any LegacyDigesting).md5(bytes)
    }
}

/// Indirection that lets the module call deprecated-but-required CommonCrypto digests
/// without deprecation warnings: calls inside a deprecated declaration do not warn, and
/// calling through the (non-deprecated) protocol requirement does not warn either.
private protocol LegacyDigesting {
    func md5(_ bytes: [UInt8]) -> [UInt8]
}

private struct DeprecatedDigests: LegacyDigesting {
    @available(macOS, deprecated: 10.15, message: "MD5 is required by the protocols LabDC speaks")
    func md5(_ bytes: [UInt8]) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        bytes.withUnsafeBufferPointer { input in
            _ = CC_MD5(input.baseAddress, CC_LONG(input.count), &digest)
        }
        return digest
    }
}
