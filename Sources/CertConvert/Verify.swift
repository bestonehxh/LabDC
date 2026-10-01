import Foundation
@_spi(FixedExpiryValidationTime) import X509

/// Result of `verify`.
public struct ChainVerification: Equatable, Sendable {
    public var valid: Bool
    /// The validated chain, leaf first, ending at the trusted CA (empty when invalid).
    public var chain: [CertificateItem]
    /// Why validation failed (one line per rejected candidate chain).
    public var failures: [String]

    public func lines() -> [String] {
        if valid {
            return ["OK: chain of \(chain.count) verified"] + chain.enumerated().map { "  \($0.offset + 1) \($0.element.certificate.subject)" }
        }
        return ["FAILED: the certificate does not verify against the given CA"] + failures.map { "  " + $0 }
    }
}

extension CertConvert {
    /// Verifies `leaf` up to one of `roots` through `intermediates` with RFC 5280 rules
    /// (signatures, validity at `time`, basic constraints, name chaining) using the
    /// swift-certificates `Verifier`. `time` nil means now.
    public static func verify(_ leaf: CertificateItem, intermediates: [CertificateItem] = [], roots: [CertificateItem],
                              at time: Date? = nil) async -> ChainVerification {
        let policy = time.map { RFC5280Policy(fixedExpiryValidationTime: $0) } ?? RFC5280Policy()
        var verifier = Verifier(rootCertificates: CertificateStore(roots.map(\.certificate))) { policy }
        let all = roots + intermediates + [leaf]
        let result = await verifier.validate(leaf: leaf.certificate,
                                             intermediates: CertificateStore(intermediates.map(\.certificate)))
        switch result {
        case .validCertificate(let chain):
            let items = chain.map { c in all.first { $0.certificate == c } ?? leaf }
            return ChainVerification(valid: true, chain: items, failures: [])
        case .couldNotValidate(let failures):
            var reasons = failures.map { "\($0.policyFailureReason)" }
            if reasons.isEmpty {
                reasons = ["no path from \(leaf.certificate.issuer) to the given CA"
                    + (leaf.certificate.notValidAfter < (time ?? Date()) ? " (the certificate has expired)" : "")]
            }
            return ChainVerification(valid: false, chain: [], failures: Array(Set(reasons)).sorted())
        }
    }
}
