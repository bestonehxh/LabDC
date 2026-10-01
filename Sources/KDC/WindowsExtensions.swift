import Foundation
import KerberosASN1
import SwiftASN1

/// NTSTATUS values the KDC reports in KERB-EXT-ERROR (MS-ERREF §2.3.1).
public enum NTStatus {
    public static let accountDisabled: UInt32 = 0xC000_0072
    public static let passwordExpired: UInt32 = 0xC000_0071
    public static let accountExpired: UInt32 = 0xC000_0193
    public static let passwordMustChange: UInt32 = 0xC000_0224
}

/// MS-KILE §2.2.1/§2.2.2 extended error `e-data`:
/// ```
/// KERB-ERROR-DATA ::= SEQUENCE {
///     data-type   [1] INTEGER,          -- 3 = KERB_ERR_TYPE_EXTENDED
///     data-value  [2] OCTET STRING OPTIONAL
/// }
/// KERB-EXT-ERROR (data-value, little endian): status (NTSTATUS) | reserved (0) | flags (1)
/// ```
/// Windows clients map the NTSTATUS to "account disabled", "password must change", ...;
/// Heimdal and MIT ignore it for these error codes.
public enum KerbErrorData {
    public static let extendedType: Int64 = 3

    public static func extended(_ status: UInt32) -> [UInt8] {
        var value: [UInt8] = []
        for word in [status, 0, 1] as [UInt32] { withUnsafeBytes(of: word.littleEndian) { value += $0 } }
        var s = DER.Serializer()
        do {
            try s.appendConstructedNode(identifier: .sequence) { c in
                try c.serialize(extendedType, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
                try c.serialize(ASN1OctetString(contentBytes: value[...]), explicitlyTaggedWithTagNumber: 2,
                                tagClass: .contextSpecific)
            }
        } catch {
            preconditionFailure("KERB-ERROR-DATA serialization failed: \(error)")
        }
        return s.serializedBytes
    }

    /// The NTSTATUS inside an extended KERB-ERROR-DATA (for tests and logs).
    public static func status(in eData: [UInt8]) -> UInt32? {
        guard let root = try? DER.parse(eData) else { return nil }
        return try? DER.sequence(root, identifier: .sequence) { nodes -> UInt32? in
            let type = try DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { try Int64(derEncoded: $0) }
            let value = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                Array(try ASN1OctetString(derEncoded: $0).bytes)
            }
            guard type == extendedType, let value, value.count >= 4 else { return nil }
            return value[0..<4].reversed().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        }
    }
}

/// PA-SUPPORTED-ENCTYPES (165, MS-KILE §2.2.8): a 32-bit little-endian bit field, carried in
/// `encrypted-pa-data`. Bits: 0x4 RC4, 0x8 AES128, 0x10 AES256; 0x10000 FAST, 0x20000
/// compound identity, 0x40000 claims, 0x80000 resource-SID compression disabled (none of
/// which this KDC announces).
public enum SupportedEnctypes {
    /// The enctype bits we can honour (DES bits 0x1/0x2 are never announced).
    public static let enctypeMask: UInt32 = 0x1C

    public static func paData(_ value: UInt32) -> PAData {
        var bytes: [UInt8] = []
        withUnsafeBytes(of: value.littleEndian) { bytes += $0 }
        return PAData(type: PADataType.supportedEnctypes, value: bytes)
    }

    public static func value(of pa: PAData) -> UInt32? {
        guard pa.type == PADataType.supportedEnctypes, pa.value.count == 4 else { return nil }
        return pa.value.reversed().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }
}

extension PAPacOptions {
    /// The PA-PAC-OPTIONS bits this KDC echoes: claims (0), branch-aware (1),
    /// forward-to-full-DC (2) and resource-based constrained delegation (3). Echoing a bit
    /// only acknowledges it (MS-KILE §3.3.5.6.4); no claims are issued in phase 1.
    public var echoed: PAPacOptions {
        var out = PAPacOptions()
        out.claims = claims
        out.branchAware = branchAware
        out.forwardToFullDC = forwardToFullDC
        out.resourceBasedConstrainedDelegation = resourceBasedConstrainedDelegation
        return out
    }
}
