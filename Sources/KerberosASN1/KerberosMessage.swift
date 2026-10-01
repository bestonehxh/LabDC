import SwiftASN1

/// A decoded top-level Kerberos message, dispatched on its APPLICATION tag.
///
/// This is what a KDC listener feeds raw datagrams / TCP records into.
public enum KerberosMessage: Hashable, Sendable {
    case asReq(ASReq)
    case tgsReq(TGSReq)
    case asRep(ASRep)
    case tgsRep(TGSRep)
    case apReq(APReq)
    case krbError(KRBError)

    /// APPLICATION tag number of the outermost element, or `nil` if it is not APPLICATION-class
    /// (or the bytes are too short to tell). Looks only at the identifier octets.
    public static func applicationTag(of bytes: [UInt8]) -> UInt? {
        guard let first = bytes.first, first & 0xC0 == 0x40 else { return nil }
        let low = UInt(first & 0x1F)
        if low != 0x1F { return low }
        // High-tag-number form (not used by Kerberos, but be precise).
        var tag: UInt = 0
        for b in bytes.dropFirst().prefix(4) {
            tag = (tag << 7) | UInt(b & 0x7F)
            if b & 0x80 == 0 { return tag }
        }
        return nil
    }

    /// Decodes AS-REQ, TGS-REQ, AS-REP, TGS-REP, AP-REQ or KRB-ERROR.
    public init(derBytes bytes: [UInt8]) throws {
        switch Self.applicationTag(of: bytes) {
        case ASReq.applicationTag: self = .asReq(try ASReq(derBytes: bytes))
        case TGSReq.applicationTag: self = .tgsReq(try TGSReq(derBytes: bytes))
        case ASRep.applicationTag: self = .asRep(try ASRep(derBytes: bytes))
        case TGSRep.applicationTag: self = .tgsRep(try TGSRep(derBytes: bytes))
        case APReq.applicationTag: self = .apReq(try APReq(derBytes: bytes))
        case KRBError.applicationTag: self = .krbError(try KRBError(derBytes: bytes))
        case let other: throw KerberosASN1Error.unexpectedApplicationTag(expected: nil, got: other)
        }
    }

    public func encode() -> [UInt8] {
        switch self {
        case .asReq(let m): return m.encode()
        case .tgsReq(let m): return m.encode()
        case .asRep(let m): return m.encode()
        case .tgsRep(let m): return m.encode()
        case .apReq(let m): return m.encode()
        case .krbError(let m): return m.encode()
        }
    }
}
