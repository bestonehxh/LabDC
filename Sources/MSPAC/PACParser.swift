/// One PAC_INFO_BUFFER header entry (MS-PAC §2.4) as found in or written to a PAC.
public struct PACInfoBuffer: Sendable, Hashable {
    public var type: PACBufferType
    public var size: UInt32
    /// Byte offset from the start of the PACTYPE, always a multiple of 8.
    public var offset: UInt64

    public init(type: PACBufferType, size: UInt32, offset: UInt64) {
        self.type = type
        self.size = size
        self.offset = offset
    }

    var range: Range<Int> { Int(offset)..<(Int(offset) + Int(size)) }
}

/// PACTYPE container serialization (MS-PAC §2.3): `cBuffers`, `Version` 0, the
/// PAC_INFO_BUFFER array, then each buffer on an 8-byte boundary with zero padding. The last
/// buffer is padded too, so the PAC length is a multiple of 8 (as in the MS-PAC §3 example).
enum PACLayout {
    static let headerSize = 8
    static let entrySize = 16
    static let alignment = 8

    static func serialize(_ buffers: [PACBuffer]) throws -> (bytes: [UInt8], entries: [PACInfoBuffer]) {
        guard buffers.count <= Int(UInt32.max) else { throw MSPACError.valueTooLarge(field: "cBuffers") }
        var entries = [PACInfoBuffer]()
        var offset = headerSize + entrySize * buffers.count
        for b in buffers {
            guard b.data.count <= Int(UInt32.max) else { throw MSPACError.valueTooLarge(field: "cbBufferSize") }
            offset = align(offset)
            entries.append(PACInfoBuffer(type: b.type, size: UInt32(b.data.count), offset: UInt64(offset)))
            offset += b.data.count
        }
        var w = ByteWriter()
        w.u32(UInt32(buffers.count))
        w.u32(0)
        for e in entries {
            w.u32(e.type.rawValue)
            w.u32(e.size)
            w.u64(e.offset)
        }
        for (b, e) in zip(buffers, entries) {
            w.zeros(Int(e.offset) - w.count)
            w.append(b.data)
        }
        w.zeros(align(w.count) - w.count)
        return (w.bytes, entries)
    }

    static func align(_ n: Int) -> Int { (n + alignment - 1) & ~(alignment - 1) }
}

/// A parsed PAC: the raw bytes, every buffer in header order, and the decoded known buffers.
/// When a type occurs more than once, the first occurrence is decoded and later ones are
/// ignored (MS-PAC §2.4) but still listed in `entries`/`buffers`.
public struct ParsedPAC: Sendable {
    /// The whole PAC exactly as parsed (what the server signature covers, after zeroing).
    public let bytes: [UInt8]
    public let entries: [PACInfoBuffer]
    /// Raw buffer contents, parallel to `entries`.
    public let buffers: [PACBuffer]

    public let logonInfo: KerberosValidationInfo?
    public let clientInfo: PACClientInfo?
    public let upnDNS: PACUpnDnsInfo?
    public let attributes: PACAttributesInfo?
    public let requestor: PACRequestor?
    public let serverChecksum: PACSignatureData?
    public let kdcChecksum: PACSignatureData?
    public let ticketChecksum: PACSignatureData?
    public let fullChecksum: PACSignatureData?
    /// Buffers of types this module does not decode (credentials, claims, delegation, ...).
    public let unknownBuffers: [PACBuffer]

    /// First header entry of `type`.
    public func entry(_ type: PACBufferType) -> PACInfoBuffer? { entries.first { $0.type == type } }

    /// First raw buffer of `type`.
    public func buffer(_ type: PACBufferType) -> PACBuffer? { buffers.first { $0.type == type } }
}

/// Parses and verifies PACs.
public enum PACParser {
    static let decodedTypes: Set<PACBufferType> = [
        .logonInfo, .clientInfo, .upnDnsInfo, .attributesInfo, .requestorSID,
        .serverChecksum, .privsvrChecksum, .ticketChecksum, .fullChecksum,
    ]

    /// Parses a PACTYPE (the ad-data of AD-WIN2K-PAC). Throws `MSPACError` on any structural
    /// problem or on a malformed known buffer.
    public static func parse(_ bytes: [UInt8]) throws -> ParsedPAC {
        var r = ByteReader(bytes, context: "PACTYPE")
        let count = try r.u32("cBuffers")
        let version = try r.u32("Version")
        guard version == 0 else { throw MSPACError.unsupportedVersion(version) }
        guard count >= 1 else { throw MSPACError.invalidHeader(reason: "cBuffers is 0") }
        guard UInt64(count) <= UInt64((bytes.count - PACLayout.headerSize) / PACLayout.entrySize) else {
            throw MSPACError.invalidHeader(reason: "cBuffers \(count) does not fit in \(bytes.count) bytes")
        }
        let headerEnd = UInt64(PACLayout.headerSize + PACLayout.entrySize * Int(count))
        var entries = [PACInfoBuffer]()
        var buffers = [PACBuffer]()
        for _ in 0..<count {
            let type = PACBufferType(rawValue: try r.u32("ulType"))
            let size = try r.u32("cbBufferSize")
            let offset = try r.u64("Offset")
            guard offset % UInt64(PACLayout.alignment) == 0 else {
                throw MSPACError.misalignedBuffer(type: type.rawValue, offset: offset)
            }
            guard offset >= headerEnd, offset <= UInt64(bytes.count), UInt64(size) <= UInt64(bytes.count) - offset else {
                throw MSPACError.bufferOutOfRange(type: type.rawValue, offset: offset, size: size)
            }
            let e = PACInfoBuffer(type: type, size: size, offset: offset)
            entries.append(e)
            buffers.append(PACBuffer(type: type, data: Array(bytes[e.range])))
        }

        func first(_ type: PACBufferType) -> [UInt8]? { buffers.first { $0.type == type }?.data }
        func signature(_ type: PACBufferType) throws -> PACSignatureData? {
            try first(type).map { try PACSignatureData(bytes: $0, bufferType: type) }
        }

        return ParsedPAC(
            bytes: bytes,
            entries: entries,
            buffers: buffers,
            logonInfo: try first(.logonInfo).map { try KerberosValidationInfo(ndr: $0) },
            clientInfo: try first(.clientInfo).map { try PACClientInfo(bytes: $0) },
            upnDNS: try first(.upnDnsInfo).map { try PACUpnDnsInfo(bytes: $0) },
            attributes: try first(.attributesInfo).map { try PACAttributesInfo(bytes: $0) },
            requestor: try first(.requestorSID).map { try PACRequestor(bytes: $0) },
            serverChecksum: try signature(.serverChecksum),
            kdcChecksum: try signature(.privsvrChecksum),
            ticketChecksum: try signature(.ticketChecksum),
            fullChecksum: try signature(.fullChecksum),
            unknownBuffers: buffers.filter { !decodedTypes.contains($0.type) }
        )
    }

    /// The exact bytes the server signature covers: the whole PAC with the `Signature` bytes
    /// (not `SignatureType`, not a RODCIdentifier) of the first server (6) and KDC (7)
    /// signature buffers set to zero. The ticket signature (0x10) and the extended KDC
    /// signature (0x13) are *not* zeroed: both are computed before the server signature
    /// (MS-PAC §2.8.3/§2.8.4) and are covered by it. (Samba's Heimdal `krb5_pac_verify` does
    /// the same; an earlier version of this function zeroed 0x13, which cannot verify a
    /// Windows or Samba service ticket.)
    public static func serverSignedData(_ pac: ParsedPAC) throws -> [UInt8] {
        zeroing(pac, [(.serverChecksum, pac.serverChecksum), (.privsvrChecksum, pac.kdcChecksum)])
    }

    /// The exact bytes the extended KDC signature (0x13) covers: the whole PAC with the
    /// `Signature` bytes of the server (6), KDC (7) and extended KDC (0x13) buffers set to
    /// zero; the ticket signature (0x10) stays as it is.
    public static func fullSignedData(_ pac: ParsedPAC) throws -> [UInt8] {
        zeroing(pac, [(.serverChecksum, pac.serverChecksum), (.privsvrChecksum, pac.kdcChecksum),
                      (.fullChecksum, pac.fullChecksum)])
    }

    private static func zeroing(_ pac: ParsedPAC, _ signatures: [(PACBufferType, PACSignatureData?)]) -> [UInt8] {
        var data = pac.bytes
        for (type, sig) in signatures {
            guard let sig, let e = pac.entry(type) else { continue }
            let start = Int(e.offset) + 4
            for i in start..<(start + sig.signature.count) { data[i] = 0 }
        }
        return data
    }

    /// Verifies the extended KDC signature (0x13) with the krbtgt key. Throws `.missingBuffer`
    /// when the PAC has none, `.signatureMismatch` when it does not verify.
    public static func verifyFullSignature(_ pac: ParsedPAC, kdcVerifier: any PACVerifier) throws {
        guard let full = pac.fullChecksum else { throw MSPACError.missingBuffer(type: PACBufferType.fullChecksum.rawValue) }
        let ok = try kdcVerifier.verify(try fullSignedData(pac), usage: PACChecksum.keyUsage, type: full.type,
                                        signature: full.signature)
        guard ok else { throw MSPACError.signatureMismatch(which: "full") }
    }

    /// Verifies the server signature with the service key and the KDC signature with the krbtgt
    /// key. Throws `.missingBuffer` or `.signatureMismatch`.
    public static func verify(_ pac: ParsedPAC, serverVerifier: any PACVerifier, kdcVerifier: any PACVerifier) throws {
        try verifyServerSignature(pac, verifier: serverVerifier)
        try verifyKDCSignature(pac, verifier: kdcVerifier)
    }

    public static func verifyServerSignature(_ pac: ParsedPAC, verifier: any PACVerifier) throws {
        guard let server = pac.serverChecksum else { throw MSPACError.missingBuffer(type: PACBufferType.serverChecksum.rawValue) }
        guard pac.kdcChecksum != nil else { throw MSPACError.missingBuffer(type: PACBufferType.privsvrChecksum.rawValue) }
        let ok = try verifier.verify(try serverSignedData(pac), usage: PACChecksum.keyUsage,
                                     type: server.type, signature: server.signature)
        guard ok else { throw MSPACError.signatureMismatch(which: "server") }
    }

    /// The KDC signature covers the server signature's `Signature` bytes only.
    public static func verifyKDCSignature(_ pac: ParsedPAC, verifier: any PACVerifier) throws {
        guard let server = pac.serverChecksum else { throw MSPACError.missingBuffer(type: PACBufferType.serverChecksum.rawValue) }
        guard let kdc = pac.kdcChecksum else { throw MSPACError.missingBuffer(type: PACBufferType.privsvrChecksum.rawValue) }
        let ok = try verifier.verify(server.signature, usage: PACChecksum.keyUsage, type: kdc.type, signature: kdc.signature)
        guard ok else { throw MSPACError.signatureMismatch(which: "kdc") }
    }

    /// Verifies the ticket signature (MS-PAC §2.8.2). `encTicketPartDER` must be the DER of the
    /// EncTicketPart with the AD-WIN2K-PAC ad-data replaced by
    /// `PACChecksum.ticketSignaturePlaceholderADData` (one zero byte); building that is the
    /// caller's job because this module does not know ASN.1.
    public static func verifyTicketSignature(_ pac: ParsedPAC, encTicketPartDER: [UInt8], kdcVerifier: any PACVerifier) throws {
        guard let ticket = pac.ticketChecksum else { throw MSPACError.missingBuffer(type: PACBufferType.ticketChecksum.rawValue) }
        let ok = try kdcVerifier.verify(encTicketPartDER, usage: PACChecksum.keyUsage, type: ticket.type, signature: ticket.signature)
        guard ok else { throw MSPACError.signatureMismatch(which: "ticket") }
    }
}
