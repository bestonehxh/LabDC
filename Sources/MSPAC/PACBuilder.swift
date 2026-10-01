/// Builds and signs a PAC.
///
/// Buffer order in the output: LOGON_INFO (1), CLIENT_INFO (0x0A), UPN_DNS_INFO (0x0C),
/// ATTRIBUTES_INFO (0x11), REQUESTOR (0x12), any appended raw buffers, then SERVER_CHECKSUM (6),
/// PRIVSVR_CHECKSUM (7), when given TICKET_CHECKSUM (0x10) and, when asked for,
/// FULL_CHECKSUM (0x13). Order carries no meaning (MS-PAC §2.4) but is fixed once signed.
///
/// Signing order (MS-PAC §2.8): the ticket signature is computed first by the caller over the
/// EncTicketPart (see `ticketChecksum(encTicketPartDER:kdcSigner:)`) and passed in; `build`
/// then lays the PAC out with zeroed server, KDC and extended KDC `Signature` fields (the
/// ticket signature already filled in), computes the extended KDC signature (krbtgt key) over
/// that whole PAC and writes it, computes the server signature over the whole PAC (the
/// extended KDC signature now filled in, as Samba/Windows do) and writes it, and finally
/// computes the KDC signature over the server signature bytes.
public struct PACBuilder: Sendable {
    enum Item: Sendable {
        case logonInfo(KerberosValidationInfo)
        case clientInfo(PACClientInfo)
        case upnDNS(PACUpnDnsInfo)
        case attributes(PACAttributesInfo)
        case requestor(PACRequestor)
        case raw(PACBuffer)
    }

    /// Types the builder writes itself; callers cannot supply them.
    public static let signatureBufferTypes: Set<PACBufferType> = [
        .serverChecksum, .privsvrChecksum, .ticketChecksum, .fullChecksum,
    ]

    private var items: [Item]

    public init(
        logonInfo: KerberosValidationInfo,
        clientInfo: PACClientInfo,
        upnDNS: PACUpnDnsInfo? = nil,
        attributes: PACAttributesInfo? = nil,
        requestor: PACRequestor? = nil
    ) {
        items = [.logonInfo(logonInfo), .clientInfo(clientInfo)]
        if let upnDNS { items.append(.upnDNS(upnDNS)) }
        if let attributes { items.append(.attributes(attributes)) }
        if let requestor { items.append(.requestor(requestor)) }
    }

    /// For the TGS path: keeps every non-signature buffer of `pac` byte-for-byte and in order
    /// (unknown types included), dropping server, KDC, ticket and extended KDC signatures so
    /// `build` can sign again with the new service key.
    public init(resigning pac: ParsedPAC) {
        items = pac.buffers.filter { !Self.signatureBufferTypes.contains($0.type) }.map { .raw($0) }
    }

    /// Appends a raw buffer (e.g. one of a type this module does not model).
    public mutating func append(_ buffer: PACBuffer) throws {
        guard !Self.signatureBufferTypes.contains(buffer.type) else {
            throw MSPACError.reservedBufferType(buffer.type.rawValue)
        }
        items.append(.raw(buffer))
    }

    /// The encoded non-signature buffers, in output order.
    public func contentBuffers() throws -> [PACBuffer] {
        try items.map { item in
            switch item {
            case .logonInfo(let v): PACBuffer(type: .logonInfo, data: try v.ndrEncoded())
            case .clientInfo(let v): PACBuffer(type: .clientInfo, data: try v.encoded())
            case .upnDNS(let v): PACBuffer(type: .upnDnsInfo, data: try v.encoded())
            case .attributes(let v): PACBuffer(type: .attributesInfo, data: v.encoded())
            case .requestor(let v): PACBuffer(type: .requestorSID, data: v.encoded())
            case .raw(let b): b
            }
        }
    }

    /// Computes the ticket signature (MS-PAC §2.8.2) with the krbtgt key, usage 17.
    ///
    /// `encTicketPartDER` is the DER encoding of the final EncTicketPart in which the ad-data
    /// of the AD-WIN2K-PAC element (inside its AD-IF-RELEVANT wrapper, at the position the real
    /// PAC will occupy) is `PACChecksum.ticketSignaturePlaceholderADData`, i.e. `04 01 00`
    /// as an OCTET STRING. MS-PAC says the ticket signature SHOULD be included only in tickets
    /// not encrypted to krbtgt (or a trust account), i.e. service tickets, not TGTs.
    public static func ticketChecksum(encTicketPartDER: [UInt8], kdcSigner: any PACSigner) throws -> PACSignatureData {
        try kdcSigner.checkedSign(encTicketPartDER)
    }

    /// Lays out and signs the PAC; returns the PACTYPE bytes (the AD-WIN2K-PAC ad-data).
    ///
    /// - Parameters:
    ///   - serverSigner: the service's long-term key (for a TGT: the krbtgt key).
    ///   - kdcSigner: the krbtgt key.
    ///   - ticketChecksum: the precomputed ticket signature, or nil to omit buffer 0x10.
    ///   - fullChecksum: add the extended KDC signature (0x13, MS-PAC §2.8.3, KB5020805) with
    ///     the krbtgt key. MS-PAC: SHOULD be present in tickets not encrypted to krbtgt (service
    ///     tickets, including kadmin/changepw), not in TGTs.
    public func build(serverSigner: any PACSigner, kdcSigner: any PACSigner, ticketChecksum: PACSignatureData?,
                      fullChecksum: Bool = false) throws -> [UInt8] {
        var buffers = try contentBuffers()
        let serverIndex = buffers.count
        buffers.append(PACBuffer(type: .serverChecksum, data: PACSignatureData(
            type: serverSigner.checksumType, signature: [UInt8](repeating: 0, count: serverSigner.signatureLength)).encoded()))
        let kdcIndex = buffers.count
        buffers.append(PACBuffer(type: .privsvrChecksum, data: PACSignatureData(
            type: kdcSigner.checksumType, signature: [UInt8](repeating: 0, count: kdcSigner.signatureLength)).encoded()))
        if let ticketChecksum {
            buffers.append(PACBuffer(type: .ticketChecksum, data: ticketChecksum.encoded()))
        }
        var fullIndex: Int?
        if fullChecksum {
            fullIndex = buffers.count
            buffers.append(PACBuffer(type: .fullChecksum, data: PACSignatureData(
                type: kdcSigner.checksumType, signature: [UInt8](repeating: 0, count: kdcSigner.signatureLength)).encoded()))
        }

        var (pac, entries) = try PACLayout.serialize(buffers)

        // Extended KDC signature over the whole PAC: server, KDC and its own Signature zero,
        // ticket signature present.
        if let fullIndex {
            let full = try kdcSigner.checkedSign(pac)
            let fullStart = Int(entries[fullIndex].offset) + 4
            pac.replaceSubrange(fullStart..<(fullStart + full.signature.count), with: full.signature)
        }

        // Server signature over the whole PAC, server and KDC Signature fields still zero.
        let server = try serverSigner.checkedSign(pac)
        let serverStart = Int(entries[serverIndex].offset) + 4
        pac.replaceSubrange(serverStart..<(serverStart + server.signature.count), with: server.signature)

        // KDC signature over the server Signature bytes only.
        let kdc = try kdcSigner.checkedSign(server.signature)
        let kdcStart = Int(entries[kdcIndex].offset) + 4
        pac.replaceSubrange(kdcStart..<(kdcStart + kdc.signature.count), with: kdc.signature)
        return pac
    }
}
