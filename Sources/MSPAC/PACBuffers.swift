/// PAC_INFO_BUFFER.ulType values (MS-PAC §2.4).
public struct PACBufferType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let logonInfo = PACBufferType(rawValue: 0x01)
    public static let credentialsInfo = PACBufferType(rawValue: 0x02)
    public static let serverChecksum = PACBufferType(rawValue: 0x06)
    public static let privsvrChecksum = PACBufferType(rawValue: 0x07)
    public static let clientInfo = PACBufferType(rawValue: 0x0A)
    public static let delegationInfo = PACBufferType(rawValue: 0x0B)
    public static let upnDnsInfo = PACBufferType(rawValue: 0x0C)
    public static let clientClaimsInfo = PACBufferType(rawValue: 0x0D)
    public static let deviceInfo = PACBufferType(rawValue: 0x0E)
    public static let deviceClaimsInfo = PACBufferType(rawValue: 0x0F)
    public static let ticketChecksum = PACBufferType(rawValue: 0x10)
    public static let attributesInfo = PACBufferType(rawValue: 0x11)
    public static let requestorSID = PACBufferType(rawValue: 0x12)
    /// Extended KDC signature (MS-PAC §2.8.3). Not produced in P0; stripped when re-signing.
    public static let fullChecksum = PACBufferType(rawValue: 0x13)

    public var description: String { "0x" + String(rawValue, radix: 16) }
}

/// One PAC buffer as raw bytes (the bytes at `Offset`, `cbBufferSize` long, without padding).
public struct PACBuffer: Sendable, Hashable {
    public var type: PACBufferType
    public var data: [UInt8]

    public init(type: PACBufferType, data: [UInt8]) {
        self.type = type
        self.data = data
    }
}

// MARK: - PAC_CLIENT_INFO (0x0A)

/// PAC_CLIENT_INFO (MS-PAC §2.7): `ClientId` = FILETIME of the ticket's `authtime`, `Name` =
/// the client's account name (UTF-16LE, `NameLength` in bytes, no terminator).
public struct PACClientInfo: Sendable, Hashable {
    public var clientId: FileTime
    public var name: String

    public init(clientId: FileTime, name: String) {
        self.clientId = clientId
        self.name = name
    }

    public func encoded() throws -> [UInt8] {
        let n = name.utf16LEBytes
        guard n.count <= Int(UInt16.max) else { throw MSPACError.valueTooLarge(field: "PAC_CLIENT_INFO.Name") }
        var w = ByteWriter()
        w.u64(clientId.rawValue)
        w.u16(UInt16(n.count))
        w.append(n)
        return w.bytes
    }

    public init(bytes: [UInt8]) throws {
        let type = PACBufferType.clientInfo.rawValue
        var r = ByteReader(bytes, context: "PAC_CLIENT_INFO")
        let id = try r.u64("ClientId")
        let length = Int(try r.u16("NameLength"))
        guard length % 2 == 0 else { throw MSPACError.invalidBuffer(type: type, reason: "odd NameLength \(length)") }
        let name = try r.take(length, "Name")
        clientId = FileTime(rawValue: id)
        self.name = String(utf16LE: name)
    }
}

// MARK: - UPN_DNS_INFO (0x0C)

/// UPN_DNS_INFO (MS-PAC §2.10). Strings are UTF-16LE without terminator; each payload starts on
/// an 8-byte boundary of the buffer, in the order UPN, DNS domain, SAM name, SID.
public struct PACUpnDnsInfo: Sendable, Hashable {
    /// Flag U: the account has no userPrincipalName; `upn` was constructed as name@dnsdomain.
    public static let flagUpnConstructed: UInt32 = 0x1
    /// Flag S: the structure carries SamName and Sid.
    public static let flagHasSamNameAndSid: UInt32 = 0x2

    public var upn: String
    public var dnsDomainName: String
    public var upnConstructed: Bool
    /// SAM name and SID (flag S). Set both or neither; `encoded()` rejects only one.
    public var samName: String?
    public var sid: SID?
    /// Flag bits other than U and S, preserved on decode ("MUST be ignored on receipt").
    public var otherFlags: UInt32 = 0

    public init(upn: String, dnsDomainName: String, upnConstructed: Bool, samName: String? = nil, sid: SID? = nil) {
        self.upn = upn
        self.dnsDomainName = dnsDomainName
        self.upnConstructed = upnConstructed
        self.samName = samName
        self.sid = sid
    }

    public var flags: UInt32 {
        var f = otherFlags & ~(Self.flagUpnConstructed | Self.flagHasSamNameAndSid)
        if upnConstructed { f |= Self.flagUpnConstructed }
        if samName != nil, sid != nil { f |= Self.flagHasSamNameAndSid }
        return f
    }

    public func encoded() throws -> [UInt8] {
        guard (samName == nil) == (sid == nil) else {
            throw MSPACError.invalidBuffer(type: PACBufferType.upnDnsInfo.rawValue, reason: "SamName and Sid must be set together")
        }
        var payloads = [upn.utf16LEBytes, dnsDomainName.utf16LEBytes]
        if let samName, let sid { payloads += [samName.utf16LEBytes, sid.bytes] }
        let headerSize = payloads.count == 4 ? 20 : 12
        var offsets = [Int]()
        var cursor = headerSize
        for p in payloads {
            cursor = (cursor + 7) & ~7
            offsets.append(cursor)
            cursor += p.count
        }
        guard cursor <= Int(UInt16.max) else { throw MSPACError.valueTooLarge(field: "UPN_DNS_INFO") }
        var w = ByteWriter()
        w.u16(UInt16(payloads[0].count)); w.u16(UInt16(offsets[0]))
        w.u16(UInt16(payloads[1].count)); w.u16(UInt16(offsets[1]))
        w.u32(flags)
        if payloads.count == 4 {
            w.u16(UInt16(payloads[2].count)); w.u16(UInt16(offsets[2]))
            w.u16(UInt16(payloads[3].count)); w.u16(UInt16(offsets[3]))
        }
        for (p, o) in zip(payloads, offsets) {
            w.zeros(o - w.count)
            w.append(p)
        }
        return w.bytes
    }

    public init(bytes: [UInt8]) throws {
        let type = PACBufferType.upnDnsInfo.rawValue
        var r = ByteReader(bytes, context: "UPN_DNS_INFO")
        func field(_ what: String) throws -> (length: Int, offset: Int) {
            let length = Int(try r.u16("\(what)Length"))
            let offset = Int(try r.u16("\(what)Offset"))
            guard offset + length <= bytes.count else {
                throw MSPACError.invalidBuffer(type: type, reason: "\(what) at \(offset)+\(length) exceeds \(bytes.count) bytes")
            }
            return (length, offset)
        }
        func string(_ f: (length: Int, offset: Int), _ what: String) throws -> String {
            guard f.length % 2 == 0 else { throw MSPACError.invalidBuffer(type: type, reason: "odd \(what)Length") }
            return String(utf16LE: Array(bytes[f.offset..<(f.offset + f.length)]))
        }
        let upnField = try field("Upn")
        let dnsField = try field("DnsDomainName")
        let flags = try r.u32("Flags")
        upn = try string(upnField, "Upn")
        dnsDomainName = try string(dnsField, "DnsDomainName")
        upnConstructed = flags & Self.flagUpnConstructed != 0
        otherFlags = flags & ~(Self.flagUpnConstructed | Self.flagHasSamNameAndSid)
        if flags & Self.flagHasSamNameAndSid != 0 {
            let samField = try field("SamName")
            let sidField = try field("Sid")
            samName = try string(samField, "SamName")
            do {
                sid = try SID(bytes: Array(bytes[sidField.offset..<(sidField.offset + sidField.length)]))
            } catch {
                throw MSPACError.invalidBuffer(type: type, reason: "Sid: \(error)")
            }
        }
    }
}

// MARK: - PAC_ATTRIBUTES_INFO (0x11)

/// PAC_ATTRIBUTES_INFO (MS-PAC §2.14): `FlagsLength` in *bits* (2 today), then
/// ceil(FlagsLength / 32) little-endian UInt32 words. Bit 0x1 PAC_WAS_REQUESTED,
/// bit 0x2 PAC_WAS_GIVEN_IMPLICITLY. Only the first word is modelled.
public struct PACAttributesInfo: Sendable, Hashable {
    public static let pacWasRequested: UInt32 = 0x1
    public static let pacWasGivenImplicitly: UInt32 = 0x2

    public var flagsLength: UInt32
    public var flags: UInt32

    public init(flags: UInt32, flagsLength: UInt32 = 2) {
        self.flags = flags
        self.flagsLength = flagsLength
    }

    /// PA-PAC-REQUEST present with include-pac TRUE -> requested; absent -> given implicitly.
    public static let requested = PACAttributesInfo(flags: pacWasRequested)
    public static let givenImplicitly = PACAttributesInfo(flags: pacWasGivenImplicitly)

    public func encoded() -> [UInt8] {
        var w = ByteWriter()
        w.u32(flagsLength)
        let words = max(1, (Int(flagsLength) + 31) / 32)
        w.u32(flags)
        w.zeros(4 * (words - 1))
        return w.bytes
    }

    public init(bytes: [UInt8]) throws {
        var r = ByteReader(bytes, context: "PAC_ATTRIBUTES_INFO")
        flagsLength = try r.u32("FlagsLength")
        let words = (Int(flagsLength) + 31) / 32
        guard words * 4 <= r.remaining else { throw MSPACError.truncated(context: "PAC_ATTRIBUTES_INFO Flags") }
        flags = words > 0 ? try r.u32("Flags") : 0
    }
}

// MARK: - PAC_REQUESTOR (0x12)

/// PAC_REQUESTOR (MS-PAC §2.15): the binary SID of the client that requested the ticket.
public struct PACRequestor: Sendable, Hashable {
    public var sid: SID

    public init(sid: SID) { self.sid = sid }

    public func encoded() -> [UInt8] { sid.bytes }

    public init(bytes: [UInt8]) throws {
        do {
            sid = try SID(bytes: bytes)
        } catch {
            throw MSPACError.invalidBuffer(type: PACBufferType.requestorSID.rawValue, reason: "\(error)")
        }
    }
}

// MARK: - PAC_SIGNATURE_DATA (6, 7, 0x10, 0x13)

/// PAC_SIGNATURE_DATA (MS-PAC §2.8): `SignatureType` (signed 32-bit checksum type), the
/// `Signature` bytes, and an optional trailing RODCIdentifier (UInt16) used only by RODCs.
public struct PACSignatureData: Sendable, Hashable {
    public var type: Int32
    public var signature: [UInt8]
    public var rodcIdentifier: UInt16?

    public init(type: Int32, signature: [UInt8], rodcIdentifier: UInt16? = nil) {
        self.type = type
        self.signature = signature
        self.rodcIdentifier = rodcIdentifier
    }

    public func encoded() -> [UInt8] {
        var w = ByteWriter()
        w.u32(UInt32(bitPattern: type))
        w.append(signature)
        if let rodcIdentifier { w.u16(rodcIdentifier) }
        return w.bytes
    }

    /// The signature length is taken from the checksum type when known (so a trailing
    /// RODCIdentifier can be recognised); otherwise everything after the type is the signature.
    public init(bytes: [UInt8], bufferType: PACBufferType) throws {
        guard bytes.count >= 4 else { throw MSPACError.truncated(context: "PAC_SIGNATURE_DATA \(bufferType)") }
        type = Int32(bitPattern: readU32LE(bytes, 0))
        let rest = bytes.count - 4
        if let known = PACChecksum.signatureLength(forChecksumType: type) {
            if rest == known {
                rodcIdentifier = nil
            } else if rest == known + 2 {
                rodcIdentifier = UInt16(bytes[4 + known]) | UInt16(bytes[5 + known]) << 8
            } else {
                throw MSPACError.invalidBuffer(type: bufferType.rawValue,
                                               reason: "\(rest) signature bytes for checksum type \(type), expected \(known)")
            }
            signature = Array(bytes[4..<(4 + known)])
        } else {
            signature = Array(bytes[4...])
            rodcIdentifier = nil
        }
    }
}
