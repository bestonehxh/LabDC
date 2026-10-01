/// A Windows security identifier (MS-DTYP §2.4.2).
///
/// Binary form (§2.4.2.2): `Revision` (1), `SubAuthorityCount`, 48-bit `IdentifierAuthority`
/// big-endian, then each sub-authority as a little-endian UInt32. Text form (§2.4.2.1):
/// `S-1-<authority>-<sub>-<sub>...`, authority in decimal below 2^32 and as `0x` + 12 hex
/// digits otherwise.
public struct SID: Sendable, Hashable, CustomStringConvertible {
    public static let maxSubAuthorities = 15

    public let revision: UInt8
    /// 48-bit identifier authority (e.g. 5 = NT Authority).
    public let identifierAuthority: UInt64
    public let subAuthorities: [UInt32]

    public init(identifierAuthority: UInt64, subAuthorities: [UInt32]) throws {
        guard identifierAuthority < (1 << 48) else { throw MSPACError.invalidSID("identifier authority exceeds 48 bits") }
        guard subAuthorities.count <= Self.maxSubAuthorities else {
            throw MSPACError.invalidSID("more than \(Self.maxSubAuthorities) sub-authorities")
        }
        revision = 1
        self.identifierAuthority = identifierAuthority
        self.subAuthorities = subAuthorities
    }

    /// Parses `S-1-5-21-...`. Only revision 1 exists.
    public init(string: String) throws {
        let parts = string.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count >= 3, parts[0] == "S" || parts[0] == "s" else {
            throw MSPACError.invalidSID("'\(string)' is not of the form S-1-<authority>[-<sub>...]")
        }
        guard parts[1] == "1" else { throw MSPACError.invalidSID("revision must be 1 in '\(string)'") }
        let auth = parts[2]
        let authority: UInt64
        if auth.hasPrefix("0x") || auth.hasPrefix("0X") {
            guard let v = UInt64(auth.dropFirst(2), radix: 16) else { throw MSPACError.invalidSID("bad authority '\(auth)'") }
            authority = v
        } else {
            guard !auth.isEmpty, auth.allSatisfy(\.isASCIIDigitCharacter), let v = UInt64(auth) else {
                throw MSPACError.invalidSID("bad authority '\(auth)'")
            }
            authority = v
        }
        var subs = [UInt32]()
        for p in parts.dropFirst(3) {
            guard !p.isEmpty, p.allSatisfy(\.isASCIIDigitCharacter), let v = UInt32(p) else {
                throw MSPACError.invalidSID("bad sub-authority '\(p)' in '\(string)'")
            }
            subs.append(v)
        }
        try self.init(identifierAuthority: authority, subAuthorities: subs)
    }

    /// Decodes exactly one binary SID occupying all of `bytes`.
    public init(bytes: [UInt8]) throws {
        let (sid, used) = try SID.decode(bytes, at: 0)
        guard used == bytes.count else { throw MSPACError.invalidSID("\(bytes.count - used) trailing bytes after SID") }
        self = sid
    }

    /// Decodes a binary SID at `offset`; returns it and the number of bytes consumed.
    static func decode(_ bytes: [UInt8], at offset: Int) throws -> (SID, Int) {
        guard offset >= 0, bytes.count - offset >= 8 else { throw MSPACError.invalidSID("truncated SID header") }
        guard bytes[offset] == 1 else { throw MSPACError.invalidSID("revision \(bytes[offset]) is not 1") }
        let n = Int(bytes[offset + 1])
        guard n <= maxSubAuthorities else { throw MSPACError.invalidSID("\(n) sub-authorities") }
        guard bytes.count - offset >= 8 + 4 * n else { throw MSPACError.invalidSID("truncated sub-authorities") }
        var authority: UInt64 = 0
        for i in 2..<8 { authority = authority << 8 | UInt64(bytes[offset + i]) }
        var subs = [UInt32]()
        for i in 0..<n { subs.append(readU32LE(bytes, offset + 8 + 4 * i)) }
        return (try SID(identifierAuthority: authority, subAuthorities: subs), 8 + 4 * n)
    }

    /// MS-DTYP §2.4.2.2 binary form.
    public var bytes: [UInt8] {
        var w = ByteWriter()
        w.u8(revision)
        w.u8(UInt8(subAuthorities.count))
        for shift in stride(from: 40, through: 0, by: -8) { w.u8(UInt8(truncatingIfNeeded: identifierAuthority >> UInt64(shift))) }
        for s in subAuthorities { w.u32(s) }
        return w.bytes
    }

    /// Length of the binary form: 8 + 4 * sub-authority count.
    public var byteCount: Int { 8 + 4 * subAuthorities.count }

    public var description: String {
        var s = "S-\(revision)-"
        if identifierAuthority < (1 << 32) {
            s += String(identifierAuthority)
        } else {
            let hex = String(identifierAuthority, radix: 16, uppercase: true)
            s += "0x" + String(repeating: "0", count: max(0, 12 - hex.count)) + hex
        }
        for sub in subAuthorities { s += "-\(sub)" }
        return s
    }

    /// This SID with `rid` appended, e.g. domain SID + 1104 -> user SID.
    public func appending(rid: UInt32) throws -> SID {
        try SID(identifierAuthority: identifierAuthority, subAuthorities: subAuthorities + [rid])
    }

    /// The last sub-authority, conventionally the RID of an account SID.
    public var rid: UInt32? { subAuthorities.last }

    /// This SID without its last sub-authority (the domain of an account SID).
    public var domain: SID? {
        guard !subAuthorities.isEmpty else { return nil }
        return try? SID(identifierAuthority: identifierAuthority, subAuthorities: Array(subAuthorities.dropLast()))
    }
}

private extension Character {
    var isASCIIDigitCharacter: Bool { ("0"..."9").contains(self) }
}
