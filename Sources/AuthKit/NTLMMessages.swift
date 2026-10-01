import Foundation
import SheepCrypto

/// NTLMSSP negotiate flags (MS-NLMP §2.2.2.5).
public struct NTLMFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let unicode = NTLMFlags(rawValue: 0x0000_0001)
    public static let oem = NTLMFlags(rawValue: 0x0000_0002)
    public static let requestTarget = NTLMFlags(rawValue: 0x0000_0004)
    public static let sign = NTLMFlags(rawValue: 0x0000_0010)
    public static let seal = NTLMFlags(rawValue: 0x0000_0020)
    public static let datagram = NTLMFlags(rawValue: 0x0000_0040)
    public static let lmKey = NTLMFlags(rawValue: 0x0000_0080)
    public static let ntlm = NTLMFlags(rawValue: 0x0000_0200)
    public static let anonymous = NTLMFlags(rawValue: 0x0000_0800)
    public static let oemDomainSupplied = NTLMFlags(rawValue: 0x0000_1000)
    public static let oemWorkstationSupplied = NTLMFlags(rawValue: 0x0000_2000)
    public static let alwaysSign = NTLMFlags(rawValue: 0x0000_8000)
    public static let targetTypeDomain = NTLMFlags(rawValue: 0x0001_0000)
    public static let targetTypeServer = NTLMFlags(rawValue: 0x0002_0000)
    public static let extendedSessionSecurity = NTLMFlags(rawValue: 0x0008_0000)
    public static let identify = NTLMFlags(rawValue: 0x0010_0000)
    public static let requestNonNTSessionKey = NTLMFlags(rawValue: 0x0040_0000)
    public static let targetInfo = NTLMFlags(rawValue: 0x0080_0000)
    public static let version = NTLMFlags(rawValue: 0x0200_0000)
    public static let negotiate128 = NTLMFlags(rawValue: 0x2000_0000)
    public static let keyExchange = NTLMFlags(rawValue: 0x4000_0000)
    public static let negotiate56 = NTLMFlags(rawValue: 0x8000_0000)
}

/// AV_PAIR (MS-NLMP §2.2.2.1).
public struct NTLMAVPair: Sendable, Hashable {
    public var id: UInt16
    public var value: [UInt8]
    public init(id: UInt16, value: [UInt8]) {
        self.id = id
        self.value = value
    }

    public static let eol: UInt16 = 0
    public static let nbComputerName: UInt16 = 1
    public static let nbDomainName: UInt16 = 2
    public static let dnsComputerName: UInt16 = 3
    public static let dnsDomainName: UInt16 = 4
    public static let dnsTreeName: UInt16 = 5
    public static let flags: UInt16 = 6
    public static let timestamp: UInt16 = 7
    public static let singleHost: UInt16 = 8
    public static let targetName: UInt16 = 9
    public static let channelBindings: UInt16 = 10

    /// MsvAvFlags bit: the AUTHENTICATE message carries a MIC.
    public static let flagMICPresent: UInt32 = 0x2

    public static func string(_ id: UInt16, _ s: String) -> NTLMAVPair { NTLMAVPair(id: id, value: s.utf16LE) }

    /// Encodes a list, appending MsvAvEOL.
    public static func encode(_ pairs: [NTLMAVPair]) -> [UInt8] {
        var out: [UInt8] = []
        for p in pairs where p.id != eol {
            out.appendLE16(p.id)
            out.appendLE16(UInt16(p.value.count))
            out += p.value
        }
        out += [0, 0, 0, 0]
        return out
    }

    /// Decodes up to MsvAvEOL (trailing bytes after EOL are ignored, as in the NTLMv2 blob).
    public static func decode(_ b: [UInt8]) throws -> [NTLMAVPair] {
        var i = 0
        var out: [NTLMAVPair] = []
        while i + 4 <= b.count {
            let id = b.le16(i), len = Int(b.le16(i + 2))
            i += 4
            if id == eol { return out }
            guard i + len <= b.count else { throw AuthKitError.malformed(what: "NTLM AV_PAIR", reason: "truncated") }
            out.append(NTLMAVPair(id: id, value: Array(b[i..<(i + len)])))
            i += len
        }
        throw AuthKitError.malformed(what: "NTLM AV_PAIR list", reason: "no MsvAvEOL")
    }
}

/// VERSION (MS-NLMP §2.2.2.10), 8 bytes.
public struct NTLMVersion: Sendable, Hashable {
    public var major: UInt8, minor: UInt8, build: UInt16, revision: UInt8
    public init(major: UInt8, minor: UInt8, build: UInt16, revision: UInt8 = 0x0F) {
        self.major = major
        self.minor = minor
        self.build = build
        self.revision = revision
    }

    /// Windows Server 2022 (10.0.20348), NTLMSSP_REVISION_W2K3.
    public static let server2022 = NTLMVersion(major: 10, minor: 0, build: 20348)

    var bytes: [UInt8] {
        var b: [UInt8] = [major, minor]
        b.appendLE16(build)
        return b + [0, 0, 0, revision]
    }
}

let ntlmSignature: [UInt8] = Array("NTLMSSP".utf8) + [0]

/// NEGOTIATE_MESSAGE (MS-NLMP §2.2.1.1); only the fields the server needs.
public struct NTLMNegotiateMessage: Sendable {
    public var flags: NTLMFlags
    public var raw: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count >= 16, Array(bytes[0..<8]) == ntlmSignature, bytes.le32(8) == 1 else {
            throw AuthKitError.malformed(what: "NTLM NEGOTIATE", reason: "bad signature or type")
        }
        flags = NTLMFlags(rawValue: bytes.le32(12))
        raw = bytes
    }
}

/// CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2). Payload order: TargetName, TargetInfo.
public struct NTLMChallengeMessage: Sendable, Hashable {
    public var flags: NTLMFlags
    public var targetName: String
    public var serverChallenge: [UInt8]
    public var targetInfo: [NTLMAVPair]
    public var version: NTLMVersion

    public init(flags: NTLMFlags, targetName: String, serverChallenge: [UInt8], targetInfo: [NTLMAVPair],
                version: NTLMVersion = .server2022) {
        self.flags = flags
        self.targetName = targetName
        self.serverChallenge = serverChallenge
        self.targetInfo = targetInfo
        self.version = version
    }

    public func encode() -> [UInt8] {
        let name = flags.contains(.unicode) ? targetName.utf16LE : Array(targetName.utf8)
        let info = NTLMAVPair.encode(targetInfo)
        var b = ntlmSignature
        b.appendLE32(2)
        b.appendLE16(UInt16(name.count)); b.appendLE16(UInt16(name.count)); b.appendLE32(56)
        b.appendLE32(flags.rawValue)
        b += serverChallenge
        b += [UInt8](repeating: 0, count: 8)
        b.appendLE16(UInt16(info.count)); b.appendLE16(UInt16(info.count)); b.appendLE32(UInt32(56 + name.count))
        b += version.bytes
        return b + name + info
    }
}

/// AUTHENTICATE_MESSAGE (MS-NLMP §2.2.1.3).
public struct NTLMAuthenticateMessage: Sendable {
    public var lmResponse: [UInt8]
    public var ntResponse: [UInt8]
    public var domain: String
    public var user: String
    public var workstation: String
    public var encryptedRandomSessionKey: [UInt8]
    public var flags: NTLMFlags
    /// Offset of the 16-byte MIC field (72) when the fixed part leaves room for it.
    public var micOffset: Int?
    public var raw: [UInt8]

    public init(_ b: [UInt8]) throws {
        guard b.count >= 64, Array(b[0..<8]) == ntlmSignature, b.le32(8) == 3 else {
            throw AuthKitError.malformed(what: "NTLM AUTHENTICATE", reason: "bad signature or type")
        }
        var minOffset = b.count
        func field(_ at: Int) throws -> [UInt8] {
            let len = Int(b.le16(at)), off = Int(b.le32(at + 4))
            if len == 0 { return [] }
            guard off >= 64, off + len <= b.count else {
                throw AuthKitError.malformed(what: "NTLM AUTHENTICATE", reason: "field at \(at) out of range")
            }
            minOffset = min(minOffset, off)
            return Array(b[off..<(off + len)])
        }
        flags = NTLMFlags(rawValue: b.le32(60))
        lmResponse = try field(12)
        ntResponse = try field(20)
        let unicode = flags.contains(.unicode)
        func text(_ bytes: [UInt8]) -> String {
            unicode ? String(utf16LE: bytes[...]) : String(decoding: bytes, as: UTF8.self)
        }
        domain = text(try field(28))
        user = text(try field(36))
        workstation = text(try field(44))
        encryptedRandomSessionKey = try field(52)
        micOffset = minOffset >= 88 ? 72 : nil
        raw = b
    }
}

/// NTLMv2 crypto (MS-NLMP §3.3.2, §3.4.5).
public enum NTLMCrypto {
    /// MD4(UTF-16LE(password)).
    public static func ntHash(password: String) -> [UInt8] { MD4.hash(password.utf16LE) }

    /// NTOWFv2 = HMAC_MD5(NT hash, UTF-16LE(Uppercase(User) + UserDom)). LMOWFv2 is the same.
    public static func ntowfv2(ntHash: [UInt8], user: String, domain: String) -> [UInt8] {
        HMACMD5.authenticate(key: ntHash, (user.uppercased() + domain).utf16LE)
    }

    /// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge | temp).
    public static func ntProofStr(responseKeyNT: [UInt8], serverChallenge: [UInt8], temp: [UInt8]) -> [UInt8] {
        HMACMD5.authenticate(key: responseKeyNT, serverChallenge + temp)
    }

    /// LMv2 response = HMAC_MD5(ResponseKeyLM, ServerChallenge | ClientChallenge) | ClientChallenge.
    public static func lmv2Response(responseKeyLM: [UInt8], serverChallenge: [UInt8], clientChallenge: [UInt8]) -> [UInt8] {
        HMACMD5.authenticate(key: responseKeyLM, serverChallenge + clientChallenge) + clientChallenge
    }

    /// `temp` (the NTLMv2_CLIENT_CHALLENGE blob with trailing Z(4)).
    public static func temp(timestamp: UInt64, clientChallenge: [UInt8], avPairs: [NTLMAVPair]) -> [UInt8] {
        var t: [UInt8] = [1, 1, 0, 0, 0, 0, 0, 0]
        t.appendLE64(timestamp)
        t += clientChallenge
        t += [0, 0, 0, 0]
        t += NTLMAVPair.encode(avPairs)
        return t + [0, 0, 0, 0]
    }

    /// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr); for NTLMv2 it is also the KeyExchangeKey.
    public static func sessionBaseKey(responseKeyNT: [UInt8], ntProofStr: [UInt8]) -> [UInt8] {
        HMACMD5.authenticate(key: responseKeyNT, ntProofStr)
    }

    /// SIGNKEY (§3.4.5.2), extended session security only.
    public static func signKey(_ exportedSessionKey: [UInt8], clientToServer: Bool) -> [UInt8] {
        let magic = clientToServer ? "session key to client-to-server signing key magic constant"
                                   : "session key to server-to-client signing key magic constant"
        return MD5.hash(exportedSessionKey + Array(magic.utf8) + [0])
    }

    /// SEALKEY (§3.4.5.3), extended session security: 128/56/40-bit truncation, then MD5 with the magic.
    public static func sealKey(_ exportedSessionKey: [UInt8], flags: NTLMFlags, clientToServer: Bool) -> [UInt8] {
        let k: [UInt8]
        if flags.contains(.negotiate128) { k = exportedSessionKey }
        else if flags.contains(.negotiate56) { k = Array(exportedSessionKey.prefix(7)) }
        else { k = Array(exportedSessionKey.prefix(5)) }
        let magic = clientToServer ? "session key to client-to-server sealing key magic constant"
                                   : "session key to server-to-client sealing key magic constant"
        return MD5.hash(k + Array(magic.utf8) + [0])
    }

    /// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE | CHALLENGE | AUTHENTICATE with MIC zeroed).
    public static func mic(exportedSessionKey: [UInt8], negotiate: [UInt8], challenge: [UInt8], authenticate: [UInt8]) -> [UInt8] {
        HMACMD5.authenticate(key: exportedSessionKey, negotiate + challenge + authenticate)
    }

    /// Current time as a FILETIME (100 ns since 1601).
    static func fileTime(_ date: Date) -> UInt64 {
        UInt64(max(0, (date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000))
    }
}

/// RC4 with persistent state (NTLM sealing handles are continuous streams, MS-NLMP §3.4.3).
struct RC4Stream: Sendable {
    private var s: [UInt8]
    private var i: UInt8 = 0
    private var j: UInt8 = 0

    init(key: [UInt8]) {
        s = (0...255).map { UInt8($0) }
        var j: UInt8 = 0
        for i in 0..<256 {
            j = j &+ s[i] &+ key[i % key.count]
            s.swapAt(i, Int(j))
        }
    }

    mutating func process(_ data: [UInt8]) -> [UInt8] {
        var out = data
        for k in out.indices {
            i = i &+ 1
            j = j &+ s[Int(i)]
            s.swapAt(Int(i), Int(j))
            out[k] ^= s[Int(s[Int(i)] &+ s[Int(j)])]
        }
        return out
    }
}
