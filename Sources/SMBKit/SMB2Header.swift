/// The 64-byte SMB2 header (MS-SMB2 §2.2.1), sync form (async form only for parsing: the
/// server never sends async responses).
///
/// ```
///  0 ProtocolId FE 'S' 'M' 'B'   4 StructureSize 64 (2)   6 CreditCharge (2)
///  8 Status / ChannelSequence+Reserved (4)                12 Command (2)
/// 14 CreditRequest/CreditResponse (2)                     16 Flags (4)
/// 20 NextCommand (4)            24 MessageId (8)          32 Reserved (4) | AsyncId (8)
/// 36 TreeId (4)                 40 SessionId (8)          48 Signature (16)
/// ```
public struct SMB2Header: Sendable, Equatable {
    public static let size = 64
    public static let protocolID: [UInt8] = [0xFE, 0x53, 0x4D, 0x42]

    public var creditCharge: UInt16 = 0
    /// NTSTATUS in responses; ChannelSequence (low 16 bits) in 3.x requests.
    public var status: UInt32 = 0
    public var command: UInt16 = 0
    public var credits: UInt16 = 0
    public var flags: UInt32 = 0
    public var nextCommand: UInt32 = 0
    public var messageID: UInt64 = 0
    /// AsyncId when `flags` has ASYNC_COMMAND (then `treeID` is not present).
    public var asyncID: UInt64 = 0
    public var processID: UInt32 = 0
    public var treeID: UInt32 = 0
    public var sessionID: UInt64 = 0
    public var signature: [UInt8] = [UInt8](repeating: 0, count: 16)

    public init(command: SMB2Command, messageID: UInt64 = 0, sessionID: UInt64 = 0, treeID: UInt32 = 0,
                credits: UInt16 = 1, creditCharge: UInt16 = 1, flags: UInt32 = 0, status: UInt32 = 0) {
        self.command = command.rawValue
        self.messageID = messageID
        self.sessionID = sessionID
        self.treeID = treeID
        self.credits = credits
        self.creditCharge = creditCharge
        self.flags = flags
        self.status = status
    }

    public init(parsing b: [UInt8]) throws {
        guard b.count >= Self.size, Array(b[0..<4]) == Self.protocolID else {
            throw SMBKitError.malformed("not an SMB2 header")
        }
        guard b.le16(4) == 64 else { throw SMBKitError.malformed("header StructureSize \(b.le16(4))") }
        creditCharge = b.le16(6)
        status = b.le32(8)
        command = b.le16(12)
        credits = b.le16(14)
        flags = b.le32(16)
        nextCommand = b.le32(20)
        messageID = b.le64(24)
        if flags & SMB2Flags.asyncCommand != 0 {
            asyncID = b.le64(32)
        } else {
            processID = b.le32(32)
            treeID = b.le32(36)
        }
        sessionID = b.le64(40)
        signature = Array(b[48..<64])
    }

    public var isSigned: Bool { flags & SMB2Flags.signed != 0 }
    public var isRelated: Bool { flags & SMB2Flags.relatedOperations != 0 }
    public var isResponse: Bool { flags & SMB2Flags.serverToRedir != 0 }

    public func encode() -> [UInt8] {
        var b = Self.protocolID
        b.put16(64)
        b.put16(creditCharge)
        b.put32(status)
        b.put16(command)
        b.put16(credits)
        b.put32(flags)
        b.put32(nextCommand)
        b.put64(messageID)
        if flags & SMB2Flags.asyncCommand != 0 {
            b.put64(asyncID)
        } else {
            b.put32(processID)
            b.put32(treeID)
        }
        b.put64(sessionID)
        b += signature.count == 16 ? signature : [UInt8](repeating: 0, count: 16)
        return b
    }
}

/// Splits a compound SMB2 PDU into its messages (each from its header to its NextCommand
/// offset, or to the end for the last one). MS-SMB2 §3.3.5.2.7.
public enum SMB2Compound {
    public static func split(_ pdu: [UInt8]) throws -> [[UInt8]] {
        var out: [[UInt8]] = []
        var offset = 0
        while true {
            guard pdu.count - offset >= SMB2Header.size else { throw SMBKitError.malformed("compound element truncated") }
            let next = Int(pdu.le32(offset + 20))
            if next == 0 {
                out.append(Array(pdu[offset...]))
                return out
            }
            guard next >= SMB2Header.size, next % 8 == 0, next <= pdu.count - offset else {
                throw SMBKitError.malformed("bad NextCommand \(next)")
            }
            out.append(Array(pdu[offset..<(offset + next)]))
            offset += next
            if out.count > 64 { throw SMBKitError.malformed("compound chain longer than 64") }
        }
    }

    /// Joins responses: every element but the last is padded to 8 bytes and gets its
    /// NextCommand. Signing must happen after this (the padding is signed).
    public static func join(_ messages: [[UInt8]]) -> [[UInt8]] {
        var out = messages
        for i in 0..<out.count where i < out.count - 1 {
            out[i].pad(to: 8)
            out[i].set32(UInt32(out[i].count), at: 20)
        }
        if var last = out.last {
            last.set32(0, at: 20)
            out[out.count - 1] = last
        }
        return out
    }
}
