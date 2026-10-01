import Foundation
import SwiftASN1

// MARK: - Common protocol

/// Every Kerberos ASN.1 type in this module: DER-parseable, DER-serializable, value-comparable, `Sendable`.
///
/// Gives each type the byte-level conveniences `init(derBytes:)` and `encode()`.
public protocol KerberosASN1Type: DERParseable, DERSerializable, Hashable, Sendable {}

extension KerberosASN1Type {
    /// Decodes one complete DER value. Trailing bytes are an error. All failures surface as `KerberosASN1Error`.
    public init(derBytes: [UInt8]) throws {
        do {
            self = try Self(derEncoded: DER.parse(derBytes))
        } catch {
            throw KerberosASN1Error.wrap(error)
        }
    }

    /// DER encoding of the value.
    ///
    /// Serialization of the types in this module cannot fail (every value they can hold has a
    /// valid DER form), so this does not throw.
    public func encode() -> [UInt8] {
        var serializer = DER.Serializer()
        do {
            try serializer.serialize(self)
        } catch {
            preconditionFailure("KerberosASN1: serialization of \(Self.self) failed: \(error)")
        }
        return serializer.serializedBytes
    }
}

/// The `[APPLICATION n]`-tagged Kerberos messages (Ticket, AS-REQ, KRB-ERROR, ...).
public protocol KerberosApplicationMessage: KerberosASN1Type {
    /// The RFC 4120 APPLICATION tag number (also the `msg-type` for the protocol messages).
    static var applicationTag: UInt { get }
}

// MARK: - Explicit-tag helpers (RFC 4120 uses EXPLICIT TAGS throughout)

extension DER.Serializer {
    @inlinable
    mutating func field<T: DERSerializable>(_ tag: UInt, _ value: T) throws {
        try self.serialize(value, explicitlyTaggedWithTagNumber: tag, tagClass: .contextSpecific)
    }

    @inlinable
    mutating func optionalField<T: DERSerializable>(_ tag: UInt, _ value: T?) throws {
        if let value { try self.field(tag, value) }
    }

    /// `[tag] SEQUENCE OF T` (always emitted, even when empty).
    @inlinable
    mutating func sequenceField<T: DERSerializable>(_ tag: UInt, _ values: [T]) throws {
        try self.serialize(explicitlyTaggedWithTagNumber: tag, tagClass: .contextSpecific) { coder in
            try coder.serializeSequenceOf(values)
        }
    }

    /// `[tag] SEQUENCE OF T OPTIONAL`, where an empty array means *absent*: an empty
    /// SEQUENCE OF is never emitted for an OPTIONAL field.
    @inlinable
    mutating func optionalSequenceField<T: DERSerializable>(_ tag: UInt, _ values: [T]) throws {
        if !values.isEmpty { try self.sequenceField(tag, values) }
    }

    /// Writes an application-tagged SEQUENCE: `[APPLICATION n] SEQUENCE { ... }`.
    @inlinable
    mutating func applicationSequence(
        _ tag: UInt,
        _ body: (inout DER.Serializer) throws -> Void
    ) throws {
        try self.serialize(explicitlyTaggedWithTagNumber: tag, tagClass: .application) { coder in
            try coder.appendConstructedNode(identifier: .sequence, body)
        }
    }
}

enum Field {
    static func required<T>(
        _ nodes: inout ASN1NodeCollection.Iterator,
        _ tag: UInt,
        _ builder: (ASN1Node) throws -> T
    ) throws -> T {
        try DER.explicitlyTagged(&nodes, tagNumber: tag, tagClass: .contextSpecific, builder)
    }

    static func optional<T>(
        _ nodes: inout ASN1NodeCollection.Iterator,
        _ tag: UInt,
        _ builder: (ASN1Node) throws -> T
    ) throws -> T? {
        try DER.optionalExplicitlyTagged(&nodes, tagNumber: tag, tagClass: .contextSpecific, builder)
    }

    static func sequenceOf<T: DERParseable>(_ node: ASN1Node) throws -> [T] {
        try DER.sequence(of: T.self, identifier: .sequence, rootNode: node)
    }

    /// Parses `[APPLICATION n] SEQUENCE { ... }`.
    static func applicationSequence<T>(
        _ node: ASN1Node,
        tag: UInt,
        _ builder: (inout ASN1NodeCollection.Iterator) throws -> T
    ) throws -> T {
        guard node.identifier.tagClass == .application else {
            throw KerberosASN1Error.unexpectedApplicationTag(expected: tag, got: nil)
        }
        guard node.identifier.tagNumber == tag else {
            throw KerberosASN1Error.unexpectedApplicationTag(expected: tag, got: node.identifier.tagNumber)
        }
        return try DER.explicitlyTagged(node, tagNumber: tag, tagClass: .application) { inner in
            try DER.sequence(inner, identifier: .sequence, builder)
        }
    }

    /// `INTEGER (5)` version fields.
    static func version(_ node: ASN1Node) throws -> Int64 {
        let v = try Int64(derEncoded: node)
        guard v == 5 else { throw KerberosASN1Error.badProtocolVersion(v) }
        return v
    }

    static func messageType(_ node: ASN1Node, expected: Int32) throws {
        let t = try Int32(derEncoded: node)
        guard t == expected else { throw KerberosASN1Error.unexpectedMessageType(expected: expected, got: t) }
    }

    static func octets(_ node: ASN1Node) throws -> [UInt8] {
        Array(try ASN1OctetString(derEncoded: node).bytes)
    }

    /// RFC 4120 `UInt32 ::= INTEGER (0..4294967295)`, parsed leniently.
    ///
    /// Some clients encode 32-bit unsigned values (nonce, kvno, seq-number) as a *signed* 32-bit
    /// INTEGER, so values above `Int32.max` arrive as 4-byte negative numbers. Both that form and
    /// the correct 5-byte `00 xx xx xx xx` form are accepted and mapped to the same `UInt32`.
    /// (swift-asn1's own unsigned parsing — `UInt32` or `ArraySlice<UInt8>` — rejects the
    /// negative form, hence the hand-written reader.)
    static func uint32(_ node: ASN1Node) throws -> UInt32 {
        guard node.identifier == .integer, case .primitive(let bytes) = node.content, !bytes.isEmpty else {
            throw KerberosASN1Error.invalidField(name: "UInt32", reason: "not a primitive INTEGER")
        }
        if bytes.count == 5 {
            guard bytes.first == 0 else {
                throw KerberosASN1Error.invalidField(name: "UInt32", reason: "value out of 32-bit range")
            }
            return bytes.dropFirst().reduce(0) { ($0 << 8) | UInt32($1) }
        }
        guard bytes.count <= 4 else {
            throw KerberosASN1Error.invalidField(name: "UInt32", reason: "value out of 32-bit range")
        }
        // 1...4 bytes: two's-complement signed; reinterpret the 32-bit pattern.
        var value: Int64 = (bytes.first! & 0x80) != 0 ? -1 : 0
        for b in bytes { value = (value << 8) | Int64(b) }
        return UInt32(truncatingIfNeeded: value)
    }

    /// The INTEGER written for a nonce: its 32-bit pattern as a signed Int32 (Heimdal/MIT wire form).
    static func nonceWireValue(_ nonce: UInt32) -> Int32 { Int32(bitPattern: nonce) }

    static func microseconds(_ node: ASN1Node) throws -> Microseconds {
        let v = try Int32(derEncoded: node)
        guard (0...999_999).contains(v) else {
            throw KerberosASN1Error.invalidField(name: "Microseconds", reason: "\(v) not in 0...999999")
        }
        return v
    }
}

// MARK: - Scalar aliases

/// RFC 4120 `Microseconds ::= INTEGER (0..999999)`.
public typealias Microseconds = Int32

/// RFC 4120 `Realm ::= KerberosString`. Modelled as a Swift `String`.
public typealias Realm = String

// MARK: - KerberosString

/// RFC 4120 `KerberosString ::= GeneralString (IA5String)`.
///
/// Encoded with the GeneralString tag (0x1B). Content is written as UTF-8 (a superset of
/// IA5; Windows also puts UTF-8 here) and must be valid UTF-8 when decoded.
public struct KerberosString: KerberosASN1Type, DERImplicitlyTaggable, ExpressibleByStringLiteral {
    public static var defaultIdentifier: ASN1Identifier { .generalString }

    public var value: String

    public init(_ value: String) { self.value = value }
    public init(stringLiteral value: String) { self.value = value }

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier, case .primitive(let bytes) = node.content else {
            throw KerberosASN1Error.invalidField(name: "KerberosString", reason: "expected GeneralString, got \(node.identifier)")
        }
        guard let s = String(validating: bytes, as: UTF8.self) else {
            throw KerberosASN1Error.invalidField(name: "KerberosString", reason: "not valid UTF-8")
        }
        self.value = s
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { $0.append(contentsOf: Array(self.value.utf8)) }
    }
}

// MARK: - KerberosTime

/// RFC 4120 `KerberosTime ::= GeneralizedTime -- with no fractional seconds`.
///
/// Stored as whole seconds since 1970-01-01T00:00:00Z. Always encoded as `YYYYMMDDHHMMSSZ`
/// (15 bytes, UTC, no fraction — Heimdal rejects fractions). Decoding tolerates a fractional
/// part (it is dropped) but requires the `Z` suffix. All calendar math uses the Gregorian
/// calendar in UTC, never `Calendar.current`.
public struct KerberosTime: KerberosASN1Type, DERImplicitlyTaggable, Comparable {
    public static var defaultIdentifier: ASN1Identifier { .generalizedTime }

    /// Earliest / latest representable instants (0001-01-01T00:00:00Z ... 9999-12-31T23:59:59Z).
    public static let minSeconds: Int64 = -62_135_596_800
    public static let maxSeconds: Int64 = 253_402_300_799

    public let secondsSince1970: Int64

    /// Clamps to `minSeconds...maxSeconds`.
    public init(secondsSince1970: Int64) {
        self.secondsSince1970 = min(max(secondsSince1970, Self.minSeconds), Self.maxSeconds)
    }

    /// Truncates (floors) any fractional second.
    public init(_ date: Date) {
        let t = date.timeIntervalSince1970.rounded(.down)
        let clamped = min(max(t, Double(Self.minSeconds)), Double(Self.maxSeconds))
        self.init(secondsSince1970: Int64(clamped))
    }

    /// Builds a time from UTC Gregorian components. Throws if a component is out of range.
    public init(year: Int, month: Int, day: Int, hour: Int = 0, minute: Int = 0, second: Int = 0) throws {
        guard let s = Self.seconds(year: year, month: month, day: day, hour: hour, minute: minute, second: second) else {
            throw KerberosASN1Error.invalidField(
                name: "KerberosTime",
                reason: "invalid date \(year)-\(month)-\(day) \(hour):\(minute):\(second)")
        }
        self.secondsSince1970 = s
    }

    /// The current time, truncated to whole seconds.
    public static var now: KerberosTime { KerberosTime(Date()) }

    public var date: Date { Date(timeIntervalSince1970: TimeInterval(secondsSince1970)) }

    public func adding(seconds: Int64) -> KerberosTime {
        KerberosTime(secondsSince1970: secondsSince1970.addingReportingOverflow(seconds).partialValue)
    }

    public static func < (lhs: KerberosTime, rhs: KerberosTime) -> Bool {
        lhs.secondsSince1970 < rhs.secondsSince1970
    }

    /// The 15 ASCII characters `YYYYMMDDHHMMSSZ`.
    public var generalizedTimeString: String { String(decoding: Self.format(secondsSince1970), as: UTF8.self) }

    // MARK: DER

    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier, case .primitive(let bytes) = node.content else {
            throw KerberosASN1Error.invalidField(name: "KerberosTime", reason: "expected GeneralizedTime, got \(node.identifier)")
        }
        self.secondsSince1970 = try Self.parse(Array(bytes))
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { $0.append(contentsOf: Self.format(self.secondsSince1970)) }
    }

    // MARK: Calendar math (Gregorian, UTC)

    static let utcGregorian: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()

    static func seconds(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int) -> Int64? {
        guard (1...9999).contains(year), (1...12).contains(month), (1...31).contains(day),
            (0...23).contains(hour), (0...59).contains(minute), (0...59).contains(second)
        else { return nil }
        var dc = DateComponents()
        dc.era = 1  // AD
        dc.year = year; dc.month = month; dc.day = day
        dc.hour = hour; dc.minute = minute; dc.second = second
        guard let date = utcGregorian.date(from: dc) else { return nil }
        // Reject days that the calendar silently normalised (e.g. Feb 30 -> Mar 2).
        let back = utcGregorian.dateComponents([.year, .month, .day], from: date)
        guard back.year == year, back.month == month, back.day == day else { return nil }
        return Int64(date.timeIntervalSince1970.rounded(.down))
    }

    static func format(_ seconds: Int64) -> [UInt8] {
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        let c = utcGregorian.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        func digits(_ v: Int, _ width: Int) -> [UInt8] {
            var out = [UInt8](repeating: 0x30, count: width)
            var v = v
            for i in stride(from: width - 1, through: 0, by: -1) {
                out[i] = 0x30 + UInt8(v % 10)
                v /= 10
            }
            return out
        }
        return digits(c.year!, 4) + digits(c.month!, 2) + digits(c.day!, 2)
            + digits(c.hour!, 2) + digits(c.minute!, 2) + digits(c.second!, 2) + [0x5A]
    }

    static func parse(_ b: [UInt8]) throws -> Int64 {
        func bad(_ why: String) -> KerberosASN1Error {
            .invalidField(name: "KerberosTime", reason: "\(why): \(String(decoding: b, as: UTF8.self))")
        }
        guard b.count >= 15, b.last == 0x5A else { throw bad("must be YYYYMMDDHHMMSS[.f]Z") }
        func num(_ range: Range<Int>) throws -> Int {
            var v = 0
            for i in range {
                guard (0x30...0x39).contains(b[i]) else { throw bad("non-digit") }
                v = v * 10 + Int(b[i] - 0x30)
            }
            return v
        }
        if b.count > 15 {
            // Optional fraction ".d+" (tolerated on input, dropped).
            guard b[14] == 0x2E, b.count > 16 else { throw bad("bad fraction") }
            _ = try num(15..<(b.count - 1))
        }
        guard let s = seconds(
            year: try num(0..<4), month: try num(4..<6), day: try num(6..<8),
            hour: try num(8..<10), minute: try num(10..<12), second: try num(12..<14))
        else { throw bad("out of range") }
        return s
    }
}
