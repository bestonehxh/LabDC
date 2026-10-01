import Foundation
import SwiftASN1

/// A malformed CMS / PKCS#10 / SCEP / EST structure.
struct ASNError: Error, CustomStringConvertible {
    var description: String
    init(_ description: String) { self.description = description }
}

/// A thin reading layer over SwiftASN1's node tree for the CMS structures SCEP devices send
/// (PK-7). DER first, BER as a fallback: some SCEP clients send indefinite-length or
/// constructed-OCTET-STRING PKCS#7.
struct ASNReader {
    let node: ASN1Node

    init(_ node: ASN1Node) { self.node = node }

    static func parse(_ bytes: [UInt8]) throws -> ASNReader {
        if let n = try? DER.parse(bytes) { return ASNReader(n) }
        do { return ASNReader(try BER.parse(bytes)) } catch {
            throw ASNError("not valid DER/BER (\(error))")
        }
    }

    static func parse(_ bytes: ArraySlice<UInt8>) throws -> ASNReader { try parse(Array(bytes)) }

    var tagClass: ASN1Identifier.TagClass { node.identifier.tagClass }
    var tagNumber: UInt { node.identifier.tagNumber }
    var isConstructed: Bool { if case .constructed = node.content { true } else { false } }
    /// The element as it was received (tag, length, content).
    var encoded: [UInt8] { Array(node.encodedBytes) }

    func isUniversal(_ tag: UInt) -> Bool { tagClass == .universal && tagNumber == tag }
    func isContext(_ tag: UInt) -> Bool { tagClass == .contextSpecific && tagNumber == tag }
    var isSequence: Bool { isUniversal(16) && isConstructed }
    var isSet: Bool { isUniversal(17) && isConstructed }

    var children: [ASNReader] {
        if case .constructed(let c) = node.content { return c.map(ASNReader.init) }
        return []
    }

    func child(_ i: Int) throws -> ASNReader {
        let c = children
        guard i < c.count else { throw ASNError("missing ASN.1 element \(i)") }
        return c[i]
    }

    /// Primitive content; a constructed (BER) string is concatenated.
    var bytes: [UInt8] {
        switch node.content {
        case .primitive(let b): return Array(b)
        case .constructed(let c): return c.flatMap { ASNReader($0).bytes }
        }
    }

    func oid() throws -> String {
        guard isUniversal(6) else { throw ASNError("expected an OBJECT IDENTIFIER") }
        return try ASN1ObjectIdentifier(derEncoded: node).description
    }

    func int() throws -> Int {
        guard isUniversal(2) else { throw ASNError("expected an INTEGER") }
        var b = bytes
        guard let first = b.first, first & 0x80 == 0 else { throw ASNError("negative or empty INTEGER") }
        while b.count > 1, b[0] == 0 { b.removeFirst() }
        guard b.count <= 7 else { throw ASNError("INTEGER out of range") }
        return b.reduce(0) { $0 << 8 | Int($1) }
    }

    /// INTEGER magnitude without the sign-padding zero (serial numbers).
    func unsignedInteger() throws -> [UInt8] {
        guard isUniversal(2) else { throw ASNError("expected an INTEGER") }
        var b = bytes
        while b.count > 1, b[0] == 0 { b.removeFirst() }
        return b
    }

    func octets() throws -> [UInt8] {
        guard isUniversal(4) else { throw ASNError("expected an OCTET STRING") }
        return bytes
    }

    /// Any of the string types a DirectoryString / PrintableString attribute may use.
    func string() throws -> String {
        guard tagClass == .universal else { throw ASNError("expected a string") }
        switch tagNumber {
        case 12, 19, 22, 20, 26, 18: // UTF8, Printable, IA5, Teletex (as Latin-1-ish UTF8), Visible, Numeric
            return String(decoding: bytes, as: UTF8.self)
        case 30: // BMPString
            let b = bytes
            var units: [UInt16] = []
            var i = 0
            while i + 1 < b.count { units.append(UInt16(b[i]) << 8 | UInt16(b[i + 1])); i += 2 }
            return String(decoding: units, as: UTF16.self)
        case 28: // UniversalString (UCS-4)
            let b = bytes
            var scalars = String.UnicodeScalarView()
            var i = 0
            while i + 3 < b.count {
                let v = UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
                if let s = Unicode.Scalar(v) { scalars.append(s) }
                i += 4
            }
            return String(scalars)
        default:
            throw ASNError("expected a string, found tag \(tagNumber)")
        }
    }
}

extension DERWriter {
    /// A DER `SET OF`: the elements sorted by their encodings (X.690 §11.6).
    static func setOf(_ items: [[UInt8]]) -> [UInt8] {
        tlv(0x31, items.sorted { $0.lexicographicallyPrecedes($1) }.flatMap { $0 })
    }

    static func printableString(_ text: String) -> [UInt8] { tlv(0x13, Array(text.utf8)) }

    /// `[n] EXPLICIT` / constructed context tag.
    static func explicit(_ n: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0xA0 | n, content) }

    /// `[n] IMPLICIT` primitive context tag.
    static func implicitPrimitive(_ n: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0x80 | n, content) }

    /// `AlgorithmIdentifier` with optional parameters (nil = absent).
    static func algorithm(_ oid: String, _ parameters: [UInt8]?) -> [UInt8] {
        sequence([self.oid(oid)] + (parameters.map { [$0] } ?? []))
    }
}
