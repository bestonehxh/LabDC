import Foundation
import SwiftASN1
import X509

/// RFC 5280 CRLReason.
public enum RevocationReason: Int, Sendable, CaseIterable {
    case unspecified = 0
    case keyCompromise = 1
    case caCompromise = 2
    case affiliationChanged = 3
    case superseded = 4
    case cessationOfOperation = 5
    case certificateHold = 6
    case removeFromCRL = 8
    case privilegeWithdrawn = 9
    case aaCompromise = 10

    /// The CLI spelling: `key-compromise`, `superseded`, ...
    public var cliName: String {
        switch self {
        case .unspecified: "unspecified"
        case .keyCompromise: "key-compromise"
        case .caCompromise: "ca-compromise"
        case .affiliationChanged: "affiliation-changed"
        case .superseded: "superseded"
        case .cessationOfOperation: "cessation-of-operation"
        case .certificateHold: "certificate-hold"
        case .removeFromCRL: "remove-from-crl"
        case .privilegeWithdrawn: "privilege-withdrawn"
        case .aaCompromise: "aa-compromise"
        }
    }

    /// Accepts the CLI spelling, the camel-case name or the number.
    public init?(text: String) {
        let t = text.lowercased().replacingOccurrences(of: "_", with: "-")
        if let n = Int(t), let r = RevocationReason(rawValue: n) { self = r; return }
        let flat = t.replacingOccurrences(of: "-", with: "")
        guard let r = Self.allCases.first(where: { $0.cliName.replacingOccurrences(of: "-", with: "") == flat })
        else { return nil }
        self = r
    }
}

/// An X.509 v2 CRL (RFC 5280 §5): built and signed by `make`, read back by `init(derEncoded:)`.
public struct CertificateRevocationList: Sendable {
    public struct Entry: Sendable, Equatable {
        /// The serial number's magnitude (big-endian, no sign padding).
        public var serial: [UInt8]
        public var revocationDate: Date
        /// Nil when the entry has no reasonCode extension (`unspecified` is written that way).
        public var reason: RevocationReason?

        public init(serial: [UInt8], revocationDate: Date, reason: RevocationReason?) {
            self.serial = serial
            self.revocationDate = revocationDate
            self.reason = reason
        }

        public var serialHex: String { serial.map { String(format: "%02x", $0) }.joined() }
    }

    public var issuer: DistinguishedName
    public var thisUpdate: Date
    public var nextUpdate: Date?
    public var crlNumber: Int64?
    public var authorityKeyIdentifier: [UInt8]?
    public var entries: [Entry]
    /// Dotted OID of the signature algorithm.
    public var signatureAlgorithmOID: String
    public let tbsBytes: [UInt8]
    public let signature: [UInt8]
    public let der: [UInt8]

    public var pem: String {
        let b64 = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN X509 CRL-----\n\(b64)\n-----END X509 CRL-----\n"
    }

    /// Builds and signs a CRL for `ca`. Entries with `unspecified` carry no reasonCode (RFC 5280
    /// §5.3.1 recommends omitting it).
    static func make(ca: CertificateAuthority, entries: [Entry], crlNumber: Int64, thisUpdate: Date,
                     nextUpdate: Date) throws -> CertificateRevocationList {
        var issuerSerializer = DER.Serializer()
        do { try issuerSerializer.serialize(ca.certificate.subject) } catch {
            throw PKIKitError.encoding("CRL issuer: \(error)")
        }
        let algorithm = ca.key.algorithmIdentifierDER
        var tbs: [[UInt8]] = [
            DERWriter.integer(1), // v2
            algorithm,
            issuerSerializer.serializedBytes,
            DERWriter.time(thisUpdate),
            DERWriter.time(nextUpdate),
        ]
        if !entries.isEmpty {
            tbs.append(DERWriter.sequence(entries.map { entry in
                var fields = [DERWriter.unsignedInteger(entry.serial), DERWriter.time(entry.revocationDate)]
                if let reason = entry.reason, reason != .unspecified {
                    fields.append(DERWriter.sequence([
                        DERWriter.extension(oid: PKIOID.crlReason, value: DERWriter.enumerated(reason.rawValue)),
                    ]))
                }
                return DERWriter.sequence(fields)
            }))
        }
        var extensions: [[UInt8]] = []
        if let keyID = ca.keyIdentifier {
            extensions.append(DERWriter.extension(oid: PKIOID.authorityKeyIdentifier,
                                                  value: DERWriter.sequence([DERWriter.tlv(0x80, keyID)])))
        }
        extensions.append(DERWriter.extension(oid: PKIOID.crlNumber, value: DERWriter.integer(crlNumber)))
        tbs.append(DERWriter.tlv(0xA0, DERWriter.sequence(extensions)))
        let tbsBytes = DERWriter.sequence(tbs)
        let signature = try ca.key.sign(tbsBytes)
        let der = DERWriter.sequence([tbsBytes, algorithm, DERWriter.bitString(signature)])
        return try CertificateRevocationList(derEncoded: der)
    }

    /// Parses a DER CRL (v1 or v2).
    public init(derEncoded bytes: [UInt8]) throws {
        func bad(_ what: String) -> PKIKitError { .encoding("CRL: \(what)") }
        let root: ASN1Node
        do { root = try DER.parse(bytes) } catch { throw bad("not DER (\(error))") }
        guard case .constructed(let top) = root.content else { throw bad("not a SEQUENCE") }
        var topNodes = top.makeIterator()
        guard let tbsNode = topNodes.next(), let algNode = topNodes.next(), let sigNode = topNodes.next(),
              case .constructed(let tbsItems) = tbsNode.content else { throw bad("want tbsCertList, algorithm, signature") }
        guard case .primitive(let sigContent) = sigNode.content, sigContent.first == 0 else { throw bad("bad signature BIT STRING") }
        self.tbsBytes = Array(tbsNode.encodedBytes)
        self.signature = Array(sigContent.dropFirst())
        self.der = bytes
        self.signatureAlgorithmOID = try Self.algorithmOID(algNode)

        var items = Array(tbsItems)
        var index = 0
        if items.first?.identifier == .integer { index += 1 } // version (v2)
        guard items.count >= index + 3 else { throw bad("tbsCertList too short") }
        index += 1 // signature AlgorithmIdentifier (repeated outside)
        do { issuer = try DistinguishedName(derEncoded: items[index]) } catch { throw bad("issuer (\(error))") }
        index += 1
        thisUpdate = try Self.time(items[index])
        index += 1
        nextUpdate = nil
        if index < items.count, items[index].identifier == .utcTime || items[index].identifier == .generalizedTime {
            nextUpdate = try Self.time(items[index])
            index += 1
        }
        entries = []
        crlNumber = nil
        authorityKeyIdentifier = nil
        if index < items.count, items[index].identifier == .sequence {
            guard case .constructed(let revoked) = items[index].content else { throw bad("revokedCertificates") }
            for node in revoked {
                guard case .constructed(let fields) = node.content else { throw bad("revoked entry") }
                let f = Array(fields)
                guard f.count >= 2, case .primitive(let serial) = f[0].content else { throw bad("revoked entry serial") }
                var reason: RevocationReason?
                if f.count >= 3 {
                    for (oid, value) in try Self.extensions(f[2]) where oid == PKIOID.crlReason {
                        let node = try DER.parse(value)
                        if case .primitive(let v) = node.content, let last = v.last {
                            reason = RevocationReason(rawValue: Int(last))
                        }
                    }
                }
                entries.append(Entry(serial: Array(serial.drop(while: { $0 == 0 })), revocationDate: try Self.time(f[1]),
                                     reason: reason))
            }
            index += 1
        }
        items = Array(items.dropFirst(index))
        if let extNode = items.first, extNode.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific) {
            guard case .constructed(let inner) = extNode.content, let seq = Array(inner).first else { throw bad("crlExtensions") }
            for (oid, value) in try Self.extensions(seq) {
                let node = try DER.parse(value)
                switch oid {
                case PKIOID.crlNumber:
                    if case .primitive(let v) = node.content {
                        crlNumber = v.reduce(Int64(0)) { ($0 << 8) | Int64($1) }
                    }
                case PKIOID.authorityKeyIdentifier:
                    if case .constructed(let akiItems) = node.content {
                        for item in akiItems where item.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific) {
                            if case .primitive(let keyID) = item.content { authorityKeyIdentifier = Array(keyID) }
                        }
                    }
                default: break
                }
            }
        }
    }

    /// True when `issuer`'s public key verifies the CRL signature (and the issuer names match).
    public func isSignatureValid(issuer certificate: Certificate) -> Bool {
        let algorithm: Certificate.SignatureAlgorithm
        switch signatureAlgorithmOID {
        case "1.2.840.10045.4.3.2": algorithm = .ecdsaWithSHA256
        case "1.2.840.10045.4.3.3": algorithm = .ecdsaWithSHA384
        case "1.2.840.113549.1.1.11": algorithm = .sha256WithRSAEncryption
        case "1.2.840.113549.1.1.12": algorithm = .sha384WithRSAEncryption
        default: return false
        }
        return issuer == certificate.subject
            && certificate.publicKey.isValidSignature(signature, for: tbsBytes, signatureAlgorithm: algorithm)
    }

    /// The entry for a serial (magnitude bytes or hex), if revoked.
    public func entry(serialHex: String) -> Entry? {
        let wanted = serialHex.lowercased().drop(while: { $0 == "0" })
        return entries.first { $0.serialHex.drop(while: { $0 == "0" }) == wanted }
    }

    private static func algorithmOID(_ node: ASN1Node) throws -> String {
        guard case .constructed(let items) = node.content, let first = Array(items).first else {
            throw PKIKitError.encoding("CRL: bad AlgorithmIdentifier")
        }
        return try ASN1ObjectIdentifier(derEncoded: first).description
    }

    private static func extensions(_ node: ASN1Node) throws -> [(String, [UInt8])] {
        guard case .constructed(let list) = node.content else { throw PKIKitError.encoding("CRL: bad Extensions") }
        var result: [(String, [UInt8])] = []
        for ext in list {
            guard case .constructed(let parts) = ext.content else { continue }
            let p = Array(parts)
            guard let oidNode = p.first, let valueNode = p.last, case .primitive(let value) = valueNode.content else { continue }
            result.append((try ASN1ObjectIdentifier(derEncoded: oidNode).description, Array(value)))
        }
        return result
    }

    private static func time(_ node: ASN1Node) throws -> Date {
        var c = DateComponents()
        c.timeZone = TimeZone(identifier: "UTC")
        if node.identifier == .utcTime {
            let t = try UTCTime(derEncoded: node)
            (c.year, c.month, c.day, c.hour, c.minute, c.second) = (t.year, t.month, t.day, t.hours, t.minutes, t.seconds)
        } else if node.identifier == .generalizedTime {
            let t = try GeneralizedTime(derEncoded: node)
            (c.year, c.month, c.day, c.hour, c.minute, c.second) = (t.year, t.month, t.day, t.hours, t.minutes, t.seconds)
        } else {
            throw PKIKitError.encoding("CRL: expected a Time")
        }
        guard let date = Calendar(identifier: .gregorian).date(from: c) else { throw PKIKitError.encoding("CRL: bad time") }
        return date
    }
}
