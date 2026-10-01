import Foundation

/// One `-----BEGIN <label>-----` block, with RFC 1421 headers (`Proc-Type`, `DEK-Info`) if any.
public struct PEMBlock: Equatable, Sendable {
    public var label: String
    public var headers: [String: String]
    public var der: [UInt8]

    public init(label: String, der: [UInt8], headers: [String: String] = [:]) {
        self.label = label
        self.der = der
        self.headers = headers
    }

    /// Scans `text` for every PEM block. Text outside blocks (openssl "Bag Attributes",
    /// comments, `openssl x509 -text` dumps) is ignored.
    public static func parseAll(_ text: String) throws -> [PEMBlock] {
        var blocks: [PEMBlock] = []
        let lines = text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" })
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        var i = 0
        while i < lines.count {
            let line = lines[i]
            guard line.hasPrefix("-----BEGIN "), line.hasSuffix("-----"), line.count > 16 else {
                i += 1
                continue
            }
            let label = String(line.dropFirst(11).dropLast(5))
            var headers: [String: String] = [:]
            var body = ""
            var closed = false
            i += 1
            while i < lines.count {
                let l = lines[i]
                if l == "-----END \(label)-----" {
                    closed = true
                    break
                }
                if l.hasPrefix("-----") { break }
                if let colon = l.firstIndex(of: ":"), body.isEmpty {
                    headers[String(l[..<colon]).trimmingCharacters(in: .whitespaces)] =
                        String(l[l.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                } else {
                    body += l
                }
                i += 1
            }
            guard closed else { throw CertConvertError.malformed("PEM block \(label) has no END line") }
            guard let der = Data(base64Encoded: body) else {
                throw CertConvertError.malformed("PEM block \(label) is not valid base64")
            }
            blocks.append(PEMBlock(label: label, der: [UInt8](der), headers: headers))
            i += 1
        }
        return blocks
    }

    /// The block as text: headers, base64 in 64-column lines, trailing newline.
    public var text: String {
        var s = "-----BEGIN \(label)-----\n"
        for key in headers.keys.sorted(by: { a, b in a == "Proc-Type" || (b != "Proc-Type" && a < b) }) {
            s += "\(key): \(headers[key]!)\n"
        }
        if !headers.isEmpty { s += "\n" }
        let b64 = Data(der).base64EncodedString()
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            s += b64[idx..<end] + "\n"
            idx = end
        }
        return s + "-----END \(label)-----\n"
    }
}

extension [PEMBlock] {
    var pemText: String { map(\.text).joined() }
}
