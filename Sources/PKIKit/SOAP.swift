import Foundation

// PK-6: the SOAP 1.2 / WS-Addressing plumbing MS-XCEP and MS-WSTEP share. Requests are parsed
// with Foundation's `XMLDocument` (namespace-aware, external entities never loaded); responses
// are written as compact strings in the prefixes and namespace layout of the AD CS examples
// (MS-XCEP §4.1, MS-WSTEP §4.1): `s:` SOAP 1.2, `a:` WS-Addressing, default namespaces on the
// payload elements, `xsi` / `xsd` declared on `s:Body`.

/// XML namespaces used by the two services.
public enum SOAPNS {
    public static let soap12 = "http://www.w3.org/2003/05/soap-envelope"
    public static let addressing = "http://www.w3.org/2005/08/addressing"
    public static let xsi = "http://www.w3.org/2001/XMLSchema-instance"
    public static let xsd = "http://www.w3.org/2001/XMLSchema"
    public static let xcep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
    public static let wstep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
    public static let wsTrust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    public static let wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    public static let authorization = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
    public static let wcfDiagnostics = "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics"
}

/// A parsed SOAP 1.2 request: the WS-Addressing header values and the first body element.
public struct SOAPRequest: @unchecked Sendable {
    public var action: String?
    public var messageID: String?
    public var to: String?
    /// The first element child of `s:Body`.
    public var body: XMLElement

    public enum ParseError: Error, CustomStringConvertible {
        case notXML(String)
        case notSOAP12(String)
        case emptyBody

        public var description: String {
            switch self {
            case .notXML(let s): "the request is not well-formed XML (\(s))"
            case .notSOAP12(let s): "not a SOAP 1.2 envelope (\(s))"
            case .emptyBody: "the SOAP body is empty"
            }
        }
    }

    public init(bytes: [UInt8]) throws {
        // No DTD at all (entity expansion, XXE): refused before the parser sees it.
        if String(decoding: bytes.prefix(4096), as: UTF8.self).range(of: "<!DOCTYPE", options: .caseInsensitive) != nil {
            throw ParseError.notXML("a DTD is not allowed")
        }
        let doc: XMLDocument
        do {
            // No DTDs, no external entities (XXE): WCF refuses DTDs too.
            doc = try XMLDocument(data: Data(bytes), options: [.nodeLoadExternalEntitiesNever])
        } catch {
            throw ParseError.notXML("\(error.localizedDescription)")
        }
        if doc.dtd != nil { throw ParseError.notXML("a DTD is not allowed") }
        guard let envelope = doc.rootElement() else { throw ParseError.notXML("no root element") }
        guard envelope.localName == "Envelope", envelope.uri == SOAPNS.soap12 else {
            throw ParseError.notSOAP12("root element {\(envelope.uri ?? "")}\(envelope.localName ?? "?")")
        }
        let header = envelope.child(SOAPNS.soap12, "Header")
        action = header?.child(SOAPNS.addressing, "Action")?.trimmedText
        messageID = header?.child(SOAPNS.addressing, "MessageID")?.trimmedText
        to = header?.child(SOAPNS.addressing, "To")?.trimmedText
        guard let bodyElement = envelope.child(SOAPNS.soap12, "Body"), let first = bodyElement.elementChildren.first else {
            throw ParseError.emptyBody
        }
        body = first
    }
}

extension XMLElement {
    /// Element children, in document order.
    var elementChildren: [XMLElement] { (children ?? []).compactMap { $0 as? XMLElement } }

    /// The first child element with this namespace and local name.
    func child(_ namespace: String?, _ name: String) -> XMLElement? {
        elementChildren.first { $0.localName == name && (namespace == nil || $0.uri == namespace) }
    }

    func children(_ namespace: String?, _ name: String) -> [XMLElement] {
        elementChildren.filter { $0.localName == name && (namespace == nil || $0.uri == namespace) }
    }

    /// The text content with surrounding white space removed.
    var trimmedText: String { (stringValue ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }

    /// `xsi:nil="true"` (any prefix bound to the XSI namespace, or an unprefixed `nil` as in the
    /// MS-XCEP §4.1.1.2 example).
    var isNil: Bool {
        for attribute in attributes ?? [] {
            guard let name = attribute.localName, name == "nil" else { continue }
            if attribute.uri == SOAPNS.xsi || attribute.uri == nil || attribute.uri == "" {
                return (attribute.stringValue ?? "").trimmingCharacters(in: .whitespaces).lowercased() == "true"
            }
        }
        return false
    }

    /// An attribute by local name (any namespace).
    func attributeValue(_ name: String) -> String? {
        (attributes ?? []).first { ($0.localName ?? $0.name) == name }?.stringValue
    }
}

/// Writing side.
public enum SOAP {
    public static let contentType = "application/soap+xml; charset=utf-8"

    /// Escapes text content and attribute values.
    public static func escape(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        for ch in text {
            switch ch {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            default: out.append(ch)
            }
        }
        return out
    }

    /// `<name>text</name>` with the text escaped.
    static func element(_ name: String, _ text: String) -> String { "<\(name)>\(escape(text))</\(name)>" }

    /// `<name xsi:nil="true"/>`.
    static func nilElement(_ name: String) -> String { "<\(name) xsi:nil=\"true\"/>" }

    /// A response envelope: `a:Action` (mustUnderstand), `a:RelatesTo` when the request had a
    /// MessageID, and `payload` inside `s:Body` (which declares `xsi` and `xsd`).
    static func envelope(action: String, relatesTo: String?, payload: String) -> [UInt8] {
        var s = "<s:Envelope xmlns:s=\"\(SOAPNS.soap12)\" xmlns:a=\"\(SOAPNS.addressing)\">"
        s += "<s:Header><a:Action s:mustUnderstand=\"1\">\(escape(action))</a:Action>"
        if let relatesTo, !relatesTo.isEmpty { s += "<a:RelatesTo>\(escape(relatesTo))</a:RelatesTo>" }
        s += "</s:Header>"
        s += "<s:Body xmlns:xsi=\"\(SOAPNS.xsi)\" xmlns:xsd=\"\(SOAPNS.xsd)\">\(payload)</s:Body></s:Envelope>"
        return Array(s.utf8)
    }

    /// The fault action WCF (AD CS's CEP/CES host) uses (MS-WSTEP §4.1.4.2).
    public static let faultAction = "http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher/fault"

    /// A SOAP 1.2 fault: `code` is `s:Sender` or `s:Receiver`; `detail` is inserted as is.
    static func fault(code: String, subcode: (namespace: String, value: String)? = nil, reason: String,
                      detail: String? = nil, relatesTo: String?) -> [UInt8] {
        var f = "<s:Fault><s:Code><s:Value>\(code)</s:Value>"
        if let subcode {
            f += "<s:Subcode><s:Value xmlns:a=\"\(escape(subcode.namespace))\">a:\(escape(subcode.value))</s:Value></s:Subcode>"
        }
        f += "</s:Code><s:Reason><s:Text xml:lang=\"en-US\">\(escape(reason))</s:Text></s:Reason>"
        if let detail { f += "<s:Detail>\(detail)</s:Detail>" }
        f += "</s:Fault>"
        return envelope(action: faultAction, relatesTo: relatesTo, payload: f)
    }
}
