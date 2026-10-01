import Store

/// `LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls [0] OPTIONAL }` (RFC 4511 §4.1.1).
public struct LDAPMessage: Sendable, Hashable {
    public var messageID: Int32
    public var operation: LDAPOperation
    public var controls: [LDAPControl]

    public init(messageID: Int32, _ operation: LDAPOperation, controls: [LDAPControl] = []) {
        self.messageID = messageID
        self.operation = operation
        self.controls = controls
    }

    /// The control with `oid`, if present.
    public func control(_ oid: String) -> LDAPControl? { controls.first { $0.oid == oid } }

    // MARK: Application tags (RFC 4511 Appendix B)

    enum Tag {
        static let bindRequest: UInt32 = 0, bindResponse: UInt32 = 1, unbindRequest: UInt32 = 2
        static let searchRequest: UInt32 = 3, searchResultEntry: UInt32 = 4, searchResultDone: UInt32 = 5
        static let modifyRequest: UInt32 = 6, modifyResponse: UInt32 = 7, addRequest: UInt32 = 8, addResponse: UInt32 = 9
        static let delRequest: UInt32 = 10, delResponse: UInt32 = 11, modDNRequest: UInt32 = 12, modDNResponse: UInt32 = 13
        static let compareRequest: UInt32 = 14, compareResponse: UInt32 = 15, abandonRequest: UInt32 = 16
        static let searchResultReference: UInt32 = 19, extendedRequest: UInt32 = 23, extendedResponse: UInt32 = 24
        static let intermediateResponse: UInt32 = 25
    }

    // MARK: Decoding

    /// Decodes one complete LDAPMessage.
    public init(bytes: [UInt8]) throws {
        try self.init(element: try BERElement(bytes: bytes))
    }

    /// Decodes just enough of a message to learn its ID (for error replies to messages that
    /// do not otherwise decode). Nil when even that fails.
    public static func messageID(of bytes: [UInt8]) -> Int32? {
        guard let e = try? BERElement(bytes: bytes), e.tag == .sequence,
              let first = try? e.children().first, first.tag == .integer else { return nil }
        return try? first.int32()
    }

    public init(element: BERElement) throws {
        var f = try BERFields(try element.expect(.sequence, "LDAPMessage"), "LDAPMessage")
        let id = try f.next(.integer, "messageID").int32()
        guard id >= 0 else { throw LDAPCoreError.malformed(what: "LDAPMessage", reason: "negative messageID") }
        messageID = id
        let op = try f.next("protocolOp")
        operation = try Self.decodeOperation(op)
        controls = []
        if let c = f.optional(.context(0, constructed: true)) {
            guard c.tag.constructed else { throw LDAPCoreError.malformed(what: "Controls", reason: "primitive") }
            controls = try c.children().map(Self.decodeControl)
        }
        // RFC 4511 §4: unknown trailing elements are ignored (extensibility).
    }

    static func decodeControl(_ e: BERElement) throws -> LDAPControl {
        var f = try BERFields(try e.expect(.sequence, "Control"), "Control")
        let oid = try f.next(.octetString, "controlType").string()
        var critical = false
        var value: [UInt8]?
        if let b = f.optional(.boolean) { critical = try b.boolean() }
        if let v = f.optional(.octetString) { value = try v.octets() }
        return LDAPControl(oid: oid, critical: critical, value: value)
    }

    static func decodeResult(_ f: inout BERFields) throws -> LDAPResult {
        let code = try f.next(.enumerated, "resultCode").integer()
        let matched = try f.next(.octetString, "matchedDN").string()
        let diag = try f.next(.octetString, "diagnosticMessage").string()
        var referral: [String]?
        if let r = f.optional(.context(3, constructed: true)) {
            referral = try r.children().map { try $0.expect(.octetString, "URI").string() }
        }
        guard let c = Int(exactly: code) else { throw LDAPCoreError.integerOverflow("resultCode") }
        return LDAPResult(LDAPResultCode(c), matchedDN: matched, diagnosticMessage: diag, referral: referral)
    }

    static func decodeAttribute(_ e: BERElement, _ what: String) throws -> LDAPAttribute {
        var f = try BERFields(try e.expect(.sequence, what), what)
        let type = try f.next(.octetString, "type").string()
        let valsElement = try f.next("vals")
        guard valsElement.tag == .set || valsElement.tag == .sequence else {
            throw LDAPCoreError.unexpectedTag(expected: "\(what).vals SET", found: valsElement.tag)
        }
        let values = try valsElement.children().map { try $0.expect(.octetString, "AttributeValue").octets() }
        return LDAPAttribute(type: type, values: values)
    }

    static func decodeOperation(_ op: BERElement) throws -> LDAPOperation {
        guard op.tag.tagClass == .application else {
            throw LDAPCoreError.unexpectedTag(expected: "protocolOp [APPLICATION n]", found: op.tag)
        }
        switch op.tag.number {
        case Tag.bindRequest:
            var f = try BERFields(op, "BindRequest")
            let version = try f.next(.integer, "version").integer()
            let name = try f.next(.octetString, "name").string()
            let auth = try f.next("authentication")
            let authentication: BindAuthentication
            switch (auth.tag.tagClass, auth.tag.number) {
            case (.contextSpecific, 0):
                authentication = .simple(try auth.octets())
            case (.contextSpecific, 3):
                var s = try BERFields(auth, "SaslCredentials")
                let mech = try s.next(.octetString, "mechanism").string()
                let creds = try s.optional(.octetString).map { try $0.octets() }
                authentication = .sasl(mechanism: mech, credentials: creds)
            default:
                throw LDAPCoreError.unexpectedTag(expected: "AuthenticationChoice", found: auth.tag)
            }
            guard let v = Int(exactly: version), (1...127).contains(v) else {
                throw LDAPCoreError.malformed(what: "BindRequest", reason: "version \(version)")
            }
            return .bindRequest(BindRequest(version: v, name: name, authentication: authentication))
        case Tag.bindResponse:
            var f = try BERFields(op, "BindResponse")
            let result = try decodeResult(&f)
            let creds = try f.optional(.context(7)).map { try $0.octets() }
            return .bindResponse(BindResponse(result: result, serverSaslCreds: creds))
        case Tag.unbindRequest:
            return .unbindRequest
        case Tag.searchRequest:
            var f = try BERFields(op, "SearchRequest")
            let base = try f.next(.octetString, "baseObject").string()
            let scopeValue = try f.next(.enumerated, "scope").integer()
            guard let scope = SearchScope(rawValue: Int(truncatingIfNeeded: scopeValue)), (0...2).contains(scopeValue) else {
                throw LDAPCoreError.malformed(what: "SearchRequest", reason: "scope \(scopeValue)")
            }
            let derefValue = try f.next(.enumerated, "derefAliases").integer()
            guard (0...3).contains(derefValue), let deref = DerefAliases(rawValue: Int(derefValue)) else {
                throw LDAPCoreError.malformed(what: "SearchRequest", reason: "derefAliases \(derefValue)")
            }
            let sizeLimit = try f.next(.integer, "sizeLimit").int32()
            let timeLimit = try f.next(.integer, "timeLimit").int32()
            let typesOnly = try f.next(.boolean, "typesOnly").boolean()
            let filter = try FilterAST(berElement: try f.next("filter"))
            let attrsElement = try f.next(.sequence, "attributes")
            let attrs = try attrsElement.children().map { try $0.expect(.octetString, "AttributeSelector").string() }
            guard sizeLimit >= 0, timeLimit >= 0 else {
                throw LDAPCoreError.malformed(what: "SearchRequest", reason: "negative limit")
            }
            return .searchRequest(SearchRequest(baseObject: base, scope: scope, derefAliases: deref, sizeLimit: sizeLimit,
                                                timeLimit: timeLimit, typesOnly: typesOnly, filter: filter, attributes: attrs))
        case Tag.searchResultEntry:
            var f = try BERFields(op, "SearchResultEntry")
            let name = try f.next(.octetString, "objectName").string()
            let attrs = try f.next(.sequence, "attributes").children().map { try decodeAttribute($0, "PartialAttribute") }
            return .searchResultEntry(SearchResultEntry(objectName: name, attributes: attrs))
        case Tag.searchResultDone:
            var f = try BERFields(op, "SearchResultDone")
            return .searchResultDone(try decodeResult(&f))
        case Tag.searchResultReference:
            let uris = try op.children().map { try $0.expect(.octetString, "URI").string() }
            return .searchResultReference(uris)
        case Tag.modifyRequest:
            var f = try BERFields(op, "ModifyRequest")
            let object = try f.next(.octetString, "object").string()
            let changes = try f.next(.sequence, "changes").children().map { c -> ModifyChange in
                var cf = try BERFields(try c.expect(.sequence, "change"), "change")
                let opValue = try cf.next(.enumerated, "operation").integer()
                guard (0...3).contains(opValue), let operation = ModifyOperation(rawValue: Int(opValue)) else {
                    throw LDAPCoreError.malformed(what: "ModifyRequest", reason: "operation \(opValue)")
                }
                return ModifyChange(operation, try decodeAttribute(try cf.next("modification"), "modification"))
            }
            return .modifyRequest(ModifyRequest(object: object, changes: changes))
        case Tag.modifyResponse:
            var f = try BERFields(op, "ModifyResponse")
            return .modifyResponse(try decodeResult(&f))
        case Tag.addRequest:
            var f = try BERFields(op, "AddRequest")
            let entry = try f.next(.octetString, "entry").string()
            let attrs = try f.next(.sequence, "attributes").children().map { try decodeAttribute($0, "Attribute") }
            return .addRequest(AddRequest(entry: entry, attributes: attrs))
        case Tag.addResponse:
            var f = try BERFields(op, "AddResponse")
            return .addResponse(try decodeResult(&f))
        case Tag.delRequest:
            return .deleteRequest(try op.string())
        case Tag.delResponse:
            var f = try BERFields(op, "DelResponse")
            return .deleteResponse(try decodeResult(&f))
        case Tag.modDNRequest:
            var f = try BERFields(op, "ModifyDNRequest")
            let entry = try f.next(.octetString, "entry").string()
            let newRDN = try f.next(.octetString, "newrdn").string()
            let deleteOld = try f.next(.boolean, "deleteoldrdn").boolean()
            let sup = try f.optional(.context(0)).map { try $0.string() }
            return .modifyDNRequest(ModifyDNRequest(entry: entry, newRDN: newRDN, deleteOldRDN: deleteOld, newSuperior: sup))
        case Tag.modDNResponse:
            var f = try BERFields(op, "ModifyDNResponse")
            return .modifyDNResponse(try decodeResult(&f))
        case Tag.compareRequest:
            var f = try BERFields(op, "CompareRequest")
            let entry = try f.next(.octetString, "entry").string()
            var ava = try BERFields(try f.next(.sequence, "ava"), "AttributeValueAssertion")
            let desc = try ava.next(.octetString, "attributeDesc").string()
            let value = try ava.next(.octetString, "assertionValue").octets()
            return .compareRequest(CompareRequest(entry: entry, attribute: desc, assertionValue: value))
        case Tag.compareResponse:
            var f = try BERFields(op, "CompareResponse")
            return .compareResponse(try decodeResult(&f))
        case Tag.abandonRequest:
            return .abandonRequest(try op.int32())
        case Tag.extendedRequest:
            var f = try BERFields(op, "ExtendedRequest")
            let name = try f.next(.context(0), "requestName").string()
            let value = try f.optional(.context(1)).map { try $0.octets() }
            return .extendedRequest(ExtendedRequest(name: name, value: value))
        case Tag.extendedResponse:
            var f = try BERFields(op, "ExtendedResponse")
            let result = try decodeResult(&f)
            let name = try f.optional(.context(10)).map { try $0.string() }
            let value = try f.optional(.context(11)).map { try $0.octets() }
            return .extendedResponse(ExtendedResponse(result: result, name: name, value: value))
        case Tag.intermediateResponse:
            var f = try BERFields(op, "IntermediateResponse")
            let name = try f.optional(.context(0)).map { try $0.string() }
            let value = try f.optional(.context(1)).map { try $0.octets() }
            return .intermediateResponse(IntermediateResponse(name: name, value: value))
        default:
            return .unrecognized(op)
        }
    }

    // MARK: Encoding

    /// DER encoding of the message.
    public func encoded() -> [UInt8] { element.encoded() }

    public var element: BERElement {
        var items: [BERElement] = [.integer(Int64(messageID)), Self.encodeOperation(operation)]
        if !controls.isEmpty {
            items.append(.sequence(controls.map(Self.encodeControl), tag: .context(0, constructed: true)))
        }
        return .sequence(items)
    }

    static func encodeControl(_ c: LDAPControl) -> BERElement {
        var items: [BERElement] = [.octetString(c.oid)]
        if c.critical { items.append(.boolean(true)) }
        if let v = c.value { items.append(.octetString(v)) }
        return .sequence(items)
    }

    static func resultItems(_ r: LDAPResult) -> [BERElement] {
        var items: [BERElement] = [.enumerated(Int64(r.resultCode.rawValue)), .octetString(r.matchedDN),
                                   .octetString(r.diagnosticMessage)]
        if let refs = r.referral { items.append(.sequence(refs.map { .octetString($0) }, tag: .context(3, constructed: true))) }
        return items
    }

    /// `vals SET OF` keeps the stored value order (AD does; clients show objectClass in
    /// hierarchy order), rather than DER's sorted SET OF.
    static func encodeAttribute(_ a: LDAPAttribute) -> BERElement {
        .sequence([.octetString(a.type), .sequence(a.values.map { .octetString($0) }, tag: .set)])
    }

    static func app(_ n: UInt32, _ items: [BERElement]) -> BERElement {
        .sequence(items, tag: .application(n, constructed: true))
    }

    static func encodeOperation(_ op: LDAPOperation) -> BERElement {
        switch op {
        case .bindRequest(let r):
            let auth: BERElement
            switch r.authentication {
            case .simple(let pw): auth = .octetString(pw, tag: .context(0))
            case let .sasl(mech, creds):
                var s: [BERElement] = [.octetString(mech)]
                if let creds { s.append(.octetString(creds)) }
                auth = .sequence(s, tag: .context(3, constructed: true))
            }
            return app(Tag.bindRequest, [.integer(Int64(r.version)), .octetString(r.name), auth])
        case .bindResponse(let r):
            var items = resultItems(r.result)
            if let c = r.serverSaslCreds { items.append(.octetString(c, tag: .context(7))) }
            return app(Tag.bindResponse, items)
        case .unbindRequest:
            return .null(tag: .application(Tag.unbindRequest, constructed: false))
        case .searchRequest(let r):
            return app(Tag.searchRequest, [
                .octetString(r.baseObject), .enumerated(Int64(r.scope.rawValue)), .enumerated(Int64(r.derefAliases.rawValue)),
                .integer(Int64(r.sizeLimit)), .integer(Int64(r.timeLimit)), .boolean(r.typesOnly), r.filter.berElement,
                .sequence(r.attributes.map { .octetString($0) }),
            ])
        case .searchResultEntry(let e):
            return app(Tag.searchResultEntry, [.octetString(e.objectName), .sequence(e.attributes.map(encodeAttribute))])
        case .searchResultDone(let r):
            return app(Tag.searchResultDone, resultItems(r))
        case .searchResultReference(let uris):
            return app(Tag.searchResultReference, uris.map { .octetString($0) })
        case .modifyRequest(let r):
            return app(Tag.modifyRequest, [
                .octetString(r.object),
                .sequence(r.changes.map { .sequence([.enumerated(Int64($0.operation.rawValue)), encodeAttribute($0.modification)]) }),
            ])
        case .modifyResponse(let r): return app(Tag.modifyResponse, resultItems(r))
        case .addRequest(let r):
            return app(Tag.addRequest, [.octetString(r.entry), .sequence(r.attributes.map(encodeAttribute))])
        case .addResponse(let r): return app(Tag.addResponse, resultItems(r))
        case .deleteRequest(let dn):
            return .octetString(dn, tag: .application(Tag.delRequest, constructed: false))
        case .deleteResponse(let r): return app(Tag.delResponse, resultItems(r))
        case .modifyDNRequest(let r):
            var items: [BERElement] = [.octetString(r.entry), .octetString(r.newRDN), .boolean(r.deleteOldRDN)]
            if let s = r.newSuperior { items.append(.octetString(s, tag: .context(0))) }
            return app(Tag.modDNRequest, items)
        case .modifyDNResponse(let r): return app(Tag.modDNResponse, resultItems(r))
        case .compareRequest(let r):
            return app(Tag.compareRequest, [.octetString(r.entry),
                                            .sequence([.octetString(r.attribute), .octetString(r.assertionValue)])])
        case .compareResponse(let r): return app(Tag.compareResponse, resultItems(r))
        case .abandonRequest(let id):
            return .integer(Int64(id), tag: .application(Tag.abandonRequest, constructed: false))
        case .extendedRequest(let r):
            var items: [BERElement] = [.octetString(r.name, tag: .context(0))]
            if let v = r.value { items.append(.octetString(v, tag: .context(1))) }
            return app(Tag.extendedRequest, items)
        case .extendedResponse(let r):
            var items = resultItems(r.result)
            if let n = r.name { items.append(.octetString(n, tag: .context(10))) }
            if let v = r.value { items.append(.octetString(v, tag: .context(11))) }
            return app(Tag.extendedResponse, items)
        case .intermediateResponse(let r):
            var items: [BERElement] = []
            if let n = r.name { items.append(.octetString(n, tag: .context(0))) }
            if let v = r.value { items.append(.octetString(v, tag: .context(1))) }
            return app(Tag.intermediateResponse, items)
        case .unrecognized(let e):
            return e
        }
    }
}
