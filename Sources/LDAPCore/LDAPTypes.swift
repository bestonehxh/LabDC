import Store

/// LDAP result codes (RFC 4511 §4.1.9 and Appendix A). A struct so codes we do not name
/// still round-trip.
public struct LDAPResultCode: RawRepresentable, Sendable, Hashable, CustomStringConvertible {
    public var rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }
    public init(_ rawValue: Int) { self.rawValue = rawValue }

    public static let success = LDAPResultCode(0)
    public static let operationsError = LDAPResultCode(1)
    public static let protocolError = LDAPResultCode(2)
    public static let timeLimitExceeded = LDAPResultCode(3)
    public static let sizeLimitExceeded = LDAPResultCode(4)
    public static let compareFalse = LDAPResultCode(5)
    public static let compareTrue = LDAPResultCode(6)
    public static let authMethodNotSupported = LDAPResultCode(7)
    public static let strongerAuthRequired = LDAPResultCode(8)
    public static let referral = LDAPResultCode(10)
    public static let adminLimitExceeded = LDAPResultCode(11)
    public static let unavailableCriticalExtension = LDAPResultCode(12)
    public static let confidentialityRequired = LDAPResultCode(13)
    public static let saslBindInProgress = LDAPResultCode(14)
    public static let noSuchAttribute = LDAPResultCode(16)
    public static let undefinedAttributeType = LDAPResultCode(17)
    public static let inappropriateMatching = LDAPResultCode(18)
    public static let constraintViolation = LDAPResultCode(19)
    public static let attributeOrValueExists = LDAPResultCode(20)
    public static let invalidAttributeSyntax = LDAPResultCode(21)
    public static let noSuchObject = LDAPResultCode(32)
    public static let aliasProblem = LDAPResultCode(33)
    public static let invalidDNSyntax = LDAPResultCode(34)
    public static let aliasDereferencingProblem = LDAPResultCode(36)
    public static let inappropriateAuthentication = LDAPResultCode(48)
    public static let invalidCredentials = LDAPResultCode(49)
    public static let insufficientAccessRights = LDAPResultCode(50)
    public static let busy = LDAPResultCode(51)
    public static let unavailable = LDAPResultCode(52)
    public static let unwillingToPerform = LDAPResultCode(53)
    public static let loopDetect = LDAPResultCode(54)
    public static let namingViolation = LDAPResultCode(64)
    public static let objectClassViolation = LDAPResultCode(65)
    public static let notAllowedOnNonLeaf = LDAPResultCode(66)
    public static let notAllowedOnRDN = LDAPResultCode(67)
    public static let entryAlreadyExists = LDAPResultCode(68)
    public static let objectClassModsProhibited = LDAPResultCode(69)
    public static let affectsMultipleDSAs = LDAPResultCode(71)
    public static let other = LDAPResultCode(80)

    public var description: String { "\(rawValue)" }
}

/// `LDAPResult` (RFC 4511 §4.1.9).
public struct LDAPResult: Sendable, Hashable {
    public var resultCode: LDAPResultCode
    public var matchedDN: String
    public var diagnosticMessage: String
    /// URIs; nil when absent.
    public var referral: [String]?

    public init(_ resultCode: LDAPResultCode, matchedDN: String = "", diagnosticMessage: String = "",
                referral: [String]? = nil) {
        self.resultCode = resultCode
        self.matchedDN = matchedDN
        self.diagnosticMessage = diagnosticMessage
        self.referral = referral
    }

    public static let success = LDAPResult(.success)
}

/// A control (RFC 4511 §4.1.11).
public struct LDAPControl: Sendable, Hashable {
    public var oid: String
    public var critical: Bool
    public var value: [UInt8]?

    public init(oid: String, critical: Bool = false, value: [UInt8]? = nil) {
        self.oid = oid
        self.critical = critical
        self.value = value
    }
}

/// `PartialAttribute` / `Attribute`: a description and its values.
public struct LDAPAttribute: Sendable, Hashable {
    public var type: String
    public var values: [[UInt8]]

    public init(type: String, values: [[UInt8]]) {
        self.type = type
        self.values = values
    }

    public init(_ type: String, strings: [String]) {
        self.init(type: type, values: strings.map { Array($0.utf8) })
    }

    public var strings: [String] { values.map { String(decoding: $0, as: UTF8.self) } }
}

/// BindRequest authentication choice.
public enum BindAuthentication: Sendable, Hashable {
    /// `simple [0] OCTET STRING`.
    case simple([UInt8])
    /// `sasl [3] SaslCredentials`.
    case sasl(mechanism: String, credentials: [UInt8]?)
}

public struct BindRequest: Sendable, Hashable {
    public var version: Int
    public var name: String
    public var authentication: BindAuthentication

    public init(version: Int = 3, name: String, authentication: BindAuthentication) {
        self.version = version
        self.name = name
        self.authentication = authentication
    }
}

public struct BindResponse: Sendable, Hashable {
    public var result: LDAPResult
    public var serverSaslCreds: [UInt8]?

    public init(result: LDAPResult, serverSaslCreds: [UInt8]? = nil) {
        self.result = result
        self.serverSaslCreds = serverSaslCreds
    }
}

public enum DerefAliases: Int, Sendable, Hashable {
    case never = 0, inSearching = 1, findingBaseObject = 2, always = 3
}

public struct SearchRequest: Sendable, Hashable {
    public var baseObject: String
    public var scope: SearchScope
    public var derefAliases: DerefAliases
    public var sizeLimit: Int32
    public var timeLimit: Int32
    public var typesOnly: Bool
    public var filter: FilterAST
    public var attributes: [String]

    public init(baseObject: String, scope: SearchScope, derefAliases: DerefAliases = .never, sizeLimit: Int32 = 0,
                timeLimit: Int32 = 0, typesOnly: Bool = false, filter: FilterAST = .everything, attributes: [String] = []) {
        self.baseObject = baseObject
        self.scope = scope
        self.derefAliases = derefAliases
        self.sizeLimit = sizeLimit
        self.timeLimit = timeLimit
        self.typesOnly = typesOnly
        self.filter = filter
        self.attributes = attributes
    }
}

public struct SearchResultEntry: Sendable, Hashable {
    public var objectName: String
    public var attributes: [LDAPAttribute]

    public init(objectName: String, attributes: [LDAPAttribute]) {
        self.objectName = objectName
        self.attributes = attributes
    }
}

public enum ModifyOperation: Int, Sendable, Hashable {
    case add = 0, delete = 1, replace = 2
    /// RFC 4525.
    case increment = 3
}

public struct ModifyChange: Sendable, Hashable {
    public var operation: ModifyOperation
    public var modification: LDAPAttribute

    public init(_ operation: ModifyOperation, _ modification: LDAPAttribute) {
        self.operation = operation
        self.modification = modification
    }
}

public struct ModifyRequest: Sendable, Hashable {
    public var object: String
    public var changes: [ModifyChange]

    public init(object: String, changes: [ModifyChange]) {
        self.object = object
        self.changes = changes
    }
}

public struct AddRequest: Sendable, Hashable {
    public var entry: String
    public var attributes: [LDAPAttribute]

    public init(entry: String, attributes: [LDAPAttribute]) {
        self.entry = entry
        self.attributes = attributes
    }
}

public struct ModifyDNRequest: Sendable, Hashable {
    public var entry: String
    public var newRDN: String
    public var deleteOldRDN: Bool
    public var newSuperior: String?

    public init(entry: String, newRDN: String, deleteOldRDN: Bool = true, newSuperior: String? = nil) {
        self.entry = entry
        self.newRDN = newRDN
        self.deleteOldRDN = deleteOldRDN
        self.newSuperior = newSuperior
    }
}

public struct CompareRequest: Sendable, Hashable {
    public var entry: String
    public var attribute: String
    public var assertionValue: [UInt8]

    public init(entry: String, attribute: String, assertionValue: [UInt8]) {
        self.entry = entry
        self.attribute = attribute
        self.assertionValue = assertionValue
    }
}

public struct ExtendedRequest: Sendable, Hashable {
    public var name: String
    public var value: [UInt8]?

    public init(name: String, value: [UInt8]? = nil) {
        self.name = name
        self.value = value
    }
}

public struct ExtendedResponse: Sendable, Hashable {
    public var result: LDAPResult
    public var name: String?
    public var value: [UInt8]?

    public init(result: LDAPResult, name: String? = nil, value: [UInt8]? = nil) {
        self.result = result
        self.name = name
        self.value = value
    }
}

public struct IntermediateResponse: Sendable, Hashable {
    public var name: String?
    public var value: [UInt8]?

    public init(name: String? = nil, value: [UInt8]? = nil) {
        self.name = name
        self.value = value
    }
}

/// `protocolOp` of an LDAPMessage.
public enum LDAPOperation: Sendable, Hashable {
    case bindRequest(BindRequest)
    case bindResponse(BindResponse)
    case unbindRequest
    case searchRequest(SearchRequest)
    case searchResultEntry(SearchResultEntry)
    case searchResultDone(LDAPResult)
    case searchResultReference([String])
    case modifyRequest(ModifyRequest)
    case modifyResponse(LDAPResult)
    case addRequest(AddRequest)
    case addResponse(LDAPResult)
    case deleteRequest(String)
    case deleteResponse(LDAPResult)
    case modifyDNRequest(ModifyDNRequest)
    case modifyDNResponse(LDAPResult)
    case compareRequest(CompareRequest)
    case compareResponse(LDAPResult)
    case abandonRequest(Int32)
    case extendedRequest(ExtendedRequest)
    case extendedResponse(ExtendedResponse)
    case intermediateResponse(IntermediateResponse)
    /// An application tag this model does not know; the raw element is kept so a server can
    /// still answer the message ID.
    case unrecognized(BERElement)

    /// Short name for logs.
    public var name: String {
        switch self {
        case .bindRequest: "BindRequest"
        case .bindResponse: "BindResponse"
        case .unbindRequest: "UnbindRequest"
        case .searchRequest: "SearchRequest"
        case .searchResultEntry: "SearchResultEntry"
        case .searchResultDone: "SearchResultDone"
        case .searchResultReference: "SearchResultReference"
        case .modifyRequest: "ModifyRequest"
        case .modifyResponse: "ModifyResponse"
        case .addRequest: "AddRequest"
        case .addResponse: "AddResponse"
        case .deleteRequest: "DelRequest"
        case .deleteResponse: "DelResponse"
        case .modifyDNRequest: "ModifyDNRequest"
        case .modifyDNResponse: "ModifyDNResponse"
        case .compareRequest: "CompareRequest"
        case .compareResponse: "CompareResponse"
        case .abandonRequest: "AbandonRequest"
        case .extendedRequest: "ExtendedRequest"
        case .extendedResponse: "ExtendedResponse"
        case .intermediateResponse: "IntermediateResponse"
        case .unrecognized(let e): "Unrecognized\(e.tag)"
        }
    }
}
