import KerberosCrypto
import MSPAC

/// `PACSigner` over KerberosCrypto: signs with one long-term key using the key's mandatory
/// checksum type (16 for AES256, 15 for AES128, -138 for RC4), as MS-PAC §2.8 requires.
public struct KeyPACSigner: PACSigner {
    public let key: KerberosKey

    public init(key: KerberosKey) { self.key = key }

    public var checksumType: Int32 { KerberosCrypto.defaultChecksumType(for: key.type).rawValue }

    public var signatureLength: Int { KerberosCrypto.defaultChecksumType(for: key.type).length }

    public func sign(_ data: [UInt8], usage: Int32) throws -> (type: Int32, signature: [UInt8]) {
        let type = KerberosCrypto.defaultChecksumType(for: key.type)
        return (type.rawValue, try KerberosCrypto.checksum(type, data: data, key: key, usage: usage))
    }
}

/// `PACVerifier` over a set of keys of one account: picks the key whose enctype matches the
/// signature's checksum type (a PAC signed with the AES256 krbtgt key verifies with that key,
/// one signed with RC4 with the RC4 key).
public struct KeySetPACVerifier: PACVerifier {
    public let keys: [KerberosKey]

    public init(keys: [KerberosKey]) { self.keys = keys }

    public func verify(_ data: [UInt8], usage: Int32, type: Int32, signature: [UInt8]) throws -> Bool {
        guard let ctype = ChecksumType(rawValue: type), let key = keys.first(where: { $0.type == ctype.keyType }) else {
            return false
        }
        return try KerberosCrypto.verifyChecksum(ctype, data: data, key: key, usage: usage, expected: signature)
    }
}
