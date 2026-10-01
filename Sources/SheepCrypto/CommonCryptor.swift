import CommonCrypto

/// One-shot `CCCrypt` helper shared by the RC4 and DES wrappers.
nonisolated enum CommonCryptor {
    static func crypt(
        _ operation: CCOperation,
        algorithm: CCAlgorithm,
        options: CCOptions,
        key: [UInt8],
        input: [UInt8]
    ) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status = key.withUnsafeBufferPointer { k in
            input.withUnsafeBufferPointer { i in
                output.withUnsafeMutableBufferPointer { o in
                    CCCrypt(operation, algorithm, options,
                            k.baseAddress, k.count,
                            nil,
                            i.baseAddress, i.count,
                            o.baseAddress, o.count,
                            &moved)
                }
            }
        }
        precondition(status == CCCryptorStatus(kCCSuccess), "CCCrypt failed with status \(status)")
        precondition(moved == input.count, "CCCrypt produced \(moved) bytes for \(input.count) input bytes")
        return output
    }
}
