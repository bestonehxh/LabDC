import CommonCrypto

/// HMAC-SHA1 (RFC 2104) via CommonCrypto. SheepCrypto only has HMAC-MD5, so the AES
/// enctypes carry their own.
nonisolated enum HMACSHA1 {
    static let outputLength = Int(CC_SHA1_DIGEST_LENGTH)

    static func authenticate(key: [UInt8], _ bytes: [UInt8]) -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: outputLength)
        key.withUnsafeBufferPointer { k in
            bytes.withUnsafeBufferPointer { d in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), k.baseAddress, k.count, d.baseAddress, d.count, &mac)
            }
        }
        return mac
    }
}

/// Raw AES-CBC with no padding via CommonCrypto, plus the RFC 3962 §5 ciphertext-stealing
/// mode built on top of it. The IV is always zero here: Kerberos messages start with a
/// random confounder, and phase 0 has no use for carried cipher state.
nonisolated enum AESCBC {
    static let blockSize = kCCBlockSizeAES128

    /// Plain CBC over whole blocks, zero IV, no padding.
    static func cbc(_ operation: Int, key: [UInt8], _ input: [UInt8]) throws(KerberosCryptoError) -> [UInt8] {
        precondition(input.count % blockSize == 0, "CBC input must be whole blocks")
        precondition([16, 24, 32].contains(key.count), "AES key must be 16, 24 or 32 bytes")
        if input.isEmpty { return [] }
        let iv = [UInt8](repeating: 0, count: blockSize)
        var output = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status = key.withUnsafeBufferPointer { k in
            iv.withUnsafeBufferPointer { v in
                input.withUnsafeBufferPointer { i in
                    output.withUnsafeMutableBufferPointer { o in
                        CCCrypt(CCOperation(operation), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                                k.baseAddress, k.count, v.baseAddress,
                                i.baseAddress, i.count, o.baseAddress, o.count, &moved)
                    }
                }
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), moved == input.count else {
            throw .commonCrypto(status: status)
        }
        return output
    }

    /// AES-CBC-CTS encryption with a zero IV (RFC 3962 §5).
    ///
    /// - Shorter than one block: zero-padded to one block and encrypted (the RFC leaves the
    ///   padding value unspecified); the output is one full block.
    /// - Exactly one block: plain AES (ECB) of that block.
    /// - Longer: CBC over the zero-padded input, then the last two ciphertext blocks are
    ///   swapped and the (new) last one truncated to the length of the final partial block.
    static func ctsEncrypt(key: [UInt8], _ plaintext: [UInt8]) throws(KerberosCryptoError) -> [UInt8] {
        let n = plaintext.count
        if n <= blockSize {
            return try cbc(kCCEncrypt, key: key, plaintext + [UInt8](repeating: 0, count: blockSize - n))
        }
        let tail = n % blockSize == 0 ? blockSize : n % blockSize     // bytes in the final block
        let padded = plaintext + [UInt8](repeating: 0, count: blockSize - tail)
        let c = try cbc(kCCEncrypt, key: key, padded)
        let lastStart = c.count - blockSize
        let prevStart = lastStart - blockSize
        return Array(c[..<prevStart]) + Array(c[lastStart...]) + Array(c[prevStart..<(prevStart + tail)])
    }

    /// Inverse of `ctsEncrypt` for inputs of at least one block. (A ciphertext of exactly one
    /// block decrypts to one block; a sub-block plaintext cannot be recovered without knowing
    /// its length, and Kerberos never produces one because of the 16-byte confounder.)
    static func ctsDecrypt(key: [UInt8], _ ciphertext: [UInt8]) throws(KerberosCryptoError) -> [UInt8] {
        let n = ciphertext.count
        precondition(n >= blockSize, "CTS ciphertext must be at least one block")
        if n == blockSize {
            return try cbc(kCCDecrypt, key: key, ciphertext)
        }
        let tail = n % blockSize == 0 ? blockSize : n % blockSize
        // Ciphertext layout: C[0 ..< k] whole CBC blocks, then E_m (full), then E_{m-1} truncated.
        let swappedStart = n - tail - blockSize
        let eLast = Array(ciphertext[swappedStart..<(swappedStart + blockSize)])       // E_m
        let ePrevHead = Array(ciphertext[(swappedStart + blockSize)...])               // E_{m-1}[0..<tail]
        // D(E_m) = P_m(zero padded) XOR E_{m-1}; its bytes past `tail` are E_{m-1}'s tail.
        let x = try cbc(kCCDecrypt, key: key, eLast)
        let ePrev = ePrevHead + Array(x[tail...])
        // Rebuild the ordinary CBC ciphertext and decrypt it in one call.
        let standard = Array(ciphertext[..<swappedStart]) + ePrev + eLast
        let p = try cbc(kCCDecrypt, key: key, standard)
        return Array(p[..<n])
    }
}

/// n-fold (RFC 3961 §5.1): stretch or shrink `input` to `outputBytes` bytes.
///
/// The input is repeated lcm(inBytes, outBytes)/inBytes times, each copy rotated right by
/// 13 bits more than the previous one (rotation over the whole copy, as a big bit string),
/// and the concatenation is cut into `outputBytes` chunks that are summed with
/// ones'-complement (end-around carry) addition.
nonisolated func nFold(_ input: [UInt8], outputBytes: Int) -> [UInt8] {
    precondition(!input.isEmpty && outputBytes > 0)
    let inBytes = input.count
    let lcm = inBytes / gcd(inBytes, outputBytes) * outputBytes
    let inBits = inBytes * 8

    var sum = [Int](repeating: 0, count: outputBytes)
    for copy in 0..<(lcm / inBytes) {
        let rotation = (13 * copy) % inBits
        for byteIndex in 0..<inBytes {
            // Byte `byteIndex` of the copy rotated right by `rotation` bits: bit j of the
            // output copy is bit (j - rotation) mod inBits of the input.
            var value = 0
            for bit in 0..<8 {
                let outBit = byteIndex * 8 + bit
                let srcBit = ((outBit - rotation) % inBits + inBits) % inBits
                let set = (input[srcBit / 8] >> (7 - UInt8(srcBit % 8))) & 1
                value |= Int(set) << (7 - bit)
            }
            sum[(copy * inBytes + byteIndex) % outputBytes] += value
        }
    }
    // Ones'-complement addition: propagate carries from the least significant byte
    // (the last) upward, wrapping the carry out of the top byte back to the bottom,
    // until no carries remain.
    var carry = 0
    repeat {
        for i in stride(from: outputBytes - 1, through: 0, by: -1) {
            let v = sum[i] + carry
            sum[i] = v & 0xFF
            carry = v >> 8
        }
    } while carry != 0
    return sum.map { UInt8($0) }
}

private nonisolated func gcd(_ a: Int, _ b: Int) -> Int {
    var (a, b) = (a, b)
    while b != 0 { (a, b) = (b, a % b) }
    return a
}
