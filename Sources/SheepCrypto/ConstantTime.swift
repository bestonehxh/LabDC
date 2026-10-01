/// Timing-safe comparison for MACs, checksums and other secrets.
public nonisolated enum ConstantTime {
    /// Returns `true` when `a` and `b` are equal. The running time depends only on the
    /// lengths, never on where the first differing byte is. Different lengths return `false`
    /// immediately (lengths of MACs are public).
    public static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for i in 0..<a.count {
            difference |= a[i] ^ b[i]
        }
        return difference == 0
    }
}
