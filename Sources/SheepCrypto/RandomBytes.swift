import Synchronization

/// Source of random bytes for keys, confounders and nonces.
///
/// `RandomBytes()` draws from `SystemRandomNumberGenerator` (the OS CSPRNG) and is what
/// production code uses. `RandomBytes(seed:)` is a deterministic xorshift64* stream for tests
/// only — it is not cryptographically secure. Copies of a seeded instance share one stream.
public struct RandomBytes: Sendable {
    private let state: State?

    /// Cryptographically secure randomness from the system.
    public init() {
        state = nil
    }

    /// Deterministic stream for tests. The same seed always yields the same bytes.
    public init(seed: UInt64) {
        state = State(seed: seed)
    }

    /// Returns `count` random bytes.
    public func next(_ count: Int) -> [UInt8] {
        precondition(count >= 0, "count must not be negative")
        var out = [UInt8]()
        out.reserveCapacity(count)
        if let state {
            state.fill(&out, count: count)
        } else {
            var generator = SystemRandomNumberGenerator()
            Self.fill(&out, count: count) { generator.next() }
        }
        return out
    }

    fileprivate static func fill(_ out: inout [UInt8], count: Int, word: () -> UInt64) {
        while out.count < count {
            var w = word()
            for _ in 0..<min(8, count - out.count) {
                out.append(UInt8(truncatingIfNeeded: w))
                w >>= 8
            }
        }
    }

    /// Shared, lock-protected xorshift64* state (Vigna 2016).
    private final class State: Sendable {
        private let x: Mutex<UInt64>

        init(seed: UInt64) {
            // Scramble the seed with one SplitMix64 step so small seeds (0, 1, 2 ...) give
            // unrelated streams, and avoid the all-zero state xorshift can never leave.
            var z = seed &+ 0x9E37_79B9_7F4A_7C15
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            z ^= z >> 31
            x = Mutex(z == 0 ? 0x2545_F491_4F6C_DD1D : z)
        }

        func fill(_ out: inout [UInt8], count: Int) {
            x.withLock { x in
                RandomBytes.fill(&out, count: count) {
                    x ^= x >> 12
                    x ^= x << 25
                    x ^= x >> 27
                    return x &* 0x2545_F491_4F6C_DD1D
                }
            }
        }
    }
}
