import Foundation
import Synchronization

/// The runtime's log lines for the app: a bounded history plus any number of live
/// `AsyncStream<LogLine>` subscribers. `ServeLog(lines:)` feeds it; the CLI keeps printing to
/// stdout as before.
public final class LogHub: Sendable {
    public let capacity: Int
    private struct State {
        var lines: [LogLine] = []
        var nextSeq = 1
        var subscribers: [UUID: AsyncStream<LogLine>.Continuation] = [:]
    }
    private let state = Mutex(State())

    public init(capacity: Int = 20_000) {
        self.capacity = capacity
    }

    /// Adds a line (assigning its `seq`) and hands it to every subscriber.
    public func append(_ line: LogLine) {
        state.withLock { s in
            var l = line
            l.seq = s.nextSeq
            s.nextSeq += 1
            s.lines.append(l)
            // Trimmed in batches (removeFirst is O(n)).
            if s.lines.count > capacity + capacity / 10 { s.lines.removeFirst(s.lines.count - capacity) }
            // Yielded under the lock so every subscriber sees the lines in seq order.
            for c in s.subscribers.values { c.yield(l) }
        }
    }

    /// Adds lines read back from disk (earlier sessions of today), before the live ones.
    public func preload(_ raws: [String]) {
        for raw in raws { append(LogLine.parse(raw)) }
    }

    /// Everything retained, oldest first.
    public func history() -> [LogLine] { state.withLock { Array($0.lines.suffix(capacity)) } }

    /// The last `n` lines.
    public func recent(_ n: Int) -> [LogLine] { state.withLock { Array($0.lines.suffix(n)) } }

    /// Lines appended from now on. With `replay`, the retained history comes first.
    public func stream(replay: Bool = false) -> AsyncStream<LogLine> {
        let (stream, continuation) = AsyncStream<LogLine>.makeStream(bufferingPolicy: .bufferingNewest(5_000))
        let id = UUID()
        state.withLock { s in
            if replay { for line in s.lines.suffix(capacity) { continuation.yield(line) } }
            s.subscribers[id] = continuation
        }
        continuation.onTermination = { [weak self] _ in
            _ = self?.state.withLock { $0.subscribers.removeValue(forKey: id) }
        }
        return stream
    }

    public var subscriberCount: Int { state.withLock { $0.subscribers.count } }
}
