import Foundation
import Synchronization

/// UI-2: a lightweight "the directory changed" feed. Every object write goes through
/// `DirectoryStore.nextUSN()` (create, modify, rename/move, delete), which publishes the new
/// USN here; observers (the app's Users page) re-read after a short debounce instead of polling.
///
/// Only writes made through this `DirectoryStore` instance are seen (the app's embedded server
/// shares one instance between LDAP, SAMR, NETLOGON, the KDC and the UI); a CLI process writing
/// to the same file with its own connection is not.
public final class StoreChangeFeed: Sendable {
    private struct State {
        var usn: Int64 = 0
        var observers: [UUID: AsyncStream<Int64>.Continuation] = [:]
    }

    private let state = Mutex(State())

    public init() {}

    /// The last USN published (0 before the first write through this instance).
    public var lastUSN: Int64 { state.withLock { $0.usn } }

    /// A stream of USNs, one element per write (buffering only the newest: a slow observer sees
    /// the latest USN, not every intermediate one). Ends when the consumer stops iterating.
    public func stream() -> AsyncStream<Int64> {
        let (stream, continuation) = AsyncStream.makeStream(of: Int64.self, bufferingPolicy: .bufferingNewest(1))
        let key = UUID()
        state.withLock { $0.observers[key] = continuation }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { _ = $0.observers.removeValue(forKey: key) }
        }
        return stream
    }

    func publish(_ usn: Int64) {
        let observers = state.withLock { s -> [AsyncStream<Int64>.Continuation] in
            s.usn = usn
            return Array(s.observers.values)
        }
        for o in observers { o.yield(usn) }
    }
}
