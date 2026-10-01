import Foundation

/// A 20-byte DCE context handle (MS-RPCE §2.2.4.20): a 4-byte attributes word followed by a
/// 16-byte UUID. A null handle is all zeroes. Servers hand these out from `RPCHandleTable`;
/// clients echo them back and the server resolves them to typed state.
public struct ContextHandle: Sendable, Hashable {
    public var attributes: UInt32
    public var uuid: [UInt8]   // 16 bytes

    public init(attributes: UInt32 = 0, uuid: [UInt8]) {
        precondition(uuid.count == 16)
        self.attributes = attributes
        self.uuid = uuid
    }

    /// The all-zero null handle.
    public static let null = ContextHandle(attributes: 0, uuid: [UInt8](repeating: 0, count: 16))
    public var isNull: Bool { attributes == 0 && uuid.allSatisfy { $0 == 0 } }

    /// The 20-byte wire form.
    public var wire: [UInt8] {
        var out = [UInt8]()
        out.append(contentsOf: (0..<4).map { UInt8(truncatingIfNeeded: attributes >> (8 * $0)) })
        out.append(contentsOf: uuid)
        return out
    }

    public init?(wire: [UInt8]) {
        guard wire.count == 20 else { return nil }
        self.attributes = UInt32(wire[0]) | (UInt32(wire[1]) << 8) | (UInt32(wire[2]) << 16) | (UInt32(wire[3]) << 24)
        self.uuid = Array(wire[4..<20])
    }
}

extension NDRWriter {
    /// Writes a 20-byte context handle (natural alignment 4).
    public func contextHandle(_ h: ContextHandle) {
        align(4)
        raw(h.wire)
    }
}

extension NDRReader {
    /// Reads a 20-byte context handle.
    public func contextHandle() throws -> ContextHandle {
        align(4)
        guard let h = ContextHandle(wire: try take(20)) else {
            throw NDRError(offset: offset, reason: "short context handle")
        }
        return h
    }
}

/// Per-connection table of live context handles. Each entry carries a caller-chosen `type` tag
/// and an opaque `state` object; the table generates fresh UUIDs and resolves handles back to
/// their state, rejecting handles it never issued or that were closed (the caller maps that to
/// `nca_s_fault_context_mismatch`).
public final class RPCHandleTable: @unchecked Sendable {
    private struct Entry { let type: String; let state: any Sendable }
    private var entries: [ContextHandleKey: Entry] = [:]
    private var counter: UInt64 = 0
    private let lock = NSLock()

    private struct ContextHandleKey: Hashable { let uuid: [UInt8] }

    public init() {}

    /// Allocates a handle of `type` bound to `state`, returning the wire handle.
    public func allocate(type: String, state: any Sendable) -> ContextHandle {
        lock.lock(); defer { lock.unlock() }
        counter += 1
        var uuid = [UInt8](repeating: 0, count: 16)
        // Deterministic-per-connection UUID: counter in the low 8 bytes, a fixed tag in the high.
        for i in 0..<8 { uuid[i] = UInt8(truncatingIfNeeded: counter >> (8 * i)) }
        uuid[8] = 0x53; uuid[9] = 0x68   // "Sh"
        let handle = ContextHandle(attributes: 0, uuid: uuid)
        entries[ContextHandleKey(uuid: uuid)] = Entry(type: type, state: state)
        return handle
    }

    /// Resolves a handle to its state, checking the type tag. Returns nil if unknown/closed or
    /// the type mismatches.
    public func resolve<T: Sendable>(_ handle: ContextHandle, type: String, as: T.Type) -> T? {
        lock.lock(); defer { lock.unlock() }
        guard let e = entries[ContextHandleKey(uuid: handle.uuid)], e.type == type else { return nil }
        return e.state as? T
    }

    /// True if the handle is currently live (any type).
    public func contains(_ handle: ContextHandle) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries[ContextHandleKey(uuid: handle.uuid)] != nil
    }

    /// Closes a handle, returning true if it existed. The caller returns a nulled handle to the
    /// client on a successful close (MS-RPCE `[out]` context-handle convention).
    @discardableResult
    public func close(_ handle: ContextHandle) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries.removeValue(forKey: ContextHandleKey(uuid: handle.uuid)) != nil
    }

    /// The number of live handles (for tests).
    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count
    }
}
