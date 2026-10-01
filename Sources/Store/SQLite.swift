import SQLite3

/// A value bound to or read from SQLite.
enum SQLValue: Sendable, Hashable {
    case null
    case int(Int64)
    case text(String)
    case blob([UInt8])

    var int: Int64? {
        switch self {
        case .int(let v): v
        case .text(let s): Int64(s)
        default: nil
        }
    }

    var text: String? {
        switch self {
        case .text(let s): s
        case .int(let v): String(v)
        case .blob(let b): String(decoding: b, as: UTF8.self)
        case .null: nil
        }
    }

    var blob: [UInt8]? {
        switch self {
        case .blob(let b): b
        case .text(let s): Array(s.utf8)
        default: nil
        }
    }

    static func optional(_ s: String?) -> SQLValue { s.map { .text($0) } ?? .null }
    static func optional(_ b: [UInt8]?) -> SQLValue { b.map { .blob($0) } ?? .null }
}

/// A single SQLite connection with a prepared-statement cache. Not thread-safe: it is owned by
/// the `DirectoryStore` actor and never escapes it.
final class SQLiteConnection {
    private let handle: OpaquePointer
    private var cache: [String: OpaquePointer] = [:]

    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    init(path: String) throws {
        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        guard rc == SQLITE_OK, let db else {
            let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open"
            if let db { sqlite3_close_v2(db) }
            throw StoreError.sqlite(code: rc, message: "\(path): \(message)")
        }
        handle = db
        sqlite3_busy_timeout(db, 5000)
    }

    deinit {
        for stmt in cache.values { sqlite3_finalize(stmt) }
        sqlite3_close_v2(handle)
    }

    private func error(_ rc: Int32, _ context: String) -> StoreError {
        let message = String(cString: sqlite3_errmsg(handle))
        if rc & 0xFF == SQLITE_CONSTRAINT {
            return .constraintViolation("\(message) (\(context))")
        }
        return .sqlite(code: rc, message: "\(message) (\(context))")
    }

    /// Runs one or more statements without parameters or results.
    func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? "exec failed"
            sqlite3_free(err)
            throw StoreError.sqlite(code: rc, message: message)
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        if let stmt = cache[sql] {
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
            return stmt
        }
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v3(handle, sql, -1, UInt32(SQLITE_PREPARE_PERSISTENT), &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw error(rc, "prepare: \(sql)") }
        cache[sql] = stmt
        return stmt
    }

    private func bind(_ stmt: OpaquePointer, _ params: [SQLValue]) throws {
        for (i, p) in params.enumerated() {
            let idx = Int32(i + 1)
            let rc: Int32
            switch p {
            case .null: rc = sqlite3_bind_null(stmt, idx)
            case .int(let v): rc = sqlite3_bind_int64(stmt, idx, v)
            case .text(let s): rc = sqlite3_bind_text(stmt, idx, s, -1, Self.transient)
            case .blob(let b):
                if b.isEmpty {
                    rc = sqlite3_bind_zeroblob(stmt, idx, 0)
                } else {
                    rc = b.withUnsafeBytes { raw in
                        sqlite3_bind_blob(stmt, idx, raw.baseAddress, Int32(b.count), Self.transient)
                    }
                }
            }
            guard rc == SQLITE_OK else { throw error(rc, "bind") }
        }
    }

    private func column(_ stmt: OpaquePointer, _ i: Int32) -> SQLValue {
        switch sqlite3_column_type(stmt, i) {
        case SQLITE_INTEGER: return .int(sqlite3_column_int64(stmt, i))
        case SQLITE_FLOAT: return .int(Int64(sqlite3_column_double(stmt, i)))
        case SQLITE_TEXT:
            guard let p = sqlite3_column_text(stmt, i) else { return .text("") }
            return .text(String(cString: p))
        case SQLITE_BLOB:
            let n = Int(sqlite3_column_bytes(stmt, i))
            guard n > 0, let p = sqlite3_column_blob(stmt, i) else { return .blob([]) }
            return .blob(Array(UnsafeRawBufferPointer(start: p, count: n)))
        default: return .null
        }
    }

    /// Runs a query and returns every row.
    @discardableResult
    func query(_ sql: String, _ params: [SQLValue] = []) throws -> [[SQLValue]] {
        let stmt = try prepare(sql)
        defer { sqlite3_reset(stmt) }
        try bind(stmt, params)
        var rows: [[SQLValue]] = []
        let n = sqlite3_column_count(stmt)
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw error(rc, sql) }
            rows.append((0..<n).map { column(stmt, $0) })
        }
        return rows
    }

    /// Runs a statement that returns no rows.
    func run(_ sql: String, _ params: [SQLValue] = []) throws {
        try query(sql, params)
    }

    /// First column of the first row, if any.
    func scalar(_ sql: String, _ params: [SQLValue] = []) throws -> SQLValue? {
        try query(sql, params).first?.first
    }

    var lastInsertRowID: Int64 { sqlite3_last_insert_rowid(handle) }
    var changes: Int { Int(sqlite3_changes(handle)) }
}
