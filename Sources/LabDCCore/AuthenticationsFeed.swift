import Foundation
import Observation

/// Activity ▸ Authentications: search, day range and result (independent of the view).
public struct AuthenticationsFilter: Equatable, Sendable {
    public enum Range: String, Sendable, CaseIterable, Identifiable {
        case today, week, all
        public var id: String { rawValue }
        public var title: String {
            switch self {
            case .today: "Today"
            case .week: "7 Days"
            case .all: "All"
            }
        }
    }

    public enum ResultFilter: String, Sendable, CaseIterable, Identifiable {
        case all, passed, failed
        public var id: String { rawValue }
        public var title: String {
            switch self {
            case .all: "All Results"
            case .passed: "Passed"
            case .failed: "Failed"
            }
        }
    }

    /// Case-insensitive; every word must match the user, method, from, reason or the log line.
    public var search = ""
    public var range: Range = .today
    public var result: ResultFilter = .all

    public init(search: String = "", range: Range = .today, result: ResultFilter = .all) {
        self.search = search
        self.range = range
        self.result = result
    }

    /// The first moment inside the range (nil: no lower bound).
    public func start(now: Date, calendar: Calendar = ServeLogFile.localGregorian) -> Date? {
        switch range {
        case .today: calendar.startOfDay(for: now)
        case .week: calendar.date(byAdding: .day, value: -6, to: calendar.startOfDay(for: now))
        case .all: nil
        }
    }

    public func matches(_ e: AuthenticationEvent, since: Date?) -> Bool {
        if let since, e.date < since { return false }
        switch result {
        case .all: break
        case .passed: if e.result != .passed { return false }
        case .failed: if e.result != .failed { return false }
        }
        let words = search.split(separator: " ", omittingEmptySubsequences: true)
        guard !words.isEmpty else { return true }
        let haystack = [e.user, e.sentName, e.methodLabel, e.methodDetail, e.from, e.reason, e.raw, e.isTest ? "test" : ""]
            .joined(separator: " ")
        for w in words where haystack.range(of: w, options: [.caseInsensitive, .diacriticInsensitive]) == nil { return false }
        return true
    }

    /// `events` (newest first) that match, newest first.
    public func apply(_ events: [AuthenticationEvent], now: Date = Date(),
                      calendar: Calendar = ServeLogFile.localGregorian) -> [AuthenticationEvent] {
        let since = start(now: now, calendar: calendar)
        return events.filter { matches($0, since: since) }
    }
}

/// Builds rows from log lines in order: events append, a `TEST` line marks the request it
/// reports on (or becomes a row when that request left no line).
public struct AuthenticationsAccumulator: Sendable {
    /// Oldest first.
    public private(set) var events: [AuthenticationEvent] = []
    /// How far back a `TEST` line looks for its request.
    static let lookBack = 50

    public init() {}

    public mutating func add(_ line: LogLine) {
        guard let item = AuthenticationEvent.parse(line) else { return }
        switch item {
        case .event(let e):
            events.append(e)
        case .testMarker(let m):
            if let i = events.indices.reversed().prefix(Self.lookBack).first(where: { m.matches(events[$0]) }) {
                events[i].isTest = true
                events[i].testMilliseconds = m.milliseconds
            } else {
                events.append(m.standaloneEvent(seq: line.seq, raw: line.raw))
            }
        }
    }

    /// Rows for `lines` (oldest first in, newest first out).
    public static func events(_ lines: [LogLine]) -> [AuthenticationEvent] {
        var a = AuthenticationsAccumulator()
        for line in lines { a.add(line) }
        return a.events.reversed()
    }
}

/// The Authentications list: rows from the live log (`LogHub`, which also holds today's earlier
/// runs) plus the earlier day files, newest first, at most `capacity` rows.
@MainActor @Observable
public final class AuthenticationsFeed {
    /// Newest first.
    public private(set) var events: [AuthenticationEvent] = []
    public let capacity: Int
    /// Day files read besides today's (for 7 Days / All).
    public private(set) var earlierDaysLoaded = 0
    /// Bumped on every change (views that only need "something changed").
    public private(set) var generation = 0
    @ObservationIgnored private var nextID = 1
    @ObservationIgnored private var lastSeq = 0
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var loadingEarlier = false
    /// Bumped by `attach`: an earlier-days read that finishes after a re-attach is dropped.
    @ObservationIgnored private var attachment = 0

    public init(capacity: Int = 5_000) {
        self.capacity = capacity
    }

    /// Subscribes first, then takes the history (duplicates are dropped by `seq`). Attaching
    /// again (a profile switch) drops the old hub's subscription and rows first, so the list and
    /// the Overview follow the new profile (owner review, 30 Sep 2026).
    public func attach(_ hub: LogHub) {
        detach()
        attachment += 1
        events = []
        lastSeq = 0
        earlierDaysLoaded = 0
        loadingEarlier = false
        generation += 1
        let stream = hub.stream()
        ingest(hub.history())
        task = Task { [weak self] in
            for await line in stream { self?.receive(line) }
        }
    }

    public func detach() {
        task?.cancel()
        task = nil
    }

    /// One live line.
    public func receive(_ line: LogLine) {
        if line.seq != 0 {
            guard line.seq > lastSeq else { return }
            lastSeq = line.seq
        }
        guard let item = AuthenticationEvent.parse(line) else { return }
        switch item {
        case .event(var e):
            e.id = takeID()
            events.insert(e, at: 0)
        case .testMarker(let m):
            if let i = events.indices.prefix(AuthenticationsAccumulator.lookBack).first(where: { m.matches(events[$0]) }) {
                events[i].isTest = true
                events[i].testMilliseconds = m.milliseconds
            } else {
                var e = m.standaloneEvent(seq: line.seq, raw: line.raw)
                e.id = takeID()
                events.insert(e, at: 0)
            }
        }
        trim()
        generation += 1
    }

    /// Lines in order (the hub's history).
    public func ingest(_ lines: [LogLine]) {
        let fresh = lines.filter { $0.seq == 0 || $0.seq > lastSeq }
        if let last = fresh.last(where: { $0.seq != 0 }) { lastSeq = last.seq }
        var new = AuthenticationsAccumulator.events(fresh)
        guard !new.isEmpty else { return }
        for i in new.indices { new[i].id = takeID() }
        events.insert(contentsOf: new, at: 0)
        trim()
        generation += 1
    }

    /// Reads the day files before today (they are older than anything in the hub) in the
    /// background and appends their rows. Runs once.
    public func loadEarlierDays(_ file: ServeLogFile, now: Date = Date()) async {
        guard !loadingEarlier else { return }
        loadingEarlier = true
        let attachment = self.attachment
        let today = file.url(for: now).lastPathComponent
        let urls = file.files().filter { $0.lastPathComponent < today }
        let capacity = self.capacity
        let older: [AuthenticationEvent] = await Task.detached(priority: .utility) {
            var a = AuthenticationsAccumulator()
            for url in urls {
                guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
                let fallback = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? now
                for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
                    let line = LogLine.parse(String(raw), fallbackDate: fallback)
                    if line.level == .banner { continue }
                    a.add(line)
                }
            }
            return Array(a.events.suffix(capacity).reversed())
        }.value
        guard attachment == self.attachment else { return }
        earlierDaysLoaded = urls.count
        guard !older.isEmpty, events.count < capacity else { return }
        var rows = Array(older.prefix(capacity - events.count))
        for i in rows.indices { rows[i].id = takeID() }
        events.append(contentsOf: rows)
        generation += 1
    }

    public func event(id: Int) -> AuthenticationEvent? { events.first { $0.id == id } }

    private func takeID() -> Int {
        defer { nextID += 1 }
        return nextID
    }

    private func trim() {
        if events.count > capacity { events.removeLast(events.count - capacity) }
    }
}
