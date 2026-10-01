import Foundation

/// UI-1c: the numbers on the Overview dashboard, derived from the directory summary and the
/// authentications feed (UI-5) — no view logic, so it is testable and reusable.
public struct DashboardStats: Equatable, Sendable {
    public struct Hour: Equatable, Sendable, Identifiable {
        /// 0…23, local time.
        public var hour: Int
        public var passed: Int
        public var failed: Int
        public var id: Int { hour }
        public var total: Int { passed + failed }

        public init(hour: Int, passed: Int = 0, failed: Int = 0) {
            self.hour = hour
            self.passed = passed
            self.failed = failed
        }
    }

    public var users: Int
    public var computersJoined: Int
    /// Distinct devices (name, else address) with at least one authentication today; Test logins
    /// from this Mac do not count.
    public var devicesToday: Int
    public var certificatesValid: Int
    public var certificatesExpiringSoon: Int
    public var authenticationsPassed: Int
    public var authenticationsFailed: Int
    /// 24 buckets, midnight to midnight today.
    public var perHour: [Hour]

    public var authenticationsToday: Int { authenticationsPassed + authenticationsFailed }

    public init(users: Int = 0, computersJoined: Int = 0, devicesToday: Int = 0, certificatesValid: Int = 0,
                certificatesExpiringSoon: Int = 0, authenticationsPassed: Int = 0, authenticationsFailed: Int = 0,
                perHour: [Hour] = (0..<24).map { Hour(hour: $0) }) {
        self.users = users
        self.computersJoined = computersJoined
        self.devicesToday = devicesToday
        self.certificatesValid = certificatesValid
        self.certificatesExpiringSoon = certificatesExpiringSoon
        self.authenticationsPassed = authenticationsPassed
        self.authenticationsFailed = authenticationsFailed
        self.perHour = perHour
    }

    public static func make(summary: DirectorySummary, events: [AuthenticationEvent], now: Date = Date(),
                            calendar: Calendar = ServeLogFile.localGregorian) -> DashboardStats {
        let start = calendar.startOfDay(for: now)
        let today = events.filter { $0.date >= start && $0.date <= now.addingTimeInterval(60) }
        var hours = (0..<24).map { Hour(hour: $0) }
        var devices = Set<String>()
        var passed = 0, failed = 0
        for e in today {
            let h = min(23, max(0, calendar.component(.hour, from: e.date)))
            if e.result == .passed { hours[h].passed += 1; passed += 1 } else { hours[h].failed += 1; failed += 1 }
            if !e.isTest, let who = e.device ?? e.address, !who.isEmpty, !AuthenticationEvent.isLoopback(who) {
                devices.insert(who.lowercased())
            }
        }
        return DashboardStats(users: summary.users, computersJoined: summary.computers, devicesToday: devices.count,
                              certificatesValid: summary.certificatesValid, certificatesExpiringSoon: summary.certificatesExpiringSoon,
                              authenticationsPassed: passed, authenticationsFailed: failed, perHour: hours)
    }
}

/// The dashboard headline: one sentence about health, with where to look.
public struct HealthHeadline: Equatable, Sendable {
    public enum Tone: Sendable, Equatable { case good, busy, bad, idle }

    public var title: String
    public var detail: String
    public var tone: Tone
    /// True when the Services page has the details (a problem or a service in progress).
    public var pointsToServices: Bool

    @MainActor
    public static func make(_ status: ServerStatus) -> HealthHeadline {
        let problems = status.problems
        switch status.phase {
        case .running where problems.isEmpty:
            let restarting = status.services.filter { $0.state == .restarting }.map(\.service.title)
            if !restarting.isEmpty {
                return .init(title: "Restarting \(restarting.joined(separator: ", "))…", detail: "The other services keep running.",
                             tone: .busy, pointsToServices: true)
            }
            return .init(title: "Everything is running", detail: status.statusSubtitle, tone: .good, pointsToServices: false)
        case .running, .problem:
            let first = problems.first ?? status.lastError ?? "A service is not running."
            let n = max(problems.count, 1)
            return .init(title: "\(n) problem\(n == 1 ? "" : "s"): \(first)", detail: "Open Services to see it and restart.",
                         tone: .bad, pointsToServices: true)
        case .starting:
            return .init(title: "Starting…", detail: "Every service starts at once.", tone: .busy, pointsToServices: false)
        case .stopping:
            return .init(title: "Stopping…", detail: "Every service stops and releases its ports.", tone: .busy, pointsToServices: false)
        case .restarting:
            return .init(title: "Restarting…", detail: "Every service stops and starts again on the same ports.", tone: .busy, pointsToServices: false)
        case .stopped:
            return .init(title: "Stopped", detail: "Restart All Services starts everything again.", tone: .idle, pointsToServices: true)
        case .notSetUp:
            return .init(title: "Not set up yet", detail: "The setup wizard creates the domain.", tone: .idle, pointsToServices: false)
        }
    }
}
