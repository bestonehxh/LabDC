import Foundation

/// Phase 5 device profiling — the contract between the DHCP side (which writes profiles into
/// `device_profiles`) and the RADIUS side (which reads them as policy facts and sends CoA when
/// one changes). docs/specs/phase5-dhcp.md §8 "Profiling → RADIUS". Kept small on purpose: both
/// sides code against this file.

/// What kind of device a MAC belongs to.
public enum DeviceCategory: String, Codable, Sendable, CaseIterable {
    case windows, macOS, iOS, android, linux, chromeOS, printer, ipPhone, accessPoint, `switch`, cameraIoT, unknown

    public var title: String {
        switch self {
        case .windows: "Windows"
        case .macOS: "macOS"
        case .iOS: "iOS/iPadOS"
        case .android: "Android"
        case .linux: "Linux"
        case .chromeOS: "ChromeOS"
        case .printer: "Printer"
        case .ipPhone: "IP phone"
        case .accessPoint: "Access point"
        case .switch: "Switch"
        case .cameraIoT: "Camera/IoT"
        case .unknown: "Unknown"
        }
    }
}

/// One device, keyed by its MAC (lowercase `aa:bb:cc:dd:ee:ff`).
public struct DeviceProfile: Sendable, Equatable {
    public enum Source: String, Codable, Sendable, CaseIterable { case dhcp4, dhcp6, manual }

    public var mac: String
    public var firstSeen: Date
    public var lastSeen: Date
    public var source: Source
    public var category: DeviceCategory
    public var os: String?
    public var vendorClass: String?
    public var hostname: String?
    /// 0…100.
    public var confidence: Int
    /// Set by hand: DHCP fingerprints no longer change category/OS.
    public var manualOverride: Bool

    public init(mac: String, firstSeen: Date, lastSeen: Date, source: Source, category: DeviceCategory, os: String? = nil,
                vendorClass: String? = nil, hostname: String? = nil, confidence: Int = 0, manualOverride: Bool = false) {
        self.mac = Self.normalizeMAC(mac) ?? mac.lowercased()
        self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.source = source; self.category = category
        self.os = os; self.vendorClass = vendorClass; self.hostname = hostname
        self.confidence = confidence; self.manualOverride = manualOverride
    }

    /// Lowercase `aa:bb:cc:dd:ee:ff` from any common spelling (`AABBCCDDEEFF`, `aa-bb-…`,
    /// `aabb.ccdd.eeff`); nil when `text` is not a 48-bit MAC.
    public static func normalizeMAC(_ text: String) -> String? {
        let hex = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard hex.allSatisfy({ $0.isHexDigit || ":-.".contains($0) }) else { return nil }
        let digits = Array(hex.filter(\.isHexDigit))
        guard digits.count == 12 else { return nil }
        return stride(from: 0, to: 12, by: 2).map { String(digits[$0...$0 + 1]) }.joined(separator: ":")
    }
}

/// Where the RADIUS side reads profiles from. The store's `device_profiles` table conforms
/// (DHCP side); `NoDeviceProfiles` when profiling is not there, `InMemoryDeviceProfiles` in tests.
public protocol DeviceProfileSource: Sendable {
    /// The profile of `mac` (any spelling); nil = never seen.
    func deviceProfile(mac: String) async throws -> DeviceProfile?
    /// MACs (canonical) whose profile was created or whose category/OS changed. Each access is a
    /// new subscription.
    var changes: AsyncStream<String> { get }
}

/// No profiling: every device is `unknown`, nothing ever changes.
public struct NoDeviceProfiles: DeviceProfileSource {
    public init() {}
    public func deviceProfile(mac: String) async throws -> DeviceProfile? { nil }
    public var changes: AsyncStream<String> { AsyncStream { $0.finish() } }
}

/// Profiles in memory with a change feed (tests, previews).
public final class InMemoryDeviceProfiles: DeviceProfileSource, @unchecked Sendable {
    private let lock = NSLock()
    private var profiles: [String: DeviceProfile] = [:]
    private var subscribers: [UUID: AsyncStream<String>.Continuation] = [:]

    public init(_ initial: [DeviceProfile] = []) {
        for p in initial { profiles[p.mac] = p }
    }

    public func deviceProfile(mac: String) async throws -> DeviceProfile? {
        guard let key = DeviceProfile.normalizeMAC(mac) else { return nil }
        return lock.withLock { profiles[key] }
    }

    /// Stores `profile`; true (and announced on `changes`) when it is new or its category/OS changed.
    @discardableResult
    public func upsert(_ profile: DeviceProfile) -> Bool {
        let (changed, targets): (Bool, [AsyncStream<String>.Continuation]) = lock.withLock {
            let old = profiles[profile.mac]
            profiles[profile.mac] = profile
            let changed = old == nil || old?.category != profile.category || old?.os != profile.os
            return (changed, Array(subscribers.values))
        }
        if changed { for c in targets { c.yield(profile.mac) } }
        return changed
    }

    public var changes: AsyncStream<String> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<String>.makeStream(bufferingPolicy: .bufferingNewest(1024))
        lock.withLock { subscribers[id] = continuation }
        continuation.onTermination = { [weak self] _ in self?.lock.withLock { _ = self?.subscribers.removeValue(forKey: id) } }
        return stream
    }
}
