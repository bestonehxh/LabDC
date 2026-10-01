import AppKit
import Observation
import LabDCCore
import SwiftUI
import UniformTypeIdentifiers

/// The Connect page's state: which device, the live values, the observations behind the
/// checklist and which computer the user says "this device" is.
@MainActor @Observable
final class ConnectModel {
    var device: DeviceKind {
        didSet { defaults.set(device.rawValue, forKey: Self.deviceKey) }
    }
    /// The account the user picked per device ("Automatic" = none).
    private(set) var pinned: [DeviceKind: String]
    var observations = ConnectObservations()
    /// The current CA (DER) for fingerprints, Save CA and the profile.
    var caDER: [UInt8]?
    /// Bumped after every reload (tests and the smoke run wait on it).
    private(set) var generation = 0
    /// Shown under the toolbar after a failed save.
    var message: String?

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var reloadTask: Task<Void, Never>?
    static let deviceKey = "connect.device"
    static let pinnedKey = "connect.pinned"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        device = defaults.string(forKey: Self.deviceKey).flatMap(DeviceKind.init(rawValue:)) ?? .windows
        let stored = defaults.dictionary(forKey: Self.pinnedKey) as? [String: String] ?? [:]
        pinned = Dictionary(uniqueKeysWithValues: stored.compactMap { k, v in DeviceKind(rawValue: k).map { ($0, v) } })
    }

    // MARK: Derived

    /// The values the guides fill in, from the server's status and settings.
    static func values(status: ServerStatus, settings: ServerSettings, caName: String?, caDER: [UInt8]?) -> ConnectValues {
        var ports: [ServeListener: Int] = [:]
        for l in status.listeners { ports[l.listener] = l.port ?? Int(l.configuredPort) }
        return ConnectValues.make(address: status.advertisedIPv4, dnsDomain: status.dnsDomain, realm: status.realm,
                                  netbios: status.netbiosDomain, dcFQDN: status.dcDNSName, baseDN: status.baseDN,
                                  ports: ports, caName: caName, caDER: caDER, allowPlainLDAP: settings.allowPlainLDAP)
    }

    func values(_ controller: ServerController) -> ConnectValues {
        Self.values(status: controller.status, settings: controller.settings, caName: controller.summary.caName, caDER: caDER)
    }

    func steps(_ values: ConnectValues) -> [GuideStep] {
        DeviceGuide.steps(for: device, values)
    }

    var checklist: [ChecklistItem] {
        DeviceChecklist.items(for: device, observations, pinned: pinnedAccount)
    }

    /// The picked computer for the current device, if it still exists.
    var pinnedAccount: String? {
        guard let p = pinned[device], observations.computers.contains(where: { $0.account == p }) else { return nil }
        return p
    }

    /// What "Automatic" resolves to (newest matching computer).
    var automaticComputer: JoinedComputer? {
        device.computers(in: observations.computers).first
    }

    /// Every computer, matching ones first, for the "This device" picker.
    var pickerComputers: [JoinedComputer] {
        let matching = device.computers(in: observations.computers)
        return matching + observations.computers.filter { c in !matching.contains(c) }
    }

    func pin(_ account: String?) {
        pinned[device] = account
        let stored = Dictionary(uniqueKeysWithValues: pinned.map { ($0.key.rawValue, $0.value) })
        defaults.set(stored, forKey: Self.pinnedKey)
    }

    func copyAllText(_ values: ConnectValues) -> String {
        DeviceGuide.plainText(for: device, values)
    }

    // MARK: Loading (event-driven, never polling)

    /// Reloads the observations and the CA.
    func reload(_ controller: ServerController) async {
        if caDER == nil || controller.isRunning {
            caDER = (try? await controller.caCertificate(der: true)).map { [UInt8]($0) } ?? caDER
        }
        observations = await ConnectObservations.load(store: controller.store, pki: controller.pki, data: controller.data,
                                                      log: controller.logs.history(),
                                                      allowPlainLDAP: controller.settings.allowPlainLDAP)
        generation += 1
    }

    /// Log lines after which a checklist may change.
    nonisolated static func isRelevant(_ line: LogLine) -> Bool {
        switch line.component {
        case "KDC", "NETLOGON", "LDAP", "SAMR", "GPO", "Store", "PKI", "SCEP", "EST", "WSTEP", "XCEP", "serve": true
        default: false
        }
    }

    /// Reloads once now, then ~0.5 s after each burst of relevant log lines, for as long as the
    /// page is shown (the view's `.task` cancels it).
    func watch(_ controller: ServerController) async {
        await reload(controller)
        for await line in controller.logs.stream() where Self.isRelevant(line) {
            guard reloadTask == nil else { continue }
            reloadTask = Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(500))
                guard !Task.isCancelled, let self else { return }
                await self.reload(controller)
                self.reloadTask = nil
            }
        }
        reloadTask?.cancel()
        reloadTask = nil
    }

    // MARK: Files

    /// The profile for Mac / iPhone (CA + LDAP account).
    func profile(_ values: ConnectValues) throws -> Data {
        guard let caDER else { throw CLIError.failure("the CA is not available yet") }
        let ldap = ConnectMobileConfig.LDAPAccount(host: values.address, useSSL: true, bindDN: values.lookupAccountDN,
                                                   searchBase: values.baseDN)
        return try ConnectMobileConfig.profile(caDER: caDER, caName: values.caName, dnsDomain: values.dnsDomain, ldap: ldap)
    }

    /// Save CA (.pem / .cer) and Save Profile: a save panel preset to the extension.
    func save(_ action: GuideAction, values: ConnectValues, controller: ServerController) {
        let ext: String
        switch action {
        case .saveCAPEM: ext = "pem"
        case .saveCACER: ext = "cer"
        case .saveMobileConfig: ext = "mobileconfig"
        default: return
        }
        let panel = NSSavePanel()
        panel.title = action == .saveMobileConfig ? "Save configuration profile" : "Save CA certificate"
        panel.nameFieldStringValue = action == .saveMobileConfig ? "LabDC \(values.dnsDomain).mobileconfig"
            : "\(values.netbios) CA.\(ext)"
        panel.allowedContentTypes = [UTType(filenameExtension: ext) ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do {
                let data: Data
                switch action {
                case .saveMobileConfig: data = try profile(values)
                default: data = try await controller.caCertificate(der: action == .saveCACER)
                }
                try data.write(to: url, options: .atomic)
                message = nil
            } catch {
                message = "Could not save \(url.lastPathComponent): \(error)"
            }
        }
    }
}
