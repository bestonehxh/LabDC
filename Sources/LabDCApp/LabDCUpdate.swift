import AppKit

// LabDC's half of the in-app updater: the ONLY file that ties the generic updater in
// Sources/LabDCApp/Update/ (copied unchanged from SheepTerm 5.0, 9 Oct 2026) to this app.
// Releases come from the public repository's latest GitHub Release: `LabDC-<mv>-<b>.zip` plus
// its Ed25519 `.zip.sig`, both made by the Sheep-family release.sh (/ship) from `.ship.conf`.

extension UpdateConfig {
    /// The Ed25519 key whose private half is in the release Mac's login Keychain (service
    /// `signingKeychainService`, account `ed25519`, made once by SheepTerm's Tools/update-keygen.sh
    /// on 9 Oct 2026). `.ship.conf` carries the same value as UPDATE_SIGN_PUBLIC_KEY,
    /// and UpdaterTests fails when the two differ. Not SheepTerm's key: one key per app.
    static let labDC = UpdateConfig(
        appName: "LabDC",
        repository: "bestonehxh/LabDC",
        tagScheme: .build,
        publicKeyBase64: "0Tx4pmnSbusIQ+2gDTD51N+YInq9jBlOigADLuraHNk=",
        signingKeychainService: "Bestchaan.LabDC.update-signing"
    )
}

@MainActor
enum AppUpdater {
    /// Install & Relaunch is the only question: Quit then stops the services cleanly
    /// (AppDelegate.applicationShouldTerminate) and the new copy starts them again. The alerts
    /// are centred (Update/UpdateAlertPanel.swift): a plain NSAlert left-aligns Details.
    static let shared = Updater(config: .labDC, hooks: UpdateHooks(presenter: CenteredUpdatePresenter()))

    /// Automatic checks are always on (the user, 9 Oct 2026: no option for it), so a stored
    /// "off" from an earlier build is cleared before the updater reads it.
    static func start() {
        UserDefaults.standard.removeObject(forKey: UpdateCore.autoCheckKey)
        shared.start()
    }
}
