import AppKit
import CertConvert
import PKIKit
import LabDCCore
import SwiftUI

/// Window ▸ Certificate Converter (⇧⌘C) and files dropped on the Dock icon: a compact window
/// with the converter alone. AppKit-managed, so it opens from the menu, from
/// `application(_:open:)` and before the domain exists (no store needed).
@MainActor
final class ConverterWindowController: NSObject, NSWindowDelegate {
    static let shared = ConverterWindowController()

    let model = ConverterModel()
    private(set) var window: NSWindow?

    override init() {
        super.init()
        model.caProvider = { await Self.domainCAs() }
    }

    /// Shows the window, adding `files` to it first.
    func show(files: [URL] = []) {
        if !files.isEmpty { model.add(urls: files) }
        let w = window ?? makeWindow()
        w.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }

    private func makeWindow() -> NSWindow {
        let hosting = NSHostingController(rootView: ConverterWindowView(model: model))
        let w = NSWindow(contentViewController: hosting)
        w.title = "Certificate Converter"
        w.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        w.setContentSize(NSSize(width: 640, height: 720))
        w.isReleasedWhenClosed = false
        w.identifier = NSUserInterfaceItemIdentifier("certificate-converter")
        w.setFrameAutosaveName("CertificateConverter")
        w.delegate = self
        w.center()
        window = w
        return w
    }

    /// The domain's CAs for "Verify Against CA": the running server's, else the data folder's
    /// `pki/` when it exists, else none (then the window offers a CA file).
    static func domainCAs() async -> [CertificateItem] {
        guard let app = AppDelegate.model else { return [] }
        if let editor = app.certificates.editor {
            return editor.authorities.compactMap { try? CertificateItem(der: $0.der) }
        }
        let pkiURL = app.controller.data.pkiURL
        guard FileManager.default.fileExists(atPath: pkiURL.appendingPathComponent(LabPKI.caCertificateFileName).path),
              let pki = try? await LabPKI.open(directory: pkiURL), let all = try? await pki.authorities() else { return [] }
        return all.compactMap { ca in (try? ca.der()).flatMap { try? CertificateItem(der: $0) } }
    }
}

/// The standalone window's content.
struct ConverterWindowView: View {
    let model: ConverterModel

    var body: some View {
        ConverterView(model: model, compact: true)
            .frame(minWidth: 520, minHeight: 480)
            .background(Theme.background)
    }
}
