import LabDCCore
import SwiftUI

/// A certificate file holding several certificates (server certificate + its CA chain): which
/// of them to add, like ticking them in GPMC's Trusted Root import (owner, 1 Oct 2026). The
/// self-signed root is ticked first (`Dot1XTrustCertificate.defaultPick`).
struct CertificatePickSheet: View {
    @Environment(\.dismiss) private var dismiss
    let fileName: String
    let certificates: [Dot1XTrustCertificate]
    let add: ([Dot1XTrustCertificate]) -> Void
    @State private var chosen: Set<String>

    init(fileName: String, certificates: [Dot1XTrustCertificate], add: @escaping ([Dot1XTrustCertificate]) -> Void) {
        self.fileName = fileName
        self.certificates = certificates
        self.add = add
        _chosen = State(initialValue: Set(Dot1XTrustCertificate.defaultPick(certificates)))
    }

    var body: some View {
        QuietSheet(title: "Which certificates of “\(fileName)”?",
                   subtitle: "Windows trusts each one you add as it is, as GPMC does — a root CA, or the server's own certificate.",
                   width: 560) {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(certificates) { c in
                    Toggle(isOn: Binding(get: { chosen.contains(c.thumbprint) },
                                         set: { on in if on { chosen.insert(c.thumbprint) } else { chosen.remove(c.thumbprint) } })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(c.name) (\(c.role))").font(Theme.body).foregroundStyle(Theme.ink)
                            Text("Subject \(c.subject)").font(Theme.caption).foregroundStyle(Theme.muted)
                            Text("Issuer \(c.issuer)").font(Theme.caption).foregroundStyle(Theme.muted)
                            Text("SHA-1 " + GroupPolicyView.grouped(c.thumbprint)).font(Theme.caption).foregroundStyle(Theme.faint)
                                .textSelection(.enabled)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .toggleStyle(.checkbox)
                }
            }
        } actions: {
            SheetButtons(chosen.count > 1 ? "Add \(chosen.count) certificates" : "Add", disabled: chosen.isEmpty) {
                add(certificates.filter { chosen.contains($0.thumbprint) })
                dismiss()
            }
        }
    }
}

/// A certificate file whose certificates wait for the pick sheet.
struct CertificatePickRequest: Identifiable {
    let id = UUID()
    let fileName: String
    let certificates: [Dot1XTrustCertificate]
    var serverNames: [String] = []
    /// The file's bytes (Certificates ▸ Trusted Roots adds from them after the pick).
    var bytes: [UInt8] = []
}
