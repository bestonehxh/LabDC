import LabDCCore
import SwiftUI

/// Settings ▸ General ▸ Domain ▸ Rename domain (owner request, 30 Sep 2026): the new DNS name,
/// a confirmation that says the services restart and devices must rejoin, progress while the
/// store, DNS and SYSVOL are rewritten, and the outcome as a quiet note.
struct DomainRenameSection: View {
    @Environment(AppModel.self) private var model
    /// The current DNS domain (`lab.sheep`).
    let currentDomain: String?
    @Binding var newDomainName: String
    @Binding var showConfirm: Bool
    @Binding var message: String?
    @State private var busy = false
    @State private var failed = false

    private var derivation: Result<DomainSetup, DomainSetup.Problem> { DomainSetup.derive(newDomainName) }
    private var proposed: DomainSetup? { try? derivation.get() }
    private var isSame: Bool { proposed?.dnsDomain == currentDomain?.lowercased() }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            QuietRow {
                HStack(alignment: .center, spacing: 14) {
                    Text("Rename domain")
                        .font(Theme.body)
                        .foregroundStyle(Theme.ink)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    TextField("New domain name", text: $newDomainName, prompt: Text("corp.example"))
                        .textFieldStyle(.quiet)
                        .frame(width: 200)
                        .autocorrectionDisabled()
                        .disabled(busy)
                        .accessibilityLabel("New DNS domain name")
                        .onSubmit { if proposed != nil, !isSame { showConfirm = true } }
                    if busy {
                        ProgressView().controlSize(.small)
                    }
                    Button(busy ? "Renaming…" : "Rename…") { showConfirm = true }
                        .buttonStyle(.quietDestructive)
                        .disabled(busy || proposed == nil || isSame || !model.controller.isRunning)
                }
            }
            if !newDomainName.trimmingCharacters(in: .whitespaces).isEmpty, case .failure(let problem) = derivation {
                QuietNote(problem.description, attention: true).padding(.top, 4)
            } else if let proposed, !isSame {
                QuietNote("Realm \(proposed.realm), base DN \(proposed.baseDN), domain controller \(proposed.dcFQDN). The NetBIOS name stays \(model.controller.status.netbiosDomain ?? "as it is").")
                    .padding(.top, 4)
            }
            if busy {
                QuietNote("Renaming… the services are stopped and start again under the new name.").padding(.top, 4)
            }
            if let message {
                QuietNote(message, attention: failed)
                    .textSelection(.enabled)
                    .padding(.top, 4)
            }
        }
        .alert("Rename \(currentDomain ?? "the domain") to \(proposed?.dnsDomain ?? newDomainName)?", isPresented: $showConfirm) {
            Button("Rename and restart", role: .destructive) { rename() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All services stop and restart under the new name. Accounts, groups, Group Policy and DNS records move with it, and passwords keep working. Every joined device must leave the domain and join \(proposed?.dnsDomain ?? "the new name") again.")
        }
    }

    private func rename() {
        guard let target = proposed?.dnsDomain else { return }
        busy = true
        message = nil
        Task {
            do {
                let result = try await model.controller.renameDomain(to: target)
                message = result.summary
                failed = false
                newDomainName = ""
            } catch {
                message = "Not renamed: \(error)"
                failed = true
            }
            busy = false
        }
    }
}
