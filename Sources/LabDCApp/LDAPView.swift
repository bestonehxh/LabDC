import AuthKit
import LabDCCore
import SwiftUI

/// The LDAP page (owner, 22 Oct 2026): only the directory's LDAP configuration, moved out of
/// Settings ▸ System — which connections the DC accepts (plain LDAP, StartTLS and LDAPS, each on
/// or off), the bind security policies, and the LDAP ports. Each change restarts the services.
struct LDAPView: View {
    @Environment(AppModel.self) private var model
    @State private var error: String?

    var body: some View {
        let settings = model.controller.settings
        let options = model.controller.serveOptions()
        let directory = model.controller.status.services.first { $0.service == .directory }
        QuietPage(title: "LDAP", subtitle: "How devices and apps reach the directory. Each change restarts the directory; everything else keeps running.") {
            VStack(alignment: .leading, spacing: 36) {
                QuietSection(title: "Connections") {
                    if let directory { ServiceStateBadge(row: directory) }
                } content: {
                    QuietRow(first: true) {
                        Toggle(isOn: binding(\.allowPlainLDAP)) {
                            SettingsLabel(title: "LDAP — port \(port(.ldap, options))",
                                          detail: settings.allowPlainLDAP
                                              ? "Devices may send a password over port \(port(.ldap, options)) unencrypted."
                                              : "Port \(port(.ldap, options)) refuses passwords unless the connection is encrypted with StartTLS.")
                        }
                        .toggleStyle(.quiet)
                        .accessibilityLabel("Allow plain LDAP")
                        .accessibilityHint("Simple binds with a password on the LDAP port without encryption")
                    }
                    QuietRow {
                        Toggle(isOn: binding(\.startTLSEnabled)) {
                            SettingsLabel(title: "StartTLS — port \(port(.ldap, options))",
                                          detail: settings.startTLSEnabled
                                              ? "Devices may encrypt a connection on port \(port(.ldap, options)) (\"secure\" on FortiGate, \"StartTLS\" on ClearPass)."
                                              : "A StartTLS request is refused; port \(port(.ldap, options)) stays unencrypted.")
                        }
                        .toggleStyle(.quiet)
                        .accessibilityLabel("Allow StartTLS")
                    }
                    QuietRow {
                        Toggle(isOn: binding(\.ldapsEnabled)) {
                            SettingsLabel(title: "LDAPS (LDAP over SSL) — port \(port(.ldaps, options))",
                                          detail: settings.ldapsEnabled
                                              ? "Encrypted from the first byte; Global Catalog over TLS runs on port \(port(.gcs, options)) too."
                                              : "Ports \(port(.ldaps, options)) and \(port(.gcs, options)) are closed.")
                        }
                        .toggleStyle(.quiet)
                        .accessibilityLabel("Allow LDAPS")
                    }
                    if !settings.allowPlainLDAP, !settings.startTLSEnabled, !settings.ldapsEnabled {
                        QuietNote("With all three off, no device can sign in with a password over LDAP; only Kerberos and NTLM binds that sign remain.",
                                  attention: true)
                            .padding(.top, 10)
                    }
                }

                QuietSection("Bind security") {
                    QuietRow(first: true) {
                        Toggle(isOn: binding(\.requireLDAPSigning)) {
                            SettingsLabel(title: "Require LDAP signing",
                                          detail: settings.requireLDAPSigning
                                              ? "Kerberos and NTLM binds on port \(port(.ldap, options)) must sign or encrypt, as Windows, Samba and macOS do. Like a Windows DC's \"Require signing\"."
                                              : "Kerberos and NTLM binds on port \(port(.ldap, options)) may skip signing, so the session can be tampered with or relayed.")
                        }
                        .toggleStyle(.quiet)
                        .accessibilityLabel("Require LDAP signing")
                    }
                    SettingsRow(title: "LDAP channel binding",
                                detail: "Ties Kerberos and NTLM binds on LDAPS and StartTLS to the TLS connection, so a relayed login fails. \"When supported\" checks every client that sends a binding.") {
                        Picker("LDAP channel binding", selection: binding(\.ldapChannelBinding)) {
                            ForEach(ChannelBindingPolicy.allCases, id: \.self) { Text($0.settingsLabel).tag($0) }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .fixedSize()
                        .accessibilityLabel("LDAP channel binding")
                    }
                }

                let shown = ServeService.directory.listeners.filter { $0.isEnabled(in: options) }
                QuietSection("Ports") {
                    ForEach(Array(shown.enumerated()), id: \.element.id) { index, listener in
                        PortRow(listener: listener, first: index == 0)
                    }
                }

                if let error {
                    QuietNote(error, attention: true)
                }
            }
        }
    }

    /// The port in use (the bound one while running), else the configured one.
    private func port(_ listener: ServeListener, _ options: ServeOptions) -> String {
        if let bound = model.controller.status.listeners.first(where: { $0.listener == listener })?.port { return String(bound) }
        let p = options.ports[listener]
        return p == 0 ? "auto" : String(p)
    }

    private func binding<T: Equatable>(_ key: WritableKeyPath<ServerSettings, T>) -> Binding<T> {
        Binding(get: { model.controller.settings[keyPath: key] }, set: { value in
            Task {
                do {
                    try await model.controller.updateSettings { $0[keyPath: key] = value }
                    error = nil
                } catch {
                    self.error = "Not saved: \(error)"
                }
            }
        })
    }
}
