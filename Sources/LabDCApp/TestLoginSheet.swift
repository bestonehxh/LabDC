import Observation
import LabDCCore
import SwiftUI

/// Activity ▸ Test login…: preset, user, password, one Advanced disclosure; the result is one
/// sentence plus an expandable detail block.
@MainActor @Observable
final class TestLoginModel {
    var preset: LoginTestRequest.Preset = .kerberos
    var user = ""
    var password = ""
    var realmForm: LoginTestRequest.RealmForm = .realm
    var workstation = "LABDC-TEST"
    var ntlmNameForm: LoginTestRequest.NameForm = .downLevel
    var ldapNameForm: LoginTestRequest.NameForm = .upn
    var msCHAPv2Style = false
    var allowComputerAccounts = true
    var ldapConnection: LoginTestRequest.LDAPConnection = .automatic
    var showAdvanced = false
    var showDetails = false
    private(set) var running = false
    var result: LoginTestResult?
    /// The preset the shown result belongs to.
    private(set) var resultPreset: LoginTestRequest.Preset?
    @ObservationIgnored private var task: Task<Void, Never>?

    init() {}

    var canRun: Bool {
        !running && !user.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    var request: LoginTestRequest {
        var r = LoginTestRequest(preset: preset, user: user.trimmingCharacters(in: .whitespaces), password: password)
        r.realmForm = realmForm
        r.workstation = workstation
        r.ntlmNameForm = ntlmNameForm
        r.ldapNameForm = ldapNameForm
        r.msCHAPv2Style = msCHAPv2Style
        r.allowComputerAccounts = allowComputerAccounts
        r.ldapConnection = ldapConnection
        return r
    }

    /// Runs the test against the running server (a result either way).
    func run(_ controller: ServerController) {
        guard canRun else { return }
        let request = self.request
        running = true
        result = nil
        showDetails = false
        task = Task { [weak self] in
            let outcome: LoginTestResult
            if let env = await controller.loginTestEnvironment() {
                outcome = await LoginTester(environment: env).run(request)
            } else {
                outcome = LoginTestResult(passed: false, milliseconds: 0, method: request.preset.shortTitle,
                                          reason: "The server is not running", failure: .other)
            }
            self?.finish(outcome, preset: request.preset)
        }
    }

    /// Waits for the running test (tests, smoke).
    func wait() async {
        await task?.value
    }

    func cancel() {
        task?.cancel()
    }

    func finish(_ outcome: LoginTestResult, preset: LoginTestRequest.Preset) {
        result = outcome
        resultPreset = preset
        running = false
        task = nil
    }

    /// Clears the result when the inputs change (a stale result would describe another request).
    func inputsChanged() {
        if !running { result = nil }
    }

    // MARK: Labels

    func realmLabel(_ form: LoginTestRequest.RealmForm, status: ServerStatus) -> String {
        switch form {
        case .realm: "\(status.realm ?? "LAB.SHEEP") (realm)"
        case .netbios: "\(status.netbiosDomain ?? "LAB") (NetBIOS alias)"
        }
    }

    func nameFormLabel(_ form: LoginTestRequest.NameForm, status: ServerStatus) -> String {
        let account = user.isEmpty ? "alice" : LoginTester.accountName(user)
        let nb = status.netbiosDomain ?? "LAB"
        let dns = status.dnsDomain ?? "lab.sheep"
        switch (preset, form) {
        case (.ntlm, .downLevel): return "\(nb) + \(account) (as NACs send it)"
        case (.ntlm, .accountOnly): return "\(account), no domain"
        case (_, .upn): return "\(account)@\(dns)"
        case (_, .downLevel): return "\(nb)\\\(account)"
        case (_, .accountOnly): return account
        case (_, .dn): return "Distinguished name (CN=…)"
        case (_, .asTyped): return "As typed"
        }
    }

    var nameForms: [LoginTestRequest.NameForm] {
        preset == .ldap ? [.upn, .downLevel, .dn, .accountOnly, .asTyped] : [.downLevel, .upn, .accountOnly, .asTyped]
    }

    static func connectionLabel(_ c: LoginTestRequest.LDAPConnection) -> String {
        switch c {
        case .automatic: "Automatic (LDAPS unless plain LDAP is allowed)"
        case .plain: "LDAP (plain)"
        case .tls: "LDAPS (TLS)"
        }
    }

    static func presetDescription(_ p: LoginTestRequest.Preset) -> String {
        switch p {
        case .kerberos: "An AS exchange with the embedded KDC, as kinit or a Windows sign-in does."
        case .ntlm: "A NETLOGON network logon with a challenge/response, as ClearPass or iMaster forwards it."
        case .ldap: "A simple bind to the directory, as a NAC's LDAP source or an app does."
        }
    }
}

struct TestLoginSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        TestLoginContent(test: model.authentications.testLogin, close: { dismiss() })
            .frame(width: 580)
    }
}

/// The sheet's content (also rendered on its own by `--smoke`), in the Quiet look: the kind of
/// sign-in as text tabs, underlined fields, "Advanced" as a word, the result as one sentence.
struct TestLoginContent: View {
    @Environment(AppModel.self) private var model
    @Bindable var test: TestLoginModel
    var close: () -> Void

    var body: some View {
        let status = model.controller.status
        VStack(alignment: .leading, spacing: 0) {
            SheetScroll { VStack(alignment: .leading, spacing: 0) {
                Text("Test a sign-in")
                    .font(Theme.emphasis)
                    .foregroundStyle(Theme.ink)
                    .accessibilityAddTraits(.isHeader)
                QuietTabs(items: LoginTestRequest.Preset.allCases.map { ($0, $0.title) }, selection: $test.preset)
                    .padding(.top, 16)
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Kind of sign-in to test")
                Text(TestLoginModel.presetDescription(test.preset))
                    .font(Theme.detail)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 10)

                VStack(alignment: .leading, spacing: 14) {
                    labeled("Username") {
                        QuietTextField("Username", text: $test.user, prompt: "alice")
                            .textFieldStyle(.quiet)
                            .textContentType(.username)
                            .accessibilityLabel("Username")
                    }
                    labeled("Password") {
                        QuietTextField("Password", text: $test.password, prompt: "Password", secure: true)
                            .textFieldStyle(.quiet)
                            .accessibilityLabel("Password")
                            .onSubmit { test.run(model.controller) }
                    }
                }
                .padding(.top, 22)

                Button(test.showAdvanced ? "Hide advanced" : "Advanced") { test.showAdvanced.toggle() }
                    .buttonStyle(.quietLink)
                    .padding(.top, 22)
                    .accessibilityValue(test.showAdvanced ? "Shown" : "Hidden")
                if test.showAdvanced {
                    VStack(alignment: .leading, spacing: 14) {
                        advanced(status)
                    }
                    .padding(.top, 14)
                }

                if let result = test.result {
                    Rectangle().fill(Theme.line).frame(height: 1)
                        .padding(.top, 24)
                    TestLoginResultView(result: result, showDetails: $test.showDetails)
                        .padding(.top, 18)
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 22)
            .padding(.bottom, 24) }
            .onChange(of: test.preset) { test.inputsChanged() }
            .onChange(of: test.user) { test.inputsChanged() }
            .onChange(of: test.password) { test.inputsChanged() }

            Rectangle().fill(Theme.line).frame(height: 1)
            HStack(alignment: .center, spacing: 22) {
                if test.running {
                    Text("Testing…")
                        .font(Theme.detail)
                        .foregroundStyle(Theme.muted)
                }
                Spacer()
                if test.running {
                    Button("Stop") { test.cancel() }
                        .buttonStyle(.quietLink)
                }
                Button("Close") { close() }
                    .buttonStyle(.quietLink)
                    .keyboardShortcut(.cancelAction)
                Button("Test") { test.run(model.controller) }
                    .buttonStyle(.quietPrimary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!test.canRun)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.background)
    }

    /// The label above the control, as in every sheet.
    private func labeled<Control: View>(_ label: String, @ViewBuilder control: () -> Control) -> some View {
        SheetField(label, control: control)
    }

    /// One choice as a text menu: the label, then the current value in ink (click for the others).
    private func choice<Value: Hashable>(_ label: String, selection: Binding<Value>, options: [Value],
                                         title: @escaping (Value) -> String) -> some View {
        labeled(label) {
            SheetPicker(label, selection: selection) {
                ForEach(options, id: \.self) { option in
                    Text(title(option)).tag(option)
                }
            }
            .accessibilityLabel(label)
            .accessibilityValue(title(selection.wrappedValue))
        }
    }

    @ViewBuilder
    private func advanced(_ status: ServerStatus) -> some View {
        switch test.preset {
        case .kerberos:
            choice("Realm", selection: $test.realmForm, options: LoginTestRequest.RealmForm.allCases) {
                test.realmLabel($0, status: status)
            }
        case .ntlm:
            labeled("Workstation") {
                QuietTextField("Workstation", text: $test.workstation, prompt: "LABDC-TEST")
                    .textFieldStyle(.quiet)
                    .help("The Workstation field of the logon: the NAC's name")
                    .accessibilityLabel("Workstation")
            }
            choice("Name form", selection: $test.ntlmNameForm, options: test.nameForms) {
                test.nameFormLabel($0, status: status)
            }
            SheetToggle("MS-CHAPv2 style (NTLMv1)", isOn: $test.msCHAPv2Style)
            .help("A 24-byte response over the RFC 2759 challenge hash with MSV1_0_ALLOW_MSVCHAPV2, as PEAP-MSCHAPv2 pass-through sends")
            SheetToggle("Allow computer accounts", isOn: $test.allowComputerAccounts)
            .help("MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT and …SERVER…: ntlm_auth and NACs set them")
        case .ldap:
            choice("Name form", selection: $test.ldapNameForm, options: test.nameForms) {
                test.nameFormLabel($0, status: status)
            }
            choice("Connection", selection: $test.ldapConnection, options: LoginTestRequest.LDAPConnection.allCases) {
                TestLoginModel.connectionLabel($0)
            }
        }
    }
}

/// The result as one sentence (ink when it passed, the attention colour when it did not) and the
/// detail lines behind "Show details".
struct TestLoginResultView: View {
    let result: LoginTestResult
    @Binding var showDetails: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(result.sentence)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(result.passed ? Theme.ink : Theme.attention)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel((result.passed ? "Passed: " : "Failed: ") + result.sentence)
            if !result.details.isEmpty {
                Button(showDetails ? "Hide details" : "Show details") { showDetails.toggle() }
                    .buttonStyle(.quietLink)
                    .accessibilityValue(showDetails ? "Shown" : "Hidden")
                if showDetails {
                    Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 6) {
                        ForEach(result.details) { d in
                            GridRow {
                                Text(d.label)
                                    .font(Theme.detail)
                                    .foregroundStyle(Theme.muted)
                                    .gridColumnAlignment(.leading)
                                Text(d.value)
                                    .font(Theme.mono)
                                    .foregroundStyle(Theme.ink)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .padding(.top, 2)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
