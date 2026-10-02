import Observation
import LabDCCore
import PKIKit
import SwiftUI

/// §7.2: 1 Domain → 2 Administrator → 3 Done (create the domain and start).
@MainActor @Observable
final class SetupWizardModel {
    enum Step: Int, CaseIterable {
        case domain = 1, administrator, done

        var title: String {
            switch self {
            case .domain: "Domain"
            case .administrator: "Administrator"
            case .done: "Done"
            }
        }
    }

    var step = Step.domain
    var domain = DomainSetup.suggested
    /// Empty = the derived name (the first DNS label upper-cased); else the owner's choice.
    /// The NetBIOS name is not in DNS, so devices learn it from the DC — it may differ from the
    /// domain's first label and cannot change after the domain exists.
    var netbios = ""
    var password = ""
    var confirm = ""
    var creating = false
    var error: String?
    /// UI-1c: the network devices reach this Mac on (nil = automatic, the first address).
    var advertise: String?
    var interfaces: [NetworkInterfaceChoice]
    /// The lab CA's key (1 Oct 2026): P-384 / ECDSA SHA-384 by default, P-256 for old gear.
    var caKeyType: CAKeyType = LabPKI.defaultLabCAKeyType

    init(interfaces: [NetworkInterfaceChoice] = NetworkInterfaces.current()) {
        self.interfaces = interfaces
    }

    /// `Wi-Fi 192.168.1.155` for the chosen (or automatic) address.
    var addressLabel: String {
        let ip = advertise ?? interfaces.first?.ipv4
        return NetworkInterfaces.choice(for: ip, in: interfaces)?.label ?? ip ?? "127.0.0.1"
    }

    var derivation: Result<DomainSetup, DomainSetup.Problem> { DomainSetup.derive(domain) }
    /// The derived setup with the NetBIOS name applied (`DomainSetup.validNetbios`: 1–15
    /// letters, digits or hyphens, upper-cased).
    var setup: DomainSetup? {
        guard var s = try? derivation.get() else { return nil }
        s.caKeyType = caKeyType
        guard !netbiosTyped else {
            guard let name = DomainSetup.validNetbios(netbios) else { return nil }
            s.netbios = name
            return s
        }
        return s
    }
    private var netbiosTyped: Bool { !netbios.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    /// Whether the NetBIOS field is filled but invalid (the Continue button waits for it).
    var netbiosInvalid: Bool { netbiosTyped && DomainSetup.validNetbios(netbios) == nil }

    /// Whether Cancel would throw away something the owner typed (it asks first then).
    var hasTypedData: Bool {
        domain.trimmingCharacters(in: .whitespacesAndNewlines) != DomainSetup.suggested
            || netbiosTyped || !password.isEmpty || !confirm.isEmpty || advertise != nil
    }
    var strength: PasswordStrength { .evaluate(password) }
    var passwordsMatch: Bool { password == confirm }

    /// The sentence under the password fields.
    var passwordHint: String {
        if !confirm.isEmpty, !passwordsMatch { return "The two passwords differ." }
        return strength.hint
    }

    var canContinue: Bool {
        switch step {
        case .domain: setup != nil
        case .administrator: strength.isAcceptable && passwordsMatch
        case .done: setup != nil && strength.isAcceptable && passwordsMatch && !creating
        }
    }

    func next() {
        guard canContinue, let n = Step(rawValue: step.rawValue + 1) else { return }
        error = nil
        step = n
    }

    func back() {
        guard !creating, let p = Step(rawValue: step.rawValue - 1) else { return }
        error = nil
        step = p
    }

    /// "Skip, use the defaults": lab.sheep and straight to the password.
    func useDefaults() {
        domain = DomainSetup.suggested
        netbios = ""
        step = .administrator
    }
}

struct SetupWizardView: View {
    @Environment(AppModel.self) private var model
    @State private var wizard = SetupWizardModel()

    var body: some View {
        SetupWizardContent(wizard: wizard, cancel: { await model.cancelWizard() }) { setup, password, advertise in
            await model.finishSetup(setup, password: password, advertise: advertise)
        }
    }
}

/// The wizard, Quiet look (owner, 27 Sep 2026): one centred column on the page background —
/// "Step 2 of 3", the step's question as a big light sentence, the explanation in muted, fields
/// with a line under them, Back as a muted word and the one strong action, and a thin 3-segment
/// progress line at the bottom. `create` provisions and starts (returns an error message on failure).
struct SetupWizardContent: View {
    @Bindable var wizard: SetupWizardModel
    let cancel: () async -> Void
    let create: (DomainSetup, String, String?) async -> String?
    /// Cancel with something typed asks first (owner review, 30 Sep 2026).
    @State private var confirmCancel = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StepIndicator(current: wizard.step)
            Group {
                switch wizard.step {
                case .domain: DomainStep(wizard: wizard)
                case .administrator: AdministratorStep(wizard: wizard)
                case .done: DoneStep(wizard: wizard)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 12)
            Spacer(minLength: 20)
            if let error = wizard.error {
                QuietNote(error, attention: true)
                    .textSelection(.enabled)
                    .padding(.bottom, 16)
            }
            buttons
            WizardProgressLine(current: wizard.step)
                .padding(.top, 32)
        }
        .frame(width: 460, height: 560)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
    }

    @ViewBuilder
    private var buttons: some View {
        HStack(alignment: .center, spacing: 24) {
            Button {
                if wizard.hasTypedData { confirmCancel = true } else { Task { await cancel() } }
            } label: {
                Text("Cancel")
                    .font(Theme.body)
                    .foregroundStyle(Theme.muted)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(wizard.creating)
            .padding(.trailing, 24)
            .accessibilityHint("Return to the previous domain, or quit")
            .alert("Discard this setup?", isPresented: $confirmCancel) {
                Button("Discard", role: .destructive) { Task { await cancel() } }
                Button("Keep editing", role: .cancel) {}
            } message: {
                Text("What you typed is not kept. The app returns to the previous domain, or quits when there is none.")
            }
            if wizard.step == .domain {
                Button { wizard.useDefaults() } label: {
                    Text("Skip, use lab.sheep")
                        .font(Theme.body)
                        .foregroundStyle(Theme.muted)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityHint("Uses the domain lab.sheep and goes to the password step")
            } else {
                Button { wizard.back() } label: {
                    Text("Back")
                        .font(Theme.body)
                        .foregroundStyle(Theme.muted)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(wizard.creating)
            }
            Spacer(minLength: 16)
            if wizard.step == .done {
                Button(wizard.creating ? "Creating…" : "Create the domain and start") {
                    guard let setup = wizard.setup else { return }
                    wizard.creating = true
                    wizard.error = nil
                    let password = wizard.password
                    Task {
                        wizard.error = await create(setup, password, wizard.advertise)
                        wizard.creating = false
                    }
                }
                .buttonStyle(.quietPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(!wizard.canContinue)
            } else {
                Button("Continue") { wizard.next() }
                    .buttonStyle(.quietPrimary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!wizard.canContinue)
            }
        }
    }
}

/// "Step 2 of 3" in the faint colour.
struct StepIndicator: View {
    let current: SetupWizardModel.Step

    var body: some View {
        Text("Step \(current.rawValue) of \(SetupWizardModel.Step.allCases.count)")
            .font(Theme.detail)
            .foregroundStyle(Theme.faint)
            .accessibilityLabel("Step \(current.rawValue) of \(SetupWizardModel.Step.allCases.count), \(current.title)")
    }
}

/// The thin progress line at the bottom: one segment per step, ink up to the current one.
struct WizardProgressLine: View {
    let current: SetupWizardModel.Step

    var body: some View {
        HStack(spacing: 6) {
            ForEach(SetupWizardModel.Step.allCases, id: \.self) { step in
                Rectangle()
                    .fill(step.rawValue <= current.rawValue ? Theme.ink : Theme.control)
                    .frame(maxWidth: .infinity)
                    .frame(height: 2)
            }
        }
        .accessibilityHidden(true)
    }
}

/// A step's question: big, light, a sentence.
struct WizardTitle: View {
    let text: String

    var body: some View {
        Text(text)
            .font(Theme.pageTitle)
            .tracking(-0.8)
            .foregroundStyle(Theme.ink)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isHeader)
    }
}

/// The explanation under a step's title.
struct WizardText: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 15))
            .foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// `Kerberos realm      LAB.SHEEP`: a derived value, label muted, value ink.
struct WizardFact: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label)
                .font(Theme.detail)
                .foregroundStyle(Theme.muted)
                .frame(width: 150, alignment: .leading)
            Text(value)
                .font(Theme.detail)
                .foregroundStyle(Theme.ink)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}

/// A caption above a field, as in the Quiet inspectors.
struct WizardFieldLabel: View {
    let text: String

    var body: some View {
        Text(text)
            .font(Theme.caption)
            .foregroundStyle(Theme.muted)
            .accessibilityHidden(true)
    }
}

struct DomainStep: View {
    @Bindable var wizard: SetupWizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            WizardTitle(text: "Name your lab's domain.")
            WizardText(text: "It becomes the Kerberos realm and the LDAP base DN. Devices use it to find this Mac.")
            FieldBox {
                VStack(alignment: .leading, spacing: 4) {
                    WizardFieldLabel(text: "Domain")
                    TextField("Domain", text: $wizard.domain, prompt: Text(DomainSetup.suggested))
                        .textFieldStyle(.quiet)
                        .accessibilityLabel("Domain name")
                    WizardFieldLabel(text: "NetBIOS name")
                    TextField("NetBIOS name", text: $wizard.netbios, prompt: Text((try? wizard.derivation.get())?.netbios ?? "LAB"))
                        .textFieldStyle(.quiet)
                        .autocorrectionDisabled()
                        .accessibilityLabel("NetBIOS domain name")
                    if wizard.netbiosInvalid {
                        QuietNote(DomainSetup.netbiosRule, attention: true)
                    }
                    switch wizard.derivation {
                    case .success(let s):
                        WizardFact(label: "Kerberos realm", value: s.realm)
                        WizardFact(label: "Base DN", value: s.baseDN)
                        WizardFact(label: "Domain controller", value: s.dcFQDN)
                    case .failure(let problem):
                        QuietNote(problem.description, attention: true)
                    }
                }
            }
            QuietNote("Everything under the name is filled in for you; the NetBIOS name is what devices show as the logon domain and can be changed here before the domain exists. Don't use .local — it collides with Bonjour.")
        }
    }
}

struct AdministratorStep: View {
    @Bindable var wizard: SetupWizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            WizardTitle(text: "Choose the Administrator password.")
            WizardText(text: "Administrator manages the domain and is the lookup account devices use for LDAP. You can change it later in Directory.")
            FieldBox {
                VStack(alignment: .leading, spacing: 4) {
                    WizardFieldLabel(text: "Password")
                    SecureField("Password", text: $wizard.password)
                        .textFieldStyle(.quiet)
                        .accessibilityLabel("Administrator password")
                }
                VStack(alignment: .leading, spacing: 4) {
                    WizardFieldLabel(text: "Confirm")
                    SecureField("Confirm", text: $wizard.confirm)
                        .textFieldStyle(.quiet)
                        .accessibilityLabel("Confirm the Administrator password")
                }
                .padding(.top, 6)
                HStack(alignment: .center, spacing: 10) {
                    StrengthMeter(level: wizard.strength.level)
                    Text(wizard.passwordHint)
                        .font(Theme.caption)
                        .foregroundStyle(wizard.strength.level == .refused || (!wizard.confirm.isEmpty && !wizard.passwordsMatch)
                                         ? Theme.attention : Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, 4)
            }
        }
    }
}

/// Three thin segments, ink as the password gets stronger; the attention colour when refused.
struct StrengthMeter: View {
    let level: PasswordStrength.Level

    var body: some View {
        HStack(spacing: 3) {
            ForEach(0..<3) { i in
                Rectangle()
                    .fill(i < filled ? color : Theme.control)
                    .frame(width: 18, height: 2)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Password strength \(label)")
    }

    private var filled: Int {
        switch level {
        case .empty: 0
        case .refused: 1
        case .fair: 2
        case .strong: 3
        }
    }

    private var color: Color {
        switch level {
        case .empty, .refused: Theme.attention
        case .fair, .strong: Theme.ink
        }
    }

    private var label: String {
        switch level {
        case .empty: "empty"
        case .refused: "too weak"
        case .fair: "fair"
        case .strong: "strong"
        }
    }
}

struct DoneStep: View {
    @Bindable var wizard: SetupWizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            WizardTitle(text: "Ready to start.")
            WizardText(text: "LabDC creates the domain on this Mac and starts every service: DNS, Kerberos, LDAP, SMB, RPC and the certificate services. "
                       + "It keeps running while the app is open.")
            if let s = wizard.setup {
                FieldBox {
                    WizardFact(label: "Domain", value: s.dnsDomain)
                    WizardFact(label: "Domain controller", value: s.dcFQDN)
                    WizardFact(label: "Administrator", value: "\(s.netbios)\\Administrator")
                    HStack(alignment: .center, spacing: 16) {
                        Text("Devices reach this Mac on")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .frame(width: 150, alignment: .leading)
                        NetworkInterfacePicker(title: "Devices reach this Mac on", interfaces: wizard.interfaces,
                                               selection: $wizard.advertise)
                            .accessibilityHint("The network whose address DNS and the domain locator hand out")
                        Spacer(minLength: 0)
                    }
                }
                QuietNote("Pick the network your PCs, switches and NAC are on. A Tailscale or VPN address only reaches devices on that VPN.")
                FieldBox {
                    HStack(alignment: .center, spacing: 16) {
                        Text("Lab CA key")
                            .font(Theme.detail)
                            .foregroundStyle(Theme.muted)
                            .frame(width: 150, alignment: .leading)
                        Picker("Lab CA key", selection: $wizard.caKeyType) {
                            Text("P-384 · ECDSA SHA-384").tag(CAKeyType.p384)
                            Text("P-256 · ECDSA SHA-256").tag(CAKeyType.p256)
                        }
                        .labelsHidden()
                        .frame(width: 220)
                        .accessibilityHint("The key of the root that issues every certificate of the domain")
                        Spacer(minLength: 0)
                    }
                }
                QuietNote("P-384 is the default and also serves WPA3-Enterprise 192-bit. P-256 suits older network gear; the key can be changed later under Certificates.")
            }
            QuietNote("Next, Overview lists what is still empty: add a user, connect a device, publish the CA.")
        }
    }
}

/// The wizard's group of fields and facts: no box in the Quiet look, just spacing.
struct FieldBox<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            content
        }
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
