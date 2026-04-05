import SwiftUI
import UniformTypeIdentifiers
import UIKit

@MainActor
class SignIPAViewModel: ObservableObject {
    @Published var ipaInfo: IPAInfo?
    @Published var p12URL: URL?
    @Published var provisionURL: URL?
    @Published var p12Password: String = ""
    @Published var certInfo: CertificateInfo?

    // Options
    @Published var bundleIDOverride: String = ""
    @Published var displayNameOverride: String = ""
    @Published var versionOverride: String = ""
    @Published var removeCapabilities: Bool = false
    @Published var removeSupportedDevices: Bool = false
    @Published var removePlugins: Bool = false
    @Published var forceSign: Bool = true
    @Published var showOptions: Bool = false
    @Published var injectDylibURLs: [URL] = []

    // State
    @Published var isSigning: Bool = false
    @Published var progress: Double = 0.0
    @Published var logs: [String] = []
    @Published var outputURL: URL?
    @Published var outputSHA256: String?
    @Published var errorMessage: String?
    @Published var showShareSheet: Bool = false

    // Pickers
    @Published var showIPAPicker = false
    @Published var showP12Picker = false
    @Published var showProvisionPicker = false
    @Published var showDylibPicker = false

    func selectIPA(_ url: URL) async {
        logs = []
        outputURL = nil
        outputSHA256 = nil
        errorMessage = nil
        addLog("Loading IPA...")
        do {
            let info = try await IPAParser.parseIPA(url: url)
            ipaInfo = info
            bundleIDOverride = info.bundleID
            displayNameOverride = info.appName
            versionOverride = info.version
            addLog("Loaded: \(info.appName) (\(info.bundleID))")
        } catch {
            errorMessage = error.localizedDescription
            addLog("Error: \(error.localizedDescription)")
        }
    }

    func selectP12(_ url: URL) {
        p12URL = url
        certInfo = nil
        if !p12Password.isEmpty {
            loadCertInfo()
        }
    }

    func loadCertInfo() {
        guard let url = p12URL, !p12Password.isEmpty else { return }
        Task {
            do {
                var info = try CertificateService.parseCertificate(p12URL: url, password: p12Password)
                certInfo = info
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    func signIPA() async {
        guard let ipaURL = ipaInfo?.url,
              let p12 = p12URL,
              let prov = provisionURL else {
            errorMessage = "Please select IPA, certificate, and provisioning profile"
            return
        }

        isSigning = true
        progress = 0.0
        logs = []
        errorMessage = nil
        outputURL = nil

        let outputName = (ipaURL.deletingPathExtension().lastPathComponent) + "_signed.ipa"
        let outputDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let output = outputDir.appendingPathComponent(outputName)

        let steps = ["Preparing...", "Extracting...", "Signing...", "Packaging..."]
        var stepIndex = 0

        do {
            let result = try await ZsignWrapper.sign(
                ipaURL: ipaURL,
                p12URL: p12,
                p12Password: p12Password,
                provisionURL: prov,
                outputURL: output,
                bundleID: bundleIDOverride.isEmpty ? nil : bundleIDOverride,
                displayName: displayNameOverride.isEmpty ? nil : displayNameOverride,
                version: versionOverride.isEmpty ? nil : versionOverride,
                injectDylibs: injectDylibURLs,
                removePlugins: removePlugins
            ) { [weak self] msg in
                DispatchQueue.main.async {
                    self?.addLog(msg)
                    stepIndex = min(stepIndex + 1, steps.count - 1)
                    self?.progress = Double(stepIndex) / Double(steps.count)
                }
            }

            outputURL = result
            outputSHA256 = computeSHA256(url: result)
            progress = 1.0

            // Save to history
            let job = SigningJob(
                timestamp: Date(),
                inputIPAName: ipaURL.lastPathComponent,
                certificateName: certInfo?.subjectCN ?? p12.lastPathComponent,
                outputIPAName: result.lastPathComponent,
                success: true
            )
            SigningHistory.shared.add(job)

            UINotificationFeedbackGenerator().notificationOccurred(.success)

        } catch {
            errorMessage = error.localizedDescription
            addLog("FAILED: \(error.localizedDescription)")
            progress = 0.0

            let job = SigningJob(
                inputIPAName: ipaURL.lastPathComponent,
                certificateName: p12.lastPathComponent,
                outputIPAName: "",
                success: false,
                errorMessage: error.localizedDescription
            )
            SigningHistory.shared.add(job)

            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        isSigning = false
    }

    private func addLog(_ msg: String) {
        logs.append("[\(timeString())] \(msg)")
    }

    private func timeString() -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "HH:mm:ss"
        return fmt.string(from: Date())
    }

    private func computeSHA256(url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        import CryptoKit
        let hash = CryptoKit.SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Main View

struct SignIPAView: View {
    @StateObject private var vm = SignIPAViewModel()

    var body: some View {
        ZStack {
            Color(hex: "0a0a0f").ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    // IPA Card
                    IPAFileCard(vm: vm)
                    // Cert Card
                    CertificateCard(vm: vm)
                    // Options Card
                    SigningOptionsCard(vm: vm)
                    // Action Card
                    SignActionCard(vm: vm)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 16)
            }
        }
        .navigationTitle("Sign IPA")
        .navigationBarTitleDisplayMode(.large)
        .fileImporter(isPresented: $vm.showIPAPicker,
                      allowedContentTypes: [.ipa, .zip],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                url.startAccessingSecurityScopedResource()
                Task { await vm.selectIPA(url) }
            }
        }
        .fileImporter(isPresented: $vm.showP12Picker,
                      allowedContentTypes: [.p12],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                url.startAccessingSecurityScopedResource()
                vm.selectP12(url)
            }
        }
        .fileImporter(isPresented: $vm.showProvisionPicker,
                      allowedContentTypes: [.mobileprovision],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                url.startAccessingSecurityScopedResource()
                vm.provisionURL = url
            }
        }
        .fileImporter(isPresented: $vm.showDylibPicker,
                      allowedContentTypes: [.dylib, .data],
                      allowsMultipleSelection: true) { result in
            if case .success(let urls) = result {
                vm.injectDylibURLs.append(contentsOf: urls)
            }
        }
        .sheet(isPresented: $vm.showShareSheet) {
            if let url = vm.outputURL {
                ShareSheet(items: [url])
            }
        }
    }
}

// MARK: - IPA Card

private struct IPAFileCard: View {
    @ObservedObject var vm: SignIPAViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("IPA File", systemImage: "doc.zipper")
                .font(.headline).foregroundColor(.white)

            Button(action: { vm.showIPAPicker = true }) {
                HStack {
                    Image(systemName: "plus.circle.fill")
                        .foregroundColor(Color(hex: "3c94fc"))
                    Text(vm.ipaInfo == nil ? "Select IPA File" : "Change IPA")
                        .foregroundColor(Color(hex: "3c94fc"))
                    Spacer()
                }
                .padding(12)
                .background(Color(hex: "3c94fc").opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            }

            if let info = vm.ipaInfo {
                Divider().background(Color.white.opacity(0.1))
                HStack(spacing: 12) {
                    if let icon = info.appIcon {
                        Image(uiImage: icon)
                            .resizable().frame(width: 52, height: 52)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    } else {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(Color.white.opacity(0.1))
                            .frame(width: 52, height: 52)
                            .overlay(Image(systemName: "app").foregroundColor(.white.opacity(0.5)))
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        Text(info.appName).font(.headline).foregroundColor(.white)
                        Text(info.bundleID).font(.caption).foregroundColor(.white.opacity(0.6))
                            .fontDesign(.monospaced)
                        HStack(spacing: 8) {
                            Text("v\(info.version)").font(.caption2).foregroundColor(.white.opacity(0.5))
                            Text(info.fileSizeFormatted).font(.caption2).foregroundColor(.white.opacity(0.5))
                        }
                    }
                    Spacer()
                }
            }
        }
        .cardPadding()
        .glassCard()
    }
}

// MARK: - Certificate Card

private struct CertificateCard: View {
    @ObservedObject var vm: SignIPAViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Certificate", systemImage: "person.badge.key.fill")
                .font(.headline).foregroundColor(.white)

            HStack(spacing: 10) {
                Button(action: { vm.showP12Picker = true }) {
                    Label(vm.p12URL == nil ? "Select .p12" : vm.p12URL!.lastPathComponent,
                          systemImage: "key.fill")
                        .font(.subheadline)
                        .foregroundColor(Color(hex: "3c94fc"))
                        .frame(maxWidth: .infinity)
                        .padding(10)
                        .background(Color(hex: "3c94fc").opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
                }
                Button(action: { vm.showProvisionPicker = true }) {
                    Label(vm.provisionURL == nil ? "Select .prov" : "Provision ✓",
                          systemImage: "checkmark.shield.fill")
                        .font(.subheadline)
                        .foregroundColor(Color(hex: "3c94fc"))
                        .frame(maxWidth: .infinity)
                        .padding(10)
                        .background(Color(hex: "3c94fc").opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
                }
            }

            if vm.p12URL != nil {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").foregroundColor(.white.opacity(0.5))
                        .font(.footnote)
                    SecureField("Password", text: $vm.p12Password)
                        .foregroundColor(.white)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .submitLabel(.done)
                        .onSubmit { vm.loadCertInfo() }
                }
                .padding(10)
                .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }

            if let cert = vm.certInfo {
                Divider().background(Color.white.opacity(0.1))
                CertBadge(cert: cert)
            }
        }
        .cardPadding()
        .glassCard()
    }
}

private struct CertBadge: View {
    let cert: CertificateInfo

    var statusColor: Color {
        switch cert.ocspStatus {
        case .valid: return cert.isExpired ? .red : .green
        case .revoked: return .orange
        default: return cert.isExpired ? .red : .yellow
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(statusColor).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(cert.subjectCN).font(.subheadline).foregroundColor(.white)
                if !cert.teamName.isEmpty {
                    Text(cert.teamName).font(.caption).foregroundColor(.white.opacity(0.6))
                }
            }
            Spacer()
            if let days = cert.daysRemaining {
                Text(days >= 0 ? "\(days)d left" : "Expired")
                    .font(.caption2)
                    .foregroundColor(days >= 0 ? .green : .red)
                    .padding(4)
                    .background((days >= 0 ? Color.green : Color.red).opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }
}

// MARK: - Signing Options Card

private struct SigningOptionsCard: View {
    @ObservedObject var vm: SignIPAViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: { withAnimation(.spring(duration: 0.3)) { vm.showOptions.toggle() } }) {
                HStack {
                    Label("Signing Options", systemImage: "slider.horizontal.3")
                        .font(.headline).foregroundColor(.white)
                    Spacer()
                    Image(systemName: vm.showOptions ? "chevron.up" : "chevron.down")
                        .foregroundColor(.white.opacity(0.5))
                        .font(.footnote)
                }
                .padding(16)
            }

            if vm.showOptions {
                Divider().background(Color.white.opacity(0.1))
                VStack(spacing: 12) {
                    OptionField(title: "Bundle ID Override", text: $vm.bundleIDOverride, placeholder: "com.example.app")
                    OptionField(title: "Display Name Override", text: $vm.displayNameOverride, placeholder: "My App")
                    OptionField(title: "Version Override", text: $vm.versionOverride, placeholder: "1.0.0")

                    OptionToggle(title: "Remove App Extensions (.appex)", isOn: $vm.removePlugins)
                    OptionToggle(title: "Force Sign All Binaries", isOn: $vm.forceSign)

                    // Inject dylibs
                    VStack(alignment: .leading, spacing: 6) {
                        Button(action: { vm.showDylibPicker = true }) {
                            Label("Inject .dylib / .framework", systemImage: "plus.circle")
                                .font(.subheadline)
                                .foregroundColor(Color(hex: "3c94fc"))
                        }
                        ForEach(vm.injectDylibURLs, id: \.path) { url in
                            HStack {
                                Image(systemName: "link").font(.caption).foregroundColor(.white.opacity(0.5))
                                Text(url.lastPathComponent).font(.caption).foregroundColor(.white.opacity(0.7))
                                Spacer()
                                Button(action: { vm.injectDylibURLs.removeAll { $0 == url } }) {
                                    Image(systemName: "xmark.circle.fill").foregroundColor(.red.opacity(0.7))
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            }
        }
        .glassCard()
    }
}

private struct OptionField: View {
    let title: String
    @Binding var text: String
    let placeholder: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundColor(.white.opacity(0.6))
            TextField(placeholder, text: $text)
                .foregroundColor(.white)
                .padding(8)
                .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        }
    }
}

private struct OptionToggle: View {
    let title: String
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) {
            Text(title).font(.subheadline).foregroundColor(.white)
        }
        .tint(Color(hex: "3c94fc"))
    }
}

// MARK: - Action Card

private struct SignActionCard: View {
    @ObservedObject var vm: SignIPAViewModel

    var canSign: Bool {
        vm.ipaInfo != nil && vm.p12URL != nil && vm.provisionURL != nil
    }

    var body: some View {
        VStack(spacing: 16) {
            if let err = vm.errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
                    Text(err).font(.subheadline).foregroundColor(.red)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            }

            Button(action: {
                Task { await vm.signIPA() }
            }) {
                HStack {
                    if vm.isSigning {
                        ProgressView().tint(.white).scaleEffect(0.85)
                    } else {
                        Image(systemName: "signature")
                    }
                    Text(vm.isSigning ? "Signing..." : "Sign IPA")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(canSign ? Color(hex: "3c94fc") : Color.gray.opacity(0.4), in: RoundedRectangle(cornerRadius: 14))
                .foregroundColor(.white)
            }
            .disabled(!canSign || vm.isSigning)

            if vm.isSigning {
                VStack(spacing: 6) {
                    ProgressView(value: vm.progress)
                        .tint(Color(hex: "3c94fc"))
                    if let lastLog = vm.logs.last {
                        Text(lastLog)
                            .font(.caption).foregroundColor(.white.opacity(0.6))
                            .fontDesign(.monospaced)
                            .lineLimit(1)
                    }
                }
            }

            if let output = vm.outputURL {
                Divider().background(Color.white.opacity(0.1))
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                        Text("Signed Successfully").font(.subheadline).foregroundColor(.green)
                    }
                    Text(output.lastPathComponent)
                        .font(.caption).foregroundColor(.white.opacity(0.7))
                        .fontDesign(.monospaced)
                    if let sha = vm.outputSHA256 {
                        Text("SHA256: \(sha.prefix(16))...")
                            .font(.caption2).foregroundColor(.white.opacity(0.4))
                            .fontDesign(.monospaced)
                    }
                    Button(action: { vm.showShareSheet = true }) {
                        Label("Export / Save to Files", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Color.green.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
                            .foregroundColor(.green)
                    }
                }
            }

            if !vm.logs.isEmpty {
                DisclosureGroup("Logs (\(vm.logs.count))") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(vm.logs, id: \.self) { line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.6))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(maxHeight: 200)
                    .background(Color.black.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
                }
                .foregroundColor(.white.opacity(0.7))
            }
        }
        .cardPadding()
        .glassCard()
    }
}

// MARK: - Share Sheet
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
