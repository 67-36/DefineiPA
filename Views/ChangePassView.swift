import SwiftUI
import UniformTypeIdentifiers
import CryptoKit

@MainActor
class ChangePassViewModel: ObservableObject {
    @Published var p12URL: URL?
    @Published var currentPassword: String = ""
    @Published var newPassword: String = ""
    @Published var confirmPassword: String = ""

    @Published var isProcessing: Bool = false
    @Published var outputURL: URL?
    @Published var outputFileSize: String?
    @Published var outputSHA256: String?
    @Published var errorMessage: String?
    @Published var showShareSheet: Bool = false
    @Published var showP12Picker = false

    var validationError: String? {
        if newPassword != confirmPassword { return "Passwords do not match" }
        if newPassword == currentPassword && !currentPassword.isEmpty { return "New password must differ from current" }
        return nil
    }

    var canChange: Bool {
        p12URL != nil && validationError == nil
    }

    func changePassword() async {
        guard let url = p12URL else { return }

        isProcessing = true
        errorMessage = nil
        outputURL = nil

        let originalName = url.deletingPathExtension().lastPathComponent
        let outputName = "\(originalName)_newpass.p12"
        let outputDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let output = outputDir.appendingPathComponent(outputName)

        do {
            try P12PasswordChanger.changePassword(
                p12URL: url,
                oldPassword: currentPassword,
                newPassword: newPassword,
                outputURL: output
            )
            outputURL = output
            outputFileSize = bytesFormatted(url: output)
            outputSHA256 = sha256String(url: output)

            // Save new password to keychain
            if let key = P12PasswordChanger.sha256Key(for: output) {
                KeychainService.save(password: newPassword, for: key)
            }

            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } catch {
            errorMessage = error.localizedDescription
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        isProcessing = false
    }

    private func bytesFormatted(url: URL) -> String? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attrs[.size] as? Int64 else { return nil }
        return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
    }

    private func sha256String(url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}

struct ChangePassView: View {
    @StateObject private var vm = ChangePassViewModel()

    var body: some View {
        ZStack {
            Color(hex: "0a0a0f").ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    ImportPasswordCard(vm: vm)
                    ActionOutputCard(vm: vm)
                }
                .padding(16)
            }
        }
        .navigationTitle("Change Password")
        .navigationBarTitleDisplayMode(.large)
        .fileImporter(isPresented: $vm.showP12Picker,
                      allowedContentTypes: [.p12],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                url.startAccessingSecurityScopedResource()
                vm.p12URL = url
                vm.errorMessage = nil
                vm.outputURL = nil
            }
        }
        .sheet(isPresented: $vm.showShareSheet) {
            if let url = vm.outputURL {
                ShareSheet(items: [url])
            }
        }
    }
}

// MARK: - Import + Password Card

private struct ImportPasswordCard: View {
    @ObservedObject var vm: ChangePassViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Certificate", systemImage: "key.2.on.ring.fill")
                .font(.headline).foregroundColor(.white)

            Button(action: { vm.showP12Picker = true }) {
                HStack {
                    Image(systemName: vm.p12URL == nil ? "doc.badge.plus" : "key.fill")
                        .foregroundColor(Color(hex: "3c94fc"))
                    Text(vm.p12URL?.lastPathComponent ?? "Select .p12 Certificate")
                        .font(.subheadline)
                        .foregroundColor(Color(hex: "3c94fc"))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if vm.p12URL != nil {
                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.footnote)
                    }
                }
                .padding(12)
                .background(Color(hex: "3c94fc").opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            }

            Divider().background(Color.white.opacity(0.1))

            // Password fields
            PasswordRow(label: "Current Password", placeholder: "Enter current password", text: $vm.currentPassword)
            PasswordRow(label: "New Password", placeholder: "Enter new password (can be empty)", text: $vm.newPassword)
            PasswordRow(label: "Confirm New", placeholder: "Confirm new password", text: $vm.confirmPassword)

            // Validation
            if let err = vm.validationError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.circle.fill").foregroundColor(.orange)
                    Text(err).font(.caption).foregroundColor(.orange)
                }
            }

            if let err = vm.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "xmark.circle.fill").foregroundColor(.red)
                    Text(err).font(.subheadline).foregroundColor(.red)
                }
                .padding(10)
                .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            }
        }
        .cardPadding()
        .glassCard()
    }
}

private struct PasswordRow: View {
    let label: String
    let placeholder: String
    @Binding var text: String
    @State private var isRevealed: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundColor(.white.opacity(0.5))
            HStack {
                if isRevealed {
                    TextField(placeholder, text: $text)
                        .foregroundColor(.white)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                } else {
                    SecureField(placeholder, text: $text)
                        .foregroundColor(.white)
                        .autocorrectionDisabled()
                }
                Button(action: { isRevealed.toggle() }) {
                    Image(systemName: isRevealed ? "eye.slash" : "eye")
                        .foregroundColor(.white.opacity(0.4))
                        .font(.footnote)
                }
            }
            .padding(10)
            .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
        }
    }
}

// MARK: - Action + Output Card

private struct ActionOutputCard: View {
    @ObservedObject var vm: ChangePassViewModel

    var body: some View {
        VStack(spacing: 16) {
            Button(action: {
                Task { await vm.changePassword() }
            }) {
                HStack {
                    if vm.isProcessing {
                        ProgressView().tint(.white).scaleEffect(0.85)
                    } else {
                        Image(systemName: "key.viewfinder")
                    }
                    Text(vm.isProcessing ? "Processing..." : "Change Password")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    vm.canChange ? Color(hex: "3c94fc") : Color.gray.opacity(0.4),
                    in: RoundedRectangle(cornerRadius: 14)
                )
                .foregroundColor(.white)
            }
            .disabled(!vm.canChange || vm.isProcessing)

            if let output = vm.outputURL {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                        Text("Password Changed!").font(.subheadline).foregroundColor(.green)
                    }

                    VStack(spacing: 4) {
                        InfoLine(label: "File", value: output.lastPathComponent)
                        if let size = vm.outputFileSize {
                            InfoLine(label: "Size", value: size)
                        }
                        if let sha = vm.outputSHA256 {
                            InfoLine(label: "SHA256", value: "\(sha.prefix(20))...", mono: true)
                        }
                    }
                    .padding(10)
                    .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))

                    Button(action: { vm.showShareSheet = true }) {
                        Label("Export / Save to Files", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Color.green.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
                            .foregroundColor(.green)
                    }
                }
            }
        }
        .cardPadding()
        .glassCard()
    }
}

private struct InfoLine: View {
    let label: String
    let value: String
    var mono: Bool = false

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.white.opacity(0.5))
                .frame(width: 60, alignment: .leading)
            Text(value)
                .font(mono ? .system(size: 11, design: .monospaced) : .footnote)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
