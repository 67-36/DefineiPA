import SwiftUI
import UniformTypeIdentifiers

@MainActor
class CheckCertViewModel: ObservableObject {
    @Published var p12URL: URL?
    @Published var provisionURL: URL?
    @Published var password: String = ""
    @Published var certInfo: CertificateInfo?
    @Published var provisionInfo: ProvisionInfo?
    @Published var isChecking: Bool = false
    @Published var errorMessage: String?
    @Published var checkOCSP: Bool = false

    @Published var showP12Picker = false
    @Published var showProvisionPicker = false

    func check() async {
        guard let url = p12URL else {
            errorMessage = "Please select a .p12 certificate"
            return
        }

        isChecking = true
        errorMessage = nil
        certInfo = nil

        do {
            var info = try CertificateService.parseCertificate(p12URL: url, password: password)
            certInfo = info

            if checkOCSP {
                await CertificateService.checkOCSP(certInfo: &info, p12URL: url, password: password)
                certInfo = info
            }

            if let prov = provisionURL {
                provisionInfo = try CertificateService.parseProvision(url: prov)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
        isChecking = false
    }
}

struct CheckCertView: View {
    @StateObject private var vm = CheckCertViewModel()

    var body: some View {
        ZStack {
            Color(hex: "0a0a0f").ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    // Import card
                    ImportCard(vm: vm)
                    // Results card
                    if let cert = vm.certInfo {
                        CertResultCard(cert: cert)
                    }
                    // Provision card
                    if let prov = vm.provisionInfo {
                        ProvisionCard(prov: prov)
                    }
                }
                .padding(16)
            }
        }
        .navigationTitle("Check Certificate")
        .navigationBarTitleDisplayMode(.large)
        .fileImporter(isPresented: $vm.showP12Picker,
                      allowedContentTypes: [.p12],
                      allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                url.startAccessingSecurityScopedResource()
                vm.p12URL = url
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
    }
}

// MARK: - Import Card

private struct ImportCard: View {
    @ObservedObject var vm: CheckCertViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Import Certificate", systemImage: "person.text.rectangle.fill")
                .font(.headline).foregroundColor(.white)

            Button(action: { vm.showP12Picker = true }) {
                FilePickerRow(
                    icon: "key.fill",
                    label: vm.p12URL?.lastPathComponent ?? "Select .p12 Certificate",
                    isSelected: vm.p12URL != nil
                )
            }

            Button(action: { vm.showProvisionPicker = true }) {
                FilePickerRow(
                    icon: "checkmark.shield.fill",
                    label: vm.provisionURL?.lastPathComponent ?? "Select .mobileprovision (optional)",
                    isSelected: vm.provisionURL != nil
                )
            }

            HStack(spacing: 8) {
                Image(systemName: "lock.fill").foregroundColor(.white.opacity(0.5)).font(.footnote)
                SecureField("Certificate Password", text: $vm.password)
                    .foregroundColor(.white)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }
            .padding(10)
            .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))

            Toggle(isOn: $vm.checkOCSP) {
                HStack(spacing: 6) {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .foregroundColor(Color(hex: "3c94fc"))
                    Text("Check OCSP Revocation Status")
                        .font(.subheadline).foregroundColor(.white)
                }
            }
            .tint(Color(hex: "3c94fc"))

            if let err = vm.errorMessage {
                HStack {
                    Image(systemName: "xmark.circle.fill").foregroundColor(.red)
                    Text(err).font(.subheadline).foregroundColor(.red)
                }
                .padding(10)
                .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            }

            Button(action: {
                Task { await vm.check() }
            }) {
                HStack {
                    if vm.isChecking {
                        ProgressView().tint(.white).scaleEffect(0.85)
                    } else {
                        Image(systemName: "magnifyingglass")
                    }
                    Text(vm.isChecking ? "Checking..." : "Check Certificate")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Color(hex: "3c94fc"), in: RoundedRectangle(cornerRadius: 12))
                .foregroundColor(.white)
            }
            .disabled(vm.p12URL == nil || vm.isChecking)
            .opacity(vm.p12URL == nil ? 0.5 : 1)
        }
        .cardPadding()
        .glassCard()
    }
}

private struct FilePickerRow: View {
    let icon: String
    let label: String
    let isSelected: Bool

    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(isSelected ? Color(hex: "3c94fc") : .white.opacity(0.5))
            Text(label)
                .font(.subheadline)
                .foregroundColor(isSelected ? Color(hex: "3c94fc") : .white.opacity(0.5))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            if isSelected {
                Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.footnote)
            }
        }
        .padding(12)
        .background(
            isSelected ? Color(hex: "3c94fc").opacity(0.1) : Color.white.opacity(0.05),
            in: RoundedRectangle(cornerRadius: 10)
        )
    }
}

// MARK: - Certificate Results Card

private struct CertResultCard: View {
    let cert: CertificateInfo
    @State private var copied: String? = nil

    var statusColor: Color {
        switch cert.ocspStatus {
        case .valid: return cert.isExpired ? .red : .green
        case .revoked: return .orange
        case .checking: return .yellow
        case .unknown: return cert.isExpired ? .red : .yellow
        }
    }

    var statusText: String {
        switch cert.ocspStatus {
        case .valid: return cert.isExpired ? "Expired" : "Valid"
        case .revoked: return "Revoked"
        case .checking: return "Checking OCSP..."
        case .unknown: return cert.isExpired ? "Expired" : "Unknown"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Status banner
            HStack {
                Circle().fill(statusColor).frame(width: 10, height: 10)
                Text(statusText)
                    .font(.headline)
                    .foregroundColor(statusColor)
                Spacer()
                if let days = cert.daysRemaining {
                    Text(days >= 0 ? "\(days) days remaining" : "Expired \(-days) days ago")
                        .font(.caption)
                        .foregroundColor(days >= 0 ? .green : .red)
                }
            }
            .padding(16)
            .background(statusColor.opacity(0.08))

            Divider().background(Color.white.opacity(0.1))

            VStack(spacing: 0) {
                CertRow(label: "Common Name", value: cert.subjectCN)
                CertRow(label: "Team Name", value: cert.teamName)
                CertRow(label: "Team ID", value: cert.teamID, mono: true)
                CertRow(label: "Serial Number", value: cert.serialNumber, mono: true)
                CertRow(label: "Issued", value: cert.issueDate.map { formatDate($0) } ?? "—")
                CertRow(label: "Expires", value: cert.expiryDate.map { formatDate($0) } ?? "—")
                CertRow(label: "Issuer", value: cert.issuer)
                CopyableRow(label: "SHA-1", value: cert.sha1Fingerprint, copied: $copied)
                CopyableRow(label: "SHA-256", value: cert.sha256Fingerprint, copied: $copied)
            }
        }
        .glassCard()
    }

    private func formatDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: date)
    }
}

private struct CertRow: View {
    let label: String
    let value: String
    var mono: Bool = false

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundColor(.white.opacity(0.5))
                .frame(width: 100, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(mono ? .system(size: 12, design: .monospaced) : .footnote)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        Divider().background(Color.white.opacity(0.06)).padding(.horizontal, 16)
    }
}

private struct CopyableRow: View {
    let label: String
    let value: String
    @Binding var copied: String?

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundColor(.white.opacity(0.5))
                .frame(width: 100, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
                .lineLimit(2)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: {
                UIPasteboard.general.string = value
                copied = label
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = nil }
            }) {
                Image(systemName: copied == label ? "checkmark.circle.fill" : "doc.on.doc")
                    .font(.caption)
                    .foregroundColor(copied == label ? .green : Color(hex: "3c94fc"))
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        Divider().background(Color.white.opacity(0.06)).padding(.horizontal, 16)
    }
}

// MARK: - Provision Card

private struct ProvisionCard: View {
    let prov: ProvisionInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Provisioning Profile", systemImage: "doc.badge.gearshape.fill")
                .font(.headline).foregroundColor(.white)

            CertRow(label: "App ID", value: prov.appID)
            CertRow(label: "Team", value: prov.teamName)
            CertRow(label: "Expires", value: prov.expiryDate.map {
                DateFormatter.localizedString(from: $0, dateStyle: .medium, timeStyle: .none)
            } ?? "—")
            CertRow(label: "Devices", value: prov.deviceCount > 0 ? "\(prov.deviceCount) UDIDs" : "—")

            if !prov.entitlements.isEmpty {
                Text("Entitlements")
                    .font(.caption).foregroundColor(.white.opacity(0.5))
                    .padding(.horizontal, 16)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(prov.entitlements.keys.sorted().prefix(8), id: \.self) { key in
                            Text(key.components(separatedBy: ".").last ?? key)
                                .font(.caption2)
                                .foregroundColor(.white)
                                .padding(6)
                                .background(Color(hex: "3c94fc").opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
                        }
                    }
                    .padding(.horizontal, 16)
                }
            }
        }
        .cardPadding()
        .glassCard()
    }
}
