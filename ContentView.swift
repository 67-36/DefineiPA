import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    var body: some View {
        ZStack {
            Color(hex: "0a0a0f")
                .ignoresSafeArea()

            TabView {
                NavigationStack {
                    SignIPAView()
                }
                .tabItem {
                    Label("Sign IPA", systemImage: "pencil.and.list.clipboard")
                }

                NavigationStack {
                    CheckCertView()
                }
                .tabItem {
                    Label("Check Cert", systemImage: "checkmark.seal.fill")
                }

                NavigationStack {
                    ChangePassView()
                }
                .tabItem {
                    Label("Change Pass", systemImage: "key.fill")
                }
            }
            .tint(Color(hex: "3c94fc"))
        }
    }
}

// MARK: - Theme Helpers
extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3:  (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6:  (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8:  (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default: (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(.sRGB, red: Double(r)/255, green: Double(g)/255, blue: Double(b)/255, opacity: Double(a)/255)
    }
}

extension View {
    @ViewBuilder
    func glassCard(cornerRadius: CGFloat = 16) -> some View {
        if #available(iOS 26.0, *) {
            self
                .glassBackgroundEffect(in: RoundedRectangle(cornerRadius: cornerRadius))
        } else {
            self
                .background(
                    RoundedRectangle(cornerRadius: cornerRadius)
                        .fill(.ultraThinMaterial)
                        .overlay(
                            RoundedRectangle(cornerRadius: cornerRadius)
                                .strokeBorder(Color.white.opacity(0.08), lineWidth: 0.5)
                        )
                        .shadow(color: .black.opacity(0.4), radius: 12, x: 0, y: 4)
                )
        }
    }

    func cardPadding() -> some View {
        self.padding(16)
    }
}

extension UTType {
    static let ipa = UTType(filenameExtension: "ipa") ?? .zip
    static let p12 = UTType(mimeType: "application/x-pkcs12") ?? .data
    static let mobileprovision = UTType(filenameExtension: "mobileprovision") ?? .data
    static let dylib = UTType(filenameExtension: "dylib") ?? .data
}
