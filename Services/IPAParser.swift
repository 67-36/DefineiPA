import Foundation
import ZIPFoundation
import UIKit

class IPAParser {

    enum ParseError: LocalizedError {
        case invalidIPA
        case noPayload
        case noAppBundle
        case noPlist

        var errorDescription: String? {
            switch self {
            case .invalidIPA: return "Not a valid IPA file"
            case .noPayload: return "No Payload directory found in IPA"
            case .noAppBundle: return "No .app bundle found in Payload"
            case .noPlist: return "Could not read Info.plist"
            }
        }
    }

    /// Parse an IPA file and return metadata
    static func parseIPA(url: URL) async throws -> IPAInfo {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("ipa_parse_\(UUID().uuidString)")
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer { try? fm.removeItem(at: tempDir) }

        // Extract IPA (it's a zip file)
        try fm.unzipItem(at: url, to: tempDir)

        let payloadDir = tempDir.appendingPathComponent("Payload")
        guard fm.fileExists(atPath: payloadDir.path) else {
            throw ParseError.noPayload
        }

        let contents = try fm.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)
        guard let appBundle = contents.first(where: { $0.pathExtension == "app" }) else {
            throw ParseError.noAppBundle
        }

        let plistURL = appBundle.appendingPathComponent("Info.plist")
        guard let plistData = fm.contents(atPath: plistURL.path),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] else {
            throw ParseError.noPlist
        }

        var info = IPAInfo()
        info.url = url
        info.appName = plist["CFBundleDisplayName"] as? String
            ?? plist["CFBundleName"] as? String
            ?? appBundle.deletingPathExtension().lastPathComponent
        info.bundleID = plist["CFBundleIdentifier"] as? String ?? ""
        info.version = plist["CFBundleShortVersionString"] as? String ?? ""
        info.buildNumber = plist["CFBundleVersion"] as? String ?? ""
        info.minimumOSVersion = plist["MinimumOSVersion"] as? String ?? ""

        // File size
        let attrs = try? fm.attributesOfItem(atPath: url.path)
        info.fileSize = attrs?[.size] as? Int64 ?? 0

        // Try to extract app icon
        info.appIcon = await extractAppIcon(from: appBundle, plist: plist)

        return info
    }

    // MARK: - Private

    private static func extractAppIcon(from appBundle: URL, plist: [String: Any]) async -> UIImage? {
        let fm = FileManager.default

        // Try CFBundleIcons → CFBundlePrimaryIcon → CFBundleIconFiles
        var iconName: String? = nil
        if let icons = plist["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            iconName = files.last
        }
        if iconName == nil {
            iconName = plist["CFBundleIconFile"] as? String
        }

        // Try common icon names
        let candidates = [iconName, "AppIcon60x60@2x", "AppIcon@2x", "Icon-60@2x", "Icon@2x", "icon", "Icon"]
            .compactMap { $0 }

        for name in candidates {
            for ext in ["", ".png"] {
                let iconPath = appBundle.appendingPathComponent(name + ext).path
                if fm.fileExists(atPath: iconPath),
                   let data = fm.contents(atPath: iconPath),
                   let image = UIImage(data: data) {
                    return image
                }
            }
        }

        // Fallback: find any .png in the root of the app bundle
        if let contents = try? fm.contentsOfDirectory(atPath: appBundle.path) {
            for file in contents where file.hasSuffix(".png") && file.lowercased().contains("icon") {
                let iconPath = appBundle.appendingPathComponent(file).path
                if let data = fm.contents(atPath: iconPath),
                   let image = UIImage(data: data) {
                    return image
                }
            }
        }

        return nil
    }
}
