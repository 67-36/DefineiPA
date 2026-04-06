import Foundation
import UIKit

class IPAParser {

    enum ParseError: LocalizedError {
        case invalidIPA, noPayload, noAppBundle, noPlist

        var errorDescription: String? {
            switch self {
            case .invalidIPA:   return "Not a valid IPA file"
            case .noPayload:    return "No Payload directory found in IPA"
            case .noAppBundle:  return "No .app bundle found in Payload"
            case .noPlist:      return "Could not read Info.plist"
            }
        }
    }

    static func parseIPA(url: URL) async throws -> IPAInfo {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
            .appendingPathComponent("ipa_parse_\(UUID().uuidString)")
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        try ZIPHelper.unzip(at: url, to: tempDir)

        let payloadDir = tempDir.appendingPathComponent("Payload")
        guard fm.fileExists(atPath: payloadDir.path) else { throw ParseError.noPayload }

        let contents = try fm.contentsOfDirectory(
            at: payloadDir, includingPropertiesForKeys: nil)
        guard let appBundle = contents.first(where: { $0.pathExtension == "app" }) else {
            throw ParseError.noAppBundle
        }

        let plistURL = appBundle.appendingPathComponent("Info.plist")
        guard let plistData = fm.contents(atPath: plistURL.path),
              let plist = try? PropertyListSerialization
                .propertyList(from: plistData, format: nil) as? [String: Any]
        else { throw ParseError.noPlist }

        var info = IPAInfo()
        info.url           = url
        info.appName       = plist["CFBundleDisplayName"] as? String
                          ?? plist["CFBundleName"]        as? String
                          ?? appBundle.deletingPathExtension().lastPathComponent
        info.bundleID      = plist["CFBundleIdentifier"]       as? String ?? ""
        info.version       = plist["CFBundleShortVersionString"] as? String ?? ""
        info.buildNumber   = plist["CFBundleVersion"]          as? String ?? ""
        info.minimumOSVersion = plist["MinimumOSVersion"]      as? String ?? ""

        if let attrs = try? fm.attributesOfItem(atPath: url.path) {
            info.fileSize = attrs[.size] as? Int64 ?? 0
        }

        info.appIcon = await extractAppIcon(from: appBundle, plist: plist)
        return info
    }

    // MARK: - Private

    private static func extractAppIcon(
        from appBundle: URL,
        plist: [String: Any]
    ) async -> UIImage? {
        let fm = FileManager.default
        var candidates: [String] = []

        if let icons   = plist["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files   = primary["CFBundleIconFiles"] as? [String] {
            candidates += files
        }
        if let name = plist["CFBundleIconFile"] as? String { candidates.append(name) }
        candidates += ["AppIcon60x60@2x", "AppIcon@2x", "Icon-60@2x", "Icon@2x", "icon", "Icon"]

        for name in candidates {
            for ext in ["", ".png"] {
                let path = appBundle.appendingPathComponent(name + ext).path
                if fm.fileExists(atPath: path),
                   let data = fm.contents(atPath: path),
                   let img  = UIImage(data: data) { return img }
            }
        }

        if let contents = try? fm.contentsOfDirectory(atPath: appBundle.path) {
            for file in contents where file.hasSuffix(".png") && file.lowercased().contains("icon") {
                let path = appBundle.appendingPathComponent(file).path
                if let data = fm.contents(atPath: path), let img = UIImage(data: data) { return img }
            }
        }
        return nil
    }
}
