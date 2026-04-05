import Foundation
import UIKit

struct IPAInfo: Identifiable {
    let id = UUID()
    var appName: String = ""
    var bundleID: String = ""
    var version: String = ""
    var buildNumber: String = ""
    var minimumOSVersion: String = ""
    var fileSize: Int64 = 0
    var appIcon: UIImage?
    var url: URL?

    var fileSizeFormatted: String {
        ByteCountFormatter.string(fromByteCount: fileSize, countStyle: .file)
    }
}
