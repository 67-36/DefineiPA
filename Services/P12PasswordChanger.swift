import Foundation
import Security
import CryptoKit

class P12PasswordChanger {

    enum P12Error: LocalizedError {
        case wrongPassword
        case invalidFormat
        case exportFailed(OSStatus)
        case writeError(Error)
        case notSupportedOnDevice

        var errorDescription: String? {
            switch self {
            case .wrongPassword: return "Wrong current password"
            case .invalidFormat: return "File is not a valid PKCS12 certificate"
            case .exportFailed(let status): return "Export failed (error \(status))"
            case .writeError(let e): return "Write error: \(e.localizedDescription)"
            case .notSupportedOnDevice: return "Re-export requires developer-signed build. Jailbreak or use macOS to change password."
            }
        }
    }

    /// Change the password of a .p12 file.
    /// On iOS, uses SecPKCS12Import + SecItemExport.
    /// NOTE: SecItemExport for identities requires the app to be code-signed with
    /// appropriate entitlements or run on a jailbroken device / developer build.
    static func changePassword(
        p12URL: URL,
        oldPassword: String,
        newPassword: String,
        outputURL: URL
    ) throws {
        let p12Data = try Data(contentsOf: p12URL)

        // Step 1: Import with old password to verify it
        let importOpts: NSDictionary = [kSecImportExportPassphrase as String: oldPassword]
        var importItems: CFArray?
        let importStatus = SecPKCS12Import(p12Data as CFData, importOpts, &importItems)

        guard importStatus == errSecSuccess else {
            if importStatus == errSecAuthFailed {
                throw P12Error.wrongPassword
            }
            throw P12Error.invalidFormat
        }

        guard let items = importItems as? [[String: Any]],
              let firstItem = items.first,
              let identity = firstItem[kSecImportItemIdentity as String] as? SecIdentity else {
            throw P12Error.invalidFormat
        }

        // Step 2: Re-export with new password
        var exportedData: CFData?
        var exportParams = SecItemImportExportKeyParameters()
        exportParams.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)

        let newPassRef = newPassword as NSString
        let retainedPass = Unmanaged.passRetained(newPassRef)
        exportParams.passphrase = retainedPass.toOpaque()
        defer { retainedPass.release() }

        let exportStatus = SecItemExport(
            identity as CFTypeRef,
            .pkcs12,
            [],
            &exportParams,
            &exportedData
        )

        guard exportStatus == errSecSuccess, let outData = exportedData as Data? else {
            // If export failed due to permission, show helpful error
            if exportStatus == errSecParam || exportStatus == errSecUnimplemented {
                throw P12Error.notSupportedOnDevice
            }
            throw P12Error.exportFailed(exportStatus)
        }

        // Step 3: Write to output file
        do {
            try outData.write(to: outputURL)
        } catch {
            throw P12Error.writeError(error)
        }
    }

    /// Compute SHA256 of file data (used as a keychain key for passwords)
    static func sha256Key(for url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}
