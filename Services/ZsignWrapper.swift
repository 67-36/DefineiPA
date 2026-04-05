import Foundation
import ZsignSwift
import ZIPFoundation

// MARK: - Errors
enum SignError: LocalizedError {
    case noAppBundle
    case signingFailed(String?)
    case zipError(Error)
    case invalidIPA

    var errorDescription: String? {
        switch self {
        case .noAppBundle: return "No .app bundle found inside IPA Payload/"
        case .signingFailed(let msg): return "Signing failed: \(msg ?? "unknown error")"
        case .zipError(let e): return "ZIP error: \(e.localizedDescription)"
        case .invalidIPA: return "Invalid IPA file"
        }
    }
}

class ZsignWrapper {

    // MARK: - Sign IPA
    /// Signs an IPA file on-device using Zsign.
    /// - Returns: URL of the signed output IPA
    @MainActor
    static func sign(
        ipaURL: URL,
        p12URL: URL,
        p12Password: String,
        provisionURL: URL,
        outputURL: URL,
        bundleID: String? = nil,
        displayName: String? = nil,
        version: String? = nil,
        injectDylibs: [URL] = [],
        removePlugins: Bool = false,
        progressCallback: @escaping (String) -> Void
    ) async throws -> URL {
        progressCallback("Preparing temp directory...")
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("zsign_\(UUID().uuidString)")
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? fm.removeItem(at: tempDir)
        }

        progressCallback("Extracting IPA...")
        do {
            try fm.unzipItem(at: ipaURL, to: tempDir)
        } catch {
            throw SignError.zipError(error)
        }

        let payloadDir = tempDir.appendingPathComponent("Payload")
        let contents = try fm.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)
        guard let appBundle = contents.first(where: { $0.pathExtension == "app" }) else {
            throw SignError.noAppBundle
        }

        progressCallback("Found app bundle: \(appBundle.lastPathComponent)")

        // Inject dylibs
        for dylib in injectDylibs {
            let frameworksDir = appBundle.appendingPathComponent("Frameworks")
            try? fm.createDirectory(at: frameworksDir, withIntermediateDirectories: true)
            let dest = frameworksDir.appendingPathComponent(dylib.lastPathComponent)
            try? fm.copyItem(at: dylib, to: dest)
            progressCallback("Injected dylib: \(dylib.lastPathComponent)")
        }

        // Remove plugins
        if removePlugins {
            let pluginsDir = appBundle.appendingPathComponent("PlugIns")
            try? fm.removeItem(at: pluginsDir)
            progressCallback("Removed PlugIns")
        }

        progressCallback("Signing with Zsign...")
        let success = await withCheckedContinuation { continuation in
            Zsign.sign(
                appPath: appBundle.path,
                provisionPath: provisionURL.path,
                p12Path: p12URL.path,
                p12Password: p12Password,
                entitlementsPath: "",
                customIdentifier: bundleID ?? "",
                customName: displayName ?? "",
                customVersion: version ?? "",
                adhoc: false,
                removeProvision: false
            ) { ok, error in
                if let err = error {
                    progressCallback("Warning: \(err.localizedDescription)")
                }
                continuation.resume(returning: ok)
            }
        }

        if !success {
            throw SignError.signingFailed(nil)
        }

        progressCallback("Signing complete. Packaging IPA...")

        // Package back into IPA
        try? fm.removeItem(at: outputURL)
        do {
            try fm.zipItem(at: payloadDir, to: outputURL, shouldKeepParent: true)
        } catch {
            throw SignError.zipError(error)
        }

        progressCallback("Done! Output: \(outputURL.lastPathComponent)")
        return outputURL
    }

    // MARK: - Check revocation via Zsign
    static func checkRevokage(
        provisionURL: URL,
        p12URL: URL,
        p12Password: String,
        completion: @escaping (Int32, Date?, String?) -> Void
    ) {
        Zsign.checkRevokage(
            provisionPath: provisionURL.path,
            p12Path: p12URL.path,
            p12Password: p12Password
        ) { status, expirationDate, error in
            completion(status, expirationDate, error)
        }
    }
}
