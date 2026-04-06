import Foundation
import ZsignSwift

// MARK: - Errors
enum SignError: LocalizedError {
    case noAppBundle
    case signingFailed(String?)
    case zipError(Error)
    case invalidIPA

    var errorDescription: String? {
        switch self {
        case .noAppBundle:             return "No .app bundle found inside IPA Payload/"
        case .signingFailed(let msg):  return "Signing failed: \(msg ?? "unknown error")"
        case .zipError(let e):         return "ZIP error: \(e.localizedDescription)"
        case .invalidIPA:              return "Invalid IPA file"
        }
    }
}

class ZsignWrapper {

    // MARK: - Sign IPA on-device

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

        progressCallback("Preparing temp directory…")
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
            .appendingPathComponent("zsign_\(UUID().uuidString)")
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer { try? fm.removeItem(at: tempDir) }

        // 1. Extract IPA
        progressCallback("Extracting IPA…")
        do {
            try ZIPHelper.unzip(at: ipaURL, to: tempDir)
        } catch {
            throw SignError.zipError(error)
        }

        let payloadDir = tempDir.appendingPathComponent("Payload")
        let contents   = try fm.contentsOfDirectory(
            at: payloadDir, includingPropertiesForKeys: nil)
        guard let appBundle = contents.first(where: { $0.pathExtension == "app" }) else {
            throw SignError.noAppBundle
        }
        progressCallback("Found: \(appBundle.lastPathComponent)")

        // 2. Inject dylibs
        for dylib in injectDylibs {
            let fwDir = appBundle.appendingPathComponent("Frameworks")
            try? fm.createDirectory(at: fwDir, withIntermediateDirectories: true)
            let dest = fwDir.appendingPathComponent(dylib.lastPathComponent)
            try? fm.copyItem(at: dylib, to: dest)
            progressCallback("Injected: \(dylib.lastPathComponent)")
        }

        // 3. Remove plugins if requested
        if removePlugins {
            try? fm.removeItem(at: appBundle.appendingPathComponent("PlugIns"))
            progressCallback("Removed PlugIns")
        }

        // 4. Sign with Zsign
        progressCallback("Signing…")
        let success = await withCheckedContinuation { cont in
            Zsign.sign(
                appPath:          appBundle.path,
                provisionPath:    provisionURL.path,
                p12Path:          p12URL.path,
                p12Password:      p12Password,
                entitlementsPath: "",
                customIdentifier: bundleID    ?? "",
                customName:       displayName ?? "",
                customVersion:    version     ?? "",
                adhoc:            false,
                removeProvision:  false
            ) { ok, error in
                if let err = error { progressCallback("Warning: \(err.localizedDescription)") }
                cont.resume(returning: ok)
            }
        }

        guard success else { throw SignError.signingFailed(nil) }

        // 5. Re-package as IPA
        progressCallback("Packaging IPA…")
        try? fm.removeItem(at: outputURL)
        do {
            try ZIPHelper.zip(directory: payloadDir, to: outputURL, keepParent: true)
        } catch {
            throw SignError.zipError(error)
        }

        progressCallback("Done: \(outputURL.lastPathComponent)")
        return outputURL
    }

    // MARK: - OCSP check via Zsign

    static func checkRevokage(
        provisionURL: URL,
        p12URL: URL,
        p12Password: String,
        completion: @escaping (Int32, Date?, String?) -> Void
    ) {
        Zsign.checkRevokage(
            provisionPath: provisionURL.path,
            p12Path:       p12URL.path,
            p12Password:   p12Password
        ) { status, expirationDate, error in
            completion(status, expirationDate, error)
        }
    }
}
