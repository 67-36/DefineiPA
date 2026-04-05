import Foundation
import Security

class KeychainService {

    private static let service = "com.astear17.signtool"

    static func save(password: String, for key: String) {
        let data = Data(password.utf8)
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String:   data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func load(for key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let str = String(data: data, encoding: .utf8) else { return nil }
        return str
    }

    static func delete(for key: String) {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Saved Certificate Pair
struct SavedCertPair: Identifiable, Codable {
    var id: UUID = UUID()
    var name: String
    var p12Path: String
    var provisionPath: String
    var sha256Key: String // Keychain key for password

    var p12URL: URL { URL(fileURLWithPath: p12Path) }
    var provisionURL: URL { URL(fileURLWithPath: provisionPath) }
}

class CertificateStore {
    static let shared = CertificateStore()
    private let defaultsKey = "saved_cert_pairs"

    var pairs: [SavedCertPair] {
        get {
            guard let data = UserDefaults.standard.data(forKey: defaultsKey),
                  let decoded = try? JSONDecoder().decode([SavedCertPair].self, from: data) else {
                return []
            }
            return decoded
        }
        set {
            if let data = try? JSONEncoder().encode(newValue) {
                UserDefaults.standard.set(data, forKey: defaultsKey)
            }
        }
    }

    func add(_ pair: SavedCertPair) {
        var all = pairs
        all.append(pair)
        pairs = all
    }

    func delete(_ pair: SavedCertPair) {
        pairs = pairs.filter { $0.id != pair.id }
        KeychainService.delete(for: pair.sha256Key)
    }
}

// MARK: - Signing Job History
class SigningHistory {
    static let shared = SigningHistory()
    private let defaultsKey = "signing_jobs"

    var jobs: [SigningJob] {
        get {
            guard let data = UserDefaults.standard.data(forKey: defaultsKey),
                  let decoded = try? JSONDecoder().decode([SigningJob].self, from: data) else {
                return []
            }
            return decoded
        }
        set {
            let limited = Array(newValue.prefix(20))
            if let data = try? JSONEncoder().encode(limited) {
                UserDefaults.standard.set(data, forKey: defaultsKey)
            }
        }
    }

    func add(_ job: SigningJob) {
        var all = jobs
        all.insert(job, at: 0)
        jobs = all
    }
}
