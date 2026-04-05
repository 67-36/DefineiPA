import Foundation

struct CertificateInfo: Identifiable {
    let id = UUID()

    var subjectCN: String = ""
    var teamName: String = ""
    var teamID: String = ""
    var serialNumber: String = ""
    var issueDate: Date?
    var expiryDate: Date?
    var issuer: String = ""
    var sha1Fingerprint: String = ""
    var sha256Fingerprint: String = ""
    var ocspStatus: OCSPStatus = .unknown

    var daysRemaining: Int? {
        guard let expiry = expiryDate else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: expiry).day
    }

    var isExpired: Bool {
        guard let expiry = expiryDate else { return false }
        return expiry < Date()
    }

    var displayStatus: String {
        switch ocspStatus {
        case .valid: return isExpired ? "Expired" : "Valid"
        case .revoked: return "Revoked"
        case .unknown: return isExpired ? "Expired" : "Unknown"
        case .checking: return "Checking..."
        }
    }
}

enum OCSPStatus: Equatable {
    case valid
    case revoked(date: Date?)
    case unknown
    case checking
}

struct ProvisionInfo: Identifiable {
    let id = UUID()
    var appID: String = ""
    var teamName: String = ""
    var expiryDate: Date?
    var deviceCount: Int = 0
    var entitlements: [String: String] = [:]
    var isExpired: Bool {
        guard let expiry = expiryDate else { return false }
        return expiry < Date()
    }
}
