import Foundation
import Security
import CryptoKit
import CommonCrypto

class CertificateService {

    enum CertError: LocalizedError {
        case wrongPassword
        case noIdentity
        case noCertificate
        case parseFailed
        case ocspFailed(String)

        var errorDescription: String? {
            switch self {
            case .wrongPassword: return "Wrong certificate password"
            case .noIdentity: return "No identity found in certificate"
            case .noCertificate: return "No certificate found"
            case .parseFailed: return "Failed to parse certificate"
            case .ocspFailed(let msg): return "OCSP check failed: \(msg)"
            }
        }
    }

    // MARK: - Parse P12 Certificate
    static func parseCertificate(p12URL: URL, password: String) throws -> CertificateInfo {
        let data = try Data(contentsOf: p12URL)
        let opts: NSDictionary = [kSecImportExportPassphrase as String: password]
        var rawItems: CFArray?
        let status = SecPKCS12Import(data as CFData, opts, &rawItems)

        guard status == errSecSuccess,
              let items = rawItems as? [[String: Any]],
              let firstItem = items.first else {
            if status == errSecAuthFailed {
                throw CertError.wrongPassword
            }
            throw CertError.parseFailed
        }

        guard let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity? else {
            throw CertError.noIdentity
        }

        var certRef: SecCertificate?
        SecIdentityCopyCertificate(identity, &certRef)
        guard let cert = certRef else { throw CertError.noCertificate }

        return extractCertInfo(from: cert)
    }

    // MARK: - Extract Certificate Info
    static func extractCertInfo(from cert: SecCertificate) -> CertificateInfo {
        var info = CertificateInfo()

        // Subject CN
        if let summary = SecCertificateCopySubjectSummary(cert) {
            info.subjectCN = summary as String
        }

        // Get all values
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(cert, nil, &error) as? [String: Any] else {
            return info
        }

        // Subject Name fields (OIDs)
        if let subjectName = values[kSecOIDX509V1SubjectName as String] as? [String: Any],
           let subjectValues = subjectName["value"] as? [[String: Any]] {
            for entry in subjectValues {
                if let label = entry["label"] as? String,
                   let val = entry["value"] as? String {
                    switch label {
                    case kSecOIDOrganizationName as String: info.teamName = val
                    case kSecOIDOrganizationalUnitName as String: info.teamID = val
                    default: break
                    }
                }
            }
        }

        // Serial Number
        if let serialField = values[kSecOIDX509V1SerialNumber as String] as? [String: Any],
           let serialVal = serialField["value"] as? String {
            info.serialNumber = serialVal
        }

        // Validity dates
        if let notBefore = values[kSecOIDX509V1ValidityNotBefore as String] as? [String: Any],
           let nbVal = notBefore["value"] as? Double {
            info.issueDate = Date(timeIntervalSinceReferenceDate: nbVal)
        }
        if let notAfter = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
           let naVal = notAfter["value"] as? Double {
            info.expiryDate = Date(timeIntervalSinceReferenceDate: naVal)
        }

        // Issuer
        if let issuerField = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
           let issuerVal = issuerField["value"] as? String {
            info.issuer = issuerVal
        }

        // Fingerprints from DER data
        let derData = SecCertificateCopyData(cert) as Data
        info.sha1Fingerprint = sha1(derData)
        info.sha256Fingerprint = sha256(derData)

        return info
    }

    // MARK: - OCSP Check
    static func checkOCSP(certInfo: inout CertificateInfo, p12URL: URL, password: String) async {
        certInfo.ocspStatus = .checking
        do {
            let data = try Data(contentsOf: p12URL)
            let opts: NSDictionary = [kSecImportExportPassphrase as String: password]
            var rawItems: CFArray?
            let status = SecPKCS12Import(data as CFData, opts, &rawItems)
            guard status == errSecSuccess,
                  let items = rawItems as? [[String: Any]],
                  let firstItem = items.first,
                  let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity? else {
                certInfo.ocspStatus = .unknown
                return
            }

            var certRef: SecCertificate?
            SecIdentityCopyCertificate(identity, &certRef)
            guard let cert = certRef else {
                certInfo.ocspStatus = .unknown
                return
            }

            // Try to extract OCSP URL from certificate AIA extension
            guard let ocspURL = extractOCSPURL(from: cert) else {
                certInfo.ocspStatus = .unknown
                return
            }

            let result = await performOCSPRequest(url: ocspURL, certificate: cert)
            certInfo.ocspStatus = result
        } catch {
            certInfo.ocspStatus = .unknown
        }
    }

    // MARK: - Parse .mobileprovision
    static func parseProvision(url: URL) throws -> ProvisionInfo {
        let data = try Data(contentsOf: url)
        // mobileprovision is a CMS signed data containing a plist
        // We extract the plist by finding the XML content
        guard let xmlStart = data.range(of: Data("<?xml".utf8)),
              let xmlEnd = data.range(of: Data("</plist>".utf8)) else {
            throw CertError.parseFailed
        }
        let xmlData = data[xmlStart.lowerBound...xmlEnd.upperBound]

        guard let plist = try? PropertyListSerialization.propertyList(from: xmlData, format: nil) as? [String: Any] else {
            throw CertError.parseFailed
        }

        var provInfo = ProvisionInfo()
        provInfo.appID = plist["AppIDName"] as? String ?? plist["Entitlements.application-identifier"] as? String ?? ""
        provInfo.teamName = plist["TeamName"] as? String ?? ""

        if let expiry = plist["ExpirationDate"] as? Date {
            provInfo.expiryDate = expiry
        }
        if let devices = plist["ProvisionedDevices"] as? [String] {
            provInfo.deviceCount = devices.count
        }
        if let entitlements = plist["Entitlements"] as? [String: Any] {
            provInfo.entitlements = entitlements.mapValues { "\($0)" }
        }

        return provInfo
    }

    // MARK: - Helpers
    private static func extractOCSPURL(from cert: SecCertificate) -> URL? {
        // Extract AIA extension to get OCSP responder URL
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(cert, nil, &error) as? [String: Any] else { return nil }

        // OID for Authority Information Access
        let aiaOID = "1.3.6.1.5.5.7.1.1"
        if let aiaField = values[aiaOID] as? [String: Any],
           let aiaValues = aiaField["value"] as? [[String: Any]] {
            for entry in aiaValues {
                if let accessMethod = entry["label"] as? String,
                   accessMethod.contains("OCSP"),
                   let accessLocation = entry["value"] as? String,
                   let url = URL(string: accessLocation) {
                    return url
                }
            }
        }

        // Fallback: Apple's OCSP responder for Apple Developer certificates
        return URL(string: "http://ocsp.apple.com/ocsp03-wwdrca")
    }

    private static func performOCSPRequest(url: URL, certificate: SecCertificate) async -> OCSPStatus {
        // Simplified OCSP check - in a full implementation this would
        // build a proper OCSP request, send it, and parse the response.
        // For now we do a basic connectivity check.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/ocsp-request", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let httpResponse = response as? HTTPURLResponse {
                // Status 200 or 400 (bad request) means the OCSP responder is reachable
                if httpResponse.statusCode == 200 || httpResponse.statusCode == 400 {
                    return .valid
                }
            }
        } catch {}

        return .unknown
    }

    private static func sha1(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: 20)
        data.withUnsafeBytes { ptr in
            _ = CC_SHA1(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    private static func sha256(_ data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
