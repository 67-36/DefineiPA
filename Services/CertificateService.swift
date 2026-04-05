import Foundation
import Security
import CryptoKit
import CommonCrypto

// MARK: - CertificateService

class CertificateService {

    enum CertError: LocalizedError {
        case wrongPassword
        case noIdentity
        case noCertificate
        case parseFailed

        var errorDescription: String? {
            switch self {
            case .wrongPassword: return "Wrong certificate password"
            case .noIdentity:    return "No identity found in certificate"
            case .noCertificate: return "No certificate found"
            case .parseFailed:   return "Failed to parse certificate"
            }
        }
    }

    // MARK: - Parse .p12 Certificate

    static func parseCertificate(p12URL: URL, password: String) throws -> CertificateInfo {
        let data = try Data(contentsOf: p12URL)
        let opts: NSDictionary = [kSecImportExportPassphrase as String: password]
        var rawItems: CFArray?
        let status = SecPKCS12Import(data as CFData, opts, &rawItems)

        guard status == errSecSuccess,
              let items = rawItems as? [[String: Any]],
              let firstItem = items.first else {
            throw status == errSecAuthFailed ? CertError.wrongPassword : CertError.parseFailed
        }
        guard let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity? else {
            throw CertError.noIdentity
        }

        var certRef: SecCertificate?
        SecIdentityCopyCertificate(identity, &certRef)
        guard let cert = certRef else { throw CertError.noCertificate }

        return extractCertInfo(from: cert)
    }

    // MARK: - Extract Certificate Info (iOS-compatible)

    static func extractCertInfo(from cert: SecCertificate) -> CertificateInfo {
        var info = CertificateInfo()

        // Subject CN — available on all iOS versions
        if let cn = SecCertificateCopySubjectSummary(cert) {
            info.subjectCN = cn as String
        }

        // SHA fingerprints from raw DER
        let derData = SecCertificateCopyData(cert) as Data
        info.sha1Fingerprint   = sha1(derData)
        info.sha256Fingerprint = sha256(derData)

        // Parse DER for all other fields
        let parsed = parseDER(Data(derData))
        info.teamName     = parsed.organizationName
        info.teamID       = parsed.organizationalUnit
        info.serialNumber = parsed.serialNumber
        info.issueDate    = parsed.notBefore
        info.expiryDate   = parsed.notAfter
        info.issuer       = parsed.issuerDescription

        // Use parsed CN if SecCertificateCopySubjectSummary returned empty
        if info.subjectCN.isEmpty, let cn = parsed.commonName {
            info.subjectCN = cn
        }

        return info
    }

    // MARK: - OCSP Check (opt-in)

    static func checkOCSP(certInfo: inout CertificateInfo, p12URL: URL, password: String) async {
        certInfo.ocspStatus = .checking
        do {
            let data = try Data(contentsOf: p12URL)
            let opts: NSDictionary = [kSecImportExportPassphrase as String: password]
            var rawItems: CFArray?
            let status = SecPKCS12Import(data as CFData, opts, &rawItems)
            guard status == errSecSuccess,
                  let items = rawItems as? [[String: Any]],
                  let first = items.first,
                  let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
                certInfo.ocspStatus = .unknown; return
            }
            var certRef: SecCertificate?
            SecIdentityCopyCertificate(identity, &certRef)
            guard let cert = certRef else { certInfo.ocspStatus = .unknown; return }

            let derData = SecCertificateCopyData(cert) as Data
            let parsed  = parseDER(Data(derData))

            guard let ocspURL = parsed.ocspURL else { certInfo.ocspStatus = .unknown; return }
            certInfo.ocspStatus = await performOCSP(url: ocspURL)
        } catch {
            certInfo.ocspStatus = .unknown
        }
    }

    // MARK: - Parse .mobileprovision

    static func parseProvision(url: URL) throws -> ProvisionInfo {
        let data = try Data(contentsOf: url)
        guard let xmlStart = data.range(of: Data("<?xml".utf8)),
              let xmlEnd   = data.range(of: Data("</plist>".utf8)) else {
            throw CertError.parseFailed
        }
        let xmlData = data[xmlStart.lowerBound...xmlEnd.upperBound]
        guard let plist = try? PropertyListSerialization.propertyList(
            from: xmlData, format: nil
        ) as? [String: Any] else { throw CertError.parseFailed }

        var p = ProvisionInfo()
        p.appID    = plist["AppIDName"]  as? String ?? ""
        p.teamName = plist["TeamName"]   as? String ?? ""
        if let exp = plist["ExpirationDate"] as? Date { p.expiryDate = exp }
        if let dev = plist["ProvisionedDevices"] as? [String] { p.deviceCount = dev.count }
        if let ent = plist["Entitlements"] as? [String: Any] {
            p.entitlements = ent.mapValues { "\($0)" }
        }
        return p
    }

    // MARK: - Private helpers

    private static func performOCSP(url: URL) async -> OCSPStatus {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/ocsp-request", forHTTPHeaderField: "Content-Type")
        req.timeoutInterval = 10
        do {
            let (_, resp) = try await URLSession.shared.data(for: req)
            if let h = resp as? HTTPURLResponse, h.statusCode == 200 || h.statusCode == 400 {
                return .valid
            }
        } catch {}
        return .unknown
    }

    private static func sha1(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: 20)
        data.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}

// MARK: - ASN.1 DER Parser (iOS-compatible, no macOS-only APIs)

private struct CertFields {
    var commonName:          String?
    var organizationName:    String  = ""
    var organizationalUnit:  String  = ""
    var issuerDescription:   String  = ""
    var serialNumber:        String  = ""
    var notBefore:           Date?
    var notAfter:            Date?
    var ocspURL:             URL?
}

private func parseDER(_ derData: Data) -> CertFields {
    var result = CertFields()
    let bytes = [UInt8](derData)
    var i = 0

    // Certificate ::= SEQUENCE { TBSCertificate, signatureAlgorithm, signature }
    guard skipTag(0x30, &i, bytes) else { return result }   // outer SEQUENCE

    // TBSCertificate ::= SEQUENCE { version, serialNumber, alg, issuer, validity, subject, ... }
    guard skipTag(0x30, &i, bytes) else { return result }   // TBSCertificate SEQUENCE

    // Optional version [0] EXPLICIT
    if i < bytes.count && bytes[i] == 0xA0 { skipTLV(&i, bytes) }

    // serialNumber INTEGER
    if i < bytes.count && bytes[i] == 0x02 {
        i += 1
        let len = derLen(&i, bytes)
        let end = min(i + len, bytes.count)
        result.serialNumber = bytes[i..<end].map { String(format: "%02X", $0) }.joined(separator: ":")
        i = end
    }

    skipTLV(&i, bytes)                                  // signature AlgorithmIdentifier

    // issuer Name
    result.issuerDescription = parseName(&i, bytes)

    // validity SEQUENCE
    if i < bytes.count && bytes[i] == 0x30 {
        i += 1; let vlen = derLen(&i, bytes); let vend = i + vlen
        result.notBefore = parseTime(&i, bytes)
        result.notAfter  = parseTime(&i, bytes)
        i = vend
    }

    // subject Name
    let (cn, org, ou) = parseNameDetail(&i, bytes)
    result.commonName         = cn
    result.organizationName   = org  ?? ""
    result.organizationalUnit = ou   ?? ""

    // Skip subjectPublicKeyInfo
    skipTLV(&i, bytes)

    // Extensions [3] EXPLICIT — optional, only in v3
    if i < bytes.count && bytes[i] == 0xA3 {
        i += 1; let elen = derLen(&i, bytes); let eend = i + elen
        result.ocspURL = parseOCSPFromExtensions(&i, bytes, eend)
        i = eend
    }

    return result
}

// MARK: - DER navigation helpers

private func skipTag(_ expected: UInt8, _ i: inout Int, _ bytes: [UInt8]) -> Bool {
    guard i < bytes.count, bytes[i] == expected else { return false }
    i += 1
    let len = derLen(&i, bytes)
    _ = len // length consumed but we stay inside
    return true
}

private func derLen(_ i: inout Int, _ bytes: [UInt8]) -> Int {
    guard i < bytes.count else { return 0 }
    let fb = bytes[i]; i += 1
    if fb & 0x80 == 0 { return Int(fb) }
    let n = Int(fb & 0x7F)
    guard n > 0, n <= 4, i + n <= bytes.count else { return 0 }
    var len = 0
    for _ in 0..<n { len = (len << 8) | Int(bytes[i]); i += 1 }
    return len
}

private func skipTLV(_ i: inout Int, _ bytes: [UInt8]) {
    guard i < bytes.count else { return }
    i += 1
    let len = derLen(&i, bytes)
    i = min(i + len, bytes.count)
}

// MARK: - Name parsing

private func parseName(_ i: inout Int, _ bytes: [UInt8]) -> String {
    let (cn, org, ou) = parseNameDetail(&i, bytes)
    var parts: [String] = []
    if let v = cn  { parts.append("CN=\(v)") }
    if let v = org { parts.append("O=\(v)")  }
    if let v = ou  { parts.append("OU=\(v)") }
    return parts.joined(separator: ", ")
}

private func parseNameDetail(_ i: inout Int, _ bytes: [UInt8])
    -> (cn: String?, org: String?, ou: String?)
{
    guard i < bytes.count, bytes[i] == 0x30 else { return (nil, nil, nil) }
    i += 1
    let nameLen = derLen(&i, bytes)
    let nameEnd = min(i + nameLen, bytes.count)
    var cn: String? = nil
    var org: String? = nil
    var ou: String? = nil

    while i < nameEnd {
        // RelativeDistinguishedName SET
        guard bytes[i] == 0x31 else { break }
        i += 1; let setLen = derLen(&i, bytes); let setEnd = min(i + setLen, bytes.count)

        // AttributeTypeAndValue SEQUENCE
        guard i < setEnd, bytes[i] == 0x30 else { i = setEnd; continue }
        i += 1; let attrLen = derLen(&i, bytes); let attrEnd = min(i + attrLen, bytes.count)

        // OID
        guard i < attrEnd, bytes[i] == 0x06 else { i = attrEnd; continue }
        i += 1; let oidLen = derLen(&i, bytes)
        guard i + oidLen <= bytes.count else { break }
        let oid = Array(bytes[i..<i + oidLen]); i += oidLen

        // String value (UTF8String 0x0C, PrintableString 0x13, IA5String 0x16, T61String 0x14)
        guard i < attrEnd else { continue }
        let vtag = bytes[i]; i += 1
        let vlen = derLen(&i, bytes)
        guard i + vlen <= bytes.count else { break }
        var val = ""
        if vtag == 0x1E { // BMPString: pairs of bytes forming UTF-16BE code units
            var utf16: [UInt16] = []
            var k = i
            while k + 1 < i + vlen && k + 1 < bytes.count {
                utf16.append(UInt16(bytes[k]) << 8 | UInt16(bytes[k + 1]))
                k += 2
            }
            val = String(decoding: utf16, as: UTF16.self)
        } else {
            val = String(bytes: bytes[i..<i + vlen], encoding: .utf8)
                ?? String(bytes: bytes[i..<i + vlen], encoding: .isoLatin1)
                ?? ""
        }
        i += vlen
        i = attrEnd

        if      oid == [85, 4, 3]  { cn  = val }
        else if oid == [85, 4, 10] { org = val }
        else if oid == [85, 4, 11] { ou  = val }

        i = setEnd
    }
    i = nameEnd
    return (cn, org, ou)
}

// MARK: - Time parsing

private func parseTime(_ i: inout Int, _ bytes: [UInt8]) -> Date? {
    guard i < bytes.count else { return nil }
    let tag = bytes[i]; guard tag == 0x17 || tag == 0x18 else { return nil }
    i += 1
    let len = derLen(&i, bytes)
    guard i + len <= bytes.count else { return nil }
    let str = String(bytes: bytes[i..<i+len], encoding: .ascii) ?? ""
    i += len

    let fmt = DateFormatter()
    fmt.locale   = Locale(identifier: "en_US_POSIX")
    fmt.timeZone = TimeZone(abbreviation: "UTC")
    if tag == 0x17 {        // UTCTime  "YYMMDDHHMMSSZ"
        fmt.dateFormat = "yyMMddHHmmssZ"
    } else {                // GeneralizedTime "YYYYMMDDHHMMSSZ"
        fmt.dateFormat = "yyyyMMddHHmmssZ"
    }
    return fmt.date(from: str)
}

// MARK: - OCSP URL from extensions

private func parseOCSPFromExtensions(_ i: inout Int, _ bytes: [UInt8], _ end: Int) -> URL? {
    // Extensions ::= SEQUENCE OF Extension { extnID OID, critical BOOL?, extnValue OCTET STRING }
    guard i < end, bytes[i] == 0x30 else { return nil }
    i += 1; _ = derLen(&i, bytes)

    // AIA OID: 1.3.6.1.5.5.7.1.1 → DER: 2B 06 01 05 05 07 01 01
    let aiaOID: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]

    while i < end {
        guard i < bytes.count, bytes[i] == 0x30 else { skipTLV(&i, bytes); continue }
        i += 1; let extLen = derLen(&i, bytes); let extEnd = min(i + extLen, bytes.count)

        // OID
        guard i < extEnd, bytes[i] == 0x06 else { i = extEnd; continue }
        i += 1; let oidLen = derLen(&i, bytes)
        let foundOID = Array(bytes[i..<min(i+oidLen, bytes.count)]); i += oidLen

        if foundOID != aiaOID { i = extEnd; continue }

        // Skip optional BOOL critical
        if i < extEnd && bytes[i] == 0x01 { skipTLV(&i, bytes) }

        // OCTET STRING containing the AIA value
        guard i < extEnd, bytes[i] == 0x04 else { i = extEnd; continue }
        i += 1; let osLen = derLen(&i, bytes); let osEnd = min(i + osLen, bytes.count)

        // AIA ::= SEQUENCE OF AccessDescription
        guard i < osEnd, bytes[i] == 0x30 else { i = osEnd; continue }
        i += 1; _ = derLen(&i, bytes)

        while i < osEnd {
            // AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
            guard i < bytes.count, bytes[i] == 0x30 else { break }
            i += 1; let adLen = derLen(&i, bytes); let adEnd = min(i + adLen, bytes.count)

            // accessMethod OID
            guard i < adEnd, bytes[i] == 0x06 else { i = adEnd; continue }
            i += 1; let amLen = derLen(&i, bytes)
            // OCSP OID: 1.3.6.1.5.5.7.48.1 → 2B 06 01 05 05 07 30 01
            let ocspOID: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]
            let amOID = Array(bytes[i..<min(i+amLen, bytes.count)]); i += amLen

            guard i < adEnd else { i = adEnd; continue }
            if amOID == ocspOID {
                // accessLocation: [6] IA5String (context tag for uniformResourceIdentifier)
                if bytes[i] == 0x86 {
                    i += 1; let uriLen = derLen(&i, bytes)
                    let uriStr = String(bytes: bytes[i..<min(i+uriLen, bytes.count)], encoding: .ascii) ?? ""
                    i += uriLen
                    return URL(string: uriStr)
                }
            }
            i = adEnd
        }
        return nil
    }
    return nil
}
