import Foundation

struct SigningJob: Identifiable, Codable {
    var id: UUID = UUID()
    var timestamp: Date = Date()
    var inputIPAName: String = ""
    var certificateName: String = ""
    var outputIPAName: String = ""
    var success: Bool = false
    var errorMessage: String?

    var statusIcon: String {
        success ? "checkmark.circle.fill" : "xmark.circle.fill"
    }
}
