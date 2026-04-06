import Foundation
// signtool_inflate_raw() is available via Bridging/SignTool-Bridging-Header.h

// MARK: - ZIP Error

enum ZIPError: LocalizedError {
    case invalidFormat
    case decompressionFailed(Int32)
    case ioError(Error)

    var errorDescription: String? {
        switch self {
        case .invalidFormat:              return "Not a valid ZIP / IPA file"
        case .decompressionFailed(let c): return "Decompression failed (zlib code \(c))"
        case .ioError(let e):             return e.localizedDescription
        }
    }
}

// MARK: - ZIPHelper

/// Minimal ZIP reader + writer that depends ONLY on Foundation and the
/// system zlib library (always present on iOS), with no third-party packages.
struct ZIPHelper {

    // MARK: - Unzip

    /// Extract a ZIP / IPA archive at `source` into `destination` directory.
    /// Supports method 0 (Stored) and method 8 (DEFLATE / raw).
    static func unzip(at source: URL, to destination: URL) throws {
        let data  = try Data(contentsOf: source)
        let bytes = [UInt8](data)
        let fm    = FileManager.default

        try fm.createDirectory(at: destination, withIntermediateDirectories: true)

        // 1. Locate End-of-Central-Directory record
        guard let eocdOff = findEOCD(bytes) else { throw ZIPError.invalidFormat }

        let entryCount = Int(u16(bytes, eocdOff + 10))
        let cdStart    = Int(u32(bytes, eocdOff + 16))

        // 2. Walk the Central Directory
        var pos = cdStart
        for _ in 0..<entryCount {
            guard pos + 46 <= bytes.count,
                  u32(bytes, pos) == 0x02014B50 else { break }   // central dir sig

            let method     = Int(u16(bytes, pos + 10))
            let cSize      = Int(u32(bytes, pos + 20))
            let uSize      = Int(u32(bytes, pos + 24))
            let nameLen    = Int(u16(bytes, pos + 28))
            let extraLen   = Int(u16(bytes, pos + 30))
            let commentLen = Int(u16(bytes, pos + 32))
            let lhOffset   = Int(u32(bytes, pos + 42))

            let nameEnd = pos + 46 + nameLen
            guard nameEnd <= bytes.count else { break }
            let name = String(bytes: bytes[(pos + 46)..<nameEnd], encoding: .utf8) ?? ""
            pos = nameEnd + extraLen + commentLen

            if name.hasSuffix("/") {                // directory entry
                try? fm.createDirectory(
                    at: destination.appendingPathComponent(name),
                    withIntermediateDirectories: true)
                continue
            }

            // Navigate to the matching local file header
            guard lhOffset + 30 <= bytes.count,
                  u32(bytes, lhOffset) == 0x04034B50 else { continue } // local file sig

            let lhNameLen  = Int(u16(bytes, lhOffset + 26))
            let lhExtraLen = Int(u16(bytes, lhOffset + 28))
            let dataStart  = lhOffset + 30 + lhNameLen + lhExtraLen
            guard dataStart + cSize <= bytes.count else { continue }

            let compressed = Data(bytes[dataStart..<(dataStart + cSize)])

            let fileData: Data
            switch method {
            case 0:   fileData = compressed                                   // Stored
            case 8:   fileData = try inflateRaw(compressed, uSize: uSize)    // DEFLATE
            default:  continue                                                 // skip
            }

            let outURL = destination.appendingPathComponent(name)
            try? fm.createDirectory(
                at: outURL.deletingLastPathComponent(),
                withIntermediateDirectories: true)
            try fileData.write(to: outURL)
        }
    }

    // MARK: - Zip  (Stored — no compression, valid for IPA re-packaging)

    /// Zip the contents of `directory` into `destination`.
    /// Uses method 0 (Stored, no compression) — perfectly valid for IPA files.
    static func zip(directory: URL, to destination: URL, keepParent: Bool = true) throws {
        let fm      = FileManager.default
        let srcPath = directory.path
        let prefix  = keepParent ? (directory.lastPathComponent + "/") : ""

        var localPart  = Data()
        var centralDir = Data()
        var count      = 0

        guard let enumerator = fm.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        for case let url as URL in enumerator {
            var isDir: ObjCBool = false
            fm.fileExists(atPath: url.path, isDirectory: &isDir)

            let rawRel = String(url.path.dropFirst(min(srcPath.count + 1, url.path.count)))
            guard !rawRel.isEmpty else { continue }
            let entryName = prefix + (isDir.boolValue ? rawRel + "/" : rawRel)
            let nameBytes = Array(entryName.utf8)

            let fileBytes = isDir.boolValue
                ? Data()
                : ((try? Data(contentsOf: url)) ?? Data())

            let crc    = zipCRC32(fileBytes)
            let lhOff  = UInt32(localPart.count)
            let fSize  = UInt32(fileBytes.count)

            // Local file header
            localPart += sig(0x04034B50)
            localPart += w16(20)            // version needed
            localPart += w16(0)             // flags
            localPart += w16(0)             // method: Stored
            localPart += w16(0) + w16(0)   // mod time / date
            localPart += w32(crc)
            localPart += w32(fSize)         // compressed size
            localPart += w32(fSize)         // uncompressed size
            localPart += w16(UInt16(nameBytes.count))
            localPart += w16(0)             // extra field length
            localPart += Data(nameBytes)
            localPart += fileBytes

            // Central directory record
            centralDir += sig(0x02014B50)
            centralDir += w16(20) + w16(20)              // version made / needed
            centralDir += w16(0) + w16(0)                // flags / method: Stored
            centralDir += w16(0) + w16(0)                // mod time / date
            centralDir += w32(crc)
            centralDir += w32(fSize) + w32(fSize)        // compressed / uncompressed
            centralDir += w16(UInt16(nameBytes.count))
            centralDir += w16(0) + w16(0)                // extra / comment length
            centralDir += w16(0) + w16(0)                // disk / internal attrs
            centralDir += w32(0)                         // external attrs
            centralDir += w32(lhOff)
            centralDir += Data(nameBytes)
            count += 1
        }

        let cdOffset = UInt32(localPart.count)
        var result   = localPart + centralDir

        // End of Central Directory
        result += sig(0x06054B50)
        result += w16(0) + w16(0)                        // disk / cd-start disk
        result += w16(UInt16(count)) + w16(UInt16(count))
        result += w32(UInt32(centralDir.count))
        result += w32(cdOffset)
        result += w16(0)                                 // comment length

        try result.write(to: destination)
    }

    // MARK: - Raw-DEFLATE via C wrapper (signtool_inflate_raw in bridging header)

    private static func inflateRaw(_ compressed: Data, uSize: Int) throws -> Data {
        // Allocate output buffer with generous headroom
        let bufSize = max(uSize + 1024, compressed.count * 10, 4096)
        var output  = [UInt8](repeating: 0, count: bufSize)
        var outLen  = UInt32(0)

        // Both closures are non-throwing; errors are communicated via return code
        let ret: Int32 = compressed.withUnsafeBytes { srcBuf in
            guard let src = srcBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
            else { return Int32(-99) }

            return output.withUnsafeMutableBytes { dstBuf -> Int32 in
                guard let dst = dstBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else { return Int32(-99) }

                return signtool_inflate_raw(
                    src, UInt32(compressed.count),
                    dst, UInt32(bufSize),
                    &outLen
                )
            }
        }

        guard ret == Z_OK else { throw ZIPError.decompressionFailed(ret) }
        return Data(output.prefix(Int(outLen)))
    }

    // MARK: - Binary helpers

    private static func findEOCD(_ b: [UInt8]) -> Int? {
        guard b.count >= 22 else { return nil }
        var i = b.count - 22
        while i >= 0 {
            if u32(b, i) == 0x06054B50 { return i }
            i -= 1
        }
        return nil
    }

    private static func u16(_ b: [UInt8], _ i: Int) -> UInt16 {
        guard i + 1 < b.count else { return 0 }
        return UInt16(b[i]) | (UInt16(b[i+1]) << 8)
    }

    private static func u32(_ b: [UInt8], _ i: Int) -> UInt32 {
        guard i + 3 < b.count else { return 0 }
        return UInt32(b[i]) | (UInt32(b[i+1]) << 8)
             | (UInt32(b[i+2]) << 16) | (UInt32(b[i+3]) << 24)
    }

    // CRC-32 per ZIP spec (ISO 3309 polynomial)
    private static func zipCRC32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                let mask = UInt32(bitPattern: -Int32(bitPattern: crc & 1))
                crc = (crc >> 1) ^ (0xEDB88320 & mask)
            }
        }
        return crc ^ 0xFFFFFFFF
    }

    // Little-endian write helpers
    private static func w16(_ v: UInt16) -> Data {
        Data([UInt8(v & 0xFF), UInt8(v >> 8)])
    }
    private static func w32(_ v: UInt32) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v>>8) & 0xFF),
              UInt8((v>>16) & 0xFF), UInt8(v >> 24)])
    }
    private static func sig(_ v: UInt32) -> Data { w32(v) }
}

// Data += convenience (file-private)
private func += (lhs: inout Data, rhs: Data) { lhs.append(rhs) }
