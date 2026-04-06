import Foundation
// zlib C functions are available via Bridging/SignTool-Bridging-Header.h

// MARK: - ZIP Error

enum ZIPError: LocalizedError {
    case invalidFormat
    case decompressionFailed(Int32)
    case ioError(Error)

    var errorDescription: String? {
        switch self {
        case .invalidFormat:             return "Not a valid ZIP/IPA file"
        case .decompressionFailed(let c): return "DEFLATE decompression failed (code \(c))"
        case .ioError(let e):            return e.localizedDescription
        }
    }
}

// MARK: - ZIPHelper  (no external dependencies — uses system libz)

struct ZIPHelper {

    // MARK: - Unzip

    /// Extract a ZIP/IPA file to `destination`.
    /// Supports method 0 (Stored) and method 8 (DEFLATE).
    static func unzip(at source: URL, to destination: URL) throws {
        let data = try Data(contentsOf: source)
        let bytes = [UInt8](data)
        let fm = FileManager.default

        try fm.createDirectory(at: destination, withIntermediateDirectories: true)

        // 1. Locate the End-of-Central-Directory record
        guard let eocdOff = findEOCD(bytes) else { throw ZIPError.invalidFormat }

        let entryCount = Int(read16LE(bytes, eocdOff + 10))
        let cdOff      = Int(read32LE(bytes, eocdOff + 16))

        // 2. Walk Central Directory entries
        var pos = cdOff
        for _ in 0..<entryCount {
            guard pos + 46 <= bytes.count,
                  read32LE(bytes, pos) == 0x02014B50 else { break }

            let method     = Int(read16LE(bytes, pos + 10))
            let cSize      = Int(read32LE(bytes, pos + 20))
            let uSize      = Int(read32LE(bytes, pos + 24))
            let nameLen    = Int(read16LE(bytes, pos + 28))
            let extraLen   = Int(read16LE(bytes, pos + 30))
            let commentLen = Int(read16LE(bytes, pos + 32))
            let lhOff      = Int(read32LE(bytes, pos + 42))

            let nameEnd = pos + 46 + nameLen
            guard nameEnd <= bytes.count else { break }
            let name = String(bytes: bytes[(pos+46)..<nameEnd], encoding: .utf8) ?? ""
            pos = nameEnd + extraLen + commentLen

            // Directory entry
            if name.hasSuffix("/") {
                try? fm.createDirectory(
                    at: destination.appendingPathComponent(name),
                    withIntermediateDirectories: true)
                continue
            }

            // File entry: navigate to local file header
            guard lhOff + 30 <= bytes.count,
                  read32LE(bytes, lhOff) == 0x04034B50 else { continue }

            let lhNameLen  = Int(read16LE(bytes, lhOff + 26))
            let lhExtraLen = Int(read16LE(bytes, lhOff + 28))
            let dataStart  = lhOff + 30 + lhNameLen + lhExtraLen
            let dataEnd    = dataStart + cSize
            guard dataEnd <= bytes.count else { continue }

            let compressed = Data(bytes[dataStart..<dataEnd])

            let fileData: Data
            switch method {
            case 0:  // Stored
                fileData = compressed
            case 8:  // DEFLATE (raw)
                fileData = try inflateRaw(compressed, uncompressedSize: uSize)
            default:
                continue // skip unsupported methods
            }

            let outURL = destination.appendingPathComponent(name)
            try fm.createDirectory(
                at: outURL.deletingLastPathComponent(),
                withIntermediateDirectories: true)
            try fileData.write(to: outURL)
        }
    }

    // MARK: - Zip (Stored — no compression, valid for IPA re-packaging)

    /// Zip the contents of `directory` into `destination`.
    /// Uses "Stored" method — no compression — sufficient for IPA files.
    static func zip(directory: URL, to destination: URL, keepParent: Bool = true) throws {
        var localData  = Data()
        var centralDir = Data()
        var count      = 0

        let fm        = FileManager.default
        let srcPath   = directory.path
        let baseName  = keepParent ? (directory.lastPathComponent + "/") : ""

        guard let enumerator = fm.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        for case let url as URL in enumerator {
            var isDir: ObjCBool = false
            fm.fileExists(atPath: url.path, isDirectory: &isDir)

            let rawRel = String(url.path.dropFirst(min(srcPath.count + 1, url.path.count)))
            if rawRel.isEmpty { continue }
            let entryName = baseName + (isDir.boolValue ? rawRel + "/" : rawRel)
            let nameBytes = Array(entryName.utf8)

            let fileData = isDir.boolValue
                ? Data()
                : ((try? Data(contentsOf: url)) ?? Data())

            let crc   = crc32zip(fileData)
            let lhOff = UInt32(localData.count)

            // Local file header (method 0 = Stored)
            var lh = Data()
            lh += sig(0x04034B50)
            lh += le16(20)                          // version needed
            lh += le16(0)                           // flags
            lh += le16(0)                           // method: stored
            lh += le16(0); lh += le16(0)            // mod time / date
            lh += le32(crc)
            lh += le32(UInt32(fileData.count))      // compressed size
            lh += le32(UInt32(fileData.count))      // uncompressed size
            lh += le16(UInt16(nameBytes.count))
            lh += le16(0)                           // extra length
            lh += Data(nameBytes)
            lh += fileData
            localData += lh

            // Central directory record
            var cd = Data()
            cd += sig(0x02014B50)
            cd += le16(20); cd += le16(20)          // version made / needed
            cd += le16(0); cd += le16(0)            // flags / method stored
            cd += le16(0); cd += le16(0)            // mod time / date
            cd += le32(crc)
            cd += le32(UInt32(fileData.count))
            cd += le32(UInt32(fileData.count))
            cd += le16(UInt16(nameBytes.count))
            cd += le16(0); cd += le16(0)            // extra / comment len
            cd += le16(0); cd += le16(0)            // disk start / int attrs
            cd += le32(0)                           // ext attrs
            cd += le32(lhOff)
            cd += Data(nameBytes)
            centralDir += cd
            count += 1
        }

        let cdOff = UInt32(localData.count)
        var result = localData + centralDir

        // End of Central Directory
        var eocd = Data()
        eocd += sig(0x06054B50)
        eocd += le16(0); eocd += le16(0)            // disk / cd-start disk
        eocd += le16(UInt16(count))
        eocd += le16(UInt16(count))
        eocd += le32(UInt32(centralDir.count))
        eocd += le32(cdOff)
        eocd += le16(0)                             // comment length
        result += eocd

        try result.write(to: destination)
    }

    // MARK: - Private helpers

    /// Raw DEFLATE decompression via zlib inflateInit2 (wbits = -15)
    private static func inflateRaw(_ compressed: Data, uncompressedSize: Int) throws -> Data {
        // Allocate output buffer with some headroom
        let bufSize = max(uncompressedSize + 512, compressed.count * 4, 1024)
        var output  = [UInt8](repeating: 0, count: bufSize)

        try compressed.withUnsafeBytes { (srcPtr: UnsafeRawBufferPointer) throws in
            guard let srcBase = srcPtr.baseAddress else { throw ZIPError.invalidFormat }

            var stream      = z_stream()
            stream.next_in  = UnsafeMutablePointer<Bytef>(
                mutating: srcBase.assumingMemoryBound(to: Bytef.self))
            stream.avail_in = uInt(compressed.count)

            try output.withUnsafeMutableBytes { (dstPtr: UnsafeMutableRawBufferPointer) in
                guard let dstBase = dstPtr.baseAddress else { return }
                stream.next_out  = dstBase.assumingMemoryBound(to: Bytef.self)
                stream.avail_out = uInt(bufSize)

                // wbits = -MAX_WBITS → raw DEFLATE (no zlib / gzip header)
                let initCode = inflateInit2_(&stream, -MAX_WBITS,
                                             ZLIB_VERSION,
                                             Int32(MemoryLayout<z_stream>.size))
                guard initCode == Z_OK else { throw ZIPError.decompressionFailed(initCode) }
                let code = inflate(&stream, Z_FINISH)
                inflateEnd(&stream)
                guard code == Z_STREAM_END || code == Z_OK else {
                    throw ZIPError.decompressionFailed(code)
                }
            }
        }

        return Data(output.prefix(uncompressedSize))
    }

    // MARK: - Binary helpers

    private static func findEOCD(_ b: [UInt8]) -> Int? {
        guard b.count >= 22 else { return nil }
        var i = b.count - 22
        while i >= 0 {
            if read32LE(b, i) == 0x06054B50 { return i }
            i -= 1
        }
        return nil
    }

    private static func read16LE(_ b: [UInt8], _ i: Int) -> UInt16 {
        guard i + 1 < b.count else { return 0 }
        return UInt16(b[i]) | (UInt16(b[i+1]) << 8)
    }

    private static func read32LE(_ b: [UInt8], _ i: Int) -> UInt32 {
        guard i + 3 < b.count else { return 0 }
        return UInt32(b[i]) | (UInt32(b[i+1]) << 8)
             | (UInt32(b[i+2]) << 16) | (UInt32(b[i+3]) << 24)
    }

    /// CRC-32 as used in ZIP (ISO 3309 / ITU-T V.42)
    private static func crc32zip(_ data: Data) -> UInt32 {
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

    private static func sig(_ v: UInt32) -> Data { le32(v) }
    private static func le16(_ v: UInt16) -> Data {
        Data([UInt8(v & 0xFF), UInt8(v >> 8)])
    }
    private static func le32(_ v: UInt32) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v>>8) & 0xFF),
              UInt8((v>>16) & 0xFF), UInt8(v >> 24)])
    }
}

// Convenience operator for Data concatenation
private func += (lhs: inout Data, rhs: Data) { lhs.append(rhs) }
