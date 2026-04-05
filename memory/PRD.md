# SignTool iOS App — PRD

## Project
Native iOS signing tool app built with Swift/SwiftUI.

## Date
2026-04-05

## Architecture
- **Platform**: Native iOS (Swift 5.9, SwiftUI)
- **Minimum iOS**: 15.0
- **Bundle ID**: com.astear17.signtool
- **Build**: Xcode project (`SignTool.xcodeproj`) + GitHub Actions

## Dependencies
| Package | Purpose |
|---------|---------|
| `khcrysalis/Zsign-Package` (branch: package) | On-device IPA signing engine (C++ via SPM) |
| `weichsel/ZIPFoundation` (≥0.9.0) | IPA extraction / re-packaging |

## File Structure (at repo root)
```
SignToolApp.swift          # @main entry point
ContentView.swift          # TabView root + theme helpers
Views/
  SignIPAView.swift        # Tab 1: Sign IPA
  CheckCertView.swift      # Tab 2: Check Certificate
  ChangePassView.swift     # Tab 3: Change Password
Models/
  CertificateInfo.swift    # OCSPStatus enum, ProvisionInfo
  IPAInfo.swift            # IPAInfo struct
  SigningJob.swift         # SigningJob Codable model
Services/
  ZsignWrapper.swift       # Zsign.sign() / checkRevokage() wrappers
  CertificateService.swift # SecPKCS12Import, OCSP, mobileprovision parsing
  IPAParser.swift          # IPA extraction + Info.plist + icon parsing
  KeychainService.swift    # Password keychain, CertificateStore, SigningHistory
  P12PasswordChanger.swift # PKCS12 re-export with new password
Resources/
  Assets.xcassets/
    AppIcon.appiconset/    # icon.png downloaded at build time from Astear17/SignTool
SignTool.xcodeproj/        # Xcode project (objectVersion=56, Xcode 16.2)
Info.plist                 # UTImportedTypeDeclarations for .p12, .mobileprovision
.github/workflows/build.yml # macOS-14 unsigned IPA artifact
```

## What's Implemented
- ✅ Tab 1: Sign IPA — Full UI with IPA picker, .p12/.mobileprovision selection, options card, real-time progress, export button
- ✅ Tab 2: Check Cert — Certificate parsing (Security.framework), fingerprints, OCSP opt-in toggle, mobileprovision parsing
- ✅ Tab 3: Change Pass — Password fields with validation, SecItemExport-based re-export
- ✅ Liquid Glass theme (iOS 26+ `.glassBackgroundEffect()` + ultraThinMaterial fallback)
- ✅ Dark theme (#0a0a0f background, #3c94fc accent)
- ✅ Keychain password storage, signing history, saved certificate pairs
- ✅ GitHub Actions workflow building unsigned IPA on macOS-14

## Backlog / P1 Remaining
- P1: Verify exact `.glassBackgroundEffect()` API when iOS 26 SDK finalizes
- P1: Test actual build on Xcode 16.2 (resolve SPM packages, ensure no build errors)
- P1: Icon download: `curl -L https://raw.githubusercontent.com/Astear17/SignTool/main/Resources/icon.png -o Resources/Assets.xcassets/AppIcon.appiconset/icon.png`
- P2: SecItemExport for P12 password change may need entitlements on stock iOS — fallback to OpenSSL via zsign if needed
- P2: Add dylib injection UI polish (progress for each dylib)
- P2: Previous certificate pairs UI in Tab 1

## How to Build
```bash
# Download icon
curl -L "https://raw.githubusercontent.com/Astear17/SignTool/main/Resources/icon.png" \
  -o "Resources/Assets.xcassets/AppIcon.appiconset/icon.png"
# Open in Xcode
open SignTool.xcodeproj
```
