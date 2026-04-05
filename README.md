# SignTool

**A native iOS app for signing IPA files, checking certificate validity, and changing certificate passwords — all on-device.**

[![Build Unsigned IPA](https://github.com/Astear17/SignTool/actions/workflows/build.yml/badge.svg)](https://github.com/Astear17/SignTool/actions/workflows/build.yml)

---

## Features

| Tab | Feature |
|-----|---------|
| **Sign IPA** | Sign any IPA with a .p12 certificate + .mobileprovision profile. Supports bundle ID override, dylib injection, plugin removal, and real-time progress. |
| **Check Cert** | Parse .p12 certificates — view CN, team, serial, fingerprints, expiry, and OCSP revocation status. |
| **Change Pass** | Change a .p12 password locally on-device. No network required. |

## Requirements

- iOS 15.0+
- Xcode 16.2+
- Swift 5.9+

## Building Locally

### 1. Clone the repository

```bash
git clone https://github.com/Astear17/SignTool.git
cd SignTool
```

### 2. Download the app icon

```bash
curl -L "https://raw.githubusercontent.com/Astear17/SignTool/main/Resources/icon.png" \
  -o "Resources/Assets.xcassets/AppIcon.appiconset/icon.png"
```

### 3. Open in Xcode

```bash
open SignTool.xcodeproj
```

Xcode will automatically resolve the SPM dependencies:
- `khcrysalis/Zsign-Package` — On-device IPA signing engine
- `weichsel/ZIPFoundation` — IPA extraction and re-packaging

### 4. Build

Select **Any iOS Device** and press **Cmd+B**. For an unsigned IPA, use the GitHub Actions workflow.

## Getting an Unsigned IPA

Every push to `main` triggers the GitHub Actions workflow at `.github/workflows/build.yml`.

1. Go to **Actions** → **Build Unsigned IPA**
2. Click **Run workflow** or wait for a push
3. Download **SignTool-unsigned-ipa** from the Artifacts section

To install the unsigned IPA, use:
- [Sideloadly](https://sideloadly.io/)
- [AltStore](https://altstore.io/)
- Or sign it using **SignTool itself** with your own developer certificate 😉

## Architecture

```
SignTool/
├── SignToolApp.swift          # @main App entry point
├── ContentView.swift          # Root TabView + theme helpers
├── Views/
│   ├── SignIPAView.swift      # Tab 1: Sign IPA
│   ├── CheckCertView.swift    # Tab 2: Check Certificate
│   └── ChangePassView.swift   # Tab 3: Change Password
├── Models/
│   ├── CertificateInfo.swift  # Certificate data model
│   ├── IPAInfo.swift          # IPA metadata model
│   └── SigningJob.swift       # Signing history model
├── Services/
│   ├── ZsignWrapper.swift     # Zsign Swift wrapper
│   ├── CertificateService.swift  # Security.framework parsing + OCSP
│   ├── IPAParser.swift        # IPA extraction + Info.plist parsing
│   ├── KeychainService.swift  # Password storage
│   └── P12PasswordChanger.swift  # PKCS12 re-export
└── Resources/
    └── Assets.xcassets/       # App icon + accent color
```

## Dependencies

| Package | Purpose | License |
|---------|---------|---------|
| [khcrysalis/Zsign-Package](https://github.com/khcrysalis/Zsign-Package) | On-device IPA signing via zsign C++ | MIT |
| [weichsel/ZIPFoundation](https://github.com/weichsel/ZIPFoundation) | ZIP/IPA extraction and packaging | MIT |

## Design

- **Liquid Glass** theme on iOS 26+ via `.glassBackgroundEffect()`
- `.ultraThinMaterial` frosted glass fallback for iOS 15–25
- Deep dark background (`#0a0a0f`) with accent blue (`#3c94fc`)
- SF Pro fonts; SF Mono for hashes and technical details

## License

GPL-3.0 — see [LICENSE](LICENSE)

## Credits

- Signing engine: [zsign](https://github.com/zhlynn/zsign) by zhlynn, packaged by [khcrysalis](https://github.com/khcrysalis/Zsign-Package)
- Inspired by [Ksign](https://github.com/Nyasami/Ksign) by Nyasami
