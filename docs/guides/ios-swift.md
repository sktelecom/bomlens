---
description: Scan an iOS or macOS app that uses Swift Package Manager or CocoaPods. Which lock files to commit, what is read without a Mac, and what to expect from Xcode-managed dependencies.
---

# How do I scan an iOS app that uses SwiftPM or CocoaPods?

BomLens reads the lock files your project already has, so the scan does not need a Mac, Xcode or a CocoaPods install. The one preparation is to make sure the lock files are in the folder you scan.

## What does the scan read?

| Dependency manager | File | If it is missing |
|--------------------|------|------------------|
| Swift Package Manager | `Package.resolved` next to `Package.swift`, or the one Xcode keeps in `*.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved` (or `*.xcworkspace/xcshareddata/swiftpm/`) | the scan runs `swift package resolve`, which needs network access to every dependency |
| CocoaPods | `Podfile.lock` | run `pod install` once and commit the file; BomLens parses it directly |

A folder that has no manifest at its top level but an Xcode project, `Package.swift`, `Podfile` or `Package.resolved` up to three folders down (for example `App/App.xcodeproj`) is scanned as Swift.

## How do I run the scan?

In the desktop app or the web UI, add the project folder and run the scan. On the command line:

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-ios-app --generate-only
```

The scan uses a Swift image from the cdxgen project. Its size is not recorded in BomLens, so the pre-download size note does not list it; run `scripts/check-setup.sh` afterwards to see what it took on disk.

## What about private dependencies?

Commit `Package.resolved`. With it present the scan skips the network resolve and reads the versions from the file, so a private Git dependency does not have to be cloned. Without it, the resolve step stops after `BOMLENS_PREP_TIMEOUT` seconds (900 by default) because Git is told never to ask for a login. For CocoaPods, `Podfile.lock` names every pod and version, so the versions are read without access to a private source. Licenses are not in that file: BomLens looks them up online in the CocoaPods trunk (`cdn.cocoapods.org`), only for pods listed under the trunk. A pod from a private spec repo or from a git or path source therefore has no license in the SBOM. Behind a proxy that inspects TLS, the lookup needs your company CA in `SBOM_EXTRA_CA_CERTS` (see [Company network](company-network.md#how-do-i-trust-my-company-ca)).

## What does the result leave out?

UIKit and other platform frameworks that Xcode supplies are not resolved by the Linux scanner, and they carry no license of their own. Expect a few components without a license in an app's SBOM for that reason. Check the completeness grade in `{Project}_{Version}_completeness.json` or on the Overview screen: when the grade is partial it lists the reasons.

Details and the bundled example are in [Ecosystems](../reference/ecosystems.md#swift--ios).
