# Swift Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Swift Package Manager (SPM) project. The dependencies are pure-Swift, so they resolve on Linux with no iOS platform or UIKit requirement.

## Project Structure

- `Package.swift`: SPM manifest (swift-tools-version 5.9)
- `Sources/`: a small executable target

## Dependencies

- **swift-argument-parser** (1.3.0+): command-line argument parsing
- **swift-log** (1.5.0+): logging API
- Plus transitive dependencies

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat` — see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/swift
../../scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `SwiftExample_1.0.0_bom.json` with swift-argument-parser, swift-log, and the transitive packages they pull in.

### Sample Components

- swift-argument-parser
- swift-log

## Build and Run (Optional)

```bash
swift build
swift run
```

Requires a Swift toolchain (Linux or macOS).

## Validate Results

```bash
# Count components
jq '.components | length' SwiftExample_1.0.0_bom.json

# List all packages
jq -r '.components[].name' SwiftExample_1.0.0_bom.json | sort -u
```

## Common Issues

### Package.resolved for exact versions

A committed `Package.resolved` pins versions. Without it, SPM resolves during the scan, which may need a Swift toolchain or network access.

## Next Steps

- Add more SPM packages and re-scan
