# Swift Example

SBOM generation for Swift projects using Swift Package Manager (SPM).

## Dependencies

- **swift-argument-parser** (1.3.0+): Command-line argument parsing
- **swift-log** (1.5.0+): Logging API

These are pure-Swift packages that resolve on Linux, so no iOS platform or UIKit dependency is required.

## Generate SBOM

```bash
cd examples/swift
../../scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --generate-only
```

## Expected Components

A handful of SPM packages, including the transitive dependencies pulled in by the two direct ones.

## Validate

```bash
jq '.components | length' SwiftExample_1.0.0_bom.json
```
