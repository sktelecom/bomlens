# Swift Example

SBOM generation for Swift projects using Swift Package Manager (SPM).

## Dependencies

- **swift-argument-parser** (1.3.0+): Command-line argument parsing
- **swift-log** (1.5.0+): Logging API

These are pure-Swift packages that resolve on Linux, so no iOS platform or UIKit dependency is required.

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.


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
