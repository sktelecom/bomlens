# Rust Example

SBOM generation for Rust projects using Cargo.

## Dependencies

- **actix-web** (4.4): Web framework
- **serde** (1.0): Serialization
- **tokio** (1.35): Async runtime

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.


```bash
cd examples/rust
../../scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --generate-only
```

## Expected Components

~35-45 crates including transitive dependencies

## Validate

```bash
jq '.components | length' RustExample_1.0.0_bom.json
```
