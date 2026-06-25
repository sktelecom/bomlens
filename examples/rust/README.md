# Rust Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Cargo-based Rust project (an actix-web server).

## Project Structure

- `Cargo.toml`: crate dependencies
- `src/`: an actix-web HTTP server

## Dependencies

- **actix-web** (4.4): web framework
- **serde** (1.0) + **serde_json** (1.0): serialization
- **tokio** (1.35): async runtime
- Plus transitive crates

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat` — see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/rust
../../scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `RustExample_1.0.0_bom.json` with roughly 35–45 crates. actix-web pulls a large transitive tree, so most entries are indirect.

### Sample Components

- actix-web
- serde / serde_json
- tokio
- actix-http

## Build and Run (Optional)

```bash
cargo build
cargo run
# Server listens on :8080
```

## Validate Results

```bash
# Count components
jq '.components | length' RustExample_1.0.0_bom.json

# List all crates
jq -r '.components[].name' RustExample_1.0.0_bom.json | sort -u
```

## Common Issues

### Cargo.lock for exact versions

A committed `Cargo.lock` pins exact versions. Without it, Cargo resolves the latest compatible versions during the scan.

## Next Steps

- Add more crates and re-scan
- Compare the SBOM with and without `Cargo.lock`
