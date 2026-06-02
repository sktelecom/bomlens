# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.1.0] - 2026-06-02

### Added

- Firmware analysis (FIRMWARE mode): unpack a firmware image and produce an SBOM and risk report.
- Supplier SBOM validation and analysis (ANALYZE mode) for SBOMs you receive from third parties.
- End-to-end support for five input forms (source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS) with a risk report emitted in every mode.
- Local web UI: launch a scan, stream live logs, and download results from the browser.
- Cosign signing of generated artifacts via `--sign`, with the key and password passed into the container at runtime.
- Multi-architecture Docker images, with architecture detected at runtime for Trivy and cosign.
- Governance and community-health documents: `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- Korean documentation style guide and a `/humanize` helper, enforced by a doc-style check.

### Changed

- Renamed the product to SBOM Generator; the post-process image is co-published as `ghcr.io/sktelecom/sbom-generator` (the legacy `sbom-scanner` name keeps working).
- Windows-friendly onboarding: a download-and-double-click web UI flow, plus consistent Windows guidance across the supplier docs.
- The Windows release archive now bundles both launchers and the host-mounted `build-prep.sh`, so it runs without the full repo.
- Reworked the scanner into a two-stage architecture (generate, then assess risk).
- Documentation refreshed to match the current product, including the web UI flow and the two core roles.

### Fixed

- Standard squashfs images now extract correctly during firmware unpacking.
- Detection of `.csproj`-only and `.gradle`-only projects (multi-glob matching bug).
- Generated artifacts are written as the host user so the Examples CI no longer fails on root-owned files.

## [v1.0.0] - 2026-02-19

### Added

- Initial public release of SBOM Tools.
- CycloneDX SBOM generation from source code for Java (Maven/Gradle), Python, Node.js, Ruby, PHP, Rust, Go, .NET, and C/C++.
- Open-source notice (고지문) and a Trivy-based security report alongside each SBOM.
- Docker image distribution via `ghcr.io/sktelecom/sbom-scanner`.
- GitHub Actions workflows for CI (ShellCheck, hadolint, integration and example tests), image publishing, and releases.

### Security

- No publicly known vulnerabilities have been reported or fixed in this project to date.

[Unreleased]: https://github.com/sktelecom/sbom-tools/compare/v1.0.0...HEAD
[v1.0.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.0.0
