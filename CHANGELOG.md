# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.1.1] - 2026-06-09

### Added

- Desktop startup screen is now bilingual: it follows the system locale (Korean on Korean systems, English elsewhere) and falls back to English, matching the web UI. The `SBOM_LANG` environment variable forces a language (`SBOM_LANG=en` or `ko`).

### Changed

- The main `README.md` is unified to English, with English UI screenshots. The Korean documentation table and Korean guides are kept for Korean users; the Korean screenshots stay with the Korean docs.

## [v1.1.0] - 2026-06-02

### Added

- Electron desktop app (`electron/`) that wraps the web UI with no console window: it checks Docker, pulls the scanner image, runs the `MODE=UI` container, and opens the UI on double-click.
- Desktop installers (`SBOM-Generator-*.exe` / `.dmg`) are built in CI and attached to tagged GitHub Releases, so non-developers can download them directly. Unsigned for now, so Windows SmartScreen prompts to confirm.
- License-manager quickstart (`docs/notice-quickstart.md`) and a setup-check helper (`scripts/check-setup.bat` / `scripts/check-setup.sh`) that reports Docker, image, and port status in Korean.
- Windows verification assets: an automated smoke test (`tests/windows-smoke.ps1`) and a manual e2e checklist (`tests/windows-e2e-checklist.md`).
- Desktop-app packaging study (`docs/desktop-app-study.md`).
- Screenshots and a flow diagram across the user guides.
- Firmware analysis (FIRMWARE mode): unpack a firmware image and produce an SBOM and risk report.
- Supplier SBOM validation and analysis (ANALYZE mode) for SBOMs you receive from third parties.
- End-to-end support for five input forms (source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS) with a risk report emitted in every mode.
- Local web UI: launch a scan, stream live logs, and download results from the browser.
- Cosign signing of generated artifacts via `--sign`, with the key and password passed into the container at runtime.
- Multi-architecture Docker images, with architecture detected at runtime for Trivy and cosign.
- Governance and community-health documents: `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- Korean documentation style guide and a `/humanize` helper, enforced by a doc-style check.

### Changed

- `scripts/sbom-ui.bat`: results go to a dedicated `%USERPROFILE%\sbom-output` folder, the scanner image is pre-pulled on first run with progress shown, and messages are in Korean.
- README routes first-time Windows users to the easiest path up front, and the license-manager quickstart leads with the desktop app and lists expected install and download times.
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

[Unreleased]: https://github.com/sktelecom/sbom-tools/compare/v1.1.1...HEAD
[v1.1.1]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.1.1
[v1.1.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.1.0
[v1.0.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.0.0
