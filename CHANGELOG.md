# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Android (AGP) source scans no longer inflate the SBOM with the build and test toolchain. The scan is scoped to the deployable release runtime classpath, so only the components shipped in the APK are recorded.
- Firmware scans no longer silently report zero CVEs from a vulnerability database that lacks NVD data. The build gate now rejects a bundled CVE database without a real NVD advisory corpus instead of shipping it.

## [v1.6.0] - 2026-07-03

### Added

- AI SBOM conformance now covers the full G7 minimum-elements checklist: seven clusters rendered as 51 checks, each tagged as read from the SBOM, inferred from signals, or requiring human review. The web UI groups the results by cluster, and the AI model guide explains what the checklist is, its EU AI Act context, and how to read the report.
- The desktop app checks for a newer release on startup and offers the download page.
- The desktop app recovers without a relaunch: the Docker-missing and failure screens have retry buttons, a scanner container that dies after the UI loads is detected and reported, containers left behind by a crash are cleaned up on the next start, and a second launch focuses the running window instead of starting a duplicate.
- Desktop quality of life: the version is visible on the start screen and About panel, window size and position are remembered, startup progress is written to a log file, and the start screens support light mode, a language toggle, and per-OS Docker installation guidance.
- New scan prefills the project name and version from the scan source (git URL, Docker image tag, uploaded file name, or SBOM metadata), marks required fields, and validates them inline.
- The macOS installer is universal: it now runs on Intel Macs as well as Apple Silicon.
- The desktop installers are covered by the release's `SHA256SUMS.txt`, so downloads can be integrity-checked.

### Changed

- Advanced scan option labels lead with what they do ("Per-file license scan", "Detect copied-in open source", "More vulnerability advisories"); the tool names moved into the hints.
- The desktop app pulls the documented image tag (`ghcr.io/sktelecom/bomlens`) — the same image it used before, under its current name.
- Installer code signing and notarization turn on automatically once certificates are registered as CI secrets; installers remain unsigned until then.

### Fixed

- OS package CVE matching in SBOM security scans was restored.
- syft output is pinned to CycloneDX 1.6 because Trivy 0.70 cannot read 1.7; security scans of syft-generated SBOMs work again.
- A failed security scan is now marked as failed in the report instead of silently reporting zero findings.
- PyPI version ranges no longer duplicate the installed version as a lower bound.
- The `--deep-license` image builds and runs again.

## [v1.5.5] - 2026-07-01

### Fixed

- Maven and Gradle source scans now record their direct dependencies in the SBOM dependency graph. The root component previously carried an empty `dependsOn`, so tools reading the graph classified every direct dependency as transitive. npm was unaffected.

## [v1.5.4] - 2026-06-28

### Added

- The result Overview leads with the section jump cards and shows Security and License classification side by side; clicking a band opens that section pre-filtered.
- Licenses are graded by copyleft strength (network / strong / weak / permissive), with separate review-needed and uncategorized classes; an unrecognised license is never assumed permissive.
- The home screen is now Scan management: search past scans, filter by scan type, and see total / at-risk / project counts, with the at-risk card doubling as a filter.
- Global search across components and CVEs from the top bar.
- Re-scan: re-run a finished scan with the same target and options from the top bar.
- The SCANOSS client ships in the base image, so vendored open-source identification works out of the box (still opt-in at scan time).
- Running firmware and AI scans can be cancelled.

### Changed

- New scan and Recent moved into the top bar, so the left rail is purely the current scan's sections.
- New scan's advanced analysis toggles moved into their own Advanced scan options section, with clearer copy and SCANOSS free-tier guidance.
- Generated HTML reports were restyled to match the web UI.
- The scan progress bar follows the real pipeline stages, and the Scan management table columns are sortable.
- The dependency rail badge shows the direct/transitive split.

### Fixed

- A source scan that falls back to syft is labelled "Source" instead of "SBOM", and now says so when the fallback was caused by Docker running out of disk.
- Fonts are self-hosted so the desktop content-security policy keeps the intended typography.

## [v1.5.3] - 2026-06-27

### Added

- The dependency graph view was redesigned to read like a commercial graph explorer.
- License distribution is shown as proportional bars, with the charts animating in on first render.
- Each scan now shows how it compares to the previous run of the same project.

### Changed

- Interactive result cards lift on hover, with motion that honours the operating system's reduced-motion setting.

### Fixed

- `SECURITY_ENRICH=false` now reaches the post-process container, so the EPSS and CISA KEV opt-out works from the host CLI for air-gapped runs.
- `--analyze`/`--sbom` combined with `--model` is now rejected instead of silently running in ANALYZE mode.
- AI SBOM generation fails closed when the model card cannot be collected (offline, or an unknown/private model id) instead of writing an empty stub ML-BOM as a valid output.
- Supplier SBOM analysis now produces the conformance report for well-formed SPDX Tag-Value inputs; a zero-count grep had aborted the Tag-Value checks.
- Reopening a past scan from history no longer shows an empty run-log panel.
- A release stays a draft until the release gate verifies it, so it is never published before its entry points are checked.

### Documentation

- Corrected the supplier-SBOM conversion note (SPDX is converted to CycloneDX 1.6; CycloneDX inputs keep their original spec version), removed the unimplemented drag-resizable columns claim from the UI reference, fixed the Node.js lock-file guidance, and added page descriptions to five navigation pages.

## [v1.5.2] - 2026-06-26

### Added

- Per-run output isolation: each scan now lands in its own `{Project}_{Version}/` subfolder, so the files from one run stay together and the CLI never litters the source tree it scans. New `--output-dir`/`-o` and `--timestamp` flags choose the base directory and keep repeat runs side by side.
- Release gate: a release is created as a draft and only published after its recommended entry points are verified for that exact release — the desktop installers are attached and the documented first-scan command produces a valid SBOM on the actual published image.
- Onboarding CI gates that keep the docs and the tool in step: a doc/tool drift check (flags, environment variables, image names, the desktop download name), an internal-link check for the getting-started pages, machine UX checks (no silent error exits, parity between the setup scripts, a complete `--help`), a desktop-app boot smoke on Windows and macOS, and a walkthrough that runs the documented first-scan command on the published image.

### Changed

- Scan outputs default to a `{Project}_{Version}/` subfolder of the current directory instead of being written flat. Set `SBOM_OUTPUT_FLAT=1` for the previous flat layout.

### Fixed

- `--byte-stable` is now reproducible: it no longer resolves dependency licenses over the network, a lookup whose success varied between runs and made two otherwise-identical scans differ.
- Source scans no longer leave root-owned build files (for example `node_modules`) in the scanned project folder or the git/zip ingestion temp directory on Linux; the scanned tree is handed back to the host user.
- The README pointed at a renamed desktop installer; the download links now use `BomLens-Setup.exe` and `BomLens-Setup.dmg`.
- Documented the `--ref` alias for `--branch`.

## [v1.5.1] - 2026-06-26

### Added

- Desktop app firmware and AI-model scans: the desktop app now runs firmware and AI-model (AIBOM) scans by launching the matching scanner image as a sibling container, pulling it on first use.
- Source file tree without ScanCode: source scans emit a `_files.json` file inventory, and the web UI shows a source tree from it when no ScanCode result is present.
- SBOM conformance is now a first-class result section, with per-element G7 evidence, examples and guidance links.
- Determinate firmware CVE-database download progress: a real percentage bar during the cve-bin-tool database fetch, falling back to the previous approximation when a scan reports no progress.

### Changed

- Web UI design-language refresh: a redesigned visual language, a Recent-scans home, and neutralized report wording.
- Release assets are unified under the BomLens name (for example `BomLens-Setup.*`), and the release notes link to the documentation site.
- The AI-model scan form now explains the open-source Notice option.

### Fixed

- Firmware scans matched zero CVEs because the published firmware image shipped an empty cve-bin-tool database. The image now bundles a populated database with a runtime refresh, the build fails if the database ends up empty, and the database path matches the location cve-bin-tool actually uses.

## [v1.5.0] - 2026-06-25

### Added

- Redesigned web UI: a new shell with Overview, Components, Dependencies, Vulnerabilities, Licenses, AI (Models & datasets / G7), and Artifacts sections; a single-card New scan form; and local Recent scans (list, re-open, delete; newest 20 shown). Every navigation element is a real link, so the logo, New scan, sidebar sections, recent scans and jump cards open in a new tab (Cmd/Ctrl/middle click) via URL-hash routing.
- AI-model SBOM (AIBOM): generate a CycloneDX ML-BOM for a HuggingFace model id — with G7 minimum-element conformance — from the web UI's AI model input. Published as the new `bomlens-aibom` image (legacy alias `sbom-scanner-aibom`).
- EPSS exploit probability and CISA KEV (actively exploited) surfaced on vulnerabilities.
- Component detail: click a component row to see its PURL, source/download location, copyright, licenses and vulnerabilities.
- License explorer: click a license to list its components, with copyleft/reciprocal licenses highlighted.
- Vulnerability view: click the severity bar to filter, plus a search box; all result tables are drag-resizable.
- Firmware analysis: cve-bin-tool now matches CVEs online (the firmware image bundles the vulnerability DB), and an enrichment step fills CPEs and SPDX licenses for a curated whitelist of well-known OSS (busybox, dropbear, dnsmasq, …) so Trivy and the notice can use them. Compressed firmware images (`.img.gz`, `.tar.xz`, …) can be uploaded.
- Open-source notice: per-component source/download location and copyright line, plus an optional PDF rendering (`SBOM_PDF` build).
- SCANOSS: a token input for the OSSKB endpoint (the free anonymous endpoint is rate-limited), and a result note that distinguishes "search unavailable" from "nothing found".

### Changed

- Advanced scan options (deep license / SCANOSS) appear only for source scans; AI-model scans drop the deep-license toggle and the (always-empty) security report.
- G7 conformance moved under the AI group, with per-element "what it is / how to satisfy" guidance.
- The live run log now appears only on the Overview, not under every section.
- The scan banner and UI startup logs are unified to "BomLens".

### Fixed

- SCANOSS found nothing on uploaded/cloned sources because they extract under a dot-prefixed `.uploads` path that scanoss-py skips by default (`--all-hidden`).
- The firmware component merge hit the command-line length limit on large rootfs images (jq now reads arrays from files via `--slurpfile`).
- The dependency graph drew edgeless SBOMs (e.g. firmware) as overlapping dots — it now shows a note — and framed large graphs too far out to read.
- AI scans were labelled by the generator's `job-<timestamp>` instead of the model name.
- The scan done-event listed every artifact in the output folder instead of only the current scan's.
- Leaving a running scan no longer lets the backgrounded scan finish and hijack the screen (the live SSE stream is closed on navigation).

## [v1.4.0] - 2026-06-23

### Added

- Identify open source copied (vendored) into C/C++ source that has no package manager. `--identify-vendored` matches file fingerprints against the SCANOSS/OSSKB knowledge base and records copied-in open source as named components (name, version, PURL, and a CPE where one exists), so the security report can surface their CVEs. It is off by default, with a one-line suggestion shown automatically when a scan looks like C/C++ embedded source, and is available in the web UI under Advanced. Matches are reconciled against the package-manager scan, so enabling it on a managed project does not duplicate dependencies or inflate the vulnerability count. Hardened with an adversarial CLI + UI test campaign (CPE-grammar safety, large-tree handling, over-detection, injection). (#168, #169)

### Changed

- The published `bomlens` image now bundles the (MIT-licensed) SCANOSS client, so `--identify-vendored` works out of the box without a custom build. (#168)

## [v1.3.1] - 2026-06-22

### Added

- Server delivery SBOM: scan a server's layers separately (OS rootfs and application) and combine them with `--merge`, which merges several CycloneDX SBOMs into one; the web UI accepts a rootfs directory as input. (#161)

### Changed

- GHCR package names are unified under the `bomlens` brand; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#156)
- The Android image pull defaults to the published `bomlens` name. (#157, #158)
- Documentation is restructured by intent with English as the canonical language, sidebar labels shortened, and the landing pages use the web UI demo gif. (#154, #155, #160)

### Fixed

- Source scans no longer leak `src@latest` as the root component name, which became a non-unique Black Duck codelocation and blocked unrelated imports. The caller's project name is now passed to cdxgen and stamped into the root component, and the pipeline fails closed if stamping does not take. (#166)
- `--merge` preserves each input's dependency graph so the merged BOM stays CycloneDX-conformant. (#164)
- Follow-ups from the v1.3.0 verification pass (V13-1/2/3). (#159)
- Corrected the first-scan link in the Korean server-delivery guide and modeled static linking as a blind spot rather than a separate layer. (#162, #163)

## [v1.3.0] - 2026-06-14

### Added

- `--trusca <project_id>` (or `--upload-target trusca`) uploads the generated SBOM to TRUSCA's native ingest endpoint as an alternative to the default Dependency-Track upload. (#148, #149)
- Vulnerability rows in the web UI expand in place to show the CVSS score and vector, the full advisory description, and reference links — surfacing data already in the Trivy report without an extra fetch.
- The components table in the web UI can now sort by name, version, or type and filter by component type and license, alongside the existing search.
- The vulnerabilities table can be filtered by severity, and the summary tab shows a license distribution (component count per license, plus unlicensed).
- The dependency graph is now interactive: click a node to see its details (version, type, licenses, direct/indirect), and search to highlight matching packages.
- Documentation site: a Release notes link in the nav (pointing at GitHub Releases) and opt-in, cookieless analytics (GoatCounter) that stays off until a site code is configured.

### Changed

- Unified the web UI's empty, loading, and error states into shared primitives so every result view looks and behaves the same, and added a retry action to the dependency and source-tree views.

### Fixed

- Dependency graph node labels were unreadable in dark mode (fixed dark text on a dark canvas); graph colors now follow the light/dark theme tokens.
- Small dependency graphs no longer over-zoom into huge, overlapping labels; zoom is capped and node spacing widened so a handful of nodes stays readable.

## [v1.2.2] - 2026-06-13

### Added

- BomLens brand identity: aperture logo, app icons, and favicon across the docs site, web UI, and desktop app. (#125, #127, #128, #130)
- Rendered documentation site (sktelecom.github.io/sbom-tools) with sidebar navigation, search, and a one-click Windows download, replacing repo-only docs. (#112, #113, #114, #115, #116)
- New documentation pages on the site: use the Docker image directly, architecture, and the two contributing guides, each with an English translation. (#126)
- English translations for the five previously Korean-only guides. (#117)

### Changed

- Renamed the product display name to BomLens; technical identifiers and download URLs are unchanged. (#120)
- The web UI header shows the BomLens brand with an SBOM generator descriptor. (#124)
- The post-process image is co-published as `ghcr.io/sktelecom/bomlens`; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#121, #122)
- Reworked the Korean guides for readability and kept the synced English pages aligned; wide architecture diagrams now stack vertically. (#123, #129)
- The docs home leads with a headline, a Get started primary button, and a product screenshot; the header brand links to the home page. (#131, #132)

### Fixed

- The desktop app startup screen background matches the web UI dark token. (#118)

## [v1.2.1] - 2026-06-12

### Security

- The web UI cleanup endpoint validates the provided token before removing staged uploads, and CI workflows run with least-privilege permissions. (#106)
- Pinned base image digests so the supply chain is verifiable (Scorecard pinned-dependencies). (#107)

### Fixed

- The NOTICE dedupes appended SPDX license texts and normalizes the Expat alias to MIT, so each license text appears once. (#108)
- The SBOM stamps `metadata.component` from the input project name and version instead of leaving it unset. (#108)
- Stabilized byte-stable SBOM output and coerced null components to empty arrays, preventing spurious diffs and parse failures. (#108)

## [v1.2.0] - 2026-06-11

### Added

- Web UI source scans (current directory, Git URL, ZIP upload) now resolve transitive dependencies through cdxgen language images, matching the CLI. The web UI previously used syft, which captured only directly declared dependencies; a Spring Boot sample went from 8 to 91 components. (#95)
- Scan results gained Components and Vulnerabilities tabs with searchable, sortable tables, next to the existing summary. (#96)
- Source scans now fetch dependency licenses (`FETCH_LICENSE`, on by default), so components and the NOTICE carry real license data instead of NOASSERTION. Set `FETCH_LICENSE=false` to skip the lookups. (#98)
- The NOTICE normalizes license aliases to SPDX ids, shows component copyright when present, and appends the SPDX standard full text of each used license from a bundled set (21 common licenses, offline). (#99)
- The security report surfaces CVSS, EPSS (exploit probability) and CISA KEV (known-exploited) signals, sorting findings KEV first, then by severity, then by EPSS. Set `SECURITY_ENRICH=false` for offline runs. (#100)
- Redesigned the post-scan artifact download experience with per-format chips and a bulk ZIP download. (#102)

### Changed

- Synced the user documentation, in-app help, and screenshots with the new features. (#101, #103)

### Fixed

- Removed the redundant maven pre-resolve step in build-prep that printed a spurious NoPluginFoundForPrefix error on every Java source scan, with no effect on the resulting SBOM. (#97)

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
- Desktop-app packaging study (`docs/internal/desktop-app-study.md`).
- Screenshots and a flow diagram across the user guides.
- Firmware analysis (FIRMWARE mode): unpack a firmware image and produce an SBOM and risk report.
- Supplier SBOM validation and analysis (ANALYZE mode) for SBOMs you receive from third parties.
- End-to-end support for five input forms (source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS) with a risk report emitted in every mode.
- Local web UI: launch a scan, stream live logs, and download results from the browser.
- Cosign signing of generated artifacts via `--sign`, with the key and password passed into the container at runtime.
- Multi-architecture Docker images, with architecture detected at runtime for Trivy and cosign.
- Governance and community-health documents: `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- Korean documentation style guide, enforced by a doc-style check.

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

[Unreleased]: https://github.com/sktelecom/sbom-tools/compare/v1.3.0...HEAD
[v1.3.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.3.0
[v1.2.2]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.2.2
[v1.2.1]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.2.1
[v1.2.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.2.0
[v1.1.1]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.1.1
[v1.1.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.1.0
[v1.0.0]: https://github.com/sktelecom/sbom-tools/releases/tag/v1.0.0
