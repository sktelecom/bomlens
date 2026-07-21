# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The Windows launchers (`sbom-ui.bat`, `check-setup.bat`) now speak English as well as Korean, following the same rule as the desktop app: `SBOM_LANG` wins, otherwise the Windows display language, and anything that is not Korean gets English. This also removes the boxes-instead-of-text problem on a Japanese console, where the font has no Hangul glyphs and no codepage can help.
- `bomlens.settings.example.txt`: environment variables do not survive a double-click, so `UI_PORT`, `SBOM_LANG`, `SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`, `SBOM_OUTPUT_DIR` and `SBOM_UI_MOUNT_DIR` are now also read from a text file beside the scripts (or `%USERPROFILE%\.bomlens\settings.txt`). A real environment variable still wins.
- Offline install: `SBOM_IMAGE_TAR` loads a `docker save` tar instead of pulling, and a `bomlens-image.tar` next to the scripts is picked up automatically. With `SBOM_PULL=never` the launcher never touches the network — a USB stick with the `.bat` and the `.tar` needs no registry, no command line and no proxy setup. `SBOM_PULL=always` refreshes a cached `:latest`, which previously stayed pinned forever once pulled.
- `sbom-ui.bat` picks a free port instead of failing: a busy **or Hyper-V/WSL-reserved** port now moves to the next free one. The reserved-range case was the common false green light — nothing is listening, yet Docker still cannot bind.
- The desktop app shows aggregate pull progress (layers complete, elapsed time) with a heartbeat, so the multi-GB first download no longer looks frozen during the long silent stretches, and both start screens gained an "Open log folder" button so a failing user can hand over `startup.log`.
- Pull failures are now classified (proxy, DNS, auth, disk, timeout) and the screen explains the actual fix. The proxy text states the thing that trips people up: the image is fetched by the Docker daemon, so setting proxy variables for the app has no effect.

### Fixed

- The first-run download figure is now the measured one. Every surface said the scanner image is "about 3-4 GB", which is its uncompressed size on disk rather than what is transferred: the registry manifest puts the actual download at about 250 MB. The launchers, the desktop app and the docs now say 250 MB, and they add the part that was missing — the first scan of a project fetches a language image as well (0.6-1.7 GB, once per language). The AI model guide's comparison figure was corrected the same way (3.5 GB to download).
- Container start failures no longer leak Korean strings into the English UI. `lib/container.mjs` threw hardcoded Korean text that bypassed i18n, so an ordinary port conflict or start timeout produced `Startup failed: docker run 실패: ...` for a non-Korean user. Errors now carry a code that `i18n.mjs` translates, and a test asserts no Hangul in the English dictionary.
- `sbom-ui.bat` no longer closes its window silently. Any failure after the Docker check — port conflict, bad mount, container crash — used to vanish instantly with no message; every path now explains itself and holds the window, and the container exit code is reported.
- A stopped Docker engine is no longer reported as "Docker is not installed" by the Windows launchers, which sent users off to reinstall Docker they already had.
- `SBOM_UI_MOUNT_DIR` handling: a trailing backslash mangled the whole `-v` argument, and a path containing `&` was executed as a command rather than printed. Trailing separators are stripped and unsafe paths are rejected with an explanation.
- No timeouts existed on the desktop app's Docker calls, so a wedged daemon or a firewalled registry hung on a live-looking window forever. Status checks are now bounded and the pull aborts when it genuinely stops making progress (a stall timeout, not an absolute one, so a slow but healthy download is not killed).
- The desktop app falls back to known Docker install paths when `docker` is missing from `PATH`. Installing Rancher Desktop without restarting Explorer left the app reporting "Docker isn't installed" while the engine ran visibly in the tray.
- `check-setup.bat` and `bomlens.settings.example.txt` now ship in the Windows release zip. The launchers' own error messages tell users to double-click `check-setup.bat`, which was not in the archive.
## [v1.8.3] - 2026-07-20

### Added

- AI-model scans can now read a private or gated HuggingFace repository. Set `HF_TOKEN` (read scope; `HUGGING_FACE_HUB_TOKEN` is accepted as an alias) and `--model` resolves repositories that are not public yet — the case that matters when you are checking your own model before publishing it. The value is passed to the container by name only, so it never appears in the process list, the SBOM, or any report. The web UI inherits the variable from the environment that launched it rather than accepting a token over HTTP, and `/capabilities` exposes only a boolean saying whether one is present. (#434)
- The conformance report now says how to close each G7 gap, not just which elements are missing. For every advisory element that has an automated source and is absent, `_conformance.md` and `.html` print the CycloneDX fragment that would satisfy it plus a link to the authoritative documentation, and `_conformance.json` carries the same under an optional `guidance` key. The guidance registry lives in `docker/lib/g7-guidance.json` (override with `G7_GUIDANCE`), keyed by element id like the regulatory crosswalk, and is the single source the web UI now reads too. Passing and review-only elements are excluded, so a well-documented model adds no section at all. The AI compliance profile lists the same gaps with their reference links and points at the conformance report for the fragments. (#435)
- Every component in the generated SBOM now carries a `bomlens:licenseClass` property with its copyleft-strength class (`network-copyleft`, `strong-copyleft`, `weak-copyleft`, `permissive`, `uncategorized`), mirroring the classification the web UI shows, and the risk report gains a per-class count table plus the network/strong-copyleft components driving the exposure. Unknown licenses are never assumed permissive. A test guard keeps the UI and scanner classifications from silently diverging. (#420)

### Fixed

- An AI-model scan whose model could not be read no longer reports success. The OWASP generator swallows a failed HuggingFace fetch, logs a warning, and fills the model card with generic defaults (`transformer`, `text-generation`, string in and out), so a `401` — or an id that does not exist at all — produced exit 0, a full artifact set, and a conformance report reading `result=pass` with 19 G7 checks satisfied, for a model nobody could open. Since that fabricated card is not empty, the existing card-present gate let it through. BomLens now inspects the generator's own log, refuses the run, deletes the output, and says the values were placeholders rather than the model; a `401` or `403` gets a hint that differs by whether a credential was supplied. A pending organizational token produces exactly this case. (#438)
- The CLI completion summary now lists the artifacts actually on disk instead of one line per requested flag, so a step that failed to deliver no longer announces a file the user does not have. Running `--spdx` or `--all` against a pre-v1.8.0 scanner image was the common case: no SPDX step exists, none runs, and the summary still named an SPDX artifact. (#425)
- `--model` no longer ships an empty security report. Both guides and the web UI state that an AI-model scan skips it because a model has no package dependencies to match CVEs against, but the CLI's risk-report defaults re-enabled security for every mode, so Trivy ran against an ML-BOM and wrote a `_security.*` set containing nothing. (#426)

### Changed

- SPDX export moved out of the New scan form and into the results. The toggle asked users to decide, before any scan ran, whether they would need SPDX later, and answering wrong meant a full rescan. A scan now always writes CycloneDX, and the SBOM card in the Artifacts section offers "Export as SPDX 2.3", which converts the finished BOM and starts the download right away; the converted file joins the artifact list and the ZIP bundle. Both paths run the same conversion helper, so the result is identical to the CLI's `--spdx`, which is unchanged along with `--all`. Signing remains CLI-only, and the button is hidden where no converter is reachable. (#439)
- The New scan form now seeds the version field with `1.0.0` when the source states no version of its own, so a first-time user who accepts the autofilled project name and presses Run no longer bounces off version validation. A version the source does carry — a docker tag, a `name-1.2.3` file, SBOM metadata — still wins, and an edit is never overwritten. (#429)
- The New scan validation summary no longer tells you to enter a project name that is already filled. Since the inline messages identify the offending fields, the line by the Run button became a neutral pointer to them, and the Korean copy lost a translationese parenthetical. (#428)
- The components table now renders large SBOMs with recycled row chunks: the whole filtered set (up to the 2,000-row server cap) is reachable by plain scrolling, offscreen rows are replaced by measured spacers so the DOM stays small, and the "Show more" button is gone. (#421)
- A failed upload or token stash on the New scan form now shows a situation-specific message (file too large, server unreachable, server error, rejected input) in both languages instead of the raw exception text; the technical detail moves to fine print. (#414)
- The nightly "macOS real scan (Colima)" job was retired: its last 19 runs all failed deterministically at Colima startup (the hosted arm64 runner boots neither the vz nor the qemu backend), so the scan never actually ran. The evidence and the re-add condition are recorded in the workflow; macOS coverage remains a maintainer-run local check. (#422)

### CI

- Example scan jobs reclaim about 25 GB of runner disk before any image work, dropping preinstalled toolchains the project never uses. The dotnet, swift and rust examples pull a language SDK image on top of the scanner image and were intermittently exhausting the runner's free space, failing with "no space left on device" before an SBOM was written. (#430)
- The Dockerfile lint (hadolint) is now blocking at error level, and the external-link check's advisory status is documented inline. (#413)
- A Korean prose style gate now lints the public docs on every PR (`scripts/ko-style/`): translation-ese patterns and the repository's terminology decisions (디렉터리/배지 spellings, 컬럼→열, 리포트→보고서, no coined words), with a self-test proving the linter still detects violations. Applying it fixed six live violations. (#417)
- The SPDX checks the Windows verification round left to a human eye — the SPDX chip and the chip addressing the `.spdx.json` artifact — are now Playwright specs, now covering the on-demand export flow that replaced the scan-form toggle. (#419)

### Documentation

- The AI-model path is now visible from the entry points. The landing intro listed inputs as source, container, binary or a received SBOM — omitting firmware and AI models entirely — so a visitor looking for a G7 or EU AI Act SBOM tool found nothing on the front page. (#427)
- The AI model guide now says where `scan-sbom.sh` comes from. It opened with `docker pull` and then invoked the script without linking any installation page, which left a reader arriving from an external guide unable to run the first command. (#440)
- Documented the SPDX export toggle in the web UI reference pages. (#436)
- The README demo GIF is now reproducible: a tagged Playwright spec drives a stubbed scan through the walkthrough and the recording is made in the same pinned container as the guide screenshots. The previous hand recording predated the regulatory crosswalk, license classification and current New scan form, and rotted silently whenever the UI moved. (#424)
- Synced the docs site and README with features shipped across v1.5–v1.8 that were undocumented, thin, or inaccurate: the web UI upload step (Dependency-Track/TRUSCA), the Maven/Node full-graph opt-outs (`BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`), the conformance spec-version overrides (`CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS`, `SPDX_SPEC_VERSIONS`), the `ENRICH_EOL` and `STALENESS_ENRICH` variables, the AI compliance profile card and `_ai-profile.*` artifacts, and the `--ui --mount` host-folder option. Corrected the `--all` description, which omitted the `--spdx` it also implies, and the "(CLI only)" note on `--byte-stable`, which has a web UI toggle as well. (#409)
- Added a CI gate (`scripts/check-doc-env-coverage.sh`) that fails when a user-facing environment variable in `scan-sbom.sh --help` is documented in neither the CLI nor the Docker-image reference — the code-to-docs counterpart of the existing docs-to-code drift check. Applying it documented the previously missing `SBOM_AIBOM_IMAGE` override. (#410)
- Korean pages: fixed translationese and coined terms concentrated in the web UI reference and the vendored-OSS guide, unified three drifting notations (디렉터리, 배지, 보고서), and recorded the terminology decisions in the style guide. (#415)
- English pages: a native-quality pass fixed two real defects — firmware-guide links mislabeled "(Korean)" and stale tool version pins in the architecture page — plus literal collocations, run-on passages, and naming consistency. (#418)
- Guide screenshots were regenerated in the pinned Playwright container, so the conformance section and New scan form images match the shipped UI (regulatory crosswalk, AI compliance card, SPDX toggle). (#416)

## [v1.8.2] - 2026-07-15

### Changed

- Supplier-SBOM conformance no longer fails outright on `pkg:generic` or custom PURLs. These were a mandatory check, so a single untraceable component failed the whole verdict even when every other requirement was met — common for embedded and firmware supplier SBOMs. The `no-generic` check is now advisory (a warning, not folded into the recommended-coverage warnings), the count stays visible through a new `untraceableComponents` field and a report line, and the overall pass/fail is left to the remaining mandatory checks.

### Fixed

- The SPDX conformance transitive-dependency check now counts `DEPENDENCY_OF` relationships as well as `DEPENDS_ON`. Syft writes OS-package dependency edges in SPDX as the reverse relationship `DEPENDENCY_OF` (for example `NetworkManager-libnm DEPENDENCY_OF NetworkManager`), never `DEPENDS_ON`, while the same scan's CycloneDX carries `dependsOn`. The check only asks whether dependency edges exist, so it now accepts both directions; previously every Syft-generated SPDX submission received a false transitive failure despite a fully populated dependency graph. Both the SPDX JSON and Tag-Value paths are covered; the CycloneDX path is unchanged.
- Post-processing modes now fail closed when the finished SBOM never reaches the host. The host-output verification was gated on `--generate-only`, so the default path — including ANALYZE — printed "Analysis Complete!" over an empty folder when the `/host-output` mount did not reach the host (an output directory outside Docker Desktop file sharing, or under `/tmp` on Colima, where only the home directory is shared to the VM). Every post-processing mode writes the output file, so its absence now reports the failure in all modes.
- Source-tree enrichment is confined to source-scan modes. The vendored-OSS (SCANOSS) and CocoaPods steps read the mounted source root with no mode guard, and the web UI mounts its host directory for every mode, so an ANALYZE of a supplier SBOM could discover a stray `Podfile.lock` in that tree and merge unrelated components into the result. Both steps are now gated on the scan mode, so ANALYZE, MERGE, IMAGE, BINARY, ROOTFS, FIRMWARE, and AIBOM no longer scan a mounted source tree.
- Empty file components from SPDX conversion are dropped. Syft's SPDX-to-CycloneDX conversion turns each SPDX file entry into a `file` component with no name and no PURL — an unidentifiable row with no CVE match, license, or attribution. A supplier SPDX with a large file section added thousands of these, skewing the notice count and the UI inventory. A normalize filter now drops only components that are both a file and carry neither name nor PURL; real packages and named or PURL-bearing file components are untouched.

## [v1.8.1] - 2026-07-15

### Added

- Regulatory crosswalk on the AI SBOM conformance report: each G7 minimum element that maps to a regulation is linked to the documentation obligation it touches, so a reviewer can see which regulatory requirement a missing element concerns. Two frameworks are mapped — the EU AI Act's Annex IV technical documentation (Regulation (EU) 2024/1689, Article 11(1)) and the Korean AI Framework Act (제31/32/33·34/35조). It is informational only: it never changes a check's status or the overall result, and the report states that BomLens does not certify compliance with any regulation. The mapping lives in `docker/lib/regulation-crosswalk.json`, keyed by G7 element id and validated against the registry so it cannot drift silently.
- AI compliance profile: for an AI SBOM, a one-page profile (`{prefix}_ai-profile.{json,md,html}`) re-aggregates the G7 status by cluster, the regulatory crosswalk, and the components whose license is flagged for review (AI behavioral-use or non-commercial). It runs no scan, makes no compliance determination, and is a no-op for a non-AI SBOM.
- Web UI: the Conformance section now shows the regulatory crosswalk as a sub-block (per-framework present/gap/review with the no-certification disclaimer) and a compact AI compliance summary card, and the AI profile reports are listed and downloadable.

### Changed

- The repository and tool identifiers were renamed from sbom-tools to bomlens; references across the docs, configuration, and image names were updated.

## [v1.8.0] - 2026-07-13

### Added

- Components past their published end-of-life are now flagged, offline by default. A bundled endoflife.date snapshot is matched by PURL coordinate (accuracy-first closed mapping — an unmapped component is left untouched, never guessed), and the result is surfaced in the web UI results. A runtime or framework past EOL receives no upstream fixes, so this answers a supply-chain question distinct from CVEs.
- Component version currency: the same snapshot reports when a component is behind the newest patch of its own release line (offline, default on — a safe in-cycle upgrade signal). With `STALENESS_ENRICH=true`, deps.dev is queried per package (opt-in, default off) for the absolute newest version, releases-behind, and last-release date across npm, PyPI, Maven, Go, Cargo, NuGet, and RubyGems.
- Opt-in SPDX output: `--spdx` (env `GENERATE_SPDX`, included in `--all`) additionally exports the finished BOM as SPDX 2.3 JSON (`{prefix}_bom.spdx.json`) after every enrichment step, with its own signature under `--sign` and byte-stable output under `--byte-stable`. The web UI gains an "SPDX export" toggle. CycloneDX remains the working and upload format; CycloneDX-only data (vulnerabilities, `bomlens:*` properties) is not carried over.
- The web UI can scan directories outside the launch folder — including the running host OS. `scan-sbom.sh --ui --mount <dir>` (repeatable; `SBOM_UI_MOUNT_DIR` for the Windows launcher) mounts each directory read-only and the Directory path input offers them as scan locations. The desktop app adds an in-app folder picker that persists the mounts across restarts. Scanning a live `/` excludes `/proc`, `/sys`, `/dev`, and `/run`.
- The sidebar rail and the overview jump card now show the conformance coverage figure (G7 element coverage for AI SBOMs, passed/total format checks otherwise), like the component and vulnerability counts.
- THIRD_PARTY_LICENSES.md now records the web UI's bundled fonts (Inter and JetBrains Mono, both OFL-1.1) with the attribution the license requires.

### Changed

- Supplier-SBOM conformance now enforces two more submission requirements as mandatory checks: the spec version must be in the accepted range (CycloneDX 1.3–1.6 and SPDX 2.2–2.3, overridable via `CYCLONEDX_SPEC_VERSIONS`/`SPDX_SPEC_VERSIONS`; AI SBOMs also accept CycloneDX 1.7, which the AIBOM toolchain emits), and every PURL must follow the standard `pkg:type/name@version` shape — colon coordinates, a missing `pkg:` prefix, a missing version, or raw spaces now fail with the offending PURLs listed. Previously only PURL presence and the `pkg:generic` ban were enforced, so a schema-valid SBOM with malformed PURLs passed.
- Firmware CVE matching no longer bundles cve-bin-tool's ~1.5 GB NVD database, which could not be built reliably — cve-bin-tool's NVD `api2` fetch is rate-limited into multi-hour stalls (and blocked outright from cloud runner IPs), and its `json-mirror` source is dead. cve-bin-tool now only identifies firmware binaries; their CPEs are matched against a compact index (~130 MB) distilled at build time from the NVD data feeds (`fkie-cad/nvd-json-data-feeds`, a plain git clone with no rate limit or API key). The firmware image builds on standard cloud runners again — no NVD key, no BuildKit secret, and no self-hosted runner — while offline/air-gap matching and the security-report contract are unchanged.

### Fixed

- `scan-sbom.sh --ui` no longer requires a TTY, so the documented web UI entry point works from CI, pipes, and wrappers instead of dying with `the input device is not a TTY`.
- When a zip created by PowerShell `Compress-Archive` is rejected by the container's `unzip` (backslash-separated entries), the scan now explains the cause and suggests re-zipping with Explorer instead of printing a bare `unzip failed`.
- Web UI layout defects found in a full-screen visual audit: the new-scan settings panel fits one screen again (advanced options and upload are collapsed disclosures with an enabled-count badge), large dependency graphs snap to a legible zoom instead of rendering as a dot cloud (the snap handler was attached after the synchronous initial layout and never fired), small result tables no longer pad to an empty 256px box, the overview card grid no longer leaves a lopsided empty tail, and the security artifact card no longer shows two identical "JSON" chips.

## [v1.7.0] - 2026-07-08

### Added

- iOS apps are now supported: a CocoaPods `Podfile.lock` or a Swift Package Manager `Package.resolved` is read into the SBOM with the full transitive pod/package set, and — for CocoaPods — the dependency graph reconstructed from the lockfile. Resolution is lockfile-first, so it runs offline and needs neither the `pod` CLI nor macOS. (cdxgen's own CocoaPods path requires `pod`, which the Swift image does not carry, and it aborted the scan when a `Podfile` was present.)
- The web UI can upload the generated SBOM to a Dependency-Track or TRUSCA server (previously CLI-only). New scan has an optional Upload section for the destination, server URL, API token, and — for TRUSCA — the project id. The token is stashed single-use and the server URL and token are used for that run only, never stored.
- New scan exposes a "Reproducible output" toggle in the advanced options, surfacing the byte-stable mode that was previously CLI-only. When on, re-scanning the same source produces a byte-for-byte identical SBOM. The toggle is hidden for supplier-SBOM analysis and AI model scans, where it does not apply.

### Changed

- Best-effort post-processing steps (normalize, CPE and AIBOM enrichment, conformance, vendored-OSS suggestion) no longer swallow real failures. They kept the never-abort guarantee by ending in `|| true`, which also hid genuine errors; each step now logs a WARN and stamps `bomlens:pipeline-step-failed` on the SBOM when it fails, so a degraded run is visible instead of silently incomplete.

### Fixed

- Maven source scans no longer inflate the SBOM with the test and provided toolchain (junit, lombok, etc.). The scan is scoped to the deployable runtime set using cdxgen's resolved scope tags — compile and runtime dependencies are kept, test and provided ones are dropped — the Maven analogue of the Android and npm release-scope fixes. Set `BOMLENS_MAVEN_FULL_GRAPH=1` to keep the full graph.
- Android product-flavor projects now scope to the release runtime classpath instead of silently falling back to the full build + test graph. The release-config selection dropped every candidate when a project had no plain `releaseRuntimeClasspath` (only flavored variants such as `freeReleaseRuntimeClasspath`), so flavored apps were reported with their whole toolchain. It now prefers the plain classpath and otherwise takes the first flavored release variant.
- Node.js (npm) source scans no longer inflate the SBOM with the `devDependencies` tree (jest, eslint, the Babel toolchain, etc.). The scan is scoped to the deployed `dependencies`, so build and test tooling the app never ships is excluded — the npm analogue of the Android release-scope fix. Set `BOMLENS_NODE_FULL_GRAPH=1` to keep the dev + prod superset.
- Android (AGP) source scans no longer inflate the SBOM with the build and test toolchain. The scan is scoped to the deployable release runtime classpath, so only the components shipped in the APK are recorded.
- Firmware scans no longer silently report zero CVEs from a vulnerability database that lacks NVD data. The build gate now rejects a bundled CVE database without a real NVD advisory corpus instead of shipping it.
- Native Windows source scans work under Git for Windows: docker bind mounts and the Git Bash resolution in `scan-sbom.bat` were corrected so a Windows (MSYS) shell can run a scan instead of failing at container start.
- Windows web/desktop UI source scans resolve transitive dependencies again. The cdxgen (and firmware/AIBOM) sibling containers were bind-mounted by a Windows drive path (`C:/…`) that the in-container Linux docker CLI cannot consume, so the scan silently fell back to syft (direct dependencies only). The siblings now inherit the UI container's mounts with `--volumes-from`, so they run on every host OS — verified on Windows, where UI and CLI scans now produce identical SBOMs.
- Firmware security reports are no longer empty. The bundled Trivy could not decode the firmware SBOM's `firmware` root component type and failed the whole scan; Trivy is now retried on an input copy whose root type is coerced to one it accepts, so the vulnerability report is populated while the delivered SBOM keeps its accurate `firmware` type.

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
- Rendered documentation site (sktelecom.github.io/bomlens) with sidebar navigation, search, and a one-click Windows download, replacing repo-only docs. (#112, #113, #114, #115, #116)
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

[Unreleased]: https://github.com/sktelecom/bomlens/compare/v1.8.2...HEAD
[v1.8.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.2
[v1.8.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.1
[v1.8.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.0
[v1.7.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.7.0
[v1.6.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.6.0
[v1.5.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.5
[v1.5.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.4
[v1.5.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.3
[v1.5.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.2
[v1.5.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.1
[v1.5.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.0
[v1.4.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.4.0
[v1.3.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.1
[v1.3.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.0
[v1.2.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.2
[v1.2.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.1
[v1.2.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.0
[v1.1.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.1
[v1.1.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.0
[v1.0.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.0.0
