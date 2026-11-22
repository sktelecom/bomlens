---
description: Call the BomLens scanner Docker image directly with docker run, for CI runners, Kubernetes jobs, and other environments where the script cannot live.
---

# Use the Docker image directly

For everyday use we recommend the [`scan-sbom.sh`](../reference/cli.md) script, which handles language detection, image selection, and volume mounts for you. This document explains how to call the image directly with `docker run` in environments where the script cannot live (CI runners, Kubernetes jobs, and so on).

## Images and tags

| Image | Purpose |
|--------|------|
| `ghcr.io/sktelecom/bomlens` | Scanning and post-processing (canonical name) |
| `ghcr.io/sktelecom/sbom-generator`, `ghcr.io/sktelecom/sbom-scanner` | Aliases of the same image (former names, same digest) |
| `ghcr.io/sktelecom/bomlens-firmware` | Firmware analysis (includes GPL tools, opt-in) (legacy alias: sbom-scanner-firmware) |
| `ghcr.io/sktelecom/bomlens-deep-cve` | Bundles grype for deep CVE matching (opt-in). Used by the CLI's `--deep-cve` and by the web UI's Deep CVE matching toggle, both of which pull it automatically as a sibling container when it is not already the running image |
| `ghcr.io/sktelecom/bomlens-deep-license` | Bundles scancode for licence detection in the project's own files (opt-in). Used by the CLI's `--deep-license` for a source scan, pulled automatically. Carries LGPL components (7-Zip on linux/amd64, intbitset, chardet); the source for 7-Zip and intbitset is in the image under `/usr/share/bomlens/sources/`, and chardet ships as Python source |
| `ghcr.io/sktelecom/bomlens-aibom` | Generates an AI-model ML-BOM (opt-in, legacy alias: sbom-scanner-aibom). Used by `--model`/`--model-file` and the web UI's AI model tile, pulled automatically as a sibling container |

`latest` and version tags are available. All published images (`ghcr.io/sktelecom/bomlens`, `bomlens-firmware`, `bomlens-deep-cve`, `bomlens-deep-license`, `bomlens-aibom`, and their aliases) support both `linux/amd64` and `linux/arm64`, so pulling any of them on an `arm64` host (an Apple Silicon Mac, an Arm server) works natively. Images are signed with cosign before publishing.

On an `arm64` host, do not force `linux/amd64` (`--platform linux/amd64` or `DOCKER_DEFAULT_PLATFORM=linux/amd64`): the image then runs under emulation, where syft in the firmware image can crash. A firmware scan tries a failed syft pass once more (not one that ran out of its time limit or was killed for memory), says in the log that it runs under emulation, and records `generate` as `degraded` in `bomlens-result.json` when the second try also fails.

```bash
docker pull ghcr.io/sktelecom/bomlens:1.15.2   # a release tag; :latest is built from main
```

## What is in the image

It is a lightweight image (based on python 3.12 slim) without language toolchains. For source scans, transitive dependency resolution is handled by the script, which pulls per-language cdxgen images separately. See [Architecture](../concepts/architecture.md) for the structure.

| Tool | Version | Role |
|------|------|------|
| syft | v1.54.1 | Scans images, binaries, and directories |
| Trivy | v0.75.0 | Vulnerability report |
| cosign | v3.1.3 | SBOM signing |
| jq | — | SBOM normalization and notice generation |
| ScanCode Toolkit | 32.5.0 | Precise license detection (included only in opt-in builds) |
| SCANOSS | 1.54.3 | Identifies open source copied into C/C++ source (`--identify-vendored`) |
| docker CLI | 29.9.2 | Starts a sibling cdxgen container when the web UI runs a source scan |
| cdxgen | 13.5.0 | Model pedigree enrichment (`bomlens-aibom` image only) |

Tool versions are pinned with `ARG` in `docker/Dockerfile`.

Every image also carries the NVD CPE index (`cpe_match.sqlite`, about 146 MB), built from the NVD data when the image is built. Firmware, root filesystem and binary scans with `--security` match the CPEs of components that have no package PURL against it, with no network (see [How CVEs are matched](../guides/firmware.md#how-cves-are-matched)). Building it clones the NVD data feeds from GitHub. When you build an image yourself where GitHub is not reachable, the build stops at that step and names `--build-arg SBOM_CPE_INDEX=false`, which leaves the index out; a firmware build does not accept it, so the firmware image always has the index.

## How much disk do the images take?

The scanner image `ghcr.io/sktelecom/bomlens` takes about 1.4 GB on disk once unpacked. A source scan then downloads one more image for the project's language, and these are much larger. The sizes below are what each image takes on disk, measured with the cdxgen tag recorded in `docker/lib/image-sizes.json`.

| Image | Used for | Size on disk |
|-------|----------|--------------|
| `bomlens` | every scan | about 1.4 GB |
| `cdxgen-alpine-node24` | Node.js | about 2.9 GB |
| `cdxgen-debian-golang124` | Go | about 3.8 GB |
| `cdxgen-java17` | Java with a Java 17 toolchain | about 3.8 GB |
| `cdxgen-debian-rust` | Rust | about 4.0 GB |
| `cdxgen-debian-ruby34` | Ruby | about 4.2 GB |
| `cdxgen-debian-php84` | PHP | about 4.3 GB |
| `cdxgen-python312` | Python | about 4.9 GB |
| `cdxgen-temurin-java21` | Java (default) | about 5.6 GB |
| `bomlens-android-sdk<API>` | Android, built locally, one per API level | about 6.3 GB |
| `cdxgen-debian-dotnet9` | .NET | about 14.7 GB |
| `cdxgen` | a tree that mixes languages | about 16 GB |

The Swift image and the opt-in images (`bomlens-firmware`, `bomlens-aibom`, `bomlens-deep-cve`) are not in this table because no size is recorded for them. An AI model scan downloads about 3.5 GB ([AI model SBOM](../guides/ai-model.md)).

Before it downloads an image, `scan-sbom.sh` prints the size and stops when the Docker engine has less free than that size plus 2 GB, naming the free space, the download size and how to clean up. The web UI only warns. `BOMLENS_SKIP_DISK_CHECK=1` skips the check. Free space that cannot be read gives a warning and the scan goes on. On macOS and Windows the engine runs in a VM whose disk is a file on the host, and some engines (Rancher Desktop, Docker Desktop on WSL 2) report the VM disk's maximum size, so the free space used is the smaller of the engine's value and the free space on the host disk that holds your home folder. `scripts/check-setup.sh` (and `check-setup.bat`) lists the BomLens images on the machine (and the scanner image `SBOM_SCANNER_IMAGE` names) with their sizes, their total and the engine's free space.

### How do I free the space?

Remove only the images BomLens downloaded, by name, so your other images stay:

```bash
docker image ls --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '^ghcr\.io/(cdxgen/|sktelecom/)|^bomlens-android-sdk' \
  | xargs docker image rm
```

`docker image prune -a` removes every image no container uses, not only BomLens's. The images are downloaded again when a scan needs them. Scan results are not touched.

Deleting images inside Docker does not always give the space back to the computer, because the engine's disk file keeps its size. Compact it afterwards:

- Docker Desktop and Rancher Desktop: raise the disk size in Settings > Resources, or compact the disk. On Windows the engine's disk is a `.vhdx` file (Rancher Desktop keeps `ext4.vhdx` under `%LOCALAPPDATA%\rancher-desktop\distro-data`) that `Optimize-VHD` or `diskpart` can compact, with the app closed and administrator rights.
- Colima: `colima ssh -- sudo fstrim -av`.

## Running directly

Select the analysis mode with the `MODE` environment variable. All examples below leave their outputs in the current directory and do not upload anything (`UPLOAD_ENABLED=false`).

### Analyze a Docker image

On Git Bash (Windows), MSYS rewrites both `/var/run/docker.sock` and the
container-side `/host-output` into Windows paths before Docker ever sees
them, silently breaking both mounts. `MSYS_NO_PATHCONV` and
`MSYS2_ARG_CONV_EXCL` below turn that rewriting off, and `cygpath -m`
converts the host side back by hand instead (`scripts/scan-sbom.sh` uses the
same pair for the same reason). WSL2, macOS and Linux shells don't rewrite
paths and skip straight to the plain `docker run` line.

<!-- runnable -->
```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/host-output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MODE=IMAGE \
  -e TARGET_IMAGE="nginx:alpine" \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Nginx" \
  -e PROJECT_VERSION="alpine" \
  ghcr.io/sktelecom/bomlens:latest
```

### Analyze a binary file

```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/target \
  -v "$HOSTPATH":/host-output \
  -e MODE=BINARY \
  -e TARGET_FILE=/target/firmware.bin \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Firmware" \
  -e PROJECT_VERSION="1.0" \
  ghcr.io/sktelecom/bomlens:latest
```

### Analyze a source directory

<!-- runnable -->
```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/src \
  -v "$HOSTPATH":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="MyApp" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

In direct runs, `SOURCE` mode reads a lock file that covers the whole tree (a `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock` or `gradle.lockfile`, with no other manifest below the root) as it is, with no build and no Docker socket, and fills the licenses it lacks from the package registry; the SBOM records this as `bomlens:detection`. That is the form to use where there is no Docker to start a sibling container in, such as a CI job that runs this image as its job image. For any other tree, syft reads the package manifests inside the container, so it may only capture direct dependencies; if you need transitive dependencies there, use `scan-sbom.sh`, which routes to the per-language cdxgen images. Syft's manifest readers need a lockfile (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` for Node, and the equivalent for other ecosystems) to resolve any of a project's declared dependencies; without one, direct-run SOURCE mode has nothing to read and the scan fails with guidance rather than reporting an empty result as complete.

### Notice and reports in one run

In direct runs, the notice and security reports are off by default. Turn on the following variables to get the same outputs as the CLI's `--all`.

<!-- runnable -->
```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/host-output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MODE=IMAGE \
  -e TARGET_IMAGE="nginx:alpine" \
  -e GENERATE_NOTICE=true \
  -e GENERATE_SECURITY=true \
  -e GENERATE_REPORT=true \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Nginx" \
  -e PROJECT_VERSION="alpine" \
  ghcr.io/sktelecom/bomlens:latest
```

## Environment variables

| Variable | Required | Default | Description |
|-----------|------|--------|------|
| `MODE` | No | `POSTPROCESS` | Analysis mode: `SOURCE`, `IMAGE`, `BINARY`, `ROOTFS`, `FIRMWARE`, `ANALYZE`, or `PLAN` (write the execution plan of a source scan, see [Engine contract](engine-contract.md#execution-plan)). Left unset, the container only post-processes an SBOM already sitting in the output directory — set it explicitly to actually scan something. |
| `PROJECT_NAME` | Yes | — | Project name |
| `PROJECT_VERSION` | Yes | — | Project version |
| `TARGET_IMAGE` | Per mode | — | Image for `IMAGE` mode. With the docker.sock mount it is read from the Docker daemon; without it, from the registry, or from an archive named with its scheme (`docker-archive:`, `oci-archive:`, `oci-dir:`) at a path mounted into the container |
| `SYFT_REGISTRY_AUTH_USERNAME`, `SYFT_REGISTRY_AUTH_PASSWORD`, `SYFT_REGISTRY_AUTH_TOKEN`, `SYFT_REGISTRY_AUTH_AUTHORITY` | — | — | `IMAGE` mode: credentials for a private registry. A docker config file mounted and named in `DOCKER_CONFIG` works too. `SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY` and `SYFT_REGISTRY_INSECURE_USE_HTTP` reach a registry with a self-signed certificate or plain HTTP. `SYFT_PLATFORM` picks the platform of a multi-platform image |
| `TARGET_FILE` | Per mode | — | File path for `BINARY`/`FIRMWARE` mode (path inside the container) |
| `TARGET_DIR` | Per mode | — | Directory path for `ROOTFS` mode |
| `UPLOAD_ENABLED` | — | `true` | If `false`, save locally without uploading (same as CLI `--generate-only`) |
| `HOST_OUTPUT_DIR` | — | — | Mounted path to copy the outputs to |
| `BOMLENS_STAGE1_EXIT`, `BOMLENS_STAGE1_OOM`, `BOMLENS_STAGE1_LOG`, `BOMLENS_STAGE1_REASON` | — | — | `POSTPROCESS` after a stage 1 you ran yourself: its exit code, `true` if it was killed for memory, and its log's file name in the output folder; or, instead of the last two, the reason already classified (`oom`, `disk-space`, `tls-trust`, `registry-auth`, `network`, `cdxgen-crash`, `cdxgen-unavailable`). Exit code 127 is read as `cdxgen-unavailable`: pass it for an `unsupported` plan, where no stage 1 ran. Stage 2 then falls back to a syft scan when stage 1 left no SBOM (see [Engine contract](engine-contract.md#execution-plan)) |
| `BOMLENS_EVENTS` | — | — | `file` or `stderr`: write progress events, one JSON object per line, to `bomlens-events.jsonl` in the output folder or to stderr (see [Engine contract](engine-contract.md#progress-events)) |
| `BOMLENS_IMAGE_REF`, `BOMLENS_IMAGE_DIGEST` | — | — | The image reference and digest the caller ran, repeated in `bomlens-result.json` (see [Engine contract](engine-contract.md)) |
| `GENERATE_NOTICE` | — | `false` | Generate the open-source notice (CLI `--notice`) |
| `GENERATE_SECURITY` | — | `false` | Generate the Trivy security report (CLI `--security`) |
| `DEEP_LICENSE` | — | `false` | Detect licences in the project's own files with scancode (CLI `--deep-license`; needs scancode in the image) |
| `DEEP_LICENSE_MAX_FILES` | — | `20000` | `DEEP_LICENSE`: a tree with more of the project's own files than this is not scanned |
| `DEEP_LICENSE_TIMEOUT` | — | `600` | `DEEP_LICENSE`: seconds before scancode is stopped |
| `BOMLENS_DEEP_LICENSE_ALL` | — | — | `DEEP_LICENSE`: set `1` to scan dependency, build and tool folders too (left out by default) |
| `DETECTION` | — | `auto` | `SOURCE` mode only. `auto` reads a covering lock file statically and otherwise runs the build or syft path as before; `static` always reads statically; `build` never does (CLI `--detection`). Static detection fills missing licenses from the package registry, so `auto` builds under `BYTE_STABLE=true` or `FETCH_LICENSE=false` |
| `REACHABILITY` | — | `false` | Judge with govulncheck whether each Go advisory's code is reached (CLI `--reachability`): on the executable in `BINARY` mode; in `SOURCE` and `POSTPROCESS`, from the govulncheck output stage 1 left (the CLI hands stage 1 the image's govulncheck) |
| `GENERATE_REPORT` | — | `false` | Generate the open-source risk report (off in direct runs, unlike the CLI default) |
| `ENRICH_MAVEN_CPE` | — | `true` | Attach an NVD-matchable `cpe:2.3` to maven components (derived from the groupId) so a CPE-aware engine can reach their NVD-only CVEs; unmapped groups get no CPE (skipped for AI SBOMs) |
| `ENRICH_GITHUB_CPE` | — | `true` | Attach an NVD-matchable `cpe:2.3` to a small, hand-verified set of `pkg:github/` components (source-repository-only coordinates, typical for large C/C++ projects with no package-manager ecosystem) so a CPE-aware engine can reach their NVD-only CVEs; anything not in the curated list gets no CPE (skipped for AI SBOMs) |
| `ENRICH_UPSTREAM_PURL` | — | `true` | For a firmware, root filesystem or binary scan, or an SBOM read from a Yocto build's records, set the purl of the upstream source repository (`pkg:github/<owner>/<repo>@<tag>`, `pkg:sourceforge`, `pkg:gnu`) on components that have no purl, a `pkg:generic` one or a `pkg:opkg` one, from the closed table in `docker/lib/upstream-purl-map.json`, or from a source download address that states a GitHub or GNU release. Any other component keeps its identifier |
| `ENRICH_INTERPRETER_CPE` | — | `true` | Attach an NVD-matchable `cpe:2.3` to a small, hand-verified set of interpreter components (e.g. Python packaged as a conda or NuGet artifact) so a CPE-aware engine can reach their NVD-only CVEs; anything not in the curated list gets no CPE (skipped for AI SBOMs) |
| `SECURITY_NVD_VERIFY` | — | `false` | With `--deep-cve`: verify each grype `nvd:cpe` finding against the live NVD version range and drop out-of-range false positives (needs `NVD_API_KEY` + network; adds minutes). Off by default — findings are kept and flagged version-unverified |
| `NVD_API_KEY` | For `SECURITY_NVD_VERIFY` | — | NVD API key used by the deep-cve version filter; passed to the container by name only (never inlined) |
| `BOMLENS_OS_LICENSES` | — | `true` | `IMAGE` and `ROOTFS` modes: read the licenses of Debian packages with Trivy, which reads the license names, common-licenses references and license text in the copyright files syft leaves as a hash. It reads the image a second time; `false` turns it off (the hashes are still removed) |
| `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` | — | `7` | With a Trivy database mounted at `/trivy-db` (read as it is, offline): the age in days past which the security step is recorded as degraded |
| `BOMLENS_GRYPE_DB_MAX_AGE_DAYS` | — | `7` | With `--deep-cve`: the age in days past which the grype database is updated with `grype db update` before the match (into a temporary folder when the image's cache cannot be written; skipped when `TRIVY_OFFLINE_SCAN` or `TRIVY_SKIP_DB_UPDATE` is `true`). A database that is not updated is still read, and the `deep-cve` step is recorded as degraded with its age. The update lives only as long as the container, so while the image's database is old every scan downloads it again. A Trivy database mounted at `/trivy-db` makes the scan offline, so grype is not updated either |
| `GRYPE_DB_UPDATE_URL` | — | grype's own | With `--deep-cve`: where `grype db update` gets the grype database, for a mirror |
| `BOMLENS_GO_VULNDB` | — | `true` | With `--security`: also match Go modules against the Go vulnerability database snapshot in the image. `false` skips it |
| `BOMLENS_GO_VULNDB_PATH` | — | the snapshot in the image | A Go vulnerability database export inside the container (`vulndb.zip` from https://vuln.go.dev/vulndb.zip, or that archive unpacked into a folder), read in place of the snapshot. It is never replaced by a download, only recorded as degraded when it is old |
| `BOMLENS_GO_VULNDB_MAX_AGE_DAYS` | — | `7` | The age in days past which the Go vulnerability database is old, counted from when the export was taken from its source (recorded at image build and at a download, else the file's modification time). The export's own date in `index/db.json` counts only when it is later; vuln.go.dev republishes the export daily even when that date stays put. An old snapshot in the image is replaced for that scan by a download (about 3.6 MB, 60-second limit) into a temporary folder, removed when the scan ends; when the scan is offline (`TRIVY_OFFLINE_SCAN` or `TRIVY_SKIP_DB_UPDATE` is `true`, as with a `/trivy-db` mount) or the download fails, the old snapshot is read and the `go-vulndb` step is recorded as degraded |
| `BOMLENS_GO_VULNDB_URL` | — | `https://vuln.go.dev/vulndb.zip` | Where that download comes from: a mirror of `vulndb.zip` (`http`, `https` or `file` URL). It is checked as the image build checks it before it is read |
| `BOMLENS_EXTRA_CA_CERTS` | - | - | A CA bundle (PEM) to trust, for a proxy that inspects TLS: a path inside the container. When you run the image yourself, mount the bundle (read-only is enough) and set this to its path. The entrypoint adds it to a copy of the system bundle (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `GIT_SSL_CAINFO`, `PIP_CERT`), to `NODE_EXTRA_CA_CERTS` and to a copy of the JDK trust store named in `JAVA_TOOL_OPTIONS`. These files are written under `/tmp` only, so a read-only root filesystem works with a writable `/tmp`. A path that cannot be read or holds no PEM certificate prints a `[WARN]` and the run goes on without the extra CA. The CLI sets this for you from `SBOM_EXTRA_CA_CERTS` |
| `ENRICH_EOL` | — | `true` | Flag components past their upstream end-of-life from a bundled offline snapshot (skipped for AI SBOMs) |
| `ENRICH_MALICIOUS` | — | `true` | Flag components that are known-malicious packages (typosquats, hijacked accounts) from a bundled offline OSV snapshot. A separate signal from vulnerabilities: the response is removal and credential rotation, not an upgrade |
| `ENRICH_OS_CONTEXT` | — | `true` | Synthesize an `operating-system` component from distro package PURLs (rpm, deb, and apk). Trivy selects the distro vulnerability feed from that component, so without it the OS packages in a supplier SBOM or rootfs scan would get no OS CVE matches at all. No-op when the SBOM has no recognizable distro packages — including a distro Trivy carries no feed for, such as OpenWRT (skipped for AI SBOMs) |
| `ENRICH_DISTRO_SUPPLIER` | — | `true` | Fill `supplier` on an rpm, deb, or apk component with the distro project's name, read from the `operating-system` component `ENRICH_OS_CONTEXT` synthesizes. Left blank for a distro with no confirmed supplier name, an ambiguous (mixed-distro) SBOM, or a component that already carries a supplier (skipped for AI SBOMs) |
| `STALENESS_ENRICH` | — | `false` | Add deps.dev version currency (how many releases behind latest); needs network access |
| `ENRICH_HF_SECURITY` | — | `true` | AIBOM mode: read HuggingFace's per-file security scan results (ClamAV + picklescan) into the ML-BOM; metadata only, no file download |
| `API_KEY`, `API_URL` | For uploads | — | Upload credential and server URL. DT uses `X-Api-Key`; TRUSCA uses a Bearer token |
| `UPLOAD_TARGET` | — | `dependency-track` | Upload destination: `dependency-track` (DT-compatible) or `trusca` (native ingest, not DT-compatible) |
| `TRUSCA_PROJECT_ID` | When `trusca` | — | Target TRUSCA project id (UUID). Must already exist (no auto-create) |
| `TRUSCA_REF` | — | `main` | Ingest ref label |
| `TRUSCA_RELEASE` | — | `PROJECT_VERSION` | Ingest release label |
| `BOMLENS_MAVEN_FULL_GRAPH` | — | — | Maven source scans: set `1` to keep the full resolved graph instead of filtering to compile/runtime scope |
| `BOMLENS_NODE_FULL_GRAPH` | - | - | Node.js source scans: set `1` to keep the full dev-plus-production graph instead of the production-only set. This is the Node.js part of `BOMLENS_INCLUDE_DEV_DEPENDENCIES`, which does the same for Node.js and also keeps the development dependencies of the other ecosystems |
| `BOMLENS_NODE_INSTALLED_LOCK` | - | on | Node.js source scans: `false` (or `0`) leaves unread the lock file npm or pnpm wrote at install (`node_modules/.package-lock.json`, `node_modules/.pnpm/lock.yaml`). Otherwise a folder with a `package.json` and no committed lock file, in it or above it, is scanned with that lock in place of one, written for the scan only and removed afterwards ([Node.js](ecosystems.md#nodejs)) |
| `BOMLENS_ANDROID_FULL_GRAPH` | - | - | Android source scans (Android SDK image): set `1` to keep the full graph, build and test tooling included, instead of filtering to the release runtime classpath |
| `BOMLENS_GRADLE_FULL_GRAPH` | - | - | Java Gradle source scans: set `1` to keep the full graph, test and compile-only dependencies included, instead of filtering to each project's runtime classpath. The filter's Gradle run resolves every project, not only the root as the plain warm-up does, so on a build with many subprojects that step takes longer |
| `BOMLENS_MAVEN_USER_REPOSITORY` | - | on | Maven source scans: `false` (or `0`) leaves the user's Maven local repository unused when it is mounted at `/bomlens-settings/m2/repository`. Otherwise Maven reads it after this scan's own repository (`-Dmaven.repo.local.tail`, Maven 3.9 or later) without writing to it, cdxgen reads POMs, licenses and jar hashes from it (`MAVEN_CACHE_DIR`), and Maven runs offline (`-o`) only when the repository it would download from does not answer ([Java (Maven)](ecosystems.md#java-maven)) |
| `BOMLENS_MAVEN_PROBE_TIMEOUT` | - | `5` | Maven source scans with the user's Maven local repository mounted: seconds the repository Maven would download from (the first `<mirror>` in `settings.xml`, else Maven Central) gets to answer before Maven runs offline (`-o`) |
| `BOMLENS_GRADLE_USER_CACHE` | - | on | Gradle source scans: `false` (or `0`) leaves the user's Gradle cache and wrapper distributions unused when they are mounted at `/bomlens-user-cache/gradle` and `/bomlens-user-cache/gradle-wrapper`. Otherwise the cache is Gradle's read-only dependency cache (`GRADLE_RO_DEP_CACHE`), and Gradle runs `--offline` only when none of the build's repositories answers ([Java (Gradle)](ecosystems.md#java-gradle)) |
| `BOMLENS_PYTHON_VENV` | - | on | Python source scans: `false` (or `0`) leaves the project's installed virtual environment unread. Otherwise, when the source has `.venv/`, `venv/` or one other top-level folder with a `pyvenv.cfg`, and the package index pip would use does not answer a short probe or `pip install` fails, the Python part of the SBOM comes from that environment's `*.dist-info` metadata, read-only, and the SBOM records `bomlens:python-environment`. The environment folder is left out of cdxgen's search, the syft fallback and the static read either way ([Python](ecosystems.md#python)) |
| `BOMLENS_BUILD_TOOL` | - | `auto` | Java source scans of a folder with both `pom.xml` and `build.gradle`: `maven` or `gradle` reads only that tool's files, `auto` keeps Gradle. The CLI sets it with `--build-tool` |
| `BOMLENS_PHP_FULL_GRAPH` | - | - | PHP (Composer) source scans: set `1` to keep the full require-plus-require-dev graph instead of filtering to the required set. This is the PHP part of `BOMLENS_INCLUDE_DEV_DEPENDENCIES` |
| `BOMLENS_KEEP_BUILD_OUTPUT` | — | — | Source scans: set `1` to leave the resolved tree in place. By default the scan restores the files its resolvers rewrote (`go.mod`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `Package.resolved`) and removes the build directories they created, so the scanned project is handed back as it was |
| `BOMLENS_PREP_TIMEOUT` | - | `900` (`1800` for Gradle/Android steps) | Seconds a single dependency-resolution step (Cargo, Go, Bundler, pip, npm, pnpm, PHP Composer, Swift, Gradle/Android) is allowed to run before it is stopped and the scan moves on without it. Set to override both defaults for every step. A step that fails or times out is logged with its own output and recorded on the SBOM as `bomlens:pipeline-step-failed`; the scan itself still completes |
| `BOMLENS_LICENSE_PROBE_TIMEOUT` | - | `6` | Source scans with `FETCH_LICENSE` on: seconds the package registry of each ecosystem found gets to answer one request before cdxgen runs. A registry that does not answer turns the license lookup off for that scan, recorded on the SBOM as `bomlens:pipeline-step-failed` `license-fetch`. Licenses then come from lock files and package metadata; no dependency is missing, and the completeness grade does not count it (the CLI prints one `[INFO]` line, the web UI an information note) |
| `BOMLENS_LICENSE_FETCH_TIMEOUT` | - | `1800` | Source scans with `FETCH_LICENSE` on: seconds the cdxgen run may take before it is stopped and run again with the license lookup off (recorded as `license-fetch`). `0` removes the limit |
| `BOMLENS_CANCEL_GRACE` | — | `30` | Seconds a cancelled scan (CLI Ctrl+C, or the web UI's cancel button) gets to stop cleanly before it is force-stopped. Applies to the CLI and `--ui`; the desktop app always uses the default |
| `BOMLENS_REATTACH_GRACE` | - | `30` | Web UI: seconds a running scan that no browser tab shows keeps running, so a reloaded or another tab can open it again, before it is cancelled (0 to 600). Read by the web UI server in the container |
| `BOMLENS_INCLUDE_NON_SHIPPED` | - | - | Source scans: set `1` to keep the manifests under test, example, benchmark and demo folders, the GitHub Actions workflows in `.github/workflows` and the Gradle wrapper in `gradle/wrapper`, which are left out by default |
| `BOMLENS_INCLUDE_DEV_DEPENDENCIES` | - | - | Source scans: set `1` to keep the development dependencies that are left out by default, in every ecosystem: npm `devDependencies` and what only they need (the production filter is not applied, as with `BOMLENS_NODE_FULL_GRAPH=1`), the components cdxgen marks as development-only (npm, pnpm, yarn, bun, uv and Poetry dependency groups, Cargo, sbt, Crystal, Gleam), the gems a root `Gemfile` declares only in its `development` and `test` groups, Composer `require-dev` (as with `BOMLENS_PHP_FULL_GRAPH=1`), and the Poetry dependency groups read from an installed Python virtual environment. The components the development-marker filter drops are recorded in `bomlens:excluded-components`. Maven, Gradle and Android scope filters drop more than development dependencies and keep their own switches (`BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_GRADLE_FULL_GRAPH`, `BOMLENS_ANDROID_FULL_GRAPH`) |
| `BOMLENS_NO_COPYRIGHT` | - | - | Source scans: set `1` to skip filling npm, Python, Go and Rust component `copyright` from the installed packages' license files |
| `BOMLENS_NO_CARGO_LICENSE` | - | - | Source scans: set `1` to skip filling Rust component licenses from `cargo metadata` (`FETCH_LICENSE=false` on the command line skips it too) |
| `BOMLENS_NO_AI_USAGE` | - | - | Source scans: set `1` to skip recording the AI the code uses (models, AI services, MCP servers, agent instruction files; see [AI usage in a source scan](artifacts.md#ai-usage-in-a-source-scan)) |
| `BOMLENS_AI_USAGE_TIMEOUT` | - | `300` | Source scans: seconds each of the two AI usage analyses may run before it is stopped and its findings are left out |
| `CYCLONEDX_SPEC_VERSION` | — | `1.6` | CycloneDX version of the generated SBOM, `1.6` or `1.7` (the CLI's `--spec-version`). AI model and dataset SBOMs are always 1.7. Any other value stops the run |
| `CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6 1.7` | Accepted CycloneDX spec versions for the conformance check (space-separated); overrides the default range |
| `AI_CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6 1.7` | Accepted CycloneDX versions for AI SBOMs (ML-BOM); always includes 1.7, the version the AIBOM toolchain emits |
| `SPDX_SPEC_VERSIONS` | — | `SPDX-2.2 SPDX-2.3` | Accepted SPDX spec versions for the conformance check |
| `PURL_MIN_PCT` | — | `90` | Conformance check: minimum percentage of components with a PURL (mandatory check). Applies to a `--deep-cve` scan too, CLI or web UI |
| `LICENSE_MIN_PCT` | — | `80` | Conformance check: minimum percentage of components with a license (recommended, warn only). Applies to a `--deep-cve` scan too, CLI or web UI |
| `HASH_MIN_PCT` | — | `50` | Conformance check: minimum percentage of components with a hash (recommended, warn only). Applies to a `--deep-cve` scan too, CLI or web UI |
| `FIELD_MIN_PCT` | — | `80` | Conformance check: minimum percentage coverage for advisory per-component regulatory fields. Applies to a `--deep-cve` scan too, CLI or web UI |
| `PURL_TYPES_FILE` | — | `docker/lib/purl-types.json` | Conformance check: the purl-spec type data that says which types exist and which of them require a namespace |
| `OS_DISTROS_FILE` | — | `docker/lib/os-distros.json` | Conformance check: the distribution ids an rpm, deb or apk namespace may carry |
| `NS_ADVISORY_TYPES` | — | `golang huggingface` | Conformance check: types whose missing namespace is reported on the advisory row instead of failing the SBOM (space-separated) |
| `LICENSE_REGISTRY` | — | `false` | The script's `--license-registry`: look up missing licences, and check a single strong-copyleft or non-commercial licence, in the package registry (deps.dev). Uses the network |
| `LICENSE_REGISTRY_VERIFY` | — | GPL, AGPL, SSPL-1.0, BUSL-1.1 and CC-BY-NC ids | SPDX ids whose single occurrence is checked against the registry, space- or comma-separated |
| `LICENSE_REGISTRY_BUDGET` | — | `240` | Seconds the lookups may take in total. Components it does not reach are left as they were, and the step is recorded as degraded |
| `LICENSE_REGISTRY_API` | — | `https://api.deps.dev/v3` | Base URL of a server that answers the deps.dev v3 version lookup, for a network that reaches the registries only through its own mirror or proxy. When nothing answers, the components stay as they were and the step is recorded as degraded (`unavailable`) |
| `COCOAPODS_CDN_URL` | - | `https://cdn.cocoapods.org` | Source scans with `FETCH_LICENSE` on: base URL of the CocoaPods trunk CDN, or of a mirror with the same `Specs/` layout, that pod licenses are read from. When it does not answer, the pods keep no license and the log says so |
| `COCOAPODS_LICENSE_BUDGET` | - | `120` | Seconds the CocoaPods podspec lookups may take in total. Pods it does not reach keep no license |
| `PURL_RESOLVE` | — | `false` | `--analyze` only (the script's `--resolve-purl`): look each identifier up in its package repository (deps.dev) and add the answer to the conformance check report as an advisory row. Uses the network |
| `MODEL_RESOLVE` | - | `false` | Source scans (the script's `--resolve-models`): read each Hugging Face model the code references from the hub. Uses the network; `HF_ENDPOINT` points at a mirror and `HF_TOKEN` reads private models |
| `MODEL_RESOLVE_MAX` | - | `20` | Models looked up in one scan. The rest are marked `not-attempted` |
| `MODEL_RESOLVE_BUDGET` | - | `240` | Seconds all the lookups of one scan may take, base models included. The models not reached are marked `not-attempted` |
| `PURL_RESOLVE_IGNORE` | — | — | Namespace prefixes to leave out of that lookup, space- or comma-separated. Use it for namespaces published only to an internal repository, which cannot be told apart from a wrong identifier |
| `PURL_RESOLVE_BUDGET` | — | `240` | Seconds the lookup may take in total. Identifiers it does not reach are reported as unchecked, never as missing |
| `ANALYZE_CPE_INDEX` | — | `false` | `--analyze` only (the script's `--analyze-cpe-index`): match the components carrying `bomlens:purlSource=upstream-map` against the bundled CPE index. |

> TRUSCA's (formerly TrustedOSS Portal) native ingest endpoint (`POST /v1/projects/{id}/sbom-ingest`, Bearer auth) is not Dependency-Track compatible. To push to a regular Dependency-Track server, keep `UPLOAD_TARGET=dependency-track` (the default).

For the full mapping between CLI flags and environment variables, see the flag mapping in [Architecture](../concepts/architecture.md).

## Building and publishing the image

The procedure for building the image yourself or publishing it for multiple platforms is in the contributor-facing [docker/README](https://github.com/sktelecom/bomlens/blob/main/docker/README.md).

---

> **Related**: [First scan](../start/first-scan.md) | [CLI reference](../reference/cli.md) | [Architecture](../concepts/architecture.md)
