---
description: Every CLI option and environment variable for BomLens, with output locations, image pinning, and troubleshooting.
---

# CLI reference

Full options, analysis modes, CI/CD integration, and troubleshooting for BomLens.

## Options reference

```bash
./scripts/scan-sbom.sh [options]
```

> **Windows**: the commands here are for macOS/Linux. Pick one of the following. See [Getting started](../start/first-scan.md) for installation.
>
> - Replace `./scripts/scan-sbom.sh` with `scripts\scan-sbom.bat` (needs Git Bash).
> - Under WSL2, run the commands as-is.
> - To work without a command line, double-click `scripts\sbom-ui.bat`, or download the desktop app.

| Option | Default | Description |
|--------|---------|-------------|
| `--project <name>` | — | **(required)** Project name |
| `--version <version>` | — | **(required)** Project version |
| `--target <target>` | current directory | What to analyze: a directory (source tree, or an OS rootfs / staging build output), a Docker image, a binary file, or a `.zip`/`.tar.gz` archive |
| `--git <url>` | — | Shallow-clone a git/GitHub URL and analyze it as source (private repos: `GIT_TOKEN` env var) |
| `--branch <ref>` | default branch | Branch, tag, or commit of the `--git` target (alias `--ref`) |
| `--firmware` | false | Force firmware mode on the `--target` file (opt-in firmware image) |
| `--analyze <sbom>` | — | Validate and analyze a supplier SBOM (alias `--sbom`). CycloneDX/SPDX. Mutually exclusive with `--target` |
| `--model <owner/name>` | — | Generate an AI SBOM (CycloneDX 1.7 ML-BOM) for a HuggingFace model via the OWASP AIBOM Generator (opt-in `bomlens-aibom` image; fetches model-card metadata over the network). Mutually exclusive with `--target`/`--analyze`/`--git`/`--merge` |
| `--merge <a.json> <b.json> …` | — | Merge two or more CycloneDX SBOMs into one, dedupe by purl, and stamp the root component with `--project`/`--version`. Optional — for a server SBOM when an external system needs a single product BOM; otherwise keep the layers separate (see the [server SBOM guide](../guides/server-delivery.md)). Mutually exclusive with `--target`/`--analyze`/`--git` |
| `--merge-root <file>` | — | With `--merge`: keep this input's `specVersion` and root component (for example an ML-BOM's CycloneDX 1.7 root with its model card) instead of writing a fresh 1.6 root. Must be one of the `--merge` files; the preserved root is renamed to `--project`/`--version` |
| `--generate-only` | false | Save locally only, without uploading |
| `--upload-target <target>` | `dependency-track` | Upload destination: `dependency-track` (DT-compatible) or `trusca` (native ingest) |
| `--trusca <project_id>` | — | Upload to TRUSCA (= `--upload-target trusca` + project id). Needs `API_URL` and a Bearer `API_KEY` |
| `--notice` | (on by default) | Generate the open-source notice (NOTICE, txt+html) |
| `--security` | (on by default) | Generate the Trivy security report (json+md+html), including CVSS, EPSS, and CISA KEV priority signals |
| `--all` | — | `--notice --security` |
| `--no-report` | false | Skip the open-source risk report (see below) |
| `--deep-license` | false | Precise license detection with scancode (opt-in image) |
| `--identify-vendored` | false | Identify open source copied (vendored) into C/C++ source that has no package manager. Matches file fingerprints against the OSSKB service (included in the published image; sends hashes, not source). See the [identify bundled OSS guide](../guides/identify-vendored.md) |
| `--byte-stable` | false | Deterministic (reproducible) SBOM output |
| `--sign` | false | cosign signature (`COSIGN_KEY` required) |
| `--output-dir <dir>` | current directory | Base directory for outputs (alias `-o`). Each scan lands in a `{Project}_{Version}/` subfolder under it, keeping the bundle together and out of the source tree |
| `--timestamp` | false | Append `_YYYYMMDD-HHMMSS` to the run subfolder so repeat scans of the same project and version are kept side by side instead of overwritten. Folder name only; SBOM bytes are unchanged |
| `--ui` | — | Launch the local web UI |
| `--help` | — | Print help |

Environment variables adjust the behavior.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/bomlens:latest` | Override the scanner image |
| `SBOM_FIRMWARE_IMAGE` | `ghcr.io/sktelecom/bomlens-firmware:latest` | Image used for firmware analysis |
| `SBOM_OUTPUT_FLAT` | — | Set to `1` to write artifacts flat in the output base, with no per-run subfolder (the pre-isolation layout, for CI that expects the old paths) |
| `SBOM_OUTPUT_DIR` | `~/sbom-output` | Output base for the desktop app and web UI (the CLI uses `--output-dir` instead). Each scan still lands in a `{Project}_{Version}/` subfolder under it |
| `CVE_BIN_TOOL_MODE` | `auto` | Firmware CVE matching. `auto` uses the bundled CVE database if present, otherwise downloads from NVD when the network is reachable. `offline` matches only against the bundled database. `online` always updates from the network. `components-only` skips CVE matching and emits a component-only SBOM |
| `CVE_BIN_TOOL_HOME` | `/opt/cve-bin-tool-home` | Location of the bundled cve-bin-tool CVE database. cve-bin-tool reads `$CVE_BIN_TOOL_HOME/.cache/cve-bin-tool/cve.db` (it keys the cache off `HOME`) |
| `CVE_BIN_TOOL_DISABLE_SOURCES` | `GAD` | cve-bin-tool data sources to disable during a firmware scan. `GAD` (GitLab Advisory) is disabled by default because it crashes the bundled cve-bin-tool on fetch |
| `SCANOSS_API_URL` | OSSKB free API | Endpoint for `--identify-vendored`. Point at a SCANOSS commercial or self-hosted endpoint for air-gapped or high-volume use |
| `SCANOSS_API_KEY` | — | Credential for `SCANOSS_API_URL`, if the endpoint requires one |
| `SCANOSS_MIN_FILES` | `2` | Minimum number of files that must match a library before it is reported, to drop one-off downstream-fork noise. Set `1` to keep every single-file match |
| `GIT_TOKEN` | — | Token for cloning private git repositories |
| `COSIGN_KEY` | — | Path to the signing key used by `--sign` |
| `FETCH_LICENSE` | `true` | Resolve dependency licenses during source scans. Set `false` to skip the lookup and run faster |
| `SECURITY_ENRICH` | `true` | Enrich the security report with EPSS and CISA KEV signals. Set `false` on air-gapped networks to skip the external lookups |
| `API_URL` | — | Upload server URL (a DT server, or the TRUSCA base) |
| `API_KEY` | — | Upload credential. Used as `X-Api-Key` for DT, as a Bearer token for TRUSCA |
| `UPLOAD_TARGET` | `dependency-track` | Upload destination: `dependency-track` or `trusca` |
| `TRUSCA_PROJECT_ID` | — | TRUSCA project id (UUID). Required when `trusca` |
| `TRUSCA_REF` | `main` | Ingest ref label |
| `TRUSCA_RELEASE` | `--version` value | Ingest release label |

Output flags are detailed in the [reports guide](../guides/reports.md); validating a received supplier SBOM is covered in the [supplier SBOM validation](../guides/supplier-sbom.md).

## Where outputs go

Each scan is isolated in its own `{Project}_{Version}/` subfolder, so the files from one run stay together and the CLI never litters the source tree it scans. That subfolder is created under a base directory:

- **CLI** (`scan-sbom.sh`): the base is the directory you ran the command in. Override it with `--output-dir <dir>` (alias `-o`).
- **Desktop app and web UI**: the base is `~/sbom-output` (`C:\Users\<you>\sbom-output` on Windows). Override it with the `SBOM_OUTPUT_DIR` environment variable.

For `--git` or archive ingestion the clone or extract happens in a temp directory that is cleaned up on exit, and only the output subfolder remains.

A re-scan of the same project and version overwrites its subfolder by default, keeping just the latest result. Add `--timestamp` to keep each run instead: it appends `_YYYYMMDD-HHMMSS` to the folder name, for example `MyApp_1.0.0_20260626-143000/`. The flag changes the folder name only, not the SBOM file names or bytes, so it works together with `--byte-stable`.

To restore the previous flat layout, where every file is written directly in the base with no per-run subfolder, set `SBOM_OUTPUT_FLAT=1`. This is meant for CI that expects the old paths.

## Pin the scanner image version

Override the scanner image with `SBOM_SCANNER_IMAGE`.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:1.1.0" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

## Troubleshooting

### Windows: no outputs appear

If the scan finishes but no output files show up, check that the folder you ran from is inside a Docker file-sharing path. Anything under your home directory (`C:\Users\...`) is shared by default in both Rancher Desktop and Docker Desktop. From an unshared location the container cannot write results to the host.

### Docker permission error

```
Got permission denied while trying to connect to the Docker daemon
```

Add your user to the `docker` group.

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Out of disk space

```
no space left on device
```

Prune the Docker cache.

```bash
docker system prune -f
```

### Anything else

1. Check verbose logs with `VERBOSE=true ./tests/test-scan.sh`.
2. Update the Docker image: `docker pull ghcr.io/sktelecom/bomlens:latest`.
3. If it still fails, open a [GitHub Issue](https://github.com/sktelecom/sbom-tools/issues) with your environment info and logs.

For how to use each mode, see the [input scenarios guide](../guides/by-input.md); for the kinds of outputs, see the [artifacts reference](artifacts.md); for language detection, see [supported ecosystems](ecosystems.md).
