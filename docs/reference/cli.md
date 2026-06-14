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
| `--target <target>` | current directory | What to analyze (directory, Docker image, binary file, or a `.zip`/`.tar.gz` archive) |
| `--git <url>` | — | Shallow-clone a git/GitHub URL and analyze it as source (private repos: `GIT_TOKEN` env var) |
| `--branch <ref>` | default branch | Branch, tag, or commit of the `--git` target |
| `--firmware` | false | Force firmware mode on the `--target` file (opt-in firmware image) |
| `--analyze <sbom>` | — | Validate and analyze a supplier SBOM (alias `--sbom`). CycloneDX/SPDX. Mutually exclusive with `--target` |
| `--generate-only` | false | Save locally only, without uploading |
| `--upload-target <target>` | `dependency-track` | Upload destination: `dependency-track` (DT-compatible) or `trusca` (native ingest) |
| `--trusca <project_id>` | — | Upload to TRUSCA (= `--upload-target trusca` + project id). Needs `API_URL` and a Bearer `API_KEY` |
| `--notice` | (on by default) | Generate the open-source notice (NOTICE, txt+html) |
| `--security` | (on by default) | Generate the Trivy security report (json+md+html), including CVSS, EPSS, and CISA KEV priority signals |
| `--all` | — | `--notice --security` |
| `--no-report` | false | Skip the open-source risk report (see below) |
| `--deep-license` | false | Precise license detection with scancode (opt-in image) |
| `--byte-stable` | false | Deterministic (reproducible) SBOM output |
| `--sign` | false | cosign signature (`COSIGN_KEY` required) |
| `--ui` | — | Launch the local web UI |
| `--help` | — | Print help |

Environment variables adjust the behavior.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOM_SCANNER_IMAGE` | `ghcr.io/sktelecom/sbom-scanner:latest` | Override the scanner image (same image as `bomlens`) |
| `SBOM_FIRMWARE_IMAGE` | `ghcr.io/sktelecom/sbom-scanner-firmware:latest` | Image used for firmware analysis |
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

Outputs are written to the directory you ran the command in (`$(pwd)`), named `{Project}_{Version}_*`. For `--git`/archive ingestion the clone/extract happens in a temp directory and only the outputs remain in the current directory (the temp directory is cleaned up on exit).

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
