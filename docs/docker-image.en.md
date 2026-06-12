# Use the Docker image directly

> **한국어**: [Docker 이미지 직접 사용](docker-image.md) · **Related**: [Getting started](getting-started.en.md) | [Usage guide](usage-guide.en.md) | [Architecture](architecture.en.md)

For everyday use we recommend the [`scan-sbom.sh`](usage-guide.en.md) script, which handles language detection, image selection, and volume mounts for you. This document explains how to call the image directly with `docker run` in environments where the script cannot live (CI runners, Kubernetes jobs, and so on).

## Images and tags

| Image | Purpose |
|--------|------|
| `ghcr.io/sktelecom/bomlens` | Scanning and post-processing (canonical name) |
| `ghcr.io/sktelecom/sbom-generator`, `ghcr.io/sktelecom/sbom-scanner` | Aliases of the same image (former names, same digest) |
| `ghcr.io/sktelecom/sbom-scanner-firmware` | Firmware analysis (includes GPL tools, opt-in) |

`latest` and version tags are available, and both `linux/amd64` and `linux/arm64` are supported. Images are signed with cosign before publishing.

```bash
docker pull ghcr.io/sktelecom/bomlens:latest
```

## What is in the image

It is a lightweight image (based on python 3.12 slim) without language toolchains. For source scans, transitive dependency resolution is handled by the script, which pulls per-language cdxgen images separately. See [Architecture](architecture.en.md) for the structure.

| Tool | Version | Role |
|------|------|------|
| syft | v1.18.1 | Scans images, binaries, and directories |
| Trivy | v0.70.0 | Vulnerability report |
| cosign | v2.4.1 | SBOM signing |
| jq | — | SBOM normalization and notice generation |
| ScanCode Toolkit | 32.3.0 | Precise license detection (included only in opt-in builds) |

Tool versions are pinned with `ARG` in `docker/Dockerfile`.

## Running directly

Select the analysis mode with the `MODE` environment variable. All examples below leave their outputs in the current directory and do not upload anything (`UPLOAD_ENABLED=false`).

### Analyze a Docker image

```bash
docker run --rm \
  -v "$(pwd)":/host-output \
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
docker run --rm \
  -v "$(pwd)":/target \
  -v "$(pwd)":/host-output \
  -e MODE=BINARY \
  -e TARGET_FILE=/target/firmware.bin \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Firmware" \
  -e PROJECT_VERSION="1.0" \
  ghcr.io/sktelecom/bomlens:latest
```

### Analyze a source directory

```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="MyApp" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

In direct runs, `SOURCE` mode has syft read the package manifests inside the container, so it may only capture direct dependencies. If you need transitive dependencies, use `scan-sbom.sh`, which routes to the per-language cdxgen images.

### Notice and reports in one run

In direct runs, the notice and security reports are off by default. Turn on the following variables to get the same outputs as the CLI's `--all`.

```bash
docker run --rm \
  -v "$(pwd)":/host-output \
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
| `MODE` | Yes | `POSTPROCESS` | Analysis mode: `SOURCE`, `IMAGE`, `BINARY`, `ROOTFS`, `FIRMWARE`, `ANALYZE` |
| `PROJECT_NAME` | Yes | — | Project name |
| `PROJECT_VERSION` | Yes | — | Project version |
| `TARGET_IMAGE` | Per mode | — | Image name for `IMAGE` mode (requires the docker.sock mount) |
| `TARGET_FILE` | Per mode | — | File path for `BINARY`/`FIRMWARE` mode (path inside the container) |
| `TARGET_DIR` | Per mode | — | Directory path for `ROOTFS` mode |
| `UPLOAD_ENABLED` | — | `true` | If `false`, save locally without uploading (same as CLI `--generate-only`) |
| `HOST_OUTPUT_DIR` | — | — | Mounted path to copy the outputs to |
| `GENERATE_NOTICE` | — | `false` | Generate the open-source notice (CLI `--notice`) |
| `GENERATE_SECURITY` | — | `false` | Generate the Trivy security report (CLI `--security`) |
| `GENERATE_REPORT` | — | `false` | Generate the open-source risk analysis report (off in direct runs, unlike the CLI default) |
| `API_KEY`, `API_URL` | For uploads | — | Authentication for trustedoss-portal (Dependency-Track compatible) uploads |

For the full mapping between CLI flags and environment variables, see the flag mapping in [Architecture](architecture.en.md).

## Building and publishing the image

The procedure for building the image yourself or publishing it for multiple platforms is in the contributor-facing [docker/README](https://github.com/sktelecom/sbom-tools/blob/main/docker/README.md).
