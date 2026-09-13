# Docker image guide (build and publish)

> **한국어**: [docker/README.ko.md](README.ko.md)

This guide is for contributors who want to build and publish the BomLens Docker image themselves.

If you only want to use the image, see the site's [Use the Docker image directly](https://sktelecom.github.io/bomlens/docker-image/) guide instead. It has `docker run` examples and environment variable descriptions.

## Image information

- Canonical name: `ghcr.io/sktelecom/bomlens` (aliases `sbom-generator`, `sbom-scanner`, same digest)
- Firmware analysis: `ghcr.io/sktelecom/bomlens-firmware` (opt-in) (legacy alias: sbom-scanner-firmware)
- Platforms: `linux/amd64`, `linux/arm64`
- Base: `python:3.12-slim`. It is a lightweight post-processing image with no language toolchain, and the bundled tools and their versions are pinned as `ARG`s in the `Dockerfile` (syft, Trivy, cosign, scancode, and more).

## Building it yourself

### Prerequisites

- Docker 20.10 or later
- 5GB or more of free disk space

### Local build

```bash
# Clone the repository
git clone https://github.com/sktelecom/bomlens.git
cd bomlens/docker

# Build
docker build -t sbom-scanner:local .

# Build time: about 10-15 minutes, depending on network speed
```

### Verifying the build

Check with tools that are actually in the image. cdxgen is not in this image; for source scans, `scan-sbom.sh` pulls the per-language official cdxgen images separately when it needs one.

```bash
# Check the image
docker images | grep sbom-scanner

# Test run
docker run --rm --entrypoint syft sbom-scanner:local version
docker run --rm --entrypoint trivy sbom-scanner:local --version
```

### Build options

#### Opting in to feature tools

Feature-specific tools are turned on with `--build-arg`. Most of them are off by default to keep the base build lightweight.

| Build arg | Default | What turning it on adds |
|-----------|--------|------------------|
| `SBOM_FIRMWARE` | `false` | Firmware analysis tools (unblob, cve-bin-tool, ubi_reader) and a CPE-to-CVE index bundle. The `bomlens-firmware` image is built with this option. The NVD data is distilled into a local index at build time by cloning `fkie-cad/nvd-json-data-feeds`, so no NVD API key or secret is needed |
| `SBOM_AIBOM` | `false` | AI model SBOM generation tools (OWASP aibom-generator + cdxgen) |
| `SBOM_DEEP_LICENSE` | `false` | Deep license scanning based on scancode-toolkit |
| `SBOM_SCANOSS` | `true` | Vendored OSS identification client (scanoss.py). Running it is gated again at runtime by `--identify-vendored` |
| `SBOM_PDF` | `false` | Notice PDF renderer (weasyprint) |

```bash
# Example: build the firmware analysis image (no NVD key or secret needed)
docker build --build-arg SBOM_FIRMWARE=true \
  -t sbom-scanner-firmware:local .
```

#### Building without cache

```bash
docker build --no-cache -t sbom-scanner:local .
```

#### Building for a specific platform

```bash
# AMD64 (Intel/AMD)
docker build --platform linux/amd64 -t sbom-scanner:amd64 .

# ARM64 (Apple Silicon)
docker build --platform linux/arm64 -t sbom-scanner:arm64 .
```

## Multi-platform builds

The official release is not done by hand. `.github/workflows/docker-publish.yml` builds for multiple platforms and publishes under three names (bomlens, sbom-generator, sbom-scanner) on every push to `main` and on release tags. The steps below are for the exceptional cases where you need to bypass the workflow: recovering from a registry outage, or a pre-release check, for example.

### Setting up buildx

```bash
# Create a buildx builder
docker buildx create --name multiplatform-builder --use

# Boot the builder
docker buildx inspect --bootstrap

# Check supported platforms
docker buildx inspect
```

### Running a multi-platform build

```bash
# Build AMD64 and ARM64 together
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/bomlens:latest \
  --push \
  .
```

Note: `--load` only works for a single platform. Use `--push` for multi-platform builds.

## Publishing to GitHub Container Registry (exceptional cases)

### 1. Create a Personal Access Token

1. On GitHub, go to Settings, then Developer settings, then Personal access tokens, and open Tokens (classic).
2. Click "Generate new token (classic)".
3. Select the scopes:
   - `write:packages` - upload packages
   - `read:packages` - download packages
4. Generate the token and save it.

### 2. Log in to GitHub Container Registry

```bash
# Set environment variables
export GITHUB_TOKEN="ghp_your_personal_access_token"
export GITHUB_USERNAME="your_github_username"

# Log in
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin
```

### 3. Build and push the image

```bash
# Multi-platform build + push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/bomlens:latest \
  --push \
  .
```

### 4. Confirm the push

```bash
# Check the image metadata (both amd64/arm64 manifests should show up)
docker buildx imagetools inspect ghcr.io/sktelecom/bomlens:latest
```

### 5. Set the package to public

Packages are Private by default. To change to Public:

1. Go to https://github.com/orgs/sktelecom/packages.
2. Select the `bomlens` package (the same applies to the `sbom-generator` and `sbom-scanner` aliases).
3. Under "Package settings", click "Change visibility" and choose "Public".
4. Type the package name to confirm.

## Image details

### Dockerfile structure

It is a two-stage build. No language toolchain goes into it: for source code, `scan-sbom.sh` delegates SBOM generation to the per-language official cdxgen images it pulls on demand, and this image handles post-processing and scanning.

- Stage 1 (`node:26-alpine`): builds the web UI (React SPA). Node exists only in this stage; only the `dist/` build output is copied into the runtime image.
- Stage 2 (`python:3.12-slim`): the runtime image. It carries syft (image/binary/RootFS scanning), Trivy (security reports), cosign (signing), the docker CLI (used when the web UI's source scan starts a sibling cdxgen container), and the entrypoint and post-processing scripts.

Tool versions are pinned as `ARG`s in the `Dockerfile`, and Renovate tracks the upstream releases and opens update PRs.

| Tool | ARG | Pinned version |
|------|-----|----------|
| syft | `SYFT_VERSION` | v1.51.0 |
| Trivy | `TRIVY_VERSION` | v0.74.0 |
| cosign | `COSIGN_VERSION` | See the [Docker image reference](../docs/reference/docker-image.md) |
| docker CLI | `DOCKER_CLI_VERSION` | See the [Docker image reference](../docs/reference/docker-image.md) |
| scanoss.py | `SCANOSS_VERSION` | 1.54.2 |
| scancode-toolkit (opt-in) | `SCANCODE_VERSION` | 32.5.0 |
| cdxgen (aibom opt-in) | `CDXGEN_VERSION` | See the [Docker image reference](../docs/reference/docker-image.md) |

### Image size

The base build is about 1GB (981MB measured locally). For a per-layer breakdown, check it directly.

```bash
docker history sbom-scanner:local
```

The firmware image (`SBOM_FIRMWARE=true`) is larger by the size of the bundled CVE database (about 0.5-1.5GB).

### Supported architectures

| Architecture | Platform | Used on |
|---------|--------|----------|
| `linux/amd64` | x86_64 | Intel/AMD servers, WSL2 |
| `linux/arm64` | aarch64 | Apple Silicon (M1/M2/M3), Arm servers |

Docker automatically pulls the image matching the current platform.

## Testing

### Integration tests

```bash
# Run the test script (point SBOM_SCANNER_IMAGE at the image you just built)
cd /path/to/bomlens
SBOM_SCANNER_IMAGE=sbom-scanner:local ./tests/test-scan.sh
```

Test scenarios:
- Node.js project
- Python project
- Java Maven project
- Ruby project
- PHP project
- Rust project
- Docker image
- Binary file
- RootFS directory

### Manual testing

```bash
# Create a simple Node.js project
mkdir test-project
cd test-project
echo '{"name":"test","version":"1.0.0","dependencies":{"express":"4.18.0"}}' > package.json
npm install --package-lock-only

# Test SBOM generation (with the image you just built)
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME=TestProject \
  -e PROJECT_VERSION=1.0.0 \
  sbom-scanner:local

# Check the result (a direct docker run saves straight into the output folder)
ls -la TestProject_1.0.0_bom.json
cat TestProject_1.0.0_bom.json | jq '.components | length'
```

## Troubleshooting

### Build failures

#### Error: "manifest unknown"

Cause: the image is not in GitHub Container Registry.

Fix:
```bash
# Check that you are logged in
docker login ghcr.io

# Check the image path
echo ghcr.io/sktelecom/bomlens:latest
```

#### Error: "no space left on device"

Cause: not enough disk space.

Fix:
```bash
# Clean up unused images
docker system prune -a

# Check disk space
df -h
```

### Runtime errors

#### Error: "Cannot connect to the Docker daemon"

Cause: the Docker socket is not mounted (IMAGE mode).

Fix:
```bash
# Linux/macOS
-v /var/run/docker.sock:/var/run/docker.sock

# Windows (Docker Desktop)
-v //./pipe/docker_engine://./pipe/docker_engine
```

#### Error: "Permission denied" (writing files)

Cause: a user permission mismatch inside the container.

Fix:
```bash
# Run as the current user
docker run --rm --user $(id -u):$(id -g) ...
```

## Advanced usage

### Building behind a proxy

```bash
# Proxy settings
docker build \
  --build-arg HTTP_PROXY=http://proxy.company.com:8080 \
  --build-arg HTTPS_PROXY=http://proxy.company.com:8080 \
  -t sbom-scanner:local .
```

### Custom entrypoint

```bash
# Enter a Bash shell
docker run --rm -it \
  -v "$(pwd)":/src \
  --entrypoint /bin/bash \
  sbom-scanner:local

# Run manually inside the container (using the syft bundled in the image)
root@container:/src# syft dir:/src -o cyclonedx-json > bom.json
```

## References

- **Dockerfile**: [docker/Dockerfile](Dockerfile)
- **Entrypoint script**: [docker/entrypoint.sh](entrypoint.sh)
- **Docker docs**: https://docs.docker.com/
- **Docker Buildx**: https://docs.docker.com/buildx/working-with-buildx/

## Contact

- **Email**: opensource@sktelecom.com
- **Issues**: [GitHub Issues](https://github.com/sktelecom/bomlens/issues)
