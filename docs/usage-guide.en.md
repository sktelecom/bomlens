# Usage guide

> **한국어**: [사용 가이드](usage-guide.md) · **Related**: [Getting started](getting-started.en.md)

Full options, analysis modes, CI/CD integration, and troubleshooting for BomLens.


## Options reference

```bash
./scripts/scan-sbom.sh [options]
```

> **Windows**: the commands here are for macOS/Linux. Pick one of the following. See [Getting started](getting-started.en.md#installation) for installation.
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

Output flags are detailed in the [notice and security guide](notice-and-security.en.md); validating a received supplier SBOM is covered in the [supplier SBOM validation guide](supplier-sbom-validation.en.md).

## Analysis modes

The right tool (cdxgen or syft) is selected automatically from the type of target. See the [architecture](architecture.en.md) doc for the selection logic.

### Source code (cdxgen)

Parses package-manager files (`pom.xml`, `package.json`, `go.mod`, etc.) to extract the dependency list.

```bash
# Analyze the current directory
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only

# Point at a specific directory
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --target "/path/to/project" \
  --generate-only
```

**Detected files**: `pom.xml`, `build.gradle`, `build.gradle.kts`, `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `composer.json`, `Gemfile`, `*.csproj`, and more.

> **Tip**: a lockfile is needed for exact versions. Run `npm install`, `go mod tidy`, etc. first.

> **C/C++**: dependencies resolve when a package manager is present (Conan `conanfile.txt` / vcpkg `vcpkg.json`). Pure CMake/Make sources without a manager produce a sparse SBOM; enrich first-party licenses with `--deep-license` and analyze the build output directory with `--target <dir>` (syft).

### GitHub URL ingestion (`--git`)

Pass a repository URL to shallow-clone it and analyze as source. No manual `git clone` needed.

```bash
# Public repository
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/repo" \
  --all --generate-only

# Specific branch/tag
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/repo" --branch "v1.2.3" --all --generate-only

# Private repository (the token is passed only via env var and never logged)
GIT_TOKEN="ghp_xxx" ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/private-repo" --all --generate-only
```

Only allowed URL forms are accepted (`https://`, `git@`, `ssh://git@`, `file://`); URLs with shell metacharacters, `..`, or spaces are rejected (to prevent path traversal and option injection).

### Source archive ingestion (ZIP / tar)

Pass an archive (`.zip`/`.tar.gz`, etc.) to `--target` and it is extracted to a temp directory and analyzed as source (with a zip-slip guard). Like GitHub zips, a single top-level folder is entered automatically.

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --target "./app-src.zip" \
  --all --generate-only
```

Supported: `.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`. (If Git Bash on Windows has no `unzip`, `tar` is used.)

### Open-source risk report (all modes)

`_risk-report.{md,html}` is generated by default in every mode (source, archive, GitHub, image, binary, RootFS, firmware, SBOM analysis). Because it aggregates license (notice) and vulnerability (security) data, the notice and security scans turn on automatically.

- To skip it, use `--no-report` (notice/security are then not forced on).
- In supplier SBOM mode (`--analyze`), a format-conformance result is added as the first section of the report. For self-generated SBOMs that section is omitted.
- Vulnerability remediation deadlines follow the SKT process: **Critical within 7 days, High within 30 days**.

### Docker image (syft)

Analyzes installed OS and application packages.

```bash
# Remote image
./scripts/scan-sbom.sh \
  --project "NginxApp" --version "1.25.0" \
  --target "nginx:1.25.0" \
  --generate-only

# Locally built image
./scripts/scan-sbom.sh \
  --project "MyService" --version "1.0.0" \
  --target "myservice:local" \
  --generate-only
```

### Binary / RootFS (syft)

```bash
# Binary file
./scripts/scan-sbom.sh \
  --project "MyFirmware" --version "3.0.0" \
  --target "./release/firmware.bin" \
  --generate-only

# Extracted RootFS directory
./scripts/scan-sbom.sh \
  --project "EmbeddedOS" --version "1.0.0" \
  --target "./rootfs/" \
  --generate-only
```

## Advanced usage

### Where outputs go

Outputs are written to the directory you ran the command in (`$(pwd)`), named `{Project}_{Version}_*`. For `--git`/archive ingestion the clone/extract happens in a temp directory and only the outputs remain in the current directory (the temp directory is cleaned up on exit).

### Pin the scanner image version

Override the scanner image with `SBOM_SCANNER_IMAGE`.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:1.1.0" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

### Deterministic (reproducible) output

When CI needs a byte-for-byte identical SBOM for the same input, use `--byte-stable` (fixed timestamp, no random serial).

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --byte-stable --generate-only
```

### All three deliverables at once (notice, SBOM, risk report)

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --all --generate-only
```

## CI/CD integration

An SBOM is a point-in-time snapshot of dependencies, so it must be regenerated whenever dependencies change to stay in sync with the code. In CI it refreshes on every build and release, attaches to release artifacts, and becomes the basis for a vulnerability policy gate.

> **Important**: the scanner is report-only — it reports vulnerabilities but always exits successfully. To fail a build on Critical findings, add a step that inspects the generated `*_security.json` (gate example below).

To reduce load, split depth by trigger: on PRs generate the SBOM quickly (`--generate-only --no-report`); on `main` and releases generate everything (`--all --generate-only`) and apply the gate.

### GitHub Actions

The `ubuntu-latest` runner ships with `jq`.

```yaml
name: SBOM

on:
  pull_request:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  # PR: lightweight SBOM only (no report)
  sbom-pr:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
      - name: Generate SBOM (lightweight)
        run: |
          ./scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --generate-only --no-report
      - uses: actions/upload-artifact@v4
        with:
          name: sbom-pr
          path: "*_bom.json"

  # main/release: full generation + vulnerability gate
  sbom-full:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
      - name: Generate SBOM + reports
        run: |
          ./scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --all --generate-only

      # The scanner is report-only and always succeeds. Fail the build here if Critical exists.
      - name: Fail on Critical vulnerabilities
        run: |
          CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
          echo "Critical vulnerabilities: $CRIT"
          if [ "$CRIT" -gt 0 ]; then
            echo "::error::$CRIT critical vulnerability(ies) found"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        if: always()   # keep reports even when the gate fails
        with:
          name: sbom
          path: |
            *_bom.json
            *_security.*
            *_risk-report.*
```

### GitLab CI

The `docker:latest` image has no `jq`, so install it before the gate.

```yaml
generate-sbom:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache jq
  script:
    - docker pull ghcr.io/sktelecom/bomlens:latest
    - ./scripts/scan-sbom.sh
        --project "$CI_PROJECT_NAME"
        --version "$CI_COMMIT_SHA"
        --all --generate-only
    # Use the report-only scanner as a build gate: fail if Critical exists
    - |
      CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
      [ "$CRIT" -eq 0 ] || { echo "$CRIT critical vulnerability(ies) found"; exit 1; }
  artifacts:
    when: always
    paths:
      - "*_bom.json"
      - "*_security.*"
```

## Output formats

The generated SBOM is CycloneDX 1.6 JSON.

The filename is `{ProjectName}_{Version}_bom.json` (e.g. `MyApp_1.0.0_bom.json`).

### Deliverables

| Deliverable | File | When generated |
|-------------|------|----------------|
| SBOM | `{P}_{V}_bom.json` | always |
| Open-source notice | `{P}_{V}_NOTICE.{txt,html}` | `--notice`/`--all`, or with the default risk report |
| Security report | `{P}_{V}_security.{json,md,html}` | `--security`/`--all`, or with the default risk report |
| **Open-source risk report** | `{P}_{V}_risk-report.{md,html}` | default (all modes) — skip with `--no-report` |
| Format conformance report | `{P}_{V}_conformance.{json,md,html}` | `--analyze` (supplier SBOM) |
| Precise licenses | `{P}_{V}_scancode.json` | `--deep-license` |
| SBOM signature | `{P}_{V}_bom.json.sig` | `--sign` |

### SBOM structure

```
bomFormat          "CycloneDX"
specVersion        "1.6"
metadata
  ├── timestamp    generation time (ISO 8601)
  └── component    project info (name, version, type)
components[]
  ├── type         "library" | "framework" | "application"
  ├── name         component name
  ├── version      version
  ├── purl         Package URL (unique identifier)
  └── licenses[]   license info (SPDX ID)
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

### No language detected (zero components)

If source analysis finds no dependencies, check for the lockfile below.

| Language | Required file |
|----------|---------------|
| Java (Maven) | `pom.xml` |
| Java (Gradle) | `build.gradle` or `build.gradle.kts` |
| Node.js | `package.json` + `package-lock.json` or `yarn.lock` |
| Python | `requirements.txt` or `pyproject.toml` + `poetry.lock` |
| Go | `go.mod` + `go.sum` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj` + `packages.lock.json` |

### Anything else

1. Check verbose logs with `VERBOSE=true ./tests/test-scan.sh`.
2. Update the Docker image: `docker pull ghcr.io/sktelecom/bomlens:latest`.
3. If it still fails, open a [GitHub Issue](https://github.com/sktelecom/sbom-tools/issues) with your environment info and logs.
