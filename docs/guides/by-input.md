---
description: How BomLens produces an SBOM, an open-source notice, and a risk report for five input forms — a GitHub URL, a ZIP archive, local source, an existing SBOM, and firmware.
---

# Input scenarios guide

## Overview

An open-source compliance manager receives deliverables from many teams in different forms. This guide shows how to produce the same three deliverables for each of five input forms.

**The three deliverables**

| Deliverable | File | Meaning |
|-------------|------|---------|
| Open-source notice | `{P}_{V}_NOTICE.{txt,html}` | the notice that satisfies license obligations |
| SBOM | `{P}_{V}_bom.json` | CycloneDX 1.6 component inventory |
| Open-source risk report | `{P}_{V}_risk-report.{md,html}` | aggregated license + vulnerability risk (with deadlines) |

For any input form, adding `--all --generate-only` produces all three at once (the risk report is on by default and is only turned off with `--no-report`).

## Common setup

> **Windows**: the commands here are for macOS/Linux. Pick one of the following. See [Getting started](../start/first-scan.md#installation) for installation.
>
> - Replace `./scripts/scan-sbom.sh` with `scripts\scan-sbom.bat` (needs Git Bash).
> - Under WSL2, run the commands as-is.
> - To work without a command line, double-click `scripts\sbom-ui.bat`.

```bash
# Docker 20.10+ required. Pull the scanner image once (or build it yourself).
docker pull ghcr.io/sktelecom/bomlens:latest   # legacy name sbom-scanner serves the same image

# For convenience, keep the script path in a variable.
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh
```

## At a glance

| Input form | Mode | Core command (summary) | Deliverables |
|------------|------|------------------------|--------------|
| GitHub URL | SOURCE | `$SBOM --git <url> --all --generate-only` | notice, SBOM, risk report |
| Source ZIP | SOURCE | `$SBOM --target app.zip --all --generate-only` | same |
| Local directory (C/C++) | SOURCE | `cd dir && $SBOM --all --generate-only` | same |
| Existing SBOM JSON | ANALYZE | `$SBOM --analyze sbom.json --generate-only` | same + conformance report |
| Firmware `.bin` | FIRMWARE | `$SBOM --target dev.bin --firmware --all --generate-only` | same |

> Every command also needs `--project <name> --version <version>` (see examples below).

## Scenario 1 — GitHub URL

A team handed you a GitHub repository. Pass the URL directly, no manual `git clone`.

```bash
$SBOM --project team1-app --version 1.0.0 \
  --git "https://github.com/org/team1-app" \
  --all --generate-only
```

- Specific branch/tag: `--branch v1.2.3`
- Private repository: `GIT_TOKEN=ghp_xxx $SBOM ... --git https://github.com/org/private ...` (the token never appears in logs)
- A shallow clone (`--depth 1`) is fetched to a temp directory and analyzed; only the deliverables remain in the current directory.

**Deliverables**: `team1-app_1.0.0_NOTICE.{txt,html}`, `team1-app_1.0.0_bom.json`, `team1-app_1.0.0_risk-report.{md,html}`

## Scenario 2 — Source ZIP

A team handed you the source as a ZIP. Pass the archive directly, no manual extraction.

```bash
$SBOM --project team2-app --version 1.0.0 \
  --target "./team2-app.zip" \
  --all --generate-only
```

- Supported: `.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`
- It is extracted to a temp directory after a zip-slip (path-escape) check; a single top-level folder is entered automatically.

**Deliverables**: notice, SBOM, risk report (three)

## Scenario 3 — Local C/C++ source directory

A team shared the source via a folder you copied locally (`~/project/c-dev`). Run from inside the directory.

```bash
cd ~/project/c-dev
$SBOM --project team3-dev --version 1.0.0 --all --deep-license --generate-only
```

**C/C++ notes**

- With a package manager (Conan `conanfile.txt` / vcpkg `vcpkg.json`), dependencies resolve and appear in the SBOM.
- Pure CMake/Make sources have no manager metadata, so the SBOM can be sparse. Enrich first-party license headers with `--deep-license`, and analyze build output (a staging/rootfs with installed libraries) separately with `$SBOM --target <build-dir> --all --generate-only` (syft).
- Even without a package manager, the risk report is still generated, aggregating licenses and vulnerabilities of detected components.

**Deliverables**: notice, SBOM, risk report (three)

## Scenario 4 — Existing SBOM JSON

A team handed you an SBOM (JSON). Validate and analyze it even without the source.

```bash
$SBOM --project team4-proj --version 2.0.0 \
  --analyze "./team4-sbom.json" \
  --generate-only
```

- Both CycloneDX and SPDX (JSON/Tag-Value) are accepted and converted to CycloneDX internally.
- `--analyze` turns on notice and security automatically, so you do not need `--all`.
- A format conformance report (`_conformance.{json,md,html}`) is also produced, and the first section of the risk report includes the conformance result (whether required fields are present).

**Deliverables**: notice, SBOM (converted), risk report, conformance report

## Scenario 5 — Firmware binary

A team handed you a built firmware image (`dev.bin`). Unpack it and identify components.

```bash
$SBOM --project team5-fw --version 1.0.0 \
  --target "./dev.bin" --firmware \
  --all --generate-only
```

- Firmware analysis needs the opt-in firmware image, which includes GPL tools (unblob, cve-bin-tool, etc.). Set it via `SBOM_FIRMWARE_IMAGE`, or pull the default (`ghcr.io/sktelecom/sbom-scanner-firmware:latest`).
- Recognized extensions (`.bin/.img/.squashfs/.ubi/...`) are auto-detected even without `--firmware`, but being explicit is recommended.
- For behavior and limits, see the [firmware analysis guide](../guides/firmware.md) (Korean).

**Deliverables**: notice, SBOM, risk report (three)

## Reading the three deliverables

- **Notice (NOTICE)**: components grouped by license. Use it to satisfy the obligation to include or disclose notices when distributing.
- **SBOM**: CycloneDX 1.6. The artifact you upload to a portal or vulnerability-management system.
- **Open-source risk report**: aggregates vulnerabilities by severity with deadlines (Critical 7 days, High 30 days). Includes a license summary and (for supplier SBOMs) the format conformance result.

## All at once in the web UI

If you are not comfortable with the CLI, use the web UI.

```bash
$SBOM --ui   # http://localhost:8080 in the browser
```

Pick a scan target at the top of the UI and provide the matching input.

| Scan target | Input |
|-------------|-------|
| Current folder | scans the source in the folder where the UI was launched |
| GitHub URL | enter the URL |
| ZIP upload | upload a `.zip`/tar file |
| SBOM upload | upload an existing SBOM (JSON), ANALYZE mode |
| Firmware upload | upload a `.bin`, etc. (run the UI from the firmware image) |
| Docker image | enter the image name |

As it runs, logs stream live; when done you can view or download the notice, SBOM, and risk report (plus the conformance report when relevant). The conformance result (pass/fail) is shown as a card at the top.

> The firmware upload tab is only enabled when the UI runs from an image that includes the firmware tools:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/sbom-scanner-firmware:latest $SBOM --ui`

## Troubleshooting / limits

- **GitHub URL**: private repos need `GIT_TOKEN`. Disallowed URL forms (shell metacharacters, `..`, spaces) are rejected for security.
- **ZIP/tar**: archives containing a path escape (zip-slip) are rejected. If Git Bash on Windows has no `unzip`, `tar` is used.
- **C/C++**: pure source without a package manager produces a sparse SBOM (see [Scenario 3](#scenario-3--local-cc-source-directory)).
- **Firmware**: statically linked libraries and vendor-modified squashfs have limited detection (see the [firmware analysis guide](../guides/firmware.md) (Korean), Limits).
- **SBOM analysis**: converting SPDX to CycloneDX may simplify some license expressions.

---

> **Related**: [Getting started](../start/first-scan.md) | [Usage guide](../reference/cli.md)
