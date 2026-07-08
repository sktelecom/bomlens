---
description: How BomLens produces an SBOM, an open-source notice, and a risk report for six input forms — a GitHub URL, a ZIP archive, local source, an existing SBOM, firmware, and a HuggingFace AI model.
---

# Input scenarios guide

## Overview

An open-source compliance manager receives deliverables from many teams in different forms. This guide shows how to produce the same three deliverables for each of six input forms. (An AI model differs slightly — an ML-BOM and no security report; see Scenario 6.)

**The three deliverables**

| Deliverable | File | Meaning |
|-------------|------|---------|
| Open-source notice | `{Project}_{Version}_NOTICE.{txt,html}` | the notice that satisfies license obligations |
| SBOM | `{Project}_{Version}_bom.json` | CycloneDX 1.6 component inventory |
| Open-source risk report | `{Project}_{Version}_risk-report.{md,html}` | aggregated license + vulnerability risk (with deadlines) |

For any input form, adding `--all --generate-only` produces all three at once (the risk report is on by default and is only turned off with `--no-report`).

## Common setup

> **Windows**: the commands here are for macOS/Linux. Pick one of the following. See [Getting started](../start/first-scan.md) for installation.
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
| AI model (HuggingFace) | AIBOM | `$SBOM --model owner/name --generate-only` | notice, ML-BOM (1.7), risk report (no security) |

> Every command also needs `--project <name> --version <version>` (see examples below).
>
> C/C++ without a package manager (Conan/vcpkg): add `--identify-vendored` so open source copied straight into the sources is detected as named components. Strongly recommended for this case — see [Scenario 3](#scenario-3--local-cc-source-directory).

## Scenario 1 — GitHub URL

A team handed you a GitHub repository. Pass the URL directly, no manual `git clone`.

<!-- runnable -->
```bash
$SBOM --project team1-app --version 1.0.0 \
  --git "https://github.com/sktelecom/sbom-tools" \
  --all --generate-only
```

- Specific branch/tag: `--branch v1.2.3`
- Private repository: `GIT_TOKEN=ghp_xxx $SBOM ... --git https://github.com/org/private ...` (the token never appears in logs)
- A shallow clone (`--depth 1`) is fetched to a temp directory and analyzed; only the deliverables remain, in a `{Project}_{Version}/` subfolder under the current directory.

**Deliverables**: `team1-app_1.0.0_NOTICE.{txt,html}`, `team1-app_1.0.0_bom.json`, `team1-app_1.0.0_risk-report.{md,html}`

## Scenario 2 — Source ZIP

A team handed you the source as a ZIP. Pass the archive directly, no manual extraction.

<!-- runnable -->
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
- Pure CMake/Make sources have no manager metadata, so the SBOM can be sparse. Enrich first-party license headers with `--deep-license`, and analyze build output (a staging/rootfs with installed libraries) separately with `$SBOM --target <build-dir> --all --generate-only` (syft). For a full server SBOM workflow — OS rootfs, application, and static-link dependencies as separate layers — see the [server SBOM guide](server-delivery.md). In the web UI, `--deep-license` is the **License scan (ScanCode)** toggle under Advanced scan options; it scans your own source files (`/src`), not the declared dependencies, and is slow, so turn it on only when you need per-file license detection.
- When the source has no package manager (plain Make/CMake) and bundles open source copied straight into the tree — common for embedded and firmware sources — `--identify-vendored` is strongly recommended. Without it the SBOM stays sparse and misses the bundled libraries; with it they are detected as named components with CPEs, so the risk report can match CVEs. See [Identify bundled open source](identify-vendored.md). BomLens also nudges you toward this option automatically when it detects this situation.
- Even without a package manager, the risk report is still generated, aggregating licenses and vulnerabilities of detected components.

**Deliverables**: notice, SBOM, risk report (three)

## Scenario 4 — Existing SBOM JSON

A team handed you an SBOM (JSON). Validate and analyze it even without the source.

<!-- runnable -->
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

- Firmware analysis needs the opt-in firmware image, which includes GPL tools (unblob, cve-bin-tool, etc.). Set it via `SBOM_FIRMWARE_IMAGE`, or pull the default (`ghcr.io/sktelecom/bomlens-firmware:latest`).
- Recognized extensions (`.bin/.img/.squashfs/.ubi/...`) are auto-detected even without `--firmware`, but being explicit is recommended.
- For behavior and limits, see the [firmware analysis guide](../guides/firmware.md) (Korean).

**Deliverables**: notice, SBOM, risk report (three)

## Scenario 6 — AI model (HuggingFace)

A team points you at a HuggingFace model instead of code. Generate an ML-BOM from the model id — no source code and no model-weight download.

```bash
$SBOM --project bert-base --version 1.0.0 \
  --model "google-bert/bert-base-uncased" \
  --generate-only
```

- Needs the opt-in aibom image (`ghcr.io/sktelecom/bomlens-aibom:latest`), pulled automatically. Set a different tag via `SBOM_AIBOM_IMAGE`.
- `--model` is mutually exclusive with `--target`/`--analyze`/`--git`/`--merge`.
- Produces a CycloneDX 1.7 **ML-BOM** (not 1.6), the notice, and the risk report, plus a G7 minimum-element conformance check. There is **no security report** — a model has no package CVEs.
- For the model card, datasets, and G7 details, see the [AI model guide](ai-model.md).

**Deliverables**: notice, ML-BOM (CycloneDX 1.7), risk report, G7 conformance

## Reading the three deliverables

- **Notice (NOTICE)**: components grouped by license. Use it to satisfy the obligation to include or disclose notices when distributing.
- **SBOM**: CycloneDX 1.6. The artifact you upload to a vulnerability-management system.
- **Open-source risk report**: aggregates vulnerabilities by severity with recommended deadlines (Critical 7 days, High 30 days). Includes a license summary and (for supplier SBOMs) the format conformance result.

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
| AI model | enter a HuggingFace model id (run the UI from the aibom image) |

For source-code scans (current folder, GitHub URL, ZIP upload), an **Advanced scan options** section offers toggles that change how the source is analyzed rather than which files are produced:

- **License scan (ScanCode)** — the UI equivalent of `--deep-license`. Scans your own source files for per-file license text and headers (1st-party). It does not download or scan the declared dependencies.
- **File-level identification (SCANOSS)** — finds third-party open source copied straight into the tree (mainly C/C++). See [Identify bundled open source](identify-vendored.md).

Both are slow and off by default, so enable them only when needed. ScanCode is available only in an image built with `--build-arg SBOM_DEEP_LICENSE=true`. For the full list of toggles and per-target availability, see the [Web UI reference](../reference/ui.md).

As it runs, logs stream live; when done you can view or download the notice, SBOM, and risk report (plus the conformance report when relevant). The conformance result (pass/fail) is shown as a card at the top.

> The firmware upload tab is only enabled when the UI runs from an image that includes the firmware tools:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-firmware:latest $SBOM --ui`

## Troubleshooting / limits

- **GitHub URL**: private repos need `GIT_TOKEN`. Disallowed URL forms (shell metacharacters, `..`, spaces) are rejected for security.
- **ZIP/tar**: archives containing a path escape (zip-slip) are rejected. If Git Bash on Windows has no `unzip`, `tar` is used.
- **C/C++**: pure source without a package manager produces a sparse SBOM (see [Scenario 3](#scenario-3--local-cc-source-directory)).
- **Firmware**: statically linked libraries and vendor-modified squashfs have limited detection (see the [firmware analysis guide](../guides/firmware.md) (Korean), Limits).
- **SBOM analysis**: converting SPDX to CycloneDX may simplify some license expressions.

---

> **Related**: [Getting started](../start/first-scan.md) | [CLI reference](../reference/cli.md)
