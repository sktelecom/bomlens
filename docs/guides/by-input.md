---
description: How BomLens produces an SBOM, an open-source notice, and a risk report for seven input forms — a GitHub URL, a ZIP archive, local source, an existing SBOM, a Yocto build directory, firmware, and a HuggingFace AI model.
---

# Input scenarios guide

## Overview

An open-source compliance manager receives deliverables from many teams in different forms. This guide shows how to produce the same four deliverables for each of seven input forms. (An AI model differs slightly — an ML-BOM and no security report; see Scenario 7.)

### The four deliverables

| Deliverable | File | Meaning |
|-------------|------|---------|
| Open-source notice | `{Project}_{Version}_NOTICE.{txt,html}` | the notice that satisfies license obligations |
| SBOM | `{Project}_{Version}_bom.json` | CycloneDX 1.6 component inventory |
| Open-source risk report | `{Project}_{Version}_risk-report.{md,html}` | aggregated license + vulnerability risk (with deadlines) |
| Conformance report | `{Project}_{Version}_conformance.{json,md,html}` | whether the SBOM meets the submission quality criteria, and what is missing |

The conformance report's file is always produced, but the web UI only shows it as a dedicated pass/fail screen when the input being checked is a supplied SBOM (the `--analyze` path); a self-generated SBOM grading itself is not a meaningful pass/fail signal for most of its checks. For a self-generated scan, open the file directly, or feed the output back in with `--analyze` to see it on screen. See [Reading the conformance report](supplier-sbom.md#reading-the-conformance-report).

For any input form, adding `--all --generate-only` produces all four at once (they are on by default and are only turned off with `--no-report`).

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
SBOM=/path/to/bomlens/scripts/scan-sbom.sh
```

## At a glance

`$SBOM` in every command below is the script path variable from [Common setup](#common-setup) — if you skipped that step, put the full path to `scan-sbom.sh` in its place.

| Input form | Mode | Core command (summary) | Deliverables |
|------------|------|------------------------|--------------|
| GitHub URL | SOURCE | `$SBOM --git <url> --all --generate-only` | notice, SBOM, risk report, conformance report |
| Source ZIP | SOURCE | `$SBOM --target app.zip --all --generate-only` | same |
| Local directory (C/C++) | SOURCE | `cd dir && $SBOM --all --generate-only` | same |
| Existing SBOM JSON | ANALYZE | `$SBOM --analyze sbom.json --generate-only` | same, but the SBOM is the converted input rather than freshly generated |
| Yocto build directory | ANALYZE | `$SBOM --target ~/poky/build --generate-only` | same |
| Build artifact (`.jar`, `.deb`, …) | BINARY | `$SBOM --target app.jar --all --generate-only` | same |
| Installer (`.exe`, `.msi`, `.dmg`) | FIRMWARE | `$SBOM --target installer.exe --all --generate-only` | same |
| Mobile app (`.apk`, `.ipa`) | FIRMWARE | `$SBOM --target app.apk --all --generate-only` | same |
| Firmware `.bin` | FIRMWARE | `$SBOM --target dev.bin --firmware --all --generate-only` | same |
| AI model (HuggingFace) | AIBOM | `$SBOM --model owner/name --generate-only` | notice, ML-BOM (1.7), risk report (no security) |
| AI model file (GGUF, safetensors, …) | MODELFILE | `$SBOM --model-file ./model.gguf --generate-only` | notice, ML-BOM (1.7), risk report (no security) |
| Published dataset (Figshare) | DATASET | `$SBOM --model <item URL> --generate-only` | notice, ML-BOM (1.7), risk report (no security) |

> Every command also needs `--project <name> --version <version>` (see examples below).
>
> C/C++ without a package manager (Conan/vcpkg): add `--identify-vendored` so open source copied straight into the sources is detected as named components. Strongly recommended for this case — see [Scenario 3](#scenario-3--local-cc-source-directory).

## Scenario 1 — GitHub URL

A team handed you a GitHub repository. Pass the URL directly, no manual `git clone`. (`$SBOM` is defined in [Common setup](#common-setup).)

<!-- runnable -->
```bash
$SBOM --project team1-app --version 1.0.0 \
  --git "https://github.com/docker/getting-started-app" \
  --all --generate-only
```

- Specific branch/tag: `--branch v1.2.3`
- Private repository: `GIT_TOKEN=ghp_xxx $SBOM ... --git https://github.com/org/private ...` (the token never appears in logs)
- A shallow clone (`--depth 1`) is fetched to a temp directory and analyzed; only the deliverables remain, in a `{Project}_{Version}/` subfolder under the current directory.
- A monorepo with its own `examples/`, `fixtures/`, or `test-data/` subfolders can pull in components that never ship in the product, because there is no option yet to scope the scan to one subfolder. Point `--git` at the specific app repository rather than an umbrella repository when that distinction matters — a component list padded with unrelated demo dependencies (and, in the worst case, one of them flagged as malicious by osv.dev when it is really just an unused dev dependency of an unrelated example) undermines the notice and risk report for everyone downstream.

**Deliverables**: `team1-app_1.0.0_NOTICE.{txt,html}`, `team1-app_1.0.0_bom.json`, `team1-app_1.0.0_risk-report.{md,html}`, `team1-app_1.0.0_conformance.{json,md,html}`

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

**Deliverables**: notice, SBOM, risk report, conformance report (four)

## Scenario 3 — Local C/C++ source directory

A team shared the source via a folder you copied locally (`~/project/c-dev`). Run from inside the directory.

```bash
cd ~/project/c-dev
$SBOM --project team3-dev --version 1.0.0 --all --deep-license --generate-only
```

- With a package manager (Conan `conanfile.txt` / vcpkg `vcpkg.json`), dependencies resolve and appear in the SBOM.
- Pure CMake/Make sources have no manager metadata, so the SBOM can be sparse. Enrich first-party license headers with `--deep-license` (needs an image built with `--build-arg SBOM_DEEP_LICENSE=true` — the default published image does not carry ScanCode, and `--deep-license` is silently skipped without it), and analyze build output (a staging/rootfs with installed libraries) separately with `$SBOM --target <build-dir> --all --generate-only` (syft). For a full server SBOM workflow — OS rootfs, application, and static-link dependencies as separate layers — see the [server SBOM guide](server-delivery.md). In the web UI, `--deep-license` is the **License scan (ScanCode)** toggle under Advanced scan options; it scans your own source files (`/src`), not the declared dependencies, and is slow, so turn it on only when you need per-file license detection.
- When the source has no package manager (plain Make/CMake) and bundles open source copied straight into the tree — common for embedded and firmware sources — `--identify-vendored` is strongly recommended. Without it the SBOM stays sparse and misses the bundled libraries; with it they are detected as named components with CPEs, so the risk report can match CVEs. See [Identify bundled open source](identify-vendored.md). BomLens also nudges you toward this option automatically when it detects this situation.
- Even without a package manager, the risk report is still generated, aggregating licenses and vulnerabilities of detected components.

**Deliverables**: notice, SBOM, risk report, conformance report (four)

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
- A format conformance report (`_conformance.{json,md,html}`) is also produced, and the first section of the risk report includes the conformance result (whether required fields are present). For what counts as a `fail` vs. a `warn`, see [Reading the conformance report](supplier-sbom.md#reading-the-conformance-report) in the supplier SBOM guide.

**Deliverables**: notice, SBOM (converted), risk report, conformance report

## Scenario 5 — Yocto build directory

You build an embedded Linux image with Yocto and want to know what shipped in it. Point the scan at the build directory; the build already recorded the answer.

```bash
$SBOM --project team5-image --version 1.0.0 \
  --target ~/poky/build \
  --generate-only
```

- Configure the build to emit an SBOM — add `INHERIT += "create-spdx-3.0"` and `INHERIT += "vex"` to `conf/local.conf` — and you get the most out of it. Without it, BomLens still reads what the build wrote by default. See [Yocto images](supplier-sbom.md#yocto-images) for the SPDX-version compatibility table and what happens when a build produced no SPDX at all.
- The image SBOM under `tmp/deploy/images/<machine>/` is analyzed — not the build tree, which holds sysroots and native build tools that never ship in the image.
- The component list is the packages installed in the image, and vulnerabilities carry the verdicts the build itself made (patched by a recipe, judged not applicable, or still open). Only the open ones count as findings.
- If several machines or images were built, the newest SBOM is analyzed and every candidate is listed in the log; pass `--analyze <file>` to choose a different one.
- In the web UI, pick the folder with the **Directory / rootfs** input (mount it with `--ui --mount ~/poky/build`, or use Add folder in the desktop app) — the same detection runs there.
- For the full behavior and its limits, see the [Yocto section of the supplier SBOM guide](supplier-sbom.md#yocto-images).

**Deliverables**: notice, SBOM, risk report, conformance report

## Scenario 6 — Firmware binary

A team handed you a built firmware image (`dev.bin`). Unpack it and identify components.

```bash
$SBOM --project team6-fw --version 1.0.0 \
  --target "./dev.bin" --firmware \
  --all --generate-only
```

- Firmware analysis needs the opt-in firmware image, which includes GPL tools (unblob, cve-bin-tool, etc.). Set it via `SBOM_FIRMWARE_IMAGE`, or pull the default (`ghcr.io/sktelecom/bomlens-firmware:latest`).
- Recognized extensions (`.bin/.img/.squashfs/.ubi/...`) are auto-detected even without `--firmware`, but being explicit is recommended.
- For behavior and limits, see the [firmware analysis guide](../guides/firmware.md).

**Deliverables**: notice, SBOM, risk report, conformance report (four)

## Scenario 7 — AI model (HuggingFace)

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

### When it is a published dataset, not a model

Research data is published where the paper put it, which for a great deal of science is a repository like Figshare rather than a model hub. Hand `--model` the item instead:

```bash
$SBOM --project cell-imaging-data --version 1.0.0 \
  --model "https://figshare.com/articles/dataset/Title/33412285" \
  --usage product --generate-only
```

The page URL, the DOI, or the item number all work, and no account or opt-in image is needed. For version selection, the licence-to-SPDX mapping, and how a private or embargoed item is handled, see [Scanning a published dataset](ai-model.md#scanning-a-published-dataset) in the AI model guide.

**Deliverables**: notice, ML-BOM (CycloneDX 1.7), risk report, conformance check

### When you have the model file, not the model id

A supplier ships weights rather than a Hub link, or the model is internal and was never published. Point at the file itself:

```bash
$SBOM --project internal-llm --version 1.0.0 \
  --model-file ./models/internal-llm-q4.gguf \
  --generate-only
```

Reads the file's own header; no network, no HuggingFace account, and no opt-in image. For the recognized formats, what each one contributes to the SBOM, and the pickle/Keras code-execution check, see [Scanning a model file](ai-model.md#scanning-a-model-file) in the AI model guide.

Deliverables are the same as Scenario 7's, minus what the model card would have supplied.

## Reading the four deliverables

- **Notice (NOTICE)**: components grouped by license. Use it to satisfy the obligation to include or disclose notices when distributing.
- **SBOM**: CycloneDX 1.6. The artifact you upload to a vulnerability-management system.
- **Open-source risk report**: aggregates vulnerabilities by severity with recommended deadlines (Critical 7 days, High 30 days). Includes a license summary and the format conformance result.
- **Conformance report**: the per-item check of whether the SBOM meets the submission quality criteria (required fields, PURL coverage, transitive dependencies, and more). The file is produced by default alongside the other three; the web UI shows it as a screen only on the `--analyze` path (see above). See [Reading the conformance report](supplier-sbom.md#reading-the-conformance-report) in the supplier SBOM guide.

## All at once in the web UI

If you are not comfortable with the CLI, use the web UI.

```bash
$SBOM --ui   # http://localhost:8080 in the browser
```

Pick a scan target at the top of the UI and provide the matching input.

| Scan target | Input |
|-------------|-------|
| Current folder | scans the source in the folder where the UI was launched |
| Directory path | a subfolder under the launch folder (e.g. an OS rootfs), a folder mounted with `--ui --mount <dir>`, or a folder picked with the desktop app's "Add folder" button |
| GitHub URL | enter the URL |
| ZIP upload | upload a `.zip`/tar file |
| Package upload | upload a build artifact — `.jar`, `.war`, `.ear`, `.deb`, `.rpm`, `.whl` |
| SBOM upload | upload an existing SBOM (JSON), ANALYZE mode |
| Firmware upload | upload a `.bin`, etc. — the tile appears automatically whenever Docker is running |
| Docker image | enter the image name |
| AI model | enter a HuggingFace model id — the tile appears automatically whenever Docker is running |
| Model file | upload a `.gguf`, `.safetensors`, `.pt`, etc. (up to 8 GB) |
| Published dataset | enter a Figshare item — its page URL, its DOI, or the item number — in the same field as the model id |

This table lists what the input scenarios in this guide cover; the full set (11 targets) is in the [web UI reference](../reference/ui.md#new-scan).

For source-code scans (current folder, GitHub URL, ZIP upload), an **Advanced scan options** section offers toggles (License scan / ScanCode, File-level identification / SCANOSS) that change how the source is analyzed rather than which files are produced, both off by default. See [Advanced scan options](../reference/ui.md#new-scan) in the Web UI reference for what each one does and per-target availability.

As it runs, logs stream live; when done you can view or download the notice, SBOM, and risk report. The conformance report file is downloadable too; its pass/fail screen only appears when the input was an uploaded SBOM (`--analyze`) rather than a fresh scan.

> The firmware upload tab appears automatically whenever the Docker engine is running. See the
> [firmware guide](firmware.md) for how it works and how to point it at a different image tag.

## Troubleshooting / limits

- **GitHub URL**: for a private repo, the CLI authenticates with the `GIT_TOKEN` environment variable; the web UI has its own token field below the URL input instead (the two are separate paths). Disallowed URL forms (shell metacharacters, `..`, spaces) are rejected for security.
- **ZIP/tar**: archives containing a path escape (zip-slip) are rejected. If Git Bash on Windows has no `unzip`, `tar` is used.
- **C/C++**: pure source without a package manager produces a sparse SBOM (see [Scenario 3](#scenario-3--local-cc-source-directory)).
- **Firmware**: statically linked libraries and vendor-modified squashfs have limited detection (see the [firmware analysis guide](../guides/firmware.md), Limits).
- **SBOM analysis**: converting SPDX to CycloneDX may simplify some license expressions.

---

> **Related**: [Getting started](../start/first-scan.md) | [CLI reference](../reference/cli.md)
