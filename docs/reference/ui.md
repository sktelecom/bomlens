---
description: Reference for the BomLens web UI and desktop app — how to launch it, the shell layout, scan targets, and the result sections.
---

# Web UI & desktop app

Scan from a browser without the CLI. The UI server is built into the scanner image, so no extra install is needed.

![The BomLens New scan screen](../images/web-ui.png)

**macOS / Linux:**
```bash
cd ~/sbom-output      # output folder (anywhere is fine)
/path/to/sbom-tools/scripts/scan-sbom.sh --ui
# → opens http://localhost:8080 automatically
```

**Windows — double-click (no command line):** in the unzipped folder, double-click `scripts\sbom-ui.bat` and a browser opens `http://localhost:8080` shortly after. Docker just needs to be running, and `sbom-ui.bat` works on Rancher Desktop or Docker Desktop (on WSL2, run `scan-sbom.sh --ui` inside WSL).

> The run location is the output folder, and it scans that folder's source only when you choose "Current folder" as the scan target. If you use a GitHub URL, an upload, or a Docker image, the run location does not matter.

## The shell

The interface has a left rail, a top bar, and a content area:

- **Left rail** — result sections grouped under Inventory, Risk & compliance, AI and Outputs, plus a Recent scans list at the bottom. The rail adapts to the scan: AI sections appear only for AI/ML SBOMs, and a section appears only when its data exists. The rail collapses to icons on narrow windows.
- **Top bar** — the product mark, the current project, and the language (한국어 / EN) and light/dark toggles.
- **Content** — the New scan form, the running view, or the active result section.

Every navigation element — the logo, New scan, the sidebar sections, the jump cards and recent scans — is a real link backed by a URL hash (`#/scan/<id>/<section>`), so Cmd/Ctrl or middle click opens it in a new tab.

## New scan

The New scan screen is two panes. On the left, pick a source — grouped into **Code** (current folder, a directory path, a GitHub URL, a ZIP upload), **Artifact** (a Docker image, a firmware image), **SBOM** (analyze an existing SBOM) and **AI model** (generate an ML-BOM from a HuggingFace model) — and fill in the source-specific input below the tiles. On the right, enter the project name and version, choose the outputs to generate, and start the scan.

| Scan target | Input method | Backend mode |
|-------------|--------------|--------------|
| Current folder | scans the source in the UI's run folder | SOURCE |
| Directory path | a subfolder under the run folder (e.g. an OS rootfs) | ROOTFS |
| GitHub URL | enter the repository URL | SOURCE (clone) |
| ZIP upload | upload a `.zip`/tar file | SOURCE (extract) |
| SBOM upload | upload an existing SBOM (JSON) | ANALYZE |
| Firmware upload | upload a `.bin`, etc. | FIRMWARE |
| Docker image | enter the image name | IMAGE |
| AI model | enter a HuggingFace model id (`org/model`) | AIBOM |

Generation options are the open-source notice and the security (vulnerability) report. Advanced scan options — ScanCode deep license detection and SCANOSS bundled-OSS identification for C/C++ — apply to source-code scans only (current folder, GitHub URL, ZIP upload); Docker images, firmware, SBOM uploads and AI models have none. Choosing SBOM upload (ANALYZE) forces the notice and security reports on for the risk analysis, and an AI-model scan produces the notice only (it has no package CVEs, so the security report is skipped).

## Scan running

During a run the screen shows the pipeline stages — generate, normalize, notices, security, report — advancing as the live log streams, so you can see where the scan is and read any error (clone failure, no Docker socket, an unsupported file) as it happens.

## Result sections

When the scan finishes, the left rail fills with the sections for that scan.

**Overview** leads with what needs attention — a failed format conformance (for an analyzed supplier SBOM), critical or high vulnerabilities, and components flagged for license review — then the at-a-glance counts, the severity distribution and the license summary, with cards that jump to each detail section. If a scan is still running, its live log appears here on the Overview, not under every section.

![Overview — needs-attention, counts, severity and jump cards](../images/app-results.png)

**Components** lists everything detected, with search and filters (has vulnerabilities, direct only, needs review) and columns for Scope (direct vs transitive) and Risk (the worst vulnerability severity and count). Large SBOMs render in pages. Click a row to expand its detail in place — the PURL, source/download location, copyright, licenses and any vulnerabilities.

![Components — Scope and Risk columns with filters](../images/web-ui-components.png)

**Vulnerabilities** sorts by severity then CVSS, with a CVSS column and the fixed version, and each row expands in place to show the CVSS vector, description and references. Click a band in the severity bar to filter to that severity, or search by CVE or package; the table columns are drag-resizable.

![Vulnerabilities — CVSS column and expandable rows](../images/web-ui-vulns.png)

**Dependencies** shows the relationships recorded in the SBOM as a graph or a tree. Direct dependencies are highlighted and packages with known vulnerabilities are marked with their severity. Switch to the tree to expand direct and transitive dependencies as a hierarchy.

![Dependencies — direct and vulnerable packages marked](../images/web-ui-dependencies.png)

**Licenses** leads with components whose terms need human review — AI behavioral-use (RAIL/Llama/Gemma) and non-commercial licenses — then the full license distribution. Click a license to list the components that use it; copyleft and reciprocal licenses (GPL, LGPL, MPL, EPL, …) are toned for review.

![Licenses — review-first, then the full distribution](../images/web-ui-licenses.png)

**Conformance** appears when you analyze an existing SBOM (the SBOM upload / ANALYZE mode), under Risk & compliance. It shows the format verdict — pass or fail — and the base CycloneDX checks (timestamp, tools, top-level component, name and version coverage, PURL coverage, transitive dependencies), with the missing items listed for each failed check. When the analyzed SBOM carries a machine-learning-model component, the G7 AI minimum-element checks (all advisory, "N of 6 present") appear here as a sub-block.

![Conformance — format verdict with the G7 advisory sub-block](../images/web-ui-g7.png)

**Artifacts** lists the generated files (SBOM, notice, risk report, security report, conformance) grouped by kind, downloadable per format or as a single ZIP. The Source tree section appears when ScanCode results are available — that is, from a source scan run with deep license detection — showing the source files with the license detected per file.

### AI surfaces

For an AI/ML SBOM (a CycloneDX SBOM with a machine-learning-model component), the rail adds:

**Models & datasets** — each model card's identifier, architecture, task, license, supplier and integrity, a four-axis disclosure panel (weights / architecture / training data / training process, as documented in the BOM), and the datasets the model references.

![Models & datasets — model card and disclosure axes](../images/web-ui-models.png)

The G7 AI minimum-element checks appear inside the **Conformance** section above — they are added only when the SBOM has a model component.

## Recent scans

Past scans in the output folder appear in the rail's Recent list (the newest 20, with the worst severity). Click one to re-open its results, or delete one to remove its artifacts. This is local files only — no account, no database.

## Notes

> The firmware upload tile is enabled only when the UI runs from an image that includes the firmware tools:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-firmware:latest ./scripts/scan-sbom.sh --ui`
>
> **Note:** the UI's source scan (current folder / ZIP / GitHub) analyzes the directory with syft inside the container. Components are captured only when there is a lock file (`package-lock.json`, `go.sum`, and so on) or installed dependencies. If you only have a manifest and need deeper resolution, use the CLI source mode (cdxgen).

**Changing the port / on a conflict:** if the default port (8080) is taken by another service, specify a different port:
```bash
UI_PORT=9090 ./scripts/scan-sbom.sh --ui      # http://localhost:9090
```

> **Note:** even though the UI is easy, a Docker engine must be installed and running (free: WSL2 + docker-ce, or Rancher Desktop). The launcher detects a missing or stopped Docker and shows the install link.
