---
description: The output files BomLens produces — file list, when each is generated, naming rules, and the SBOM structure summary.
---

# Artifacts reference

The generated SBOM is CycloneDX 1.6 JSON. An SPDX 2.3 JSON copy, converted from the final CycloneDX BOM, is produced by `--spdx` during a CLI scan or on demand from the results screen in the UI. Both paths run the same conversion and give the same file. CycloneDX remains the primary format, and CycloneDX-only data (vulnerabilities, `bomlens:*` properties) is not carried over.

The filename is `{Project}_{Version}_bom.json` (e.g. `MyApp_1.0.0_bom.json`).

## Output files

| File | When generated | Description |
|------|----------------|-------------|
| `{Project}_{Version}_bom.json` | always | SBOM (CycloneDX 1.6) |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all`, or Export as SPDX 2.3 in the UI | SBOM (SPDX 2.3, converted from the CycloneDX output) |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / risk report default | open-source notice |
| `{Project}_{Version}_NOTICE.pdf` | same as above, when a PDF renderer is built into the image (`--build-arg SBOM_PDF=true`) | the notice rendered to PDF; skipped with a log line otherwise |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{Project}_{Version}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | default (all modes) — omit with `--no-report`; `--analyze` always produces it regardless, since that is what it measures | format conformance report, with a regulatory crosswalk roll-up for every SBOM (EU CRA via BSI TR-03183-2, the US SBOM minimum elements of 2026 — reference only, no compliance determination). For an AI SBOM it also carries the G7 checks and, for each advisory element still missing, the CycloneDX fragment that would satisfy it. See a [rendered example](../samples/aether-7b-5attn_conformance.html) |
| `{Project}_{Version}_ai-profile.json` / `.md` | AI SBOM (`--model`, or `--analyze` on an SBOM with a model component) | AI compliance profile: G7 rollup, the closable gaps with their reference links, license-flagged components, regulatory crosswalk, and the model risk assessment (`riskAssessment`: per-model ok/conditional/caution/review verdicts with conditions, reasons and the usage scenario; guidance, not legal advice). The same rollup opens the conformance HTML, so there is no separate HTML profile |
| `{Project}_{Version}_scancode.json` | `--deep-license` | raw scancode result |
| `{Project}_{Version}_files.json` | a source-having scan (a firmware scan always; other modes when `--deep-license` did not already produce `_scancode.json`) | ScanCode-shaped file-tree inventory (structure only, no licenses) backing the source-tree view |
| `{Project}_{Version}_source.json` | a source-having scan | snapshot of the scanned tree's file content, backing the file viewer (the scanned tree itself does not outlive the container) |
| `{Project}_{Version}_input.json` | `--analyze` | the supplier SBOM's own format, spec version, tool and authorship, captured before the CycloneDX conversion rewrites all of it |
| `{Project}_{Version}_yocto_vex.json` | a Yocto build (a build directory named directly, or `--analyze` on one) | how many CVEs the build already patched or judged not applicable — numbers not recoverable from the CycloneDX output or the security report, which list only what is still unresolved |
| `{Project}_{Version}_vendored.cdx.json` | `--identify-vendored` on a source scan, with the opt-in SCANOSS image | vendored open-source components identified inside the source tree (SCANOSS) |
| `{Project}_{Version}_security_epss.json` | whenever the security report is generated | EPSS score and KEV status per vulnerability (null/false when generated offline), used to prioritize the security report |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign signature (with `--spdx`, a `_bom.spdx.json.sig` is produced too) |
| `{new}_model-diff.json` | `--diff <old.json> <new.json>` | AI-model drift report comparing two already-generated SBOMs: matched model verdict/license/hash changes, plus any component present in only one of the two files. Named after the newer input (`<new>_bom.json` → `<new>_model-diff.json`), not `{Project}_{Version}` — `--diff` takes no project or version of its own |

`{P}` = project name, `{V}` = version (special characters are normalized to `_`).

The conditions above are the CLI flags. In the web UI and the desktop app the same choices are the generation options on the New scan screen — Notice and Security report — and every file produced is listed in the Artifacts section of the results, downloadable per format or as one ZIP. SPDX is not a scan option there: the SBOM card in that section has an **Export as SPDX 2.3** button that converts the finished BOM whenever you need it, and the converted file joins the artifact list and the ZIP. The UI has no signing, so an SPDX exported that way is unsigned; use `--spdx --sign` in the CLI when you need a signature. See [Web UI and desktop app](ui.md).

## SBOM structure

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

For the per-language PURL format, see [Supported ecosystems](ecosystems.md).
