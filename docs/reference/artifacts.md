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
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{Project}_{Version}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | `--analyze` | format conformance report. For an AI SBOM it also carries the G7 checks and, for each advisory element still missing, the CycloneDX fragment that would satisfy it. See a [rendered example](../samples/aether-7b-5attn_conformance.html) |
| `{Project}_{Version}_ai-profile.json` / `.md` / `.html` | AI SBOM (`--model`, or `--analyze` on an SBOM with a model component) | AI compliance profile: G7 rollup, the closable gaps with their reference links, license-flagged components, and regulatory crosswalk (advisory, not a certification). See a [rendered example](../samples/aether-7b-5attn_ai-profile.html) |
| `{Project}_{Version}_scancode.json` | `--deep-license` | raw scancode result |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign signature (with `--spdx`, a `_bom.spdx.json.sig` is produced too) |

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
