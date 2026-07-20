---
description: The output files BomLens produces — file list, when each is generated, naming rules, and the SBOM structure summary.
---

# Artifacts reference

The generated SBOM is CycloneDX 1.6 JSON. With `--spdx` an SPDX 2.3 JSON copy is exported alongside it, converted from the final CycloneDX BOM — CycloneDX remains the primary format, and CycloneDX-only data (vulnerabilities, `bomlens:*` properties) is not carried over.

The filename is `{Project}_{Version}_bom.json` (e.g. `MyApp_1.0.0_bom.json`).

## Output files

| File | When generated | Description |
|------|----------------|-------------|
| `{Project}_{Version}_bom.json` | always | SBOM (CycloneDX 1.6) |
| `{Project}_{Version}_bom.spdx.json` | `--spdx` / `--all` | SBOM (SPDX 2.3, converted from the CycloneDX output) |
| `{Project}_{Version}_NOTICE.txt` / `.html` | `--notice` / `--all` / risk report default | open-source notice |
| `{Project}_{Version}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{Project}_{Version}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{Project}_{Version}_conformance.json` / `.md` / `.html` | `--analyze` | format conformance report. For an AI SBOM it also carries the G7 checks and, for each advisory element still missing, the CycloneDX fragment that would satisfy it |
| `{Project}_{Version}_ai-profile.json` / `.md` / `.html` | AI SBOM (`--model`, or `--analyze` on an SBOM with a model component) | AI compliance profile: G7 rollup, the closable gaps with their reference links, license-flagged components, and regulatory crosswalk (advisory, not a certification) |
| `{Project}_{Version}_scancode.json` | `--deep-license` | raw scancode result |
| `{Project}_{Version}_bom.json.sig` | `--sign` | cosign signature (with `--spdx`, a `_bom.spdx.json.sig` is produced too) |

`{P}` = project name, `{V}` = version (special characters are normalized to `_`).

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
