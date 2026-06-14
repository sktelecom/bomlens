---
description: The output files BomLens produces — file list, when each is generated, naming rules, and the SBOM structure summary.
---

# Artifacts reference

The generated SBOM is CycloneDX 1.6 JSON.

The filename is `{ProjectName}_{Version}_bom.json` (e.g. `MyApp_1.0.0_bom.json`).

## Output files

| File | When generated | Description |
|------|----------------|-------------|
| `{P}_{V}_bom.json` | always | SBOM (CycloneDX 1.6) |
| `{P}_{V}_NOTICE.txt` / `.html` | `--notice` / `--all` / risk report default | open-source notice |
| `{P}_{V}_security.json` / `.md` / `.html` | `--security` / `--all` / risk report default | Trivy security report |
| `{P}_{V}_risk-report.md` / `.html` | default (all modes) — omit with `--no-report` | open-source risk report |
| `{P}_{V}_conformance.json` / `.md` / `.html` | `--analyze` | format conformance report |
| `{P}_{V}_scancode.json` | `--deep-license` | raw scancode result |
| `{P}_{V}_bom.json.sig` | `--sign` | cosign signature |

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
