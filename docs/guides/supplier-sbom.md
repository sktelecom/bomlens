---
description: Validate that a supplier-submitted SBOM (CycloneDX/SPDX) meets the requirements with BomLens, then analyze licenses and vulnerabilities into a risk report to send back.
---

# Supplier SBOM validation guide

How to validate that an SBOM (JSON) submitted by a supplier meets the submission requirements. After validation, it analyzes the licenses and vulnerabilities and produces a risk report to send back to the supplier. You only need the SBOM file — no source code required.

For the design background and the internal validation logic, see the maintainer doc [Supplier SBOM validation and analysis](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/supplier-sbom-analysis.md) (Korean).

## When to use it

Use it when a supplier or another team hands you an SBOM file instead of source, and you need to confirm the SBOM meets the submission criteria and then check its licenses and vulnerabilities. The input can be CycloneDX or SPDX (JSON, Tag-Value); it is converted to CycloneDX internally for analysis.

The criteria follow SK Telecom's [supply chain security guide](https://sktelecom.github.io/guide/supply-chain/for-suppliers/) and its [SBOM submission requirements](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/).

| Category | Criteria |
|----------|----------|
| Format | CycloneDX v1.3–1.6 or SPDX v2.2–2.3 |
| Required metadata | timestamp, tool info, top-level component name and version |
| Required component fields | name, version, PURL (`pkg:generic` not allowed) |
| Completeness | both direct and transitive dependencies included |
| Recommended | supplier, license (SPDX ID), hash |

## Running it all at once

### From the web UI

Open the web UI, choose **SBOM upload**, and upload the file you received; enter a project name and version, then run.

```bash
./scripts/scan-sbom.sh --ui     # opens http://localhost:8080
#   Windows: double-click scripts\sbom-ui.bat
```

Installation is in [Getting started](../start/first-scan.md).

### From the CLI

Pull the scanner image once (`docker pull ghcr.io/sktelecom/bomlens:latest`), then pass the SBOM file to `--analyze`:

```bash
./scripts/scan-sbom.sh --project supplier-app --version 2.0.0 \
  --analyze "./supplier-sbom.json" \
  --generate-only
```

`--analyze` turns on notice and security analysis automatically, so you do not need to add `--all`. `--generate-only` leaves only the outputs in the current directory and cleans up the temporary working copy. For the remaining options, see the [usage guide](../reference/cli.md#options-reference).

## The four outputs

| Output | File | Meaning |
|--------|------|---------|
| Conformance report | `{Project}_{Version}_conformance.{json,md,html}` | whether the submission criteria are met, and what is missing |
| SBOM (converted) | `{Project}_{Version}_bom.json` | the input normalized to CycloneDX 1.6 |
| Open-source notice | `{Project}_{Version}_NOTICE.{txt,html}` | components grouped by license |
| Risk report | `{Project}_{Version}_risk-report.{md,html}` | conformance, vulnerabilities, and licenses combined, with response deadlines |

Unlike a self-generated SBOM, a received SBOM additionally produces a conformance report, and its summary goes into section 1 of the risk report.

## Reading the conformance report

The conformance report is the per-item check of whether the received SBOM meets the submission criteria. Validation is based on the original input before conversion, so even for SPDX it checks the fields of the original SPDX.

- If any required item falls short, it is a `fail`. The required items match the criteria table in [When to use it](#when-to-use-it) — timestamp, tool info, top-level component, name/version coverage, PURL coverage (no `pkg:generic`), and transitive dependencies.
- If a recommended item (license, hash coverage) falls short, it is a `warn`, not a rejection reason.
- The cards at the top of the HTML report show pass/fail and the list of missing items.

When a `fail` appears, tell the supplier which fields are missing and ask for resubmission. The most common rejection reasons are a missing PURL, use of `pkg:generic`, and missing transitive dependencies (only direct dependencies submitted).

## Reading the risk report

The risk report (`_risk-report`) is a document for the supplier, built by re-aggregating the outputs above without a new scan. It has four parts.

1. Requirements met — the conformance results table. If `fail`, the rejection reason is stated.
2. Vulnerability tally and response deadlines — a severity tally plus the criteria that Critical must get a response plan or risk justification within 7 days and High within 30 days, laid out in a table.
3. License summary — the notice and license coverage.
4. Next steps — guidance on submitting a response plan.

## SPDX input

If you supply SPDX (JSON, Tag-Value), it is converted to CycloneDX internally with `syft convert` and then analyzed through the same pipeline. Conformance validation is based on the original SPDX before conversion, because metadata such as timestamp, tools, or transitive dependencies can be normalized away during conversion. Some SPDX license expressions may be simplified when moved to CycloneDX.

## Asking the supplier to remediate

After validation and analysis, send the risk report (`_risk-report.html`) to the supplier and ask for the following.

- Fix the conformance `fail` items and resubmit the SBOM.
- Submit a response plan or risk justification for Critical vulnerabilities within 7 days and High within 30 days.

Company-wide registration, response tracking, and history management are out of scope for this tool — they belong to SKT's internal system (TOSCA) and the portal. This tool covers validating, analyzing, and reporting on a single SBOM locally.

## Limits

- Validation is based on the presence and coverage of required fields. It does not guarantee semantic accuracy such as whether a PURL points to the exact package or whether a version is real.
- Whether transitive dependencies are included is inferred from the presence of edges in the dependency graph; it is not proof that the graph is complete.
- The accuracy of vulnerability and license analysis depends directly on the quality of the input SBOM, especially PURL and version accuracy.

---

> **Related**: [Getting started](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [Notice and security guide](../guides/reports.md)
