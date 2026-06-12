# Supplier SBOM validation guide

> **Related**: [Getting started](getting-started.md) | [Scenarios guide](scenarios-guide.md) | [Usage guide](usage-guide.md) | [Notice and security guide](notice-and-security.md)

How to take an SBOM (JSON) submitted by a supplier, validate that it meets the requirements, analyze its licenses and vulnerabilities, and produce a risk report to send back to the supplier. You only need the SBOM file — no source code required.

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

Pull the scanner image once (`docker pull ghcr.io/sktelecom/bomlens:latest`), then pass the SBOM file you received to `--analyze`.

```bash
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh

$SBOM --project supplier-app --version 2.0.0 \
  --analyze "./supplier-sbom.json" \
  --generate-only
```

`--analyze` turns on notice and security analysis automatically, so you do not need to add `--all`. `--generate-only` leaves only the outputs in the current directory and cleans up the temporary working copy.

> **Windows**: to work without the command line, double-click `scripts\sbom-ui.bat` to open the web UI, choose "SBOM upload" at the top, and upload the file. For installation, see [Getting started](getting-started.md).

## The four outputs

| Output | File | Meaning |
|--------|------|---------|
| Conformance report | `{P}_{V}_conformance.{json,md,html}` | whether the submission criteria are met, and what is missing |
| SBOM (converted) | `{P}_{V}_bom.json` | the input normalized to CycloneDX 1.6 |
| Open-source notice | `{P}_{V}_NOTICE.{txt,html}` | components grouped by license |
| Risk report | `{P}_{V}_risk-report.{md,html}` | conformance, vulnerabilities, and licenses combined, with response deadlines |

Unlike a self-generated SBOM, a received SBOM additionally produces a conformance report, and its summary goes into section 1 of the risk report.

## Reading the conformance report

The conformance report is the per-item check of whether the received SBOM meets the submission criteria. Validation is based on the original input before conversion, so even for SPDX it checks the fields of the original SPDX.

- If a required item (timestamp, tool info, top-level component, name/version coverage, PURL coverage, no `pkg:generic`, transitive dependencies) falls short, it is a `fail`.
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
