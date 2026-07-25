---
description: Validate that an SBOM (CycloneDX/SPDX) you received meets your quality criteria with BomLens, then analyze licenses and vulnerabilities into a risk report.
---

# Supplier SBOM validation guide

How to validate that an SBOM (JSON) received from a supplier or another team meets your quality criteria. After validation, BomLens analyzes the licenses and vulnerabilities and produces a risk report. You only need the SBOM file — no source code required.

For the design background and the internal validation logic, see the maintainer doc [Supplier SBOM validation and analysis](https://github.com/sktelecom/bomlens/blob/main/docs/maintainers/supplier-sbom-analysis.md) (Korean).

## When to use it

Use it when a supplier or another team hands you an SBOM file instead of source, and you need to confirm the SBOM meets your quality criteria and then check its licenses and vulnerabilities. The input can be CycloneDX or SPDX (JSON, Tag-Value); it is converted to CycloneDX internally for analysis.

The criteria check whether an SBOM is good enough for dependency review. Requirements vary by organization; as one reference, see SK Telecom's [supply chain security guide](https://sktelecom.github.io/guide/supply-chain/for-suppliers/) and its [SBOM requirements](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/).

| Category | Criteria |
|----------|----------|
| Format | CycloneDX v1.3–1.6 or SPDX v2.2–2.3 |
| Required metadata | timestamp, tool info, top-level component name and version |
| Required component fields | name, version, PURL in standard `pkg:type/name@version` form (`pkg:generic` not allowed) |
| Completeness | both direct and transitive dependencies included |
| Recommended | supplier, license (SPDX ID), hash |

> The accepted format ranges above are the SK Telecom submission defaults. If your organization accepts a different range, override them with the `CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS` (AI SBOMs), and `SPDX_SPEC_VERSIONS` environment variables (space-separated lists). They are listed in the [Docker image environment variables](../reference/docker-image.md).

## Running it all at once

### From the web UI

Open the web UI, choose **SBOM upload**, and upload the file you received; enter a project name and version, then run.

For a Java (Maven) heavy SBOM, turn on **Deep CVE matching (maven, NVD)** in the scan options. It also checks older Maven libraries against NVD-only vulnerabilities that other advisory sources miss, at the cost of a longer scan. The option appears only for SBOM upload, and the first run downloads the deep-cve image once. It is the same matching as the CLI's `--deep-cve`.

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

`--analyze` turns on notice and security analysis automatically, so you do not need to add `--all`. `--generate-only` leaves only the outputs in a `{Project}_{Version}/` subfolder under the current directory and cleans up the temporary working copy. For the remaining options, see the [usage guide](../reference/cli.md#options-reference).

## The four outputs

| Output | File | Meaning |
|--------|------|---------|
| Conformance report | `{Project}_{Version}_conformance.{json,md,html}` | whether the quality criteria are met, and what is missing |
| SBOM (converted) | `{Project}_{Version}_bom.json` | SPDX inputs converted to CycloneDX 1.6; CycloneDX inputs keep their original spec version |
| Open-source notice | `{Project}_{Version}_NOTICE.{txt,html}` | components grouped by license |
| Risk report | `{Project}_{Version}_risk-report.{md,html}` | conformance, vulnerabilities, and licenses combined, with response deadlines |

Unlike a self-generated SBOM, a received SBOM additionally produces a conformance report, and its summary goes into section 1 of the risk report.

## Reading the conformance report

The conformance report is the per-item check of whether the received SBOM meets the quality criteria. Validation is based on the original input before conversion, so even for SPDX it checks the fields of the original SPDX.

- If any required item falls short, it is a `fail`. The required items match the criteria table in [When to use it](#when-to-use-it) — spec version range (CycloneDX v1.3–1.6, SPDX v2.2–2.3), timestamp, tool info, top-level component, name/version coverage, PURL coverage and syntax (standard `pkg:type/name@version` form, no `pkg:generic`), and transitive dependencies. AI SBOMs are also accepted at CycloneDX 1.7, which the AIBOM toolchain emits.
- If a recommended item falls short, it is a `warn`, not a `fail`. Besides license and hash coverage, this includes the advisory per-component fields the regulatory baselines call for — SHA-512 checksum coverage, component creator, component filename, source/distribution URI, and the delivered-file properties (marked review when no scan can see the artifact).
- The cards at the top of the HTML report show pass/fail and the list of missing items.
- Each check that corresponds to a regulatory baseline carries the reference under its row, and a crosswalk section rolls the coverage up per framework — BSI TR-03183-2 (the German technical guideline for the EU Cyber Resilience Act) and the US NTIA minimum elements. The crosswalk is reference material and makes no compliance determination; the [AI model SBOM guide](ai-model.md#regulatory-crosswalk) describes how it works.

When a `fail` appears, tell whoever sent the SBOM which fields are missing and ask them to fix it. The most common unmet items are a missing PURL, use of `pkg:generic`, and missing transitive dependencies (only direct dependencies included).

## Reading the risk report

The risk report (`_risk-report`) is a document built by re-aggregating the outputs above without a new scan. It has four parts.

1. Requirements met — the conformance results table. If `fail`, the unmet items are stated.
2. Vulnerability tally and response deadlines — a severity tally plus the recommended deadlines (a response plan or risk justification within 7 days for Critical and 30 days for High), laid out in a table.
3. License summary — the notice and license coverage.
4. Next steps — guidance on a response plan.

## SPDX input

If you supply SPDX (JSON, Tag-Value), it is converted to CycloneDX internally with `syft convert` and then analyzed through the same pipeline. Conformance validation is based on the original SPDX before conversion, because metadata such as timestamp, tools, or transitive dependencies can be normalized away during conversion. Some SPDX license expressions may be simplified when moved to CycloneDX.

## Asking for remediation

After validation and analysis, send the risk report (`_risk-report.html`) to whoever sent the SBOM and ask for the following.

- Fix the conformance `fail` items and send the SBOM again.
- Prepare a response plan or risk justification for Critical vulnerabilities within 7 days and High within 30 days (recommended deadlines).

Response tracking, exception approval, and history management are out of scope for this tool — they belong to a separate vulnerability and risk management system. This tool covers validating, analyzing, and reporting on a single SBOM locally.

## Limits

- Validation is based on the presence and coverage of required fields. It does not guarantee semantic accuracy such as whether a PURL points to the exact package or whether a version is real.
- Whether transitive dependencies are included is inferred from the presence of edges in the dependency graph; it is not proof that the graph is complete.
- The accuracy of vulnerability and license analysis depends directly on the quality of the input SBOM, especially PURL and version accuracy.

---

> **Related**: [Getting started](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [Notice and security guide](../guides/reports.md)
