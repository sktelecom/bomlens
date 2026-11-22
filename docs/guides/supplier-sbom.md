---
description: Validate that an SBOM (CycloneDX/SPDX) you received meets your quality criteria with BomLens, then analyze licenses and vulnerabilities into a risk report.
---

# Supplier SBOM validation guide

How to validate that an SBOM (JSON) received from a supplier or another team meets your quality criteria. After validation, BomLens analyzes the licenses and vulnerabilities and produces a risk report. You only need the SBOM file — no source code required.

## Submitting an SBOM you made

If you supply software to SK Telecom, check your SBOM against the submission criteria before you send it.

1. When you scan, choose the SKT submission profile. In the desktop app or web UI, open **Output format** in the scan settings and set **Conformance profile** to SKT submission. On the CLI, add `--conformance-profile skt-submission`. The default profile stays as it is, so choose this on every scan.
2. Open **Conformance check** in the result. If it fails, fix what the failed rows name and scan again ([Reading the conformance check report](#reading-the-conformance-check-report)).
3. When it passes, submit only `{Project}_{Version}_bom.json` from the output folder. The other files are for your own review.

## When to use it

Use it when a supplier or another team hands you an SBOM file instead of source, and you need to confirm the SBOM meets your quality criteria and then check its licenses and vulnerabilities. The input can be CycloneDX (JSON or XML) or SPDX (JSON, Tag-Value); it is converted to CycloneDX internally for analysis. SPDX RDF/XML is not supported yet.

BomLens was built for SK Telecom's supplier SBOM submission, and the table below follows its requirements. The criteria check whether an SBOM is good enough for dependency review. Requirements vary by organization; see SK Telecom's [supply chain security guide](https://sktelecom.github.io/guide/supply-chain/for-suppliers/) and its [SBOM requirements](https://sktelecom.github.io/guide/supply-chain/for-suppliers/requirements/).

| Category | Criteria |
|----------|----------|
| Format | CycloneDX v1.3–1.7 or SPDX v2.2–2.3 |
| Required metadata | timestamp, tool info, top-level component name and version |
| Required component fields | name, version, PURL in standard `pkg:type/name@version` form, with the namespace the type requires (`pkg:maven/<groupId>/<artifactId>`, `pkg:rpm/<distro>/<name>`); a type purl-spec defines, and not `pkg:generic` |
| Completeness | both direct and transitive dependencies included |
| Recommended | supplier, license (SPDX ID), hash |

> The accepted format ranges above are the SK Telecom submission defaults. If your organization accepts a different range, override them with the `CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS` (AI SBOMs), and `SPDX_SPEC_VERSIONS` environment variables (space-separated lists). They are listed in the [Docker image environment variables](../reference/docker-image.md).

The `pkg:generic` line above comes from the `skt-submission` profile, not the default one, which treats `pkg:generic` as advisory and accepts 90% PURL coverage rather than 100%. An SBOM upload in the web UI uses `skt-submission` unless you change it; the CLI needs `--conformance-profile skt-submission`.

## Running it all at once

### From the desktop app or the web UI

Open the desktop app or the web UI (setup is in [First scan](../start/first-scan.md)), choose **SBOM upload**, and upload the file you received; enter a project name and version, then run. A Yocto SPDX 2.2 build hands over an `<image>.spdx.tar.zst` rather than a document. That archive uploads here too, since it is the only SBOM such a build produces.

If the SBOM leans Java (Maven), turn on **Deep CVE matching (NVD CPE)** in the scan options. It checks older Maven libraries against NVD-only vulnerabilities that other advisory sources miss, at the cost of a longer scan. It is the same matching as the CLI's `--deep-cve`; for which scan modes offer the toggle and what the first run downloads, see [Deep CVE matching](reports.md#deep-cve-matching---deep-cve).

### From the CLI

Prefer no command line? See the [no-CLI quick start](../start/no-cli.md) first. What follows is the CLI path.

Pass the SBOM file to `--analyze`. The first scan pulls the scanner image by itself.

```bash
./scripts/scan-sbom.sh --project supplier-app --version 2.0.0 \
  --analyze "./supplier-sbom.json" \
  --conformance-profile skt-submission \
  --generate-only
```

`--analyze` turns on notice and security analysis automatically, so you do not need to add `--all`. `--generate-only` leaves only the outputs in a `{Project}_{Version}/` subfolder under the current directory and cleans up the temporary working copy. For the remaining options, see the [usage guide](../reference/cli.md#options-reference).

## The four outputs

| Output | File | Meaning |
|--------|------|---------|
| Conformance check report | `{Project}_{Version}_conformance.{json,md,html}` | whether the quality criteria are met, and what is missing |
| SBOM (converted) | `{Project}_{Version}_bom.json` | SPDX inputs converted to CycloneDX 1.6; CycloneDX inputs keep their original spec version |
| Open-source notice | `{Project}_{Version}_NOTICE.{txt,html}` | components grouped by license |
| Risk report | `{Project}_{Version}_risk-report.{md,html}` | conformance, vulnerabilities, and licenses combined, with response deadlines |

A self-generated scan produces the same conformance check report file by default too (see [Input scenarios](by-input.md#the-four-deliverables)), and its summary goes into section 1 of the risk report either way. The web UI shows the result under **Conformance check** for both kinds of scan, with the profile it was graded against.

## Reading the conformance check report

The report checks the SBOM's own fields row by row against the selected profile. For SPDX input it checks the original document before conversion. Pass and fail here are results against the format requirements of the selected conformance profile. This is not a legal compliance determination. The screen shows the verdict as Pass or Fail; `fail` and `warn` below are the values written in the report file.

- A required row that falls short is a `fail`, and one `fail` fails the SBOM.
- A recommended row that falls short is a `warn`. It does not change the verdict.
- Ask whoever sent the SBOM to fix each `fail` and send it again. The most common ones are a missing PURL, `pkg:generic`, a PURL built from the display name (which loses the namespace) and missing transitive dependencies.

| Row | Default profile | `skt-submission` |
|-----|-----------------|------------------|
| Spec version (CycloneDX v1.3–1.7, SPDX v2.2–2.3), timestamp, tool info | `fail` | `fail` |
| Top-level component name and version | `fail`; a fixed name such as `.` or `/scan` is `warn` | `fail` |
| Name and version coverage of package components (100%) | `fail` | `fail` |
| PURL coverage | `fail` under 90% | `fail` under 100% |
| PURL syntax, and the namespace a type requires (`pkg:maven/<groupId>/...`) | `fail` | `fail` |
| `pkg:generic` | `warn` | `fail` |
| PURL type defined by purl-spec | `warn` | `fail` |
| OS package namespace names a distribution; version value is a version | `warn` | `fail` |
| Transitive dependencies | `fail` | `fail` |
| Version needed (a version or the supplier's reason) | not checked | `fail` |
| No upstream purl | not checked | `warn` |
| License, hash and the other per-component fields; 2026 minimum elements | `warn` | `warn` |

Firmware, root filesystem, binary and Yocto build scans under `skt-submission` relax some rows to `warn`. That rule, the first-party exemption, `--resolve-purl`, the suggested fixes and what the check does not cover are in the [artifacts reference](../reference/artifacts.md#conformance-check-report).

## Reading the risk report

The risk report (`_risk-report`) is a document built by re-aggregating the outputs above without a new scan. It has four parts.

1. Requirements met — the conformance results table. If `fail`, the unmet items are stated.
2. Vulnerability tally and response deadlines — a severity tally plus the recommended deadlines (a response plan or risk justification within 7 days for Critical and 30 days for High), laid out in a table.
3. License summary — the notice and license coverage.
4. Next steps — guidance on a response plan.

## SPDX input

A CycloneDX XML document is rewritten as CycloneDX JSON before validation, keeping component hashes, the root component and the dependency links from it; services, vulnerabilities, pedigree and evidence sections are not carried over, and the scan log names any it skipped. A document that declares a DTD or an entity is refused. If you supply SPDX (JSON, Tag-Value), it is converted to CycloneDX internally with `syft convert` and then analyzed through the same pipeline. Conformance validation is based on the original SPDX before conversion, because metadata such as timestamp, tools, or transitive dependencies can be normalized away during conversion. Some SPDX license expressions may be simplified when moved to CycloneDX.

A Yocto SPDX document is read with its own parser, as is a Yocto build directory. See the [Yocto build SBOM guide](yocto.md).

## Asking for remediation

After validation and analysis, send the risk report (`_risk-report.html`) to whoever sent the SBOM and ask for the following.

- Fix the conformance `fail` items and send the SBOM again.
- Prepare a response plan or risk justification for Critical vulnerabilities within 7 days and High within 30 days (recommended deadlines).

The conformance report ends with a "Message for the supplier" section under `--analyze`: one sentence per failed item (and per warning that names components) with the affected component names and how to fix it. Copy it into the request as it is. Each failed item also carries its own fix in the report, and a missing top-level name or version is stated in words.

Response tracking, exception approval, and history management are out of scope for this tool — they belong to a separate vulnerability and risk management system. This tool covers validating, analyzing, and reporting on a single SBOM locally.

## Limits

- Validation is based on the presence and coverage of required fields. It does not guarantee semantic accuracy such as whether a PURL points to the exact package or whether a version is real.
- Whether transitive dependencies are included is inferred from the presence of edges in the dependency graph; it is not proof that the graph is complete.
- The accuracy of vulnerability and license analysis depends directly on the quality of the input SBOM, especially PURL and version accuracy.

---

> **Related**: [First scan](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [Notice and security guide](../guides/reports.md) | [What the reports mean](../concepts/reports-explained.md)
