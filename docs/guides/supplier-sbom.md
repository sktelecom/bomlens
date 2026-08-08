---
description: Validate that an SBOM (CycloneDX/SPDX) you received meets your quality criteria with BomLens, then analyze licenses and vulnerabilities into a risk report.
---

# Supplier SBOM validation guide

How to validate that an SBOM (JSON) received from a supplier or another team meets your quality criteria. After validation, BomLens analyzes the licenses and vulnerabilities and produces a risk report. You only need the SBOM file — no source code required.


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

Open the web UI, choose **SBOM upload**, and upload the file you received; enter a project name and version, then run. A Yocto SPDX 2.2 build hands over an `<image>.spdx.tar.zst` rather than a document — that archive uploads here too, since it is the only SBOM such a build produces.

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
- If a recommended item falls short, it is a `warn`, not a `fail`. Besides license and hash coverage, this includes the advisory per-component fields the regulatory baselines call for — SHA-512 checksum coverage, component creator, component filename, source/distribution URI, the delivered-file properties (marked review when no scan can see the artifact), and the file component identifier coverage described below.
- Name/version and PURL coverage are measured over package components only. A binary or firmware SBOM also lists the delivered files as file components, and a file on disk has no package version and no PURL type to carry, so counting them would mark an SBOM short on a field that cannot exist there. Files are still expected to be identified, by the identifier they do carry: the file identifier check measures how many of them have a hash. An SBOM that lists files and no packages at all is a `fail`, because vulnerability matching keys on package identifiers and a file listing answers none of it.
- The cards at the top of the HTML report show pass/fail and the list of missing items.
- Each check that corresponds to a regulatory baseline carries the reference under its row, and a crosswalk section rolls the coverage up per framework — BSI TR-03183-2 (the German technical guideline for the EU Cyber Resilience Act) and the US SBOM minimum elements (2026). The crosswalk is reference material and makes no compliance determination; the [AI model SBOM guide](ai-model.md#regulatory-crosswalk) describes how it works.

When a `fail` appears, tell whoever sent the SBOM which fields are missing and ask them to fix it. The most common unmet items are a missing PURL, use of `pkg:generic`, and missing transitive dependencies (only direct dependencies included).

## Reading the risk report

The risk report (`_risk-report`) is a document built by re-aggregating the outputs above without a new scan. It has four parts.

1. Requirements met — the conformance results table. If `fail`, the unmet items are stated.
2. Vulnerability tally and response deadlines — a severity tally plus the recommended deadlines (a response plan or risk justification within 7 days for Critical and 30 days for High), laid out in a table.
3. License summary — the notice and license coverage.
4. Next steps — guidance on a response plan.

## SPDX input

If you supply SPDX (JSON, Tag-Value), it is converted to CycloneDX internally with `syft convert` and then analyzed through the same pipeline. Conformance validation is based on the original SPDX before conversion, because metadata such as timestamp, tools, or transitive dependencies can be normalized away during conversion. Some SPDX license expressions may be simplified when moved to CycloneDX.

## Yocto images

A Yocto build can produce its own SPDX SBOM, and BomLens reads it with a dedicated parser rather than the generic SPDX path, because a Yocto document carries two things the generic path loses.

To produce one, add the following to `local.conf` and build as usual.

```
INHERIT += "create-spdx-3.0"
INHERIT += "vex"
```

Which SPDX version a release can write is not a choice everywhere:

| Release | SPDX by default | `create-spdx-3.0` available |
|---------|-----------------|-----------------------------|
| 4.0 Kirkstone (LTS) | 2.2 | **no** — the class does not exist in this release |
| 5.0 Scarthgap (LTS) | 2.2 | yes |
| 5.1 Styhead and later | 3.0 | yes (it is the default) |

On Kirkstone the setting above cannot be used; that build writes SPDX 2.2, which is read as described below.

Then point the scan at the build directory. You do not need to know where the build put the SBOM.

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --generate-only
```

The build directory is recognized as one, and the image SBOM it published — `tmp/deploy/images/<machine>/<image>.rootfs.spdx.json`, or `tmp-glibc/…` on an OpenEmbedded build — is analyzed. The build tree itself is not walked: scanning it as a directory would report sysroots and native build tools that never ship in the image.

When several machines or images were built, the most recently written SBOM is analyzed and all the candidates are listed in the log; pass a specific one with `--analyze <file>` to choose another. A build that writes its images somewhere else entirely (a relocated `DEPLOY_DIR`) is not found this way either, so name that document the same way. When all you were sent is the SBOM file, upload it in the web UI or pass it to `--analyze`.

The web UI reads the same folder: pick it with the Directory input (mount it first with `--ui --mount ~/poky/build`, or use Add folder in the desktop app) and the detection runs exactly as it does on the command line.

### A build that produced no SPDX at all

Turning `create-spdx` on is a build-configuration change, and whoever holds a finished build directory cannot always make one. A build records what it shipped regardless, and those records are read instead:

| What | Where | Gives |
|------|-------|-------|
| Image package manifest | `tmp/deploy/images/<machine>/<image>.manifest` | the installed packages and their versions |
| License manifest | `tmp/deploy/licenses/**/license.manifest` | each package's license and the recipe it came from |
| cve-check report | `tmp/log/cve/cve-summary.json` | per CVE, whether a recipe patched it, judged it not applicable, or left it open |

This is the weakest of the three inputs, and worth knowing why: there are no CPEs, so vulnerability matching has only names and versions to work with, and the CVE verdicts are only as complete as the build's own `cve-check` run (a build that never ran it reports no verdicts rather than none existing). No conformance report is produced either — conformance measures a document someone sent you against submission criteria, and there is no document here. Adding the two `local.conf` lines above and rebuilding remains the better answer.

If the directory is a Yocto build but holds neither an SPDX document nor an image manifest, the scan stops and names the two settings above rather than falling back to a directory scan whose result would misrepresent the image.

What you get differs from a normal SBOM scan in two ways.

The component list contains only the packages installed in the image. A Yocto document also describes every source archive the build consumed, which is useful for provenance but would misrepresent what the product ships. Those are left out.

Vulnerabilities come from the build itself. Yocto runs a CVE analysis while building and records a verdict per CVE, so it knows whether a recipe applied the patch. Those verdicts are shown split three ways: patched during the build, judged not applicable, and still open. Only the open ones are counted as findings. On the reference `core-image-minimal` image this is the difference between reporting 12255 vulnerabilities and reporting none, since every one of them was already closed by the build.

Two limits are worth knowing before you start.

SPDX 2.2 is read, but with less in it. Yocto 4.0 (Kirkstone) and 5.0 (Scarthgap) emit SPDX 2.2 by default, and that form is not a document at all: the deploy directory holds one `<image>.spdx.tar.zst` and nothing else. Inside it are the image document, a document per installed package and one per recipe. BomLens reads the archive itself — measured against the published Yocto 5.0.14 `core-image-minimal`, it yields the same 36 packages the image manifest lists, with their licenses and CPEs. What they do not give is the build's CVE verdicts — only SPDX 3.0 records which CVEs a recipe patched — so vulnerabilities are matched from the CPEs like any other SBOM, and a CVE the build already patched can appear as open. Pull the image document out of the archive and upload it alone and you get an almost empty result, which is said rather than left to look like a clean scan. When a build directory holds both formats, the SPDX 3.0 document is the one analyzed even if the 2.2 one is newer. No conformance report is produced for an archive: it is a bundle of documents rather than a submitted one, so there is nothing to measure against the submission criteria.

Conformance checks that depend on PURL will fail. Yocto identifies packages with CPE rather than PURL, so PURL coverage and the checks derived from it cannot pass. The report says how many components carry a CPE instead, and the row cites the baselines — BSI TR-03183-2 and the US SBOM minimum elements — that accept either identifier. The verdict is the submission criteria's, not theirs: PURL is required here because the default vulnerability matching keys on it.

Two more required checks behave differently on a Yocto image, for reasons in the document rather than in the tool. The top-level component fails for want of a version: bitbake writes the image package with a name and no `software_packageVersion` (measured on the reference `core-image-minimal`).

Uploads are capped at 100 MB. For scale, the reference `core-image-minimal` document is 15.8 MB with 35 installed packages. A build directory scanned with `--target` reads the file from disk, so the cap does not apply there.

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
