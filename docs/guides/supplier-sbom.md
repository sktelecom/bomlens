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

The `pkg:generic` line above is the `skt-submission` conformance profile (`--conformance-profile skt-submission`), not the tool's own default. The default profile treats `pkg:generic` as advisory instead of a failing requirement and accepts 90% PURL coverage rather than 100%; the web UI's submission-review screen already defaults to `skt-submission`, but the CLI does not, so pass the flag explicitly when checking against this table.

## Running it all at once

### From the desktop app or the web UI

Open the desktop app or the web UI (setup is in [First scan](../start/first-scan.md)), choose **SBOM upload**, and upload the file you received; enter a project name and version, then run. A Yocto SPDX 2.2 build hands over an `<image>.spdx.tar.zst` rather than a document. That archive uploads here too, since it is the only SBOM such a build produces.

If the SBOM leans Java (Maven), turn on **Deep CVE matching (NVD CPE)** in the scan options. It checks older Maven libraries against NVD-only vulnerabilities that other advisory sources miss, at the cost of a longer scan. It is the same matching as the CLI's `--deep-cve`; for which scan modes offer the toggle and what the first run downloads, see [Deep CVE matching](reports.md#deep-cve-matching---deep-cve).

### From the CLI

Prefer no command line? See the [no-CLI quick start](../start/no-cli.md) first. What follows is the CLI path.

Pull the scanner image once (`docker pull ghcr.io/sktelecom/bomlens:latest`), then pass the SBOM file to `--analyze`:

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

The report checks the SBOM's own fields row by row against the selected profile. For SPDX input it checks the original document before conversion. Pass and fail here are results against the format requirements of the selected conformance profile. This is not a legal compliance determination.

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

The conformance check report of a build directory scan measures the SBOM the scan writes (`<Project>_<Version>_bom.json`), which is the file to submit, rather than the build's own document. That SBOM records `bomlens:scanMode` `YOCTO`, and under `--conformance-profile skt-submission` it is judged the way a firmware scan is: it records the packages installed, not a dependency graph. A Yocto document passed to `--analyze` is judged as it was written.

Because that SBOM is the scan's own, it is completed the way a generated SBOM is. `--sbom-author`, `--supplier` and `--license` (as `concluded`) are recorded, BomLens is listed as a tool with the `build` lifecycle phase, and the image keeps the name the build gave it but gets a `bom-ref`, the `--version` when the build wrote none, and a dependency on every installed package. A timestamp is written when the build gave none, as the manifests do not. With these three options the `bsi-tr-03183-2` rows for the SBOM creator, the dependency graph and the primary component can pass. A Yocto document passed to `--analyze` on its own is someone else's SBOM and none of this is applied to it.

### Your own recipes and vendor binaries

The build records every package it installed, your in-house recipes and a chip vendor's binary recipes included, but nothing in it says which of them are yours or who supplied them. Say so in a declaration file and pass it with `--components`. A component names its recipe (PN, the recipe name without its version) in `bomlens:yocto-recipe`, not a file path, since the paths differ for every machine and work directory:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "application",
      "name": "media-daemon",
      "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
      "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "first-party" },
        { "name": "bomlens:yocto-recipe", "value": "media-daemon" }
      ]
    }
  ]
}
```

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --components meta-example/sbom-declared.cdx.json
```

The declaration goes on every package of that recipe installed in the image (`media-daemon` and `media-daemon-cli`, for example). Each keeps the name, version, purl and CPE the build wrote, gets the declared type, supplier, licence (as `concluded`) and `bomlens:origin`, and is marked `bomlens:declared`. The files the SPDX document lists for the package are nested under it with their hashes and file names. Yocto hashes files, not packages: SPDX 3.0 gives SHA-256, and SHA-512 from Yocto 6.1; SPDX 2.2 gives SHA-1 and SHA-256; the manifests give no files. BomLens does not make up a package hash, so under `--conformance-profile bsi-tr-03183-2` a SHA-512 or file name the build did not record, and the file properties no Yocto record gives, are reported as not in the source SBOM, a warning. Under `skt-submission` the first-party exemption from the PURL rows needs a SHA-512, so on a build before 6.1 your packages keep needing a purl (their `pkg:yocto` purl counts as one without an upstream repository).

The scan fails, naming the recipe, when a declared recipe installed no package in the image; the SBOM written so far is kept as `<Project>_<Version>_bom.refused.json`. A recipe declaration cannot also give `bomlens:artifact`, or the `hashes`, `purl` or `cpe` the build decides. A component with neither a recipe nor a file, such as a blob the device loads at run time, is added as in a source scan, unless it has the name of a package the image installs: that one is declared by its recipe.

A package is matched only by the recipe the build recorded for it (in the SPDX document, or in `license.manifest` for a build without SPDX); one whose recipe was not recorded is not matched by its name, and the refusal names it. A multilib or SDK variant of a recipe (`lib32-media-daemon`, `nativesdk-media-daemon`) is a recipe of its own: declare it separately, and the log warns about any the image installs. Declarations apply to the build directory given with `--target`; `--components` is refused with `--analyze`, since an SBOM passed there is received and is not changed. The web UI cannot declare Yocto recipes yet.

The supplier alone can also come from the build. With SPDX 3.0, set it per recipe in your layer and build again:

```
SPDX_PACKAGE_SUPPLIER_name:pn-media-daemon = "Example Corp"
SPDX_PACKAGE_SUPPLIER_type:pn-media-daemon = "organization"
```

Yocto writes it as the package's `suppliedBy`, which BomLens reads as its supplier. It is a name only, with no URL or email (which BSI TR-03183-2 asks of a creator), and it does not mark the package as yours, so the declaration file is still the way to state `bomlens:origin`. SPDX 2.2 writes `SPDX_SUPPLIER`, whose default names OpenEmbedded rather than the actual supplier, and BomLens does not read it.

### A build that produced no SPDX at all

Turning `create-spdx` on is a build-configuration change, and whoever holds a finished build directory cannot always make one. A build records what it shipped regardless, and those records are read instead:

| What | Where | Gives |
|------|-------|-------|
| Image package manifest | `tmp/deploy/images/<machine>/<image>.manifest` | the installed packages and their versions |
| License manifest | `tmp/deploy/licenses/**/license.manifest` | each package's license and the recipe it came from |
| cve-check report | `tmp/log/cve/cve-summary.json` | per CVE, whether a recipe patched it, judged it not applicable, or left it open |

This is the weakest of the three inputs, and worth knowing why: there are no CPEs, so vulnerability matching has only names and versions to work with, and the CVE verdicts are only as complete as the build's own `cve-check` run (a build that never ran it reports no verdicts rather than none existing). The conformance check report measures the SBOM read from these records, as for any build directory scan. Adding the two `local.conf` lines above and rebuilding remains the better answer.

If the directory is a Yocto build but holds neither an SPDX document nor an image manifest, the scan stops and names the two settings above rather than falling back to a directory scan whose result would misrepresent the image.

What you get differs from a normal SBOM scan in three ways.

The component list contains only the packages installed in the image. A Yocto document also describes every source archive the build consumed, which is useful for provenance but would misrepresent what the product ships. Those are left out.

Vulnerabilities come from the build itself. Yocto runs a CVE analysis while building and records a verdict per CVE, so it knows whether a recipe applied the patch. Those verdicts are shown split three ways: patched during the build, judged not applicable, and still open. Only the open ones are counted as findings. On the reference `core-image-minimal` image this is the difference between reporting 12255 vulnerabilities and reporting none, since every one of them was already closed by the build.

Components get the upstream repository purl, as in a firmware scan, for the projects BomLens can name from the build's records: by the recipe a package came from, or, for SPDX 2.2, by the recipe's source download address. See [Upstream repository purl](firmware.md#upstream-repository-purl) for which projects are covered.

Two limits are worth knowing before you start.

SPDX 2.2 is read, but with less in it. Yocto 4.0 (Kirkstone) and 5.0 (Scarthgap) emit SPDX 2.2 by default, and that form is not a document at all: the deploy directory holds one `<image>.spdx.tar.zst` and nothing else. Inside it are the image document, a document per installed package and one per recipe. BomLens reads the archive itself. Measured against the published Yocto 5.0.14 `core-image-minimal`, it yields the same 36 packages the image manifest lists, with their licenses and CPEs. What they do not give is the build's CVE verdicts (only SPDX 3.0 records which CVEs a recipe patched), so with `--security` vulnerabilities are matched from the CPEs against the NVD CPE index in the image (a CPE with vendor `*` by product name across every vendor, so a product name another project shares can bring that project's CVEs), and a CVE the build already patched can appear as open. Pull the image document out of the archive and upload it alone and you get an almost empty result, which is said rather than left to look like a clean scan. When a build directory holds both formats, the SPDX 3.0 document is the one analyzed even if the 2.2 one is newer. An archive passed to `--analyze` gets no conformance check report: it is a bundle of documents rather than a submitted one, so there is nothing to measure against the submission criteria. Found in a build directory, the SBOM read from it is checked instead.

Conformance checks that depend on PURL will fail. Yocto identifies packages with CPE rather than PURL, so PURL coverage and the checks derived from it cannot pass. The report says how many components carry a CPE instead, and the row cites the baselines — BSI TR-03183-2 and the US SBOM minimum elements — that accept either identifier. The verdict is the submission criteria's, not theirs: PURL is required here because the default vulnerability matching keys on it.

Two more required checks behave differently on a Yocto image, for reasons in the document rather than in the tool. The top-level component fails for want of a version: bitbake writes the image package with a name and no `software_packageVersion` (measured on the reference `core-image-minimal`). Scanned from a build directory, the image takes `--version` instead.

Uploads are capped at 100 MB. For scale, the reference `core-image-minimal` document is 15.8 MB with 35 installed packages. A build directory scanned with `--target` reads the file from disk, so the cap does not apply there.

## Asking for remediation

After validation and analysis, send the risk report (`_risk-report.html`) to whoever sent the SBOM and ask for the following.

- Fix the conformance `fail` items and send the SBOM again.

The conformance report ends with a "Message for the supplier" section under `--analyze`: one sentence per failed item (and per warning that names components) with the affected component names and how to fix it. Copy it into the request as it is. Each failed item also carries its own fix in the report, and a missing top-level name or version is stated in words.
- Prepare a response plan or risk justification for Critical vulnerabilities within 7 days and High within 30 days (recommended deadlines).

Response tracking, exception approval, and history management are out of scope for this tool — they belong to a separate vulnerability and risk management system. This tool covers validating, analyzing, and reporting on a single SBOM locally.

## Limits

- Validation is based on the presence and coverage of required fields. It does not guarantee semantic accuracy such as whether a PURL points to the exact package or whether a version is real.
- Whether transitive dependencies are included is inferred from the presence of edges in the dependency graph; it is not proof that the graph is complete.
- The accuracy of vulnerability and license analysis depends directly on the quality of the input SBOM, especially PURL and version accuracy.

---

> **Related**: [First scan](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [Notice and security guide](../guides/reports.md) | [What the reports mean](../concepts/reports-explained.md)
