---
description: Make an SBOM from a Yocto build directory with BomLens, from the SPDX the build wrote or from the manifests it leaves without one, listing only the packages installed in the image.
---

# Yocto build SBOM guide

How to make an SBOM from a Yocto build directory. Point the scan at the build directory and BomLens reads the image SBOM the build published, or the manifests a build without SPDX still writes. Your own recipes and vendor binaries can be declared in a file the scan applies to the image's packages.

## How a Yocto build is read


A Yocto build can produce its own SPDX SBOM, and BomLens reads it with a dedicated parser rather than the generic SPDX path, because a Yocto document carries two things the generic path loses.

To produce one, add the following to `local.conf` and build as usual.

```
INHERIT += "create-spdx-3.0"
INHERIT += "vex"
```

Which SPDX version a release can write is not a choice everywhere:

| Release | SPDX by default | `create-spdx-3.0` available |
|---------|-----------------|-----------------------------|
| 4.0 Kirkstone (LTS) | 2.2 | **no**, the class does not exist in this release |
| 5.0 Scarthgap (LTS) | 2.2 | yes |
| 5.1 Styhead and later | 3.0 | yes (it is the default) |

On Kirkstone the setting above cannot be used; that build writes SPDX 2.2, which is read as described below.

Then point the scan at the build directory. You do not need to know where the build put the SBOM.

```bash
./scripts/scan-sbom.sh --project my-image --version 1.0.0 \
  --target ~/poky/build --generate-only
```

The build directory is recognized as one, and the image SBOM it published is analyzed: `tmp/deploy/images/<machine>/<image>.rootfs.spdx.json`, or `tmp-glibc/…` on an OpenEmbedded build. The build tree itself is not walked: scanning it as a directory would report sysroots and native build tools that never ship in the image.

When several machines or images were built, the most recently written SBOM is analyzed and all the candidates are listed in the log; pass a specific one with `--analyze <file>` to choose another. A build that writes its images somewhere else entirely (a relocated `DEPLOY_DIR`) is not found this way either, so name that document the same way. When all you were sent is the SBOM file, upload it in the web UI or pass it to `--analyze`.

The web UI reads the same folder: pick it with the Choose folder tile (mount it first with `--ui --mount ~/poky/build`, or use Add folder… in the desktop app) and the detection runs exactly as it does on the command line.

The conformance check report of a build directory scan measures the SBOM the scan writes (`<Project>_<Version>_bom.json`), which is the file to submit, rather than the build's own document. That SBOM records `bomlens:scanMode` `YOCTO`, and under `--conformance-profile skt-submission` it is judged the way a firmware scan is: it records the packages installed, not a dependency graph. A Yocto document passed to `--analyze` is judged as it was written.

Because that SBOM is the scan's own, it is completed the way a generated SBOM is. `--sbom-author`, `--supplier` and `--license` (as `concluded`) are recorded, BomLens is listed as a tool with the `build` lifecycle phase, and the image keeps the name the build gave it but gets a `bom-ref`, the `--version` when the build wrote none, and a dependency on every installed package. A timestamp is written when the build gave none, as the manifests do not. With these three options the `bsi-tr-03183-2` rows for the SBOM creator, the dependency graph and the primary component can pass. A Yocto document passed to `--analyze` on its own is someone else's SBOM and none of this is applied to it.

## Your own recipes and vendor binaries

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

## A build that produced no SPDX at all

Turning `create-spdx` on is a build-configuration change, and whoever holds a finished build directory cannot always make one. A build records what it shipped regardless, and those records are read instead:

| What | Where | Gives |
|------|-------|-------|
| Image package manifest | `tmp/deploy/images/<machine>/<image>.manifest` | the installed packages and their versions |
| License manifest | `tmp/deploy/licenses/**/license.manifest` | each package's license and the recipe it came from |
| cve-check report | `tmp/log/cve/cve-summary.json` | per CVE, whether a recipe patched it, judged it not applicable, or left it open |

This is the weakest of the three inputs, and worth knowing why: there are no CPEs, so vulnerability matching has only names and versions to work with, and the CVE verdicts are only as complete as the build's own `cve-check` run (a build that never ran it reports no verdicts rather than none existing). The conformance check report measures the SBOM read from these records, as for any build directory scan. Adding the two `local.conf` lines above and rebuilding remains the better answer.

If the directory is a Yocto build but holds neither an SPDX document nor an image manifest, the scan stops and names the two settings above rather than falling back to a directory scan whose result would misrepresent the image.

## How the result differs from a normal scan

What you get differs from a normal SBOM scan in three ways.

The component list contains only the packages installed in the image. A Yocto document also describes every source archive the build consumed, which is useful for provenance but would misrepresent what the product ships. Those are left out.

Vulnerabilities come from the build itself. Yocto runs a CVE analysis while building and records a verdict per CVE, so it knows whether a recipe applied the patch. Those verdicts are shown split three ways: patched during the build, judged not applicable, and still open. Only the open ones are counted as findings. On the reference `core-image-minimal` image this is the difference between reporting 12255 vulnerabilities and reporting none, since every one of them was already closed by the build.

Components get the upstream repository purl, as in a firmware scan, for the projects BomLens can name from the build's records: by the recipe a package came from, or, for SPDX 2.2, by the recipe's source download address. See [Upstream repository purl](firmware.md#upstream-repository-purl) for which projects are covered.

## Limits

Two limits are worth knowing before you start.

SPDX 2.2 is read, but with less in it. Yocto 4.0 (Kirkstone) and 5.0 (Scarthgap) emit SPDX 2.2 by default, and that form is not a document at all: the deploy directory holds one `<image>.spdx.tar.zst` and nothing else. Inside it are the image document, a document per installed package and one per recipe. BomLens reads the archive itself. Measured against the published Yocto 5.0.14 `core-image-minimal`, it yields the same 36 packages the image manifest lists, with their licenses and CPEs. What they do not give is the build's CVE verdicts (only SPDX 3.0 records which CVEs a recipe patched), so with `--security` vulnerabilities are matched from the CPEs against the NVD CPE index in the image (a CPE with vendor `*` by product name across every vendor, so a product name another project shares can bring that project's CVEs), and a CVE the build already patched can appear as open. Pull the image document out of the archive and upload it alone and you get an almost empty result, which is said rather than left to look like a clean scan. When a build directory holds both formats, the SPDX 3.0 document is the one analyzed even if the 2.2 one is newer. An archive passed to `--analyze` gets no conformance check report: it is a bundle of documents rather than a submitted one, so there is nothing to measure against the submission criteria. Found in a build directory, the SBOM read from it is checked instead.

Conformance checks that depend on PURL will fail. Yocto identifies packages with CPE rather than PURL, so PURL coverage and the checks derived from it cannot pass. The report says how many components carry a CPE instead, and the row cites the baselines that accept either identifier (BSI TR-03183-2 and the US SBOM minimum elements). The verdict is the submission criteria's, not theirs: PURL is required here because the default vulnerability matching keys on it.

Two more required checks behave differently on a Yocto image, for reasons in the document rather than in the tool. The top-level component fails for want of a version: bitbake writes the image package with a name and no `software_packageVersion` (measured on the reference `core-image-minimal`). Scanned from a build directory, the image takes `--version` instead.

Uploads are capped at 100 MB. For scale, the reference `core-image-minimal` document is 15.8 MB with 35 installed packages. A build directory scanned with `--target` reads the file from disk, so the cap does not apply there.
