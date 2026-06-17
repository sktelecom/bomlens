---
description: How a supplier builds an SBOM for a delivered server — scan the OS rootfs, the application, and the static-link dependencies as separate layers and submit them separately, merging into one BOM only when the submission system requires it.
---

# Server delivery guide

## Overview

A delivered server is not a single source tree. It is an operating system, the application installed on top of it, and libraries that were linked into the binaries during the build. A scan of any one of these misses the others, which is the usual reason a server SBOM is rejected.

This guide treats a server as two layers — the OS and the application — and scans each with BomLens. Submit the layer SBOMs separately — that is the default, and it keeps each reviewable on its own. Merge them into one product SBOM only when a submission system asks for a single file (see [Optional: merge into one SBOM](#optional-merge-into-one-sbom)).

| Layer | What it covers | Symptom if omitted |
|-------|----------------|--------------------|
| OS | The OS and its installed packages (e.g. CentOS plus everything in the rpm database) | OS vulnerabilities missing |
| Application | The delivered application and its package-manager dependencies, direct and transitive | Application dependencies missing |

Beyond the two layers, statically linked libraries (for example an openssl or liblfds built into the binary) are a blind spot. A package manager does not declare them and the OS package database does not list them, so neither layer's scan finds them. They have to be detected and recorded separately, and missing them is the most common rejection cause — see [Static-link libraries](#static-link-libraries-a-blind-spot-of-both-layers) below.

One tool, BomLens, produces both layers; only the input changes. The requirement is that the OS, the application, and the static-link libraries are all accounted for — not that they end up in one file.

## Common setup

> **Windows**: the commands here are for macOS/Linux. See [Getting started](../start/first-scan.md#installation) for the `scan-sbom.bat` and WSL2 equivalents.

```bash
# Docker 20.10+ required. Pull the scanner image once.
docker pull ghcr.io/sktelecom/bomlens:latest

# Keep the script path in a variable.
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh
```

## Layer 1 — OS packages

Scan the server's rootfs (the extracted root filesystem) or a container image of it. Syft reads the rpm/dpkg/apk database and records every installed package with a real purl (`pkg:rpm/...`).

```bash
# A rootfs directory:
$SBOM --project mms-relay-os --version 6.10 \
  --target /path/to/server-rootfs \
  --all --generate-only

# Or, if the server is packaged as a container image:
$SBOM --project mms-relay-os --version 6.10 \
  --target mms-relay:6.10 \
  --all --generate-only
```

The target must contain the package database. A folder holding only unpacked install files, with no rpm database, yields empty purls and is rejected. Use the real rootfs or image.

## Layer 2 — Application code and dependencies

Scan the application source after the build. With a package manager (Maven, npm, pip, Go modules, Conan, and others), transitive dependencies resolve automatically.

```bash
cd /path/to/app-source
$SBOM --project mms-relay-app --version 2.0.0 --all --generate-only
```

Build first. Scanning before the build or install leaves transitive dependencies unresolved. For a pure CMake/Make application with no manifest, the component list is sparse; add `--deep-license` to record the first-party source licenses.

## Static-link libraries (a blind spot of both layers)

Source scanners do not see libraries that were statically linked into a binary, and neither does the OS package database — this is the blind spot the two layers leave. There is no fully automatic path, so combine two approaches.

Analyze the delivered binary or firmware image to catch what tooling can find:

```bash
$SBOM --project mms-relay-bin --version 2.0.0 \
  --target /path/to/delivered-binary \
  --all --generate-only
```

For what the scan still misses, record the source and version by hand from the build script — for example the openssl release the build pulls in (`openssl 1.1.1za`). A precise inventory of statically linked components comes from binary composition analysis (BDBA); SKT runs that as a complementary check, so the supplier does not carry it alone.

## Verify each layer before submitting

Submit the per-layer SBOMs (and the static-link SBOM) as they are. Check each one — not a combined file — so a gap is caught where it belongs. Confirm it is well formed and that its components carry real purls.

```bash
for bom in mms-relay-os_6.10_bom.json mms-relay-app_2.0.0_bom.json mms-relay-bin_2.0.0_bom.json; do
  echo "$bom: $(jq '.components | length' "$bom") components, \
$(jq '[.components[] | select(.purl)] | length' "$bom") with purl"
done
```

The two counts should be close for each layer. A large gap means many components lack a purl, which usually points to a raw-directory scan or a hand-written entry. Then validate the schema with the [CycloneDX validator](https://github.com/CycloneDX/cyclonedx-cli).

Keeping the layers separate is the default for a reason: a reviewer sees at a glance which layer is missing or where a vulnerability sits, and each SBOM keeps its own dependency graph (`dependencies`).

## Optional: merge into one SBOM

Merge only when the submission or upload system expects a single product BOM (Dependency-Track and TRUSCA both register one BOM per project). `--merge` combines the layers, dedupes components by purl, and stamps the top-level component with the delivered product name and version.

```bash
$SBOM --project mms-relay-server --version 1.0.0 \
  --merge mms-relay-os_6.10_bom.json \
          mms-relay-app_2.0.0_bom.json \
          mms-relay-bin_2.0.0_bom.json \
  --generate-only
```

This writes `mms-relay-server_1.0.0_bom.json` with `metadata.component` set to the server product, plus the notice and risk report over the merged set. Each component keeps a `bomlens:layer` property, so you can still filter by layer (`jq '.components[] | select(.properties[]?.value == "centos")'`).

One trade-off: the merge drops the per-layer `dependencies` trees (their `bom-ref` namespaces collide). If the transitive-dependency graph matters for review, submit the layers separately instead.

## What gets a server SBOM rejected

- **Hand-written SBOMs.** A `tool: manual` SBOM almost always omits components. Always generate with a tool.
- **`pkg:generic` components.** Use the standard purl types (`pkg:rpm`, `pkg:maven`, and so on) so vulnerability matching works.
- **Raw-directory scans with no metadata.** Scanning a folder of unpacked install files, with no package database, leaves purls empty and the whole SBOM is rejected. Target a real rootfs or image.
- **Scanning before the build.** Building the SBOM from a pre-build source tree drops transitive dependencies.

## Using the web UI

The OS and application layers can also run from the web UI (`$SBOM --ui`). Put the rootfs under the folder where you launch the UI and use the **Directory path** input, or scan a container image with the **Docker image** input. Paths outside the launch folder are rejected for safety, so the static-link layer and the optional merge are most direct from the CLI.

---

> **Related**: [Input scenarios](by-input.md) | [Firmware analysis](firmware.md) | [Validating a received SBOM](supplier-sbom.md) | [CLI reference](../reference/cli.md)
