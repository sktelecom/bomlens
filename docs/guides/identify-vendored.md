---
description: Identify open source copied (vendored) into C/C++ embedded source that has no package manager, so a normal BomLens scan that finds almost nothing turns into a real component list with versions and CVEs.
---

# Identify bundled open source (C/C++)

Use this when you scan a C/C++ embedded source tree and BomLens finds almost nothing.

## When you need it

A normal scan reads a package manager (npm, Maven, pip, Go, Conan, and so on) to learn what open source a project uses. C/C++ embedded firmware usually has no package manager: the open source is copied straight into the source tree (this is called *vendored* source — for example a copy of openssl, zlib, or liblfds under `third_party/`). cdxgen cannot name those files, so the SBOM comes back almost empty, with each file listed as an unidentified `pkg:generic` entry.

When that happens, BomLens prints a one-line hint suggesting this option, and the web UI shows the same hint after the scan. You do not need to recognize the situation yourself.

`--identify-vendored` matches the file fingerprints of your sources against the public OSSKB knowledge base and records each match as a real component (name, version, PURL), so the copied-in open source shows up in the SBOM — and, where the library has known CVEs, in the security report.

## What is sent

Only file **fingerprints** (hashes) are sent to the OSSKB service. Your source code never leaves the machine. The supplier can run this in their own environment before any contract.

## On a package-managed project

This option is for source with no package manager. If your project uses npm, Maven, pip, Go, and so on, the normal scan already resolves your dependencies and you do not need it. If you turn it on anyway, BomLens reconciles the results: dependency and build directories (`node_modules`, `vendor`, `dist`, and the like) are skipped, and any match whose name a package-manager component already carries is dropped in favor of that authoritative identity. So enabling it on a managed project does not duplicate known dependencies or inflate the vulnerability count — at most it adds genuinely copied-in source the package manager could not see.

Matches are recorded read-only, tagged with their source and confidence. BomLens does not provide an accept/reject audit workflow; if you need to confirm or triage matches, upload the SBOM to TRUSCA and do it there.

## Prerequisites

Build (or pull) an image that includes the SCANOSS client:

```bash
docker build --build-arg SBOM_SCANOSS=true -t bomlens ./docker
```

## Run it

```bash
scan-sbom.sh --project trelay --version 26.4.0 --target ./src \
  --identify-vendored --all --generate-only
```

In the web UI, open **Advanced** and turn on **Identify bundled open source**. The option appears only for a source scan when the image supports it.

## What you get

- Copied-in open source appears in the SBOM as named components with versions, each tagged `vendored` (a `bomlens:layer=vendored` property).
- Components that map to a known product get a CPE, so the Trivy security report lists their CVEs. For example a vendored `openssl 1.1.1w` shows up with its advisories.
- Niche libraries with no entry in the vulnerability databases (for example `liblfds`, `libaes`, `djbdns`) are still identified by name and version; they simply have no CVEs to report, which is a limit of the public data, not of the scan.

Only full-file matches become components. Partial (snippet) matches are noisy and are left out, so the report stays clean.

## Endpoint and limits

The default endpoint is the free OSSKB API, which is rate-limited and intended for identification only. For high-volume or air-gapped use, point at a SCANOSS commercial or self-hosted endpoint:

```bash
SCANOSS_API_URL=https://your-scanoss-endpoint \
SCANOSS_API_KEY=your-key \
scan-sbom.sh --project trelay --version 26.4.0 --target ./src --identify-vendored --all --generate-only
```

Version precision is approximate. A file match reports the release where that file content first appeared, so different files of the same library can resolve to slightly different versions and a copied-in library may be reported a point release off. Treat the version (and any CVEs derived from it) as a starting point for review, not a final verdict.

Results are a best-effort estimate that benefits from human review. See the OSSKB terms and license notes in [THIRD_PARTY_LICENSES.md](https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md).
