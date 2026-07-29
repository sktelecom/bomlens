# Third-Party Licenses

> **한국어**: [THIRD_PARTY_LICENSES.ko.md](THIRD_PARTY_LICENSES.ko.md)

BomLens (Apache-2.0) keeps its own code in shell scripts and bundles several open-source tools into its Docker images to generate and analyze SBOMs. This document is the license inventory for the bundled tools and the distribution obligations that come with them.

## Compliance summary

- The BomLens shell scripts invoke the bundled tools as separate processes (exec) and do not modify their sources. The copyleft of GPL and AGPL tools therefore does not propagate to the Apache-2.0 code of BomLens (per the FSF reading: pipes, CLI calls, and exec make separate programs; bundling in a container is mere aggregation).
- The tool binaries are still redistributed inside the images, so the license texts and, for GPL tools, a path to the corresponding source are provided. The SPDX license texts (Apache-2.0, MIT, GPL-2.0, GPL-3.0, and others) ship inside the images at `/usr/local/lib/sbom/licenses/`, and each tool's source is available from the Source URL in the tables below.
- BomLens ships its own terms with every distribution. In the images they are at `/usr/local/lib/sbom/notices/`, holding `LICENSE`, `NOTICE`, and this document; in the release bundles they sit at the top of the extracted tree; in the desktop installer they are in the app's resources folder. Passing those files along when you redistribute an image or a bundle is what Apache-2.0 §4 asks for.
- No AGPL-licensed tool is included. Running the web UI (`--ui`) therefore does not trigger the AGPL §13 network clause.
- GPL tools live only in a separate opt-in image (`bomlens-firmware`); the base image (`bomlens`) stays permissive-only. The other opt-in images (`bomlens-aibom`, `bomlens-deep-cve`) carry permissive tools only.

## Base image — `ghcr.io/sktelecom/bomlens` (permissive-only)

| Tool | Purpose | License (SPDX) | Source |
|------|---------|----------------|--------|
| cdxgen (official language images) | SBOM generation from source | Apache-2.0 | https://github.com/CycloneDX/cdxgen |
| syft | SBOM for images, binaries, and directories | Apache-2.0 | https://github.com/anchore/syft |
| Trivy | Vulnerability scanning | Apache-2.0 | https://github.com/aquasecurity/trivy |
| trivy-db | Vulnerability database | Apache-2.0 | https://github.com/aquasecurity/trivy-db |
| cosign | SBOM signing | Apache-2.0 | https://github.com/sigstore/cosign |
| scancode-toolkit | Detailed license detection (opt-in) | Apache-2.0 (parts of the dataset CC-BY-4.0 and others) | https://github.com/aboutcode-org/scancode-toolkit |
| scanoss (scanoss.py) | Vendored open-source identification (bundled by default; disable with `SBOM_SCANOSS=false`) | MIT (the bundled `osadl-copyleft.json` dataset is CC-BY-4.0) | https://github.com/scanoss/scanoss.py |
| owasp-aibom-generator | AI model SBOM generation (opt-in `SBOM_AIBOM`, separate image `bomlens-aibom`; calls the HuggingFace API) | Apache-2.0 | https://github.com/GenAI-Security-Project/aibom-generator |
| jq | SBOM post-processing helper | MIT (some components BSD, ICU, or Lucent) | https://github.com/jqlang/jq |

Data: NVD, the vulnerability source, is public domain and requires attribution to "NIST/NVD".

### Web UI npm packages

The web UI (`--ui`) is a React single-page application. npm package code is compiled into the build output, and that output is redistributed inside the base image and the desktop installer, so the copyright and permission notices MIT and ISC ask for have to travel with it.

The authoritative record is `third-party-licenses.txt`, generated at build time. It lists only the packages that actually reach the bundle and reproduces each one's license text in full. Open it at `/third-party-licenses.txt` in the web UI; inside the image it is at `/usr/local/lib/sbom-web/dist/third-party-licenses.txt`. It comes from the bundled module graph rather than the `package.json` declaration because the two differ: declared dependencies used only at build time (tailwindcss, typescript) never reach the distribution, and a package can be declared and installed yet dropped from the bundle because nothing imports it.

The 23 packages currently in the bundle are below. All are permissive; none is copyleft.

| Package | Purpose | License (SPDX) |
|---------|---------|----------------|
| react, react-dom, scheduler | UI rendering | MIT |
| @radix-ui/react-label, react-progress, react-slot, react-primitive, react-context, react-compose-refs | Accessible primitives | MIT |
| cytoscape, cytoscape-dagre, dagre, graphlib, lodash | Dependency graph rendering and layout | MIT |
| i18next, react-i18next, i18next-browser-languagedetector | English and Korean switching | MIT |
| class-variance-authority | Component variant definitions | Apache-2.0 |
| clsx, tailwind-merge | Class name composition | MIT |
| lucide-react | Icons | ISC |
| @fontsource/inter, @fontsource/jetbrains-mono | Fonts (see the section below) | OFL-1.1 |

`npm run notices:check` keeps the list from going stale by checking the generated file. CI fails when a bundled package declares no license, when no license text was found to reproduce, or when any copyleft license appears.

### Web UI components (adapted from shadcn/ui)

shadcn/ui is not a library you install; its component code is copied into the project. So it never appears in the npm dependency list even though the code is in this repository. The following seven files under `docker/web/frontend/src/components/ui/` are shadcn/ui components adapted to our design tokens and accessibility requirements.

| Files | Origin |
|-------|--------|
| `badge.tsx`, `button.tsx`, `card.tsx`, `input.tsx`, `label.tsx`, `progress.tsx`, `tabs.tsx` | shadcn/ui (MIT, Copyright (c) 2023 shadcn), https://github.com/shadcn-ui/ui |

Those seven carry the upstream MIT notice alongside our own copyright line, and each is tagged `SPDX-License-Identifier: Apache-2.0 AND MIT`. The MIT text ships inside the images at `/usr/local/lib/sbom/licenses/MIT.txt`.

`barlist.tsx`, `select.tsx`, `state.tsx`, and `switch.tsx` in the same directory were written here and are Apache-2.0 only. `switch.tsx` follows shadcn/ui's visual proportions (track and thumb sizes) but is implemented separately as a native checkbox.

### Web UI fonts

The web UI (`--ui`) bundles two typefaces through `@fontsource` for consistent typography and for offline and desktop (Electron) operation. The font files (woff2) are compiled into the web SPA at build time and ship with the base image; no external font CDN is called.

| Font | Purpose | License (SPDX) | Source |
|------|---------|----------------|--------|
| Inter | Body and UI typeface | OFL-1.1 | https://github.com/rsms/inter |
| JetBrains Mono | Code and monospace typeface | OFL-1.1 | https://github.com/JetBrains/JetBrainsMono |

The SIL Open Font License 1.1 requires attribution, and both fonts are bundled unmodified:

- Inter: Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)
- JetBrains Mono: Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)

The full OFL-1.1 text is available as `OFL.txt` in each repository listed under Source.

### Vendored open-source identification and the OSSKB API (opt-in)

`--identify-vendored` bundles only the `scanoss.py` client (MIT). The client is part of the default build; to leave it out, build with `docker build --build-arg SBOM_SCANOSS=false`. The SCANOSS Engine (GPL-2.0) that performs the matching is **not** included — the hosted OSSKB API (`api.osskb.org`) is called instead. That is why, unlike the GPL tools in the firmware image, this can sit in the base image (MIT). The bundled `osadl-copyleft.json` dataset is CC-BY-4.0 data rather than code and requires attribution only.

Using the OSSKB API (operated by the Software Transparency Foundation) comes with these terms:

- What leaves the machine is **file fingerprints (hashes)**, not source code.
- The returned data may be used **for software identification only**; redistributing OSSKB data or caching it into a separate database is **prohibited**. BomLens emits results only as SBOM components for that one scan, which stays within this scope.
- The service is free and best-effort, and it is **rate-limited**. The exact limits are not published and are discretionary under the terms ("STF may limit the number or frequency of transactions per user through the OSSKB"). A scan looks up a fingerprint per file, so repeatedly scanning a large source tree will be throttled — this is meant for one-off identification. For bulk, repeated, or organization-wide use, and for air-gapped environments, point `SCANOSS_API_URL` and `SCANOSS_API_KEY` at the commercial SCANOSS service or a self-hosted endpoint.
- Results are provided as identification hints that need human review; accuracy is not warranted.
- Terms: https://www.softwaretransparency.org/terms

## Firmware image — `ghcr.io/sktelecom/bomlens-firmware` (contains GPL, opt-in)

This is a separate opt-in image that isolates the heavy unpacking and binary-analysis tools together with their GPL components.
Build: `docker build --build-arg SBOM_FIRMWARE=true -t bomlens-firmware ./docker`.
The design is described in [docs/maintainers/firmware-analysis.md](docs/maintainers/firmware-analysis.md).

The versions below match the build ARG defaults in `docker/Dockerfile` (pinned for supply-chain hygiene; overridable through the ARG).

| Tool | Pinned version (ARG) | Purpose | License (SPDX) | Copyleft | Source |
|------|----------------------|---------|----------------|----------|--------|
| unblob | 26.3.30 (`UNBLOB_VERSION`) | Primary firmware unpacker | MIT | permissive | https://github.com/onekey-sec/unblob |
| cve-bin-tool | 3.4 (`CVE_BIN_TOOL_VERSION`) | Identifies stripped binaries and their CVEs | **GPL-3.0** | strong | https://github.com/intel/cve-bin-tool |
| ubi_reader | 0.8.13 (`UBI_READER_VERSION`) | UBI and UBIFS extraction | **GPL-3.0** | strong | https://github.com/onekey-sec/ubi_reader |
| squashfs-tools (unsquashfs) | (apt distribution version) | Fallback for standard squashfs extraction | GPL-2.0+ | strong | https://github.com/plougher/squashfs-tools |
| e2fsprogs, p7zip, unar, cpio, cabextract, jefferson, and others | (apt distribution version) | Extraction binaries invoked by unblob | GPL-2.0+ and others | strong or various | Debian packages |

### Fallback and optional tools (not installed by default)

- BANG (GPL-3.0, https://github.com/armijnhemel/binaryanalysis-ng): `scan-firmware.sh` uses it as an unpacking fallback when `bang-scanner` is on the PATH. Its dependencies are heavy, so it is not part of the image; install it separately and it is picked up automatically. The unpacking fallback order is unblob, BANG, unsquashfs (squashfs), then binwalk.
- binwalk: the PyPI `binwalk` 2.x distribution is broken (`binwalk.core` is missing), so it is not installed in the image. `scan-firmware.sh` uses a working `binwalk` from the PATH as the last fallback, but standard squashfs is already handled a step earlier by unsquashfs.
- sasquatch (GPL-2.0, https://github.com/onekey-sec/sasquatch): used by an unblob handler for vendor-modified, non-standard squashfs. Standard squashfs is covered by the `squashfs-tools` (unsquashfs) fallback, so it is not part of the image.

### GPL source code offer (firmware image)

Every GPL tool in the firmware image is fetched at a pinned version from a public repository or package registry. **The GPL license texts (GPL-2.0, GPL-3.0) are distributed inside the image at `/usr/local/lib/sbom/licenses/`.** Source code for exactly the version installed in the image is available from the Source URL in the table above, at the matching tag or release, and the firmware image carries the location of this document in the `com.sktelecom.sbom.gpl-source-offer` label. If you need source beyond that, request it through a repository issue.

## deep-cve image — `ghcr.io/sktelecom/bomlens-deep-cve` (permissive, opt-in)

This is a separate opt-in image for `--deep-cve`. It uses the CPE matcher in grype to find NVD-only Maven CVEs that Trivy misses. The vulnerability database is large (about 1.8 GB), so it is kept out of the base image and pulled when needed.
Build: `docker build --build-arg SBOM_DEEP_CVE=true -t bomlens-deep-cve ./docker`.

The version below matches the build ARG default in `docker/Dockerfile` (pinned; overridable through the ARG).

| Tool | Pinned version (ARG) | Purpose | License (SPDX) | Copyleft | Source |
|------|----------------------|---------|----------------|----------|--------|
| grype | v0.112.0 (`GRYPE_VERSION`) | CPE-based NVD CVE matching | Apache-2.0 | permissive | https://github.com/anchore/grype |

Data: the grype vulnerability database baked into the image at build time is assembled by Anchore from public vulnerability sources — NVD (public domain), GitHub Security Advisories (CC-BY-4.0), and distribution security databases (each under its own terms). The database is pinned with `GRYPE_DB_AUTO_UPDATE=false`, so no network access happens during a scan.

---

*This document is a general compliance summary, not legal advice. The licenses of record are the LICENSE files in each upstream project.*
