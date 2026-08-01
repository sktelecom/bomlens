# Third-Party Licenses

> **한국어**: [THIRD_PARTY_LICENSES.ko.md](THIRD_PARTY_LICENSES.ko.md)

BomLens (Apache-2.0) keeps its own code in shell scripts and bundles several open-source tools into its Docker images to generate and analyze SBOMs. This document is the license inventory for the bundled tools and the distribution obligations that come with them.

## Compliance summary

- The BomLens shell scripts invoke the bundled tools as separate processes (exec) and do not modify their sources. The copyleft of GPL and AGPL tools therefore does not propagate to the Apache-2.0 code of BomLens (per the FSF reading: pipes, CLI calls, and exec make separate programs; bundling in a container is mere aggregation).
- The tool binaries are still redistributed inside the images, so the license texts and, for GPL tools, a path to the corresponding source are provided. The SPDX license texts (Apache-2.0, MIT, GPL-2.0, GPL-3.0, and others) ship inside the images at `/usr/local/lib/sbom/licenses/`, and each tool's source is available from the Source URL in the tables below.
- BomLens ships its own terms with every distribution. In the images they are at `/usr/local/lib/sbom/notices/`, holding `LICENSE`, `NOTICE`, and this document; in the release bundles they sit at the top of the extracted tree; in the desktop installer they are in the app's resources folder. Passing those files along when you redistribute an image or a bundle is what Apache-2.0 §4 asks for.
- No AGPL-licensed tool is included. Running the web UI (`--ui`) therefore does not trigger the AGPL §13 network clause.
- The GPL-licensed analysis tools live only in a separate opt-in image (`bomlens-firmware`). The tools installed into the base image (`bomlens`) and into the other opt-in images (`bomlens-aibom`, `bomlens-deep-cve`) are permissive.
- Every image, the base one included, is built on `python:3.12-slim` and therefore also contains Debian system packages under the GPL, the LGPL and other licenses. That is inherent to any Linux base image; there is no GPL-free one. See [Debian packages in every image](#debian-packages-in-every-image) below for what this means and where the source is.

## Base image — `ghcr.io/sktelecom/bomlens` (BomLens tools; see also the Debian base below)

| Tool | Purpose | License (SPDX) | Source |
|------|---------|----------------|--------|
| cdxgen (official language images) | SBOM generation from source | Apache-2.0 | https://github.com/CycloneDX/cdxgen |
| syft | SBOM for images, binaries, and directories | Apache-2.0 | https://github.com/anchore/syft |
| Trivy | Vulnerability scanning | Apache-2.0 | https://github.com/aquasecurity/trivy |
| trivy-db | Vulnerability database | Apache-2.0 | https://github.com/aquasecurity/trivy-db |
| cosign | SBOM signing | Apache-2.0 | https://github.com/sigstore/cosign |
| scancode-toolkit | Detailed license detection. Build-time opt-in (`SBOM_DEEP_LICENSE=true`); **not present in the published images**, which are built with the default `false` | Apache-2.0 (parts of the dataset CC-BY-4.0 and others) | https://github.com/aboutcode-org/scancode-toolkit |
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
| ubi_reader | 0.8.14 (`UBI_READER_VERSION`) | UBI and UBIFS extraction | **GPL-3.0** | strong | https://github.com/onekey-sec/ubi_reader |
| sasquatch | `sasquatch-v4.5.1-6` (`SASQUATCH_VERSION`) | Reads vendor squashfs variants standard unsquashfs refuses | GPL-2.0 | strong | https://github.com/onekey-sec/sasquatch |
| jefferson | 0.4.7 (pip, pulled in by unblob) | JFFS2 extraction | MIT | permissive | https://github.com/onekey-sec/jefferson |

Debian packages installed on top, with the versions measured in the published image:

| Package | Version | Purpose | License (SPDX) |
|---------|---------|---------|----------------|
| squashfs-tools (unsquashfs) | 1:4.6.1-1 | Fallback for standard squashfs extraction | GPL-2.0+ |
| binutils | 2.44-3 | `readelf` for the ELF component identification pass | GPL-3.0+ |
| e2fsprogs | 1.47.2-3+b11 | ext filesystem extraction | GPL-2.0 |
| cpio | 2.15+dfsg-2 | Archive extraction | GPL-3.0+ |
| cabextract | 1.11-2 | Windows installer container extraction | GPL-2.0+ |
| lzop, lz4, liblzo2-2 | 1.04-2, 1.10.0-4, 2.10-3+b1 | Compression codecs invoked by the unpackers | GPL-2.0+ |
| p7zip / 7zip, unar | (apt distribution version) | 7z and vendor container formats | LGPL-2.1+ and others |

For all of these the corresponding source is the Debian source package; see [Debian packages in every image](#debian-packages-in-every-image).

The unpacking chain in `scan-firmware.sh` is unblob, then unsquashfs for a file
`file` reports as squashfs, then 7z for the container formats Windows deliveries
arrive in, then binwalk. A second pass opens filesystem images that were carved
out but not extracted, trying unsquashfs and then sasquatch.

### Fallback tools not installed in the image

- binwalk: the PyPI `binwalk` 2.x distribution is broken (`binwalk.core` is missing), so it is not installed in the image. `scan-firmware.sh` uses a working `binwalk` from the PATH as the last fallback, but standard squashfs is already handled a step earlier by unsquashfs.

### GPL source code for the firmware tools

Every GPL tool in the firmware image is fetched at a pinned version from a public repository or package registry. **The GPL license texts (GPL-2.0, GPL-3.0) are distributed inside the image at `/usr/local/lib/sbom/licenses/`.** Source code for exactly the version installed in the image is available from the Source URL in the table above, at the matching tag or release, and the firmware image carries the location of this document in the `com.sktelecom.sbom.gpl-source-offer` label.

Tools installed from Debian packages rather than from a pinned upstream release — squashfs-tools, e2fsprogs, p7zip, unar, cpio, cabextract and the rest — are covered by [Debian packages in every image](#debian-packages-in-every-image) below, because for a Debian binary the corresponding source is the Debian source package, not the upstream tag.

## deep-cve image — `ghcr.io/sktelecom/bomlens-deep-cve` (permissive, opt-in)

This is a separate opt-in image for `--deep-cve`. It uses the CPE matcher in grype to find NVD-only Maven CVEs that Trivy misses. The vulnerability database is large (about 1.8 GB), so it is kept out of the base image and pulled when needed.
Build: `docker build --build-arg SBOM_DEEP_CVE=true -t bomlens-deep-cve ./docker`.

The version below matches the build ARG default in `docker/Dockerfile` (pinned; overridable through the ARG).

| Tool | Pinned version (ARG) | Purpose | License (SPDX) | Copyleft | Source |
|------|----------------------|---------|----------------|----------|--------|
| grype | v0.112.0 (`GRYPE_VERSION`) | CPE-based NVD CVE matching | Apache-2.0 | permissive | https://github.com/anchore/grype |

Data: the grype vulnerability database baked into the image at build time is assembled by Anchore from public vulnerability sources — NVD (public domain), GitHub Security Advisories (CC-BY-4.0), and distribution security databases (each under its own terms). The database is pinned with `GRYPE_DB_AUTO_UPDATE=false`, so no network access happens during a scan.

## Android SDK images — `ghcr.io/sktelecom/bomlens-android-sdk<API>`

cdxgen publishes no Android-SDK-bearing image and marks Android as having no transitive support, so an Android project cannot be delegated to it. These images add an Android SDK platform on top of cdxgen's java image, one image per `compileSdk` (API 30 through 35). `scan-sbom.sh` detects the project's `compileSdk` and pulls the matching tag; `ANDROID_IMAGE_PREFIX` overrides where it comes from. The legacy `sbom-scanner-android-sdk<API>` name points at the same digest.

They hold no BomLens code, so they are not covered by our Apache-2.0 grant. What they contain:

| Component | Source | Terms |
|-----------|--------|-------|
| cdxgen java image (`cdxgen-temurin-java21`, digest-pinned) | https://github.com/CycloneDX/cdxgen | Apache-2.0 |
| Android SDK command-line tools, platform-tools, `platforms;android-<API>`, `build-tools;<API>.0.0` | Installed by `sdkmanager` from https://dl.google.com/android/repository/ | Android Software Development Kit License Agreement, https://developer.android.com/studio/terms |

The Android SDK is not open source and is not under Apache-2.0. Its terms grant a non-sublicensable licence to use the SDK to develop Android applications (§3.1) and restrict copying and redistribution of the SDK or any part of it, except where a third-party licence requires otherwise (§3.4). Anyone pulling these images is bound by those terms directly, and using the images is not a substitute for accepting them.

Each SDK component carries its own `NOTICE.txt` inside the image (under `/opt/android-sdk/`), which is where the third-party notices for the SDK's own contents live. The `/opt/android-sdk/licenses/` files are acceptance markers written by `sdkmanager`, not licence texts.

## Desktop installer — Electron and Chromium

The desktop installer (`BomLens-Setup.exe`, `BomLens-Setup.dmg`) packages the app with an Electron runtime, so it redistributes Electron and the Chromium build inside it.

| Component | License (SPDX) | Notice file |
|-----------|----------------|-------------|
| Electron | MIT | `LICENSE.electron` |
| Chromium and its bundled third-party code | BSD-3-Clause and many others | `LICENSES.chromium.html` |

Chromium's third-party set includes LGPL-2.1-or-later components, FFmpeg among them. Electron ships FFmpeg as a separate shared library (`libffmpeg.dll` on Windows, `libffmpeg.dylib` on macOS) rather than statically linked, which is what the LGPL's relinking clause asks for.

BomLens's own terms travel with the installer as well: `LICENSE`, `NOTICE` and this document are placed in the app's resources folder (`electron/electron-builder.yml`).

## Debian packages in every image

Every BomLens image is built on `python:3.12-slim`, a Debian-based image. Alongside the tools listed above it therefore contains Debian system packages, and most of them are copyleft: of the 128 packages in the base image, more than a hundred carry GPL or LGPL terms. bash, coreutils, grep, sed, gzip, findutils, wget and tar are GPL-3.0-or-later; git and mawk are GPL-2.0; the GNU C library is LGPL-2.1-or-later. No GPL-free Linux base image exists — Alpine ships BusyBox under GPL-2.0, and every glibc-based image ships LGPL — so this is a property of container images generally rather than a choice made here.

BomLens applies no patches to any of these packages. It installs them with `apt-get` and invokes them as separate processes, so the corresponding source is the unmodified Debian source package.

To list every package and its exact version in an image you hold:

```bash
docker run --rm --entrypoint dpkg-query ghcr.io/sktelecom/bomlens:latest \
  -W -f='${Package} ${Version} ${Architecture}\n'
```

Each package's license and copyright statement is preserved inside the image at `/usr/share/doc/<package>/copyright`.

### Source for the Debian packages

Corresponding source for any version listed is available from Debian's source archive:

```
https://snapshot.debian.org/
```

Use `snapshot.debian.org` rather than `deb.debian.org`: it is addressable by exact version and keeps historical versions, so these directions stay valid for images built at any date. Equivalently, from inside the image:

```bash
apt-get source <package>=<version>
```

### Written offer (GPL-2.0 components)

For any component in these images licensed under version 2 of the GNU General Public License, SK Telecom Co., Ltd. offers, valid for three years from the date you obtained the image, to give any third party a complete machine-readable copy of the corresponding source code, for a charge no more than the cost of physically performing the distribution. Request it by opening an issue at https://github.com/sktelecom/bomlens/issues.

---

*This document is a general compliance summary, not legal advice. The licenses of record are the LICENSE files in each upstream project.*
