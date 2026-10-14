---
description: Unpack network-device firmware binaries (.bin, squashfs, and more) to identify components and check the SBOM, licenses, and vulnerabilities with BomLens firmware analysis.
---

# Firmware analysis guide

How to identify components and check the SBOM, licenses, and vulnerabilities in a network-device firmware binary (`.bin`, `.img`, squashfs, and so on). Use it when you only have the binary and no source, such as firmware received from a supplier.

## How it works

Firmware is a single file that packs and seals an operating system and dozens of libraries. Feeding a firmware file straight into a normal scan detects almost nothing and yields an empty SBOM. Firmware analysis first unpacks the contents, then identifies components.

1. Unpack the firmware (unblob, falling back to `unsquashfs`, `7z`, then `binwalk`) to extract the rootfs.
2. Use `syft` to identify components installed by a package manager (opkg, dpkg, apk, rpm).
   An image can carry more than one filesystem, and a tree sitting beside the rootfs rather
   than inside it is cataloged too. Three kinds are recognized, each by the record of what is
   installed in it rather than by its directory name: a container image store, identified by
   the image index Docker keeps (the usual layout on a switch OS, where most of what runs is in
   a container); a second filesystem carrying its own package database; and an interpreter's
   installed library set, such as a Python `site-packages`. Set `FW_EXTRA_ROOTS=false` to read
   only the rootfs. Components from a container store record the image they belong to in
   `bomlens:container:image`, and the images themselves appear as `container`
   components. A package installed by `dpkg` inside a container is identified by the
   distribution the container runs, read from the `os-release` in its own layers, so that
   the vulnerability step has something to match it against; those carry
   `bomlens:purlSource`. An SPDX export keeps this: the images and the
   distribution are packages there, and the membership is a `CONTAINS`
   relationship.
3. Use the signature checkers of `cve-bin-tool` to identify stripped static binaries (busybox, openssl, dropbear, and so on) and give them a CPE.
4. Merge the two results into one SBOM, then run the same post-processing as a normal scan (licenses, CVEs, signing). CVEs of components with no package PURL come from the NVD CPE index in the image (see [How CVEs are matched](#how-cves-are-matched)).

## Preparing the firmware image

Firmware analysis needs a separate image that bundles the unpacking and binary-identification tools (unblob, cve-bin-tool, and so on). These are GPL-family tools, so they are kept out of the lightweight base image and split into an opt-in firmware image.

```bash
docker pull ghcr.io/sktelecom/bomlens-firmware:latest
```

This image is the default, so adding `--firmware` pulls it without any extra setting. To use a different tag, set the environment variable `SBOM_FIRMWARE_IMAGE`.

In the web UI and the desktop app you do not have to run that command: the firmware input offers a Download now button with the download size, and shows how many layers are done while it runs. Without it the image is still pulled on the first firmware scan, so the only difference is whether the wait happens before the scan or inside it.

## Running it

Firmware analysis needs the firmware image (above), whether you use the web UI or the CLI.

### From the web UI

Launch the web UI as usual — you do not need to point it at this image yourself. As long as the Docker engine is running, the base UI image launches this firmware image as a sibling container over the Docker socket, and the firmware upload tile appears automatically.

```bash
./scripts/scan-sbom.sh --ui
#   Windows: just double-click sbom-ui.bat
```

Set `SBOM_FIRMWARE_IMAGE` only if you want a different tag or an internal mirror registry. It takes effect only as a real environment variable — the settings file `bomlens.settings.txt` that a double-clicked `.bat` reads does not support this key.

```bash
SBOM_FIRMWARE_IMAGE=<your-mirror>:<tag> ./scripts/scan-sbom.sh --ui
```

Enter a project name and version, choose the firmware upload tile, upload the file, and run.

### From the CLI

Pass the firmware file you received to `--target` and add `--firmware`:

```bash
./scripts/scan-sbom.sh --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --all --generate-only
```

- Recognized extensions (`.bin`, `.img`, `.squashfs`, `.sqsh`, `.ubi`, `.ubifs`, `.trx`, `.chk`, `.fw`, `.rom`, `.dlf`, `.bix`) are auto-detected even without `--firmware`, but being explicit is recommended.
- The outputs are the same three as a normal scan: the notice (`_NOTICE`), the SBOM (`_bom.json`), and the risk report (`_risk-report`).
- A release folder can be passed as it is. When `--target` is a folder with no manifest or build file at its top level that directly holds one firmware image or one extracted root filesystem (for example `images/` with `rootfs/`, `install/`, a kernel and an image file), that image or root filesystem is scanned and the scan prints which one. A file counts as a firmware image by its firmware or filesystem signature, or by an extension used for firmware (`.bix`, `.trx`, `.chk`, `.dlf`, `.ubi`, `.ubifs`, `.squashfs`, `.sqsh`, `.rom`, `.fw`, `.jffs2`, `.cramfs`); a `.bin` or `.img` needs the signature. A folder with executables, shared libraries, `.asar`, `node_modules`, model weights or tokenizer files at its top level, or with more than 20 top-level files, is scanned as source, so an unpacked desktop app, a model snapshot or a build output staging folder keeps its source scan. When there are several, the scan stops and lists the `--target` for each. When the root filesystem it picked has no package database, the warning also lists the larger files beside it (over 1 MiB, at most five) as `--target "<file>" --firmware` commands to try. `--as-source` scans the folder itself as source instead.

## Reading the results

The output is the same NOTICE, SBOM and risk report as any other scan (see [What the reports mean](../concepts/reports-explained.md) and the [artifacts reference](../reference/artifacts.md) for the general shape), but a firmware SBOM has one thing worth knowing before you read it: some components carry no version at all. When a binary's version string did not survive the build, BomLens still records that the library is linked in — read from the ELF's SONAME and NEEDED entries, structure rather than a string match — and tags that component `bomlens:evidenceGrade = presence-only`. A missing version there is not a gap in the scan; it means the binary itself carries no version to read, and the component is real regardless. For a license obligation this is enough (the library is present whether or not anything says which release), but it means version-based CVE matching has nothing to key on for that component.

The unpacker also reports how much of the image it could open, and BomLens records that beside the result. The totals go on the firmware component as `bomlens:firmware:*` properties (`input-bytes`, `recognized-regions`, `unknown-regions`, `unknown-bytes`, `unknown-top-level-percent`, `nested-unknown-regions`, `encrypted-regions`, `extraction-failed`, `extraction-failed-formats`, `missing-extractors`), and the risk report adds a "Firmware analysis scope" section when any part of the image went unopened. Read it as the scope of the scan: components inside a region that was not recognized, was encrypted, or needed an extraction tool the scanner image does not include are not in the SBOM, so a clean vulnerability table describes only what could be opened. The unrecognized share and byte count are measured at the top level of the image; unrecognized regions inside extracted content are counted apart. The section is written only for a scan BomLens ran itself, not for an SBOM you submit for review. Only totals are kept; the unpacker's full report is not written to the output folder.

If the syft package-identification pass fails, the scan does not stop: syft's own error goes into the scan log, and the SBOM records which pass failed as `bomlens:pipeline-step-failed` (`firmware-packages` for the main rootfs; `firmware-extra-roots` for a secondary package source unpacking finds alongside it, such as a nested container image store or a filesystem with its own package database). A component count lower than expected is worth checking the scan log for this before assuming the firmware genuinely holds that few packages.

## Upstream repository purl

A component read out of a binary or a firmware package database has no purl, a `pkg:generic` one, or a `pkg:opkg` one. None of these names a project, so a tool that looks components up by purl cannot identify it even when the name and version are right. For firmware, root filesystem and binary scans, BomLens sets the purl of the project's upstream source repository at its release tag, for example `pkg:github/mirror/busybox@1_22_1`, `pkg:github/gregkh/linux@v3.10.18`, `pkg:sourceforge/boa@0.94.13` or `pkg:gnu/readline@5.2`.

The conversion uses a closed table (`docker/lib/upstream-purl-map.json`) of projects whose repository and tag spelling were checked: BusyBox, curl, OpenSSL 1.x, OpenSSH, Linux, zlib, U-Boot, Net-SNMP, ncurses, net-tools, libxml2, SQLite, glibc, Dropbear, Mbed TLS, Python, Boa and readline. A component is matched by its name or its CPE, and only when it has a version of a form the table covers; a package rebuild count such as `-1` and a kernel build hash are removed first, and a Linux or glibc base release written `5.4.0` takes the tag of `5.4`. A component not in the table keeps the identifier it had, since a guessed repository or tag would name a different version. When a scan reports a project both as the operating-system component and as a package or binary with the same purl, as syft does for BusyBox, only the package or binary gets the purl. The version, the CPE and the evidence are not changed, so the CVEs found from them stay in the report. The new purl is marked `bomlens:purlSource = upstream-map`, and a purl it replaced is kept in `bomlens:originalPurl`. Set `ENRICH_UPSTREAM_PURL=false` to turn it off.

## Supplying the versions the scan could not read

A component tagged `presence-only` has no version, so neither a CVE lookup nor a purl lookup can use it. Every firmware, root filesystem and binary scan lists those components on the console and writes them to `<Project>_<Version>_component-versions.template.csv`. Write the version shipped in the product after each name and pass the file back:

```bash
./scripts/scan-sbom.sh --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --component-versions device-fw_1.0.0_component-versions.template.csv --generate-only
```

The file is CSV with two columns, `name,version`; lines starting with `#` and rows left empty are skipped. The template can be filled in where it is: when the file passed is that template, the scan leaves it as you wrote it and only lists what is still missing. A filled version is marked `bomlens:versionSource = supplier-declared` and gets the upstream purl above. When the scan read a version from the delivered files, that version is kept and a warning shows both, because a source tree can hold several releases of one project and the binary shows which one shipped. A name the scan did not find is added as a component marked `bomlens:identifiedBy = supplier-declared`. A file over 256 KiB, a row that is not two fields, a name or version with characters outside letters, digits and `. _ + ~ -`, or one name given two versions is refused with the line number: the SBOM and the other files are written without the file's versions, and the scan exits 1. A component whose version reads `UNKNOWN` (a kernel module with no version in its metadata) counts as having none, so it is in the template. A component whose name holds other characters, such as a space, is listed on the console instead of in the template.

## How CVEs are matched

Trivy matches components by their package PURL, with a database it downloads at scan time as in any other scan. A component with no package PURL (none, `pkg:generic`, `pkg:opkg`, or a source repository PURL such as `pkg:github`) is matched by its CPE against the NVD CPE index built into the image (`cpe_match.sqlite`), and its CVEs go into the same security report. This match runs with `--security` in firmware, root filesystem and binary scans, once, after every step that adds CPEs. A component identified by name and version through BomLens's name list (`cpe-name-map.json`), OpenSSH or BusyBox for example, is matched as well as one the signature checkers gave a CPE. The result manifest records the step as `match-cpe` with `offered`, `components` and `cves` counts.

The index is distilled from the NVD data when the image is built, so the match needs no network and no NVD API key, and its data is as recent as the image. Pull a newer image to update it. cve-bin-tool only identifies binaries; it does not download or read a vulnerability database. `CVE_BIN_TOOL_MODE=components-only` turns the CPE match off while identification still runs. An image built with `--build-arg SBOM_CPE_INDEX=false` has no index, and the step is recorded as `skipped` (`not_installed`).

A component with no version, or with no package PURL and no CPE the index was asked about, is listed in the security report under "Components that could not be checked" (`UncheckedComponents` in `_security.json`). A short vulnerability table therefore covers only the components that were checked.

The scan prints "This product uses NVD data but is not endorsed or certified by the NVD.", and the image carries the data attribution in `/opt/cve-bin-tool-home/CVE-DATA-NOTICE.txt`. OSV (Open Source Vulnerabilities) advisories are not bundled, to keep share-alike data out of the redistributed image.

## License note

The firmware image contains GPL tools (cve-bin-tool, sasquatch, and some extractors that unblob depends on). The shell scripts only invoke them as separate processes, so copyleft does not propagate into our code, but redistributing GPL binaries in an image carries the obligation to include the license texts and offer the source. For the full inventory, see [Bundled tool licenses](https://github.com/sktelecom/bomlens/blob/main/THIRD_PARTY_LICENSES.md). The GPL analysis tools live only in this firmware image. Every image including the base one is Debian-based, though, so all of them also carry GPL system packages; source directions for those are in the same document.

## Limits

- The open-source tool stack detects roughly 60–85% of components, and the result depends heavily on the firmware type, how aggressively it is stripped, and whether unpacking succeeds.
- Without function-level binary fingerprinting, stripped or inlined components and binaries with version strings removed are missed.
- Statically linked libraries, vendor-modified squashfs, encrypted or signed firmware, and renamed libraries go undetected or are misidentified.
- The resulting SBOM is a best-effort estimate, so do not use it as the sole basis for legal license compliance.

---

> **Related**: [Getting started](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [CLI reference](../reference/cli.md) | [Notice and security guide](../guides/reports.md)
