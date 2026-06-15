---
description: Unpack network-device firmware binaries (.bin, squashfs, and more) to identify components and check the SBOM, licenses, and vulnerabilities with BomLens firmware analysis.
---

# Firmware analysis guide

How to identify components and check the SBOM, licenses, and vulnerabilities in a network-device firmware binary (`.bin`, `.img`, squashfs, and so on) submitted by a supplier.

For the tool selection rationale and the internal design, see the maintainer doc [Firmware analysis](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/firmware-analysis.md) (Korean).

## How it works

Firmware is a single file that packs and seals an operating system and dozens of libraries. Feeding a firmware file straight into a normal scan detects almost nothing and yields an empty SBOM. Firmware analysis first unpacks the contents, then identifies components.

1. Unpack the firmware (unblob, with BANG as a fallback) to extract the rootfs.
2. Use `syft` to identify components installed by a package manager (opkg, dpkg, apk, rpm).
3. Use `cve-bin-tool` to find the versions and vulnerabilities of stripped static binaries (busybox, openssl, dropbear, and so on).
4. Merge the two results into one SBOM, then run the same post-processing as a normal scan (licenses, CVEs, signing).

## Preparing the firmware image

Firmware analysis needs a separate image that bundles the unpacking and binary-identification tools (unblob, cve-bin-tool, and so on). These are GPL-family tools, so they are kept out of the lightweight base image and split into an opt-in firmware image.

```bash
docker pull ghcr.io/sktelecom/bomlens-firmware:latest
```

This image is the default, so adding `--firmware` pulls it without any extra setting. To use a different tag, set the environment variable `SBOM_FIRMWARE_IMAGE`.

## Running it

Pass the firmware file you received to `--target` and add `--firmware`.

```bash
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh

$SBOM --project device-fw --version 1.0.0 \
  --target "./device.bin" --firmware \
  --all --generate-only
```

- Recognized extensions (`.bin`, `.img`, `.squashfs`, `.ubi`, `.ubifs`, `.trx`, `.chk`, `.fw`, `.rom`) are auto-detected even without `--firmware`, but being explicit is recommended.
- The outputs are the same three as a normal scan: the notice (`_NOTICE`), the SBOM (`_bom.json`), and the risk report (`_risk-report`).

> **Web UI**: the firmware upload tab is enabled only when the UI runs from the firmware image.
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-firmware:latest $SBOM --ui`

## License note

The firmware image contains GPL tools (cve-bin-tool, BANG, and some extractors that unblob depends on). The shell scripts only invoke them as separate processes, so copyleft does not propagate into our code, but redistributing GPL binaries in an image carries the obligation to include the license texts and offer the source. For the full inventory, see [Bundled tool licenses](https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md). The GPL tools live only in this firmware image; the base image stays permissive-only.

## Limits

- The open-source tool stack detects roughly 60–85%, and the result depends heavily on the firmware type, how aggressively it is stripped, and whether unpacking succeeds.
- Without function-level binary fingerprinting, unlike commercial tools, stripped or inlined components and binaries with version strings removed are missed.
- Statically linked libraries, vendor-modified squashfs, encrypted or signed firmware, and renamed libraries are not detected or are inaccurate.
- The resulting SBOM is a best-effort estimate, so do not use it as the sole basis for legal license compliance.

---

> **Related**: [Getting started](../start/first-scan.md) | [Scenarios guide](../guides/by-input.md) | [Usage guide](../reference/cli.md) | [Notice and security guide](../guides/reports.md)
