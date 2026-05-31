#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# scan-firmware.sh — unpack a firmware image and build a CycloneDX SBOM.
#
# Usage: scan-firmware.sh <firmware_file> <output_sbom.json> <version>
#   produces <output_sbom.json> (CycloneDX, components from package DB + binaries)
#
# Pipeline (see docs/firmware-analysis.md §5):
#   ① unpack   : unblob (preferred) -> BANG / binwalk (fallback)
#   ② packages : syft dir:<rootfs>            -> package-manager components
#   ③ binaries : cve-bin-tool --sbom-output   -> stripped static binaries (Phase 2)
#   ④ merge    : jq, dedupe by purl (fallback name@version)
#
# Tools live ONLY in the opt-in `sbom-scanner-firmware` image. Everything here is
# best-effort: a missing/failed stage degrades gracefully rather than aborting,
# so the common post-processing pipeline always receives a valid SBOM.
set -e

FW="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"

if [ -z "$FW" ] || [ ! -f "$FW" ]; then
    echo "[firmware] firmware file not found: $FW" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[firmware] output path is required (usage: scan-firmware.sh <firmware> <out.json> <version>)" >&2
    exit 1
fi

if ! command -v syft >/dev/null 2>&1; then
    echo "[firmware] ERROR: syft not installed in this image." >&2
    echo "[firmware]   Rebuild the firmware image: docker build --build-arg SBOM_FIRMWARE=true -t sbom-scanner-firmware ./docker" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
EXTRACT="$WORK/extract"
mkdir -p "$EXTRACT"

GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FILE_INFO="firmware image"
command -v file >/dev/null 2>&1 && FILE_INFO=$(file -b "$FW" 2>/dev/null || echo "firmware image")

# --------------------------------------------------------
# ① Unpack — unblob preferred; BANG, then format-specific extractors, as fallback.
# Each step is gated on whether real files actually landed (exit codes are
# unreliable: unblob returns 0 even when an extractor dependency is missing).
# --------------------------------------------------------
has_extracted() { [ -n "$(find "$EXTRACT" -type f -size +0c 2>/dev/null | head -1)" ]; }
unpacked=0

if command -v unblob >/dev/null 2>&1; then
    echo "[firmware] unpacking with unblob..."
    unblob --extract-dir "$EXTRACT" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
if [ "$unpacked" = 0 ] && command -v bang-scanner >/dev/null 2>&1; then
    echo "[firmware] unblob produced nothing; falling back to BANG..."
    bang-scanner -f "$FW" -u "$EXTRACT" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
# squashfs is the most common firmware filesystem; unsquashfs (squashfs-tools)
# handles standard images even when unblob's sasquatch handler is absent.
if [ "$unpacked" = 0 ] && command -v unsquashfs >/dev/null 2>&1 && printf '%s' "$FILE_INFO" | grep -qi squashfs; then
    echo "[firmware] falling back to unsquashfs..."
    unsquashfs -f -d "$EXTRACT/squashfs-root" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
if [ "$unpacked" = 0 ] && command -v binwalk >/dev/null 2>&1; then
    echo "[firmware] falling back to binwalk extraction..."
    binwalk --run-as=root --extract --directory "$EXTRACT" "$FW" >/dev/null 2>&1 \
        || binwalk --extract --directory "$EXTRACT" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi

if [ "$unpacked" = 0 ]; then
    echo "[firmware] WARN: no unpacker produced files (unblob/BANG/unsquashfs/binwalk)." >&2
    echo "[firmware]       Firmware may be encrypted/signed or in an unsupported format; emitting best-effort SBOM." >&2
fi

# --------------------------------------------------------
# ② Locate a rootfs candidate (parent of the first 'etc' dir; else extract root).
# --------------------------------------------------------
ROOTFS="$EXTRACT"
etc_dir=$(find "$EXTRACT" -type d -name etc 2>/dev/null | head -1)
if [ -n "$etc_dir" ]; then
    ROOTFS=$(dirname "$etc_dir")
    echo "[firmware] rootfs candidate: ${ROOTFS#"$EXTRACT"/} (relative to extract root)"
else
    echo "[firmware] no rootfs marker found; scanning whole extraction tree"
fi

# --------------------------------------------------------
# ③ Package components (syft) + binary components (cve-bin-tool).
# --------------------------------------------------------
PKG_SBOM="$WORK/pkg.cdx.json"
echo "[firmware] syft: cataloging packages under rootfs..."
if ! syft "dir:$ROOTFS" -o cyclonedx-json > "$PKG_SBOM" 2>/dev/null; then
    echo "[firmware] WARN: syft directory scan failed; continuing without package components." >&2
    echo '{"components":[]}' > "$PKG_SBOM"
fi

BIN_SBOM="$WORK/bin.cdx.json"
if command -v cve-bin-tool >/dev/null 2>&1; then
    echo "[firmware] cve-bin-tool: scanning binaries for known components..."
    # cve-bin-tool exits non-zero when it finds CVEs; ignore the exit code and
    # validate the SBOM file afterwards. --offline avoids an NVD DB download
    # (CVE matching is handled later by Trivy in the common pipeline).
    cve-bin-tool --offline --quiet \
        --sbom-output "$BIN_SBOM" --sbom-type cyclonedx --sbom-format json \
        "$ROOTFS" >/dev/null 2>&1 || true
    if [ ! -s "$BIN_SBOM" ] || ! jq empty "$BIN_SBOM" >/dev/null 2>&1; then
        echo "[firmware] WARN: cve-bin-tool produced no usable SBOM; continuing without binary components." >&2
        echo '{"components":[]}' > "$BIN_SBOM"
    fi
else
    echo "[firmware] cve-bin-tool not installed; skipping binary identification (Phase 2)."
    echo '{"components":[]}' > "$BIN_SBOM"
fi

# --------------------------------------------------------
# ④ Merge package + binary components, dedupe by purl (fallback name@version).
# --------------------------------------------------------
# Keep only components with a real name (drops syft's empty "os:unknown" noise).
comps_of() { jq -c '[.components[]? | select((.name // "") != "")]' "$1" 2>/dev/null || echo '[]'; }
PKG_COMPS=$(comps_of "$PKG_SBOM")
BIN_COMPS=$(comps_of "$BIN_SBOM")

MERGED=$(jq -n --argjson a "$PKG_COMPS" --argjson b "$BIN_COMPS" '
    ($a + $b)
    | group_by(.purl // ((.name // "") + "@" + (.version // "")))
    | map(.[0])
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
')

NPKG=$(echo "$PKG_COMPS" | jq 'length')
NBIN=$(echo "$BIN_COMPS" | jq 'length')
NTOTAL=$(echo "$MERGED" | jq 'length')

jq -n \
    --argjson comps "$MERGED" \
    --arg name "$(basename "$FW")" \
    --arg version "$VERSION" \
    --arg desc "$FILE_INFO" \
    --arg ts "$GEN_AT" '
{
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    timestamp: $ts,
    tools: { components: [
      { type: "application", name: "unblob" },
      { type: "application", name: "syft" },
      { type: "application", name: "cve-bin-tool" }
    ] },
    component: { type: "firmware", name: $name, version: $version, description: $desc }
  },
  components: $comps
}' > "$OUTPUT"

echo "[firmware] SBOM written: $OUTPUT (components=${NTOTAL}: packages=${NPKG}, binaries=${NBIN})"
