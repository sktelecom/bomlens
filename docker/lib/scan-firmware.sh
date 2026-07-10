#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# scan-firmware.sh — unpack a firmware image and build a CycloneDX SBOM.
#
# Usage: scan-firmware.sh <firmware_file> <output_sbom.json> <version> [out_prefix]
#   produces <output_sbom.json> (CycloneDX, components from package DB + binaries)
#   and, when out_prefix is given and cve-bin-tool can match CVEs online:
#            <out_prefix>_security_cvebintool.json
#              (Trivy-shaped CVE rows that scan-security.sh merges into _security.json)
#
# Pipeline (see docs/firmware-analysis.md §5):
#   ① unpack   : unblob (preferred) -> BANG / binwalk (fallback)
#   ② packages : syft dir:<rootfs>            -> package-manager components
#   ③ binaries : cve-bin-tool                 -> stripped static binaries (Phase 2)
#                + ONLINE CVE matching (NVD/vuln DB) on those binaries (Plan 2):
#                cve-bin-tool matches CVEs by version signature, not by purl/CPE,
#                so it finds CVEs on firmware binaries that have neither (the
#                common-pipeline Trivy needs purl/CPE and otherwise reports 0).
#   ④ merge    : jq, dedupe by purl (fallback name@version)
#
# Tools live ONLY in the opt-in `bomlens-firmware` image. Everything here is
# best-effort: a missing/failed stage degrades gracefully rather than aborting,
# so the common post-processing pipeline always receives a valid SBOM.
set -e

FW="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"
OUT_PREFIX="${4:-}"

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
    echo "[firmware]   Rebuild the firmware image: docker build --build-arg SBOM_FIRMWARE=true -t bomlens-firmware ./docker" >&2
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

# Source file tree for the web UI (structure only, no licenses). The extracted
# rootfs is in this script's temp dir and is removed on EXIT, so emit it here
# while it exists. Writes ${OUT_PREFIX}_files.json into the caller's working dir
# (where the entrypoint collects artifacts). Best-effort; never aborts the scan.
if [ -n "$OUT_PREFIX" ]; then
    SFT="$(cd "$(dirname "$0")" && pwd)/source-file-tree.sh"
    if [ -f "$SFT" ]; then
        bash "$SFT" "$ROOTFS" "${OUT_PREFIX}_files.json" || true
    fi
fi

# --------------------------------------------------------
# ③ Package components (syft) + binary components (cve-bin-tool).
# --------------------------------------------------------
PKG_SBOM="$WORK/pkg.cdx.json"
echo "[firmware] syft: cataloging packages under rootfs..."
if ! syft "dir:$ROOTFS" -o cyclonedx-json@1.6 > "$PKG_SBOM" 2>/dev/null; then
    echo "[firmware] WARN: syft directory scan failed; continuing without package components." >&2
    echo '{"components":[]}' > "$PKG_SBOM"
fi

BIN_SBOM="$WORK/bin.cdx.json"
CVE_JSON="$WORK/cve-bin-tool.json"
echo '{"components":[]}' > "$BIN_SBOM"
echo '[]' > "$CVE_JSON"

# Plan 2 — CVE matching. cve-bin-tool is used ONLY to IDENTIFY binaries (its
# signature checkers), emitting a CycloneDX SBOM whose components carry a CPE. It
# does NOT match CVEs here: CPE->CVE matching is done by firmware-cpe-match.py
# against the bundled NVD CPE index (cpe_match.sqlite, distilled at image-build
# time by build-cpe-index.py from the NVD data feeds). This removes the ~1.5 GB
# cve.db and the throttled NVD api2 fetch while keeping offline/air-gap matching.
# CVE_BIN_TOOL_MODE: auto (default; identify + match) | components-only (identify,
# no CVE matching).
CVE_BIN_TOOL_MODE="${CVE_BIN_TOOL_MODE:-auto}"
# cve-bin-tool 3.x hard-codes its DB cache to $HOME/.cache/cve-bin-tool/cve.db and
# refuses to run on an empty cache (EmptyCache). The image bundles a tiny STUB DB
# there purely to satisfy that check; identification never reads CVE data from it.
CVE_BIN_TOOL_HOME="${CVE_BIN_TOOL_HOME:-/opt/cve-bin-tool-home}"
BUNDLED_DB="$CVE_BIN_TOOL_HOME/.cache/cve-bin-tool/cve.db"
# Distilled CPE->CVE applicability index (built by docker/build-cpe-index.py).
FW_CPE_INDEX="${FW_CPE_INDEX:-$CVE_BIN_TOOL_HOME/cpe_match.sqlite}"
# GAD/OSV are cve-bin-tool data sources; disabling them keeps identification from
# reaching out. Override with CVE_BIN_TOOL_DISABLE_SOURCES.
CVE_BIN_TOOL_DISABLE_SOURCES="${CVE_BIN_TOOL_DISABLE_SOURCES:-GAD,OSV}"
disable_args=()
if [ -n "$CVE_BIN_TOOL_DISABLE_SOURCES" ]; then disable_args=(-d "$CVE_BIN_TOOL_DISABLE_SOURCES"); fi

if command -v cve-bin-tool >/dev/null 2>&1; then
    echo "[firmware] cve-bin-tool: identifying binary components (signature checkers)..."
    # Required NVD attribution (the bundled index is derived from NVD data).
    echo "[firmware] This product uses NVD data but is not endorsed or certified by the NVD."

    # cve-bin-tool needs a non-empty cache to run at all; give it a writable HOME
    # with the bundled stub DB symlinked in (read-only; --update=never never writes).
    CVE_HOME="$WORK/cve-home"
    mkdir -p "$CVE_HOME/.cache/cve-bin-tool"
    if [ -f "$BUNDLED_DB" ]; then
        ln -sf "$BUNDLED_DB" "$CVE_HOME/.cache/cve-bin-tool/cve.db"
    fi

    # Identification only: emit the component SBOM; no CVE report, no network.
    # NOTE: no --quiet. cve-bin-tool suppresses the --sbom-output file under --quiet
    # when it finds 0 CVEs, and against the stub DB it always finds 0; the verbose
    # table is dropped by the stdout redirect, but the SBOM is still written.
    env HOME="$CVE_HOME" cve-bin-tool --update=never "${disable_args[@]}" \
        --sbom-output "$BIN_SBOM" --sbom-type cyclonedx --sbom-format json \
        "$ROOTFS" >/dev/null 2>&1 || true

    if [ ! -s "$BIN_SBOM" ] || ! jq empty "$BIN_SBOM" >/dev/null 2>&1; then
        echo "[firmware] WARN: cve-bin-tool produced no usable SBOM; continuing without binary components." >&2
        echo '{"components":[]}' > "$BIN_SBOM"
    fi

    # ③.5 CPE -> CVE matching against the bundled NVD index. firmware-cpe-match.py
    # reads the identified components' CPEs and emits cve-bin-tool-shaped rows into
    # $CVE_JSON, which step ⑤ reshapes into the sidecar (downstream contract kept).
    if [ "$CVE_BIN_TOOL_MODE" = "components-only" ]; then
        echo "[firmware] CVE_BIN_TOOL_MODE=components-only: skipping CVE matching."
    elif [ -f "$FW_CPE_INDEX" ] && command -v python3 >/dev/null 2>&1; then
        python3 "$(dirname "$0")/firmware-cpe-match.py" "$BIN_SBOM" "$FW_CPE_INDEX" \
            > "$CVE_JSON" 2>/dev/null || echo '[]' > "$CVE_JSON"
    else
        echo "[firmware] WARN: no CPE index at $FW_CPE_INDEX; emitting component-only (no CVEs)." >&2
    fi
    if [ ! -s "$CVE_JSON" ] || ! jq empty "$CVE_JSON" >/dev/null 2>&1; then
        echo '[]' > "$CVE_JSON"
    fi
else
    echo "[firmware] cve-bin-tool not installed; skipping binary identification (Phase 2)."
fi

# --------------------------------------------------------
# ④ Merge package + binary components, dedupe by purl (fallback name@version).
# --------------------------------------------------------
# Keep only components with a real name (drops syft's empty "os:unknown" noise).
# A large rootfs (e.g. an OpenWRT ext4 image) yields huge component arrays.
# Pass them to jq through files (--slurpfile), not --argjson, or the merge blows
# the command-line length limit ("Argument list too long").
comps_of() { jq -c '[.components[]? | select((.name // "") != "")]' "$1" 2>/dev/null || echo '[]'; }
comps_of "$PKG_SBOM" > "$WORK/pkg-comps.json"
comps_of "$BIN_SBOM" > "$WORK/bin-comps.json"

jq -n --slurpfile a "$WORK/pkg-comps.json" --slurpfile b "$WORK/bin-comps.json" '
    ($a[0] + $b[0])
    | group_by(.purl // ((.name // "") + "@" + (.version // "")))
    | map(.[0])
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
' > "$WORK/merged.json"

NPKG=$(jq 'length' "$WORK/pkg-comps.json")
NBIN=$(jq 'length' "$WORK/bin-comps.json")
NTOTAL=$(jq 'length' "$WORK/merged.json")

jq -n \
    --slurpfile comps "$WORK/merged.json" \
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
  components: $comps[0]
}' > "$OUTPUT"

echo "[firmware] SBOM written: $OUTPUT (components=${NTOTAL}: packages=${NPKG}, binaries=${NBIN})"

# --------------------------------------------------------
# ⑤ Plan 2 — emit cve-bin-tool CVEs as a Trivy-shaped sidecar.
# cve-bin-tool's JSON is a flat list of rows: { product, version, cve_number,
# severity, score, cvss_version, cvss_vector, source, ... }. We reshape it into
# the exact contract the web layer (server.py security_summary) and our report
# renderer read: { "Results": [ { "Target", "Vulnerabilities": [ {
# VulnerabilityID, PkgName, InstalledVersion, Severity, CVSS, PrimaryURL } ] } ] }.
# scan-security.sh merges this sidecar into _security.json AFTER Trivy runs, so
# the contract is never broken and both engines' findings appear in one report.
# Written only when out_prefix is provided and there is at least one CVE row.
# --------------------------------------------------------
if [ -n "$OUT_PREFIX" ]; then
    NCVE=$(jq 'if type=="array" then length else 0 end' "$CVE_JSON" 2>/dev/null || echo 0)
    if [ "${NCVE:-0}" -gt 0 ]; then
        SIDE="${OUT_PREFIX}_security_cvebintool.json"
        # NVD severity is upper-case already; default UNKNOWN. score -> CVSS V3.
        # PrimaryURL points at NVD for the CVE id. Dedupe identical (cve,pkg,ver).
        jq '
          [ .[]? | select((.cve_number // "") | test("^CVE-")) | {
              VulnerabilityID: .cve_number,
              PkgName: (.product // ""),
              InstalledVersion: (.version // ""),
              Severity: ((.severity // "UNKNOWN") | ascii_upcase),
              PrimaryURL: ("https://nvd.nist.gov/vuln/detail/" + .cve_number),
              CVSS: ( (.score // null) as $s
                      | if ($s != null and ($s|tostring|test("^[0-9.]+$")) and (($s|tonumber) > 0))
                        then { "cve-bin-tool": { ("V" + ((.cvss_version // "3")|tostring) + "Score"): ($s|tonumber) } }
                        else {} end ),
              source: "cve-bin-tool"
            } ]
          | unique_by([.VulnerabilityID, .PkgName, .InstalledVersion])
          | { Results: [ { Target: "firmware (cve-bin-tool)", Class: "firmware", Vulnerabilities: . } ] }
        ' "$CVE_JSON" > "$SIDE" 2>/dev/null || echo '{"Results":[]}' > "$SIDE"
        NSIDE=$(jq '[.Results[].Vulnerabilities[]?] | length' "$SIDE" 2>/dev/null || echo 0)
        echo "[firmware] cve-bin-tool found ${NSIDE} CVE(s) -> $SIDE (merged into the security report)."
    else
        echo "[firmware] cve-bin-tool reported no CVEs (or CVE matching was skipped)."
    fi
fi
