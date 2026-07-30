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
# Which unpackers were actually available and run. The failure message used to
# name the whole chain whether or not a given tool was installed, which sent
# people looking for a format problem when the tool simply was not there.
tried=""
note_tried() { tried="${tried:+$tried, }$1"; }

# Firmware input is attacker-supplied, and unpackers have no built-in bound: a
# decompression bomb or a malformed/deeply-nested image can spin an extractor
# indefinitely. Wrap each in `timeout` so a hang cannot stall the scan (the
# `|| true` then moves to the next fallback). Overridable; falls back to no
# wrapper if `timeout` is somehow absent from the image.
FW_UNPACK_TIMEOUT="${FW_UNPACK_TIMEOUT:-900}"
_tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$FW_UNPACK_TIMEOUT" "$@"; else "$@"; fi; }

if command -v unblob >/dev/null 2>&1; then
    echo "[firmware] unpacking with unblob..."
    note_tried unblob
    _tmo unblob --extract-dir "$EXTRACT" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
# -no-xattrs, on both call sites below: unsquashfs restores extended attributes
# by default, and writing security.selinux is not permitted inside the container.
# It treats that as fatal and aborts mid-extraction, so a perfectly standard
# squashfs came out empty. The attributes are of no use to us — we read the files,
# we do not boot them.
#
# squashfs is the most common firmware filesystem; unsquashfs (squashfs-tools)
# handles standard images even when unblob's sasquatch handler is absent.
if [ "$unpacked" = 0 ] && command -v unsquashfs >/dev/null 2>&1 && printf '%s' "$FILE_INFO" | grep -qi squashfs; then
    echo "[firmware] falling back to unsquashfs..."
    note_tried unsquashfs
    _tmo unsquashfs -no-xattrs -f -d "$EXTRACT/squashfs-root" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
# 7z reads the container formats Windows deliveries arrive in — NSIS and Inno
# Setup installers, self-extracting cabinets, MSI — none of which unblob unpacks.
# A supplier's product installer is a common input, and until this fallback ran
# it produced an empty extraction and therefore an empty SBOM. 7z is already in
# the image (unblob shells out to it), so this costs nothing. Last in the chain
# because it will also happily carve fragments out of files it does not really
# understand; anything the earlier, format-aware unpackers claim wins.
if [ "$unpacked" = 0 ] && command -v 7z >/dev/null 2>&1; then
    echo "[firmware] falling back to 7z extraction..."
    note_tried 7z
    _tmo 7z x -y -bso0 -bsp0 -o"$EXTRACT/7z-out" -- "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi
if [ "$unpacked" = 0 ] && command -v binwalk >/dev/null 2>&1; then
    echo "[firmware] falling back to binwalk extraction..."
    note_tried binwalk
    _tmo binwalk --run-as=root --extract --directory "$EXTRACT" "$FW" >/dev/null 2>&1 \
        || _tmo binwalk --extract --directory "$EXTRACT" "$FW" >/dev/null 2>&1 || true
    has_extracted && unpacked=1
fi

if [ "$unpacked" = 0 ]; then
    echo "[firmware] WARN: no unpacker produced files (tried: ${tried:-none available})." >&2
    echo "[firmware]       Firmware may be encrypted/signed or in an unsupported format; emitting best-effort SBOM." >&2
fi

# --------------------------------------------------------
# ①.5 Extract filesystem images that were carved out but not opened.
#
# unblob recognizes a filesystem inside a firmware blob and carves it into its own
# file, but does not always extract it: its squashfs handler shells out to
# `sasquatch`, which this image does not bundle. The carve still counts as "unblob
# produced files", so the fallback chain above is skipped and the pipeline goes on
# to catalog one opaque multi-megabyte blob. Partial success is worse than failure
# here, because failure at least reaches the next unpacker.
#
# The carve is recoverable: plain unsquashfs opens a standard image perfectly well
# (given -no-xattrs, see above). So make a second pass over the extraction tree and
# unpack any filesystem image still sitting there as a single file. Measured on an
# OpenWrt rootfs image: 1 component before, 199 after.
#
# Only files of at least 256 KiB are probed with `file`, to keep this from running
# a subprocess per entry on a tree with thousands of small files.
# --------------------------------------------------------
# Each entry is one line: "<path inside the firmware><TAB><why the extractor refused>".
# Keeping the reason is the point. Guessing at the cause once cost a release note
# that told readers to go find sasquatch when the extractor was in fact refusing
# to write an SELinux attribute — a one-flag problem. Report what the tool said.
CARVED_UNOPENED=""
extract_carved_filesystems() {
    local img out err reason found=0
    # Returns non-zero when nothing was opened, which is also the right answer when
    # the extractor is absent: the caller's loop reads success as "made progress".
    command -v unsquashfs >/dev/null 2>&1 || return 1
    err="$WORK/unsquashfs.err"
    while IFS= read -r img; do
        [ -f "$img" ] || continue
        case "$(file -b "$img" 2>/dev/null)" in
            *Squashfs*) ;;
            *) continue ;;
        esac
        out="$img.extracted"
        [ -e "$out" ] && continue
        if _tmo unsquashfs -no-xattrs -f -d "$out" "$img" >/dev/null 2>"$err" \
           && [ -n "$(find "$out" -type f -print -quit 2>/dev/null)" ]; then
            echo "[firmware] opened a carved squashfs image: ${img#"$EXTRACT"/}"
            found=1
        else
            rm -rf "$out"
            reason=$(grep -m1 -iE 'fatal|error|unsupported|cannot|refus' "$err" 2>/dev/null \
                     | tr -d '\r' | cut -c1-160)
            [ -n "$reason" ] || reason="no output produced and the extractor gave no reason"
            CARVED_UNOPENED="${CARVED_UNOPENED}${img#"$EXTRACT"/}	${reason}
"
        fi
    done < <(find "$EXTRACT" -type f -size +256k 2>/dev/null)
    rm -f "$err"
    return $((1 - found))
}

# An image can nest (firmware -> partition -> squashfs), and each pass can expose
# a new carve, so repeat while progress is being made. Bounded so a crafted image
# cannot loop forever.
carve_round=0
while [ "$carve_round" -lt 3 ] && extract_carved_filesystems; do
    carve_round=$((carve_round + 1))
    unpacked=1
done

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

# File tree + content snapshot for the web UI. The extracted rootfs is in this
# script's temp dir and is removed on EXIT, so both are emitted here while it
# exists. They land in the caller's working dir (where the entrypoint collects
# artifacts): ${OUT_PREFIX}_files.json is the structure, ${OUT_PREFIX}_source.json
# the readable content behind it — configs, init scripts and licence texts, under
# the snapshot's own size caps so a multi-GB rootfs cannot bloat the output.
# Best-effort; never aborts the scan.
if [ -n "$OUT_PREFIX" ]; then
    LIB="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$LIB/source-file-tree.sh" ]; then
        bash "$LIB/source-file-tree.sh" "$ROOTFS" "${OUT_PREFIX}_files.json" || true
    fi
    if [ -f "$LIB/source-snapshot.py" ] && [ -f "${OUT_PREFIX}_files.json" ]; then
        python3 "$LIB/source-snapshot.py" \
            "$ROOTFS" "${OUT_PREFIX}_files.json" "${OUT_PREFIX}_source.json" || true
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
#
# Names are also stripped back to the path inside the firmware. cve-bin-tool
# names a file it could not attribute to a package by its full path on disk,
# which at this point is the throwaway unpack directory:
#
#   /tmp/tmp.lf7KK2AeBn/extract/fw.img.xz_extract/xz.uncompressed_extract/
#   8388608-545257472.fat_extract/initramfs8_extract/…/usr/bin/findmnt
#
# Shipping that verbatim puts the scanning machine's temp path into a document
# meant to be handed to other people, and buries the one useful part. unblob
# names every nesting level `<something>_extract/`, so the text after the last
# one is the path as it exists inside the firmware — keep exactly that.
#
# cve-bin-tool also writes one placeholder component named after the directory it
# was pointed at (`CVEBINTOOL-extract`), whether or not it identified anything.
# Shipping it means a scan that found nothing still reports one component, which
# reads as a result rather than as the empty answer it is. It carries no version,
# no purl and no CPE, so nothing downstream can use it either. Drop it.
comps_of() {
    jq -c '[.components[]? | select((.name // "") != "")
           | select((.name // "") | startswith("CVEBINTOOL-") | not)
           | .name |= (if test("_extract/") then (split("_extract/") | last)
                       elif startswith("/") then (split("/") | last)
                       else . end)]' "$1" 2>/dev/null || echo '[]'
}
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
# ④.5 Say why an empty result is empty.
#
# Zero components has several causes, and they call for different responses:
# encrypted firmware is nothing the reader can do anything about, a squashfs
# variant we cannot open is a gap in this image, and a tree we walked but could
# not attribute is a limit of the identifiers. Reporting all three as a bare
# "components=0" leaves the reader unable to tell a clean scan from a failed one.
#
# Measured on seven vendor firmware images: three returned zero, for three
# different reasons.
# --------------------------------------------------------
if [ "${NTOTAL:-0}" -eq 0 ]; then
    NFILES=$(find "$EXTRACT" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo "[firmware] WARN: no components identified." >&2
    if [ -n "$CARVED_UNOPENED" ]; then
        echo "[firmware]       A filesystem image was found but could not be opened:" >&2
        printf '%s' "$CARVED_UNOPENED" | while IFS="$(printf '\t')" read -r path reason; do
            [ -n "$path" ] || continue
            echo "[firmware]         $path" >&2
            echo "[firmware]           $reason" >&2
        done
    elif [ "$unpacked" = 0 ]; then
        echo "[firmware]       Nothing could be unpacked at all; see the warning above." >&2
    elif [ "${NFILES:-0}" -le 8 ]; then
        echo "[firmware]       Only ${NFILES} file(s) came out of the image and no filesystem was" >&2
        echo "[firmware]       found inside it. A payload that yields no known format and does" >&2
        echo "[firmware]       not compress is normally encrypted or signed." >&2
    else
        echo "[firmware]       ${NFILES} file(s) were unpacked, but they carry no package database" >&2
        echo "[firmware]       and no binary matched a known version signature." >&2
    fi
fi

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
