#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# identify-vendored.sh — identify open source copied (vendored) into a source tree.
#
# Usage: identify-vendored.sh <source_dir> <output_sbom.json> <version>
#   produces <output_sbom.json> (CycloneDX 1.6) whose components are the open-source
#   files SCANOSS matched against its public knowledge base (OSSKB).
#
# Why this exists: a C/C++ embedded source tree with no package manager (raw
# CMake/Make) yields an almost-empty SBOM — cdxgen lists each source file as a
# pkg:generic component with no name/version. The real open source lives in files
# copied straight into the tree (liblfds, djbdns, libaes, openssl, …). SCANOSS
# winnowing fingerprints those files and matches them to a known release, so we
# can record them as proper components (name + version + purl).
#
# Precision: only FULL-FILE matches (id == "file") are promoted to components.
# Snippet matches (a few lines copied from elsewhere) are noisy and are skipped
# here, so the SBOM that feeds the security/notice pipeline stays clean.
#
# Privacy: SCANOSS sends file FINGERPRINTS (hashes), not source code, to the
# OSSKB API. Endpoint/credentials are overridable via SCANOSS_API_URL /
# SCANOSS_API_KEY (default: the free api.osskb.org).
#
# Best-effort: a missing tool, no network, or no match degrades to an empty
# components array rather than aborting — the caller always gets a valid SBOM.
set -e

SRC="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "[vendored] source directory not found: $SRC" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[vendored] output path is required (usage: identify-vendored.sh <src> <out.json> <version>)" >&2
    exit 1
fi

GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Always emit a valid (possibly empty) CycloneDX envelope, used on every
# graceful-degrade path below so the caller never sees a missing/half file.
# $1 = scanoss status recorded on metadata.properties so the UI can tell apart
# "search failed (rate limit / no network / no token)" from "search ran, found
# nothing". Defaults to unavailable since this is only called on failure paths.
write_empty() {
    local status="${1:-unavailable}"
    jq -n --arg version "$VERSION" --arg ts "$GEN_AT" --arg status "$status" '
    {
      bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
      metadata: {
        timestamp: $ts,
        tools: { components: [ { type: "application", name: "scanoss" } ] },
        component: { type: "application", name: "vendored", version: $version },
        properties: [ { name: "bomlens:scanoss:status", value: $status } ]
      },
      components: []
    }' > "$OUTPUT"
}

if ! command -v scanoss-py >/dev/null 2>&1; then
    echo "[vendored] scanoss-py not installed in this image; skipping vendored identification." >&2
    echo "[vendored]   Rebuild with: docker build --build-arg SBOM_SCANOSS=true -t bomlens ./docker" >&2
    write_empty
    exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "[vendored] ERROR: jq not installed in this image." >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RAW="$WORK/scanoss-raw.json"

# Folders owned by a package manager or a build (their contents are already
# declared by the cdxgen scan, or are generated output). Excluding them keeps
# SCANOSS from re-identifying known dependencies as duplicate pkg:github
# components — the main over-detection risk when this option is enabled on a
# normal, package-managed project. (Name reconciliation in entrypoint.sh is the
# second line of defence for anything that slips through.)
SKIP_FOLDERS="node_modules vendor dist build target out .venv venv \
__pycache__ .gradle .m2 .git bower_components Pods .next .tox .cargo .bundle"
SKIP_ARGS=()
for d in $SKIP_FOLDERS; do SKIP_ARGS+=(--skip-folder "$d"); done
# Ignore tiny files: too little content to identify reliably, a common source of
# spurious file matches (boilerplate headers, empty stubs).
SKIP_ARGS+=(--skip-size 256)

# Run SCANOSS. --skip-snippets keeps it to full-file matching (precision) and is
# faster/lighter on the API. We take the RAW result (default JSON, keyed by file
# path) rather than scanoss' own CycloneDX so we fully control which matches are
# promoted and which provenance properties are attached.
#
# --all-hidden: web-UI uploads and git clones are extracted UNDER the server's
# .uploads/ directory, and scanoss-py skips any path with a dot-prefixed
# component by default — so without this flag every uploaded/cloned source
# fingerprints zero files and never matches. The SKIP_FOLDERS list below still
# excludes .git/.gradle/etc., so this only re-includes the real source tree.
echo "[vendored] SCANOSS: fingerprinting $SRC (file hashes only; source stays local)..."
# shellcheck disable=SC2086
if ! scanoss-py scan "$SRC" --all-hidden --skip-snippets "${SKIP_ARGS[@]}" --output "$RAW" \
        ${SCANOSS_API_URL:+--apiurl "$SCANOSS_API_URL"} \
        ${SCANOSS_API_KEY:+--key "$SCANOSS_API_KEY"} >/dev/null 2>&1; then
    echo "[vendored] WARN: SCANOSS scan failed (no network / rate limit / bad endpoint); no vendored components." >&2
    write_empty "unavailable"
    exit 0
fi
if [ ! -s "$RAW" ] || ! jq empty "$RAW" >/dev/null 2>&1; then
    echo "[vendored] WARN: SCANOSS produced no usable result; no vendored components." >&2
    write_empty "unavailable"
    exit 0
fi

# Transform raw SCANOSS JSON -> CycloneDX components.
#   - keep only full-file matches (.id == "file")
#   - carry SCANOSS' cpe through when present (lets Trivy match CVEs directly;
#     normalize-sbom.sh fills the gap for libraries SCANOSS gives no cpe for)
#   - normalize the version: OSSKB returns git-tag forms (e.g. "openssl-3.0.0",
#     "v1.2.13"), which would otherwise produce a malformed CPE and miss CVEs.
#     Strip a leading "<component>-"/"<component>_" and a leading "v" before a digit.
#   - tag provenance: bomlens:layer=vendored, identifiedBy=scanoss, match %, source file
#   - dedupe by purl (fallback name@version), matching merge-sbom.sh
#
# Components are written to a file and passed to the final jq via --slurpfile, NOT
# --argjson: a large source tree yields thousands of matches, and a multi-hundred-KB
# --argjson string overflows Linux's per-argument limit (MAX_ARG_STRLEN, 128 KB),
# which would silently produce an empty/invalid SBOM on the (Linux) scanner image.
# Coverage filter (precision over noise). The free OSSKB often matches a
# widely-copied file to a downstream project that vendored the library rather than
# the canonical upstream, so a real source tree produces many one-off matches to
# unrelated forks. Group file matches by library NAME and promote a component only
# when at least SCANOSS_MIN_FILES files agree on it; single-file fork noise is
# dropped. Within a kept group the version and PURL are the consensus (most common)
# value, which also fixes per-file version disagreement. Set SCANOSS_MIN_FILES=1 to
# disable the filter (keep every single-file match).
MIN_FILES="${SCANOSS_MIN_FILES:-2}"
case "$MIN_FILES" in ''|*[!0-9]*) MIN_FILES=2 ;; esac
COMPS_FILE="$WORK/comps.json"
jq -c --argjson minfiles "$MIN_FILES" '
    [ to_entries[]
      | .key as $file
      | .value[]?
      | select((.id // "") == "file")
      | { name: (.component // ((.purl[0] // "") | sub("^pkg:[^/]+/"; ""))),
          version: ( (.component // "") as $c
                     | (.version // "")
                     | ltrimstr($c + "-") | ltrimstr($c + "_")
                     | sub("^[vV](?=[0-9])"; "") ),
          purl: (.purl[0] // null),
          cpe: (.cpe[0]? // null),
          matched: (.matched // ""),
          licenses: [ .licenses[]?.name // empty ] }
      | select((.name // "") != "")
    ]
    | group_by(.name | ascii_downcase)
    | map(
        . as $g
        | ($g | length) as $files
        | select($files >= $minfiles)
        | ($g | map(.version) | map(select(. != ""))) as $vers
        | ($g | map(.purl) | map(select(. != null))) as $purls
        | (if ($purls | length) > 0 then ($purls | group_by(.) | max_by(length) | .[0]) else null end) as $purl
        | (if ($vers | length) > 0 then ($vers | group_by(.) | max_by(length) | .[0]) else "" end) as $ver
        | { type: "library",
            name: ($g[0].name),
            version: $ver,
            purl: $purl,
            cpe: ($g | map(.cpe) | map(select(. != null)) | (.[0] // null)),
            licenses: ( [ $g[].licenses[]? ] | map(select(. != null and . != ""))
                        | unique | map({ license: { name: . } }) ),
            properties: ( [
                { name: "bomlens:layer",         value: "vendored" },
                { name: "bomlens:identifiedBy",  value: "scanoss" },
                { name: "bomlens:scanoss:files", value: ($files | tostring) },
                { name: "bomlens:scanoss:match", value: ($g[0].matched) },
                { name: "bomlens:scanoss:purl",  value: ($purl // "") }
              ] | map(select((.value // "") != "")) )
          }
        | with_entries(select(.value != null and .value != "" and .value != []))
      )
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
' "$RAW" > "$COMPS_FILE" 2>/dev/null || true
# Guard: ensure a valid JSON array even if the transform failed.
if [ ! -s "$COMPS_FILE" ] || ! jq -e 'type=="array"' "$COMPS_FILE" >/dev/null 2>&1; then
    echo '[]' > "$COMPS_FILE"
fi

NCOMP=$(jq 'length' "$COMPS_FILE" 2>/dev/null || echo 0)
# matched when SCANOSS returned full-file hits; no-match when the search ran
# cleanly but found nothing vendored. (The failure paths above record
# "unavailable".) The UI uses this to explain an empty result.
if [ "${NCOMP:-0}" -gt 0 ]; then SCANOSS_STATUS="matched"; else SCANOSS_STATUS="no-match"; fi

jq -n \
    --slurpfile comps "$COMPS_FILE" \
    --arg version "$VERSION" \
    --arg ts "$GEN_AT" \
    --arg status "$SCANOSS_STATUS" '
{
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    timestamp: $ts,
    tools: { components: [ { type: "application", name: "scanoss" } ] },
    properties: [ { name: "bomlens:scanoss:status", value: $status } ]
  },
  components: $comps[0]
}' > "$OUTPUT"

echo "[vendored] SBOM written: $OUTPUT (vendored components=${NCOMP})"
