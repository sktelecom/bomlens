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
write_empty() {
    jq -n --arg version "$VERSION" --arg ts "$GEN_AT" '
    {
      bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
      metadata: {
        timestamp: $ts,
        tools: { components: [ { type: "application", name: "scanoss" } ] },
        component: { type: "application", name: "vendored", version: $version }
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
echo "[vendored] SCANOSS: fingerprinting $SRC (file hashes only; source stays local)..."
# shellcheck disable=SC2086
if ! scanoss-py scan "$SRC" --skip-snippets "${SKIP_ARGS[@]}" --output "$RAW" \
        ${SCANOSS_API_URL:+--apiurl "$SCANOSS_API_URL"} \
        ${SCANOSS_API_KEY:+--key "$SCANOSS_API_KEY"} >/dev/null 2>&1; then
    echo "[vendored] WARN: SCANOSS scan failed (no network / rate limit / bad endpoint); no vendored components." >&2
    write_empty
    exit 0
fi
if [ ! -s "$RAW" ] || ! jq empty "$RAW" >/dev/null 2>&1; then
    echo "[vendored] WARN: SCANOSS produced no usable result; no vendored components." >&2
    write_empty
    exit 0
fi

# Transform raw SCANOSS JSON -> CycloneDX components.
#   - keep only full-file matches (.id == "file")
#   - carry SCANOSS' cpe through when present (lets Trivy match CVEs directly;
#     normalize-sbom.sh fills the gap for libraries SCANOSS gives no cpe for)
#   - tag provenance: bomlens:layer=vendored, identifiedBy=scanoss, match %, source file
#   - dedupe by purl (fallback name@version), matching merge-sbom.sh
COMPS=$(jq -c '
    [ to_entries[]
      | .key as $file
      | .value[]?
      | select((.id // "") == "file")
      | {
          type: "library",
          name: (.component // ((.purl[0] // "") | sub("^pkg:[^/]+/"; ""))),
          version: (.version // ""),
          purl: (.purl[0] // null),
          cpe: (.cpe[0]? // null),
          licenses: ( [ .licenses[]?.name // empty ]
                      | map(select(. != null and . != "")) | unique
                      | map({ license: { name: . } }) ),
          properties: ( [
              { name: "bomlens:layer",          value: "vendored" },
              { name: "bomlens:identifiedBy",   value: "scanoss" },
              { name: "bomlens:scanoss:match",  value: (.matched // "") },
              { name: "bomlens:scanoss:file",   value: $file },
              { name: "bomlens:scanoss:purl",   value: (.purl[0] // "") }
            ] | map(select((.value // "") != "")) )
        }
      | with_entries(select(.value != null and .value != "" and .value != []))
      | select((.name // "") != "")
    ]
    | group_by(.purl // ((.name // "") + "@" + (.version // "")))
    | map(.[0])
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
' "$RAW" 2>/dev/null || echo '[]')

NCOMP=$(echo "$COMPS" | jq 'length' 2>/dev/null || echo 0)

jq -n \
    --argjson comps "$COMPS" \
    --arg version "$VERSION" \
    --arg ts "$GEN_AT" '
{
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    timestamp: $ts,
    tools: { components: [ { type: "application", name: "scanoss" } ] }
  },
  components: $comps
}' > "$OUTPUT"

echo "[vendored] SBOM written: $OUTPUT (vendored components=${NCOMP})"
