#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# normalize-sbom.sh — make a CycloneDX SBOM deterministic (byte-stable).
#
# Usage: normalize-sbom.sh <sbom.json> [--stable]
#   (no flag)  sort components only (stable ordering, timestamps preserved)
#   --stable   also pin metadata.timestamp and drop random serialNumber so that
#              identical inputs produce byte-identical output (CI diff / reproducibility)
set -e

SBOM="$1"
MODE="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[normalize] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[normalize] WARN: $SBOM is not valid JSON; skipping normalization" >&2
    exit 0
fi

TMP="$(mktemp)"

# Always: coerce a missing/null components field to an empty array. cdxgen emits
# components:null when it cannot resolve any component (e.g. a swift tree with no
# Package.resolved), which is spec-invalid — CycloneDX requires components to be an
# array. Apply this first so every later step receives an array.
NULL_FIX='(.components) |= (if type=="array" then . else [] end)'

# Always: sort components deterministically by purl (fallback name@version).
SORT_FILTER='(.components) |= (if type=="array" then sort_by(.purl // ((.name // "") + "@" + (.version // ""))) else . end)'

# cdxgen can emit spec-invalid swift PURLs: pkg:swift REQUIRES a namespace
# (e.g. pkg:swift/github.com/apple/swift-log@1.0.0), but the root component and
# first-party modules come out as pkg:swift/<name>@<ver> with no namespace. A
# single invalid PURL on the root component makes strict parsers (Trivy) reject
# the WHOLE SBOM ("failed to parse PURL: namespace is required"), so the security
# scan silently produces an empty report. Drop only those invalid purls (the
# component name/version are retained); valid namespaced swift purls are untouched.
PURL_FIX='(.metadata.component) |= (if (has("purl") and (.purl|test("^pkg:swift/[^/]+@"))) then with_entries(select(.key!="purl")) else . end) | (.components) |= (if type=="array" then map(if (has("purl") and (.purl|test("^pkg:swift/[^/]+@"))) then with_entries(select(.key!="purl")) else . end) else . end)'

# Always: normalize component license aliases to SPDX ids. cdxgen records some
# licenses as non-SPDX free text ("Expat license", "Apache License 2.0"); the v1.3
# web UI surfaces (license filter, distribution card, dependency tree) read these
# raw, so the same license splits into several buckets. normalize() (shared with
# generate-notice.sh) maps only recognized aliases — a non-alias string and a
# valid-but-wrong upstream id (e.g. cdxgen mislabeling a package 0BSD) are left
# as-is rather than guessed. Free text that maps to a single SPDX id is promoted
# from .license.name / .expression to a proper .license.id; the source url is kept.
NORMALIZE_DEF="$(cat "$SCRIPT_DIR/spdx-normalize.jq")"
LICENSE_FIX='(.components) |= (if type=="array" then map(
  if (.licenses|type)=="array" then
    .licenses |= map(
      if (has("expression") and (.expression|type)=="string") then
        (normalize(.expression)) as $n |
        (if $n != .expression then {license:{id:$n}} else . end)
      elif ((.license|type)=="object" and (.license.id == null) and ((.license.name // null) != null)) then
        .license |= (normalize(.name) as $n |
          (if $n != .name then ({id:$n} + (if .url then {url:.url} else {} end)) else . end))
      else . end
    )
  else . end
) else . end)'

if [ "$MODE" = "--stable" ]; then
    # Reproducible build: pin every timestamp (metadata + annotations + tools),
    # drop random serial number. cdxgen also embeds a human-readable build date
    # inside metadata annotations — normalize that to keep output byte-stable.
    # cdxgen further leaks the random name of the temp virtualenv it builds to
    # resolve python deps (cdxgen-venv-XXXXXX) into component evidence values, so
    # the same input yields a different byte stream each run; pin that suffix too.
    jq -S "
        ${NORMALIZE_DEF}
        ${NULL_FIX}
        | ${PURL_FIX}
        | ${LICENSE_FIX}
        | ${SORT_FILTER}
        | walk(if type==\"object\" and has(\"timestamp\") then .timestamp = \"1970-01-01T00:00:00Z\" else . end)
        | walk(if type==\"string\" then gsub(\"cdxgen-venv-[A-Za-z0-9]+\"; \"cdxgen-venv\") else . end)
        | (if (.annotations|type)==\"array\" then
              .annotations |= map(if (.text|type)==\"string\"
                  then .text |= gsub(\"created on [A-Za-z0-9, :]+ with cdxgen\"; \"created on (normalized) with cdxgen\")
                  else . end)
           else . end)
        | del(.serialNumber)
    " "$SBOM" > "$TMP"
else
    jq -S "${NORMALIZE_DEF} ${NULL_FIX} | ${PURL_FIX} | ${LICENSE_FIX} | ${SORT_FILTER}" "$SBOM" > "$TMP"
fi

mv "$TMP" "$SBOM"
echo "[normalize] normalized: $SBOM (mode=${MODE:-sort-only})"
