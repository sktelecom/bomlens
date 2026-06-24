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

# Make vendored (SCANOSS-identified) components reachable by the security scan.
# SCANOSS labels C/C++ matches with pkg:github/<owner>/<repo> PURLs, which Trivy
# does NOT use for CVE matching — it matches OS/language PURLs and CPEs. Without a
# CPE these components are identified but carry no vulnerabilities, breaking the
# identify->CVE chain. For components SCANOSS already gave a cpe we leave it alone;
# otherwise we look the version-stripped PURL coordinate up in vendored-purl-map.json
# and synthesize a cpe:2.3 (NVD). Coordinates not in the map (niche libraries with
# no NVD record) keep their PURL and are simply identified, not vuln-matched.
#
# The version goes verbatim into the CPE's version field, so it MUST be CPE-safe:
# a `:` (field separator), space, or wildcard (`*`/`?`) in the version would shift
# or break the 13-field cpe:2.3 grammar and could make Trivy reject the whole SBOM
# (the same failure class as the swift-purl bug above). SCANOSS versions are
# attacker-influenceable (they come from the matched upstream), so only synthesize
# a CPE when the version matches a conservative token; otherwise leave the
# component identified-only (PURL kept, no CPE) rather than emit a malformed one.
VMAP_JSON='{}'
[ -f "$SCRIPT_DIR/vendored-purl-map.json" ] && VMAP_JSON=$(cat "$SCRIPT_DIR/vendored-purl-map.json")
VENDORED_CPE_FIX='(.components) |= (if type=="array" then map(
  if ( ((.properties // []) | map(select(.name=="bomlens:identifiedBy" and .value=="scanoss")) | length) > 0 )
     and (.cpe == null) and (.purl != null)
     and ((.version // "") | test("^[A-Za-z0-9][A-Za-z0-9_.+-]*$"))
  then
    ( .purl | split("@")[0] | split("?")[0] ) as $coord
    | ($vmap[$coord]) as $m
    | (if ($m != null)
        then . + { cpe: ("cpe:2.3:a:" + $m.cpe_vendor + ":" + $m.cpe_product + ":" + .version + ":*:*:*:*:*:*:*") }
        else . end)
  else . end
) else . end)'

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

# Tag components whose declared license needs human review (AI behavioral-use /
# non-commercial) with a bomlens:licenseReview property, so the web UI can badge
# them from structural data. Uses the SAME classifier as the NOTICE's review
# section (license-flags.jq), so badge and notice never disagree. Runs after
# LICENSE_FIX so normalized .license.id is in place; permissive/copyleft are not
# flagged (license_flag returns "" → no property added).
LICENSE_FLAGS_DEF="$(cat "$SCRIPT_DIR/license-flags.jq")"
LICENSE_REVIEW_FIX='(.components) |= (if type=="array" then map(
  ([ (.licenses // [])[] | (.license.id // .license.name // .expression // "") | license_flag(.) ]
    | map(select(. != "")) | (.[0] // "")) as $flag
  | if $flag != "" then
      .properties = (((.properties // []) | map(select(.name != "bomlens:licenseReview")))
        + [{name:"bomlens:licenseReview", value:$flag}])
    else . end
) else . end)'

if [ "$MODE" = "--stable" ]; then
    # Reproducible build: pin every timestamp (metadata + annotations + tools),
    # drop random serial number. cdxgen also embeds a human-readable build date
    # inside metadata annotations — normalize that to keep output byte-stable.
    # cdxgen further leaks the random name of the temp virtualenv it builds to
    # resolve python deps (cdxgen-venv-XXXXXX) into component evidence values, so
    # the same input yields a different byte stream each run; pin that suffix too.
    jq -S --argjson vmap "$VMAP_JSON" "
        ${LICENSE_FLAGS_DEF}
        ${NORMALIZE_DEF}
        ${NULL_FIX}
        | ${PURL_FIX}
        | ${VENDORED_CPE_FIX}
        | ${LICENSE_FIX}
        | ${LICENSE_REVIEW_FIX}
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
    jq -S --argjson vmap "$VMAP_JSON" "${LICENSE_FLAGS_DEF} ${NORMALIZE_DEF} ${NULL_FIX} | ${PURL_FIX} | ${VENDORED_CPE_FIX} | ${LICENSE_FIX} | ${LICENSE_REVIEW_FIX} | ${SORT_FILTER}" "$SBOM" > "$TMP"
fi

mv "$TMP" "$SBOM"
echo "[normalize] normalized: $SBOM (mode=${MODE:-sort-only})"
