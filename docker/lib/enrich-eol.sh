#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-eol.sh — flag components whose release cycle has reached end-of-life
# (EOL), fully OFFLINE, using a bundled endoflife.date snapshot.
#
# Usage: enrich-eol.sh <sbom.json>
#
# Why: "is this component still maintained / supported?" is a supply-chain risk
# distinct from CVEs. A runtime or framework past its EOL gets no security fixes,
# so a Critical/High later has no upstream patch. This step answers, per
# component, whether its release cycle is past its published EOL date.
#
# How (accuracy-first, mirrors enrich-cpe.sh's closed-whitelist philosophy):
#   1. Match by PURL coordinate, not display name. A component whose purl starts
#      with a rule's purlPrefix (eol-purl-map.json) maps to an endoflife.date
#      product. One product arrives under many names (spring-boot-starter-web,
#      spring-boot-autoconfigure, ...) so name matching would miss most of them.
#   2. Derive the release `cycle` from the version's leading segments per the
#      rule's granularity (major, or major.minor).
#   3. Look that cycle up in the bundled endoflife dataset (eol-data.json) and
#      read its `eol`. A date past today => EOL; a future date or false => not
#      EOL; a boolean true => EOL. No cycle entry, no purl, no mapping, or an
#      unparseable version => bomlens:eol=unknown (never a guess).
#
# Offline by design: the dataset is baked into the image at build time
# (see Dockerfile), so this makes ZERO network calls and works air-gapped. The
# dataset path is $EOL_DATA_FILE, defaulting to eol-data.json beside this script;
# if it is absent (e.g. a build that did not bundle it) the step is skipped.
#
# Attribution: EOL dates are sourced from endoflife.date (bundled snapshot). The
# snapshot date is recorded on each flagged component as bomlens:eol:source.
set -e

SBOM="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[eol] SBOM file not found: $SBOM" >&2
    exit 1
fi
if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[eol] WARN: $SBOM is not valid JSON; skipping EOL enrichment" >&2
    exit 0
fi

MAP_FILE="$SCRIPT_DIR/eol-purl-map.json"
DATA_FILE="${EOL_DATA_FILE:-$SCRIPT_DIR/eol-data.json}"
if [ ! -f "$MAP_FILE" ]; then
    echo "[eol] WARN: eol-purl-map.json not found; skipping EOL enrichment" >&2
    exit 0
fi
if [ ! -f "$DATA_FILE" ]; then
    # No bundled endoflife snapshot (e.g. an image built without the EOL data
    # layer). Skip cleanly rather than fail — EOL is best-effort.
    echo "[eol] endoflife dataset not bundled ($DATA_FILE); skipping EOL enrichment" >&2
    exit 0
fi

RULES=$(jq -c '.rules // []' "$MAP_FILE" 2>/dev/null || echo '[]')
# Snapshot date the dataset was fetched (for attribution); falls back to "unknown".
SNAP=$(jq -r '._snapshot // "unknown"' "$DATA_FILE" 2>/dev/null || echo unknown)
TODAY=$(date -u +%Y-%m-%d)

TMP="$(mktemp)"
# EOL decision, per component:
#   cycle(version, gran): strip a leading 'v', keep the leading numeric segments
#     (1 for "major", 2 for "major.minor"); "" if no numeric lead (=> unknown).
#   eol field in the dataset is a date "YYYY-MM-DD", or a boolean. ISO dates
#   compare correctly with string < (lexicographic == chronological).
if jq --argjson rules "$RULES" \
      --slurpfile ds "$DATA_FILE" \
      --arg today "$TODAY" \
      --arg snap "$SNAP" '
  ($ds[0]) as $data
  | def norm_segs(v):
      ((v // "") | ltrimstr("v") | split(".")
        | map(capture("^(?<n>[0-9]+)").n // empty));
  def cycle_of(v; gran):
      (norm_segs(v)) as $s
      | if ($s | length) == 0 then null
        elif gran == "major" then $s[0]
        else (if ($s | length) >= 2 then ($s[0] + "." + $s[1]) else $s[0] end)
        end;
  def strip_eol_props:
      (.properties // []) | map(select((.name // "") | startswith("bomlens:eol") | not));
  def put(nm; val): [{name: nm, value: (val|tostring)}];

  (.components) |= (if type == "array" then map(
    (.purl // "") as $purl
    | ($rules | map(select(.purlPrefix as $p | $purl | startswith($p))) | first) as $rule
    | if ($rule == null) or ($purl == "")
      then .
      else
        (cycle_of(.version; $rule.cycle)) as $cyc
        | ($data[$rule.product] // []) as $cycles
        | (if $cyc == null then null
           else ($cycles | map(select((.cycle|tostring) == $cyc)) | first) end) as $entry
        | (if $entry == null then {state: "unknown", date: null}
           elif ($entry.eol | type) == "boolean"
             then {state: (if $entry.eol then "true" else "false" end), date: null}
           elif ($entry.eol | type) == "string"
             then {state: (if ($entry.eol < $today) then "true" else "false" end), date: $entry.eol}
           else {state: "unknown", date: null} end) as $v
        | .properties = (strip_eol_props
            + put("bomlens:eol"; $v.state)
            + put("bomlens:eol:product"; $rule.product)
            + (if $cyc != null then put("bomlens:eol:cycle"; $cyc) else [] end)
            + (if $v.date != null then put("bomlens:eol:date"; $v.date) else [] end)
            + put("bomlens:eol:source"; "endoflife.date@" + $snap))
      end
  ) else . end)
' "$SBOM" > "$TMP" 2>/dev/null; then
    E=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:eol" and .value=="true"))] | length' "$TMP" 2>/dev/null || echo 0)
    F=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:eol" and .value=="false"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    echo "[eol] flagged ${E} end-of-life and ${F} still-supported component(s) from endoflife.date@${SNAP}."
else
    rm -f "$TMP"
    echo "[eol] WARN: EOL enrichment jq failed; leaving SBOM unchanged" >&2
fi
