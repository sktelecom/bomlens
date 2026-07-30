#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-malicious.sh — flag components that are known-malicious packages, fully
# OFFLINE, using a bundled OSV snapshot.
#
# Usage: enrich-malicious.sh <sbom.json>
#
# Why this is not just another vulnerability: a CVE says an honest package has a
# flaw you can patch. A malicious package was published to attack whoever
# installs it — typosquats, hijacked maintainer accounts, install-time payloads.
# The response is removal and credential rotation, not an upgrade, so it is
# reported as its own signal rather than another row in the severity table.
#
# How (mirrors enrich-eol.sh's accuracy-first approach):
#   1. Match by PURL, never by name. Malicious packages are deliberately named to
#      resemble real ones, so a name match is exactly the wrong tool here.
#   2. A PURL in the index means every published version is malicious — which is
#      the usual case (of 232,687 indexed packages, 29,038 name specific
#      versions). When the advisory did name versions, the component's version
#      must be among them; otherwise it is not flagged.
#   3. No entry, no purl, or no bundled index => nothing is stamped. An absent
#      property means "not assessed", never "clean".
#
# Offline by design: the dataset is baked into the image at build time (see
# Dockerfile / build-malicious-index.py), so this makes ZERO network calls and
# works air-gapped. The dataset path is $MALICIOUS_DATA_FILE, defaulting to
# malicious-index.json beside this script; if it is absent (a build that did not
# bundle it) the step is skipped cleanly.
#
# Freshness caveat: malicious-package reporting moves fast, so the snapshot date
# is stamped on every flagged component (bomlens:malicious:source) and shown in
# the reports. A clean result means "not in the snapshot", not "safe today".
set -e

SBOM="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[malicious] SBOM file not found: $SBOM" >&2
    exit 1
fi
if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[malicious] WARN: $SBOM is not valid JSON; skipping malicious-package check" >&2
    exit 0
fi

DATA_FILE="${MALICIOUS_DATA_FILE:-$SCRIPT_DIR/malicious-index.json}"
if [ ! -f "$DATA_FILE" ]; then
    # No bundled snapshot (e.g. an image built without the malicious-index layer).
    # Skip cleanly rather than fail — the check is best-effort, never a blocker.
    echo "[malicious] OSV malicious snapshot not bundled ($DATA_FILE); skipping check" >&2
    exit 0
fi

SNAP=$(jq -r '._snapshot // "unknown"' "$DATA_FILE" 2>/dev/null || echo unknown)

TMP="$(mktemp)"
# Per component: look its purl up in the index. The purl is used verbatim — OSV
# writes the same "pkg:<type>/<name>@<version>" form BomLens carries, minus the
# version, so the lookup key is the purl with any version and qualifiers removed.
if jq --slurpfile ds "$DATA_FILE" --arg snap "$SNAP" '
  ($ds[0]) as $data
  | def base_purl(p):
      # "pkg:npm/left-pad@1.3.0?arch=x64" -> "pkg:npm/left-pad". Qualifiers and
      # the fragment go first, then the version, leaving the key OSV indexes by.
      ((p // "")
        | if . == "" then ""
          else sub("[?#].*$"; "")
               | if test("@") then .[0:(rindex("@"))] else . end
          end);
  def strip_props:
      (.properties // []) | map(select(((.name // "")) as $n
        | ($n | startswith("bomlens:malicious")) | not));
  (.components) |= (if type == "array" then map(
    (base_purl(.purl)) as $key
    | (if $key == "" then null else ($data.packages[$key] // null) end) as $mal
    | if $mal == null then .
      else
        # Versions are listed only when a subset of releases is malicious; with
        # no list every published version is, which is the common case.
        (($data.versions[$key]) // null) as $vers
        | (.version // "") as $cv
        | (if $vers == null then true
           else (($vers | index($cv)) != null) end) as $hit
        | if $hit | not then .
          else
            .properties = (strip_props
              + [{name: "bomlens:malicious", value: "true"},
                 {name: "bomlens:malicious:id", value: $mal},
                 {name: "bomlens:malicious:source", value: ("osv.dev@" + $snap)}])
          end
      end
  ) else . end)
' "$SBOM" > "$TMP" 2>/dev/null; then
    N=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:malicious" and .value=="true"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    if [ "$N" -gt 0 ]; then
        echo "[malicious] flagged ${N} known-malicious package(s) from osv.dev@${SNAP}. Remove them and rotate any credentials the build could reach."
    else
        echo "[malicious] no known-malicious packages in this SBOM (osv.dev@${SNAP})."
    fi
else
    rm -f "$TMP"
    echo "[malicious] WARN: malicious-package jq failed; leaving SBOM unchanged" >&2
fi
