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
#   2. A PURL in the index means every published version is malicious in the
#      usual case (a typosquat, a hijacked account). When the advisory instead
#      names specific versions, the component's version must be among them.
#      When it gives a SEMVER/ECOSYSTEM range instead (introduced/fixed/
#      last_affected, the common shape for a compromised-then-patched
#      release), the component's version is compared against that range
#      rather than assumed malicious just for sharing the PURL. A version the
#      comparison cannot parse is left unflagged and marked
#      bomlens:malicious:rangeUnknown instead of guessing either way.
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
# shellcheck source=docker/lib/pipeline-step.sh
. "$SCRIPT_DIR/pipeline-step.sh"

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
    # Stamped on the document (not a component): a reader of the SBOM must be
    # able to tell "the index was missing" from "checked, nothing in the
    # snapshot" — an absent index otherwise looks identical to a clean result.
    echo "[malicious] OSV malicious snapshot not bundled ($DATA_FILE); skipping check" >&2
    mark_document_status "$SBOM" "bomlens:malicious-check-unavailable" \
        "OSV malicious-package index not built into this image"
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

  # Plain dotted-numeric comparison (major.minor.patch...), pre-release/build
  # metadata (the "-beta.1" / "+build" suffix) stripped and the numeric core
  # compared instead of ordered against it. Anything that is not plain dotted
  # digits after stripping (a Go pseudo-version, a distro epoch, a non-numeric
  # segment) cannot be compared at all, and ver_cmp says so by returning null
  # rather than guessing.
  def ver_ok(v):
      (v // "" | sub("[-+].*$"; "") | split(".")) as $parts
      | ($parts | length) > 0 and ($parts | all(test("^[0-9]+$")));
  def ver_tuple(v):
      (v | sub("[-+].*$"; "") | split(".") | map(tonumber));
  def has_suffix(v): (v // "") | test("[-+]");
  # -1, 0, 1, or null when the numeric cores cannot be told apart (see ver_ok
  # above) OR when they tie but at least one side carries a pre-release/build
  # suffix. That second case matters at a range boundary: stripped down to its
  # numeric core, "1.2.11-beta" reads as equal to a "fixed": "1.2.11" event,
  # but semver orders a pre-release BEFORE the release it precedes, so
  # "1.2.11-beta" is still inside the affected window right up to the fix,
  # not past it. Rather than pick a direction on a stripped comparison that
  # cannot see the suffix, an exact tie with a suffix on either side is left
  # unresolved and range_hits below turns that into rangeUnknown, the same
  # "do not guess" treatment as a version ver_ok cannot parse at all.
  def ver_cmp(a; b):
      if (ver_ok(a) and ver_ok(b)) then
        (ver_tuple(a)) as $ta | (ver_tuple(b)) as $tb
        | ([$ta, $tb] | map(length) | max) as $n
        | ([range(0;$n)] | map(($ta[.] // 0) - ($tb[.] // 0)) | map(select(. != 0)) | .[0]) as $d
        | if $d == null and (has_suffix(a) or has_suffix(b)) then null
          else ($d // 0) | (if . > 0 then 1 elif . < 0 then -1 else 0 end)
          end
      else null
      end;

  # Replay one OSV range block'"'"'s events (introduced/fixed/last_affected,
  # in the order OSV lists them) against the component version, the same
  # event-log semantics OSV itself defines. "limit" events are not used by
  # any bundled advisory today and are ignored rather than guessed at.
  def range_hits($cv; $events):
      reduce $events[] as $ev
        ({affected: false, unknown: false};
         if .unknown then .
         elif ($ev.introduced != null) then
           (ver_cmp($cv; $ev.introduced)) as $c
           | if $c == null then .unknown = true
             elif $ev.introduced == "0" or $c >= 0 then .affected = true
             else . end
         elif ($ev.fixed != null) then
           if .affected then
             (ver_cmp($cv; $ev.fixed)) as $c
             | if $c == null then .unknown = true
               elif $c >= 0 then .affected = false
               else . end
           else . end
         elif ($ev.last_affected != null) then
           if .affected then
             (ver_cmp($cv; $ev.last_affected)) as $c
             | if $c == null then .unknown = true
               elif $c > 0 then .affected = false
               else . end
           else . end
         else . end);
  # "malicious" (affected by at least one range block), "clean" (in none),
  # or "unknown" (a version the ranges could not be compared against).
  def range_verdict($cv; $ranges):
      ($ranges | map(range_hits($cv; .))) as $hits
      | if ($hits | any(.affected and (.unknown | not))) then "malicious"
        elif ($hits | any(.unknown)) then "unknown"
        else "clean"
        end;

  (.components) |= (if type == "array" then map(
    (base_purl(.purl)) as $key
    | (if $key == "" then null else ($data.packages[$key] // null) end) as $mal
    | if $mal == null then .
      else
        # Versions are listed only when a subset of releases is malicious; with
        # neither a version list nor a range, every published version is,
        # which is the common case (typosquats, hijacked accounts).
        (($data.versions[$key]) // null) as $vers
        | (($data.ranges[$key]) // null) as $ranges
        | (.version // "") as $cv
        | (if $vers != null then (if ($vers | index($cv)) != null then "malicious" else "clean" end)
           elif $ranges != null then range_verdict($cv; $ranges)
           else "malicious"
           end) as $verdict
        | if $verdict == "clean" then .
          elif $verdict == "malicious" then
            .properties = (strip_props
              + [{name: "bomlens:malicious", value: "true"},
                 {name: "bomlens:malicious:id", value: $mal},
                 {name: "bomlens:malicious:source", value: ("osv.dev@" + $snap)}])
          else
            # Not a confirmed verdict: the advisory names a version range but
            # this component'"'"'s own version could not be compared against it.
            # Surfaced separately from bomlens:malicious so a reader does not
            # read "not flagged" as "confirmed clean".
            .properties = (strip_props
              + [{name: "bomlens:malicious:rangeUnknown", value: "true"},
                 {name: "bomlens:malicious:id", value: $mal},
                 {name: "bomlens:malicious:source", value: ("osv.dev@" + $snap)}])
          end
      end
  ) else . end)
' "$SBOM" > "$TMP" 2>/dev/null; then
    N=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:malicious" and .value=="true"))] | length' "$TMP" 2>/dev/null || echo 0)
    U=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:malicious:rangeUnknown" and .value=="true"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    if [ "$N" -gt 0 ]; then
        echo "[malicious] flagged ${N} known-malicious package(s) from osv.dev@${SNAP}. Remove them and rotate any credentials the build could reach."
    else
        echo "[malicious] no known-malicious packages in this SBOM (osv.dev@${SNAP})."
    fi
    if [ "$U" -gt 0 ]; then
        echo "[malicious] ${U} component(s) matched a range-limited advisory but could not be compared to it (unusual version format); not flagged, see bomlens:malicious:rangeUnknown."
    fi
else
    rm -f "$TMP"
    echo "[malicious] WARN: malicious-package jq failed; leaving SBOM unchanged" >&2
fi
