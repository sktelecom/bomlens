#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# assess-ai-risk.sh — stamp every machine-learning-model and data component
# with a usability verdict (bomlens:assessment:*) derived from the curated
# license-terms registry (ai-risk-knowledge.json). Offline, pure
# post-processing: it reads nothing but the SBOM and the registry, so it runs
# after normalize-sbom.sh (SPDX ids in place) and before validate-sbom.sh.
#
# Verdicts: ok | conditional | caution | review, worst-of ranked
# caution > review > conditional > ok — a known blocker outranks an unknown,
# an unknown outranks known-conditional (the same "never read unknown as safe"
# rule as bomlens:licenseClass). A license the registry does not know falls to
# review, never to a guess. Later axes (file security, dataset signals) append
# to bomlens:assessment:axes; overall is the worst verdict across the axes
# that were actually evaluated.
#
# The verdict is guidance, not legal advice — every report that prints it must
# carry the registry's disclaimer. Idempotent: previous bomlens:assessment:*
# properties are dropped and re-appended at a fixed position, so re-runs and
# --byte-stable output stay byte-identical.
#
# Usage: assess-ai-risk.sh <sbom.json>
#   env AI_RISK_KNOWLEDGE  override the registry path (tests)
set -e

SBOM="$1"
KB="${AI_RISK_KNOWLEDGE:-$(dirname "$0")/ai-risk-knowledge.json}"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[assess] SBOM not found: ${SBOM:-<missing>} (usage: assess-ai-risk.sh <sbom.json>)" >&2
    exit 1
fi
if [ ! -f "$KB" ]; then
    echo "[assess] license-terms registry not found ($KB); skipping." >&2
    exit 0
fi

# Self-gate: only an SBOM that carries a model component gets assessed, so
# ANALYZE over a plain dependency SBOM is a clean no-op.
if ! jq -e '[.components[]? | select(.type=="machine-learning-model")] | length > 0' "$SBOM" >/dev/null 2>&1; then
    echo "[assess] no machine-learning-model component; skipping."
    exit 0
fi

TMP=$(mktemp)
jq --slurpfile kb "$KB" '
  $kb[0].licenseTerms as $terms

  # Same normalization as the registry match contract (and license-flags.jq):
  # lowercase, runs of space/dot/underscore/slash/dash collapse to one space.
  | def norm($s): (($s // "") | ascii_downcase | gsub("[ ._/-]+"; " ")
                   | sub("^ +"; "") | sub(" +$"; ""));
  def vrank: {"caution": 4, "review": 3, "conditional": 2, "ok": 1};

  # First entry whose ids match exactly, else the first whose regex matches —
  # in registry file order (specific families come before generic ones there).
  def match_entry($lic):
    norm($lic) as $n
    | ( first($terms[] | select(any(.ids[]?; norm(.) == $n)))
        // first($terms[] | select((.match // "") as $m
                                   | ($m != "") and (($n | test($m)) // false)))
        // null );

  def lic_strings:
    [ (.licenses // [])[] | (.license.id // .license.name // .expression // "")
      | select(. != "") ];

  # License axis for one component: worst verdict across its licenses, the
  # matched registry keys, and one human-readable reason per license.
  def assess_license:
    lic_strings as $ls
    | if ($ls | length) == 0 then
        { verdict: "review", keys: [],
          reasons: ["no license declared (review)"] }
      else
        [ $ls[] | . as $l | (match_entry($l)) as $e
          | if $e == null then
              { v: "review", k: null,
                r: "license \($l): not in the license-terms registry (review)" }
            else
              { v: $e.verdict, k: $e.key,
                r: "license \($l): \($e.name) (\($e.verdict))" }
            end ] as $per
        | { verdict: ($per | map(.v) | max_by(vrank[.])),
            keys:    ($per | map(.k) | map(select(. != null)) | unique),
            reasons: ($per | map(.r)) }
      end;

  def strip_assessment:
    (.properties // []) | map(select(.name | startswith("bomlens:assessment:") | not));

  (.components) |= (if type == "array" then map(
      if (.type == "machine-learning-model" or .type == "data") then
        (assess_license) as $a
        | .properties = (strip_assessment + [
            { name: "bomlens:assessment:axes",         value: "license" },
            { name: "bomlens:assessment:license",      value: $a.verdict },
            { name: "bomlens:assessment:license:keys", value: ($a.keys | join(",")) },
            { name: "bomlens:assessment:overall",      value: $a.verdict },
            { name: "bomlens:assessment:reasons",      value: ($a.reasons[0:8] | join("; ")) }
          ])
      else . end
  ) else . end)
' "$SBOM" > "$TMP"
mv "$TMP" "$SBOM"

COUNTS=$(jq -r '
  [ .components[]? | select(.type=="machine-learning-model" or .type=="data")
    | ((.properties // [])[] | select(.name=="bomlens:assessment:overall") | .value) ]
  | group_by(.) | map("\(.[0])=\(length)") | join(" ")' "$SBOM")
echo "[assess] stamped bomlens:assessment:* (${COUNTS:-none})"
