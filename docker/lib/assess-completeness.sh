#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# assess-completeness.sh - decide, in one place, whether a scan's result can be
# read as complete, and say why when it cannot.
#
# Usage: assess-completeness.sh <sbom.json> <out_prefix>
#   writes <out_prefix>_completeness.json and prints the grade on stdout.
#
# Why one place: the security report, the risk report, the NOTICE and the
# conformance check each used to read its own part of the SBOM, and an empty or
# partial SBOM came out of them as "no known vulnerabilities". They all read
# this file now (see report_completeness_load in report-common.sh), so a person
# who is handed a report alone is told the same thing the SBOM property says.
#
# Grades
#   complete    no reason found
#   partial     the result is usable but does not cover everything
#   unreliable  the source declares dependencies the scan did not resolve (a project
#               with nothing to declare and no component is only partial)
#
# Inputs, all read from the SBOM, so the verdict is a function of the document
# and a report run later (or on a copy) cannot disagree with the scan:
#   no component                                  (no-components, or
#                                                 no-components-supplied for a received
#                                                 SBOM, which is unreliable)
#   bomlens:sbom-supplied=true                    (a received SBOM; the converted document
#                                                 carries it). The one caller that reads
#                                                 the input before it is converted (the
#                                                 conformance check of --analyze) sets
#                                                 BOMLENS_SBOM_SUPPLIED=true for that call.
#                                                 The scan mode is not read: a Yocto build
#                                                 directory also runs as ANALYZE but its
#                                                 SBOM is generated here, not received.
#   bomlens:sbom-empty-with-manifests             (empty-with-manifests, or
#                                                 unsupported-build-system when every
#                                                 manifest is a vcpkg, Conan or CMake FetchContent one)
#   bomlens:sbom-empty-all-excluded              (only-excluded-dependencies: every declared
#                                                 dependency was left out as development-only
#                                                 or not deployed, so none is listed)
#   bomlens:sbom-tool-degraded                    (tool-degraded)
#   bomlens:pipeline-step-failed, for the steps that resolve dependencies
#                                                 (resolution-failed)
#   bomlens:lockfile-missing, bomlens:lockfile-corrupt (detect-lockfile-state.sh),
#   bomlens:source:versionPinning=unpinned        (lockfile-missing, lockfile-corrupt)
#   components of a package ecosystem no vulnerability source covers
#                                                 (unchecked-ecosystem)
#
# The file holds, per reason, a code and a sentence pair (en/ko) from
# completeness-reasons.json; the codes are the contract, the sentences are for
# people. The reports read the sentence in REPORT_LANG.
#
# Best-effort: a document that is not CycloneDX JSON gets no file (the exit code
# is 0 either way), because the reports treat a missing file as "not assessed".
set -e

SBOM="$1"
OUT_PREFIX="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REGISTRY="${BOMLENS_COMPLETENESS_REASONS:-$SCRIPT_DIR/completeness-reasons.json}"
COVERAGE="$SCRIPT_DIR/vuln-coverage.jq"

if [ -z "$SBOM" ] || [ -z "$OUT_PREFIX" ]; then
    echo "[completeness] usage: assess-completeness.sh <sbom.json> <out_prefix>" >&2
    exit 1
fi
OUT="${OUT_PREFIX}_completeness.json"
rm -f "$OUT"
if [ ! -f "$SBOM" ] || ! command -v jq >/dev/null 2>&1; then
    exit 0
fi
if [ ! -f "$REGISTRY" ] || [ ! -f "$COVERAGE" ]; then
    echo "[completeness] completeness-reasons.json or vuln-coverage.jq is missing beside $0; the image is incomplete. Fix: rebuild the scanner image." >&2
    exit 0
fi
# Only a CycloneDX document is read; an SPDX one has no components[] to count.
if ! jq -e '.bomFormat == "CycloneDX"' "$SBOM" >/dev/null 2>&1; then
    exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
# shellcheck disable=SC2016  # jq program, not shell
if ! jq --arg supplied_env "${BOMLENS_SBOM_SUPPLIED:-}" --slurpfile reg "$REGISTRY" "$(cat "$COVERAGE")"'
  # Text that comes from the document is cut to a short single line: a supplier
  # SBOM (--analyze) is not trusted, and these strings reach a terminal and HTML.
  def clean($n): (tostring | gsub("\\p{Cc}"; " ") | .[0:$n]);
  def prop($n): [(.metadata.properties // [])[]? | select(type == "object" and .name == $n) | .value | select(type == "string" and length > 0)];
  ($reg[0]) as $R
  | ([ .components[]? | recurse(.components[]?) ]) as $comps
  | (prop("bomlens:sbom-empty-with-manifests") | first // null) as $empty
  | (prop("bomlens:sbom-empty-all-excluded") | first // null) as $allexcl
  | (prop("bomlens:sbom-tool-degraded") | first // null) as $degraded
  | ([ prop("bomlens:pipeline-step-failed")[] | clean(100) | select(. as $s | ($R.resolutionSteps | index($s)) or any(($R.resolutionStepPrefixes // [])[]; . as $p | $s | startswith($p))) ]
       | unique | .[0:20]) as $failed
  | (([ prop("bomlens:lockfile-missing")[] | clean(200) ])
       + (if any((.metadata.component.properties // [])[]?; .name == "bomlens:source:versionPinning" and .value == "unpinned")
            and (prop("bomlens:lockfile-missing") | length == 0)
          then ["version ranges without a lock file"] else [] end)) as $nolock
  | (([ prop("bomlens:lockfile-missing")[] | clean(200) ])
       + (if any((.metadata.component.properties // [])[]?; .name == "bomlens:source:versionPinning" and .value == "unpinned")
            and (prop("bomlens:lockfile-missing") | length == 0)
          then ["락 파일 없이 버전 범위만 선언됨"] else [] end)) as $nolock_ko
  | ([ prop("bomlens:lockfile-corrupt")[] | clean(200) ]) as $corrupt
  | ([ $comps[] | select(vc_unsupported_ecosystem) | vc_purl_type ]
       | group_by(.) | map({ecosystem: .[0], count: length})) as $unsup
  | ((.metadata.component.type // "") | IN("machine-learning-model", "data")) as $model_root
  | ((prop("bomlens:sbom-supplied") | first // "") == "true" or $supplied_env == "true") as $supplied
  | ($empty != null and ($empty | split(",") | map(gsub("^\\s+|\\s+$"; "") | split("/") | last)
        | all(.[]; test("^(vcpkg\\.json|conanfile\\.(txt|py)|CMakeLists\\.txt)$")))) as $cpp_only
  | ([
      (if ($comps | length) == 0 and ($empty == null) and ($allexcl == null) and ($model_root | not)
         then {code: (if $supplied then "no-components-supplied" else "no-components" end), detail: ""} else empty end),
      (if $allexcl != null and $empty == null then {code: "only-excluded-dependencies", detail: ($allexcl | clean(200))} else empty end),
      (if $empty != null then {code: (if $cpp_only then "unsupported-build-system" else "empty-with-manifests" end), detail: ($empty | clean(200))} else empty end),
      (if $degraded != null then {code: "tool-degraded", detail: ($degraded | clean(100))} else empty end),
      (if ($failed | length) > 0 then {code: "resolution-failed", detail: ($failed | join(", "))} else empty end),
      (if ($nolock | length) > 0 then {code: "lockfile-missing", detail: ($nolock | join("; ") | .[0:200]), detailKo: ($nolock_ko | join("; ") | .[0:200])} else empty end),
      (if ($corrupt | length) > 0 then {code: "lockfile-corrupt", detail: ($corrupt | join("; ") | .[0:200])} else empty end),
      (if ($unsup | length) > 0 then {code: "unchecked-ecosystem", detail: ($unsup | map("\(.ecosystem): \(.count)") | join(", "))} else empty end)
    ]
    | map(. as $r | ($R.reasons[$r.code]) as $d
          | {code: $r.code,
             grade: (if $r.code == "lockfile-corrupt" and ($comps | length) == 0 then "unreliable" else $d.grade end),
             detail: $r.detail,
             message: {en: ($d.en | sub("\\{detail\\}"; $r.detail)), ko: ($d.ko | sub("\\{detail\\}"; ($r.detailKo // $r.detail)))},
             fix: {en: $d.fixEn, ko: $d.fixKo}})) as $reasons
  | (if ($reasons | any(.[]; .grade == "unreliable")) then "unreliable"
     elif ($reasons | length) > 0 then "partial" else "complete" end) as $grade
  | {schemaVersion: 1,
     grade: $grade,
     gradeLabel: $R.grades[$grade],
     componentCount: ($comps | length),
     reasons: $reasons,
     uncheckedEcosystems: $unsup}
' "$SBOM" > "$TMP" 2>/dev/null; then
    echo "[completeness] WARN: could not assess $SBOM; no completeness result was written." >&2
    exit 0
fi
mv "$TMP" "$OUT"
trap - EXIT
jq -r '.grade' "$OUT"
