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
#                                                 or not deployed, so none is listed; a value
#                                                 "<package.json> devDependencies: <names>"
#                                                 is a manifest that declares nothing else,
#                                                 and gets the fix fixEnDevOnly)
#   bomlens:sbom-tool-degraded                    (tool-degraded)
#   bomlens:pipeline-step-failed, for the steps that resolve dependencies
#                                                 (resolution-failed), with
#   bomlens:pipeline-step-cause ("<step>: <what the build tool reported>")
#                                                 and bomlens:resolution-hint (a
#                                                 code in resolutionHints: a cause
#                                                 with its own sentence and fix,
#                                                 which may raise the grade)
#   bomlens:lockfile-missing, bomlens:lockfile-corrupt (detect-lockfile-state.sh),
#   bomlens:source:versionPinning=unpinned        (lockfile-missing, lockfile-corrupt; the
#                                                 fix names the command that writes each
#                                                 missing lock file, from lockCommands)
#   bomlens:manifest-not-read (detect-lockfile-state.sh)
#                                                 (manifest-not-read: a vcpkg.json or
#                                                 conanfile.py whose dependencies are not in
#                                                 the SBOM; left out when the SBOM is empty,
#                                                 which unsupported-build-system already says)
#   bomlens:python-environment-unsure             (installed-environment-unsure: the Python
#                                                 part was read from an installed environment
#                                                 and some of it could not be settled)
#   bomlens:vulnerability-check-failed            (vulnerability-check-failed: the security
#                                                 scan was asked for and did not run or
#                                                 failed; the value says why). Stamped by
#                                                 entrypoint.sh after the scan
#                                                 (mark_vulnerability_check in
#                                                 pipeline-step.sh) and removed before the
#                                                 conformance check, so a scan with
#                                                 --no-security never carries it. Two callers
#                                                 judge without that stamp and pass the fact
#                                                 in BOMLENS_VULNERABILITY_CHECK_FAILED: the
#                                                 security report of the failed scan itself,
#                                                 and the refreshed conformance check of
#                                                 --analyze, which reads the input as
#                                                 received (with BOMLENS_SBOM_SUPPLIED=true the
#                                                 input's own stamp, a supplier's run, is not read).
#                                                 A Trivy database that is only old is not a
#                                                 reason: the check ran against it.
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
if ! jq --arg supplied_env "${BOMLENS_SBOM_SUPPLIED:-}" --arg vuln_env "${BOMLENS_VULNERABILITY_CHECK_FAILED:-}" --slurpfile reg "$REGISTRY" "$(cat "$COVERAGE")"'
  # Text that comes from the document is cut to a short single line: a supplier
  # SBOM (--analyze) is not trusted, and these strings reach a terminal and HTML.
  def clean($n): (tostring | gsub("\\p{Cc}"; " ") | .[0:$n]);
  def sentence: if test("[.!?]$") then . else . + "." end;
  def prop($n): [(.metadata.properties // [])[]? | select(type == "object" and .name == $n) | .value | select(type == "string" and length > 0)];
  ($reg[0]) as $R
  | ([ .components[]? | recurse(.components[]?) ]) as $comps
  | (prop("bomlens:sbom-empty-with-manifests") | first // null) as $empty
  | (prop("bomlens:sbom-empty-all-excluded") | first // null) as $allexcl
  | (prop("bomlens:sbom-tool-degraded") | first // null) as $degraded
  | ([ prop("bomlens:pipeline-step-failed")[] | clean(100) | select(. as $s | ($R.resolutionSteps | index($s)) or any(($R.resolutionStepPrefixes // [])[]; . as $p | $s | startswith($p))) ]
       | unique | .[0:20]) as $failed
  | ([ prop("bomlens:pipeline-step-cause")[] | clean(400)
       | select(. as $c | any($failed[]; . as $s | $c | startswith($s + ": ")))
       | sub("^[^:]+: "; "") | .[0:300] ] | unique | .[0:3]) as $causes
  | (prop("bomlens:resolution-hint")) as $hint_props
  | ([ ($R.resolutionHints // {}) | keys_unsorted[] | select(. as $k | $hint_props | index($k)) ]) as $hints
  | (([ prop("bomlens:lockfile-missing")[] | clean(200) ])
       + (if any((.metadata.component.properties // [])[]?; .name == "bomlens:source:versionPinning" and .value == "unpinned")
            and (prop("bomlens:lockfile-missing") | length == 0)
          then ["version ranges without a lock file"] else [] end)) as $nolock
  | (([ prop("bomlens:lockfile-missing")[] | clean(200) ])
       + (if any((.metadata.component.properties // [])[]?; .name == "bomlens:source:versionPinning" and .value == "unpinned")
            and (prop("bomlens:lockfile-missing") | length == 0)
          then ["락 파일 없이 버전 범위만 선언됨"] else [] end)) as $nolock_ko
  # The command that writes each missing lock file, for the fix sentence: the
  # lock named in "go.mod: no go.sum", a value that is the lock name itself, and
  # for version ranges without a lock file the package types the SBOM holds.
  | ($R.reasons["lockfile-missing"].lockCommands // {}) as $LC
  | ([ (prop("bomlens:lockfile-missing")[] | split("; ")[] | (capture(": no (?<l>[^ ]+)$").l // .)),
       (if any((.metadata.component.properties // [])[]?; .name == "bomlens:source:versionPinning" and .value == "unpinned")
          then ($comps[] | (.purl // "") | strings | capture("^pkg:(?<t>[a-z]+)/").t) else empty end) ]
     | map($LC[.] // empty)
     | reduce .[] as $c ([]; if any(.[]; . == $c) then . else . + [$c] end)) as $lockcmds
  | ([ prop("bomlens:lockfile-corrupt")[] | clean(200) ]) as $corrupt
  | (prop("bomlens:manifest-not-read") | first // null) as $notread
  | (prop("bomlens:python-environment-unsure") | first // null) as $venv_unsure
  # The input of --analyze as received (BOMLENS_SBOM_SUPPLIED=true) may carry
  # the stamp of the run of the supplier, which says nothing about this one.
  | (if $vuln_env != "" then $vuln_env
     elif $supplied_env == "true" then null
     else (prop("bomlens:vulnerability-check-failed") | first // null) end) as $vuln_failed
  | ([ $comps[] | select(vc_unsupported_ecosystem) | vc_purl_type ]
       | group_by(.) | map({ecosystem: .[0], count: length})) as $unsup
  | ((.metadata.component.type // "") | IN("machine-learning-model", "data")) as $model_root
  | ((prop("bomlens:sbom-supplied") | first // "") == "true" or $supplied_env == "true") as $supplied
  | ($empty != null and ($empty | split(",") | map(gsub("^\\s+|\\s+$"; "") | split("/") | last)
        | all(.[]; test("^(vcpkg\\.json|conanfile\\.(txt|py)|CMakeLists\\.txt)$")))) as $cpp_only
  | ([
      (if ($comps | length) == 0 and ($empty == null) and ($allexcl == null) and ($model_root | not)
         then {code: (if $supplied then "no-components-supplied" else "no-components" end), detail: ""} else empty end),
      (if $allexcl != null and $empty == null then {code: "only-excluded-dependencies", detail: ($allexcl | clean(200)), devOnly: ($allexcl | test(" devDependencies: "))} else empty end),
      (if $empty != null then {code: (if $cpp_only then "unsupported-build-system" else "empty-with-manifests" end), detail: ($empty | clean(200))} else empty end),
      (if $degraded != null then {code: "tool-degraded", detail: ($degraded | clean(100)), hints: [$hints[] | $R.resolutionHints[.] | select(.reason == "tool-degraded")]} else empty end),
      (if ($failed | length) > 0 then {code: "resolution-failed", detail: ($failed | join(", ")), causes: $causes, hints: [$hints[] | $R.resolutionHints[.] | select(.reason == null)]} else empty end),
      (if ($nolock | length) > 0 then {code: "lockfile-missing", detail: ($nolock | join("; ") | .[0:200]), detailKo: ($nolock_ko | join("; ") | .[0:200])} else empty end),
      (if ($corrupt | length) > 0 then {code: "lockfile-corrupt", detail: ($corrupt | join("; ") | .[0:200])} else empty end),
      (if $notread != null and $empty == null then {code: "manifest-not-read", detail: ($notread | clean(200))} else empty end),
      (if $venv_unsure != null then {code: "installed-environment-unsure", detail: ($venv_unsure | clean(200))} else empty end),
      (if $vuln_failed != null then {code: "vulnerability-check-failed", detail: ($vuln_failed | clean(200))} else empty end),
      (if ($unsup | length) > 0 then {code: "unchecked-ecosystem", detail: ($unsup | map("\(.ecosystem): \(.count)") | join(", "))} else empty end)
    ]
    # A failed step may carry the cause the build tool reported and hints,
    # causes with a fix of their own (resolutionHints): the message names
    # them and the fix is theirs in place of the general advice. A hint may
    # also raise the grade (a result whose dependencies are not known at all).
    | map(. as $r | ($R.reasons[$r.code]) as $d
          | ($r.hints // []) as $rh
          # A hint marked general (its fix is "fix the build error and scan
          # again") gives its fix only when no other hint names a specific one:
          # the specific fix already ends in "scan again". Its message stays.
          | (($rh | map(select(.general != true))) as $specific
             | if ($specific | length) > 0 then $specific else $rh end) as $rhfix
          | (($r.causes // []) | map(sentence) | join(" ")) as $cause
          | {code: $r.code,
             grade: (if $r.code == "lockfile-corrupt" and ($comps | length) == 0 then "unreliable"
                     elif any($rh[]; .grade == "unreliable") then "unreliable"
                     else $d.grade end),
             detail: $r.detail,
             message: {en: ([($d.en | sub("\\{detail\\}"; $r.detail)), ($rh[] | .en), (if $cause != "" then "\($R.labels.cause.en) \($cause)" else empty end)] | join(" ")),
                       ko: ([($d.ko | sub("\\{detail\\}"; ($r.detailKo // $r.detail))), ($rh[] | .ko), (if $cause != "" then "\($R.labels.cause.ko) \($cause)" else empty end)] | join(" "))},
             fix: (if ($r.devOnly // false) and $d.fixEnDevOnly != null
                   then {en: $d.fixEnDevOnly, ko: $d.fixKoDevOnly}
                   elif $r.code == "lockfile-missing" and ($lockcmds | length) > 0 and $d.fixEnCommands != null
                   then {en: ($d.fixEnCommands | sub("\\{commands\\}"; $lockcmds | join(", "))),
                         ko: ($d.fixKoCommands | sub("\\{commands\\}"; $lockcmds | join(", ")))}
                   else {en: ([(if $cause != "" then "\($R.labels.cause.en) \($cause)" else empty end), (if ($rhfix | length) > 0 then ($rhfix[] | .fixEn) else $d.fixEn end)] | join(" ")),
                         ko: ([(if $cause != "" then "\($R.labels.cause.ko) \($cause)" else empty end), (if ($rhfix | length) > 0 then ($rhfix[] | .fixKo) else $d.fixKo end)] | join(" "))} end)})) as $reasons
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
