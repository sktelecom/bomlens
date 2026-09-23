#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# evaluate-gate.sh — judge the --fail-on conditions against what this scan produced.
#
# Usage: evaluate-gate.sh <sbom.json> <out_prefix> <condition>[,<condition>...]
#
# Writes <out_prefix>_gate.result, one line per condition:
#
#     <status><TAB><condition><TAB><detail>
#
# with status one of
#     met       the condition holds (the gate should fail)
#     ok        the condition was judged and does not hold
#     unjudged  there is not enough in this scan to judge it
#
# scripts/scan-sbom.sh reads that file and turns it into the exit code, so the
# host needs no jq. The conditions are a closed list, on purpose: each one reads a
# fact this scan already records, and a new one needs a reason written down.
#
#     vulnerability=<critical|high|medium|low>
#         any finding in <out_prefix>_security.json at that severity or worse,
#         counted the way the security report counts them: one per (purl or name,
#         id), and with the kernel's advisories left out (they are reported on
#         their own, and an old kernel carries thousands). UNKNOWN never counts.
#         A finding wins over an error: if findings are listed the condition is
#         met even when the run also recorded a ScanError. With none listed, a
#         missing report or a ScanError is unjudged (a failed vulnerability-
#         database download must not read as "no vulnerabilities", which is what
#         an air-gapped run would otherwise look like).
#     malicious-package
#         any component flagged bomlens:malicious. The property is absent when the
#         bundled snapshot is missing or the check was turned off, and absent
#         means "not assessed", so that case is unjudged, not ok. So is a component
#         that matched an advisory whose version range could not be compared
#         (bomlens:malicious:rangeUnknown), and a run whose check recorded that it
#         was unavailable or failed.
#     license-conflict
#         any component whose bomlens:licenseConflict verdict is "incompatible"
#         with the license the product is distributed under. Verdicts exist only
#         when the SBOM's root declares that license (--license sets it for source
#         and rootfs scans; a supplier SBOM carries its own), so without one this
#         is unjudged, and so is a run whose compatibility step recorded nothing.
#         Components whose verdict is "unknown" are counted in the detail.
#
#     empty-result
#         the scan identified no software: no component is left once the
#         operating-system and file entries are set aside (a rootfs or image scan
#         that named no package is empty even though it lists files). Read from the
#         conformance report's own `emptyResult` signal (validate-sbom.sh), not
#         recounted here. Unjudged when the scan wrote no conformance report or the
#         report carries no such signal (SPDX 3.0 that could not be converted). Not
#         offered for AI model and dataset inputs (the CLI refuses it).
#     license-coverage=<pct>
#         fewer than <pct> percent of those same components declare a license
#         (NOASSERTION and NONE are not declarations), the percentage rounded down.
#         Read from the report's `licenseCoverage` signal, which is separate from
#         its license check, so that check and the conformance verdict are
#         untouched. Unjudged when there is no conformance report or no signal, and
#         when there is nothing to measure (no such components); an empty result is
#         what empty-result is for.
#
# The result file is written in one piece and holds exactly one line per
# condition asked for, so a reader can tell a complete judgement from a cut-off
# one.
set -u

SBOM="${1:-}"; OUT_PREFIX="${2:-}"; CONDITIONS="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT="${OUT_PREFIX}_gate.result"
PARTIAL="${RESULT}.tmp.$$"
SECURITY="${OUT_PREFIX}_security.json"
CONFORMANCE="${OUT_PREFIX}_conformance.json"

if [ -z "$SBOM" ] || [ -z "$OUT_PREFIX" ] || [ ! -f "$SBOM" ]; then
    echo "[gate] usage: evaluate-gate.sh <sbom.json> <out_prefix> <conditions>" >&2
    exit 2
fi

rm -f "$RESULT"
: > "$PARTIAL"
trap 'rm -f "$PARTIAL"' EXIT
emit() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$PARTIAL"; }

# Whether each input can be read at all. An unreadable file says nothing about
# what it holds, so every condition that needs it is unjudged rather than ok.
SBOM_READABLE=1; jq empty "$SBOM" >/dev/null 2>&1 || SBOM_READABLE=0
unreadable_sbom() { # <cond> -> emits and returns 0 when the SBOM cannot be read
    [ "$SBOM_READABLE" -eq 1 ] && return 1
    emit unjudged "$1" "the SBOM could not be read"; return 0
}

# Up to five "name@version" labels, for the detail column. The selector is one of
# this file's own constants, never input.
labels() { # <jq selector over .components[]>
    jq -r '[ .components[]? | select('"$1"') | ((.name // "?") + "@" + (.version // "?")) ] | .[0:5] | join(", ")' "$SBOM" 2>/dev/null
}
count_components() { # <jq selector> -> a number, or empty when jq failed
    jq '[ .components[]? | select('"$1"') ] | length' "$SBOM" 2>/dev/null
}
is_number() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; esac; return 0; }

# A document-level status the pipeline stamped: the check did not run or failed.
step_problem() { # <step label> <status property name or ""> -> prints why, if any
    jq -r --arg step "$1" --arg prop "$2" '
        (.metadata.properties // []) as $p
        | if ($prop != "") and ($p | any(.name == $prop)) then "the step recorded that it was unavailable"
          elif $p | any(.name == "bomlens:pipeline-step-failed" and .value == $step) then "the step failed during this scan"
          else empty end' "$SBOM" 2>/dev/null
}

KERNEL_NAMES='["linux_kernel","linux-kernel","kernel","linux"]'

judge_vulnerability() { # <cond> <severity>
    local cond="$1" sev set count kernel err
    sev="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"
    case "$sev" in
        CRITICAL) set='["CRITICAL"]' ;;
        HIGH)     set='["CRITICAL","HIGH"]' ;;
        MEDIUM)   set='["CRITICAL","HIGH","MEDIUM"]' ;;
        LOW)      set='["CRITICAL","HIGH","MEDIUM","LOW"]' ;;
        *) emit unjudged "$cond" "unknown severity '$2'"; return ;;
    esac
    if [ ! -f "$SECURITY" ]; then
        emit unjudged "$cond" "no security report was produced for this scan"; return
    fi
    if ! jq empty "$SECURITY" >/dev/null 2>&1; then
        emit unjudged "$cond" "the security report could not be read"; return
    fi
    # The same view of the findings as the report and the web screen: one per
    # (purl or name, id), the kernel's advisories counted apart from the rest.
    local unique='[ .Results[]?.Vulnerabilities[]?
        | { sev: (.Severity // ""), pkg: (.PkgName // ""), purl: ((.PkgIdentifier // {}).PURL // ""), id: (.VulnerabilityID // "") } ]
        | unique_by([ (if .purl != "" then .purl else .pkg end), .id ])
        | map(select(.sev as $s | $set | index($s)))'
    count="$(jq --argjson set "$set" --argjson kn "$KERNEL_NAMES" "$unique"' | map(select((.pkg | ascii_downcase) as $n | ($kn | index($n)) | not)) | length' "$SECURITY" 2>/dev/null)"
    kernel="$(jq --argjson set "$set" --argjson kn "$KERNEL_NAMES" "$unique"' | map(select((.pkg | ascii_downcase) as $n | ($kn | index($n)) != null)) | length' "$SECURITY" 2>/dev/null)"
    is_number "$count" || { emit unjudged "$cond" "the security report could not be read"; return; }
    is_number "$kernel" || kernel=0
    err="$(jq -r '.ScanError.Message // empty' "$SECURITY" 2>/dev/null)"
    local note=""
    [ "$kernel" -gt 0 ] && note=" ($kernel kernel advisory(ies) are reported separately and not counted)"
    if [ "$count" -gt 0 ]; then
        emit met "$cond" "$count finding(s) at $sev or worse${note}"
    elif [ -n "$err" ]; then
        emit unjudged "$cond" "the vulnerability scan did not complete: $err"
    else
        emit ok "$cond" "no finding at $sev or worse${note}"
    fi
}

judge_malicious() { # <cond>
    local cond="$1" count unknown data problem
    unreadable_sbom "$cond" && return
    count="$(count_components '(.properties // []) | any(.name=="bomlens:malicious" and .value=="true")')"
    is_number "$count" || { emit unjudged "$cond" "the SBOM could not be read"; return; }
    if [ "$count" -gt 0 ]; then
        emit met "$cond" "$count component(s) flagged malicious: $(labels '(.properties // []) | any(.name=="bomlens:malicious" and .value=="true")')"
        return
    fi
    unknown="$(count_components '(.properties // []) | any(.name=="bomlens:malicious:rangeUnknown" and .value=="true")')"
    if is_number "$unknown" && [ "$unknown" -gt 0 ]; then
        emit unjudged "$cond" "$unknown component(s) matched an advisory whose version range could not be compared: $(labels '(.properties // []) | any(.name=="bomlens:malicious:rangeUnknown" and .value=="true")')"
        return
    fi
    problem="$(step_problem enrich-malicious bomlens:malicious-check-unavailable)"
    data="${MALICIOUS_DATA_FILE:-$SCRIPT_DIR/malicious-index.json}"
    if [ "${ENRICH_MALICIOUS:-true}" = "false" ]; then
        emit unjudged "$cond" "the malicious-package check was turned off (ENRICH_MALICIOUS=false)"
    elif [ -n "$problem" ]; then
        emit unjudged "$cond" "the malicious-package check did not complete: $problem"
    elif [ ! -f "$data" ]; then
        emit unjudged "$cond" "this image has no malicious-package snapshot to check against"
    else
        emit ok "$cond" "no component is in the malicious-package snapshot"
    fi
}

judge_license_conflict() { # <cond>
    local cond="$1" outbound total assessed count unknown problem
    unreadable_sbom "$cond" && return
    outbound="$(jq -r '[ (.metadata.component.licenses // [])[] | (.license.id // .license.name // .expression // "") | select(. != "") ] | first // ""' "$SBOM" 2>/dev/null)"
    if [ -z "$outbound" ]; then
        emit unjudged "$cond" "the product's own license is not recorded in this SBOM's root component, so no conflict was assessed (--license records it for source and rootfs scans; a supplier SBOM has to carry it)"
        return
    fi
    problem="$(step_problem normalize "")"
    total="$(count_components 'true')"
    assessed="$(count_components '(.properties // []) | any(.name=="bomlens:licenseConflict")')"
    if [ -n "$problem" ]; then
        emit unjudged "$cond" "the license-compatibility step did not complete: $problem"
        return
    fi
    if is_number "$total" && is_number "$assessed" && [ "$total" -gt 0 ] && [ "$assessed" -eq 0 ]; then
        emit unjudged "$cond" "no license-compatibility verdict was recorded for any component"
        return
    fi
    count="$(count_components '(.properties // []) | any(.name=="bomlens:licenseConflict" and .value=="incompatible")')"
    unknown="$(count_components '(.properties // []) | any(.name=="bomlens:licenseConflict" and .value=="unknown")')"
    is_number "$count" || { emit unjudged "$cond" "the SBOM could not be read"; return; }
    local note=""
    is_number "$unknown" && [ "$unknown" -gt 0 ] && note=" ($unknown component(s) could not be assessed)"
    if [ "$count" -gt 0 ]; then
        emit met "$cond" "$count component(s) incompatible with $outbound: $(labels '(.properties // []) | any(.name=="bomlens:licenseConflict" and .value=="incompatible")')${note}"
    else
        emit ok "$cond" "no component is incompatible with $outbound${note}"
    fi
}

# The conformance report the pipeline already wrote is the only source for the
# two conditions below. Prints nothing and returns 1 when it cannot be used.
conformance_readable() { # <cond> -> emits unjudged and returns 1 when unusable
    if [ ! -f "$CONFORMANCE" ]; then
        emit unjudged "$1" "no conformance report was produced for this scan"; return 1
    fi
    if ! jq empty "$CONFORMANCE" >/dev/null 2>&1; then
        emit unjudged "$1" "the conformance report could not be read"; return 1
    fi
    return 0
}

judge_empty_result() { # <cond>
    local cond="$1" empty count
    conformance_readable "$cond" || return
    empty="$(jq -r 'if (.emptyResult | type) == "boolean" then (.emptyResult | tostring) else "" end' "$CONFORMANCE" 2>/dev/null)"
    count="$(jq -r '.softwareComponentCount // empty' "$CONFORMANCE" 2>/dev/null)"
    is_number "$count" || count="?"
    case "$empty" in
        true)  emit met "$cond" "the scan found ${count} software component(s); operating-system and file entries are not counted" ;;
        false) emit ok "$cond" "the scan found ${count} software component(s)" ;;
        *)     emit unjudged "$cond" "this report carries no component count (the format of this SBOM was not measured)" ;;
    esac
}

judge_license_coverage() { # <cond> <pct>
    local cond="$1" min="$2" line declared total pct detail
    case "$min" in ''|*[!0-9]*) emit unjudged "$cond" "'$min' is not a whole percentage from 0 to 100"; return ;; esac
    if [ "${#min}" -gt 3 ] || [ "$((10#$min))" -gt 100 ]; then
        emit unjudged "$cond" "'$min' is not a whole percentage from 0 to 100"; return
    fi
    min=$((10#$min))
    conformance_readable "$cond" || return
    line="$(jq -r '.licenseCoverage
        | if (type != "object") then "absent"
          else "\(.declared // "")\t\(.total // "")\t\(.pct // "")" end' "$CONFORMANCE" 2>/dev/null)"
    if [ -z "$line" ] || [ "$line" = "absent" ]; then
        emit unjudged "$cond" "this report carries no license coverage (the format of this SBOM was not measured)"; return
    fi
    IFS=$'\t' read -r declared total pct <<< "$line"
    if ! is_number "$declared" || ! is_number "$total"; then
        emit unjudged "$cond" "the license coverage in this report could not be read"; return
    fi
    if [ "$total" -eq 0 ]; then
        emit unjudged "$cond" "there is no software component to measure license coverage on (operating-system and file entries are not counted)"; return
    fi
    is_number "$pct" || pct=$((declared * 100 / total))
    detail="${pct}% (${declared}/${total})"
    if [ "$pct" -lt "$min" ]; then
        emit met "$cond" "license coverage is ${detail:-unknown}, below ${min}%"
    else
        emit ok "$cond" "license coverage is ${detail:-unknown}, at or above ${min}%"
    fi
}

IFS=',' read -r -a WANTED <<< "$CONDITIONS"
for cond in "${WANTED[@]}"; do
    [ -n "$cond" ] || continue
    case "$cond" in
        vulnerability=*)   judge_vulnerability "$cond" "${cond#vulnerability=}" ;;
        malicious-package) judge_malicious "$cond" ;;
        license-conflict)  judge_license_conflict "$cond" ;;
        empty-result)      judge_empty_result "$cond" ;;
        license-coverage=*) judge_license_coverage "$cond" "${cond#license-coverage=}" ;;
        *) emit unjudged "$cond" "not a known condition" ;;
    esac
done
# Publish in one piece: a reader sees the whole judgement or none of it.
mv "$PARTIAL" "$RESULT"
exit 0
