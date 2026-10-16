#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# generate-risk-report.sh — assemble a supplier-facing risk report by RE-AGGREGATING
# artifacts already produced by the pipeline (no new scan is run).
#
# Usage: generate-risk-report.sh <out_prefix> <project_name> [scan_mode]
#   reads  <out_prefix>_conformance.json   (validate-sbom.sh)
#          <out_prefix>_security.json       (scan-security.sh / Trivy)
#          <out_prefix>_NOTICE.txt          (generate-notice.sh)
#   writes <out_prefix>_risk-report.md  and  <out_prefix>_risk-report.html
#
# Aggregates a supply-chain risk view: conformance verdict + vulnerability triage
# with recommended Critical-7-day / High-30-day remediation deadlines. Missing
# inputs are skipped gracefully. See docs/supplier-sbom-analysis.md §6.
#
# scan_mode selects the report kind (see the "Report kind" block below); pass
# the caller's $SCAN_MODE. Omitting it is treated as a self-generated scan.
set -e

OUT_PREFIX="$1"
PROJECT="${2:-project}"
SCAN_MODE="${3:-}"

if [ -z "$OUT_PREFIX" ]; then
    echo "[risk] out_prefix required (usage: generate-risk-report.sh <out_prefix> <project_name>)" >&2
    exit 1
fi

CONF="${OUT_PREFIX}_conformance.json"
SEC="${OUT_PREFIX}_security.json"
NOTICE="${OUT_PREFIX}_NOTICE.txt"
MD="${OUT_PREFIX}_risk-report.md"
HTML="${OUT_PREFIX}_risk-report.html"
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Recommended remediation deadlines (Critical / High).
CRIT_DAYS=7
HIGH_DAYS=30

# --------------------------------------------------------
# Conformance summary
# --------------------------------------------------------
CONF_RESULT="N/A"; CONF_FORMAT="N/A"
CONF_FAILS='[]'
if [ -f "$CONF" ] && jq empty "$CONF" >/dev/null 2>&1; then
    CONF_RESULT=$(jq -r '.result // "N/A"' "$CONF")
    CONF_FORMAT=$(jq -r '.format // "N/A"' "$CONF")
    CONF_FAILS=$(jq -c '[.checks[]? | select(.required and .status=="fail") | .label]' "$CONF")
fi

# --------------------------------------------------------
# Vulnerability aggregation (Trivy JSON)
# --------------------------------------------------------
FINDINGS='[]'; UNREACHED_N=0
if [ -f "$SEC" ] && jq empty "$SEC" >/dev/null 2>&1; then
    # A finding govulncheck judged not reachable (--reachability) is counted
    # apart, as the security report does.
    UNREACHED_N=$(jq '[ .Results[]?.Vulnerabilities[]?
        | select(((.["bomlens:reachability"] // {}).state // "") == "not_affected") ] | length' "$SEC" 2>/dev/null || echo 0)
    FINDINGS=$(jq -c '
      [ .Results[]?.Vulnerabilities[]?
        | select(((.["bomlens:reachability"] // {}).state // "") != "not_affected") | {
          id: .VulnerabilityID,
          pkg: .PkgName,
          version: .InstalledVersion,
          severity: (.Severity // "UNKNOWN"),
          fixed: (.FixedVersion // "")
        } ]
      | sort_by({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)
    ' "$SEC" 2>/dev/null || echo '[]')
fi
sev_count() { echo "$FINDINGS" | jq "[.[] | select(.severity==\"$1\")] | length"; }

# Components no vulnerability check could reach (scan-security.sh writes them to
# _security.json as UncheckedComponents): no version, or no package purl and no
# CPE that was matched. A clean table must not read as covering them.
UNCHECKED_N=0; UNCHECKED_TOP='[]'; UNCHECKED_LIST_MAX=20
if [ -f "$SEC" ] && jq empty "$SEC" >/dev/null 2>&1; then
    UNCHECKED_N=$(jq '.UncheckedComponents.Count // 0 | if type == "number" then . else 0 end' "$SEC" 2>/dev/null || echo 0)
    UNCHECKED_TOP=$(jq -c --argjson max "$UNCHECKED_LIST_MAX" \
        '[(.UncheckedComponents.Components // [])[0:$max][]
          | {name: (.Name // "" | tostring), version: (.Version // "" | tostring), reason: (.Reason // "" | tostring)}]' \
        "$SEC" 2>/dev/null || echo '[]')
fi
C=$(sev_count CRITICAL); H=$(sev_count HIGH); M=$(sev_count MEDIUM); L=$(sev_count LOW); U=$(sev_count UNKNOWN)
TOTAL=$(echo "$FINDINGS" | jq 'length')

# Components proved present with no version recovered (bomlens:evidenceGrade).
# They carry no version, purl or CPE, so no vulnerability database can be asked
# about them. Printing the severity table without saying so lets "0 vulnerabilities"
# read as covering the whole SBOM when part of it was never eligible to be checked.
PRESENCE_ONLY=0
if [ -f "${OUT_PREFIX}_bom.json" ] && jq empty "${OUT_PREFIX}_bom.json" >/dev/null 2>&1; then
    PRESENCE_ONLY=$(jq '[.components[]? | select(any(.properties[]?;
        .name == "bomlens:evidenceGrade" and .value == "presence-only"))] | length' \
        "${OUT_PREFIX}_bom.json" 2>/dev/null || echo 0)
fi

# Firmware analysis scope (scan-firmware.sh stamps bomlens:firmware:* from the
# unpacker's own report). Regions the unpacker could not identify or open hold
# components this SBOM does not list, so a clean vulnerability table describes
# only what was opened. Read for a FIRMWARE scan only: an SBOM handed in for
# review (ANALYZE) is data from someone else, and its properties are not this
# scan's statement about its own coverage. Absent when the report was unavailable:
# no section rather than a reassuring blank.
FW_SCOPE=false; FW_UNKNOWN_PCT=0; FW_UNKNOWN_BYTES=0
FW_FAILED=0; FW_FAILED_FORMATS=""; FW_MISSING=""; FW_ENCRYPTED=0
if [ "$SCAN_MODE" = "FIRMWARE" ] && [ -f "${OUT_PREFIX}_bom.json" ] \
   && jq empty "${OUT_PREFIX}_bom.json" >/dev/null 2>&1; then
    fw_prop() { jq -r --arg n "bomlens:firmware:$1" \
        '[.metadata.component.properties[]? | select(.name == $n) | .value][0] // ""' \
        "${OUT_PREFIX}_bom.json" 2>/dev/null; }
    # Values are interpolated into Markdown and HTML, so keep only the characters
    # a number, a handler name or a tool name can contain: a number that is not
    # plainly one is dropped, not repaired into a plausible one.
    fw_num() { fw_prop "$1" | grep -E '^[0-9]+(\.[0-9]+)?$' | cut -c1-12; }
    fw_list() { fw_prop "$1" | tr -cd 'A-Za-z0-9_.,+-' | cut -c1-200; }
    if [ -n "$(fw_prop input-bytes)" ]; then
        FW_UNKNOWN_PCT=$(fw_num unknown-top-level-percent); FW_UNKNOWN_PCT="${FW_UNKNOWN_PCT:-0}"
        FW_UNKNOWN_BYTES=$(fw_num unknown-bytes); FW_UNKNOWN_BYTES="${FW_UNKNOWN_BYTES:-0}"
        FW_FAILED=$(fw_num extraction-failed); FW_FAILED="${FW_FAILED:-0}"
        FW_ENCRYPTED=$(fw_num encrypted-regions); FW_ENCRYPTED="${FW_ENCRYPTED:-0}"
        FW_FAILED_FORMATS=$(fw_list extraction-failed-formats)
        FW_MISSING=$(fw_list missing-extractors)
        case "$FW_UNKNOWN_BYTES$FW_FAILED$FW_ENCRYPTED" in *[!0-9]*) ;; *)
            if [ "$FW_UNKNOWN_BYTES" -gt 0 ] || [ "$FW_FAILED" -gt 0 ] \
               || [ "$FW_ENCRYPTED" -gt 0 ] || [ -n "$FW_MISSING" ]; then
                FW_SCOPE=true
            fi ;;
        esac
    fi
fi

# --------------------------------------------------------
# Report kind: on the ANALYZE path this is a SUPPLIER SBOM review (validate an
# externally-submitted SBOM format); otherwise it is a SELF-GENERATED
# open-source risk analysis report (source/firmware/image/binary/rootfs/AI
# scan), even though a conformance artifact now exists there too (every
# generation mode self-checks against the same criteria). The format-
# validation section only applies to the supplier case: a self-generated SBOM
# grading its own format is not a meaningful pass/fail signal for most checks.
# Section numbering is assigned once here; the titles and every other
# user-facing string are set in the localization block below.
# --------------------------------------------------------
if [ "$SCAN_MODE" = "ANALYZE" ] && [ "$CONF_RESULT" != "N/A" ]; then
    HAS_CONF=true
    S_CONF=1; S_VULN=2; S_LIC=3; S_NEXT=4
else
    HAS_CONF=false
    # Self mode: no conformance check section, so numbering starts at vulnerabilities.
    S_CONF=""; S_VULN=1; S_LIC=2; S_NEXT=3
fi

# --------------------------------------------------------
# License summary (from NOTICE text, best-effort)
# --------------------------------------------------------
LIC_COUNT="N/A"
if [ -f "$NOTICE" ]; then
    LIC_COUNT=$(grep -c '^License: ' "$NOTICE" 2>/dev/null || echo 0)
fi

# --------------------------------------------------------
# License classification (copyleft strength) from the finished SBOM. Uses the
# SAME classifier as normalize-sbom.sh and the web UI (the shared
# license-flags.jq, which mirrors licenses.ts), so the report's counts always
# agree with the bomlens:licenseClass properties and the UI badges — even for
# an SBOM that predates the property. Skipped when no BOM artifact exists.
# --------------------------------------------------------
BOM="${OUT_PREFIX}_bom.json"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)"
# Shared look of the HTML reports (design tokens, print rules, time format).
if [ ! -f "$LIB_DIR/report-common.sh" ]; then
    echo "[risk] report-common.sh not found next to $0; the image is incomplete. Fix: rebuild the scanner image." >&2
    exit 1
fi
# shellcheck source=report-common.sh
. "$LIB_DIR/report-common.sh"
# The components whose licenses this report counts. For a source or image scan
# the root component is the scanned project itself, whose own license is not a
# third-party obligation, so it is left out (as the NOTICE file leaves it out).
# For an AI model or dataset scan the root is the model or dataset under
# review, and its license is the one that matters most: a model with no
# dependent datasets has no other component at all, and read as 0 licenses.
# shellcheck disable=SC2016
LIC_SUBJECTS='((if ((.metadata.component.type // "") | IN("machine-learning-model", "data"))
                then [.metadata.component] else [] end) + [ .components[]? ])'
LIC_CLASS='null'
if [ -f "$BOM" ] && jq empty "$BOM" >/dev/null 2>&1 \
   && jq -e '(.metadata.component.type // "") | IN("machine-learning-model", "data")' "$BOM" >/dev/null 2>&1; then
    LIC_COUNT=$(jq -r "$LIC_SUBJECTS"'
      | [ .[] | (.licenses // [])[] | (.license.id // .license.name // .expression // empty) ]
      | unique | length' "$BOM" 2>/dev/null || echo "$LIC_COUNT")
fi
if [ -f "$BOM" ] && [ -f "$LIB_DIR/license-flags.jq" ] && jq empty "$BOM" >/dev/null 2>&1; then
    LIC_CLASS=$(jq -c "$(cat "$LIB_DIR/license-flags.jq")$LIC_SUBJECTS"'
      | [ .[] | { class: component_license_class,
                           label: ((.name // "?") + "@" + (.version // "?")) } ] as $rows
      | { nc: ([$rows[] | select(.class=="network-copyleft") | .label]),
          sc: ([$rows[] | select(.class=="strong-copyleft")  | .label]),
          wk: ([$rows[] | select(.class=="weak-copyleft")]   | length),
          pm: ([$rows[] | select(.class=="permissive")]      | length),
          un: ([$rows[] | select(.class=="uncategorized")]   | length) }
    ' "$BOM" 2>/dev/null || echo 'null')
fi
# Outbound-license conflict rollup. normalize-sbom.sh stamps a per-component
# bomlens:licenseConflict verdict, but ONLY when the SBOM's root component
# declares an outbound license (see --license / PROJECT_LICENSE). With no
# declaration no property exists and this whole block stays absent from the
# report — an omitted section means "not assessed", never "no conflicts".
OUTBOUND_LIC=""; LC_INCOMPAT=0; LC_COND=0; LC_UNKNOWN=0; LC_TOP='[]'
if [ -f "$BOM" ] && jq empty "$BOM" >/dev/null 2>&1; then
    OUTBOUND_LIC=$(jq -r '[ (.metadata.component.licenses // [])[]
        | (.license.id // .license.name // .expression // "") | select(. != "") ] | first // ""' "$BOM" 2>/dev/null || echo "")
    if [ -n "$OUTBOUND_LIC" ]; then
        LC_COUNTS=$(jq -c '[ .components[]?
            | { v: (((.properties // [])[] | select(.name=="bomlens:licenseConflict") | .value) // ""),
                label: ((.name // "?") + "@" + (.version // "?")) } | select(.v != "") ] as $rows
          | { i: ([$rows[] | select(.v=="incompatible")] | length),
              c: ([$rows[] | select(.v=="conditional")]  | length),
              u: ([$rows[] | select(.v=="unknown")]      | length),
              top: ([$rows[] | select(.v=="incompatible") | .label] | .[0:10]) }' "$BOM" 2>/dev/null || echo '{}')
        LC_INCOMPAT=$(echo "$LC_COUNTS" | jq '.i // 0')
        LC_COND=$(echo "$LC_COUNTS" | jq '.c // 0')
        LC_UNKNOWN=$(echo "$LC_COUNTS" | jq '.u // 0')
        LC_TOP=$(echo "$LC_COUNTS" | jq -c '.top // []')
    fi
fi

# Known-malicious packages (enrich-malicious.sh, bundled OSV snapshot). Kept
# apart from the vulnerability counts on purpose: a CVE is a flaw to patch,
# whereas a malicious package has to be removed and any credential the build
# could reach rotated. Absent from the report entirely when the snapshot was not
# bundled — no section rather than a reassuring zero.
MAL_COUNT=0; MAL_SNAP=""; MAL_TOP='[]'
if [ -f "$BOM" ] && jq empty "$BOM" >/dev/null 2>&1; then
    MAL_ROWS=$(jq -c '[ .components[]?
        | select((.properties // []) | any(.name=="bomlens:malicious" and .value=="true"))
        | { label: ((.name // "?") + "@" + (.version // "?")),
            id: (((.properties // [])[] | select(.name=="bomlens:malicious:id") | .value) // ""),
            src: (((.properties // [])[] | select(.name=="bomlens:malicious:source") | .value) // "") } ]' \
        "$BOM" 2>/dev/null || echo '[]')
    MAL_COUNT=$(echo "$MAL_ROWS" | jq 'length')
    MAL_SNAP=$(echo "$MAL_ROWS" | jq -r '.[0].src // ""')
    MAL_TOP=$(echo "$MAL_ROWS" | jq -c '.[0:20]')
fi

# AI model risk assessment rollup (AIBOM/ANALYZE): re-aggregate the
# bomlens:assessment:* verdicts assess-ai-risk.sh stamped; absent for a plain
# software SBOM, in which case the section is skipped entirely.
AS_MODELS=0; AS_OK=0; AS_COND=0; AS_CAU=0; AS_REV=0
if [ -f "$BOM" ] && jq empty "$BOM" >/dev/null 2>&1; then
    AS_COUNTS=$(jq -c '[ ([.metadata.component // empty] + [.components[]?])[]
        | select(.type=="machine-learning-model")
        | ((.properties // [])[] | select(.name=="bomlens:assessment:overall") | .value) ]
        | { n: length, ok: (map(select(.=="ok"))|length), c: (map(select(.=="conditional"))|length),
            w: (map(select(.=="caution"))|length), r: (map(select(.=="review"))|length) }' "$BOM" 2>/dev/null || echo '{"n":0}')
    AS_MODELS=$(echo "$AS_COUNTS" | jq '.n // 0')
    AS_OK=$(echo "$AS_COUNTS" | jq '.ok // 0'); AS_COND=$(echo "$AS_COUNTS" | jq '.c // 0')
    AS_CAU=$(echo "$AS_COUNTS" | jq '.w // 0'); AS_REV=$(echo "$AS_COUNTS" | jq '.r // 0')
fi

HAS_LIC_CLASS=false
NC=0; SC=0; WK=0; PM=0; UN=0; COPYLEFT_TOTAL=0
COPYLEFT_TOP='[]'
if [ "$LIC_CLASS" != "null" ]; then
    HAS_LIC_CLASS=true
    NC=$(echo "$LIC_CLASS" | jq '.nc | length')
    SC=$(echo "$LIC_CLASS" | jq '.sc | length')
    WK=$(echo "$LIC_CLASS" | jq '.wk')
    PM=$(echo "$LIC_CLASS" | jq '.pm')
    UN=$(echo "$LIC_CLASS" | jq '.un')
    COPYLEFT_TOTAL=$((NC + SC))
    # Up to 10 drivers of the copyleft exposure: network-copyleft first, then
    # strong; each keeps the SBOM's (sorted) component order, so the list is
    # deterministic.
    COPYLEFT_TOP=$(echo "$LIC_CLASS" | jq -c '
      ([.nc[] | {label: ., class: "network-copyleft"}]
       + [.sc[] | {label: ., class: "strong-copyleft"}]) | .[0:10]')
fi

# --------------------------------------------------------
# Localization (REPORT_LANG=ko). English is the default; only the Markdown/HTML
# below are localized. Data and identifiers (CVE ids, package names, severities,
# license-class names, counts, dates, URLs, bomlens:* property names) are never
# translated. Korean swaps chrome strings from
# docker/lib/i18n/report-strings.ko.json. The AI-verdict labels and disclaimer
# reuse the aiprofile.* keys so this report and the AI profile never disagree.
# --------------------------------------------------------
REPORT_LANG="${REPORT_LANG:-en}"; [ "$REPORT_LANG" = "ko" ] || REPORT_LANG="en"
KO_CAT="$(dirname "$0")/i18n/report-strings.ko.json"
if [ "$REPORT_LANG" = "ko" ] && [ ! -f "$KO_CAT" ]; then
    echo "[risk] WARN: ko report catalog not found ($KO_CAT); using English." >&2
    REPORT_LANG="en"
fi
kstr() { jq -r --arg k "$1" '.[$k] // $k' "$KO_CAT"; }
# shellcheck disable=SC2059  # the format is a trusted catalog template, not user input
tfmt() { local f; f="$(kstr "$1")"; shift; printf -- "$f" "$@"; }

CONF_UP=$(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')

if [ "$REPORT_LANG" = "ko" ]; then
    P_TITLE=$(tfmt risk.md_title "$PROJECT"); P_H1=$(kstr risk.h1)
    P_SUBTITLE=""
    if [ "$HAS_CONF" = "true" ]; then P_SUBTITLE=$(kstr risk.subtitle_supplier); fi
    P_MD_GEN=$(tfmt risk.md_generated "$GEN_AT")
    P_MD_INTRO=$(kstr risk.md_intro)
    P_H2_CONF=$(kstr risk.h2_conf)
    P_MD_CONF_FMT=$(tfmt risk.md_conf_format "$CONF_FORMAT")
    P_MD_CONF_RESULT=$(tfmt risk.md_conf_result "$CONF_UP")
    P_MD_CONF_FAIL=$(kstr risk.md_conf_fail)
    P_CONF_RESULT_LBL=$(kstr risk.conf_result_label)
    P_CONF_FAIL_B=$(kstr risk.conf_fail_b)
    P_CONF_FAIL_TXT=$(kstr risk.conf_fail_txt)
    P_H2_VULN=$(kstr risk.h2_vuln)
    P_DL_LEAD=$(kstr risk.deadline_note_lead); P_DL_TAIL=$(kstr risk.deadline_note_tail)
    P_DL_BOLD_CRIT=$(tfmt risk.deadline_bold_crit "$CRIT_DAYS")
    P_DL_BOLD_HIGH=$(tfmt risk.deadline_bold_high "$HIGH_DAYS")
    P_DL_CRIT=$(tfmt risk.deadline_crit "$CRIT_DAYS")
    P_DL_HIGH=$(tfmt risk.deadline_high "$HIGH_DAYS")
    P_DL_POLICY=$(kstr risk.deadline_policy)
    P_TH_DEADLINE=$(kstr risk.th_deadline)
    P_VULN_NONE_MD=$(kstr risk.vuln_none_md); P_VULN_NONE_HTML=$(kstr risk.vuln_none_html)
    P_PRESENCE_MD=$(tfmt risk.presence_only_md "$PRESENCE_ONLY" "$PRESENCE_ONLY")
    P_PRESENCE_HTML=$(tfmt risk.presence_only_html "$PRESENCE_ONLY" "$PRESENCE_ONLY")
    P_UNCHECKED_MD=$(tfmt risk.unchecked_md "$UNCHECKED_N")
    P_UNREACHED_MD=$(tfmt risk.unreached_md "$UNREACHED_N")
    P_UNREACHED_HTML=$(tfmt risk.unreached_html "$UNREACHED_N")
    P_UNCHECKED_HTML=$(tfmt risk.unchecked_html "$UNCHECKED_N")
    P_UNCHECKED_MORE=$(tfmt risk.unchecked_more "$((UNCHECKED_N - UNCHECKED_LIST_MAX))")
    P_REASON_NO_VERSION=$(kstr risk.unchecked_no_version)
    P_REASON_NO_ID=$(kstr risk.unchecked_no_identifier)
    P_VULN_NONE_CHECKED_MD=$(kstr risk.vuln_none_checked_md); P_VULN_NONE_CHECKED_HTML=$(kstr risk.vuln_none_checked_html)
    P_FW_SCOPE_H=$(kstr risk.fw_scope_h)
    P_FW_LABEL=$(kstr risk.fw_scope_label)
    P_FW_UNKNOWN=$(tfmt risk.fw_scope_unknown "$FW_UNKNOWN_PCT" "$FW_UNKNOWN_BYTES")
    P_FW_FAILED=$(tfmt risk.fw_scope_failed "$FW_FAILED")
    P_FW_ENCRYPTED=$(tfmt risk.fw_scope_encrypted "$FW_ENCRYPTED")
    P_FW_TAIL=$(kstr risk.fw_scope_tail)
    P_FW_FORMATS=$(tfmt risk.fw_scope_formats "$FW_FAILED_FORMATS")
    P_FW_MISSING=$(tfmt risk.fw_scope_missing "$FW_MISSING")
    P_H2_LIC=$(kstr risk.h2_lic)
    P_LIC_NO_NOTICE_MD=$(kstr risk.lic_no_notice_md); P_LIC_NO_NOTICE_HTML=$(kstr risk.lic_no_notice_html)
    P_MD_LIC_COUNT=$(tfmt risk.md_lic_count "$LIC_COUNT" "$OUT_PREFIX")
    P_LIC_HTML_PRE=$(kstr risk.lic_html_pre); P_LIC_HTML_POST=$(kstr risk.lic_html_post)
    P_H3_LICCLASS=$(kstr risk.h3_licclass)
    P_LICCLASS_INTRO_MD=$(kstr risk.licclass_intro_md)
    P_LICCLASS_INTRO_A=$(kstr risk.licclass_intro_html_a); P_LICCLASS_INTRO_B=$(kstr risk.licclass_intro_html_b)
    P_COPYLEFT_DRIVERS=$(kstr risk.copyleft_drivers)
    P_H3_LICCONFLICT=$(kstr risk.h3_licconflict)
    P_LICCONFLICT_INTRO=$(kstr risk.licconflict_intro)
    P_TH_LC=$(kstr risk.th_licconflict)
    P_LICCONFLICT_DRIVERS=$(kstr risk.licconflict_drivers)
    P_H3_MALICIOUS=$(kstr risk.h3_malicious)
    P_MALICIOUS_INTRO=$(kstr risk.malicious_intro)
    P_MALICIOUS_LIST=$(kstr risk.malicious_list)
    P_COPYLEFT_MORE_MD=$(tfmt risk.copyleft_more_md "$((COPYLEFT_TOTAL - 10))")
    P_CL_MORE_PRE=$(kstr risk.copyleft_more_pre); P_CL_MORE_MID=$(kstr risk.copyleft_more_mid); P_CL_MORE_END=$(kstr risk.copyleft_more_end)
    P_H3_AI=$(kstr risk.h3_ai)
    P_AI_SEE_MD=$(tfmt risk.ai_see_md "$OUT_PREFIX")
    P_AI_SEE_HTML=$(kstr risk.ai_see_html)
    P_AI_DISC=$(kstr risk.ai_disclaimer)
    L_OK=$(kstr aiprofile.v_ok); L_COND=$(kstr aiprofile.v_conditional)
    L_CAU=$(kstr aiprofile.v_caution); L_REV=$(kstr aiprofile.v_review)
    P_H2_NEXT=$(kstr risk.h2_next)
    P_NEXT1_PRE=$(kstr risk.next1_pre); P_NEXT1_BOLD=$(kstr risk.next1_bold); P_NEXT1_POST=$(kstr risk.next1_post)
    P_NEXT2_CONF=$(kstr risk.next2_conf)
    P_NEXT2_SELF_MD=$(tfmt risk.next2_self_md "$OUT_PREFIX" "$OUT_PREFIX")
    P_NEXT2_SELF_HTML=$(kstr risk.next2_self_html)
    P_KIND=$(kstr risk.kind)
    P_META_PROJECT=$(kstr risk.meta_project); P_META_GENERATED=$(kstr risk.meta_generated); P_META_FORMAT=$(kstr risk.meta_format)
else
    P_TITLE="Open-source risk report — ${PROJECT}"; P_H1="Open-source risk report"
    P_SUBTITLE=""
    if [ "$HAS_CONF" = "true" ]; then P_SUBTITLE="Supplier SBOM under review"; fi
    P_MD_GEN="- Generated: ${GEN_AT}"
    P_MD_INTRO="- This report re-aggregates the vulnerability and license artifacts already produced, without running a new scan."
    P_H2_CONF="Requirements met (conformance check)"
    P_MD_CONF_FMT="- Input format: ${CONF_FORMAT}"
    P_MD_CONF_RESULT="- Check result: **${CONF_UP}**"
    P_MD_CONF_FAIL="> ⚠️ **Unmet conformance check items** — the required items below are missing. We recommend fixing them and checking again."
    P_CONF_RESULT_LBL="Check result:"
    P_CONF_FAIL_B="Unmet conformance check items"
    P_CONF_FAIL_TXT=" — the required items below are missing. We recommend fixing them and checking again."
    P_H2_VULN="Vulnerability analysis and remediation deadlines"
    P_DL_LEAD="Recommended remediation deadlines: "
    P_DL_TAIL=". We recommend preparing a remediation plan or risk justification."
    P_DL_BOLD_CRIT="Critical → within ${CRIT_DAYS} days"
    P_DL_BOLD_HIGH="High → within ${HIGH_DAYS} days"
    P_DL_CRIT="within ${CRIT_DAYS} days"
    P_DL_HIGH="within ${HIGH_DAYS} days"
    P_DL_POLICY="Per policy"
    P_TH_DEADLINE="Deadline"
    P_VULN_NONE_MD="_No known vulnerabilities, or no security artifact was produced._"
    P_VULN_NONE_HTML="No known vulnerabilities, or no security artifact was produced."
    P_PRESENCE_MD="> ${PRESENCE_ONLY} component(s) were proved present but no version could be recovered. With no version there is nothing to ask a vulnerability database about, so the counts above do not cover them. The licence obligations still apply."
    P_PRESENCE_HTML="<b>${PRESENCE_ONLY} component(s)</b> were proved present but no version could be recovered. With no version there is nothing to ask a vulnerability database about, so the counts above do not cover them. The licence obligations still apply."
    P_UNREACHED_MD="> ${UNREACHED_N} finding(s) are not reachable: govulncheck found that the affected Go code is not called or not in the executable (--reachability). They are not in the counts above; the security report lists them."
    P_UNREACHED_HTML="<b>${UNREACHED_N} finding(s) are not reachable</b>: govulncheck found that the affected Go code is not called or not in the executable (--reachability). They are not in the counts above; the security report lists them."
    P_UNCHECKED_MD="> ${UNCHECKED_N} component(s) could not be checked: they have no version, or no package purl and no CPE that was matched, so no vulnerability database was asked about them. The counts above do not cover them."
    P_UNCHECKED_HTML="<b>${UNCHECKED_N} component(s) could not be checked</b>: they have no version, or no package purl and no CPE that was matched, so no vulnerability database was asked about them. The counts above do not cover them."
    P_UNCHECKED_MORE="… and $((UNCHECKED_N - UNCHECKED_LIST_MAX)) more (the security report lists them all)"
    P_REASON_NO_VERSION="no version"
    P_REASON_NO_ID="no package purl or matched CPE"
    P_VULN_NONE_CHECKED_MD="_No vulnerability was found in the components that were checked. The components that could not be checked are listed above._"
    P_VULN_NONE_CHECKED_HTML="No vulnerability was found in the components that were checked. The components that could not be checked are listed above."
    P_FW_SCOPE_H="Firmware analysis scope"
    P_FW_LABEL="Analysis scope:"
    P_FW_UNKNOWN="${FW_UNKNOWN_PCT}% of the image (${FW_UNKNOWN_BYTES} bytes) was not recognized as a known format."
    P_FW_FAILED="${FW_FAILED} extraction step(s) did not complete."
    P_FW_ENCRYPTED="${FW_ENCRYPTED} region(s) are encrypted."
    P_FW_TAIL="Components in any part of the image that was not opened are not listed in this SBOM, so the vulnerability counts above describe only what could be opened."
    P_FW_FORMATS="Formats whose extraction did not complete: ${FW_FAILED_FORMATS}."
    P_FW_MISSING="Extraction tools the scanner image does not include: ${FW_MISSING}."
    P_H2_LIC="License summary"
    P_LIC_NO_NOTICE_MD="_Skipped: no NOTICE artifact was produced._"
    P_LIC_NO_NOTICE_HTML="Skipped: no NOTICE artifact was produced."
    P_MD_LIC_COUNT="- Distinct licenses identified: ${LIC_COUNT} (see \`${OUT_PREFIX}_NOTICE.{txt,html}\` for details)"
    P_LIC_HTML_PRE="Distinct licenses identified:"
    P_LIC_HTML_POST=" (see the NOTICE artifact for details)."
    P_H3_LICCLASS="License classification (copyleft strength)"
    P_LICCLASS_INTRO_MD="Each component is also recorded in the SBOM with a \`bomlens:licenseClass\` property. An unrecognized license is left uncategorized rather than assumed permissive."
    P_LICCLASS_INTRO_A="Each component is also recorded in the SBOM with a "
    P_LICCLASS_INTRO_B=" property. An unrecognized license is left uncategorized rather than assumed permissive."
    P_COPYLEFT_DRIVERS="Components that create copyleft exposure (network/strong, up to 10):"
    P_H3_LICCONFLICT="Outbound-license conflicts"
    P_LICCONFLICT_INTRO="Dependencies checked against the declared outbound license. Advisory only — it surfaces combinations that need a person to look, and makes no legal determination."
    P_TH_LC="| Outbound license | Incompatible | Conditional | Unknown |"
    P_LICCONFLICT_DRIVERS="Dependencies whose terms clash with the outbound license (up to 10):"
    P_H3_MALICIOUS="Known-malicious packages"
    P_MALICIOUS_INTRO="These are not vulnerabilities to patch. A package published to attack whoever installs it has to be removed, and any credential the build could reach should be rotated."
    P_MALICIOUS_LIST="Packages matched against the bundled OSV snapshot:"
    P_COPYLEFT_MORE_MD="- … and $((COPYLEFT_TOTAL - 10)) more (see the SBOM \`bomlens:licenseClass\` property for all)"
    P_CL_MORE_PRE="… and "
    P_CL_MORE_MID=" more (see the SBOM "
    P_CL_MORE_END=" property for all)"
    P_H3_AI="AI model risk assessment"
    P_AI_SEE_MD="Per-model rationale and conditions are in \`${OUT_PREFIX}_ai-profile.md\`."
    P_AI_SEE_HTML="Per-model rationale and conditions are in the AI compliance profile artifact."
    P_AI_DISC="This assessment is guidance, not legal advice."
    L_OK="No restriction signals"; L_COND="Conditional use"; L_CAU="Caution"; L_REV="Needs review"
    P_H2_NEXT="Next steps"
    P_NEXT1_PRE="Prepare a "
    P_NEXT1_BOLD="remediation plan or risk justification"
    P_NEXT1_POST=" within the recommended deadlines above."
    P_NEXT2_CONF="If the conformance check failed, fill the missing items and regenerate the SBOM."
    P_NEXT2_SELF_MD="Keep and distribute the notice (\`${OUT_PREFIX}_NOTICE.{txt,html}\`) together with the SBOM (\`${OUT_PREFIX}_bom.json\`)."
    P_NEXT2_SELF_HTML="Keep and distribute the notice (NOTICE) together with the SBOM."
    P_KIND="Open-source risk report"
    P_META_PROJECT="Project:"; P_META_GENERATED="Generated:"; P_META_FORMAT="Input format:"
fi

# Only the parts that apply are said, so a scan that lost nothing but one tool
# does not read "0% ... 0 steps ... 0 regions".
FW_SCOPE_TEXT=""
if [ "$FW_SCOPE" = "true" ]; then
    [ "${FW_UNKNOWN_BYTES:-0}" -gt 0 ] && FW_SCOPE_TEXT="${FW_SCOPE_TEXT:+$FW_SCOPE_TEXT }${P_FW_UNKNOWN}"
    [ "${FW_FAILED:-0}" -gt 0 ] && FW_SCOPE_TEXT="${FW_SCOPE_TEXT:+$FW_SCOPE_TEXT }${P_FW_FAILED}"
    [ "${FW_ENCRYPTED:-0}" -gt 0 ] && FW_SCOPE_TEXT="${FW_SCOPE_TEXT:+$FW_SCOPE_TEXT }${P_FW_ENCRYPTED}"
    FW_SCOPE_TEXT="${FW_SCOPE_TEXT:+$FW_SCOPE_TEXT }${P_FW_TAIL}"
fi

# The supplier review is a subtitle, not a second report name: the report is the
# open-source risk report either way (docker/web/frontend/src/locales/GLOSSARY.md).
SUBTITLE_MD=""; SUBTITLE_HTML=""
if [ -n "$P_SUBTITLE" ]; then
    SUBTITLE_MD="_${P_SUBTITLE}_"
    SUBTITLE_HTML="<p class=\"subtitle\">${P_SUBTITLE}</p>
"
fi

# Shared composites (built from the localized pieces above; identical structure
# in both languages, so the deadline note stays one place).
P_VULN_NOTE_MD="> ${P_DL_LEAD}**${P_DL_BOLD_CRIT}, ${P_DL_BOLD_HIGH}**${P_DL_TAIL}"
P_VULN_NOTE_HTML="<div class=\"note\">${P_DL_LEAD}<b>${P_DL_BOLD_CRIT}</b>, <b>${P_DL_BOLD_HIGH}</b>${P_DL_TAIL}</div>"

# --------------------------------------------------------
# Markdown
# --------------------------------------------------------
{
    echo "# ${P_TITLE}"
    echo ""
    if [ -n "$SUBTITLE_MD" ]; then echo "${SUBTITLE_MD}"; echo ""; fi
    echo "${P_MD_GEN}"
    echo "${P_MD_INTRO}"
    echo ""
    if [ "$HAS_CONF" = "true" ]; then
        echo "## ${S_CONF}. ${P_H2_CONF}"
        echo ""
        echo "${P_MD_CONF_FMT}"
        echo "${P_MD_CONF_RESULT}"
        if [ "$CONF_RESULT" = "fail" ]; then
            echo ""
            echo "${P_MD_CONF_FAIL}"
            echo ""
            echo "$CONF_FAILS" | jq -r '.[] | "- " + .'
        fi
        echo ""
    fi
    echo "## ${S_VULN}. ${P_H2_VULN}"
    echo ""
    echo "${P_VULN_NOTE_MD}"
    echo ""
    echo "| Critical | High | Medium | Low | Unknown | Total |"
    echo "|---:|---:|---:|---:|---:|---:|"
    echo "| ${C} | ${H} | ${M} | ${L} | ${U} | ${TOTAL} |"
    echo ""
    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "${P_UNREACHED_MD}"
        echo ""
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        # The list names the presence-only components too (no version), so
        # their separate note is not repeated.
        echo "${P_UNCHECKED_MD}"
        echo ""
        # shellcheck disable=SC2016
        echo "$UNCHECKED_TOP" | jq -r --arg nv "$P_REASON_NO_VERSION" --arg ni "$P_REASON_NO_ID" '.[] |
            "- `" + (.name | gsub("`"; "")) + "`" + (if .version != "" then " " + .version else "" end)
            + " (" + (if .reason == "no-version" then $nv elif .reason == "no-identifier" then $ni else .reason end) + ")"'
        if [ "$UNCHECKED_N" -gt "$UNCHECKED_LIST_MAX" ]; then echo "- ${P_UNCHECKED_MORE}"; fi
        echo ""
    elif [ "${PRESENCE_ONLY:-0}" -gt 0 ]; then
        echo "${P_PRESENCE_MD}"
        echo ""
    fi
    if [ "$FW_SCOPE" = "true" ]; then
        echo "### ${P_FW_SCOPE_H}"
        echo ""
        echo "> ${FW_SCOPE_TEXT}"
        if [ -n "$FW_FAILED_FORMATS" ]; then echo ">"; echo "> ${P_FW_FORMATS}"; fi
        if [ -n "$FW_MISSING" ]; then echo ">"; echo "> ${P_FW_MISSING}"; fi
        echo ""
    fi
    if [ "$TOTAL" -gt 0 ]; then
        echo "| Severity | CVE | Package | Installed | Fixed | ${P_TH_DEADLINE} |"
        echo "|----------|-----|---------|-----------|-------|-----------|"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "$P_DL_CRIT" --arg hd "$P_DL_HIGH" --arg pol "$P_DL_POLICY" '.[] |
            "| \(.severity) | \(.id) | \(.pkg) | \(.version) | \(.fixed) | \(
              if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else $pol end
            ) |"'
    elif [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "${P_VULN_NONE_CHECKED_MD}"
    else
        echo "${P_VULN_NONE_MD}"
    fi
    echo ""
    echo "## ${S_LIC}. ${P_H2_LIC}"
    echo ""
    if [ "$LIC_COUNT" = "N/A" ]; then
        echo "${P_LIC_NO_NOTICE_MD}"
    else
        echo "${P_MD_LIC_COUNT}"
    fi
    if [ "$HAS_LIC_CLASS" = "true" ]; then
        echo ""
        echo "### ${P_H3_LICCLASS}"
        echo ""
        echo "${P_LICCLASS_INTRO_MD}"
        echo ""
        echo "| Network copyleft | Strong copyleft | Weak copyleft | Permissive | Uncategorized |"
        echo "|---:|---:|---:|---:|---:|"
        echo "| ${NC} | ${SC} | ${WK} | ${PM} | ${UN} |"
        if [ "$COPYLEFT_TOTAL" -gt 0 ]; then
            echo ""
            echo "${P_COPYLEFT_DRIVERS}"
            echo ""
            echo "$COPYLEFT_TOP" | jq -r '.[] | "- `" + .label + "` (" + .class + ")"'
            if [ "$COPYLEFT_TOTAL" -gt 10 ]; then
                echo "${P_COPYLEFT_MORE_MD}"
            fi
        fi
    fi
    if [ -n "$OUTBOUND_LIC" ]; then
        echo ""
        echo "### ${P_H3_LICCONFLICT}"
        echo ""
        echo "${P_LICCONFLICT_INTRO}"
        echo ""
        echo "${P_TH_LC}"
        echo "|---|---:|---:|---:|"
        echo "| \`${OUTBOUND_LIC}\` | ${LC_INCOMPAT} | ${LC_COND} | ${LC_UNKNOWN} |"
        if [ "$LC_INCOMPAT" -gt 0 ]; then
            echo ""
            echo "${P_LICCONFLICT_DRIVERS}"
            echo ""
            echo "$LC_TOP" | jq -r '.[] | "- `" + . + "`"'
        fi
    fi
    if [ "$MAL_COUNT" -gt 0 ]; then
        echo ""
        echo "### ${P_H3_MALICIOUS}"
        echo ""
        echo "${P_MALICIOUS_INTRO}"
        echo ""
        echo "${P_MALICIOUS_LIST}"
        echo ""
        echo "$MAL_TOP" | jq -r '.[] | "- `" + .label + "` (" + .id + ")"'
        echo ""
        echo "_${MAL_SNAP}_"
    fi
    if [ "$AS_MODELS" -gt 0 ]; then
        echo ""
        echo "### ${P_H3_AI}"
        echo ""
        echo "${P_AI_SEE_MD} ${P_AI_DISC}"
        echo ""
        echo "| ${L_OK} | ${L_COND} | ${L_CAU} | ${L_REV} |"
        echo "|---:|---:|---:|---:|"
        echo "| ${AS_OK} | ${AS_COND} | ${AS_CAU} | ${AS_REV} |"
    fi
    echo ""
    echo "## ${S_NEXT}. ${P_H2_NEXT}"
    echo ""
    echo "1. ${P_NEXT1_PRE}**${P_NEXT1_BOLD}**${P_NEXT1_POST}"
    if [ "$HAS_CONF" = "true" ]; then
        echo "2. ${P_NEXT2_CONF}"
    else
        echo "2. ${P_NEXT2_SELF_MD}"
    fi
} > "$MD"

# --------------------------------------------------------
# HTML (cards/table/CSP/escape pattern from scan-security.sh)
# --------------------------------------------------------
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
conf_class="warn"; [ "$CONF_RESULT" = "pass" ] && conf_class="pass"; [ "$CONF_RESULT" = "fail" ] && conf_class="fail"
# Meta suffix only states the input format for supplier (ANALYZE) reports (section
# numbers S_CONF/S_VULN/S_LIC/S_NEXT were assigned once near the top).
META_FORMAT=""; [ "$HAS_CONF" = "true" ] && META_FORMAT=" &middot; ${P_META_FORMAT} $(esc "$CONF_FORMAT")"
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="${REPORT_LANG}"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>${P_H1} — $(esc "$PROJECT")</title>
HTMLHEAD
    report_style
    cat <<HTMLHEAD2
</head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">${P_KIND}</div>
</header>
<h1>${P_H1}</h1>
${SUBTITLE_HTML}<p class="meta">${P_META_PROJECT} $(esc "$PROJECT") &middot; ${P_META_GENERATED} $(report_time_html "$GEN_AT")${META_FORMAT}</p>
HTMLHEAD2

    if [ "$HAS_CONF" = "true" ]; then
        echo "<h2>${S_CONF}. ${P_H2_CONF}</h2>"
        echo "<div class=\"cards\"><span class=\"pill pill-${conf_class}\">${P_CONF_RESULT_LBL} ${CONF_UP}</span></div>"
        if [ "$CONF_RESULT" = "fail" ]; then
            echo "<div class=\"note\"><b>${P_CONF_FAIL_B}</b>${P_CONF_FAIL_TXT}"
            echo "<ul>"
            echo "$CONF_FAILS" | jq -r '.[] | "<li>" + (.|@html) + "</li>"'
            echo "</ul></div>"
        fi
    fi

    cat <<HTMLSEC
<h2>${S_VULN}. ${P_H2_VULN}</h2>
${P_VULN_NOTE_HTML}
<div class="cards">
 <span class="pill pill-crit">Critical <span class="count">${C}</span></span>
 <span class="pill pill-high">High <span class="count">${H}</span></span>
 <span class="pill pill-med">Medium <span class="count">${M}</span></span>
 <span class="pill pill-low">Low <span class="count">${L}</span></span>
 <span class="pill pill-info">Unknown <span class="count">${U}</span></span>
</div>
HTMLSEC

    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "<div class=\"note\">${P_UNREACHED_HTML}</div>"
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "<div class=\"note\">${P_UNCHECKED_HTML}<ul>"
        # shellcheck disable=SC2016
        echo "$UNCHECKED_TOP" | jq -r --arg nv "$P_REASON_NO_VERSION" --arg ni "$P_REASON_NO_ID" '.[] |
            "<li><code>" + (.name | @html) + "</code>" + (if .version != "" then " " + (.version | @html) else "" end)
            + " (" + ((if .reason == "no-version" then $nv elif .reason == "no-identifier" then $ni else .reason end) | @html) + ")</li>"'
        if [ "$UNCHECKED_N" -gt "$UNCHECKED_LIST_MAX" ]; then echo "<li>$(esc "$P_UNCHECKED_MORE")</li>"; fi
        echo "</ul></div>"
    elif [ "${PRESENCE_ONLY:-0}" -gt 0 ]; then
        echo "<div class=\"note\">${P_PRESENCE_HTML}</div>"
    fi
    if [ "$FW_SCOPE" = "true" ]; then
        echo "<div class=\"note\"><b>${P_FW_LABEL}</b> ${FW_SCOPE_TEXT}"
        if [ -n "$FW_FAILED_FORMATS" ]; then echo "<br>${P_FW_FORMATS}"; fi
        if [ -n "$FW_MISSING" ]; then echo "<br>${P_FW_MISSING}"; fi
        echo "</div>"
    fi

    if [ "$TOTAL" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><thead><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>${P_TH_DEADLINE}</th></tr></thead><tbody>"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "$P_DL_CRIT" --arg hd "$P_DL_HIGH" --arg pol "$P_DL_POLICY" '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td class=\"id\">" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + ((if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else $pol end)|@html) + "</td></tr>"'
        echo "</tbody></table></div>"
    elif [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "<p>${P_VULN_NONE_CHECKED_HTML}</p>"
    else
        echo "<p>${P_VULN_NONE_HTML}</p>"
    fi

    echo "<h2>${S_LIC}. ${P_H2_LIC}</h2>"
    if [ "$LIC_COUNT" = "N/A" ]; then
        echo "<p><em>${P_LIC_NO_NOTICE_HTML}</em></p>"
    else
        echo "<p>${P_LIC_HTML_PRE} <b>${LIC_COUNT}</b>${P_LIC_HTML_POST}</p>"
    fi
    if [ "$HAS_LIC_CLASS" = "true" ]; then
        echo "<h3>${P_H3_LICCLASS}</h3>"
        echo "<p>${P_LICCLASS_INTRO_A}<code>bomlens:licenseClass</code>${P_LICCLASS_INTRO_B}</p>"
        cat <<HTMLLIC
<div class="cards">
 <span class="pill pill-cat-network">Network copyleft <span class="count">${NC}</span></span>
 <span class="pill pill-cat-strong">Strong copyleft <span class="count">${SC}</span></span>
 <span class="pill pill-cat-weak">Weak copyleft <span class="count">${WK}</span></span>
 <span class="pill pill-cat-permissive">Permissive <span class="count">${PM}</span></span>
 <span class="pill pill-cat-review">Uncategorized <span class="count">${UN}</span></span>
</div>
HTMLLIC
        if [ "$COPYLEFT_TOTAL" -gt 0 ]; then
            echo "<p>${P_COPYLEFT_DRIVERS}</p>"
            echo "<ul class=\"mono\">"
            echo "$COPYLEFT_TOP" | jq -r '.[] | "<li>" + (.label|@html) + " (" + .class + ")</li>"'
            if [ "$COPYLEFT_TOTAL" -gt 10 ]; then
                echo "<li>${P_CL_MORE_PRE}$((COPYLEFT_TOTAL - 10))${P_CL_MORE_MID}<code>bomlens:licenseClass</code>${P_CL_MORE_END}</li>"
            fi
            echo "</ul>"
        fi
    fi
    if [ -n "$OUTBOUND_LIC" ]; then
        echo "<h3>${P_H3_LICCONFLICT}</h3>"
        echo "<p>${P_LICCONFLICT_INTRO}</p>"
        echo "<p><code>$(printf '%s' "$OUTBOUND_LIC" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</code></p>"
        cat <<HTMLLC
<div class="cards">
 <span class="pill pill-crit">Incompatible <span class="count">${LC_INCOMPAT}</span></span>
 <span class="pill pill-med">Conditional <span class="count">${LC_COND}</span></span>
 <span class="pill pill-info">Unknown <span class="count">${LC_UNKNOWN}</span></span>
</div>
HTMLLC
        if [ "$LC_INCOMPAT" -gt 0 ]; then
            echo "<p>${P_LICCONFLICT_DRIVERS}</p>"
            echo "<ul class=\"mono\">"
            echo "$LC_TOP" | jq -r '.[] | "<li>" + (.|@html) + "</li>"'
            echo "</ul>"
        fi
    fi

    if [ "$MAL_COUNT" -gt 0 ]; then
        echo "<h3>${P_H3_MALICIOUS}</h3>"
        echo "<p>${P_MALICIOUS_INTRO}</p>"
        echo "<div class=\"cards\"><span class=\"pill pill-crit\">${P_H3_MALICIOUS} <span class=\"count\">${MAL_COUNT}</span></span></div>"
        echo "<p>${P_MALICIOUS_LIST}</p>"
        echo "<ul class=\"mono\">"
        echo "$MAL_TOP" | jq -r '.[] | "<li>" + (.label|@html) + " (" + (.id|@html) + ")</li>"'
        echo "</ul>"
        echo "<p class=\"meta\">$(printf '%s' "$MAL_SNAP" | sed 's/&/\&amp;/g; s/</\&lt;/g')</p>"
    fi
    if [ "$AS_MODELS" -gt 0 ]; then
        echo "<h3>${P_H3_AI}</h3>"
        echo "<p>${P_AI_SEE_HTML} ${P_AI_DISC}</p>"
        cat <<HTMLASSESS
<div class="cards">
 <span class="pill pill-pass">${L_OK} <span class="count">${AS_OK}</span></span>
 <span class="pill pill-med">${L_COND} <span class="count">${AS_COND}</span></span>
 <span class="pill pill-high">${L_CAU} <span class="count">${AS_CAU}</span></span>
 <span class="pill pill-info">${L_REV} <span class="count">${AS_REV}</span></span>
</div>
HTMLASSESS
    fi

    echo "<h2>${S_NEXT}. ${P_H2_NEXT}</h2>"
    echo "<ol>"
    echo " <li>${P_NEXT1_PRE}<b>${P_NEXT1_BOLD}</b>${P_NEXT1_POST}</li>"
    if [ "$HAS_CONF" = "true" ]; then
        echo " <li>${P_NEXT2_CONF}</li>"
    else
        echo " <li>${P_NEXT2_SELF_HTML}</li>"
    fi
    echo "</ol>"
    echo "</body></html>"
} > "$HTML"

echo "[risk] generated: $MD, $HTML (conformance=${CONF_RESULT}, vulns total=${TOTAL}, crit=${C}, high=${H}, copyleft=${COPYLEFT_TOTAL} strong/network + ${WK} weak${OUTBOUND_LIC:+, license-conflict incompatible=${LC_INCOMPAT}}, malicious=${MAL_COUNT})"
