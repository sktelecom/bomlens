#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# generate-risk-report.sh — assemble a supplier-facing risk report by RE-AGGREGATING
# artifacts already produced by the pipeline (no new scan is run).
#
# Usage: generate-risk-report.sh <out_prefix> <project_name>
#   reads  <out_prefix>_conformance.json   (validate-sbom.sh)
#          <out_prefix>_security.json       (scan-security.sh / Trivy)
#          <out_prefix>_NOTICE.txt          (generate-notice.sh)
#   writes <out_prefix>_risk-report.md  and  <out_prefix>_risk-report.html
#
# Aggregates a supply-chain risk view: conformance verdict + vulnerability triage
# with recommended Critical-7-day / High-30-day remediation deadlines. Missing
# inputs are skipped gracefully. See docs/supplier-sbom-analysis.md §6.
set -e

OUT_PREFIX="$1"
PROJECT="${2:-project}"

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
FINDINGS='[]'
if [ -f "$SEC" ] && jq empty "$SEC" >/dev/null 2>&1; then
    FINDINGS=$(jq -c '
      [ .Results[]?.Vulnerabilities[]? | {
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
C=$(sev_count CRITICAL); H=$(sev_count HIGH); M=$(sev_count MEDIUM); L=$(sev_count LOW); U=$(sev_count UNKNOWN)
TOTAL=$(echo "$FINDINGS" | jq 'length')

# --------------------------------------------------------
# Report kind: with a conformance artifact this is a SUPPLIER SBOM review
# (validate an externally-submitted SBOM format); without one it is a
# SELF-GENERATED open-source risk analysis report (source/firmware/image/
# binary/rootfs scan). The format-validation section only applies to the
# supplier case. Section numbering is assigned once here; the titles and every
# other user-facing string are set in the localization block below.
# --------------------------------------------------------
if [ "$CONF_RESULT" = "N/A" ]; then
    HAS_CONF=false
    # Self mode: no format-validation section, so numbering starts at vulnerabilities.
    S_CONF=""; S_VULN=1; S_LIC=2; S_NEXT=3
else
    HAS_CONF=true
    S_CONF=1; S_VULN=2; S_LIC=3; S_NEXT=4
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
LIC_CLASS='null'
if [ -f "$BOM" ] && [ -f "$LIB_DIR/license-flags.jq" ] && jq empty "$BOM" >/dev/null 2>&1; then
    LIC_CLASS=$(jq -c "$(cat "$LIB_DIR/license-flags.jq")"'
      [ .components[]? | { class: component_license_class,
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

# AI model risk assessment rollup (AIBOM/ANALYZE): re-aggregate the
# bomlens:assessment:* verdicts assess-ai-risk.sh stamped; absent for a plain
# software SBOM, in which case the section is skipped entirely.
AS_MODELS=0; AS_OK=0; AS_COND=0; AS_CAU=0; AS_REV=0
if [ -f "$BOM" ] && jq empty "$BOM" >/dev/null 2>&1; then
    AS_COUNTS=$(jq -c '[ .components[]? | select(.type=="machine-learning-model")
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
    if [ "$HAS_CONF" = "true" ]; then
        P_TITLE=$(tfmt risk.md_title_supplier "$PROJECT"); P_H1=$(kstr risk.h1_supplier)
    else
        P_TITLE=$(tfmt risk.md_title_self "$PROJECT"); P_H1=$(kstr risk.h1_self)
    fi
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
    P_H2_LIC=$(kstr risk.h2_lic)
    P_LIC_NO_NOTICE_MD=$(kstr risk.lic_no_notice_md); P_LIC_NO_NOTICE_HTML=$(kstr risk.lic_no_notice_html)
    P_MD_LIC_COUNT=$(tfmt risk.md_lic_count "$LIC_COUNT" "$OUT_PREFIX")
    P_LIC_HTML_PRE=$(kstr risk.lic_html_pre); P_LIC_HTML_POST=$(kstr risk.lic_html_post)
    P_H3_LICCLASS=$(kstr risk.h3_licclass)
    P_LICCLASS_INTRO_MD=$(kstr risk.licclass_intro_md)
    P_LICCLASS_INTRO_A=$(kstr risk.licclass_intro_html_a); P_LICCLASS_INTRO_B=$(kstr risk.licclass_intro_html_b)
    P_TH_UNCAT=$(kstr risk.th_uncat)
    P_COPYLEFT_DRIVERS=$(kstr risk.copyleft_drivers)
    P_H3_LICCONFLICT=$(kstr risk.h3_licconflict)
    P_LICCONFLICT_INTRO=$(kstr risk.licconflict_intro)
    P_TH_LC=$(kstr risk.th_licconflict)
    P_LICCONFLICT_DRIVERS=$(kstr risk.licconflict_drivers)
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
    if [ "$HAS_CONF" = "true" ]; then
        P_TITLE="Supplier SBOM risk report — ${PROJECT}"; P_H1="Supplier SBOM risk report"
    else
        P_TITLE="Open-source risk analysis report — ${PROJECT}"; P_H1="Open-source risk analysis report"
    fi
    P_MD_GEN="- Generated: ${GEN_AT}"
    P_MD_INTRO="- This report re-aggregates the vulnerability and license artifacts already produced, without running a new scan."
    P_H2_CONF="Requirements met (format validation)"
    P_MD_CONF_FMT="- Input format: ${CONF_FORMAT}"
    P_MD_CONF_RESULT="- Validation result: **${CONF_UP}**"
    P_MD_CONF_FAIL="> ⚠️ **Unmet format-validation items** — the required items below are missing. We recommend fixing them and re-validating."
    P_CONF_RESULT_LBL="Validation result:"
    P_CONF_FAIL_B="Unmet format-validation items"
    P_CONF_FAIL_TXT=" — the required items below are missing. We recommend fixing them and re-validating."
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
    P_TH_UNCAT="Uncategorized"
    P_COPYLEFT_DRIVERS="Components that create copyleft exposure (network/strong, up to 10):"
    P_H3_LICCONFLICT="Outbound-license conflicts"
    P_LICCONFLICT_INTRO="Dependencies checked against the declared outbound license. Advisory only — it surfaces combinations that need a person to look, and makes no legal determination."
    P_TH_LC="| Outbound license | Incompatible | Conditional | Unknown |"
    P_LICCONFLICT_DRIVERS="Dependencies whose terms clash with the outbound license (up to 10):"
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
    P_NEXT2_CONF="If format validation failed, fill the missing items and regenerate the SBOM."
    P_NEXT2_SELF_MD="Keep and distribute the notice (\`${OUT_PREFIX}_NOTICE.{txt,html}\`) together with the SBOM (\`${OUT_PREFIX}_bom.json\`)."
    P_NEXT2_SELF_HTML="Keep and distribute the notice (NOTICE) together with the SBOM."
    P_KIND="Risk Report"
    P_META_PROJECT="Project:"; P_META_GENERATED="Generated:"; P_META_FORMAT="Input format:"
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
    if [ "$TOTAL" -gt 0 ]; then
        echo "| Severity | CVE | Package | Installed | Fixed | ${P_TH_DEADLINE} |"
        echo "|----------|-----|---------|-----------|-------|-----------|"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "$P_DL_CRIT" --arg hd "$P_DL_HIGH" --arg pol "$P_DL_POLICY" '.[] |
            "| \(.severity) | \(.id) | \(.pkg) | \(.version) | \(.fixed) | \(
              if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else $pol end
            ) |"'
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
        echo "| Network copyleft | Strong copyleft | Weak copyleft | Permissive | ${P_TH_UNCAT} |"
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
<title>${P_H1} — ${PROJECT}</title>
<style>
 :root{
  --bg:#fafafa;--surface:#ffffff;--text:#18181b;--muted:#6c6c75;--border:#e5e5ea;
  --brand:#EA002C;--brand-2:#F47725;--th-bg:#f4f4f5;--row-hover:#fafafa;
  --radius:.375rem;--radius-card:.5rem;
  --shadow:0 1px 2px rgb(0 0 0/.04),0 2px 8px -2px rgb(0 0 0/.08);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
 }
 @media (prefers-color-scheme:dark){:root{
  --bg:#0a0a0c;--surface:#18181b;--text:#fafafa;--muted:#a1a1aa;--border:#27272a;
  --th-bg:#1f1f23;--row-hover:#202024;
  --shadow:0 1px 2px rgb(0 0 0/.3),0 2px 8px -2px rgb(0 0 0/.5);
 }}
 *{box-sizing:border-box;}
 body{font-family:var(--font);background:var(--bg);color:var(--text);
  max-width:1040px;margin:0 auto;padding:2.5rem 1.5rem 4rem;line-height:1.55;
  -webkit-font-smoothing:antialiased;}
 a{color:var(--brand);}
 .report-header{display:flex;align-items:flex-end;justify-content:space-between;
  gap:1rem;flex-wrap:wrap;padding-bottom:.85rem;border-bottom:1px solid var(--border);
  margin-bottom:1.5rem;}
 .wordmark{display:flex;align-items:center;gap:.5rem;font-size:1.15rem;font-weight:800;
  letter-spacing:-.02em;color:var(--brand);}
 .wordmark .tag{font-size:.62rem;font-weight:700;letter-spacing:.1em;color:var(--muted);
  border:1px solid var(--border);border-radius:999px;padding:.15rem .5rem;background:var(--surface);}
 .report-kind{font-size:.78rem;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.07em;}
 h1{font-size:1.55rem;font-weight:700;letter-spacing:-.01em;margin:.2rem 0 .35rem;}
 h2{font-size:1.15rem;font-weight:600;letter-spacing:-.01em;margin:2.1rem 0 .8rem;}
 h3{font-size:.95rem;font-weight:600;margin:1.3rem 0 .4rem;}
 .meta{color:var(--muted);font-size:.875rem;margin:.15rem 0 0;}
 .cards{display:flex;gap:.5rem;flex-wrap:wrap;margin:1.1rem 0 1.3rem;}
 .pill{display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .7rem;
  border-radius:999px;font-size:.8rem;font-weight:600;line-height:1.1;}
 .pill .count{font-variant-numeric:tabular-nums;}
 .pill-crit{background:rgba(220,38,38,.12);color:#dc2626;}
 .pill-high{background:rgba(234,88,12,.12);color:#ea580c;}
 .pill-med{background:rgba(202,138,4,.14);color:#ca8a04;}
 .pill-low{background:rgba(37,99,235,.12);color:#2563eb;}
 .pill-info{background:rgba(113,113,122,.14);color:#71717a;}
 .pill-kev{background:rgba(234,0,44,.12);color:#EA002C;}
 .pill-pass{background:rgba(22,163,74,.12);color:#16a34a;}
 .pill-fail{background:rgba(220,38,38,.12);color:#dc2626;}
 .pill-warn{background:rgba(202,138,4,.14);color:#ca8a04;}
 .note{background:rgba(244,119,37,.09);border-left:3px solid var(--brand-2);
  border-radius:var(--radius);padding:.75rem 1rem;margin:1rem 0 1.3rem;font-size:.875rem;}
 .note b{color:var(--text);}
 .table-wrap{border:1px solid var(--border);border-radius:var(--radius-card);
  overflow-x:auto;box-shadow:var(--shadow);background:var(--surface);margin:1rem 0 1.5rem;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th{background:var(--th-bg);text-align:left;font-size:.7rem;font-weight:600;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  padding:.6rem .8rem;border-bottom:1px solid var(--border);white-space:nowrap;}
 td{padding:.6rem .8rem;border-bottom:1px solid var(--border);vertical-align:top;}
 tr:last-child td{border-bottom:none;}
 tr:hover td{background:var(--row-hover);}
 td.num{text-align:right;font-variant-numeric:tabular-nums;}
 .sev-CRITICAL{color:#dc2626;font-weight:700;}
 .sev-HIGH{color:#ea580c;font-weight:700;}
 .sev-MEDIUM{color:#ca8a04;font-weight:600;}
 .sev-LOW{color:#2563eb;font-weight:600;}
 .sev-UNKNOWN{color:#71717a;}
 .mono li{font-family:var(--mono);font-size:.82rem;}
 ol,ul{margin:.5rem 0 0;padding-left:1.3rem;}
 li{margin:.3rem 0;}
</style></head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">${P_KIND}</div>
</header>
<h1>${P_H1}</h1>
<p class="meta">${P_META_PROJECT} $(esc "$PROJECT") &middot; ${P_META_GENERATED} ${GEN_AT}${META_FORMAT}</p>
HTMLHEAD

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

    if [ "$TOTAL" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>${P_TH_DEADLINE}</th></tr>"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "$P_DL_CRIT" --arg hd "$P_DL_HIGH" --arg pol "$P_DL_POLICY" '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + ((if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else $pol end)|@html) + "</td></tr>"'
        echo "</table></div>"
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
 <span class="pill pill-crit">Network copyleft <span class="count">${NC}</span></span>
 <span class="pill pill-high">Strong copyleft <span class="count">${SC}</span></span>
 <span class="pill pill-med">Weak copyleft <span class="count">${WK}</span></span>
 <span class="pill pill-pass">Permissive <span class="count">${PM}</span></span>
 <span class="pill pill-info">${P_TH_UNCAT} <span class="count">${UN}</span></span>
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

echo "[risk] generated: $MD, $HTML (conformance=${CONF_RESULT}, vulns total=${TOTAL}, crit=${C}, high=${H}, copyleft=${COPYLEFT_TOTAL}${OUTBOUND_LIC:+, license-conflict incompatible=${LC_INCOMPAT}})"
