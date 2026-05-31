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
# Mirrors the SKT review output: conformance verdict + vulnerability triage with
# the Critical-7-day / High-30-day remediation deadlines. Missing inputs are
# skipped gracefully. See docs/supplier-sbom-analysis.md §6.
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

# Remediation SLAs (SKT process step ③).
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
# (validate an externally-submitted SBOM's format); without one it is a
# SELF-GENERATED 오픈소스위험분석보고서 (source/firmware/image/binary/rootfs scan).
# The format-validation section only applies to the supplier case.
# --------------------------------------------------------
if [ "$CONF_RESULT" = "N/A" ]; then
    HAS_CONF=false
    REPORT_TITLE="오픈소스위험분석보고서 — ${PROJECT}"
    HTML_H1="오픈소스위험분석보고서"
    # Self mode: no 포맷 검증 section, so numbering starts at 취약점.
    S_CONF=""; S_VULN=1; S_LIC=2; S_NEXT=3
else
    HAS_CONF=true
    REPORT_TITLE="공급사 SBOM 위험 보고서 — ${PROJECT}"
    HTML_H1="공급사 SBOM 위험 보고서"
    S_CONF=1; S_VULN=2; S_LIC=3; S_NEXT=4
fi

# deadline string per severity (Korean, per SKT process)
deadline_for() {
    case "$1" in
        CRITICAL) echo "${CRIT_DAYS}일 이내" ;;
        HIGH)     echo "${HIGH_DAYS}일 이내" ;;
        *)        echo "정책에 따름" ;;
    esac
}

# --------------------------------------------------------
# License summary (from NOTICE text, best-effort)
# --------------------------------------------------------
LIC_COUNT="N/A"
if [ -f "$NOTICE" ]; then
    LIC_COUNT=$(grep -c '^License: ' "$NOTICE" 2>/dev/null || echo 0)
fi

# --------------------------------------------------------
# Markdown
# --------------------------------------------------------
{
    echo "# ${REPORT_TITLE}"
    echo ""
    echo "- 생성: ${GEN_AT}"
    echo "- 본 보고서는 새 스캔 없이 취약점/라이선스 산출물을 재집계한 것입니다."
    echo ""
    if [ "$HAS_CONF" = "true" ]; then
        echo "## ${S_CONF}. 요구사항 충족 (포맷 검증)"
        echo ""
        echo "- 입력 포맷: ${CONF_FORMAT}"
        echo "- 검증 결과: **$(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')**"
        if [ "$CONF_RESULT" = "fail" ]; then
            echo ""
            echo "> ⚠️ **SKT 포맷 검증 반려 사유** — 아래 필수 항목 미충족. 보완 후 재제출이 필요합니다."
            echo ""
            echo "$CONF_FAILS" | jq -r '.[] | "- " + .'
        fi
        echo ""
    fi
    echo "## ${S_VULN}. 취약점 분석 및 대응 기한"
    echo ""
    echo "> SKT 검증 프로세스 ③: **Critical → ${CRIT_DAYS}일 이내, High → ${HIGH_DAYS}일 이내** 대응계획 또는 위험 정당화 제출이 필요합니다."
    echo ""
    echo "| Critical | High | Medium | Low | Unknown | Total |"
    echo "|---:|---:|---:|---:|---:|---:|"
    echo "| ${C} | ${H} | ${M} | ${L} | ${U} | ${TOTAL} |"
    echo ""
    if [ "$TOTAL" -gt 0 ]; then
        echo "| Severity | CVE | Package | Installed | Fixed | 대응 기한 |"
        echo "|----------|-----|---------|-----------|-------|-----------|"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "${CRIT_DAYS}일 이내" --arg hd "${HIGH_DAYS}일 이내" '.[] |
            "| \(.severity) | \(.id) | \(.pkg) | \(.version) | \(.fixed) | \(
              if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else "정책에 따름" end
            ) |"'
    else
        echo "_알려진 취약점이 없거나 security 산출물이 없습니다._"
    fi
    echo ""
    echo "## ${S_LIC}. 라이선스 요약"
    echo ""
    if [ "$LIC_COUNT" = "N/A" ]; then
        echo "_NOTICE 산출물이 없어 생략합니다._"
    else
        echo "- 식별된 distinct 라이선스: ${LIC_COUNT}건 (상세는 \`${OUT_PREFIX}_NOTICE.{txt,html}\` 참조)"
    fi
    echo ""
    echo "## ${S_NEXT}. 다음 단계"
    echo ""
    echo "1. 위 대응 기한 내 **대응계획 또는 위험 정당화**를 SKT 검증 프로세스 ③에 따라 제출."
    if [ "$HAS_CONF" = "true" ]; then
        echo "2. 포맷 검증이 반려(fail)된 경우 누락 항목을 보완하여 SBOM 재제출."
        echo "3. 결과는 SKT 내부 시스템(TOSCA)에 등록·관리됩니다(포털 범위)."
    else
        echo "2. 고지문(\`${OUT_PREFIX}_NOTICE.{txt,html}\`)과 SBOM(\`${OUT_PREFIX}_bom.json\`)을 납품 산출물로 함께 제출."
        echo "3. 결과는 SKT 내부 시스템(TOSCA)에 등록·관리됩니다(포털 범위)."
    fi
} > "$MD"

# --------------------------------------------------------
# HTML (cards/table/CSP/escape pattern from scan-security.sh)
# --------------------------------------------------------
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
conf_class="warn"; [ "$CONF_RESULT" = "pass" ] && conf_class="pass"; [ "$CONF_RESULT" = "fail" ] && conf_class="fail"
# Meta suffix only states 입력 포맷 for supplier (ANALYZE) reports (section numbers
# S_CONF/S_VULN/S_LIC/S_NEXT were assigned once near the top).
META_FORMAT=""; [ "$HAS_CONF" = "true" ] && META_FORMAT=" &middot; 입력 포맷: ${CONF_FORMAT}"
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>${HTML_H1} — ${PROJECT}</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;}
 h1{border-bottom:2px solid #ddd;padding-bottom:.4rem;} h2{margin-top:1.8rem;}
 .meta{color:#666;font-size:.9rem;}
 .cards{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0;}
 .card{padding:.6rem 1rem;border-radius:6px;color:#fff;font-weight:600;}
 .pass{background:#16a34a;} .fail{background:#dc2626;} .warn{background:#6b7280;}
 .crit{background:#dc2626;} .high{background:#ea580c;} .med{background:#d97706;}
 .low{background:#2563eb;} .unk{background:#6b7280;}
 .note{background:#fff7ed;border-left:4px solid #ea580c;padding:.6rem 1rem;margin:1rem 0;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th,td{border:1px solid #e3e3e3;padding:.4rem .6rem;text-align:left;}
 th{background:#f3f4f6;}
 .sev-CRITICAL{color:#dc2626;font-weight:700;} .sev-HIGH{color:#ea580c;font-weight:700;}
 .sev-MEDIUM{color:#d97706;} .sev-LOW{color:#2563eb;}
 ul{margin:.3rem 0 0 1rem;}
</style></head><body>
<h1>${HTML_H1}</h1>
<p class="meta">Project: $(esc "$PROJECT") &middot; Generated: ${GEN_AT}${META_FORMAT}</p>
HTMLHEAD

    if [ "$HAS_CONF" = "true" ]; then
        echo "<h2>${S_CONF}. 요구사항 충족 (포맷 검증)</h2>"
        echo "<div class=\"cards\"><div class=\"card ${conf_class}\">검증 결과: $(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')</div></div>"
        if [ "$CONF_RESULT" = "fail" ]; then
            echo "<div class=\"note\"><b>SKT 포맷 검증 반려 사유</b> — 아래 필수 항목 미충족. 보완 후 재제출이 필요합니다."
            echo "<ul>"
            echo "$CONF_FAILS" | jq -r '.[] | "<li>" + (.|@html) + "</li>"'
            echo "</ul></div>"
        fi
    fi

    cat <<HTMLSEC
<h2>${S_VULN}. 취약점 분석 및 대응 기한</h2>
<div class="note">SKT 검증 프로세스 ③: <b>Critical → ${CRIT_DAYS}일 이내</b>, <b>High → ${HIGH_DAYS}일 이내</b> 대응계획 또는 위험 정당화 제출이 필요합니다.</div>
<div class="cards">
 <div class="card crit">Critical ${C}</div>
 <div class="card high">High ${H}</div>
 <div class="card med">Medium ${M}</div>
 <div class="card low">Low ${L}</div>
 <div class="card unk">Unknown ${U}</div>
</div>
HTMLSEC

    if [ "$TOTAL" -gt 0 ]; then
        echo "<table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>대응 기한</th></tr>"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "${CRIT_DAYS}일 이내" --arg hd "${HIGH_DAYS}일 이내" '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + ((if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else "정책에 따름" end)|@html) + "</td></tr>"'
        echo "</table>"
    else
        echo "<p>알려진 취약점이 없거나 security 산출물이 없습니다.</p>"
    fi

    echo "<h2>${S_LIC}. 라이선스 요약</h2>"
    if [ "$LIC_COUNT" = "N/A" ]; then
        echo "<p><em>NOTICE 산출물이 없어 생략합니다.</em></p>"
    else
        echo "<p>식별된 distinct 라이선스: <b>${LIC_COUNT}</b>건 (상세는 NOTICE 산출물 참조).</p>"
    fi

    echo "<h2>${S_NEXT}. 다음 단계</h2>"
    echo "<ol>"
    echo " <li>위 대응 기한 내 <b>대응계획 또는 위험 정당화</b>를 SKT 검증 프로세스 ③에 따라 제출.</li>"
    if [ "$HAS_CONF" = "true" ]; then
        echo " <li>포맷 검증이 반려(fail)된 경우 누락 항목을 보완하여 SBOM 재제출.</li>"
    else
        echo " <li>고지문(NOTICE)과 SBOM을 납품 산출물로 함께 제출.</li>"
    fi
    echo " <li>결과는 SKT 내부 시스템(TOSCA)에 등록·관리됩니다(포털 범위).</li>"
    echo "</ol>"
    echo "</body></html>"
} > "$HTML"

echo "[risk] generated: $MD, $HTML (conformance=${CONF_RESULT}, vulns total=${TOTAL}, crit=${C}, high=${H})"
