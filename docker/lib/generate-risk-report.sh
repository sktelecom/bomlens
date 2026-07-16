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
# (validate an externally-submitted SBOM's format); without one it is a
# SELF-GENERATED 오픈소스 위험 분석 보고서 (source/firmware/image/binary/rootfs scan).
# The format-validation section only applies to the supplier case.
# --------------------------------------------------------
if [ "$CONF_RESULT" = "N/A" ]; then
    HAS_CONF=false
    REPORT_TITLE="오픈소스 위험 분석 보고서 — ${PROJECT}"
    HTML_H1="오픈소스 위험 분석 보고서"
    # Self mode: no 포맷 검증 section, so numbering starts at 취약점.
    S_CONF=""; S_VULN=1; S_LIC=2; S_NEXT=3
else
    HAS_CONF=true
    REPORT_TITLE="공급사 SBOM 위험 보고서 — ${PROJECT}"
    HTML_H1="공급사 SBOM 위험 보고서"
    S_CONF=1; S_VULN=2; S_LIC=3; S_NEXT=4
fi

# deadline string per severity (Korean, recommended)
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
            echo "> ⚠️ **포맷 검증 미충족 항목** — 아래 필수 항목이 빠져 있습니다. 보완 후 재검증을 권장합니다."
            echo ""
            echo "$CONF_FAILS" | jq -r '.[] | "- " + .'
        fi
        echo ""
    fi
    echo "## ${S_VULN}. 취약점 분석 및 대응 기한"
    echo ""
    echo "> 권고 대응 기한: **Critical → ${CRIT_DAYS}일 이내, High → ${HIGH_DAYS}일 이내** 대응계획 또는 위험 정당화를 마련하는 것을 권장합니다."
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
    if [ "$HAS_LIC_CLASS" = "true" ]; then
        echo ""
        echo "### 라이선스 분류 (카피레프트 강도)"
        echo ""
        echo "각 컴포넌트는 SBOM에 \`bomlens:licenseClass\` 속성으로도 기록되어 있습니다. 인식되지 않은 라이선스는 permissive로 간주하지 않고 미분류(uncategorized)로 남깁니다."
        echo ""
        echo "| Network copyleft | Strong copyleft | Weak copyleft | Permissive | 미분류 |"
        echo "|---:|---:|---:|---:|---:|"
        echo "| ${NC} | ${SC} | ${WK} | ${PM} | ${UN} |"
        if [ "$COPYLEFT_TOTAL" -gt 0 ]; then
            echo ""
            echo "카피레프트 노출을 만드는 컴포넌트 (network/strong, 최대 10개):"
            echo ""
            echo "$COPYLEFT_TOP" | jq -r '.[] | "- `" + .label + "` (" + .class + ")"'
            if [ "$COPYLEFT_TOTAL" -gt 10 ]; then
                echo "- 외 $((COPYLEFT_TOTAL - 10))개 (전체는 SBOM의 \`bomlens:licenseClass\` 속성 참조)"
            fi
        fi
    fi
    echo ""
    echo "## ${S_NEXT}. 다음 단계"
    echo ""
    echo "1. 위 권고 대응 기한 내 **대응계획 또는 위험 정당화**를 마련."
    if [ "$HAS_CONF" = "true" ]; then
        echo "2. 포맷 검증에 실패한 경우 누락 항목을 보완하여 SBOM을 재생성."
    else
        echo "2. 고지문(\`${OUT_PREFIX}_NOTICE.{txt,html}\`)과 SBOM(\`${OUT_PREFIX}_bom.json\`)을 함께 보관·배포."
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
 <div class="report-kind">Risk Report</div>
</header>
<h1>${HTML_H1}</h1>
<p class="meta">Project: $(esc "$PROJECT") &middot; Generated: ${GEN_AT}${META_FORMAT}</p>
HTMLHEAD

    if [ "$HAS_CONF" = "true" ]; then
        echo "<h2>${S_CONF}. 요구사항 충족 (포맷 검증)</h2>"
        echo "<div class=\"cards\"><span class=\"pill pill-${conf_class}\">검증 결과: $(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')</span></div>"
        if [ "$CONF_RESULT" = "fail" ]; then
            echo "<div class=\"note\"><b>포맷 검증 미충족 항목</b> — 아래 필수 항목이 빠져 있습니다. 보완 후 재검증을 권장합니다."
            echo "<ul>"
            echo "$CONF_FAILS" | jq -r '.[] | "<li>" + (.|@html) + "</li>"'
            echo "</ul></div>"
        fi
    fi

    cat <<HTMLSEC
<h2>${S_VULN}. 취약점 분석 및 대응 기한</h2>
<div class="note">권고 대응 기한: <b>Critical → ${CRIT_DAYS}일 이내</b>, <b>High → ${HIGH_DAYS}일 이내</b> 대응계획 또는 위험 정당화를 마련하는 것을 권장합니다.</div>
<div class="cards">
 <span class="pill pill-crit">Critical <span class="count">${C}</span></span>
 <span class="pill pill-high">High <span class="count">${H}</span></span>
 <span class="pill pill-med">Medium <span class="count">${M}</span></span>
 <span class="pill pill-low">Low <span class="count">${L}</span></span>
 <span class="pill pill-info">Unknown <span class="count">${U}</span></span>
</div>
HTMLSEC

    if [ "$TOTAL" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>대응 기한</th></tr>"
        # shellcheck disable=SC2016
        echo "$FINDINGS" | jq -r --arg cd "${CRIT_DAYS}일 이내" --arg hd "${HIGH_DAYS}일 이내" '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + ((if .severity=="CRITICAL" then $cd elif .severity=="HIGH" then $hd else "정책에 따름" end)|@html) + "</td></tr>"'
        echo "</table></div>"
    else
        echo "<p>알려진 취약점이 없거나 security 산출물이 없습니다.</p>"
    fi

    echo "<h2>${S_LIC}. 라이선스 요약</h2>"
    if [ "$LIC_COUNT" = "N/A" ]; then
        echo "<p><em>NOTICE 산출물이 없어 생략합니다.</em></p>"
    else
        echo "<p>식별된 distinct 라이선스: <b>${LIC_COUNT}</b>건 (상세는 NOTICE 산출물 참조).</p>"
    fi
    if [ "$HAS_LIC_CLASS" = "true" ]; then
        echo "<h3>라이선스 분류 (카피레프트 강도)</h3>"
        echo "<p>각 컴포넌트는 SBOM에 <code>bomlens:licenseClass</code> 속성으로도 기록되어 있습니다. 인식되지 않은 라이선스는 permissive로 간주하지 않고 미분류(uncategorized)로 남깁니다.</p>"
        cat <<HTMLLIC
<div class="cards">
 <span class="pill pill-crit">Network copyleft <span class="count">${NC}</span></span>
 <span class="pill pill-high">Strong copyleft <span class="count">${SC}</span></span>
 <span class="pill pill-med">Weak copyleft <span class="count">${WK}</span></span>
 <span class="pill pill-pass">Permissive <span class="count">${PM}</span></span>
 <span class="pill pill-info">미분류 <span class="count">${UN}</span></span>
</div>
HTMLLIC
        if [ "$COPYLEFT_TOTAL" -gt 0 ]; then
            echo "<p>카피레프트 노출을 만드는 컴포넌트 (network/strong, 최대 10개):</p>"
            echo "<ul class=\"mono\">"
            echo "$COPYLEFT_TOP" | jq -r '.[] | "<li>" + (.label|@html) + " (" + .class + ")</li>"'
            if [ "$COPYLEFT_TOTAL" -gt 10 ]; then
                echo "<li>외 $((COPYLEFT_TOTAL - 10))개 (전체는 SBOM의 <code>bomlens:licenseClass</code> 속성 참조)</li>"
            fi
            echo "</ul>"
        fi
    fi

    echo "<h2>${S_NEXT}. 다음 단계</h2>"
    echo "<ol>"
    echo " <li>위 권고 대응 기한 내 <b>대응계획 또는 위험 정당화</b>를 마련.</li>"
    if [ "$HAS_CONF" = "true" ]; then
        echo " <li>포맷 검증에 실패한 경우 누락 항목을 보완하여 SBOM을 재생성.</li>"
    else
        echo " <li>고지문(NOTICE)과 SBOM을 함께 보관·배포.</li>"
    fi
    echo "</ol>"
    echo "</body></html>"
} > "$HTML"

echo "[risk] generated: $MD, $HTML (conformance=${CONF_RESULT}, vulns total=${TOTAL}, crit=${C}, high=${H}, copyleft=${COPYLEFT_TOTAL})"
