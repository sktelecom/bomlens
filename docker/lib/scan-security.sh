#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# scan-security.sh — run Trivy against a CycloneDX SBOM and render a security report.
#
# Usage: scan-security.sh <sbom.json> <out_prefix> <project_name>
#   produces  <out_prefix>_security.json   (raw Trivy JSON)
#             <out_prefix>_security.md      (human summary)
#             <out_prefix>_security.html    (visual summary)
#
# Engine: Trivy (pinned in Dockerfile). DB: NVD + OSV + GHSA.
set -e

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[security] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! command -v trivy >/dev/null 2>&1; then
    echo "[security] WARN: trivy not installed in this image; skipping security report" >&2
    exit 0
fi

JSON="${OUT_PREFIX}_security.json"
MD="${OUT_PREFIX}_security.md"
HTML="${OUT_PREFIX}_security.html"
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[security] running Trivy SBOM scan..."
# --exit-code 0: report-only (never fail the scan pipeline on findings).
if ! trivy sbom --quiet --format json --output "$JSON" --exit-code 0 "$SBOM" 2>/tmp/trivy.err; then
    echo "[security] WARN: Trivy scan failed:" >&2
    cat /tmp/trivy.err >&2
    # Emit an empty-but-valid report so downstream steps don't break.
    echo '{"Results":[]}' > "$JSON"
fi

# Ensure .Results exists even when Trivy omits it (e.g. SBOM with no components).
if ! jq -e 'has("Results")' "$JSON" >/dev/null 2>&1; then
    tmp_r="$(mktemp)"
    if jq '. + {Results: []}' "$JSON" > "$tmp_r" 2>/dev/null; then mv "$tmp_r" "$JSON"; else echo '{"Results":[]}' > "$JSON"; rm -f "$tmp_r"; fi
fi

# Flatten findings: id, pkg, version, severity, fixed, cvss, title.
# cvss = highest V3 (fallback V2) score across Trivy's CVSS sources.
FINDINGS=$(jq -r '
  [ .Results[]?.Vulnerabilities[]? | {
      id: .VulnerabilityID,
      pkg: .PkgName,
      version: .InstalledVersion,
      severity: (.Severity // "UNKNOWN"),
      fixed: (.FixedVersion // ""),
      cvss: ([ (.CVSS // {}) | to_entries[] | .value | (.V3Score // .V2Score) ]
              | map(select(. != null)) | (max // null)),
      title: (.Title // .Description // "" | .[0:120])
    } ]
' "$JSON" 2>/dev/null || echo '[]')

# --- Priority enrichment (best-effort, network) -------------------------------
# EPSS = probability the CVE is exploited in the wild (FIRST.org, 0..1).
# KEV  = the CVE is on CISA's Known Exploited Vulnerabilities list (actively
# exploited, top priority). Both are looked up online; set SECURITY_ENRICH=false
# to skip (offline / air-gapped) — the report then omits the EPSS/KEV columns.
SECURITY_ENRICH="${SECURITY_ENRICH:-true}"
KEV_URL="${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
EPSS_API="${EPSS_API:-https://api.first.org/data/v1/epss}"
ENRICHED="false"; EPSS_MAP="{}"; KEV_LIST="[]"
CVE_LIST=$(echo "$FINDINGS" | jq -r '[.[].id | select(test("^CVE-"))] | unique | join(",")')
if [ "$SECURITY_ENRICH" != "false" ] && [ -n "$CVE_LIST" ]; then
    echo "[security] enriching with EPSS + CISA KEV..."
    EPSS_MAP=$(curl -sSfL --max-time 20 "$EPSS_API?cve=$CVE_LIST" 2>/dev/null \
        | jq '[.data[]? | {key: .cve, value: (.epss | tonumber)}] | from_entries' 2>/dev/null || echo "{}")
    KEV_LIST=$(curl -sSfL --max-time 25 "$KEV_URL" 2>/dev/null \
        | jq '[.vulnerabilities[]?.cveID]' 2>/dev/null || echo "[]")
    [ -n "$EPSS_MAP" ] || EPSS_MAP="{}"
    [ -n "$KEV_LIST" ] || KEV_LIST="[]"
    ENRICHED="true"
fi

# Merge epss/kev, then sort: KEV first, then severity, then EPSS desc.
FINDINGS=$(echo "$FINDINGS" | jq --argjson epss "$EPSS_MAP" --argjson kev "$KEV_LIST" '
  map(.id as $cid | . + { epss: ($epss[$cid] // null), kev: (($kev | index($cid)) != null) })
  | sort_by([ (if .kev then 0 else 1 end),
              ({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5),
              (- (.epss // 0)) ])
')

count() { echo "$FINDINGS" | jq "[.[] | select(.severity==\"$1\")] | length"; }
C=$(count CRITICAL); H=$(count HIGH); M=$(count MEDIUM); L=$(count LOW); U=$(count UNKNOWN)
TOTAL=$(echo "$FINDINGS" | jq 'length')
KEV_COUNT=$(echo "$FINDINGS" | jq '[.[] | select(.kev)] | length')

# ---------- Markdown ----------
{
    echo "# Security Report — ${PROJECT}"
    echo ""
    echo "- Generated: ${GEN_AT}"
    echo "- Engine: Trivy (SBOM scan)"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Critical | High | Medium | Low | Unknown | Total |"
    echo "|---:|---:|---:|---:|---:|---:|"
    echo "| ${C} | ${H} | ${M} | ${L} | ${U} | ${TOTAL} |"
    echo ""
    if [ "$ENRICHED" = "true" ]; then
        echo "- Actively exploited (CISA KEV): **${KEV_COUNT}**"
        echo "- Priority order: KEV first, then severity, then EPSS (exploit probability)."
        echo ""
    fi
    if [ "$TOTAL" -gt 0 ]; then
        echo "## Findings"
        echo ""
        echo "| Severity | KEV | CVSS | EPSS | CVE | Package | Installed | Fixed |"
        echo "|----------|-----|-----:|-----:|-----|---------|-----------|-------|"
        echo "$FINDINGS" | jq -r '.[] |
            "| \(.severity)" +
            " | \(if .kev then "⚠️ KEV" else "" end)" +
            " | \(.cvss // "")" +
            " | \(if .epss then ((.epss*1000|floor)/1000|tostring) else "" end)" +
            " | \(.id) | \(.pkg) | \(.version) | \(.fixed) |"'
    else
        echo "_No known vulnerabilities found._"
    fi
} > "$MD"

# ---------- HTML ----------
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Security Report — ${PROJECT}</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;}
 h1{border-bottom:2px solid #ddd;padding-bottom:.4rem;}
 .meta{color:#666;font-size:.9rem;}
 .cards{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0;}
 .card{padding:.6rem 1rem;border-radius:6px;color:#fff;font-weight:600;}
 .crit{background:#dc2626;} .high{background:#ea580c;} .med{background:#d97706;}
 .low{background:#2563eb;} .unk{background:#6b7280;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th,td{border:1px solid #e3e3e3;padding:.4rem .6rem;text-align:left;}
 th{background:#f3f4f6;}
 .sev-CRITICAL{color:#dc2626;font-weight:700;} .sev-HIGH{color:#ea580c;font-weight:700;}
 .sev-MEDIUM{color:#d97706;} .sev-LOW{color:#2563eb;}
 .kev{background:#dc2626;color:#fff;font-weight:600;}
 .kevbadge{background:#dc2626;color:#fff;border-radius:4px;padding:.05rem .35rem;font-size:.75rem;font-weight:700;}
 td.num{text-align:right;font-variant-numeric:tabular-nums;}
</style></head><body>
<h1>Security Report</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Engine: Trivy</p>
<div class="cards">
 <div class="card crit">Critical ${C}</div>
 <div class="card high">High ${H}</div>
 <div class="card med">Medium ${M}</div>
 <div class="card low">Low ${L}</div>
 <div class="card unk">Unknown ${U}</div>
HTMLHEAD
    [ "$ENRICHED" = "true" ] && echo " <div class=\"card kev\">KEV ${KEV_COUNT}</div>"
    echo "</div>"
    [ "$ENRICHED" = "true" ] && echo "<p class=\"meta\">EPSS = exploit probability (FIRST.org) &middot; KEV = CISA known-exploited &middot; priority: KEV → severity → EPSS</p>"

    if [ "$TOTAL" -gt 0 ]; then
        echo "<table><tr><th>Severity</th><th>KEV</th><th>CVSS</th><th>EPSS</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>"
        echo "$FINDINGS" | jq -r '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (if .kev then "<span class=\"kevbadge\">KEV</span>" else "" end) + "</td>" +
            "<td class=\"num\">" + ((.cvss // "" )|tostring|@html) + "</td>" +
            "<td class=\"num\">" + (if .epss then ((.epss*1000|floor)/1000|tostring) else "" end) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + (.title|@html) + "</td></tr>"'
        echo "</table>"
    else
        echo "<p>No known vulnerabilities found.</p>"
    fi
    echo "</body></html>"
} > "$HTML"

echo "[security] generated: $JSON, $MD, $HTML (total=${TOTAL}, critical=${C}, high=${H}, kev=${KEV_COUNT})"
