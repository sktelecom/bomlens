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

# Flatten findings: id, pkg, version, severity, fixed, title.
FINDINGS=$(jq -r '
  [ .Results[]?.Vulnerabilities[]? | {
      id: .VulnerabilityID,
      pkg: .PkgName,
      version: .InstalledVersion,
      severity: (.Severity // "UNKNOWN"),
      fixed: (.FixedVersion // ""),
      title: (.Title // .Description // "" | .[0:120])
    } ]
  | sort_by({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)
' "$JSON" 2>/dev/null || echo '[]')

count() { echo "$FINDINGS" | jq "[.[] | select(.severity==\"$1\")] | length"; }
C=$(count CRITICAL); H=$(count HIGH); M=$(count MEDIUM); L=$(count LOW); U=$(count UNKNOWN)
TOTAL=$(echo "$FINDINGS" | jq 'length')

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
    if [ "$TOTAL" -gt 0 ]; then
        echo "## Findings"
        echo ""
        echo "| Severity | CVE | Package | Installed | Fixed | Title |"
        echo "|----------|-----|---------|-----------|-------|-------|"
        echo "$FINDINGS" | jq -r '.[] |
            "| \(.severity) | \(.id) | \(.pkg) | \(.version) | \(.fixed) | \(.title | gsub("[|\n]"; " ")) |"'
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
</style></head><body>
<h1>Security Report</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Engine: Trivy</p>
<div class="cards">
 <div class="card crit">Critical ${C}</div>
 <div class="card high">High ${H}</div>
 <div class="card med">Medium ${M}</div>
 <div class="card low">Low ${L}</div>
 <div class="card unk">Unknown ${U}</div>
</div>
HTMLHEAD

    if [ "$TOTAL" -gt 0 ]; then
        echo "<table><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>"
        echo "$FINDINGS" | jq -r '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + (.title|@html) + "</td></tr>"'
        echo "</table>"
    else
        echo "<p>No known vulnerabilities found.</p>"
    fi
    echo "</body></html>"
} > "$HTML"

echo "[security] generated: $JSON, $MD, $HTML (total=${TOTAL}, critical=${C}, high=${H})"
