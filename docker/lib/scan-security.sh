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

# Merge a Trivy-shaped CVE sidecar from another engine, if present. Firmware
# scans drop ${OUT_PREFIX}_security_cvebintool.json: cve-bin-tool matches CVEs on
# stripped binaries by version signature (no purl/CPE), which Trivy cannot do, so
# without this merge the firmware security report is empty. The sidecar already
# carries the .Results[].Vulnerabilities[] contract, so we just append its
# Results to Trivy's — the web layer and the renderer below read one unified file.
SIDECAR="${OUT_PREFIX}_security_cvebintool.json"
if [ -f "$SIDECAR" ] && jq -e '.Results' "$SIDECAR" >/dev/null 2>&1; then
    SIDE_N=$(jq '[.Results[].Vulnerabilities[]?] | length' "$SIDECAR" 2>/dev/null || echo 0)
    if [ "${SIDE_N:-0}" -gt 0 ]; then
        tmp_m="$(mktemp)"
        if jq -s '{ Results: ((.[0].Results // []) + (.[1].Results // [])) }
                  + (.[0] | del(.Results))' "$JSON" "$SIDECAR" > "$tmp_m" 2>/dev/null; then
            mv "$tmp_m" "$JSON"
            echo "[security] merged ${SIDE_N} cve-bin-tool CVE(s) from $(basename "$SIDECAR")."
        else
            rm -f "$tmp_m"
            echo "[security] WARN: failed to merge cve-bin-tool sidecar; reporting Trivy results only." >&2
        fi
    fi
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

# Persist the EPSS/KEV enrichment as a sidecar map (keyed by CVE id) so the web
# UI can surface it — the raw _security.json from Trivy carries neither. Always
# written (null epss / false kev when offline), so the reader has a stable shape.
echo "$FINDINGS" | jq 'map({key: .id, value: {epss: .epss, kev: .kev}}) | from_entries' \
    > "${OUT_PREFIX}_security_epss.json" 2>/dev/null || echo "{}" > "${OUT_PREFIX}_security_epss.json"

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
 .kevbadge{display:inline-block;background:rgba(234,0,44,.12);color:#EA002C;
  border-radius:999px;padding:.12rem .5rem;font-size:.72rem;font-weight:700;}
 .mono li{font-family:var(--mono);font-size:.82rem;}
 ol,ul{margin:.5rem 0 0;padding-left:1.3rem;}
 li{margin:.3rem 0;}
</style></head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">Security Report</div>
</header>
<h1>Security Report</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Engine: Trivy</p>
<div class="cards">
 <span class="pill pill-crit">Critical <span class="count">${C}</span></span>
 <span class="pill pill-high">High <span class="count">${H}</span></span>
 <span class="pill pill-med">Medium <span class="count">${M}</span></span>
 <span class="pill pill-low">Low <span class="count">${L}</span></span>
 <span class="pill pill-info">Unknown <span class="count">${U}</span></span>
HTMLHEAD
    [ "$ENRICHED" = "true" ] && echo " <span class=\"pill pill-kev\">KEV <span class=\"count\">${KEV_COUNT}</span></span>"
    echo "</div>"
    [ "$ENRICHED" = "true" ] && echo "<p class=\"meta\">EPSS = exploit probability (FIRST.org) &middot; KEV = CISA known-exploited &middot; priority: KEV → severity → EPSS</p>"

    if [ "$TOTAL" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>KEV</th><th>CVSS</th><th>EPSS</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>"
        echo "$FINDINGS" | jq -r '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (if .kev then "<span class=\"kevbadge\">KEV</span>" else "" end) + "</td>" +
            "<td class=\"num\">" + ((.cvss // "" )|tostring|@html) + "</td>" +
            "<td class=\"num\">" + (if .epss then ((.epss*1000|floor)/1000|tostring) else "" end) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + (.title|@html) + "</td></tr>"'
        echo "</table></div>"
    else
        echo "<p>No known vulnerabilities found.</p>"
    fi
    echo "</body></html>"
} > "$HTML"

echo "[security] generated: $JSON, $MD, $HTML (total=${TOTAL}, critical=${C}, high=${H}, kev=${KEV_COUNT})"
