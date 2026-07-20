#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# generate-ai-profile.sh — assemble an AI compliance profile by RE-AGGREGATING
# artifacts already produced by the pipeline (no new scan is run). One
# governance-facing page for an AI SBOM that ties together what today lives in
# separate reports: the G7 minimum-element status (headline + per cluster), the
# regulatory crosswalk, the licenses flagged for human review, and the elements a
# person still has to fill in.
#
# Usage: generate-ai-profile.sh <out_prefix> <project_name>
#   reads  <out_prefix>_conformance.json   (validate-sbom.sh; must carry G7 checks)
#          <out_prefix>_bom.json            (the finished CycloneDX SBOM)
#   writes <out_prefix>_ai-profile.json  and  _ai-profile.md  and  _ai-profile.html
#
# AI-only and best-effort: if the conformance report carries no G7 checks (i.e.
# this is not an AI SBOM), it exits 0 without writing anything. It never runs a
# scan and never aborts the pipeline. It makes no compliance determination — it
# re-groups findings the pipeline already produced.
set -e

OUT_PREFIX="$1"
PROJECT="${2:-project}"
if [ -z "$OUT_PREFIX" ]; then
    echo "[ai-profile] out_prefix required (usage: generate-ai-profile.sh <out_prefix> <project_name>)" >&2
    exit 1
fi

CONF="${OUT_PREFIX}_conformance.json"
BOM="${OUT_PREFIX}_bom.json"
JSON="${OUT_PREFIX}_ai-profile.json"
MD="${OUT_PREFIX}_ai-profile.md"
HTML="${OUT_PREFIX}_ai-profile.html"
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CAP=100   # cap license-review rows shown in the MD/HTML (JSON keeps them all)

# Gate: need a conformance report that actually carries G7 checks. Anything else
# (a plain dependency SBOM, or no conformance report) is not an AI SBOM.
if [ ! -f "$CONF" ] || ! jq -e '[.checks[]? | select(.id|startswith("g7-"))] | length > 0' "$CONF" >/dev/null 2>&1; then
    echo "[ai-profile] no G7 conformance checks found; skipping (not an AI SBOM)."
    exit 0
fi

# --------------------------------------------------------
# G7 status: headline counts, per-cluster rollup, review list — all from the
# conformance checks. present = pass; gap = advisory warn with an automated
# source; review = elements with no automated source (source "na").
# --------------------------------------------------------
G7=$(jq -c '
  [ .checks[]? | select(.id|startswith("g7-")) ] as $g
  | { total:   ($g|length),
      auto:    ($g | map(select((.source//"")!="na")) | length),
      present: ($g | map(select(.status=="pass")) | length),
      gap:     ($g | map(select(.status=="warn" and ((.source//"")!="na"))) | length),
      review:  ($g | map(select((.source//"")=="na")) | length),
      clusters: ( $g | group_by(.cluster) | map({
                    cluster: (.[0].cluster // "other"),
                    total:   length,
                    present: (map(select(.status=="pass"))|length),
                    gap:     (map(select(.status=="warn" and ((.source//"")!="na")))|length),
                    review:  (map(select((.source//"")=="na"))|length) }) ),
      reviewItems: ( $g | map(select((.source//"")=="na")) | map({id, label, cluster}) ),
      # Advisory elements that ARE automatable but absent — the closable set. The
      # conformance report carries the CycloneDX fragment for each; here we keep
      # the roll-up plus the reference link so the two artifacts do not duplicate.
      gapItems: ( $g | map(select(.status=="warn" and ((.source//"")!="na")))
                     | map({id, label, cluster, docUrl: (.guidance.docUrl // "")}) )
    }' "$CONF")

XW=$(jq -c '.regulatoryCrosswalk // {frameworks:[],disclaimer:""}' "$CONF")
CONF_RESULT=$(jq -r '.result // "N/A"' "$CONF")

# --------------------------------------------------------
# License review flags from the finished SBOM. normalize-sbom.sh tags components
# whose declared license is an AI behavioral-use or non-commercial license with a
# bomlens:licenseReview property (same classifier as the NOTICE's review section).
# --------------------------------------------------------
LIC='{"total":0,"behavioral":0,"nonCommercial":0,"items":[]}'
if [ -f "$BOM" ]; then
    LIC=$(jq -c '
      [ .components[]?
        | ((.properties // [])[]? | select(.name=="bomlens:licenseReview") | .value) as $flag
        | select($flag != null)
        | { name: (.name // "(unnamed)"),
            version: (.version // ""),
            license: ([ (.licenses // [])[] | (.license.id // .license.name // .expression) ]
                       | map(select(. != null and . != "")) | (.[0] // "")),
            flag: $flag } ]
      | { total: length,
          behavioral:    (map(select(.flag=="behavioral-use"))|length),
          nonCommercial: (map(select(.flag=="non-commercial"))|length),
          items: . }' "$BOM" 2>/dev/null || echo '{"total":0,"behavioral":0,"nonCommercial":0,"items":[]}')
fi

# --------------------------------------------------------
# JSON profile
# --------------------------------------------------------
jq -n --arg project "$PROJECT" --arg ts "$GEN_AT" --arg confResult "$CONF_RESULT" \
   --argjson g7 "$G7" --argjson xwalk "$XW" --argjson lic "$LIC" '
{ project: $project, generatedAt: $ts, conformanceResult: $confResult,
  g7: $g7, regulatoryCrosswalk: $xwalk, licenseReview: $lic }' > "$JSON"

# Human-readable label for a license-review flag.
flag_label() {
    case "$1" in
        behavioral-use) echo "Behavioral-use restriction" ;;
        non-commercial) echo "Non-commercial" ;;
        *)              echo "$1" ;;
    esac
}

# --------------------------------------------------------
# Markdown
# --------------------------------------------------------
{
    echo "# AI compliance profile — ${PROJECT}"
    echo ""
    echo "- Generated: ${GEN_AT}"
    echo "- This profile re-aggregates the conformance and SBOM artifacts already produced; it runs no scan and makes no compliance determination."
    echo ""

    echo "## Summary"
    echo ""
    A=$(echo "$G7" | jq -r '.auto'); P=$(echo "$G7" | jq -r '.present')
    Gp=$(echo "$G7" | jq -r '.gap'); Rv=$(echo "$G7" | jq -r '.review')
    LT=$(echo "$LIC" | jq -r '.total'); LB=$(echo "$LIC" | jq -r '.behavioral'); LN=$(echo "$LIC" | jq -r '.nonCommercial')
    echo "- G7 minimum elements: **${P} / ${A} present** (of the automatically checkable), ${Gp} gap, ${Rv} need human review."
    echo "- Licenses flagged for review: **${LT}** (${LB} behavioral-use, ${LN} non-commercial)."
    echo "- Base conformance result: **$(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')** (the overall pass/fail comes from the required format checks, not from G7)."
    echo ""

    echo "## Licenses flagged for review"
    echo ""
    if [ "$LT" -gt 0 ]; then
        echo "| Component | Version | License | Flag |"
        echo "|-----------|---------|---------|------|"
        echo "$LIC" | jq -r --argjson cap "$CAP" '.items[0:$cap][] |
            "| \(.name|gsub("[|\n]";" ")) | \(.version|gsub("[|\n]";" ")) | \(.license|gsub("[|\n]";" ")) | \(
              if .flag=="behavioral-use" then "Behavioral-use restriction"
              elif .flag=="non-commercial" then "Non-commercial" else .flag end) |"'
        [ "$LT" -gt "$CAP" ] && echo "" && echo "_… and $((LT - CAP)) more (see the JSON profile)._"
    else
        echo "_No components carry an AI behavioral-use or non-commercial license flag._"
    fi
    echo ""

    echo "## G7 minimum elements by cluster"
    echo ""
    echo "| Cluster | Present | Gap | Review | Total |"
    echo "|---------|--------:|----:|-------:|------:|"
    echo "$G7" | jq -r '.clusters[] | "| \(.cluster) | \(.present) | \(.gap) | \(.review) | \(.total) |"'
    echo ""

    if [ "$(echo "$XW" | jq -r '.frameworks | length')" -gt 0 ]; then
        echo "## Regulatory crosswalk"
        echo ""
        echo "$XW" | jq -r '.disclaimer'
        echo ""
        echo "| Framework | Present | Gap | Review | Mapped |"
        echo "|-----------|--------:|----:|-------:|-------:|"
        echo "$XW" | jq -r '.frameworks[] | "| \(.title|gsub("[|\n]";" ")) | \(.present) | \(.gap) | \(.review) | \(.total) |"'
        echo ""
        echo "The full element-by-element mapping is in the conformance report (\`${OUT_PREFIX}_conformance.*\`)."
        echo ""
    fi

    if [ "$Gp" -gt 0 ]; then
        echo "## How to close the gaps"
        echo ""
        echo "These G7 elements have an automated source but are absent from the SBOM. The conformance report (\`${OUT_PREFIX}_conformance.md\`) carries the CycloneDX fragment that would satisfy each one."
        echo ""
        echo "$G7" | jq -r '.gapItems[] | "- \(.label) (\(.cluster))" + (if (.docUrl // "") != "" then " — \(.docUrl)" else "" end)'
        echo ""
    fi

    if [ "$Rv" -gt 0 ]; then
        echo "## Elements a person still has to fill in"
        echo ""
        echo "These G7 elements have no automated source; they are surfaced for human review, not guessed."
        echo ""
        echo "$G7" | jq -r '.reviewItems[] | "- \(.label) (\(.cluster))"'
        echo ""
    fi
} > "$MD"

# --------------------------------------------------------
# HTML (cards/table/CSP/escape pattern shared with the other reports)
# --------------------------------------------------------
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
conf_class="warn"; [ "$CONF_RESULT" = "pass" ] && conf_class="pass"; [ "$CONF_RESULT" = "fail" ] && conf_class="fail"
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>AI compliance profile — ${PROJECT}</title>
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
 .meta{color:var(--muted);font-size:.875rem;margin:.15rem 0 0;}
 .cards{display:flex;gap:.5rem;flex-wrap:wrap;margin:1.1rem 0 1.3rem;}
 .pill{display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .7rem;
  border-radius:999px;font-size:.8rem;font-weight:600;line-height:1.1;}
 .pill .count{font-variant-numeric:tabular-nums;}
 .pill-pass{background:rgba(22,163,74,.12);color:#16a34a;}
 .pill-fail{background:rgba(220,38,38,.12);color:#dc2626;}
 .pill-warn{background:rgba(202,138,4,.14);color:#ca8a04;}
 .pill-info{background:rgba(113,113,122,.14);color:#71717a;}
 .note{background:rgba(244,119,37,.09);border-left:3px solid var(--brand-2);
  border-radius:var(--radius);padding:.75rem 1rem;margin:1rem 0 1.3rem;font-size:.875rem;}
 .table-wrap{border:1px solid var(--border);border-radius:var(--radius-card);
  overflow-x:auto;box-shadow:var(--shadow);background:var(--surface);margin:1rem 0 1.5rem;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th{background:var(--th-bg);text-align:left;font-size:.7rem;font-weight:600;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  padding:.6rem .8rem;border-bottom:1px solid var(--border);white-space:nowrap;}
 td{padding:.6rem .8rem;border-bottom:1px solid var(--border);vertical-align:top;}
 td.num{text-align:right;font-variant-numeric:tabular-nums;}
 tr:last-child td{border-bottom:none;}
 tr:hover td{background:var(--row-hover);}
 ul{margin:.5rem 0 0;padding-left:1.3rem;}
 li{margin:.3rem 0;}
</style></head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">AI compliance profile</div>
</header>
<h1>AI compliance profile</h1>
<p class="meta">Project: $(esc "$PROJECT") &middot; Generated: ${GEN_AT}</p>
<div class="note">This profile re-aggregates the conformance and SBOM artifacts already produced. It runs no scan and makes no compliance determination.</div>
<div class="cards">
 <span class="pill pill-pass">G7 present <span class="count">${P} / ${A}</span></span>
 <span class="pill pill-warn">G7 gap <span class="count">${Gp}</span></span>
 <span class="pill pill-info">Needs review <span class="count">${Rv}</span></span>
 <span class="pill pill-fail">License flags <span class="count">${LT}</span></span>
 <span class="pill pill-${conf_class}">Base result: $(echo "$CONF_RESULT" | tr '[:lower:]' '[:upper:]')</span>
</div>
HTMLHEAD

    echo "<h2>Licenses flagged for review</h2>"
    if [ "$LT" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><tr><th>Component</th><th>Version</th><th>License</th><th>Flag</th></tr>"
        echo "$LIC" | jq -r --argjson cap "$CAP" '.items[0:$cap][] |
            "<tr><td>" + (.name|@html) + "</td><td>" + (.version|@html) + "</td>" +
            "<td>" + (.license|@html) + "</td><td>" + ((
              if .flag=="behavioral-use" then "Behavioral-use restriction"
              elif .flag=="non-commercial" then "Non-commercial" else .flag end)|@html) + "</td></tr>"'
        echo "</table></div>"
        [ "$LT" -gt "$CAP" ] && echo "<p class=\"meta\">… and $((LT - CAP)) more (see the JSON profile).</p>"
    else
        echo "<p>No components carry an AI behavioral-use or non-commercial license flag.</p>"
    fi

    echo "<h2>G7 minimum elements by cluster</h2>"
    echo "<div class=\"table-wrap\"><table><tr><th>Cluster</th><th>Present</th><th>Gap</th><th>Review</th><th>Total</th></tr>"
    echo "$G7" | jq -r '.clusters[] |
        "<tr><td>" + (.cluster|@html) + "</td><td class=\"num\">" + (.present|tostring) +
        "</td><td class=\"num\">" + (.gap|tostring) + "</td><td class=\"num\">" + (.review|tostring) +
        "</td><td class=\"num\">" + (.total|tostring) + "</td></tr>"'
    echo "</table></div>"

    if [ "$(echo "$XW" | jq -r '.frameworks | length')" -gt 0 ]; then
        echo "<h2>Regulatory crosswalk</h2>"
        echo "<p class=\"meta\">$(esc "$(echo "$XW" | jq -r '.disclaimer')")</p>"
        echo "<div class=\"table-wrap\"><table><tr><th>Framework</th><th>Present</th><th>Gap</th><th>Review</th><th>Mapped</th></tr>"
        echo "$XW" | jq -r '.frameworks[] |
            "<tr><td>" + (.title|@html) + "</td><td class=\"num\">" + (.present|tostring) +
            "</td><td class=\"num\">" + (.gap|tostring) + "</td><td class=\"num\">" + (.review|tostring) +
            "</td><td class=\"num\">" + (.total|tostring) + "</td></tr>"'
        echo "</table></div>"
        echo "<p class=\"meta\">The full element-by-element mapping is in the conformance report.</p>"
    fi

    if [ "$Gp" -gt 0 ]; then
        echo "<h2>How to close the gaps</h2>"
        echo "<p>These G7 elements have an automated source but are absent from the SBOM. The conformance report carries the CycloneDX fragment that would satisfy each one.</p>"
        echo "<ul>"
        echo "$G7" | jq -r '.gapItems[] |
            "<li>" + ((.label + " (" + .cluster + ")")|@html) +
            (if (.docUrl // "") != "" then " &mdash; " + (.docUrl|@html) else "" end) + "</li>"'
        echo "</ul>"
    fi

    if [ "$Rv" -gt 0 ]; then
        echo "<h2>Elements a person still has to fill in</h2>"
        echo "<p>These G7 elements have no automated source; they are surfaced for human review, not guessed.</p>"
        echo "<ul>"
        echo "$G7" | jq -r '.reviewItems[] | "<li>" + ((.label + " (" + .cluster + ")")|@html) + "</li>"'
        echo "</ul>"
    fi
    echo "</body></html>"
} > "$HTML"

echo "[ai-profile] generated: $JSON, $MD, $HTML (G7 present=${P}/${A}, license flags=${LT})"
