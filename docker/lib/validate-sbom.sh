#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# validate-sbom.sh — check a supplier-submitted SBOM against SKT submission
# requirements (the "format validation" step of the SKT review process).
#
# Usage: validate-sbom.sh <sbom_file> <out_prefix> <project_name>
#   produces <out_prefix>_conformance.json   (machine-readable result)
#            <out_prefix>_conformance.md      (human summary)
#            <out_prefix>_conformance.html    (visual summary)
#
# Validation runs against the ORIGINAL submission (before any CycloneDX
# conversion), so SPDX-specific metadata is judged accurately. It NEVER aborts
# the pipeline: a non-conformant SBOM yields result="fail" but exit 0.
#
# Requirements (see docs/supplier-sbom-analysis.md §4):
#   mandatory : timestamp, tool info, top component, name+version coverage,
#               PURL coverage (>= threshold), no pkg:generic, transitive edges
#   recommended (warn only): license coverage, hash coverage
#   AI SBOMs (machine-learning-model present): G7 minimum-element checks are
#               appended (model id/license/card/integrity, datasets, openness),
#               all recommended — see docs/internal/ai-sbom-readiness.md.
set -e

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

# Coverage thresholds (percent). Override via env to tune strictness.
PURL_MIN_PCT="${PURL_MIN_PCT:-90}"      # mandatory
LICENSE_MIN_PCT="${LICENSE_MIN_PCT:-80}" # recommended (warn)
HASH_MIN_PCT="${HASH_MIN_PCT:-50}"       # recommended (warn)
MISSING_CAP=50                            # cap missing-item lists in the report

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[validate] SBOM file not found: $SBOM" >&2
    exit 1
fi

JSON="${OUT_PREFIX}_conformance.json"
MD="${OUT_PREFIX}_conformance.md"
HTML="${OUT_PREFIX}_conformance.html"
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --------------------------------------------------------
# Format detection
# --------------------------------------------------------
FORMAT="unknown"
if jq -e '.bomFormat=="CycloneDX" and (.specVersion!=null)' "$SBOM" >/dev/null 2>&1; then
    FORMAT="CycloneDX"
elif jq -e '.spdxVersion!=null' "$SBOM" >/dev/null 2>&1; then
    FORMAT="SPDX-JSON"
elif grep -q '^SPDXVersion:' "$SBOM" 2>/dev/null; then
    FORMAT="SPDX-TagValue"
fi
echo "[validate] detected format: $FORMAT"

# Shared jq helper: percentage with zero-guard (jq source, not shell — vars are intentional).
# shellcheck disable=SC2016
PCT_DEF='def pct($n;$d): if $d==0 then 0 else (($n*100/$d)|floor) end;'

# --------------------------------------------------------
# Per-format check arrays. Each emits a JSON array of:
#   {id,label,required(bool),status("pass"|"fail"|"warn"),detail,missing[]}
# --------------------------------------------------------
cdx_checks() {
    jq -c \
       --argjson purlmin "$PURL_MIN_PCT" \
       --argjson licmin "$LICENSE_MIN_PCT" \
       --argjson hashmin "$HASH_MIN_PCT" \
       --argjson cap "$MISSING_CAP" "
    $PCT_DEF
    ([.components[]?]) as \$c
    | (\$c|length) as \$tot
    | (.metadata.tools) as \$t
    | (if (\$t|type)==\"array\" then (\$t|length)
       elif (\$t|type)==\"object\" then (((\$t.components//[])+(\$t.services//[]))|length)
       else 0 end) as \$tools
    | ([ \$c[] | select((.name==null) or (.version==null)) | (.name // .purl // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$c[] | select(.purl==null) | (.name // \"(unnamed)\") ]) as \$miss_purl
    | ([ \$c[] | select((.purl // \"\") | startswith(\"pkg:generic\")) | (.name // .purl) ]) as \$generic
    | ((\$c | map(select((.licenses // []) | length > 0)) | length)) as \$lic_ok
    | ((\$c | map(select((.hashes // []) | length > 0)) | length)) as \$hash_ok
    | ([ .dependencies[]? | .dependsOn[]? ] | length) as \$dep_edges
    | (.metadata.timestamp // \"\") as \$ts
    | (.metadata.component // {}) as \$top
    | (\$tot - (\$miss_purl|length)) as \$purl_ok
    | [
       {id:\"timestamp\", label:\"Timestamp (metadata.timestamp)\", required:true,
        status:(if (\$ts|length)>0 then \"pass\" else \"fail\" end), detail:\$ts, missing:[]},
       {id:\"tools\", label:\"Tool info (metadata.tools)\", required:true,
        status:(if \$tools>0 then \"pass\" else \"fail\" end), detail:\"\(\$tools) tool(s)\", missing:[]},
       {id:\"top-component\", label:\"Top-level component name+version\", required:true,
        status:(if ((\$top.name//\"\")|length)>0 and ((\$top.version//\"\")|length)>0 then \"pass\" else \"fail\" end),
        detail:((\$top.name//\"(none)\") + \"@\" + (\$top.version//\"\")), missing:[]},
       {id:\"name-version\", label:\"Component name+version coverage (100%)\", required:true,
        status:(if (\$miss_nv|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$tot - (\$miss_nv|length))/\(\$tot)\", missing:(\$miss_nv[0:\$cap])},
       {id:\"purl\", label:\"PURL coverage (>= \(\$purlmin)%)\", required:true,
        status:(if pct(\$purl_ok;\$tot) >= \$purlmin then \"pass\" else \"fail\" end),
        detail:\"\(pct(\$purl_ok;\$tot))% (\(\$purl_ok)/\(\$tot))\", missing:(\$miss_purl[0:\$cap])},
       {id:\"no-generic\", label:\"No pkg:generic / custom PURL (0)\", required:true,
        status:(if (\$generic|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$generic|length) offending\", missing:(\$generic[0:\$cap])},
       {id:\"transitive\", label:\"Transitive dependencies (graph edges)\", required:true,
        status:(if \$dep_edges>0 then \"pass\" else \"fail\" end),
        detail:\"\(\$dep_edges) edge(s)\", missing:[]},
       {id:\"license\", label:\"License coverage (>= \(\$licmin)%, recommended)\", required:false,
        status:(if pct(\$lic_ok;\$tot) >= \$licmin then \"pass\" else \"warn\" end),
        detail:\"\(pct(\$lic_ok;\$tot))% (\(\$lic_ok)/\(\$tot))\", missing:[]},
       {id:\"hash\", label:\"Hash coverage (>= \(\$hashmin)%, recommended)\", required:false,
        status:(if pct(\$hash_ok;\$tot) >= \$hashmin then \"pass\" else \"warn\" end),
        detail:\"\(pct(\$hash_ok;\$tot))% (\(\$hash_ok)/\(\$tot))\", missing:[]}
      ]" "$SBOM"
}

# G7 AI SBOM minimum-element checks (appended for CycloneDX SBOMs that carry a
# machine-learning-model component). Maps the model/dataset/metadata clusters of
# the G7 "minimum elements for AI SBOMs" to fields present in a CycloneDX 1.7
# ML-BOM. All are recommended (required:false) — G7 is a non-binding guideline,
# and several fields (integrity hashes, the openness 4-axis) depend on what the
# model publisher declared, so the report surfaces coverage and a human judges.
# System-level / infrastructure / KPI clusters are not checkable from a
# single-model AI SBOM and are intentionally omitted.
g7_ai_checks() {
    jq -c --argjson cap "$MISSING_CAP" '
    def cov($missing; $tot; $label; $id; $ev):
      {id:$id, label:$label, required:false,
       status:(if $tot==0 then "warn" elif ($missing|length)==0 then "pass" else "warn" end),
       detail:"\($tot - ($missing|length))/\($tot) model component(s)",
       missing:($missing[0:$cap]), evidence:(($ev | unique)[0:$cap])};
    ([.components[]? | select(.type=="machine-learning-model")]) as $m
    | ($m|length) as $mtot
    | ([$m[] | select(((.purl//"")=="") and ((.cpe//"")=="")) | (.name // "(unnamed)")]) as $no_id
    | ([$m[] | select(((.hashes//[])|length)==0) | (.name // "(unnamed)")]) as $no_hash
    | ([$m[] | select(((.licenses//[])|length)==0) | (.name // "(unnamed)")]) as $no_lic
    | ([$m[] | select((.modelCard.modelParameters//null)==null) | (.name // "(unnamed)")]) as $no_mc
    | ([$m[] | (.purl // .cpe) | select(. != null and . != "")]) as $ev_id
    | ([$m[] | .licenses[]? | (.license.id // .license.name // .expression) | select(. != null and . != "")]) as $ev_lic
    | ([$m[] | .modelCard.modelParameters | select(. != null) | (.architectureFamily // .modelArchitecture // "documented")]) as $ev_mc
    | ([$m[] | .hashes[]? | .alg | select(. != null)]) as $ev_hash
    | (([.. | objects | select(has("datasets")) | .datasets[]?] + [.components[]? | select(.type=="data")])) as $ds
    | ([$ds[] | (.name // .ref // (.componentData.name) // "dataset") | select(. != null and . != "")]) as $ev_ds
    | ([.. | strings | select(test("open[ _-]?(weight|architecture|data|training)";"i"))]) as $ev_open
    | [
        cov($no_id;   $mtot; "G7 model identifier (PURL/CPE)"; "g7-model-id"; $ev_id),
        cov($no_lic;  $mtot; "G7 model license"; "g7-model-license"; $ev_lic),
        cov($no_mc;   $mtot; "G7 model card (architecture/training parameters)"; "g7-model-card"; $ev_mc),
        cov($no_hash; $mtot; "G7 model integrity (hashes)"; "g7-model-hash"; $ev_hash),
        {id:"g7-datasets", label:"G7 dataset provenance (datasets referenced)", required:false,
         status:(if ($ds|length)>0 then "pass" else "warn" end), detail:"\($ds|length) dataset reference(s)",
         missing:[], evidence:(($ev_ds | unique)[0:$cap])},
        {id:"g7-openness", label:"G7 model openness (weight/architecture/data/training)", required:false,
         status:(if ($ev_open|length)>0 then "pass" else "warn" end),
         detail:(if ($ev_open|length)>0 then "declared" else "not declared in the SBOM" end),
         missing:[], evidence:(($ev_open | unique)[0:$cap])}
      ]' "$SBOM"
}

spdx_json_checks() {
    jq -c \
       --argjson purlmin "$PURL_MIN_PCT" \
       --argjson licmin "$LICENSE_MIN_PCT" \
       --argjson hashmin "$HASH_MIN_PCT" \
       --argjson cap "$MISSING_CAP" "
    $PCT_DEF
    ([.packages[]?]) as \$p
    | (\$p|length) as \$tot
    | ([ .creationInfo.creators[]? | select(startswith(\"Tool:\")) ] | length) as \$tools
    | (.creationInfo.created // \"\") as \$ts
    | ([ \$p[] | select((.name==null) or (.versionInfo==null)) | (.name // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$p[] | select(([.externalRefs[]? | select(.referenceType==\"purl\")]|length)==0) | (.name // \"(unnamed)\") ]) as \$miss_purl
    | ([ \$p[] | .externalRefs[]? | select((.referenceLocator // \"\")|startswith(\"pkg:generic\")) | .referenceLocator ]) as \$generic
    | ((\$p | map(select(((.licenseConcluded // \"NOASSERTION\") != \"NOASSERTION\") or ((.licenseDeclared // \"NOASSERTION\") != \"NOASSERTION\"))) | length)) as \$lic_ok
    | ((\$p | map(select((.checksums // [])|length>0)) | length)) as \$hash_ok
    | ([ .relationships[]? | select(.relationshipType==\"DEPENDS_ON\") ] | length) as \$dep_edges
    | (.name // \"\") as \$docname
    | ((.documentDescribes // []) | length) as \$describes
    | (\$tot - (\$miss_purl|length)) as \$purl_ok
    | [
       {id:\"timestamp\", label:\"Timestamp (creationInfo.created)\", required:true,
        status:(if (\$ts|length)>0 then \"pass\" else \"fail\" end), detail:\$ts, missing:[]},
       {id:\"tools\", label:\"Tool info (creationInfo.creators Tool:)\", required:true,
        status:(if \$tools>0 then \"pass\" else \"fail\" end), detail:\"\(\$tools) tool(s)\", missing:[]},
       {id:\"top-component\", label:\"Document name + described root\", required:true,
        status:(if (\$docname|length)>0 and (\$describes>0 or \$tot>0) then \"pass\" else \"fail\" end),
        detail:\$docname, missing:[]},
       {id:\"name-version\", label:\"Package name+version coverage (100%)\", required:true,
        status:(if (\$miss_nv|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$tot - (\$miss_nv|length))/\(\$tot)\", missing:(\$miss_nv[0:\$cap])},
       {id:\"purl\", label:\"PURL coverage (>= \(\$purlmin)%)\", required:true,
        status:(if pct(\$purl_ok;\$tot) >= \$purlmin then \"pass\" else \"fail\" end),
        detail:\"\(pct(\$purl_ok;\$tot))% (\(\$purl_ok)/\(\$tot))\", missing:(\$miss_purl[0:\$cap])},
       {id:\"no-generic\", label:\"No pkg:generic / custom PURL (0)\", required:true,
        status:(if (\$generic|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$generic|length) offending\", missing:(\$generic[0:\$cap])},
       {id:\"transitive\", label:\"Transitive dependencies (DEPENDS_ON)\", required:true,
        status:(if \$dep_edges>0 then \"pass\" else \"fail\" end),
        detail:\"\(\$dep_edges) edge(s)\", missing:[]},
       {id:\"license\", label:\"License coverage (>= \(\$licmin)%, recommended)\", required:false,
        status:(if pct(\$lic_ok;\$tot) >= \$licmin then \"pass\" else \"warn\" end),
        detail:\"\(pct(\$lic_ok;\$tot))% (\(\$lic_ok)/\(\$tot))\", missing:[]},
       {id:\"hash\", label:\"Hash coverage (>= \(\$hashmin)%, recommended)\", required:false,
        status:(if pct(\$hash_ok;\$tot) >= \$hashmin then \"pass\" else \"warn\" end),
        detail:\"\(pct(\$hash_ok;\$tot))% (\(\$hash_ok)/\(\$tot))\", missing:[]}
      ]" "$SBOM"
}

# SPDX Tag-Value: coarse, presence-based grep checks (best-effort; JSON formats
# above are exact). Per-package coverage isn't computed for Tag-Value.
spdx_tv_checks() {
    # grep -c prints the count AND exits 1 when it is zero, so `grep -cE … || echo 0`
    # appended a second "0" line for every empty match, producing "0\n0". Under
    # set -e that broke --argjson (invalid number) and aborted the whole function,
    # so a well-formed Tag-Value SBOM — where pkg:generic is always 0 — never got a
    # conformance report. Capture the count and emit exactly one integer.
    g() { local n; n=$(grep -cE "$1" "$SBOM" 2>/dev/null) || true; printf '%s' "${n:-0}"; }
    local ts tools names vers purls generic deps lics hashes
    ts=$(g '^Created:'); tools=$(g '^Creator: ?Tool:')
    names=$(g '^PackageName:'); vers=$(g '^PackageVersion:')
    purls=$(g 'ExternalRef: ?PACKAGE-MANAGER purl'); generic=$(g 'purl +pkg:generic')
    deps=$(g 'Relationship:.*DEPENDS_ON'); lics=$(g '^PackageLicenseConcluded:'); hashes=$(g '^PackageChecksum:')
    jq -cn \
       --argjson ts "$ts" --argjson tools "$tools" --argjson names "$names" \
       --argjson vers "$vers" --argjson purls "$purls" --argjson generic "$generic" \
       --argjson deps "$deps" --argjson lics "$lics" --argjson hashes "$hashes" '
    [
      {id:"timestamp", label:"Timestamp (Created:)", required:true, status:(if $ts>0 then "pass" else "fail" end), detail:"\($ts) found", missing:[]},
      {id:"tools", label:"Tool info (Creator: Tool:)", required:true, status:(if $tools>0 then "pass" else "fail" end), detail:"\($tools) tool(s)", missing:[]},
      {id:"top-component", label:"Document/package present", required:true, status:(if $names>0 then "pass" else "fail" end), detail:"\($names) package(s)", missing:[]},
      {id:"name-version", label:"PackageName + PackageVersion present", required:true, status:(if $names>0 and $vers>=$names then "pass" else "fail" end), detail:"names=\($names), versions=\($vers)", missing:[]},
      {id:"purl", label:"PURL external refs present", required:true, status:(if $purls>0 and $purls>=$names then "pass" else "fail" end), detail:"\($purls) purl ref(s) for \($names) package(s)", missing:[]},
      {id:"no-generic", label:"No pkg:generic / custom PURL (0)", required:true, status:(if $generic==0 then "pass" else "fail" end), detail:"\($generic) offending", missing:[]},
      {id:"transitive", label:"Transitive dependencies (DEPENDS_ON)", required:true, status:(if $deps>0 then "pass" else "fail" end), detail:"\($deps) relationship(s)", missing:[]},
      {id:"license", label:"License present (recommended)", required:false, status:(if $lics>0 then "pass" else "warn" end), detail:"\($lics) license field(s)", missing:[]},
      {id:"hash", label:"Checksums present (recommended)", required:false, status:(if $hashes>0 then "pass" else "warn" end), detail:"\($hashes) checksum(s)", missing:[]}
    ]'
}

# --------------------------------------------------------
# Compute checks for the detected format.
# --------------------------------------------------------
case "$FORMAT" in
    CycloneDX)
        CHECKS=$(cdx_checks)
        # Append G7 AI minimum-element checks when this is an AI SBOM (carries a
        # machine-learning-model component) — works for both a generated AIBOM and
        # a supplier-submitted AI SBOM under ANALYZE.
        if jq -e '[.components[]? | select(.type=="machine-learning-model")] | length > 0' "$SBOM" >/dev/null 2>&1; then
            G7=$(g7_ai_checks)
            CHECKS=$(printf '%s\n%s' "$CHECKS" "$G7" | jq -cs 'add')
            echo "[validate] AI SBOM detected -> added G7 minimum-element checks"
        fi
        ;;
    SPDX-JSON)     CHECKS=$(spdx_json_checks) ;;
    SPDX-TagValue) CHECKS=$(spdx_tv_checks) ;;
    *)
        CHECKS='[{"id":"format","label":"Recognized SBOM format","required":true,"status":"fail","detail":"not CycloneDX or SPDX","missing":[]}]'
        ;;
esac
[ -n "$CHECKS" ] || CHECKS='[{"id":"parse","label":"Parseable SBOM","required":true,"status":"fail","detail":"could not evaluate","missing":[]}]'

# Overall result: fail if any mandatory check failed.
RESULT=$(echo "$CHECKS" | jq -r 'if any(.[]; .required and .status=="fail") then "fail" else "pass" end')
N_FAIL=$(echo "$CHECKS" | jq '[.[] | select(.required and .status=="fail")] | length')
N_WARN=$(echo "$CHECKS" | jq '[.[] | select(.status=="warn")] | length')

# --------------------------------------------------------
# JSON report
# --------------------------------------------------------
jq -n \
   --arg project "$PROJECT" --arg format "$FORMAT" --arg result "$RESULT" \
   --arg ts "$GEN_AT" --argjson checks "$CHECKS" '
{ project: $project, format: $format, result: $result, generatedAt: $ts, checks: $checks }
' > "$JSON"

# --------------------------------------------------------
# Markdown report
# --------------------------------------------------------
{
    echo "# SBOM Conformance — ${PROJECT}"
    echo ""
    echo "- Generated: ${GEN_AT}"
    echo "- Format: ${FORMAT}"
    echo "- Result: **$(echo "$RESULT" | tr '[:lower:]' '[:upper:]')** (mandatory failures: ${N_FAIL}, warnings: ${N_WARN})"
    echo ""
    echo "| Status | Requirement | Required | Detail | Evidence |"
    echo "|--------|-------------|:--------:|--------|----------|"
    echo "$CHECKS" | jq -r '.[] |
        "| \(if .status=="pass" then "✅" elif .status=="fail" then "❌" else "⚠️" end) | \(.label) | \(if .required then "yes" else "no" end) | \(.detail | gsub("[|\n]"; " ")) | \(((.evidence // []) | join(", ")) | gsub("[|\n]"; " ")) |"'
    echo ""
    # Missing-item detail for failed mandatory checks.
    if echo "$CHECKS" | jq -e 'any(.[]; .required and .status=="fail" and (.missing|length>0))' >/dev/null; then
        echo "## Missing / non-conformant items"
        echo ""
        echo "$CHECKS" | jq -r '.[] | select(.required and .status=="fail" and (.missing|length>0)) |
            "### \(.label)\n" + (.missing | map("- " + (. | tostring)) | join("\n")) + "\n"'
    fi
} > "$MD"

# --------------------------------------------------------
# HTML report (cards/table/CSP/escape pattern borrowed from scan-security.sh)
# --------------------------------------------------------
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>SBOM Conformance — ${PROJECT}</title>
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
 .pill-pass{background:rgba(22,163,74,.12);color:#16a34a;}
 .pill-fail{background:rgba(220,38,38,.12);color:#dc2626;}
 .pill-warn{background:rgba(202,138,4,.14);color:#ca8a04;}
 .pill-info{background:rgba(113,113,122,.14);color:#71717a;}
 .table-wrap{border:1px solid var(--border);border-radius:var(--radius-card);
  overflow-x:auto;box-shadow:var(--shadow);background:var(--surface);margin:1rem 0 1.5rem;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th{background:var(--th-bg);text-align:left;font-size:.7rem;font-weight:600;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  padding:.6rem .8rem;border-bottom:1px solid var(--border);white-space:nowrap;}
 td{padding:.6rem .8rem;border-bottom:1px solid var(--border);vertical-align:top;}
 tr:last-child td{border-bottom:none;}
 tr:hover td{background:var(--row-hover);}
 .s-pass{color:#16a34a;font-weight:700;}
 .s-fail{color:#dc2626;font-weight:700;}
 .s-warn{color:#ca8a04;font-weight:700;}
 .mono{list-style:none;padding-left:0;}
 .mono li{font-family:var(--mono);font-size:.82rem;margin:.3rem 0;}
 ol,ul{margin:.5rem 0 0;padding-left:1.3rem;}
 li{margin:.3rem 0;}
</style></head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">Conformance</div>
</header>
<h1>SBOM Conformance Report</h1>
<p class="meta">Project: $(printf '%s' "$PROJECT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g') &middot; Generated: ${GEN_AT} &middot; Format: ${FORMAT}</p>
<div class="cards">
 <span class="pill pill-$( [ "$RESULT" = "pass" ] && echo pass || echo fail )">Result: $(echo "$RESULT" | tr '[:lower:]' '[:upper:]')</span>
 <span class="pill pill-fail">Mandatory failures: <span class="count">${N_FAIL}</span></span>
 <span class="pill pill-warn">Warnings: <span class="count">${N_WARN}</span></span>
</div>
<div class="table-wrap"><table><tr><th>Status</th><th>Requirement</th><th>Required</th><th>Detail</th><th>Evidence</th></tr>
HTMLHEAD
    echo "$CHECKS" | jq -r '.[] |
        "<tr><td class=\"s-\(.status)\">" + (.status|ascii_upcase|@html) + "</td>" +
        "<td>" + (.label|@html) + "</td><td>" + (if .required then "yes" else "no" end) + "</td>" +
        "<td>" + ((.detail // "")|@html) + "</td>" +
        "<td>" + (((.evidence // []) | join(", "))|@html) + "</td></tr>"'
    echo "</table></div>"
    if echo "$CHECKS" | jq -e 'any(.[]; .required and .status=="fail" and (.missing|length>0))' >/dev/null; then
        echo "<h2>Missing / non-conformant items</h2>"
        echo "$CHECKS" | jq -r '.[] | select(.required and .status=="fail" and (.missing|length>0)) |
            "<h3>" + (.label|@html) + "</h3><ul class=\"mono\">" + (.missing | map("<li>" + (.|tostring|@html) + "</li>") | join("")) + "</ul>"'
    fi
    echo "</body></html>"
} > "$HTML"

echo "[validate] $FORMAT -> result=$RESULT (mandatory fails=$N_FAIL, warns=$N_WARN): $JSON, $MD, $HTML"
exit 0
