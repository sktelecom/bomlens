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
    def cov($missing; $tot; $label; $id):
      {id:$id, label:$label, required:false,
       status:(if $tot==0 then "warn" elif ($missing|length)==0 then "pass" else "warn" end),
       detail:"\($tot - ($missing|length))/\($tot) model component(s)", missing:($missing[0:$cap])};
    ([.components[]? | select(.type=="machine-learning-model")]) as $m
    | ($m|length) as $mtot
    | ([$m[] | select(((.purl//"")=="") and ((.cpe//"")=="")) | (.name // "(unnamed)")]) as $no_id
    | ([$m[] | select(((.hashes//[])|length)==0) | (.name // "(unnamed)")]) as $no_hash
    | ([$m[] | select(((.licenses//[])|length)==0) | (.name // "(unnamed)")]) as $no_lic
    | ([$m[] | select((.modelCard.modelParameters//null)==null) | (.name // "(unnamed)")]) as $no_mc
    | (([.. | objects | select(has("datasets")) | .datasets[]?] + [.components[]? | select(.type=="data")]) | length) as $ds_count
    | ([.. | strings | select(test("open[ _-]?(weight|architecture|data|training)";"i"))] | length) as $open_hits
    | [
        cov($no_id;   $mtot; "G7 model identifier (PURL/CPE)"; "g7-model-id"),
        cov($no_lic;  $mtot; "G7 model license"; "g7-model-license"),
        cov($no_mc;   $mtot; "G7 model card (architecture/training parameters)"; "g7-model-card"),
        cov($no_hash; $mtot; "G7 model integrity (hashes)"; "g7-model-hash"),
        {id:"g7-datasets", label:"G7 dataset provenance (datasets referenced)", required:false,
         status:(if $ds_count>0 then "pass" else "warn" end), detail:"\($ds_count) dataset reference(s)", missing:[]},
        {id:"g7-openness", label:"G7 model openness (weight/architecture/data/training)", required:false,
         status:(if $open_hits>0 then "pass" else "warn" end),
         detail:(if $open_hits>0 then "declared" else "not declared in the SBOM" end), missing:[]}
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
    g() { grep -cE "$1" "$SBOM" 2>/dev/null || echo 0; }
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
    echo "| Status | Requirement | Required | Detail |"
    echo "|--------|-------------|:--------:|--------|"
    echo "$CHECKS" | jq -r '.[] |
        "| \(if .status=="pass" then "✅" elif .status=="fail" then "❌" else "⚠️" end) | \(.label) | \(if .required then "yes" else "no" end) | \(.detail | gsub("[|\n]"; " ")) |"'
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
 body{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;}
 h1{border-bottom:2px solid #ddd;padding-bottom:.4rem;}
 .meta{color:#666;font-size:.9rem;}
 .cards{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0;}
 .card{padding:.6rem 1rem;border-radius:6px;color:#fff;font-weight:600;}
 .pass{background:#16a34a;} .fail{background:#dc2626;} .warn{background:#d97706;}
 table{border-collapse:collapse;width:100%;font-size:.85rem;}
 th,td{border:1px solid #e3e3e3;padding:.4rem .6rem;text-align:left;}
 th{background:#f3f4f6;}
 .s-pass{color:#16a34a;font-weight:700;} .s-fail{color:#dc2626;font-weight:700;} .s-warn{color:#d97706;font-weight:700;}
 ul{margin:.3rem 0 0 1rem;} li{font-family:ui-monospace,monospace;font-size:.82rem;}
</style></head><body>
<h1>SBOM Conformance Report</h1>
<p class="meta">Project: $(printf '%s' "$PROJECT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g') &middot; Generated: ${GEN_AT} &middot; Format: ${FORMAT}</p>
<div class="cards">
 <div class="card $( [ "$RESULT" = "pass" ] && echo pass || echo fail )">Result: $(echo "$RESULT" | tr '[:lower:]' '[:upper:]')</div>
 <div class="card fail">Mandatory failures: ${N_FAIL}</div>
 <div class="card warn">Warnings: ${N_WARN}</div>
</div>
<table><tr><th>Status</th><th>Requirement</th><th>Required</th><th>Detail</th></tr>
HTMLHEAD
    echo "$CHECKS" | jq -r '.[] |
        "<tr><td class=\"s-\(.status)\">" + (.status|ascii_upcase|@html) + "</td>" +
        "<td>" + (.label|@html) + "</td><td>" + (if .required then "yes" else "no" end) + "</td>" +
        "<td>" + ((.detail // "")|@html) + "</td></tr>"'
    echo "</table>"
    if echo "$CHECKS" | jq -e 'any(.[]; .required and .status=="fail" and (.missing|length>0))' >/dev/null; then
        echo "<h2>Missing / non-conformant items</h2>"
        echo "$CHECKS" | jq -r '.[] | select(.required and .status=="fail" and (.missing|length>0)) |
            "<h3>" + (.label|@html) + "</h3><ul>" + (.missing | map("<li>" + (.|tostring|@html) + "</li>") | join("")) + "</ul>"'
    fi
    echo "</body></html>"
} > "$HTML"

echo "[validate] $FORMAT -> result=$RESULT (mandatory fails=$N_FAIL, warns=$N_WARN): $JSON, $MD, $HTML"
exit 0
