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
# Requirements (see docs/maintainers/supplier-sbom-analysis.md §4):
#   mandatory : spec version (CycloneDX 1.3-1.6 / SPDX 2.2-2.3; AI SBOMs also
#               accept CycloneDX 1.7), timestamp, tool info, top component,
#               name+version coverage, PURL coverage (>= threshold), PURL
#               syntax, no pkg:generic, transitive edges
#   recommended (warn only): license coverage, hash coverage
#   AI SBOMs (machine-learning-model present): the full G7 minimum-element
#               checklist is appended (7 clusters / 50 elements, data-driven from
#               docker/lib/g7-registry.json), all recommended, each tagged with a
#               data source.
set -e

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

# Coverage thresholds (percent). Override via env to tune strictness.
PURL_MIN_PCT="${PURL_MIN_PCT:-90}"      # mandatory
LICENSE_MIN_PCT="${LICENSE_MIN_PCT:-80}" # recommended (warn)
HASH_MIN_PCT="${HASH_MIN_PCT:-50}"       # recommended (warn)
MISSING_CAP=50                            # cap missing-item lists in the report

# Accepted spec versions (space-separated), per the SKT submission
# requirements. Override via env. AI SBOMs (ML-BOM) additionally accept
# CycloneDX 1.7: the OWASP AIBOM Generator emits 1.7 and the G7 model fields
# need it, while the plain dependency-SBOM submission range stays 1.3-1.6.
CYCLONEDX_SPEC_VERSIONS="${CYCLONEDX_SPEC_VERSIONS:-1.3 1.4 1.5 1.6}"
AI_CYCLONEDX_SPEC_VERSIONS="${AI_CYCLONEDX_SPEC_VERSIONS:-$CYCLONEDX_SPEC_VERSIONS 1.7}"
SPDX_SPEC_VERSIONS="${SPDX_SPEC_VERSIONS:-SPDX-2.2 SPDX-2.3}"

# Practical PURL shape gate (purl-spec): pkg:type/[namespace/]name@version
# [?qualifiers][#subpath]. The segment charset tolerates the unencoded '@'
# some tools emit for npm scopes; spaces, colon coordinates, a missing 'pkg:'
# prefix and a missing '@version' are offenders.
PURL_SYNTAX_REGEX='^pkg:[a-z][a-z0-9.+-]*(/[A-Za-z0-9._%~@+-]+)+@[A-Za-z0-9._%~+:-]+(\?[A-Za-z0-9._%~+=&:,/-]+)?(#[A-Za-z0-9._%~+/-]+)?$'

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
# $1: space-separated accepted specVersion values for this SBOM kind.
cdx_checks() {
    jq -c \
       --argjson purlmin "$PURL_MIN_PCT" \
       --argjson licmin "$LICENSE_MIN_PCT" \
       --argjson hashmin "$HASH_MIN_PCT" \
       --argjson cap "$MISSING_CAP" \
       --arg okvers "${1:-$CYCLONEDX_SPEC_VERSIONS}" \
       --arg purlre "$PURL_SYNTAX_REGEX" "
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
    | ([ \$c[] | (.purl // empty) | select(test(\$purlre) | not) ]) as \$badpurl
    | (\$okvers | split(\" \")) as \$vers
    | ((.specVersion // \"\") | tostring) as \$sv
    | ((\$c | map(select((.licenses // []) | length > 0)) | length)) as \$lic_ok
    | ((\$c | map(select((.hashes // []) | length > 0)) | length)) as \$hash_ok
    | ([ .dependencies[]? | .dependsOn[]? ] | length) as \$dep_edges
    | (.metadata.timestamp // \"\") as \$ts
    | (.metadata.component // {}) as \$top
    | (\$tot - (\$miss_purl|length)) as \$purl_ok
    | [
       {id:\"spec-version\", label:(\"Spec version (CycloneDX \" + (\$vers|join(\"/\")) + \")\"), required:true,
        status:(if (\$vers | index(\$sv)) != null then \"pass\" else \"fail\" end),
        detail:(\"CycloneDX \" + \$sv), missing:[]},
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
       {id:\"purl-syntax\", label:\"PURL syntax (pkg:type/name@version)\", required:true,
        status:(if (\$badpurl|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$badpurl|length) malformed\", missing:(\$badpurl[0:\$cap])},
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
# machine-learning-model component). Data-driven: the 7 clusters / 50 elements of
# the G7 "SBOM for AI — Minimum Elements" live in docker/lib/g7-registry.json,
# each mapped to a CycloneDX presence expression (cdxPath) and a data-source tag
# (auto/inferred/declared/na). All checks are recommended (required:false) — G7 is
# non-binding. Elements with no automated source (cdxPath null, source "na" —
# system data flows, security controls, KPI benchmarks, dataset sensitivity) are
# surfaced as "requires human review" rather than silently omitted, so the report
# shows the full 50-element picture and which slice the tool actually covers.
#
# Evaluation builds ONE jq program from the registry (element expressions inlined
# as code, static fields JSON-encoded as literals) and runs it in a single pass —
# no per-element subprocess, and backslashes in expressions survive since they are
# never round-tripped through the shell as data. The program binds $models once so
# per-model expressions do not re-traverse the component array, and the fold is
# part of the same program: a registry syntax error fails THAT single jq call, so
# the loud-warn + "[]" fallback actually fires (a two-stage pipe would return the
# LAST jq's exit status and swallow a compile failure into silence).
#
# Two element shapes:
#   cdxPath     — boolean presence over the whole SBOM (pass / not present).
#   missingPath — per-model coverage: a jq expression (may use $models) returning
#                 the names of model components MISSING the element. Keeps the
#                 old cov() semantics: pass only when EVERY model has it, warn with
#                 the offender list and an "N/M model component(s)" detail otherwise
#                 (an any-model check would hide non-compliant models in a
#                 multi-model supplier SBOM).
g7_ai_checks() {
    local reg="${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}"
    if [ ! -f "$reg" ]; then
        echo "[validate] WARN: G7 registry not found at $reg; skipping G7 checks." >&2
        echo "[]"
        return
    fi
    local prog
    prog=$(jq -r '
        "([.components[]? | select(.type==\"machine-learning-model\")]) as $models | ["
        + ([ .clusters[] as $c | $c.elements[] |
            "{id:" + (.id|@json)
            + ",label:" + (.label|@json)
            + ",required:false"
            + ",cluster:" + ($c.id|@json)
            + ",source:" + (.source|@json)
            + ",role:" + ((.role // "")|@json)
            + ",_present:(" + (if (.source=="na" or (.cdxPath==null)) then "null" else "(try (" + .cdxPath + ") catch false)" end) + ")"
            + ",_missing:(" + (if (.missingPath==null) then "null" else "(try (" + .missingPath + ") catch null)" end) + ")"
            + ",_mtot:($models|length)"
            + ",_ev:(" + (if (.evidencePath==null) then "[]" else "(try (" + .evidencePath + ") catch [])" end) + ")"
            + "}"
        ] | join(",")) + "]"
    ' "$reg") || { echo "[]"; return; }

    # Fold appended to the same program (single jq run — see header comment).
    local fold='
        | map(
            (if .source=="na" then {status:"warn", detail:"requires human review (no automated source)", missing:[]}
             elif ._missing != null then
               (._mtot) as $t | (._missing|length) as $m |
               (if $t==0 then {status:"warn", detail:"no machine-learning-model components", missing:[]}
                elif $m==0 then {status:"pass", detail:"\($t)/\($t) model component(s)", missing:[]}
                else {status:"warn", detail:"\($t - $m)/\($t) model component(s)", missing:(._missing[0:$cap])} end)
             elif ._present==true then {status:"pass", detail:"present", missing:[]}
             elif ._present==false then {status:"warn", detail:"not present in the SBOM", missing:[]}
             else {status:"warn", detail:"requires human review (no automated source)", missing:[]} end) as $s
            | {id, label, required, status:$s.status, detail:$s.detail, missing:$s.missing,
               evidence: ((._ev // []) | unique | .[0:$cap]),
               cluster, source, role}
        )'
    local out
    if ! out=$(jq -c --argjson cap "$MISSING_CAP" "${prog}${fold}" "$SBOM" 2>&1); then
        echo "[validate] WARN: G7 registry evaluation failed; G7 checks skipped this run." >&2
        echo "[validate]   $out" >&2
        echo "[]"
        return
    fi
    echo "$out"
}

spdx_json_checks() {
    jq -c \
       --argjson purlmin "$PURL_MIN_PCT" \
       --argjson licmin "$LICENSE_MIN_PCT" \
       --argjson hashmin "$HASH_MIN_PCT" \
       --argjson cap "$MISSING_CAP" \
       --arg okvers "$SPDX_SPEC_VERSIONS" \
       --arg purlre "$PURL_SYNTAX_REGEX" "
    $PCT_DEF
    ([.packages[]?]) as \$p
    | (\$p|length) as \$tot
    | ([ .creationInfo.creators[]? | select(startswith(\"Tool:\")) ] | length) as \$tools
    | (.creationInfo.created // \"\") as \$ts
    | ([ \$p[] | select((.name==null) or (.versionInfo==null)) | (.name // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$p[] | select(([.externalRefs[]? | select(.referenceType==\"purl\")]|length)==0) | (.name // \"(unnamed)\") ]) as \$miss_purl
    | ([ \$p[] | .externalRefs[]? | select((.referenceLocator // \"\")|startswith(\"pkg:generic\")) | .referenceLocator ]) as \$generic
    | ([ \$p[] | .externalRefs[]? | select(.referenceType==\"purl\") | (.referenceLocator // \"\") | select(test(\$purlre) | not) ]) as \$badpurl
    | (\$okvers | split(\" \")) as \$vers
    | (.spdxVersion // \"\") as \$sv
    | ((\$p | map(select(((.licenseConcluded // \"NOASSERTION\") != \"NOASSERTION\") or ((.licenseDeclared // \"NOASSERTION\") != \"NOASSERTION\"))) | length)) as \$lic_ok
    | ((\$p | map(select((.checksums // [])|length>0)) | length)) as \$hash_ok
    | ([ .relationships[]? | select(.relationshipType==\"DEPENDS_ON\") ] | length) as \$dep_edges
    | (.name // \"\") as \$docname
    | ((.documentDescribes // []) | length) as \$describes
    | (\$tot - (\$miss_purl|length)) as \$purl_ok
    | [
       {id:\"spec-version\", label:(\"Spec version (\" + (\$vers|join(\"/\")) + \")\"), required:true,
        status:(if (\$vers | index(\$sv)) != null then \"pass\" else \"fail\" end),
        detail:\$sv, missing:[]},
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
       {id:\"purl-syntax\", label:\"PURL syntax (pkg:type/name@version)\", required:true,
        status:(if (\$badpurl|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$badpurl|length) malformed\", missing:(\$badpurl[0:\$cap])},
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
    local ts tools names vers purls generic deps lics hashes verpat specok purlok
    ts=$(g '^Created:'); tools=$(g '^Creator: ?Tool:')
    names=$(g '^PackageName:'); vers=$(g '^PackageVersion:')
    purls=$(g 'ExternalRef: ?PACKAGE-MANAGER purl'); generic=$(g 'purl +pkg:generic')
    deps=$(g 'Relationship:.*DEPENDS_ON'); lics=$(g '^PackageLicenseConcluded:'); hashes=$(g '^PackageChecksum:')
    verpat=$(printf '%s' "$SPDX_SPEC_VERSIONS" | sed 's/\./\\./g; s/ /|/g')
    specok=$(g "^SPDXVersion: *($verpat) *\$")
    purlok=$(g 'ExternalRef: ?PACKAGE-MANAGER purl +pkg:[a-z][a-z0-9.+-]*/[^ ]+@[^ ]+ *$')
    jq -cn \
       --argjson ts "$ts" --argjson tools "$tools" --argjson names "$names" \
       --argjson vers "$vers" --argjson purls "$purls" --argjson generic "$generic" \
       --argjson deps "$deps" --argjson lics "$lics" --argjson hashes "$hashes" \
       --argjson specok "$specok" --argjson purlok "$purlok" --arg okvers "$SPDX_SPEC_VERSIONS" '
    [
      {id:"spec-version", label:"Spec version (\($okvers|split(" ")|join("/")))", required:true, status:(if $specok>0 then "pass" else "fail" end), detail:"\($specok) accepted SPDXVersion line(s)", missing:[]},
      {id:"timestamp", label:"Timestamp (Created:)", required:true, status:(if $ts>0 then "pass" else "fail" end), detail:"\($ts) found", missing:[]},
      {id:"tools", label:"Tool info (Creator: Tool:)", required:true, status:(if $tools>0 then "pass" else "fail" end), detail:"\($tools) tool(s)", missing:[]},
      {id:"top-component", label:"Document/package present", required:true, status:(if $names>0 then "pass" else "fail" end), detail:"\($names) package(s)", missing:[]},
      {id:"name-version", label:"PackageName + PackageVersion present", required:true, status:(if $names>0 and $vers>=$names then "pass" else "fail" end), detail:"names=\($names), versions=\($vers)", missing:[]},
      {id:"purl", label:"PURL external refs present", required:true, status:(if $purls>0 and $purls>=$names then "pass" else "fail" end), detail:"\($purls) purl ref(s) for \($names) package(s)", missing:[]},
      {id:"no-generic", label:"No pkg:generic / custom PURL (0)", required:true, status:(if $generic==0 then "pass" else "fail" end), detail:"\($generic) offending", missing:[]},
      {id:"purl-syntax", label:"PURL syntax (pkg:type/name@version)", required:true, status:(if $purls<=$purlok then "pass" else "fail" end), detail:"\($purls - $purlok) malformed", missing:[]},
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
        # AI SBOMs (carry a machine-learning-model component) get two extras:
        # the widened spec-version range (the AIBOM toolchain emits 1.7) and
        # the G7 minimum-element checks — works for both a generated AIBOM and
        # a supplier-submitted AI SBOM under ANALYZE.
        IS_AI=false
        if jq -e '[.components[]? | select(.type=="machine-learning-model")] | length > 0' "$SBOM" >/dev/null 2>&1; then
            IS_AI=true
        fi
        if [ "$IS_AI" = true ]; then
            CHECKS=$(cdx_checks "$AI_CYCLONEDX_SPEC_VERSIONS")
            G7=$(g7_ai_checks)
            CHECKS=$(printf '%s\n%s' "$CHECKS" "$G7" | jq -cs 'add')
            echo "[validate] AI SBOM detected -> added G7 minimum-element checks"
        else
            CHECKS=$(cdx_checks "$CYCLONEDX_SPEC_VERSIONS")
        fi
        ;;
    SPDX-JSON)     CHECKS=$(spdx_json_checks) ;;
    SPDX-TagValue) CHECKS=$(spdx_tv_checks) ;;
    *)
        CHECKS='[{"id":"format","label":"Recognized SBOM format","required":true,"status":"fail","detail":"not CycloneDX or SPDX","missing":[]}]'
        ;;
esac
[ -n "$CHECKS" ] || CHECKS='[{"id":"parse","label":"Parseable SBOM","required":true,"status":"fail","detail":"could not evaluate","missing":[]}]'

# Overall result: fail if any mandatory check failed. G7 elements with no
# automated source (source "na") are counted separately as review items — a
# well-formed AIBOM should not read as "30 warnings" just because a dozen G7
# elements are checkable only by a human.
RESULT=$(echo "$CHECKS" | jq -r 'if any(.[]; .required and .status=="fail") then "fail" else "pass" end')
N_FAIL=$(echo "$CHECKS" | jq '[.[] | select(.required and .status=="fail")] | length')
N_WARN=$(echo "$CHECKS" | jq '[.[] | select(.status=="warn" and ((.source // "") != "na"))] | length')
N_REVIEW=$(echo "$CHECKS" | jq '[.[] | select((.source // "") == "na")] | length')

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
    echo "- Result: **$(echo "$RESULT" | tr '[:lower:]' '[:upper:]')** (mandatory failures: ${N_FAIL}, warnings: ${N_WARN}, needs review: ${N_REVIEW})"
    echo ""
    echo "| Status | Requirement | Required | Detail | Evidence |"
    echo "|--------|-------------|:--------:|--------|----------|"
    echo "$CHECKS" | jq -r '.[] |
        "| \(if .status=="pass" then "✅" elif .status=="fail" then "❌" elif (.source // "")=="na" then "🔍" else "⚠️" end) | \(.label) | \(if .required then "yes" else "no" end) | \(.detail | gsub("[|\n]"; " ")) | \(((.evidence // []) | join(", ")) | gsub("[|\n]"; " ")) |"'
    echo ""
    # Missing-item detail for every non-passing check that names offenders —
    # mandatory failures AND advisory G7 warns (a reviewer needs to know WHICH
    # model components lack the license/hash, not just the count).
    if echo "$CHECKS" | jq -e 'any(.[]; .status!="pass" and (.missing|length>0))' >/dev/null; then
        echo "## Missing / non-conformant items"
        echo ""
        echo "$CHECKS" | jq -r '.[] | select(.status!="pass" and (.missing|length>0)) |
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
 <span class="pill">Needs review: <span class="count">${N_REVIEW}</span></span>
</div>
<div class="table-wrap"><table><tr><th>Status</th><th>Requirement</th><th>Required</th><th>Detail</th><th>Evidence</th></tr>
HTMLHEAD
    echo "$CHECKS" | jq -r '.[] |
        "<tr><td class=\"s-\(.status)\">" + (if (.source // "")=="na" then "REVIEW" else (.status|ascii_upcase) end|@html) + "</td>" +
        "<td>" + (.label|@html) + "</td><td>" + (if .required then "yes" else "no" end) + "</td>" +
        "<td>" + ((.detail // "")|@html) + "</td>" +
        "<td>" + (((.evidence // []) | join(", "))|@html) + "</td></tr>"'
    echo "</table></div>"
    if echo "$CHECKS" | jq -e 'any(.[]; .status!="pass" and (.missing|length>0))' >/dev/null; then
        echo "<h2>Missing / non-conformant items</h2>"
        echo "$CHECKS" | jq -r '.[] | select(.status!="pass" and (.missing|length>0)) |
            "<h3>" + (.label|@html) + "</h3><ul class=\"mono\">" + (.missing | map("<li>" + (.|tostring|@html) + "</li>") | join("")) + "</ul>"'
    fi
    echo "</body></html>"
} > "$HTML"

echo "[validate] $FORMAT -> result=$RESULT (mandatory fails=$N_FAIL, warns=$N_WARN, review=$N_REVIEW): $JSON, $MD, $HTML"
exit 0
