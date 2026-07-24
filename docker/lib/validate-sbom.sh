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
FIELD_MIN_PCT="${FIELD_MIN_PCT:-80}"     # advisory: regulatory per-component fields
MISSING_CAP=50                            # cap missing-item lists in the report

# Accepted spec versions (space-separated), per the SKT submission
# requirements. Override via env. AI SBOMs (ML-BOM) additionally accept
# CycloneDX 1.7: the OWASP AIBOM Generator emits 1.7 and the G7 model fields
# need it, while the plain dependency-SBOM submission range stays 1.3-1.6.
CYCLONEDX_SPEC_VERSIONS="${CYCLONEDX_SPEC_VERSIONS:-1.3 1.4 1.5 1.6}"
AI_CYCLONEDX_SPEC_VERSIONS="${AI_CYCLONEDX_SPEC_VERSIONS:-$CYCLONEDX_SPEC_VERSIONS 1.7}"
SPDX_SPEC_VERSIONS="${SPDX_SPEC_VERSIONS:-SPDX-2.2 SPDX-2.3 SPDX-3.0}"

# Practical PURL shape gate (purl-spec): pkg:type/[namespace/]name@version
# [?qualifiers][#subpath]. The segment charset tolerates the unencoded '@'
# some tools emit for npm scopes; spaces, colon coordinates, a missing 'pkg:'
# prefix and a missing '@version' are offenders.
PURL_SYNTAX_REGEX='^pkg:[a-z][a-z0-9.+-]*(/[A-Za-z0-9._%~@+-]+)+@[A-Za-z0-9._%~+:-]+(\?[A-Za-z0-9._%~+=&:,/-]+)?(#[A-Za-z0-9._%~+/-]+)?$'

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[validate] SBOM file not found: $SBOM" >&2
    exit 1
fi

# Normalize input encoding (UTF-16/BOM/stray preamble) so jq and grep see UTF-8.
# Validation still runs against the original submission's content — only the
# encoding is corrected, not the SBOM data.
# shellcheck source=docker/lib/sbom-detect.sh
. "$(dirname "$0")/sbom-detect.sh"
SBOM="$(normalize_sbom_encoding "$SBOM" "$(dirname "$OUT_PREFIX")")"

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
elif jq -e '(.["@context"]? // "" | tostring | test("spdx.org/rdf/3")) or (.["@graph"]? != null)' "$SBOM" >/dev/null 2>&1; then
    FORMAT="SPDX-3.0"
elif grep -q '^SPDXVersion:' "$SBOM" 2>/dev/null; then
    FORMAT="SPDX-TagValue"
fi
echo "[validate] detected format: $FORMAT"

# Shared jq helper: percentage with zero-guard (jq source, not shell — vars are intentional).
#
# The 0 an empty denominator returns is a placeholder that keeps jq from dividing
# by zero — it is not a measurement. Any caller comparing the result against a
# minimum must rule out an empty denominator FIRST, or "nothing to measure" reads
# as "0%, the worst possible score" and fails the SBOM for a field that had no
# subject. The coverage checks below do exactly that.
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
       --argjson fieldmin "$FIELD_MIN_PCT" \
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
    | ([ \$c[] | select(.type != \"data\") ]) as \$pkg
    | (\$pkg|length) as \$ptot
    # name+version and purl coverage are package questions, so they are measured
    # over \$pkg (everything except type \"data\") rather than every component. A
    # data component — a training dataset, say — has no package version and no
    # purl type to carry: purl defines none for a dataset. Counting them would
    # fail an otherwise complete SBOM for a field that cannot exist. License and
    # checksum coverage below still count them, because those they can carry.
    | ([ \$pkg[] | select((.name==null) or (.version==null)) | (.name // .purl // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$pkg[] | select(.purl==null) | (.name // \"(unnamed)\") ]) as \$miss_purl
    | ([ \$c[] | select((.purl // \"\") | startswith(\"pkg:generic\")) | (.name // .purl) ]) as \$generic
    | ([ \$c[] | (.purl // empty) | select(test(\$purlre) | not) ]) as \$badpurl
    | (\$okvers | split(\" \")) as \$vers
    | ((.specVersion // \"\") | tostring) as \$sv
    | ((\$c | map(select((.licenses // []) | length > 0)) | length)) as \$lic_ok
    | ((\$c | map(select((.hashes // []) | length > 0)) | length)) as \$hash_ok
    | ([ .dependencies[]? | .dependsOn[]? ] | length) as \$dep_edges
    | (.metadata.timestamp // \"\") as \$ts
    | (.metadata.component // {}) as \$top
    | (\$ptot - (\$miss_purl|length)) as \$purl_ok
    # Per-component fields named by the regulatory crosswalk (BSI TR-03183-2 /
    # NTIA). All advisory: they describe how well the SBOM would answer a
    # regulator, and never move the submission verdict. Measured over \$pkg for
    # the same reason name+version is — a data component carries no filename,
    # creator or artifact URI — except the SHA-512 tally, which counts every
    # component because a dataset can carry a checksum.
    | ([ \$pkg[] | select(((.authors // []) | length > 0) or ((.publisher // \"\") != \"\")
                          or (((.supplier // {}) | length) > 0) or (((.manufacturer // {}) | length) > 0)) ] | length) as \$creator_ok
    | ([ \$pkg[] | select((.properties // []) | any(.name == \"bsi:component:filename\")) ] | length) as \$fname_ok
    | ([ \$c[] | select((.hashes // []) | any(.alg == \"SHA-512\")) ] | length) as \$sha512_ok
    | ([ \$pkg[] | select((.externalReferences // []) | any(.type == \"vcs\" or .type == \"distribution\")) ] | length) as \$uri_ok
    | ([ \$pkg[] | select((.properties // []) as \$props
                          | (\$props | any(.name == \"bsi:component:executable\"))
                            and (\$props | any(.name == \"bsi:component:archive\"))
                            and (\$props | any(.name == \"bsi:component:structured\"))) ] | length) as \$fprops_ok
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
        detail:\"\(\$ptot - (\$miss_nv|length))/\(\$ptot)\", missing:(\$miss_nv[0:\$cap])},
       {id:\"purl\", label:\"PURL coverage (>= \(\$purlmin)%)\", required:true,
        status:(if \$ptot==0 or pct(\$purl_ok;\$ptot) >= \$purlmin then \"pass\" else \"fail\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$purl_ok;\$ptot))% (\(\$purl_ok)/\(\$ptot))\" end),
        missing:(\$miss_purl[0:\$cap])},
       {id:\"no-generic\", label:\"Traceable PURL (no pkg:generic, advisory)\", required:false,
        status:(if (\$generic|length)==0 then \"pass\" else \"warn\" end),
        detail:\"\(\$generic|length) untraceable\", missing:(\$generic[0:\$cap])},
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
        detail:\"\(pct(\$hash_ok;\$tot))% (\(\$hash_ok)/\(\$tot))\", missing:[]},
       {id:\"hash-algorithm\", label:\"SHA-512 checksum coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        status:(if \$tot==0 or pct(\$sha512_ok;\$tot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$tot==0 then \"nothing to measure\"
                else \"\(pct(\$sha512_ok;\$tot))% (\(\$sha512_ok)/\(\$tot))\" end), missing:[]},
       {id:\"component-creator\", label:\"Component creator coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        status:(if \$ptot==0 or pct(\$creator_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$creator_ok;\$ptot))% (\(\$creator_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"component-filename\", label:\"Component filename coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        status:(if \$ptot==0 or pct(\$fname_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$fname_ok;\$ptot))% (\(\$fname_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"artifact-uri\", label:\"Source or distribution URI coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        status:(if \$ptot==0 or pct(\$uri_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$uri_ok;\$ptot))% (\(\$uri_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"file-properties\", label:\"Delivered-file properties (executable/archive/structured)\", required:false,
        source:(if \$ptot==0 or \$fprops_ok>0 then \"auto\" else \"na\" end),
        status:(if \$ptot==0 or pct(\$fprops_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                elif \$fprops_ok==0 then \"requires inspecting the delivered files (no automated source in this scan)\"
                else \"\(pct(\$fprops_ok;\$ptot))% (\(\$fprops_ok)/\(\$ptot))\" end), missing:[]}
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
    # The regulatory crosswalk used to be joined here, over the G7 elements only.
    # It now runs once over the whole check array (see join_crosswalk below) so the
    # plain CycloneDX checks carry their CRA / NTIA references too.
    #
    # Join the fill-in guidance (best-effort): the CycloneDX fragment
    # that would satisfy each element, so the report can answer "how do I close
    # this gap" and not just "this is missing". Attached only where a mapping
    # exists, and like the crosswalk it never changes a status or the result.
    local guide="${G7_GUIDANCE:-$(dirname "$0")/g7-guidance.json}"
    if [ -f "$guide" ]; then
        local gjoined
        if gjoined=$(printf '%s' "$out" | jq -c --slurpfile g "$guide" '
            (($g[0].map) // {}) as $m
            | (($g[0].review) // {}) as $r
            | map(if $m[.id] then . + {guidance: $m[.id]} else . end)
            | map(if $r[.id] then . + {reviewGuide: $r[.id]} else . end)' 2>/dev/null); then
            out="$gjoined"
        else
            echo "[validate] WARN: G7 guidance join failed; continuing without it." >&2
        fi
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
    | ([ .relationships[]? | select(.relationshipType==\"DEPENDS_ON\" or .relationshipType==\"DEPENDENCY_OF\") ] | length) as \$dep_edges
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
        status:(if \$tot==0 or pct(\$purl_ok;\$tot) >= \$purlmin then \"pass\" else \"fail\" end),
        detail:(if \$tot==0 then \"no packages to measure\"
                else \"\(pct(\$purl_ok;\$tot))% (\(\$purl_ok)/\(\$tot))\" end),
        missing:(\$miss_purl[0:\$cap])},
       {id:\"no-generic\", label:\"Traceable PURL (no pkg:generic, advisory)\", required:false,
        status:(if (\$generic|length)==0 then \"pass\" else \"warn\" end),
        detail:\"\(\$generic|length) untraceable\", missing:(\$generic[0:\$cap])},
       {id:\"purl-syntax\", label:\"PURL syntax (pkg:type/name@version)\", required:true,
        status:(if (\$badpurl|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$badpurl|length) malformed\", missing:(\$badpurl[0:\$cap])},
       {id:\"transitive\", label:\"Transitive dependencies (DEPENDS_ON/DEPENDENCY_OF)\", required:true,
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
    deps=$(g 'Relationship:.*(DEPENDS_ON|DEPENDENCY_OF)'); lics=$(g '^PackageLicenseConcluded:'); hashes=$(g '^PackageChecksum:')
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
      {id:"no-generic", label:"Traceable PURL (no pkg:generic, advisory)", required:false, status:(if $generic==0 then "pass" else "warn" end), detail:"\($generic) untraceable", missing:[]},
      {id:"purl-syntax", label:"PURL syntax (pkg:type/name@version)", required:true, status:(if $purls<=$purlok then "pass" else "fail" end), detail:"\($purls - $purlok) malformed", missing:[]},
      {id:"transitive", label:"Transitive dependencies (DEPENDS_ON/DEPENDENCY_OF)", required:true, status:(if $deps>0 then "pass" else "fail" end), detail:"\($deps) relationship(s)", missing:[]},
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
    SPDX-3.0)
        # SPDX 3.0 is JSON-LD (@graph); the 2.x package/relationship shape the
        # spdx_json checks read does not exist. Measure conformance on the
        # CycloneDX that syft produces from it — the same converter the analysis
        # pipeline uses — so PURL coverage, name/version, and transitive edges
        # come from real component data instead of reading as all-zero.
        SPDX3_CDX="${OUT_PREFIX}.spdx3-cdx.$$.json"
        if command -v syft >/dev/null 2>&1 \
           && syft convert "$SBOM" -o cyclonedx-json@1.6="$SPDX3_CDX" >/dev/null 2>&1 \
           && [ -s "$SPDX3_CDX" ]; then
            SBOM="$SPDX3_CDX"
            CHECKS=$(cdx_checks "$CYCLONEDX_SPEC_VERSIONS")
            rm -f "$SPDX3_CDX"
            echo "[validate] SPDX 3.0 measured via CycloneDX conversion"
        else
            echo "[validate] WARN: syft unavailable; SPDX 3.0 recognized but not measured" >&2
            CHECKS='[{"id":"spec-version","label":"Spec version (SPDX-3.0)","required":true,"status":"pass","detail":"SPDX-3.0 (recognized; not measured without syft)","missing":[]}]'
        fi
        ;;
    SPDX-TagValue) CHECKS=$(spdx_tv_checks) ;;
    *)
        CHECKS='[{"id":"format","label":"Recognized SBOM format","required":true,"status":"fail","detail":"not CycloneDX or SPDX","missing":[]}]'
        ;;
esac
[ -n "$CHECKS" ] || CHECKS='[{"id":"parse","label":"Parseable SBOM","required":true,"status":"fail","detail":"could not evaluate","missing":[]}]'

# --------------------------------------------------------
# Join the regulatory crosswalk (best-effort) over EVERY check, not just the G7
# elements: docker/lib/regulation-crosswalk.json is keyed by check id, so a plain
# CycloneDX check picks up its CRA / BSI / NTIA references the same way a G7
# element picks up its EU AI Act reference. Purely informational — it never
# changes a status or the overall result. A missing or invalid crosswalk leaves
# every check with regulations:[] and the run continues.
# --------------------------------------------------------
XWALK_FILE="${REGULATION_CROSSWALK:-$(dirname "$0")/regulation-crosswalk.json}"
if [ -f "$XWALK_FILE" ]; then
    if XW_JOINED=$(printf '%s' "$CHECKS" | jq -c --slurpfile x "$XWALK_FILE" '
        (($x[0].map) // {}) as $m
        | (($x[0].frameworks) // {}) as $fw
        | map(. + {regulations: (($m[.id] // []) | map(
            . + {short:    ($fw[.framework].short // .framework),
                 short_ko: ($fw[.framework].short_ko // $fw[.framework].short // .framework)}))})' 2>/dev/null); then
        CHECKS="$XW_JOINED"
    else
        echo "[validate] WARN: regulation crosswalk join failed; continuing without it." >&2
    fi
fi

# Overall result: fail if any mandatory check failed. G7 elements with no
# automated source (source "na") are counted separately as review items — a
# well-formed AIBOM should not read as "30 warnings" just because a dozen G7
# elements are checkable only by a human.
RESULT=$(echo "$CHECKS" | jq -r 'if any(.[]; .required and .status=="fail") then "fail" else "pass" end')
N_FAIL=$(echo "$CHECKS" | jq '[.[] | select(.required and .status=="fail")] | length')
# no-generic is advisory (untraceable-component visibility), counted on its own
# line below rather than folded into the recommended-coverage warnings.
N_WARN=$(echo "$CHECKS" | jq '[.[] | select(.status=="warn" and ((.source // "") != "na") and .id != "no-generic")] | length')
N_REVIEW=$(echo "$CHECKS" | jq '[.[] | select((.source // "") == "na")] | length')
# Untraceable components: count of pkg:generic / custom PURLs (from the no-generic
# check's detail, "N untraceable"). Does NOT affect RESULT — surfaced so a pass
# never hides components that can't be tracked for supply-chain / CVE matching.
N_UNTRACEABLE=$(echo "$CHECKS" | jq -r '([.[] | select(.id=="no-generic")][0].detail // "0") | split(" ")[0] | (tonumber? // 0)')

# --------------------------------------------------------
# Regulatory crosswalk summary (informational). Groups the checks that carry
# crosswalk mappings by regulation framework and, per framework, counts how many
# mapped requirements are present / a gap / review-only and lists them. Never
# affects RESULT — it is a documentation-preparation view, not a compliance
# verdict. An AI SBOM picks up the AI frameworks on top of the SBOM-field ones
# every CycloneDX SBOM gets. Empty (frameworks:[]) when the crosswalk file is
# absent or nothing maps.
# --------------------------------------------------------
XW_SUMMARY='{"frameworks":[],"disclaimer":""}'
if [ -f "$XWALK_FILE" ]; then
    XW_SUMMARY=$(echo "$CHECKS" | jq -c --slurpfile x "$XWALK_FILE" '
      ($x[0].frameworks // {}) as $fw
      | [ .[] | select((.regulations // []) | length > 0) ] as $rows
      | { disclaimer: ($x[0].disclaimer // ""),
          frameworks: [
            $fw | to_entries[] | .key as $fid | .value as $meta
            | ($rows | map(select((.regulations // []) | any(.framework==$fid)))) as $frows
            | select(($frows|length) > 0)
            | { id: $fid, title: ($meta.title // $fid), source: ($meta.source // ""),
                total:   ($frows|length),
                present: ($frows | map(select(.status=="pass")) | length),
                gap:     ($frows | map(select(.status=="warn" and ((.source//"")!="na"))) | length),
                review:  ($frows | map(select((.source//"")=="na")) | length),
                elements:($frows | map({id, label, status, source, detail,
                            refs: [ (.regulations // [])[] | select(.framework==$fid) | .ref ]})) }
          ] }' 2>/dev/null) || XW_SUMMARY='{"frameworks":[],"disclaimer":""}'
fi

# --------------------------------------------------------
# AI coverage rollup (AI SBOMs only). Same numbers the AI compliance profile
# reports, computed here so the reader gets the overview and the per-check detail
# in one page instead of two. Empty for a plain dependency SBOM.
# --------------------------------------------------------
G7_CLUSTERS='[]'
if echo "$CHECKS" | jq -e 'any(.[]; .id|startswith("g7-"))' >/dev/null 2>&1; then
    REG_FILE="${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}"
    G7_CLUSTERS=$(echo "$CHECKS" | jq -c --slurpfile reg "$REG_FILE" '
      ([ $reg[0].clusters[] | {(.id): {name: .name, name_ko: (.name_ko // .name)}} ] | add) as $names
      | ([ $reg[0].clusters[].id ]) as $order
      | [ .[] | select(.id|startswith("g7-")) ]
      | group_by(.cluster)
      | sort_by((.[0].cluster // "") as $c | ($order | index($c)) // 99)
      | map({ cluster: (.[0].cluster // "other"),
              name:    ($names[(.[0].cluster // "")].name // (.[0].cluster // "other")),
              name_ko: ($names[(.[0].cluster // "")].name_ko // (.[0].cluster // "other")),
              total:   length,
              present: (map(select(.status=="pass"))|length),
              gap:     (map(select(.status=="warn" and ((.source//"")!="na")))|length),
              review:  (map(select((.source//"")=="na"))|length) })' 2>/dev/null || echo '[]')
fi

# Components whose declared license restricts use — the same classifier the NOTICE
# and the web UI share. Read straight from the SBOM, so it does not depend on
# normalize-sbom.sh having tagged the components first.
LIC_REVIEW='[]'
if [ "$G7_CLUSTERS" != "[]" ] && [ -f "$(dirname "$0")/license-flags.jq" ]; then
    LIC_FLAGS_DEF="$(cat "$(dirname "$0")/license-flags.jq")"
    LIC_REVIEW=$(jq -c "$LIC_FLAGS_DEF"'
      [ .components[]?
        | { name: (.name // "(unnamed)"), version: (.version // ""),
            license: ([ (.licenses // [])[] | (.license.id // .license.name // .expression) ]
                       | map(select(. != null and . != "")) | (.[0] // "")) }
        | . + {flag: license_flag(.license)}
        | select(.flag != "") ]' "$SBOM" 2>/dev/null || echo '[]')
fi

# --------------------------------------------------------
# JSON report
# --------------------------------------------------------
jq -n \
   --arg project "$PROJECT" --arg format "$FORMAT" --arg result "$RESULT" \
   --arg ts "$GEN_AT" --argjson checks "$CHECKS" --argjson xwalk "$XW_SUMMARY" \
   --argjson untraceable "$N_UNTRACEABLE" '
{ project: $project, format: $format, result: $result, generatedAt: $ts,
  untraceableComponents: $untraceable, checks: $checks }
+ (if ($xwalk.frameworks | length) > 0 then { regulatoryCrosswalk: $xwalk } else {} end)
' > "$JSON"

# --------------------------------------------------------
# Localization (REPORT_LANG=ko). The JSON above is NEVER localized — it is an
# English contract the web layer and CI consume. Only the human-facing Markdown
# and HTML below are localized. English (the default) renders the exact inline
# literals it always did (RCHECKS/RXW = the English CHECKS/XW_SUMMARY, every
# chrome var = its English literal), so its output stays byte-identical. Korean
# swaps the chrome strings from docker/lib/i18n/report-strings.ko.json and the
# per-row label/detail text (element labels via g7-registry.json label_ko).
# --------------------------------------------------------
REPORT_LANG="${REPORT_LANG:-en}"; [ "$REPORT_LANG" = "ko" ] || REPORT_LANG="en"
KO_CAT="$(dirname "$0")/i18n/report-strings.ko.json"
if [ "$REPORT_LANG" = "ko" ] && [ ! -f "$KO_CAT" ]; then
    echo "[validate] WARN: ko report catalog not found ($KO_CAT); using English." >&2
    REPORT_LANG="en"
fi
# kstr KEY -> the ko string for KEY (or KEY itself if missing, so a gap is visible).
kstr() { jq -r --arg k "$1" '.[$k] // $k' "$KO_CAT"; }
# tfmt KEY ARGS... -> the ko template for KEY, filled with printf (%s placeholders).
# shellcheck disable=SC2059  # the format is a trusted catalog template, not user input
tfmt() { local f; f="$(kstr "$1")"; shift; printf -- "$f" "$@"; }

RESULT_UP=$(echo "$RESULT" | tr '[:lower:]' '[:upper:]')
PROJECT_ESC=$(printf '%s' "$PROJECT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
# Header link: an AI SBOM carries the model's own page as an external reference, so
# the project name can point at it. A plain dependency SBOM has none — stays text.
MODEL_URL=$(jq -r '[.components[]? | select(.type=="machine-learning-model")
    | .externalReferences[]? | select(.type=="website") | .url
    | select(type=="string" and startswith("https://"))] | .[0] // empty' "$SBOM" 2>/dev/null || true)
PROJECT_HTML="$PROJECT_ESC"
if [ -n "$MODEL_URL" ]; then
    MODEL_URL_ESC=$(printf '%s' "$MODEL_URL" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    PROJECT_HTML="<a href=\"${MODEL_URL_ESC}\" target=\"_blank\" rel=\"noopener noreferrer\">${PROJECT_ESC}</a>"
fi
HTML_LANG="en"
RCHECKS="$CHECKS"
RXW="$XW_SUMMARY"

if [ "$REPORT_LANG" = "ko" ]; then
    HTML_LANG="ko"
    REG="${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}"
    # Localize per-row label + detail into a render copy (status/missing/guidance/
    # evidence/regulations untouched, so the render loops below are unchanged).
    RCHECKS=$(printf '%s' "$CHECKS" | jq -c --slurpfile cat "$KO_CAT" --slurpfile reg "$REG" '
      ($cat[0]) as $C
      | ([ $reg[0].clusters[].elements[] | {(.id): .label_ko} ] | add) as $RK
      | def llabel($id; $en):
          if ($id|startswith("g7-")) then ($RK[$id] // $en)
          elif ($en|test("^Spec version \\(CycloneDX ")) then ($C["conformance.label.spec_cdx"] | gsub("%v%"; ($en|capture("^Spec version \\(CycloneDX (?<v>.+)\\)$").v)))
          elif ($en|test("^Spec version \\(")) then ($C["conformance.label.spec_other"] | gsub("%v%"; ($en|capture("^Spec version \\((?<v>.+)\\)$").v)))
          elif ($en|test("^PURL coverage ")) then ($C["conformance.label.purl"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          elif ($en|test("^License coverage ")) then ($C["conformance.label.license"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          elif ($en|test("^Hash coverage ")) then ($C["conformance.label.hash"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          # These four capture the threshold from ">= N%" rather than the first
          # run of digits: "SHA-512 checksum coverage" would otherwise report 512.
          elif ($en|test("^SHA-512 checksum coverage ")) then ($C["conformance.label.sha512"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Component creator coverage ")) then ($C["conformance.label.creator"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Component filename coverage ")) then ($C["conformance.label.filename"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Source or distribution URI coverage ")) then ($C["conformance.label.artifact_uri"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          else ($C["conformance.label_exact"][$en] // $en) end;
        def ldetail($d):
          if $d=="present" then $C["conformance.detail.present"]
          elif $d=="not present in the SBOM" then $C["conformance.detail.not_present"]
          elif $d=="requires human review (no automated source)" then $C["conformance.detail.review"]
          elif $d=="no packages to measure" then $C["conformance.detail.no_packages"]
          elif $d=="nothing to measure" then $C["conformance.detail.nothing"]
          elif $d=="requires inspecting the delivered files (no automated source in this scan)" then $C["conformance.detail.file_props_review"]
          elif $d=="no machine-learning-model components" then $C["conformance.detail.no_models"]
          elif $d=="not CycloneDX or SPDX" then $C["conformance.detail.not_cdx_spdx"]
          elif $d=="could not evaluate" then $C["conformance.detail.could_not_eval"]
          elif ($d|test("^[0-9]+/[0-9]+ model component\\(s\\)$")) then ($d|capture("^(?<a>[0-9]+)/(?<b>[0-9]+)")) as $m | ($C["conformance.detail.model_components"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ tool\\(s\\)$")) then ($C["conformance.detail.tool"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ edge\\(s\\)$")) then ($C["conformance.detail.edge"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ untraceable$")) then ($C["conformance.detail.untraceable"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ malformed$")) then ($C["conformance.detail.malformed"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ found$")) then ($C["conformance.detail.found"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ accepted SPDXVersion line\\(s\\)$")) then ($C["conformance.detail.spdxver"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ package\\(s\\)$")) then ($C["conformance.detail.package"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^names=[0-9]+, versions=[0-9]+$")) then ($d|capture("names=(?<a>[0-9]+), versions=(?<b>[0-9]+)")) as $m | ($C["conformance.detail.names_versions"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ purl ref\\(s\\) for [0-9]+ package\\(s\\)$")) then ($d|capture("^(?<a>[0-9]+) purl ref\\(s\\) for (?<b>[0-9]+)")) as $m | ($C["conformance.detail.purl_refs"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ relationship\\(s\\)$")) then ($C["conformance.detail.relationship"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ license field\\(s\\)$")) then ($C["conformance.detail.license_field"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ checksum\\(s\\)$")) then ($C["conformance.detail.checksum"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          else $d end;
      map(.label = llabel(.id; .label) | .detail = ldetail(.detail)
          | (if (.reviewGuide.how_ko // "") != "" then .reviewGuide.how = .reviewGuide.how_ko else . end))
    ') || RCHECKS="$CHECKS"
    # Crosswalk: swap the framework display titles and the disclaimer for their
    # Korean wording from the crosswalk file itself (same convention as the G7
    # registry's label_ko). The `source` line stays verbatim — a regulation's
    # citation is an identifier, not prose. The JSON contract keeps the English
    # title, so this touches the render copy only.
    RXW=$(printf '%s' "$XW_SUMMARY" | jq -c --slurpfile x "$XWALK_FILE" '
      (($x[0].frameworks) // {}) as $F
      | .disclaimer = ($x[0].disclaimer_ko // .disclaimer)
      | .frameworks |= map(.title = ($F[.id].title_ko // .title))') || RXW="$XW_SUMMARY"
fi

# Chrome strings: English literals by default (byte-identical), catalog for ko.
if [ "$REPORT_LANG" = "ko" ]; then
    C_MD_TITLE=$(tfmt conformance.md_title "$PROJECT")
    C_MD_GEN=$(tfmt conformance.md_generated "$GEN_AT")
    C_MD_FMT=$(tfmt conformance.md_format "$FORMAT")
    C_MD_RESULT=$(tfmt conformance.md_result "$RESULT_UP" "$N_FAIL" "$N_WARN" "$N_REVIEW")
    C_MD_UNTRACE=$(tfmt conformance.md_untraceable "$N_UNTRACEABLE")
    C_TH_STATUS=$(kstr conformance.th_status); C_TH_REQMT=$(kstr conformance.th_requirement)
    C_TH_REQD=$(kstr conformance.th_required); C_TH_DETAIL=$(kstr conformance.th_detail)
    C_TH_EVID=$(kstr conformance.th_evidence); C_FIX_SUMMARY=$(kstr conformance.fix_summary)
    C_CHECK_SUMMARY=$(kstr conformance.check_summary)
    C_H2_SUBMIT=$(kstr conformance.h2_submission); C_SUBMIT_INTRO=$(kstr conformance.submission_intro)
    C_H2_CLUSTERS=$(kstr aiprofile.h2_clusters); C_TH_CLUSTER=$(kstr aiprofile.th_cluster)
    C_TH_PRESENT=$(kstr aiprofile.th_present); C_TH_GAP=$(kstr aiprofile.th_gap)
    C_TH_REVIEWCNT=$(kstr aiprofile.th_review); C_TH_TOTAL=$(kstr aiprofile.th_total)
    C_H2_LIC=$(kstr aiprofile.h2_lic); C_TH_COMP=$(kstr aiprofile.th_component)
    C_TH_VER=$(kstr aiprofile.th_version); C_TH_LIC=$(kstr aiprofile.th_license)
    C_TH_FLAG=$(kstr aiprofile.th_flag); C_LIC_NONE=$(kstr aiprofile.lic_none_html)
    C_H2_G7CHK=$(kstr conformance.h2_g7checks); C_G7CHK_INTRO=$(kstr conformance.g7checks_intro)
    C_H2_MISSING=$(kstr conformance.h2_missing); C_H2_FILL=$(kstr conformance.h2_fill)
    C_FILL_INTRO=$(kstr conformance.fill_intro); C_H2_XWALK=$(kstr conformance.h2_crosswalk)
    C_YES=$(kstr common.yes); C_NO=$(kstr common.no)
    C_REF=$(kstr conformance.reference); C_REF="${C_REF%% *}"   # "참고:" prefix
    C_TH_FRAMEWORK=$(kstr aiprofile.th_framework)
    C_HTML_TITLE=$(tfmt conformance.html_title "$PROJECT")
    C_KIND=$(kstr conformance.kind); C_H1=$(kstr conformance.h1)
    C_META="$(kstr conformance.meta_project): ${PROJECT_HTML} &middot; $(kstr conformance.meta_generated): ${GEN_AT} &middot; $(kstr conformance.meta_format): ${FORMAT}"
    C_PILL_RESULT="$(kstr conformance.pill_result) ${RESULT_UP}"
    C_PILL_FAIL=$(kstr conformance.pill_failures); C_PILL_WARN=$(kstr conformance.pill_warnings)
    C_PILL_REVIEW=$(kstr conformance.pill_review); C_PILL_UNTRACE=$(kstr conformance.pill_untraceable)
else
    C_MD_TITLE="SBOM Conformance — ${PROJECT}"
    C_MD_GEN="- Generated: ${GEN_AT}"
    C_MD_FMT="- Format: ${FORMAT}"
    C_MD_RESULT="- Result: **${RESULT_UP}** (mandatory failures: ${N_FAIL}, warnings: ${N_WARN}, needs review: ${N_REVIEW})"
    C_MD_UNTRACE="- Untraceable components (pkg:generic / custom PURL): ${N_UNTRACEABLE} — advisory, does not affect the result"
    C_TH_STATUS="Status"; C_TH_REQMT="Requirement"; C_TH_REQD="Required"; C_TH_DETAIL="Detail"
    C_TH_EVID="Evidence / how"; C_FIX_SUMMARY="How to fill this"; C_CHECK_SUMMARY="What to establish"
    C_H2_SUBMIT="SBOM format requirements"
    C_H2_CLUSTERS="G7 minimum elements by cluster"
    C_TH_CLUSTER="Cluster"; C_TH_PRESENT="Present"; C_TH_GAP="Gap"; C_TH_REVIEWCNT="Review"; C_TH_TOTAL="Total"
    C_H2_LIC="Licenses flagged for review"
    C_TH_COMP="Component"; C_TH_VER="Version"; C_TH_LIC="License"; C_TH_FLAG="Flag"
    C_LIC_NONE="No components carry an AI behavioral-use or non-commercial license flag."
    C_SUBMIT_INTRO="What the SBOM itself has to carry. The same bar applies however the SBOM was produced, and a single mandatory failure makes the overall result a failure."
    C_H2_G7CHK="G7 minimum elements"
    C_G7CHK_INTRO="Advisory elements from the G7 \"Software Bill of Materials for AI — Minimum Elements\". Being advisory they never move the result, and elements with no automated source are marked for review."
    C_H2_MISSING="Missing / non-conformant items"; C_H2_FILL="How to fill the gaps"
    C_FILL_INTRO="Each element below is advisory and does not affect the result. The fragment shows the shape that would satisfy it."
    C_H2_XWALK="Regulatory crosswalk"
    C_YES="yes"; C_NO="no"
    C_REF="Reference:"
    C_TH_FRAMEWORK="Framework"
    C_HTML_TITLE="SBOM Conformance — ${PROJECT}"
    C_KIND="Conformance"; C_H1="SBOM Conformance Report"
    C_META="Project: ${PROJECT_HTML} &middot; Generated: ${GEN_AT} &middot; Format: ${FORMAT}"
    C_PILL_RESULT="Result: ${RESULT_UP}"
    C_PILL_FAIL="Mandatory failures:"; C_PILL_WARN="Warnings:"; C_PILL_REVIEW="Needs review:"
    C_PILL_UNTRACE="Untraceable (pkg:generic):"
fi

# --------------------------------------------------------
# Markdown report
# --------------------------------------------------------
{
    echo "# ${C_MD_TITLE}"
    echo ""
    echo "${C_MD_GEN}"
    echo "${C_MD_FMT}"
    echo "${C_MD_RESULT}"
    [ "${N_UNTRACEABLE:-0}" -gt 0 ] && echo "${C_MD_UNTRACE}"
    echo ""
    # Same split as the HTML: verdict-bearing submission requirements first, the
    # advisory G7 elements after, each under its own heading and reason.
    md_rows() {   # $1: "submission" | "g7"
        echo "$RCHECKS" | jq -r --arg yes "$C_YES" --arg no "$C_NO" --arg kind "$1" \
            --arg lang "$REPORT_LANG" '
            [ .[] | select(if $kind=="g7" then (.id|startswith("g7-")) else ((.id|startswith("g7-"))|not) end) ][] |
            # Same idea as the HTML: the regulatory references sit with the
            # requirement instead of being reprinted as their own table.
            (((.regulations // []) | map((if $lang=="ko" then .short_ko else .short end) + " " + .ref)) as $refs
             | if ($refs|length) > 0 then " — " + ($refs|join(" · ")) else "" end) as $reftext |
            "| \(if .status=="pass" then "✅" elif .status=="fail" then "❌" elif (.source // "")=="na" then "🔍" else "⚠️" end) | \((.label + $reftext) | gsub("[|\n]"; " ")) | "
            + (if $kind=="g7" then "" else "\(if .required then $yes else $no end) | " end)
            + "\(.detail | gsub("[|\n]"; " ")) | \(((.evidence // []) | join(", ")) | gsub("[|\n]"; " ")) |"'
    }
    # Crosswalk roll-up leads the Markdown too, for the same reason it leads the
    # HTML: the reader gets the per-framework picture before the row-by-row detail.
    if [ "$(echo "$RXW" | jq -r '.frameworks | length')" -gt 0 ]; then
        echo "## ${C_H2_XWALK}"
        echo ""
        echo "| ${C_TH_FRAMEWORK} | ${C_TH_PRESENT} | ${C_TH_GAP} | ${C_TH_REVIEWCNT} | ${C_TH_TOTAL} |"
        echo "|-----------|:-------:|:---:|:------:|:-----:|"
        echo "$RXW" | jq -r '.frameworks[] |
            "| \(.title | gsub("[|\n]";" ")) | \(.present) | \(.gap) | \(.review) | \(.total) |"'
        echo ""
        echo "$RXW" | jq -r '.frameworks[] | "- \(.title | gsub("[|\n]";" ")) — \(.source | gsub("[|\n]";" "))"'
        echo ""
        echo "$RXW" | jq -r '.disclaimer'
        echo ""
    fi
    echo "## ${C_H2_SUBMIT}"
    echo ""
    echo "${C_SUBMIT_INTRO}"
    echo ""
    echo "| ${C_TH_STATUS} | ${C_TH_REQMT} | ${C_TH_REQD} | ${C_TH_DETAIL} | ${C_TH_EVID} |"
    echo "|--------|-------------|:--------:|--------|----------|"
    md_rows submission
    echo ""
    if echo "$RCHECKS" | jq -e 'any(.[]; .id|startswith("g7-"))' >/dev/null; then
        echo "## ${C_H2_G7CHK}"
        echo ""
        echo "${C_G7CHK_INTRO}"
        echo ""
        echo "| ${C_TH_STATUS} | ${C_TH_REQMT} | ${C_TH_DETAIL} | ${C_TH_EVID} |"
        echo "|--------|-------------|--------|----------|"
        md_rows g7
        echo ""
    fi
    # Missing-item detail for every non-passing check that names offenders —
    # mandatory failures AND advisory G7 warns (a reviewer needs to know WHICH
    # model components lack the license/hash, not just the count).
    if echo "$RCHECKS" | jq -e 'any(.[]; .status!="pass" and (.missing|length>0))' >/dev/null; then
        echo "## ${C_H2_MISSING}"
        echo ""
        echo "$RCHECKS" | jq -r '.[] | select(.status!="pass" and (.missing|length>0)) |
            "### \(.label)\n" + (.missing | map("- " + (. | tostring)) | join("\n")) + "\n"'
    fi
    # How to fill the gaps (AI SBOMs only): the CycloneDX fragment that would
    # satisfy each advisory element still missing. Scoped to real gaps — passing
    # elements need nothing, and the "na" ones have no fragment to show — so a
    # well-documented model adds no section at all.
    if echo "$RCHECKS" | jq -e 'any(.[]; (.guidance // null) != null and .status=="warn" and ((.source // "") != "na"))' >/dev/null; then
        echo "## ${C_H2_FILL}"
        echo ""
        echo "${C_FILL_INTRO}"
        echo ""
        echo "$RCHECKS" | jq -r --arg ref "$C_REF" '.[] | select((.guidance // null) != null and .status=="warn" and ((.source // "") != "na")) |
            "### \(.label)",
            "",
            "```json",
            .guidance.snippet,
            "```",
            "",
            "\($ref) \(.guidance.docUrl)",
            ""'
    fi
} > "$MD"

# --------------------------------------------------------
# HTML report (cards/table/CSP/escape pattern borrowed from scan-security.sh)
# --------------------------------------------------------
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="${HTML_LANG}"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>${C_HTML_TITLE}</title>
<style>
 :root{
  --bg:#fafafa;--surface:#ffffff;--text:#18181b;--muted:#6c6c75;--border:#e5e5ea;
  --brand:#EA002C;--brand-2:#F47725;--th-bg:#f4f4f5;--row-hover:#fafafa;--review:#2563eb;
  --radius:.375rem;--radius-card:.5rem;
  --shadow:0 1px 2px rgb(0 0 0/.04),0 2px 8px -2px rgb(0 0 0/.08);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
 }
 @media (prefers-color-scheme:dark){:root{
  --bg:#0a0a0c;--surface:#18181b;--text:#fafafa;--muted:#a1a1aa;--border:#27272a;
  --th-bg:#1f1f23;--row-hover:#202024;--review:#60a5fa;
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
 .s-review{color:var(--review);font-weight:700;}
 td.num{color:var(--muted);font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap;}
 th.num{text-align:right;}
 td.req{white-space:nowrap;}
 details.fix{margin:.4rem 0 0;}
 details.fix summary{cursor:pointer;color:var(--brand);font-size:.8rem;font-weight:600;}
 details.fix pre{margin:.4rem 0 .2rem;}
 details.fix .meta{font-size:.8rem;}
 .mono{list-style:none;padding-left:0;}
 .mono li{font-family:var(--mono);font-size:.82rem;margin:.3rem 0;}
 pre{background:var(--th-bg);border:1px solid var(--border);border-radius:var(--radius);
     padding:.6rem .75rem;overflow-x:auto;margin:.5rem 0;}
 pre code{font-family:var(--mono);font-size:.8rem;white-space:pre;}
 ol,ul{margin:.5rem 0 0;padding-left:1.3rem;}
 li{margin:.3rem 0;}
</style></head><body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">${C_KIND}</div>
</header>
<h1>${C_H1}</h1>
<p class="meta">${C_META}</p>
<div class="cards">
 <span class="pill pill-$( [ "$RESULT" = "pass" ] && echo pass || echo fail )">${C_PILL_RESULT}</span>
 <span class="pill pill-fail">${C_PILL_FAIL} <span class="count">${N_FAIL}</span></span>
 <span class="pill pill-warn">${C_PILL_WARN} <span class="count">${N_WARN}</span></span>
 <span class="pill">${C_PILL_REVIEW} <span class="count">${N_REVIEW}</span></span>
$( [ "${N_UNTRACEABLE:-0}" -gt 0 ] && echo " <span class=\"pill\">${C_PILL_UNTRACE} <span class=\"count\">${N_UNTRACEABLE}</span></span>" )
</div>
HTMLHEAD
    # Two tables, not one. The submission requirements decide the verdict; the G7
    # elements are advisory and never do. Mixed into a single 60-row table the
    # reader cannot tell which is which, or why a given row is there. The G7 table
    # also drops the "required" column — every value in it would read "no".
    #
    # Evidence column doubles as the fix column: an advisory element that is
    # missing carries its fill-in fragment inline (collapsed), so the reader never
    # has to match a row against a separate section further down the page.
    html_rows() {   # $1: "submission" | "g7"
        echo "$RCHECKS" | jq -r --arg yes "$C_YES" --arg no "$C_NO" \
            --arg fix "$C_FIX_SUMMARY" --arg chk "$C_CHECK_SUMMARY" --arg ref "$C_REF" --arg kind "$1" \
            --arg lang "$REPORT_LANG" '
            [ .[] | select(if $kind=="g7" then (.id|startswith("g7-")) else ((.id|startswith("g7-"))|not) end) ]
            | to_entries[] | .key as $i | .value |
            (if (.source // "")=="na" then "s-review" else "s-\(.status)" end) as $cls |
            "<tr><td class=\"num\">" + (($i+1)|tostring) + "</td>" +
            "<td class=\"" + $cls + "\">" + (if (.source // "")=="na" then "REVIEW" else (.status|ascii_upcase) end|@html) + "</td>" +
            # The regulatory references ride under the requirement they belong to.
            # They used to be their own table further down, which reprinted every
            # mapped row verbatim; here they cost one line and stay next to the
            # status the reader is already looking at.
            "<td>" + (.label|@html) +
            (((.regulations // []) | map((if $lang=="ko" then .short_ko else .short end) + " " + .ref)) as $refs
             | if ($refs|length) > 0
               then "<br><span class=\"meta\">" + (($refs|join(" · "))|@html) + "</span>"
               else "" end) + "</td>" +
            (if $kind=="g7" then "" else "<td class=\"req\">" + (if .required then $yes else $no end) + "</td>" end) +
            "<td>" + ((.detail // "")|@html) + "</td>" +
            "<td>" + (((.evidence // []) | join(", "))|@html) +
            (if ((.guidance // null) != null and .status=="warn" and ((.source // "") != "na"))
             then "<details class=\"fix\"><summary>" + ($fix|@html) + "</summary>"
                  + "<pre><code>" + (.guidance.snippet|@html) + "</code></pre>"
                  + (if ((.guidance.docUrl // "")|startswith("http"))
                     then "<p class=\"meta\">" + ($ref|@html) + " <a href=\"" + (.guidance.docUrl|@html)
                          + "\" target=\"_blank\" rel=\"noopener noreferrer\">"
                          + ((.guidance.docUrl | capture("^https?://(?<h>[^/]+)").h)|@html) + "</a></p>"
                     else "" end)
                  + "</details>"
             elif ((.reviewGuide // null) != null and (.source // "")=="na")
             then "<details class=\"fix\"><summary>" + ($chk|@html) + "</summary>"
                  + "<p>" + (.reviewGuide.how|@html) + "</p>"
                  + (if ((.reviewGuide.docUrl // "")|startswith("http"))
                     then "<p class=\"meta\">" + ($ref|@html) + " <a href=\"" + (.reviewGuide.docUrl|@html)
                          + "\" target=\"_blank\" rel=\"noopener noreferrer\">"
                          + ((.reviewGuide.docUrl | capture("^https?://(?<h>[^/]+)").h)|@html) + "</a></p>"
                     else "" end)
                  + "</details>"
             else "" end) +
            "</td></tr>"'
    }
    # AI SBOMs lead with the rollup: coverage per cluster and the licenses that
    # need a human decision. Everything below is the per-check detail behind it.
    if [ "$G7_CLUSTERS" != "[]" ]; then
        echo "<h2>${C_H2_CLUSTERS}</h2>"
        echo "<div class=\"table-wrap\"><table><tr><th>${C_TH_CLUSTER}</th><th>${C_TH_PRESENT}</th><th>${C_TH_GAP}</th><th>${C_TH_REVIEWCNT}</th><th>${C_TH_TOTAL}</th></tr>"
        echo "$G7_CLUSTERS" | jq -r --arg lang "$REPORT_LANG" '.[] |
            "<tr><td>" + ((if $lang=="ko" then .name_ko else .name end)|@html) + "</td>"
            + "<td>" + (.present|tostring) + "</td><td>" + (.gap|tostring) + "</td>"
            + "<td>" + (.review|tostring) + "</td><td>" + (.total|tostring) + "</td></tr>"'
        echo "$G7_CLUSTERS" | jq -r --arg total "$C_TH_TOTAL" '
            "<tr><td><b>" + ($total|@html) + "</b></td><td><b>" + (map(.present)|add|tostring)
            + "</b></td><td><b>" + (map(.gap)|add|tostring) + "</b></td><td><b>"
            + (map(.review)|add|tostring) + "</b></td><td><b>" + (map(.total)|add|tostring) + "</b></td></tr>"'
        echo "</table></div>"
        echo "<h2>${C_H2_LIC}</h2>"
        if [ "$(echo "$LIC_REVIEW" | jq 'length')" -gt 0 ]; then
            echo "<div class=\"table-wrap\"><table><tr><th>${C_TH_COMP}</th><th>${C_TH_VER}</th><th>${C_TH_LIC}</th><th>${C_TH_FLAG}</th></tr>"
            echo "$LIC_REVIEW" | jq -r '.[] |
                "<tr><td>" + (.name|@html) + "</td><td>" + (.version|@html) + "</td>"
                + "<td>" + (.license|@html) + "</td><td>" + (.flag|@html) + "</td></tr>"'
            echo "</table></div>"
        else
            echo "<p class=\"meta\">${C_LIC_NONE}</p>"
        fi
    fi
    # Regulatory crosswalk: one row per framework, and it leads rather than
    # trails. Each mapped requirement carries its own reference down in the check
    # tables, so this answers only "how much of each framework does this SBOM
    # document" — the question a reader wants answered before reading 50 rows,
    # not after. It replaces a section that reprinted every mapped row with the
    # same labels, statuses and details as the table one screen up.
    if [ "$(echo "$RXW" | jq -r '.frameworks | length')" -gt 0 ]; then
        echo "<h2>${C_H2_XWALK}</h2>"
        echo "<div class=\"table-wrap\"><table><tr><th>${C_TH_FRAMEWORK}</th><th>${C_TH_PRESENT}</th><th>${C_TH_GAP}</th><th>${C_TH_REVIEWCNT}</th><th>${C_TH_TOTAL}</th></tr>"
        echo "$RXW" | jq -r '.frameworks[] |
            "<tr><td>" + (.title|@html)
            + "<br><span class=\"meta\">" + (.source|@html) + "</span></td>"
            + "<td>" + (.present|tostring) + "</td><td>" + (.gap|tostring) + "</td>"
            + "<td>" + (.review|tostring) + "</td><td>" + (.total|tostring) + "</td></tr>"'
        echo "</table></div>"
        echo "<p class=\"meta\">$(echo "$RXW" | jq -r '.disclaimer' | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</p>"
    fi
    echo "<h2>${C_H2_SUBMIT}</h2>"
    echo "<p class=\"meta\">${C_SUBMIT_INTRO}</p>"
    echo "<div class=\"table-wrap\"><table><tr><th class=\"num\">#</th><th>${C_TH_STATUS}</th><th>${C_TH_REQMT}</th><th>${C_TH_REQD}</th><th>${C_TH_DETAIL}</th><th>${C_TH_EVID}</th></tr>"
    html_rows submission
    echo "</table></div>"
    if echo "$RCHECKS" | jq -e 'any(.[]; .id|startswith("g7-"))' >/dev/null; then
        echo "<h2>${C_H2_G7CHK}</h2>"
        echo "<p class=\"meta\">${C_G7CHK_INTRO}</p>"
        echo "<div class=\"table-wrap\"><table><tr><th class=\"num\">#</th><th>${C_TH_STATUS}</th><th>${C_TH_REQMT}</th><th>${C_TH_DETAIL}</th><th>${C_TH_EVID}</th></tr>"
        html_rows g7
        echo "</table></div>"
    fi
    if echo "$RCHECKS" | jq -e 'any(.[]; .status!="pass" and (.missing|length>0))' >/dev/null; then
        echo "<h2>${C_H2_MISSING}</h2>"
        echo "$RCHECKS" | jq -r '.[] | select(.status!="pass" and (.missing|length>0)) |
            "<h3>" + (.label|@html) + "</h3><ul class=\"mono\">" + (.missing | map("<li>" + (.|tostring|@html) + "</li>") | join("")) + "</ul>"'
    fi
    # The fill-in fragments used to live here as their own section; they now ride
    # in the evidence column of the row they belong to (see above). The Markdown
    # report keeps the section — a table cell cannot hold a code block there.
    echo "</body></html>"
} > "$HTML"

echo "[validate] $FORMAT -> result=$RESULT (mandatory fails=$N_FAIL, warns=$N_WARN, review=$N_REVIEW, untraceable=$N_UNTRACEABLE): $JSON, $MD, $HTML"
exit 0
