#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# validate-sbom.sh — check a supplier-submitted SBOM against SKT submission
# requirements (the "format validation" step of the SKT review process).
#
# Usage: validate-sbom.sh <sbom_file> <out_prefix> <project_name>
#   produces <out_prefix>_conformance.json   (machine-readable result)
#            <out_prefix>_conformance.md      (human summary)
#            <out_prefix>_conformance.html    (visual summary)
#            <out_prefix>_summary.result      (key<TAB>value facts for the CLI closing summary)
#            <out_prefix>_conformance.result  (bare "pass"/"fail", for --fail-on-conformance
#                                              to read without a host jq dependency)
#
# Validation runs against the ORIGINAL submission (before any CycloneDX
# conversion), so SPDX-specific metadata is judged accurately. It NEVER aborts
# the pipeline: a non-conformant SBOM yields result="fail" but exit 0.
#
# Requirements:
#   mandatory : spec version (CycloneDX 1.3-1.7 / SPDX 2.2-2.3), timestamp,
#               tool info, top component, name+version coverage, PURL coverage
#               (>= threshold), PURL syntax, PURL namespace where the type
#               requires one, no pkg:generic, transitive edges
#   recommended (warn only): license coverage, hash coverage
#   AI SBOMs (machine-learning-model present): the full G7 minimum-element
#               checklist is appended (7 clusters / 50 elements, data-driven from
#               docker/lib/g7-registry.json), all recommended, each tagged with a
#               data source.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Shared look of the HTML reports (design tokens, print rules, time format).
if [ ! -f "$SCRIPT_DIR/report-common.sh" ]; then
    echo "[validate] report-common.sh not found next to $0; the image is incomplete. Fix: rebuild the scanner image." >&2
    exit 1
fi
# shellcheck source=report-common.sh
. "$SCRIPT_DIR/report-common.sh"
# shellcheck source=docker/lib/cdx-version.sh
. "$SCRIPT_DIR/cdx-version.sh"

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

# cosign (--sign) writes a DETACHED signature next to the SBOM ("$SBOM.sig"),
# not an embedded CycloneDX .signature field (see entrypoint.sh's cosign
# invocation). The cisa-sbom-author-signature element only ever looked at
# .signature, so a signed submission never satisfied it. Checked once here so
# the ANALYZE path (a supplier's own submission, .sig already sitting next to
# it) and the generation path (this scan's own re-run after signing, see
# entrypoint.sh) share the same signal.
if [ -f "${SBOM}.sig" ]; then HAS_SIG_FILE=true; else HAS_SIG_FILE=false; fi
# Set by entrypoint.sh only on the post-signing re-run, to phrase the gap
# accurately when a requested signature failed rather than reporting it the
# same as "signing was never asked for".
SIGN_REQUESTED="${SIGN_SBOM:-false}"
SIGN_ATTEMPT_FAILED="${SIGN_FAILED:-0}"

# Submission profile. "skt-submission" tightens PURL coverage to 100% and makes
# both pkg:generic and a purl type that purl-spec does not define required
# (failing) checks instead of advisory ones; "default" keeps the existing
# thresholds. Unknown values fall back to "default".
#
# "bsi-tr-03183-2" measures the SBOM against BSI TR-03183-2 v2.1.0: CycloneDX
# 1.6 or later (SPDX 3.0 or later), and the bsi-* rows below (bsi_checks). PURL
# coverage is advisory there, because the guideline lists other identifiers
# among the additional fields (5.2.4), to be given where they exist.
CONFORMANCE_PROFILE="${CONFORMANCE_PROFILE:-default}"
PURL_REQUIRED=true
# BSI TR-03183-2 section 4: CycloneDX 1.6 or later, SPDX 3.0.1 or later.
BSI_CYCLONEDX_SPEC_VERSIONS="1.6 1.7"
BSI_SPDX_SPEC_VERSIONS="SPDX-3.0"
case "$CONFORMANCE_PROFILE" in
    skt-submission) _PURL_DEFAULT=100; GENERIC_REQUIRED=true;  PURL_TYPE_REQUIRED=true ;;
    bsi-tr-03183-2) _PURL_DEFAULT=90;  GENERIC_REQUIRED=false; PURL_TYPE_REQUIRED=false; PURL_REQUIRED=false
                    CYCLONEDX_SPEC_VERSIONS="${CYCLONEDX_SPEC_VERSIONS:-$BSI_CYCLONEDX_SPEC_VERSIONS}"
                    SPDX_SPEC_VERSIONS="${SPDX_SPEC_VERSIONS:-$BSI_SPDX_SPEC_VERSIONS}" ;;
    default|"")     _PURL_DEFAULT=90;  GENERIC_REQUIRED=false; PURL_TYPE_REQUIRED=false ;;
    *)              echo "[validate] WARN: unknown CONFORMANCE_PROFILE '$CONFORMANCE_PROFILE'; using default." >&2
                     _PURL_DEFAULT=90; GENERIC_REQUIRED=false; PURL_TYPE_REQUIRED=false ;;
esac

# Coverage thresholds (percent). Override via env to tune strictness.
PURL_MIN_PCT="${PURL_MIN_PCT:-$_PURL_DEFAULT}" # mandatory
LICENSE_MIN_PCT="${LICENSE_MIN_PCT:-80}" # recommended (warn)
HASH_MIN_PCT="${HASH_MIN_PCT:-50}"       # recommended (warn)
FIELD_MIN_PCT="${FIELD_MIN_PCT:-80}"     # advisory: regulatory per-component fields
MISSING_CAP=50                            # cap missing-item lists in the report

# Accepted spec versions (space-separated), per the SKT submission
# requirements. Override via env.
#
# CycloneDX 1.7 is accepted for every kind of SBOM. It was released in October
# 2025 and generators have been emitting it since, so a submission at 1.7 is a
# current document, not an unsupported one. What this pipeline WRITES is 1.6
# unless CYCLONEDX_SPEC_VERSION=1.7 (docker/lib/cdx-version.sh): reading a
# version and emitting it are separate decisions. The AI list stays a
# variable of its own so that narrowing CYCLONEDX_SPEC_VERSIONS by env never
# rejects the AIBOM toolchain's own output, which is always 1.7.
CYCLONEDX_SPEC_VERSIONS="${CYCLONEDX_SPEC_VERSIONS:-1.3 1.4 1.5 1.6 1.7}"
AI_CYCLONEDX_SPEC_VERSIONS="${AI_CYCLONEDX_SPEC_VERSIONS:-$CYCLONEDX_SPEC_VERSIONS 1.7}"
SPDX_SPEC_VERSIONS="${SPDX_SPEC_VERSIONS:-SPDX-2.2 SPDX-2.3 SPDX-3.0}"

# Practical PURL shape gate (purl-spec): pkg:type/[namespace/]name[@version]
# [?qualifiers][#subpath]. The segment charset tolerates the unencoded '@'
# some tools emit for npm scopes; spaces, colon coordinates and a missing 'pkg:'
# prefix are offenders.
#
# The version is optional here because it is optional in the spec. Requiring it
# made this check report a syntax error for an identifier that has none —
# measured on a switch OS, 3,581 of them, nearly all `pkg:generic/<kernel
# module>` — and a missing version is not a malformed identifier. That a version
# is missing is worth reporting, and two other checks already do: `name-version`
# fails on it as a required row, and `no-generic` warns that the identifier
# cannot be traced. Counting the same gap a third time, under the name of a
# different defect, told a reader to go looking for broken syntax that was not
# there.
PURL_SYNTAX_REGEX='^pkg:[a-z][a-z0-9.+-]*(/[A-Za-z0-9._%~@+-]+)+(@[A-Za-z0-9._%~+:-]+)?(\?[A-Za-z0-9._%~+=&:,/-]+)?(#[A-Za-z0-9._%~+/-]+)?$'

# Some purl types carry a required namespace in the slot between the type and
# the name: the distribution for an OS package (pkg:rpm/rhel/bind@...), the
# groupId for a Maven artifact (pkg:maven/org.slf4j/slf4j-api@...), the owner
# for a repository. Vulnerability matching and repository lookup both key on
# it, so an identifier missing it is syntactically well formed and resolves to
# nothing: a server SBOM measured this way reported 261 packages and matched
# zero. A generator that rebuilds identifiers from a component's display name
# instead of reading the package manager loses the namespace the same way, for
# a whole Java dependency tree at once. PURL_SYNTAX_REGEX cannot catch either,
# because the namespace is optional there, which is correct for npm and pypi.
#
# Which types require one is data, not code: docker/lib/purl-types.json mirrors
# the namespace_definition.requirement of each type definition in purl-spec.
# Two of the required types are measured but never failed, because an
# identifier of theirs can legitimately carry no namespace:
#
#   golang       a module path can be a bare host ("connect.example.com"), and
#                syft writes the Go standard library as pkg:golang/stdlib
#   huggingface  a model published outside an organisation has no owner
#                segment ("bert-base-uncased")
#
# Both are reported on an advisory row instead, so the gap stays visible
# without rejecting an identifier that is correct as written.
NS_ADVISORY_TYPES="${NS_ADVISORY_TYPES:-golang huggingface}"
PURL_TYPES_FILE="${PURL_TYPES_FILE:-$(dirname "$0")/purl-types.json}"

# An alternation that matches nothing, for when a list comes out empty: '()'
# inside the regex below would match every purl of any type.
_NO_TYPE='\x00never\x00'
_ns_required="rpm|deb|apk"   # fallback if the type data is unreadable
_ns_advisory="$_NO_TYPE"
PURL_KNOWN_TYPES='[]'
if [ -f "$PURL_TYPES_FILE" ]; then
    _req=$(jq -r --arg adv "$NS_ADVISORY_TYPES" '
        ($adv | split(" ")) as $a
        | [ .types | to_entries[] | select(.value.namespace == "required") | .key
            | . as $k | select(($a | index($k)) == null) ] | join("|")' "$PURL_TYPES_FILE" 2>/dev/null) || _req=""
    _adv=$(jq -r --arg adv "$NS_ADVISORY_TYPES" '
        ($adv | split(" ")) as $a
        | [ .types | to_entries[] | select(.value.namespace == "required") | .key
            | . as $k | select(($a | index($k)) != null) ] | join("|")' "$PURL_TYPES_FILE" 2>/dev/null) || _adv=""
    _known=$(jq -c '[ .types | keys[] ]' "$PURL_TYPES_FILE" 2>/dev/null) || _known=""
    [ -n "$_req" ] && _ns_required="$_req"
    [ -n "$_adv" ] && _ns_advisory="$_adv"
    [ -n "$_known" ] && PURL_KNOWN_TYPES="$_known"
else
    echo "[validate] WARN: $PURL_TYPES_FILE not found; PURL namespace checks cover OS packages only and the purl type check is skipped." >&2
fi
# The submission profile also accepts two purl types for projects published
# outside GitHub, which purl-spec has not defined yet: pkg:sourceforge and
# pkg:gnu, each naming the project at its release on that site. upstream-purl.py writes them for the
# projects that are found there (boa, readline). Space-separated; empty turns
# the exception off.
if [ "$CONFORMANCE_PROFILE" = "skt-submission" ] && [ "$PURL_KNOWN_TYPES" != "[]" ]; then
    _extra=$(printf '%s' "${SUBMISSION_PURL_TYPES-gnu sourceforge}" | jq -Rc 'split(" ") | map(select(length > 0) | ascii_downcase)')
    PURL_KNOWN_TYPES=$(jq -nc --argjson a "$PURL_KNOWN_TYPES" --argjson b "${_extra:-[]}" '$a + $b | unique')
fi
# The second pattern of each pair asks whether a segment ending in '/' follows
# the type; '@?#' are excluded from the segment so a version, qualifier or
# subpath is never mistaken for a namespace.
NS_PURL_TYPE_REGEX="^pkg:($_ns_required)/"
NS_PURL_NS_REGEX="^pkg:($_ns_required)/[^/@?#]+/"
NS_ADV_PURL_TYPE_REGEX="^pkg:($_ns_advisory)/"
NS_ADV_PURL_NS_REGEX="^pkg:($_ns_advisory)/[^/@?#]+/"
NS_ADVISORY_LABEL=$(printf '%s' "$_ns_advisory" | tr '|' '/')
[ "$NS_ADVISORY_LABEL" = "$_NO_TYPE" ] && NS_ADVISORY_LABEL="these types"

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

# The first-party exemption from the PURL rows. A first-party component (one
# the declaration file added: bomlens:origin = first-party) that names its
# supplier and carries a SHA-512 is identified by those two. It is not
# published to a package repository, so there is no purl for it to carry, and
# it is left out of the PURL coverage, pkg:generic and upstream-purl rows. A
# third-party declared component is not: it came from somewhere, and that
# place may well have an identifier.
#
# Those properties are only words in a JSON file, so the exemption is granted
# only where this pipeline wrote them: the component carries the mark
# apply-declared-components.py sets (bomlens:declared = true, exactly once, with
# exactly one bomlens:origin), that step ran in this very scan (entrypoint.sh exports DECLARED_COMPONENTS_APPLIED=1 after it
# succeeds; it replaces any marked component the input carried), and the SBOM
# is not a received one (MODE ANALYZE). The SHA-512 must be a SHA-512: 128 hex
# digits. The components exempted are listed on their own advisory row.
if [ "${DECLARED_COMPONENTS_APPLIED:-}" = "1" ] && [ "${MODE:-}" != "ANALYZE" ]; then
    FP_EXEMPT_ON=true
else
    FP_EXEMPT_ON=false
fi
# shellcheck disable=SC2016  # jq source; $fpOn and $k are jq variables.
FP_EXEMPT_DEF='def fp_sha512: (.hashes // []) | if type == "array" then . else [] end
        | any(type == "object" and .alg == "SHA-512" and ((.content // "") | type == "string" and test("^[0-9a-fA-F]{128}$")));
    def first_party_exempt: $fpOn
        and ([ (.properties // []) | if type == "array" then .[] else empty end
               | select(type == "object" and .name == "bomlens:origin") | .value ] == ["first-party"])
        and ([ (.properties // []) | if type == "array" then .[] else empty end
               | select(type == "object" and .name == "bomlens:declared") | .value ] == ["true"])
        and ((.supplier // {}) | if type == "object" then ((.name // "") != "") or (((.url // []) | length) > 0) else false end)
        and (fp_sha512 or ([ (.components // [])[]? | select(.type? == "file") ] as $k
                           | ($k | length) > 0 and all($k[]; fp_sha512)));'

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
       --argjson genericRequired "$GENERIC_REQUIRED" \
       --argjson typeRequired "$PURL_TYPE_REQUIRED" \
       --argjson purlRequired "$PURL_REQUIRED" \
       --argjson fpOn "$FP_EXEMPT_ON" \
       --argjson knowntypes "$PURL_KNOWN_TYPES" \
       --arg okvers "${1:-$CYCLONEDX_SPEC_VERSIONS}" \
       --arg purlre "$PURL_SYNTAX_REGEX" \
       --arg nsre "$NS_PURL_TYPE_REGEX" \
       --arg nsnsre "$NS_PURL_NS_REGEX" \
       --arg advre "$NS_ADV_PURL_TYPE_REGEX" \
       --arg advnsre "$NS_ADV_PURL_NS_REGEX" \
       --arg advtypes "$NS_ADVISORY_LABEL" "
    $PCT_DEF
    # A component made of several delivered files (a declared component with
    # more than one bomlens:artifact) carries the per-file fields, hashes
    # included, on its nested type \"file\" components, not on itself: it
    # counts as having a field when every one of those files has it.
    def bsi_files_all(f): ([ (.components // [])[] | select(.type == \"file\") ]) as \$k
                          | (\$k | length) > 0 and all(\$k[]; f);
    def has_hash: (.hashes // []) | length > 0;
    def bsi_fname: (.properties // []) | any(.name == \"bsi:component:filename\");
    def bsi_sha512: (.hashes // []) | any(.alg == \"SHA-512\");
    def bsi_fprops: (.properties // []) as \$props
                    | (\$props | any(.name == \"bsi:component:executable\"))
                      and (\$props | any(.name == \"bsi:component:archive\"))
                      and (\$props | any(.name == \"bsi:component:structured\"));
    # The first-party exemption (FP_EXEMPT_DEF above).
    $FP_EXEMPT_DEF
    ([.components[]?]) as \$c
    | (\$c|length) as \$tot
    | (.metadata.tools) as \$t
    | (if (\$t|type)==\"array\" then (\$t|length)
       elif (\$t|type)==\"object\" then (((\$t.components//[])+(\$t.services//[]))|length)
       else 0 end) as \$tools
    | ([ \$c[] | select(.type != \"data\" and .type != \"file\" and .type != \"operating-system\") ]) as \$pkg
    | (\$pkg|length) as \$ptot
    | ([ \$c[] | select(.type == \"file\") ]) as \$file
    | (\$file|length) as \$ftot
    # name+version and purl coverage are package questions, so they are measured
    # over \$pkg (every component except type \"data\", \"file\" and
    # \"operating-system\") rather than every component. A data component (a
    # training dataset, say) has no package version and no purl type to carry:
    # purl defines none for a dataset. A file component is the same case seen
    # from the other side: a binary or firmware scan enumerates the delivered
    # files, and purl defines no type for a file on disk either. An
    # operating-system component is the same case again, one level up: it names
    # the distribution itself (\"debian@12\"), not an installable package, and
    # purl's schemes identify installable packages, never a distribution as a
    # whole. Counting any of the three would fail an otherwise complete SBOM for
    # a field that cannot exist on that component. A firmware SBOM whose
    # packages are all identified still read as 10% PURL coverage because its
    # file inventory sat in the denominator, and every rootfs/image scan carries
    # exactly one operating-system component that would otherwise cap PURL
    # coverage below 100% no matter how complete the rest of it is. Files are
    # not exempt from identification: the file-identifier check below measures
    # the intrinsic identifier they DO carry, a hash. License and checksum
    # coverage still count every component, because those they can carry.
    | ([ \$pkg[] | select((.name==null) or (.version==null)) | (.name // .purl // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$pkg[] | select(first_party_exempt) | (.name // \"(unnamed)\") + (if ((.version // \"\") | tostring) != \"\" then \"@\" + (.version | tostring) else \"\" end) ]) as \$fp_names
    | (\$fp_names | length) as \$fp_exempt
    | (\$ptot - \$fp_exempt) as \$purl_tot
    | ([ \$pkg[] | select(.purl==null) | select(first_party_exempt | not) | (.name // \"(unnamed)\") ]) as \$miss_purl
    # Packages that carry a CPE where they carry no PURL. The submission criteria
    # require a PURL, so this does not change the verdict. It reads as
    # unidentified components when the truth can be identified another way,
    # and the regulatory baselines under this row (BSI 5.2.4, NTIA) accept either.
    # A Yocto image is the case in point: bitbake writes CPEs, never PURLs.
    | ([ \$pkg[] | select((.purl==null) and ((.cpe // \"\") != \"\")) ] | length) as \$cpe_only
    # File components carry no purl, so their identifier is the hash the scanner
    # computed over the file itself. The CISA 2026 minimum elements accept an
    # intrinsic identifier in that role alongside PURL and CPE, so this is what
    # \"identified\" means for a file and the coverage is measured on its own.
    | ([ \$file[] | select((.hashes // []) | length > 0) ] | length) as \$fhash_ok
    | ([ \$file[] | select(((.hashes // []) | length) == 0) | (.name // \"(unnamed)\") ]) as \$miss_fid
    | ([ \$c[] | select((.purl // \"\") | startswith(\"pkg:generic\")) | select(first_party_exempt | not) | (.name // .purl) ]) as \$generic
    | ([ \$c[] | (.purl // empty) | select(test(\$purlre) | not) ]) as \$badpurl
    | ([ \$c[] | (.purl // empty) | select(test(\$nsre)) ]) as \$ns_purl
    | ([ \$ns_purl[] | select(test(\$nsnsre) | not) ]) as \$ns_nons
    | ([ \$c[] | (.purl // empty) | select(test(\$advre)) ]) as \$adv_purl
    | ([ \$adv_purl[] | select(test(\$advnsre) | not) ]) as \$adv_nons
    # The type is everything between 'pkg:' and the first '/', minus a version
    # on a purl that has no namespace at all (pkg:applications/java@11.0.25 is
    # type \"applications\"; pkg:foo@1 is type \"foo\"). purl-spec says the type is
    # case insensitive and canonically lower case, so it is compared that way.
    | ([ \$c[] | (.purl // empty) | select(startswith(\"pkg:\"))
         | . as \$pu
         | (\$pu | ltrimstr(\"pkg:\") | split(\"/\")[0] | split(\"@\")[0] | ascii_downcase) as \$ty
         | select((\$knowntypes | index(\$ty)) == null) | \$pu ]) as \$unk_type
    | (\$okvers | split(\" \")) as \$vers
    | ((.specVersion // \"\") | tostring) as \$sv
    | ((\$c | map(select((.licenses // []) | length > 0)) | length)) as \$lic_ok
    | ((\$c | map(select(has_hash or bsi_files_all(has_hash))) | length)) as \$hash_ok
    | ([ .dependencies[]? | .dependsOn[]? ] | length) as \$dep_edges
    # The graph-completeness self-declaration BomLens writes to
    # compositions[0].aggregate (complete/incomplete/unknown), when present.
    # Advisory only, folded into the transitive-dependencies detail text below
    # -- never changes this check's status/required, so it cannot move RESULT.
    | ((.compositions[0].aggregate // \"\")) as \$agg
    | (.metadata.timestamp // \"\") as \$ts
    | (.metadata.component // {}) as \$top
    | (\$purl_tot - (\$miss_purl|length)) as \$purl_ok
    | (if \$fp_exempt > 0 then \"; \(\$fp_exempt) first-party component(s) identified by supplier and SHA-512 instead\" else \"\" end) as \$fp_note
    # Per-component fields named by the regulatory crosswalk (BSI TR-03183-2 /
    # NTIA). All advisory: they describe how well the SBOM would answer a
    # regulator, and never move the submission verdict. Measured over \$pkg for
    # the same reason name+version is — a data component carries no filename,
    # creator or artifact URI — except the SHA-512 tally, which counts every
    # component because a dataset can carry a checksum.
    | ([ \$pkg[] | select(((.authors // []) | length > 0) or ((.publisher // \"\") != \"\")
                          or (((.supplier // {}) | length) > 0) or (((.manufacturer // {}) | length) > 0)) ] | length) as \$creator_ok
    | ([ \$pkg[] | select(bsi_fname or bsi_files_all(bsi_fname)) ] | length) as \$fname_ok
    | ([ \$c[] | select(bsi_sha512 or bsi_files_all(bsi_sha512)) ] | length) as \$sha512_ok
    | ([ \$pkg[] | select((.externalReferences // []) | any(.type == \"vcs\" or .type == \"distribution\")) ] | length) as \$uri_ok
    | ([ \$pkg[] | select(bsi_fprops or bsi_files_all(bsi_fprops)) ] | length) as \$fprops_ok
    | [
       {id:\"spec-version\", label:(\"Spec version (CycloneDX \" + (\$vers|unique|join(\"/\")) + \")\"), required:true,
        status:(if (\$vers | index(\$sv)) != null then \"pass\" else \"fail\" end),
        detail:(\"CycloneDX \" + \$sv), missing:[]},
       {id:\"timestamp\", label:\"Timestamp (metadata.timestamp)\", required:true,
        status:(if (\$ts|length)>0 then \"pass\" else \"fail\" end), detail:\$ts, missing:[]},
       {id:\"tools\", label:\"Tool info (metadata.tools)\", required:true,
        status:(if \$tools>0 then \"pass\" else \"fail\" end), detail:\"\(\$tools) tool(s)\", missing:[]},
       # A fixed value some generators write in place of the product name (a dot
       # or the scanned directory) makes unrelated submissions collide.
       # Under the submission profile it fails; elsewhere the row warns.
       {id:\"top-component\", label:\"Top-level component name+version\", required:true,
        status:(if ((\$top.name//\"\")|length)==0 or ((\$top.version//\"\")|length)==0 then \"fail\"
                elif ((\$top.name) as \$n | [\".\",\"..\",\"/\",\"/scan\"] | index(\$n)) != null
                then (if \$typeRequired then \"fail\" else \"warn\" end)
                else \"pass\" end),
        detail:((\$top.name//\"(none)\") + \"@\" + (\$top.version//\"\")
                + (if (\$top.name // \"\") as \$n | [\".\",\"..\",\"/\",\"/scan\"] | index(\$n) then \" (a fixed value, not a product name: change metadata.component.name)\" else \"\" end)), missing:[]},
       # Nothing to measure is not a coverage failure, EXCEPT when the packages
       # went missing because this check stopped counting file components. A
       # binary scan that recovered only a file listing identified no package, and
       # the submission criteria exist to answer questions that need one — the
       # default vulnerability matching keys on PURLs, and a file inventory
       # supports none of it however complete. Reporting that as \"0/0, met\" would
       # pass an SBOM that named nothing.
       #
       # An SBOM with no components at all, or one whose components are all data,
       # keeps the earlier behaviour: both checks agree and neither complains,
       # because there the empty denominator is not something an exclusion here
       # created. A dataset carries no purl and no package version by definition,
       # and an SBOM listing only datasets is a legitimate one to submit.
       {id:\"name-version\", label:\"Component name+version coverage (100%)\", required:true,
        source:(if \$ptot==0 and \$ftot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ptot==0 and \$ftot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then (if \$ftot>0 then \"fail\" else \"warn\" end)
                elif (\$miss_nv|length)==0 then \"pass\" else \"fail\" end),
        detail:(if \$ptot==0 then (if \$ftot>0 then \"no package components (file inventory only)\"
                                   else \"no packages to measure\" end)
                else \"\(\$ptot - (\$miss_nv|length))/\(\$ptot)\" end),
        missing:(\$miss_nv[0:\$cap])},
       # Every package being an exempt first-party component leaves nothing
       # to measure, and nothing missing either: that passes, saying why.
       {id:\"purl\", label:(if \$purlRequired then \"PURL coverage (>= \(\$purlmin)%)\" else \"PURL coverage (>= \(\$purlmin)%, advisory)\" end), required:\$purlRequired,
        source:(if \$ptot==0 and \$ftot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ptot==0 and \$ftot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then (if \$ftot>0 and \$purlRequired then \"fail\" else \"warn\" end)
                elif \$purl_tot==0 then \"pass\"
                elif pct(\$purl_ok;\$purl_tot) >= \$purlmin then \"pass\"
                elif \$purlRequired then \"fail\" else \"warn\" end),
        detail:(if \$ptot==0 then (if \$ftot>0 then \"no package components (file inventory only)\"
                                   else \"no packages to measure\" end)
                elif \$purl_tot==0 then \"0/0\" + \$fp_note
                else \"\(pct(\$purl_ok;\$purl_tot))% (\(\$purl_ok)/\(\$purl_tot))\"
                     + (if \$cpe_only > 0 then \"; \(\$cpe_only) identified by CPE instead\" else \"\" end) + \$fp_note end),
        missing:(\$miss_purl[0:\$cap])},
       {id:\"file-identifier\", label:\"File component identifier coverage (hash, >= \(\$fieldmin)%, recommended)\", required:false,
        source:(if \$ftot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ftot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ftot==0 then \"warn\" elif pct(\$fhash_ok;\$ftot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ftot==0 then \"no file components\"
                else \"\(pct(\$fhash_ok;\$ftot))% (\(\$fhash_ok)/\(\$ftot))\" end),
        missing:(\$miss_fid[0:\$cap])},
       {id:\"no-generic\", label:(if \$genericRequired then \"Traceable PURL (no pkg:generic)\" else \"Traceable PURL (no pkg:generic, advisory)\" end), required:\$genericRequired,
        status:(if (\$generic|length)==0 then \"pass\" elif \$genericRequired then \"fail\" else \"warn\" end),
        detail:\"\(\$generic|length) untraceable\", missing:(\$generic[0:\$cap])},
       {id:\"purl-syntax\", label:\"PURL syntax (pkg:type/[namespace/]name)\", required:true,
        status:(if (\$badpurl|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$badpurl|length) malformed\", missing:(\$badpurl[0:\$cap])},
       {id:\"purl-namespace\", label:\"PURL namespace where the type requires it (pkg:maven/<groupId>/name)\", required:true,
        source:(if (\$ns_purl|length)==0 then \"na\" else \"auto\" end),
        naKind:(if (\$ns_purl|length)==0 then \"not-applicable\" else \"\" end),
        status:(if (\$ns_nons|length)==0 then \"pass\" else \"fail\" end),
        detail:(if (\$ns_purl|length)==0 then \"no identifiers of a type that requires a namespace\"
                else \"\(\$ns_nons|length) without namespace\" end),
        missing:(\$ns_nons[0:\$cap])},
       {id:\"purl-namespace-advisory\", label:(\"PURL namespace for \" + \$advtypes + \" (advisory)\"), required:false,
        source:(if (\$adv_purl|length)==0 then \"na\" else \"auto\" end),
        naKind:(if (\$adv_purl|length)==0 then \"not-applicable\" else \"\" end),
        status:(if (\$adv_nons|length)==0 then \"pass\" else \"warn\" end),
        detail:(if (\$adv_purl|length)==0 then \"no identifiers of a type that requires a namespace\"
                else \"\(\$adv_nons|length) without namespace\" end),
        missing:(\$adv_nons[0:\$cap])},
       {id:\"purl-type\", label:(if \$typeRequired then \"PURL type defined by purl-spec\" else \"PURL type defined by purl-spec (advisory)\" end), required:\$typeRequired,
        source:(if (\$knowntypes|length)==0 then \"na\" else \"auto\" end),
        status:(if (\$knowntypes|length)==0 then \"warn\"
                elif (\$unk_type|length)==0 then \"pass\"
                elif \$typeRequired then \"fail\" else \"warn\" end),
        detail:(if (\$knowntypes|length)==0 then \"purl type list unavailable\"
                else \"\(\$unk_type|length) undefined type(s)\" end),
        missing:(\$unk_type[0:\$cap])},
       {id:\"transitive\", label:\"Transitive dependencies (graph edges)\", required:true,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$dep_edges>0 then \"pass\" elif \$tot==0 then \"warn\" else \"fail\" end),
        detail:((if \$dep_edges==0 and \$tot==0 then \"nothing to relate\"
                 else \"\(\$dep_edges) edge(s)\" end)
                + (if \$agg==\"\" then \"\"
                   elif \$agg==\"unknown\" and \$dep_edges==0 and \$tot>0 then \", graph completeness unknown\"
                   elif \$agg==\"unknown\" then \", graph completeness unknown (no positive evidence found, not a defect)\"
                   else \", declared \(\$agg)\" end)), missing:[]},
       {id:\"license\", label:\"License coverage (>= \(\$licmin)%, recommended)\", required:false,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot>0 and pct(\$lic_ok;\$tot) >= \$licmin then \"pass\" else \"warn\" end),
        detail:(if \$tot==0 then \"nothing to measure\"
                else \"\(pct(\$lic_ok;\$tot))% (\(\$lic_ok)/\(\$tot))\" end), missing:[]},
       {id:\"hash\", label:\"Hash coverage (>= \(\$hashmin)%, recommended)\", required:false,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot>0 and pct(\$hash_ok;\$tot) >= \$hashmin then \"pass\" else \"warn\" end),
        detail:(if \$tot==0 then \"nothing to measure\"
                else \"\(pct(\$hash_ok;\$tot))% (\(\$hash_ok)/\(\$tot))\" end), missing:[]},
       {id:\"hash-algorithm\", label:\"SHA-512 checksum coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot==0 then \"warn\" elif pct(\$sha512_ok;\$tot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$tot==0 then \"nothing to measure\"
                else \"\(pct(\$sha512_ok;\$tot))% (\(\$sha512_ok)/\(\$tot))\" end), missing:[]},
       {id:\"component-creator\", label:\"Component creator coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        source:(if \$ptot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ptot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then \"warn\" elif pct(\$creator_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$creator_ok;\$ptot))% (\(\$creator_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"component-filename\", label:\"Component filename coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        source:(if \$ptot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ptot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then \"warn\" elif pct(\$fname_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$fname_ok;\$ptot))% (\(\$fname_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"artifact-uri\", label:\"Source or distribution URI coverage (>= \(\$fieldmin)%, recommended)\", required:false,
        source:(if \$ptot==0 then \"na\" else \"auto\" end),
        naKind:(if \$ptot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then \"warn\" elif pct(\$uri_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                else \"\(pct(\$uri_ok;\$ptot))% (\(\$uri_ok)/\(\$ptot))\" end), missing:[]},
       {id:\"file-properties\", label:\"Delivered-file properties (executable/archive/structured)\", required:false,
        source:(if \$ptot==0 then \"na\" elif \$fprops_ok>0 then \"auto\" else \"na\" end),
        naKind:(if \$ptot==0 then \"not-applicable\" else \"\" end),
        status:(if \$ptot==0 then \"warn\" elif pct(\$fprops_ok;\$ptot) >= \$fieldmin then \"pass\" else \"warn\" end),
        detail:(if \$ptot==0 then \"no packages to measure\"
                elif \$fprops_ok==0 then \"requires inspecting the delivered files (no automated source in this scan)\"
                else \"\(pct(\$fprops_ok;\$ptot))% (\(\$fprops_ok)/\(\$ptot))\" end), missing:[]}
      ]
      # Which components the first-party exemption took out of the PURL rows,
      # by name, so a reviewer can check each one. Only when there are any.
      + (if \$fp_exempt == 0 then [] else
         [{id:\"first-party-exempt\", label:\"First-party components identified by supplier and SHA-512 instead of a purl (advisory)\",
           label_ko:\"purl 대신 공급자와 SHA-512로 식별한 자체개발 구성요소 (권고)\", required:false,
           status:\"warn\", detail:\"\(\$fp_exempt) component(s) left out of the PURL rows\",
           detail_ko:\"PURL 항목에서 제외한 구성요소 \(\$fp_exempt)개\", missing:(\$fp_names[0:\$cap])}] end)" "$SBOM"
}

# Registry-driven minimum-element checks. A registry is a declarative file listing
# the elements of one baseline, each mapped to a CycloneDX expression and a
# data-source tag (auto/inferred/declared/na); docker/lib/g7-registry.json holds
# the 7 clusters / 50 elements of the G7 "SBOM for AI — Minimum Elements".
#
# The registry declares three things about itself, so a second baseline can be
# added as data rather than as another copy of this evaluator:
#   subject      — jq expression selecting the components per-element coverage is
#                  measured over. G7 measures over model components; a baseline
#                  about software components measures over those instead.
#   subjectLabel — what one of them is called in the report ("model component").
#   required     — per element. An unsatisfied element fails when the baseline
#                  makes it mandatory and warns when it does not. Every G7 element
#                  is advisory (G7 is non-binding), so nothing there fails.
# All three have defaults that reproduce the G7 behaviour exactly, so a registry
# that declares none of them behaves as this evaluator always did.
#
# Elements with no automated source (cdxPath null, source "na" —
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
#                 Two optional companions: absentSource "na" reports the element
#                 as a human-review item while cdxPath finds nothing (the G7
#                 system data flow, data usage, input/output and application
#                 area, which only a declared or supplied service fills), and
#                 declaredPath, a jq boolean, marks a pass as the publisher's
#                 declaration in the detail.
#   missingPath — per-model coverage: a jq expression (may use $models) returning
#                 the names of model components MISSING the element. Keeps the
#                 old cov() semantics: pass only when EVERY model has it, warn with
#                 the offender list and an "N/M model component(s)" detail otherwise
#                 (an any-model check would hide non-compliant models in a
#                 multi-model supplier SBOM).
# Does this registry have anything to say about this SBOM? The registry answers,
# through an `appliesWhen` jq boolean over the SBOM; a registry that declares none
# applies to everything.
#
# Only a clean false means "does not apply" (jq -e exits 1 on a false or null
# result). A broken expression exits with something else, and that answers as
# APPLIES on purpose: a registry we cannot read is a defect, and the way a defect
# gets reported is registry_checks running and failing loudly. Returning "does not
# apply" there would delete the whole baseline from the report without a word.
# $1: registry file.
registry_applies() {
    local reg="$1"
    [ -f "$reg" ] || return 1
    local when rc
    when=$(jq -r '.appliesWhen // "true"' "$reg" 2>/dev/null) || return 0
    jq -e "$when" "$SBOM" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 1 ] && return 1
    return 0
}

# $1: registry file. $2: display name used in the warnings this prints.
registry_checks() {
    local reg="$1" what="$2"
    if [ ! -f "$reg" ]; then
        echo "[validate] WARN: $what registry not found at $reg; skipping $what checks." >&2
        echo "[]"
        return
    fi
    local prog
    prog=$(jq -r '
        ((.subject // "([.metadata.component // empty] + [.components[]?]) | map(select(.type==\"machine-learning-model\"))")) as $subject
        | ((.subjectLabel // "model component")) as $slabel
        | ((.emptySubjectDetail // "no machine-learning-model components")) as $sempty
        | "(" + $subject + ") as $subjects | ["
        + ([ .clusters[] as $c | $c.elements[] |
            "{id:" + (.id|@json)
            + ",label:" + (.label|@json)
            # Carried on the check itself, not only looked up when this file
            # renders Korean: a consumer of the JSON contract (the web UI) has no
            # registry to look it up in.
            + ",label_ko:" + ((.label_ko // "")|@json)
            + ",required:" + ((.required // false)|tojson)
            + ",cluster:" + ($c.id|@json)
            + ",source:" + (.source|@json)
            + ",role:" + ((.role // "")|@json)
            + ",_present:(" + (if (.source=="na" or (.cdxPath==null)) then "null" else "(try (" + .cdxPath + ") catch false)" end) + ")"
            + ",_absent:" + ((.absentSource // null)|@json)
            + ",_decl:(" + (if (.declaredPath==null) then "false" else "(try (" + .declaredPath + ") catch false)" end) + ")"
            + ",_missing:(" + (if (.missingPath==null) then "null" else "(try (" + .missingPath + ") catch null)" end) + ")"
            + ",_stot:($subjects|length)"
            + ",_slabel:" + ($slabel|@json)
            + ",_sempty:" + ($sempty|@json)
            + ",_ev:(" + (if (.evidencePath==null) then "[]" else "(try (" + .evidencePath + ") catch [])" end) + ")"
            + "}"
        ] | join(",")) + "]"
    ' "$reg") || { echo "[]"; return; }

    # Fold appended to the same program (single jq run — see header comment).
    # An element the SBOM does not satisfy fails when the baseline requires it and
    # warns when the baseline only recommends it. "Requires human review" is not a
    # verdict either way: the SBOM may well satisfy it, and no check here can tell.
    #
    # An element with absentSource "na" is a human-review item until its cdxPath
    # finds a value, and reports source "na" then, so it counts exactly as an
    # element with no automated source does. One whose declaredPath holds was
    # satisfied by the publisher's declaration, and its detail says so.
    local fold='
        | map(
            (if .required then "fail" else "warn" end) as $unmet
            | (if (._present==false and ._absent=="na") then "na" else .source end) as $src
            | (if $src=="na" then {status:"warn", detail:"requires human review (no automated source)", missing:[]}
             elif ._missing != null then
               (._stot) as $t | (._missing|length) as $m |
               (if $t==0 then {status:"warn", detail:._sempty, missing:[]}
                elif $m==0 then {status:"pass", detail:"\($t)/\($t) \(._slabel)(s)", missing:[]}
                else {status:$unmet, detail:"\($t - $m)/\($t) \(._slabel)(s)", missing:(._missing[0:$cap])} end)
             elif ._present==true and ._decl==true then
               {status:"pass", detail:"present (publisher'"'"'s declaration, not verified by BomLens)", missing:[]}
             elif ._present==true then {status:"pass", detail:"present", missing:[]}
             elif ._present==false then
               (if .id=="cisa-sbom-author-signature" and $signRequested and ($signFailed=="1")
                then {status:$unmet, detail:"signature requested but failed", missing:[]}
                else {status:$unmet, detail:"not present in the SBOM", missing:[]} end)
             else {status:"warn", detail:"requires human review (no automated source)", missing:[]} end) as $s
            | {id, label, label_ko, required, status:$s.status, detail:$s.detail,
               missing:$s.missing,
               evidence: ((._ev // []) | unique | .[0:$cap]),
               cluster, source:$src, role}
        )'
    local out
    if ! out=$(jq -c --argjson cap "$MISSING_CAP" --argjson hasSigFile "$HAS_SIG_FILE" \
            --argjson signRequested "$SIGN_REQUESTED" --arg signFailed "$SIGN_ATTEMPT_FAILED" \
            "${prog}${fold}" "$SBOM" 2>&1); then
        echo "[validate] WARN: $what registry evaluation failed; $what checks skipped this run." >&2
        echo "[validate]   $out" >&2
        echo "[]"
        return
    fi
    echo "$out"
}

# Attach a baseline's guidance to its evaluated checks (best-effort): the fragment
# that would satisfy an element, so the report can answer "how do I close this gap"
# and not only "this is missing", and the note for an element a person has to
# establish. Attached only where a mapping exists, and like the crosswalk it never
# changes a status or the result.
#
# The regulatory crosswalk used to be joined per baseline. It now runs once over
# the whole check array (see join_crosswalk below) so the plain CycloneDX checks
# carry their CRA / BSI references too.
# $1: evaluated checks (JSON array). $2: guidance file. $3: name for the warning.
join_guidance() {
    local checks="$1" guide="$2" what="$3"
    if [ ! -f "$guide" ]; then echo "$checks"; return; fi
    local joined
    if joined=$(printf '%s' "$checks" | jq -c --slurpfile g "$guide" '
        (($g[0].map) // {}) as $m
        | (($g[0].review) // {}) as $r
        | map(if $m[.id] then . + {guidance: $m[.id]} else . end)
        | map(if $r[.id] then . + {reviewGuide: $r[.id]} else . end)' 2>/dev/null); then
        echo "$joined"
    else
        echo "[validate] WARN: $what guidance join failed; continuing without it." >&2
        echo "$checks"
    fi
}

# G7 checks: the registry evaluation above, plus the guidance for that baseline.
# Kept apart so the evaluator stays about evaluating.
g7_ai_checks() {
    local out
    out=$(registry_checks "${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}" "G7")
    [ "$out" = "[]" ] && { echo "[]"; return; }
    join_guidance "$out" "${G7_GUIDANCE:-$(dirname "$0")/g7-guidance.json}" "G7"
}

# BSI TR-03183-2 v2.1.0 rows (profile bsi-tr-03183-2, CycloneDX only). Section
# 5.2.1 asks of the SBOM a creator given as an email address or URL and a
# timestamp (the timestamp row above already requires one), and section 5.2.2
# asks of every component its creator, name, version, filename, dependencies,
# distribution licence, SHA-512 of the deployable component and the
# executable, archive and structured properties.
#
# What is required depends on where a component came from. A component the
# declaration file added (it carries bomlens:origin) is one whose supplier said
# what it is and, through bomlens:artifact, which file it is: BomLens reads the
# file and fills in the hashes and the properties, so those rows fail when a
# field is missing. A component the scan found is described by what its
# package manager publishes, and no scan can give every one of them a
# filename and a SHA-512 (open question 1 of the first-party plan). Those are
# measured on one advisory row, with counts and the gaps of each component, and
# never move the result.
#
# A declared library or framework that names no build output (linked into a
# program, so with no file of its own) has no filename, hash or file
# properties to give; it is listed on an advisory row instead of failing the
# three file rows. Any other type (an application, firmware, a container, a
# driver) is a deliverable, and fails them without a file.
#
# The primary component (metadata.component) is the product: its creator,
# name, version and concluded licence are required, and its filename, SHA-512
# and file properties too when it names its file (hashes or bomlens:artifact);
# otherwise those three are reported on an advisory row.
#
# Creators are read where sbomqs v2.1.3 reads them (checked on the fixture):
# metadata.authors with an email, or metadata.manufacturer with a url or
# contact email, for the SBOM; supplier or manufacturer with a url or contact
# email for a component.
#
# The dependency graph has to reach every component from the primary one, and
# its completeness has to be indicated clearly (5.2.2): with no compositions
# entry the row warns rather than passing. A component with no dependencies
# entry of its own (a leaf should have one with an empty dependsOn) is listed
# on an advisory row. Nothing here writes a completeness value.
#
# A package read from a Yocto build has no SHA-512 when the build did not
# write one: Yocto writes file hashes only, and SHA-512 only from 6.1. Its
# missing SHA-512 is reported as not in the source SBOM, and stays advisory.
# So are a missing filename (the manifests list no files) and missing file
# properties (no Yocto record says whether a file is executable, an archive or
# structured): a package declared by recipe gets the files the build listed,
# not the files themselves. This holds only for the SBOM a scan generated from
# a Yocto build directory in this run (MODE YOCTO), and only for the
# components a Yocto reader wrote in it, which entrypoint.sh lists by bom-ref
# in the file YOCTO_READER_REFS names. A property in the document
# (bomlens:identifiedBy) could be written by anyone, so it is not read for this.
#
# Nested type "file" components (a component with several build outputs)
# count for the component that holds them, as everywhere else in this file.
YOCTO_REFS_FILE=/dev/null
if [ "${MODE:-}" = "YOCTO" ] && [ -n "${YOCTO_READER_REFS:-}" ] && [ -f "${YOCTO_READER_REFS}" ]; then
    YOCTO_REFS_FILE="$YOCTO_READER_REFS"
fi
bsi_checks() {
    jq -c --argjson cap "$MISSING_CAP" --slurpfile yrefs "$YOCTO_REFS_FILE" '
    def props($n): [ (.properties // [])[]? | select(.name? == $n) | .value ];
    def kids: [ (.components // [])[]? | select(.type? == "file") ];
    def own_or_files(f): f or (kids as $k | ($k | length) > 0 and all($k[]; f));
    def contact_ok: type == "object"
        and ((((.url // []) | if type == "array" then . else [] end) | any(type == "string" and length > 0))
             or (((.contact // []) | if type == "array" then . else [] end) | any(type == "object" and ((.email // "") != ""))));
    def creator_ok: [.supplier, .manufacturer] | any(contact_ok);
    def nv_ok: ((.name // "") != "") and (((.version // "") | tostring) != "");
    # The distribution licence as BSI TR-03183-2 reads it: an SPDX identifier
    # or expression, or a LicenseRef- for a licence the SPDX list does not
    # hold (6.1), marked "acknowledgement": "concluded" (section 8 gives the
    # distribution licence that way, and "declared" to the original one).
    def lic_ok: (.licenses // []) | if type == "array" then . else [] end
        | any(type == "object"
              and (((.expression // "") != "" and .acknowledgement == "concluded")
                   or ((.license // {}) | type == "object" and .acknowledgement == "concluded"
                       and (((.id // "") != "") or ((.name // "") | test("^LicenseRef-[A-Za-z0-9.-]+$"))))));
    def fname_ok: own_or_files(props("bsi:component:filename") | length > 0);
    # A SHA-512 is 128 hex digits, on the component or on a distribution
    # reference (where section 8 puts the hash of the deployable file).
    def sha512_list: (. // []) | if type == "array" then . else [] end
        | any(type == "object" and .alg == "SHA-512" and ((.content // "") | type == "string" and test("^[0-9a-fA-F]{128}$")));
    def sha512_here: (.hashes | sha512_list)
        or ((.externalReferences // []) | if type == "array" then . else [] end
            | any(type == "object" and .type == "distribution" and (.hashes | sha512_list)));
    def sha512_ok: own_or_files(sha512_here);
    def fprops_ok: own_or_files(props("bsi:component:executable") as $e | props("bsi:component:archive") as $a
                                | props("bsi:component:structured") as $s | ($e|length) > 0 and ($a|length) > 0 and ($s|length) > 0);
    def yocto_src: (.["bom-ref"] // "") as $r | ($r | type) == "string" and ((($yrefs[0] // {}) | if type == "object" then .[$r] else null end) == true);
    # The declared rows where a Yocto package lacks what the build did not record.
    def from_build($id): $id == "bsi-declared-sha512" or $id == "bsi-declared-filename" or $id == "bsi-declared-file-properties";
    # A declared component is delivered as a file when it names a build
    # output, carries a filename, holds file components, or is a package of
    # a Yocto build (installed as files).
    def has_file: (props("bomlens:artifact") | length > 0) or fname_ok or (kids | length > 0) or yocto_src;
    def may_lack_file: .type == "library" or .type == "framework";
    def clabel: (.name // "(unnamed)") + (if ((.version // "") | tostring) != "" then "@" + (.version | tostring) else "" end);
    # Components the dependency graph reaches from the primary component,
    # walked one level at a time.
    def reach($g; $root): {seen: {($root): true}, front: [$root]}
        | until((.front | length) == 0;
            .seen as $s
            | ([ .front[] | ($g[.] // [])[] | select(type == "string") ] | unique | map(select($s[.] | not))) as $new
            | .seen = (reduce $new[] as $n (.seen; .[$n] = true))
            | .front = $new)
        | .seen;

    ([ .components[]? | select(type == "object") ]) as $c
    | ([ $c[] | select(.type != "data" and .type != "file" and .type != "operating-system") ]) as $pkg
    | ([ $pkg[] | select(props("bomlens:origin") | length > 0) ]) as $decl
    | ([ $pkg[] | select(props("bomlens:origin") | length == 0) ]) as $scan
    | ([ $decl[] | select(has_file or (may_lack_file | not)) ]) as $dfile
    | ([ $decl[] | select((has_file | not) and may_lack_file) | clabel ]) as $dnofile
    | ($decl | length) as $dn | ($dfile | length) as $dfn
    # SBOM creator (5.2.1).
    | (.metadata // {}) as $m
    | (if ($m.manufacturer | contact_ok) then "metadata.manufacturer"
       elif (($m.authors // []) | if type == "array" then . else [] end | any(type == "object" and ((.email // "") != ""))) then "metadata.authors"
       else "" end) as $sbom_creator
    # Dependency graph (5.2.1, 5.2.2): every component reached from the
    # primary one.
    | (($m.component // {})["bom-ref"] // "") as $root
    | (reduce (.dependencies // [])[]? as $d ({};
          if ($d | type) == "object" and (($d.ref // "") | type) == "string"
          then .[$d.ref] = ((.[$d.ref] // []) + (($d.dependsOn // []) | if type == "array" then . else [] end))
          else . end)) as $g
    | (if $root == "" then {} else reach($g; $root) end) as $reached
    | ([ $c[] | select((.["bom-ref"] // "") as $r | $r == "" or ($reached[$r] | not)) | clabel ]) as $unreached
    | (((.compositions // [])[0].aggregate) // "") as $agg
    | ([ (.dependencies // [])[]? | select(type == "object" and ((.dependsOn // null) | type) == "array") | .ref ]) as $has_entry
    | ([ $c[] | select((.["bom-ref"] // "") as $r | $r == "" or ($has_entry | index($r)) == null) | clabel ]) as $no_entry
    # The primary component.
    | ($m.component // {}) as $top
    | ($top | (has_file or ((.hashes // []) | length > 0))) as $top_file
    | ($top | [ (if creator_ok then empty else "creator" end),
                (if nv_ok then empty else "name and version" end),
                (if lic_ok then empty else "concluded licence" end) ]) as $top_gaps
    | ($top | [ (if fname_ok then empty else "filename" end),
                (if sha512_ok then empty else "SHA-512" end),
                (if fprops_ok then empty else "file properties" end) ]) as $top_file_gaps
    | ($top_gaps + (if $top_file then $top_file_gaps else [] end)) as $top_all
    | {"creator": "제작자", "name and version": "이름과 버전", "concluded licence": "배포 라이선스(concluded)",
       "filename": "파일 이름", "SHA-512": "SHA-512", "file properties": "파일 속성"} as $gap_ko
    # One row per field over the declared components: what fails and what
    # is reported as not in the source SBOM.
    | def drow($id; $lbl; $lbl_ko; $subject; f; $ref):
        ([ $subject[] | select(f | not) ]) as $bad
        | ([ $bad[] | select(from_build($id) and yocto_src) | clabel + " (not in the source SBOM)" ]) as $nosrc
        | ([ $bad[] | select((from_build($id) and yocto_src) | not) | clabel ]) as $miss
        | ($subject | length) as $n
        | {id: $id, label: $lbl, label_ko: $lbl_ko, required: true,
           source: (if $n == 0 then "na" else "auto" end),
           naKind: (if $n == 0 then "not-applicable" else "" end),
           status: (if $n == 0 then "warn" elif ($miss | length) > 0 then "fail" elif ($nosrc | length) > 0 then "warn" else "pass" end),
           detail: (if $n == 0 then (if $dn == 0 then "no declared components" else "no declared component has a file of its own" end)
                    else "\($n - ($bad | length))/\($n) declared component(s)"
                         + (if ($nosrc | length) > 0 then "; \($nosrc | length) not in the source SBOM" else "" end) end),
           detail_ko: (if $n == 0 then (if $dn == 0 then "선언한 구성요소 없음" else "자체 파일이 있는 선언 구성요소 없음" end)
                       else "선언 구성요소 \($n - ($bad | length))/\($n)개"
                            + (if ($nosrc | length) > 0 then ", 원본 SBOM에 없음 \($nosrc | length)개" else "" end) end),
           missing: (($miss + $nosrc)[0:$cap]),
           reviewGuide: (if ($miss | length) > 0 then $ref else null end)}
        | if .reviewGuide == null then del(.reviewGuide) else . end;
    def guide($how; $how_ko): {how: $how, how_ko: $how_ko, docUrl: "https://sktelecom.github.io/bomlens/reference/cli/"};
    # The advisory row for the components the scan found: the gaps of each.
    ([ $scan[] | . as $x
       | ([ (if creator_ok then empty else "creator" end),
            (if nv_ok then empty else "version" end),
            (if fname_ok then empty else "filename" end),
            (if sha512_ok then empty elif yocto_src then "SHA-512 (not in the source SBOM)" else "SHA-512" end),
            (if fprops_ok then empty else "file properties" end),
            (if lic_ok then empty else "concluded licence" end) ]) as $gaps
       | select(($gaps | length) > 0) | ($x | clabel) + ": " + ($gaps | join(", ")) ]) as $scan_gaps
    | def cnt(f): [ $scan[] | select(f) ] | length;
    ($scan | length) as $sn
    | ([ $scan[] | select((sha512_ok | not) and yocto_src) ] | length) as $scan_nosrc
    | [
       {id: "bsi-sbom-creator", label: "SBOM creator with an email address or URL",
        label_ko: "이메일 주소나 URL이 있는 SBOM 작성자", required: true,
        status: (if $sbom_creator != "" then "pass" else "fail" end),
        detail: (if $sbom_creator != "" then $sbom_creator else "no metadata.manufacturer with a url or contact email, and no metadata.authors entry with an email" end),
        detail_ko: (if $sbom_creator != "" then $sbom_creator else "url이나 연락처 이메일이 있는 metadata.manufacturer도, 이메일이 있는 metadata.authors도 없음" end),
        missing: []}
       + (if $sbom_creator != "" then {} else {reviewGuide: guide(
           "Name the SBOM creator with an email address: scan again with --sbom-author \"Example Corp <sbom@example.com>\", which BomLens writes to metadata.authors with the email.";
           "이메일 주소와 함께 SBOM 작성자를 적습니다. --sbom-author \"Example Corp <sbom@example.com>\" 옵션으로 다시 스캔하면 BomLens가 이메일을 포함해 metadata.authors에 기록합니다.")} end),
       {id: "bsi-dependency-graph", label: "Every component reached from the primary component in the dependency graph",
        label_ko: "의존 관계 그래프에서 최상위 구성요소로부터 모든 구성요소에 도달", required: true,
        source: (if ($c | length) == 0 then "na" else "auto" end),
        naKind: (if ($c | length) == 0 then "not-applicable" else "" end),
        status: (if ($c | length) == 0 then "warn" elif $root == "" or ($unreached | length) > 0 then "fail"
                 elif $agg == "" then "warn" else "pass" end),
        detail: (if ($c | length) == 0 then "nothing to relate"
                 elif $root == "" then "the primary component (metadata.component) has no bom-ref"
                 else "\(($c | length) - ($unreached | length))/\($c | length) component(s) reached" end
                 + (if $agg == "" then "; completeness is not indicated (no compositions entry), which BSI TR-03183-2 5.2.2 requires to be indicated clearly"
                    else ", completeness indicated as \($agg)" end)),
        detail_ko: (if ($c | length) == 0 then "연결할 구성요소 없음"
                    elif $root == "" then "최상위 구성요소(metadata.component)에 bom-ref가 없음"
                    else "구성요소 \(($c | length) - ($unreached | length))/\($c | length)개 도달" end
                    + (if $agg == "" then "; 완전성 표시가 없음(compositions 항목 없음). BSI TR-03183-2 5.2.2는 완전성을 분명히 표시하도록 요구함"
                       else ", 완전성 표시 \($agg)" end)),
        missing: ($unreached[0:$cap])},
       {id: "bsi-dependency-entries", label: "Every component has its own dependencies entry, empty for a leaf (advisory)",
        label_ko: "모든 구성요소에 자체 dependencies 항목 있음, 말단 구성요소는 빈 항목 (권고)", required: false,
        source: (if ($c | length) == 0 then "na" else "auto" end),
        naKind: (if ($c | length) == 0 then "not-applicable" else "" end),
        status: (if ($no_entry | length) == 0 then "pass" else "warn" end),
        detail: "\(($c | length) - ($no_entry | length))/\($c | length) component(s) with an entry",
        detail_ko: "dependencies 항목이 있는 구성요소 \(($c | length) - ($no_entry | length))/\($c | length)개",
        missing: ($no_entry[0:$cap])},
       ({id: "bsi-primary-component", label: ("Primary component: creator with an email address or URL, name, version and concluded licence"
                                             + (if $top_file then ", filename, SHA-512 and file properties" else "" end)),
         label_ko: ("최상위 구성요소: 이메일 주소나 URL이 있는 제작자, 이름, 버전, 배포 라이선스(concluded)"
                    + (if $top_file then ", 파일 이름, SHA-512, 파일 속성" else "" end)),
         required: true,
         status: (if ($top_all | length) == 0 then "pass" else "fail" end),
         detail: (if ($top_all | length) == 0 then "met" else "missing: " + ($top_all | join(", ")) end),
         detail_ko: (if ($top_all | length) == 0 then "충족" else "누락: " + ($top_all | map($gap_ko[.] // .) | join(", ")) end),
         missing: (if ($top_all | length) == 0 then [] else [ ($top | clabel) + ": " + ($top_all | join(", ")) ] end)}
        + (if ($top_gaps | length) == 0 then {} else {reviewGuide: guide(
            "The product is metadata.component. Scan again with --supplier \"Example Corp <https://example.com>\" (or an email in the brackets) for its creator, and --license for its distribution licence. A licence given with --license replaces the one the generator or the project manifest supplied and is written as \"acknowledgement\": \"concluded\"; without --license, the licence read from the scan stays as it is, which is not a concluded one.";
            "제품은 metadata.component입니다. 제작자는 --supplier \"Example Corp <https://example.com>\" 옵션(괄호 안에 이메일도 가능)으로, 배포 라이선스는 --license 옵션으로 다시 스캔해 기록합니다. --license로 준 라이선스는 생성 도구나 프로젝트 매니페스트가 정한 라이선스를 대신하며 \"acknowledgement\": \"concluded\"로 기록됩니다. --license가 없으면 스캔에서 읽은 라이선스를 그대로 두며, 이는 concluded 라이선스가 아닙니다.")} end)),
       {id: "bsi-primary-component-file", label: "Primary component: filename, SHA-512 and file properties (advisory when it names no file of its own)",
        label_ko: "최상위 구성요소: 파일 이름, SHA-512, 파일 속성 (자체 파일을 지정하지 않으면 권고)", required: false,
        source: (if $top_file then "na" else "auto" end),
        naKind: (if $top_file then "not-applicable" else "" end),
        status: (if $top_file or ($top_file_gaps | length) == 0 then "pass" else "warn" end),
        detail: (if $top_file then "measured on the primary component row"
                 else "the primary component names no delivered file (no hashes or bomlens:artifact), so these are advisory"
                      + (if ($top_file_gaps | length) > 0 then "; missing: " + ($top_file_gaps | join(", ")) else "" end) end),
        detail_ko: (if $top_file then "최상위 구성요소 항목에서 확인"
                    else "최상위 구성요소가 배포 파일을 지정하지 않아(해시나 bomlens:artifact 없음) 권고로 보고함"
                         + (if ($top_file_gaps | length) > 0 then "; 누락: " + ($top_file_gaps | map($gap_ko[.] // .) | join(", ")) else "" end) end),
        missing: []},
       drow("bsi-declared-creator"; "Declared components: creator with an email address or URL (supplier or manufacturer)";
            "선언 구성요소: 이메일 주소나 URL이 있는 제작자(supplier 또는 manufacturer)"; $decl; creator_ok;
            guide("Give each listed component a supplier (or manufacturer) with a url or a contact email in the declaration file.";
                  "선언 파일에서 표시된 구성요소의 supplier(또는 manufacturer)에 url이나 연락처 이메일을 적습니다.")),
       drow("bsi-declared-name-version"; "Declared components: name and version"; "선언 구성요소: 이름과 버전"; $decl; nv_ok;
            guide("Give each listed component a name and a version in the declaration file.";
                  "선언 파일에서 표시된 구성요소에 이름과 버전을 적습니다.")),
       drow("bsi-declared-license"; "Declared components: concluded distribution licence as an SPDX identifier, expression or LicenseRef-";
            "선언 구성요소: SPDX 식별자, 표현식, LicenseRef- 형식의 배포 라이선스(concluded)"; $decl; lic_ok;
            guide("Give each listed component its distribution licence as an SPDX identifier or expression, or as a LicenseRef- name for a licence the SPDX list does not hold, for example {\"license\": {\"name\": \"LicenseRef-ExampleCorp-Proprietary\"}}. BomLens marks a declared licence \"acknowledgement\": \"concluded\" unless the declaration says \"declared\"; the distribution licence has to be the concluded one.";
                  "선언 파일에서 표시된 구성요소의 배포 라이선스를 SPDX 식별자나 표현식으로 적고, SPDX 목록에 없는 라이선스는 LicenseRef- 이름으로 적습니다. 예: {\"license\": {\"name\": \"LicenseRef-ExampleCorp-Proprietary\"}}. BomLens는 선언 파일이 \"declared\"로 적지 않은 라이선스에 \"acknowledgement\": \"concluded\"를 붙이며, 배포 라이선스는 concluded여야 합니다.")),
       drow("bsi-declared-filename"; "Declared components: filename (bsi:component:filename)";
            "선언 구성요소: 파일 이름(bsi:component:filename)"; $dfile; fname_ok;
            guide("Name the build output of each listed component in bomlens:artifact; the scan writes its file name.";
                  "표시된 구성요소의 빌드 산출물 경로를 bomlens:artifact에 적으면 스캔이 파일 이름을 기록합니다.")),
       drow("bsi-declared-sha512"; "Declared components: SHA-512 of the deployable file";
            "선언 구성요소: 배포 파일의 SHA-512"; $dfile; sha512_ok;
            guide("Name the build output of each listed component in bomlens:artifact; the scan computes its SHA-512.";
                  "표시된 구성요소의 빌드 산출물 경로를 bomlens:artifact에 적으면 스캔이 SHA-512를 계산합니다.")),
       drow("bsi-declared-file-properties"; "Declared components: executable, archive and structured properties";
            "선언 구성요소: 실행, 압축, 구조 속성"; $dfile; fprops_ok;
            guide("Name the build output of each listed component in bomlens:artifact; the scan reads the three properties from the file.";
                  "표시된 구성요소의 빌드 산출물 경로를 bomlens:artifact에 적으면 스캔이 파일에서 세 속성을 읽습니다.")),
       {id: "bsi-declared-without-file", label: "Declared libraries and frameworks with no file of their own, linked into another component (filename, SHA-512 and file properties not required, advisory)",
        label_ko: "다른 구성요소에 링크되어 자체 파일이 없는 선언 라이브러리와 프레임워크 (파일 이름, SHA-512, 파일 속성은 필수 아님, 권고)", required: false,
        source: (if $dn == 0 then "na" else "auto" end),
        naKind: (if $dn == 0 then "not-applicable" else "" end),
        status: (if ($dnofile | length) == 0 then "pass" else "warn" end),
        detail: (if $dn == 0 then "no declared components" else "\($dnofile | length) of \($dn) declared component(s); a declared component of any other type fails the file rows without a file" end),
        detail_ko: (if $dn == 0 then "선언한 구성요소 없음" else "선언 구성요소 \($dn)개 중 \($dnofile | length)개. 그 밖의 유형은 파일이 없으면 파일 항목에서 실패함" end),
        missing: ($dnofile[0:$cap])},
       {id: "bsi-scanned-components", label: "Components the scan found: BSI TR-03183-2 component fields (advisory, not required for scanned components)",
        label_ko: "스캔이 찾은 구성요소: BSI TR-03183-2 구성요소 필드 (권고, 스캔한 구성요소에는 필수 아님)", required: false,
        source: (if $sn == 0 then "na" else "auto" end),
        naKind: (if $sn == 0 then "not-applicable" else "" end),
        status: (if ($scan_gaps | length) == 0 then "pass" else "warn" end),
        detail: (if $sn == 0 then "no scanned components"
                 else "creator \(cnt(creator_ok))/\($sn), version \(cnt(nv_ok))/\($sn), filename \(cnt(fname_ok))/\($sn), SHA-512 \(cnt(sha512_ok))/\($sn)"
                      + (if $scan_nosrc > 0 then " (\($scan_nosrc) not in the source SBOM)" else "" end)
                      + ", file properties \(cnt(fprops_ok))/\($sn), concluded licence \(cnt(lic_ok))/\($sn)" end),
        detail_ko: (if $sn == 0 then "스캔한 구성요소 없음"
                    else "제작자 \(cnt(creator_ok))/\($sn), 버전 \(cnt(nv_ok))/\($sn), 파일 이름 \(cnt(fname_ok))/\($sn), SHA-512 \(cnt(sha512_ok))/\($sn)"
                         + (if $scan_nosrc > 0 then " (원본 SBOM에 없음 \($scan_nosrc)개)" else "" end)
                         + ", 파일 속성 \(cnt(fprops_ok))/\($sn), 배포 라이선스(concluded) \(cnt(lic_ok))/\($sn)" end),
        missing: ($scan_gaps[0:$cap])}
      ]' "$SBOM"
}

spdx_json_checks() {
    jq -c \
       --argjson purlmin "$PURL_MIN_PCT" \
       --argjson licmin "$LICENSE_MIN_PCT" \
       --argjson hashmin "$HASH_MIN_PCT" \
       --argjson cap "$MISSING_CAP" \
       --argjson genericRequired "$GENERIC_REQUIRED" \
       --argjson typeRequired "$PURL_TYPE_REQUIRED" \
       --argjson purlRequired "$PURL_REQUIRED" \
       --argjson knowntypes "$PURL_KNOWN_TYPES" \
       --arg okvers "$SPDX_SPEC_VERSIONS" \
       --arg purlre "$PURL_SYNTAX_REGEX" \
       --arg nsre "$NS_PURL_TYPE_REGEX" \
       --arg nsnsre "$NS_PURL_NS_REGEX" \
       --arg advre "$NS_ADV_PURL_TYPE_REGEX" \
       --arg advnsre "$NS_ADV_PURL_NS_REGEX" \
       --arg advtypes "$NS_ADVISORY_LABEL" "
    $PCT_DEF
    # A package for one file of a multi-file component (primaryPackagePurpose
    # FILE, which spdx-declared.py writes) is not a package of its own here,
    # as a CycloneDX file component is not: the component that CONTAINS it is
    # counted, and has checksums when every file it contains has them.
    ([.packages[]? | select((.primaryPackagePurpose // \"\") == \"FILE\")]) as \$fpk
    | ([.packages[]? | select((.primaryPackagePurpose // \"\") != \"FILE\")]) as \$p
    | (reduce \$fpk[] as \$f ({}; .[\$f.SPDXID // \"\"] = (((\$f.checksums // []) | length) > 0))) as \$fsum
    | (reduce (.relationships // [])[] as \$r ({};
          if \$r.relationshipType == \"CONTAINS\" and (\$fsum | has(\$r.relatedSpdxElement // \"\"))
          then .[\$r.spdxElementId // \"\"] = ((.[\$r.spdxElementId // \"\"] // []) + [\$fsum[\$r.relatedSpdxElement]])
          else . end)) as \$kids
    | (\$p|length) as \$tot
    | ([ .creationInfo.creators[]? | select(startswith(\"Tool:\")) ] | length) as \$tools
    | (.creationInfo.created // \"\") as \$ts
    | ([ \$p[] | select((.name==null) or (.versionInfo==null)) | (.name // \"(unnamed)\") ]) as \$miss_nv
    | ([ \$p[] | select(([.externalRefs[]? | select(.referenceType==\"purl\")]|length)==0) | (.name // \"(unnamed)\") ]) as \$miss_purl
    # See the CycloneDX side: a package identified by CPE and not by PURL still
    # fails the submission criteria, but the report says which of the two it is.
    | ([ \$p[] | select((([.externalRefs[]? | select(.referenceType==\"purl\")]|length)==0)
                       and (([.externalRefs[]? | select(.referenceType==\"cpe23Type\")]|length)>0)) ] | length) as \$cpe_only
    | ([ \$p[] | .externalRefs[]? | select((.referenceLocator // \"\")|startswith(\"pkg:generic\")) | .referenceLocator ]) as \$generic
    | ([ \$p[] | .externalRefs[]? | select(.referenceType==\"purl\") | (.referenceLocator // \"\") | select(test(\$purlre) | not) ]) as \$badpurl
    | ([ \$p[] | .externalRefs[]? | select(.referenceType==\"purl\") | (.referenceLocator // \"\") ]) as \$purl_all
    | ([ \$purl_all[] | select(test(\$nsre)) ]) as \$ns_purl
    | ([ \$ns_purl[] | select(test(\$nsnsre) | not) ]) as \$ns_nons
    | ([ \$purl_all[] | select(test(\$advre)) ]) as \$adv_purl
    | ([ \$adv_purl[] | select(test(\$advnsre) | not) ]) as \$adv_nons
    # See the CycloneDX side for how the type is read off the identifier.
    | ([ \$purl_all[] | select(startswith(\"pkg:\"))
         | . as \$pu
         | (\$pu | ltrimstr(\"pkg:\") | split(\"/\")[0] | split(\"@\")[0] | ascii_downcase) as \$ty
         | select((\$knowntypes | index(\$ty)) == null) | \$pu ]) as \$unk_type
    | (\$okvers | split(\" \")) as \$vers
    | (.spdxVersion // \"\") as \$sv
    | ((\$p | map(select(((.licenseConcluded // \"NOASSERTION\") != \"NOASSERTION\") or ((.licenseDeclared // \"NOASSERTION\") != \"NOASSERTION\"))) | length)) as \$lic_ok
    | ((\$p | map(select(((.checksums // [])|length>0)
                          or ((\$kids[.SPDXID // \"\"] // []) as \$k | (\$k | length) > 0 and all(\$k[]; .)))) | length)) as \$hash_ok
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
       # A document with no packages has nothing to measure here, the same state
       # the CycloneDX branch above reports as not-applicable. Reporting it as
       # \"0/0, met\" would count an empty denominator toward coverage and let a
       # document that named nothing clear the bar.
       {id:\"name-version\", label:\"Package name+version coverage (100%)\", required:true,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot==0 then \"warn\" elif (\$miss_nv|length)==0 then \"pass\" else \"fail\" end),
        detail:(if \$tot==0 then \"no packages to measure\"
                else \"\(\$tot - (\$miss_nv|length))/\(\$tot)\" end),
        missing:(\$miss_nv[0:\$cap])},
       {id:\"purl\", label:(if \$purlRequired then \"PURL coverage (>= \(\$purlmin)%)\" else \"PURL coverage (>= \(\$purlmin)%, advisory)\" end), required:\$purlRequired,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot==0 then \"warn\" elif pct(\$purl_ok;\$tot) >= \$purlmin then \"pass\" elif \$purlRequired then \"fail\" else \"warn\" end),
        detail:(if \$tot==0 then \"no packages to measure\"
                else \"\(pct(\$purl_ok;\$tot))% (\(\$purl_ok)/\(\$tot))\"
                     + (if \$cpe_only > 0 then \"; \(\$cpe_only) identified by CPE instead\" else \"\" end) end),
        missing:(\$miss_purl[0:\$cap])},
       {id:\"no-generic\", label:(if \$genericRequired then \"Traceable PURL (no pkg:generic)\" else \"Traceable PURL (no pkg:generic, advisory)\" end), required:\$genericRequired,
        status:(if (\$generic|length)==0 then \"pass\" elif \$genericRequired then \"fail\" else \"warn\" end),
        detail:\"\(\$generic|length) untraceable\", missing:(\$generic[0:\$cap])},
       {id:\"purl-syntax\", label:\"PURL syntax (pkg:type/[namespace/]name)\", required:true,
        status:(if (\$badpurl|length)==0 then \"pass\" else \"fail\" end),
        detail:\"\(\$badpurl|length) malformed\", missing:(\$badpurl[0:\$cap])},
       {id:\"purl-namespace\", label:\"PURL namespace where the type requires it (pkg:maven/<groupId>/name)\", required:true,
        source:(if (\$ns_purl|length)==0 then \"na\" else \"auto\" end),
        naKind:(if (\$ns_purl|length)==0 then \"not-applicable\" else \"\" end),
        status:(if (\$ns_nons|length)==0 then \"pass\" else \"fail\" end),
        detail:(if (\$ns_purl|length)==0 then \"no identifiers of a type that requires a namespace\"
                else \"\(\$ns_nons|length) without namespace\" end),
        missing:(\$ns_nons[0:\$cap])},
       {id:\"purl-namespace-advisory\", label:(\"PURL namespace for \" + \$advtypes + \" (advisory)\"), required:false,
        source:(if (\$adv_purl|length)==0 then \"na\" else \"auto\" end),
        naKind:(if (\$adv_purl|length)==0 then \"not-applicable\" else \"\" end),
        status:(if (\$adv_nons|length)==0 then \"pass\" else \"warn\" end),
        detail:(if (\$adv_purl|length)==0 then \"no identifiers of a type that requires a namespace\"
                else \"\(\$adv_nons|length) without namespace\" end),
        missing:(\$adv_nons[0:\$cap])},
       {id:\"purl-type\", label:(if \$typeRequired then \"PURL type defined by purl-spec\" else \"PURL type defined by purl-spec (advisory)\" end), required:\$typeRequired,
        source:(if (\$knowntypes|length)==0 then \"na\" else \"auto\" end),
        status:(if (\$knowntypes|length)==0 then \"warn\"
                elif (\$unk_type|length)==0 then \"pass\"
                elif \$typeRequired then \"fail\" else \"warn\" end),
        detail:(if (\$knowntypes|length)==0 then \"purl type list unavailable\"
                else \"\(\$unk_type|length) undefined type(s)\" end),
        missing:(\$unk_type[0:\$cap])},
       {id:\"transitive\", label:\"Transitive dependencies (DEPENDS_ON/DEPENDENCY_OF)\", required:true,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$dep_edges>0 then \"pass\" elif \$tot==0 then \"warn\" else \"fail\" end),
        detail:(if \$dep_edges==0 and \$tot==0 then \"nothing to relate\"
                else \"\(\$dep_edges) edge(s)\" end), missing:[]},
       {id:\"license\", label:\"License coverage (>= \(\$licmin)%, recommended)\", required:false,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot>0 and pct(\$lic_ok;\$tot) >= \$licmin then \"pass\" else \"warn\" end),
        detail:\"\(pct(\$lic_ok;\$tot))% (\(\$lic_ok)/\(\$tot))\", missing:[]},
       {id:\"hash\", label:\"Hash coverage (>= \(\$hashmin)%, recommended)\", required:false,
        source:(if \$tot==0 then \"na\" else \"auto\" end),
        naKind:(if \$tot==0 then \"not-applicable\" else \"\" end),
        status:(if \$tot>0 and pct(\$hash_ok;\$tot) >= \$hashmin then \"pass\" else \"warn\" end),
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
    local ns_purls ns_ns_ok adv_purls adv_ns_ok known_ok known_alt
    ts=$(g '^Created:'); tools=$(g '^Creator: ?Tool:')
    names=$(g '^PackageName:'); vers=$(g '^PackageVersion:')
    purls=$(g 'ExternalRef: ?PACKAGE-MANAGER purl'); generic=$(g 'purl +pkg:generic')
    deps=$(g 'Relationship:.*(DEPENDS_ON|DEPENDENCY_OF)'); lics=$(g '^PackageLicenseConcluded:'); hashes=$(g '^PackageChecksum:')
    verpat=$(printf '%s' "$SPDX_SPEC_VERSIONS" | sed 's/\./\\./g; s/ /|/g')
    specok=$(g "^SPDXVersion: *($verpat) *\$")
    purlok=$(g 'ExternalRef: ?PACKAGE-MANAGER purl +pkg:[a-z][a-z0-9.+-]*/[^ ]+ *$')
    # Same questions on the Tag-Value side: how many identifiers of a type that
    # requires a namespace carry one, and how many use a type purl-spec defines.
    # Counted, not listed, like every other row here.
    ns_purls=$(g "ExternalRef: ?PACKAGE-MANAGER purl +pkg:($_ns_required)/")
    ns_ns_ok=$(g "ExternalRef: ?PACKAGE-MANAGER purl +pkg:($_ns_required)/[^/@?#]+/")
    adv_purls=$(g "ExternalRef: ?PACKAGE-MANAGER purl +pkg:($_ns_advisory)/")
    adv_ns_ok=$(g "ExternalRef: ?PACKAGE-MANAGER purl +pkg:($_ns_advisory)/[^/@?#]+/")
    known_alt=$(printf '%s' "$PURL_KNOWN_TYPES" | jq -r 'join("|")')
    if [ -n "$known_alt" ]; then
        known_ok=$(g "ExternalRef: ?PACKAGE-MANAGER purl +pkg:($known_alt)[/@]")
    else
        known_ok="$purls"   # no type data: nothing to judge, the row says so
    fi
    jq -cn \
       --argjson ts "$ts" --argjson tools "$tools" --argjson names "$names" \
       --argjson vers "$vers" --argjson purls "$purls" --argjson generic "$generic" \
       --argjson deps "$deps" --argjson lics "$lics" --argjson hashes "$hashes" \
       --argjson specok "$specok" --argjson purlok "$purlok" \
       --argjson nsp "$ns_purls" --argjson nsok "$ns_ns_ok" \
       --argjson advp "$adv_purls" --argjson advok "$adv_ns_ok" \
       --argjson knownok "$known_ok" --argjson knowntypes "$PURL_KNOWN_TYPES" \
       --arg advtypes "$NS_ADVISORY_LABEL" --arg okvers "$SPDX_SPEC_VERSIONS" \
       --argjson genericRequired "$GENERIC_REQUIRED" --argjson typeRequired "$PURL_TYPE_REQUIRED" \
       --argjson purlRequired "$PURL_REQUIRED" '
    [
      {id:"spec-version", label:"Spec version (\($okvers|split(" ")|join("/")))", required:true, status:(if $specok>0 then "pass" else "fail" end), detail:"\($specok) accepted SPDXVersion line(s)", missing:[]},
      {id:"timestamp", label:"Timestamp (Created:)", required:true, status:(if $ts>0 then "pass" else "fail" end), detail:"\($ts) found", missing:[]},
      {id:"tools", label:"Tool info (Creator: Tool:)", required:true, status:(if $tools>0 then "pass" else "fail" end), detail:"\($tools) tool(s)", missing:[]},
      {id:"top-component", label:"Document/package present", required:true, status:(if $names>0 then "pass" else "fail" end), detail:"\($names) package(s)", missing:[]},
      {id:"name-version", label:"PackageName + PackageVersion present", required:true, status:(if $names>0 and $vers>=$names then "pass" else "fail" end), detail:"names=\($names), versions=\($vers)", missing:[]},
      {id:"purl", label:(if $purlRequired then "PURL external refs present" else "PURL external refs present (advisory)" end), required:$purlRequired, status:(if $purls>0 and $purls>=$names then "pass" elif $purlRequired then "fail" else "warn" end), detail:"\($purls) purl ref(s) for \($names) package(s)", missing:[]},
      {id:"no-generic", label:(if $genericRequired then "Traceable PURL (no pkg:generic)" else "Traceable PURL (no pkg:generic, advisory)" end), required:$genericRequired, status:(if $generic==0 then "pass" elif $genericRequired then "fail" else "warn" end), detail:"\($generic) untraceable", missing:[]},
      {id:"purl-syntax", label:"PURL syntax (pkg:type/[namespace/]name)", required:true, status:(if $purls<=$purlok then "pass" else "fail" end), detail:"\($purls - $purlok) malformed", missing:[]},
      {id:"purl-namespace", label:"PURL namespace where the type requires it (pkg:maven/<groupId>/name)", required:true, source:(if $nsp==0 then "na" else "auto" end), naKind:(if $nsp==0 then "not-applicable" else "" end), status:(if $nsp<=$nsok then "pass" else "fail" end), detail:(if $nsp==0 then "no identifiers of a type that requires a namespace" else "\($nsp - $nsok) without namespace" end), missing:[]},
      {id:"purl-namespace-advisory", label:("PURL namespace for " + $advtypes + " (advisory)"), required:false, source:(if $advp==0 then "na" else "auto" end), naKind:(if $advp==0 then "not-applicable" else "" end), status:(if $advp<=$advok then "pass" else "warn" end), detail:(if $advp==0 then "no identifiers of a type that requires a namespace" else "\($advp - $advok) without namespace" end), missing:[]},
      {id:"purl-type", label:(if $typeRequired then "PURL type defined by purl-spec" else "PURL type defined by purl-spec (advisory)" end), required:$typeRequired, source:(if ($knowntypes|length)==0 then "na" else "auto" end), status:(if ($knowntypes|length)==0 then "warn" elif $purls<=$knownok then "pass" elif $typeRequired then "fail" else "warn" end), detail:(if ($knowntypes|length)==0 then "purl type list unavailable" else "\($purls - $knownok) undefined type(s)" end), missing:[]},
      {id:"transitive", label:"Transitive dependencies (DEPENDS_ON/DEPENDENCY_OF)", required:true, status:(if $deps>0 or $names==0 then "pass" else "fail" end), detail:(if $deps==0 and $names==0 then "nothing to relate" else "\($deps) relationship(s)" end), missing:[]},
      {id:"license", label:"License present (recommended)", required:false, status:(if $lics>0 then "pass" else "warn" end), detail:"\($lics) license field(s)", missing:[]},
      {id:"hash", label:"Checksums present (recommended)", required:false, status:(if $hashes>0 then "pass" else "warn" end), detail:"\($hashes) checksum(s)", missing:[]}
    ]'
}

# --------------------------------------------------------
# Measurements for --fail-on (docker/lib/evaluate-gate.sh). Printed as one JSON
# object:
#   softwareComponentCount  components other than operating-system and file
#                           entries: what the scan identified as software (for
#                           SPDX, packages the document DESCRIBES are the
#                           subject itself, as CycloneDX's metadata.component
#                           is, and are not counted)
#   emptyResult             true when that count is 0
#   licenseCoverage         {declared,total,pct}: of those components, how many
#                           declare a license, and the percentage rounded down.
#                           A license of NOASSERTION or NONE (any case) is not a
#                           declaration, in every format. pct is null when
#                           total is 0.
# Separate from the checks on purpose: the license check keeps its own counting
# (and its report text), and these numbers can differ from it.
# --------------------------------------------------------
cdx_signal() {
    jq -c '
      ([ .components[]? | select(.type != "operating-system" and .type != "file") ]) as $s
      | ($s | length) as $n
      | ([ $s[] | select([ (.licenses // [])[] | objects
                            | (.license.id // .license.name // .expression // "")
                            | select(type == "string" and . != "" and (ascii_upcase != "NOASSERTION") and (ascii_upcase != "NONE")) ]
                          | length > 0) ] | length) as $d
      | { softwareComponentCount: $n, emptyResult: ($n == 0),
          licenseCoverage: { declared: $d, total: $n, pct: (if $n == 0 then null else (($d * 100 / $n) | floor) end) } }' "$SBOM" 2>/dev/null || echo '{}'
}
spdx_json_signal() {
    jq -c '
      def declared($v): ($v // "NOASSERTION") | (ascii_upcase != "NOASSERTION" and ascii_upcase != "NONE");
      ([ (.documentDescribes // [])[]?, (.relationships[]? | select(.relationshipType == "DESCRIBES" and .spdxElementId == "SPDXRef-DOCUMENT") | .relatedSpdxElement) ]) as $roots
      # A FILE package (one file of a multi-file component) is left out, as
      # cdx_signal leaves out a file component.
      | ([ .packages[]? | select((.SPDXID // "") as $id | ($roots | index($id)) == null)
                        | select((.primaryPackagePurpose // "") != "FILE") ]) as $p
      | ($p | length) as $n
      | ([ $p[] | select(declared(.licenseConcluded) or declared(.licenseDeclared)) ] | length) as $d
      | { softwareComponentCount: $n, emptyResult: ($n == 0),
          licenseCoverage: { declared: $d, total: $n, pct: (if $n == 0 then null else (($d * 100 / $n) | floor) end) } }' "$SBOM" 2>/dev/null || echo '{}'
}
spdx_tv_signal() {
    # One record per PackageName; a package declares a license when either license
    # line names something other than NOASSERTION or NONE.
    local counts n d
    counts=$(awk '
        function flush() { if (inpkg && !(id in root)) { n++; if (ok) d++ } }
        NR == FNR { if ($1 == "Relationship:" && $2 == "SPDXRef-DOCUMENT" && $3 == "DESCRIBES") root[$4] = 1; next }
        /^PackageName:/ { flush(); inpkg = 1; ok = 0; id = ""; next }
        /^SPDXID:/ { if (inpkg) { id = $2 } next }
        /^PackageLicense(Concluded|Declared):/ {
            v = $0; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t\r]+$/, "", v); u = toupper(v)
            if (inpkg && u != "" && u != "NOASSERTION" && u != "NONE") ok = 1
        }
        END { flush(); printf "%d %d", n + 0, d + 0 }' "$SBOM" "$SBOM" 2>/dev/null) || counts="0 0"
    n=${counts% *}; d=${counts#* }
    jq -cn --argjson n "${n:-0}" --argjson d "${d:-0}" '
      { softwareComponentCount: $n, emptyResult: ($n == 0),
        licenseCoverage: { declared: $d, total: $n, pct: (if $n == 0 then null else (($d * 100 / $n) | floor) end) } }'
}

# The bsi-* rows, under the bsi-tr-03183-2 profile, for a CycloneDX document
# (an SPDX 3.0 one is measured on its CycloneDX conversion). If they cannot be
# evaluated, a failing row says so: a BSI verdict without them would be a pass
# on the generic rows alone.
add_bsi_checks() {
    [ "$CONFORMANCE_PROFILE" = "bsi-tr-03183-2" ] || return 0
    local bsi
    if bsi=$(bsi_checks) && [ -n "$bsi" ]; then
        # The general file-properties row reads "no automated source" when no
        # component carries the properties, which would contradict the
        # bsi-declared-file-properties row; the bsi-* rows replace it here.
        CHECKS=$(printf '%s\n%s' "$CHECKS" "$bsi" | jq -cs 'add | map(select(.id != "file-properties"))')
        echo "[validate] added the BSI TR-03183-2 checks"
    else
        bsi_unmeasured "could not evaluate" "검사를 수행하지 못함"
    fi
}

# A failing bsi-evaluation row, for an SBOM the bsi-* rows could not be
# measured on: a BSI verdict must not rest on the general rows alone.
# $1/$2: the reason, English and Korean.
bsi_unmeasured() {
    echo "[validate] WARN: the BSI TR-03183-2 checks were not evaluated ($1); a failing row stands in for them." >&2
    CHECKS=$(printf '%s\n%s' "$CHECKS" "$(jq -cn --arg d "$1" --arg dk "$2" '[{id: "bsi-evaluation",
        label: "BSI TR-03183-2 checks evaluated", label_ko: "BSI TR-03183-2 검사 수행", required: true,
        status: "fail", detail: $d, detail_ko: $dk, missing: []}]')" | jq -cs 'add')
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
        # The model can sit in either place: the AIBOM generator leaves it in
        # components[] and fills metadata.component with its scan job, while a
        # spec-shaped AI SBOM names the model as the document's own component.
        # A dataset scan carries no model at all — the item IS the document — and
        # is emitted at 1.7 for the same reason: `data` components and their
        # governance are what the AI clusters are written against. It qualifies on
        # the marker the dataset collectors stamp, so an ordinary SBOM that happens
        # to carry a `data` component is not swept in.
        IS_AI=false
        if jq -e '([.metadata.component // empty] + [.components[]?])
                  | map(select(.type == "machine-learning-model"
                               or (.type == "data"
                                   and ((.properties // [])
                                        | any(.name == "bomlens:dataset:collectedBy")))))
                  | length > 0' "$SBOM" >/dev/null 2>&1; then
            IS_AI=true
        fi
        # Whether a registry applies to THIS SBOM is the registry's own statement
        # (appliesWhen, a jq boolean; absent means always), not a rule spelled out
        # here. The G7 registry declares the AI condition, so this reads the same
        # as the AI test above for it — and a baseline that applies to every SBOM
        # can be added without another branch in this file. The spec-version range
        # stays keyed off IS_AI: that is about which CycloneDX versions we accept,
        # not about which baseline we measure against.
        if [ "$IS_AI" = true ]; then
            CHECKS=$(cdx_checks "$AI_CYCLONEDX_SPEC_VERSIONS")
        else
            CHECKS=$(cdx_checks "$CYCLONEDX_SPEC_VERSIONS")
        fi
        SIGNAL=$(cdx_signal)
        if registry_applies "${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}"; then
            G7=$(g7_ai_checks)
            CHECKS=$(printf '%s\n%s' "$CHECKS" "$G7" | jq -cs 'add')
            echo "[validate] AI SBOM detected -> added G7 minimum-element checks"
        fi
        # The 2026 SBOM minimum elements apply to all software, so this registry
        # declares no condition and is measured on every CycloneDX SBOM. Its
        # elements are advisory and none of them moves the verdict; the submission
        # criteria above remain the thing that decides pass or fail.
        CISA_REG="${CISA_REGISTRY:-$(dirname "$0")/cisa-registry.json}"
        if registry_applies "$CISA_REG"; then
            CISA=$(registry_checks "$CISA_REG" "CISA")
            CISA=$(join_guidance "$CISA" "${CISA_GUIDANCE:-$(dirname "$0")/cisa-guidance.json}" "CISA")
            CHECKS=$(printf '%s\n%s' "$CHECKS" "$CISA" | jq -cs 'add')
            echo "[validate] added the 2026 SBOM minimum-element checks"
        fi
        add_bsi_checks
        ;;
    SPDX-JSON)     CHECKS=$(spdx_json_checks); SIGNAL=$(spdx_json_signal) ;;
    SPDX-3.0)
        # SPDX 3.0 is JSON-LD (@graph); the 2.x package/relationship shape the
        # spdx_json checks read does not exist. Measure conformance on the
        # CycloneDX that syft produces from it — the same converter the analysis
        # pipeline uses — so PURL coverage, name/version, and transitive edges
        # come from real component data instead of reading as all-zero.
        SPDX3_CDX="${OUT_PREFIX}.spdx3-cdx.$$.json"
        # Yocto documents are measured on the set the pipeline actually analyses.
        # syft turns this document into 1000 components of which 872 are source
        # FILES, so name/version coverage reads 35/1000 and the verdict describes a
        # document nobody downstream sees — the report is built from the 35 installed
        # packages parse-yocto-spdx.py extracts. Measuring what is judged is the
        # point of a conformance check. Non-Yocto SPDX 3.0 falls through to syft.
        if command -v python3 >/dev/null 2>&1 \
           && [ -f "$(dirname "$0")/parse-yocto-spdx.py" ] \
           && python3 "$(dirname "$0")/parse-yocto-spdx.py" "$SBOM" "$SPDX3_CDX" >/dev/null 2>&1 \
           && [ -s "$SPDX3_CDX" ]; then
            SBOM="$SPDX3_CDX"
            CHECKS=$(cdx_checks "$CYCLONEDX_SPEC_VERSIONS")
            SIGNAL=$(cdx_signal)
            add_bsi_checks
            rm -f "$SPDX3_CDX"
            echo "[validate] SPDX 3.0 (Yocto) measured on the installed package set"
        elif command -v syft >/dev/null 2>&1 \
           && syft convert "$SBOM" -o "cyclonedx-json@$CDX_SPEC_VERSION=$SPDX3_CDX" >/dev/null 2>&1 \
           && [ -s "$SPDX3_CDX" ]; then
            SBOM="$SPDX3_CDX"
            CHECKS=$(cdx_checks "$CYCLONEDX_SPEC_VERSIONS")
            SIGNAL=$(cdx_signal)
            add_bsi_checks
            rm -f "$SPDX3_CDX"
            echo "[validate] SPDX 3.0 measured via CycloneDX conversion"
        else
            echo "[validate] WARN: syft unavailable; SPDX 3.0 recognized but not measured" >&2
            CHECKS='[{"id":"spec-version","label":"Spec version (SPDX-3.0)","required":true,"status":"pass","detail":"SPDX-3.0 (recognized; not measured without syft)","missing":[]}]'
        fi
        ;;
    SPDX-TagValue) CHECKS=$(spdx_tv_checks); SIGNAL=$(spdx_tv_signal) ;;
    *)
        CHECKS='[{"id":"format","label":"Recognized SBOM format","required":true,"status":"fail","detail":"not CycloneDX or SPDX","missing":[]}]'
        ;;
esac
# Under the BSI profile, a document no bsi-* row was measured on (SPDX 2.x,
# Tag-Value, SPDX 3.0 without syft, an unknown format) gets the failing row.
if [ "$CONFORMANCE_PROFILE" = "bsi-tr-03183-2" ] && [ -n "$CHECKS" ] \
   && ! printf '%s' "$CHECKS" | jq -e 'any(.[]; .id | startswith("bsi-"))' >/dev/null 2>&1; then
    bsi_unmeasured "the BSI checks read CycloneDX, and this $FORMAT document could not be measured as CycloneDX" \
        "BSI 검사는 CycloneDX를 읽으며, 이 $FORMAT 문서는 CycloneDX로 확인할 수 없음"
fi
[ -n "$CHECKS" ] || CHECKS='[{"id":"parse","label":"Parseable SBOM","required":true,"status":"fail","detail":"could not evaluate","missing":[]}]'

# --------------------------------------------------------
# Repository resolution (advisory, opt-in, format independent).
#
# docker/lib/resolve-purl.py asks a package repository whether each identifier
# names something that exists, and leaves its answer in a sidecar beside the
# report. That step runs before this one and only when the scan asked for it,
# so its absence is the normal case and reads as "not checked", never as a gap.
#
# The row can only ever warn. An identifier that resolves to nothing is usually
# a generator defect (a groupId repeated inside the artifactId, a vendor
# display name in the namespace slot), but a package published only to a
# company-internal repository answers exactly the same way, and a submission
# may legitimately be full of them.
# --------------------------------------------------------
RESOLVE_FILE="${PURL_RESOLUTION_FILE:-${OUT_PREFIX}_purl-resolution.json}"
if [ "$FORMAT" = "unknown" ]; then
    : # nothing was read, so there are no identifiers to have looked up
elif [ -f "$RESOLVE_FILE" ]; then
    if RESOLVE_ROW=$(jq -c --argjson cap "$MISSING_CAP" '
        (.counts // {}) as $c
        | (($c.found // 0) + ($c.missing // 0)) as $checked
        | [{id: "purl-resolution",
            label: "PURL resolves in its repository (advisory)",
            required: false,
            source: (if $checked == 0 then "na" else "auto" end),
            naKind: (if $checked == 0 then "not-applicable" else "" end),
            status: (if ($c.missing // 0) == 0 then "pass" else "warn" end),
            detail: (if $checked == 0 then "nothing could be looked up"
                     else "\($c.missing // 0) of \($checked) not found in the repository" end),
            missing: ((.missing // [])[0:$cap])}]' "$RESOLVE_FILE" 2>/dev/null); then
        CHECKS=$(printf '%s\n%s' "$CHECKS" "$RESOLVE_ROW" | jq -cs 'add')
    else
        echo "[validate] WARN: could not read $RESOLVE_FILE; the repository-resolution row is omitted." >&2
    fi
else
    CHECKS=$(printf '%s\n%s' "$CHECKS" '[{"id":"purl-resolution",
        "label":"PURL resolves in its repository (advisory)","required":false,
        "source":"na","naKind":"not-applicable","status":"pass",
        "detail":"repository lookup not run","missing":[]}]' | jq -cs 'add')
fi

# --------------------------------------------------------
# Submission profile: what the supplier has to do next.
#
# A firmware, root filesystem or binary SBOM fails the submission for two
# different reasons, and they have different fixes. A component found without
# a version needs the supplier to say which version shipped (the scan writes
# <prefix>_component-versions.template.csv for that, read back with
# --component-versions). A component with a version and still no purl a lookup
# can resolve is one the upstream purl table does not cover, which the supplier
# cannot fix by editing the SBOM. Both are already counted by the generic rows
# above (name+version, PURL coverage, no pkg:generic); these two say which is
# which. Package components only, the same set those rows measure.
#
# Under --analyze the document is a supplier's SBOM under review: no template is
# written and --component-versions is not offered, and the upstream purl table
# is not applied. The rows stay, worded as what to ask the supplier for.
#
# A supplier with no version to give says why, in the reason column of the
# --component-versions file; component-versions.py records it as
# bomlens:versionReason. Those components are listed on the version-needed row
# as explained (explained[]: name and reason) instead of failing it. The
# upstream-purl row lists what the table does not cover but does not block the
# submission: the supplier cannot fix it, and SK Telecom checks those
# separately.
#
# The generic rows count the same components again. For a firmware, root
# filesystem or binary scan this pipeline ran, they defer to the two rows here
# instead of failing on what these rows excuse: name+version on the explained
# components, PURL coverage and no pkg:generic on the explained and the
# no-upstream-purl components, and the transitive row, since such a scan
# records the packages found in delivered files, not a dependency graph. Each
# such row is shown as a warning that says why. A component with neither a
# version nor a reason still fails them. A source scan, and any SBOM under
# --analyze, keeps the generic rows as measured: a missing purl or dependency
# graph is something its supplier can fix.
# --------------------------------------------------------
SUBMIT_FILE="$(basename "$OUT_PREFIX")_bom.json"
SUBMIT_EXCUSE=""
# Which file goes to the reviewer. A scan writes a dozen files, and all of them
# have been sent. Said in the summary for a scan this pipeline produced; under
# --analyze the document under test is already the submission.
SUBMIT_NOTE_FILE=""
if [ "$CONFORMANCE_PROFILE" = "skt-submission" ] && [ "${MODE:-}" != "ANALYZE" ]; then
    SUBMIT_NOTE_FILE="$SUBMIT_FILE"
fi
if [ "$CONFORMANCE_PROFILE" = "skt-submission" ] && [ "$FORMAT" = "CycloneDX" ]; then
    _submit_analyze=false
    [ "${MODE:-}" = "ANALYZE" ] && _submit_analyze=true
    _submit_fwmode=false
    case "${MODE:-}" in FIRMWARE|ROOTFS|BINARY|YOCTO) _submit_fwmode=true ;; esac
    if SUBMIT_ROWS=$(jq -c --argjson cap "$MISSING_CAP" --argjson analyze "$_submit_analyze" --argjson fpOn "$FP_EXEMPT_ON" \
            --arg fwmode "$_submit_fwmode" --arg scanmode "${MODE:-}" \
            --arg tmpl "$(basename "$OUT_PREFIX")_component-versions.template.csv" '
        [ .components[]? | select(.type != "data" and .type != "file" and .type != "operating-system") ] as $pkg
        | ["own-code", "not-open-source", "version-unknown"] as $reasons
        | def reason: [ (.properties // [])[]? | select(.name? == "bomlens:versionReason") | .value ]
                      | map(select(. as $v | $reasons | index($v))) | first;
        # The first-party exemption of the PURL rows (FP_EXEMPT_DEF).
        '"$FP_EXEMPT_DEF"'
        [ $pkg[] | select(((.version // "") | tostring) == "") ] as $versionless
        | [ $versionless[] | select(reason == null) | (.name // "(unnamed)") ] as $nover
        | [ $versionless[] | select(reason != null) | {name: (.name // "(unnamed)"), reason: reason} ] as $explained
        | [ $pkg[] | select(((.version // "") | tostring) != "") | select(first_party_exempt | not)
                   | select(((.purl // "") == "") or ((.purl // "") | test("^pkg:(generic|opkg|openwrt|yocto)/"; "i")))
                   | ((.name // "(unnamed)") + "@" + (.version | tostring)) ] as $noup
        # What the generic rows would still fail on once the explained and the
        # no-upstream-purl components are excused (see the note above).
        | ([ $pkg[] | select((.name == null) or (.version == null)) | select(reason == null) ] | length) as $nv_block
        | ([ $pkg[] | select(.purl == null)
                    | select(((.version // "") | tostring) == "" and reason == null) ] | length) as $purl_block
        | ([ .components[]? | select((.purl // "") | startswith("pkg:generic"))
                            | select(((.type // "library") as $t | ["data", "file", "operating-system"] | index($t)) != null
                                     or (((.version // "") | tostring) == "" and reason == null)) ] | length) as $generic_block
        # Under --analyze, only an SBOM that says a BomLens firmware, root
        # filesystem or binary scan wrote it (bomlens:scanMode, written since
        # that scan began recording it) is judged as one; any other SBOM, an
        # older one included, is judged as measured.
        | ([ (.metadata.properties // [])[]? | select(.name? == "bomlens:scanMode") | .value
             | select(. == "FIRMWARE" or . == "ROOTFS" or . == "BINARY" or . == "YOCTO") ] | first) as $declared_mode
        | (if $fwmode == "true" then $scanmode elif $analyze then ($declared_mode // "") else "" end) as $fw_as
        # Nothing is deferred for an SBOM with no package at all (a file
        # inventory only: the generic rows fail it for naming nothing), nor
        # while any component has neither a version nor a reason.
        | ($fw_as != "" and ($pkg | length) > 0 and ($nover | length) == 0) as $fw
        | {excuse: {nv_block: $nv_block, purl_block: $purl_block, generic_block: $generic_block,
                    explained: ($explained | length), fw: $fw, mode: $fw_as},
           rows:
          [ {id: "versions-needed", label: "Version for every component (version needed)",
             label_ko: "모든 구성요소의 버전 (버전 보충 필요)",
             required: true, source: (if ($pkg | length) == 0 then "na" else "auto" end),
             naKind: (if ($pkg | length) == 0 then "not-applicable" else "" end),
             status: (if ($nover | length) == 0 then "pass" else "fail" end),
             detail: ("\($nover | length) without a version"
                      + (if ($explained | length) > 0 then ", \($explained | length) explained by the supplier" else "" end)),
             missing: ($nover[0:$cap]), explained: ($explained[0:$cap]),
             reviewGuide: (if $analyze then {
               how: "This SBOM lists these components without a version, so they cannot be checked for vulnerabilities. Ask the supplier for the version shipped in the product, in a corrected SBOM: a BomLens firmware, root filesystem or binary scan writes the components it could not read a version for to a template the supplier fills in and passes back with --component-versions. A component the supplier has no version for carries a reason instead (bomlens:versionReason) and is listed as explained.",
               how_ko: "이 SBOM에는 버전이 없는 구성요소가 있어 취약점을 확인할 수 없습니다. 제품에 들어간 버전을 넣은 SBOM을 공급사에 다시 요청합니다. BomLens 펌웨어, 루트 파일시스템, 바이너리 스캔은 버전을 읽지 못한 구성요소를 템플릿 파일로 쓰고, 공급사는 버전을 채운 템플릿을 --component-versions 옵션으로 넘겨 다시 스캔합니다. 공급사가 버전을 알 수 없는 구성요소에는 버전 대신 사유(bomlens:versionReason)가 적히고, 공급사 소명 목록에 따로 표시됩니다.",
               docUrl: "https://sktelecom.github.io/bomlens/guides/supplier-sbom/"}
             elif $scanmode == "YOCTO" then {
               how: "The Yocto build records these packages without a version. Set the version in the recipe of each package (PV), build the image again, and scan the build directory again. A version template and --component-versions do not apply to a Yocto build, whose versions come from the build records.",
               how_ko: "Yocto 빌드 기록에 버전 없이 남은 패키지입니다. 각 패키지 레시피의 버전(PV)을 지정해 이미지를 다시 빌드하고, 빌드 디렉터리를 다시 스캔합니다. Yocto 빌드는 버전을 빌드 기록에서 읽으므로 버전 양식과 --component-versions는 쓰지 않습니다.",
               docUrl: "https://sktelecom.github.io/bomlens/guides/supplier-sbom/"}
             else {
               how: ("The scan found these components but could not read their version. Write the version shipped in the product after each name in " + $tmpl + " (CSV: name,version,reason), then scan again with --component-versions " + $tmpl + ". When there is no version to give, leave it empty and write the reason instead: own-code, not-open-source or version-unknown. A version the scan read from the delivered files is kept."),
               how_ko: ("스캔이 찾았지만 버전을 읽지 못한 구성요소입니다. " + $tmpl + " 파일(CSV, name,version,reason)의 각 이름 뒤에 제품에 들어간 버전을 적고 --component-versions " + $tmpl + " 옵션으로 다시 스캔합니다. 적을 버전이 없으면 버전을 비우고 사유를 적습니다. 사유는 own-code(자체 개발 코드), not-open-source(오픈소스 아님), version-unknown(버전 확인 불가) 중 하나입니다. 스캔이 배포 파일에서 읽은 버전은 그대로 유지됩니다."),
               docUrl: "https://sktelecom.github.io/bomlens/guides/firmware/"} end)},
            {id: "upstream-purl", label: "Upstream purl for every versioned component (no upstream purl, reviewed by SK Telecom)",
             label_ko: "버전이 있는 모든 구성요소의 upstream purl (upstream purl 없음, SK텔레콤 확인)",
             required: false, source: (if ($pkg | length) == 0 then "na" else "auto" end),
             naKind: (if ($pkg | length) == 0 then "not-applicable" else "" end),
             status: (if ($noup | length) == 0 then "pass" else "warn" end),
             detail: "\($noup | length) without an upstream purl", missing: ($noup[0:$cap]),
             reviewGuide: (if $analyze then {
               how: "These components have a version but no purl that names their source repository (none, pkg:generic, pkg:opkg, pkg:openwrt or pkg:yocto), so they cannot be looked up by purl. Ask the supplier for an SBOM that gives each one the purl of its source repository at the release tag, for example by scanning again with a current BomLens firmware, root filesystem or binary scan.",
               how_ko: "버전은 있지만 소스 저장소를 가리키는 purl이 없어(purl 없음, pkg:generic, pkg:opkg, pkg:openwrt, pkg:yocto) purl로 조회할 수 없는 구성요소입니다. 각 구성요소에 릴리스 태그 기준 소스 저장소 purl을 넣은 SBOM을 공급사에 요청합니다. 최신 BomLens로 펌웨어, 루트 파일시스템, 바이너리를 다시 스캔하는 방법이 있습니다.",
               docUrl: "https://sktelecom.github.io/bomlens/guides/supplier-sbom/"}
             else {
               how: "These components have a version but no purl that names their source repository, because the upstream purl table does not cover the project or that version form. This is not for the supplier to fix and does not block the submission: submit the SBOM as it is, and SK Telecom checks these components separately. Do not edit the SBOM by hand.",
               how_ko: "버전은 있지만 소스 저장소를 가리키는 purl이 없는 구성요소입니다. upstream purl 변환표에 해당 프로젝트나 그 버전 형식이 없기 때문입니다. 공급사가 고칠 항목이 아니며 제출을 막지 않습니다. SBOM을 직접 고치지 말고 그대로 제출하면 SK텔레콤이 이 구성요소를 따로 확인합니다.",
               docUrl: "https://sktelecom.github.io/bomlens/guides/firmware/"} end)} ] }
        ' "$SBOM" 2>/dev/null); then
        SUBMIT_EXCUSE=$(printf '%s' "$SUBMIT_ROWS" | jq -c '.excuse')
        CHECKS=$(printf '%s\n%s' "$CHECKS" "$(printf '%s' "$SUBMIT_ROWS" | jq -c '.rows')" | jq -cs 'add')
    else
        echo "[validate] WARN: could not measure the submission next steps; those two rows are omitted." >&2
    fi
fi

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
# Korean wording for every check, carried alongside the English contract.
#
# Registry rows ship label_ko with their elements. The checks this file writes
# itself do not: their labels carry a threshold ("PURL coverage (>= 90%)") or a
# spec version, so they cannot be looked up whole and are matched by pattern
# against the same catalog the reports use. Details are matched the same way.
#
# This runs regardless of REPORT_LANG. The reader's language is chosen in the
# client, long after the scan, so shipping only one language's wording is what
# left the conformance screen showing English prose under a Korean heading for
# the seventeen format checks.
KO_CATALOG="${REPORT_STRINGS_KO:-$(dirname "$0")/i18n/report-strings.ko.json}"
KO_REG="${G7_REGISTRY:-$(dirname "$0")/g7-registry.json}"
KO_REG_CISA="${CISA_REGISTRY:-$(dirname "$0")/cisa-registry.json}"
[ -f "$KO_REG_CISA" ] || KO_REG_CISA="$KO_REG"
if [ -f "$KO_CATALOG" ] && [ -f "$KO_REG" ]; then
    if KO_JOINED=$(printf '%s' "$CHECKS" | jq -c --slurpfile cat "$KO_CATALOG" \
            --slurpfile reg "$KO_REG" --slurpfile reg2 "$KO_REG_CISA" '

      ($cat[0]) as $C
      | (([ ($reg[0], $reg2[0]) | .clusters[].elements[] | select(.label_ko != null) | {(.id): .label_ko} ] | add) // {}) as $RK
      | def llabel($id; $en):
          if ($RK[$id] != null) then $RK[$id]
          elif ($en|test("^Spec version \\(CycloneDX ")) then ($C["conformance.label.spec_cdx"] | gsub("%v%"; ($en|capture("^Spec version \\(CycloneDX (?<v>.+)\\)$").v)))
          elif ($en|test("^Spec version \\(")) then ($C["conformance.label.spec_other"] | gsub("%v%"; ($en|capture("^Spec version \\((?<v>.+)\\)$").v)))
          elif ($en|test("^PURL coverage .*, advisory\\)$")) then ($C["conformance.label.purl"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)) | sub("\\)$"; ", 권고)"))
          elif ($en|test("^PURL coverage ")) then ($C["conformance.label.purl"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          elif ($en|test("^License coverage ")) then ($C["conformance.label.license"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          elif ($en|test("^Hash coverage ")) then ($C["conformance.label.hash"] | gsub("%n%"; ($en|capture("(?<n>[0-9]+)").n)))
          # These four capture the threshold from ">= N%" rather than the first
          # run of digits: "SHA-512 checksum coverage" would otherwise report 512.
          elif ($en|test("^SHA-512 checksum coverage ")) then ($C["conformance.label.sha512"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Component creator coverage ")) then ($C["conformance.label.creator"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Component filename coverage ")) then ($C["conformance.label.filename"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^Source or distribution URI coverage ")) then ($C["conformance.label.artifact_uri"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          elif ($en|test("^File component identifier coverage ")) then ($C["conformance.label.file_identifier"] | gsub("%n%"; ($en|capture(">= (?<n>[0-9]+)%").n)))
          # The advisory namespace row names the types it measured, so its label
          # is built rather than looked up whole.
          elif ($en|test("^PURL namespace for ")) then ($C["conformance.label.purl_ns_advisory"] | gsub("%t%"; ($en|capture("^PURL namespace for (?<t>.+) \\(advisory\\)$").t)))
          else ($C["conformance.label_exact"][$en] // $en) end;
        def ldetail($d):
          if $d=="present" then $C["conformance.detail.present"]
          elif $d=="present (publisher'"'"'s declaration, not verified by BomLens)" then $C["conformance.detail.present_declared"]
          elif $d=="not present in the SBOM" then $C["conformance.detail.not_present"]
          elif $d=="signature requested but failed" then $C["conformance.detail.sign_requested_failed"]
          elif $d=="requires human review (no automated source)" then $C["conformance.detail.review"]
          elif $d=="no packages to measure" then $C["conformance.detail.no_packages"]
          elif $d=="no package components (file inventory only)" then $C["conformance.detail.files_only"]
          elif $d=="no file components" then $C["conformance.detail.no_files"]
          elif $d=="nothing to measure" then $C["conformance.detail.nothing"]
          elif $d=="requires inspecting the delivered files (no automated source in this scan)" then $C["conformance.detail.file_props_review"]
          elif $d=="no machine-learning-model components" then $C["conformance.detail.no_models"]
          elif $d=="not CycloneDX or SPDX" then $C["conformance.detail.not_cdx_spdx"]
          elif $d=="could not evaluate" then $C["conformance.detail.could_not_eval"]
          elif $d=="no components" then $C["conformance.detail.no_subject_components"]
          elif ($d|test("^[0-9]+/[0-9]+ component\\(s\\)$")) then ($d|capture("^(?<a>[0-9]+)/(?<b>[0-9]+)")) as $m | ($C["conformance.detail.subject_components"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+/[0-9]+ model component\\(s\\)$")) then ($d|capture("^(?<a>[0-9]+)/(?<b>[0-9]+)")) as $m | ($C["conformance.detail.model_components"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ tool\\(s\\)$")) then ($C["conformance.detail.tool"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ edge\\(s\\)$")) then ($C["conformance.detail.edge"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ untraceable$")) then ($C["conformance.detail.untraceable"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ malformed$")) then ($C["conformance.detail.malformed"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif $d=="no identifiers of a type that requires a namespace" then $C["conformance.detail.no_ns_purls"]
          elif ($d|test("^[0-9]+ without namespace$")) then ($C["conformance.detail.no_namespace"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ without a version, [0-9]+ explained by the supplier$")) then ($d|capture("^(?<a>[0-9]+) without a version, (?<b>[0-9]+)")) as $m | ($C["conformance.detail.without_version_explained"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ without a version$")) then ($C["conformance.detail.without_version"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ without an upstream purl$")) then ($C["conformance.detail.without_upstream_purl"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ undefined type\\(s\\)$")) then ($C["conformance.detail.undefined_type"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif $d=="purl type list unavailable" then $C["conformance.detail.no_type_list"]
          elif $d=="repository lookup not run" then $C["conformance.detail.resolve_not_run"]
          elif $d=="nothing could be looked up" then $C["conformance.detail.resolve_nothing"]
          elif ($d|test("^[0-9]+ of [0-9]+ not found in the repository$")) then ($d|capture("^(?<a>[0-9]+) of (?<b>[0-9]+)")) as $m | ($C["conformance.detail.resolve_missing"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ found$")) then ($C["conformance.detail.found"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ accepted SPDXVersion line\\(s\\)$")) then ($C["conformance.detail.spdxver"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ package\\(s\\)$")) then ($C["conformance.detail.package"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^names=[0-9]+, versions=[0-9]+$")) then ($d|capture("names=(?<a>[0-9]+), versions=(?<b>[0-9]+)")) as $m | ($C["conformance.detail.names_versions"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ purl ref\\(s\\) for [0-9]+ package\\(s\\)$")) then ($d|capture("^(?<a>[0-9]+) purl ref\\(s\\) for (?<b>[0-9]+)")) as $m | ($C["conformance.detail.purl_refs"]|gsub("%a%";$m.a)|gsub("%b%";$m.b))
          elif ($d|test("^[0-9]+ relationship\\(s\\)$")) then ($C["conformance.detail.relationship"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ license field\\(s\\)$")) then ($C["conformance.detail.license_field"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          elif ($d|test("^[0-9]+ checksum\\(s\\)$")) then ($C["conformance.detail.checksum"]|gsub("%n%";($d|capture("(?<n>[0-9]+)").n)))
          else $d end;
      # A row that carries its own Korean detail (the bsi-* rows) keeps it.
      map(.label_ko = (if (.label_ko // "") != "" then .label_ko else llabel(.id; .label) end)
          | .detail_ko = (if (.detail_ko // "") != "" then .detail_ko
                          else ldetail(.detail)
                               | sub("; (?<n>[0-9]+) first-party component\\(s\\) identified by supplier and SHA-512 instead$";
                                     "; 자체개발 구성요소 \(.n)개는 공급자와 SHA-512로 식별") end))
    ' 2>/dev/null); then
        CHECKS="$KO_JOINED"
    else
        echo "[validate] WARN: Korean labels unavailable; the report stays English." >&2
    fi
fi

# Submission profile: the generic rows defer to the version-needed and
# upstream-purl rows (see "Submission profile" above). Runs after the Korean
# join so the reason can be appended to both detail lines. SUBMIT_RELAXED_MODE
# names the scan mode the SBOM was judged as when any row was deferred, for the
# summary line that tells the reviewer why.
SUBMIT_RELAXED_MODE=""
if [ -n "$SUBMIT_EXCUSE" ]; then
    _checks_before="$CHECKS"
    if DEFERRED=$(printf '%s' "$CHECKS" | jq -c --argjson x "$SUBMIT_EXCUSE" '
        def defer($en; $ko): .status = "warn" | .detail = ((.detail // "") + "; " + $en)
                             | .detail_ko = ((.detail_ko // .detail // "") + "; " + $ko);
        map(if .status != "fail" or (.required | not) or ($x.fw | not) then .
            elif .id == "name-version" and $x.nv_block == 0 then
              defer("\($x.explained) explained by the supplier, see the version-needed row";
                    "공급사 소명 \($x.explained)개, 버전 보충 필요 항목 참고")
            elif .id == "purl" and $x.purl_block == 0 then
              defer("the rest are listed on the version-needed and upstream-purl rows";
                    "나머지는 버전 보충 필요, upstream purl 없음 항목에 표시")
            elif .id == "no-generic" and $x.generic_block == 0 then
              defer("listed on the version-needed and upstream-purl rows";
                    "버전 보충 필요, upstream purl 없음 항목에 표시")
            elif .id == "transitive" and $x.fw then
              defer("a firmware, root filesystem, binary or Yocto build SBOM records the packages found, not a dependency graph";
                    "펌웨어, 루트 파일시스템, 바이너리, Yocto 빌드 SBOM은 의존 관계 그래프 없이 찾은 패키지를 기록함")
            else . end)' 2>/dev/null); then
        CHECKS="$DEFERRED"
        [ "$CHECKS" != "$_checks_before" ] && SUBMIT_RELAXED_MODE=$(printf '%s' "$SUBMIT_EXCUSE" | jq -r '.mode // ""')
    else
        echo "[validate] WARN: could not apply the submission profile to the generic rows; they stay as measured." >&2
    fi
fi

RESULT=$(echo "$CHECKS" | jq -r 'if any(.[]; .required and .status=="fail") then "fail" else "pass" end')
N_FAIL=$(echo "$CHECKS" | jq '[.[] | select(.required and .status=="fail")] | length')
# no-generic is advisory (untraceable-component visibility), counted on its own
# line below rather than folded into the recommended-coverage warnings.
N_WARN=$(echo "$CHECKS" | jq '[.[] | select(.status=="warn" and ((.source // "") != "na") and .id != "no-generic")] | length')
# Two kinds of check carry no automated verdict, and they are not the same
# statement. A review item has something to judge and no automated source for it;
# a not-applicable item has nothing to judge at all, because what it measures is
# absent from this document (no packages, no files, no parts to relate). Neither
# counts as met, and neither counts against the document — but reporting them
# together would call an unmeasurable field "needs review", and counting either
# as a pass would put a document that declares less ahead of one that declares
# more and is measured on it.
N_REVIEW=$(echo "$CHECKS" | jq '[.[] | select((.source // "") == "na" and ((.naKind // "") != "not-applicable"))] | length')
N_NA=$(echo "$CHECKS" | jq '[.[] | select((.naKind // "") == "not-applicable")] | length')
# Untraceable components: count of pkg:generic / custom PURLs (from the no-generic
# check's detail, "N untraceable"). Does NOT affect RESULT — surfaced so a pass
# never hides components that can't be tracked for supply-chain / CVE matching.
N_UNTRACEABLE=$(echo "$CHECKS" | jq -r '([.[] | select(.id=="no-generic")][0].detail // "0") | split(" ")[0] | (tonumber? // 0)')

# --------------------------------------------------------
# pipelineStepsFailed: best-effort post-process steps (normalize,
# CPE/EOL/malicious enrichment, notice generation, and the like) that failed
# during generation are recorded on the SBOM itself by
# docker/lib/pipeline-step.sh's mark_pipeline_warning, one metadata.properties
# entry per failed step (bomlens:pipeline-step-failed). A conformance PASS
# computed over an SBOM whose upstream steps did not all succeed may be
# judging incomplete data, so the report says so as a document-level note --
# never a lowered check status (an artificially lowered, correctly
# computed check reads as an unjust rejection).
#
# Read straight from $SBOM (the document under test itself), not
# OUTPUT_FILE, so an --analyze run sees whatever the submitted document
# already carries. $SBOM is untrusted supplier input there, so the same caps
# used everywhere else in this file apply: MAX_PIPELINE_STEP_LEN chars per
# id, MAX_PIPELINE_STEPS ids kept (the rest counted, not shown). Deduped with
# order preserved -- mirrors server.py's pipeline_steps_seen, kept in sync
# (see #87). A non-JSON document (SPDX Tag-Value), one with no `metadata`, or
# one with no such property all fall through to the same {steps:[],more:0}
# rather than an error.
MAX_PIPELINE_STEP_LEN=100
MAX_PIPELINE_STEPS=20
PIPELINE_STEPS_RESULT=$(jq -c --argjson maxlen "$MAX_PIPELINE_STEP_LEN" --argjson maxn "$MAX_PIPELINE_STEPS" '
  ([ (((.metadata // {}).properties) // [])[]?
     | select(type=="object" and .name=="bomlens:pipeline-step-failed")
     | .value
     | select(type=="string" and length>0)
   ] | .[0:2000]) as $raw
  | (reduce $raw[] as $v ({seen:{}, out:[]};
       if .seen[$v] then . else {seen: (.seen + {($v): true}), out: (.out + [$v])} end)
    ).out as $deduped
  | ($deduped | map(if (length > $maxlen) then .[0:$maxlen] else . end)) as $trimmed
  | {steps: ($trimmed[0:$maxn]), more: ([(($trimmed|length) - $maxn), 0] | max)}
' "$SBOM" 2>/dev/null) || true
[ -n "$PIPELINE_STEPS_RESULT" ] || PIPELINE_STEPS_RESULT='{"steps":[],"more":0}'
PIPELINE_STEPS_FAILED=$(printf '%s' "$PIPELINE_STEPS_RESULT" | jq -c '.steps // []')
PIPELINE_STEPS_FAILED_MORE=$(printf '%s' "$PIPELINE_STEPS_RESULT" | jq -r '.more // 0')

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
            # `failed` is stated rather than left to arithmetic. It used to be
            # absent, and every reader of these four numbers had to work it out as
            # total - present - gap - review — which the web UI did, under the
            # heading "advisory". The most serious category was being displayed
            # under the mildest name.
            | { id: $fid, title: ($meta.title // $fid), source: ($meta.source // ""),
                total:   ($frows|length),
                present: ($frows | map(select(.status=="pass")) | length),
                gap:     ($frows | map(select(.status=="warn" and ((.source//"")!="na"))) | length),
                review:  ($frows | map(select((.source//"")=="na")) | length),
                failed:  ($frows | map(select(.status=="fail")) | length),
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
# Two measurements stated on their own, so --fail-on empty-result and
# --fail-on license-coverage read a value instead of inferring it from a check
# that passes or warns on an empty denominator. Neither changes RESULT nor any
# check. SIGNAL is set per format above (empty when the format was not measured).
[ -n "${SIGNAL:-}" ] || SIGNAL='{}'
jq -n \
   --arg project "$PROJECT" --arg format "$FORMAT" --arg result "$RESULT" \
   --arg ts "$GEN_AT" --argjson checks "$CHECKS" --argjson xwalk "$XW_SUMMARY" \
   --argjson untraceable "$N_UNTRACEABLE" --arg profile "$CONFORMANCE_PROFILE" \
   --argjson pipelineStepsFailed "$PIPELINE_STEPS_FAILED" --argjson pipelineStepsFailedMore "$PIPELINE_STEPS_FAILED_MORE" \
   --argjson signal "$SIGNAL" --arg submitFile "$SUBMIT_NOTE_FILE" --arg relaxedAs "$SUBMIT_RELAXED_MODE" '
{ project: $project, format: $format, result: $result, generatedAt: $ts,
  profile: $profile, untraceableComponents: $untraceable, checks: $checks,
  pipelineStepsFailed: $pipelineStepsFailed, pipelineStepsFailedMore: $pipelineStepsFailedMore }
+ $signal
+ (if $submitFile != "" then { submitFile: $submitFile } else {} end)
+ (if $relaxedAs != "" then { submissionJudgedAs: $relaxedAs } else {} end)
+ (if ($xwalk.frameworks | length) > 0 then { regulatoryCrosswalk: $xwalk } else {} end)
' > "$JSON"

# Bare pass/fail sidecar for --fail-on-conformance (scripts/scan-sbom.sh): a
# single word, so the CLI can gate on it without requiring jq on the host.
printf '%s' "$RESULT" > "${OUT_PREFIX}_conformance.result"

# Closing-summary sidecar for the CLI (scripts/scan-sbom.sh), one "key<TAB>value"
# line per fact, so the host needs no jq. The counts are the SIGNAL measured
# above, the same numbers as the conformance report's top-level fields; only the
# purl share is counted here (CycloneDX only, "-" otherwise). Not written for an
# AI SBOM (no software to count) or when nothing was measured.
rm -f "${OUT_PREFIX}_summary.result"
if [ "${IS_AI:-false}" != true ] && printf '%s' "$SIGNAL" | jq -e 'has("softwareComponentCount")' >/dev/null 2>&1; then
    _sum_purl="-"
    if [ "$FORMAT" = "CycloneDX" ]; then
        # The same package set and rule as the conformance report's purl check:
        # every component except data, file and operating-system ones.
        _sum_purl=$(jq -r '[ .components[]? | select(.type != "operating-system" and .type != "file" and .type != "data") ] as $p
            | if ($p | length) == 0 then "-"
              else (([ $p[] | select(.purl != null) ] | length) * 100 / ($p | length) | floor | tostring) end' "$SBOM" 2>/dev/null) || _sum_purl="-"
    fi
    {
        printf '%s' "$SIGNAL" | jq -r '"components\t\(.softwareComponentCount)",
            "licensed\t\(.licenseCoverage.declared // 0)",
            "licensePercent\t\(.licenseCoverage.pct // "-")"'
        printf 'purlPercent\t%s\n' "${_sum_purl:--}"
        # A shallow fallback analysis and any failed post-processing step are the
        # two reasons a result is smaller than the scan was asked to give. Values
        # come from the SBOM (a supplier's document under --analyze), so every
        # control character is replaced and the length is capped before they can
        # reach a terminal.
        jq -r '((.metadata.properties // [])[]? | select(.name == "bomlens:sbom-tool-degraded") | .value)
               | select(type == "string") | gsub("\\p{Cc}"; " ") | .[0:100] | "reduced\t\(.)"' "$SBOM" 2>/dev/null | head -n 1
        # Manifests that declare dependencies, in a scan that found none.
        jq -r '((.metadata.properties // [])[]? | select(.name == "bomlens:sbom-empty-with-manifests") | .value)
               | select(type == "string") | gsub("\\p{Cc}"; " ") | .[0:200] | "emptyManifests\t\(.)"' "$SBOM" 2>/dev/null | head -n 1
        printf '%s' "$PIPELINE_STEPS_FAILED" | jq -r --argjson more "${PIPELINE_STEPS_FAILED_MORE:-0}" '
            if length > 0 then "failedSteps\t\(map(gsub("\\p{Cc}"; " ") | .[0:100]) | join(", "))\(if $more > 0 then " (and \($more) more)" else "" end)" else empty end' 2>/dev/null
    } > "${OUT_PREFIX}_summary.result" 2>/dev/null
fi

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
MODEL_URL=$(jq -r '[([.metadata.component // empty] + [.components[]?])[]
    | select(.type=="machine-learning-model")
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
    # Registry rows are labelled from the registry that declares them, so a
    # baseline added later is translated by shipping label_ko with its elements
    # and nothing here needs to know its id prefix. The catalog below stays for
    # the checks this file writes itself, whose labels carry a threshold or a
    # spec version and so cannot be looked up whole.
    REG_CISA="${CISA_REGISTRY:-$(dirname "$0")/cisa-registry.json}"
    [ -f "$REG_CISA" ] || REG_CISA="$REG"
    # Localize per-row label + detail into a render copy (status/missing/guidance/
    # evidence/regulations untouched, so the render loops below are unchanged).
    # The Korean label and detail were computed once when the checks were built
    # (see the localization join above) and ride on the rows as label_ko /
    # detail_ko. Rendering is then a swap, so the report and the JSON can never
    # disagree about the wording.
    RCHECKS=$(printf '%s' "$CHECKS" | jq -c '
      map((if (.label_ko // "") != "" then .label = .label_ko else . end)
          | (if (.detail_ko // "") != "" then .detail = .detail_ko else . end)
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
    C_MD_RESULT=$(tfmt conformance.md_result "$RESULT_UP" "$N_FAIL" "$N_WARN" "$N_REVIEW" "$N_NA")
    C_MD_PROFILE=$(tfmt conformance.md_profile "$CONFORMANCE_PROFILE")
    C_MD_UNTRACE=$(tfmt conformance.md_untraceable "$N_UNTRACEABLE")
    C_TH_STATUS=$(kstr conformance.th_status); C_TH_REQMT=$(kstr conformance.th_requirement)
    C_TH_REQD=$(kstr conformance.th_required); C_TH_DETAIL=$(kstr conformance.th_detail)
    C_TH_EVID=$(kstr conformance.th_evidence); C_FIX_SUMMARY=$(kstr conformance.fix_summary)
    C_CHECK_SUMMARY=$(kstr conformance.check_summary)
    C_H2_SUBMIT=$(kstr conformance.h2_submission); C_SUBMIT_INTRO=$(kstr conformance.submission_intro)
    C_H2_CLUSTERS=$(kstr aiprofile.h2_clusters); C_TH_CLUSTER=$(kstr aiprofile.th_cluster)
    C_TH_PRESENT=$(kstr aiprofile.th_present); C_TH_GAP=$(kstr aiprofile.th_gap)
    C_TH_REVIEWCNT=$(kstr aiprofile.th_review); C_TH_TOTAL=$(kstr aiprofile.th_total)
    C_TH_FAILED=$(kstr crosswalk.th_failed)
    C_H2_LIC=$(kstr aiprofile.h2_lic); C_TH_COMP=$(kstr aiprofile.th_component)
    C_TH_VER=$(kstr aiprofile.th_version); C_TH_LIC=$(kstr aiprofile.th_license)
    C_TH_FLAG=$(kstr aiprofile.th_flag); C_LIC_NONE=$(kstr aiprofile.lic_none_html)
    C_H2_G7CHK=$(kstr conformance.h2_g7checks); C_G7CHK_INTRO=$(kstr conformance.g7checks_intro)
    C_H2_MISSING=$(kstr conformance.h2_missing); C_H2_FILL=$(kstr conformance.h2_fill)
    C_H2_EXPLAINED=$(kstr conformance.h2_explained)
    C_H2_REVIEW=$(kstr conformance.h2_review); C_REVIEW_INTRO=$(kstr conformance.review_intro)
    C_FILL_INTRO=$(kstr conformance.fill_intro); C_H2_XWALK=$(kstr conformance.h2_crosswalk)
    C_YES=$(kstr common.yes); C_NO=$(kstr common.no)
    C_REF=$(kstr conformance.reference); C_REF="${C_REF%% *}"   # "참고:" prefix
    C_TH_FRAMEWORK=$(kstr aiprofile.th_framework)
    C_HTML_TITLE=$(tfmt conformance.html_title "$PROJECT_ESC")
    C_KIND=$(kstr conformance.kind); C_H1=$(kstr conformance.h1)
    C_META="$(kstr conformance.meta_project): ${PROJECT_HTML} &middot; $(kstr conformance.meta_generated): $(report_time_html "$GEN_AT") &middot; $(kstr conformance.meta_format): ${FORMAT} &middot; $(kstr conformance.meta_profile): ${CONFORMANCE_PROFILE}"
    C_PILL_RESULT="$(kstr conformance.pill_result) ${RESULT_UP}"
    C_PILL_FAIL=$(kstr conformance.pill_failures); C_PILL_WARN=$(kstr conformance.pill_warnings)
    C_PILL_REVIEW=$(kstr conformance.pill_review); C_PILL_UNTRACE=$(kstr conformance.pill_untraceable)
    C_PILL_NA=$(kstr conformance.pill_na)
else
    C_MD_TITLE="SBOM conformance check — ${PROJECT}"
    C_MD_GEN="- Generated: ${GEN_AT}"
    C_MD_FMT="- Format: ${FORMAT}"
    C_MD_RESULT="- Result: **${RESULT_UP}** (mandatory failures: ${N_FAIL}, warnings: ${N_WARN}, needs review: ${N_REVIEW}, not applicable: ${N_NA})"
    C_MD_PROFILE="- Profile: ${CONFORMANCE_PROFILE}"
    C_MD_UNTRACE="- Untraceable components (pkg:generic / custom PURL): ${N_UNTRACEABLE} — advisory, does not affect the result"
    C_TH_STATUS="Status"; C_TH_REQMT="Requirement"; C_TH_REQD="Required"; C_TH_DETAIL="Detail"
    C_TH_EVID="Evidence / how"; C_FIX_SUMMARY="How to fill this"; C_CHECK_SUMMARY="What to establish"
    C_H2_SUBMIT="SBOM format requirements"
    C_H2_CLUSTERS="G7 minimum elements by cluster"
    C_TH_CLUSTER="Cluster"; C_TH_PRESENT="Present"; C_TH_GAP="Gap"; C_TH_REVIEWCNT="Review"; C_TH_TOTAL="Total"
    C_TH_FAILED="Failed"
    C_H2_LIC="Licenses flagged for review"
    C_TH_COMP="Component"; C_TH_VER="Version"; C_TH_LIC="License"; C_TH_FLAG="Flag"
    C_LIC_NONE="No components carry an AI behavioral-use or non-commercial license flag."
    C_SUBMIT_INTRO="What the SBOM itself has to carry. The same bar applies however the SBOM was produced, and a single mandatory failure makes the overall result a failure."
    C_H2_G7CHK="G7 minimum elements"
    C_G7CHK_INTRO="Advisory elements from the G7 \"Software Bill of Materials for AI — Minimum Elements\". Being advisory they never move the result, and elements with no automated source are marked for review."
    C_H2_MISSING="Missing / non-conformant items"; C_H2_FILL="How to fill the gaps"
    C_H2_EXPLAINED="Explained by the supplier (no version, with a reason)"
    C_H2_REVIEW="What needs a person"; C_REVIEW_INTRO="Items no scan can settle, and what to establish for each."
    C_FILL_INTRO="Each element below is advisory and does not affect the result. The fragment shows the shape that would satisfy it."
    C_H2_XWALK="Regulatory crosswalk"
    C_YES="yes"; C_NO="no"
    C_REF="Reference:"
    C_TH_FRAMEWORK="Framework"
    C_HTML_TITLE="SBOM conformance check — ${PROJECT_ESC}"
    C_KIND="Conformance check"; C_H1="Conformance check report"
    C_META="Project: ${PROJECT_HTML} &middot; Generated: $(report_time_html "$GEN_AT") &middot; Format: ${FORMAT} &middot; Profile: ${CONFORMANCE_PROFILE}"
    C_PILL_RESULT="Result: ${RESULT_UP}"
    C_PILL_FAIL="Mandatory failures:"; C_PILL_WARN="Warnings:"; C_PILL_REVIEW="Needs review:"
    C_PILL_NA="Not applicable:"
    C_PILL_UNTRACE="Untraceable (pkg:generic):"
fi

# Pipeline-steps-failed line for md/html. Built once here, in whichever
# language was chosen above, then just emitted where empty. The step ids come
# straight off $SBOM -- untrusted supplier input under --analyze -- so each is
# escaped/stripped for its target format (never interpolated raw): html gets
# the same &/</> escaping as PROJECT_ESC, wrapped in <code>; md has any
# backtick removed (a literal backtick could otherwise break out of the code
# span) and newlines flattened to spaces. No id-to-check mapping here by
# design -- the finding it names is document-wide, not a specific check.
C_PIPELINE_STEPS_MD=""
C_PIPELINE_STEPS_HTML=""
if [ "$(printf '%s' "$PIPELINE_STEPS_FAILED" | jq 'length')" -gt 0 ]; then
    if [ "$REPORT_LANG" = "ko" ]; then
        _pl_intro=$(kstr conformance.pipeline_steps_intro)
    else
        _pl_intro="Pipeline steps that failed during generation (this SBOM may be incomplete)"
    fi
    _pl_ids_md=$(printf '%s' "$PIPELINE_STEPS_FAILED" | jq -r '
        map(gsub("`";"") | gsub("[\r\n]";" ")) | map("`" + . + "`") | join(", ")')
    _pl_ids_html=$(printf '%s' "$PIPELINE_STEPS_FAILED" | jq -r '
        map(gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("[\r\n]";" "))
        | map("<code>" + . + "</code>") | join(", ")')
    _pl_more=""
    if [ "${PIPELINE_STEPS_FAILED_MORE:-0}" -gt 0 ]; then
        if [ "$REPORT_LANG" = "ko" ]; then
            _pl_more=" $(tfmt conformance.pipeline_steps_more "$PIPELINE_STEPS_FAILED_MORE")"
        else
            _pl_more=" (and ${PIPELINE_STEPS_FAILED_MORE} more)"
        fi
    fi
    C_PIPELINE_STEPS_MD="- ${_pl_intro}: ${_pl_ids_md}${_pl_more}"
    C_PIPELINE_STEPS_HTML="<p class=\"meta pipeline-steps-failed\">${_pl_intro}: ${_pl_ids_html}${_pl_more}</p>"
fi

# The file to submit, for the submission profile (see SUBMIT_NOTE_FILE). The
# name is this run's own output prefix, which the entrypoint restricts to safe
# characters; it is still escaped for HTML.
C_SUBMIT_MD=""
C_SUBMIT_HTML=""
if [ -n "$SUBMIT_NOTE_FILE" ]; then
    _sf_html=$(printf '%s' "$SUBMIT_NOTE_FILE" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    if [ "$REPORT_LANG" = "ko" ]; then
        C_SUBMIT_MD="- $(tfmt conformance.submit_file "\`${SUBMIT_NOTE_FILE}\`")"
        C_SUBMIT_HTML="<p class=\"meta submit-file\">$(tfmt conformance.submit_file "<code>${_sf_html}</code>")</p>"
    else
        C_SUBMIT_MD="- Submit \`${SUBMIT_NOTE_FILE}\` only. The other files in the output folder are for your own review."
        C_SUBMIT_HTML="<p class=\"meta submit-file\">Submit <code>${_sf_html}</code> only. The other files in the output folder are for your own review.</p>"
    fi
fi
# What the BSI profile requires of which components (see bsi_checks).
if [ "$CONFORMANCE_PROFILE" = "bsi-tr-03183-2" ]; then
    if [ "$REPORT_LANG" = "ko" ]; then
        _bn=$(kstr conformance.bsi_profile_note)
    else
        _bn="BSI TR-03183-2 v2.1.0: the fields of section 5.2.2 are required for the components the declaration file added (bomlens:origin), and reported with counts, as advisory, for the components the scan found."
    fi
    C_SUBMIT_MD="${C_SUBMIT_MD:+$C_SUBMIT_MD
}- ${_bn}"
    C_SUBMIT_HTML="${C_SUBMIT_HTML:+$C_SUBMIT_HTML
}<p class=\"meta bsi-profile\">${_bn}</p>"
fi
# Why some general rows read as warnings (see SUBMIT_RELAXED_MODE). The mode is
# one of four fixed words, so it needs no escaping.
if [ -n "$SUBMIT_RELAXED_MODE" ]; then
    if [ "$REPORT_LANG" = "ko" ]; then
        _rx=$(tfmt conformance.submit_judged_as "bomlens:scanMode=${SUBMIT_RELAXED_MODE}")
    else
        _rx="Judged as a BomLens firmware, root filesystem, binary or Yocto build scan SBOM (bomlens:scanMode=${SUBMIT_RELAXED_MODE}), so some general rows are shown as warnings."
    fi
    C_SUBMIT_MD="${C_SUBMIT_MD:+$C_SUBMIT_MD
}- ${_rx}"
    C_SUBMIT_HTML="${C_SUBMIT_HTML:+$C_SUBMIT_HTML
}<p class=\"meta submit-judged\">${_rx}</p>"
fi

# --------------------------------------------------------
# Markdown report
# --------------------------------------------------------
{
    echo "# ${C_MD_TITLE}"
    echo ""
    echo "${C_MD_GEN}"
    echo "${C_MD_FMT}"
    echo "${C_MD_PROFILE}"
    echo "${C_MD_RESULT}"
    [ "${N_UNTRACEABLE:-0}" -gt 0 ] && echo "${C_MD_UNTRACE}"
    [ -n "$C_PIPELINE_STEPS_MD" ] && echo "$C_PIPELINE_STEPS_MD"
    [ -n "$C_SUBMIT_MD" ] && echo "$C_SUBMIT_MD"
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
            "| \(if .status=="pass" then "✅" elif .status=="fail" then "❌" elif (.naKind // "")=="not-applicable" then "—" elif (.source // "")=="na" then "🔍" else "⚠️" end) | \((.label + $reftext) | gsub("[|\n]"; " ")) | "
            + (if $kind=="g7" then "" else "\(if .required then $yes else $no end) | " end)
            + "\(.detail | gsub("[|\n]"; " ")) | \(((.evidence // []) | join(", ")) | gsub("[|\n]"; " ")) |"'
    }
    # Crosswalk roll-up leads the Markdown too, for the same reason it leads the
    # HTML: the reader gets the per-framework picture before the row-by-row detail.
    if [ "$(echo "$RXW" | jq -r '.frameworks | length')" -gt 0 ]; then
        echo "## ${C_H2_XWALK}"
        echo ""
        echo "| ${C_TH_FRAMEWORK} | ${C_TH_PRESENT} | ${C_TH_GAP} | ${C_TH_FAILED} | ${C_TH_REVIEWCNT} | ${C_TH_TOTAL} |"
        echo "|-----------|:-------:|:---:|:------:|:------:|:-----:|"
        echo "$RXW" | jq -r '.frameworks[] |
            "| \(.title | gsub("[|\n]";" ")) | \(.present) | \(.gap) | \(.failed // 0) | \(.review) | \(.total) |"'
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
    # The components the supplier gave a reason for instead of a version
    # (submission profile, version-needed row). Listed whether the row passed or
    # not: the reviewer decides whether to accept each explanation.
    if echo "$RCHECKS" | jq -e 'any(.[]; (.explained // []) | length > 0)' >/dev/null; then
        echo "## ${C_H2_EXPLAINED}"
        echo ""
        echo "$RCHECKS" | jq -r '.[] | select((.explained // []) | length > 0) |
            .explained[] | "- " + (.name | tostring) + ": " + (.reason | tostring)'
        echo ""
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
    # What needs a person: the same notes the HTML shows, for readers of the
    # markdown — which is the copy that gets pasted into a ticket. Same condition,
    # so the two renderings cannot drift into saying different things.
    if echo "$RCHECKS" | jq -e 'any(.[]; (.reviewGuide // null) != null and .status != "pass")' >/dev/null; then
        echo "## ${C_H2_REVIEW}"
        echo ""
        echo "${C_REVIEW_INTRO}"
        echo ""
        echo "$RCHECKS" | jq -r --arg ref "$C_REF" '.[] | select((.reviewGuide // null) != null and .status != "pass") |
            "### \(.label)",
            "",
            .reviewGuide.how,
            "",
            "\($ref) \(.reviewGuide.docUrl)",
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
HTMLHEAD
    report_style
    cat <<HTMLHEAD2
</head><body>
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
$( [ "${N_NA:-0}" -gt 0 ] && echo " <span class=\"pill\">${C_PILL_NA} <span class=\"count\">${N_NA}</span></span>" )
$( [ "${N_UNTRACEABLE:-0}" -gt 0 ] && echo " <span class=\"pill\">${C_PILL_UNTRACE} <span class=\"count\">${N_UNTRACEABLE}</span></span>" )
</div>
$( [ -n "$C_PIPELINE_STEPS_HTML" ] && printf '%s\n' "$C_PIPELINE_STEPS_HTML" )
$( [ -n "$C_SUBMIT_HTML" ] && printf '%s\n' "$C_SUBMIT_HTML" )
HTMLHEAD2
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
            (if (.naKind // "")=="not-applicable" then "s-na"
             elif (.source // "")=="na" then "s-review" else "s-\(.status)" end) as $cls |
            "<tr><td class=\"num\">" + (($i+1)|tostring) + "</td>" +
            "<td class=\"" + $cls + "\">" + (if (.naKind // "")=="not-applicable" then "N/A"
                                              elif (.source // "")=="na" then "REVIEW"
                                              else (.status|ascii_upcase) end|@html) + "</td>" +
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
             elif ((.reviewGuide // null) != null and .status != "pass")
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
        echo "<div class=\"table-wrap\"><table><thead><tr><th>${C_TH_CLUSTER}</th><th>${C_TH_PRESENT}</th><th>${C_TH_GAP}</th><th>${C_TH_REVIEWCNT}</th><th>${C_TH_TOTAL}</th></tr></thead><tbody>"
        echo "$G7_CLUSTERS" | jq -r --arg lang "$REPORT_LANG" '.[] |
            "<tr><td>" + ((if $lang=="ko" then .name_ko else .name end)|@html) + "</td>"
            + "<td>" + (.present|tostring) + "</td><td>" + (.gap|tostring) + "</td>"
            + "<td>" + (.review|tostring) + "</td><td>" + (.total|tostring) + "</td></tr>"'
        echo "$G7_CLUSTERS" | jq -r --arg total "$C_TH_TOTAL" '
            "<tr><td><b>" + ($total|@html) + "</b></td><td><b>" + (map(.present)|add|tostring)
            + "</b></td><td><b>" + (map(.gap)|add|tostring) + "</b></td><td><b>"
            + (map(.review)|add|tostring) + "</b></td><td><b>" + (map(.total)|add|tostring) + "</b></td></tr>"'
        echo "</tbody></table></div>"
        echo "<h2>${C_H2_LIC}</h2>"
        if [ "$(echo "$LIC_REVIEW" | jq 'length')" -gt 0 ]; then
            echo "<div class=\"table-wrap\"><table><thead><tr><th>${C_TH_COMP}</th><th>${C_TH_VER}</th><th>${C_TH_LIC}</th><th>${C_TH_FLAG}</th></tr></thead><tbody>"
            echo "$LIC_REVIEW" | jq -r '.[] |
                "<tr><td>" + (.name|@html) + "</td><td>" + (.version|@html) + "</td>"
                + "<td>" + (.license|@html) + "</td><td>" + (.flag|@html) + "</td></tr>"'
            echo "</tbody></table></div>"
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
        echo "<div class=\"table-wrap\"><table><thead><tr><th>${C_TH_FRAMEWORK}</th><th>${C_TH_PRESENT}</th><th>${C_TH_GAP}</th><th>${C_TH_FAILED}</th><th>${C_TH_REVIEWCNT}</th><th>${C_TH_TOTAL}</th></tr></thead><tbody>"
        echo "$RXW" | jq -r '.frameworks[] |
            "<tr><td>" + (.title|@html)
            + "<br><span class=\"meta\">" + (.source|@html) + "</span></td>"
            + "<td>" + (.present|tostring) + "</td><td>" + (.gap|tostring) + "</td>"
            + "<td>" + ((.failed // 0)|tostring) + "</td>"
            + "<td>" + (.review|tostring) + "</td><td>" + (.total|tostring) + "</td></tr>"'
        echo "</tbody></table></div>"
        echo "<p class=\"meta\">$(echo "$RXW" | jq -r '.disclaimer' | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</p>"
    fi
    echo "<h2>${C_H2_SUBMIT}</h2>"
    echo "<p class=\"meta\">${C_SUBMIT_INTRO}</p>"
    echo "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">#</th><th>${C_TH_STATUS}</th><th>${C_TH_REQMT}</th><th>${C_TH_REQD}</th><th>${C_TH_DETAIL}</th><th>${C_TH_EVID}</th></tr></thead><tbody>"
    html_rows submission
    echo "</tbody></table></div>"
    if echo "$RCHECKS" | jq -e 'any(.[]; .id|startswith("g7-"))' >/dev/null; then
        echo "<h2>${C_H2_G7CHK}</h2>"
        echo "<p class=\"meta\">${C_G7CHK_INTRO}</p>"
        echo "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">#</th><th>${C_TH_STATUS}</th><th>${C_TH_REQMT}</th><th>${C_TH_DETAIL}</th><th>${C_TH_EVID}</th></tr></thead><tbody>"
        html_rows g7
        echo "</tbody></table></div>"
    fi
    if echo "$RCHECKS" | jq -e 'any(.[]; .status!="pass" and (.missing|length>0))' >/dev/null; then
        echo "<h2>${C_H2_MISSING}</h2>"
        echo "$RCHECKS" | jq -r '.[] | select(.status!="pass" and (.missing|length>0)) |
            "<h3>" + (.label|@html) + "</h3><ul class=\"mono\">" + (.missing | map("<li>" + (.|tostring|@html) + "</li>") | join("")) + "</ul>"'
    fi
    if echo "$RCHECKS" | jq -e 'any(.[]; (.explained // []) | length > 0)' >/dev/null; then
        echo "<h2>${C_H2_EXPLAINED}</h2>"
        echo "$RCHECKS" | jq -r '"<ul class=\"mono\">" + ([.[] | select((.explained // []) | length > 0) | .explained[]
            | "<li>" + (.name|tostring|@html) + ": " + (.reason|tostring|@html) + "</li>"] | join("")) + "</ul>"'
    fi
    # The fill-in fragments used to live here as their own section; they now ride
    # in the evidence column of the row they belong to (see above). The Markdown
    # report keeps the section — a table cell cannot hold a code block there.
    echo "</body></html>"
} > "$HTML"

echo "[validate] $FORMAT -> result=$RESULT (mandatory fails=$N_FAIL, warns=$N_WARN, review=$N_REVIEW, n/a=$N_NA, untraceable=$N_UNTRACEABLE): $JSON, $MD, $HTML"
exit 0
