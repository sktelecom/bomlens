#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# normalize-sbom.sh — make a CycloneDX SBOM deterministic (byte-stable).
#
# Usage: normalize-sbom.sh <sbom.json> [--stable]
#   (no flag)  sort components only (stable ordering, timestamps preserved)
#   --stable   also pin metadata.timestamp and drop random serialNumber so that
#              identical inputs produce byte-identical output (CI diff / reproducibility)
set -e

SBOM="$1"
MODE="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[normalize] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[normalize] WARN: $SBOM is not valid JSON; skipping normalization" >&2
    exit 0
fi

TMP="$(mktemp)"

# Always: coerce a missing/null components field to an empty array. cdxgen emits
# components:null when it cannot resolve any component (e.g. a swift tree with no
# Package.resolved), which is spec-invalid — CycloneDX requires components to be an
# array. Apply this first so every later step receives an array.
NULL_FIX='(.components) |= (if type=="array" then . else [] end)'

# Always: drop empty file components. syft's SPDX->CycloneDX conversion turns each
# SPDX file entry into a CycloneDX component of type "file" with NO name and NO
# purl — an unidentifiable noise row (no CVE match, no license, no attribution).
# A supplier SPDX with a large file section (e.g. a 5804-package rootfs SBOM)
# inflates the component set with thousands of these (~5956 on one real input),
# skewing the NOTICE component count and the UI inventory. Drop only components
# that are BOTH a file AND carry neither name nor purl — real packages (which
# always have a name or purl) and named file components are untouched.
DROP_EMPTY_FILES='(.components) |= (if type=="array" then map(select((.type != "file") or ((.name // "") != "") or ((.purl // "") != ""))) else . end)'

# Always: sort components deterministically by purl (fallback name@version).
SORT_FILTER='(.components) |= (if type=="array" then sort_by(.purl // ((.name // "") + "@" + (.version // ""))) else . end)'

# Always: surface the delivered filename as bsi:component:filename. BSI TR-03183-2
# section 5.2.2 (the CRA field guideline) makes the actual filename a required
# per-component field, and the conformance report scores it. syft already records
# where each component was found, in a syft:location:N:path property, but at a
# tool-specific key the conformance check does not read. Copy the basename of the
# first such path to the BSI-conventional key so a value we ALREADY have counts
# toward the field, instead of asking the user to add it by hand.
#
# The catch: syft's location path is where a component was FOUND, which equals the
# component's own file only for a real artifact (a scanned .so / .jar / .deb), not
# for a manifest-declared one — a GitHub Action found in ci.yml, an npm dep found
# in package-lock.json. Writing "ci.yml" as actions/checkout's filename would be a
# wrong value, not a measurement. So the basename is taken ONLY when it looks like
# a distributable artifact: it must end in a known artifact extension (optionally
# followed by a numeric soversion, e.g. libssl.so.3). A manifest path (.yml,
# package-lock.json, requirements.txt, pom.xml, …) has no such extension and is
# skipped, staying a review item rather than being filled with a guess. Scoped:
#   - only when no bsi:component:filename already exists (never overwrite);
#   - basename via the last "/"-segment (rindex), matching how syft writes paths;
#   - only when that basename matches ARTIFACT_EXT_RE.
# cdxgen has no location property at all, so this is a no-op there.
ARTIFACT_EXT_RE='\\.(jar|war|ear|aar|so|a|dll|dylib|deb|rpm|apk|whl|egg|gem|nupkg|tgz|crate|ko|node|pyd|exe|bin)(\\.[0-9]+)*$'
FILENAME_FILTER='(.components) |= (if type=="array" then map(
    if (.properties? // []) | any(.name == "bsi:component:filename") then .
    else ( [ (.properties? // [])[]
             | select((.name | type=="string") and (.name | test("^syft:location:[0-9]+:path$")))
             | .value ]
           | map(select(type=="string" and (. != "")))
           | (.[0] // "") ) as $p
      | if $p == "" then .
        else ($p | (if test("/") then .[(rindex("/")+1):] else . end)) as $base
          | if ($base != "") and ($base | test("'"$ARTIFACT_EXT_RE"'"))
            then .properties = ((.properties // []) + [{name:"bsi:component:filename", value:$base}])
            else .
            end
        end
    end) else . end)'

# Python range-lower-bound de-duplication. For a requirements.txt range dep like
# `flask>=2.0`, cdxgen (after build-prep runs `pip install`) emits TWO components:
# the manifest range LOWER BOUND (Flask@2.0, evidence technique=manifest-analysis,
# carrying a cdx:pypi:versionSpecifiers property) AND the actually-installed version
# (Flask@3.1.3, technique=instrumentation, no specifier). The lower bound is a
# CONSTRAINT, not an installed artifact: it is orphaned from the dependency graph
# yet still gets CVE-matched, so the same package appears at two versions and the
# old lower bound draws phantom vulnerabilities. Drop the lower bound when an
# installed sibling (same name, no specifier) exists. Scoped to pkg:pypi so
# ecosystems where multiple versions of one package legitimately coexist
# (npm/maven diamond deps) are untouched; the $used graph guard keeps any component
# that is actually referenced. Also strips the dropped refs from the dependency graph.
PYRANGE_DEDUP='
  ( [ .components[]?
      | select(((.purl // "") | startswith("pkg:pypi/"))
               and (((.properties // []) | any(.name=="cdx:pypi:versionSpecifiers")) | not))
      | (.name // "" | ascii_downcase) ] | unique ) as $installed
  | ( [ .dependencies[]? | (.ref, (.dependsOn[]?)) ] | unique ) as $used
  | ( [ .components[]?
        | select(((.purl // "") | startswith("pkg:pypi/"))
                 and ((.properties // []) | any(.name=="cdx:pypi:versionSpecifiers"))
                 and ((.name // "" | ascii_downcase) as $nm | ($installed | index($nm)) != null)
                 and ((.["bom-ref"] // .purl // "") as $r | ($used | index($r)) == null))
        | (.["bom-ref"] // .purl) ] | unique ) as $drop
  | .components |= map(select((.["bom-ref"] // .purl // "") as $r | ($drop | index($r)) == null))
  | (if (.dependencies|type)=="array" then
        .dependencies |= ( map(select((.ref // "") as $r | ($drop | index($r)) == null))
                           | map(.dependsOn |= (if type=="array" then map(select(. as $d | ($drop|index($d))==null)) else . end)) )
     else . end)'

# cdxgen can emit spec-invalid swift PURLs: pkg:swift REQUIRES a namespace
# (e.g. pkg:swift/github.com/apple/swift-log@1.0.0), but the root component and
# first-party modules come out as pkg:swift/<name>@<ver> with no namespace. A
# single invalid PURL on the root component makes strict parsers (Trivy) reject
# the WHOLE SBOM ("failed to parse PURL: namespace is required"), so the security
# scan silently produces an empty report. Drop only those invalid purls (the
# component name/version are retained); valid namespaced swift purls are untouched.
PURL_FIX='(.metadata.component) |= (if (has("purl") and (.purl|test("^pkg:swift/[^/]+@"))) then with_entries(select(.key!="purl")) else . end) | (.components) |= (if type=="array" then map(if (has("purl") and (.purl|test("^pkg:swift/[^/]+@"))) then with_entries(select(.key!="purl")) else . end) else . end)'

# Make vendored (SCANOSS-identified) components reachable by the security scan.
# SCANOSS labels C/C++ matches with pkg:github/<owner>/<repo> PURLs, which Trivy
# does NOT use for CVE matching — it matches OS/language PURLs and CPEs. Without a
# CPE these components are identified but carry no vulnerabilities, breaking the
# identify->CVE chain. For components SCANOSS already gave a cpe we leave it alone;
# otherwise we look the version-stripped PURL coordinate up in vendored-purl-map.json
# and synthesize a cpe:2.3 (NVD). Coordinates not in the map (niche libraries with
# no NVD record) keep their PURL and are simply identified, not vuln-matched.
#
# The version goes verbatim into the CPE's version field, so it MUST be CPE-safe:
# a `:` (field separator), space, or wildcard (`*`/`?`) in the version would shift
# or break the 13-field cpe:2.3 grammar and could make Trivy reject the whole SBOM
# (the same failure class as the swift-purl bug above). SCANOSS versions are
# attacker-influenceable (they come from the matched upstream), so only synthesize
# a CPE when the version matches a conservative token; otherwise leave the
# component identified-only (PURL kept, no CPE) rather than emit a malformed one.
VMAP_JSON='{}'
[ -f "$SCRIPT_DIR/vendored-purl-map.json" ] && VMAP_JSON=$(cat "$SCRIPT_DIR/vendored-purl-map.json")
VENDORED_CPE_FIX='(.components) |= (if type=="array" then map(
  if ( ((.properties // []) | map(select(.name=="bomlens:identifiedBy" and .value=="scanoss")) | length) > 0 )
     and (.cpe == null) and (.purl != null)
     and ((.version // "") | test("^[A-Za-z0-9][A-Za-z0-9_.+-]*$"))
  then
    ( .purl | split("@")[0] | split("?")[0] ) as $coord
    | ($vmap[$coord]) as $m
    | (if ($m != null)
        then . + { cpe: ("cpe:2.3:a:" + $m.cpe_vendor + ":" + $m.cpe_product + ":" + .version + ":*:*:*:*:*:*:*") }
        else . end)
  else . end
) else . end)'

# Make OS packages (deb/apk/rpm) matchable by the Trivy security scan. Distro
# advisories (Debian security tracker, Alpine secdb, RPM OVAL) are keyed by the
# SOURCE package name (libssl3 -> openssl), but Trivy only reads the source name
# from its own aquasecurity:trivy:SrcName property — it ignores the `upstream`
# purl qualifier syft emits, and it has no name fallback. On any third-party
# CycloneDX SBOM the OS result therefore comes out with the distro and packages
# fully recognized yet ZERO vulnerabilities, silently (verified against Trivy
# 0.70 and 0.72: distroless debian-12 image scan finds 42 CVEs, the same
# packages via syft SBOM find 0; adding SrcName restores all 42). Synthesize
# the Src* properties from the purl: source name from the `upstream` qualifier
# (percent-decoded; falls back to the package name — dpkg/apk omit the source
# field when it equals the binary name), source version from upstream's
# embedded `@version` when present, else the component version. deb splits
# [epoch:]version[-release] like dpkg; apk keeps the version whole; rpm parses
# the source-RPM filename (name-version-release.src.rpm). Components that
# already carry SrcName (Trivy-generated SBOMs via ANALYZE) are left untouched.
OS_SRC_FIX='
def hexnib: if . >= 97 then . - 87 else . - 48 end;
def pdecode: gsub("%(?<h>[0-9A-Fa-f]{2})"; (.h | ascii_downcase | explode | map(hexnib) | [.[0] * 16 + .[1]] | implode));
def vr_split: . as $v | ($v | rindex("-")) as $i
  | if $i == null then {v: $v, r: ""} else {v: $v[0:$i], r: $v[($i + 1):($v | length)]} end;
def epoch_split: if test("^[0-9]+:") then capture("^(?<e>[0-9]+):(?<rest>.*)$") else {e: null, rest: .} end;
def src_props($sn; $sv; $sr; $se):
  [{name: "aquasecurity:trivy:SrcName", value: $sn},
   {name: "aquasecurity:trivy:SrcVersion", value: $sv}]
  + (if ($sr // "") != "" then [{name: "aquasecurity:trivy:SrcRelease", value: $sr}] else [] end)
  + (if $se != null then [{name: "aquasecurity:trivy:SrcEpoch", value: $se}] else [] end);
(.components) |= (if type=="array" then map(
  (.purl // "") as $p
  | (($p | capture("^pkg:(?<t>deb|apk|rpm)/") | .t) // null) as $ptype
  | if ($ptype != null) and ((.name // "") != "") and ((.version // "") != "")
       and (((.properties // []) | any(.name == "aquasecurity:trivy:SrcName")) | not)
    then
      (($p | capture("[?&]upstream=(?<u>[^&#]+)") | .u | pdecode) // null) as $up
      | (($p | capture("[?&]epoch=(?<e>[0-9]+)") | .e) // null) as $qe
      | (if $ptype == "apk" then
           .properties = ((.properties // [])
             + src_props((if $up then ($up | split("@")[0]) else .name end); .version; ""; null))
         elif $ptype == "rpm" and ($up != null)
              and (($up | endswith(".src.rpm")) or ($up | endswith(".nosrc.rpm"))) then
           ($up | if endswith(".nosrc.rpm") then .[0:(length - 10)] else .[0:(length - 8)] end) as $srpm
           | ($srpm | vr_split) as $nv_r
           | ($nv_r.v | vr_split) as $n_v
           | if $nv_r.r != "" and $n_v.r != "" and $n_v.v != "" then
               .properties = ((.properties // []) + src_props($n_v.v; $n_v.r; $nv_r.r; $qe))
             else
               ((.version | epoch_split) as $es | ($es.rest | vr_split) as $vr
                | .properties = ((.properties // []) + src_props(.name; $vr.v; $vr.r; ($qe // $es.e))))
             end
         else
           (if $up then ($up | split("@")) else [.name] end) as $us
           | (($us[1] // .version) | epoch_split) as $es
           | ($es.rest | vr_split) as $vr
           | .properties = ((.properties // []) + src_props($us[0]; $vr.v; $vr.r; ($qe // $es.e)))
         end)
    else . end
) else . end)'

# Always: normalize component license aliases to SPDX ids. cdxgen records some
# licenses as non-SPDX free text ("Expat license", "Apache License 2.0"); the v1.3
# web UI surfaces (license filter, distribution card, dependency tree) read these
# raw, so the same license splits into several buckets. normalize() (shared with
# generate-notice.sh) maps only recognized aliases — a non-alias string and a
# valid-but-wrong upstream id (e.g. cdxgen mislabeling a package 0BSD) are left
# as-is rather than guessed. Free text that maps to a single SPDX id is promoted
# from .license.name / .expression to a proper .license.id; the source url is kept.
NORMALIZE_DEF="$(cat "$SCRIPT_DIR/spdx-normalize.jq")"
LICENSE_FIX='(.components) |= (if type=="array" then map(
  if (.licenses|type)=="array" then
    .licenses |= map(
      if (has("expression") and (.expression|type)=="string") then
        (normalize(.expression)) as $n |
        (if $n != .expression then {license:{id:$n}} else . end)
      elif ((.license|type)=="object" and (.license.id == null) and ((.license.name // null) != null)) then
        .license |= (normalize(.name) as $n |
          (if $n != .name then ({id:$n} + (if .url then {url:.url} else {} end)) else . end))
      else . end
    )
  else . end
) else . end)'

# Tag components whose declared license needs human review (AI behavioral-use /
# non-commercial) with a bomlens:licenseReview property, so the web UI can badge
# them from structural data. Uses the SAME classifier as the NOTICE's review
# section (license-flags.jq), so badge and notice never disagree. Runs after
# LICENSE_FIX so normalized .license.id is in place; permissive/copyleft are not
# flagged (license_flag returns "" → no property added).
LICENSE_FLAGS_DEF="$(cat "$SCRIPT_DIR/license-flags.jq")"
LICENSE_REVIEW_FIX='(.components) |= (if type=="array" then map(
  ([ (.licenses // [])[] | (.license.id // .license.name // .expression // "") | license_flag(.) ]
    | map(select(. != "")) | (.[0] // "")) as $flag
  | if $flag != "" then
      .properties = (((.properties // []) | map(select(.name != "bomlens:licenseReview")))
        + [{name:"bomlens:licenseReview", value:$flag}])
    else . end
) else . end)'

# Stamp every component with its copyleft-strength class as a
# bomlens:licenseClass property (network-copyleft / strong-copyleft /
# weak-copyleft / permissive / uncategorized), using the SAME classifier the
# web UI computes from (license-flags.jq mirrors licenses.ts), so the SBOM a
# supplier submits, the risk report and the UI badge never disagree. When a
# component carries several licenses the strongest class wins (licenses.ts
# TIER_RANK precedence); no license info means "uncategorized", never
# permissive. Runs after LICENSE_FIX so normalized .license.id is in place.
# Any previous bomlens:licenseClass is replaced and the property is appended
# at a fixed position, so re-runs and --byte-stable output stay byte-identical.
# Orthogonal to bomlens:licenseReview: a component can carry both.
LICENSE_CLASS_FIX='(.components) |= (if type=="array" then map(
  .properties = (((.properties // []) | map(select(.name != "bomlens:licenseClass")))
    + [{name:"bomlens:licenseClass", value: component_license_class}])
) else . end)'

if [ "$MODE" = "--stable" ]; then
    # Reproducible build: pin every timestamp (metadata + annotations + tools),
    # drop random serial number. cdxgen also embeds a human-readable build date
    # inside metadata annotations — normalize that to keep output byte-stable.
    # cdxgen further leaks the random name of the temp virtualenv it builds to
    # resolve python deps (cdxgen-venv-XXXXXX) into component evidence values, so
    # the same input yields a different byte stream each run; pin that suffix too.
    jq -S --argjson vmap "$VMAP_JSON" "
        ${LICENSE_FLAGS_DEF}
        ${NORMALIZE_DEF}
        ${NULL_FIX}
        | ${DROP_EMPTY_FILES}
        | ${PYRANGE_DEDUP}
        | ${PURL_FIX}
        | ${VENDORED_CPE_FIX}
        | ${OS_SRC_FIX}
        | ${LICENSE_FIX}
        | ${LICENSE_REVIEW_FIX}
        | ${LICENSE_CLASS_FIX}
        | ${FILENAME_FILTER}
        | ${SORT_FILTER}
        | walk(if type==\"object\" and has(\"timestamp\") then .timestamp = \"1970-01-01T00:00:00Z\" else . end)
        | walk(if type==\"string\" then gsub(\"cdxgen-venv-[A-Za-z0-9]+\"; \"cdxgen-venv\") else . end)
        | (if (.annotations|type)==\"array\" then
              .annotations |= map(if (.text|type)==\"string\"
                  then .text |= gsub(\"created on [A-Za-z0-9, :]+ with cdxgen\"; \"created on (normalized) with cdxgen\")
                  else . end)
           else . end)
        | del(.serialNumber)
    " "$SBOM" > "$TMP"
else
    jq -S --argjson vmap "$VMAP_JSON" "${LICENSE_FLAGS_DEF} ${NORMALIZE_DEF} ${NULL_FIX} | ${DROP_EMPTY_FILES} | ${PYRANGE_DEDUP} | ${PURL_FIX} | ${VENDORED_CPE_FIX} | ${OS_SRC_FIX} | ${LICENSE_FIX} | ${LICENSE_REVIEW_FIX} | ${LICENSE_CLASS_FIX} | ${FILENAME_FILTER} | ${SORT_FILTER}" "$SBOM" > "$TMP"
fi

mv "$TMP" "$SBOM"
echo "[normalize] normalized: $SBOM (mode=${MODE:-sort-only})"
