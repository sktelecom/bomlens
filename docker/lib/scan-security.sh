#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[security] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! command -v trivy >/dev/null 2>&1; then
    echo "[security] WARN: trivy not installed in this image; skipping security report" >&2
    exit 0
fi

JSON="${OUT_PREFIX}_security.json"
# Trivy's own result, kept apart below only when another engine is merged in.
# A copy left by an earlier run in the same folder is not this run's.
TRIVY_ONLY="${OUT_PREFIX}_security_trivy.json"
rm -f "$TRIVY_ONLY"
MD="${OUT_PREFIX}_security.md"
HTML="${OUT_PREFIX}_security.html"
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[security] running Trivy SBOM scan..."
# Trivy's stderr goes to a file of this run's own: a shared /tmp/trivy.err let
# two scans at once read each other's errors and pick the wrong retry.
TRIVY_ERR=$(mktemp)
trap 'rm -f "$TRIVY_ERR"' EXIT
# --exit-code 0: report-only (never fail the scan pipeline on findings).
trivy_ok=""
trivy_in="$SBOM"
trivy_in_tmp=""
for _attempt in 1 2; do
    if trivy sbom --quiet --format json --output "$JSON" --exit-code 0 "$trivy_in" 2>"$TRIVY_ERR"; then
        trivy_ok=1
        break
    fi
    command -v jq >/dev/null 2>&1 || break
    next="$(mktemp)"
    if grep -qi "invalid specification version" "$TRIVY_ERR" \
       && jq '
           (.specVersion // "") as $s
           # A supplier-submitted SBOM can carry a malformed specVersion (observed:
           # syft2 1.46.0 writing "1.70" instead of "1.7") that Trivy refuses outright.
           # Strip a spurious trailing zero when the shape matches; otherwise fall back
           # to the newest version Trivy is known to accept.
           | .specVersion = (if ($s | test("^[0-9]+\\.[0-9]0$")) then ($s | sub("0$"; ""))
                              else "1.6" end)
         ' "$trivy_in" > "$next" 2>/dev/null; then
        echo "[security] Trivy rejected the SBOM's specVersion (\"$(jq -r '.specVersion' "$trivy_in")\"); re-ran with it normalized for Trivy input (delivered SBOM unchanged)."
    elif grep -qi "unmarshal component type\|unsupported type" "$TRIVY_ERR" \
       && jq '.metadata.component.type = "application"' "$trivy_in" > "$next" 2>/dev/null; then
        # Trivy 0.70's CycloneDX decoder rejects some valid-but-newer ROOT component
        # types ("firmware" from a firmware scan is CycloneDX 1.4+), failing the whole
        # decode with "unsupported type". Retry with the root coerced to a type Trivy
        # accepts; the delivered SBOM keeps its accurate type — only Trivy's input copy
        # is remapped, and component types are left untouched, so vulnerability
        # matching is unaffected.
        echo "[security] Trivy could not decode the SBOM's root component type; re-ran with it coerced to 'application' for Trivy input (delivered SBOM unchanged)."
    else
        rm -f "$next"
        break
    fi
    [ -n "$trivy_in_tmp" ] && rm -f "$trivy_in_tmp"
    trivy_in="$next"
    trivy_in_tmp="$next"
done
[ -n "$trivy_in_tmp" ] && rm -f "$trivy_in_tmp"

if [ -z "$trivy_ok" ] && grep -qi "multiple types of OS packages" "$TRIVY_ERR" && command -v jq >/dev/null 2>&1; then
    # Trivy's SBOM decoder refuses a CycloneDX document whose OS packages span more
    # than one package-manager family (e.g. an rpm base merged with a deb or apk
    # layer) — it can't tell which single OS the packages belong to. merge-sbom.sh
    # produces exactly this shape for layered images that mix bases, so the whole
    # scan (every purl type, not just the OS packages) would otherwise fail. Work
    # around it by scanning once per OS family present — each pass keeps every
    # non-OS-package component plus only that family's OS packages — and unioning
    # the results; the delivered SBOM is untouched, only Trivy's input copies split.
    os_types=$(jq -r '
        [ .components[]? | (.purl // "")
          | select(test("^pkg:(rpm|deb|apk)/"))
          | capture("^pkg:(?<t>rpm|deb|apk)/").t ]
        | unique | .[]' "$SBOM" 2>/dev/null)
    if [ -n "$os_types" ]; then
        split_outs=()
        for t in $os_types; do
            split_in="$(mktemp)"; split_out="$(mktemp)"
            jq --arg t "$t" '
                .components = [ .components[]
                    | select((((.purl // "") | test("^pkg:(rpm|deb|apk)/")) | not)
                              or ((.purl // "") | test("^pkg:" + $t + "/"))) ]
            ' "$SBOM" > "$split_in" 2>/dev/null
            if trivy sbom --quiet --format json --output "$split_out" --exit-code 0 "$split_in" 2>>"$TRIVY_ERR"; then
                split_outs+=("$split_out")
            else
                rm -f "$split_out"
            fi
            rm -f "$split_in"
        done
        if [ "${#split_outs[@]}" -gt 0 ]; then
            # Every split keeps the full non-OS component set, so a non-OS finding
            # (e.g. a maven CVE) is independently redetected in each split and would
            # appear once per OS family without this — dedup by (Target,
            # purl-or-pkg, CVE) while keeping each Target's findings grouped.
            jq -s '
                [ .[].Results[]? ]
                | group_by(.Target)
                | map({
                    Target: .[0].Target,
                    Class: .[0].Class,
                    Vulnerabilities: ([ .[].Vulnerabilities[]? ]
                        | group_by(((.PkgIdentifier // {}).PURL // .PkgName // "") + "|" + (.VulnerabilityID // ""))
                        | map(.[0]))
                  })
                | { Results: . }
            ' "${split_outs[@]}" > "$JSON" 2>/dev/null \
                && trivy_ok=1
            echo "[security] Trivy rejected the SBOM's mixed OS package families ($(echo "$os_types" | tr '\n' ' ')); re-ran once per family and merged the results (delivered SBOM unchanged)."
        fi
        rm -f "${split_outs[@]}"
    fi
fi
if [ -z "$trivy_ok" ]; then
    echo "[security] WARN: Trivy scan failed:" >&2
    cat "$TRIVY_ERR" >&2
    # Emit an empty-but-valid report so downstream steps don't break, but record
    # the failure in the report itself (ScanError): an empty Results array is
    # otherwise indistinguishable from a clean "0 vulnerabilities" result, and
    # consumers have misread failed scans (DB download failure, undecodable
    # SBOM) as a pass. Trivy prints its fatal reason as the last stderr line.
    ERR_MSG=$(tr -d '\000\r' < "$TRIVY_ERR" | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-400)
    jq -n --arg msg "${ERR_MSG:-trivy sbom exited with an error}" \
        '{Results: [], ScanError: {Engine: "Trivy", Message: $msg}}' > "$JSON"
fi

# Ensure .Results exists even when Trivy omits it (e.g. SBOM with no components).
if ! jq -e 'has("Results")' "$JSON" >/dev/null 2>&1; then
    tmp_r="$(mktemp)"
    if jq '. + {Results: []}' "$JSON" > "$tmp_r" 2>/dev/null; then mv "$tmp_r" "$JSON"; else echo '{"Results":[]}' > "$JSON"; rm -f "$tmp_r"; fi
fi

# Deep-CVE (opt-in image): run grype's CPE matcher for the NVD-only maven CVEs
# Trivy misses (older Apache libs whose CVEs live in NVD keyed by CPE, absent from
# the GitHub Security Advisory data Trivy uses for maven). scan-nvd-cpe.py drops a
# ${OUT_PREFIX}_security_grype.json sidecar in the same .Results[].Vulnerabilities[]
# shape. grype is only in the deep-cve image, so this is a no-op elsewhere; the
# script also self-skips when grype is absent. Disable with DEEP_CVE=false.
if command -v grype >/dev/null 2>&1 && [ "${DEEP_CVE:-true}" != "false" ]; then
    python3 "$SCRIPT_DIR/scan-nvd-cpe.py" "$SBOM" "$OUT_PREFIX" \
        || echo "[security] WARN: grype CPE (deep-cve) scan failed; reporting Trivy results only." >&2
fi

# Merge Trivy-shaped CVE sidecars from other engines, if present:
#   _security_cvebintool.json: components with no package purl, matched by CPE
#                                against the bundled NVD index (match-cpe-index.sh)
#   _security_grype.json       — deep-cve maven NVD-CPE findings (grype)
# Each already carries the .Results[].Vulnerabilities[] contract, so we append its
# Results to Trivy's; the FINDINGS dedup above collapses any (purl, cve) overlap so
# the report and its counts read one unified, non-double-counted file.
#   _security_yocto.json       — the CVEs a Yocto build left unresolved: VEX
#                                statements from an SPDX 3.0 document
#                                (parse-yocto-spdx.py), or cve-check's Unpatched
#                                entries when the build published no SPDX
#                                (parse-yocto-manifests.py). The ones the build
#                                patched or judged not applicable are counted in
#                                _yocto_vex.json instead of listed here.
for engine in cvebintool grype yocto; do
    SIDECAR="${OUT_PREFIX}_security_${engine}.json"
    [ -f "$SIDECAR" ] && jq -e '.Results' "$SIDECAR" >/dev/null 2>&1 || continue
    SIDE_N=$(jq '[.Results[].Vulnerabilities[]?] | length' "$SIDECAR" 2>/dev/null || echo 0)
    [ "${SIDE_N:-0}" -gt 0 ] || continue
    # Keep Trivy's own output apart before the first merge: a program that runs
    # this image as its scan engine reads one engine's results (the
    # vulnerabilities.trivy output in bomlens-result.json). Without a sidecar
    # there is no copy, and _security.json itself is Trivy's output.
    [ -f "$TRIVY_ONLY" ] || cp "$JSON" "$TRIVY_ONLY"
    tmp_m="$(mktemp)"
    # Append the sidecar's Results but drop any (purl-or-name, cve) already present
    # in the accumulated report, so the raw _security.json is de-duplicated at the
    # source — the web layer reads it directly and must not double-count grype/Trivy
    # overlap. (The FINDINGS dedup above independently protects the rendered report.)
    if jq -s '
        def key: (((.PkgIdentifier // {}).PURL // .PkgName) // "") + "|" + (.VulnerabilityID // "");
        (.[0].Results // []) as $base
        | ([ $base[].Vulnerabilities[]? | key ] | unique) as $seen
        | { Results: ($base + [ .[1].Results[]
              | .Vulnerabilities = [ (.Vulnerabilities // [])[] | select((. | key) as $k | ($seen | index($k)) | not) ] ]) }
          + (.[0] | del(.Results))' "$JSON" "$SIDECAR" > "$tmp_m" 2>/dev/null; then
        KEPT_N=$(jq '[.Results[].Vulnerabilities[]?] | length' "$tmp_m" 2>/dev/null || echo 0)
        PREV_N=$(jq '[.Results[].Vulnerabilities[]?] | length' "$JSON" 2>/dev/null || echo 0)
        mv "$tmp_m" "$JSON"
        echo "[security] merged $((KEPT_N - PREV_N)) new ${engine} CVE(s) (of ${SIDE_N}; overlap deduped) from $(basename "$SIDECAR")."
    else
        rm -f "$tmp_m"
        echo "[security] WARN: failed to merge ${engine} sidecar; reporting prior results only." >&2
    fi
done

# --- Go reachability (--reachability) ------------------------------------------
#
# The step before this one (reachability.sh) wrote govulncheck's judgements as a
# CycloneDX VEX. Each finding it covers, matched on the advisory id (the CVE or
# one of its references) and the component (purl, else module path and
# version), carries the judgement as "bomlens:reachability" in _security.json,
# and the document has a Reachability summary. A finding judged not_affected
# (code_not_reachable) is listed on its own below and left out of the totals,
# as the kernel's advisories are: it is shown, not dropped. A finding with no
# judgement (not a Go advisory, or one govulncheck does not know) is unchanged.
REACH_DOC="${REACHABILITY_DOC:-}"
if [ -n "$REACH_DOC" ] && [ -f "$REACH_DOC" ] && jq -e '.vulnerabilities | type == "array"' "$REACH_DOC" >/dev/null 2>&1; then
    tmp_r="$(mktemp)"
    if jq --slurpfile vex "$REACH_DOC" --arg doc "$(basename "$REACH_DOC")" '
        def np: (. // "") | tostring | sub("[?#].*$"; "") | ascii_downcase;
        def nv: (. // "") | sub("^(go|v)(?=[0-9])"; "");
        def modkey: np | sub("^pkg:golang/"; "") | (split("@") | (.[0:-1] | join("@")) + "@" + (.[-1] | nv));
        ($vex[0]) as $v
        | ([ $v.components[]? | {key: (.["bom-ref"] // .purl // ""), value: (.purl // "")} ] | from_entries) as $purls
        | ([ $v.vulnerabilities[]? as $x
             | ([$x.id] + [$x.references[]?.id]) as $ids
             | $x.affects[]? | ($purls[.ref] // "") as $p | select($p != "")
             | $ids[] as $id
             | ({key: (($p | np) + "|" + $id), value: $x},
                {key: (($p | modkey) + "|" + $id), value: $x}) ]
           | from_entries) as $map
        | ($v.metadata.properties // [] | map(select(.name == "bomlens:reachability:mode")) | .[0].value // "") as $mode
        | .Results = [ (.Results // [])[] | .Vulnerabilities = [ (.Vulnerabilities // [])[]
            | ((.PkgIdentifier // {}).PURL // "") as $tp
            | (.VulnerabilityID // "") as $id
            | ($map[($tp | np) + "|" + $id]
               // $map[((.PkgName // "") | ascii_downcase) + "@" + (.InstalledVersion | nv) + "|" + $id]) as $x
            | if $x then . + {"bomlens:reachability": ({state: $x.analysis.state}
                  + (if $x.analysis.justification then {justification: $x.analysis.justification} else {} end)
                  + {detail: ($x.analysis.detail // ""),
                     level: ([$x.properties[]? | select(.name == "bomlens:reachability:level") | .value][0] // null),
                     engine: "govulncheck", mode: $mode})}
              else . end ] ]
        | .Reachability = {Engine: "govulncheck", Mode: $mode, Document: $doc}
      ' "$JSON" > "$tmp_r" 2>/dev/null; then
        mv "$tmp_r" "$JSON"
    else
        rm -f "$tmp_r"
        echo "[security] WARN: could not apply the reachability judgements; the report lists every finding as reported." >&2
    fi
fi

# Flatten findings: id, pkg, version, severity, fixed, cvss, title.
# cvss = highest V3 (fallback V2) score across Trivy's CVSS sources.
FINDINGS=$(jq -r '
  [ .Results[]?.Vulnerabilities[]? | {
      id: .VulnerabilityID,
      pkg: .PkgName,
      purl: ((.PkgIdentifier // {}).PURL // ""),
      version: .InstalledVersion,
      severity: (.Severity // "UNKNOWN"),
      fixed: (.FixedVersion // ""),
      cvss: ([ (.CVSS // {}) | to_entries[] | .value | (.V3Score // .V2Score) ]
              | map(select(. != null)) | (max // null)),
      title: (.Title // .Description // "" | .[0:120]),
      # deep-cve: a grype CPE match whose NVD version range was not verified
      # (SECURITY_NVD_VERIFY off / NVD unreachable). Surfaced so the reader sees
      # which findings may be loose-version false positives.
      unverified: (.["bomlens:cpeVersionUnverified"] // false),
      # --reachability: govulncheck judgement (null when there is none).
      reach: ((.["bomlens:reachability"] // {}).state // null),
      reach_detail: ((.["bomlens:reachability"] // {}).detail // "")
    } ]
  # Dedup by (purl-or-name, CVE): when the deep-CVE grype pass and Trivy both
  # report the same finding they must count once. purl is the stable key across
  # engines; fall back to the package name when a finding carries no purl.
  | unique_by([ (if .purl != "" then .purl else .pkg end), .id ])
' "$JSON" 2>/dev/null || echo '[]')

# --- The kernel is counted separately -----------------------------------------
#
# A rootfs carries one kernel, and an old one carries thousands of advisories:
# measured on two consumer router images, 5,262 and 5,032 CVEs against a single
# component. Nearly all of them are for subsystems that image never compiled in,
# and there is no way to tell which from the SBOM. Left in the table they bury
# every finding a reader can act on, and left in the severity totals they make a
# device with two real criticals read the same as one with two thousand.
#
# So they are reported, but on their own: a count in the summary and a list of
# their own, out of the table and out of the totals. The names are a closed list,
# matched exactly — the kernel arrives under different names depending on which
# pass found it: `linux_kernel` from a signature checker, `kernel` from an opkg or
# rpm database, and `linux-kernel` or `linux` from an advisory feed.
KERNEL_FINDINGS=$(echo "$FINDINGS" | jq '
  [ .[] | select((.pkg // "" | ascii_downcase)
                 | IN("linux_kernel", "linux-kernel", "kernel", "linux")) ]')
FINDINGS=$(echo "$FINDINGS" | jq '
  [ .[] | select(((.pkg // "" | ascii_downcase)
                  | IN("linux_kernel", "linux-kernel", "kernel", "linux")) | not) ]')
KERNEL_TOTAL=$(echo "$KERNEL_FINDINGS" | jq 'length')

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

# Findings govulncheck judged not reachable: listed apart, out of the totals
# (see the reachability block above). Split after the EPSS lookup so the
# sidecar covers them too.
UNREACHED_FINDINGS=$(echo "$FINDINGS" | jq '[ .[] | select(.reach == "not_affected") ]')
FINDINGS=$(echo "$FINDINGS" | jq '[ .[] | select(.reach != "not_affected") ]')
UNREACHED_N=$(echo "$UNREACHED_FINDINGS" | jq 'length')
REACHED_N=$(echo "$FINDINGS" | jq '[ .[] | select(.reach == "exploitable") ] | length')
if jq -e 'has("Reachability")' "$JSON" >/dev/null 2>&1; then
    tmp_rs="$(mktemp)"
    if jq --argjson na "$UNREACHED_N" --argjson ex "$REACHED_N" \
        '.Reachability += {NotAffected: $na, Exploitable: $ex}' "$JSON" > "$tmp_rs" 2>/dev/null; then
        mv "$tmp_rs" "$JSON"
    else
        rm -f "$tmp_rs"
    fi
fi

# Failure marker written above (survives the sidecar merge, which keeps every
# non-Results key). Non-empty => the Trivy findings are missing, not zero.
SCAN_ERR=$(jq -r '.ScanError.Message // empty' "$JSON" 2>/dev/null)

# --- Components no check could reach -------------------------------------------
#
# Trivy reads a package purl; the CPE index (match-cpe-index.sh, run before this
# for firmware, rootfs and binary scans, BOMLENS_CPE_INDEX_MATCHED=true) reads a
# CPE. A component with neither that a check used, or with no version at all,
# was never asked about, so an empty table says nothing about it. They are
# named in the report and kept in _security.json as UncheckedComponents for the
# web layer and the risk report. A component that has a finding was checked by
# definition (a grype CPE match, for one), matched on purl or on name and
# version. A Yocto build's recipes were checked by the build's own cve-check
# when _yocto_vex.json holds its judgements (an --analyze of a Yocto SBOM or
# build directory), so they are not listed. The classifier is vuln-coverage.jq,
# shared with match-cpe-index.sh. Not computed when the scan itself failed: the
# failure note already says nothing was checked.
UNCHECKED='[]'
if [ -z "$SCAN_ERR" ] && [ -f "$SCRIPT_DIR/vuln-coverage.jq" ]; then
    _cpe_matched=false
    if [ "${BOMLENS_CPE_INDEX_MATCHED:-false}" = "true" ]; then
        _cpe_matched=true
    fi
    _yocto_checked=false
    if [ -f "${OUT_PREFIX}_yocto_vex.json" ] \
       && jq -e '([(.judgements // {})[]? | numbers] | add // 0) + (.unresolved // 0) > 0' \
            "${OUT_PREFIX}_yocto_vex.json" >/dev/null 2>&1; then
        _yocto_checked=true
    fi
    # Through a file: an old kernel's advisories make this list larger than one
    # command-line argument may be.
    _found="$(mktemp)"
    { echo "$FINDINGS"; echo "$KERNEL_FINDINGS"; echo "$UNREACHED_FINDINGS"; } | jq -cs \
        '[add[] | (.purl // ""), (((.pkg // "") + "|" + (.version // "")) | ascii_downcase)]
         | map(select(. != "" and . != "|")) | unique' > "$_found" 2>/dev/null || echo '[]' > "$_found"
    UNCHECKED=$(jq -c --argjson cm "$_cpe_matched" --argjson yc "$_yocto_checked" --slurpfile foundf "$_found" \
        "$(cat "$SCRIPT_DIR/vuln-coverage.jq")"' ($foundf[0] // []) as $found
        | [ (.components // [])[] | recurse(.components[]?)
          | select(vc_in_scope)
          | (.purl // "") as $p | (((.name // "") + "|" + vc_version) | ascii_downcase) as $n
          | select((($p != "" and ($p | IN($found[]))) or ($n | IN($found[]))) | not)
          | . as $c | (vc_unchecked_reason($cm; $yc)) as $r
          | {Name: $c.name, Version: ($c.version // ""), PURL: ($c.purl // ""), Reason: $r} ]
        | unique_by([.Name, .Version, .Reason])' "$SBOM" 2>/dev/null || echo '[]')
    rm -f "$_found"
    [ -n "$UNCHECKED" ] || UNCHECKED='[]'
    tmp_u="$(mktemp)"
    if echo "$UNCHECKED" | jq --slurpfile j "$JSON" \
        '. as $u | $j[0] + {UncheckedComponents: {Count: ($u | length), Components: $u}}' \
        > "$tmp_u" 2>/dev/null; then mv "$tmp_u" "$JSON"; else rm -f "$tmp_u"; fi
fi
UNCHECKED_N=$(echo "$UNCHECKED" | jq 'length')
# The report lists at most this many; the rest are in _security.json.
UNCHECKED_MAX=200

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
    if [ -n "$SCAN_ERR" ]; then
        echo "> The vulnerability scan did not complete, so this report does not reflect the target's actual exposure."
        echo ">"
        echo "> Error: \`${SCAN_ERR}\`"
        echo ""
    fi
    if [ "$ENRICHED" = "true" ]; then
        echo "- Actively exploited (CISA KEV): **${KEV_COUNT}**"
        echo "- Priority order: KEV first, then severity, then EPSS (exploit probability)."
        echo ""
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "- Could not be checked: **${UNCHECKED_N}** component(s), listed below. No vulnerability"
        echo "  database was asked about them, so the counts above do not cover them."
        echo ""
    fi
    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "- Not reachable: **${UNREACHED_N}** finding(s), listed separately below and not"
        echo "  included in the counts above. govulncheck found that the affected Go code is"
        echo "  not called (source) or not in the executable (binary); each is recorded as"
        echo "  \`not_affected\` (\`code_not_reachable\`) in \`$(basename "${REACH_DOC:-reachability.cdx.json}")\`."
        echo ""
    fi
    if [ "${KERNEL_TOTAL:-0}" -gt 0 ]; then
        echo "- Kernel advisories: **${KERNEL_TOTAL}**, listed separately below and not"
        echo "  included in the counts above. Most advisories against a kernel are for"
        echo "  subsystems a given device never compiled in, and the SBOM cannot tell which,"
        echo "  so counting them here would bury the findings this report exists to show."
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
            " | \(.id)\(if .unverified then " †" else "" end)\(if .reach == "exploitable" then " ‡" else "" end) | \(.pkg) | \(.version) | \(.fixed) |"'
        # Footnote only when at least one finding is version-unverified.
        if echo "$FINDINGS" | jq -e 'any(.[]; .unverified)' >/dev/null 2>&1; then
            echo ""
            echo "† CPE-matched against NVD but the version range was not verified (deep-cve; set \`SECURITY_NVD_VERIFY=true\` with network + \`NVD_API_KEY\` to drop loose-version false positives)."
        fi
        if [ "${REACHED_N:-0}" -gt 0 ]; then
            echo ""
            echo "‡ Reached: govulncheck found a call path to the affected Go code (source) or the affected symbol in the executable (binary)."
        fi
    elif [ -n "$SCAN_ERR" ]; then
        echo "_Scan failed — no results were produced._"
    elif [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "_No vulnerability was found in the components that were checked. ${UNCHECKED_N} component(s) could not be checked; they are listed below._"
    elif [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "_No reachable vulnerability was found. ${UNREACHED_N} finding(s) are not reachable; they are listed below._"
    else
        echo "_No known vulnerabilities found._"
    fi
    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo ""
        echo "## Not reachable"
        echo ""
        echo "govulncheck judged that the code these advisories name is not reached. They are"
        echo "recorded as \`not_affected\` with \`code_not_reachable\` in"
        echo "\`$(basename "${REACH_DOC:-reachability.cdx.json}")\`, and are not in the counts above."
        echo ""
        echo "| Severity | CVSS | CVE | Package | Installed | Fixed | Why |"
        echo "|----------|-----:|-----|---------|-----------|-------|-----|"
        echo "$UNREACHED_FINDINGS" | jq -r 'def cell: tostring | gsub("[|\n]"; " ");
            sort_by({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)[] |
            "| \(.severity) | \(.cvss // "") | \(.id) | \(.pkg) | \(.version) | \(.fixed) | \(.reach_detail | cell) |"'
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo ""
        echo "## Components that could not be checked"
        echo ""
        echo "${UNCHECKED_N} component(s) could not be checked against a vulnerability database:"
        echo "they have no version, or no package purl and no CPE that was matched. A clean"
        echo "result does not cover them."
        echo ""
        echo "| Component | Version | PURL | Reason |"
        echo "|-----------|---------|------|--------|"
        echo "$UNCHECKED" | jq -r --argjson max "$UNCHECKED_MAX" 'def cell: tostring | gsub("[|\n]"; " ");
            .[0:$max][] |
            "| \(.Name | cell) | \(.Version | cell) | \(.PURL | cell) | \({"no-version": "no version", "no-identifier": "no package purl or matched CPE"}[.Reason] // .Reason) |"'
        if [ "$UNCHECKED_N" -gt "$UNCHECKED_MAX" ]; then
            echo ""
            echo "… and $((UNCHECKED_N - UNCHECKED_MAX)) more, listed in \`UncheckedComponents\` in \`$(basename "$JSON")\`."
        fi
    fi
    if [ "${KERNEL_TOTAL:-0}" -gt 0 ]; then
        echo ""
        echo "## Kernel advisories"
        echo ""
        echo "These are the advisories filed against the kernel this image carries. They"
        echo "are here rather than in the table above because a kernel accumulates"
        echo "thousands of them and most concern subsystems a given device never built."
        echo "Read them against the kernel configuration, not as a list to work through."
        echo ""
        echo "| Severity | CVSS | CVE | Package | Installed | Fixed |"
        echo "|----------|-----:|-----|---------|-----------|-------|"
        echo "$KERNEL_FINDINGS" | jq -r 'sort_by(
            {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)[] |
            "| \(.severity) | \(.cvss // "") | \(.id) | \(.pkg) | \(.version) | \(.fixed) |"'
    fi
} > "$MD"

# ---------- HTML ----------
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
PROJECT_ESC="$(esc "$PROJECT")"
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Security Report — ${PROJECT_ESC}</title>
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
<p class="meta">Project: ${PROJECT_ESC} &middot; Generated: ${GEN_AT} &middot; Engine: Trivy</p>
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
    if [ -n "$SCAN_ERR" ]; then
        ERR_HTML=$(printf '%s' "$SCAN_ERR" | jq -Rr '@html')
        echo "<div class=\"note\"><b>Scan failed.</b> The vulnerability scan did not complete, so this report does not reflect the target's actual exposure.<br><code>${ERR_HTML}</code></div>"
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "<div class=\"note\"><b>${UNCHECKED_N} component(s) could not be checked</b> and are listed below. No vulnerability database was asked about them, so the counts above do not cover them.</div>"
    fi
    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "<div class=\"note\"><b>${UNREACHED_N} finding(s) are not reachable</b> and are listed at the end of this report, not in the counts above. govulncheck found that the affected Go code is not called (source) or not in the executable (binary); each is recorded as <code>not_affected</code> (<code>code_not_reachable</code>) in <code>$(esc "$(basename "${REACH_DOC:-reachability.cdx.json}")")</code>.</div>"
    fi
    if [ "${KERNEL_TOTAL:-0}" -gt 0 ]; then
        echo "<div class=\"note\"><b>${KERNEL_TOTAL} kernel advisories</b> are listed at the end of this report and are not included in the counts above. Most advisories against a kernel are for subsystems a given device never compiled in, and the SBOM cannot tell which, so counting them here would bury the findings this report exists to show.</div>"
    fi

    if [ "$TOTAL" -gt 0 ]; then
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>KEV</th><th>CVSS</th><th>EPSS</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>"
        echo "$FINDINGS" | jq -r '.[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td>" + (if .kev then "<span class=\"kevbadge\">KEV</span>" else "" end) + "</td>" +
            "<td class=\"num\">" + ((.cvss // "" )|tostring|@html) + "</td>" +
            "<td class=\"num\">" + (if .epss then ((.epss*1000|floor)/1000|tostring) else "" end) + "</td>" +
            "<td>" + (.id|@html) + (if .unverified then " <span title=\"CPE-matched; NVD version range not verified\">&dagger;</span>" else "" end) + (if .reach == "exploitable" then " <span title=\"" + (.reach_detail|@html) + "\">&Dagger;</span>" else "" end) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + (.title|@html) + "</td></tr>"'
        echo "</table></div>"
        if echo "$FINDINGS" | jq -e 'any(.[]; .unverified)' >/dev/null 2>&1; then
            echo "<p class=\"meta\">&dagger; CPE-matched against NVD but the version range was not verified (deep-cve; set <code>SECURITY_NVD_VERIFY=true</code> with network + <code>NVD_API_KEY</code> to drop loose-version false positives).</p>"
        fi
        if [ "${REACHED_N:-0}" -gt 0 ]; then
            echo "<p class=\"meta\">&Dagger; Reached: govulncheck found a call path to the affected Go code (source) or the affected symbol in the executable (binary).</p>"
        fi
    elif [ -n "$SCAN_ERR" ]; then
        echo "<p>Scan failed &mdash; no results were produced.</p>"
    elif [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "<p>No vulnerability was found in the components that were checked. ${UNCHECKED_N} component(s) could not be checked; they are listed below.</p>"
    elif [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "<p>No reachable vulnerability was found. ${UNREACHED_N} finding(s) are not reachable; they are listed below.</p>"
    else
        echo "<p>No known vulnerabilities found.</p>"
    fi
    if [ "${UNCHECKED_N:-0}" -gt 0 ]; then
        echo "<h2>Components that could not be checked</h2>"
        echo "<p class=\"meta\">They have no version, or no package purl and no CPE that was matched, so no vulnerability database was asked about them. A clean result does not cover them.</p>"
        echo "<div class=\"table-wrap\"><table><tr><th>Component</th><th>Version</th><th>PURL</th><th>Reason</th></tr>"
        echo "$UNCHECKED" | jq -r --argjson max "$UNCHECKED_MAX" '.[0:$max][] |
            "<tr><td>" + (.Name|@html) + "</td><td>" + (.Version|@html) + "</td>" +
            "<td>" + (.PURL|@html) + "</td>" +
            "<td>" + ({"no-version": "no version", "no-identifier": "no package purl or matched CPE"}[.Reason] // .Reason | @html) + "</td></tr>"'
        echo "</table></div>"
        if [ "$UNCHECKED_N" -gt "$UNCHECKED_MAX" ]; then
            echo "<p class=\"meta\">&hellip; and $((UNCHECKED_N - UNCHECKED_MAX)) more, listed in <code>UncheckedComponents</code> in <code>$(esc "$(basename "$JSON")")</code>.</p>"
        fi
    fi
    if [ "${UNREACHED_N:-0}" -gt 0 ]; then
        echo "<h2>Not reachable</h2>"
        echo "<p class=\"meta\">govulncheck judged that the code these advisories name is not reached. They are recorded as <code>not_affected</code> with <code>code_not_reachable</code> in <code>$(esc "$(basename "${REACH_DOC:-reachability.cdx.json}")")</code>, and are not in the counts above.</p>"
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>CVSS</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Why</th></tr>"
        echo "$UNREACHED_FINDINGS" | jq -r 'sort_by(
            {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td class=\"num\">" + ((.cvss // "")|tostring|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td>" +
            "<td>" + (.reach_detail|@html) + "</td></tr>"'
        echo "</table></div>"
    fi
    if [ "${KERNEL_TOTAL:-0}" -gt 0 ]; then
        echo "<h2>Kernel advisories</h2>"
        echo "<p class=\"meta\">Advisories filed against the kernel this image carries. Read them against the kernel configuration, not as a list to work through: a kernel accumulates thousands and most concern subsystems a given device never built.</p>"
        echo "<div class=\"table-wrap\"><table><tr><th>Severity</th><th>CVSS</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th></tr>"
        echo "$KERNEL_FINDINGS" | jq -r 'sort_by(
            {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.severity] // 5)[] |
            "<tr><td class=\"sev-\(.severity)\">" + (.severity|@html) + "</td>" +
            "<td class=\"num\">" + ((.cvss // "")|tostring|@html) + "</td>" +
            "<td>" + (.id|@html) + "</td><td>" + (.pkg|@html) + "</td>" +
            "<td>" + (.version|@html) + "</td><td>" + (.fixed|@html) + "</td></tr>"'
        echo "</table></div>"
    fi
    echo "</body></html>"
} > "$HTML"

if [ -n "$SCAN_ERR" ]; then
    echo "[security] generated: $JSON, $MD, $HTML (SCAN FAILED — results incomplete: ${SCAN_ERR})"
else
    echo "[security] generated: $JSON, $MD, $HTML (total=${TOTAL}, critical=${C}, high=${H}, kev=${KEV_COUNT}, unchecked=${UNCHECKED_N:-0}${REACH_DOC:+, not-reachable=${UNREACHED_N:-0}})"
fi
