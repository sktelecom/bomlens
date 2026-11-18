#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# gradle-version-catalog.sh — list the libraries a Gradle version catalog declares.
#
# Usage: gradle-version-catalog.sh <source_dir> <output_sbom.json> [version]
#   reads <source_dir>/gradle/libs.versions.toml (and any other
#   gradle/*.versions.toml) and writes <output_sbom.json> (CycloneDX) whose
#   components are the [libraries] entries as pkg:maven/<group>/<name>@<version>.
#
# Why this exists: when the Gradle build cannot run (no Docker, or the cdxgen path
# failed) the manifest-only fallback reads no Gradle file, so a project that
# declares its dependencies in a version catalog comes back with none. The catalog
# is plain TOML, so the declared libraries can be read without building.
#
# What the list is: a declaration, not a resolution. A catalog entry says a library
# may be used; it does not say a module uses it, which configuration it is in, or
# which version Gradle picks after conflict resolution. So every component carries
# bomlens:source=version-catalog, and the caller keeps the result graded partial.
# A library with no version (its version comes from a BOM or a platform) is
# skipped, because a purl without a version cannot be matched to a vulnerability.
#
# Forms read:
#   name = "group:artifact:version"
#   name = { module = "group:artifact", version.ref = "key" }
#   name = { module = "group:artifact", version = "1.0" }
#   name = { group = "g", name = "a", version = { strictly = "1.0" } }
#   [versions] key = "1.0"  or  key = { strictly | require | prefer = "1.0" }
#
# Exit 0 with a components list (possibly empty) when a catalog was read; exit 3
# when there is no catalog to read; exit 1 on a usage error.
set -e

SRC="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"
SELFDIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=docker/lib/cdx-version.sh
. "$SELFDIR/cdx-version.sh"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "[catalog] source directory not found: ${SRC:-<empty>}. Fix: pass the project folder." >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[catalog] output path is required (usage: gradle-version-catalog.sh <src> <out.json> [version])" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "[catalog] ERROR: jq not installed in this image." >&2
    exit 1
fi

CATALOGS=()
for f in "$SRC"/gradle/*.versions.toml; do
    if [ -f "$f" ]; then CATALOGS+=("$f"); fi
done
if [ "${#CATALOGS[@]}" -eq 0 ]; then
    exit 3
fi

# One tab-separated line per library with a version: group, name, version.
# A library whose version cannot be found prints "group<TAB>name<TAB>" and the
# jq step below drops it.
# shellcheck disable=SC2016  # awk program, not shell
catalog_rows() {
    awk '
    function strip(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    # Value of  key = "..."  inside an inline table; empty when the key is absent.
    function field(tbl, key,    re, m) {
        re = "(^|[{, \t])" key "[ \t]*=[ \t]*\"[^\"]*\""
        if (match(tbl, re)) {
            m = substr(tbl, RSTART, RLENGTH)
            sub(/^[^"]*"/, "", m); sub(/"$/, "", m)
            return m
        }
        return ""
    }
    function nested_version(tbl,    m, k, v) {
        # version = { strictly = "1.0" } (also require, prefer)
        if (match(tbl, /version[ \t]*=[ \t]*\{[^}]*\}/)) {
            m = substr(tbl, RSTART, RLENGTH)
            sub(/^[^{]*\{/, "", m); sub(/\}$/, "", m)
            if (m ~ /(^|[ \t,])ref[ \t]*=/) { v = field("{" m, "ref"); if (v != "") return "@" v }
            return pick("{" m)
        }
        return ""
    }
    # The soft version first (prefer), then the required one. A range or a
    # dynamic version (1.+, latest.release, [1.0,2.0[) is not one version a
    # vulnerability can be matched to, so it counts as no version.
    function pick(tbl,    v) {
        v = field(tbl, "prefer"); if (v == "") v = field(tbl, "require"); if (v == "") v = field(tbl, "strictly")
        return v
    }
    function clean_version(v) {
        sub(/!!$/, "", v)
        if (v ~ /[\[\]\(\),+]/ || v ~ /^latest\./) return ""
        return v
    }
    function unq(k) { gsub(/^[ \t]*"|"[ \t]*$/, "", k); return k }
    # Two passes over each file (it is named twice): the first collects [versions],
    # the second reads [libraries], so the order of the tables does not matter,
    # and a key never leaks from one catalog file into another (ver is cleared
    # at the start of each file by the caller running awk once per file).
    BEGIN { sq = sprintf("%c", 39) }
    FNR == 1 { sec = ""; pass = (FNR == NR) ? 1 : 2 }
    /^[ \t]*#/ { next }
    /^[ \t]*\[/ {
        sec = $0; sub(/[ \t]*#.*$/, "", sec); gsub(/[ \t\r]/, "", sec); next
    }
    {
        line = $0
        # single-quoted TOML strings read like double-quoted ones
        gsub(sq, "\"", line)
        # drop a trailing comment that follows the closing quote or brace
        sub(/[ \t]+#[^"}]*$/, "", line)
        eq = index(line, "=")
        if (eq == 0) next
        key = unq(strip(substr(line, 1, eq - 1))); val = strip(substr(line, eq + 1))
        if (sec == "[versions]") {
            if (pass != 1) next
            if (val ~ /^"/) { v = val; sub(/^"/, "", v); sub(/".*$/, "", v); ver[key] = v }
            else if (val ~ /^\{/) { ver[key] = pick(val) }
            next
        }
        if (sec != "[libraries]" || pass != 2) next
        g = ""; a = ""; v = ""
        if (val ~ /^"/) {
            s = val; sub(/^"/, "", s); sub(/".*$/, "", s)
            n = split(s, p, ":")
            if (n >= 3) { g = p[1]; a = p[2]; v = p[3] } else if (n == 2) { g = p[1]; a = p[2] }
        } else if (val ~ /^\{/) {
            m = field(val, "module")
            if (m != "") { n = split(m, p, ":"); g = p[1]; a = p[2] }
            else { g = field(val, "group"); a = field(val, "name") }
            v = field(val, "version.ref")
            if (v != "") { v = ver[v] }
            else {
                v = field(val, "version")
                if (v == "") {
                    nv = nested_version(val)
                    if (nv ~ /^@/) { nv = substr(nv, 2); v = ver[nv] } else { v = nv }
                }
            }
        }
        if (g != "" && a != "") print g "\t" a "\t" clean_version(v)
        else print "-\t-\t"   # a line of a form this reader does not follow: counted as skipped
    }' "$@" "$@"
}

ROWS="$(mktemp)"
trap 'rm -f "$ROWS"' EXIT
for f in "${CATALOGS[@]}"; do
    catalog_rows "$f" >> "$ROWS"
done

SKIPPED=$(awk -F '\t' '$3 == ""' "$ROWS" | wc -l | tr -d ' ')
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
jq -R -s --arg version "$VERSION" --arg ts "$GEN_AT" --arg spec "$CDX_SPEC_VERSION" '
  def enc: @uri;
  ([ split("\n")[] | select(length > 0) | split("\t") | select(length == 3 and .[2] != "")
     | {g: .[0], n: .[1], v: .[2]} ]
   | unique_by([.g, .n, .v])
   | map(. as $c | ("pkg:maven/\($c.g | enc)/\($c.n | enc)@\($c.v | enc)") as $purl
         | {type: "library", "bom-ref": $purl, group: $c.g, name: $c.n, version: $c.v, purl: $purl,
            properties: [{name: "bomlens:source", value: "version-catalog"}]})) as $comps
  | {bomFormat: "CycloneDX", specVersion: $spec, version: 1,
     metadata: {timestamp: $ts,
                tools: {components: [{type: "application", name: "bomlens-gradle-version-catalog"}]},
                component: {type: "application", name: "gradle-version-catalog", version: $version}},
     components: $comps}
' "$ROWS" > "$OUTPUT"

N=$(jq '.components | length' "$OUTPUT")
echo "[catalog] ${#CATALOGS[@]} version catalog file(s): $N librar$([ "$N" = 1 ] && echo y || echo ies) read; $SKIPPED skipped (no single version, or a form not read)." >&2
