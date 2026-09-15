#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-artifact-registry-sync.sh — guard against the four places that know
# about a scan-output filename suffix drifting apart.
#
# docker/entrypoint.sh writes every artifact; docker/web/server.py's
# ARTIFACT_SUFFIXES decides what the web UI lists, downloads and deletes;
# .gitignore keeps them out of git status; docs/reference/artifacts.md tells a
# user what to expect. A suffix can legitimately be excluded from any one of
# these (a merge-scratch sidecar is not meant to be independently downloadable,
# for instance), so this is not "one list, four copies" — it is a hand-kept
# registry of what SHOULD be true for each suffix, checked against what
# actually is. Add a line to REGISTRY below whenever entrypoint.sh starts
# writing a new one (this script cross-checks entrypoint.sh itself below, so
# forgetting to update the registry now fails CI instead of staying silent).
#
# Scope: the entrypoint.sh cross-check only reads that one file. A sidecar
# written exclusively from docker/lib/*.py or *.sh without ever being named in
# entrypoint.sh (as an ARTIFACTS+= entry or an `[ -f ... ]` check) is outside
# what this direction can see — entrypoint.sh's own varied string styles (an
# f-string, a `+`-concatenation, a bash for-loop over extensions) already
# defeat one regular expression; every producer script's own dialect would
# need its own.
#
# Columns: SUFFIX :: web(yes/no) :: gitignore(yes/no) :: docs-pattern
#   web       — must (yes) / must not (no) appear in server.py's ARTIFACT_SUFFIXES
#   gitignore — must (yes) appear in .gitignore (every suffix here should be)
#   docs      — a grep -E pattern that must appear in docs/reference/artifacts.md,
#               or "skip" for an internal sidecar the docs need not mention. A
#               row whose extension is one of several the doc groups onto one
#               line (docs write "_NOTICE.txt` / `.html`", not each suffix in
#               full) gives the shared stem as the pattern rather than its own
#               full suffix.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER="$ROOT/docker/web/server.py"
GITIGNORE="$ROOT/.gitignore"
DOCS="$ROOT/docs/reference/artifacts.md"
ENTRYPOINT="$ROOT/docker/entrypoint.sh"
fail=0

REGISTRY="
_bom.json               :: yes :: yes :: _bom\.json
_bom.json.sig           :: yes :: yes :: _bom\.json\.sig
_bom.spdx.json          :: yes :: yes :: _bom\.spdx\.json
_bom.spdx.json.sig      :: yes :: yes :: _bom\.spdx\.json\.sig
_NOTICE.txt             :: yes :: yes :: _NOTICE
_NOTICE.html            :: yes :: yes :: _NOTICE
_NOTICE.pdf             :: yes :: yes :: _NOTICE
_security.json          :: yes :: yes :: _security\.
_security.md            :: yes :: yes :: _security\.
_security.html          :: yes :: yes :: _security\.
_conformance.json       :: yes :: yes :: _conformance
_conformance.md         :: yes :: yes :: _conformance
_conformance.html       :: yes :: yes :: _conformance
_conformance.result     :: no  :: yes :: skip
_risk-report.md         :: yes :: yes :: _risk-report
_risk-report.html       :: yes :: yes :: _risk-report
_scancode.json          :: yes :: yes :: _scancode\.json
_files.json             :: yes :: yes :: _files\.json
_source.json            :: yes :: yes :: _source\.json
_input.json             :: yes :: yes :: _input\.json
_yocto_vex.json         :: yes :: yes :: _yocto_vex\.json
_security_epss.json     :: yes :: yes :: _security_epss\.json
_vendored.cdx.json      :: yes :: yes :: _vendored\.cdx\.json
_ai-profile.json        :: yes :: yes :: _ai-profile
_ai-profile.md          :: yes :: yes :: _ai-profile
_vex.json               :: yes :: yes :: _vex\.json
_modelica.cdx.json      :: no  :: yes :: skip
_cocoapods.cdx.json     :: no  :: yes :: skip
_conda.cdx.json         :: no  :: yes :: skip
_security_cvebintool.json :: no :: yes :: skip
_security_grype.json    :: no  :: yes :: skip
_security_yocto.json    :: no  :: yes :: skip
"

# _vex.json is deliberately absent from entrypoint.sh's KNOWN_ARTIFACT_SUFFIXES
# below, and that is not an oversight for the forward check to catch: it is
# the one entry here the scan pipeline never writes at all (POST /vex-verdict
# in server.py does, after a scan is already done) and the one entry that
# must NOT be swept by a re-scan's stale-artifact cleanup. A CVE judgement a
# supplier recorded against last week's scan of this project/version has to
# survive scanning it again today; every other suffix here is regenerated
# fresh each run, which is exactly why the cleanup sweeps it first.
CLEANUP_EXEMPT="
_vex.json
"

[ -f "$SERVER" ] || { echo "ERROR: $SERVER not found"; exit 2; }
[ -f "$GITIGNORE" ] || { echo "ERROR: $GITIGNORE not found"; exit 2; }
[ -f "$DOCS" ] || { echo "ERROR: $DOCS not found"; exit 2; }
[ -f "$ENTRYPOINT" ] || { echo "ERROR: $ENTRYPOINT not found"; exit 2; }

# The ARTIFACT_SUFFIXES tuple, as a flat list of suffix literals. Comment
# lines are dropped before the quote extraction (otherwise a suffix-shaped
# string mentioned only in a comment would be misread as a real entry), and
# the result is filtered to the actual suffix shape as a second net.
suffixes_in_code=$(awk '/^ARTIFACT_SUFFIXES = \(/,/^\)/' "$SERVER" \
    | grep -v '^[[:space:]]*#' \
    | grep -oE '"_[A-Za-z0-9._-]+"' \
    | tr -d '"' \
    | grep -E '^_[A-Za-z0-9._-]+$')

registry_suffixes=$(printf '%s\n' "$REGISTRY" | awk -F ' :: ' 'NF==4 {gsub(/ /,"",$1); print $1}')

while IFS= read -r line; do
    [ -z "$line" ] && continue
    nf=$(printf '%s' "$line" | awk -F ' :: ' '{print NF}')
    if [ "$nf" -ne 4 ]; then
        echo "FAIL: malformed REGISTRY line (expected SUFFIX :: web :: gitignore :: docs-pattern): $line"
        fail=1
        continue
    fi
    suf=$(printf '%s' "$line" | awk -F ' :: ' '{gsub(/ /,"",$1); print $1}')
    web=$(printf '%s' "$line" | awk -F ' :: ' '{gsub(/ /,"",$2); print $2}')
    gi=$(printf '%s' "$line" | awk -F ' :: ' '{gsub(/ /,"",$3); print $3}')
    docpat=$(printf '%s' "$line" | awk -F ' :: ' '{gsub(/^ +| +$/,"",$4); print $4}')

    case "$web" in
        yes|no) ;;
        *) echo "FAIL: $suf has an invalid web column '$web' (must be yes/no)."; fail=1; continue ;;
    esac
    case "$gi" in
        yes|no) ;;
        *) echo "FAIL: $suf has an invalid gitignore column '$gi' (must be yes/no)."; fail=1; continue ;;
    esac
    if [ -z "$docpat" ]; then
        echo "FAIL: $suf has an empty docs-pattern column (use 'skip' to intentionally skip)."
        fail=1
        continue
    fi

    in_code=$(printf '%s\n' "$suffixes_in_code" | grep -qFx "$suf" && echo yes || echo no)
    if [ "$web" != "$in_code" ]; then
        if [ "$web" = "yes" ]; then
            echo "FAIL: $suf should be in server.py's ARTIFACT_SUFFIXES (web UI results/download/delete) but is not."
        else
            echo "FAIL: $suf is in server.py's ARTIFACT_SUFFIXES but the registry says it should not be — either it's a genuine sidecar that leaked in, or this registry entry is stale."
        fi
        fail=1
    fi

    if [ "$gi" = "yes" ] && ! grep -qFx "*${suf}" "$GITIGNORE"; then
        echo "FAIL: *${suf} is missing from .gitignore."
        fail=1
    fi

    if [ "$docpat" != "skip" ] && ! grep -qE -- "$docpat" "$DOCS"; then
        echo "FAIL: $suf (pattern: $docpat) is missing from docs/reference/artifacts.md."
        fail=1
    fi
done < <(printf '%s\n' "$REGISTRY")

# Reverse direction (server.py -> registry): a suffix in ARTIFACT_SUFFIXES
# that the registry has never heard of.
while IFS= read -r suf; do
    [ -z "$suf" ] && continue
    if ! printf '%s\n' "$registry_suffixes" | grep -qFx "$suf"; then
        echo "FAIL: server.py's ARTIFACT_SUFFIXES has '$suf', which is not in the REGISTRY here."
        echo "      Add a line for it in scripts/check-artifact-registry-sync.sh."
        fail=1
    fi
done < <(printf '%s\n' "$suffixes_in_code")

# Reverse direction (entrypoint.sh -> registry): a suffix entrypoint.sh writes
# (ARTIFACTS+= or an `[ -f ... ]` existence check naming it) that the registry
# has never heard of. entrypoint.sh's for-loops build some suffixes from a
# variable extension (e.g. "${OUT_PREFIX}_ai-profile.${ext}"), which this
# regex can only capture up to the trailing dot; those are matched against the
# registry by stem instead of by exact suffix.
entrypoint_suffixes=$(grep -ohE '\$\{OUT_PREFIX\}_[A-Za-z0-9._-]+' "$ENTRYPOINT" \
    | sed 's/^\${OUT_PREFIX}//' | sort -u)
while IFS= read -r suf; do
    [ -z "$suf" ] && continue
    stem="${suf%.}"
    if [ "$stem" != "$suf" ]; then
        if ! printf '%s\n' "$registry_suffixes" | grep -qF "$stem"; then
            echo "FAIL: entrypoint.sh writes a '${stem}.<ext>' family the REGISTRY has no entry for."
            echo "      Add a line for it in scripts/check-artifact-registry-sync.sh."
            fail=1
        fi
        continue
    fi
    if ! printf '%s\n' "$registry_suffixes" | grep -qFx "$suf"; then
        echo "FAIL: entrypoint.sh writes '$suf', which is not in the REGISTRY here."
        echo "      Add a line for it in scripts/check-artifact-registry-sync.sh."
        fail=1
    fi
done < <(printf '%s\n' "$entrypoint_suffixes")

# entrypoint.sh's own stale-artifact cleanup (KNOWN_ARTIFACT_SUFFIXES) is meant
# to mirror the REGISTRY exactly: every suffix any producer script can write,
# so a re-scan's leftover from a previous run's mode/options is always
# recognized. Checked both directions: the array must have everything the
# REGISTRY has, and nothing the REGISTRY does not.
cleanup_suffixes=$(awk '/^KNOWN_ARTIFACT_SUFFIXES=\(/,/^\)/' "$ENTRYPOINT" \
    | grep -v '^[[:space:]]*#' \
    | grep -v '^KNOWN_ARTIFACT_SUFFIXES=' \
    | grep -oE '_[A-Za-z0-9._-]+' \
    | grep -E '^_[A-Za-z0-9._-]+$' | sort -u)
if [ -z "$cleanup_suffixes" ]; then
    echo "FAIL: could not find entrypoint.sh's KNOWN_ARTIFACT_SUFFIXES array (stale-artifact cleanup)."
    fail=1
else
    while IFS= read -r suf; do
        [ -z "$suf" ] && continue
        if printf '%s\n' "$CLEANUP_EXEMPT" | grep -qFx "$suf"; then
            continue
        fi
        if ! printf '%s\n' "$cleanup_suffixes" | grep -qFx "$suf"; then
            echo "FAIL: $suf is in the REGISTRY but missing from entrypoint.sh's KNOWN_ARTIFACT_SUFFIXES, so a re-scan would not clean up a stale one."
            fail=1
        fi
    done < <(printf '%s\n' "$registry_suffixes")
    while IFS= read -r suf; do
        [ -z "$suf" ] && continue
        if ! printf '%s\n' "$registry_suffixes" | grep -qFx "$suf"; then
            echo "FAIL: entrypoint.sh's KNOWN_ARTIFACT_SUFFIXES has '$suf', which is not in the REGISTRY here."
            echo "      Add a line for it in scripts/check-artifact-registry-sync.sh."
            fail=1
        fi
    done < <(printf '%s\n' "$cleanup_suffixes")
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Artifact registry sync check failed — entrypoint.sh/server.py/.gitignore/docs disagree about a scan output file."
    exit 1
fi
echo "OK: entrypoint.sh, server.py, .gitignore and docs/reference/artifacts.md agree with the artifact registry."
