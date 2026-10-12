#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# deep-license.sh - licence detection in the project's own source files (scancode).
#
# Usage: deep-license.sh <source-dir> <output-json>
#
# Scans only the project's own files: dependency copies (node_modules, vendor,
# virtual environments), build output and tool metadata are left out, because
# their licences come from the package managers, and a tree that holds them can
# be orders of magnitude larger. BOMLENS_DEEP_LICENSE_ALL=1 scans everything.
#
# Bounded so one scan cannot run without end: the eligible files are counted
# first and a tree over DEEP_LICENSE_MAX_FILES (default 20000) is not scanned,
# and scancode is stopped after DEEP_LICENSE_TIMEOUT seconds (default 600).
# Output is written to a per-run temporary file and moved into place only when
# scancode finished, so two scans never share a path and a stopped scan leaves
# no partial result.
#
# scancode matches an ignored name against every folder in a path, the tree's
# own folder included. When the tree's own folder has one of the names below
# (a web UI upload of a dist or build folder), that name is dropped from the
# list for this run, so the tree is scanned rather than skipped as a whole.
# Output paths are relative to the tree (--strip-root), the same as _files.json.
#
# Folder names in DEEP_LICENSE_EXCLUDE (space-separated) are left out as well;
# entrypoint.sh passes this run's output folder when it sits inside the tree.
#
# Exit codes, read by entrypoint.sh for the result manifest:
#   0 done   1 scancode failed   3 scancode not installed
#   4 over the file limit   5 timed out
#   6 done, but scancode reported errors on some files (the result is kept)

set -u

SRC="${1:?source dir}"
OUT="${2:?output json}"
SCANCODE="${BOMLENS_SCANCODE:-scancode}"
MAX_FILES="${DEEP_LICENSE_MAX_FILES:-20000}"
TIMEOUT_S="${DEEP_LICENSE_TIMEOUT:-600}"
case "$MAX_FILES" in ''|*[!0-9]*) MAX_FILES=20000 ;; esac
case "$TIMEOUT_S" in ''|*[!0-9]*) TIMEOUT_S=600 ;; esac

# Folders that are not the project's own source.
EXCLUDED_DIRS="node_modules vendor bower_components .venv venv virtualenv site-packages
dist build target out .next .nuxt __pycache__ .gradle
.git .hg .svn .tox .mypy_cache .pytest_cache .ruff_cache .idea .vscode"
EXCLUDED_DIRS="$EXCLUDED_DIRS ${DEEP_LICENSE_EXCLUDE:-}"

command -v "$SCANCODE" >/dev/null 2>&1 || exit 3
[ -d "$SRC" ] || { echo "[deep-license] source dir not found: $SRC" >&2; exit 1; }

keep_all=""
case "${BOMLENS_DEEP_LICENSE_ALL:-}" in 1|true) keep_all=1 ;; esac

SRC="$(cd "$SRC" && pwd)"
root_name="$(basename "$SRC" | tr '[:upper:]' '[:lower:]')"
kept=""
for d in $EXCLUDED_DIRS; do
    if [ "$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]')" = "$root_name" ]; then
        echo "[deep-license] the scanned folder is itself named $d; folders named $d inside it are scanned too." >&2
        continue
    fi
    kept="$kept $d"
done
EXCLUDED_DIRS="$kept"

# Count the files scancode would read, pruning the excluded folders at any
# depth below the tree's own folder (scancode compares names without regard to
# case, hence -iname), not following symbolic links, and stop counting past
# the limit.
prune=()
if [ -z "$keep_all" ]; then
    for d in $EXCLUDED_DIRS; do
        [ ${#prune[@]} -gt 0 ] && prune+=(-o)
        prune+=(-iname "$d")
    done
fi
if [ ${#prune[@]} -gt 0 ]; then
    n=$(find "$SRC" -mindepth 1 \( -type d \( "${prune[@]}" \) -prune \) -o -type f -print 2>/dev/null | head -n $((MAX_FILES + 1)) | wc -l | tr -d '[:space:]')
else
    n=$(find "$SRC" -mindepth 1 -type f -print 2>/dev/null | head -n $((MAX_FILES + 1)) | wc -l | tr -d '[:space:]')
fi
if [ "${n:-0}" -gt "$MAX_FILES" ]; then
    echo "[deep-license] more than $MAX_FILES source files to scan; skipped (raise DEEP_LICENSE_MAX_FILES to scan it)." >&2
    exit 4
fi

# A bare folder name makes scancode ignore that folder at any depth.
ignore=()
if [ -z "$keep_all" ]; then
    for d in $EXCLUDED_DIRS; do ignore+=(--ignore "$d"); done
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/bomlens-scancode.XXXXXX")" || exit 1
trap 'rm -f "$tmp"' EXIT
runner=()
# -k: a scancode that ignores the stop signal is killed 30 seconds later.
command -v timeout >/dev/null 2>&1 && runner=(timeout -k 30 "$TIMEOUT_S")
"${runner[@]}" "$SCANCODE" --license --strip-root --json-pp "$tmp" "${ignore[@]}" "$SRC" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "[deep-license] scancode did not finish within ${TIMEOUT_S}s; stopped (raise DEEP_LICENSE_TIMEOUT to allow longer)." >&2
    exit 5
fi
# scancode exits 1 when some files could not be read or timed out one by one,
# yet still writes a complete result for the rest; keep it and say so.
if [ ! -s "$tmp" ] || ! grep -q '"files"' "$tmp" || { [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; }; then
    echo "[deep-license] scancode failed (exit $rc)." >&2
    exit 1
fi
chmod 644 "$tmp" 2>/dev/null
mv "$tmp" "$OUT" || exit 1
if [ "$rc" -eq 1 ]; then
    echo "[deep-license] scancode reported errors on some files; the result for the others is kept." >&2
    exit 6
fi
exit 0
