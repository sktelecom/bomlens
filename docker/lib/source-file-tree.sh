#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# source-file-tree.sh — emit a ScanCode-shaped file inventory for the source view.
#
# Usage: source-file-tree.sh <source_dir> <out_file>
#
# The web UI's source-tree panel parses ScanCode output (`_scancode.json`), but
# ScanCode (deep-license) is opt-in and off by default, so most scans show no
# tree even though the scanned files are right there. This walks the scanned
# source directory and writes the SAME `{"files":[{"path","type"}, …]}` shape
# ScanCode emits — just without license fields — so the frontend's parseScanCode
# consumes it unchanged and the tree shows structure with empty license columns.
#
# Paths are relative to the source root (no leading "/"), matching ScanCode.
# Common noise (.git, node_modules, build outputs) is excluded and the entry
# count is capped so a giant tree can't bloat the artifact; truncation is logged
# (never silent). Best-effort: any failure leaves no file and never breaks a scan.
set -e

SRC="$1"
OUT="$2"

[ -n "$SRC" ] && [ -d "$SRC" ] || exit 0
[ -n "$OUT" ] || exit 0
command -v find >/dev/null 2>&1 || exit 0

# Cap on emitted entries (files + directories). A typical source tree is far
# below this; the cap only guards against a pathological monorepo / vendored
# bundle bloating the JSON. Override via SOURCE_TREE_MAX for testing.
MAX_ENTRIES="${SOURCE_TREE_MAX:-20000}"

# Directories whose contents are noise for a "what's in my source" view: VCS
# metadata, dependency caches, and common build outputs. Pruned wholesale so we
# don't walk into them at all.
PRUNE_DIRS=".git node_modules .svn .hg .venv venv __pycache__ \
.gradle .mvn target build dist out vendor bower_components .next .nuxt \
.tox .pytest_cache .mypy_cache .idea .vscode .terraform .cache"

# Build the find prune expression: -name X -o -name Y … wrapped in ( ) -prune.
prune_expr=()
first=1
for d in $PRUNE_DIRS; do
    if [ "$first" -eq 1 ]; then
        prune_expr+=(-name "$d"); first=0
    else
        prune_expr+=(-o -name "$d")
    fi
done

# Collect "<type>\t<relpath>" lines (relative to SRC). cd into SRC so find emits
# "./path"; we strip the leading "./" to keep paths root-relative. Two passes
# (directories, then files) avoid GNU-only -printf — portable across BSD find.
tmp=$(mktemp 2>/dev/null) || exit 0
trap 'rm -f "$tmp"' EXIT

(
    cd "$SRC" 2>/dev/null || exit 0
    # Directories: prune the noise dirs (so we don't descend into them) and tag
    # the survivors with "d". -mindepth 1 skips "." (the root itself).
    find . -mindepth 1 \
        \( -type d \( "${prune_expr[@]}" \) -prune \) -o \
        \( -type d -print \) 2>/dev/null \
        | sed -e 's#^\./##' -e '/^$/d' -e 's/^/d\t/'
    # Files: same prune so we never enter the noise dirs, then tag with "f".
    find . -mindepth 1 \
        \( -type d \( "${prune_expr[@]}" \) -prune \) -o \
        \( -type f -print \) 2>/dev/null \
        | sed -e 's#^\./##' -e '/^$/d' -e 's/^/f\t/'
) > "$tmp" || true

total=$(wc -l < "$tmp" 2>/dev/null | tr -d ' ')
total="${total:-0}"
truncated=0
if [ "$total" -gt "$MAX_ENTRIES" ]; then
    truncated=1
    head -n "$MAX_ENTRIES" "$tmp" > "$tmp.cut" 2>/dev/null && mv "$tmp.cut" "$tmp"
fi

# Emit the ScanCode files subset. Prefer jq for correct JSON escaping; fall back
# to a minimal escaper if jq is unavailable (the scanner image always has jq).
if command -v jq >/dev/null 2>&1; then
    if ! jq -R -s '
        {files: (
            split("\n")
            | map(select(length > 0) | split("\t"))
            | map({
                path: .[1],
                type: (if .[0] == "d" then "directory" else "file" end)
              })
        )}
    ' "$tmp" > "$OUT" 2>/dev/null; then
        echo "[WARN] source-file-tree: jq failed; no file tree emitted." >&2
        rm -f "$OUT"
        exit 0
    fi
else
    echo "[WARN] source-file-tree: jq unavailable; no file tree emitted." >&2
    exit 0
fi

emitted=$(jq '.files | length' "$OUT" 2>/dev/null || echo 0)
echo "[INFO] source-file-tree: wrote $emitted entr$([ "$emitted" = "1" ] && echo y || echo ies) to $(basename "$OUT")."
if [ "$truncated" -eq 1 ]; then
    echo "[WARN] source-file-tree: truncated at $MAX_ENTRIES entries (source tree larger than the cap); the file view is partial."
fi
exit 0
