#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# check-examples-sync.sh — keep the example set in sync with what documents and
# tests claim. The real examples/<lang> directories are the source of truth;
# every one of them must appear in:
#   - the directory-structure block of docs/reference/ecosystems.md  (catches B-6: a
#     present example missing from the guide, e.g. swift)
#   - the example->manifest map in examples/test-all.sh        (catches B-5: the
#     batch test silently skipping an example)
# and the examples for lock-file ecosystems (nodejs, go, rust, php) must carry
# their lock file.
# No Docker needed.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDE="$ROOT_DIR/docs/reference/ecosystems.md"
TESTALL="$ROOT_DIR/examples/test-all.sh"
MISSING=0

for f in "$GUIDE" "$TESTALL"; do
    [ -f "$f" ] || { echo "[ERROR] missing required file: $f"; exit 1; }
done

for d in "$ROOT_DIR"/examples/*/; do
    lang="$(basename "$d")"

    if grep -Eq "(├──|└──) ${lang}/" "$GUIDE"; then
        echo "  ok:   ${lang} listed in docs/reference/ecosystems.md"
    else
        echo "  MISS: ${lang} not in docs/reference/ecosystems.md directory list"
        MISSING=$((MISSING + 1))
    fi

    if grep -Eq "\"${lang}:" "$TESTALL"; then
        echo "  ok:   ${lang} mapped in examples/test-all.sh"
    else
        echo "  MISS: ${lang} not mapped in examples/test-all.sh"
        MISSING=$((MISSING + 1))
    fi
done

# Examples for ecosystems that use a lock file carry it, so a first scan of
# them reads exact versions and grades complete.
for pair in "nodejs:package-lock.json" "go:go.sum" "rust:Cargo.lock" "php:composer.lock"; do
    lang="${pair%%:*}"
    lock="${pair#*:}"
    [ -d "$ROOT_DIR/examples/$lang" ] || continue
    if [ -f "$ROOT_DIR/examples/$lang/$lock" ]; then
        echo "  ok:   ${lang} has ${lock}"
    else
        echo "  MISS: examples/${lang}/${lock} is missing"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
if [ "$MISSING" -eq 0 ]; then
    echo "OK: every examples/ directory is documented and tested"
else
    echo "FAIL: ${MISSING} sync gap(s) — update the guide or test-all.sh, or add the missing lock file"
    exit 1
fi
