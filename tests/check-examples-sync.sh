#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# check-examples-sync.sh — keep the example set in sync with what documents and
# tests claim. The real examples/<lang> directories are the source of truth;
# every one of them must appear in:
#   - the directory-structure block of docs/reference/ecosystems.md  (catches B-6: a
#     present example missing from the guide, e.g. swift)
#   - the example->manifest map in examples/test-all.sh        (catches B-5: the
#     batch test silently skipping an example)
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

echo ""
if [ "$MISSING" -eq 0 ]; then
    echo "OK: every examples/ directory is documented and tested"
else
    echo "FAIL: ${MISSING} sync gap(s) — update the guide and/or test-all.sh"
    exit 1
fi
