#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# detect-version-pinning.sh — record whether the scanned source pinned the
# versions its SBOM reports.
#
# The defect this addresses: when a project states ranges rather than exact
# versions and ships no lock file, the resolver picks whatever is newest at scan
# time. The SBOM then carries specific version numbers -- 2.12.1, 2.5.2 -- and a
# reader takes them for what is installed on their machine. It is not: it is what
# a fresh install would fetch today. The vulnerability count inherits the same
# gap, and reads lower than the truth for anyone running an older tree.
#
# Nothing here re-resolves anything. It answers one question from the files that
# are present: did this tree fix its versions, or leave them to the resolver?
#
#   pinned     a lock file, or a manifest whose entries all carry an exact version
#   unpinned   a manifest with no lock file and no exact versions
#   (silent)   anything we cannot judge -- Maven and Gradle declare versions in
#              the build file with no lock of their own, so calling them either
#              way would be a guess. No property is written and the UI says
#              nothing, which is the honest outcome for "we do not know".
#
# Usage: detect-version-pinning.sh <source_dir> <sbom.json>
set -e

SRC="$1"
SBOM="$2"

[ -n "$SRC" ] && [ -d "$SRC" ] || exit 0
[ -n "$SBOM" ] && [ -f "$SBOM" ] || exit 0

PROP="bomlens:source:versionPinning"

# Lock files, by the ecosystems that have one. Presence is the whole answer:
# a lock file exists precisely to fix the resolved set.
for lock in poetry.lock Pipfile.lock uv.lock pdm.lock \
            package-lock.json yarn.lock pnpm-lock.yaml npm-shrinkwrap.json \
            go.sum Cargo.lock Gemfile.lock composer.lock \
            Package.resolved Podfile.lock; do
    if [ -f "$SRC/$lock" ]; then
        VERDICT="pinned"
        break
    fi
done

# No lock file. Two ecosystems can still be judged from the manifest itself.
if [ -z "${VERDICT:-}" ]; then
    if [ -f "$SRC/requirements.txt" ]; then
        # Every requirement line either carries `==` (or the rarer `===`) or it
        # does not pin. Comments, blank lines, and pip's own option lines (-r,
        # --index-url) are not requirements and do not count either way.
        # `grep -c` prints the count either way and exits 1 when it is zero, so
        # the exit status is discarded rather than turned into a second number.
        TOTAL=$(grep -cE '^[[:space:]]*[A-Za-z0-9]' "$SRC/requirements.txt" 2>/dev/null) || true
        EXACT=$(grep -cE '^[[:space:]]*[A-Za-z0-9][^#]*===?[[:space:]]*[0-9]' "$SRC/requirements.txt" 2>/dev/null) || true
        TOTAL=${TOTAL:-0}; EXACT=${EXACT:-0}
        if [ "$TOTAL" -gt 0 ] && [ "$EXACT" -eq "$TOTAL" ]; then
            VERDICT="pinned"
        elif [ "$TOTAL" -gt 0 ]; then
            VERDICT="unpinned"
        fi
    elif [ -f "$SRC/package.json" ]; then
        # npm without a lock file: the manifest's ranges are resolved at install
        # time, so the SBOM's versions are today's answer to them.
        VERDICT="unpinned"
    elif [ -f "$SRC/pyproject.toml" ] || [ -f "$SRC/setup.py" ] || [ -f "$SRC/setup.cfg" ]; then
        # A Python project packaged without a lock file states ranges the same
        # way; setup.py/setup.cfg have no exact-version convention to check.
        VERDICT="unpinned"
    fi
fi

[ -n "${VERDICT:-}" ] || exit 0

TMP="${SBOM}.pinning.tmp"
# Idempotent: a re-run drops its own previous property before appending, so the
# document stays byte-identical across repeated post-processing.
if jq --arg n "$PROP" --arg v "$VERDICT" '
      .metadata.component.properties =
        (((.metadata.component.properties // []) | map(select(.name != $n)))
         + [{name: $n, value: $v}])
    ' "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
    echo "[pinning] source versions: $VERDICT"
else
    rm -f "$TMP"
    echo "[pinning] could not record the version-pinning state" >&2
fi
