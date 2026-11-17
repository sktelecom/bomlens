#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# detect-lockfile-state.sh - record on the SBOM when a lock file the source
# needs is missing or cannot be read.
#
# Usage: detect-lockfile-state.sh <source_dir> <sbom.json>
#
# A project that has a Podfile and no Podfile.lock, or a Package.resolved that
# is damaged, comes out of a scan with no pods or packages and no message: the
# resolver has nothing to read. The SBOM then looks like the project has no such
# dependencies. This writes what is found on the tree as two document properties
# that assess-completeness.sh turns into a reason in every report:
#
#   bomlens:lockfile-missing   a manifest that declares dependencies and has no
#                              lock file beside it ("Podfile: no Podfile.lock")
#   bomlens:lockfile-corrupt   a lock file that is not readable
#                              ("Package.resolved cannot be parsed")
#
# npm and Python manifests without a lock file are already recorded by
# detect-version-pinning.sh (bomlens:source:versionPinning), which
# assess-completeness.sh reads as well, so they are not repeated here.
#
# Nothing is written when nothing is found. Re-running replaces the properties,
# so the document stays byte-identical across repeated post-processing.
set -e

SRC="$1"
SBOM="$2"

[ -n "$SRC" ] && [ -d "$SRC" ] || exit 0
[ -n "$SBOM" ] && [ -f "$SBOM" ] || exit 0
command -v jq >/dev/null 2>&1 || exit 0

DEPTH=4
MISSING=""
CORRUPT=""

# One line, no control characters, so a file name cannot reach a terminal or a
# report as markup or an escape sequence.
clean() { printf '%s' "$1" | tr -d '\000-\037\177' | cut -c1-120; }
add_missing() { MISSING="${MISSING:+$MISSING; }$(clean "$1")"; }
add_corrupt() { CORRUPT="${CORRUPT:+$CORRUPT; }$(clean "$1")"; }
# Relative path of a file under the source tree ("." directory prints as the bare name).
rel() { local p="${1#"$SRC"}"; p="${p#/}"; printf '%s' "$p"; }

# Files named $1 outside the folders that hold other people's code or build output.
find_named() {
    find "$SRC" -maxdepth "$DEPTH" \
        \( -name .git -o -name node_modules -o -name Pods -o -name Carthage -o -name vendor \
           -o -name build -o -name .build -o -name DerivedData -o -name target \) -prune \
        -o -type f -name "$1" -print 2>/dev/null | sort
}

# A manifest that declares dependencies, with no lock file next to it.
check_pair() { # <manifest name> <lock name> <grep -E pattern showing a declared dependency>
    local f d
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        d="$(dirname "$f")"
        [ -f "$d/$2" ] && continue
        grep -Eq "$3" "$f" 2>/dev/null || continue
        add_missing "$(rel "$f"): no $2"
    done <<EOF
$(find_named "$1")
EOF
}
check_pair Podfile Podfile.lock '^[[:space:]]*pod[[:space:]]+["'"'"']'
check_pair Package.swift Package.resolved '\.package\('
check_pair Gemfile Gemfile.lock '^[[:space:]]*gem[[:space:]]+["'"'"']'

# A lock file that is there and cannot be read.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ! jq -e '(.pins // .object.pins) | type == "array"' "$f" >/dev/null 2>&1; then
        add_corrupt "$(rel "$f") cannot be parsed"
    fi
done <<EOF
$(find_named Package.resolved)
EOF
for name in package-lock.json composer.lock; do
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        jq empty "$f" >/dev/null 2>&1 || add_corrupt "$(rel "$f") cannot be parsed"
    done <<EOF
$(find_named "$name")
EOF
done
while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -q '^PODS:' "$f" 2>/dev/null || add_corrupt "$(rel "$f") has no PODS section"
done <<EOF
$(find_named Podfile.lock)
EOF

# Nothing found and nothing of an earlier run to remove: leave the file alone.
if [ -z "$MISSING" ] && [ -z "$CORRUPT" ] \
   && ! jq -e 'any(.metadata.properties[]?; .name == "bomlens:lockfile-missing" or .name == "bomlens:lockfile-corrupt")' "$SBOM" >/dev/null 2>&1; then
    exit 0
fi
TMP="${SBOM}.lockstate.tmp"
if jq --arg miss "$MISSING" --arg bad "$CORRUPT" '
      ((.metadata.properties // [])
        | map(select(.name != "bomlens:lockfile-missing" and .name != "bomlens:lockfile-corrupt"))) as $keep
      | .metadata.properties = ($keep
          + (if $miss != "" then [{name: "bomlens:lockfile-missing", value: $miss}] else [] end)
          + (if $bad != "" then [{name: "bomlens:lockfile-corrupt", value: $bad}] else [] end))
    ' "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
    [ -z "$MISSING" ] || echo "[lockfile] lock file missing: $MISSING"
    [ -z "$CORRUPT" ] || echo "[lockfile] lock file not readable: $CORRUPT"
else
    rm -f "$TMP"
    echo "[lockfile] could not record the lock file state" >&2
fi
