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
#   bomlens:manifest-not-read  a C/C++ manifest the scan does not read, with the
#                              dependencies it declares that no component in the
#                              SBOM names ("vcpkg.json: fmt, curl"). cdxgen reads
#                              conanfile.txt, conan.lock and the package names of
#                              CMake files; it reads vcpkg.json and conanfile.py
#                              only in a C/C++-only run with source analysis,
#                              which the source scan does not use.
#
# The manifest/lock pairs checked: Podfile, Package.swift, Gemfile, go.mod
# (go.sum), Cargo.toml (Cargo.lock beside it or in a folder above it, for a
# workspace member) and composer.json (composer.lock). Each counts only when it
# declares a dependency, so a crate with an empty [dependencies] table or a
# composer.json that requires only php is not reported.
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
           -o -name build -o -name .build -o -name DerivedData -o -name target \
           -o -name vcpkg_installed -o -path '*/vcpkg/ports' \) -prune \
        -o -type f -name "$1" -print 2>/dev/null | sort
}

# Xcode keeps the Package.resolved of a project that has a Package.swift in the
# project or the workspace bundle (<name>.xcodeproj/project.xcworkspace/
# xcshareddata/swiftpm/, <name>.xcworkspace/xcshareddata/swiftpm/), not beside
# Package.swift. cdxgen and SwiftPM read it from there, so it is the lock file.
xcode_lock() { # <dir> <lock name>: prints the first one found
    local x
    for x in "$1"/*.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/"$2" \
             "$1"/*.xcworkspace/xcshareddata/swiftpm/"$2"; do
        if [ -f "$x" ]; then printf '%s' "$x"; return 0; fi
    done
    return 1
}

# A manifest that declares dependencies, with no lock file next to it.
check_pair() { # <manifest name> <lock name> <grep -E pattern showing a declared dependency>
    local f d
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        d="$(dirname "$f")"
        [ -f "$d/$2" ] && continue
        if [ "$2" = Package.resolved ] && xcode_lock "$d" "$2" >/dev/null; then continue; fi
        grep -Eq "$3" "$f" 2>/dev/null || continue
        add_missing "$(rel "$f"): no $2"
    done <<EOF
$(find_named "$1")
EOF
}
check_pair Podfile Podfile.lock '^[[:space:]]*pod[[:space:]]+["'"'"']'
check_pair Package.swift Package.resolved '\.package\('
check_pair Gemfile Gemfile.lock '^[[:space:]]*gem[[:space:]]+["'"'"']'
check_pair go.mod go.sum '^[[:space:]]*require([[:space:]]|\()'

# Cargo: the lock file of a workspace member is the one at the workspace root,
# so a Cargo.lock in any folder above it, up to the scan root, counts.
cargo_declares() { # <Cargo.toml>: a dependency table with at least one entry
    awk '
        /^[[:space:]]*\[/ {
            s = ($0 ~ /^[[:space:]]*\[(target\.[^]]+\.)?(dev-|build-)?dependencies\][[:space:]]*(#.*)?$/ \
                 || $0 ~ /^[[:space:]]*\[workspace\.dependencies\][[:space:]]*(#.*)?$/)
            if ($0 ~ /^[[:space:]]*\[(target\.[^]]+\.)?(dev-|build-)?dependencies\.[^]]+\]/) f = 1
            next
        }
        s && /^[[:space:]]*["A-Za-z0-9_-][^=]*=/ { f = 1 }
        END { exit !f }' "$1" 2>/dev/null
}
while IFS= read -r f; do
    [ -n "$f" ] || continue
    d="$(dirname "$f")"
    locked=""
    while :; do
        if [ -f "$d/Cargo.lock" ]; then locked=1; break; fi
        [ "$d" != "$SRC" ] && [ "$d" != "/" ] && [ "$d" != "." ] || break
        d="$(dirname "$d")"
    done
    [ -z "$locked" ] || continue
    cargo_declares "$f" || continue
    add_missing "$(rel "$f"): no Cargo.lock"
done <<EOF
$(find_named Cargo.toml)
EOF

# Composer: a package requirement has a vendor name ("vendor/package"); php,
# ext-* and lib-* are platform requirements that need no lock file.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$(dirname "$f")/composer.lock" ] && continue
    jq -e '(.require // {}) | type == "object" and any(keys[]; contains("/"))' "$f" >/dev/null 2>&1 || continue
    add_missing "$(rel "$f"): no composer.lock"
done <<EOF
$(find_named composer.json)
EOF

# C/C++ manifests the scan does not read. A declared name counts as read when a
# component of the SBOM has it (case aside): CMake's find_package or a component
# listed in sbom-declared.cdx.json can carry it.
NOTREAD=""
add_notread() { NOTREAD="${NOTREAD:+$NOTREAD; }$(clean "$1")"; }
SBOM_NAMES="$(jq -c '[.components[]? | recurse(.components[]?) | .name | strings | ascii_downcase] | unique' "$SBOM" 2>/dev/null)"
[ -n "$SBOM_NAMES" ] || SBOM_NAMES='[]'
unlisted() { # <json array of declared names>: prints those no component names, comma-separated
    jq -rn --argjson have "$SBOM_NAMES" --argjson want "$1" \
        '[$want[] | select(. as $n | $have | index($n | ascii_downcase) | not)] | unique | join(", ")' 2>/dev/null
}
while IFS= read -r f; do
    [ -n "$f" ] || continue
    # The ports a build uses; a host dependency (a build tool) and vcpkg's own
    # helper ports (vcpkg-cmake, vcpkg-cmake-config) are not part of the product.
    if ! names="$(jq -c '[(.dependencies // [])[]
            | if type == "string" then . elif type == "object" and (.host != true) then .name else empty end
            | strings | select(length > 0 and (startswith("vcpkg-") | not))]' "$f" 2>/dev/null)"; then
        add_notread "$(rel "$f"): cannot be parsed"
        continue
    fi
    miss="$(unlisted "$names")"
    [ -z "$miss" ] || add_notread "$(rel "$f"): $miss"
done <<EOF
$(find_named vcpkg.json)
EOF
# conanfile.py: a conan.lock beside it is read instead. The references are the
# quoted "name/version" strings of its requires (not tool_requires,
# build_requires, test_requires or python_requires, which are build tools).
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$(dirname "$f")/conan.lock" ] && continue
    names="$(awk '
        /(tool|build|test|python)_requires/ { inreq = 0; next }
        /(^|[^A-Za-z0-9_])requires[[:space:]]*(=|\()/ { inreq = 1 }
        inreq {
            line = $0
            while (match(line, /["'"'"'][A-Za-z0-9_.+-]+\/[^"'"'"'@]+(@[^"'"'"']*)?["'"'"']/)) {
                ref = substr(line, RSTART + 1, RLENGTH - 2); sub(/\/.*/, "", ref)
                printf "%s\n", ref
                line = substr(line, RSTART + RLENGTH)
            }
            if ($0 ~ /[)\]][[:space:]]*(#.*)?$/ || $0 !~ /[(\[,][[:space:]]*(#.*)?$/) inreq = 0
        }' "$f" 2>/dev/null | jq -Rsc 'split("\n") | map(select(length > 0))')"
    [ -n "$names" ] || continue
    miss="$(unlisted "$names")"
    [ -z "$miss" ] || add_notread "$(rel "$f"): $miss"
done <<EOF
$(find_named conanfile.py)
EOF

# A lock file that is there and cannot be read.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ! jq -e '(.pins // .object.pins) | type == "array"' "$f" >/dev/null 2>&1; then
        add_corrupt "$(rel "$f") cannot be parsed"
    fi
done <<EOF
$(find_named Package.resolved)
$(find "$SRC" -maxdepth 6 \( -name .git -o -name node_modules -o -name Pods -o -name Carthage -o -name vendor -o -name build -o -name .build -o -name DerivedData -o -name target \) -prune \
    -o -type f -path '*.xc*/xcshareddata/swiftpm/Package.resolved' -print 2>/dev/null | sort)
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
OWN_PROPS='["bomlens:lockfile-missing", "bomlens:lockfile-corrupt", "bomlens:manifest-not-read"]'
if [ -z "$MISSING" ] && [ -z "$CORRUPT" ] && [ -z "$NOTREAD" ] \
   && ! jq -e --argjson own "$OWN_PROPS" 'any(.metadata.properties[]?; .name as $n | $own | index($n))' "$SBOM" >/dev/null 2>&1; then
    exit 0
fi
TMP="${SBOM}.lockstate.tmp"
if jq --arg miss "$MISSING" --arg bad "$CORRUPT" --arg unread "$NOTREAD" --argjson own "$OWN_PROPS" '
      ((.metadata.properties // [])
        | map(select(.name as $n | $own | index($n) | not))) as $keep
      | .metadata.properties = ($keep
          + (if $miss != "" then [{name: "bomlens:lockfile-missing", value: $miss}] else [] end)
          + (if $bad != "" then [{name: "bomlens:lockfile-corrupt", value: $bad}] else [] end)
          + (if $unread != "" then [{name: "bomlens:manifest-not-read", value: $unread}] else [] end))
    ' "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
    [ -z "$MISSING" ] || echo "[lockfile] lock file missing: $MISSING"
    [ -z "$CORRUPT" ] || echo "[lockfile] lock file not readable: $CORRUPT"
    [ -z "$NOTREAD" ] || echo "[lockfile] dependencies declared in a manifest the scan does not read are not in the SBOM: $NOTREAD. Fix: list them in sbom-declared.cdx.json at the project root and scan again."
else
    rm -f "$TMP"
    echo "[lockfile] could not record the lock file state" >&2
fi
