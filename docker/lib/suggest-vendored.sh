#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# suggest-vendored.sh — surface the --identify-vendored option only when it helps.
#
# Usage: suggest-vendored.sh <sbom.json> <source_dir>
#
# Vendored-OSS identification (SCANOSS) is needed almost exclusively for C/C++
# embedded source with no package manager — a small slice of users. So the option
# is off by default and hidden; this helper detects the one situation where it
# matters and tells the user, in one plain line, to switch it on. It never runs
# the scan itself (that sends fingerprints to an external API — the user decides).
#
# Trigger = no package-manager manifest + C/C++ source present + the scan found
# almost nothing (few components, or mostly cdxgen pkg:generic file entries).
# When it fires it also records `bomlens:suggest-identify-vendored=true` on the
# SBOM metadata so the web UI can show the same hint as a result banner.
#
# Best-effort and silent on anything unexpected: it must never break a scan.
set -e

SBOM="$1"
SRC="$2"

[ -n "$SBOM" ] && [ -f "$SBOM" ] || exit 0
[ -n "$SRC" ] && [ -d "$SRC" ] || exit 0
command -v jq >/dev/null 2>&1 || exit 0

# Already enabled? Nothing to suggest.
[ "${IDENTIFY_VENDORED:-false}" = "true" ] && exit 0

# C/C++ source present in the tree?
has_c=$(find "$SRC" -type f \( \
        -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
        -o -name '*.h' -o -name '*.hpp' -o -name '*.hh' \) 2>/dev/null | head -1)
[ -n "$has_c" ] || exit 0

# No package manager? Reuse the shared language detector. It returns "unknown"
# precisely when no manifest (pom.xml/package.json/go.mod/Conan/vcpkg/…) is found,
# which is the raw-CMake/Make C/C++ case this feature targets. With a manifest,
# cdxgen already resolves dependencies and the hint would be noise.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=docker/lib/source-detect.sh
. "$SCRIPT_DIR/source-detect.sh"
[ "$(detect_lang "$SRC")" = "unknown" ] || exit 0

# Did the scan come up nearly empty, or mostly pkg:generic file noise?
total=$(jq '[.components[]?] | length' "$SBOM" 2>/dev/null || echo 0)
generic=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:generic"))] | length' "$SBOM" 2>/dev/null || echo 0)
total=${total:-0}; generic=${generic:-0}

sparse=0
if [ "$total" -le 3 ]; then
    sparse=1
elif [ "$total" -gt 0 ] && [ "$((generic * 100 / total))" -ge 60 ]; then
    sparse=1
fi
[ "$sparse" = 1 ] || exit 0

cat >&2 <<'EOF'
[hint] This looks like a C/C++ source tree with no package manager, and the scan
       found little. Open source is often copied (vendored) straight into such
       sources and a normal scan cannot see it. To identify it, re-run with:
           --identify-vendored
       Only file fingerprints (hashes) are sent to the OSSKB service — your source
       code stays local. See docs/guides/identify-vendored.md
EOF

# Record the suggestion on the SBOM so the web UI can show a matching banner.
TMP="$(mktemp)"
if jq '(.metadata.properties) = ((.metadata.properties // [])
        + [{ name: "bomlens:suggest-identify-vendored", value: "true" }])' \
        "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
else
    rm -f "$TMP"
fi
exit 0
