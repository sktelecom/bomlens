#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-doc-env-coverage.sh — guard against adding a user-facing environment
# variable to the tool without documenting it.
#
# The authoritative list of user-facing env vars is the "Environment:" block of
# scripts/scan-sbom.sh --help. Every name there must appear in one of the user
# reference pages (docs/reference/cli.md or docs/reference/docker-image.md).
# Adding a var to the help text but forgetting the docs therefore fails CI.
#
# This is the code->docs direction. check-docs-drift.sh checks the reverse
# (docs referencing an env var that no longer exists in code), so the two gates
# together keep the environment documentation and the tool in sync both ways.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELP_SRC="$ROOT/scripts/scan-sbom.sh"
DOCS=("$ROOT/docs/reference/cli.md" "$ROOT/docs/reference/docker-image.md")
bt='`'
fail=0

# 1) Pull the user-facing env names from the "Environment:" help block. Entries
#    start at a two-space indent (VAR then its description); continuation lines
#    are indented further and are skipped.
envs="$(awk '
    /^Environment:/ { inblock=1; next }
    /^[A-Za-z]/     { inblock=0 }
    inblock && /^  [A-Z][A-Z0-9_]+/ { print $1 }
' "$HELP_SRC")"

[ -n "$envs" ] || { echo "ERROR: could not read the Environment block from $HELP_SRC"; exit 2; }

# 2) Each must be documented (as `VAR`) in at least one reference page.
while IFS= read -r v; do
    [ -z "$v" ] && continue
    found=0
    for d in "${DOCS[@]}"; do
        [ -f "$d" ] || continue
        if grep -qF "${bt}${v}${bt}" "$d"; then found=1; break; fi
    done
    if [ "$found" -eq 0 ]; then
        echo "FAIL: env var '$v' is advertised in scan-sbom.sh --help but is documented in neither"
        echo "      docs/reference/cli.md nor docs/reference/docker-image.md."
        echo "      Add a row/mention for ${bt}${v}${bt} to one of them (and its .ko.md mirror)."
        fail=1
    fi
done <<EOF
$envs
EOF

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "The env help block is the user-facing contract; a new variable must be documented."
    exit 1
fi

echo "OK: every user-facing environment variable in scan-sbom.sh --help is documented."
