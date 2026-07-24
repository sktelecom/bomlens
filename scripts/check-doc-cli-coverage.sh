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
# check-doc-cli-coverage.sh — guard against adding a CLI flag to the tool
# without documenting it.
#
# The authoritative list of user-facing flags is the "Options:" block of
# scripts/scan-sbom.sh --help. Every flag there must appear in the options
# reference (docs/reference/cli.md). Adding a flag to the help text but
# forgetting the docs therefore fails CI.
#
# This is the flag counterpart of check-doc-env-coverage.sh, which covers the
# "Environment:" block the same way.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELP_SRC="$ROOT/scripts/scan-sbom.sh"
DOC="$ROOT/docs/reference/cli.md"
bt='`'
fail=0

# 1) Pull the flags from the "Options:" help block. Entries start at a
#    two-space indent (--flag then its description); continuation lines are
#    indented further and are skipped, so aliases mentioned in prose are not
#    picked up.
flags="$(awk '
    /^Options:/     { inblock=1; next }
    /^[A-Za-z]/     { inblock=0 }
    inblock && /^  --[a-z]/ { print $1 }
' "$HELP_SRC")"

[ -n "$flags" ] || { echo "ERROR: could not read the Options block from $HELP_SRC"; exit 2; }

# 2) Each must have its own row in the options table ("| `--flag ...` | ..."),
#    not merely a backticked mention in some other row's description — a
#    passing mention is exactly how a missing flag hides.
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qE "^\| ${bt}${f}[ ${bt}]" "$DOC"; then
        echo "FAIL: CLI flag '$f' is advertised in scan-sbom.sh --help but has no row"
        echo "      in the options table of docs/reference/cli.md."
        echo "      Add a ${bt}${f}${bt} row to the table (and its .ko.md mirror)."
        fail=1
    fi
done <<EOF
$flags
EOF

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "The options help block is the user-facing contract; a new flag must be documented."
    exit 1
fi

echo "OK: every CLI flag in scan-sbom.sh --help is documented in docs/reference/cli.md."
