#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-publication-terms.sh — keep two kinds of text out of anything we
# publish: the names of commercial analysis products, and measurements taken
# against them.
#
# Why both. The naming rule is editorial: this project describes what it does
# on its own terms and does not put competitors' names in its history. The
# measurement rule is the one that actually matters, and it is easy to miss.
# Licences for commercial analysis tools routinely forbid disclosing a
# comparison of their results with another product, and that restriction
# attaches to publishing the comparison, not to using the trademark. So
# renaming the product to "the commercial reference" and keeping "40/50"
# removes the name and leaves the disclosure. Both patterns are therefore
# checked, and the euphemisms are checked precisely because they read as if
# the problem had been solved.
#
# What is NOT restricted, deliberately:
#   - device vendor names (Zyxel, MikroTik, NETGEAR, ...). Naming the firmware
#     a judgement was derived from is what makes the judgement checkable, and
#     those measurements are against the vendor's own published notice rather
#     than against anyone's product.
#   - open-source tools we build on or compare with (syft, cdxgen, Trivy).
#   - licence texts and scan output, which are data and are exempted below.
#
# Usage:
#   check-publication-terms.sh                 # tracked files
#   check-publication-terms.sh --commits RANGE # commit messages in a range
#   check-publication-terms.sh --text FILE     # arbitrary text (a PR body)
# No Docker needed.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

# Commercial analysis products. Naming one in a commit, a document or a PR is
# an editorial matter; the measurement patterns below are the licence matter.
PRODUCTS='Black ?Duck|BDBA|Insignary|Cybellum|Finite State|Synopsys|Veracode|Checkmarx|WhiteSource|Revenera|Flexera|FOSSLight'

# Measurements against such a product, including the euphemisms that hide the
# name. "N/50" style scores are the corpus totals those comparisons produced.
MEASUREMENTS='commercial reference|reference[ -]tool|reference tool recall|the reference found|[0-9]{1,3}/(50|351|557)\b'

# Paths whose hits are data rather than prose. Licence texts are legal
# documents and are never edited; scan output records what a scanner found,
# including advisory URLs that belong to a vendor; and this script has to
# contain the patterns it looks for.
EXEMPT='^(docker/lib/licenses/|docs/demo/data/|LICENSE|.*/LICENSE|scripts/check-publication-terms\.sh$|\.github/workflows/publication-terms\.yml$)'

fail=0

report() {
    # $1 where, $2 the matching line
    printf '  %s\n      %s\n' "$1" "$2"
}

scan_stream() {
    # Reads "location<TAB>text" pairs and reports anything matching either set.
    # Returns 1 when it found something. It runs at the end of a pipeline, i.e.
    # in a subshell, so its verdict has to travel through the exit status
    # rather than through a variable.
    local label="$1" named=0 measured=0 loc txt
    while IFS=$'\t' read -r loc txt; do
        [ -z "${txt:-}" ] && continue
        if printf '%s' "$txt" | grep -qEi "$PRODUCTS"; then
            [ "$named" -eq 0 ] && echo "$label — commercial product named:" && named=1
            report "$loc" "$txt"
        elif printf '%s' "$txt" | grep -qE "$MEASUREMENTS"; then
            [ "$measured" -eq 0 ] && echo "$label — measurement against a commercial product:" && measured=1
            report "$loc" "$txt"
        fi
    done
    [ "$named" -eq 0 ] && [ "$measured" -eq 0 ]
}

check_tracked_files() {
    local f
    git ls-files -z | while IFS= read -r -d '' f; do
        printf '%s' "$f" | grep -qE "$EXEMPT" && continue
        # Skip binaries and anything large enough to be data.
        [ -f "$f" ] || continue
        grep -Iq . "$f" 2>/dev/null || continue
        grep -nEi "$PRODUCTS|$MEASUREMENTS" "$f" 2>/dev/null \
            | while IFS= read -r hit; do printf '%s:%s\t%s\n' "$f" "${hit%%:*}" "${hit#*:}"; done
    done | scan_stream "tracked files"
}

check_commits() {
    local range="$1" sha
    git log --format='%H' "$range" | while IFS= read -r sha; do
        git log -1 --format='%s%n%b' "$sha" \
            | while IFS= read -r line; do printf '%s\t%s\n' "${sha:0:10}" "$line"; done
    done | scan_stream "commit messages in $range"
}

check_text() {
    local file="$1" label n=0
    label="$(basename "$file")"
    while IFS= read -r line; do
        n=$((n + 1))
        printf '%s:%s\t%s\n' "$label" "$n" "$line"
    done < "$file" | scan_stream "$label"
}

case "${1:-}" in
    --commits) [ $# -ge 2 ] || { echo "usage: $0 --commits RANGE" >&2; exit 2; }
               check_commits "$2" || fail=1 ;;
    --text)    [ $# -ge 2 ] || { echo "usage: $0 --text FILE" >&2; exit 2; }
               [ -f "$2" ] || { echo "no such file: $2" >&2; exit 2; }
               check_text "$2" || fail=1 ;;
    "")        check_tracked_files || fail=1 ;;
    *)         echo "usage: $0 [--commits RANGE | --text FILE]" >&2; exit 2 ;;
esac

if [ "$fail" -ne 0 ]; then
    cat <<'EOF'

Describe the capability on its own terms instead. A gap is worth recording as
"components linked into another binary were not identified"; it does not need
a score against someone else's product, and publishing that score is what the
licence for that product restricts. Measurements against a vendor's own
published notice carry no such restriction and can stay.

Data that legitimately contains one of these strings (a licence text, scanner
output) belongs under one of the exempt paths at the top of this script.
EOF
    exit 1
fi

echo "[OK] no commercial product names or comparison figures in the checked text."
