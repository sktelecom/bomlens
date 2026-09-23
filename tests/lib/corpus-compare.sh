#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# corpus-compare.sh - judge a results.tsv written by tests/test-real-corpus.sh
# against an earlier run and against fixed floors.
#
# Usage: corpus-compare.sh <current.tsv> [baseline.tsv] [drop-points] [floor.tsv]
#
# License coverage is judged per ecosystem, as the mean over repositories that
# were "ok" (in both files, for the comparison with the baseline):
#   - a fall of drop-points (default 10) or more against the baseline is a
#     regression, when at least two repositories of the ecosystem were compared
#     (one repository is reported but not judged: a single one moves too much);
#   - a mean below the ecosystem's floor in floor.tsv (columns: ecosystem,
#     minimum mean percent; committed in the repository, so lowering one is
#     visible in review) is a regression, with or without a baseline. Floors stop
#     a slow decline that stays under the drop threshold each night.
# Component counts that changed, repositories missing from either file and a
# baseline written with different columns are reported. A missing or empty
# baseline skips the comparison, not the floors.
# Exit: 0 no regression, 1 regression, 2 unusable input.
set -uo pipefail

CUR="${1:-}"; BASE="${2:-}"; DROP="${3:-10}"; FLOOR="${4:-}"
EXPECTED_HEADER=$'name\tecosystem\tlockfile\tstatus\texit\tcomponents\tpurl_pct\tlicense_pct\tseconds\ttree_clean'
usage() { echo "[ERROR] usage: corpus-compare.sh <current.tsv> [baseline.tsv] [drop-points] [floor.tsv]"; exit 2; }
[ -n "$CUR" ] && [ -f "$CUR" ] || usage
case "$DROP" in ''|*[!0-9]*) echo "[ERROR] drop-points must be a whole number"; exit 2 ;; esac
[ -z "$FLOOR" ] || [ -f "$FLOOR" ] || { echo "[ERROR] floor file not found: $FLOOR"; exit 2; }
[ "$(head -n 1 "$CUR" | tr -d '\r')" = "$EXPECTED_HEADER" ] || { echo "[ERROR] $CUR does not have the expected columns"; exit 2; }

USE_BASE=1
if [ -z "$BASE" ] || [ ! -s "$BASE" ]; then
    echo "No baseline to compare with (first run, or the earlier results were not kept)."
    USE_BASE=0
elif [ "$(head -n 1 "$BASE" | tr -d '\r')" != "$EXPECTED_HEADER" ]; then
    echo "The earlier results have different columns; the comparison is skipped."
    USE_BASE=0
fi
# The floors travel as "ecosystem=percent" words; the baseline (when used) is the
# first file and the current results the last.
FLOORS=""
[ -z "$FLOOR" ] || FLOORS=$(awk -F'\t' '{ sub(/\r$/, "") } $0 !~ /^#/ && NF >= 2 && $2 ~ /^[0-9]+$/ { printf "%s=%s ", $1, $2 }' "$FLOOR")
if [ "$USE_BASE" -eq 1 ]; then FILES=("$BASE" "$CUR"); else FILES=("$CUR"); fi

awk -F'\t' -v drop="$DROP" -v usebase="$USE_BASE" -v floors="$FLOORS" '
    BEGIN { nfl = split(floors, fl, " "); for (i = 1; i <= nfl; i++) { split(fl[i], kv, "="); floor[kv[1]] = kv[2] + 0 } }
    { sub(/\r$/, "") }
    FNR == 1 { fidx++ }
    usebase && fidx == 1 { if (FNR > 1) { bstat[$1] = $4; bcomp[$1] = $6; blic[$1] = $8; beco[$1] = $2; binorder[++nb] = $1 } next }
    FNR == 1 { next }
    {
        name = $1; eco = $2; incur[name] = 1
        if (!(eco in ecoseen)) { ecoseen[eco] = 1; order[++neco] = eco }
        if ($4 == "ok" && $8 ~ /^[0-9]+$/) { fn[eco]++; fsum[eco] += $8 }
        if (!usebase) next
        if (!(name in bstat)) { newrepo[++nnew] = name; next }
        if ($4 == "ok" && bstat[name] == "ok") {
            if (bcomp[name] != $6) changed[++nch] = sprintf("  %s (%s): components %s -> %s", name, eco, bcomp[name], $6)
            if ($8 ~ /^[0-9]+$/ && blic[name] ~ /^[0-9]+$/) { n[eco]++; bsum[eco] += blic[name]; csum[eco] += $8 }
        }
    }
    END {
        bad = 0
        if (usebase) {
            printf "License coverage against the earlier run (mean of repositories, percent)\n"
            printf "  %-12s %5s %9s %8s %8s\n", "ecosystem", "repos", "baseline", "current", "change"
            shown = 0
            for (i = 1; i <= neco; i++) {
                e = order[i]; if (!(e in n)) continue
                shown++; b = bsum[e] / n[e]; c = csum[e] / n[e]; d = c - b; flag = ""
                if (d <= -drop) { if (n[e] >= 2) { flag = "  REGRESSION"; bad = 1 } else flag = "  (one repository, not judged)" }
                printf "  %-12s %5d %9.1f %8.1f %+8.1f%s\n", e, n[e], b, c, d, flag
            }
            if (shown == 0) printf "  (no repository was ok in both runs)\n"
            if (nch > 0) { printf "Component counts that changed (information only)\n"; for (i = 1; i <= nch; i++) print changed[i] }
            for (i = 1; i <= nnew; i++) printf "Not in the earlier results (left out): %s\n", newrepo[i]
            for (i = 1; i <= nb; i++) if (!(binorder[i] in incur)) printf "In the earlier results but not in this run: %s (%s)\n", binorder[i], beco[binorder[i]]
        }
        nf = 0; for (k in floor) nf++
        if (nf > 0) {
            printf "License coverage against the floors (mean of ok repositories, percent)\n"
            printf "  %-12s %5s %8s %6s\n", "ecosystem", "repos", "current", "floor"
            for (i = 1; i <= neco; i++) {
                e = order[i]; if (!(e in floor)) continue
                if (!(e in fn)) { printf "  %-12s %5d %8s %6d  (no ok repository, not judged)\n", e, 0, "-", floor[e]; continue }
                c = fsum[e] / fn[e]; flag = ""
                if (c < floor[e]) { flag = "  REGRESSION"; bad = 1 }
                printf "  %-12s %5d %8.1f %6d%s\n", e, fn[e], c, floor[e], flag
            }
        }
        exit bad
    }
' "${FILES[@]}"
