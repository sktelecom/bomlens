#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-shard.sh - run one shard of a long, flat test script.
#
# Sourced by a test script near its top, right after its own setup lines:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/lib/test-shard.sh"
#   test_shard_run "${BASH_SOURCE[0]}" '<section header regex>' "$@"
#
# The script is read as three parts: the shared setup (everything before the
# first section header), its sections (each starts at a line matching the
# header regex) and the closing summary (from the line `# shard: closing
# summary` to the end), which prints the counts and sets the exit code. A section whose header line comes right after the
# line `# shard: same unit as the section above` stays in one unit with the
# section before it, for a section that reuses what the one above made.
#
# TEST_SHARD selects what runs:
#   unset or empty  the whole script, unchanged (test_shard_run returns).
#   list            print "<unit number><TAB><first header>" per unit, exit 0.
#   i/N             run the shared setup, the units of shard i and the
#                   closing summary, as one script; exit with its code. Units
#                   are dealt to the N shards back and forth (1..N, then N..1,
#                   and again), so long sections that sit next to each other
#                   do not all land in one shard. A shard with no unit fails.
# TEST_SHARD_PLAN=1 with i/N prints the selected unit numbers, one per line,
# after checking that the assembled script parses, and runs nothing.
#
# The assembled script runs with TEST_SHARD_SELF set to the original path, so
# the script resolves its repository paths from it instead of the temp file.

test_shard_run() {
    local self="$1" section_re="$2"
    local end_re='^# shard: closing summary$'
    shift 2
    [ -n "${TEST_SHARD:-}" ] || return 0
    [ -z "${TEST_SHARD_CHILD:-}" ] || return 0

    if [ "$TEST_SHARD" = "list" ]; then
        awk -v sre="$section_re" -v ere="$end_re" '
            { line[NR] = $0 }
            $0 ~ ere { last_end = NR }
            END {
                n = 0
                for (i = 1; i <= NR; i++) {
                    if (last_end && i >= last_end) break
                    if (line[i] ~ sre && line[i-1] != "# shard: same unit as the section above") {
                        n++; printf "%d\t%s\n", n, line[i]
                    }
                }
            }' "$self"
        exit 0
    fi

    local i n
    case "$TEST_SHARD" in
        */*) i="${TEST_SHARD%%/*}"; n="${TEST_SHARD#*/}" ;;
        *) i=""; n="" ;;
    esac
    case "$i$n" in
        ''|*[!0-9]*) i=0 ;;
    esac
    if [ "$i" -lt 1 ] || [ "$n" -lt 1 ] || [ "$i" -gt "$n" ]; then
        echo "[ERROR] TEST_SHARD='$TEST_SHARD': use i/N with 1 <= i <= N, or 'list'." >&2
        exit 2
    fi

    local tmp units
    tmp="$(mktemp "${TMPDIR:-/tmp}/test-shard.XXXXXX")" || exit 2
    units="$(awk -v sre="$section_re" -v ere="$end_re" -v want="$i" -v of="$n" -v out="$tmp" '
        { line[NR] = $0 }
        $0 ~ ere { last_end = NR }
        END {
            if (!last_end) exit 3
            unit = 0; keep = 1
            for (k = 1; k <= NR; k++) {
                if (k < last_end && line[k] ~ sre && line[k-1] != "# shard: same unit as the section above") {
                    unit++
                    r = (unit - 1) % (2 * of)
                    keep = ((r < of ? r : 2 * of - 1 - r) == want - 1)
                    if (keep) print unit
                }
                if (k >= last_end) keep = 1
                print (keep ? line[k] : "") > out
            }
        }' "$self")" || { rm -f "$tmp"; echo "[ERROR] $self has no '# shard: closing summary' line." >&2; exit 2; }

    if [ -z "$units" ]; then
        rm -f "$tmp"
        echo "[ERROR] TEST_SHARD=$TEST_SHARD selects no section of $self." >&2
        exit 1
    fi
    if ! bash -n "$tmp"; then
        rm -f "$tmp"
        echo "[ERROR] TEST_SHARD=$TEST_SHARD of $self does not parse; a unit boundary splits a block." >&2
        exit 1
    fi
    if [ "${TEST_SHARD_PLAN:-}" = "1" ]; then
        rm -f "$tmp"
        echo "$units"
        exit 0
    fi

    # Lines left out are kept as blank lines, so a failure's line number still
    # points at the same line of the original script.
    echo "TEST_SHARD $TEST_SHARD: units $(echo "$units" | tr '\n' ' ')of $(TEST_SHARD=list test_shard_run "$self" "$section_re" | wc -l | tr -d ' ')"
    local rc=0
    TEST_SHARD_CHILD=1 TEST_SHARD_SELF="$self" bash "$tmp" "$@" || rc=$?
    rm -f "$tmp"
    exit "$rc"
}
