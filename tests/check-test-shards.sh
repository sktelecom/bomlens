#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# check-test-shards.sh - the CI shards of a long test suite still run all of it.
#
# For each job of .github/workflows/ci.yml that runs a suite in shards, reads
# the shard values ("i/N") the job's matrix lists and checks that:
#   - they are exactly 1/N .. N/N, so no shard is left out of the matrix;
#   - for a script sharded by tests/lib/test-shard.sh, every shard parses and
#     selects at least one unit, no unit is in two shards, and together they
#     select every unit TEST_SHARD=list prints.
# Runs no test; it takes a few seconds.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI="$ROOT_DIR/.github/workflows/ci.yml"
FAIL=0
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
pass() { echo "  PASS: $1"; }

# <job id>: the "i/N" values quoted anywhere in that job's block of ci.yml.
job_shards() {
    awk -v job="  $1:" '
        $0 == job { on = 1; next }
        on && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { exit }
        on { print }
    ' "$CI" | grep -oE '"[0-9]+/[0-9]+"' | tr -d '"' | sort -u -t/ -k1,1n
}

# <job id> <script, or - for a job sharded by its own tool>
check_job() {
    local job="$1" script="$2" shards n want i
    shards="$(job_shards "$job")"
    echo "== $job${script:+ ($script)} =="
    if [ -z "$shards" ]; then
        fail "$job lists no shard values in ci.yml"
        return
    fi
    n="$(echo "$shards" | head -1 | cut -d/ -f2)"
    want="$(i=1; while [ "$i" -le "$n" ]; do echo "$i/$n"; i=$((i + 1)); done)"
    if [ "$shards" = "$want" ]; then
        pass "$job runs shards 1/$n to $n/$n"
    else
        fail "$job runs shards [$(echo "$shards" | tr '\n' ' ')], expected [$(echo "$want" | tr '\n' ' ')]"
        return
    fi
    [ "$script" != "-" ] || return

    local all picked got
    all="$(TEST_SHARD=list bash "$ROOT_DIR/$script" | cut -f1)"
    if [ -z "$all" ]; then
        fail "$script: TEST_SHARD=list printed no unit"
        return
    fi
    picked=""
    for i in $shards; do
        if ! got="$(TEST_SHARD="$i" TEST_SHARD_PLAN=1 bash "$ROOT_DIR/$script")"; then
            fail "$script: shard $i does not parse or selects nothing"
            continue
        fi
        echo "  shard $i: $(echo "$got" | wc -l | tr -d ' ') unit(s)"
        picked="$picked$got"$'\n'
    done
    picked="$(echo "$picked" | sed '/^$/d' | sort -n)"
    if [ "$picked" = "$(echo "$all" | sort -n)" ]; then
        pass "$script: the $n shards select each of its $(echo "$all" | wc -l | tr -d ' ') units exactly once"
    else
        fail "$script: the shards do not select each unit exactly once"
        diff <(echo "$all" | sort -n) <(echo "$picked") | head -20
    fi
}

check_job postprocess-unit tests/test-postprocess.sh
check_job contract tests/test-windows.sh
check_job ui -

echo ""
if [ "$FAIL" -eq 0 ]; then echo "Shard check passed"; else echo "Shard check: $FAIL failure(s)"; fi
[ "$FAIL" -eq 0 ]
