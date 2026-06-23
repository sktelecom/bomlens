#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-snapshot.sh — output regression snapshots for the SBOM post-processing
# pipeline. Runs the real post-process scripts over fixed input fixtures,
# strips volatile fields (tests/lib/snapshot-normalize.jq), and diffs the result
# against committed golden snapshots in tests/snapshots/.
#
# Why: the other unit tests assert a handful of fields. A bump to a tool or a jq
# change can alter the output in ways those asserts miss (specVersion, dropped
# fields, license shape, cpe synthesis). The snapshot makes ANY such change show
# up as a reviewable diff instead of a silent regression.
#
#   bash tests/test-snapshot.sh                 # compare against goldens (CI)
#   UPDATE_SNAPSHOTS=1 bash tests/test-snapshot.sh   # regenerate goldens after
#                                                    # an intended change
#
# Pure jq/bash — no Docker. Covers OUR pipeline. Drift caused by a tool VERSION
# (cdxgen/syft emitting different output) is caught by the generation snapshot in
# the docker / upstream-compat jobs, which reuse the same normalizer.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures"
SNAP_DIR="$ROOT_DIR/tests/snapshots"
NORM="$ROOT_DIR/tests/lib/snapshot-normalize.jq"
UPDATE="${UPDATE_SNAPSHOTS:-0}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
# shellcheck disable=SC2001  # sed prefixes every diff line; ${//} can't do per-line
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/        /'; FAIL=$((FAIL + 1)); }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for snapshot tests"; exit 1
fi

mkdir -p "$SNAP_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# check_snapshot <name> <produced-json>
# Normalizes the produced SBOM and compares to tests/snapshots/<name>.json, or
# (re)writes the golden when UPDATE_SNAPSHOTS=1.
check_snapshot() {
    local name="$1" produced="$2"
    local golden="$SNAP_DIR/${name}.json"
    local norm="$WORK/${name}.norm.json"
    if ! jq -S -f "$NORM" "$produced" > "$norm" 2>"$WORK/${name}.err"; then
        fail "$name: normalize failed" "$(cat "$WORK/${name}.err")"
        return
    fi
    if [ "$UPDATE" = "1" ]; then
        cp "$norm" "$golden"
        echo "  WROTE: $name"
        return
    fi
    if [ ! -f "$golden" ]; then
        fail "$name: golden missing ($golden). Seed it with UPDATE_SNAPSHOTS=1."
        return
    fi
    if diff -u "$golden" "$norm" > "$WORK/${name}.diff" 2>&1; then
        pass "$name matches golden"
    else
        fail "$name drifted from golden (review the change; if intended: UPDATE_SNAPSHOTS=1)" \
             "$(head -40 "$WORK/${name}.diff")"
    fi
}

echo "== snapshot: normalize-sbom.sh on license aliases =="
cp "$FIX/license-aliases.json" "$WORK/lic.json"
bash "$LIB/normalize-sbom.sh" "$WORK/lic.json" >/dev/null 2>&1
check_snapshot "normalize-license-aliases" "$WORK/lic.json"

echo "== snapshot: normalize-sbom.sh coerces null components =="
cp "$FIX/null-components.json" "$WORK/nul.json"
bash "$LIB/normalize-sbom.sh" "$WORK/nul.json" >/dev/null 2>&1
check_snapshot "normalize-null-components" "$WORK/nul.json"

echo "== snapshot: vendored identify -> merge -> normalize (PURL->CPE chain) =="
# Mock scanoss-py so no network/image is needed (mirrors test-postprocess.sh).
mkdir -p "$WORK/bin" "$WORK/srctree/src"
echo 'int main(void){return 0;}' > "$WORK/srctree/src/main.c"
cat > "$WORK/bin/scanoss-py" <<'MOCK'
#!/bin/bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && cp "$SCANOSS_RAW_FIXTURE" "$out"
exit 0
MOCK
chmod +x "$WORK/bin/scanoss-py"
export SCANOSS_RAW_FIXTURE="$FIX/scanoss-raw.json"
PATH="$WORK/bin:$PATH" bash "$LIB/identify-vendored.sh" "$WORK/srctree" "$WORK/vend.json" "26.4.0" >/dev/null 2>&1
bash "$LIB/merge-sbom.sh" "$WORK/merged.json" "trelay" "26.4.0" \
    "$FIX/cdxgen-cpp-sparse.json" "$WORK/vend.json" >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/merged.json" >/dev/null 2>&1
check_snapshot "vendored-merged-normalized" "$WORK/merged.json"

echo ""
if [ "$UPDATE" = "1" ]; then
    echo "Snapshots written to $SNAP_DIR"
    exit 0
fi
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
