#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-verify-weights.sh — No-Docker checks for verify-model-weights.py, the
# script behind --verify-weights (MODE=AIBOM opt-in): download only a
# HuggingFace repo's pickle-format weight files and run the same local
# picklescan verification MODE=MODELFILE already runs on a supplied file.
#
# huggingface_hub is stubbed via PYTHONPATH (same technique tests/test-aibom.sh
# uses for enrich-aibom.sh): list_repo_tree returns a tree fixed per scenario,
# and hf_hub_download copies from a local samples directory instead of hitting
# the network, so no test here ever makes a real HTTP call.
#
# The size-cap / file-count enforcement is asserted independently of
# picklescan (it never needs to run a scan to be checked); the actual verdict
# mapping (unsafe/clean, worst-wins across files) needs picklescan installed
# and is gated the same way tests/test-modelfile.sh gates its real-scan
# section, so this runs unscanned-but-still-useful on a dev machine without it.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
SCRIPT="$LIB/verify-model-weights.py"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

for tool in python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required"; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/hfstub" "$WORK/samples"

cat > "$WORK/hfstub/huggingface_hub.py" <<'STUB'
import json
import os
import shutil


class _F:
    def __init__(self, path, size):
        self.path = path
        self.size = size


class HfApi:
    def list_repo_tree(self, mid, expand=False):
        with open(os.environ["VERIFY_TREE_FILE"]) as fh:
            entries = json.load(fh)
        return [_F(e["path"], e.get("size")) for e in entries]

    def model_info(self, mid, **kw):
        raise RuntimeError("not stubbed")


def hf_hub_download(repo_id, filename, cache_dir=None, **kw):
    calls_file = os.environ.get("VERIFY_DL_CALLS", "")
    if calls_file:
        with open(calls_file, "a") as fh:
            fh.write(filename + "\n")
    cache_log = os.environ.get("VERIFY_CACHE_LOG", "")
    if cache_log and cache_dir:
        with open(cache_log, "w") as fh:
            fh.write(cache_dir)
    src = os.path.join(os.environ["VERIFY_SAMPLES_DIR"], os.path.basename(filename))
    if not os.path.isfile(src):
        raise RuntimeError("404 not found: %s" % filename)
    dst_dir = cache_dir or "/tmp"
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(filename))
    shutil.copyfile(src, dst)
    return dst
STUB

# --- build sample weight files ----------------------------------------------
python3 - "$WORK/samples" <<'PY'
import os, pickle, sys, zipfile

out = sys.argv[1]
p = lambda n: os.path.join(out, n)


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


# A plain pickle stream with nothing dangerous in it.
with open(p("clean.bin"), "wb") as f:
    pickle.dump({"weights": [1, 2, 3]}, f)

# torch.save layout (zip whose payload is a pickle) carrying a dangerous global.
with zipfile.ZipFile(p("evil.pt"), "w") as z:
    z.writestr("archive/data.pkl", pickle.dumps(Evil()))
    z.writestr("archive/data/0", b"\x00" * 64)

# Declared as small in the tree listing but actually over a tiny test cap, to
# exercise the post-download re-check (the tree API's size can be stale).
with open(p("stale-size.bin"), "wb") as f:
    f.write(b"\x80\x02}q\x00." + b"\x00" * 4096)
PY

tree_file() {  # writes a tree JSON from "path:size path:size ..." and echoes its location
    local out="$WORK/tree-$RANDOM.json"
    python3 -c "
import json, sys
entries = []
for tok in sys.argv[1:]:
    path, size = tok.rsplit(':', 1)
    entries.append({'path': path, 'size': (int(size) if size != '-' else None)})
json.dump(entries, open('$out', 'w'))
" "$@"
    echo "$out"
}

run_verify() {  # $1 sbom (copied fresh from fixture), rest passed as env already exported
    cp "$FIX/aibom-owasp-1_7.json" "$WORK/$1"
    PYTHONPATH="$WORK/hfstub" VERIFY_SAMPLES_DIR="$WORK/samples" \
        python3 "$SCRIPT" "$WORK/$1" google-bert/bert-base-uncased
}
set_tree() { VERIFY_TREE_FILE="$(tree_file "$@")"; export VERIFY_TREE_FILE; }
mprop() { jq -r --arg n "$1" '[.components[] | select(.type=="machine-learning-model") | .properties[]? | select(.name==$n) | .value] | first // ""' "$WORK/$2"; }

echo "== a repo with no pickle-format weights is left untouched =="
set_tree model.safetensors:1000 config.json:-
run_verify safe.json >"$WORK/safe.out" 2>&1
rc=$?
[ "$rc" = "0" ] && pass "exits 0 (best-effort, not a failure)" || fail "exit code=$rc"
[ "$(mprop bomlens:localscan:status safe.json)" = "" ] && pass "no localscan status stamped" || fail "status stamped despite no pickle weights"
grep -q "nothing to verify" "$WORK/safe.out" && pass "the log says why" || fail "log: $(cat "$WORK/safe.out")"

echo "== a file over the size cap is skipped, not scanned or stamped =="
set_tree clean.bin:999999999
AIBOM_VERIFY_MAX_BYTES=1024 run_verify oversized.json >"$WORK/oversized.out" 2>&1
[ "$(mprop bomlens:localscan:status oversized.json)" = "" ] && pass "no status stamped when every candidate exceeds the cap" || fail "status stamped despite the size cap"

echo "== the tree API's declared size can be stale; the downloaded bytes are re-checked =="
: > "$WORK/dl-calls.txt"
export VERIFY_DL_CALLS="$WORK/dl-calls.txt"
set_tree stale-size.bin:10
AIBOM_VERIFY_MAX_BYTES=100 run_verify stale.json >"$WORK/stale.out" 2>&1
[ "$(wc -l < "$WORK/dl-calls.txt" | tr -d ' ')" = "1" ] && pass "the file was downloaded once despite the small declared size" || fail "download call count=$(cat "$WORK/dl-calls.txt")"
[ "$(mprop bomlens:localscan:status stale.json)" = "" ] && pass "the actual (larger) size is caught after download; nothing stamped" || fail "status stamped for an over-cap file"
unset VERIFY_DL_CALLS

echo "== AIBOM_VERIFY_MAX_FILES caps how many candidates are downloaded =="
: > "$WORK/dl-calls.txt"
export VERIFY_DL_CALLS="$WORK/dl-calls.txt"
set_tree a.bin:10 b.bin:10 c.bin:10
# a/b/c.bin do not exist as samples, so every download 404s (status=error) —
# this scenario only checks how many downloads were ATTEMPTED, not their verdicts.
AIBOM_VERIFY_MAX_FILES=2 run_verify capped.json >"$WORK/capped.out" 2>&1
got=$(sort "$WORK/dl-calls.txt" | tr '\n' ',' )
[ "$got" = "a.bin,b.bin," ] && pass "only the first 2 (sorted) candidates were downloaded, c.bin left unchecked" || fail "downloads=$got"
unset VERIFY_DL_CALLS

if python3 -c "import picklescan" 2>/dev/null; then
    echo "== worst-wins rollup across multiple weight files, with picklescan installed =="
    : > "$WORK/dl-calls.txt"
    export VERIFY_DL_CALLS="$WORK/dl-calls.txt"
    set_tree clean.bin:100 evil.pt:100
    run_verify multi.json >"$WORK/multi.out" 2>&1
    [ "$(mprop bomlens:localscan:status multi.json)" = "unsafe" ] && pass "one dangerous file among clean ones rolls up to unsafe" || fail "status=$(mprop bomlens:localscan:status multi.json)"
    [ "$(mprop bomlens:localscan:filesChecked multi.json)" = "2" ] && pass "both files counted as checked" || fail "filesChecked=$(mprop bomlens:localscan:filesChecked multi.json)"
    f=$(mprop bomlens:localscan:findings multi.json)
    case "$f" in
        evil.pt:*) pass "the finding names the offending file" ;;
        *) fail "findings='$f', expected it prefixed with evil.pt" ;;
    esac
    tool=$(mprop bomlens:localscan:tool multi.json)
    case "$tool" in picklescan*) pass "the tool version is recorded" ;; *) fail "tool='$tool'" ;; esac

    echo "== a clean-only repo rolls up to clean =="
    set_tree clean.bin:100
    run_verify allclean.json >"$WORK/allclean.out" 2>&1
    [ "$(mprop bomlens:localscan:status allclean.json)" = "clean" ] && pass "a single clean pickle reads clean" || fail "status=$(mprop bomlens:localscan:status allclean.json)"

    echo "== re-running is idempotent =="
    set_tree evil.pt:100
    run_verify idem.json >/dev/null 2>&1
    run_verify idem.json >/dev/null 2>&1
    scnt=$(jq '[.components[] | select(.type=="machine-learning-model") | .properties[]? | select(.name=="bomlens:localscan:status")] | length' "$WORK/idem.json")
    [ "$scnt" = "1" ] && pass "re-verifying keeps one status property" || fail "status properties=$scnt, expected 1"

    echo "== the temp cache used for the download is removed when the run ends =="
    set_tree evil.pt:100
    export VERIFY_CACHE_LOG="$WORK/cache-dir.txt"
    run_verify cleanup.json >/dev/null 2>&1
    cache_dir="$(cat "$WORK/cache-dir.txt" 2>/dev/null || true)"
    if [ -n "$cache_dir" ] && [ ! -d "$cache_dir" ]; then
        pass "the temp download/cache directory no longer exists after the run"
    else
        fail "temp cache directory '$cache_dir' was left behind"
    fi
    unset VERIFY_CACHE_LOG
    unset VERIFY_DL_CALLS
else
    echo "  SKIP: picklescan not installed (pip install picklescan) — cap/wiring behavior is still covered above"
fi

echo ""
echo "=========================================="
echo " verify-model-weights: $PASS passed, $FAIL failed"
echo "=========================================="
[ "$FAIL" -eq 0 ] || exit 1
