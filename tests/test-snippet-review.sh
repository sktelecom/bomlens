#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-snippet-review.sh — No-Docker tests for docker/lib/snippet-review.py
#
# What these guard:
#   - matches are grouped by source and sorted into decide / auto / reference tiers
#   - a decision applies to the whole group, needs its reason, and goes stale when the matched files change
#   - code a person called their own, a coincidence or already declared leaves the SBOM; every undecided
#     group that needs a decision is marked pending instead of being dropped
#   - the review page loads nothing from the network, escapes its data, and reads only files under --root
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT_DIR/docker/lib/snippet-review.py"
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

for t in jq python3; do command -v "$t" >/dev/null 2>&1 || { echo "[ERROR] $t is required"; exit 1; }; done
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/raw.json" <<'JSON'
{"src/a.c":[{"id":"file","matched":"100%","lines":"all","purl":["pkg:github/acme/libfoo"],"component":"libfoo","version":"1.2.0","licenses":[{"name":"MIT"}],"file_hash":"aa11"}],
 "src/b.c":[{"id":"file","matched":"100%","lines":"all","purl":["pkg:github/acme/libfoo"],"component":"libfoo","version":"1.2.0","licenses":[{"name":"MIT"}],"file_hash":"bb22"}],
 "src/c.c":[{"id":"snippet","matched":"62%","lines":"10-60","oss_lines":"200-250","purl":["pkg:github/acme/libbar"],"component":"libbar","version":"3.0","licenses":[{"name":"GPL-2.0-only"}],"file_hash":"cc33"}],
 "src/d.c":[{"id":"snippet","matched":"15%","lines":"5-9","purl":["pkg:github/acme/tiny"],"component":"tiny","version":"0.1","licenses":[],"file_hash":"dd44"}],
 "src/e.c":[{"id":"file","matched":"100%","lines":"all","purl":["pkg:github/acme/nolic"],"component":"nolic","version":"1.0","licenses":[],"file_hash":"ee55"}],
 "src/f.c":[{"id":"snippet","matched":"80%","lines":"1-30","purl":["pkg:github/acme/one"],"component":"one","version":"1","licenses":[{"name":"MIT"}],"file_hash":"ff66"},
            {"id":"snippet","matched":"75%","lines":"1-30","purl":["pkg:github/acme/two"],"component":"two","version":"1","licenses":[{"name":"MIT"}],"file_hash":"ff66"}],
 "src/g.c":[{"id":"none"}]}
JSON
tier() { python3 - "$TOOL" "$TMP/raw.json" "$1" <<'PY'
import importlib.util, json, sys
s = importlib.util.spec_from_file_location("sr", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
g = {i["key"]: i for i in m.groups_of(json.load(open(sys.argv[2])))}
print(g[sys.argv[3]]["tier"] + ":" + ",".join(g[sys.argv[3]]["reasons"]))
PY
}

# ---- tiers ----------------------------------------------------------------------------
[ "$(tier pkg:github/acme/libfoo)" = "auto:" ] && pass "whole files from one source with a license are confirmed by evidence" || fail "libfoo is not auto"
[ "$(tier pkg:github/acme/libbar)" = "decide:partial" ] && pass "a partial copy of 11 lines or more and 40% or more needs a decision" || fail "libbar is not decide:partial" "$(tier pkg:github/acme/libbar)"
[ "$(tier pkg:github/acme/tiny)" = "reference:" ] && pass "a match of 10 lines or fewer is shown for information only" || fail "tiny is not reference"
[ "$(tier pkg:github/acme/nolic)" = "decide:license" ] && pass "a whole-file match with no license found needs a decision" || fail "nolic is not decide:license"
[ "$(tier pkg:github/acme/one)" = "decide:partial,split" ] && pass "a file claimed by several sources is marked as split" || fail "split file not marked" "$(tier pkg:github/acme/one)"

# ---- queue ----------------------------------------------------------------------------
q="$(python3 "$TOOL" queue "$TMP/raw.json" 2>/dev/null | cut -f1 | sort | tr '\n' ' ')"
[ "$q" = "pkg:github/acme/libbar pkg:github/acme/nolic pkg:github/acme/one pkg:github/acme/two " ] && pass "the queue lists only the groups that need a decision" || fail "unexpected queue" "$q"

# ---- decisions ------------------------------------------------------------------------
cat > "$TMP/comps.json" <<'JSON'
[{"type":"library","name":"libfoo","version":"1.2.0","purl":"pkg:github/acme/libfoo","properties":[{"name":"bomlens:scanoss:purl","value":"pkg:github/acme/libfoo"}]},
 {"type":"library","name":"libbar","version":"3.0","purl":"pkg:github/acme/libbar","properties":[{"name":"bomlens:scanoss:purl","value":"pkg:github/acme/libbar"}]},
 {"type":"library","name":"nolic","version":"1.0","purl":"pkg:github/acme/nolic","properties":[{"name":"bomlens:scanoss:purl","value":"pkg:github/acme/nolic"}]}]
JSON
echo '[]' > "$TMP/none.json"
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/none.json" 2>/dev/null)"
if [ "$(jq 'length' <<<"$out")" = "3" ] \
   && [ "$(jq -r '[.[] | select(.name=="libbar") | .properties[] | select(.name=="bomlens:review") | .value] | first' <<<"$out")" = "pending" ] \
   && [ "$(jq -r '[.[] | select(.name=="libfoo") | .properties[] | select(.name=="bomlens:review")] | length' <<<"$out")" = "0" ]; then
    pass "with no decisions nothing is dropped and every group that needs one is marked pending"
else fail "undecided groups were dropped or not marked" "$out"; fi

cat > "$TMP/dec.json" <<'JSON'
[{"component":"pkg:github/acme/libbar","decision":"ours","reason":"https://git.example/ours/repo","reviewer":"a","files":[{"hash":"cc33","lines":"10-60"}]},
 {"component":"pkg:github/acme/nolic","decision":"version","version":"1.1","reason":"checked the tag","reviewer":"a"}]
JSON
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/dec.json" 2>/dev/null)"
if [ "$(jq -r '[.[].name] | join(",")' <<<"$out")" = "libfoo,nolic" ] && [ "$(jq -r '.[] | select(.name=="nolic") | .version' <<<"$out")" = "1.1" ]; then
    pass "code decided to be our own leaves the SBOM, and a corrected version replaces the detected one"
else fail "decisions were not applied" "$out"; fi

sed 's/"cc33"/"changed"/' "$TMP/dec.json" > "$TMP/dec-stale.json"
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/dec-stale.json" 2>/dev/null)"
if [ "$(jq -r '[.[] | select(.name=="libbar") | .properties[] | select(.name=="bomlens:review") | .value] | first' <<<"$out")" = "pending" ]; then
    pass "a decision pinned to files that no longer match goes back to the queue instead of applying"
else fail "a stale decision still applied" "$out"; fi

echo '[{"component":"pkg:github/acme/libbar","decision":"ours","reviewer":"a"},{"component":"pkg:github/acme/nolic","decision":"declared"}]' > "$TMP/dec-bad.json"
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/dec-bad.json" 2>"$TMP/bad.err")"
if [ "$(jq 'length' <<<"$out")" = "3" ] && [ "$(grep -c 'malformed or incomplete' "$TMP/bad.err")" = "2" ]; then
    pass "a decision without its reason, or a declared-as name, is ignored with a warning"
else fail "an incomplete decision was applied" "$(cat "$TMP/bad.err")"; fi

echo '[{"component":"pkg:github/acme/libbar","decision":"add","reason":"checked"}]' > "$TMP/dec-add.json"
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/dec-add.json" 2>/dev/null)"
if [ "$(jq -r '[.[] | select(.name=="libbar") | .properties[] | select(.name=="bomlens:review") | .value] | first' <<<"$out")" = "add: checked" ]; then
    pass "an accepted match stays in the SBOM and records the review"
else fail "the add decision was not recorded" "$out"; fi

# ---- page -----------------------------------------------------------------------------
mkdir -p "$TMP/src"; seq 1 80 | sed 's/^/line /' > "$TMP/src/c.c"
python3 "$TOOL" page "$TMP/raw.json" --root "$TMP" > "$TMP/page.html" 2>/dev/null
if ! grep -q -E 'https?://[^"]*\.(js|css)|<link |src="http' "$TMP/page.html" && grep -q 'line 80' "$TMP/page.html" && grep -q 'line 1\\n' "$TMP/page.html"; then
    pass "the page loads nothing from the network and carries the whole of the user's matched file"
else fail "the page references the network or lacks the file text"; fi
if grep -q '"tree": \[[^]]*"src/c.c"' "$TMP/page.html"; then pass "the user's source tree is listed with the matched files in it"; else fail "the source tree is missing"; fi
echo '{"../../etc/hosts":[{"id":"snippet","matched":"90%","lines":"1-30","purl":["pkg:x/y"],"component":"y","version":"1","licenses":[],"file_hash":"zz"}]}' > "$TMP/trav.json"
python3 "$TOOL" page "$TMP/trav.json" --root "$TMP/src" 2>/dev/null | grep -q '"texts": {}' && pass "a path that leaves --root is never read" || fail "a path outside --root was read"
echo '{"x.c":[{"id":"snippet","matched":"90%","lines":"1-30","purl":["pkg:x/y"],"component":"</script><b>","version":"1","licenses":[],"file_hash":"q"}]}' > "$TMP/xss.json"
python3 "$TOOL" page "$TMP/xss.json" 2>/dev/null | grep -c '</script><b>' | grep -qx 0 && pass "data that contains a closing script tag cannot break out of the page" || fail "unescaped data in the page"
if grep -q "innerHTML" "$TOOL"; then fail "the page uses innerHTML"; else pass "the page builds its content without innerHTML"; fi

# ---- original side --------------------------------------------------------------------
mkdir -p "$TMP/origin/libbar-3.0/lib"; seq 1 300 | sed 's/^/orig /' > "$TMP/origin/libbar-3.0/lib/bar.c"
tar -czf "$TMP/rel/libbar-3.0.tar.gz" -C "$TMP/origin" libbar-3.0 2>/dev/null || { mkdir -p "$TMP/rel"; tar -czf "$TMP/rel/libbar-3.0.tar.gz" -C "$TMP/origin" libbar-3.0; }
sed 's#"oss_lines":"200-250"#"oss_lines":"200-250","file":"lib/bar.c"#' "$TMP/raw.json" > "$TMP/raw-origin.json"
python3 "$TOOL" page "$TMP/raw-origin.json" --origin "$TMP/rel" > "$TMP/page-origin.html" 2>/dev/null
if grep -q 'orig 300' "$TMP/page-origin.html" && grep -q '"lib/bar.c"' "$TMP/page-origin.html" && grep -q '"oss_lines": "200-250"' "$TMP/page-origin.html"; then
    pass "with the release sources the page carries the whole original file, its tree, and the matched region"
else fail "the original file, its tree or the region is missing"; fi
python3 "$TOOL" page "$TMP/raw.json" > "$TMP/page-noorigin.html" 2>/dev/null
grep -q 'orig 200' "$TMP/page-noorigin.html" && fail "original lines appeared without --origin" || pass "without --origin no original text is shown, only the address and line numbers"

echo
echo "snippet review: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
