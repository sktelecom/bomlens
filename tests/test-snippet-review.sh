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
 "src/g.c":[{"id":"none"}],
 "src/h.c":[{"id":"snippet","matched":"30%","lines":"1-30","purl":["pkg:github/acme/one"],"component":"one","version":"1","licenses":[{"name":"MIT"}],"file_hash":"hh77"},
            {"id":"snippet","matched":"30%","lines":"100-130","purl":["pkg:github/acme/two"],"component":"two","version":"1","licenses":[{"name":"MIT"}],"file_hash":"hh77"}],
 "src/big.c":[{"id":"snippet","matched":"6%","lines":"200-260","purl":["pkg:github/acme/hugefile"],"component":"hugefile","version":"2","licenses":[{"name":"GPL-2.0-only"}],"file_hash":"bg88"}],
 "src/m.c":[{"id":"snippet","matched":"90%","lines":"1-40","purl":["pkg:github/acme/permis"],"component":"permis","version":"1","licenses":[{"name":"MIT"}],"file_hash":"mm99"},
            {"id":"snippet","matched":"85%","lines":"1-40","purl":["pkg:github/acme/strong"],"component":"strong","version":"1","licenses":[{"name":"GPL-3.0-only"}],"file_hash":"mm99"}]}
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
[ "$(tier pkg:github/acme/libbar)" = "decide:partial,copyleft" ] && pass "a partial copy of 11 lines or more and 40% or more needs a decision" || fail "libbar is not decide:partial" "$(tier pkg:github/acme/libbar)"
[ "$(tier pkg:github/acme/tiny)" = "reference:" ] && pass "a match of 10 lines or fewer is shown for information only" || fail "tiny is not reference"
[ "$(tier pkg:github/acme/nolic)" = "decide:license" ] && pass "a whole-file match with no license found needs a decision" || fail "nolic is not decide:license"
[ "$(tier pkg:github/acme/hugefile)" = "decide:partial,copyleft" ] && pass "a long copy inside a big file needs a decision however small its share of the file" || fail "a diluted copy was not asked about" "$(tier pkg:github/acme/hugefile)"

# the shape of a real answer: a whole-file match to another project whose license text carries a GPL clause
cat > "$TMP/real.json" <<'JSON'
{"adler32.c":[{"id":"file","matched":"100%","lines":"all","oss_lines":"all","purl":["pkg:sourceforge/api-simple-completa/api-"],"component":"api-simple-completa/api-","version":"2025-03",
  "licenses":[{"name":"GPL-2.0-or-later AND GPL-1.0-or-later AND Zlib"},{"name":"HPND-Pbmplus"}],"file_hash":"2edfc7ec","source_hash":"4dc406b7","file":"adler32.c","release_date":"2025-03-01"}]}
JSON
rt="$(python3 - "$TOOL" "$TMP/real.json" <<'PY'
import importlib.util, json, sys
s = importlib.util.spec_from_file_location("sr", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
g = m.groups_of(json.load(open(sys.argv[2])))[0]
print(g["tier"] + ":" + ",".join(g["reasons"]) + ":" + g["files"][0]["akey"])
PY
)"
[ "$rt" = "decide:copyleft:4dc406b7:all" ] && pass "a whole-file match whose license carries a copyleft obligation is not confirmed on its own, and keeps the scan's own hash of the user's file as a second key" || fail "a copyleft whole-file match was auto-confirmed" "$rt"
printf '[{"component":"pkg:sourceforge/api-simple-completa/api-","decision":"coincidence","reviewer":"a","files":[{"key":"unmatched-root-key","alt":"4dc406b7:all"}]}]' > "$TMP/dec-alt.json"
echo '[{"type":"library","name":"api-simple-completa/api-","version":"2025-03","properties":[]}]' > "$TMP/comps-real.json"
out="$(python3 "$TOOL" apply "$TMP/comps-real.json" "$TMP/real.json" "$TMP/dec-alt.json" 2>/dev/null)"
[ "$(jq 'length' <<<"$out")" = "0" ] && pass "a decision made on a page built with the source tree still applies from the scan's own hash when no tree is given" || fail "the second key did not match" "$out"

# ---- queue ----------------------------------------------------------------------------
q="$(python3 "$TOOL" queue "$TMP/raw.json" 2>/dev/null | awk -F'\t' '{print $2}' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
[ "$q" = " 2 contest; 4 group;" ] || [ "$q" = " 2 contest; 3 group;" ] && pass "the queue lists the groups and the contests that need a decision" || fail "unexpected queue" "$q"

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
[{"component":"pkg:github/acme/libbar","decision":"ours","reason":"https://git.example/ours/repo","reviewer":"a","files":[{"key":"cc33:10-60"}]},
 {"component":"pkg:github/acme/nolic","decision":"version","version":"1.1","reason":"checked the tag","reviewer":"a"}]
JSON
out="$(python3 "$TOOL" apply "$TMP/comps.json" "$TMP/raw.json" "$TMP/dec.json" 2>/dev/null)"
if [ "$(jq -r '[.[].name] | join(",")' <<<"$out")" = "libfoo,nolic" ] && [ "$(jq -r '.[] | select(.name=="nolic") | .version' <<<"$out")" = "1.1" ]; then
    pass "code decided to be our own leaves the SBOM, and a corrected version replaces the detected one"
else fail "decisions were not applied" "$out"; fi

sed 's/cc33/changed/' "$TMP/dec.json" > "$TMP/dec-stale.json"
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

# ---- contests -------------------------------------------------------------------------
contest() { python3 - "$TOOL" "$1" <<'PY'
import importlib.util, json, sys
s = importlib.util.spec_from_file_location("sr", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
items = m.groups_of(json.load(open(sys.argv[2])))
cs = [i for i in items if i["kind"] == "contest"]
print(json.dumps([{"name": c["name"], "n": len(c["files"]), "differs": c["differs"], "key": c["key"], "purls": sorted(f["purl"] for f in c["files"])} for c in cs]))
PY
}
cj="$(contest "$TMP/raw.json")"
if [ "$(jq 'length' <<<"$cj")" = "2" ] && [ "$(jq -r '[.[] | select(.name=="src/f.c") | .n][0]' <<<"$cj")" = "2" ] && [ "$(jq -r '[.[] | select(.name=="src/f.c") | .differs][0]' <<<"$cj")" = "false" ]; then
    pass "two sources matching the same lines of one file form one contest"
else fail "the contest was not detected" "$cj"; fi
[ "$(jq -r '[.[] | select(.name=="src/h.c")] | length' <<<"$cj")" = "0" ] && pass "two sources matching different regions of one file are a combination, not a contest" || fail "a combination was treated as a contest"
[ "$(jq -r '[.[] | select(.name=="src/m.c") | .differs][0]' <<<"$cj")" = "true" ] && pass "a contest between a permissive and a strong copyleft source is marked as differing in obligation" || fail "the obligation difference was not flagged"
ck="$(jq -r '[.[] | select(.name=="src/f.c") | .key][0]' <<<"$cj")"
cat > "$TMP/comps2.json" <<'JSON'
[{"type":"library","name":"one","version":"1","properties":[]},{"type":"library","name":"two","version":"1","properties":[]},
 {"type":"library","name":"libfoo","version":"1.2.0","properties":[]}]
JSON
out="$(python3 "$TOOL" apply "$TMP/comps2.json" "$TMP/raw.json" "$TMP/none.json" 2>/dev/null)"
if [ "$(jq '[.[] | select(.name=="one" or .name=="two") | .properties[] | select(.name=="bomlens:review" and .value=="pending")] | length' <<<"$out")" -ge 1 ] && [ "$(jq 'length' <<<"$out")" = "3" ]; then
    pass "an undecided contest keeps every candidate in the SBOM, marked pending, so nothing is silently dropped"
else fail "an undecided contest dropped a candidate or was not marked" "$out"; fi
cat > "$TMP/dec-c.json" <<JSON
[{"contest":"$ck","decision":"origin","choice":"pkg:github/acme/one","version":"1","reason":"header names the project","reviewer":"a",
  "others":[{"purl":"pkg:github/acme/two","version":"1","license":"MIT"}]}]
JSON
out="$(python3 "$TOOL" apply "$TMP/comps2.json" "$TMP/raw.json" "$TMP/dec-c.json" 2>/dev/null)"
if [ "$(jq -r '[.[].name] | sort | join(",")' <<<"$out")" = "libfoo,one,two" ] && [ "$(jq -r '[.[] | select(.name=="one") | .properties[] | select(.name=="bomlens:alsoMatched") | .value][0]' <<<"$out")" = "pkg:github/acme/two@1 (permissive)" ]; then
    pass "choosing the origin keeps that source and records the other as also matched; a source with other files of its own stays"
else fail "the origin choice was not applied" "$out"; fi
mk="$(jq -r '[.[] | select(.name=="src/m.c") | .key][0]' <<<"$cj")"
cat > "$TMP/comps3.json" <<'JSON'
[{"type":"library","name":"permis","version":"1","properties":[]},{"type":"library","name":"strong","version":"1","properties":[]}]
JSON
cat > "$TMP/dec-m.json" <<JSON
[{"contest":"$mk","decision":"origin","choice":"pkg:github/acme/permis","version":"1","reason":"header says permis","reviewer":"a",
  "others":[{"purl":"pkg:github/acme/strong","version":"1","license":"GPL-3.0-only"}]}]
JSON
out="$(python3 "$TOOL" apply "$TMP/comps3.json" "$TMP/raw.json" "$TMP/dec-m.json" 2>"$TMP/m.err")"
if [ "$(jq -r '[.[].name] | join(",")' <<<"$out")" = "permis" ] && grep -q "weaker than candidate" "$TMP/m.err"; then
    pass "a source whose every file went to the other is dropped, and picking the weaker obligation is reported for sampling"
else fail "the weaker-obligation choice was not handled" "$(cat "$TMP/m.err")"; fi
echo "[{\"contest\":\"$ck\",\"decision\":\"origin\",\"choice\":\"pkg:github/acme/one\",\"reviewer\":\"a\"}]" > "$TMP/dec-c-bad.json"
out="$(python3 "$TOOL" apply "$TMP/comps2.json" "$TMP/raw.json" "$TMP/dec-c-bad.json" 2>/dev/null)"
[ "$(jq 'length' <<<"$out")" = "3" ] && pass "an origin choice without its reason is ignored" || fail "an origin choice without a reason was applied"
# a candidate that appears later with a different obligation sends the decision back to the queue
python3 - "$TMP/raw.json" "$TMP/raw-new.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
r["src/f.c"].append({"id": "snippet", "matched": "70%", "lines": "1-30", "purl": ["pkg:github/acme/gplfork"], "component": "gplfork", "version": "1", "licenses": [{"name": "GPL-2.0-only"}], "file_hash": "ff66"})
json.dump(r, open(sys.argv[2], "w"))
PY
nk="$(contest "$TMP/raw-new.json" | jq -r '[.[] | select(.name=="src/f.c") | .key][0]')"
sed "s/$ck/$nk/" "$TMP/dec-c.json" > "$TMP/dec-c2.json"
out="$(python3 "$TOOL" apply "$TMP/comps2.json" "$TMP/raw-new.json" "$TMP/dec-c2.json" 2>/dev/null)"
if [ "$(jq -r '[.[] | select(.name=="two")] | length' <<<"$out")" = "1" ]; then
    pass "a new candidate with a different obligation sends an earlier origin choice back to the queue"
else fail "a stale origin choice still applied after a new candidate appeared"; fi

# ---- accepted sources the scan's own list did not carry --------------------------------------
echo '[{"component":"pkg:github/acme/libbar","decision":"add","reason":"checked"}]' > "$TMP/dec-add2.json"
echo '[]' > "$TMP/empty-comps.json"
out="$(python3 "$TOOL" apply "$TMP/empty-comps.json" "$TMP/raw.json" "$TMP/dec-add2.json" 2>/dev/null)"
[ "$(jq -r '.[0].name' <<<"$out")" = "libbar" ] && pass "accepting a partial copy adds the component even when the scan's own list did not carry it" || fail "the accepted partial copy did not reach the SBOM" "$out"
echo '[{"component":"pkg:github/acme/libbar","decision":"add"}]' > "$TMP/dec-add3.json"
[ "$(python3 "$TOOL" apply "$TMP/empty-comps.json" "$TMP/raw.json" "$TMP/dec-add3.json" 2>/dev/null | jq 'length')" = "0" ] && pass "an add decision without a reason is ignored" || fail "an add without a reason was applied"

# ---- keys -----------------------------------------------------------------------------
python3 - "$TOOL" "$TMP" <<'PY' && pass "a decision follows the matched lines, not their line numbers or the rest of the file" || fail "the region key changed with unrelated edits"
import importlib.util, os, sys
s = importlib.util.spec_from_file_location("sr", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
tmp = sys.argv[2]; body = [f"matched line {i}" for i in range(20)]
os.makedirs(tmp + "/ka", exist_ok=True); os.makedirs(tmp + "/kb", exist_ok=True)
open(tmp + "/ka/x.c", "w").write("\n".join(["a"] + body + ["b"]) + "\n")
open(tmp + "/kb/x.c", "w").write("\n".join(["new header", "another"] + body + ["different tail", "more"]) + "\n")
fa = {"path": "x.c", "lines": "2-21", "hash": "", "source_hash": ""}; fb = {"path": "x.c", "lines": "3-22", "hash": "", "source_hash": ""}
ha, ra = m.local_keys(tmp + "/ka", fa); hb, rb = m.local_keys(tmp + "/kb", fb)
sys.exit(0 if ra == rb and ha != hb else 1)
PY
if grep -q "'bomlens-snippet-review:' + D.id" "$TOOL"; then pass "the page keeps its drafts per scan, so another scan's page does not show them"; else fail "the page storage key is not per scan"; fi
mkdir -p "$TMP/rel2"; : > "$TMP/rel2/libx-1.2.10.tar.gz"; tar -czf "$TMP/rel2/libx-1.2.10.tar.gz" -C "$TMP/origin" libbar-3.0
python3 - "$TOOL" "$TMP/rel2" <<'PY' && pass "a release named libx-1.2.10 is not taken for libx-1.2" || fail "the source release name matched across a version boundary"
import importlib.util, sys
s = importlib.util.spec_from_file_location("sr", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
f = {"origin_file": "lib/bar.c", "component": "libx", "version": "1.2", "path": "p", "origin_tree": ""}
v = m.origin_view(sys.argv[2], [f], m.Budget(10**6))
sys.exit(0 if not v["texts"] and not v["trees"] else 1)
PY

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
