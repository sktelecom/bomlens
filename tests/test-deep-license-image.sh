#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-deep-license-image.sh - the deep-license image, run for real.
#
# Usage: tests/test-deep-license-image.sh <deep-license-image> [<base-image>]
#
# Scans examples/nodejs with scripts/scan-sbom.sh and checks the result
# manifest (bomlens-result.json) the way tests/test-engine-contract.sh does
# for the scripts:
#   - with --deep-license on the deep-license image: the deep-license step is
#     ok, _scancode.json is written and listed as license-scan.scancode, and
#     the manifest validates against schemas/engine-result-1.json;
#   - with --deep-license on the base image (no scancode): the step is
#     skipped with reason not_installed, not missing and not ok;
#   - without --deep-license: the step is disabled.
# The last two run only when a base image is given. Needs Docker, jq, and
# the cdxgen Node.js image (pulled on first use).

set -u

DL_IMAGE="${1:?deep-license image}"
BASE_IMAGE="${2:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT_DIR/schemas/engine-result-1.json"
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# scan <name> <image> [extra scan-sbom.sh flags...] - prints the manifest path.
scan() {
    local name="$1" image="$2"; shift 2
    SBOM_SCANNER_IMAGE="$image" SBOM_DEEP_LICENSE_IMAGE="$image" \
        bash "$ROOT_DIR/scripts/scan-sbom.sh" --project dl --version 1.0 \
        --target "$ROOT_DIR/examples/nodejs" --generate-only --output-dir "$WORK/$name" "$@" \
        > "$WORK/$name.log" 2>&1
    printf '%s' "$WORK/$name/dl_1.0/bomlens-result.json"
}

step_of() { jq -r '[.steps[] | select(.id=="deep-license")][0] | "\(.status) \(.reason)"' "$1" 2>/dev/null; }

echo "== --deep-license on $DL_IMAGE =="
M="$(scan dl "$DL_IMAGE" --deep-license)"
if [ ! -f "$M" ]; then
    fail "no bomlens-result.json" "$(tail -20 "$WORK/dl.log")"
else
    [ "$(step_of "$M")" = "ok null" ] && pass "deep-license is ok" || fail "deep-license is $(step_of "$M")" "$(tail -20 "$WORK/dl.log")"
    [ -s "$WORK/dl/dl_1.0/dl_1.0_scancode.json" ] && pass "_scancode.json is written" || fail "no _scancode.json"
    [ "$(jq -r '[.outputs[] | select(.role=="license-scan.scancode")][0].path' "$M")" = "dl_1.0_scancode.json" ] \
        && pass "it is listed as license-scan.scancode" || fail "outputs: $(jq -c '[.outputs[].role]' "$M")"
    jq -e 'any(.files[]?; .path == "index.js" and .type == "file")' "$WORK/dl/dl_1.0/dl_1.0_scancode.json" >/dev/null 2>&1 \
        && pass "scancode read the project's own files (index.js, path relative to the tree)" \
        || fail "index.js is not in the result" "$(jq -c '[.files[]?.path][0:10]' "$WORK/dl/dl_1.0/dl_1.0_scancode.json" 2>/dev/null)"
    if python3 -c "import jsonschema" 2>/dev/null; then
        err="$(python3 - "$SCHEMA" "$M" <<'PY'
import json, sys, jsonschema
v = jsonschema.Draft202012Validator(json.load(open(sys.argv[1])))
print("\n".join(e.message[:200] for e in v.iter_errors(json.load(open(sys.argv[2])))))
PY
)"
        [ -z "$err" ] && pass "the manifest validates against the schema" || fail "schema errors" "$err"
    else
        echo "  SKIP: jsonschema is not installed"
    fi
fi

# A tree whose own folder is named like an excluded one (a web UI upload of a
# dist/ folder), holding a node_modules: run the image directly in SOURCE mode
# the way the web UI does. With no Docker socket it falls back to syft, which
# is enough here: only the licence scan is checked.
echo "== a tree named dist with a node_modules, image run directly =="
mkdir -p "$WORK/tree/dist/node_modules/dep" "$WORK/direct"
cp -R "$ROOT_DIR/examples/nodejs/." "$WORK/tree/dist/"
printf '// SPDX-License-Identifier: GPL-3.0-only\n' > "$WORK/tree/dist/node_modules/dep/index.js"
# A lockfile, so the syft fallback this run takes finds the declared
# dependency and the scan is not rejected as empty before the licence step.
echo '{"name":"nodejs-example","version":"1.0.0","dependencies":{"dep":"1.0.0"}}' > "$WORK/tree/dist/package.json"
cat > "$WORK/tree/dist/package-lock.json" <<'EOF2'
{"name":"nodejs-example","version":"1.0.0","lockfileVersion":3,"requires":true,
 "packages":{"":{"name":"nodejs-example","version":"1.0.0","dependencies":{"dep":"1.0.0"}},
  "node_modules/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","license":"GPL-3.0-only"}}}
EOF2
docker run --rm -v "$WORK/tree:/scan:ro" -v "$WORK/direct:/host-output" -w /host-output \
    -e MODE=SOURCE -e SOURCE_ROOT=/scan/dist -e PROJECT_NAME=dl -e PROJECT_VERSION=1.0 \
    -e HOST_OUTPUT_DIR=/host-output -e UPLOAD_ENABLED=false -e BOMLENS_ARTIFACT_CLEANUP=1 \
    -e DEEP_LICENSE=true -e ENRICH_EOL=false -e ENRICH_MALICIOUS=false \
    "$DL_IMAGE" > "$WORK/direct.log" 2>&1
SC="$WORK/direct/dl_1.0_scancode.json"
[ "$(step_of "$WORK/direct/bomlens-result.json")" = "ok null" ] && pass "deep-license is ok" \
    || fail "deep-license is $(step_of "$WORK/direct/bomlens-result.json")" "$(tail -20 "$WORK/direct.log")"
jq -e 'any(.files[]?; .path == "index.js")' "$SC" >/dev/null 2>&1 \
    && pass "the tree is scanned although its folder is named dist" \
    || fail "index.js missing from the result" "$(jq -c '[.files[]?.path][0:10]' "$SC" 2>/dev/null)"
# scancode still lists the ignored folder itself; what matters is that no file
# inside it was read.
jq -e '[.files[]? | select(.type == "file" and (.path | test("(^|/)node_modules/")))] | length == 0' "$SC" >/dev/null 2>&1 \
    && pass "no file inside node_modules is scanned" \
    || fail "files inside node_modules were scanned" "$(jq -c '[.files[]? | select(.path | test("node_modules")) | [.path, .type]]' "$SC" 2>/dev/null)"

echo "== LGPL sources in the image, and no copyleft package beyond the documented ones =="
src_ls="$(docker run --rm --entrypoint sh "$DL_IMAGE" -c 'ls /usr/share/bomlens/sources/p7zip-16.02 /usr/share/bomlens/sources/intbitset-*' 2>&1)"
for f in p7zip_16.02_src_all.tar.bz2 "p7zip_16.02+dfsg-6.debian.tar.xz" 15-Enhanced-encryption-strength.patch.zip README intbitset-; do
    printf '%s\n' "$src_ls" | grep -qF "$f" && pass "sources include $f" || fail "sources lack $f" "$src_ls"
done
# Every installed distribution whose licence metadata names a GPL family
# licence must be one THIRD_PARTY_LICENSES.md accounts for (an LGPL component
# with its source bundled, or a dual licence used under the other choice).
copyleft="$(docker run --rm --entrypoint python3 "$DL_IMAGE" - <<'PY'
import importlib.metadata as m, re
allowed = {"chardet", "intbitset", "extractcode-7z", "gemfileparser2", "text-unidecode",
           "typecode-libmagic", "extractcode-libarchive", "scancode-toolkit"}
for d in m.distributions():
    md = d.metadata
    text = " ".join(filter(None, [md.get("License-Expression"), md.get("License")] + md.get_all("Classifier", [])))
    name = re.sub(r"[-_.]+", "-", (md.get("Name") or "")).lower()
    if re.search(r"\b(A|L)?GPL\b|General Public License", text) and name not in allowed:
        print(name)
PY
)"
[ -z "$copyleft" ] && pass "no undocumented GPL-family package in the image" || fail "undocumented GPL-family packages:" "$copyleft"

if [ -n "$BASE_IMAGE" ]; then
    echo "== --deep-license on $BASE_IMAGE (no scancode) =="
    M="$(scan base-dl "$BASE_IMAGE" --deep-license)"
    [ "$(step_of "$M")" = "skipped not_installed" ] && pass "deep-license is skipped, not_installed" \
        || fail "deep-license is $(step_of "$M")" "$(tail -20 "$WORK/base-dl.log")"
    echo "== --deep-license when the scancode image cannot be pulled =="
    SBOM_SCANNER_IMAGE="$BASE_IMAGE" SBOM_DEEP_LICENSE_IMAGE="bomlens-test/no-such-image:0" \
        bash "$ROOT_DIR/scripts/scan-sbom.sh" --project dl --version 1.0 \
        --target "$ROOT_DIR/examples/nodejs" --generate-only --output-dir "$WORK/nopull" --deep-license \
        > "$WORK/nopull.log" 2>&1
    rc=$?
    M="$WORK/nopull/dl_1.0/bomlens-result.json"
    [ "$rc" = 0 ] && [ "$(step_of "$M")" = "skipped fallback" ] && [ "$(jq -r .run.status "$M")" = "succeeded_degraded" ] \
        && pass "the scan still runs on the base image, records skipped/fallback, and the run is succeeded_degraded" \
        || fail "rc=$rc, deep-license is $(step_of "$M")" "$(tail -20 "$WORK/nopull.log")"
    echo "== no --deep-license on $BASE_IMAGE =="
    M="$(scan base "$BASE_IMAGE")"
    [ "$(step_of "$M")" = "disabled null" ] && pass "deep-license is disabled" \
        || fail "deep-license is $(step_of "$M")" "$(tail -20 "$WORK/base.log")"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
